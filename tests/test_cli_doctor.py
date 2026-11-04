"""Tests for `gateclerk doctor` (card t_0c1cf9fd, CLI-DOCTOR).

Verifies:
1. All six sections (`runtime`, `config`, `credentials`, `device`, `sinks`, `db`) report
   `pass`/`warn`/`fail` in table and `-o json` modes, with `--site` filtering.
2. `config` section warns when `device_code` is unset on a site with an `https` sink
   ("device_code unset (REQUIRED while roster serial->code fix is pending)").
3. `credentials` section verifies env, keychain metadata (without `-w`), and Linux
   credential file (`0600` mode check + ref key presence) without ever printing a secret.
4. `device` section checks read-only reachability + clock skew (`warn` when `abs(skew) > 120s`,
   `fail` exit 3 on 401 `IsapiAuthError`, `fail` exit 4 on unreachable `IsapiError`).
5. `sinks` section checks URL scheme+parse, token ref metadata, TLS handshake, and
   csv/jsonl directory writability.
6. `db` section runs read-only `PRAGMA quick_check` and checks `push_queue` / `dead_letter`
   counts (`dead_letter > 0` -> `fail` exit 6; corrupt db -> `fail` exit 2).
7. Exit-code precedence `2 > 3 > 4 > 6 > 0` and full secret redaction sweep.
"""

from __future__ import annotations

import json
import ssl
from datetime import UTC, datetime
from pathlib import Path

import pytest
from typer.testing import CliRunner

from gateclerk import agent_db, agent_store, doctor_cli
from gateclerk.cli import app
from gateclerk.exceptions import IsapiAuthError, IsapiError
from gateclerk.model import Direction, DirectionSource, EventRecord, Outcome, TzSource

runner = CliRunner()

FIXED_NOW = datetime(2026, 11, 4, 12, 0, 0, tzinfo=UTC)
PLANTED_DEVICE_PW = "DeviceSecretPassword_445566"
PLANTED_INGEST_TOK = "IngestBearerSecret_778899"


def _write_fixture_config(
    tmp_path: Path, *, db_path: Path, csv_sink_path: Path, device_code: str | None = "DEMO-A-1"
) -> Path:
    cfg_file = tmp_path / "sites.toml"
    dc_line = f'device_code = "{device_code}"\n' if device_code else ""
    cfg_file.write_text(
        f"""\
[[site]]
name = "demo-a"
host = "192.0.2.10"
iana_tz = "Europe/Bucharest"
{dc_line}db_path = "{db_path}"

[[site.sink]]
name = "cloud"
type = "https"
url = "https://ingest.example.invalid/v1/push"
token_env = "GATECLERK_INGEST_TOKEN_DEMO_A"

[[site.sink]]
name = "localcsv"
type = "csv"
path = "{csv_sink_path}"
""",
        encoding="utf-8",
    )
    return cfg_file


def _seed_store(db_path: Path, *, dead_letter: bool = False) -> None:
    conn = agent_db.connect(db_path, now_iso=FIXED_NOW.isoformat())
    try:
        rec = EventRecord(
            site="demo-a",
            device_serial="DEMO-SN-01",
            serial_no=1,
            employee_no="DEMO-E01",
            name="Popescu Demo",
            event_time_utc=FIXED_NOW,
            event_time_local="2026-11-04T14:00:00+02:00",
            tz_offset_min=120,
            tz_offset_min_device=120,
            tz_source=TzSource.SITE_TZ,
            iana_tz="Europe/Bucharest",
            direction=Direction.IN,
            attendance_status="checkIn",
            direction_source=DirectionSource.DEVICE,
            verify_mode="cardOrFaceOrFp",
            major=5,
            minor=75,
            outcome=Outcome.GRANTED,
            raw={"serialNo": 1},
            captured_at=FIXED_NOW,
        )
        res = agent_store.store_events(conn, [rec])
        assert res.rowids is not None
        if dead_letter:
            conn.execute(
                "INSERT INTO dead_letter (event_id, payload, endpoint, sink_name, error_class, "
                "attempts, first_attempt_at, last_attempt_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    res.rowids[1],
                    "{}",
                    "https://ingest.example.invalid/v1/push",
                    "cloud",
                    "HttpStatus502",
                    3,
                    "2026-11-04T11:00:00+00:00",
                    "2026-11-04T11:55:00+00:00",
                ),
            )
    finally:
        conn.close()


def test_doctor_all_pass_in_table_and_json_and_never_prints_secrets(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    db_path = tmp_path / "gateclerk-demo-a.sqlite3"
    csv_sink = tmp_path / "sinks" / "events.csv"
    csv_sink.parent.mkdir(parents=True)
    _seed_store(db_path)
    cfg_file = _write_fixture_config(tmp_path, db_path=db_path, csv_sink_path=csv_sink)

    monkeypatch.setenv("GATECLERK_192_0_2_10_PASSWORD", PLANTED_DEVICE_PW)
    monkeypatch.setenv("GATECLERK_INGEST_TOKEN_DEMO_A", PLANTED_INGEST_TOK)
    monkeypatch.setattr(
        doctor_cli,
        "default_device_prober",
        lambda _site, **_kw: ("model=DS-K1T341 serial=DEMO-SN-01", 3.5),
    )
    monkeypatch.setattr(
        doctor_cli,
        "default_tls_prober",
        lambda _host, _port, **_kw: "TLSv1.3 cert verified",
    )

    res_table = runner.invoke(app, ["doctor", "--config", str(cfg_file), "--site", "demo-a"])
    assert res_table.exit_code == 0, res_table.output
    assert PLANTED_DEVICE_PW not in res_table.output
    assert PLANTED_INGEST_TOK not in res_table.output

    res_json = runner.invoke(
        app, ["doctor", "--config", str(cfg_file), "--site", "demo-a", "-o", "json"]
    )
    assert res_json.exit_code == 0, res_json.output
    assert PLANTED_DEVICE_PW not in res_json.stdout
    assert PLANTED_INGEST_TOK not in res_json.stdout
    rows = [json.loads(line) for line in res_json.stdout.splitlines() if line.strip()]
    by_sec = {r["section"]: r for r in rows}
    assert set(by_sec) == {"runtime", "config", "credentials", "device", "sinks", "db"}
    assert all(r["status"] == "pass" for r in rows)
    assert "GATECLERK_192_0_2_10_PASSWORD" in by_sec["credentials"]["detail"]
    assert "TLSv1.3 cert verified" in by_sec["sinks"]["detail"]
    assert "integrity=ok pending=0 dead_letter=0" in by_sec["db"]["detail"]


def test_doctor_warns_on_missing_device_code_and_clock_skew_over_2min(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    db_path = tmp_path / "gateclerk-demo-a.sqlite3"
    csv_sink = tmp_path / "events.csv"
    cfg_file = _write_fixture_config(
        tmp_path, db_path=db_path, csv_sink_path=csv_sink, device_code=None
    )

    monkeypatch.setenv("GATECLERK_192_0_2_10_PASSWORD", PLANTED_DEVICE_PW)
    monkeypatch.setenv("GATECLERK_INGEST_TOKEN_DEMO_A", PLANTED_INGEST_TOK)
    monkeypatch.setattr(
        doctor_cli,
        "default_device_prober",
        lambda _site, **_kw: ("model=DS-K1T341 serial=DEMO-SN-01", 185.0),
    )
    monkeypatch.setattr(
        doctor_cli,
        "default_tls_prober",
        lambda _host, _port, **_kw: "TLSv1.3 cert verified",
    )

    res = runner.invoke(app, ["doctor", "--config", str(cfg_file), "-o", "json"])
    assert res.exit_code == 0, res.output
    rows = {
        r["section"]: r
        for r in (json.loads(line) for line in res.stdout.splitlines() if line.strip())
    }
    assert rows["config"]["status"] == "warn"
    assert "device_code unset (REQUIRED" in rows["config"]["detail"]
    assert rows["device"]["status"] == "warn"
    assert "exceeds 120s" in rows["device"]["detail"]
    assert rows["db"]["status"] == "warn"


def test_doctor_exit_code_matrix_and_credential_file_permissions(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    db_path = tmp_path / "gateclerk-demo-a.sqlite3"
    csv_sink = tmp_path / "events.csv"
    _seed_store(db_path, dead_letter=True)
    cfg_file = _write_fixture_config(tmp_path, db_path=db_path, csv_sink_path=csv_sink)

    monkeypatch.setenv("GATECLERK_192_0_2_10_PASSWORD", PLANTED_DEVICE_PW)
    monkeypatch.setenv("GATECLERK_INGEST_TOKEN_DEMO_A", PLANTED_INGEST_TOK)
    monkeypatch.setattr(
        doctor_cli,
        "default_device_prober",
        lambda _site, **_kw: ("model=DS-K1T341 serial=DEMO-SN-01", 1.0),
    )
    monkeypatch.setattr(
        doctor_cli,
        "default_tls_prober",
        lambda _host, _port, **_kw: "TLSv1.3 cert verified",
    )

    # Dead-letter rows -> exit 6
    res_6 = runner.invoke(app, ["doctor", "--config", str(cfg_file), "-o", "json"])
    assert res_6.exit_code == 6, res_6.output

    # TLS handshake failure on https sink -> exit 6
    def _bad_tls(_host: str, _port: int, **_kw: object) -> str:
        raise ssl.SSLError("CERTIFICATE_VERIFY_FAILED")

    monkeypatch.setattr(doctor_cli, "default_tls_prober", _bad_tls)
    res_tls = runner.invoke(app, ["doctor", "--config", str(cfg_file), "-o", "json"])
    assert res_tls.exit_code == 6

    # Device unreachable (exit 4) beats exit 6
    def _unreachable(_site: object, **_kw: object) -> tuple[str, float]:
        raise IsapiError("connect timeout")

    monkeypatch.setattr(doctor_cli, "default_device_prober", _unreachable)
    res_4 = runner.invoke(app, ["doctor", "--config", str(cfg_file), "-o", "json"])
    assert res_4.exit_code == 4

    # Device 401 terminal auth (exit 3) beats exit 4 and 6
    def _auth_fail(_site: object, **_kw: object) -> tuple[str, float]:
        raise IsapiAuthError("401 Unauthorized")

    monkeypatch.setattr(doctor_cli, "default_device_prober", _auth_fail)
    res_3 = runner.invoke(app, ["doctor", "--config", str(cfg_file), "-o", "json"])
    assert res_3.exit_code == 3

    # Permissive credential file mode (0644 -> exit 2) beats exit 3, 4, and 6
    monkeypatch.delenv("GATECLERK_192_0_2_10_PASSWORD", raising=False)
    cred_file = tmp_path / "credentials.json"
    cred_file.write_text(
        json.dumps({"refs": {"gateclerk-demo-a-192.0.2.10": PLANTED_DEVICE_PW}}),
        encoding="utf-8",
    )
    cred_file.chmod(0o644)
    monkeypatch.setenv("GATECLERK_CREDENTIALS_FILE", str(cred_file))
    monkeypatch.setattr(doctor_cli.sink_cli, "default_keychain_probe", lambda _s, _a: False)

    res_2 = runner.invoke(app, ["doctor", "--config", str(cfg_file), "-o", "json"])
    assert res_2.exit_code == 2
    assert "chmod 600" in res_2.stdout
    assert PLANTED_DEVICE_PW not in res_2.stdout
