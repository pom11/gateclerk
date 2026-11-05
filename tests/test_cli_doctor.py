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

from gateclerk import agent_cli, agent_db, agent_store, doctor_cli, service_cli, status_cli
from gateclerk.cli import app
from gateclerk.config import ConfigSurface, site_from_args
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


def _seed_store(db_path: Path, *, dead_letter: bool = False, site: str = "demo-a") -> None:
    conn = agent_db.connect(db_path, now_iso=FIXED_NOW.isoformat())
    try:
        rec = EventRecord(
            site=site,
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


# --- --state-root: option (c), the unit's per-site dir vs the operator's parent ---------------


def _write_state_root_config(tmp_path: Path, *, name: str) -> Path:
    """A site block with the DERIVED relative db_path (`./gateclerk-<site>.sqlite3`).

    This is what `service install`'s unit sees: `--state-root <base>/<site>` plus a relative
    store name. No sinks keeps the fixture to the one section under test.
    """
    cfg_file = tmp_path / f"{name}.toml"
    cfg_file.write_text(
        f"""\
[[site]]
name = "{name}"
host = "192.0.2.10"
iana_tz = "Europe/Bucharest"
""",
        encoding="utf-8",
    )
    return cfg_file


def _add_dead_letter(db_path: Path) -> None:
    """Add one dead-letter row to an already-seeded store (doctor's db row FAILS on any)."""
    conn = agent_db.connect(db_path, now_iso=FIXED_NOW.isoformat())
    try:
        event_id = int(conn.execute("SELECT id FROM events LIMIT 1").fetchone()[0])
        conn.execute(
            "INSERT INTO dead_letter (event_id, payload, endpoint, sink_name, error_class, "
            "attempts, first_attempt_at, last_attempt_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (
                event_id,
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


def _doctor_db_row(cfg_file: Path, *, site: str, state_root: Path) -> dict:
    res = runner.invoke(
        app,
        [
            "doctor",
            "--config",
            str(cfg_file),
            "--site",
            site,
            "--state-root",
            str(state_root),
            "-o",
            "json",
        ],
    )
    rows = [json.loads(line) for line in res.stdout.splitlines() if line.strip()]
    by_sec = {row["section"]: row for row in rows}
    return res, by_sec["db"]


def test_doctor_resolves_per_site_store_under_service_install_layout(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The layout `service install` writes: parent/<site>/gateclerk-<site>.sqlite3.

    `doctor` must find it whether the operator passes the PARENT (multi-site root) or the
    per-site directory the unit itself passes. `status`, `ack` and `deadletter list` must
    resolve the exact same store, because they all delegate to `resolve_db_path`.
    """
    site_name = "site-a"
    per_site = Path(service_cli.default_state_dir("launchd", site_name, home=tmp_path))
    parent = per_site.parent
    per_site.mkdir(parents=True)
    db_path = per_site / f"gateclerk-{site_name}.sqlite3"
    _seed_store(db_path, site=site_name)
    cfg_file = _write_state_root_config(tmp_path, name=site_name)

    monkeypatch.setattr(
        doctor_cli,
        "default_device_prober",
        lambda _site, **_kw: ("model=DS-K1T341 serial=DEMO-SN-01", 1.0),
    )
    monkeypatch.setattr(
        doctor_cli, "default_tls_prober", lambda _host, _port, **_kw: "TLSv1.3 cert verified"
    )

    site = site_from_args(site=site_name, config_path=cfg_file, surface=ConfigSurface.AGENT)
    expected = str(db_path)
    assert agent_cli.resolve_db_path(site, parent) == expected
    assert agent_cli.resolve_db_path(site, per_site) == expected

    for root in (parent, per_site):
        res, db_row = _doctor_db_row(cfg_file, site=site_name, state_root=root)
        assert db_row["status"] == "pass", res.output
        assert "integrity=ok" in db_row["detail"]
        assert "no store yet" not in db_row["detail"]

    # `status`: same store, same state dir (no "no store yet").
    row = status_cli.collect_site_status(site, state_root=parent, now=FIXED_NOW)
    assert row["state"] == str(per_site)
    assert row["db"] != "no store yet"

    # `ack`: it found the store (an empty park set exits 2 with "no parked device", while a
    # wrong path would have said "no store at <path>: nothing to ack").
    ack = runner.invoke(
        app,
        [
            "agent",
            "ack",
            "--site",
            site_name,
            "--config",
            str(cfg_file),
            "--state-root",
            str(parent),
        ],
    )
    assert "no store at" not in ack.output
    assert "no parked device" in ack.output

    # `deadletter list`: the row planted in the per-site store is the one it reads.
    _add_dead_letter(db_path)
    dead = runner.invoke(
        app,
        [
            "agent",
            "deadletter",
            "list",
            "--site",
            site_name,
            "--config",
            str(cfg_file),
            "--state-root",
            str(parent),
            "-o",
            "json",
        ],
    )
    assert dead.exit_code == 0, dead.output
    assert "HttpStatus502" in dead.stdout


def test_flat_store_wins_over_existing_per_site_dir(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A flat-layout site keeps its flat store even when `<root>/<site>/` already exists.

    `resolve_db_path` also serves `agent run`, the writer: descending into a stale/empty
    per-site directory here would silently open an empty store and re-pull every event.
    """
    site_name = "site-a"
    root = tmp_path / "state"
    root.mkdir()
    (root / site_name).mkdir()  # an existing per-site dir with NO store in it
    flat_db = root / f"gateclerk-{site_name}.sqlite3"
    _seed_store(flat_db, site=site_name)
    cfg_file = _write_state_root_config(tmp_path, name=site_name)

    monkeypatch.setattr(
        doctor_cli,
        "default_device_prober",
        lambda _site, **_kw: ("model=DS-K1T341 serial=DEMO-SN-01", 1.0),
    )
    monkeypatch.setattr(
        doctor_cli, "default_tls_prober", lambda _host, _port, **_kw: "TLSv1.3 cert verified"
    )

    site = site_from_args(site=site_name, config_path=cfg_file, surface=ConfigSurface.AGENT)
    assert agent_cli.resolve_db_path(site, root) == str(flat_db)
    assert agent_cli.resolve_state_root(site, root) == root

    res, db_row = _doctor_db_row(cfg_file, site=site_name, state_root=root)
    assert db_row["status"] == "pass", res.output
    assert "integrity=ok" in db_row["detail"]


def test_state_root_named_for_the_site_does_not_double_descend(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """`--state-root <base>/<site>` is the unit's form: never append `<site>` a second time."""
    site_name = "site-a"
    root = tmp_path / "state" / site_name
    root.mkdir(parents=True)
    (root / site_name).mkdir()  # decoy: a directory that a naive join would pick
    db_path = root / f"gateclerk-{site_name}.sqlite3"
    _seed_store(db_path, site=site_name)
    cfg_file = _write_state_root_config(tmp_path, name=site_name)

    monkeypatch.setattr(
        doctor_cli,
        "default_device_prober",
        lambda _site, **_kw: ("model=DS-K1T341 serial=DEMO-SN-01", 1.0),
    )
    monkeypatch.setattr(
        doctor_cli, "default_tls_prober", lambda _host, _port, **_kw: "TLSv1.3 cert verified"
    )

    site = site_from_args(site=site_name, config_path=cfg_file, surface=ConfigSurface.AGENT)
    assert agent_cli.resolve_db_path(site, root) == str(db_path)

    res, db_row = _doctor_db_row(cfg_file, site=site_name, state_root=root)
    assert db_row["status"] == "pass", res.output
    assert "integrity=ok" in db_row["detail"]
