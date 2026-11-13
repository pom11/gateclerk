"""Tests for GC-P06 — the doctor must look for the `token-ref` name the sink checker emits.

`sink_cli._check_token_refs` emits `SinkCheck(check="token-ref")` (singular). `doctor_cli`
used to compare against `"token-refs"` (plural) in two places, which made both branches
unreachable:

  * the Linux credential-file fallback never ran, so a bearer stored in
    `~/.config/gateclerk/credentials.json` failed the doctor (exit 6);
  * a genuinely missing sink token landed in the push-failure bucket (exit 6) instead of
    the config bucket (exit 2).

These tests drive `run_doctor` directly (no keychain, no socket, no device) with a site
whose https sink names a keychain ref, so the credential-file rung is the only thing that
can save it.
"""

from __future__ import annotations

import inspect
import json
import re
import ssl
from datetime import UTC, datetime
from pathlib import Path

from gateclerk import agent_db, agent_store, credentials, doctor_cli, sink_cli
from gateclerk import config as cfg
from gateclerk.cli_conventions import CONFIG_ERROR_EXIT
from gateclerk.credentials import CREDENTIALS_FILE_ENV
from gateclerk.doctor_cli import PUSH_FAILURE_EXIT
from gateclerk.model import Direction, DirectionSource, EventRecord, Outcome, TzSource

FIXED_NOW = datetime(2026, 11, 4, 12, 0, 0, tzinfo=UTC)
PLANTED_DEVICE_PW = "DeviceSecretPassword_445566"
PLANTED_INGEST_TOK = "IngestBearerSecret_778899"
SITE = "demo-a"
HOST = "192.0.2.10"
INGEST_REF = "gateclerk-ingest-demo-a"


def _write_fixture_config(tmp_path: Path, *, db_path: Path) -> Path:
    """One https sink that names a keychain REF (`token_keychain`) and nothing else.

    This is the Linux shape the dead branch was written for: the bearer lives in
    `credentials.json` under that ref, so the doctor must fall back to the file instead of
    failing the sink.
    """
    cfg_file = tmp_path / "sites.toml"
    cfg_file.write_text(
        f"""\
[[site]]
name = "{SITE}"
host = "{HOST}"
iana_tz = "Europe/Bucharest"
device_code = "DEMO-A-1"
db_path = "{db_path}"

[[site.sink]]
name = "cloud"
type = "https"
url = "https://ingest.example.invalid/v1/push"
token_keychain = "{INGEST_REF}"
""",
        encoding="utf-8",
    )
    return cfg_file


def _seed_store(db_path: Path, *, dead_letter: bool = False) -> None:
    """A live store (doctor's `db` row fails on a missing file and on any dead letter)."""
    conn = agent_db.connect(db_path, now_iso=FIXED_NOW.isoformat())
    try:
        rec = EventRecord(
            site=SITE,
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


def _write_credential_file(tmp_path: Path, *, refs: dict[str, str]) -> Path:
    """A 0600 `credentials.json` (the Linux backend's store), pointed at by env."""
    cred_file = tmp_path / "credentials.json"
    cred_file.write_text(json.dumps({"refs": refs}), encoding="utf-8")
    cred_file.chmod(0o600)
    return cred_file


def _credential_refs() -> dict[str, str]:
    """The refs the fixture's `credentials.json` carries: device password + ingest bearer."""
    return {
        INGEST_REF: PLANTED_INGEST_TOK,
        cfg.credential_ref(SITE, HOST): PLANTED_DEVICE_PW,
    }


def _env(
    tmp_path: Path,
    *,
    cred_file: Path | None,
    device_pw: bool = True,
    ingest_env: bool = False,
) -> dict[str, str]:
    """The env the doctor runs with. Explicit and merged, so the operator's real HOME is never read.

    `credentials.resolve_file_store` merges `os.environ` under the mapping it is handed, so
    the `GATECLERK_CREDENTIALS_FILE` key is always set here — to the fixture file, or to a
    path that does not exist when the test means "no credential file at all".
    """
    _host_user, host_pw_env, _global_user, _global_pw = cfg.env_var_names(HOST)
    env: dict[str, str] = {
        CREDENTIALS_FILE_ENV: str(cred_file if cred_file else tmp_path / "absent-credentials.json")
    }
    if device_pw:
        env[host_pw_env] = PLANTED_DEVICE_PW
    if ingest_env:
        env["GATECLERK_INGEST_TOKEN_DEMO_A"] = PLANTED_INGEST_TOK
    return env


def _rows_by_section(rows: list[doctor_cli.DoctorRow]) -> dict[str, doctor_cli.DoctorRow]:
    return {row.section: row for row in rows}


def _no_keychain(_service: str, _account: str) -> bool:
    """The headless-Linux answer: there is no keychain here, so nothing resolves from it."""
    return False


def _tls_ok(_host: str, _port: int) -> str:
    return "TLSv1.3 cert verified"


def test_doctor_token_ref_falls_back_to_credentials_file(tmp_path: Path) -> None:
    """A bearer that exists ONLY in `credentials.json` must satisfy the sinks row (exit 0).

    Keychain probe says False, there is no token env, and the sink names `token_keychain`,
    so the only rung that can answer is the credential file. Before the fix the sinks row
    failed with exit 6 here.
    """
    db_path = tmp_path / "gateclerk-demo-a.sqlite3"
    _seed_store(db_path)
    cfg_file = _write_fixture_config(tmp_path, db_path=db_path)
    cred_file = _write_credential_file(tmp_path, refs=_credential_refs())

    rows, code = doctor_cli.run_doctor(
        config_path=cfg_file,
        site=SITE,
        env=_env(tmp_path, cred_file=cred_file),
        keychain_probe=_no_keychain,
        device_prober=lambda _site, **_kw: ("model=DS-K1T341 serial=DEMO-SN-01", 3.5),
        tls_prober=_tls_ok,
    )
    sinks = _rows_by_section(rows)["sinks"]

    assert code == 0, f"sinks row: {sinks.status} {sinks.detail}"
    assert sinks.status == "pass"
    assert sinks.exit_code == 0
    # The row says WHERE the bearer resolved, and never carries its value.
    assert "credentials.json" in sinks.detail
    assert PLANTED_INGEST_TOK not in sinks.detail
    assert PLANTED_INGEST_TOK not in json.dumps([r.as_dict() for r in rows])


def test_doctor_missing_token_ref_is_exit_2_not_6(tmp_path: Path) -> None:
    """No env, no keychain, no credential file -> a config error (2), not a push failure (6).

    Nothing about this site can deliver a byte, but the fault is configuration, and R2 says
    an operator must be able to tell "not configured" apart from "could not deliver".
    """
    db_path = tmp_path / "gateclerk-demo-a.sqlite3"
    _seed_store(db_path)
    cfg_file = _write_fixture_config(tmp_path, db_path=db_path)

    rows, code = doctor_cli.run_doctor(
        config_path=cfg_file,
        site=SITE,
        env=_env(tmp_path, cred_file=None),
        keychain_probe=_no_keychain,
        device_prober=lambda _site, **_kw: ("model=DS-K1T341 serial=DEMO-SN-01", 3.5),
        tls_prober=_tls_ok,
    )
    sinks = _rows_by_section(rows)["sinks"]

    assert sinks.status == "fail"
    assert sinks.exit_code == CONFIG_ERROR_EXIT == 2
    assert code == CONFIG_ERROR_EXIT
    assert code != PUSH_FAILURE_EXIT
    assert "token-ref" in sinks.detail


def test_doctor_and_sink_cli_use_the_same_check_name(tmp_path: Path) -> None:
    """The name the doctor branches on must be a name the sink checker can actually emit."""
    sink_src = inspect.getsource(sink_cli)
    doctor_src = inspect.getsource(doctor_cli)

    # The plural typo is gone from both modules (quoted literals, comments and summaries).
    for src in (sink_src, doctor_src):
        assert not re.search(r"""["']token-refs["']""", src)
    assert '"token-ref"' in sink_src
    assert '"token-ref"' in doctor_src

    # And the singular name is the one a live `check_sink` really reports for a missing ref.
    cfg_file = _write_fixture_config(tmp_path, db_path=tmp_path / "gateclerk-demo-a.sqlite3")
    site = cfg.find_site(cfg.load_sites(cfg_file, surface=cfg.ConfigSurface.CLI), SITE)
    checks = sink_cli.check_sink(site, site.effective_sinks[0], env={}, keychain_probe=_no_keychain)
    emitted = {chk.check for chk in checks}
    assert "token-ref" in emitted
    # It is the FAILING check that carries the name — that is the event the doctor's
    # credential-file fallback keys on, so the name has to match on that branch too.
    assert "token-ref" in {chk.check for chk in checks if not chk.ok}


def test_doctor_still_exits_6_for_a_sink_push_failure(tmp_path: Path) -> None:
    """The fix must not flatten the exit matrix: a delivery-path failure still exits 6.

    Two delivery-shaped faults, both with the sink token resolved (so the sinks row is the
    only thing that can move the code): a failed TLS handshake, and a dead-letter row from a
    previous push that got a 5xx.
    """
    db_path = tmp_path / "gateclerk-demo-a.sqlite3"
    _seed_store(db_path)
    cfg_file = _write_fixture_config(tmp_path, db_path=db_path)
    cred_file = _write_credential_file(tmp_path, refs=_credential_refs())
    env = _env(tmp_path, cred_file=cred_file)

    def _handshake_fails(_host: str, _port: int) -> str:
        raise ssl.SSLError("certificate verify failed")

    rows, code = doctor_cli.run_doctor(
        config_path=cfg_file,
        site=SITE,
        env=env,
        keychain_probe=_no_keychain,
        device_prober=lambda _site, **_kw: ("model=DS-K1T341 serial=DEMO-SN-01", 3.5),
        tls_prober=_handshake_fails,
    )
    sinks = _rows_by_section(rows)["sinks"]
    assert sinks.status == "fail"
    assert sinks.exit_code == PUSH_FAILURE_EXIT == 6
    assert code == PUSH_FAILURE_EXIT

    # A dead letter (a push that got a 5xx) also stays a 6, with the sinks row passing.
    dead_path = tmp_path / "dead.sqlite3"
    _seed_store(dead_path, dead_letter=True)
    dead_cfg = _write_fixture_config(tmp_path, db_path=dead_path)
    rows_2, code_2 = doctor_cli.run_doctor(
        config_path=dead_cfg,
        site=SITE,
        env=env,
        keychain_probe=_no_keychain,
        device_prober=lambda _site, **_kw: ("model=DS-K1T341 serial=DEMO-SN-01", 3.5),
        tls_prober=_tls_ok,
    )
    by_sec = _rows_by_section(rows_2)
    assert by_sec["sinks"].status == "pass"
    assert by_sec["db"].status == "fail"
    assert by_sec["db"].exit_code == PUSH_FAILURE_EXIT
    assert code_2 == PUSH_FAILURE_EXIT


def test_token_ref_name_is_used_by_the_credentials_module_too() -> None:
    """Guard: the doctor's file fallback still reads the ref through `credentials.ingest_ref`.

    The fallback resolves `spec.token_keychain or credentials.ingest_ref(site)`; the card
    out-of-scope list names `credentials.py`, so pin the ref name the fallback looks for.
    """
    assert credentials.ingest_ref(SITE) == INGEST_REF
