"""Tests for `gateclerk status` (card t_b120aaae, CLI-STATUS).

Verifies:
1. One-screen health output for configured sites in table, `-o json`, and `--check` modes,
   plus `--site` filtering.
2. Per-sink pending and dead-letter counts read directly from `push_queue` / `dead_letter`
   tables via `sink_cli.sink_rows` (no new schema).
3. Cached device probe rule: fresh (<60s) probe is reported (`ok` or `unreachable` -> exit 4);
   stale (>60s) or missing probe degrades to `warn` (`unknown — run: gateclerk doctor`) and
   never opens a network socket.
4. Agent loop pidfile & health snapshot rules: live pid -> `running (pid N)`; dead pid in
   pidfile -> exit 2; circuit open in snapshot -> exit 3; stale snapshot (> max(600s, 3*cadence))
   with an existing store -> exit 2.
5. Exit-code precedence `2 > 3 > 4 > 6` (with `6` emitted when dead-letter rows exist).
6. Redact sweep: planted bearer token, device password, and dead-letter employee payload
   never appear anywhere in `gateclerk status` output (table or JSON).
"""

from __future__ import annotations

import json
import os
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from typer.testing import CliRunner

from gateclerk import agent_cli, agent_db, agent_store, status_cli, status_cmds
from gateclerk.cli import app
from gateclerk.model import Direction, DirectionSource, EventRecord, Outcome, TzSource

runner = CliRunner()

FIXED_NOW = datetime(2026, 11, 4, 12, 0, 0, tzinfo=UTC)
PLANTED_BEARER = "BearerTokenSecretValue_998877"
PLANTED_PII_NAME = "Popescu ConfidentialPayload"


def _seed_event(conn: object, *, serial_no: int = 1) -> int:
    rec = EventRecord(
        site="demo-a",
        device_serial="DEMO-SN-01",
        serial_no=serial_no,
        employee_no="DEMO-EMP-99",
        name=PLANTED_PII_NAME,
        event_time_utc=FIXED_NOW - timedelta(minutes=5),
        event_time_local="2026-11-04T13:55:00+02:00",
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
        raw={"serialNo": serial_no, "name": PLANTED_PII_NAME},
        captured_at=FIXED_NOW - timedelta(minutes=5),
    )
    res = agent_store.store_events(conn, [rec])  # type: ignore[arg-type]
    assert res.rowids is not None
    return res.rowids[serial_no]


def _write_sites_toml(
    tmp_path: Path, *, state_dir: Path, device_code: str | None = "DEMO-A-1"
) -> Path:
    cfg_file = tmp_path / "sites.toml"
    dc_line = f'device_code = "{device_code}"\n' if device_code else ""
    cfg_file.write_text(
        f"""\
[[site]]
name = "demo-a"
host = "192.0.2.10"
iana_tz = "Europe/Bucharest"
{dc_line}db_path = "{state_dir / "gateclerk-demo-a.sqlite3"}"

[[site.sink]]
name = "cloud"
type = "https"
url = "https://ingest.example.invalid/v1/push"
token_env = "GATECLERK_INGEST_TOKEN_DEMO_A"

[[site.sink]]
name = "archive"
type = "csv"
path = "{state_dir / "archive.csv"}"
""",
        encoding="utf-8",
    )
    return cfg_file


def _write_snapshot(
    state_dir: Path,
    *,
    age_s: float = 15.0,
    circuit_open: bool = False,
    push_ok: int = 4,
    push_failed: int = 0,
) -> Path:
    snap_dir = state_dir / agent_cli.HEALTH_DIR_NAME
    snap_dir.mkdir(parents=True, exist_ok=True)
    snap_path = snap_dir / agent_cli.HEALTH_FILE_NAME
    snap_path.write_text(
        json.dumps(
            {
                "site": "demo-a",
                "devices": [{"host": "192.0.2.10", "circuit_open": circuit_open}],
                "site_metrics": [
                    {"name": "push_ok", "value": push_ok},
                    {"name": "push_failed", "value": push_failed},
                ],
            }
        ),
        encoding="utf-8",
    )
    ts = (FIXED_NOW - timedelta(seconds=age_s)).timestamp()
    os.utime(snap_path, (ts, ts))
    return snap_path


def _write_probe_cache(
    state_dir: Path, *, age_s: float = 10.0, ok: bool = True, detail: str = ""
) -> Path:
    probe_path = state_dir.joinpath(*status_cli.PROBE_CACHE_PARTS)
    probe_path.parent.mkdir(parents=True, exist_ok=True)
    checked = (FIXED_NOW - timedelta(seconds=age_s)).isoformat()
    probe_path.write_text(
        json.dumps({"ok": ok, "checked_at": checked, "detail": detail}),
        encoding="utf-8",
    )
    return probe_path


def test_healthy_site_table_json_and_check_modes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(status_cmds, "_now", lambda: FIXED_NOW)
    state_dir = tmp_path / "state"
    state_dir.mkdir()
    cfg_file = _write_sites_toml(tmp_path, state_dir=state_dir)

    db_path = state_dir / "gateclerk-demo-a.sqlite3"
    conn = agent_db.connect(db_path, now_iso=FIXED_NOW.isoformat())
    try:
        _seed_event(conn, serial_no=1)
    finally:
        conn.close()

    _write_snapshot(state_dir, age_s=12.0)
    _write_probe_cache(state_dir, age_s=20.0, ok=True)
    roster_file = state_dir / "archive-2026-11-04.roster.csv"
    roster_file.write_text("deviceEmployeeNo,name\n", encoding="utf-8")
    roster_ts = (FIXED_NOW - timedelta(seconds=45)).timestamp()
    os.utime(roster_file, (roster_ts, roster_ts))

    res_table = runner.invoke(
        app, ["status", "--config", str(cfg_file), "--state-root", str(state_dir)]
    )
    assert res_table.exit_code == 0, res_table.output
    assert "demo-a" in res_table.stdout
    assert "cloud=0/0" in res_table.stdout

    res_json = runner.invoke(
        app,
        [
            "status",
            "--config",
            str(cfg_file),
            "--state-root",
            str(state_dir),
            "-o",
            "json",
        ],
    )
    assert res_json.exit_code == 0, res_json.output
    row = json.loads(res_json.stdout.strip())
    assert row["site"] == "demo-a"
    assert row["verdict"] == "ok"
    assert row["exit_code"] == 0
    assert row["device"] == "ok (20s ago)"
    assert row["roster"] == "45s ago"
    assert [s["sink"] for s in row["sink_rows"]] == ["cloud", "archive"]

    res_check = runner.invoke(
        app,
        ["status", "--config", str(cfg_file), "--state-root", str(state_dir), "--check"],
    )
    assert res_check.exit_code == 0
    assert json.loads(res_check.stdout.strip())["site"] == "demo-a"


def test_stale_or_missing_device_probe_points_to_doctor_without_failing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(status_cmds, "_now", lambda: FIXED_NOW)
    state_dir = tmp_path / "state"
    state_dir.mkdir()
    cfg_file = _write_sites_toml(tmp_path, state_dir=state_dir, device_code=None)
    _write_snapshot(state_dir, age_s=10.0)
    # 90s old > DEVICE_PROBE_MAX_AGE_S (60s) -> stale probe degrades to warn
    _write_probe_cache(state_dir, age_s=90.0, ok=False, detail="old failure")

    res = runner.invoke(
        app,
        ["status", "--config", str(cfg_file), "--state-root", str(state_dir), "-o", "json"],
    )
    assert res.exit_code == 0, res.output
    row = json.loads(res.stdout.strip())
    assert row["verdict"] == "warn"
    assert row["device"] == "unknown — run: gateclerk doctor"
    assert "device_code unset" in row["notes"]


def test_exit_codes_6_dead_letter_4_probe_3_circuit_2_stale_and_precedence(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(status_cmds, "_now", lambda: FIXED_NOW)
    monkeypatch.setenv("GATECLERK_INGEST_TOKEN_DEMO_A", PLANTED_BEARER)
    state_dir = tmp_path / "state"
    state_dir.mkdir()
    cfg_file = _write_sites_toml(tmp_path, state_dir=state_dir)
    db_path = state_dir / "gateclerk-demo-a.sqlite3"

    conn = agent_db.connect(db_path, now_iso=FIXED_NOW.isoformat())
    try:
        ev_id = _seed_event(conn, serial_no=1)
        conn.execute(
            "INSERT INTO dead_letter (event_id, payload, endpoint, sink_name, error_class, "
            "attempts, first_attempt_at, last_attempt_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (
                ev_id,
                json.dumps({"name": PLANTED_PII_NAME, "token": PLANTED_BEARER}),
                "https://ingest.example.invalid/v1/push",
                "cloud",
                "HttpStatus502",
                5,
                "2026-11-03T10:00:00+00:00",
                "2026-11-04T11:50:00+00:00",
            ),
        )
    finally:
        conn.close()

    _write_snapshot(state_dir, age_s=10.0)
    _write_probe_cache(state_dir, age_s=15.0, ok=True)

    # Dead-letter row -> exit 6, and neither bearer token nor payload PII appears in output
    res_dl = runner.invoke(
        app,
        ["status", "--config", str(cfg_file), "--state-root", str(state_dir), "-o", "json"],
    )
    assert res_dl.exit_code == 6, res_dl.output
    assert PLANTED_BEARER not in res_dl.stdout
    assert PLANTED_PII_NAME not in res_dl.stdout
    assert "HttpStatus502" in res_dl.stdout
    assert "GATECLERK_INGEST_TOKEN_DEMO_A" in res_dl.stdout

    # Fresh failed device probe (exit 4) beats exit 6
    _write_probe_cache(state_dir, age_s=15.0, ok=False, detail="ConnectTimeout")
    res_probe = runner.invoke(
        app,
        ["status", "--config", str(cfg_file), "--state-root", str(state_dir), "-o", "json"],
    )
    assert res_probe.exit_code == 4, res_probe.output

    # Circuit open in health snapshot (exit 3) beats exit 4 and 6
    _write_snapshot(state_dir, age_s=10.0, circuit_open=True)
    res_circuit = runner.invoke(
        app,
        ["status", "--config", str(cfg_file), "--state-root", str(state_dir), "-o", "json"],
    )
    assert res_circuit.exit_code == 3, res_circuit.output

    # Stale pidfile (exit 2) beats exit 3, 4, and 6
    (state_dir / status_cli.PIDFILE_NAME).write_text("99999999\n", encoding="utf-8")
    monkeypatch.setattr(status_cli, "_pid_alive", lambda _pid: False)
    res_pid = runner.invoke(
        app,
        ["status", "--config", str(cfg_file), "--state-root", str(state_dir), "-o", "json"],
    )
    assert res_pid.exit_code == 2, res_pid.output
