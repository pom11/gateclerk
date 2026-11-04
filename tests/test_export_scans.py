"""Tests for `gateclerk export scans` (card t_5a0f39b2, EXPORT-SCANS).

Verifies:
1. Golden CSV and JSONL output from the agent's local SQLite store (`events` table) in
   `(event_time_utc, serial_no)` order (`jsonl` = verbatim `EventRecord.to_jsonl()` lines).
2. Filter matrix: `--site` (required when `> 1` site is configured in `sites.toml`),
   `--device`, `--employee`, `--since`, `--until`, `--direction` (`in|out|any`).
3. Streaming bound: cursor never calls `fetchall()`; monkeypatching
   `SCAN_EXPORT_CHUNK_SIZE = 2` streams rows in chunks of 2.
4. Personal-data law: help text states scans are personal data (GDPR-adjacent), TTY
   refuses without `--output <path>`, and `--output <path>` writes data to the file only
   while printing path + row count to stderr.
5. `--redact` drops `employee_no`, `cardNo`, and `name` columns and strips personal
   identifiers from `raw` and JSONL output.
6. `docs/EXPORT-COLUMNS.md` matches `SCAN_EXPORT_COLUMNS`.
"""

from __future__ import annotations

import csv
import io
import json
import sqlite3
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
from typer.testing import CliRunner

from _cli_surface import command_at, declared_prose
from gateclerk import agent_db, agent_store, export_cli
from gateclerk.cli import CONFIG_ERROR_EXIT, app
from gateclerk.export_cli import SCAN_EXPORT_COLUMNS, SCAN_EXPORT_REDACTED_COLUMNS
from gateclerk.model import Direction, DirectionSource, EventRecord, Outcome, TzSource

runner = CliRunner()


def _make_record(
    *,
    site: str = "demo-a",
    device_serial: str = "DEMO-DEV-01",
    serial_no: int,
    employee_no: str,
    name: str,
    card_no: str,
    utc_iso: str,
    local_iso: str,
    direction: Direction = Direction.IN,
) -> EventRecord:
    dt_utc = datetime.fromisoformat(utc_iso).astimezone(UTC)
    return EventRecord(
        site=site,
        device_serial=device_serial,
        serial_no=serial_no,
        employee_no=employee_no,
        name=name,
        event_time_utc=dt_utc,
        event_time_local=local_iso,
        tz_offset_min=120,
        tz_offset_min_device=120,
        tz_source=TzSource.SITE_TZ,
        iana_tz="Europe/Bucharest",
        tz_unresolved=False,
        tz_ambiguous=False,
        tz_nonexistent=False,
        tz_reason=None,
        tz_offset_mismatch=False,
        direction=direction,
        attendance_status="checkIn" if direction is Direction.IN else "checkOut",
        direction_source=DirectionSource.DEVICE,
        verify_mode="cardOrFaceOrFp",
        major=5,
        minor=75,
        outcome=Outcome.GRANTED,
        unknown_code=False,
        encrypted_person_data=False,
        raw={
            "serialNo": serial_no,
            "employeeNoString": employee_no,
            "name": name,
            "cardNo": card_no,
            "time": local_iso,
        },
        captured_at=datetime(2026, 11, 4, 12, 0, tzinfo=UTC),
    )


def _seed_fixture_env(
    tmp_path: Path, *, multi_site: bool = False
) -> tuple[Path, list[EventRecord]]:
    cfg_path = tmp_path / "sites.toml"
    db_a = tmp_path / "gateclerk-demo-a.sqlite3"
    toml_text = f"""\
[[site]]
name = "demo-a"
host = "192.0.2.10"
iana_tz = "Europe/Bucharest"
db_path = "{db_a}"
"""
    if multi_site:
        db_b = tmp_path / "gateclerk-demo-b.sqlite3"
        toml_text += f"""
[[site]]
name = "demo-b"
host = "192.0.2.20"
iana_tz = "Europe/Bucharest"
db_path = "{db_b}"
"""
    cfg_path.write_text(toml_text, encoding="utf-8")

    records_dev1 = [
        # Inserted out of chronological order so ORDER BY (event_time_utc, serial_no) is tested.
        _make_record(
            serial_no=102,
            employee_no="DEMO-E02",
            name="Ionescu Demo",
            card_no="CARD-9002",
            utc_iso="2026-11-04T07:00:00+00:00",
            local_iso="2026-11-04T09:00:00+02:00",
            direction=Direction.IN,
        ),
        _make_record(
            serial_no=101,
            employee_no="DEMO-E01",
            name="Popescu Demo",
            card_no="CARD-9001",
            utc_iso="2026-11-04T06:00:00+00:00",
            local_iso="2026-11-04T08:00:00+02:00",
            direction=Direction.IN,
        ),
        _make_record(
            serial_no=103,
            employee_no="DEMO-E01",
            name="Popescu Demo",
            card_no="CARD-9001",
            utc_iso="2026-11-04T14:30:00+00:00",
            local_iso="2026-11-04T16:30:00+02:00",
            direction=Direction.OUT,
        ),
    ]
    records_dev2 = [
        _make_record(
            device_serial="DEMO-DEV-02",
            serial_no=201,
            employee_no="DEMO-E02",
            name="Ionescu Demo",
            card_no="CARD-9002",
            utc_iso="2026-11-05T06:15:00+00:00",
            local_iso="2026-11-05T08:15:00+02:00",
            direction=Direction.IN,
        ),
    ]

    conn = agent_db.connect(db_a, now_iso="2026-11-04T12:00:00+00:00")
    try:
        agent_store.store_events(conn, records_dev1)
        agent_store.store_events(conn, records_dev2)
    finally:
        conn.close()

    ordered = sorted(records_dev1 + records_dev2, key=lambda r: (r.event_time_utc, r.serial_no))
    return cfg_path, ordered


def test_golden_csv_and_jsonl_in_event_time_serial_order(tmp_path: Path) -> None:
    cfg_path, ordered = _seed_fixture_env(tmp_path)

    jsonl_res = runner.invoke(
        app, ["export", "scans", "--config", str(cfg_path), "--format", "jsonl"]
    )
    assert jsonl_res.exit_code == 0, jsonl_res.output
    lines = [line for line in jsonl_res.stdout.splitlines() if line.strip()]
    assert lines == [r.to_json() for r in ordered]

    csv_res = runner.invoke(app, ["export", "scans", "--config", str(cfg_path), "--format", "csv"])
    assert csv_res.exit_code == 0, csv_res.output
    rows = list(csv.reader(io.StringIO(csv_res.stdout)))
    assert tuple(rows[0]) == SCAN_EXPORT_COLUMNS
    assert len(rows) == 5  # header + 4 ordered scans
    serials = [int(r[SCAN_EXPORT_COLUMNS.index("serial_no")]) for r in rows[1:]]
    assert serials == [101, 102, 103, 201]
    cards = [r[SCAN_EXPORT_COLUMNS.index("cardNo")] for r in rows[1:]]
    assert cards == ["CARD-9001", "CARD-9002", "CARD-9001", "CARD-9002"]


def test_filter_matrix_site_device_employee_since_until_direction(tmp_path: Path) -> None:
    cfg_path, _ = _seed_fixture_env(tmp_path, multi_site=True)

    # >1 site configured without --site -> exit 2
    no_site = runner.invoke(app, ["export", "scans", "--config", str(cfg_path)])
    assert no_site.exit_code == CONFIG_ERROR_EXIT
    assert "--site is required" in no_site.output

    # Filter by --site + --device
    by_dev = runner.invoke(
        app,
        [
            "export",
            "scans",
            "--config",
            str(cfg_path),
            "--site",
            "demo-a",
            "--device",
            "DEMO-DEV-02",
            "--format",
            "jsonl",
        ],
    )
    assert by_dev.exit_code == 0, by_dev.output
    objs = [json.loads(line) for line in by_dev.stdout.splitlines() if line.strip()]
    assert [o["serial_no"] for o in objs] == [201]

    # Filter by --employee + --direction out
    by_emp_dir = runner.invoke(
        app,
        [
            "export",
            "scans",
            "--config",
            str(cfg_path),
            "--site",
            "demo-a",
            "--employee",
            "DEMO-E01",
            "--direction",
            "out",
            "--format",
            "jsonl",
        ],
    )
    assert by_emp_dir.exit_code == 0, by_emp_dir.output
    objs = [json.loads(line) for line in by_emp_dir.stdout.splitlines() if line.strip()]
    assert [o["serial_no"] for o in objs] == [103]

    # Filter by --since and --until (site-local wall dates/times)
    by_window = runner.invoke(
        app,
        [
            "export",
            "scans",
            "--config",
            str(cfg_path),
            "--site",
            "demo-a",
            "--since",
            "2026-11-04T08:30:00",
            "--until",
            "2026-11-04T17:00:00",
            "--format",
            "jsonl",
        ],
    )
    assert by_window.exit_code == 0, by_window.output
    objs = [json.loads(line) for line in by_window.stdout.splitlines() if line.strip()]
    assert [o["serial_no"] for o in objs] == [102, 103]


def test_streaming_bound_uses_fetchmany_chunks_and_never_fetchall(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    cfg_path, _ = _seed_fixture_env(tmp_path)
    monkeypatch.setattr(export_cli, "SCAN_EXPORT_CHUNK_SIZE", 2)

    fetchmany_sizes: list[int] = []
    real_open = export_cli._open_scan_cursor

    class _GuardedCursor:
        def __init__(self, inner: sqlite3.Cursor) -> None:
            self._inner = inner

        def fetchmany(self, size: int = 1) -> list[Any]:
            fetchmany_sizes.append(size)
            return self._inner.fetchmany(size)

        def fetchall(self) -> list[Any]:
            raise AssertionError("export_scans must stream via fetchmany, never fetchall")

    monkeypatch.setattr(
        export_cli,
        "_open_scan_cursor",
        lambda conn, sql, params: _GuardedCursor(real_open(conn, sql, params)),  # type: ignore[return-value]
    )

    res = runner.invoke(app, ["export", "scans", "--config", str(cfg_path), "--format", "csv"])
    assert res.exit_code == 0, res.output
    # 4 rows with chunk size 2 -> two chunks of 2 plus final EOF call -> [2, 2, 2]
    assert fetchmany_sizes == [2, 2, 2]


def test_tty_refuses_without_output_and_redact_strips_personal_identifiers(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    cfg_path, _ = _seed_fixture_env(tmp_path)
    out_csv = tmp_path / "out" / "scans.csv"
    out_jsonl = tmp_path / "out" / "scans.jsonl"

    monkeypatch.setattr(export_cli, "_stdout_is_tty", lambda: True)
    refused = runner.invoke(app, ["export", "scans", "--config", str(cfg_path)])
    assert refused.exit_code == CONFIG_ERROR_EXIT
    assert "TTY" in refused.output
    assert not out_csv.exists()

    ok_csv = runner.invoke(
        app,
        [
            "export",
            "scans",
            "--config",
            str(cfg_path),
            "--output",
            str(out_csv),
            "--redact",
            "--bom",
        ],
    )
    assert ok_csv.exit_code == 0, ok_csv.output
    assert "wrote 4 scan row(s)" in ok_csv.output
    text_csv = out_csv.read_text(encoding="utf-8")
    assert text_csv.startswith("\ufeffsite,device_serial,serial_no,event_time_utc,")
    rows = list(csv.reader(io.StringIO(text_csv.lstrip("\ufeff"))))
    assert tuple(rows[0]) == SCAN_EXPORT_REDACTED_COLUMNS
    for pii in ("DEMO-E01", "DEMO-E02", "CARD-9001", "CARD-9002", "Popescu Demo", "Ionescu Demo"):
        assert pii not in text_csv

    ok_jsonl = runner.invoke(
        app,
        [
            "export",
            "scans",
            "--config",
            str(cfg_path),
            "--format",
            "jsonl",
            "--output",
            str(out_jsonl),
            "--redact",
        ],
    )
    assert ok_jsonl.exit_code == 0, ok_jsonl.output
    text_jsonl = out_jsonl.read_text(encoding="utf-8")
    for pii in ("DEMO-E01", "DEMO-E02", "CARD-9001", "CARD-9002", "Popescu Demo", "Ionescu Demo"):
        assert pii not in text_jsonl
    for line in text_jsonl.splitlines():
        obj = json.loads(line)
        assert "employee_no" not in obj
        assert "name" not in obj
        assert "cardNo" not in obj["raw"]


def test_help_mentions_personal_data_and_export_columns_doc_is_in_sync() -> None:
    prose = declared_prose(command_at(app, ["export", "scans"])).lower()
    assert "personal data" in prose
    assert "gdpr" in prose

    doc = (Path(__file__).resolve().parents[1] / "docs" / "EXPORT-COLUMNS.md").read_text(
        encoding="utf-8"
    )
    for col in SCAN_EXPORT_COLUMNS:
        assert f"`{col}`" in doc, f"docs/EXPORT-COLUMNS.md missing `{col}`"
