"""Tests for `gateclerk export non-punches` (card GC-P20 / E22).

What the operator gets: the DISTINCT fingerprints of scans this poller already pushed to BC
that were NOT granted punches, so BC-P30 can mark them ignored and recalculate. Three
properties the card fixes, each pinned from both sides where it can be:

1. READ-ONLY. Nothing in this path writes: not the store, not the ledger, not BC. Pinned by
   a byte checksum + mtime + size of the store before/after the CLI runs, and by the
   connection seam refusing a write outright (a `PRAGMA query_only` guard, not a promise).
2. FINGERPRINTS ONLY. One column, `fingerprint`; no employee number, name, card number or
   raw payload anywhere in the bytes. The fingerprint is BC's dedupe key and is emitted
   verbatim — hashing it a second time would break the join it exists for.
3. ONLY WHAT WAS PUSHED. The poller's ledger (`PushLedger.sent_event_ids`) is the only
   evidence of "already at BC"; an event the ledger does not name is not in the report,
   and a missing ledger is an empty report with a note, never a crash.

The store fixture is `tests/test_export_scans.py`'s (same sites.toml + `store_events`
shape) and the ledger writer is `tests/test_p2_07b_agent_cli.py`'s (`PushLedger.append`).
"""

from __future__ import annotations

import csv
import hashlib
import io
import json
import sqlite3
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
from typer.testing import CliRunner

from gateclerk import agent_cli, agent_db, agent_store, export_cli
from gateclerk.cli import CONFIG_ERROR_EXIT, app
from gateclerk.exceptions import ConfigError
from gateclerk.model import Direction, DirectionSource, EventRecord, Outcome, TzSource

runner = CliRunner()

SITE = "demo-a"
DB_NAME = "gateclerk-demo-a.sqlite3"
#: A stand-in push target. The ledger stores this string, so it must stay synthetic.
TARGET = "https://bc.example.invalid/ingest"
T0 = datetime(2026, 11, 4, 12, 0, tzinfo=UTC)

#: PII the seeded rows carry. Every one of these must be absent from the report.
SECRET_EMPLOYEE = "DEMO-E01"
SECRET_NAME = "Popescu Demo"
SECRET_CARD = "CARD-9001"


def _record(
    *,
    serial_no: int,
    local_time: str,
    employee_no: str | None = SECRET_EMPLOYEE,
    name: str = SECRET_NAME,
    card_no: str = SECRET_CARD,
    verify_mode: str | None = "cardOrFaceOrFp",
    major: int | None = 5,
    minor: int | None = 75,
    outcome: Outcome = Outcome.GRANTED,
    unknown_code: bool = False,
) -> EventRecord:
    """One stored event with a fingerprint of its own.

    The fingerprint is `sha256(employee_no, event_time_local, minor)`
    (`model.fingerprint_key_hash`), so `local_time` is what makes two rows distinguishable.
    """
    return EventRecord(
        site=SITE,
        device_serial="DEMO-DEV-01",
        serial_no=serial_no,
        employee_no=employee_no,
        name=name,
        event_time_utc=datetime.fromisoformat("2026-11-04T10:00:00+00:00"),
        event_time_local=local_time,
        tz_offset_min=120,
        tz_offset_min_device=120,
        tz_source=TzSource.SITE_TZ,
        iana_tz="Europe/Bucharest",
        direction=Direction.IN,
        attendance_status="checkIn",
        direction_source=DirectionSource.DEVICE,
        verify_mode=verify_mode,
        major=major,
        minor=minor,
        outcome=outcome,
        unknown_code=unknown_code,
        raw={
            "serialNo": serial_no,
            "employeeNoString": employee_no,
            "name": name,
            "cardNo": card_no,
            "time": local_time,
        },
        captured_at=T0,
    )


#: The card's four-event store: a granted punch, a denial, an informational event, and a
#: code the curated table cannot name.
GRANTED = _record(serial_no=100, local_time="2026-11-04T12:00:00+02:00")
DENIED = _record(serial_no=101, local_time="2026-11-04T12:01:00+02:00", outcome=Outcome.DENIED)
INFO = _record(
    serial_no=102,
    local_time="2026-11-04T12:02:00+02:00",
    major=3,
    minor=64,
    outcome=Outcome.INFO,
    verify_mode=None,
)
UNKNOWN = _record(
    serial_no=103,
    local_time="2026-11-04T12:03:00+02:00",
    minor=999,
    outcome=Outcome.INFO,
    unknown_code=True,
)
ALL_EVENTS = (GRANTED, DENIED, INFO, UNKNOWN)


def _seed(tmp_path: Path, records: tuple[EventRecord, ...] = ALL_EVENTS) -> tuple[Path, Path]:
    """Write sites.toml + the store the way `export scans`' fixture does. Returns (cfg, db)."""
    cfg_path = tmp_path / "sites.toml"
    db = tmp_path / DB_NAME
    cfg_path.write_text(
        f'[[site]]\nname = "{SITE}"\nhost = "192.0.2.10"\n'
        f'iana_tz = "Europe/Bucharest"\ndb_path = "{db}"\n',
        encoding="utf-8",
    )
    conn = agent_db.connect(db)
    try:
        agent_store.store_events(conn, list(records))
    finally:
        conn.close()
    return cfg_path, db


def _push(db: Path, event_ids: list[int], *, kind: str = "sent") -> Path:
    """Record these ids as pushed in the ledger that sits beside the store."""
    ledger_path = db.parent / agent_cli.PUSH_LEDGER_FILE_NAME
    agent_cli.PushLedger(ledger_path).append(event_ids, endpoint=TARGET, kind=kind)
    return ledger_path


def _rows_by_serial(db: Path) -> dict[int, tuple[int, str]]:
    """serial_no -> (event id, fingerprint_hash) straight from the store."""
    conn = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
    conn.row_factory = sqlite3.Row
    try:
        return {
            int(row["serial_no"]): (int(row["id"]), str(row["fingerprint_hash"]))
            for row in conn.execute("SELECT id, serial_no, fingerprint_hash FROM events")
        }
    finally:
        conn.close()


def _report_text(cfg_path: Path, **kwargs: Any) -> tuple[int, str, str]:
    """Call the export function into a buffer. Returns (count, stdout_text, stderr_text)."""
    out = io.StringIO()
    count, message = export_cli.export_non_punch_fingerprints(
        config_path=cfg_path, dest_stream=out, is_tty=False, **kwargs
    )
    return count, out.getvalue(), message


def _combined(result: Any) -> str:
    return result.output + (getattr(result, "stderr", "") or "")


# --- 1. what the report lists ----------------------------------------------------------------


def test_report_lists_only_pushed_non_punch_fingerprints(tmp_path: Path) -> None:
    """The card's four-event case, verbatim.

    Ledger names the denial and the granted punch; the info event and the unknown code were
    never pushed. So exactly one fingerprint may appear: the denial's.
    """
    cfg_path, db = _seed(tmp_path)
    rows = _rows_by_serial(db)
    _push(db, [rows[100][0], rows[101][0]])

    count, text, message = _report_text(cfg_path)

    assert count == 1
    assert message == ""
    body = [line for line in text.splitlines() if line.strip()]
    assert body == ["fingerprint", rows[101][1]]
    for serial in (100, 102, 103):
        assert rows[serial][1] not in text, f"event {serial} must not be in the report"


def test_report_excludes_an_unpushed_non_punch_even_when_it_is_denied(tmp_path: Path) -> None:
    """The ledger, not the verdict, is what limits the report.

    Same store as above with ONLY the granted punch in the ledger: the denial is a
    non-punch, but BC has never seen it, so the repair must not claim it did.
    """
    cfg_path, db = _seed(tmp_path)
    rows = _rows_by_serial(db)
    _push(db, [rows[100][0]])

    count, text, _ = _report_text(cfg_path)

    assert count == 0
    assert text == "fingerprint\n"
    assert rows[101][1] not in text


def test_a_gone_dead_letter_counts_as_pushed(tmp_path: Path) -> None:
    """`gone` is evidence the event left the building, exactly as `sent` is (GC-P16a's rule).

    The owner discarded a dead letter, so BC will never receive it — but the operator still
    needs to know the store holds a non-punch the poller is done with. `sent_event_ids`
    already treats the two alike; this pins that the report inherits that and does not
    re-derive the ledger's meaning.
    """
    cfg_path, db = _seed(tmp_path)
    rows = _rows_by_serial(db)
    _push(db, [rows[101][0]], kind="gone")

    count, text, _ = _report_text(cfg_path)

    assert count == 1
    assert rows[101][1] in text


def test_a_torn_ledger_line_is_skipped_not_fatal(tmp_path: Path) -> None:
    """A torn last line (a poller killed mid-append) costs one id, not the whole report."""
    cfg_path, db = _seed(tmp_path)
    rows = _rows_by_serial(db)
    ledger = _push(db, [rows[101][0]])
    ledger.write_text(ledger.read_text(encoding="utf-8") + '{"e": 9, "t": "broken\n', "utf-8")

    count, text, _ = _report_text(cfg_path)

    assert count == 1
    assert rows[101][1] in text


def test_report_matches_the_granted_punch_rule(tmp_path: Path) -> None:
    """`verify_mode` decides, and it decides the classifier's way (strip + lowercase).

    A granted major-5 row whose verify mode is a non-auth mode is a door-state record, not a
    punch, so it belongs in the report. The same row with a real mode — padded and
    mixed-case, as a device sends it — is a punch and does not.
    """
    invalid = _record(serial_no=200, local_time="2026-11-04T13:00:00+02:00", verify_mode="invalid")
    real = _record(
        serial_no=201, local_time="2026-11-04T13:01:00+02:00", verify_mode="  CardOrFaceOrFp "
    )
    cfg_path, db = _seed(tmp_path, (invalid, real))
    rows = _rows_by_serial(db)
    _push(db, [rows[200][0], rows[201][0]])

    count, text, _ = _report_text(cfg_path)

    assert count == 1
    assert rows[200][1] in text
    assert rows[201][1] not in text


def test_an_unattributed_granted_event_is_a_non_punch(tmp_path: Path) -> None:
    """No employee_no means no timesheet line, however the device voted (GC-P01's arm).

    Both rows arrive as SQL NULL: `EventRecord` normalises an empty `employee_no` to None, so
    the `<> ''` arm of the predicate is not reachable from this path (the empty-string case is
    pinned separately, by a row written straight into the store).
    """
    anonymous = _record(serial_no=210, local_time="2026-11-04T14:00:00+02:00", employee_no=None)
    blank = _record(serial_no=211, local_time="2026-11-04T14:01:00+02:00", employee_no="")
    cfg_path, db = _seed(tmp_path, (anonymous, blank))
    rows = _rows_by_serial(db)
    _push(db, [rows[210][0], rows[211][0]])

    count, text, _ = _report_text(cfg_path)

    assert count == 2
    assert rows[210][1] in text and rows[211][1] in text


def test_a_granted_row_carrying_unknown_code_is_a_non_punch(tmp_path: Path) -> None:
    """The `unknown_code = 0` arm bites on its own.

    The classifier can never produce `granted` + `unknown_code` (GC-P01's note: the granted
    minors ARE the curated table), so no `store_events` fixture reaches this shape — which is
    exactly why the arm needs a row written by hand. If the arm is dropped, this row starts
    disappearing from the report.
    """
    cfg_path, db = _seed(tmp_path, ())
    conn = agent_db.connect(db)
    conn.execute(
        "INSERT INTO events (jsonl, revision, stored_at, updated_at, key_algorithm,"
        " idempotency_hash, idempotency_json, fingerprint_hash, fingerprint_json,"
        " site, device_serial, serial_no, raw, major, minor, outcome, unknown_code,"
        " employee_no, verify_mode) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        (
            "{}",
            1,
            "2026-11-04T10:00:00+00:00",
            "2026-11-04T10:00:00+00:00",
            "sha256",
            "h220",
            "{}",
            "fp-unknown-code-220",
            "{}",
            SITE,
            "DEMO-DEV-01",
            220,
            "{}",
            5,
            75,
            "granted",
            1,
            SECRET_EMPLOYEE,
            "cardOrFaceOrFp",
        ),
    )
    conn.commit()
    pushed_id = int(conn.execute("SELECT id FROM events WHERE serial_no = 220").fetchone()["id"])
    conn.close()
    _push(db, [pushed_id])

    count, text, _ = _report_text(cfg_path)

    assert count == 1
    assert "fp-unknown-code-220" in text


def test_a_row_with_a_null_verdict_column_is_still_a_non_punch(tmp_path: Path) -> None:
    """The COALESCE arm, pinned. A punch that cannot be PROVEN is not a punch.

    `major` arrives NULL here. With the card's literal `NOT (major = 5 AND ...)`, that
    comparison is UNKNOWN, `NOT UNKNOWN` is UNKNOWN, and the row silently vanishes from the
    only report whose job is to name everything BC was handed — a miss nobody sees. NULL means
    the verdict is not there, so the row is not a granted punch and belongs on the list.
    """
    cfg_path, db = _seed(tmp_path, ())
    conn = agent_db.connect(db)
    conn.execute(
        "INSERT INTO events (jsonl, revision, stored_at, updated_at, key_algorithm,"
        " idempotency_hash, idempotency_json, fingerprint_hash, fingerprint_json,"
        " site, device_serial, serial_no, raw, major, minor, outcome, unknown_code,"
        " employee_no, verify_mode) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        (
            "{}",
            1,
            "2026-11-04T10:00:00+00:00",
            "2026-11-04T10:00:00+00:00",
            "sha256",
            "h230",
            "{}",
            "fp-null-major-230",
            "{}",
            SITE,
            "DEMO-DEV-01",
            230,
            "{}",
            None,  # <- no verdict at all: not provably a punch
            75,
            "granted",
            0,
            SECRET_EMPLOYEE,
            "cardOrFaceOrFp",
        ),
    )
    conn.commit()
    pushed_id = int(conn.execute("SELECT id FROM events WHERE serial_no = 230").fetchone()["id"])
    conn.close()
    _push(db, [pushed_id])

    count, text, _ = _report_text(cfg_path)

    assert count == 1
    assert "fp-null-major-230" in text


def test_a_row_whose_employee_no_is_an_empty_string_is_a_non_punch(tmp_path: Path) -> None:
    """The `employee_no <> ''` arm, pinned with the only row that can reach it.

    `EventRecord` normalises an empty `employee_no` to NULL at construction (measured: an
    `EventRecord(employee_no="")` stores SQL NULL), so the ingest can never put `''` in the
    column and no `store_events` fixture can produce it. The arm therefore guards the store
    against a row that arrived some other way — a hand-mended row, a restored bundle. Written
    by hand for the same reason, and it is the case that catches dropping the arm.
    """
    cfg_path, db = _seed(tmp_path, ())
    conn = agent_db.connect(db)
    conn.execute(
        "INSERT INTO events (jsonl, revision, stored_at, updated_at, key_algorithm,"
        " idempotency_hash, idempotency_json, fingerprint_hash, fingerprint_json,"
        " site, device_serial, serial_no, raw, major, minor, outcome, unknown_code,"
        " employee_no, verify_mode) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        (
            "{}",
            1,
            "2026-11-04T10:00:00+00:00",
            "2026-11-04T10:00:00+00:00",
            "sha256",
            "h240",
            "{}",
            "fp-empty-employee-240",
            "{}",
            SITE,
            "DEMO-DEV-01",
            240,
            "{}",
            5,
            75,
            "granted",
            0,
            "",  # the value the model refuses to store, hence written here
            "cardOrFaceOrFp",
        ),
    )
    conn.commit()
    stored = conn.execute("SELECT employee_no, typeof(employee_no) AS t FROM events").fetchone()
    assert (stored["employee_no"], stored["t"]) == ("", "text"), (
        "the fixture must really hold an empty string, or this test guards nothing"
    )
    pushed_id = int(conn.execute("SELECT id FROM events WHERE serial_no = 240").fetchone()["id"])
    conn.close()
    _push(db, [pushed_id])

    count, text, _ = _report_text(cfg_path)

    assert count == 1
    assert "fp-empty-employee-240" in text


def test_report_is_the_complement_of_the_queue_rule(tmp_path: Path) -> None:
    """The drift guard: the report and `queue_new_events` must disagree on every row.

    Both read the same columns and both claim to implement one rule — GC-P01's punch
    candidate, negated here. Two copies of a rule drift, so this pins them BEHAVIOURALLY:
    over one store with every event pushed, the report's fingerprints are exactly the
    fingerprints of the events the queue refused to queue. Move either predicate and this
    fails; the card's five tests cannot see that.
    """
    cfg_path, db = _seed(tmp_path)
    conn = agent_db.connect(db)
    try:
        queued_ids = {
            int(row["event_id"]) for row in conn.execute("SELECT event_id FROM push_queue")
        }
        assert not queued_ids, "no pass has run, so nothing is queued yet"
        queue_new_events = agent_cli.queue_new_events(conn, endpoint=TARGET, now=T0)
        assert queue_new_events, "the fixture must contain at least one punch candidate"
        queued_ids = {
            int(row["event_id"]) for row in conn.execute("SELECT event_id FROM push_queue")
        }
    finally:
        conn.close()

    rows = _rows_by_serial(db)
    _push(db, [event_id for event_id, _fp in rows.values()])

    count, text, _ = _report_text(cfg_path)

    expected = {fp for event_id, fp in rows.values() if event_id not in queued_ids}
    listed = set(text.splitlines()[1:])
    assert count == len(expected) == len(listed)
    assert listed == expected
    # The fixture's one punch candidate is on the queue's side, never on the report's.
    assert rows[100][1] not in listed


# --- 2. what the report contains -------------------------------------------------------------


def test_report_has_one_column_and_no_pii(tmp_path: Path) -> None:
    """Header is exactly `fingerprint`, and none of the seeded identities appear anywhere."""
    cfg_path, db = _seed(tmp_path)
    rows = _rows_by_serial(db)
    _push(db, [rows[101][0], rows[102][0], rows[103][0]])

    count, text, _ = _report_text(cfg_path)

    parsed = list(csv.reader(io.StringIO(text)))
    assert parsed[0] == ["fingerprint"]
    assert len(parsed[0]) == 1
    assert [r[0] for r in parsed[1:]] == sorted([rows[101][1], rows[102][1], rows[103][1]])
    assert count == 3
    for secret in (SECRET_EMPLOYEE, SECRET_NAME, SECRET_CARD, "DEMO-DEV-01", "serialNo"):
        assert secret not in text, f"{secret!r} must never reach the report"


def test_jsonl_output_is_one_fingerprint_object_per_line(tmp_path: Path) -> None:
    """The machine form carries the same single field, and nothing else."""
    cfg_path, db = _seed(tmp_path)
    rows = _rows_by_serial(db)
    _push(db, [rows[101][0], rows[103][0]])

    count, text, _ = _report_text(cfg_path, fmt="jsonl")

    objects = [json.loads(line) for line in text.splitlines() if line.strip()]
    assert count == 2 == len(objects)
    assert {tuple(sorted(o)) for o in objects} == {("fingerprint",)}
    assert {o["fingerprint"] for o in objects} == {rows[101][1], rows[103][1]}
    for secret in (SECRET_EMPLOYEE, SECRET_NAME, SECRET_CARD):
        assert secret not in text


def test_fingerprints_are_distinct_and_verbatim(tmp_path: Path) -> None:
    """DISTINCT, and not hashed a second time — this value is BC's dedupe key.

    Two pushed NON-punch rows sharing one fingerprint (the guard's whole purpose: the same
    scan read twice, on two serialNos) must produce ONE line, and that line must be the stored
    `fingerprint_hash` byte-for-byte — BC joins on it.
    """
    first = _record(serial_no=300, local_time="2026-11-04T15:00:00+02:00", outcome=Outcome.DENIED)
    twin = _record(serial_no=301, local_time="2026-11-04T15:00:00+02:00", outcome=Outcome.DENIED)
    cfg_path, db = _seed(tmp_path, (first, twin))
    conn = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
    conn.row_factory = sqlite3.Row
    try:
        stored = [
            str(row["fingerprint_hash"])
            for row in conn.execute("SELECT fingerprint_hash FROM events ORDER BY serial_no")
        ]
        ids = [int(row["id"]) for row in conn.execute("SELECT id FROM events ORDER BY serial_no")]
    finally:
        conn.close()
    assert stored[0] == stored[1], "the fixture needs two events sharing one fingerprint"
    _push(db, ids)

    count, text, _ = _report_text(cfg_path)

    assert count == 1
    assert text == f"fingerprint\n{stored[0]}\n"


# --- 3. read-only ----------------------------------------------------------------------------


def test_report_reads_the_store_without_writing(tmp_path: Path) -> None:
    """Byte-identical store after the report: mtime, size and checksum all unmoved.

    The store is the operator's only local record of the scans (R1: BC is the store; this is
    a repair input, not a second record), so the report must not be able to touch it — not a
    row, and not even a WAL checkpoint that rewrites the file.
    """
    cfg_path, db = _seed(tmp_path)
    rows = _rows_by_serial(db)
    _push(db, [rows[101][0]])
    ledger = db.parent / agent_cli.PUSH_LEDGER_FILE_NAME
    before = (db.stat().st_mtime_ns, db.stat().st_size, hashlib.sha256(db.read_bytes()).hexdigest())
    ledger_before = (ledger.stat().st_size, ledger.read_bytes())

    result = runner.invoke(
        app,
        ["export", "non-punches", "--config", str(cfg_path), "--output", str(tmp_path / "r.csv")],
    )

    assert result.exit_code == 0, _combined(result)
    after = (db.stat().st_mtime_ns, db.stat().st_size, hashlib.sha256(db.read_bytes()).hexdigest())
    assert after == before, "the store file must be byte-identical after the report"
    assert (ledger.stat().st_size, ledger.read_bytes()) == ledger_before
    assert (tmp_path / "r.csv").read_text(encoding="utf-8") == f"fingerprint\n{rows[101][1]}\n"


def test_the_store_connection_refuses_a_write(tmp_path: Path) -> None:
    """The read-only guarantee is a guard, not an intent.

    The connection the report uses answers a write with an error. `PRAGMA query_only` is the
    mechanism — a URI `mode=ro` would fail on a WAL store whose `-shm` is missing, which is
    the ordinary state of a live site, so the guard is what holds here. Temp tables still
    work: they live in the temp database, which is exactly how the ledger ids get in without
    the store file being touched.
    """
    _cfg_path, db = _seed(tmp_path)
    conn = export_cli._open_read_only_store(db)
    try:
        with pytest.raises(sqlite3.OperationalError):
            conn.execute("UPDATE events SET name = 'x'")
        with pytest.raises(sqlite3.OperationalError):
            conn.execute("DELETE FROM events WHERE id = 1")
        conn.execute("CREATE TEMP TABLE probe (event_id INTEGER PRIMARY KEY)")
        conn.execute("INSERT INTO temp.probe VALUES (7)")
        assert conn.execute("SELECT event_id FROM temp.probe").fetchone()[0] == 7
    finally:
        conn.close()


# --- 4. the ledger is the only evidence of "pushed" ------------------------------------------


def test_report_is_empty_when_the_ledger_is_missing(tmp_path: Path) -> None:
    """No ledger: nothing is KNOWN to be pushed, so the report is empty — and still exit 0."""
    cfg_path, db = _seed(tmp_path)
    assert not (db.parent / agent_cli.PUSH_LEDGER_FILE_NAME).exists()

    count, text, message = _report_text(cfg_path)

    assert count == 0
    assert message == (
        f"no {agent_cli.PUSH_LEDGER_FILE_NAME} at {db.parent}; nothing is known to be pushed"
    )
    assert text == ""

    result = runner.invoke(app, ["export", "non-punches", "--config", str(cfg_path)])
    assert result.exit_code == 0, _combined(result)
    assert "nothing is known to be pushed" in _combined(result)


def test_an_empty_ledger_is_not_a_crash(tmp_path: Path) -> None:
    """A ledger file with no lines is the same answer as no file: zero, not an error."""
    cfg_path, db = _seed(tmp_path)
    (db.parent / agent_cli.PUSH_LEDGER_FILE_NAME).write_text("", encoding="utf-8")

    count, text, message = _report_text(cfg_path)

    assert count == 0
    assert text == "fingerprint\n"
    assert message == ""


def test_a_ledger_naming_only_missing_events_reports_nothing(tmp_path: Path) -> None:
    """Ids the store no longer has (GC-P16a pruned them) must not raise or invent a row."""
    cfg_path, db = _seed(tmp_path)
    _push(db, [4001, 4002])

    count, text, _ = _report_text(cfg_path)

    assert count == 0
    assert text == "fingerprint\n"


# --- 5. the CLI surface ----------------------------------------------------------------------


def test_cli_writes_the_file_and_reports_the_count_on_stderr(tmp_path: Path) -> None:
    """`--output` writes the file and says so on stderr; stdout stays clean for a pipe."""
    cfg_path, db = _seed(tmp_path)
    rows = _rows_by_serial(db)
    _push(db, [rows[101][0]])
    out_file = tmp_path / "out" / "non-punches.csv"

    result = runner.invoke(
        app, ["export", "non-punches", "--config", str(cfg_path), "--output", str(out_file)]
    )

    assert result.exit_code == 0, _combined(result)
    assert out_file.read_text(encoding="utf-8") == f"fingerprint\n{rows[101][1]}\n"
    assert "1 fingerprint" in _combined(result)


def test_cli_prints_to_a_pipe_without_an_output_file(tmp_path: Path) -> None:
    """Unlike `export scans`, an unsuppressed stdout is enough: the report has no PII."""
    cfg_path, db = _seed(tmp_path)
    rows = _rows_by_serial(db)
    _push(db, [rows[101][0]])

    result = runner.invoke(app, ["export", "non-punches", "--config", str(cfg_path)])

    assert result.exit_code == 0, _combined(result)
    assert result.stdout == f"fingerprint\n{rows[101][1]}\n"


def test_cli_refuses_an_interactive_tty_without_output(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Same TTY rule as the other exports: no silent file, and no terminal dump either."""
    cfg_path, db = _seed(tmp_path)
    rows = _rows_by_serial(db)
    _push(db, [rows[101][0]])
    monkeypatch.setattr(export_cli, "_stdout_is_tty", lambda: True)

    refused = runner.invoke(app, ["export", "non-punches", "--config", str(cfg_path)])

    assert refused.exit_code == CONFIG_ERROR_EXIT
    assert "TTY" in _combined(refused)
    assert list(tmp_path.glob("*.csv")) == []

    ok = runner.invoke(
        app,
        ["export", "non-punches", "--config", str(cfg_path), "--output", str(tmp_path / "x.csv")],
    )
    assert ok.exit_code == 0, _combined(ok)
    assert (tmp_path / "x.csv").read_text(encoding="utf-8") == f"fingerprint\n{rows[101][1]}\n"


def test_a_missing_store_is_a_config_error_not_a_traceback(tmp_path: Path) -> None:
    """`resolve_scan_store_path`'s refusal reaches the operator as exit 2."""
    cfg_path = tmp_path / "sites.toml"
    cfg_path.write_text(
        f'[[site]]\nname = "{SITE}"\nhost = "192.0.2.10"\n'
        f'iana_tz = "Europe/Bucharest"\ndb_path = "{tmp_path / "absent.sqlite3"}"\n',
        encoding="utf-8",
    )

    result = runner.invoke(app, ["export", "non-punches", "--config", str(cfg_path)])

    assert result.exit_code == CONFIG_ERROR_EXIT
    assert "not found" in _combined(result)


def test_an_unknown_format_is_refused(tmp_path: Path) -> None:
    """`--format` is the same closed list as the other exports."""
    cfg_path, db = _seed(tmp_path)
    _push(db, [1])

    with pytest.raises(ConfigError):
        _report_text(cfg_path, fmt="xlsx")


# --- 6. the ledger id set is unbounded; the insert is not ------------------------------------


class _ExecutemanyHitsTheLimit(sqlite3.Connection):
    """A connection whose `executemany` behaves like a build with a tiny parameter limit."""

    def executemany(self, sql, seq):  # type: ignore[override]
        raise sqlite3.OperationalError("too many parameters")


def _read_only_conn(
    tmp_path: Path, name: str, factory: type[sqlite3.Connection]
) -> sqlite3.Connection:
    """A store connection built the way `_open_read_only_store` builds its own.

    The fallback must be proven on a READ-ONLY connection, not on a plain one: the report's
    whole design (temp tables allowed, store writes refused) is a property of that open mode,
    and a transaction that writes only TEMP tables is legal there only because SQLite says so.
    """
    db = tmp_path / name
    seed = sqlite3.connect(str(db))
    seed.execute("CREATE TABLE events (id INTEGER PRIMARY KEY, fingerprint_hash TEXT)")
    seed.execute("INSERT INTO events (fingerprint_hash) VALUES ('fp')")
    seed.commit()
    seed.close()
    uri = f"{db.resolve().as_uri()}?mode=ro"
    conn = sqlite3.connect(uri, uri=True, factory=factory, isolation_level=None)
    conn.execute("CREATE TABLE temp.pushed_events (event_id INTEGER NOT NULL PRIMARY KEY)")
    return conn


def test_pushed_id_insert_falls_back_to_one_row_at_a_time(tmp_path: Path) -> None:
    """The card's bound: a ledger larger than SQLite's parameter limit still gets in.

    Exercised by making `executemany` fail rather than by writing 100k ledger lines: the
    fallback is the behaviour under test, and it must not swallow the error — it must do the
    same inserts one at a time.
    """
    conn = _read_only_conn(tmp_path, "ids.sqlite3", _ExecutemanyHitsTheLimit)
    ids = list(range(1, 2501))

    export_cli._insert_pushed_event_ids(conn, ids)

    got = [int(row[0]) for row in conn.execute("SELECT event_id FROM temp.pushed_events")]
    assert got == ids
    # Still the same read-only connection the fallback ran on: the store stays unwritable.
    with pytest.raises(sqlite3.OperationalError):
        conn.execute("DELETE FROM events")
    conn.close()


def test_a_write_lock_error_is_not_misread_as_the_parameter_limit(tmp_path: Path) -> None:
    """The fallback triggers on the parameter limit and nothing else.

    A locked db must still raise: silently switching to single-row inserts would turn a
    transient lock into a slow hang and hide the real reason from the operator.
    """

    class _Locked(sqlite3.Connection):
        def executemany(self, sql, seq):  # type: ignore[override]
            raise sqlite3.OperationalError("database is locked")

    conn = _read_only_conn(tmp_path, "locked.sqlite3", _Locked)

    with pytest.raises(sqlite3.OperationalError, match="locked"):
        export_cli._insert_pushed_event_ids(conn, [1, 2, 3])
    conn.close()


def test_the_report_streams_and_never_materializes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """`fetchall` is off limits: a year-old store must not become a year-long list in RAM.

    The cursor handed to the writer refuses `fetchall` outright, so the loop passes only if it
    reads with `fetchmany` — the same bound `export scans` pins for itself.
    """

    class _NoFetchallCursor:
        def __init__(self, inner: sqlite3.Cursor) -> None:
            self._inner = inner

        def fetchmany(self, size: int) -> list[sqlite3.Row]:
            return self._inner.fetchmany(size)

        def fetchall(self) -> list[sqlite3.Row]:
            raise AssertionError("the report must stream with fetchmany, never fetchall")

    cfg_path, db = _seed(tmp_path)
    rows = _rows_by_serial(db)
    _push(db, [rows[101][0]])
    real_cursor = export_cli._open_non_punch_cursor

    monkeypatch.setattr(
        export_cli,
        "_open_non_punch_cursor",
        lambda conn, event_ids: _NoFetchallCursor(real_cursor(conn, event_ids)),
    )

    count, text, _ = _report_text(cfg_path)

    assert count == 1
    assert rows[101][1] in text
