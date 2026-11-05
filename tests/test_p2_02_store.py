"""Card P2-02: the sqlite store — (device_serial, serial_no) UPSERT + completed-only checkpoint.

BINDING SPEC: docs/P2-SITE-AGENT.md §1 seams 1-3 + §2b (SIGNED OFF 2026-10-19).
Device truth: docs/OBSERVED.md ("Event log census": serialNo is device-wide monotonic,
the major=3 noise interleaves with punches — serials 5742..5753 — which is what makes a
device-wide serial checkpoint sound; paging.py:612-615 hands ChunkResult.max_serial_no
ONLY for completed chunks).

The five DoD cases the card dictates, 1:1 to test names below:

(1) UPSERT idempotence — the same JSONL line twice = 1 row and the second write is
    FREE: not merely "the row looks the same afterwards" but zero statement cost
    (total_changes delta 0), rowid identity, and no revision/updated_at churn. That is
    the "re-poll of the overlap window must be free" clause, and the pin that catches
    a UPSERT written without the `WHERE ... IS NOT excluded...` guard (which would
    rewrite the row — same bytes, real write, churned updated_at — every poll).
(2) overlap re-poll heals — drop a row (mid-page crash shape), re-store the same
    batch, the row is back with its identity rebuilt and the count is right.
(3) checkpoint — REFUSES an uncompleted chunk (`completed=False` raises, nothing
    written), advances over completed chunks, and a lower value never regresses: the
    refusal is pinned (typed error + row unmoved + zero statement cost), an equal
    value is a no-op (a 5-min poll with no new events re-reports the same serial every
    tick and must not churn), and the advance is ONE UPSERT (one statement —
    SIGTERM between two statements could halve the checkpoint).
(4) 27-key JSONL round-trip — the line the store keeps is `to_jsonl()` verbatim and
    parses back through `model.EventRecord.from_jsonl` to an equal record, and the
    key columns carry `model.RECORD_JSON_KEYS` in declaration order plus both digests.
(5) watermark helper boundary — `db_size_bytes`, and warn strictly ABOVE the
    threshold: exactly-at is not over.

Plus the card's own extras: pragmas (WAL + synchronous=NORMAL, crash-safe under a
systemd kill), the migration list extensible + forward-only (P2-04 appends its
queue/dead-letter entries — pinned by actually appending a fake v3 and reopening), and
the NULL-serial refusal this card's design note records.

Offline by construction: tmp sqlite files only (conftest.netoff would still kill a
socket; nothing here opens one). Fixtures carry masked names only (`User E<n>` —
tests/fixtures/README convention); no real host or serial appears here.
"""

from __future__ import annotations

import json
import re
import sqlite3
from datetime import UTC, datetime
from typing import Any

import pytest

import gateclerk.agent_db as agent_db
import gateclerk.agent_store as agent_store
from gateclerk.model import RECORD_JSON_KEYS, EventRecord, event_keys, from_jsonl, to_jsonl

SITE = "site-a"
SERIAL = "MASKED-SER-1"

#: A fixed clock: every timestamp assertion in this file is byte-pinned, never "now-ish".
T0 = datetime(2026, 10, 19, 10, 0, 0, tzinfo=UTC)
T1 = datetime(2026, 10, 19, 10, 5, 0, tzinfo=UTC)
T0_ISO = T0.isoformat()
T1_ISO = T1.isoformat()


def make_record(**over: Any) -> EventRecord:
    """One site-a-shaped record (masked: name is `User E<n>`, serial as OBSERVED.md)."""
    payload: dict[str, Any] = {
        "site": SITE,
        "device_serial": SERIAL,
        "serial_no": 5742,
        "employee_no": "1",
        "name": "User E1",
        "event_time_utc": "2026-10-12T12:11:16+00:00",
        "event_time_local": "2026-10-12T14:11:16+02:00",
        "tz_offset_min": 180,
        "tz_offset_min_device": 120,
        "tz_source": "site-tz",
        "iana_tz": "Europe/Bucharest",
        "tz_offset_mismatch": True,
        "direction": "in",
        "attendance_status": "checkIn",
        "direction_source": "device",
        "verify_mode": "cardOrFaceOrFp",
        "major": 5,
        "minor": 75,
        "outcome": "granted",
        "raw": {"major": 5, "minor": 75, "serialNo": 5742},
        "captured_at": "2026-10-19T10:00:00+00:00",
    }
    payload.update(over)
    return EventRecord.from_dict(payload)


def one_line(record: EventRecord) -> str:
    """`to_jsonl()` for one record minus its trailing newline — the stored line."""
    return to_jsonl([record])[:-1]


@pytest.fixture
def db(tmp_path):
    """A fresh agent db (connect = pragmas + migrations), closed after the test."""
    conn = agent_db.connect(tmp_path / "agent.sqlite3")
    yield conn
    conn.close()


def event_count(conn: sqlite3.Connection) -> int:
    return conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]


def row_state(conn: sqlite3.Connection, serial_no: int) -> tuple[Any, ...]:
    """The full identity tuple of one event row: rowid, bytes, bookkeeping columns."""
    row = conn.execute(
        "SELECT rowid, jsonl, revision, stored_at, updated_at FROM events"
        " WHERE device_serial = ? AND serial_no = ?",
        (SERIAL, serial_no),
    ).fetchone()
    assert row is not None, f"event serial_no={serial_no} is gone"
    return tuple(row)


def checkpoint_row(conn: sqlite3.Connection) -> tuple[Any, ...] | None:
    row = conn.execute(
        "SELECT checkpoint_serial, checkpoint_time, updated_at FROM checkpoint"
        " WHERE device_serial = ?",
        (SERIAL,),
    ).fetchone()
    return tuple(row) if row else None


# -----------------------------------------------------------------------------------------
# (0) the connection seam: pragmas + migration bookkeeping
# -----------------------------------------------------------------------------------------


def test_connect_applies_the_crash_safety_pragmas(tmp_path) -> None:
    """journal_mode=WAL + synchronous=NORMAL (card: crash-safe on a systemd kill)."""
    conn = agent_db.connect(tmp_path / "agent.sqlite3")
    try:
        assert conn.execute("PRAGMA journal_mode").fetchone()[0] == "wal"
        # NORMAL reports as 1; FULL is 2 — pin the number, not the name.
        assert conn.execute("PRAGMA synchronous").fetchone()[0] == 1
    finally:
        conn.close()


def test_connect_is_idempotent_and_keeps_the_rows(tmp_path) -> None:
    """Reopening (the restart-resumes-from-checkpoint shape) neither wipes nor re-migrates."""
    path = tmp_path / "agent.sqlite3"
    conn = agent_db.connect(path)
    agent_store.store_events(conn, [make_record()], now=T0)
    applied_first = conn.execute(
        "SELECT version FROM schema_migrations ORDER BY version"
    ).fetchall()
    conn.close()

    conn2 = agent_db.connect(path)
    try:
        assert event_count(conn2) == 1, "reopen must not lose the stored event"
        applied_second = conn2.execute(
            "SELECT version FROM schema_migrations ORDER BY version"
        ).fetchall()
        assert applied_second == applied_first, "reopen must not re-apply migrations"
    finally:
        conn2.close()


# -----------------------------------------------------------------------------------------
# (1) UPSERT idempotence — same line twice = 1 row, second write is FREE
# -----------------------------------------------------------------------------------------


def test_storing_the_same_line_twice_is_one_row_and_costs_zero_statements(db) -> None:
    """The card's core clause: re-poll is a no-op that refreshes nothing AND is FREE.

    Three independent pins, all on the second store:
      * one row, same rowid (identity — no delete/reinsert);
      * `revision` and `updated_at` unmoved (no churn of ANY kind);
      * `conn.total_changes` delta 0 (a UPSERT without the `IS NOT excluded` guard
        rewrites identical bytes: the row would look right but pay a write every poll
        and churn the audit columns — exactly the mutant this pin kills).
    """
    record = make_record()
    first = agent_store.store_events(db, [record], now=T0)
    assert first.inserted == 1 and first.refreshed == 0 and first.unchanged == 0

    before = db.total_changes
    pinned = row_state(db, 5742)
    second = agent_store.store_events(db, [record], now=T1)
    after = db.total_changes

    assert second.inserted == 0 and second.refreshed == 0 and second.unchanged == 1
    assert after - before == 0, (
        "the re-store cost a statement — the overlap re-poll must be FREE, not merely"
        " invisible (pin: ON CONFLICT DO UPDATE ... WHERE jsonl IS NOT excluded.jsonl)"
    )
    assert row_state(db, 5742) == pinned, "re-store churned row identity, revision or timestamps"
    assert event_count(db) == 1


def test_second_store_keeps_first_contact_timestamps(db) -> None:
    """stored_at is first-seen truth: an overlap re-store must not relabel it."""
    agent_store.store_events(db, [make_record()], now=T0)
    agent_store.store_events(db, [make_record()], now=T1)
    (_rowid, _jsonl, _rev, stored_at, updated_at) = row_state(db, 5742)
    assert stored_at == updated_at == T0_ISO, (
        "both stamps belong to the first store; the free no-op must not touch either"
    )


def test_changed_bytes_for_the_same_key_refresh_and_bump_revision(db) -> None:
    """The other side of the UPSERT: a genuine content change DOES land.

    The key stays the key, so a changed line must refresh the row, advance `revision`,
    move `updated_at`, and keep `stored_at` first-seen. (This is also the pin that the
    DO UPDATE branch exists at all — a bare INSERT..ON CONFLICT DO NOTHING would pass
    every idempotence test above and silently never heal a wrong row.)
    """
    agent_store.store_events(db, [make_record(name="User E1")], now=T0)
    before = db.total_changes
    result = agent_store.store_events(db, [make_record(name="User E2")], now=T1)
    assert result.refreshed == 1 and result.inserted == 0 and result.unchanged == 0
    assert db.total_changes - before == 1

    (_rowid, jsonl, revision, stored_at, updated_at) = row_state(db, 5742)
    assert revision == 2 and updated_at == T1_ISO and stored_at == T0_ISO
    assert json.loads(jsonl)["name"] == "User E2"


def test_batch_of_the_same_key_in_one_call_stays_one_row(db) -> None:
    """A batch may legitimately repeat a key (overlap page + new page); last bytes win."""
    agent_store.store_events(
        db,
        [make_record(name="User E1"), make_record(name="User E1"), make_record(name="User E3")],
        now=T0,
    )
    assert event_count(db) == 1
    assert json.loads(row_state(db, 5742)[1])["name"] == "User E3"


# -----------------------------------------------------------------------------------------
# (2) overlap re-poll heals
# -----------------------------------------------------------------------------------------


def test_dropped_row_is_healed_by_re_storing_the_same_batch(db) -> None:
    """Crash-mid-page shape: the row is gone, the overlap poll re-stores it exactly.

    Count right, content byte-identical (the line was stored verbatim, so healing
    cannot lose a field), and the healed row reads as a NEW row.
    """
    batch = [make_record(serial_no=5742), make_record(serial_no=5743, minor=21)]
    agent_store.store_events(db, batch, now=T0)
    assert event_count(db) == 2

    db.execute("DELETE FROM events WHERE serial_no = 5742")  # simulate the lost write
    assert event_count(db) == 1

    result = agent_store.store_events(db, batch, now=T1)
    assert result.inserted == 1 and result.unchanged == 1
    assert event_count(db) == 2

    (_rowid, jsonl, revision, stored_at, updated_at) = row_state(db, 5742)
    assert revision == 1, "a healed row is a NEW row (the old one died), not a bump"
    assert stored_at == updated_at == T1_ISO
    assert jsonl == one_line(make_record(serial_no=5742)), (
        "the healed line must be the model's to_jsonl bytes verbatim"
    )


def test_re_storing_a_batch_never_duplicates_any_key(db) -> None:
    """Whole-batch replay (the restart case): every key still exactly one row."""
    batch = [make_record(serial_no=s) for s in (5742, 5743, 5744)]
    agent_store.store_events(db, batch, now=T0)
    agent_store.store_events(db, batch, now=T1)
    agent_store.store_events(db, batch, now=T1)
    assert event_count(db) == 3


# -----------------------------------------------------------------------------------------
# (3) checkpoint — completed-only advance, monotonic guard, one UPSERT
# -----------------------------------------------------------------------------------------


def test_checkpoint_refuses_an_uncompleted_chunk(db) -> None:
    """completed=False must RAISE and write NOTHING.

    paging.py:612-615 only supplies ChunkResult.max_serial_no for COMPLETED chunks;
    accepting a half-failed walk's max would let the next poll skip the failed
    chunk's events — the exact bug seam 2 exists to close.
    """
    with pytest.raises(agent_store.CheckpointNotCompletedError):
        agent_store.advance_checkpoint(
            db, SERIAL, 5742, completed=False, checkpoint_time=T0_ISO, now=T0
        )
    assert checkpoint_row(db) is None, "a refused advance must leave no row at all"
    before = db.total_changes
    with pytest.raises(agent_store.CheckpointNotCompletedError):
        agent_store.advance_checkpoint(db, SERIAL, 9999, completed=False, now=T0)
    assert db.total_changes == before, "the refusal must not write anything either"


def test_checkpoint_advances_over_completed_chunks(db) -> None:
    result = agent_store.advance_checkpoint(
        db, SERIAL, 5742, completed=True, checkpoint_time=T0_ISO, now=T0
    )
    assert result.advanced is True
    assert checkpoint_row(db) == (5742, T0_ISO, T0_ISO)

    result = agent_store.advance_checkpoint(
        db, SERIAL, 5753, completed=True, checkpoint_time=T1_ISO, now=T1
    )
    assert result.advanced is True
    assert checkpoint_row(db) == (5753, T1_ISO, T1_ISO)
    assert agent_store.read_checkpoint(db, SERIAL).checkpoint_serial == 5753


def test_checkpoint_never_regresses_and_the_refusal_is_pinned(db) -> None:
    """A LOWER max must raise + leave the row byte-identical + cost zero statements.

    The card demands the refusal be pinned, not just the value: pin the exception
    type, the unmoved row, AND the zero statement cost (the guard lives in the UPSERT's
    WHERE, so a regression attempt is free — and would be silent if you only read the
    value back).
    """
    agent_store.advance_checkpoint(db, SERIAL, 5753, completed=True, checkpoint_time=T1_ISO, now=T1)
    pinned = checkpoint_row(db)
    before = db.total_changes

    with pytest.raises(agent_store.CheckpointRegressionError):
        agent_store.advance_checkpoint(
            db, SERIAL, 5742, completed=True, checkpoint_time=T0_ISO, now=T1
        )
    assert checkpoint_row(db) == pinned
    assert db.total_changes - before == 0, "the monotonic guard must cost nothing to enforce"


def test_checkpoint_equal_value_is_a_no_op_without_churn(db) -> None:
    """A 5-min tick with no new events re-reports the SAME serial: no write, no churn.

    (A guard written `>=` instead of `>` would rewrite the row every quiet tick — the
    checkpoint would look healthy while churning updated_at forever.)
    """
    agent_store.advance_checkpoint(db, SERIAL, 5753, completed=True, checkpoint_time=T1_ISO, now=T1)
    pinned = checkpoint_row(db)
    before = db.total_changes
    result = agent_store.advance_checkpoint(
        db, SERIAL, 5753, completed=True, checkpoint_time=T0_ISO, now=T1
    )
    assert result.advanced is False
    assert checkpoint_row(db) == pinned
    assert db.total_changes - before == 0


def test_checkpoint_advance_is_one_statement(db) -> None:
    """SIGTERM-safety (P2-03's rule): one successful advance = one statement of change."""
    before = db.total_changes
    agent_store.advance_checkpoint(db, SERIAL, 5753, completed=True, checkpoint_time=T1_ISO, now=T1)
    assert db.total_changes - before == 1, (
        "a multi-statement advance can be caught half-applied by a systemd kill"
    )


def test_checkpoint_time_survives_a_later_advance_without_one(db) -> None:
    """checkpoint_time is caller-supplied truth (the max-serial record's device-local
    time — DESIGN.md's (last_serial_no, last_event_time_local)); a later advance with
    None must never blank it: P2-03's window lower bound (checkpoint_time - overlap)
    reads it every tick."""
    agent_store.advance_checkpoint(db, SERIAL, 5742, completed=True, checkpoint_time=T0_ISO, now=T0)
    agent_store.advance_checkpoint(db, SERIAL, 5753, completed=True, checkpoint_time=None, now=T1)
    assert checkpoint_row(db) == (5753, T0_ISO, T1_ISO)


def test_completed_chunk_without_a_serial_advances_nothing(db) -> None:
    """An empty completed chunk has max_serial_no=None (paging): accept it as a no-op
    rather than storing a NULL checkpoint (a NULL would poison the next tick's window
    lower bound)."""
    before = db.total_changes
    result = agent_store.advance_checkpoint(db, SERIAL, None, completed=True, now=T0)
    assert result.advanced is False
    assert checkpoint_row(db) is None
    assert db.total_changes == before


def test_negative_checkpoint_serial_is_refused(db) -> None:
    """serialNo counts up from 0 (OBSERVED.md: earliest serial 27); a negative max
    means the caller mis-parsed a page — refuse rather than poison the row (and the
    CHECK constraint is the second wall under it)."""
    with pytest.raises(agent_store.CheckpointRegressionError):
        agent_store.advance_checkpoint(db, SERIAL, -1, completed=True, now=T0)
    assert checkpoint_row(db) is None


def test_checkpoint_failure_rolls_back_and_the_connection_survives(db) -> None:
    """A sqlite-level failure INSIDE the advance (an int64-overflowing serial — the
    CHECK/constraint wall, not the Python guard) must roll the transaction back and
    leave the connection usable for the next honest tick."""
    with pytest.raises(Exception):  # noqa: B017 — binding overflow, exact type is sqlite's
        agent_store.advance_checkpoint(db, SERIAL, 2**63, completed=True, now=T0)
    result = agent_store.advance_checkpoint(db, SERIAL, 5742, completed=True, now=T1)
    assert result.advanced is True
    assert checkpoint_row(db) == (5742, None, T1_ISO)


def test_naive_clock_is_refused_by_both_writers(db) -> None:
    """DTZ policy enforced AT the seam: a naive `now` would stamp payroll audit
    columns with an unknowable offset — refuse (P2-03 injects an aware clock)."""
    naive = datetime(2026, 10, 19, 10, 0, 0)  # noqa: DTZ001 — the point is that it IS naive
    with pytest.raises(ValueError, match="tz-aware"):
        agent_store.store_events(db, [make_record()], now=naive)
    with pytest.raises(ValueError, match="tz-aware"):
        agent_store.advance_checkpoint(db, SERIAL, 5742, completed=True, now=naive)
    assert event_count(db) == 0 and checkpoint_row(db) is None


def test_checkpoint_is_per_device_serial(db) -> None:
    """One db may carry several devices; the checkpoint rows must not cross."""
    agent_store.advance_checkpoint(db, "DEV-A", 100, completed=True, now=T0)
    agent_store.advance_checkpoint(db, "DEV-B", 200, completed=True, now=T0)
    assert agent_store.read_checkpoint(db, "DEV-A").checkpoint_serial == 100
    assert agent_store.read_checkpoint(db, "DEV-B").checkpoint_serial == 200
    with pytest.raises(agent_store.CheckpointRegressionError):
        agent_store.advance_checkpoint(db, "DEV-B", 50, completed=True, now=T1)
    assert agent_store.read_checkpoint(db, "DEV-A").checkpoint_serial == 100


def test_read_checkpoint_on_unknown_device_is_none(db) -> None:
    assert agent_store.read_checkpoint(db, "never-seen") is None


# -----------------------------------------------------------------------------------------
# (4) 27-key JSONL round-trip through the store
# -----------------------------------------------------------------------------------------


def test_stored_line_is_the_to_jsonl_bytes_verbatim_and_round_trips(db) -> None:
    """Store keeps `to_jsonl()`'s line untouched; from_jsonl rebuilds an EQUAL record.

    The frozen 27-key contract is BOTH the push payload and the store's content: if
    the store re-serialised (key order, separators, ensure_ascii), the round-trip
    alone would still pass — the byte-identity pin is what makes 'verbatim' mean
    something.
    """
    record = make_record()
    agent_store.store_events(db, [record], now=T0)
    stored = db.execute("SELECT jsonl FROM events").fetchone()[0]
    assert stored == one_line(record), "the stored line drifted from to_jsonl()"

    (rebuilt,) = from_jsonl(to_jsonl([record]))
    (restored,) = from_jsonl(stored + "\n")
    assert restored == rebuilt == record


def test_events_columns_are_the_frozen_contract_plus_both_digests(db) -> None:
    """The events table must carry every RECORD_JSON_KEYS column (P2-04's dead-letter
    and P2-07's queries read the same contract the push payload uses) plus both key
    digests (spec §2b: the payload line AND both digests are stored)."""
    names = [c[1] for c in db.execute("PRAGMA table_info(events)").fetchall()]
    for key in RECORD_JSON_KEYS:
        assert key in names, f"contract key {key!r} missing from the events columns"
    for digest_col in (
        "idempotency_hash",
        "idempotency_json",
        "fingerprint_hash",
        "fingerprint_json",
    ):
        assert digest_col in names

    record = make_record()
    agent_store.store_events(db, [record], now=T0)
    row = db.execute("SELECT * FROM events").fetchone()
    expected = record.to_dict()
    for key in RECORD_JSON_KEYS:
        if key == "raw":
            # The device dict has no sqlite scalar form: the column holds it as JSON
            # text (the round-trip of the WHOLE record goes through `jsonl` anyway).
            assert json.loads(row["raw"]) == expected["raw"], "raw column lost the device dict"
        else:
            assert row[key] == expected[key], f"column {key} drifted from to_dict()"


def test_insert_column_list_is_the_contract_tuple(db) -> None:
    """The static UPSERT's column list == head bookkeeping + RECORD_JSON_KEYS, in order.

    The UPSERT is static SQL (no interpolation, so nothing runtime can reshape it) —
    this pin is what stops that literal from drifting from the frozen contract:
    a key added to model.RECORD_JSON_KEYS without a column here would silently stop
    being stored in its queryable form (the jsonl line would still carry it, which is
    exactly how a drift stays invisible for a release).
    """
    head = agent_store._UPSERT.split("VALUES")[0]
    listed = head[head.index("(") + 1 : head.rindex(")")].replace("\n", " ")
    cols = [c.strip() for c in listed.split(",") if c.strip()]
    assert cols[:2] == ["id", "revision"], "id/revision are literals, not parameters"
    assert tuple(cols[2:]) == agent_store._UPSERT_COLUMNS
    assert tuple(cols[2 + len(agent_store._HEAD_COLUMNS) :]) == RECORD_JSON_KEYS, (
        "flattened columns ARE the contract tuple"
    )
    # Parameters: one '?' per non-literal column, and _row_values supplies exactly that.
    values = agent_store._UPSERT.split("VALUES")[1].split("ON CONFLICT")[0]
    assert values.count("?") == len(agent_store._UPSERT_COLUMNS)
    record = make_record()
    assert len(agent_store._row_values(record, one_line(record), T0_ISO)) == len(
        agent_store._UPSERT_COLUMNS
    )
    # And the row actually lands with every contract column populated as to_dict().
    agent_store.store_events(db, [record], now=T0)
    row = db.execute("SELECT * FROM events").fetchone()
    assert row["device_serial"] == SERIAL and row["serial_no"] == 5742


def test_column_pin_bites_a_renamed_contract_key() -> None:
    """Mutant catcher FOR the pin above (runs its real comparison against a mutated
    contract tuple): if the pin were written the lazy way — comparing the SQL against
    a hardcoded list — a renamed/added contract key would pass it. This derives both
    sides exactly as the pin does and asserts a drifted tuple makes them differ.

    (A tautology guard on purpose: the ONLY mutant it has to catch is a pin that
    stopped reading RECORD_JSON_KEYS, and that is what the equality below proves.)
    """
    head = agent_store._UPSERT.split("VALUES")[0]
    listed = head[head.index("(") + 1 : head.rindex(")")].replace("\n", " ")
    flat = tuple(c.strip() for c in listed.split(",") if c.strip())[
        2 + len(agent_store._HEAD_COLUMNS) :
    ]
    mutated = (*RECORD_JSON_KEYS[:-1], "renamed_key")
    assert flat == RECORD_JSON_KEYS, "precondition: the shipped pin passes"
    assert flat != mutated, (
        "the pin's comparison cannot distinguish a renamed contract key — it is not "
        "comparing the SQL against the live tuple"
    )
    dropped = RECORD_JSON_KEYS[:-1]
    assert flat != dropped, "the pin cannot catch a key removed from the contract either"


def test_digest_columns_match_model_event_keys(db) -> None:
    """The stored digests are model.event_keys()'s values — not a second implementation."""
    record = make_record()
    agent_store.store_events(db, [record], now=T0)
    row = db.execute("SELECT * FROM events").fetchone()
    want = event_keys(record)
    assert row["idempotency_hash"] == want["idempotency_hash"]
    assert row["idempotency_json"] == want["idempotency_json"]
    assert row["fingerprint_hash"] == want["fingerprint_hash"]
    assert row["fingerprint_json"] == want["fingerprint_json"]
    assert row["key_algorithm"] == want["algorithm"]


def test_unique_index_is_exactly_the_pinned_key(db) -> None:
    """UNIQUE(device_serial, serial_no) — pin the index, not just the behaviour: a
    UNIQUE on (site, serial_no) would collide two devices' rings silently."""
    ddl = [
        r[0]
        for r in db.execute("SELECT sql FROM sqlite_master WHERE type = 'index'").fetchall()
        if r[0]
    ]
    joined = " ".join(ddl)
    assert "device_serial" in joined and "serial_no" in joined, f"no UNIQUE over the key: {ddl}"


# -----------------------------------------------------------------------------------------
# (5) watermark helper boundary
# -----------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("size", "warn_bytes", "should_warn"),
    [
        (100, 100, False),  # exactly at the watermark is NOT over (spec: `>`)
        (101, 100, True),  # one byte over warns
        (99, 100, False),
        (100, 101, False),
        (1, 1, False),
        (0, 0, False),  # an empty db is not over zero
    ],
)
def test_watermark_is_strictly_above_the_threshold(tmp_path, size, warn_bytes, should_warn) -> None:
    """db_warn_bytes boundary: warn iff size > threshold (spec §2b; P2-05 alerts on it)."""
    path = tmp_path / "sized.sqlite3"
    path.write_bytes(b"\0" * size)
    assert agent_store.db_size_bytes(path) == size
    check = agent_store.check_db_watermark(path, warn_bytes)
    assert check.warn is should_warn
    assert check.size_bytes == size
    assert check.warn_bytes == warn_bytes
    assert check.over_by_bytes == (size - warn_bytes if should_warn else 0)


def test_watermark_on_a_missing_db_file_is_not_a_warning(tmp_path) -> None:
    """Before the first poll there is no file: that is 0 bytes, not an alarm."""
    check = agent_store.check_db_watermark(tmp_path / "absent.sqlite3", 10)
    assert check.warn is False and check.size_bytes == 0
    assert agent_store.db_size_bytes(tmp_path / "absent.sqlite3") == 0


# -----------------------------------------------------------------------------------------
# migration list: additive + forward-only + extensible (P2-04 appends here)
# -----------------------------------------------------------------------------------------


def test_migrations_are_a_list_of_ascending_versions() -> None:
    versions = [m.version for m in agent_db.MIGRATIONS]
    assert versions == sorted(versions) and len(set(versions)) == len(versions)
    assert versions and versions[0] == 1, "the migration list starts at 1 and counts up"
    for m in agent_db.MIGRATIONS:
        assert m.name and m.sql, "every migration names itself and its additive SQL"
        assert_additive(m)


def assert_additive(migration: agent_db.Migration) -> None:
    """The additive law: a migration may CREATE, and may REBUILD a table to change a
    constraint it cannot ALTER, but it may never destroy data.

    sqlite cannot change a `UNIQUE` constraint in place, so SINKS-CORE's v5/v6 (queue
    identity moving from `UNIQUE(event_id, endpoint)` to `UNIQUE(event_id, sink_name)`)
    use the documented rebuild shape: CREATE the replacement -> INSERT INTO it SELECT the
    rows -> DROP the old -> ALTER ... RENAME the replacement back. That honours the law in
    the only sense it means — every row survives — so it is allowed here, and the row-for-
    row claim is pinned behaviourally where it can actually be observed:
    tests/test_sinks_storage.py walks a real pre-upgrade backlog through each step. A drop
    with no copy-out, or a replacement that never takes the old name back, still fails.
    """
    for dropped in re.findall(r"DROP\s+TABLE\s+(?:IF\s+EXISTS\s+)?(\w+)", migration.sql, re.I):
        copied_out = re.search(
            rf"INSERT\s+INTO\s+\w+\s*\([^)]*\)\s*SELECT.*?\bFROM\s+{dropped}\b",
            migration.sql,
            re.DOTALL | re.IGNORECASE,
        )
        renamed_back = re.search(
            rf"ALTER\s+TABLE\s+\w+\s+RENAME\s+TO\s+{dropped}\b", migration.sql, re.IGNORECASE
        )
        assert copied_out and renamed_back, (
            f"migration {migration.version} destroys table {dropped} "
            "(no copy-out before the drop, or the name is never restored)"
        )


def test_a_new_migration_appends_and_applies_on_next_open(tmp_path, monkeypatch) -> None:
    """P2-04's contract: it appends queue/dead-letter entries to MIGRATIONS; the next
    connect applies ONLY the new one onto the existing schema. A frozen (or rebuilt)
    migration list would break P2-04 silently — this pins the seam by appending a fake
    v3 exactly the way P2-04 will."""
    path = tmp_path / "agent.sqlite3"
    conn = agent_db.connect(path)
    conn.execute(
        "INSERT INTO checkpoint (device_serial, checkpoint_serial, updated_at)"
        " VALUES ('KEEP-ME', 7, 'x')"
    )
    conn.close()

    fake_next = agent_db.Migration(
        version=len(agent_db.MIGRATIONS) + 1,  # 3 today: P2-04 appends exactly here
        name="fake_queue_for_test",
        sql="CREATE TABLE fake_queue (id INTEGER PRIMARY KEY, payload TEXT NOT NULL)",
    )
    monkeypatch.setattr(agent_db, "MIGRATIONS", (*agent_db.MIGRATIONS, fake_next))

    conn2 = agent_db.connect(path)
    try:
        applied = [
            r[0] for r in conn2.execute("SELECT version FROM schema_migrations ORDER BY version")
        ]
        assert applied[-1] == fake_next.version
        assert applied[:-1] == [m.version for m in agent_db.MIGRATIONS[:-1]]
        # additive: the old data survived the new migration
        assert (
            conn2.execute(
                "SELECT checkpoint_serial FROM checkpoint WHERE device_serial='KEEP-ME'"
            ).fetchone()[0]
            == 7
        )
        conn2.execute("INSERT INTO fake_queue (payload) VALUES ('line')")
    finally:
        conn2.close()


def test_reversed_migration_list_is_refused(tmp_path, monkeypatch) -> None:
    """Forward-only: a list that no longer ascends must RAISE, not apply out of order
    (an out-of-order apply would half-build a schema and look fine)."""
    monkeypatch.setattr(agent_db, "MIGRATIONS", tuple(reversed(agent_db.MIGRATIONS)))
    with pytest.raises(agent_db.MigrationOrderError):
        agent_db.connect(tmp_path / "agent.sqlite3")


def test_middle_swapped_migration_list_is_refused(tmp_path, monkeypatch) -> None:
    """The ASCENDING check specifically — not the start-at-1 guard by accident.

    A reversed list trips BOTH guards (its first version is not 1), so a mutation
    that removes only the ascending check still passes the reversed test (the
    start-at-1 guard fires) and the order check looks pinned when it is not. A swap
    that keeps version 1 first (1,3,2) trips ONLY the ascending check — with the
    check gone the loop would happily apply 3 before 2 and connect would succeed.
    """
    fake_v3 = agent_db.Migration(version=3, name="three", sql="SELECT 1")
    fake_v2 = agent_db.Migration(version=2, name="two", sql="SELECT 1")
    monkeypatch.setattr(agent_db, "MIGRATIONS", (agent_db.MIGRATIONS[0], fake_v3, fake_v2))
    with pytest.raises(agent_db.MigrationOrderError):
        agent_db.connect(tmp_path / "agent.sqlite3")


def test_duplicate_migration_version_is_refused(tmp_path, monkeypatch) -> None:
    dupe = agent_db.Migration(version=agent_db.MIGRATIONS[0].version, name="dupe", sql="SELECT 1")
    monkeypatch.setattr(agent_db, "MIGRATIONS", (*agent_db.MIGRATIONS, dupe))
    with pytest.raises(agent_db.MigrationOrderError):
        agent_db.connect(tmp_path / "agent.sqlite3")


def test_migration_list_not_starting_at_one_is_refused(tmp_path, monkeypatch) -> None:
    """The start-at-1 guard on its own (the reversed case trips the ascending check
    first, so this list — ascending but starting at 2 — isolates this branch)."""
    fake = agent_db.Migration(version=2, name="no_v1", sql="CREATE TABLE t (x)")
    monkeypatch.setattr(agent_db, "MIGRATIONS", (fake,))
    with pytest.raises(agent_db.MigrationOrderError, match="version 1"):
        agent_db.connect(tmp_path / "agent.sqlite3")


def test_a_store_from_the_future_is_refused(tmp_path) -> None:
    """Downgrade wall: a db already at a version this code does not ship must NOT be
    opened (an old binary writing a new schema is how P2-04's rows would meet P2-02's
    columns). Simulated the way an upgrade actually looks: a version ahead of the shipped
    list present, this binary behind it.

    The version is `len(MIGRATIONS) + 1`, not a literal 3: P2-04 has shipped v3 (queue) and
    v4 (dead-letter) for real, so a v3 row is now a schema this code knows and would not be
    refused. The wall is about the version the code does NOT have.
    """
    path = tmp_path / "agent.sqlite3"
    agent_db.connect(path).close()
    future = len(agent_db.MIGRATIONS) + 1
    conn = sqlite3.connect(path)
    conn.execute(
        "INSERT INTO schema_migrations (version, name, applied_at) VALUES (?, 'p2_next', 'x')",
        (future,),
    )
    conn.commit()
    conn.close()

    with pytest.raises(agent_db.MigrationTooNewError, match=f"version {future}"):
        agent_db.connect(path)
    # And the refusal left the future schema untouched (no half-repair attempted).
    conn = sqlite3.connect(path)
    at_future = conn.execute(
        "SELECT COUNT(*) FROM schema_migrations WHERE version = ?", (future,)
    ).fetchone()[0]
    assert at_future == 1
    conn.close()


def test_a_failing_migration_rolls_back_whole_entry(tmp_path, monkeypatch) -> None:
    """Migration atomicity: a new entry whose SECOND statement fails must leave
    neither of its tables nor its bookkeeping row — a crash mid-migration resumes at
    that entry, not half-inside it.

    The version is `len(MIGRATIONS) + 1`, not a literal 3: P2-04 appended v3 (queue) and
    v4 (dead-letter) to the list this seam exists for, so "the next entry" is whatever the
    shipped history does not have yet. Pinning a literal here would break this card's own
    test on every append — which is the opposite of the extensibility it pins.
    """
    path = tmp_path / "agent.sqlite3"
    agent_db.connect(path).close()

    boom = agent_db.Migration(
        version=len(agent_db.MIGRATIONS) + 1,
        name="half_a_table",
        sql="CREATE TABLE will_not_survive (x); CREATE TABLE bad (x, x);",  # dup column fails
    )
    monkeypatch.setattr(agent_db, "MIGRATIONS", (*agent_db.MIGRATIONS, boom))
    with pytest.raises(sqlite3.OperationalError):
        agent_db.connect(path)

    conn = sqlite3.connect(path)
    names = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    assert "will_not_survive" not in names, "the first statement survived a rolled-back entry"
    # Bookkeeping for THE ENTRY UNDER TEST (not a literal 3, which P2-04 has shipped for
    # real now): the rolled-back entry must have left no row of its own.
    rows_new = conn.execute(
        "SELECT COUNT(*) FROM schema_migrations WHERE version = ?", (boom.version,)
    ).fetchone()[0]
    assert rows_new == 0
    conn.close()


# -----------------------------------------------------------------------------------------
# refusals: the pinned key must be honoured, not quietly worked around
# -----------------------------------------------------------------------------------------


def test_record_without_serial_is_refused_and_batch_stays_unwritten(db) -> None:
    """The key is (device_serial, serial_no); SQLite dedupes NULLs NEVER (probe:
    (SN-2, NULL) inserts twice). Storing such a row anyway means every overlap poll
    duplicates it; silently digest-deduping it merges two different events. Both lose
    data, so REFUSE loudly — and leave NO partial batch (a half-written refused batch
    is the same silent-partial-write class the checkpoint rule refuses)."""
    good = make_record(serial_no=5742)
    orphan = make_record(serial_no=None)
    with pytest.raises(agent_store.UnusableRecordError) as exc:
        agent_store.store_events(db, [good, orphan], now=T0)
    assert "serial_no" in str(exc.value)
    assert event_count(db) == 0, "a refused batch must leave NOTHING behind"


def test_mixed_device_serials_in_one_batch_are_refused(db) -> None:
    """store_events reports ONE device_serial on the result (P2-03 advances the
    checkpoint from it); a mixed batch would make that number a lie."""
    other = make_record(device_serial="DEV-B")
    with pytest.raises(agent_store.MixedDeviceError):
        agent_store.store_events(db, [make_record(), other], now=T0)
    assert event_count(db) == 0


def test_store_rollback_leaves_the_connection_usable(db) -> None:
    """The refused batch must ROLL BACK, not sit in a dangling BEGIN.

    `store_events` owns its transaction (isolation_level=None), so an exception that
    skips COMMIT would otherwise leave BEGIN open on this connection and poison every
    later write of the same poll loop. After the refusal the same connection stores a
    good batch normally — that is the proof the rollback really happened.
    """
    with pytest.raises(agent_store.UnusableRecordError):
        agent_store.store_events(db, [make_record(serial_no=None)], now=T0)
    result = agent_store.store_events(db, [make_record()], now=T1)
    assert result.inserted == 1 and event_count(db) == 1


def test_empty_batch_is_an_empty_result(db) -> None:
    result = agent_store.store_events(db, [], now=T0)
    assert result.inserted == 0 and result.refreshed == 0 and result.unchanged == 0
    assert result.device_serial is None


# -----------------------------------------------------------------------------------------
# query seams the sibling cards consume (P2-03 loop, P2-04 pusher)
# -----------------------------------------------------------------------------------------


def test_event_lookup_by_key_returns_the_payload_line(db) -> None:
    """P2-04 queues payloads by rowid/key: the store must expose the lookup."""
    record = make_record()
    result = agent_store.store_events(db, [record], now=T0)
    rowid = agent_store.event_rowid(db, SERIAL, 5742)
    assert rowid == result.rowids[5742]
    assert agent_store.event_jsonl(db, rowid) == one_line(record)


def test_event_rowid_for_a_missing_key_is_none(db) -> None:
    assert agent_store.event_rowid(db, SERIAL, 9999) is None
