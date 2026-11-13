"""GC-P16a — prune already-pushed events out of the local site store.

WHY (docs/internal/go-live-finish/GC-P16a.md; R1: BC owns the permanent record, the
agent is a buffer). `events` keeps every scan with its flattened `name`, `employee_no`
and `cardNo` forever, even though Table 70607 has held the permanent copy since the
row was pushed. Unbounded local PII retention is the defect; the fix is a delete that
can only ever reach a row the poller has PROVEN left the building, and only after a
retention window.

The three refusals this file exists to pin, in order of how much they cost if they
break:

* an event the ledger never saw (never pushed -> never deleted),
* an event still pointed at by `push_queue` (the FK says RESTRICT; the prune's own
  `NOT EXISTS` says the same thing out loud, and covers the queue row's absence of
  `event_time_utc` edge cases),
* an event with a `dead_letter` row (that row has NO FK, so only the prune's own
  predicate protects it — test 4 therefore deletes the dead-letter row and shows the
  same event then DOES go).

The prune cadence (at most once per day) and the checkpoint's untouchedness are pinned
where they live: the real `SiteAgent.tick()` for the cadence, the real `checkpoint`
row for the untouchedness.

So is what the delete does to the ALERTS, because this is the product's only sanctioned
`DELETE FROM events` and P2-05's "stored history disappeared" arm reads that same
`MIN(serial_no)` on every ok tick. The delete accounts for itself to the policy whose
connection it deleted from; the cases below pin both halves — the sanctioned rise
stays quiet, and every rise that nobody accounted for (or that goes past the floor the
prune left) still pages with the evidence it always carried.

Offline by construction: tmp sqlite files and FakeDevice only. Fixture shapes are
imported, not copied (P2-02's `make_record`/`db`, P2-07b's `AgentHarness`,
test_ring_floor_probe's `_advance_clock`, which moves the fake's RTC with the agent's
clock so a one-day jump does not invent a `clock_skew` alert).
"""

from __future__ import annotations

import sqlite3
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

import gateclerk.agent_cli as agent_cli
import gateclerk.agent_db as agent_db
import gateclerk.agent_store as agent_store
from gateclerk.agent_alert import AlertPolicy
from gateclerk.agent_store import prune_pushed_events
from gateclerk.sinks import IMPLICIT_SINK_NAME
from test_p2_02_store import SERIAL, SITE, make_record
from test_p2_03_scheduler import T0
from test_p2_07b_agent_cli import AgentHarness, punch_events, seeded_device
from test_ring_floor_probe import _advance_clock

#: A frozen clock: every age in this file is arithmetic on these two instants, never now-ish.
NOW = datetime(2026, 11, 13, 12, 0, 0, tzinfo=UTC)
RETENTION_DAYS = 14
#: Older than the window: 30 days back, comfortably past the 14-day cutoff.
OLD_ISO = (NOW - timedelta(days=30)).isoformat()
#: Inside the window: one day back must survive even when the ledger says `sent`.
FRESH_ISO = (NOW - timedelta(days=1)).isoformat()
CUTOFF = (NOW - timedelta(days=RETENTION_DAYS)).isoformat()

#: The two endpoints a site can aim buffers at in these fixtures. Real-looking shapes,
#: TEST-NET-free because they are file stubs, not hosts.
ENDPOINT_A = "stub://tmp/ingest-a.jsonl"
ENDPOINT_B = "stub://tmp/ingest-b.jsonl"


@pytest.fixture
def db(tmp_path: Path):
    """A fresh agent db (connect = pragmas + migrations), closed after the test.

    Same fixture as tests/test_p2_02_store.py: the prune lives in that module and must
    be exercised against the shipped schema, not a hand-built table.
    """
    conn = agent_db.connect(tmp_path / "agent.sqlite3")
    yield conn
    conn.close()


def store_aged(db: sqlite3.Connection, *, serial_no: int, event_time_utc: str | None) -> int:
    """Store one real-shaped record with a chosen `event_time_utc`; return its rowid.

    The record goes in through `store_events` (not a hand-written INSERT) so the row
    carries the same flattened PII columns production writes: this is a retention test
    about the rows the agent actually leaves behind.
    """
    record = make_record(
        serial_no=serial_no,
        event_time_utc=event_time_utc,
        employee_no=str(serial_no),
        name=f"User E{serial_no}",
    )
    agent_store.store_events(db, [record], now=NOW)
    rowid = agent_store.event_rowid(db, SERIAL, serial_no)
    assert rowid is not None, f"serial {serial_no} did not land in the store"
    return rowid


def queued(db: sqlite3.Connection, *, event_id: int, sink_name: str = IMPLICIT_SINK_NAME) -> None:
    """A real-shaped `push_queue` buffer pointing at one event (the FK-carrying case)."""
    db.execute(
        "INSERT INTO push_queue (event_id, payload, endpoint, sink_name, attempts,"
        " next_attempt_at, enqueued_at) VALUES (?, ?, ?, ?, 0, ?, ?)",
        (event_id, "{}", ENDPOINT_A, sink_name, NOW.isoformat(), NOW.isoformat()),
    )


def dead_lettered(
    db: sqlite3.Connection, *, event_id: int, sink_name: str = IMPLICIT_SINK_NAME
) -> None:
    """A real-shaped `dead_letter` row pointing at one event (the no-FK case)."""
    db.execute(
        "INSERT INTO dead_letter (event_id, payload, endpoint, sink_name, error_class,"
        " attempts, first_attempt_at, last_attempt_at) VALUES (?, ?, ?, ?, ?, 3, ?, ?)",
        (
            event_id,
            "{}",
            ENDPOINT_A,
            sink_name,
            "TransportError",
            NOW.isoformat(),
            NOW.isoformat(),
        ),
    )


def checkpoint_row(db: sqlite3.Connection) -> tuple[Any, ...]:
    """The whole `checkpoint` table, every column — the identity a prune must never disturb.

    `zip(keys, values)` rather than a `.keys()` loop: a `sqlite3.Row` iterates its VALUES,
    so the obvious comprehension would compare column values against each other and pass
    for the wrong reason.
    """
    return tuple(
        tuple(zip(row.keys(), tuple(row), strict=True))
        for row in db.execute("SELECT * FROM checkpoint ORDER BY device_serial").fetchall()
    )


# --- the store-side delete ---------------------------------------------------------------


def test_old_pushed_event_is_deleted(db: sqlite3.Connection) -> None:
    """A pushed event past the retention window is gone, and the count says so.

    Also pins the assumption the delete's `event_time_utc < ?` relies on: the contract
    writes that column as UTC (`tz.py:334` normalises with `astimezone(UTC)`), so a
    lexical ISO comparison IS chronological order. A row that stopped being `+00:00`
    would silently age in the wrong direction, so it is asserted rather than assumed.
    """
    rowid = store_aged(db, serial_no=5742, event_time_utc=OLD_ISO)
    stored = db.execute("SELECT event_time_utc FROM events WHERE id = ?", (rowid,)).fetchone()[0]
    assert stored == OLD_ISO and stored.endswith("+00:00")
    assert stored < CUTOFF, "the fixture must sit on the old side of the cutoff"

    assert prune_pushed_events(db, event_ids={rowid}, before_utc=CUTOFF) == 1
    assert db.execute("SELECT COUNT(*) FROM events").fetchone()[0] == 0


def test_new_or_unpushed_event_is_kept(db: sqlite3.Connection) -> None:
    """Neither reason to keep a row may be dropped: not-in-the-ledger, and inside-window.

    Two rows, one failure each: an OLD row the ledger never named (the prune is not a
    purge) and a LEDGER-NAMED row that is only one day old (the window is a retention
    promise, not an eager delete).
    """
    unpushed = store_aged(db, serial_no=5742, event_time_utc=OLD_ISO)
    fresh = store_aged(db, serial_no=5743, event_time_utc=FRESH_ISO)

    assert prune_pushed_events(db, event_ids={fresh}, before_utc=CUTOFF) == 0

    survivors = {row[0] for row in db.execute("SELECT id FROM events")}
    assert survivors == {unpushed, fresh}, "one of the two keep-rules was dropped"


def test_queued_event_is_kept_even_when_old(db: sqlite3.Connection) -> None:
    """A buffer that still points at the event keeps it — and the FK really does bite.

    The predicate is what makes this readable; `ON DELETE RESTRICT` is what makes it
    true even if someone edits the predicate away, so this test pins both: the prune
    returns 0, and a raw `DELETE` of the same row raises.
    """
    rowid = store_aged(db, serial_no=5742, event_time_utc=OLD_ISO)
    queued(db, event_id=rowid)

    assert prune_pushed_events(db, event_ids={rowid}, before_utc=CUTOFF) == 0
    assert db.execute("SELECT COUNT(*) FROM events").fetchone()[0] == 1

    with pytest.raises(sqlite3.IntegrityError):
        db.execute("DELETE FROM events WHERE id = ?", (rowid,))
    assert db.execute("SELECT COUNT(*) FROM push_queue").fetchone()[0] == 1


def test_dead_lettered_event_is_kept(db: sqlite3.Connection) -> None:
    """A dead-letter row keeps its event even though nothing points at it in the db.

    `dead_letter.event_id` has no FK by design (the row must outlive the event), so
    `NOT EXISTS (SELECT 1 FROM dead_letter ...)` is the ONLY thing standing between a
    prune and an unrecoverable loss: the punch never reached the ingest and its payload
    is gone with the row. The second half is the control — remove the dead-letter row
    (the owner's `agent deadletter delete`, the sanctioned way) and the same event, with
    the same ledger entry and the same age, DOES get pruned.
    """
    rowid = store_aged(db, serial_no=5742, event_time_utc=OLD_ISO)
    dead_lettered(db, event_id=rowid)

    assert prune_pushed_events(db, event_ids={rowid}, before_utc=CUTOFF) == 0
    assert db.execute("SELECT COUNT(*) FROM events").fetchone()[0] == 1

    db.execute("DELETE FROM dead_letter")
    assert prune_pushed_events(db, event_ids={rowid}, before_utc=CUTOFF) == 1
    assert db.execute("SELECT COUNT(*) FROM events").fetchone()[0] == 0


def test_prune_never_touches_the_checkpoint(db: sqlite3.Connection) -> None:
    """The walk's starting truth survives a prune that actually deleted something.

    The checkpoint is not a cache: a pruned row must not lower, blank or re-stamp it,
    or the next poll window would re-read ground the agent has already pushed. The
    comparison is the whole row tuple (serial, time, epoch, firmware, updated_at), so a
    churned `updated_at` fails it too.
    """
    rowid = store_aged(db, serial_no=5742, event_time_utc=OLD_ISO)
    agent_store.advance_checkpoint(
        db, SERIAL, 5742, completed=True, checkpoint_time=OLD_ISO, now=NOW
    )
    before = checkpoint_row(db)
    assert before, "the fixture needs a checkpoint row to protect"

    assert prune_pushed_events(db, event_ids={rowid}, before_utc=CUTOFF) == 1
    assert checkpoint_row(db) == before, "the prune disturbed the checkpoint"


# --- the ledger accessor -------------------------------------------------------------------


def test_sent_event_ids_unions_sinks_and_counts_gone_as_pushed(tmp_path: Path) -> None:
    """The accessor hands the prune ids and nothing else — every sink, `sent` or `gone`.

    `gone` is the owner-discarded case the card names in WHY: it is evidence the event
    left the building exactly as `sent` is. With N sinks per site, "already pushed" is a
    fact about a sink, so the union across buckets is deliberately the widest set the
    poller has proof for — and the return type is ids only, no endpoint, sink name or
    payload.
    """
    from gateclerk.agent_cli import PushLedger

    ledger = PushLedger(tmp_path / "push-ledger.jsonl")
    ledger.append([1, 2], endpoint=ENDPOINT_A)
    ledger.append([3], endpoint=ENDPOINT_B, sink_name="csv-archive")
    ledger.append([4], endpoint=ENDPOINT_A, kind="gone")

    ids = ledger.sent_event_ids()

    assert ids == {1, 2, 3, 4}
    assert all(isinstance(event_id, int) for event_id in ids)
    assert "User E" not in repr(ids), "the accessor's repr must not carry payload"

    # The same answer from a COLD ledger over the same file. This is the shape the daily
    # prune actually runs at after a `Restart=always` restart: nothing has been pushed
    # yet in this process, so `sent_event_ids()` has to get every id out of the appended
    # lines — an accessor that only saw the in-process buckets would report an empty
    # ledger and the store would never shrink again.
    assert PushLedger(ledger.path).sent_event_ids() == {1, 2, 3, 4}


def test_prune_of_an_empty_ledger_deletes_nothing(db: sqlite3.Connection) -> None:
    """No proof, no delete: the empty ledger short-circuits without touching the store.

    The short-circuit is also the only guard against `id IN (SELECT ... FROM empty temp
    table)` reading as "everything" to a future editor, so it is pinned by the count and
    by a follow-up call that still deletes the row once it has proof.
    """
    rowid = store_aged(db, serial_no=5742, event_time_utc=OLD_ISO)

    assert prune_pushed_events(db, event_ids=set(), before_utc=CUTOFF) == 0
    assert db.execute("SELECT COUNT(*) FROM events").fetchone()[0] == 1

    assert prune_pushed_events(db, event_ids={rowid}, before_utc=CUTOFF) == 1


def test_a_prune_that_moves_the_store_floor_does_not_page_lost_history(
    db: sqlite3.Connection, tmp_path: Path
) -> None:
    """A sanctioned prune is not lost history: the anti-loss arm must not page for it.

    `AlertPolicy.check_stall` treats a rise in `MIN(serial_no)` as evidence of loss — the
    arm exists precisely because spec §2b says a purge is the owner's and must not happen
    by accident. GC-P16a added the first deletion the AGENT is allowed to make, and the
    arm could not tell the two apart, so in a long-running unit the tick after the daily
    prune paged a critical alert for a delete that was correct.

    The attribution travels with the delete: `prune_pushed_events` tells the policy it is
    named in the `policy=` argument which devices it touched and what floor remains (see
    that function's docstring, and the tick hook, which passes its own policy). The
    two tests below are the counter-cases this one cannot cover: a rise nobody accounted
    for still pages, and a rise PAST the pruned floor still pages.
    """
    old = store_aged(db, serial_no=100, event_time_utc=OLD_ISO)
    fresh = store_aged(db, serial_no=200, event_time_utc=FRESH_ISO)
    agent_store.advance_checkpoint(
        db, SERIAL, 200, completed=True, checkpoint_time=FRESH_ISO, now=NOW
    )
    policy = AlertPolicy(
        site=SITE, cadence_s=300, conn=db, park_dir=tmp_path / "park", now=lambda: NOW
    )
    assert policy.check_stall(SERIAL) is None, "no evidence on the first look"

    assert prune_pushed_events(db, event_ids={old, fresh}, before_utc=CUTOFF, policy=policy) == 1
    assert policy.check_stall(SERIAL) is None, "a sanctioned prune is not lost history"


def test_an_unsanctioned_purge_of_the_oldest_row_still_pages_lost_history(
    db: sqlite3.Connection, tmp_path: Path
) -> None:
    """The arm keeps its teeth: the SAME delete, made without the prune, still pages.

    This is the shape the xfail marker could not express. The store, the checkpoint and
    the policy are those of the test above, and the row that goes is the row the prune
    would have gone — but it leaves by a raw `DELETE FROM events`, which is the owner's
    purge (spec §2b: theirs alone) and nothing tells the policy about it. The evidence is
    the same `100 -> 200` text it carried before the attribution existed.
    """
    old = store_aged(db, serial_no=100, event_time_utc=OLD_ISO)
    store_aged(db, serial_no=200, event_time_utc=FRESH_ISO)
    agent_store.advance_checkpoint(
        db, SERIAL, 200, completed=True, checkpoint_time=FRESH_ISO, now=NOW
    )
    policy = AlertPolicy(
        site=SITE, cadence_s=300, conn=db, park_dir=tmp_path / "park", now=lambda: NOW
    )
    assert policy.check_stall(SERIAL) is None, "no evidence on the first look"

    db.execute("DELETE FROM events WHERE id = ?", (old,))

    fired = policy.check_stall(SERIAL)
    assert fired is not None, "an unaccounted rise in MIN(serial_no) is lost history"
    assert fired.kind == "checkpoint_stall"
    assert fired.level == "critical"
    assert "oldest stored serialNo rose 100 -> 200" in fired.note
    assert "stored history disappeared" in fired.note


def test_a_rise_past_the_pruned_floor_is_still_evidence(
    db: sqlite3.Connection, tmp_path: Path
) -> None:
    """Attribution is a floor, not a free pass: excused is "up to here", nothing above.

    One-time suppression ("the next rise is a prune") would leave the arm blind for
    whatever followed the prune, and with a 14-day window on a 5-minute cadence an
    unaccounted loss can land minutes after a legitimate one. So the policy records the
    floor the prune left behind and excuses a rise only while the observed floor stays at
    or below it. Here the prune moves 100 -> 200 (quiet) and a raw delete then moves
    200 -> 300 (pages).
    """
    old = store_aged(db, serial_no=100, event_time_utc=OLD_ISO)
    middle = store_aged(db, serial_no=200, event_time_utc=FRESH_ISO)
    store_aged(db, serial_no=300, event_time_utc=FRESH_ISO)
    agent_store.advance_checkpoint(
        db, SERIAL, 300, completed=True, checkpoint_time=FRESH_ISO, now=NOW
    )
    policy = AlertPolicy(
        site=SITE, cadence_s=300, conn=db, park_dir=tmp_path / "park", now=lambda: NOW
    )
    assert policy.check_stall(SERIAL) is None, "no evidence on the first look"

    assert prune_pushed_events(db, event_ids={old, middle}, before_utc=CUTOFF, policy=policy) == 1
    assert policy.check_stall(SERIAL) is None, "the sanctioned rise is accounted for"

    db.execute("DELETE FROM events WHERE id = ?", (middle,))
    fired = policy.check_stall(SERIAL)
    assert fired is not None, "a rise past the pruned floor is not excused by the prune"
    assert "oldest stored serialNo rose 200 -> 300" in fired.note


def test_a_second_prune_replaces_the_excuse_rather_than_widening_it(
    db: sqlite3.Connection, tmp_path: Path
) -> None:
    """The excuse describes the store as the LAST delete left it — never a wider one.

    A monotone "highest floor ever seen" rule survives a device whose serial space
    restarts (GC-P15's reset: the store's floor legitimately drops) and then hushes a real
    loss up to that old, high number. So the notification is replaced, not raised. Here the
    first prune leaves 200, the serials then restart below it, a second prune leaves 2 — and
    the next unsanctioned rise to 3 pages, where a carried-over 200 would have excused it.
    """
    old = store_aged(db, serial_no=100, event_time_utc=OLD_ISO)
    store_aged(db, serial_no=200, event_time_utc=FRESH_ISO)
    agent_store.advance_checkpoint(
        db, SERIAL, 200, completed=True, checkpoint_time=FRESH_ISO, now=NOW
    )
    policy = AlertPolicy(
        site=SITE, cadence_s=300, conn=db, park_dir=tmp_path / "park", now=lambda: NOW
    )
    assert policy.check_stall(SERIAL) is None
    assert prune_pushed_events(db, event_ids={old}, before_utc=CUTOFF, policy=policy) == 1
    assert policy.check_stall(SERIAL) is None, "the sanctioned rise stays quiet"

    # The device's serial space restarts below the pruned floor: the store drops back to 1,
    # which is a LOWER floor and therefore not evidence of anything (P2-05's rule).
    db.execute("DELETE FROM events")
    low = store_aged(db, serial_no=1, event_time_utc=OLD_ISO)
    second = store_aged(db, serial_no=2, event_time_utc=FRESH_ISO)
    store_aged(db, serial_no=3, event_time_utc=FRESH_ISO)
    assert policy.check_stall(SERIAL) is None, "a lower floor is not evidence"

    assert prune_pushed_events(db, event_ids={low}, before_utc=CUTOFF, policy=policy) == 1
    assert policy._pruned_floor == {SERIAL: 2}, "the excuse is the floor THIS delete left"
    assert policy.check_stall(SERIAL) is None, "1 -> 2 was the prune's own doing"

    db.execute("DELETE FROM events WHERE id = ?", (second,))
    fired = policy.check_stall(SERIAL)
    assert fired is not None, "a rise past the NEWEST floor is not excused by an old one"
    assert "oldest stored serialNo rose 2 -> 3" in fired.note


def test_a_policy_reading_a_different_store_is_not_credited(
    db: sqlite3.Connection, tmp_path: Path
) -> None:
    """`policy.conn is conn` is the difference between an excuse and a lie.

    The attribution excuses a rise in the store the policy actually reads, so a policy
    wired to another database must learn nothing from this delete: crediting it would hush
    the anti-loss arm of a site whose rows this statement never touched.
    """
    other = agent_db.connect(tmp_path / "other-site.sqlite3")
    try:
        old = store_aged(db, serial_no=100, event_time_utc=OLD_ISO)
        store_aged(db, serial_no=200, event_time_utc=FRESH_ISO)
        policy = AlertPolicy(
            site=SITE, cadence_s=300, conn=other, park_dir=tmp_path / "park", now=lambda: NOW
        )

        assert prune_pushed_events(db, event_ids={old}, before_utc=CUTOFF, policy=policy) == 1
        assert policy._pruned_floor == {}, "a policy over another store learns nothing"
    finally:
        other.close()


def test_a_prune_that_empties_a_device_leaves_no_excuse_behind(
    db: sqlite3.Connection, tmp_path: Path
) -> None:
    """The prune that removes a device's LAST row notes no floor — and excuses nothing.

    `read_oldest_serial` answers None for an empty device, while `_pruned_floor` is typed
    int: a None entry there would be an excuse no reader can interpret, so `note_pruned`
    declines it and the anti-loss arm stays exactly as it was. The second half is the
    teeth — the rows stored after the empty store are protected by whatever delete removes
    THEM, never by this one.
    """
    only = store_aged(db, serial_no=100, event_time_utc=OLD_ISO)
    agent_store.advance_checkpoint(
        db, SERIAL, 100, completed=True, checkpoint_time=OLD_ISO, now=NOW
    )
    policy = AlertPolicy(
        site=SITE, cadence_s=300, conn=db, park_dir=tmp_path / "park", now=lambda: NOW
    )
    assert policy.check_stall(SERIAL) is None

    assert prune_pushed_events(db, event_ids={only}, before_utc=CUTOFF, policy=policy) == 1
    assert policy._pruned_floor == {}, "an empty device has no floor to be trusted to"
    assert policy.check_stall(SERIAL) is None, "no floor is not a rise"

    low = store_aged(db, serial_no=5, event_time_utc=FRESH_ISO)
    store_aged(db, serial_no=6, event_time_utc=FRESH_ISO)
    assert policy.check_stall(SERIAL) is None, "the first look at the new rows seeds"
    db.execute("DELETE FROM events WHERE id = ?", (low,))
    fired = policy.check_stall(SERIAL)
    assert fired is not None, "an emptied store must not excuse a later loss"
    assert "oldest stored serialNo rose 5 -> 6" in fired.note


def test_a_prune_that_never_committed_attributes_nothing(
    db: sqlite3.Connection, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A delete that did not land must not buy an excuse.

    The statement's own transaction is what makes this true: the floor is read after the
    delete and reported only after the commit, so anything that breaks in between leaves
    both the rows and the policy exactly as they were. The seam fails the floor read (the
    statement right after the delete) so the transaction has a reason to roll back.
    """
    old = store_aged(db, serial_no=100, event_time_utc=OLD_ISO)
    store_aged(db, serial_no=200, event_time_utc=FRESH_ISO)
    policy = AlertPolicy(
        site=SITE, cadence_s=300, conn=db, park_dir=tmp_path / "park", now=lambda: NOW
    )
    real = agent_store.read_oldest_serial

    def exploding(*_args: object, **_kwargs: object) -> None:
        raise sqlite3.OperationalError("disk I/O error (test seam)")

    monkeypatch.setattr(agent_store, "read_oldest_serial", exploding)
    try:
        with pytest.raises(sqlite3.OperationalError, match="test seam"):
            prune_pushed_events(db, event_ids={old}, before_utc=CUTOFF, policy=policy)
    finally:
        monkeypatch.setattr(agent_store, "read_oldest_serial", real)

    assert db.execute("SELECT COUNT(*) FROM events").fetchone()[0] == 2, "the delete rolled back"
    assert policy._pruned_floor == {}, "a delete that never landed excuses nothing"


def test_the_attribution_carries_no_payload(db: sqlite3.Connection, tmp_path: Path) -> None:
    """What crosses the store/policy boundary: the device's serial and one integer.

    White-box on purpose — `policy._pruned_floor` IS the whole surface the delete is
    allowed to touch, so the equality is the shape pin and the `repr` scan is the PII pin.
    `store_aged` writes a real-shaped row (flattened `name`, `employee_no`, `raw`), so a
    leak here would be a leak of exactly what GC-P16a's "only a count" rule keeps out of
    the prune's return value.
    """
    old = store_aged(db, serial_no=100, event_time_utc=OLD_ISO)
    store_aged(db, serial_no=200, event_time_utc=FRESH_ISO)
    policy = AlertPolicy(
        site=SITE, cadence_s=300, conn=db, park_dir=tmp_path / "park", now=lambda: NOW
    )

    assert prune_pushed_events(db, event_ids={old}, before_utc=CUTOFF, policy=policy) == 1

    attributed = policy._pruned_floor
    assert attributed == {SERIAL: 200}, "one integer per touched device, nothing else"
    assert "User E100" not in repr(attributed), "the notification must not carry payload"


# --- the tick hook -------------------------------------------------------------------------


def test_prune_runs_at_most_once_per_day(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Two ticks the same day prune once; a tick a day later prunes again.

    The prune is a full-table statement, so per-tick is the wrong cadence for a site
    polling every 5 minutes (288 deletes/day for no retention gain). `>=` is the
    boundary a frozen clock can pin exactly: the jump is exactly one day.

    The monkeypatched prune also records what the tick handed it, which is where the
    retention window, the ledger wiring and the attribution target are pinned: the cutoff
    is the moment minus `DEFAULT_LOCAL_RETENTION_DAYS` expressed in UTC (the column it
    filters is UTC — `tz.py:334`), the ids are the ones the real push just recorded as
    `sent` (tests 1-4 above pin what the real delete does with them), and the policy is the
    object whose `check_stall` reads this same store (below it, the alerts).

    The harness clock is deliberately Bucharest-local (P2-03's `T0`), which is what makes
    the UTC half of the cutoff assertion non-vacuous: an un-normalised cutoff would be a
    `+03:00` string compared lexically against `+00:00` rows, and would age every event
    by three hours.
    """
    calls: list[dict[str, Any]] = []

    def counting_prune(
        _conn: sqlite3.Connection,
        *,
        event_ids: set[int],
        before_utc: str,
        policy: Any = None,
    ) -> int:
        calls.append({"event_ids": set(event_ids), "before_utc": before_utc, "policy": policy})
        return 0

    monkeypatch.setattr(agent_cli, "prune_pushed_events", counting_prune)
    device = seeded_device()
    device.add_events(*punch_events(T0, -300))
    harness = AgentHarness(tmp_path, device, monkeypatch)
    agent = harness.api_agent()
    try:
        agent.tick()
        agent.tick()
        assert len(calls) == 1, "the prune must run once per day, not once per tick"
        assert T0.utcoffset() is not None and T0.utcoffset() != timedelta(0), (
            "this scenario's clock must be a non-UTC zone or the cutoff assertion is vacuous"
        )
        assert (
            calls[0]["before_utc"]
            == (T0 - timedelta(days=agent_cli.DEFAULT_LOCAL_RETENTION_DAYS))
            .astimezone(UTC)
            .isoformat()
        )
        rowids = {row[0] for row in agent.conn.execute("SELECT id FROM events")}
        assert rowids and calls[0]["event_ids"] == rowids, (
            "the prune must receive the ids the push recorded as sent, and nothing else"
        )
        assert calls[0]["policy"] is agent.policy, (
            "the prune must be handed the very policy that reads this store: that object "
            "is the only thing that can be told about the delete (GC-P16a follow-up)"
        )

        _advance_clock(harness, device, timedelta(days=1))
        agent.tick()
        assert len(calls) == 2, "a day later the prune must run again"
    finally:
        agent.close()
