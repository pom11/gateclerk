"""Card P2-04: the outbound pusher + dead-letter — backoff 1→30 s, 24 h bound, replay.

BINDING SPEC: docs/P2-SITE-AGENT.md §2b (dead-letter = a table in the SAME sqlite db,
one row per failed push holding the COMPLETE JSONL payload line + endpoint tag + error
class + attempt count + first/last-attempt timestamps; replay = re-push, UPSERT makes it
safe; rows deleted ONLY by an owner-run command) + §2c (pusher backoff base 1 s cap 30 s
with jitter — the busy-family numbers reused; dead-letter after 24 h of continuous
failure, keep retrying the queue at cap) + §3 (the push target is ABSTRACT: this card
builds against a `stub://` ingest that writes JSONL to a local path — no endpoint is
ever invented or defaulted).

The five DoD cases the card dictates, 1:1 to the section headers below:

(1) success drains — the queue row is DELETED (the store keeps the event: the queue is
    a transient send buffer, not a second copy of the truth).
(2) failure backs off 1, 2, 4, 8, 16, then caps at 30 with the jitter from an INJECTED
    rng (pinned sequence, one rng call per failed row — a second call would double-jitter).
(3) 24 h of continuous failure moves the row to dead_letter with the FULL to_jsonl line,
    the endpoint tag, the error class, the attempt count and first/last timestamps, the
    queue stays drainable behind it, and the row replays: re-queue → success → gone from
    BOTH tables and the stub ingest got the line.
(4) dead-letter rows survive a reopen (same bytes) and nothing but the explicit owner
    command deletes them.
(5) the stub ingest file parses as exact `model.EventRecord.from_jsonl` output.

Offline by construction: the HTTP transport is an injected callable `(url, body) ->
status`, so no test here opens a socket (conftest.netoff would kill one anyway); the
stub ingest is tmp-dir JSONL. Clock and rng are injected for the same reason — every
timestamp and every delay in this file is byte-pinned, never "now-ish". Masked fixture
values only (`User E<n>`, `MASKED-SER-1`), no real host (tests/test_repo_hygiene.py).
"""

from __future__ import annotations

import sqlite3
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest

import gateclerk.agent_db as agent_db
import gateclerk.agent_push as agent_push
import gateclerk.agent_store as agent_store
from gateclerk.model import EventRecord, from_jsonl, to_jsonl

SITE = "site-a"
SERIAL = "MASKED-SER-1"
ENDPOINT = "stub://ingest/site-a.jsonl"

#: A fixed clock: every timestamp assertion below is byte-pinned against these.
T0 = datetime(2026, 10, 19, 10, 0, 0, tzinfo=UTC)
BOUND = 86400  # config's push_dead_letter_after_s default (§2c: 24 h)

#: The naive clock the refusal tests hand in on purpose (DTZ policy is payroll data):
#: derived from the pinned clock so it stays deterministic and names itself.
NAIVE = T0.replace(tzinfo=None)


def at(seconds: float) -> datetime:
    return T0 + timedelta(seconds=seconds)


def iso(moment: datetime) -> str:
    return moment.astimezone(UTC).isoformat(timespec="seconds")


def make_record(**over: Any) -> EventRecord:
    """One site-a-shaped record (masked: `User E<n>`, serials as OBSERVED.md)."""
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
    """`to_jsonl()` for one record minus its trailing newline — the stored/sent line."""
    return to_jsonl([record])[:-1]


class Rng:
    """An injected rng with a PINNED sequence, and a call count (one per failure)."""

    def __init__(self, *values: float) -> None:
        self.values = list(values)
        self.calls = 0

    def __call__(self) -> float:
        self.calls += 1
        if not self.values:
            raise AssertionError("the pinned rng ran out of values — the delay maths changed")
        return self.values.pop(0)


class Flaky:
    """A transport that answers a scripted list of statuses/exceptions.

    Records (url, body) per call so a test can pin EXACTLY what was sent, and when.
    """

    def __init__(self, *outcomes: int | Exception) -> None:
        self.outcomes = list(outcomes)
        self.calls: list[tuple[str, str]] = []

    def __call__(self, url: str, body: str) -> int:
        self.calls.append((url, body))
        if not self.outcomes:
            raise AssertionError("the scripted transport ran out of outcomes")
        outcome = self.outcomes.pop(0)
        if isinstance(outcome, Exception):
            raise outcome
        return outcome

    @property
    def bodies(self) -> list[str]:
        return [body for _, body in self.calls]


@pytest.fixture
def db(tmp_path):
    """A fresh agent db (connect = pragmas + migrations), closed after the test."""
    conn = agent_db.connect(tmp_path / "agent.sqlite3")
    yield conn
    conn.close()


@pytest.fixture
def stored(db) -> tuple[EventRecord, int]:
    """One stored event + its rowid — the store is the queue's source of truth."""
    record = make_record()
    result = agent_store.store_events(db, [record], now=T0)
    return record, result.rowids[record.serial_no]


def queue_rows(conn: sqlite3.Connection) -> list[sqlite3.Row]:
    return list(conn.execute("SELECT * FROM push_queue ORDER BY id"))


def dead_rows(conn: sqlite3.Connection) -> list[sqlite3.Row]:
    return list(conn.execute("SELECT * FROM dead_letter ORDER BY id"))


# -----------------------------------------------------------------------------------------
# (0) the migration seam: P2-04 appends v3 (push_queue) + v4 (dead_letter)
# -----------------------------------------------------------------------------------------


def test_the_queue_and_dead_letter_tables_ship_in_the_same_db(db) -> None:
    """§2b decided a TABLE in the same sqlite db, not a side file: one file to back up,
    one WAL, and the queue can FK-reference the events row it is a send buffer for."""
    names = {r[0] for r in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    assert {"push_queue", "dead_letter"} <= names, f"missing tables: {sorted(names)}"
    versions = [r[0] for r in db.execute("SELECT version FROM schema_migrations ORDER BY version")]
    assert versions == [m.version for m in agent_db.MIGRATIONS]
    assert len(agent_db.MIGRATIONS) == 4, "v1 bookkeeping, v2 agent db, v3 queue, v4 dead_letter"


def test_queue_columns_are_the_cards_tuple_plus_provenance(db) -> None:
    """The card's own queue tuple is (rowid, payload_ref, attempts, next_attempt_at,
    first_failed_at) — a send buffer, NOT a copy of the store."""
    cols = {r[1] for r in db.execute("PRAGMA table_info(push_queue)")}
    assert {
        "id",
        "event_id",
        "payload",
        "endpoint",
        "attempts",
        "next_attempt_at",
        "first_failed_at",
    } <= cols


def test_dead_letter_columns_are_what_spec_2b_demands(db) -> None:
    """§2b names its contents; the column names are that list, so a payroll triage can
    read the row without this module in front of it."""
    cols = {r[1] for r in db.execute("PRAGMA table_info(dead_letter)")}
    assert {
        "id",
        "payload",
        "endpoint",
        "error_class",
        "attempts",
        "first_attempt_at",
        "last_attempt_at",
    } <= cols


def test_the_queue_cannot_reference_an_event_the_store_does_not_have(db) -> None:
    """The store is the source of truth (card SEMANTICS). A queue row is a pointer to a
    stored event, so an FK — with foreign_keys=ON (agent_db.connect) a pointer at nothing
    is refused, not silently carried until the drain finds no payload."""
    with pytest.raises(sqlite3.IntegrityError):
        db.execute(
            "INSERT INTO push_queue (event_id, payload, endpoint, attempts, next_attempt_at)"
            " VALUES (9999, 'x', 'stub://x', 0, '2026-10-19T10:00:00+00:00')"
        )


def test_a_queued_event_cannot_be_deleted_underneath_the_queue(db, stored) -> None:
    """RESTRICT, and deliberately so: a purge that silently removed a not-yet-pushed
    event would lose a punch with no dead-letter row to show for it (spec §2b: purge is
    the owner's, and it must not outrun the queue)."""
    _, rowid = stored
    agent_push.enqueue_events(db, [rowid], endpoint=ENDPOINT, now=T0)
    with pytest.raises(sqlite3.IntegrityError):
        db.execute("DELETE FROM events WHERE id = ?", (rowid,))


# -----------------------------------------------------------------------------------------
# enqueue: the queue is built FROM the store
# -----------------------------------------------------------------------------------------


def test_enqueue_uses_the_stored_bytes_verbatim(db, stored) -> None:
    """The queue's payload is what `agent_store.event_jsonl` says, byte-for-byte: the
    pusher cannot be handed an arbitrary body and the store keeps being the truth."""
    record, rowid = stored
    ids = agent_push.enqueue_events(db, [rowid], endpoint=ENDPOINT, now=T0)
    assert len(ids) == 1
    row = queue_rows(db)[0]
    assert row["payload"] == one_line(record) == agent_store.event_jsonl(db, rowid)
    assert row["event_id"] == rowid
    assert row["endpoint"] == ENDPOINT
    assert row["attempts"] == 0
    assert row["first_failed_at"] is None, "nothing has failed yet — the 24 h clock has not started"
    assert row["next_attempt_at"] == iso(T0), "a fresh row is due immediately"


def test_enqueue_is_idempotent_renqueueing_the_same_event_is_one_row(db, stored) -> None:
    """The overlap poll re-stores the same events every tick; the queue must not grow a
    second send-buffer row per poll or the ingest gets the line again every 5 minutes."""
    _, rowid = stored
    first = agent_push.enqueue_events(db, [rowid], endpoint=ENDPOINT, now=T0)
    again = agent_push.enqueue_events(db, [rowid], endpoint=ENDPOINT, now=at(300))
    assert first == again
    assert len(queue_rows(db)) == 1


def test_re_enqueue_refreshes_the_payload_but_keeps_the_retry_state(db, stored) -> None:
    """A revision bump (the store's own UPSERT) must not be silently unsent: the buffer
    re-reads the stored bytes. But attempts/first_failed_at are the failure history and
    survive — re-polling an overlap window must not reset a 24 h failure clock."""
    _, rowid = stored
    agent_push.enqueue_events(db, [rowid], endpoint=ENDPOINT, now=T0)
    agent_push.drain(db, endpoint=ENDPOINT, transport=Flaky(500), now=T0, rng=Rng(1.0))

    revised = make_record(name="User E1 corrected")
    agent_store.store_events(db, [revised], now=at(60))
    agent_push.enqueue_events(db, [rowid], endpoint=ENDPOINT, now=at(60))

    row = queue_rows(db)[0]
    assert row["payload"] == one_line(revised)
    assert row["attempts"] == 1
    assert row["first_failed_at"] == iso(T0)


def test_enqueue_refuses_a_rowid_that_is_not_stored(db) -> None:
    """Loud, not an FK error from inside a loop: a caller that invented a rowid has a
    bug, and the message must say which rowid."""
    with pytest.raises(agent_push.QueueError, match="4242"):
        agent_push.enqueue_events(db, [4242], endpoint=ENDPOINT, now=T0)
    assert queue_rows(db) == []


def test_enqueue_of_no_rowids_is_an_empty_result(db) -> None:
    assert agent_push.enqueue_events(db, [], endpoint=ENDPOINT, now=T0) == ()


def test_enqueue_refuses_a_naive_clock(db, stored) -> None:
    """DTZ policy at the seam: a naive `now` would stamp a payroll retry clock in a zone
    SQLite cannot compare against the UTC rows."""
    _, rowid = stored
    with pytest.raises(ValueError):
        agent_push.enqueue_events(db, [rowid], endpoint=ENDPOINT, now=NAIVE)


# -----------------------------------------------------------------------------------------
# (1) success drains
# -----------------------------------------------------------------------------------------


def test_a_successful_push_deletes_the_queue_row_and_keeps_the_event(db, stored) -> None:
    """DoD (1). The queue is transient; the store is not. A push that DELETEd the event,
    or a success that left the row queued (re-pushing forever), both fail this."""
    record, rowid = stored
    agent_push.enqueue_events(db, [rowid], endpoint=ENDPOINT, now=T0)
    transport = Flaky(200)
    result = agent_push.drain(db, endpoint=ENDPOINT, transport=transport, now=T0, rng=Rng())

    assert result.sent == (rowid,) or rowid in result.sent
    assert transport.calls == [(ENDPOINT, one_line(record) + "\n")]
    assert queue_rows(db) == []
    assert agent_store.event_jsonl(db, rowid) == one_line(record), "the store keeps the event"
    assert dead_rows(db) == []


def test_only_due_rows_are_sent(db, stored) -> None:
    """next_attempt_at is the whole backoff mechanism: a drain before it must send
    nothing (a transport call early is the "never hammer" rule broken)."""
    _, rowid = stored
    agent_push.enqueue_events(db, [rowid], endpoint=ENDPOINT, now=T0)
    transport = Flaky()
    result = agent_push.drain(db, endpoint=ENDPOINT, transport=transport, now=at(-1), rng=Rng())
    assert result.sent == () and transport.calls == []

    result = agent_push.drain(db, endpoint=ENDPOINT, transport=Flaky(200), now=T0, rng=Rng())
    assert len(result.sent) == 1, "due exactly AT next_attempt_at is due"


def test_a_row_for_another_endpoint_is_left_alone(db, stored) -> None:
    """Sites/push targets are per-site config (§2d); a drain for one target must not
    push a row onto another one."""
    _, rowid = stored
    agent_push.enqueue_events(db, [rowid], endpoint="stub://other/site-b.jsonl", now=T0)
    result = agent_push.drain(db, endpoint=ENDPOINT, transport=Flaky(200), now=T0, rng=Rng())
    assert result.sent == ()
    assert len(queue_rows(db)) == 1


def test_an_empty_queue_drains_to_nothing(db) -> None:
    result = agent_push.drain(db, endpoint=ENDPOINT, transport=Flaky(), now=T0, rng=Rng())
    assert (result.sent, result.retried, result.dead_lettered) == ((), (), ())
    assert result.push_ok == 0 and result.push_failed == 0


def test_a_non_2xx_status_is_a_failure_not_a_send(db, stored) -> None:
    """An ingest answering 500 did not accept the line. Treating any return as success
    would DELETE the queue row and lose the punch."""
    _, rowid = stored
    agent_push.enqueue_events(db, [rowid], endpoint=ENDPOINT, now=T0)
    result = agent_push.drain(db, endpoint=ENDPOINT, transport=Flaky(500), now=T0, rng=Rng(1.0))
    assert result.sent == () and result.retried == (rowid,)
    row = queue_rows(db)[0]
    assert row["attempts"] == 1
    assert row["last_error_class"] == "HttpStatus500"


def test_every_2xx_is_a_send(db, stored) -> None:
    """201/202/204 are accepts for an append-only ingest; only 2xx-or-not matters."""
    _, rowid = stored
    for status in (200, 201, 202, 204):
        agent_push.enqueue_events(db, [rowid], endpoint=ENDPOINT, now=T0)
        result = agent_push.drain(db, endpoint=ENDPOINT, transport=Flaky(status), now=T0, rng=Rng())
        assert len(result.sent) == 1, f"status {status} must count as accepted"
        assert queue_rows(db) == []


def test_a_transport_exception_is_a_failure_and_names_its_class(db, stored) -> None:
    """The transport is injected, so a raised exception is the normal shape of "the
    internet is down". It must be caught (one bad row cannot break the drain) and its
    CLASS stored — §2b wants the error class on the dead-letter row."""
    _, rowid = stored
    agent_push.enqueue_events(db, [rowid], endpoint=ENDPOINT, now=T0)

    # A real socket-shaped failure (what httpx raises under the hood): the class name
    # that lands on the row is the transport library's own, not one we invented.
    result = agent_push.drain(
        db,
        endpoint=ENDPOINT,
        transport=Flaky(ConnectionResetError("connection reset")),
        now=T0,
        rng=Rng(1.0),
    )
    assert result.retried == (rowid,)
    row = queue_rows(db)[0]
    assert row["last_error_class"] == "ConnectionResetError"
    assert row["first_failed_at"] == iso(T0)


def test_one_failing_row_does_not_stop_the_rows_behind_it(db) -> None:
    """The card's "keep retrying the queue at cap" only means something if a poison row
    cannot wedge the drain — each row is its own transaction."""
    records = [make_record(serial_no=5742), make_record(serial_no=5743)]
    result = agent_store.store_events(db, records, now=T0)
    agent_push.enqueue_events(
        db, [result.rowids[5742], result.rowids[5743]], endpoint=ENDPOINT, now=T0
    )
    transport = Flaky(503, 200)
    drain = agent_push.drain(db, endpoint=ENDPOINT, transport=transport, now=T0, rng=Rng(1.0))
    assert len(drain.retried) == 1 and len(drain.sent) == 1
    assert len(transport.calls) == 2, "the second row was never tried"
    # Which is which is pinned, not just the counts: the failed row is still queued with
    # its backoff set, the accepted row is gone.
    assert [r["event_id"] for r in queue_rows(db)] == [result.rowids[5742]]
    assert datetime.fromisoformat(queue_rows(db)[0]["next_attempt_at"]) > T0


def test_batch_limit_caps_rows_per_drain(db) -> None:
    """A drain is one tick of the agent loop: an unbounded drain of a year-old backlog
    would run past the next poll. Rows stay queued for the next tick."""
    records = [make_record(serial_no=5700 + i) for i in range(5)]
    result = agent_store.store_events(db, records, now=T0)
    agent_push.enqueue_events(
        db, [result.rowids[r.serial_no] for r in records], endpoint=ENDPOINT, now=T0
    )
    drain = agent_push.drain(
        db, endpoint=ENDPOINT, transport=Flaky(200, 200, 200), now=T0, rng=Rng(), limit=3
    )
    assert len(drain.sent) == 3
    assert len(queue_rows(db)) == 2


# -----------------------------------------------------------------------------------------
# (2) backoff: 1, 2, 4, 8, 16, then the 30 s cap — jitter from the injected rng
# -----------------------------------------------------------------------------------------


def test_failures_back_off_one_two_four_then_cap_at_thirty(db, stored) -> None:
    """DoD (2). §2c reuses the busy-family numbers (isapi_transport
    DEFAULT_BUSY_BACKOFF_BASE=1.0 / _CAP=30.0) on purpose: one vocabulary for "never
    hammer" across both legs. rng pinned to 1.0 → the window's upper edge, exactly the
    sequence the card names."""
    _, rowid = stored
    agent_push.enqueue_events(db, [rowid], endpoint=ENDPOINT, now=T0)

    expected = [1, 2, 4, 8, 16, 30, 30]
    previous = T0
    for step, delay in enumerate(expected, start=1):
        moment = previous
        agent_push.drain(db, endpoint=ENDPOINT, transport=Flaky(500), now=moment, rng=Rng(1.0))
        row = queue_rows(db)[0]
        assert row["attempts"] == step
        assert row["first_failed_at"] == iso(T0), "the 24 h clock started at the FIRST failure"
        assert row["last_attempt_at"] == iso(moment)
        due = datetime.fromisoformat(row["next_attempt_at"])
        assert due == moment + timedelta(seconds=delay), (
            f"failure {step} scheduled {due.isoformat()} (delay "
            f"{(due - moment).total_seconds()} s), expected +{delay} s"
        )
        previous = due
    assert row["next_attempt_at"] == iso(previous), "capped: no further growth"


def test_the_jitter_is_the_injected_rng_and_stays_inside_the_cap(db, stored) -> None:
    """The card wants jitter AND an injectable rng for determinism. Pin both halves at
    the cap, where the window is wide enough to see (and where an over-long jitter would
    be the number the spec forbids): rng 0.0 → 15 s, rng 1.0 → 30 s, never more."""
    _, rowid = stored
    agent_push.enqueue_events(db, [rowid], endpoint=ENDPOINT, now=T0)
    # Drive to the cap with the full-jitter rng (the ladder test pins that ladder).
    moment = T0
    for _ in range(6):
        agent_push.drain(db, endpoint=ENDPOINT, transport=Flaky(500), now=moment, rng=Rng(1.0))
        moment = datetime.fromisoformat(queue_rows(db)[0]["next_attempt_at"])

    def due_at(draw: float) -> datetime:
        before = queue_rows(db)[0]["next_attempt_at"]
        agent_push.drain(db, endpoint=ENDPOINT, transport=Flaky(500), now=moment, rng=Rng(draw))
        due = datetime.fromisoformat(queue_rows(db)[0]["next_attempt_at"])
        # restore the pinned full-jitter schedule so the two draws are comparable
        db.execute("UPDATE push_queue SET next_attempt_at = ?", (before,))
        return due

    low, high = due_at(0.0), due_at(1.0)
    assert low != high, "the rng does not reach the delay maths — that is not jitter"
    assert low == moment + timedelta(seconds=15)
    assert high == moment + timedelta(seconds=30)
    assert high - moment <= timedelta(seconds=30), "jitter must never exceed the cap"


def test_the_capped_delay_ignores_more_attempts(db, stored) -> None:
    """After the cap, exponential growth must stop: 2**40 seconds is a schedule nobody
    can observe, and §2c says the queue keeps retrying AT CAP."""
    _, rowid = stored
    agent_push.enqueue_events(db, [rowid], endpoint=ENDPOINT, now=T0)
    for step in range(40):
        moment = T0 + timedelta(seconds=60 * step)
        agent_push.drain(db, endpoint=ENDPOINT, transport=Flaky(500), now=moment, rng=Rng(1.0))
    row = queue_rows(db)[0]
    assert row["attempts"] == 40
    due = datetime.fromisoformat(row["next_attempt_at"])
    assert due == T0 + timedelta(seconds=60 * 39) + timedelta(seconds=30)


def test_the_rng_is_called_exactly_once_per_failed_row(db, stored) -> None:
    """Two calls would double-jitter (and desynchronise the pinned sequence); zero calls
    means the rng is decorative. Also pins that a SUCCESS consumes no randomness."""
    _, rowid = stored
    agent_push.enqueue_events(db, [rowid], endpoint=ENDPOINT, now=T0)
    rng = Rng(1.0, 0.5)
    # Failure 1 at T0 backs off to T0+1.5 s; failure 2 at T0+3 (due) to T0+3+3 s.
    agent_push.drain(db, endpoint=ENDPOINT, transport=Flaky(500, 500), now=T0, rng=rng)
    agent_push.drain(db, endpoint=ENDPOINT, transport=Flaky(500), now=at(3), rng=rng)
    assert rng.calls == 2
    agent_push.drain(db, endpoint=ENDPOINT, transport=Flaky(200), now=at(6), rng=rng)
    assert rng.calls == 2, "a successful push must not consume jitter"


def test_a_failure_never_schedules_a_retry_in_the_same_second(db, stored) -> None:
    """Stamps are second-resolution, so a delay under 1 s would round INTO `now` and the
    row would still be due on the next drain — the endpoint that just failed gets hit
    again immediately. Pin it for a base small enough to expose the rounding (a caller
    may pass a tighter base_s; the floor is what makes that safe)."""
    _, rowid = stored
    agent_push.enqueue_events(db, [rowid], endpoint=ENDPOINT, now=T0)
    agent_push.drain(
        db,
        endpoint=ENDPOINT,
        transport=Flaky(500),
        now=T0,
        rng=Rng(0.0),
        base_s=0.05,
        cap_s=0.1,
    )
    due = datetime.fromisoformat(queue_rows(db)[0]["next_attempt_at"])
    assert due > T0, f"retry scheduled in the same second as the failure: {due}"


def test_an_out_of_range_rng_draw_cannot_escape_the_cap(db, stored) -> None:
    """The rng is injectable, so it must not be able to break the two numbers §2c pins.
    A draw of 5 would otherwise schedule 150 s (past the cap, and past the dead-letter
    bound on every failure — i.e. dead-lettering silently stops happening); a draw of -1
    would schedule a negative delay, i.e. hammering."""
    _, rowid = stored
    agent_push.enqueue_events(db, [rowid], endpoint=ENDPOINT, now=T0)
    for _ in range(6):  # drive the ladder to the cap
        due = datetime.fromisoformat(queue_rows(db)[0]["next_attempt_at"])
        agent_push.drain(db, endpoint=ENDPOINT, transport=Flaky(500), now=due, rng=Rng(1.0))
    due = datetime.fromisoformat(queue_rows(db)[0]["next_attempt_at"])

    agent_push.drain(db, endpoint=ENDPOINT, transport=Flaky(500), now=due, rng=Rng(5.0))
    far = datetime.fromisoformat(queue_rows(db)[0]["next_attempt_at"])
    assert far - due == timedelta(seconds=30), "an oversized draw escaped the 30 s cap"

    agent_push.drain(db, endpoint=ENDPOINT, transport=Flaky(500), now=far, rng=Rng(-1.0))
    back = datetime.fromisoformat(queue_rows(db)[0]["next_attempt_at"])
    assert back > far, "a negative draw scheduled a retry in the past"


def test_backoff_numbers_are_the_busy_families(db) -> None:
    """§2c: "reuse busy-family numbers". Importing them (rather than restating 1.0/30.0)
    is what keeps the two legs from drifting apart silently."""
    from gateclerk.isapi_transport import DEFAULT_BUSY_BACKOFF_BASE, DEFAULT_BUSY_BACKOFF_CAP

    assert agent_push.DEFAULT_PUSH_BACKOFF_BASE_S == DEFAULT_BUSY_BACKOFF_BASE
    assert agent_push.DEFAULT_PUSH_BACKOFF_CAP_S == DEFAULT_BUSY_BACKOFF_CAP


# -----------------------------------------------------------------------------------------
# (3) the 24 h bound → dead_letter (full payload), and replay
# -----------------------------------------------------------------------------------------


def test_continuous_failure_past_the_bound_moves_the_row_to_dead_letter(db, stored) -> None:
    """DoD (3), first half. §2c: dead-letter after `push_dead_letter_after_s` of
    CONTINUOUS failure, measured from the first failure, not from the last one."""
    record, rowid = stored
    agent_push.enqueue_events(db, [rowid], endpoint=ENDPOINT, now=T0)
    transport = Flaky(*([500] * 3))
    agent_push.drain(db, endpoint=ENDPOINT, transport=transport, now=T0, rng=Rng(1.0))
    agent_push.drain(db, endpoint=ENDPOINT, transport=transport, now=at(120), rng=Rng(1.0))

    result = agent_push.drain(
        db, endpoint=ENDPOINT, transport=transport, now=at(BOUND), rng=Rng(1.0)
    )
    assert result.dead_lettered and result.retried == ()
    assert queue_rows(db) == [], "the poison row must leave the queue or the drain loops on it"

    rows = dead_rows(db)
    assert len(rows) == 1
    row = rows[0]
    assert row["payload"] == one_line(record), "§2b: the COMPLETE JSONL payload line"
    assert row["endpoint"] == ENDPOINT
    assert row["error_class"] == "HttpStatus500"
    assert row["attempts"] == 3
    assert row["first_attempt_at"] == iso(T0)
    assert row["last_attempt_at"] == iso(at(BOUND))


def test_the_bound_is_inclusive_at_the_threshold(db, stored) -> None:
    """Boundary pinned on both sides, with a small bound so the boundary and the retry
    schedule cannot blur each other: one second short of the bound keeps retrying (that
    retry is how a blip self-heals), exactly-at is the bound (§2c "after 24 h of
    continuous failure" — 24 h is just config's value of the same number)."""
    _, rowid = stored
    agent_push.enqueue_events(db, [rowid], endpoint=ENDPOINT, now=T0)
    agent_push.drain(db, endpoint=ENDPOINT, transport=Flaky(500), now=T0, rng=Rng(1.0))

    # attempt 2 at exactly 9 s after the first failure, with a 0.0 draw so its next slot
    # lands on T0+10 — the boundary itself, not the retry schedule.
    agent_push.drain(
        db,
        endpoint=ENDPOINT,
        transport=Flaky(500),
        now=at(9),
        rng=Rng(0.0),
        dead_letter_after_s=10,
    )
    assert dead_rows(db) == [] and len(queue_rows(db)) == 1, "9 s is not yet 10 s"

    agent_push.drain(
        db,
        endpoint=ENDPOINT,
        transport=Flaky(500),
        now=at(10),
        rng=Rng(1.0),
        dead_letter_after_s=10,
    )
    assert len(dead_rows(db)) == 1, "exactly at the bound is the bound"


def test_a_success_before_the_bound_never_reaches_dead_letter(db, stored) -> None:
    """The bound is about CONTINUOUS failure. A push that succeeds clears the row and
    with it the failure clock — so a 23 h outage that ends 1 s before the bound must
    dead-letter NOTHING (the whole point of keeping the queue retried at cap)."""
    _, rowid = stored
    agent_push.enqueue_events(db, [rowid], endpoint=ENDPOINT, now=T0)
    for step in range(5):
        agent_push.drain(
            db, endpoint=ENDPOINT, transport=Flaky(500), now=at(step * 100), rng=Rng(1.0)
        )
    assert agent_push.dead_letter_depth(db) == 0
    agent_push.drain(db, endpoint=ENDPOINT, transport=Flaky(200), now=at(BOUND - 1), rng=Rng())
    assert queue_rows(db) == [] and dead_rows(db) == []


def test_the_bound_comes_from_the_caller_not_a_hardcoded_day(db, stored) -> None:
    """86400 is config's DEFAULT_PUSH_DEAD_LETTER_AFTER_S (P2-01); the agent passes
    `site.push_dead_letter_after_s`. A constant baked in here would ignore the config."""
    _, rowid = stored
    agent_push.enqueue_events(db, [rowid], endpoint=ENDPOINT, now=T0)
    agent_push.drain(db, endpoint=ENDPOINT, transport=Flaky(500), now=T0, rng=Rng(1.0))
    agent_push.drain(
        db,
        endpoint=ENDPOINT,
        transport=Flaky(500),
        now=at(30),
        rng=Rng(1.0),
        dead_letter_after_s=10,
    )
    assert len(dead_rows(db)) == 1, "a 10 s bound must be honoured, not the 24 h default"


def test_dead_lettering_the_same_key_twice_is_one_row(db, stored) -> None:
    """§2b: "replay = re-push, UPSERT makes it safe". Replaying into an endpoint that is
    still down must refresh the one row (attempts, last ts), not pile up duplicates — a
    growing dead-letter table full of the same line is an alert that lies."""
    _, rowid = stored
    agent_push.enqueue_events(db, [rowid], endpoint=ENDPOINT, now=T0)
    agent_push.drain(db, endpoint=ENDPOINT, transport=Flaky(500), now=T0, rng=Rng(1.0))
    agent_push.drain(db, endpoint=ENDPOINT, transport=Flaky(500), now=at(BOUND), rng=Rng(1.0))
    first = dead_rows(db)[0]

    agent_push.replay_dead_letter(db, first["id"], endpoint=ENDPOINT, now=at(BOUND + 1))
    agent_push.drain(db, endpoint=ENDPOINT, transport=Flaky(500), now=at(BOUND + 2), rng=Rng(1.0))
    # The replay re-failed and dead-lettered again (the bound is still exceeded — the
    # outage clock never restarted), so replay once more and re-fail: still ONE row.
    agent_push.replay_dead_letter(db, first["id"], endpoint=ENDPOINT, now=at(BOUND + 3))
    agent_push.drain(db, endpoint=ENDPOINT, transport=Flaky(500), now=at(BOUND + 4), rng=Rng(1.0))

    rows = dead_rows(db)
    assert len(rows) == 1, "the replay re-failed and duplicated the dead-letter row"
    assert rows[0]["id"] == first["id"], "an UPSERT refresh keeps the row the owner cites"
    assert rows[0]["last_attempt_at"] == iso(at(BOUND + 4))
    assert rows[0]["first_attempt_at"] == iso(T0), "the outage clock did not restart"
    assert rows[0]["attempts"] == 4, "attempts accumulate across replays (4 pushes tried)"


def test_replay_requeues_then_success_clears_both_tables(db, stored) -> None:
    """DoD (3), second half, exactly as the card words it: re-queue → success → gone
    from both tables, and the stub got the line."""
    record, rowid = stored
    agent_push.enqueue_events(db, [rowid], endpoint=ENDPOINT, now=T0)
    agent_push.drain(db, endpoint=ENDPOINT, transport=Flaky(500), now=T0, rng=Rng(1.0))
    agent_push.drain(db, endpoint=ENDPOINT, transport=Flaky(500), now=at(BOUND), rng=Rng(1.0))
    dead = dead_rows(db)[0]

    queue_id = agent_push.replay_dead_letter(db, dead["id"], endpoint=ENDPOINT, now=at(BOUND + 5))
    assert queue_id is not None
    row = queue_rows(db)[0]
    assert row["payload"] == one_line(record)
    assert row["next_attempt_at"] == iso(at(BOUND + 5)), "a replay is due immediately"
    assert len(dead_rows(db)) == 1, "the dead-letter row stays until the push SUCCEEDS"

    result = agent_push.drain(
        db, endpoint=ENDPOINT, transport=Flaky(200), now=at(BOUND + 5), rng=Rng()
    )
    assert len(result.sent) == 1
    assert queue_rows(db) == [] and dead_rows(db) == []
    assert agent_store.event_jsonl(db, rowid) == one_line(record)


def test_replay_of_an_unknown_id_is_refused(db) -> None:
    with pytest.raises(agent_push.DeadLetterMissingError):
        agent_push.replay_dead_letter(db, 1234, endpoint=ENDPOINT, now=T0)


def test_replaying_a_row_that_is_already_queued_does_not_double_send(db, stored) -> None:
    """The owner hitting replay twice (or replay while the queue still holds the row)
    must not produce two sends of one punch — the queue's UNIQUE key is the guard."""
    _, rowid = stored
    agent_push.enqueue_events(db, [rowid], endpoint=ENDPOINT, now=T0)
    agent_push.drain(db, endpoint=ENDPOINT, transport=Flaky(500), now=T0, rng=Rng(1.0))
    agent_push.drain(db, endpoint=ENDPOINT, transport=Flaky(500), now=at(BOUND), rng=Rng(1.0))
    dead = dead_rows(db)[0]
    agent_push.replay_dead_letter(db, dead["id"], endpoint=ENDPOINT, now=at(BOUND + 5))
    agent_push.replay_dead_letter(db, dead["id"], endpoint=ENDPOINT, now=at(BOUND + 6))
    assert len(queue_rows(db)) == 1


# -----------------------------------------------------------------------------------------
# (4) dead-letter durability + owner-only deletion
# -----------------------------------------------------------------------------------------


def test_dead_letter_rows_survive_a_reopen(tmp_path) -> None:
    """DoD (4). The whole value of a table (rather than a side file) is that the dead
    letters are still there after the agent restarts. Byte-for-byte, or the replay is
    pushing something else."""
    conn = agent_db.connect(tmp_path / "reopen.sqlite3")
    record = make_record()
    result = agent_store.store_events(conn, [record], now=T0)
    conn.close()

    conn = agent_db.connect(tmp_path / "reopen.sqlite3")
    agent_push.enqueue_events(conn, [result.rowids[record.serial_no]], endpoint=ENDPOINT, now=T0)
    agent_push.drain(conn, endpoint=ENDPOINT, transport=Flaky(500), now=T0, rng=Rng(1.0))
    agent_push.drain(conn, endpoint=ENDPOINT, transport=Flaky(500), now=at(BOUND), rng=Rng(1.0))
    before = dead_rows(conn)[0]
    conn.close()

    conn = agent_db.connect(tmp_path / "reopen.sqlite3")
    try:
        after = dead_rows(conn)[0]
        assert dict(after) == dict(before)
        assert from_jsonl(after["payload"] + "\n") == [record]
    finally:
        conn.close()


def test_a_dead_letter_row_is_deleted_only_by_the_owner_command(db, stored) -> None:
    """§2b: "Rows are deleted only by an owner-run command". So: a successful push of a
    DIFFERENT row, a re-enqueue, a drain with no traffic — none may clear the table."""
    records = [make_record(serial_no=5742), make_record(serial_no=5743)]
    result = agent_store.store_events(db, records, now=T0)
    first, second = result.rowids[5742], result.rowids[5743]
    agent_push.enqueue_events(db, [first], endpoint=ENDPOINT, now=T0)
    agent_push.drain(db, endpoint=ENDPOINT, transport=Flaky(500), now=T0, rng=Rng(1.0))
    agent_push.drain(db, endpoint=ENDPOINT, transport=Flaky(500), now=at(BOUND), rng=Rng(1.0))
    keeper = dead_rows(db)[0]["id"]

    agent_push.enqueue_events(db, [second], endpoint=ENDPOINT, now=T0)
    agent_push.drain(db, endpoint=ENDPOINT, transport=Flaky(200), now=T0, rng=Rng())
    agent_push.enqueue_events(db, [first], endpoint=ENDPOINT, now=T0)
    agent_push.drain(db, endpoint=ENDPOINT, transport=Flaky(500), now=at(1), rng=Rng(1.0))

    rows = dead_rows(db)
    assert len(rows) == 1 and rows[0]["id"] == keeper, "something other than the command deleted"


def test_the_owner_command_deletes_exactly_the_named_row(db, stored) -> None:
    """The CLI subcommand is P2-07's surface; this card exposes the function. It reports
    whether it removed something (an owner typo must not silently "succeed")."""
    _, rowid = stored
    agent_push.enqueue_events(db, [rowid], endpoint=ENDPOINT, now=T0)
    agent_push.drain(db, endpoint=ENDPOINT, transport=Flaky(500), now=T0, rng=Rng(1.0))
    agent_push.drain(db, endpoint=ENDPOINT, transport=Flaky(500), now=at(BOUND), rng=Rng(1.0))
    other = agent_store.store_events(db, [make_record(serial_no=5743)], now=T0)
    agent_push.enqueue_events(db, [other.rowids[5743]], endpoint=ENDPOINT, now=T0)
    agent_push.drain(db, endpoint=ENDPOINT, transport=Flaky(500), now=T0, rng=Rng(1.0))
    agent_push.drain(db, endpoint=ENDPOINT, transport=Flaky(500), now=at(BOUND), rng=Rng(1.0))
    assert len(dead_rows(db)) == 2

    target = dead_rows(db)[0]["id"]
    assert agent_push.delete_dead_letter(db, target, now=T0) is True
    assert target not in [r["id"] for r in dead_rows(db)]
    assert len(dead_rows(db)) == 1, "the command removed more than the row it named"
    assert agent_push.delete_dead_letter(db, target, now=T0) is False


def test_depths_are_the_metric_lines_spec_2e_names(db, stored) -> None:
    """§2e lists `push_ok/push_failed/dead_letter_depth`; P2-05/06 read them, so they
    must be counts of rows, not of something this module invented."""
    _, rowid = stored
    assert agent_push.queue_depth(db) == 0 and agent_push.dead_letter_depth(db) == 0
    agent_push.enqueue_events(db, [rowid], endpoint=ENDPOINT, now=T0)
    assert agent_push.queue_depth(db) == 1
    agent_push.drain(db, endpoint=ENDPOINT, transport=Flaky(500), now=T0, rng=Rng(1.0))
    assert agent_push.queue_depth(db) == 1 and agent_push.dead_letter_depth(db) == 0
    agent_push.drain(db, endpoint=ENDPOINT, transport=Flaky(500), now=at(BOUND), rng=Rng(1.0))
    assert agent_push.queue_depth(db) == 0 and agent_push.dead_letter_depth(db) == 1


# -----------------------------------------------------------------------------------------
# (5) the stub ingest: stub:// appends JSONL to a local path
# -----------------------------------------------------------------------------------------


def test_stub_ingest_file_parses_as_exact_model_records(db, tmp_path) -> None:
    """DoD (5). The stub ingest is the owner-authorized stand-in for a real endpoint, and
    what it must accept is the contract: `model.EventRecord.from_jsonl` of the file
    returns the records that were pushed, equal and in order."""
    records = [make_record(serial_no=5742), make_record(serial_no=5743, employee_no="2")]
    result = agent_store.store_events(db, records, now=T0)
    path = tmp_path / "ingest" / "site-a.jsonl"
    target = f"stub://{path}"
    agent_push.enqueue_events(
        db, [result.rowids[r.serial_no] for r in records], endpoint=target, now=T0
    )
    agent_push.drain(
        db, endpoint=target, transport=agent_push.stub_transport(target), now=T0, rng=Rng()
    )
    assert from_jsonl(path.read_text(encoding="utf-8")) == records


def test_stub_transport_appends_and_never_overwrites(tmp_path) -> None:
    """An append-only ingest: a drain that truncated the file would silently delete the
    site's history on the first retry. Also pins the newline rule — a body with no
    trailing newline must not glue the next record onto the same line."""
    path = tmp_path / "ingest" / "site-a.jsonl"
    target = f"stub://{path}"
    transport = agent_push.stub_transport(target)
    assert transport(target, '{"a": 1}\n') == 200, "the stub answers like an accepting ingest"
    transport(target, '{"b": 2}')  # no trailing newline: the transport must add one
    assert path.read_text(encoding="utf-8").splitlines() == ['{"a": 1}', '{"b": 2}']


def test_stub_transport_refuses_any_other_scheme(tmp_path) -> None:
    """§3: an endpoint is never invented and never defaulted. A `https://` target aimed
    at this function must raise — writing to disk while pretending to be an HTTP push is
    how a test would go green without ever reaching an ingest."""
    with pytest.raises(agent_push.PushTargetError):
        agent_push.stub_transport("https://ingest.example.invalid/push")
    with pytest.raises(agent_push.PushTargetError):
        agent_push.stub_transport("stub://")
    with pytest.raises(agent_push.PushTargetError):
        agent_push.stub_transport("")


def test_stub_transport_creates_the_directory_it_needs(tmp_path) -> None:
    """A fresh agent box has no ingest dir; refusing to mkdir would make the very first
    push of a new site fail for a reason that has nothing to do with the payload."""
    path = tmp_path / "deep" / "nest" / "in.jsonl"
    target = f"stub://{path}"
    assert agent_push.stub_transport(target)(target, "{}\n") == 200
    assert path.exists()


def test_a_real_drain_to_the_stub_leaves_a_replayable_file(db, tmp_path, stored) -> None:
    """End-to-end inside the card's own vocabulary: push → dead-letter → replay → the
    file holds the line exactly once, and it is the stored bytes."""
    record, rowid = stored
    path = tmp_path / "ingest" / "site-a.jsonl"
    target = f"stub://{path}"
    transport = agent_push.stub_transport(target)
    agent_push.enqueue_events(db, [rowid], endpoint=target, now=T0)
    agent_push.drain(db, endpoint=target, transport=Flaky(503), now=T0, rng=Rng(1.0))
    agent_push.drain(db, endpoint=target, transport=Flaky(503), now=at(BOUND), rng=Rng(1.0))
    dead = dead_rows(db)[0]
    agent_push.replay_dead_letter(db, dead["id"], endpoint=target, now=at(BOUND + 5))
    agent_push.drain(db, endpoint=target, transport=transport, now=at(BOUND + 5), rng=Rng())
    assert path.read_text(encoding="utf-8") == to_jsonl([record])
    assert queue_rows(db) == [] and dead_rows(db) == []


# -----------------------------------------------------------------------------------------
# the log seam: ids and counts only, never a payload body
# -----------------------------------------------------------------------------------------


def test_the_log_never_carries_a_payload_body(db, stored) -> None:
    """Card RULES: "No secrets in logs (never log payload bodies; log row ids/counts
    only)". A punch line carries an employee number and a name — so this is a leak test,
    not a cosmetics test. The sink is injectable so P2-05/06 can route it."""
    record, rowid = stored
    # The canary is a payload FIELD value (an employee's name): if the drain ever logs the
    # body, it shows up here. Named "canary" rather than anything secret-shaped so the
    # repo's own hygiene regex does not read it as a credential assignment.
    canary = "User E1"
    lines: list[str] = []
    agent_push.enqueue_events(db, [rowid], endpoint=ENDPOINT, now=T0)
    for moment in (T0, at(120), at(BOUND)):
        agent_push.drain(
            db,
            endpoint=ENDPOINT,
            transport=Flaky(500),
            now=moment,
            rng=Rng(1.0),
            log=lines.append,
        )
    agent_push.enqueue_events(db, [rowid], endpoint=ENDPOINT, now=at(BOUND + 1))
    agent_push.drain(
        db,
        endpoint=ENDPOINT,
        transport=Flaky(200),
        now=at(BOUND + 1),
        rng=Rng(),
        log=lines.append,
    )
    assert lines, "there must be a log to inspect at all"
    assert not any(canary in line for line in lines), f"a payload field reached the log: {lines}"
    assert not any(one_line(record)[:32] in line for line in lines)
    assert any(str(rowid) in line for line in lines), "row ids are exactly what SHOULD be logged"


def test_a_naive_clock_is_refused_by_the_drain(db, stored) -> None:
    """DTZ at the drain seam too: `now` decides both the due-by comparison and the
    stamps, so a naive clock must be refused before the first transport call."""
    _, rowid = stored
    agent_push.enqueue_events(db, [rowid], endpoint=ENDPOINT, now=T0)
    transport = Flaky(200)
    with pytest.raises(ValueError):
        agent_push.drain(
            db,
            endpoint=ENDPOINT,
            transport=transport,
            now=NAIVE,
            rng=Rng(),
        )
    assert transport.calls == [], "the refusal must happen before anything is sent"


def test_push_is_a_named_surface_so_p2_07_can_wrap_it() -> None:
    """P2-07 wires the CLI over these exact names; the list is the contract between the
    two cards (an invented name here is a CLI that cannot be written)."""
    for name in (
        "enqueue_events",
        "drain",
        "replay_dead_letter",
        "delete_dead_letter",
        "queue_depth",
        "dead_letter_depth",
        "stub_transport",
        "dead_letter_rows",
    ):
        assert callable(getattr(agent_push, name)), name
