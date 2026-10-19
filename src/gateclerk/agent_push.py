"""The P2 site agent's outbound pusher: sqlite send buffer, backoff, dead-letter.

Card P2-04 (docs/P2-SITE-AGENT.md §2b + §2c + §3, SIGNED OFF 2026-10-19). Three pieces,
all of them the spec's, none invented:

**The queue is a buffer, not a second store.** `push_queue` rows point at stored events
(`event_id` FK, `ON DELETE RESTRICT`) and carry only send state — attempts, next_attempt,
first_failed — plus the payload bytes the drain must not have to re-derive. The store
stays the source of truth (spec §1 seam 1), so a successful push DELETEs the queue row
and leaves the event exactly where it was. `RESTRICT` rather than `CASCADE` on purpose:
a purge that outran the queue would delete an un-pushed punch with no dead-letter row to
show for it — that combination is the silent data loss this whole module exists to
prevent, so the db refuses it instead of trusting the caller.

**The dead-letter is a table in the same db** (§2b decided, not a side file), holding the
COMPLETE JSONL line plus endpoint tag, error class, attempt count and first/last-attempt
timestamps. It is keyed UNIQUE(event_id, endpoint): replay re-pushes and the UPSERT makes
that safe (the card's own words), so a row that fails again REFRESHES rather than
duplicating — a table of forty copies of one punch is an alert that lies. `first_attempt_at`
is never overwritten: it is the outage's start, which is the number the 24 h bound and a
human triage both read. Only `delete_dead_letter` removes a row (§2b: "deleted only by an
owner-run command"); the CLI subcommand is P2-07's surface.

**Backoff reuses the busy-family numbers** (§2c: base 1 s, cap 30 s — imported from
`isapi_transport`, not restated) with "equal jitter": half the window fixed, half drawn
from the injected rng. Half-fixed because a rng of 0 would otherwise schedule a retry at
this exact instant and re-hit the endpoint inside the same tick; the window is capped
before the draw, so no rng value can push a delay past 30 s. Failures keep retrying the
queue at the cap; the row leaves the queue only when `now - first_failed_at` reaches
`push_dead_letter_after_s` (P2-01's config key, passed in by the caller — the 24 h is
config, not a constant living here).

Two refusals this module owns:

* `PushTargetError` — the target is an ABSTRACT ref and is never invented or defaulted
  (§3): only `config.PUSH_TARGET_SCHEMES` (`stub://`, `https://`) are accepted, checked
  case-sensitively like P2-01's validator does.
* `QueueError` / `DeadLetterMissingError` — a queue row must point at a real stored
  event, and a replay must name a real dead-letter row. A silently-skipped id is a
  punch nobody will ever find out was never sent.

The HTTP transport is an INJECTED callable `(url, body) -> status`: this module never
imports a client and never opens a socket, and `stub_transport` (the owner-authorized
local ingest: append JSONL to a local path) is the only implementation this card ships.
"""

from __future__ import annotations

import sqlite3
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from gateclerk.config import DEFAULT_PUSH_DEAD_LETTER_AFTER_S, PUSH_TARGET_SCHEMES
from gateclerk.isapi_transport import DEFAULT_BUSY_BACKOFF_BASE, DEFAULT_BUSY_BACKOFF_CAP

__all__ = [
    "DEAD_LETTER_COLUMNS",
    "DEFAULT_PUSH_BACKOFF_BASE_S",
    "DEFAULT_PUSH_BACKOFF_CAP_S",
    "DEFAULT_PUSH_BATCH_LIMIT",
    "DEFAULT_PUSH_DEAD_LETTER_AFTER_S",
    "QUEUE_COLUMNS",
    "DeadLetter",
    "DeadLetterMissingError",
    "DrainResult",
    "HttpStatusRejectedError",
    "Pending",
    "PushError",
    "PushTargetError",
    "QueueError",
    "Transport",
    "dead_letter_depth",
    "dead_letter_rows",
    "delete_dead_letter",
    "drain",
    "enqueue_events",
    "pending_rows",
    "queue_depth",
    "replay_dead_letter",
    "stub_transport",
]

#: The pusher's backoff numbers ARE the device busy-family numbers (§2c: "reuse the
#: busy-family numbers as defaults"). Imported, not copied: the two legs of the agent
#: must not be able to drift into two different definitions of "never hammer".
DEFAULT_PUSH_BACKOFF_BASE_S = DEFAULT_BUSY_BACKOFF_BASE
DEFAULT_PUSH_BACKOFF_CAP_S = DEFAULT_BUSY_BACKOFF_CAP

#: Rows one `drain` will attempt. A drain is one tick of the agent loop; an unbounded
#: drain of a week-old backlog would run past the next poll (and past the nonce budget).
#: The rest of the backlog is still queued, due, on the next tick.
DEFAULT_PUSH_BATCH_LIMIT = 200

#: The synthetic error class for "the ingest answered a non-2xx status" (§2b wants an
#: error class on the row, and an HTTP status has no exception class of its own).
HTTP_ERROR_CLASS = "HttpStatus"


class PushError(Exception):
    """Base for pusher-level refusals."""


class PushTargetError(PushError):
    """The push target is not an accepted abstract ref (§3 — never invented, never defaulted)."""


class QueueError(PushError):
    """The queue cannot be built from what was asked: the event is not in the store."""


class DeadLetterMissingError(PushError):
    """No dead-letter row has that id: a replay must name a row that exists."""


#: The injected HTTP transport: a target ref + one JSONL body -> HTTP status. Raising is
#: the normal shape of "the internet is down" and is handled like any other failure.
Transport = Callable[[str, str], int]

#: A log sink: one pre-formatted line. Row ids and counts ONLY — never a payload body
#: (card RULES; a punch line carries an employee number and a name).
LogSink = Callable[[str], None]


@dataclass(frozen=True, slots=True)
class DrainResult:
    """What one drain did. `sent`/`retried`/`dead_lettered` are event rowids.

    `push_ok` / `push_failed` / `dead_letter_depth` are the §2e metric vocabulary: P2-05
    and P2-06 read these, so they count ROWS, not anything this module invented.
    """

    endpoint: str
    sent: tuple[int, ...] = ()
    retried: tuple[int, ...] = ()
    dead_lettered: tuple[int, ...] = ()

    @property
    def push_ok(self) -> int:
        return len(self.sent)

    @property
    def push_failed(self) -> int:
        return len(self.retried) + len(self.dead_lettered)


@dataclass(frozen=True, slots=True)
class Pending:
    """One queue row, read back (the CLI/health surface must not hand-write SQL)."""

    id: int
    event_id: int
    endpoint: str
    attempts: int
    next_attempt_at: str
    first_failed_at: str | None
    last_attempt_at: str | None
    last_error_class: str | None


@dataclass(frozen=True, slots=True)
class DeadLetter:
    """One dead-letter row: exactly what §2b demanded the table hold."""

    id: int
    event_id: int
    payload: str
    endpoint: str
    error_class: str
    attempts: int
    first_attempt_at: str
    last_attempt_at: str


# --- the schema P2-04 appends to the migration seam (v3 + v4) ------------------------------

#: The queue's own columns (the card's tuple is (rowid, payload_ref, attempts,
#: next_attempt_at, first_failed_at); the extras are the provenance §2b's dead-letter
#: needs without a second lookup, and the endpoint this buffer is aimed at).
QUEUE_COLUMNS: tuple[str, ...] = (
    "id",
    "event_id",
    "payload",
    "endpoint",
    "attempts",
    "first_failed_at",
    "last_attempt_at",
    "last_error_class",
    "next_attempt_at",
    "enqueued_at",
)

DEAD_LETTER_COLUMNS: tuple[str, ...] = (
    "id",
    "event_id",
    "payload",
    "endpoint",
    "error_class",
    "attempts",
    "first_attempt_at",
    "last_attempt_at",
)

_PUSH_QUEUE_V3 = """
CREATE TABLE push_queue (
    id INTEGER PRIMARY KEY,
    -- A send buffer POINTS at a stored event; it is not a copy of the store. RESTRICT
    -- (not CASCADE) is the load-bearing choice: deleting an event that has not been
    -- pushed yet is refused, so no purge can outrun the queue and lose a punch with no
    -- dead-letter row to account for it (spec §2b: purging is the owner's, and it must
    -- not be able to do this by accident).
    event_id INTEGER NOT NULL REFERENCES events(id) ON DELETE RESTRICT,
    -- The bytes to send, read from events.jsonl at enqueue time: the drain must not
    -- re-derive the payload (that would put a serialisation step on the send path, and
    -- P2-02 proved the stored line IS to_jsonl() verbatim).
    payload TEXT NOT NULL,
    endpoint TEXT NOT NULL,
    attempts INTEGER NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    -- The 24 h clock starts at the FIRST failure and survives a re-enqueue: it measures
    -- the outage, not the age of this row.
    first_failed_at TEXT,
    last_attempt_at TEXT,
    last_error_class TEXT,
    -- Due when this is <= now. `attempts + next_attempt_at` IS the backoff: the drain
    -- never sleeps, it just finds what is due (an agent that sleeps 30 s would miss the
    -- next poll window; SIGTERM would interrupt the sleep anyway).
    next_attempt_at TEXT NOT NULL,
    enqueued_at TEXT NOT NULL,
    -- One buffer per (event, target): the overlap poll re-stores the same events every
    -- 5 minutes and must not grow a second row per poll (that is a duplicate push).
    UNIQUE (event_id, endpoint)
);

-- The drain's query shape is (endpoint, due-by): without this index every 5-min tick
-- scans the whole backlog.
CREATE INDEX push_queue_due ON push_queue (endpoint, next_attempt_at);
"""

_DEAD_LETTER_V4 = """
CREATE TABLE dead_letter (
    id INTEGER PRIMARY KEY,
    -- No FK here, deliberately: the dead-letter row must OUTLIVE the event row (it is
    -- the record of what could not be sent, and §2b says it is deleted only by the
    -- owner's command), and a payload-carrying row does not need a parent to be
    -- readable. `event_id` stays for the triage join.
    event_id INTEGER NOT NULL,
    -- §2b: the COMPLETE JSONL payload line, so a replay needs nothing but this table.
    payload TEXT NOT NULL,
    endpoint TEXT NOT NULL,
    error_class TEXT NOT NULL,
    attempts INTEGER NOT NULL CHECK (attempts >= 1),
    first_attempt_at TEXT NOT NULL,
    last_attempt_at TEXT NOT NULL,
    -- "replay = re-push, UPSERT makes it safe" (spec §2b): re-failing a replay REFRESHES
    -- this row instead of duplicating it, so the depth is a count of distinct pushes.
    UNIQUE (event_id, endpoint)
);

CREATE INDEX dead_letter_endpoint ON dead_letter (endpoint);
"""

# --- helpers --------------------------------------------------------------------------------


def _stamp(moment: datetime) -> str:
    """ISO-8601 in UTC, second resolution — the same shape agent_store stamps with."""
    if moment.tzinfo is None:
        raise ValueError("push timestamps must be tz-aware (payroll data; pyproject DTZ)")
    return moment.astimezone(UTC).isoformat(timespec="seconds")


def _parse(stored: str) -> datetime:
    """Read back one of this module's own stamps (always aware, always UTC)."""
    return datetime.fromisoformat(stored)


def _check_endpoint(endpoint: str, *, what: str) -> None:
    """Refuse any target outside `PUSH_TARGET_SCHEMES` (§3), case-sensitively.

    Same policy as P2-01's config validator: `HTTPS://` is a mistake worth a loud error,
    and `ftp://`/`file://`/scheme-less are exactly the shapes that would turn "abstract
    ingest ref" into an endpoint someone invented at 2 a.m.
    """
    if not endpoint.startswith(PUSH_TARGET_SCHEMES):
        allowed = " or ".join(PUSH_TARGET_SCHEMES)
        raise PushTargetError(
            f"{what} {endpoint!r} has an unacceptable scheme: a push target must start "
            f"with {allowed} (docs/P2-SITE-AGENT.md §3 — never invented, never defaulted)"
        )


def _error_class(outcome: int | BaseException) -> str:
    """§2b's "error class": the exception's class name, or `HttpStatus<code>`.

    The status is folded INTO the name deliberately: `HttpStatusRejected` tells an owner
    nothing about whether to wait for the ingest or fix our payload, and §2b asks for one
    column, not a column plus a detail column.
    """
    if isinstance(outcome, HttpStatusRejectedError):
        return f"{HTTP_ERROR_CLASS}{outcome.status}"
    if isinstance(outcome, BaseException):
        return type(outcome).__name__
    return f"{HTTP_ERROR_CLASS}{outcome}"


def _draw(rng: Callable[[], float]) -> float:
    """One jitter draw, forced into [0, 1].

    A guard, not a courtesy: the caller normally passes `random.random`, but the rng is
    injectable on purpose (the tests need a pinned sequence), and a draw outside [0, 1]
    would scale the delay outside the window — under 1 s, or past the 30 s cap §2c names.
    A delay past the cap on EVERY failure also pushes the retry out past the 24 h bound,
    which would silently disable dead-lettering: the worst failure an rng could cause.
    """
    return min(1.0, max(0.0, float(rng())))


def _backoff_delay_s(
    attempts: int,
    rng: Callable[[], float],
    *,
    base_s: float,
    cap_s: float,
) -> float:
    """Seconds to wait after failure number `attempts` (1-based): equal jitter.

    `window = min(base * 2**(attempts-1), cap)` — the busy-family ladder — and the
    actual delay is half the window plus half drawn from `rng`. Half-fixed so the worst
    rng draw cannot schedule a retry at this same instant (the next drain in the tick
    would hammer the endpoint, which is the rule §1 seam 9 exists for); the cap is
    applied BEFORE the draw, so no rng value can exceed it. The rng is drawn exactly
    once per failed row and never on a success.

    The 1 s floor is not decoration: stamps are second-resolution, so a delay under 1 s
    would round INTO the current second and the row would still be `next_attempt_at <=
    now` on the next drain — an immediate re-hit of an endpoint that just failed, which is
    the "never hammer" rule (§1 seam 9) broken by arithmetic rather than by intent.
    """
    window = min(base_s * (2.0 ** (attempts - 1)), cap_s)
    return max(1.0, window * (0.5 + 0.5 * _draw(rng)))


# --- enqueue: building the buffer FROM the store --------------------------------------------


def enqueue_events(
    conn: sqlite3.Connection,
    event_ids: Iterable[int],
    *,
    endpoint: str,
    now: datetime,
) -> tuple[int, ...]:
    """Queue stored events for `endpoint`; returns the queue row ids.

    Payload bytes come from `events.jsonl` in the INSERT's SELECT — the caller hands over
    rowids, never bodies, so the store stays the source of truth (card SEMANTICS).

    Idempotent on (event_id, endpoint): a re-enqueue refreshes the payload (an event whose
    bytes were revised by an overlap poll must not stay unsent) and PRESERVES the retry
    state — attempts and `first_failed_at` are the outage history, and re-polling an
    overlap window must not be able to reset a 24 h failure clock.
    """
    _check_endpoint(endpoint, what="push target")
    stamp = _stamp(now)
    ids: list[int] = []
    conn.execute("BEGIN IMMEDIATE")
    try:
        for event_id in event_ids:
            exists = conn.execute("SELECT 1 FROM events WHERE id = ?", (event_id,)).fetchone()
            if exists is None:
                raise QueueError(
                    f"cannot queue event id {event_id}: no such row in `events`. The "
                    "store is the source of truth — store the record first and queue "
                    "the rowid the StoreResult reported (or the digest of the key you "
                    "actually stored)."
                )
            conn.execute(
                """
                INSERT INTO push_queue (
                    id, event_id, payload, endpoint, attempts,
                    first_failed_at, last_attempt_at, last_error_class,
                    next_attempt_at, enqueued_at
                )
                SELECT NULL, events.id, events.jsonl, ?, 0,
                       NULL, NULL, NULL, ?, ?
                  FROM events WHERE events.id = ?
                ON CONFLICT(event_id, endpoint) DO UPDATE
                SET payload = excluded.payload
                RETURNING id
                """,
                (endpoint, stamp, stamp, event_id),
            ).fetchone()
            row = conn.execute(
                "SELECT id FROM push_queue WHERE event_id = ? AND endpoint = ?",
                (event_id, endpoint),
            ).fetchone()
            ids.append(row["id"])
    except BaseException:
        conn.execute("ROLLBACK")
        raise
    conn.execute("COMMIT")
    return tuple(ids)


# --- drain: the retry loop (one tick) ---------------------------------------------------------


def drain(
    conn: sqlite3.Connection,
    *,
    endpoint: str,
    transport: Transport,
    now: datetime,
    rng: Callable[[], float],
    dead_letter_after_s: int = DEFAULT_PUSH_DEAD_LETTER_AFTER_S,
    base_s: float = DEFAULT_PUSH_BACKOFF_BASE_S,
    cap_s: float = DEFAULT_PUSH_BACKOFF_CAP_S,
    limit: int = DEFAULT_PUSH_BATCH_LIMIT,
    log: LogSink | None = None,
) -> DrainResult:
    """Push every due row for `endpoint`; back off, or dead-letter, whatever fails.

    Due means `next_attempt_at <= now` for THIS endpoint — rows aimed at another target
    are left alone (§2d: push target is per site), and a row that is not due is not sent
    even by one second (§1 seam 9: never hammer). `now` and `rng` are injected so the
    1→30 s ladder and the 24 h bound are testable at second resolution; the agent passes
    its clock and `random.random`.

    Each row is its own transaction and its own transport call, so one poison row cannot
    wedge the rows behind it (the spec's "keep retrying the queue" only means something
    if a failure is not allowed to stop the drain). Success DELETEs the queue row and any
    dead-letter row for the same key — the store keeps the event either way.
    """
    stamp = _stamp(now)
    rows = conn.execute(
        "SELECT id, event_id, payload, attempts, first_failed_at FROM push_queue"
        " WHERE endpoint = ? AND next_attempt_at <= ? ORDER BY next_attempt_at, id LIMIT ?",
        (endpoint, stamp, max(1, int(limit))),
    ).fetchall()

    sent: list[int] = []
    retried: list[int] = []
    dead_lettered: list[int] = []
    for row in rows:
        outcome = _call_transport(transport, endpoint, row["payload"])
        if isinstance(outcome, int):
            _mark_sent(conn, queue_id=row["id"], event_id=row["event_id"], endpoint=endpoint)
            sent.append(row["event_id"])
            continue

        attempts = row["attempts"] + 1
        first_failed_at = _note_failure(conn, row, attempts, outcome, now, stamp)
        elapsed = (now - _parse(first_failed_at)).total_seconds()
        if elapsed >= dead_letter_after_s:
            _move_to_dead_letter(
                conn,
                row,
                event_id=row["event_id"],
                payload=row["payload"],
                endpoint=endpoint,
                attempts=attempts,
                error_class=_error_class(outcome),
                first_failed_at=first_failed_at,
                last_attempt=stamp,
            )
            dead_lettered.append(row["event_id"])
        else:
            delay = _backoff_delay_s(attempts, rng, base_s=base_s, cap_s=cap_s)
            conn.execute("BEGIN IMMEDIATE")
            try:
                conn.execute(
                    "UPDATE push_queue SET next_attempt_at = ? WHERE id = ?",
                    (_stamp(now + timedelta(seconds=round(delay, 3))), row["id"]),
                )
            except BaseException:
                conn.execute("ROLLBACK")
                raise
            conn.execute("COMMIT")
            retried.append(row["event_id"])

    if log is not None:
        log(
            f"push drain: sent={len(sent)} retried={len(retried)} "
            f"dead_lettered={len(dead_lettered)} "
            f"ids={sorted(set(sent) | set(retried) | set(dead_lettered))}"
        )
    return DrainResult(
        endpoint=endpoint,
        sent=tuple(sent),
        retried=tuple(retried),
        dead_lettered=tuple(dead_lettered),
    )


class HttpStatusRejectedError(Exception):
    """The ingest answered a non-2xx status: the line was NOT accepted.

    Carries the status because §2b wants the error class on the dead-letter row and an
    operator reading `HttpStatus503` knows whether to wait for the ingest or fix our
    payload — the bare class name would not tell them which.
    """

    def __init__(self, status: int, *args: object) -> None:
        super().__init__(f"the ingest answered {status}", *args)
        self.status = status


def _call_transport(transport: Transport, endpoint: str, payload: str) -> int | Exception:
    """One send attempt. A raised exception is a failure with a class, not a crash.

    The payload goes out as one JSONL line (newline-terminated so the ingest can append
    batches without gluing two records together — `model.to_jsonl`'s own guarantee).
    """
    try:
        status = transport(endpoint, f"{payload}\n")
    except Exception as exc:  # the transport is injected: anything it raises means
        return exc  # "not accepted", and one bad row must not break the whole drain.
    return status if 200 <= status < 300 else HttpStatusRejectedError(status)


def _note_failure(
    conn: sqlite3.Connection,
    row: sqlite3.Row,
    attempts: int,
    outcome: int | BaseException,
    now: datetime,
    stamp: str,
) -> str:
    """Record a failed attempt; return the (possibly newly set) first-failure stamp.

    `first_failed_at` is written by the FIRST failure and never moved afterwards: it is
    the start of the continuous-failure span §2c measures the 24 h bound against. The
    `COALESCE` keeps that true even if a racing writer got here first.
    """
    error_class = _error_class(outcome)
    conn.execute("BEGIN IMMEDIATE")
    try:
        conn.execute(
            """
            UPDATE push_queue
               SET attempts = ?,
                   first_failed_at = COALESCE(first_failed_at, ?),
                   last_attempt_at = ?,
                   last_error_class = ?
             WHERE id = ?
            """,
            (attempts, stamp, stamp, error_class, row["id"]),
        )
    except BaseException:
        conn.execute("ROLLBACK")
        raise
    conn.execute("COMMIT")
    return row["first_failed_at"] or stamp


def _mark_sent(conn: sqlite3.Connection, *, queue_id: int, event_id: int, endpoint: str) -> None:
    """Success: DELETE the buffer row and any dead-letter row for the same key.

    One transaction, so a kill cannot leave the event dead-lettered *and* delivered. The
    events row is untouched — the queue is transient, the store is the truth.
    """
    conn.execute("BEGIN IMMEDIATE")
    try:
        conn.execute("DELETE FROM push_queue WHERE id = ?", (queue_id,))
        conn.execute(
            "DELETE FROM dead_letter WHERE event_id = ? AND endpoint = ?",
            (event_id, endpoint),
        )
    except BaseException:
        conn.execute("ROLLBACK")
        raise
    conn.execute("COMMIT")


def _move_to_dead_letter(
    conn: sqlite3.Connection,
    row: sqlite3.Row,
    *,
    event_id: int,
    payload: str,
    endpoint: str,
    attempts: int,
    error_class: str,
    first_failed_at: str,
    last_attempt: str,
) -> None:
    """Dead-letter the row and drain the queue behind it, in ONE transaction.

    The UPSERT keeps the row's identity stable (`first_attempt_at` and the id are not
    overwritten) so the owner can cite one row across replays; the queue DELETE is in the
    same transaction because a poison row left in the queue is a drain that loops on it
    forever instead of continuing to push the healthy events behind it.
    """
    conn.execute("BEGIN IMMEDIATE")
    try:
        conn.execute(
            """
            INSERT INTO dead_letter (
                id, event_id, payload, endpoint, error_class,
                attempts, first_attempt_at, last_attempt_at
            ) VALUES (NULL, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(event_id, endpoint) DO UPDATE
            SET payload = excluded.payload,
                error_class = excluded.error_class,
                attempts = excluded.attempts,
                last_attempt_at = excluded.last_attempt_at
            """,
            (event_id, payload, endpoint, error_class, attempts, first_failed_at, last_attempt),
        )
        conn.execute("DELETE FROM push_queue WHERE id = ?", (row["id"],))
    except BaseException:
        conn.execute("ROLLBACK")
        raise
    conn.execute("COMMIT")


# --- replay + the owner's delete command -------------------------------------------------------


def replay_dead_letter(
    conn: sqlite3.Connection,
    dead_letter_id: int,
    *,
    endpoint: str | None = None,
    now: datetime,
) -> int:
    """Re-queue one dead-letter row for another push; returns the queue row id.

    `endpoint` defaults to the target the row failed against (§2b's "replay = re-push"),
    and may be overridden when the ingest has moved. The retry state is carried over —
    attempts continue and `first_failed_at` stays the original outage start, so a replay
    into an endpoint that is still down dead-letters again promptly instead of buying a
    fresh 24 hours. Replaying twice (or while the row is somehow still queued) is safe:
    the queue's UNIQUE(event_id, endpoint) means one buffer, one send.

    The dead-letter row itself STAYS until a push of that key succeeds: a replay that has
    not yet been accepted is not evidence the owner can delete the payload by.
    """
    row = conn.execute("SELECT * FROM dead_letter WHERE id = ?", (dead_letter_id,)).fetchone()
    if row is None:
        raise DeadLetterMissingError(
            f"no dead_letter row with id {dead_letter_id}: nothing to replay. List them "
            "with `dead_letter_rows` (P2-07's `gateclerk dead-letter list`)."
        )
    target = row["endpoint"] if endpoint is None else endpoint
    _check_endpoint(target, what="push target")
    stamp = _stamp(now)
    conn.execute("BEGIN IMMEDIATE")
    try:
        conn.execute(
            """
            INSERT INTO push_queue (
                id, event_id, payload, endpoint, attempts,
                first_failed_at, last_attempt_at, last_error_class,
                next_attempt_at, enqueued_at
            )
            SELECT NULL, event_id, payload, ?, attempts,
                   first_attempt_at, last_attempt_at, error_class, ?, ?
              FROM dead_letter WHERE id = ?
            ON CONFLICT(event_id, endpoint) DO UPDATE
            SET payload = excluded.payload
            """,
            (target, stamp, stamp, dead_letter_id),
        )
        queued = conn.execute(
            "SELECT id FROM push_queue WHERE event_id = ? AND endpoint = ?",
            (row["event_id"], target),
        ).fetchone()
    except BaseException:
        conn.execute("ROLLBACK")
        raise
    conn.execute("COMMIT")
    return queued["id"]


def delete_dead_letter(
    conn: sqlite3.Connection, dead_letter_id: int, *, now: datetime | None = None
) -> bool:
    """The owner command that removes one dead-letter row; True when it removed something.

    This is the ONLY code path that deletes from `dead_letter` (§2b) — no drain, no
    re-enqueue, no success of another row may touch the table, and no TTL lives here. It
    reports whether the id existed because an owner typo must not look like a success:
    the payload is the only copy of a punch that never reached the ingest.

    `now` is optional because the removal needs no timestamp; a caller that has a clock
    should pass it so the log line is pinned rather than wall-clock.
    """
    row = conn.execute(
        "SELECT event_id FROM dead_letter WHERE id = ?", (dead_letter_id,)
    ).fetchone()
    conn.execute("BEGIN IMMEDIATE")
    try:
        conn.execute("DELETE FROM dead_letter WHERE id = ?", (dead_letter_id,))
    except BaseException:
        conn.execute("ROLLBACK")
        raise
    conn.execute("COMMIT")
    if row is None:
        return False
    _ = now  # accepted for call-site symmetry with the other owner commands
    return True


# --- read seams (P2-05's gauge, P2-07's CLI) ---------------------------------------------------


def queue_depth(conn: sqlite3.Connection) -> int:
    """Rows waiting to go out (§2e's backlog gauge)."""
    return conn.execute("SELECT COUNT(*) FROM push_queue").fetchone()[0]


def dead_letter_depth(conn: sqlite3.Connection) -> int:
    """§2e's `dead_letter_depth`: distinct pushes the owner has not cleared. The
    UPSERT-on-replay is what makes this a count of pushes and not a count of attempts."""
    return conn.execute("SELECT COUNT(*) FROM dead_letter").fetchone()[0]


def pending_rows(
    conn: sqlite3.Connection, *, endpoint: str | None = None, limit: int = DEFAULT_PUSH_BATCH_LIMIT
) -> tuple[Pending, ...]:
    """The queue, due-first — payload deliberately NOT included (a CLI table that prints
    payloads is how payroll fields end up on a terminal)."""
    sql = (
        "SELECT id, event_id, endpoint, attempts, next_attempt_at, first_failed_at,"
        " last_attempt_at, last_error_class FROM push_queue"
    )
    args: list[Any] = []
    if endpoint is not None:
        sql += " WHERE endpoint = ?"
        args.append(endpoint)
    sql += " ORDER BY next_attempt_at, id LIMIT ?"
    args.append(max(1, int(limit)))
    return tuple(
        Pending(
            id=row["id"],
            event_id=row["event_id"],
            endpoint=row["endpoint"],
            attempts=row["attempts"],
            next_attempt_at=row["next_attempt_at"],
            first_failed_at=row["first_failed_at"],
            last_attempt_at=row["last_attempt_at"],
            last_error_class=row["last_error_class"],
        )
        for row in conn.execute(sql, args)
    )


def dead_letter_rows(
    conn: sqlite3.Connection, *, endpoint: str | None = None, limit: int = DEFAULT_PUSH_BATCH_LIMIT
) -> tuple[DeadLetter, ...]:
    """The dead letters, oldest outage first — the triage list the owner reads."""
    sql = (
        "SELECT id, event_id, payload, endpoint, error_class, attempts,"
        " first_attempt_at, last_attempt_at FROM dead_letter"
    )
    args: list[Any] = []
    if endpoint is not None:
        sql += " WHERE endpoint = ?"
        args.append(endpoint)
    sql += " ORDER BY first_attempt_at, id LIMIT ?"
    args.append(max(1, int(limit)))
    return tuple(
        DeadLetter(
            id=row["id"],
            event_id=row["event_id"],
            payload=row["payload"],
            endpoint=row["endpoint"],
            error_class=row["error_class"],
            attempts=row["attempts"],
            first_attempt_at=row["first_attempt_at"],
            last_attempt_at=row["last_attempt_at"],
        )
        for row in conn.execute(sql, args)
    )


# --- the stub ingest (§3: the abstract target, made real locally) ----------------------------


def stub_transport(target: str) -> Transport:
    """A transport that appends the JSONL body to a local file: `stub://<path>`.

    This is the owner-authorized local ingest (card + spec §3) and the only ingest this
    card ships — it exists so the pusher, its tests and an operator's dry run all exercise
    the REAL payload path against something that is not an invented endpoint. It writes
    the bytes it was handed (append-only: truncating would delete the site's history on
    the first retry) and answers 200, which is the whole contract `drain` relies on.

    The scheme check is not decoration: aimed at an `https://` target it must REFUSE, or
    a test could go green by writing to disk while believing it pushed to an ingest.
    """
    if not target.startswith("stub://"):
        raise PushTargetError(
            f"stub ingest cannot serve {target!r}: a stub target is `stub://<local path>`. "
            "https:// targets need a real transport, and this repo does not invent "
            "endpoints (docs/P2-SITE-AGENT.md §3)."
        )
    remainder = target[len("stub://") :].strip()
    if not remainder:
        raise PushTargetError("stub target names no path: use stub://</path/to/ingest.jsonl>")
    path = Path(remainder)

    def send(url: str, body: str) -> int:
        # `url` is the target ref the drain passes to every transport; a stub writes to
        # the path baked in here, so the argument is intentionally unused.
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a", encoding="utf-8") as handle:
            handle.write(body if body.endswith("\n") else f"{body}\n")
        return 200

    return send
