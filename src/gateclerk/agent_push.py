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

The HTTP transport is an INJECTED callable `(url, body) -> status`. P2-04 shipped only
`stub_transport` (the owner-authorized local ingest: append JSONL to a local path);
Task 15 adds the real one, `https_transport` — and it is still the same injected
seam, so the queue, the backoff ladder and the dead-letter machinery above are
untouched by the switch (test_t15 pins that: the same `drain` accepts either).

Task 15 (spec §7, the merged `gateclerk_ingest` function is the frozen contract):

    POST <push_target>                      Content-Type: application/jsonl
    Authorization: Bearer *** ingest token>     401 absent/unknown/revoked
    X-GateClerk-Site: <SITE>                        CONFIRMS the token's site only;
                                                  a contradicting claim is 403 there

The bearer DETERMINES the site server-side, so it is resolved PER SITE with no global
fallback rung — explicit token > env `GATECLERK_INGEST_TOKEN_<SITE>` > keychain service
`gateclerk-ingest-<site>` (account = site) — and it is held only as a `secrets.Secret`:
repr/str of the transport, every message this module raises about it, and every column
of `push_queue`/`dead_letter` are token-free by construction (`test_token_never_logged`).
A missing token is a loud refusal naming the `security add-generic-password` command,
never a header-less send: an unauthenticated POST is a 401 and a punch in the dead-
letter queue for reasons the owner could have fixed at install time.
"""

from __future__ import annotations

import re
import sqlite3
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from gateclerk.config import (
    DEFAULT_PUSH_DEAD_LETTER_AFTER_S,
    SINK_REF_SCHEMES,
    DeviceTarget,
    KeychainReader,
)
from gateclerk.credentials import (
    INGEST_REF_PREFIX,
    INGEST_TOKEN_ENV_PREFIX,
    resolve_ingest_token,
)
from gateclerk.exceptions import CredentialUnavailable
from gateclerk.isapi_transport import DEFAULT_BUSY_BACKOFF_BASE, DEFAULT_BUSY_BACKOFF_CAP
from gateclerk.model import UserRecord
from gateclerk.secrets import Secret, redact
from gateclerk.sinks import IMPLICIT_SINK_NAME, sink_name_problem

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
    "HttpsIngestTransport",
    "IngestTokenUnavailableError",
    "Pending",
    "PushError",
    "PushTargetError",
    "QueueError",
    "Transport",
    "dead_letter_depth",
    "dead_letter_rows",
    "delete_dead_letter",
    "device_users_line",
    "drain",
    "enqueue_events",
    "https_transport",
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

#: The one sink-name shape the config cannot produce but the storage layer must accept:
#: the v5/v6 migration mints `legacy+<rowid>` for a pre-upgrade event that had been
#: buffered against two targets (see `agent_db`), and the `+` keeps it from ever colliding
#: with — or being confused for — a configured sink name.
_MIGRATED_SINK_NAME = re.compile(r"^legacy\+[0-9]+$")


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
    `sink_name` (SINKS-CORE) names the sink this drain served — one per configured sink,
    so a per-sink backlog can be reported instead of one blended number.
    """

    endpoint: str
    sink_name: str = IMPLICIT_SINK_NAME
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
    """One queue row, read back (the CLI/health surface must not hand-write SQL).

    `sink_name` (SINKS-CORE) is the row's identity — which configured sink it belongs to;
    `endpoint` is the ref the row was aimed at when it was queued, kept for triage.
    """

    id: int
    event_id: int
    sink_name: str
    endpoint: str
    attempts: int
    next_attempt_at: str
    first_failed_at: str | None
    last_attempt_at: str | None
    last_error_class: str | None


@dataclass(frozen=True, slots=True)
class DeadLetter:
    """One dead-letter row: exactly what §2b demanded the table hold (+ the sink)."""

    id: int
    event_id: int
    payload: str
    sink_name: str
    endpoint: str
    error_class: str
    attempts: int
    first_attempt_at: str
    last_attempt_at: str


# --- the schema P2-04 appends to the migration seam (v3 + v4) ------------------------------

#: The queue's own columns (the card's tuple is (rowid, payload_ref, attempts,
#: next_attempt_at, first_failed_at); the extras are the provenance §2b's dead-letter
#: needs without a second lookup, and — since SINKS-CORE — the SINK this buffer belongs
#: to. `endpoint` stayed as provenance: the ref a row actually failed against is not
#: necessarily today's configured ref).
QUEUE_COLUMNS: tuple[str, ...] = (
    "id",
    "event_id",
    "payload",
    "sink_name",
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
    "sink_name",
    "endpoint",
    "error_class",
    "attempts",
    "first_attempt_at",
    "last_attempt_at",
)

# The queue/dead-letter DDL lives in `gateclerk.agent_db.MIGRATIONS` (v3 + v4, rebuilt
# per-sink by v5 + v6) — this module reads those tables, it does not declare them.
# `QUEUE_COLUMNS` / `DEAD_LETTER_COLUMNS` above are the read-side contract.


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
    """Refuse any target outside `SINK_REF_SCHEMES` (§3), case-sensitively.

    Same policy as P2-01's config validator: `HTTPS://` is a mistake worth a loud error,
    and `ftp://`/scheme-less are exactly the shapes that would turn "abstract ingest ref"
    into an endpoint someone invented at 2 a.m.

    SINKS-CORE widens the queue's accepted set by `file://` (see `config.SINK_REF_SCHEMES`)
    because a csv/jsonl sink's ref is a local path, and the storage layer must be able to
    hold a row for it. That is not §3 loosening: `push_target` still refuses `file://`
    (config's own `_push_target_problem` keeps `PUSH_TARGET_SCHEMES`), and a `file://` ref
    can only be MINTED by the sink registry from a validated absolute, traversal-free path
    — so no config can put one here by hand.
    """
    if not endpoint.startswith(SINK_REF_SCHEMES):
        allowed = " or ".join(SINK_REF_SCHEMES)
        raise PushTargetError(
            f"{what} {endpoint!r} has an unacceptable scheme: a push target must start "
            f"with {allowed} (docs/P2-SITE-AGENT.md §3 — never invented, never defaulted)"
        )


def _check_sink_name(sink_name: str) -> None:
    """Refuse a sink identity the config could never have produced (SINKS-CORE).

    The name is a queue KEY (`UNIQUE (event_id, sink_name)`), a log-line token and the
    value of the CSV `sink_name` column, so it keeps the config's identifier rule rather
    than absorbing whatever a caller passes. Without it a row could be written under a
    name no configured sink can ever select — a punch that is queued, counted, and
    unreachable forever, which is exactly the silent loss this module refuses elsewhere.

    `legacy+<n>` is the one shape outside the identifier rule that is legal here: the v5/v6
    migrations mint it for a pre-upgrade event that was buffered against two targets (see
    `agent_db`), so the storage layer accepts it and nothing else.
    """
    if _MIGRATED_SINK_NAME.match(sink_name or ""):
        return
    problem = sink_name_problem(sink_name)
    if problem is not None:
        raise QueueError(f"{problem} — a row keyed on an unusable name can never be drained")


def _error_class(outcome: BaseException) -> str:
    """§2b's "error class": the exception's class name, or `HttpStatus<code>`.

    The status is folded INTO the name deliberately: the bare class name tells an owner
    nothing about whether to wait for the ingest or fix our payload, and §2b asks for one
    column, not a column plus a detail column. Every failure reaches here as an exception
    (a non-2xx status is wrapped in `HttpStatusRejectedError` by `_call_transport`), so a
    bare status can never arrive as an int.
    """
    if isinstance(outcome, HttpStatusRejectedError):
        return f"{HTTP_ERROR_CLASS}{outcome.status}"
    return type(outcome).__name__


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
    sink_name: str = IMPLICIT_SINK_NAME,
) -> tuple[int, ...]:
    """Queue stored events for one sink; returns the queue row ids.

    Payload bytes come from `events.jsonl` in the INSERT's SELECT — the caller hands over
    rowids, never bodies, so the store stays the source of truth (card SEMANTICS).

    `sink_name` is the row's IDENTITY (SINKS-CORE) and `endpoint` the physical ref it is
    aimed at. Both default to the site's single legacy sink (`IMPLICIT_SINK_NAME` + the
    ref the caller supplies), which is what keeps `agent_cli`'s existing
    `endpoint=site.push_target` call working unchanged for a `push_target`-only site —
    the storage half of "zero config change at upgrade".

    Idempotent on (event_id, sink_name): a re-enqueue refreshes the payload (an event whose
    bytes were revised by an overlap poll must not stay unsent) and PRESERVES the retry
    state — attempts and `first_failed_at` are the outage history, and re-polling an
    overlap window must not be able to reset a 24 h failure clock. Two sinks of one site
    each get their own row for the same event, each with its own clock.
    """
    _check_endpoint(endpoint, what="push target")
    _check_sink_name(sink_name)
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
                    id, event_id, payload, sink_name, endpoint, attempts,
                    first_failed_at, last_attempt_at, last_error_class,
                    next_attempt_at, enqueued_at
                )
                SELECT NULL, events.id, events.jsonl, ?, ?, 0,
                       NULL, NULL, NULL, ?, ?
                  FROM events WHERE events.id = ?
                ON CONFLICT(event_id, sink_name) DO UPDATE
                SET payload = excluded.payload, endpoint = excluded.endpoint
                RETURNING id
                """,
                (sink_name, endpoint, stamp, stamp, event_id),
            ).fetchone()
            row = conn.execute(
                "SELECT id FROM push_queue WHERE event_id = ? AND sink_name = ?",
                (event_id, sink_name),
            ).fetchone()
            ids.append(row["id"])
    except BaseException:
        conn.execute("ROLLBACK")
        raise
    conn.execute("COMMIT")
    return tuple(ids)


# --- drain: the retry loop (one tick) ---------------------------------------------------------


def default_row_meta(event_id: int, sink_name: str, enqueued_at: str) -> dict[str, str]:
    """The envelope a rendering sink's row is built from — the queue's own three fields.

    `enqueued_at` is the QUEUE row's stamp, not "now": after a two-day outage a reader of a
    csv archive can still tell queue lag from event time, which is the only reason the
    column exists. `sink_name` is the row's identity as stored, so a `legacy+<n>` row
    migrated by v5/v6 reports the name it was queued under rather than today's configured
    name (a row that lied about which sink served it would be unattributable forever).
    """
    return {"event_id": str(event_id), "sink_name": sink_name, "enqueued_at": enqueued_at}


#: The callable shape `drain` hands a rendering transport: the queue row's facts.
RowMeta = Callable[[int, str, str], Mapping[str, str]]


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
    sink_name: str = IMPLICIT_SINK_NAME,
    row_meta: RowMeta | None = None,
) -> DrainResult:
    """Push every due row for one sink; back off, or dead-letter, whatever fails.

    Due means `next_attempt_at <= now` for THIS sink — rows belonging to another sink are
    left alone (one sink's outage must not stall another's, and §2d's per-site isolation
    is now per-sink), and a row that is not due is not sent even by one second (§1 seam 9:
    never hammer). `now` and `rng` are injected so the 1→30 s ladder and the 24 h bound are
    testable at second resolution; the agent passes its clock and `random.random`.

    `sink_name` defaults to the implicit legacy sink, and rows are matched on `endpoint` as
    well: the legacy caller (which passes only `endpoint=site.push_target`) must not start
    draining a row another sink owns, and a pre-upgrade row whose ref was rewritten by a
    config edit stays exactly as unreachable as it was before the upgrade — never silently
    sent somewhere else.

    Each row is its own transaction and its own transport call, so one poison row cannot
    wedge the rows behind it (the spec's "keep retrying the queue" only means something
    if a failure is not allowed to stop the drain). Success DELETEs the queue row and any
    dead-letter row for the same key — the store keeps the event either way.

    What a failure COSTS depends on what the failure was: a permanent payload rejection
    (`PERMANENT_REJECT_STATUSES` — 400, 422) dead-letters on the FIRST failure because a line
    the ingest will never accept is not an outage and re-sending it for a day only spends the
    site's request budget; a transient one (a 5xx, a raised network error) keeps the 24 h bound
    and the jitter ladder; and 401/403 keep retrying, because those are credential problems
    that `HttpsIngestTransport`'s token re-read can heal without a restart.

    `row_meta` (SINKS-WIRING) is the queue's side of the file sinks' contract: a transport
    that declares `renders_rows = True` is handed the row's own facts (`event_id`,
    `sink_name`, `enqueued_at`) and turns them plus the stored payload into the line it
    writes, because the sink's FORMAT is the sink's business and this module holds no
    type-specific branch. A render failure is a row failure — the same backoff, the same
    error class, the same eventual dead-letter — never a skip: `default_row_meta` is the
    default so a caller that does not care still gets the documented columns. A transport
    that declares nothing (the stub transport, the https transport, every test fake) is
    called with the payload exactly as before, newline and all.
    """
    stamp = _stamp(now)
    _check_sink_name(sink_name)
    meta_for: RowMeta = row_meta if row_meta is not None else default_row_meta
    rows = conn.execute(
        "SELECT id, event_id, payload, attempts, first_failed_at, enqueued_at FROM push_queue"
        " WHERE sink_name = ? AND endpoint = ? AND next_attempt_at <= ?"
        " ORDER BY next_attempt_at, id LIMIT ?",
        (sink_name, endpoint, stamp, max(1, int(limit))),
    ).fetchall()

    sent: list[int] = []
    retried: list[int] = []
    dead_lettered: list[int] = []
    for row in rows:
        outcome = _send_row(transport, endpoint, row, sink_name=sink_name, meta_for=meta_for)
        if isinstance(outcome, int):
            _mark_sent(
                conn,
                queue_id=row["id"],
                event_id=row["event_id"],
                sink_name=sink_name,
            )
            sent.append(row["event_id"])
            continue

        attempts = row["attempts"] + 1
        # The outage clock is decided BEFORE the write: it is the row's existing stamp, or
        # this instant when this is the first failure. Deciding it here (rather than after
        # a write) is what lets the failure and its reschedule land in ONE transaction.
        first_failed_at = row["first_failed_at"] or stamp
        elapsed = (now - _parse(first_failed_at)).total_seconds()
        permanent = (
            isinstance(outcome, HttpStatusRejectedError)
            and outcome.status in PERMANENT_REJECT_STATUSES
        )
        if elapsed >= dead_letter_after_s or permanent:
            _move_to_dead_letter(
                conn,
                row,
                event_id=row["event_id"],
                payload=row["payload"],
                sink_name=sink_name,
                endpoint=endpoint,
                attempts=attempts,
                error_class=_error_class(outcome),
                first_failed_at=first_failed_at,
                last_attempt=stamp,
            )
            dead_lettered.append(row["event_id"])
        else:
            # One draw, one transaction: the attempt count and the new due time are the
            # same fact. Written separately, a SIGTERM between them would leave attempts
            # bumped with `next_attempt_at` still <= now — every restart of the agent
            # would re-hit the endpoint immediately, which is §1 seam 9 broken by a crash
            # rather than by intent (and the UPSERT would make it free to repeat).
            delay_s = _backoff_delay_s(attempts, rng, base_s=base_s, cap_s=cap_s)
            _note_failure(
                conn,
                row,
                attempts=attempts,
                outcome=outcome,
                stamp=stamp,
                next_attempt_at=_stamp(now + timedelta(seconds=round(delay_s, 3))),
            )
            retried.append(row["event_id"])

    if log is not None:
        # The prefix and the three counter fields stay EXACTLY as P2-04 printed them:
        # `agent_health.observe_push_log` partitions on "push drain: " and refuses a line
        # with anything before it, so a reworded prefix would silently zero the §2e push
        # gauges (a health counter that stops counting is worse than one that is wrong).
        # The sink rides as an extra token, which that parser ignores by design.
        log(
            f"push drain: sink={sink_name} sent={len(sent)} retried={len(retried)} "
            f"dead_lettered={len(dead_lettered)} "
            f"ids={sorted(set(sent) | set(retried) | set(dead_lettered))}"
        )
    return DrainResult(
        endpoint=endpoint,
        sink_name=sink_name,
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


#: Statuses that say the payload itself will never be accepted. Retrying them for
#: 24 h only burns the site's request budget; the owner must fix or discard the row.
#: 401/403 are deliberately NOT here: those are token/config problems that a re-read
#: can fix (see the token refresh in `HttpsIngestTransport.__call__`).
PERMANENT_REJECT_STATUSES: frozenset[int] = frozenset({400, 422})


def _send_row(
    transport: Transport,
    endpoint: str,
    row: sqlite3.Row,
    *,
    sink_name: str,
    meta_for: RowMeta,
) -> int | Exception:
    """One send attempt for one queue row, render seam included (SINKS-WIRING).

    Two shapes of transport, one failure model:

    * `renders_rows = True` (a csv/jsonl `FileSinkWriter`): the sink's format is the sink's
      business, so this module hands over the ROW's facts and the transport builds the line.
      A render that raises is folded into the outcome exactly like a send that raises —
      attempts burn, the outage clock starts, the error class lands on the row — because a
      punch that cannot be rendered is a punch that did not get delivered, and the only
      alternative is dropping it silently.
    * anything else (the stub transport, `HttpsIngestTransport`, every test fake): the
      payload goes out newline-terminated exactly as P2-04 shipped it, byte for byte. The
      attribute check — not a type check, not a registry lookup — is what keeps the queue
      free of any knowledge of sink types (SINKS-CORE's contract with the queue).

    The row's stored payload is never mutated: rendering produces the LINE, the payload
    stays what the store holds, so a re-delivery re-renders from the same bytes.
    """
    payload = row["payload"]
    if getattr(transport, "renders_rows", False):
        try:
            body = transport.render(  # type: ignore[attr-defined]
                payload, meta_for(int(row["event_id"]), sink_name, row["enqueued_at"])
            )
        except Exception as exc:  # a broken render is a failed ROW, never a silent skip
            return exc
    else:
        body = f"{payload}\n"
    try:
        status = transport(endpoint, body)
    except Exception as exc:  # the transport is injected: anything it raises means
        return exc  # "not accepted", and one bad row must not break the whole drain.
    return status if 200 <= status < 300 else HttpStatusRejectedError(status)


def _call_transport(transport: Transport, endpoint: str, payload: str) -> int | Exception:
    """One send attempt. A raised exception is a failure with a class, not a crash.

    The payload goes out as one JSONL line (newline-terminated so the ingest can append
    batches without gluing two records together — `model.to_jsonl`'s own guarantee).

    Kept as the plain, render-free call for any caller that has no queue row to hand
    (replay paths, probes). `drain` uses `_send_row`, which adds the optional render seam.
    """
    try:
        status = transport(endpoint, f"{payload}\n")
    except Exception as exc:  # the transport is injected: anything it raises means
        return exc  # "not accepted", and one bad row must not break the whole drain.
    return status if 200 <= status < 300 else HttpStatusRejectedError(status)


def _note_failure(
    conn: sqlite3.Connection,
    row: sqlite3.Row,
    *,
    attempts: int,
    outcome: Exception,
    stamp: str,
    next_attempt_at: str,
) -> None:
    """Record a failed attempt AND reschedule it, in ONE transaction.

    One transaction because the two halves are one fact: a kill between them would leave
    `attempts` bumped while `next_attempt_at` is still <= now, so the next drain (or the
    next agent start) would re-hit the endpoint that just failed — the "never hammer" rule
    broken by a crash instead of by intent.

    `first_failed_at` is written by the FIRST failure and never moved afterwards: it is the
    start of the continuous-failure span §2c measures the 24 h bound against. The
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
                   last_error_class = ?,
                   next_attempt_at = ?
             WHERE id = ?
            """,
            (attempts, stamp, stamp, error_class, next_attempt_at, row["id"]),
        )
    except BaseException:
        conn.execute("ROLLBACK")
        raise
    conn.execute("COMMIT")


def _mark_sent(
    conn: sqlite3.Connection,
    *,
    queue_id: int,
    event_id: int,
    sink_name: str,
) -> None:
    """Success: DELETE the buffer row and any dead-letter row for the same sink key.

    One transaction, so a kill cannot leave the event dead-lettered *and* delivered. The
    events row is untouched — the queue is transient, the store is the truth.

    The dead-letter delete is keyed on (event_id, sink_name): a row dead-lettered for
    ANOTHER sink must survive this success, because that sink has still not received the
    punch. Clearing it by event alone would be the silent loss §2b exists to prevent.
    """
    conn.execute("BEGIN IMMEDIATE")
    try:
        conn.execute("DELETE FROM push_queue WHERE id = ?", (queue_id,))
        conn.execute(
            "DELETE FROM dead_letter WHERE event_id = ? AND sink_name = ?",
            (event_id, sink_name),
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
    sink_name: str,
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

    The UPSERT key is (event_id, sink_name) — one dead-letter row per (push, sink), so a
    punch that reached one sink and failed against another is visible as exactly that.
    """
    conn.execute("BEGIN IMMEDIATE")
    try:
        conn.execute(
            """
            INSERT INTO dead_letter (
                id, event_id, payload, sink_name, endpoint, error_class,
                attempts, first_attempt_at, last_attempt_at
            ) VALUES (NULL, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(event_id, sink_name) DO UPDATE
            SET payload = excluded.payload,
                endpoint = excluded.endpoint,
                error_class = excluded.error_class,
                attempts = excluded.attempts,
                last_attempt_at = excluded.last_attempt_at
            """,
            (
                event_id,
                payload,
                sink_name,
                endpoint,
                error_class,
                attempts,
                first_failed_at,
                last_attempt,
            ),
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
    sink_name: str | None = None,
) -> int:
    """Re-queue one dead-letter row for another push; returns the queue row id.

    `endpoint` defaults to the ref the row failed against (§2b's "replay = re-push") and
    may be overridden when the ingest has moved. `sink_name` (SINKS-CORE) defaults to the
    sink the row belongs to — the row's identity is what its outage clock was measured
    against, so replaying "into the archive" and replaying "into the ingest" are different
    acts and stay separate rows.

    The retry state is carried over — attempts continue and `first_failed_at` stays the
    original outage start, so a replay into a sink that is still down dead-letters again
    promptly instead of buying a fresh 24 hours. Replaying twice (or while the row is
    somehow still queued) is safe: the queue's UNIQUE(event_id, sink_name) means one
    buffer, one send.

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
    sink = row["sink_name"] if sink_name is None else sink_name
    _check_endpoint(target, what="push target")
    _check_sink_name(sink)
    stamp = _stamp(now)
    conn.execute("BEGIN IMMEDIATE")
    try:
        conn.execute(
            """
            INSERT INTO push_queue (
                id, event_id, payload, sink_name, endpoint, attempts,
                first_failed_at, last_attempt_at, last_error_class,
                next_attempt_at, enqueued_at
            )
            SELECT NULL, event_id, payload, ?, ?, attempts,
                   first_attempt_at, last_attempt_at, error_class, ?, ?
              FROM dead_letter WHERE id = ?
            ON CONFLICT(event_id, sink_name) DO UPDATE
            SET payload = excluded.payload, endpoint = excluded.endpoint
            """,
            (sink, target, stamp, stamp, dead_letter_id),
        )
        queued = conn.execute(
            "SELECT id FROM push_queue WHERE event_id = ? AND sink_name = ?",
            (row["event_id"], sink),
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


def queue_depth(conn: sqlite3.Connection, *, sink_name: str | None = None) -> int:
    """Rows waiting to go out (§2e's backlog gauge).

    `sink_name` (SINKS-WIRING) narrows it to one sink's backlog — the same filter
    `pending_rows`/`dead_letter_rows` already take, so the agent's per-sink "is anything
    pending" probe does not have to count the whole table (another sink's outage would
    otherwise keep this sink's bearer probe warm and spend a `security` invocation on it).
    """
    if sink_name is None:
        return conn.execute("SELECT COUNT(*) FROM push_queue").fetchone()[0]
    return conn.execute(
        "SELECT COUNT(*) FROM push_queue WHERE sink_name = ?", (sink_name,)
    ).fetchone()[0]


def dead_letter_depth(conn: sqlite3.Connection) -> int:
    """§2e's `dead_letter_depth`: distinct pushes the owner has not cleared. The
    UPSERT-on-replay is what makes this a count of pushes and not a count of attempts."""
    return conn.execute("SELECT COUNT(*) FROM dead_letter").fetchone()[0]


def pending_rows(
    conn: sqlite3.Connection,
    *,
    endpoint: str | None = None,
    limit: int = DEFAULT_PUSH_BATCH_LIMIT,
    sink_name: str | None = None,
) -> tuple[Pending, ...]:
    """The queue, due-first — payload deliberately NOT included (a CLI table that prints
    payloads is how payroll fields end up on a terminal).

    `sink_name` (SINKS-CORE) filters to one sink's backlog; an unknown name is an empty
    result, not an error — a sink can be removed from config while its rows are still
    queued, and the operator still has to be able to list them.
    """
    sql = (
        "SELECT id, event_id, sink_name, endpoint, attempts, next_attempt_at,"
        " first_failed_at, last_attempt_at, last_error_class FROM push_queue"
    )
    clauses: list[str] = []
    args: list[Any] = []
    if endpoint is not None:
        clauses.append("endpoint = ?")
        args.append(endpoint)
    if sink_name is not None:
        clauses.append("sink_name = ?")
        args.append(sink_name)
    if clauses:
        sql += " WHERE " + " AND ".join(clauses)
    sql += " ORDER BY next_attempt_at, id LIMIT ?"
    args.append(max(1, int(limit)))
    return tuple(
        Pending(
            id=row["id"],
            event_id=row["event_id"],
            sink_name=row["sink_name"],
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
    conn: sqlite3.Connection,
    *,
    endpoint: str | None = None,
    limit: int = DEFAULT_PUSH_BATCH_LIMIT,
    sink_name: str | None = None,
) -> tuple[DeadLetter, ...]:
    """The dead letters, oldest outage first — the triage list the owner reads."""
    sql = (
        "SELECT id, event_id, payload, sink_name, endpoint, error_class, attempts,"
        " first_attempt_at, last_attempt_at FROM dead_letter"
    )
    clauses: list[str] = []
    args: list[Any] = []
    if endpoint is not None:
        clauses.append("endpoint = ?")
        args.append(endpoint)
    if sink_name is not None:
        clauses.append("sink_name = ?")
        args.append(sink_name)
    if clauses:
        sql += " WHERE " + " AND ".join(clauses)
    sql += " ORDER BY first_attempt_at, id LIMIT ?"
    args.append(max(1, int(limit)))
    return tuple(
        DeadLetter(
            id=row["id"],
            event_id=row["event_id"],
            payload=row["payload"],
            sink_name=row["sink_name"],
            endpoint=row["endpoint"],
            error_class=row["error_class"],
            attempts=row["attempts"],
            first_attempt_at=row["first_attempt_at"],
            last_attempt_at=row["last_attempt_at"],
        )
        for row in conn.execute(sql, args)
    )


# --- the HTTPS ingest transport (Task 15: spec §7, the real push target) ---------------------

#: The only scheme this transport serves — checked case-sensitively, like P2-01's
#: validator (`HTTPS://` in a config is a mistake worth a loud error).
INGEST_SCHEME = "https://"

#: The env rung is the AGENT's own contract: `GATECLERK_INGEST_TOKEN_<SITE>`.
#: The Cloud Run receiver reads its own Secret Manager/env names, which
#: are legacy-prefixed and deliberately not spelled here (see the private plan).
#: The two processes are configured separately; neither name has to match.

#: The keychain service holding one site's ingest token. The account is the site (the
#: device credential's account is the host — different item, different purpose, both
#: macOS-managed: device creds and the ingest token never enter sites.toml). Same string
#: as the resolver's `ingest_ref(site)`: one name, backend chosen by the resolver.
INGEST_KEYCHAIN_SERVICE_PREFIX = INGEST_REF_PREFIX

#: Wall-clock ceilings for one push. The connect budget is short because a dead
#: endpoint should fail fast into P2-04's backoff, not stall the tick; the read budget
#: is generous because a 200-line batch travels to Cloud Run, waits on BC writes, and
#: the function is allowed to take its time (a read timeout here is a retry, never a
#: loss — idempotency lives server-side on the fingerprint).
DEFAULT_INGEST_CONNECT_TIMEOUT_S = 10.0
DEFAULT_INGEST_READ_TIMEOUT_S = 30.0


class IngestTokenUnavailableError(PushError):
    """No bearer token for this site: refused BEFORE sending, never a header-less POST.

    A POST without `Authorization` is a 401 by contract — the same queue failure class
    an outage produces, but caused by an install step nobody ran. Naming the exact
    `security add-generic-password` command turns the agent's log line into the fix.
    The message names the keychain SERVICE (never any value) and passes through
    `secrets.redact` like every other text this module raises.
    """


def ingest_token_env_var(site: str) -> str:
    """The env variable naming one site's ingest token: `GATECLERK_INGEST_TOKEN_<SITE>`.

    Site names are uppercased for the lookup because the function uppercases site codes
    before comparing (`GATECLERK_SITES` / `GATECLERK_INGEST_TOKEN_SITE-A` on both ends).
    """
    return f"{INGEST_TOKEN_ENV_PREFIX}{site.strip().upper()}"


def ingest_keychain_service(site: str) -> str:
    """The keychain service holding one site's ingest token: `gateclerk-ingest-<site>`."""
    return f"{INGEST_KEYCHAIN_SERVICE_PREFIX}{site.strip()}"


def _add_token_command(site: str) -> str:
    """The copy-pasteable command that would satisfy a missing ingest token.

    Built here rather than reusing `DeviceTarget.add_command()` because that one carries
    a `user=` comment hint for a *device login* — an ingest bearer has no user half, and
    a misleading command is worse than none. `-w` last so the value is prompted, never
    typed into shell history (DESIGN.md credential plumbing).
    """
    import shlex

    service = ingest_keychain_service(site)
    return (
        "security add-generic-password -U "
        f"-s {shlex.quote(service)} -a {shlex.quote(site.strip())} -w"
    )


class HttpsIngestTransport:
    """The real `Transport`: one POST per drain row, bearer-authenticated, TLS-verified.

    Implements the injected callable `(url, body) -> status` P2-04 defined — this class
    changes nothing about the queue, the backoff ladder or the dead-letter table. A
    non-2xx status is RETURNED (drain folds it into `HttpStatus<code>` and its existing
    policy); a raised httpx error is the normal shape of "the internet is down" and the
    drain already treats any exception as one failed row. Deliberately NOT wrapped into
    a private exception class: the class name (`ConnectError` vs `ReadTimeout`) is the
    operator's diagnostic, and §2b's error-class column reads it verbatim.

    The token lives only in `_token: Secret` — the holder whose repr/str are `***`.
    `repr(self)` prints the Secret wrapper, never a value; the label names the SOURCE
    (`keychain:gateclerk-ingest-site-a`, `env:GATECLERK_INGEST_TOKEN_SITE-A`, `flag`) so an
    operator can tell which rung answered without printing what it answered.

    The token is resolved LAZILY (first send) and cached: building the agent must not
    spend a `security` call (each is a macOS ACL prompt) before there is anything to
    send, and a keychain added ten minutes after install still works — the next drain
    resolves it on its own.
    """

    __slots__ = (
        "_client",
        "_env",
        "_explicit",
        "_keychain",
        "_owns_client",
        "_token",
        "_token_env",
        "_token_keychain",
        "confirm_site",
        "site",
        "timeout",
        "verify",
    )

    def __init__(
        self,
        site: str,
        *,
        token: str | Secret | None = None,
        env: Mapping[str, str] | None = None,
        keychain: Any = None,
        token_env: str | None = None,
        token_keychain: str | None = None,
        client: Any = None,
        confirm_site: bool = True,
        connect_timeout_s: float = DEFAULT_INGEST_CONNECT_TIMEOUT_S,
        read_timeout_s: float = DEFAULT_INGEST_READ_TIMEOUT_S,
    ) -> None:
        if not site or not site.strip():
            raise ValueError("an ingest transport needs the site name it authenticates as")
        import httpx

        self.site = site.strip()
        #: The `X-GateClerk-Site` claim is a CONFIRMATION only (the token determines the
        #: site); a site whose operator prefers to send no claim at all gets that.
        self.confirm_site = bool(confirm_site)
        self._env = env
        self._keychain = keychain
        #: Token REF OVERRIDEs (names, never values) for a caller that authenticates as the
        #: site but reads its bearer from somewhere else — the sink layer's `token_env` /
        #: `token_keychain`. None keeps the site's own refs. Stored unresolved on purpose:
        #: a REF costs nothing at construction, where a READ can raise (see `_resolve_token`).
        self._token_env = token_env
        self._token_keychain = token_keychain
        self._explicit = (
            Secret(token, label=f"flag:{self.site}") if isinstance(token, str) else token
        )
        self._token: Secret | None = None
        self._owns_client = client is None
        # TLS verification stays ON: a bearer token over a TLS connection that trusts
        # whoever answers the DNS is the credential handed to the network (gotchas §4.1
        # bans verify=False repo-wide). `trust_env=False` on the client WE build keeps
        # the push off any proxy configured in the ambient environment — a proxy would
        # see the bearer header, and the agent's own network path must not depend on
        # ambient shell state (forked children included) to reach the ingest.
        self.timeout = httpx.Timeout(read_timeout_s, connect=connect_timeout_s)
        self.verify = True
        self._client: Any = (
            client
            if client is not None
            else httpx.Client(
                timeout=self.timeout,
                verify=True,
                trust_env=False,
                headers={"User-Agent": "gateclerk-agent/1"},
            )
        )
        if client is not None:
            # Read the injected client's own posture rather than asserting our default:
            # an honest `verify` attribute beats a decorative one.
            self.verify = getattr(client, "verify", True) is True

    # --- the Transport seam ----------------------------------------------------------------

    def __call__(self, url: str, body: str) -> int:
        self._check_url(url)
        token = self._resolve_token()
        headers = {
            "Authorization": f"Bearer {token.reveal()}",
            # Pinned by the function's own frozen test docstring (`Content-Type:
            # application/jsonl`); the body itself is the byte-verbatim stored line.
            "Content-Type": "application/jsonl",
        }
        if self.confirm_site:
            # Uppercase because the function uppercases the claim before comparing it
            # to the token's site; a wrong-cased claim is still only ever a claim.
            headers["X-GateClerk-Site"] = self.site.upper()
        payload = body if body.endswith("\n") else f"{body}\n"
        response = self._client.post(
            url,
            content=payload.encode("utf-8"),
            headers=headers,
        )
        status = int(response.status_code)
        if status in (401, 403):
            # The next attempt re-reads the credential ladder (rotated token, wrong site,
            # credential file just installed). Do not dead-letter: this is an install step.
            #
            # The memo in `_resolve_token` exists for a reason — every macOS `security` read
            # can raise an ACL prompt, so a drain must not re-ask per row. Dropping it ONLY on
            # an auth rejection keeps that property (a 200 or a 5xx never costs a re-read) and
            # is the whole recovery: this call still returns the status it got, and the row is
            # already rescheduled, so the SAME row is not re-sent inside this drain pass.
            self._token = None
        # The response body is NOT folded into any exception or log: a server message
        # is uncontrolled text, and §2b's error class needs only the status.
        return status

    def close(self) -> None:
        """Release the socket pool — only for the client this transport built."""
        if self._owns_client:
            self._client.close()

    # --- the wire-shape guards and the token rungs -------------------------------------------

    def _check_url(self, url: str) -> None:
        if not url.startswith(INGEST_SCHEME):
            raise PushTargetError(
                f"the bearer transport cannot serve {url!r}: it speaks {INGEST_SCHEME} "
                "only. A bearer token must never cross clear text, and a bearer "
                "transport aimed at a local stub would let a test go green by writing "
                "to disk while believing it authenticated to the ingest."
            )

    @property
    def token_label(self) -> str | None:
        """What we may safely say about the token (which rung answered), or None."""
        return None if self._token is None else self._token.label

    def token_available(self) -> bool:
        """Whether a bearer token can be produced now — a probe, returns no secret.

        For the agent's push step: an `https://` target whose token is missing must warn
        and LEAVE the rows queued rather than run a drain whose every row dies on
        `IngestTokenUnavailable` — the 24 h dead-letter clock measures OUTAGES (§2c),
        and a never-installed keychain item is not an outage, it is an install step.
        Resolves and caches on success (the resolver is lazy and idempotent); any
        failure — missing item, locked keychain — answers False and the push path
        surfaces the real class later.
        """
        try:
            self._resolve_token()
        except Exception:
            return False
        return True

    def _resolve_token(self) -> Secret:
        """flag > env > platform store (macOS Keychain) > credential file — per site, then refuse.

        The ladder itself is `credentials.resolve_ingest_token`, the same one a device
        password walks, so a Linux release host (no Keychain) resolves the bearer from the
        env rung or the 0600 credential file with no other change. What stays specific to
        this transport:

        * no global fallback rung ON PURPOSE — the function's contract is that the token
          DETERMINES the site, so a resolver that fell back to another site's token would
          either 403 (site_token_mismatch, zero BC traffic) or, the bad case, authenticate
          fine and attribute one site's punches to another;
        * the failure is `IngestTokenUnavailableError`, this module's class, so the pusher's
          error column reads "install step", not "outage";
        * the resolution is cached, because every `security` call can raise a macOS ACL
          prompt and a drain must not re-ask per row.

        `self._token_env` / `self._token_keychain` override WHICH REF each rung reads (the sink
        layer's job — see `sink_writers.build_https_sink_transport`); the LADDER is unchanged
        either way, so an override only redirects a rung, it never removes one.
        """
        if self._token is not None:
            return self._token
        try:
            resolved = resolve_ingest_token(
                self.site,
                token=self._explicit,
                env=self._env,
                # Resolved HERE, not left to the resolver's own default: this module's
                # `KeychainReader` name is the seam three tests monkeypatch to simulate a
                # missing item, and letting `gateclerk.credentials` build the reader instead
                # would silently route past the patch (a fake that is never called reads as
                # a pass, which is the worst direction for a credential test to fail in).
                keychain=self._keychain if self._keychain is not None else KeychainReader(),
                env_var=self._token_env or ingest_token_env_var(self.site),
                keychain_service=self._token_keychain or ingest_keychain_service(self.site),
            )
        except CredentialUnavailable as exc:
            # The resolver's own text already opens with "no ingest bearer token for site
            # …" (`what` is worded for it) and names the service, never a value; this adds
            # this module's class — so the pusher's error column reads "install step", not
            # "outage" — plus the paste-away `security` line on every platform, and
            # `redact` is belt-and-braces against a future reader echoing a value.
            raise IngestTokenUnavailableError(
                redact(
                    f"{exc}\n    add it with: {_add_token_command(self.site)}",
                    self._token,
                )
            ) from None
        self._token = resolved.secret
        return self._token

    def _read_keychain(self) -> Secret | None:
        """The Keychain rung, kept as the documented seam p1-02/Task-15 tests reach for.

        `resolve_ingest_token` is what calls it now (via `store_target`); this is the
        single-site, single-service form and stays because a caller outside the transport
        (a future `creds check --target ingest`) wants exactly that.
        """
        target = DeviceTarget(
            host=self.site,  # the keychain ACCOUNT is the site (device creds: the host)
            site=self.site,
            keychain_service=ingest_keychain_service(self.site),
        )
        reader = self._keychain if self._keychain is not None else KeychainReader()
        try:
            # with_comment=False: a second `security` invocation is a second macOS ACL
            # prompt, and a bearer token has no `user=` hint to read anyway.
            item = reader.read(target, with_comment=False)
        except CredentialUnavailable as exc:
            # config.py guarantees this message names service/account and no value;
            # re-raise the pusher's own class so the operator gets the ingest-specific
            # fix line. `redact` is belt-and-braces against a future reader echoing one.
            raise IngestTokenUnavailableError(
                redact(
                    f"no ingest bearer token for site {self.site!r}: {exc}\n"
                    f"    add it with: {_add_token_command(self.site)}",
                    self._token,
                )
            ) from None
        return item.password


def https_transport(
    site: str,
    *,
    token: str | Secret | None = None,
    env: Mapping[str, str] | None = None,
    keychain: Any = None,
    token_env: str | None = None,
    token_keychain: str | None = None,
    client: Any = None,
    confirm_site: bool = True,
    connect_timeout_s: float = DEFAULT_INGEST_CONNECT_TIMEOUT_S,
    read_timeout_s: float = DEFAULT_INGEST_READ_TIMEOUT_S,
) -> HttpsIngestTransport:
    """Build the HTTPS ingest transport for one site (the factory mirrors p1-02's rungs).

    `token`/`env`/`keychain`/`client` are all injectable for exactly the reason they are
    across this repo: a test that reads the real keychain or opens a real socket is not
    a test (conftest's netoff would kill the socket anyway). Production passes nothing
    but the site and gets flag>env>keychain resolution over `gateclerk-ingest-<site>`.

    `token_env` / `token_keychain` redirect the env and platform-store RUNGS to a different
    REF (names only, never values) while the site stays the authenticated identity — the
    sink layer's `[[site.sink]]` block uses them so one site may deliver through two
    sinks with two bearers. Nothing is read here: the ladder runs on the first send.
    """
    return HttpsIngestTransport(
        site,
        token=token,
        env=env,
        keychain=keychain,
        token_env=token_env,
        token_keychain=token_keychain,
        client=client,
        confirm_site=confirm_site,
        connect_timeout_s=connect_timeout_s,
        read_timeout_s=read_timeout_s,
    )


# --- the hourly roster line (Task 15: "also push device-user list hourly") --------------------

#: The four user keys the ingest's `device_users` classifier reads — and the whole
#: privacy boundary of this line. `UserRecord` already strips the device `password`
#: hash at read time; what stays home on top of that is payroll-adjacent metadata the
#: BC Nelegati list has no use for: validity windows, user type, the raw device blob.
_ROSTER_USER_KEYS = ("employee_no", "name", "cardNo", "hasFace")


def device_users_line(
    *,
    device_code: str,
    users: Sequence[UserRecord] | Iterable[UserRecord],
) -> str:
    """One JSONL roster line, byte-shaped exactly as `gateclerk_ingest` classifies it.

    The function's rule (functions/main.py, frozen contract): `kind == "device_users"`,
    a non-empty `deviceCode`, a `users` LIST, and per user `employee_no` (empty -> 400
    invalid_user_line), `name`, `cardNo` (or `card_no`), `hasFace` (or `has_face`).
    Everything else it ignores, so everything else is data with no reason to cross the
    wire. `cardNo`/`hasFace` are read from the record's verbatim device `raw` blob
    (`cardNo`, `numOfFace`) because those are the shapes OBSERVED.md records; a device
    that said neither answers `None`/False, which is the honest roster, not a gap.

    `deviceCode` is the BC page-70602 code when the site configures one, else the
    serial — the function resolves serial -> code through `gateclerkDevices` and accepts
    either. An unknown-or-blocked one comes back 422 with the actionable list.

    Compact separators + `ensure_ascii=False` + exactly one trailing newline: the
    function `splitlines()`s the body, a pretty-printed roster would arrive as broken
    lines, and names with diacritics must survive as themselves (model._dumps' rule).
    """
    import json

    payload = {
        "kind": "device_users",
        "deviceCode": device_code,
        "users": [_roster_user(user) for user in users],
    }
    return json.dumps(payload, ensure_ascii=False, separators=(",", ":"), allow_nan=False) + "\n"


def _roster_user(user: UserRecord) -> dict[str, Any]:
    """The four-key projection of one UserRecord — no more keys may exist here.

    Accepts `UserRecord` or any object exposing `employee_no`/`name`/`raw` so a caller
    holding deserialized records is not forced to re-validate them just to roster.
    """
    raw: Mapping[str, Any] = getattr(user, "raw", None) or {}
    card = raw.get("cardNo", raw.get("card_no"))
    faces = raw.get("numOfFace")
    # `numOfFace` is the device's own face count (OBSERVED.md); any non-zero is a face
    # on file. Absent = the device did not say = False, never a guess of True.
    has_face = isinstance(faces, (int, float)) and not isinstance(faces, bool) and bool(faces)
    return {
        "employee_no": user.employee_no,
        "name": user.name,
        "cardNo": None if card is None else str(card),
        "hasFace": has_face,
    }


# --- the stub ingest (§3: the abstract target, made real locally) ----------------------------


def stub_transport(target: str) -> Transport:
    """A transport that appends the JSONL body to a local file: `stub://<path>`.

    This is the owner-authorized local ingest (card + spec §3); P2-04 shipped only
    `stub_transport` while Task 15 adds the real one, `https_transport` — it exists so the
    pusher, its tests and an operator's dry run all exercise the REAL payload path against
    something that is not an invented endpoint. It writes the bytes it was handed
    (append-only: truncating would delete the site's history on the first retry) and
    answers 200, which is the whole contract `drain` relies on.

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
