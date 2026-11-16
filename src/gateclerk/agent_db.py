"""sqlite connection seam for the P2 site agent: pragmas + forward-only migrations.

Card P2-02 (docs/internal/P2-SITE-AGENT.md §1 seams 1-3, §2b, SIGNED OFF 2026-10-19). This is
the *connection* half of the store; the semantics (events UPSERT, completed-only
checkpoint, watermark) live in `gateclerk.agent_store`. stdlib `sqlite3` only — the
agent box gets one dependency fewer to rot, and the store is a handful of tables.

Pragmas (card: "crash-safe on systemd kill"):

* `journal_mode=WAL` — a SIGTERM'd writer leaves the WAL, not a torn main db; readers
  (P2-05's /healthz, a payroll triage) never block behind the poll loop.
* `synchronous=NORMAL` — under WAL this fsyncs at checkpoints, not per commit: a kill
  can lose the tail of the WAL, never a committed checkpoint, and the UPSERT key makes
  the re-poll heal exactly what the tail lost (DESIGN.md "Idempotency key"). FULL
  would buy nothing here and slow every 5-min tick.

Migrations are an EXTENSIBLE, additive, forward-only list — `MIGRATIONS` is the seam
P2-04 appends its `push_queue` + `dead_letter` entries to (its card says so; the
extensibility is pinned by tests, not prose). Rules enforced at connect:

* versions strictly ascending from 1 (a reversed or duplicated list raises
  `MigrationOrderError` rather than half-building a schema out of order);
* each migration is ONE transaction (statements executed individually inside an
  explicit BEGIN — `executescript` would commit that BEGIN first and autocommit the
  script; atomicity here is deliberate, a crash between two entries resumes at the
  right one);
* a db already at a version *ahead* of the code is refused — an old binary writing a
  new schema is how P2-04's rows would meet P2-02's columns and silently mismatch.
"""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

__all__ = [
    "MIGRATIONS",
    "Migration",
    "MigrationOrderError",
    "MigrationTooNewError",
    "connect",
    "current_version",
    "migrate",
]


class MigrationOrderError(Exception):
    """The MIGRATIONS list is not strictly ascending from 1 — refuse to open at all."""


class MigrationTooNewError(Exception):
    """The db file carries a schema version this code does not know (downgrade)."""


@dataclass(frozen=True, slots=True)
class Migration:
    """One additive schema step. `sql` is a DDL script (multiple statements ok).

    Statements are split on ';' and executed individually inside one transaction, so
    a migration's SQL is plain DDL (no triggers or strings containing semicolons) —
    true for v1 and for P2-04's two CREATE TABLE entries.
    """

    version: int
    name: str
    sql: str


# --- the shipped migrations (v1: events + checkpoint; P2-04 appends v2+) ------------------

_EVENTS_V1 = """
CREATE TABLE events (
    id INTEGER PRIMARY KEY,
    -- The payload: the model.EventRecord.to_jsonl() line, byte-verbatim (the frozen
    -- 27-key contract IS the push payload, so what we store is what we push).
    jsonl TEXT NOT NULL,
    -- UPSERT audit: bumped only when the stored bytes actually change.
    revision INTEGER NOT NULL DEFAULT 1,
    -- First-seen / last-change stamps (UTC ISO). `stored_at` never moves on a
    -- conflict; `updated_at` moves only with a real revision bump.
    stored_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    -- Both key digests + their JSON twins (spec §2b: payload line + both digests).
    -- The JSON twin next to a hash is what makes a UNIQUE collision visible to a
    -- human instead of silently merging two punches (model.event_keys).
    key_algorithm TEXT NOT NULL,
    idempotency_hash TEXT NOT NULL,
    idempotency_json TEXT NOT NULL,
    fingerprint_hash TEXT NOT NULL,
    fingerprint_json TEXT NOT NULL,
    -- The frozen contract, flattened to queryable columns. Names and order ARE
    -- model.RECORD_JSON_KEYS (tests/test_p2_02_store.py pins every name against the
    -- tuple, so the schema and the contract cannot drift unnoticed); `raw` is the
    -- device dict as JSON text.
    site TEXT NOT NULL,
    device_serial TEXT NOT NULL,
    serial_no INTEGER,
    employee_no TEXT,
    name TEXT,
    event_time_utc TEXT,
    event_time_local TEXT,
    tz_offset_min INTEGER,
    tz_offset_min_device INTEGER,
    tz_source TEXT,
    iana_tz TEXT,
    tz_unresolved INTEGER,
    tz_ambiguous INTEGER,
    tz_nonexistent INTEGER,
    tz_reason TEXT,
    tz_offset_mismatch INTEGER,
    direction TEXT,
    attendance_status TEXT,
    direction_source TEXT,
    verify_mode TEXT,
    major INTEGER,
    minor INTEGER,
    outcome TEXT,
    unknown_code INTEGER,
    encrypted_person_data INTEGER,
    raw TEXT NOT NULL,
    captured_at TEXT
);

CREATE UNIQUE INDEX events_key ON events (device_serial, serial_no);

-- The query shapes P2-04 (push drain) and P2-07 (CLI read) need; a payroll triage
-- by employee+day must not table-scan a year of noise.
CREATE INDEX events_fingerprint ON events (fingerprint_hash);
CREATE INDEX events_employee_time ON events (employee_no, event_time_utc);
"""

_CHECKPOINT_V1 = """
CREATE TABLE checkpoint (
    device_serial TEXT PRIMARY KEY,
    -- max(serialNo) device-wide (noise included — OBSERVED.md "Event log census").
    checkpoint_serial INTEGER NOT NULL CHECK (checkpoint_serial >= 0),
    -- The device-local time of the record that carries checkpoint_serial, verbatim
    -- from the caller (DESIGN.md: (last_serial_no, last_event_time_local)). Never
    -- derived here: the next poll window is [this - overlap, now] (P2-03).
    checkpoint_time TEXT,
    updated_at TEXT NOT NULL
);
"""

_SCHEMA_MIGRATIONS = """
CREATE TABLE schema_migrations (
    version INTEGER PRIMARY KEY,
    name TEXT NOT NULL,
    applied_at TEXT NOT NULL
);
"""

# --- P2-04 appends here (v3: push queue; v4: dead-letter) ------------------------------------

_PUSH_QUEUE_V3 = """
CREATE TABLE push_queue (
    id INTEGER PRIMARY KEY,
    -- A send buffer POINTS at a stored event; it is not a second copy of the store.
    -- RESTRICT (not CASCADE) is the load-bearing choice: deleting an event that has not
    -- been pushed yet is refused by the db, so no purge can outrun the queue and lose a
    -- punch with no dead-letter row to account for it (spec §2b: purging is the owner's,
    -- and it must not be able to do this by accident).
    event_id INTEGER NOT NULL REFERENCES events(id) ON DELETE RESTRICT,
    -- The bytes to send, copied from events.jsonl at enqueue time: the drain must not
    -- re-derive the payload (that would put a serialisation step on the send path, and
    -- P2-02 proved the stored line IS `to_jsonl()` verbatim).
    payload TEXT NOT NULL,
    endpoint TEXT NOT NULL,
    attempts INTEGER NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    -- The 24 h clock starts at the FIRST failure and survives a re-enqueue: it measures
    -- the outage, not the age of this row (spec §2c "continuous failure").
    first_failed_at TEXT,
    last_attempt_at TEXT,
    last_error_class TEXT,
    -- Due when this is <= now. `attempts` + this column IS the backoff: the drain never
    -- sleeps, it finds what is due (an agent that slept 30 s would miss the next poll
    -- window, and a systemd kill would interrupt the sleep anyway).
    next_attempt_at TEXT NOT NULL,
    enqueued_at TEXT NOT NULL,
    -- One buffer per (event, target): the overlap poll re-stores the same events every
    -- 5 minutes and must not grow a second row per poll — that would be a duplicate push.
    -- SINKS-CORE note: this is the SINGLE-target shape, replaced by `push_queue_per_sink`
    -- (v5) with UNIQUE (event_id, sink_name). `endpoint` survives as provenance.
    UNIQUE (event_id, endpoint)
);

-- The drain's query shape is (endpoint, due-by); without this index every 5-min tick
-- scans the whole backlog.
CREATE INDEX push_queue_due ON push_queue (endpoint, next_attempt_at);
"""

_DEAD_LETTER_V4 = """
CREATE TABLE dead_letter (
    id INTEGER PRIMARY KEY,
    -- No FK here, deliberately: a dead-letter row must OUTLIVE the event row (it is the
    -- record of what could not be sent, and §2b says it is deleted only by the owner's
    -- command), and a payload-carrying row needs no parent to be readable. `event_id`
    -- stays for the triage join back to the store.
    event_id INTEGER NOT NULL,
    -- §2b: the COMPLETE JSONL payload line, so a replay needs nothing but this table.
    payload TEXT NOT NULL,
    endpoint TEXT NOT NULL,
    error_class TEXT NOT NULL,
    attempts INTEGER NOT NULL CHECK (attempts >= 1),
    first_attempt_at TEXT NOT NULL,
    last_attempt_at TEXT NOT NULL,
    -- "replay = re-push, UPSERT makes it safe" (spec §2b): re-failing a replay REFRESHES
    -- this row instead of duplicating it, so the depth counts distinct pushes.
    UNIQUE (event_id, endpoint)
);

CREATE INDEX dead_letter_endpoint ON dead_letter (endpoint);
"""

_SERIAL_EPOCH_V7 = """
ALTER TABLE events ADD COLUMN serial_epoch INTEGER NOT NULL DEFAULT 0;

DROP INDEX events_key;

CREATE UNIQUE INDEX events_key ON events (device_serial, serial_epoch, serial_no);

ALTER TABLE checkpoint ADD COLUMN serial_epoch INTEGER NOT NULL DEFAULT 0;

ALTER TABLE checkpoint ADD COLUMN firmware TEXT;
"""

# --- SINKS-CORE appends here (v5 + v6: per-sink delivery state) -------------------------------
#
# Today's queue was keyed `UNIQUE (event_id, endpoint)`, which is exactly the shape of the
# config that produced it: ONE `push_target` per site. Named sinks let one site have
# several delivery targets, so the identity of a buffer becomes `(event_id, sink_name)`.
#
# Why these two steps REBUILD rather than ALTER: sqlite cannot drop or change a UNIQUE
# constraint, and a table-level UNIQUE cannot be replaced by an index on a live table. So
# each step creates the new table, COPIES every row (no filtering, no re-derivation), drops
# the old table and renames. `DROP TABLE` here is therefore not the "migrations never
# destroy" rule being broken — it is the only way to change a constraint while keeping
# every byte, and the rule it must satisfy instead is the stronger one: the copy carries
# every payload, attempt count and outage stamp. `test_upgrade_preserves_payload_bytes_and_
# retry_state_byte_for_byte` (tests/test_sinks_storage.py) is that guarantee, and
# `test_migrations_are_a_list_of_ascending_versions` pins the copy shape.
#
# `endpoint` STAYS as provenance: an owner triaging a two-month-old outage reads the ref
# the row actually failed against, which is not necessarily today's configured ref.
#
# Pre-upgrade rows are addressed to the implicit sink (`sinks.IMPLICIT_SINK_NAME` =
# `legacy`), because a site that had a `push_target` has exactly one sink after the
# upgrade and it is that target. The one case that cannot be `legacy` for every row: the
# old UNIQUE allowed ONE event to be buffered against TWO targets (the operator moved
# `push_target` while a backlog was queued). The oldest row of an event keeps `legacy`
# (it is the site's sink); any additional row gets `legacy+<id>`, which cannot collide and
# — carrying a `+`, which the config's identifier rule rejects — can never be mistaken for
# a configured sink name.

_PUSH_QUEUE_V5 = """
CREATE TABLE push_queue_v5 (
    id INTEGER PRIMARY KEY,
    -- Same pointer, same law: a send buffer POINTS at a stored event and RESTRICTs the
    -- delete that would orphan a punch (see v3; the choice survives the rebuild).
    event_id INTEGER NOT NULL REFERENCES events(id) ON DELETE RESTRICT,
    payload TEXT NOT NULL,
    -- Provenance now, identity before: `sink_name` is which sink this buffer belongs to.
    endpoint TEXT NOT NULL,
    sink_name TEXT NOT NULL,
    attempts INTEGER NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    first_failed_at TEXT,
    last_attempt_at TEXT,
    last_error_class TEXT,
    next_attempt_at TEXT NOT NULL,
    enqueued_at TEXT NOT NULL,
    -- One buffer per (event, SINK): the overlap poll re-queues the same events every
    -- 5 minutes and must not grow a second row per poll, but two sinks of one site each
    -- get their own buffer (and their own 24 h outage clock) for the same event.
    UNIQUE (event_id, sink_name)
);

INSERT INTO push_queue_v5 (
    id, event_id, payload, endpoint, sink_name, attempts,
    first_failed_at, last_attempt_at, last_error_class,
    next_attempt_at, enqueued_at
)
SELECT
    id, event_id, payload, endpoint,
    CASE WHEN id = (SELECT MIN(later.id) FROM push_queue AS later
                     WHERE later.event_id = push_queue.event_id)
         THEN 'legacy'
         ELSE 'legacy+' || id
    END,
    attempts, first_failed_at, last_attempt_at, last_error_class,
    next_attempt_at, enqueued_at
  FROM push_queue;

DROP TABLE push_queue;

ALTER TABLE push_queue_v5 RENAME TO push_queue;

-- Both drain query shapes are indexed: the per-sink one is the one the agent now runs,
-- the per-endpoint one keeps a pre-upgrade backlog (and any owner's ad-hoc triage) from
-- turning a 5-minute tick into a full scan.
CREATE INDEX push_queue_due ON push_queue (endpoint, next_attempt_at);
CREATE INDEX push_queue_sink_due ON push_queue (sink_name, next_attempt_at);
"""

_DEAD_LETTER_V6 = """
CREATE TABLE dead_letter_v6 (
    id INTEGER PRIMARY KEY,
    -- No FK, deliberately, and unchanged by this step: the row must OUTLIVE the event
    -- (§2b: deleted only by the owner's command) and carries its own payload.
    event_id INTEGER NOT NULL,
    payload TEXT NOT NULL,
    endpoint TEXT NOT NULL,
    sink_name TEXT NOT NULL,
    error_class TEXT NOT NULL,
    attempts INTEGER NOT NULL CHECK (attempts >= 1),
    first_attempt_at TEXT NOT NULL,
    last_attempt_at TEXT NOT NULL,
    -- Re-failing a replay REFRESHES this row instead of duplicating it, per sink: so
    -- `dead_letter_depth` counts distinct (push, sink) pairs.
    UNIQUE (event_id, sink_name)
);

INSERT INTO dead_letter_v6 (
    id, event_id, payload, endpoint, sink_name, error_class,
    attempts, first_attempt_at, last_attempt_at
)
SELECT
    id, event_id, payload, endpoint,
    CASE WHEN id = (SELECT MIN(later.id) FROM dead_letter AS later
                     WHERE later.event_id = dead_letter.event_id)
         THEN 'legacy'
         ELSE 'legacy+' || id
    END,
    error_class, attempts, first_attempt_at, last_attempt_at
  FROM dead_letter;

DROP TABLE dead_letter;

ALTER TABLE dead_letter_v6 RENAME TO dead_letter;

CREATE INDEX dead_letter_endpoint ON dead_letter (endpoint);
CREATE INDEX dead_letter_sink ON dead_letter (sink_name);
"""

# --- GC-P15 follow-up appends here (v8: the quiet-tick reset probe's audit trail) ----------
#
# `DeviceLoop._probe_newest_serial` answers one question on a quiet tick — "is the newest
# serial the device still holds below our checkpoint, i.e. was the terminal swapped?" — and
# until now threw the answer away. The only durable trace of a probe was
# `agent_store.reset_checkpoint`, which runs ONLY when the probe CONFIRMED a reset, so an
# operator reading the db could not tell "we never looked" from "we looked and the ring is
# quiet", and `RESET_PROBE_INTERVAL_S` lived in `DeviceLoop.__init__` — one page per hour
# became one page per restart.
#
# This table is that missing answer: what the probe ASKED (the window, as a UTC pair) and
# what it COST (the AcsEvent POSTs it sent). It is written on every COMPLETED read, the
# NO MATCH one included — the empty answer is the one `check_stall` needs (P2-05).
#
# Why a purpose-built table rather than columns on an existing one: there is no `probe`
# table in this schema (`checkpoint`, `events`, `push_queue`, `dead_letter` are the whole
# history), and `checkpoint` is one row per device whose `updated_at` means "the
# checkpoint moved" — a read that changes nothing must never touch that row, because
# P2-05's stall arm reads it as the age of the last accepted event.
#
# Why `kind` is IN the primary key: the device ring-floor read (`DeviceLoop
# .probe_ring_floor`) is a different question with a different direction on the wire
# (`tests/test_ring_floor_probe.py::_probe_conditions` separates the two by
# `timeReverseOrder`), and the two must not vouch for each other. With `kind` in the key a
# future ring-floor row can neither overwrite the reset probe's row nor satisfy its budget.
_PROBE_AUDIT_V8 = """
CREATE TABLE probe_audit (
    device_serial TEXT NOT NULL,
    -- Which question this row answers: 'reset' = the quiet-tick newest-first page
    -- (agent_loop.RESET_PROBE_*). The vocabulary lives with the writer,
    -- agent_store.PROBE_KINDS — a kind nobody reads would silently fork the budget.
    kind TEXT NOT NULL,
    -- The window the probe ASKED for, as UTC ISO written by agent_store._now_iso (the
    -- one stamp format every clock column in this db uses). `window_to_utc` doubles as
    -- the instant the probe ran: it is the loop's own `now` at the moment of the read,
    -- which is what the hourly budget is measured from — a second "probed_at" column
    -- would only be able to disagree with it.
    window_from_utc TEXT NOT NULL,
    window_to_utc TEXT NOT NULL,
    -- AcsEvent POSTs the probe actually sent. NOT the rows it got back: "what did this
    -- cost" is the question an operator reads this column to answer.
    reads INTEGER NOT NULL DEFAULT 0 CHECK (reads >= 0),
    PRIMARY KEY (device_serial, kind)
);
"""

MIGRATIONS: tuple[Migration, ...] = (
    Migration(
        version=1,
        name="schema_migrations_bookkeeping",
        # The bookkeeping table is its own entry precisely so the list has a real
        # ORDER to pin: a forward-only history needs at least two entries before
        # "ascending" means anything (tests reverse the list to prove the guard).
        sql=_SCHEMA_MIGRATIONS,
    ),
    Migration(
        version=2,
        name="events_and_checkpoint",
        # Both tables in one entry: an events store without a checkpoint table is
        # not a usable state, so this entry is "the agent db".
        sql=_EVENTS_V1 + _CHECKPOINT_V1,
    ),
    # --- P2-04 (the pusher) appends from here; the same forward-only rules apply. ----------
    Migration(version=3, name="push_queue", sql=_PUSH_QUEUE_V3),
    Migration(version=4, name="dead_letter", sql=_DEAD_LETTER_V4),
    # --- SINKS-CORE (named sinks) appends from here: per-sink delivery state. See the
    # comment block above v5 for why these REBUILD the tables instead of altering them. --
    Migration(version=5, name="push_queue_per_sink", sql=_PUSH_QUEUE_V5),
    Migration(version=6, name="dead_letter_per_sink", sql=_DEAD_LETTER_V6),
    # Card t_fbd85a10: a device's event serialNo can restart after a firmware upgrade
    # or a log clear. The epoch is the only legal way two punches may share a serial:
    # old rows keep epoch 0, a confirmed reset opens epoch+1. The checkpoint carries
    # the current epoch and the firmware it was written under — the evidence pair the
    # loop compares before it allows a rewind (agent_store.reset_checkpoint).
    Migration(version=7, name="serial_epoch", sql=_SERIAL_EPOCH_V7),
    # GC-P15 follow-up: the quiet-tick reset probe's audit trail (see _PROBE_AUDIT_V8).
    # Additive: a fresh CREATE of an empty table, no copy, no rebuild, no existing row
    # touched — the loop starts recording on its next probe.
    Migration(version=8, name="probe_audit", sql=_PROBE_AUDIT_V8),
)


def current_version(conn: sqlite3.Connection) -> int:
    """Highest applied migration version (0 for a file that has no table yet)."""
    row = conn.execute(
        "SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'schema_migrations'"
    ).fetchone()
    if row is None:
        return 0
    return conn.execute("SELECT COALESCE(MAX(version), 0) FROM schema_migrations").fetchone()[0]


def _statements(sql: str) -> list[str]:
    """Split a DDL script into statements.

    `--` comment lines are dropped FIRST (they legitimately carry semicolons — prose
    does), then split on ';'. Safe for the plain DDL this list carries (no string
    literals with semicolons or comment markers — true for v1 and P2-04's entries;
    anything wilder belongs in `executescript` with its own atomicity caveat).
    """
    body = "\n".join(line.split("--", 1)[0] for line in sql.splitlines())
    return [stmt.strip() for stmt in body.split(";") if stmt.strip()]


def migrate(conn: sqlite3.Connection, now_iso: str) -> tuple[int, ...]:
    """Apply pending migrations in order; return the versions newly applied.

    `isolation_level=None` (what `connect` uses) means BEGIN/COMMIT are ours to
    control, so each migration is exactly one transaction. Refuses an out-of-order
    list (a half-built schema looks identical to a built one until a write hits the
    missing column) and refuses a downgrade — a v2 writer's rows under a v1 reader is
    a corruption event, not a compatibility question.
    """
    versions = [m.version for m in MIGRATIONS]
    if versions != sorted(versions) or len(set(versions)) != len(versions):
        raise MigrationOrderError(
            f"MIGRATIONS versions {versions} are not strictly ascending — a migration "
            "list is an ordered history; reordering or duplicating applies DDL out of "
            "order (or twice) and leaves a schema that only half-exists"
        )
    if versions and versions[0] != 1:
        raise MigrationOrderError(f"MIGRATIONS must start at version 1, got {versions[0]}")

    applied_now = current_version(conn)
    if applied_now > len(versions) or applied_now not in (0, *versions):
        raise MigrationTooNewError(
            f"db is at schema version {applied_now}, this code ships {versions} — "
            "running an older binary against a newer store would write rows the new "
            "schema cannot trust (downgrade is not supported; restore or upgrade)"
        )

    done: list[int] = []
    for m in MIGRATIONS:
        if m.version <= applied_now:
            continue
        conn.execute("BEGIN IMMEDIATE")
        try:
            for stmt in _statements(m.sql):
                conn.execute(stmt)
            conn.execute(
                "INSERT INTO schema_migrations (version, name, applied_at) VALUES (?, ?, ?)",
                (m.version, m.name, now_iso),
            )
        except BaseException:
            conn.execute("ROLLBACK")
            raise
        conn.execute("COMMIT")
        done.append(m.version)
    return tuple(done)


def connect(path: Path | str, *, now_iso: str | None = None) -> sqlite3.Connection:
    """Open (creating if needed) the agent db: pragmas on, migrations applied.

    `check_same_thread=False` + a single-writer discipline is the agent's shape: the
    poll loop owns writes; the health surface may read concurrently. `foreign_keys`
    is ON for the tables P2-04 adds (queue -> events references); the shipped v1 has
    no FKs, so it changes nothing today but a store opened without it would silently
    allow a dangling queue row tomorrow.
    """
    conn = sqlite3.connect(str(path), isolation_level=None, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    conn.execute("PRAGMA foreign_keys=ON")
    migrate(conn, now_iso or datetime.now(UTC).isoformat(timespec="seconds"))
    return conn
