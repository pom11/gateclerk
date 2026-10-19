"""sqlite connection seam for the P2 site agent: pragmas + forward-only migrations.

Card P2-02 (docs/P2-SITE-AGENT.md §1 seams 1-3, §2b, SIGNED OFF 2026-10-19). This is
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
