"""The P2 site agent's event store: (device_serial, serial_no) UPSERT + completed-only checkpoint.

Card P2-02 (docs/P2-SITE-AGENT.md §1 seams 1-3 + §2b, SIGNED OFF 2026-10-19; device
truth docs/OBSERVED.md). Semantics are pinned by the spec and the box — this module
implements them, it does not invent them:

UPSERT (seam 1). `events` is UNIQUE(device_serial, serial_no) and every write is
`INSERT .. ON CONFLICT DO UPDATE SET .. WHERE events.jsonl IS NOT excluded.jsonl`.
That `WHERE` is the whole "re-polling an overlap window is free" guarantee (DESIGN.md
"Idempotency key"; the mechanism a mid-page crash heals by): a re-stored identical line
conflicts, the guard is false, and SQLite does *no* write at all — verified zero
statement cost (total_changes delta 0) and row identity (same rowid, same revision,
same stamps) in tests. Without the guard the UPSERT would rewrite identical bytes every
5-min tick: same visible row, a real write, and `updated_at` churning forever — a
store that lies about which records were ever corrected.

What is stored (seam 6 / spec §2b): the `model.EventRecord.to_jsonl()` line
byte-verbatim (the frozen 27-key contract IS the push payload — what we store is what
we push), plus both key digests from `model.event_keys`, plus the same fields
flattened to queryable columns (contract names from model.RECORD_JSON_KEYS).

Checkpoint (seam 2). Per device: checkpoint_serial = max(serialNo) *device-wide*
(noise included — OBSERVED.md "Event log census": serials 5742..5753 interleave),
checkpoint_time (the caller's: the device-local time of the max-serial record),
updated_at. `advance_checkpoint` takes an explicit `completed` flag and REFUSES
`completed=False` — `paging.ChunkResult.max_serial_no` exists only for completed
chunks (paging.py:612-615), and accepting a half-failed walk's max is exactly how a
crash would silently skip a chunk's events. The monotonic guard (`WHERE
excluded.checkpoint_serial > checkpoint.checkpoint_serial`) makes a lower value both
refused and free; an equal value is a no-op (a quiet tick re-reports the same serial
and must not churn). One UPSERT per advance: no half-applied checkpoint under a kill.

Watermark (spec §2b decision (b): keep-everything + watermark alert — alerting itself
is P2-05): `db_size_bytes` is the gauge value, `check_db_watermark` says whether it is
*over* the threshold (strictly; exactly-at is not over).

Two refusals this module owns, both anti-loss:

* `UnusableRecordError` — a record with `serial_no=None` cannot honour the pinned key:
  SQLite treats NULLs as distinct, so such a row would be *duplicated by every overlap
  poll*, while digest-deduping it would merge two different events. Both lose data, so
  we refuse the record loudly (and leave the batch unwritten) instead of choosing a
  silent loss. OBSERVED.md shows serialNo on every real record; if a site's fw ever
  stops sending it, that is the moment for a deliberate decision, not a quiet fallback.
* `MixedDeviceError` — a batch that spans device_serials would make the result's
  device_serial (what P2-03 advances the checkpoint from) a lie. One device per call.
"""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from gateclerk.model import RECORD_JSON_KEYS, EventRecord, event_keys, to_jsonl

__all__ = [
    "Checkpoint",
    "CheckpointAdvanced",
    "CheckpointNotCompletedError",
    "CheckpointRegressionError",
    "MixedDeviceError",
    "StoreError",
    "StoreResult",
    "UnusableRecordError",
    "WatermarkCheck",
    "advance_checkpoint",
    "check_db_watermark",
    "db_size_bytes",
    "event_jsonl",
    "event_rowid",
    "read_checkpoint",
    "read_oldest_serial",
    "store_events",
]


class StoreError(Exception):
    """Base for store-level refusals."""


class UnusableRecordError(StoreError):
    """The record cannot honour the UNIQUE(device_serial, serial_no) key (see module doc)."""


class MixedDeviceError(StoreError):
    """One batch, one device: the stored checkpoint/serial identity is per-device."""


class CheckpointNotCompletedError(StoreError):
    """Advance refused: the chunk did not complete (seam 2 — paging.py:612-615)."""


class CheckpointRegressionError(StoreError):
    """Advance refused: a lower serial must never move the checkpoint backwards."""


@dataclass(frozen=True, slots=True)
class StoreResult:
    """What one store_events call did. `unchanged` counts the FREE no-ops."""

    inserted: int
    refreshed: int
    unchanged: int
    device_serial: str | None = None
    #: serial_no -> rowid, for every key the batch touched (P2-04 queues by rowid).
    rowids: dict[int, int] | None = None

    def __post_init__(self) -> None:
        if self.rowids is None:
            object.__setattr__(self, "rowids", {})


@dataclass(frozen=True, slots=True)
class Checkpoint:
    """One device's checkpoint row, read back."""

    device_serial: str
    checkpoint_serial: int
    checkpoint_time: str | None
    updated_at: str


@dataclass(frozen=True, slots=True)
class CheckpointAdvanced:
    """The outcome of one advance attempt (`advanced=False` only for a quiet tick)."""

    device_serial: str
    checkpoint_serial: int | None
    advanced: bool


@dataclass(frozen=True, slots=True)
class WatermarkCheck:
    """The db-size gauge against the threshold (P2-05 alerts on `warn`)."""

    size_bytes: int
    warn_bytes: int

    @property
    def warn(self) -> bool:
        return self.size_bytes > self.warn_bytes

    @property
    def over_by_bytes(self) -> int:
        return max(0, self.size_bytes - self.warn_bytes)


def _now_iso(now: datetime | None) -> str:
    moment = now or datetime.now(UTC)
    if moment.tzinfo is None:
        raise ValueError("store timestamps must be tz-aware (payroll data; pyproject DTZ)")
    return moment.astimezone(UTC).isoformat(timespec="seconds")


# --- the UPSERT ---------------------------------------------------------------------------

#: Columns the flattened record fills (after jsonl/revision/stamps/digests). ARE
#: model.RECORD_JSON_KEYS — derived, not restated, so the parameter order in
#: `_row_values` and the frozen contract cannot drift apart. The INSERT's literal
#: column list below is pinned to this tuple by
#: test_insert_column_list_is_the_contract_tuple.
_CONTRACT_COLUMNS: tuple[str, ...] = RECORD_JSON_KEYS

#: The INSERT target columns, in parameter order (head bookkeeping + contract).
_HEAD_COLUMNS: tuple[str, ...] = (
    "jsonl",
    "stored_at",
    "updated_at",
    "key_algorithm",
    "idempotency_hash",
    "idempotency_json",
    "fingerprint_hash",
    "fingerprint_json",
)
_UPSERT_COLUMNS: tuple[str, ...] = (*_HEAD_COLUMNS, *_CONTRACT_COLUMNS)

#: Static SQL on purpose (no interpolation anywhere): every value is a bound '?'.
#: `revision` is a constant 1 here — the DO UPDATE bumps it — and `id` is the
#: INTEGER PRIMARY KEY rowid, filled by sqlite.
_UPSERT = """
INSERT INTO events (
    id, revision,
    jsonl, stored_at, updated_at,
    key_algorithm, idempotency_hash, idempotency_json, fingerprint_hash, fingerprint_json,
    site, device_serial, serial_no, employee_no, name,
    event_time_utc, event_time_local, tz_offset_min, tz_offset_min_device, tz_source,
    iana_tz, tz_unresolved, tz_ambiguous, tz_nonexistent, tz_reason, tz_offset_mismatch,
    direction, attendance_status, direction_source, verify_mode, major, minor, outcome,
    unknown_code, encrypted_person_data, raw, captured_at
) VALUES (
    NULL, 1,
    ?, ?, ?,
    ?, ?, ?, ?, ?,
    ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
    ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
    ?, ?, ?, ?, ?, ?, ?
)
ON CONFLICT(device_serial, serial_no) DO UPDATE
SET jsonl = excluded.jsonl,
    revision = events.revision + 1,
    updated_at = excluded.updated_at
WHERE events.jsonl IS NOT excluded.jsonl
RETURNING id, revision
"""
# The FREE-overlap guard (the WHERE above) is the whole "re-polling an overlap
# window is FREE" clause (module doc): identical bytes make the guard false and
# sqlite writes NOTHING — zero statement cost, row identity untouched. The
# flattened columns carry NULL-able scalars only (to_dict() output); `raw` is the
# device dict as JSON text.


def _row_values(record: EventRecord, line: str, stamp: str) -> list[Any]:
    """One UPSERT parameter tuple: jsonl verbatim + digests + flattened contract.

    `to_dict()` is the model's own flat view (datetimes already ISO, enums already
    str) — the same dict `to_jsonl` serialises, so the columns and the stored line
    cannot disagree. `raw` has no sqlite scalar form: it goes in as JSON text.
    """
    keys = event_keys(record)
    payload = record.to_dict()
    values: list[Any] = [
        line,
        stamp,
        stamp,
        keys["algorithm"],
        keys["idempotency_hash"],
        keys["idempotency_json"],
        keys["fingerprint_hash"],
        keys["fingerprint_json"],
    ]
    for column in _CONTRACT_COLUMNS:
        value = payload[column]
        if column == "raw":
            # The device dict has no sqlite scalar form: JSON text keeps it lossless.
            value = json.dumps(value, ensure_ascii=False, separators=(",", ":"))
        values.append(value)
    return values


def store_events(
    conn: sqlite3.Connection,
    records: Sequence[EventRecord],
    *,
    now: datetime | None = None,
) -> StoreResult:
    """UPSERT a batch (one poll window / one chunk's records). Returns per-outcome counts.

    One transaction, so a batch is all-or-nothing (a crash mid-batch leaves nothing
    half-stored — the overlap poll is the healer, and it needs a clean key space).
    A batch that repeats a key is legal (overlap page + new page in one call): the
    guard makes the repeat free and the last line for the key wins.
    """
    batch = list(records)
    if not batch:
        return StoreResult(inserted=0, refreshed=0, unchanged=0)

    serials = {r.device_serial for r in batch}
    if len(serials) > 1:
        raise MixedDeviceError(
            f"batch spans device_serials {sorted(serials)} — checkpoint and window "
            "state are per-device; call store_events once per device (P2-03's loop shape)"
        )
    device_serial = batch[0].device_serial

    stamp = _now_iso(now)
    inserted = refreshed = unchanged = 0
    rowids: dict[int, int] = {}

    conn.execute("BEGIN IMMEDIATE")
    try:
        for record in batch:
            if record.serial_no is None:
                raise UnusableRecordError(
                    f"record for device {device_serial!r} has serial_no=None: the store's "
                    "key is UNIQUE(device_serial, serial_no) and SQLite never dedupes "
                    "NULLs, so storing it would duplicate the row on every overlap poll "
                    "(and digest-deduping it would merge two different events). Route it "
                    "to the dead-letter/alert path instead (P2-04/P2-05)."
                )
            line = to_jsonl([record])[:-1]  # the to_jsonl line without its newline
            returned = conn.execute(_UPSERT, _row_values(record, line, stamp)).fetchone()
            if returned is None:
                # The guard said "identical bytes already in the row": the row exists
                # (the conflict happened), so this lookup cannot miss — if it ever
                # does, that is corruption, and a loud failure beats a 0 rowid.
                unchanged += 1
                rowid = event_rowid(conn, device_serial, record.serial_no)
                if rowid is None:
                    raise StoreError(
                        f"conflict on ({device_serial!r}, {record.serial_no}) but no row: "
                        "the events table changed underneath this batch"
                    )
            else:
                rowid = returned["id"]
                if returned["revision"] == 1:
                    inserted += 1
                else:
                    refreshed += 1
            rowids[record.serial_no] = rowid
    except BaseException:
        conn.execute("ROLLBACK")
        raise
    conn.execute("COMMIT")

    return StoreResult(
        inserted=inserted,
        refreshed=refreshed,
        unchanged=unchanged,
        device_serial=device_serial,
        rowids=rowids,
    )


def event_rowid(conn: sqlite3.Connection, device_serial: str, serial_no: int) -> int | None:
    """The rowid for one key (None when the row does not exist)."""
    row = conn.execute(
        "SELECT id FROM events WHERE device_serial = ? AND serial_no = ?",
        (device_serial, serial_no),
    ).fetchone()
    return None if row is None else row["id"]


def event_jsonl(conn: sqlite3.Connection, rowid: int) -> str | None:
    """The stored payload line for one rowid — byte-verbatim what the push sends."""
    row = conn.execute("SELECT jsonl FROM events WHERE id = ?", (rowid,)).fetchone()
    return None if row is None else row["jsonl"]


# --- the checkpoint -----------------------------------------------------------------------

_CK_INSERT = """
INSERT INTO checkpoint (device_serial, checkpoint_serial, checkpoint_time, updated_at)
VALUES (?, ?, ?, ?)
ON CONFLICT(device_serial) DO UPDATE
SET checkpoint_serial = excluded.checkpoint_serial,
    -- A later advance that cannot name the time must not blank the known one: the
    -- next tick's window lower bound (checkpoint_time - overlap) reads this column.
    checkpoint_time = COALESCE(excluded.checkpoint_time, checkpoint.checkpoint_time),
    updated_at = excluded.updated_at
WHERE excluded.checkpoint_serial > checkpoint.checkpoint_serial
RETURNING checkpoint_serial
"""


def read_oldest_serial(conn: sqlite3.Connection, device_serial: str) -> int | None:
    """The store's floor for one device: ``MIN(serial_no)``, or None with no rows.

    DESIGN.md OQ4 names this number as the ring-rolling detector's input: "the agent
    must record oldest-serialNo per poll (a monotonic increase of the minimum =
    rolling started = punches are being lost)". In THIS store (§2b keep-everything)
    the minimum only rises when rows the agent already kept are gone — the same
    loss event seen from the near side. P2-05's ``check_stall`` reads it as
    evidence-of-loss; the health surface keeps its own metric line (agent_health
    renders `oldest_serial` from the same table, NOTES-p2-06: "no fabrication").
    """
    row = conn.execute(
        "SELECT MIN(serial_no) m FROM events WHERE device_serial = ?",
        (device_serial,),
    ).fetchone()
    return row["m"]


def advance_checkpoint(
    conn: sqlite3.Connection,
    device_serial: str,
    max_serial: int | None,
    *,
    completed: bool,
    checkpoint_time: str | None = None,
    now: datetime | None = None,
) -> CheckpointAdvanced:
    """Advance one device's checkpoint — ONLY over a completed chunk (seam 2).

    `completed=False` raises: paging hands `ChunkResult.max_serial_no` only for
    completed chunks, and checkpointing a half-failed walk's max would skip the failed
    chunk's events on the next poll (DESIGN.md "Paging + checkpoint").

    `max_serial is None` (a completed chunk that held no events) is a no-op, never a
    NULL checkpoint: a NULL would poison P2-03's window lower bound.

    A LOWER serial raises `CheckpointRegressionError` and writes nothing; an EQUAL
    serial is a quiet no-op (the guard is `>`, so no churn). A successful advance is
    exactly ONE statement of change (pinned by test) — no half-applied checkpoint for
    a systemd kill to find.
    """
    if not completed:
        raise CheckpointNotCompletedError(
            f"refusing to advance {device_serial!r} to {max_serial!r}: the chunk did not "
            "complete. paging.py only supplies max_serial_no for completed chunks "
            "(paging.py:612-615); a checkpoint over a half-failed walk skips events."
        )
    if max_serial is None:
        return CheckpointAdvanced(
            device_serial=device_serial, checkpoint_serial=None, advanced=False
        )
    if max_serial < 0:
        raise CheckpointRegressionError(
            f"checkpoint serial {max_serial} is negative — serialNo counts up from 0"
        )

    stamp = _now_iso(now)
    conn.execute("BEGIN IMMEDIATE")
    try:
        # Read the current serial and apply the UPSERT inside ONE transaction: the
        # refusal is reported from the same state the write saw, so it cannot race.
        current = conn.execute(
            "SELECT checkpoint_serial FROM checkpoint WHERE device_serial = ?",
            (device_serial,),
        ).fetchone()
        returned = conn.execute(
            _CK_INSERT, (device_serial, max_serial, checkpoint_time, stamp)
        ).fetchone()
    except BaseException:
        conn.execute("ROLLBACK")
        raise
    conn.execute("COMMIT")

    if returned is not None:
        return CheckpointAdvanced(
            device_serial=device_serial,
            checkpoint_serial=returned["checkpoint_serial"],
            advanced=True,
        )
    if current is not None and max_serial < current["checkpoint_serial"]:
        raise CheckpointRegressionError(
            f"refusing to move {device_serial!r} from {current['checkpoint_serial']} down "
            f"to {max_serial}: the checkpoint only moves forward (a serial reset is a "
            "fingerprint-guard question — DESIGN.md — not a checkpoint regression)"
        )
    return CheckpointAdvanced(
        device_serial=device_serial, checkpoint_serial=max_serial, advanced=False
    )


def read_checkpoint(conn: sqlite3.Connection, device_serial: str) -> Checkpoint | None:
    """The device's checkpoint row, or None when the device has never advanced."""
    row = conn.execute(
        "SELECT device_serial, checkpoint_serial, checkpoint_time, updated_at"
        " FROM checkpoint WHERE device_serial = ?",
        (device_serial,),
    ).fetchone()
    if row is None:
        return None
    return Checkpoint(
        device_serial=row["device_serial"],
        checkpoint_serial=row["checkpoint_serial"],
        checkpoint_time=row["checkpoint_time"],
        updated_at=row["updated_at"],
    )


# --- the disk watermark (gauge; alerting is P2-05) -----------------------------------------


def db_size_bytes(path: Path | str) -> int:
    """Bytes of the main db file (0 when the agent has not created it yet).

    The WAL/SHM siblings are deliberately NOT counted: they are transient journal
    bytes, and the keep-everything growth the watermark exists to watch (spec §2b)
    lives in the main file.
    """
    try:
        return Path(path).stat().st_size
    except FileNotFoundError:
        return 0


def check_db_watermark(path: Path | str, warn_bytes: int) -> WatermarkCheck:
    """Size vs threshold: `warn` is strictly ABOVE (spec §2b "db > 2 GB -> warning").

    Exactly-at is not over — a threshold that fired at its own value would make the
    first alert meaningless and re-fire every tick near a round size. `warn_bytes`
    comes from config (P2-01's `db_warn_bytes`); this helper takes it explicitly so
    the boundary is testable without config and alertable without this module.
    """
    return WatermarkCheck(size_bytes=db_size_bytes(path), warn_bytes=warn_bytes)
