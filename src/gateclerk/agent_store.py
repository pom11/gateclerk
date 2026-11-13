"""The P2 site agent's event store: (device_serial, serial_epoch, serial_no) UPSERT +
completed-only checkpoint.

Card P2-02 (docs/internal/P2-SITE-AGENT.md §1 seams 1-3 + §2b, SIGNED OFF 2026-10-19; device
truth docs/internal/OBSERVED.md). Semantics are pinned by the spec and the box — this module
implements them, it does not invent them:

UPSERT (seam 1). `events` is UNIQUE(device_serial, serial_epoch, serial_no) and every
write is `INSERT .. ON CONFLICT DO UPDATE SET .. WHERE events.jsonl IS NOT excluded.jsonl`.
`serial_epoch` is 0 for every pre-reset row; card t_fbd85a10 adds the next epoch only
when the loop has confirmed a device serialNo reset, so the new generation's reused
serials cannot overwrite the old rows. That `WHERE` is the whole "re-polling an
overlap window is free" guarantee (DESIGN.md "Idempotency key"; the mechanism a
mid-page crash heals by): a re-stored identical line conflicts, the guard is false,
and SQLite does *no* write at all — verified zero statement cost (total_changes delta
0) and row identity (same rowid, same revision, same stamps) in tests. Without the
guard the UPSERT would rewrite identical bytes every 5-min tick: same visible row, a
real write, and `updated_at` churning forever — a store that lies about which records
were ever corrected.

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

Retention (GC-P16a): `prune_pushed_events` is the ONE `DELETE FROM events` in the
product, and it can only reach a row the poller has proof of having delivered (the
caller passes `PushLedger.sent_event_ids()`) and that has aged past the local window.
Everything else stays the owner's call, and everything the queue or the dead-letter
still points at survives. See the function's own docstring for the four guards.

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
    "PROBE_KINDS",
    "PROBE_KIND_RESET",
    "Checkpoint",
    "CheckpointAdvanced",
    "CheckpointNotCompletedError",
    "CheckpointRegressionError",
    "CheckpointReset",
    "MixedDeviceError",
    "ProbeWindow",
    "StoreError",
    "StoreResult",
    "UnusableRecordError",
    "WatermarkCheck",
    "advance_checkpoint",
    "check_db_watermark",
    "db_size_bytes",
    "event_jsonl",
    "event_rowid",
    "prune_pushed_events",
    "read_checkpoint",
    "read_oldest_serial",
    "read_probe_window",
    "record_probe_window",
    "reset_checkpoint",
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
    #: Which serial generation the checkpoint names. 0 on every pre-reset row; a
    #: confirmed serial reset opens the next epoch so a reused serialNo cannot
    #: collide with (or overwrite) a row from the previous generation.
    serial_epoch: int = 0
    #: The firmware version the checkpoint was written under, when known. The loop
    #: compares it with a fresh deviceInfo read before accepting a lower newest
    #: serial as reset evidence (agent_loop._reset_evidence).
    firmware: str | None = None


@dataclass(frozen=True, slots=True)
class CheckpointReset:
    """The outcome of one confirmed serial reset (`reset_checkpoint`)."""

    device_serial: str
    old_serial: int
    new_serial: int
    old_epoch: int
    new_epoch: int


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


def _from_iso(stamp: str) -> datetime:
    """Read back a stamp `_now_iso` wrote — the only format this db's clock columns use.

    The counterpart exists because `probe_audit`'s window pair is read by the loop's
    budget, not just by an operator: parsing it here (instead of at each call site) keeps
    one reader for one format, and a naive stamp — which nothing here writes — is refused
    rather than compared against an aware `now` (that comparison would raise TypeError
    inside a poll tick).
    """
    moment = datetime.fromisoformat(stamp)
    if moment.tzinfo is None:
        raise ValueError(f"stamp {stamp!r} is naive; every clock column here is UTC ISO")
    return moment


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
    "serial_epoch",
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
    serial_epoch,
    site, device_serial, serial_no, employee_no, name,
    event_time_utc, event_time_local, tz_offset_min, tz_offset_min_device, tz_source,
    iana_tz, tz_unresolved, tz_ambiguous, tz_nonexistent, tz_reason, tz_offset_mismatch,
    direction, attendance_status, direction_source, verify_mode, major, minor, outcome,
    unknown_code, encrypted_person_data, raw, captured_at
) VALUES (
    NULL, 1,
    ?, ?, ?,
    ?, ?, ?, ?, ?,
    ?,
    ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
    ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
    ?, ?, ?, ?, ?, ?, ?
)
ON CONFLICT(device_serial, serial_epoch, serial_no) DO UPDATE
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


def _row_values(record: EventRecord, line: str, stamp: str, serial_epoch: int = 0) -> list[Any]:
    """One UPSERT parameter tuple: jsonl verbatim + digests + flattened contract.

    `to_dict()` is the model's own flat view (datetimes already ISO, enums already
    str) — the same dict `to_jsonl` serialises, so the columns and the stored line
    cannot disagree. `raw` has no sqlite scalar form: it goes in as JSON text.
    `serial_epoch` is store bookkeeping, not contract: it never appears in the
    payload, it only lets two generations share a serialNo in one table.
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
        serial_epoch,
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
    serial_epoch: int = 0,
) -> StoreResult:
    """UPSERT a batch (one poll window / one chunk's records). Returns per-outcome counts.

    One transaction, so a batch is all-or-nothing (a crash mid-batch leaves nothing
    half-stored — the overlap poll is the healer, and it needs a clean key space).
    A batch that repeats a key is legal (overlap page + new page in one call): the
    guard makes the repeat free and the last line for the key wins.

    `serial_epoch` is the current generation of the device's serialNo. Before the
    UPSERT, a record whose fingerprint `(employee_no, event_time_local, minor)` is
    already stored for this device is skipped as the same punch: that is the
    secondary guard DESIGN.md defines for a serial reset, and it is what stops a
    pre-reset punch re-read after the reset from being pushed twice under the new
    epoch. Only a record with no matching fingerprint gets a row in this epoch, so
    two different punches may share a serialNo across epochs without merging.
    """
    batch = list(records)
    if not batch:
        return StoreResult(inserted=0, refreshed=0, unchanged=0)
    if serial_epoch < 0:
        raise ValueError(f"serial_epoch {serial_epoch} cannot be negative")

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
                    "key is UNIQUE(device_serial, serial_epoch, serial_no) and SQLite never "
                    "dedupes NULLs, so storing it would duplicate the row on every overlap "
                    "poll (and digest-deduping it would merge two different events). Route it "
                    "to the dead-letter/alert path instead (P2-04/P2-05)."
                )
            exact = conn.execute(
                "SELECT 1 FROM events WHERE device_serial = ? AND serial_epoch = ?"
                " AND serial_no = ?",
                (device_serial, serial_epoch, record.serial_no),
            ).fetchone()
            if exact is None:
                already = conn.execute(
                    "SELECT 1 FROM events WHERE device_serial = ? AND serial_epoch <> ?"
                    " AND fingerprint_hash = ? LIMIT 1",
                    (device_serial, serial_epoch, record.fingerprint_hash),
                ).fetchone()
                if already is not None:
                    # Same employee + device-local time + minor: the same punch, already
                    # kept under an older epoch. Never a second push across a reset.
                    unchanged += 1
                    continue
            line = to_jsonl([record])[:-1]  # the to_jsonl line without its newline
            returned = conn.execute(
                _UPSERT, _row_values(record, line, stamp, serial_epoch)
            ).fetchone()
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
INSERT INTO checkpoint (
    device_serial, checkpoint_serial, checkpoint_time, serial_epoch, firmware, updated_at
)
VALUES (?, ?, ?, ?, ?, ?)
ON CONFLICT(device_serial) DO UPDATE
SET checkpoint_serial = excluded.checkpoint_serial,
    -- A later advance that cannot name the time must not blank the known one: the
    -- next tick's window lower bound (checkpoint_time - overlap) reads this column.
    checkpoint_time = COALESCE(excluded.checkpoint_time, checkpoint.checkpoint_time),
    -- The firmware the checkpoint was written under is reset evidence; an advance
    -- that cannot name it keeps the known one.
    firmware = COALESCE(excluded.firmware, checkpoint.firmware),
    updated_at = excluded.updated_at
WHERE excluded.checkpoint_serial > checkpoint.checkpoint_serial
  AND excluded.serial_epoch = checkpoint.serial_epoch
RETURNING checkpoint_serial
"""


def read_oldest_serial(conn: sqlite3.Connection, device_serial: str) -> int | None:
    """The store's floor for one device: ``MIN(serial_no)``, or None with no rows.

    This is OUR keep-everything store's minimum, not the device's oldest retained
    event: real ring rollover does not move it. A rise here means rows the agent
    already kept are gone (deleted or lost), so P2-05's ``check_stall`` names this
    arm "stored history disappeared". The device-side ring floor is a separate
    read-only probe (``DeviceLoop.probe_ring_floor``, card t_ed9c7e92; DESIGN.md:411)
    that asks for the oldest retained event of any major; the health surface keeps its
    own store metric line (agent_health renders `oldest_serial` from the same table,
    NOTES-p2-06: "no fabrication").
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
    serial_epoch: int = 0,
    firmware: str | None = None,
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
    a systemd kill to find. A different `serial_epoch` is never advanced here: only
    `reset_checkpoint`, after the loop has confirmed reset evidence, may open one.
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
    if serial_epoch < 0:
        raise CheckpointRegressionError(
            f"serial_epoch {serial_epoch} is negative — an epoch starts at 0"
        )

    stamp = _now_iso(now)
    conn.execute("BEGIN IMMEDIATE")
    try:
        # Read the current serial and apply the UPSERT inside ONE transaction: the
        # refusal is reported from the same state the write saw, so it cannot race.
        current = conn.execute(
            "SELECT checkpoint_serial, serial_epoch FROM checkpoint WHERE device_serial = ?",
            (device_serial,),
        ).fetchone()
        returned = conn.execute(
            _CK_INSERT,
            (device_serial, max_serial, checkpoint_time, serial_epoch, firmware, stamp),
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
    if current is not None and serial_epoch != current["serial_epoch"]:
        raise CheckpointRegressionError(
            f"refusing to advance {device_serial!r} from epoch {current['serial_epoch']} "
            f"under epoch {serial_epoch}: only a confirmed serial reset may open a new "
            "epoch (reset_checkpoint)"
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


def reset_checkpoint(
    conn: sqlite3.Connection,
    device_serial: str,
    *,
    expected_serial: int,
    new_serial: int,
    checkpoint_time: str | None = None,
    firmware: str | None = None,
    now: datetime | None = None,
) -> CheckpointReset:
    """Open a new serial epoch after a CONFIRMED reset — the only legal rewind.

    The caller has already seen the device's newest serial below the checkpoint and
    read the fresh deviceInfo evidence (`agent_loop._reset_evidence`); this function
    is the store half, not the decision. `expected_serial` is a compare-and-swap: if
    the checkpoint moved since the walk began, refuse rather than rewind a state the
    caller did not see (two writers are not expected, but a wrong rewind is exactly
    the silent loss this card forbids). One UPDATE keeps the row atomic under a kill.
    """
    if new_serial < 0:
        raise CheckpointRegressionError(
            f"reset checkpoint serial {new_serial} is negative — serialNo counts up from 0"
        )
    stamp = _now_iso(now)
    conn.execute("BEGIN IMMEDIATE")
    try:
        current = conn.execute(
            "SELECT checkpoint_serial, serial_epoch FROM checkpoint WHERE device_serial = ?",
            (device_serial,),
        ).fetchone()
        if current is None:
            raise CheckpointRegressionError(
                f"refusing to reset {device_serial!r}: no checkpoint row to rewind"
            )
        if current["checkpoint_serial"] != expected_serial:
            raise CheckpointRegressionError(
                f"refusing to reset {device_serial!r}: expected checkpoint serial "
                f"{expected_serial}, found {current['checkpoint_serial']} — the state "
                "moved after the reset evidence was read"
            )
        returned = conn.execute(
            "UPDATE checkpoint"
            " SET checkpoint_serial = ?,"
            "     checkpoint_time = COALESCE(?, checkpoint_time),"
            "     serial_epoch = serial_epoch + 1,"
            "     firmware = COALESCE(?, firmware),"
            "     updated_at = ?"
            " WHERE device_serial = ? AND checkpoint_serial = ?"
            " RETURNING serial_epoch",
            (new_serial, checkpoint_time, firmware, stamp, device_serial, expected_serial),
        ).fetchone()
    except BaseException:
        conn.execute("ROLLBACK")
        raise
    conn.execute("COMMIT")
    return CheckpointReset(
        device_serial=device_serial,
        old_serial=expected_serial,
        new_serial=new_serial,
        old_epoch=current["serial_epoch"],
        new_epoch=returned["serial_epoch"],
    )


def read_checkpoint(conn: sqlite3.Connection, device_serial: str) -> Checkpoint | None:
    """The device's checkpoint row, or None when the device has never advanced."""
    row = conn.execute(
        "SELECT device_serial, checkpoint_serial, checkpoint_time, updated_at,"
        " serial_epoch, firmware FROM checkpoint WHERE device_serial = ?",
        (device_serial,),
    ).fetchone()
    if row is None:
        return None
    return Checkpoint(
        device_serial=row["device_serial"],
        checkpoint_serial=row["checkpoint_serial"],
        checkpoint_time=row["checkpoint_time"],
        updated_at=row["updated_at"],
        serial_epoch=row["serial_epoch"],
        firmware=row["firmware"],
    )


# --- the probe audit trail (GC-P15 follow-up) ----------------------------------------------
#
# A quiet tick answers "was the terminal swapped?" with one newest-first AcsEvent page
# (`agent_loop._probe_newest_serial`) and, before this section, threw the answer away: the
# only durable trace of a probe was `reset_checkpoint`, which runs only when the probe
# CONFIRMED a reset. These two functions are the store half of the missing answer — what
# the probe ASKED (the window) and what it COST (the pages it sent) — written even when the
# page came back NO MATCH, because "we looked and nothing moved" is exactly the state
# P2-05's `check_stall` cannot otherwise distinguish from "we never looked".
#
# One row per (device, kind): the ring-floor read asks a different question and must never
# satisfy this probe's budget (see `_PROBE_AUDIT_V8` in agent_db for the schema argument).

#: The quiet-tick reset probe (`agent_loop.RESET_PROBE_INTERVAL_S` / `_probe_newest_serial`).
PROBE_KIND_RESET = "reset"

#: Every kind `record_probe_window` accepts. A kind nothing reads would fork a second
#: budget line no operator can see, so a new kind must arrive together with its reader.
PROBE_KINDS: frozenset[str] = frozenset({PROBE_KIND_RESET})


@dataclass(frozen=True, slots=True)
class ProbeWindow:
    """One device's last COMPLETED probe of one kind: what it asked, what it cost.

    The stamps are the stored text (one format, `_now_iso`); `probed_at` is the parsed
    instant the loop's budget is measured against.
    """

    device_serial: str
    kind: str
    window_from_utc: str
    window_to_utc: str
    reads: int

    @property
    def probed_at(self) -> datetime:
        """When the probe ran — the upper bound it asked for (`_PROBE_AUDIT_V8`)."""
        return _from_iso(self.window_to_utc)


#: One UPSERT and nothing else: `reset_checkpoint`'s kill-safety argument applies verbatim
#: here — the systemd unit can die between any two statements, so the row must land whole.
_PROBE_UPSERT = """
INSERT INTO probe_audit (
    device_serial, kind, window_from_utc, window_to_utc, reads
) VALUES (?, ?, ?, ?, ?)
ON CONFLICT(device_serial, kind) DO UPDATE
SET window_from_utc = excluded.window_from_utc,
    window_to_utc = excluded.window_to_utc,
    reads = excluded.reads
RETURNING reads
"""


def record_probe_window(
    conn: sqlite3.Connection,
    device_serial: str,
    *,
    kind: str,
    window_from: datetime,
    window_to: datetime,
    reads: int,
) -> ProbeWindow:
    """Record what one COMPLETED probe asked for and what it cost (one UPSERT).

    Both window bounds go through `_now_iso`, so this column pair is the same UTC ISO
    instant-format as every other clock column here; the caller passes the SAME instants it
    put on the wire (relabeled for the device inside paging), not a re-derivation.

    Refusals, all before any write, all loud:
    * an unknown `kind` — a kind nothing reads is a forked budget (see `PROBE_KINDS`);
    * `window_to < window_from` — an inverted window was never asked for; `chunk_window`
      refuses to page one, so a row claiming it would be a stamp for a request that could
      not have been sent (an equal pair is legal: paging yields no chunk and no request);
    * a negative `reads`, or a naive bound (the db has no naive instants).

    Deliberately NOT recorded: a probe whose read raised. A row here means "a page came
    back over this window" (empty included); stamping a dead read as one of those would
    make the failure indistinguishable from the clean answer the row exists to prove, and
    the loop's own `warn` line is where a dead probe is reported.
    """
    if kind not in PROBE_KINDS:
        raise ValueError(
            f"unknown probe kind {kind!r}; this db records {sorted(PROBE_KINDS)} — a kind "
            "nothing reads would keep a budget no operator can see, so add its reader first"
        )
    for name, bound in (("window_from", window_from), ("window_to", window_to)):
        if bound.tzinfo is None:
            raise ValueError(
                f"probe {name} must be tz-aware (payroll data; pyproject DTZ) — a naive "
                "bound has no place in a window the store is asked to remember"
            )
    if window_to < window_from:
        raise ValueError(
            f"probe window is inverted ({window_from.isoformat()} -> "
            f"{window_to.isoformat()}): paging refuses to walk one, so no request "
            "ever asked for it"
        )
    if reads < 0:
        raise ValueError(f"probe reads {reads} is negative — a request count counts up")
    lower = _now_iso(window_from)
    upper = _now_iso(window_to)

    conn.execute("BEGIN IMMEDIATE")
    try:
        conn.execute(_PROBE_UPSERT, (device_serial, kind, lower, upper, reads)).fetchone()
    except BaseException:
        conn.execute("ROLLBACK")
        raise
    conn.execute("COMMIT")
    return ProbeWindow(
        device_serial=device_serial,
        kind=kind,
        window_from_utc=lower,
        window_to_utc=upper,
        reads=reads,
    )


def read_probe_window(
    conn: sqlite3.Connection, device_serial: str, *, kind: str
) -> ProbeWindow | None:
    """The device's last recorded probe of `kind` (None = it has never completed one).

    READ THE ROW FOR WHAT IT IS: one answer about ITS OWN WINDOW. `window_to_utc` is the
    instant the read ran and `[window_from_utc, window_to_utc]` the range it covered, so the
    question this row can answer is "what did the device hold, over that range, as of that
    instant" — never "has the device been quiet ever since". A consumer that wants the
    latter must compare `probed_at` with its own clock and treat the row as stale the moment
    the window it describes ends; reading an old row as an all-time answer would page (or
    stay silent) on evidence that has expired. P2-05's `check_stall` does not consult this
    table yet — that wiring and its alert vocabulary are a separate decision.
    """
    row = conn.execute(
        "SELECT device_serial, kind, window_from_utc, window_to_utc, reads"
        " FROM probe_audit WHERE device_serial = ? AND kind = ?",
        (device_serial, kind),
    ).fetchone()
    if row is None:
        return None
    return ProbeWindow(
        device_serial=row["device_serial"],
        kind=row["kind"],
        window_from_utc=row["window_from_utc"],
        window_to_utc=row["window_to_utc"],
        reads=row["reads"],
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


# --- GC-P16a: local retention (BC is the store, the agent is a buffer) ---------------------


def prune_pushed_events(
    conn: sqlite3.Connection,
    *,
    event_ids: set[int],
    before_utc: str,
) -> int:
    """Delete pushed events older than the cutoff; queued/dead-lettered rows survive.

    WHY. Table 70607 owns the permanent payroll record, so an event this poller has
    already delivered — or the owner has already discarded — is a local copy of PII
    (`name`, `employee_no`, the `raw` device dict) with no reason to live on forever.
    This is the only statement in the product that deletes from `events`; the rest of
    retention (the bundle TTL, the ledger's own growth) is elsewhere, and an owner's
    hand-made purge is still theirs alone (spec §2b).

    Four rows it can never delete, each guard load-bearing:

    * anything not named in `event_ids`. The caller hands over the poller's own ledger
      (`PushLedger.sent_event_ids()`), so "we have proof this left the building" is a
      precondition rather than a hope — an unpushed event is the diagnostic buffer
      staying useful, and an empty ledger short-circuits before a write transaction
      opens at all;
    * anything with no `event_time_utc` or no older than `before_utc`. An unresolved
      time is not evidence of age (`tz.py`: an unresolvable stamp keeps the row with
      `event_time_utc = None` and `tz_unresolved`), and the window is a retention
      promise, not an eager delete;
    * anything `push_queue` still points at. `ON DELETE RESTRICT` already refuses that
      delete at the db level; the explicit `NOT EXISTS` says the same thing in the query
      so the intent survives a future edit of either half;
    * anything with a `dead_letter` row. That table deliberately has NO foreign key (the
      record of a punch that never reached the ingest must outlive the event — v4), so
      here `NOT EXISTS` is the only thing between this statement and an unrecoverable
      loss. `tests/test_gc_p16a_prune_events.py` pins it with the control that removes
      the dead-letter row and shows the same event then does go.

    `before_utc` is compared as TEXT, and that is chronological for this column and only
    for this column: `event_time_utc` is written from `ResolvedTime.utc` (`tz.py:334`,
    `astimezone(UTC)`), so every stored value is `+00:00` ISO. A caller holding a
    non-UTC clock must normalise before formatting — the tick hook in `agent_cli` does.

    One transaction per batch, the module's idiom (`store_events` above): staging and
    delete all apply or none, because these rows cannot be recovered locally — the
    ledger is the only proof they were ever here.

    Returns the number of rows deleted, and nothing else: no id, name or payload crosses
    this boundary (P2-06's rule for state surfaces, applied to a return value).
    """
    if not event_ids:
        return 0
    ids = sorted(event_ids)
    conn.execute("BEGIN IMMEDIATE")
    try:
        conn.execute(
            "CREATE TEMP TABLE IF NOT EXISTS prune_ids (event_id INTEGER NOT NULL PRIMARY KEY)"
        )
        conn.execute("DELETE FROM temp.prune_ids")
        conn.executemany(
            "INSERT OR IGNORE INTO temp.prune_ids VALUES (?)",
            ((event_id,) for event_id in ids),
        )
        cur = conn.execute(
            """
            DELETE FROM events
             WHERE id IN (SELECT event_id FROM temp.prune_ids)
               AND event_time_utc IS NOT NULL
               AND event_time_utc < ?
               AND NOT EXISTS (SELECT 1 FROM push_queue AS q WHERE q.event_id = events.id)
               AND NOT EXISTS (SELECT 1 FROM dead_letter AS d WHERE d.event_id = events.id)
            """,
            (before_utc,),
        )
        deleted = cur.rowcount
    except BaseException:
        conn.execute("ROLLBACK")
        raise
    conn.execute("COMMIT")
    return deleted
