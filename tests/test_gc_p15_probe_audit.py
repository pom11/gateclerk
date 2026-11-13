"""GC-P15 follow-up: the quiet-tick reset probe leaves a durable trace and a durable budget.

BINDING SPEC: GC-P15's own request math (one extra newest-first page, at most once an
hour) plus the two consequences its shipped probe left behind — both real failures, not
tidiness:

(1) the answer was thrown away. The only durable trace of a probe was
    `agent_store.reset_checkpoint`, which runs ONLY when the probe CONFIRMED a reset, so
    "we never looked" and "we looked and the ring is quiet" produced the same db. P2-05's
    `check_stall` reads a store it cannot interrogate, and an operator triaging a silent
    agent reads the same blind db;
(2) `RESET_PROBE_INTERVAL_S` lived in `DeviceLoop.__init__` (`self._last_reset_probe_at`),
    so every process start reset the budget and "at most one page per hour" became "one
    page per restart" — a real request budget spent against a device that counts nonces
    (spec §2a).

The pins below are the store half (schema v8 `probe_audit`, the one UPSERT that writes it,
the refusals that keep the row worth reading) and the loop half (a quiet tick with nothing
to find still records the window it asked for and what it cost; a restart inherits the
budget from that row; the monotonic clock remains the only clock that can spend it; and the
ring-floor read stays a DIFFERENT question with no row of its own).

Offline by construction: FakeDevice behind the real IsapiClient, tmp sqlite, injected wall
+ monotonic clocks, no socket. The harness and every device seed are GC-P15's own
(`tests/test_gc_p15_cold_reset.py`), imported rather than re-derived, so this file cannot
drift from the scenario the shipped probe was written against — including its honour-the-
filter arm (`FakeDevice.honour_event_major_filter`, installed by `honouring_device`), without
which the quiet tick is unreachable: the narrow `major=5` poll would answer with the very
`major=3` heartbeats the `major=0` probe exists to find, and the assertions below would pass
off the pre-existing in-window branch.

Request counts here filter on `served.had_auth`: a NEW client (every restart) pays the
digest handshake's unauthenticated first hop, and counting that hop as a read would make
the cadence assertion below lie by exactly one.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from zoneinfo import ZoneInfo

import pytest

from fakedevice import FakeDevice
from gateclerk import agent_db, agent_loop, agent_store
from gateclerk.agent_db import connect
from gateclerk.agent_loop import RESET_PROBE_INTERVAL_S, RESET_PROBE_WINDOW_S
from gateclerk.agent_store import (
    PROBE_KIND_RESET,
    Checkpoint,
    read_checkpoint,
    read_probe_window,
    record_probe_window,
)
from gateclerk.exceptions import IsapiError
from test_gc_p15_cold_reset import (
    QUIET_S,
    SERIAL,
    LoopHarness,
    kill_probe_reads,
    quiet_replacement,
)
from test_p2_03_scheduler import EVENT_PATH, T0

#: One probe's worth of window, narrower than the retained ring so the pair under test is
#: demonstrably the caller's and not a constant the store could have invented.
WINDOW_S = 3 * 60 * 60

SITE = ZoneInfo("Europe/Bucharest")  # the scenario's site zone (test_p2_03_scheduler.SITE_TZ)


def utc(seconds_ago: float) -> datetime:
    """One instant on the scenario clock (`T0` is the harness's first tick, site wall)."""
    return T0 - timedelta(seconds=seconds_ago)


def as_utc(moment: datetime) -> str:
    """The one stamp format this db writes, computed here rather than typed from memory."""
    return moment.astimezone(UTC).isoformat(timespec="seconds")


def audit_rows(conn) -> list[dict[str, Any]]:
    """Every `probe_audit` row, as dicts — what an operator reads out of the db."""
    return [dict(r) for r in conn.execute("SELECT * FROM probe_audit ORDER BY device_serial, kind")]


def probe_posts(device: FakeDevice) -> list[dict[str, Any]]:
    """The authenticated newest-first one-row POSTs — the probe's own requests."""
    return _served_event_conds(device, reverse=True)


def narrow_posts(device: FakeDevice) -> list[dict[str, Any]]:
    """The authenticated oldest-first window POSTs — the narrow poll every tick owes."""
    return _served_event_conds(device, reverse=False)


def _served_event_conds(device: FakeDevice, *, reverse: bool) -> list[dict[str, Any]]:
    import json

    out = []
    for served in device.served:
        if served.method != "POST" or served.path != EVENT_PATH or not served.had_auth:
            continue
        if not served.body or b"AcsEventCond" not in served.body:
            continue
        cond = json.loads(served.body).get("AcsEventCond", {})
        if not isinstance(cond, dict) or "startTime" not in cond:
            continue
        if bool(cond.get("timeReverseOrder")) is reverse:
            out.append(cond)
    return out


def restart(h: LoopHarness, tmp_path: Path) -> LoopHarness:
    """The same db file, the same fake device, the same clocks — new process memory.

    A fresh `LoopHarness` over the same path is what a systemd restart is here: a new
    `DeviceLoop` (so `self._last_reset_probe_at` is None again), a new `IsapiClient` (so the
    transport's own state is gone) and a cleared capability cache — while the sqlite file the
    durable budget lives in is the one already written. The clocks are shared because the
    operator did not touch them; only the process restarted.
    """
    return LoopHarness(tmp_path, h.device, clock=h.clock, monotonic=h.monotonic)


# ===========================================================================================
# (A) the store half: schema v8, and the one UPSERT that writes it
# ===========================================================================================


def test_probe_audit_ships_as_an_additive_v8() -> None:
    """A new entry, appended: the history stays forward-only and nothing before v8 moved."""
    assert [m.version for m in agent_db.MIGRATIONS] == list(range(1, len(agent_db.MIGRATIONS) + 1))
    latest = agent_db.MIGRATIONS[-1]
    assert (latest.version, latest.name) == (8, "probe_audit")
    # Additive in the strong sense: one CREATE of an empty table. The per-sink steps (v5/v6)
    # rebuild because a UNIQUE constraint cannot be altered in sqlite; a new table must not
    # borrow that shape, or "additive" stops meaning "nothing can be lost".
    sql = latest.sql.upper()
    assert "CREATE TABLE PROBE_AUDIT" in sql
    assert "DROP TABLE" not in sql and "INSERT INTO" not in sql and "ALTER" not in sql


def test_a_v7_store_upgrades_to_v8_without_losing_its_checkpoint(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A deployed site IS a v7 db with a checkpoint in it: the upgrade must not disturb it."""
    path = tmp_path / "agent.sqlite3"
    monkeypatch.setattr(agent_db, "MIGRATIONS", tuple(agent_db.MIGRATIONS[:7]))
    old = connect(path)
    assert agent_db.current_version(old) == 7
    old.execute(
        "INSERT INTO checkpoint (device_serial, checkpoint_serial, checkpoint_time,"
        " serial_epoch, firmware, updated_at) VALUES (?, ?, ?, ?, ?, ?)",
        (SERIAL, 100, "2026-10-19T09:55:00", 0, "V1.0.2", as_utc(utc(0))),
    )
    monkeypatch.undo()  # the reopen must use the real, v8-carrying history

    new = connect(path)
    try:
        assert agent_db.current_version(new) == agent_db.MIGRATIONS[-1].version
        cp = read_checkpoint(new, SERIAL)
        assert cp is not None and (cp.checkpoint_serial, cp.serial_epoch) == (100, 0)
        assert read_probe_window(new, SERIAL, kind=PROBE_KIND_RESET) is None
    finally:
        new.close()


def test_the_row_carries_exactly_the_columns_the_schema_promises(tmp_path: Path) -> None:
    """An operator reads this table by hand; a column drifting in would be a lie in it."""
    conn = connect(tmp_path / "agent.sqlite3")
    columns = {r["name"] for r in conn.execute("PRAGMA table_info(probe_audit)")}
    assert columns == {"device_serial", "kind", "window_from_utc", "window_to_utc", "reads"}


def test_record_probe_window_writes_the_callers_window_in_the_stores_one_format(
    tmp_path: Path,
) -> None:
    """The pair is what the probe ASKED, relabelled to UTC — not a re-derivation.

    `T0` is a site-wall afternoon in `Europe/Bucharest` (a +03:00 October), so the stored
    digits must shift by the site offset and carry the same `+00:00` label `_now_iso` writes
    on every other clock column: an operator comparing `checkpoint.updated_at` with
    `probe_audit.window_to_utc` is reading two stamps that must mean the same thing.
    """
    conn = connect(tmp_path / "agent.sqlite3")
    lower, upper = utc(WINDOW_S), utc(0)

    row = record_probe_window(
        conn, SERIAL, kind=PROBE_KIND_RESET, window_from=lower, window_to=upper, reads=1
    )

    assert row.window_to_utc == as_utc(upper)
    assert row.window_from_utc == as_utc(lower)
    assert row.window_to_utc.endswith("+00:00")  # one format; never a `Z`, never naive
    assert row.reads == 1
    assert audit_rows(conn) == [
        {
            "device_serial": SERIAL,
            "kind": PROBE_KIND_RESET,
            "window_from_utc": as_utc(lower),
            "window_to_utc": as_utc(upper),
            "reads": 1,
        }
    ]
    # `probed_at` is the instant the budget is measured against: the upper bound, parsed
    # back to the same instant it was written from.
    assert row.probed_at == upper.astimezone(UTC)
    assert read_probe_window(conn, SERIAL, kind=PROBE_KIND_RESET) == row


def test_record_probe_window_is_exactly_one_statement_of_change(tmp_path: Path) -> None:
    """Kill-safety, borrowed from `reset_checkpoint` verbatim.

    The systemd unit can die between any two statements, so the row must land whole or not
    at all — one UPSERT is the whole write, for the first record AND for every replacement of
    it (a two-statement write could be caught halfway, with the row naming a window the unit
    died in the middle of asking for).
    """
    conn = connect(tmp_path / "agent.sqlite3")
    lower, upper = utc(WINDOW_S), utc(0)

    before = conn.total_changes
    record_probe_window(
        conn, SERIAL, kind=PROBE_KIND_RESET, window_from=lower, window_to=upper, reads=1
    )
    inserted = conn.total_changes - before

    before = conn.total_changes
    record_probe_window(
        conn,
        SERIAL,
        kind=PROBE_KIND_RESET,
        window_from=utc(2 * WINDOW_S),
        window_to=utc(0),
        reads=2,
    )
    replaced = conn.total_changes - before

    assert (inserted, replaced) == (1, 1)
    assert len(audit_rows(conn)) == 1


def test_the_row_is_one_per_device_and_kind(tmp_path: Path) -> None:
    """The ring floor must not be able to answer for the reset probe's budget.

    `kind` is in the primary key for exactly this: two questions from one device keep two
    rows, so a future `ring_floor` row can neither overwrite the reset probe's window nor
    satisfy the hourly budget measured from it (and vice versa — the half a shared row would
    get wrong silently, because on the db the two reads look alike).
    """
    conn = connect(tmp_path / "agent.sqlite3")
    lower, upper = utc(WINDOW_S), utc(0)
    record_probe_window(
        conn, SERIAL, kind=PROBE_KIND_RESET, window_from=lower, window_to=upper, reads=1
    )
    record_probe_window(
        conn,
        "MASKED-SER-2",
        kind=PROBE_KIND_RESET,
        window_from=lower,
        window_to=upper,
        reads=1,
    )
    conn.execute(
        "INSERT INTO probe_audit (device_serial, kind, window_from_utc, window_to_utc, reads)"
        " VALUES (?, 'ring_floor', ?, ?, ?)",
        (SERIAL, as_utc(lower), as_utc(upper), 1),
    )

    rows = audit_rows(conn)
    assert [(r["device_serial"], r["kind"]) for r in rows] == [
        (SERIAL, "reset"),
        (SERIAL, "ring_floor"),
        ("MASKED-SER-2", "reset"),
    ]
    # The reset reader sees only the reset answer, even with a fresher row of the other kind
    # sitting beside it.
    row = read_probe_window(conn, SERIAL, kind=PROBE_KIND_RESET)
    assert row is not None and row.kind == PROBE_KIND_RESET


def test_a_refusal_writes_nothing(tmp_path: Path) -> None:
    """Each refusal below names a row that would be read as evidence and is not evidence.

    An unknown `kind` would fork a budget no reader exists for; an inverted pair names a
    window `chunk_window` refuses to walk (so no request ever asked it); a negative count
    names a cost that cannot have been paid; a naive bound has no instant to compare with
    `now`, and comparing one would raise `TypeError` inside a poll tick.
    """
    conn = connect(tmp_path / "agent.sqlite3")
    lower, upper = utc(WINDOW_S), utc(0)
    cases: list[tuple[dict[str, Any], str]] = [
        (
            {"kind": "ring_floor", "window_from": lower, "window_to": upper, "reads": 1},
            "unknown probe kind",
        ),
        (
            {"kind": PROBE_KIND_RESET, "window_from": upper, "window_to": lower, "reads": 1},
            "inverted",
        ),
        (
            {"kind": PROBE_KIND_RESET, "window_from": lower, "window_to": upper, "reads": -1},
            "negative",
        ),
        (
            {
                "kind": PROBE_KIND_RESET,
                "window_from": lower.replace(tzinfo=None),
                "window_to": upper,
                "reads": 1,
            },
            "tz-aware",
        ),
    ]
    for kwargs, needle in cases:
        before = conn.total_changes
        with pytest.raises(ValueError) as exc:
            record_probe_window(conn, SERIAL, **kwargs)
        assert needle in str(exc.value), (needle, str(exc.value))
        assert conn.total_changes == before, f"{needle}: the refusal wrote a row"
    assert audit_rows(conn) == []
    assert read_probe_window(conn, SERIAL, kind=PROBE_KIND_RESET) is None


def test_an_empty_window_is_recordable_and_a_missing_row_reads_as_never_probed(
    tmp_path: Path,
) -> None:
    """`window_from == window_to` is legal and costs zero requests.

    `chunk_window` yields no chunk for an empty range (paging.py: "an empty range (start ==
    end) yields no chunks"), so a probe whose checkpoint stamp IS `now` asked a window it
    never sent. A row saying `reads = 0` is the honest record of that, and the store must not
    invent a minimum cost for it.
    """
    conn = connect(tmp_path / "agent.sqlite3")
    now = utc(0)
    row = record_probe_window(
        conn, SERIAL, kind=PROBE_KIND_RESET, window_from=now, window_to=now, reads=0
    )
    assert row.window_from_utc == row.window_to_utc
    assert row.reads == 0
    assert read_probe_window(conn, "MASKED-SER-9", kind=PROBE_KIND_RESET) is None


def test_the_store_is_the_only_writer_and_a_fresh_db_has_no_rows(tmp_path: Path) -> None:
    """The audit trail is not a second truth: exactly one INSERT, and no other statement.

    GC-P15's `reset_checkpoint` is a single UPDATE on `checkpoint` and stays that way — the
    probe's row cannot ride on it, because the case `check_stall` needs is the probe that
    found NOTHING (and a rewind-free probe is the common one).
    """
    source = Path(agent_store.__file__).read_text(encoding="utf-8")
    assert source.count("INSERT INTO probe_audit") == 1
    assert source.count("UPDATE probe_audit") == 0
    assert source.count("DELETE FROM probe_audit") == 0
    conn = connect(tmp_path / "agent.sqlite3")
    assert audit_rows(conn) == []


# ===========================================================================================
# (B) the loop half: a quiet tick records what it asked, even when it finds nothing
# ===========================================================================================


def test_a_quiet_tick_with_nothing_to_find_still_records_the_window_and_the_cost(
    tmp_path: Path,
) -> None:
    """The card's first DoD line: a checked-and-clean agent must not look like a silent one.

    Nothing here rewinds (the newest serial is above the checkpoint), so what GC-P15 shipped
    was a tick that returned `ok` and left no trace at all. Now the db says what was asked:
    the window `[checkpoint_time, now]`, and the one page it cost.
    """
    h = quiet_replacement(tmp_path, new_serials=[(101, "2026-10-19T10:08:00")], upgraded=False)
    assert read_probe_window(h.conn, SERIAL, kind=PROBE_KIND_RESET) is None

    quiet = h.tick()

    assert quiet.ok and quiet.records == 0 and quiet.serial_reset is None
    row = read_probe_window(h.conn, SERIAL, kind=PROBE_KIND_RESET)
    assert row is not None and row.kind == PROBE_KIND_RESET
    assert row.reads == 1 == len(probe_posts(h.device))
    # The stored pair IS the window the probe asked for, in the store's one instant format.
    # Compared as instants against the loop's own clock — the wire form is the same window
    # relabelled with the claimed device offset (paging's "window offsets are ARITHMETIC for
    # the device"), so digit-for-digit equality with `startTime` would be a different
    # question, and GC-P15 already pins that one.
    assert row.window_to_utc == as_utc(T0 + timedelta(seconds=QUIET_S))
    cp = read_checkpoint(h.conn, SERIAL)
    assert cp is not None and cp.checkpoint_time is not None
    checkpoint_at = datetime.fromisoformat(cp.checkpoint_time).replace(tzinfo=SITE)
    assert row.window_from_utc == as_utc(checkpoint_at)
    # `lower` is the checkpoint, never the 7-day ring floor: an audit row advertising the
    # wider read would describe a request the loop never made.
    assert checkpoint_at > T0 - timedelta(seconds=RESET_PROBE_WINDOW_S)


def test_a_quiet_tick_over_an_empty_ring_records_the_read_that_came_back_with_nothing(
    tmp_path: Path,
) -> None:
    """The literal case `check_stall` needs: the probe asked, the device answered, empty.

    The log is wiped and refilled with NOTHING — a swapped terminal whose reader has not seen
    a card yet produces exactly this. The newest-first page comes back with zero records, so
    there is no serial to name and the tick ends `ok`. This is the path GC-P15 threw away
    wholesale, and the one an empty `probe_audit` table cannot tell apart from an agent that
    never looked: the row, with the window it covered and the one request it cost, is the
    entire difference between "checked and clean" and "silent".
    """
    h = quiet_replacement(tmp_path, new_serials=[])

    quiet = h.tick()

    assert quiet.ok and quiet.records == 0 and quiet.serial_reset is None
    row = read_probe_window(h.conn, SERIAL, kind=PROBE_KIND_RESET)
    assert row is not None, "an empty answer is still an answer, and must be auditable"
    assert row.reads == 1 == len(probe_posts(h.device))
    assert narrow_posts(h.device), "the narrow poll still ran first, as every quiet tick owes"


def test_the_probe_row_survives_a_restart_and_spends_no_extra_event_post(
    tmp_path: Path,
) -> None:
    """The card's second DoD line: the hour is the budget, not the process.

    `quiet_replacement` has already paid for one probe. Rebuilding the loop over the same db
    — new `DeviceLoop`, new client, cleared caps cache — must inherit that row and stay shut
    for the rest of the hour. The only event POST the restarted loop makes is the narrow poll
    every tick owes.
    """
    h = quiet_replacement(tmp_path, new_serials=[(101, "2026-10-19T10:08:00")], upgraded=False)
    assert h.tick().ok
    assert len(probe_posts(h.device)) == 1

    h2 = restart(h, tmp_path)
    assert h2.loop is not h.loop and h2.conn is not h.conn  # genuinely new process memory
    before_narrow = len(narrow_posts(h.device))
    quiet = h2.tick()

    assert quiet.ok and quiet.records == 0 and quiet.serial_reset is None
    assert len(probe_posts(h2.device)) == 1, "the restart spent a page the hour had not earned"
    assert len(narrow_posts(h2.device)) == before_narrow + 1
    assert read_probe_window(h2.conn, SERIAL, kind=PROBE_KIND_RESET) == read_probe_window(
        h.conn, SERIAL, kind=PROBE_KIND_RESET
    )


def test_a_restart_after_the_hour_expired_probes_again(tmp_path: Path) -> None:
    """The other half: a stale row inherits a SPENT budget, so a swap is still findable.

    Inheriting is not the same as never probing — a unit restarted every ten minutes must
    still answer the reset question once an hour, or this card would have traded a silent
    agent for a permanently blind one.
    """
    h = quiet_replacement(tmp_path, new_serials=[(101, "2026-10-19T10:08:00")], upgraded=False)
    assert h.tick().ok
    assert len(probe_posts(h.device)) == 1

    h.clock.advance(RESET_PROBE_INTERVAL_S + 120)
    h.monotonic.advance(RESET_PROBE_INTERVAL_S + 120)
    h2 = restart(h, tmp_path)
    quiet = h2.tick()

    assert quiet.ok and quiet.records == 0
    probes = probe_posts(h2.device)
    assert len(probes) == 2, "a stale stored probe must not silence the next hour"
    assert probes[1]["maxResults"] == 1 and probes[1]["major"] == 0
    row = read_probe_window(h2.conn, SERIAL, kind=PROBE_KIND_RESET)
    assert row is not None and row.reads == 1


def test_the_durable_instant_seeds_the_budget_once_and_a_clock_jump_cannot_spend_it_twice(
    tmp_path: Path,
) -> None:
    """The durable row seeds the budget ONCE; the monotonic clock is what spends it.

    The seed is the wall clock's only vote, and it is taken at the first quiet tick after a
    start (`_seed_reset_probe_budget`). A wall that jumps forward afterwards — an NTP
    correction, an operator's `date -s`, a mislabelled stamp — must not buy a request: the
    gate has since been a monotonic delta. GC-P15's invariant, kept while the *source* of the
    budget moves to the db. (The other direction is safe by construction: a backward jump can
    only push the seeded deadline further out.)
    """
    h = quiet_replacement(tmp_path, new_serials=[(101, "2026-10-19T10:08:00")], upgraded=False)
    assert h.tick().ok
    assert len(probe_posts(h.device)) == 1

    h2 = restart(h, tmp_path)
    # The seed spends the wall clock's one vote here, with the stored probe still minutes
    # old: the inherited budget is spent, and this quiet tick asks for nothing.
    assert h2.tick().ok
    assert len(probe_posts(h2.device)) == 1

    # Now the wall jumps past the hour while monotonic moves a minute. The row it would have
    # consulted says "probed just now", and the wall must not be able to overrule that.
    h2.clock.advance(RESET_PROBE_INTERVAL_S + 600)
    h2.monotonic.advance(60)
    assert h2.tick().ok
    assert len(probe_posts(h2.device)) == 1, "a wall-clock jump bought a page"

    # The same hour spent honestly, monotonic: now the probe is due and it runs.
    h2.monotonic.advance(RESET_PROBE_INTERVAL_S)
    assert h2.tick().ok
    assert len(probe_posts(h2.device)) == 2


def test_a_confirmed_reset_leaves_one_probe_row_and_the_epoch_bump(
    tmp_path: Path,
) -> None:
    """The write does not ride on `reset_checkpoint`; it is the probe's own record.

    GC-P15's R1 case: the swap is found and epoch 1 opens. Two facts must hold together — the
    checkpoint rewound (`reset_checkpoint`, one UPDATE on `checkpoint`, unchanged by this
    card) and the probe's row is the SAME row the quiet tick would have written had it found
    nothing: one row, `kind='reset'`, naming the window that was asked.
    """
    h = quiet_replacement(
        tmp_path, new_serials=[(1, "2026-10-19T09:57:00"), (3, "2026-10-19T10:08:00")]
    )

    quiet = h.tick()

    assert quiet.ok and quiet.serial_reset is not None
    assert (quiet.serial_reset.old_serial, quiet.serial_reset.new_serial) == (100, 3)
    cp = read_checkpoint(h.conn, SERIAL)
    assert cp is not None and (cp.checkpoint_serial, cp.serial_epoch) == (3, 1)
    rows = audit_rows(h.conn)
    assert [r["kind"] for r in rows] == [PROBE_KIND_RESET]  # not one per step
    assert rows[0]["reads"] == 1
    assert rows[0]["window_from_utc"] == as_utc(
        datetime.fromisoformat("2026-10-19T09:55:00").replace(tzinfo=SITE)
    )


def test_a_window_the_checkpoint_collapsed_to_zero_width_asks_nothing_and_claims_nothing(
    tmp_path: Path,
) -> None:
    """A probe that sent no request writes no row — the one `reads = 0` that was ever true.

    `chunk_window` yields nothing when `since == until`, so a checkpoint stamped exactly at the
    loop's current instant leaves a window that was never asked for. Recording `reads = 0`
    there would write a row that looks exactly like the clean NO MATCH this audit exists to
    keep, from a read that never happened: the row means "a page was asked for over this window
    and came back", and nothing was asked.
    """
    h = quiet_replacement(tmp_path, new_serials=[(1, "2026-10-19T10:08:00")])
    now = h.loop._now()
    collapsed = Checkpoint(
        device_serial=SERIAL,
        checkpoint_serial=100,
        checkpoint_time=now.isoformat(timespec="seconds"),
        updated_at=as_utc(now),
    )

    assert h.loop._probe_newest_serial(collapsed) == (None, None)
    assert probe_posts(h.device) == [], "a zero-width window must not spend the hour's page"
    assert audit_rows(h.conn) == []


def test_a_probe_that_dies_records_no_window(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A dead read is not an answer, and the row means "an answer came back".

    The probe bends and never breaks (GC-P15 DoD 4) and the audit row deliberately stays
    empty: a `reads = 0` row would be indistinguishable from the clean NO MATCH the row exists
    to prove. The honest price is that a restart right after a dead probe may spend one page
    again — bounded, and cheaper than an audit table nobody can trust.
    """
    h = quiet_replacement(tmp_path, new_serials=[(1, "2026-10-19T10:08:00")])
    kill_probe_reads(monkeypatch)  # only the newest-first read dies; the poll completes

    quiet = h.tick()

    assert quiet.ok and quiet.serial_reset is None
    assert any("reset probe" in w and "failed" in w for w in h.warns), h.warns
    assert read_probe_window(h.conn, SERIAL, kind=PROBE_KIND_RESET) is None
    assert audit_rows(h.conn) == []


def test_an_unplaceable_checkpoint_probes_nothing_and_records_nothing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Fail closed stays fail closed: no request, and now also no row to mislead.

    GC-P15's deviation refused to widen the window when the checkpoint stamp cannot be placed.
    This pins the follow-through: the audit trail does not remember a window the probe
    declined to ask for. The injection fails only the probe's own parse — the narrow walk's
    floor lands first and that walk must still complete.
    """
    h = quiet_replacement(tmp_path, new_serials=[(1, "2026-10-19T10:08:00")])
    real = agent_loop._parse_stamp
    calls = iter([1])  # the second `_parse_stamp` call is the probe's

    def flaky(stamp: str, *, site_tz: Any) -> Any:
        if next(calls, None) is None:
            raise IsapiError("injected: the checkpoint stamp cannot be placed")
        return real(stamp, site_tz=site_tz)

    monkeypatch.setattr(agent_loop, "_parse_stamp", flaky)
    quiet = h.tick()

    assert quiet.ok, quiet.error  # the narrow walk's own truth still stands
    assert quiet.serial_reset is None and quiet.advanced is False
    assert probe_posts(h.device) == []
    assert any("cannot place checkpoint" in w for w in h.warns), h.warns
    assert read_probe_window(h.conn, SERIAL, kind=PROBE_KIND_RESET) is None


def test_the_ring_floor_read_still_has_no_row_of_its_own(tmp_path: Path) -> None:
    """The two questions stay two questions in the db, not only on the wire.

    `probe_ring_floor` answers "did the device evict what we had not read?" — oldest-first,
    all majors, no `timeReverseOrder` (which is how
    `tests/test_ring_floor_probe.py::_probe_conditions` tells the two apart). It is offered by
    `agent_cli` at the first ok tick after a gap and writes nothing today. This pin is what
    stops a follow-up card from filing that answer under `reset` and crediting the reset
    probe's budget with a read that asked something else.
    """
    h = quiet_replacement(tmp_path, new_serials=[(101, "2026-10-19T10:08:00")], upgraded=False)
    assert h.tick().ok
    cp = read_checkpoint(h.conn, SERIAL)
    assert cp is not None and cp.checkpoint_time is not None
    rows_before = audit_rows(h.conn)
    polls_before = len(narrow_posts(h.device))

    floor = h.loop.probe_ring_floor(cp.checkpoint_time)

    # The read really happened (a `+ 0` request would make the row assertion below vacuous)
    # and it answered: the ring's oldest row in that window is the heartbeat the swap left.
    assert len(narrow_posts(h.device)) == polls_before + 1
    assert floor == 101
    assert audit_rows(h.conn) == rows_before
    assert [r["kind"] for r in audit_rows(h.conn)] == [PROBE_KIND_RESET]


# ===========================================================================================
# (C) the row and the constant agree about what "hourly" means
# ===========================================================================================


def test_the_budget_is_measured_from_the_stored_instant_not_from_the_rows_presence(
    tmp_path: Path,
) -> None:
    """A row older than the interval is a SPENT budget — "a row exists" is not the gate.

    Hand-written rather than produced by the loop, because this is the state a device that was
    offline for a day leaves behind, and the reader must judge it against
    `RESET_PROBE_INTERVAL_S`.
    """
    h = quiet_replacement(tmp_path, new_serials=[(101, "2026-10-19T10:08:00")], upgraded=False)
    assert h.tick().ok
    assert len(probe_posts(h.device)) == 1

    stale = utc(RESET_PROBE_INTERVAL_S + 60)
    h.conn.execute(
        "UPDATE probe_audit SET window_to_utc = ?, window_from_utc = ? WHERE kind = 'reset'",
        (as_utc(stale), as_utc(stale - timedelta(seconds=WINDOW_S))),
    )
    h2 = restart(h, tmp_path)
    assert h2.tick().ok
    assert len(probe_posts(h2.device)) == 2


def test_a_probe_never_writes_more_than_one_row_per_device(tmp_path: Path) -> None:
    """Three probe hours, three replacements, one row: the trail is a state, not a log.

    Bounded growth is the point of the singleton shape — an agent that probes once an hour for
    a year must not grow a table the health surface has to scan, and the budget question is
    always about the LAST probe. The window pair moves, the row does not multiply.
    """
    h = quiet_replacement(tmp_path, new_serials=[(101, "2026-10-19T10:08:00")], upgraded=False)
    first = h.tick()
    assert first.ok
    first_row = read_probe_window(h.conn, SERIAL, kind=PROBE_KIND_RESET)
    assert first_row is not None

    for _ in range(2):
        h.clock.advance(RESET_PROBE_INTERVAL_S + 60)
        h.monotonic.advance(RESET_PROBE_INTERVAL_S + 60)
        assert h.tick().ok

    rows = audit_rows(h.conn)
    assert len(rows) == 1
    assert len(probe_posts(h.device)) == 3
    assert rows[0]["window_to_utc"] > first_row.window_to_utc
