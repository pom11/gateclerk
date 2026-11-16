"""GC-P15 follow-up 3: does a durable ring floor earn a second `probe_audit` kind? **No.**

The decision this file pins (card `t_bde31e68`, option 1)
---------------------------------------------------------
`PROBE_KINDS` stays `{PROBE_KIND_RESET}`, `DeviceLoop.probe_ring_floor` stays a one-shot live
read, and `record_probe_window` keeps refusing the ring-floor name. Three reasons, each
defended by a test below:

1. **there is no budget for a row to be the memory of.** The reset probe earned a row because
   `_last_reset_probe_at` is an in-process hourly cadence, so "one page per hour" was
   restarting as "one page per restart". The ring-floor read has no such state: its gate is
   `agent_cli.SiteAgent._last_ok_at`, seeded across restarts by `_last_ok_from_health` from
   the health snapshot's mtime, and advanced by the same ok tick that spends the page. A
   restart cannot re-spend it; an unreadable seed spends nothing at all. Pinned as behaviour
   already (`tests/test_ring_floor_probe.py::test_short_restart_does_not_probe`,
   `::test_quiet_week_of_successful_polls_sends_no_extra_request_and_no_page`); this file
   pins the *decision* so the row cannot be added on the strength of the old premise.
2. **the row has no answer to give.** The v8 row is five columns with no result column, so a
   `ring_floor` row would record "a page came back over this window, empty included" while
   the question that read exists to answer is "did the ring evict events we had not read?".
   For `reset` the window+cost pair IS the operator's answer; for `ring_floor` it is loss
   evidence in appearance only — the exact all-time misreading
   `agent_store.read_probe_window`'s reading rule exists to close. The row shape is pinned
   against this by `test_the_row_type_carries_no_quiet_ever_since_claim` in
   `tests/test_gc_p15_probe_reader.py`, which this file deliberately does not loosen.
3. **the renderer is not the gate.** `all_probe_windows` and `gateclerk agent probe list`
   enumerate rows and know nothing about kinds, so "add its reader first" is satisfied
   before a kind exists. The honest reading is therefore *purpose or nothing* — and a kind
   whose only reader is a renderer that cannot display its subject is option 1 in a costume.

Offline by construction: tmp sqlite, the parent's own helpers (imported, never re-derived),
`CliRunner` with `agent_cli._now` frozen. The one thing written by hand here is a row the
sanctioned writer refuses, and the test that writes it asserts that refusal on the same
connection first — so a loosened store fails this file instead of agreeing with it.
"""

from __future__ import annotations

import inspect
import sqlite3
from datetime import datetime, timedelta
from pathlib import Path

import pytest

from gateclerk import agent_alert, agent_store
from gateclerk.agent_db import connect
from gateclerk.agent_store import (
    PROBE_KIND_RESET,
    PROBE_KINDS,
    all_probe_windows,
    record_probe_window,
)
from test_gc_p15_probe_audit import WINDOW_S, as_utc, utc
from test_gc_p15_probe_reader import OTHER_SERIAL, SERIAL, probe_json, sites_file
from test_p2_03_scheduler import T0

#: The names a follow-up card would reach for when wiring the ring floor in. All refused:
#: the decision is about purpose, so pinning one spelling would leave two doors open.
RING_FLOOR_NAMES = ("ring_floor", "ring", "floor")


def insert_hypothetical_row(
    conn: sqlite3.Connection,
    *,
    serial: str,
    kind: str,
    ran_at: datetime,
    window_s: float = WINDOW_S,
    reads: int = 1,
) -> None:
    """One `probe_audit` row written BY HAND: a shape no sanctioned writer can produce.

    Legitimate only because the whole point is the READER's generality, which no sanctioned
    writer can exercise while one kind is the vocabulary. The stamp pair goes through
    `as_utc`, the store's own format, so the hypothetical row is byte-comparable with a real
    one and the screen has nothing extra to cope with.
    """
    conn.execute(
        "INSERT INTO probe_audit (device_serial, kind, window_from_utc, window_to_utc, reads)"
        " VALUES (?, ?, ?, ?, ?)",
        (serial, kind, as_utc(ran_at - timedelta(seconds=window_s)), as_utc(ran_at), reads),
    )
    conn.commit()


def seed_across_kinds(tmp_path: Path) -> Path:
    """One device with BOTH kinds plus a second device, seeded against the asserted order.

    Insert order is deliberately the opposite of `(device_serial, kind)` — the discipline a
    pin against an `ORDER BY` needs, because rows seeded in key order agree with a query
    whose ordering was dropped. The sanctioned writer supplies the `reset` row; the two
    ring-floor rows are hand-written, and the refusal loop below is what licenses that: it
    runs on this same connection first, so this fixture cannot survive a loosened
    `PROBE_KINDS`.
    """
    db_path = tmp_path / "agent.sqlite3"
    conn = connect(db_path)
    try:
        for name in RING_FLOOR_NAMES:
            with pytest.raises(ValueError, match="add its reader first"):
                record_probe_window(
                    conn,
                    SERIAL,
                    kind=name,
                    window_from=utc(60),
                    window_to=utc(30),
                    reads=1,
                )
        # Hand-written rows first (lowest rowid first), then the sanctioned one, so key order
        # and insertion order cannot coincide.
        insert_hypothetical_row(conn, serial=OTHER_SERIAL, kind="ring_floor", ran_at=utc(30))
        insert_hypothetical_row(conn, serial=SERIAL, kind="ring_floor", ran_at=utc(120))
        record_probe_window(
            conn,
            SERIAL,
            kind=PROBE_KIND_RESET,
            window_from=utc(60 + WINDOW_S),
            window_to=utc(60),
            reads=1,
        )
    finally:
        conn.close()
    return db_path


# --- (A) the store refuses the name ----------------------------------------------------------


@pytest.mark.parametrize("kind", RING_FLOOR_NAMES)
def test_the_store_refuses_the_ring_floor_kind_by_name(tmp_path: Path, kind: str) -> None:
    """No `ring_floor` row can be written, and the refusal says why.

    The message is the rule, not just an error: *"a kind nothing reads would keep a budget no
    operator can see, so add its reader first"*. The reader now exists, so what is still
    missing — and what this card decided is missing — is the purpose. Three spellings,
    because a card that wanted the kind would not necessarily pick `ring_floor`.
    """
    conn = connect(tmp_path / "agent.sqlite3")
    try:
        with pytest.raises(ValueError, match="add its reader first") as excinfo:
            record_probe_window(
                conn,
                SERIAL,
                kind=kind,
                window_from=utc(120),
                window_to=utc(60),
                reads=1,
            )
        assert kind in str(excinfo.value)
        assert conn.execute("SELECT COUNT(*) n FROM probe_audit").fetchone()["n"] == 0
    finally:
        conn.close()


def test_the_accepted_vocabulary_is_the_reset_probe_alone() -> None:
    """The decided set, stated as a set — so widening it is a failing test, not an edit.

    A future card may legitimately add a kind, and this test is where it has to say so out
    loud: it must arrive together with a writer, a question the five-column row can actually
    answer, and this card's answer to "what is the durable row FOR". Until then the name must
    not even exist as a constant: a `PROBE_KIND_RING_FLOOR` with no writer and no purpose is
    the costume this card exists to refuse.
    """
    assert frozenset({PROBE_KIND_RESET}) == PROBE_KINDS
    assert agent_store.PROBE_KIND_RESET == "reset"
    for name in ("PROBE_KIND_RING_FLOOR", "PROBE_KIND_RING", "PROBE_KIND_FLOOR"):
        assert not hasattr(agent_store, name), f"{name} would be a kind with no reader"


# --- (B) the renderer is kind-agnostic: plumbing was never the gate --------------------------


def test_a_hypothetical_second_kind_renders_with_no_code_change(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """`agent probe list` already renders a kind it has never heard of, and orders it.

    This is the proof that the parent's reader is not the missing half: the screen enumerates
    rows (`all_probe_windows` -> one line per row) and computes age from `window_to_utc`
    without consulting `kind` at all. Two things follow, and both are asserted:

    * a second kind would appear with no code change, so nobody may claim plumbing as the
      reason the card refused one — the gate is purpose;
    * the ordering pin bites **across kinds for one device**, which no sanctioned writer can
      ever exercise: the rows are seeded against the asserted order, and dropping the
      `ORDER BY` reorders them (mutation probe P5, CAUGHT). The `kind` term itself is
      redundant while `kind` sits in the PRIMARY KEY — sqlite satisfies both spellings from
      `sqlite_autoindex_probe_audit_1` — so that probe (P4) is reported as observationally
      equivalent rather than counted as a gap.
    """
    db_path = seed_across_kinds(tmp_path)
    cfg = sites_file(tmp_path, db_path)

    exit_code, rows, out = probe_json(cfg, "-o", "json", monkeypatch=monkeypatch, now=T0)

    assert exit_code == 0, out
    assert [(r["device_serial"], r["kind"]) for r in rows] == [
        (OTHER_SERIAL, "ring_floor"),
        (SERIAL, PROBE_KIND_RESET),
        (SERIAL, "ring_floor"),
    ], "key order, seeded against it — dropping `kind` from the ORDER BY reorders this"
    assert [r["age_s"] for r in rows] == [30.0, 60.0, 120.0], "age is `now - window_to_utc`"
    assert all(r["current"] is True for r in rows), "all three are inside the default bound"
    assert all(r["reads"] == 1 for r in rows)
    # The renderer never needed to know the kind: it echoes the stored text verbatim, and the
    # store's own read of the same table agrees with the screen row for row.
    assert {r["kind"] for r in rows} == {PROBE_KIND_RESET, "ring_floor"}
    conn = connect(db_path)
    try:
        assert [(r.device_serial, r.kind) for r in all_probe_windows(conn)] == [
            (row["device_serial"], row["kind"]) for row in rows
        ], "the screen is a renderer of `all_probe_windows`, not a second read"
    finally:
        conn.close()


def test_one_row_per_device_and_kind_holds_across_kinds(tmp_path: Path) -> None:
    """The PRIMARY KEY's whole promise: a `reset` write cannot spend or erase a ring row.

    `_PROBE_AUDIT_V8` puts `kind` in the key so the two reads can never vouch for each other.
    Until this file that promise was unexercisable — the sanctioned writer could only produce
    one kind — so the UPSERT's conflict target was only ever tested against itself. Here the
    `reset` row is rewritten through the writer while the hypothetical ring rows sit in the
    same table for the same devices: only the `reset` row may move.
    """
    db_path = seed_across_kinds(tmp_path)
    conn = connect(db_path)
    try:
        before = {(row.device_serial, row.kind): row for row in all_probe_windows(conn)}
        record_probe_window(
            conn,
            SERIAL,
            kind=PROBE_KIND_RESET,
            window_from=utc(600 + WINDOW_S),
            window_to=utc(600),
            reads=2,
        )
        after = {(row.device_serial, row.kind): row for row in all_probe_windows(conn)}

        assert set(after) == set(before), "no kind gained or lost a row"
        moved = after[(SERIAL, PROBE_KIND_RESET)]
        assert moved.reads == 2 and moved.window_to_utc == as_utc(utc(600))
        for key in before:
            if key == (SERIAL, PROBE_KIND_RESET):
                continue
            assert after[key] == before[key], f"{key} was touched by a `reset` write"
    finally:
        conn.close()


# --- (C) the alert keeps asking the device ---------------------------------------------------


def test_the_alert_never_reads_the_probe_table() -> None:
    """The screen may show a row's age; `check_stall` must keep asking the device.

    `check_stall` takes the floor as a callable (`ring_probe`) precisely because a stored
    answer is a stale answer. Nothing in this module may import or query the audit table —
    the same line GC-P15 follow-up 2 held for `reset`, restated here for the ring floor
    because that is the kind a future card would be tempted to wire in. `agent_store` itself
    is legitimately imported here (`read_checkpoint`, `read_oldest_serial`), so the pin is on
    the probe symbols, not on the module.
    """
    source = inspect.getsource(agent_alert)

    for symbol in (
        "probe_audit",
        "all_probe_windows",
        "read_probe_window",
        "record_probe_window",
        "probe_age_s",
        "probe_is_current",
        "PROBE_KIND",
    ):
        assert symbol not in source, f"agent_alert reads the probe table via {symbol}"
    # And the live path is really a call: the floor arrives as a zero-arg callable.
    assert "ring_probe()" in source
