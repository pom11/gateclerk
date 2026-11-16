"""GC-P15 follow-up 2: `probe_audit` gets a READER — the operator's, not a new alert.

The decision this file pins (card `t_95d5e373`, option 1)
---------------------------------------------------------
A stored quiet-probe row is **operator evidence, not stall evidence**. `check_stall` gains no
arm and no suppressor, and its episode key (`frozen updated_at | evidence`) is untouched.
Three reasons, each of which a test below defends:

1. the row records **what was asked and what it cost** — `window_from_utc`, `window_to_utc`,
   `reads` — and NOT what the device answered (`_probe_newest_serial` passes only the window
   and the request count, and a row means "a page came back over this window, **empty
   included**"). A suppressor built on it would page-suppress on *having asked*;
2. the arms such a suppressor could reach are exactly the arms carrying real evidence of loss
   (`stale and failing`, `floor_evicted`), and `floor_evicted` is offered only at the first ok
   tick after a gap — i.e. only when every stored probe row predates that gap;
3. a term that changes every `RESET_PROBE_INTERVAL_S` is not a function of the incident, so
   it would either re-page one frozen stall hourly or silently swallow a genuine new incident.

What replaced the alert: `gateclerk agent probe list`, `agent_store.all_probe_windows`, and
the reading rule as code (`probe_age_s`, `probe_is_current`).

The reading rule, stated once so the tests can aim at it
--------------------------------------------------------
A row is evidence about **its own window**: `window_to_utc` is the instant the read ran and
`[window_from_utc, window_to_utc]` the range it covered. So:

* a row's age is `now - window_to_utc` — **never** `now - window_from_utc`, which would show a
  probe that ran this second as an hour old and would read the *width of the window asked for*
  as elapsed silence (the trap the card names);
* "current" cannot be derived from the row. It is the CONSUMER's bound (`max_age_s`), stated by
  the reader and movable by the reader (`--max-age-s`);
* a row past its bound answers the historical question and **nothing** about now — it must not
  be read as "quiet ever since", and here it must not be hidden either: the operator sees the
  history and the `current` column changes.

The row type deliberately has no fifth kind of claim: five columns, no result column, no
"quiet" flag. `test_the_row_type_carries_no_quiet_ever_since_claim` holds that line.

Offline by construction: tmp sqlite, injected clocks, and for the one end-to-end case the
parent's own harness (`tests/test_gc_p15_cold_reset.py::quiet_replacement` — imported, not
re-derived, so the quiet tick here is the same scenario GC-P15 shipped against, honour-the-
filter arm included). No socket, no wall clock, no device.
"""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from typer.testing import CliRunner

from gateclerk import agent_cli, agent_store
from gateclerk.agent_cmds import PROBE_STALE_DEFAULT_S
from gateclerk.agent_db import connect
from gateclerk.agent_loop import RESET_PROBE_INTERVAL_S
from gateclerk.agent_store import (
    PROBE_KIND_RESET,
    ProbeWindow,
    all_probe_windows,
    probe_age_s,
    probe_is_current,
    record_probe_window,
)
from gateclerk.cli import app
from test_gc_p15_cold_reset import SERIAL, quiet_replacement
from test_gc_p15_probe_audit import WINDOW_S, as_utc, utc
from test_p2_03_scheduler import T0

runner = CliRunner()

#: The site label the CLI is driven with. The `agent` surface is strict about `iana_tz`, so
#: the config below declares it (the same zone the GC-P15 scenario runs in).
SITE = "probe-site"
OTHER_SERIAL = "GATECLERK-TEST-SN-02"

#: One bound, explicitly narrower than the loop's budget, so a test that passes with it cannot
#: be passing because of the default.
BOUND_S = 600.0


def row_at(
    *,
    serial: str = SERIAL,
    kind: str = PROBE_KIND_RESET,
    ran_at: datetime = T0,
    window_s: float = WINDOW_S,
    reads: int = 1,
) -> ProbeWindow:
    """One row built the way the store builds it: window pair in the store's one format."""
    return ProbeWindow(
        device_serial=serial,
        kind=kind,
        window_from_utc=as_utc(ran_at - timedelta(seconds=window_s)),
        window_to_utc=as_utc(ran_at),
        reads=reads,
    )


def seed(tmp_path: Path, *rows: ProbeWindow) -> Path:
    """Write `rows` through the sanctioned writer and hand back the db path.

    Going through `record_probe_window` (never a raw INSERT) is the point: if the writer ever
    stops storing the pair the reader reads, these tests fail instead of agreeing with it.
    """
    db_path = tmp_path / "agent.sqlite3"
    conn = connect(db_path)
    for row in rows:
        record_probe_window(
            conn,
            row.device_serial,
            kind=row.kind,
            window_from=datetime.fromisoformat(row.window_from_utc),
            window_to=datetime.fromisoformat(row.window_to_utc),
            reads=row.reads,
        )
    conn.close()
    return db_path


def sites_file(tmp_path: Path, db_path: Path) -> Path:
    """The smallest config the AGENT surface accepts: name, host, zone, store."""
    cfg_file = tmp_path / "sites.toml"
    cfg_file.write_text(
        f"""[[site]]
name = "{SITE}"
host = "192.0.2.10"
iana_tz = "Europe/Bucharest"
db_path = "{db_path}"
""",
        encoding="utf-8",
    )
    return cfg_file


def probe_json(
    cfg_file: Path,
    *extra: str,
    monkeypatch: pytest.MonkeyPatch | None = None,
    now: datetime | None = None,
) -> tuple[int, list[dict[str, Any]], str]:
    """Run `agent probe list -o json` and hand back (exit, rows, output).

    `now` is installed through `agent_cli._now` — the same freeze seam `agent run` threads —
    so the screen and the loop that wrote the row are read in one time universe, and no test
    in this file depends on the real wall clock.
    """
    if now is not None:
        assert monkeypatch is not None, "a frozen `now` needs the monkeypatch fixture"
        monkeypatch.setattr(agent_cli, "_now", lambda: now)
    result = runner.invoke(
        app,
        ["agent", "probe", "list", "--site", SITE, "--config", str(cfg_file), *extra],
    )
    rows = [json.loads(line) for line in result.output.splitlines() if line.startswith("{")]
    return result.exit_code, rows, result.output


# --- the reading rule, as code ---------------------------------------------------------------


def test_the_age_of_a_row_is_measured_from_the_instant_the_read_ran(tmp_path: Path) -> None:
    """`now - window_to_utc`, never `now - window_from_utc`.

    The one mutation this exists to catch: measuring from the lower bound. On this row the two
    differ by the whole window (3 h), so a swapped bound reports a probe that ran *this second*
    as three hours stale — and the screen would then read the width of the window the loop
    asked for as though it were elapsed silence.
    """
    row = row_at(ran_at=T0)
    assert probe_age_s(row, now=T0) == 0.0
    assert probe_age_s(row, now=T0 + timedelta(seconds=90)) == 90.0


def test_a_fresh_row_is_current_yet_still_covers_only_the_window_it_asked() -> None:
    """The card's first clause: a FRESH row is not "quiet ever since".

    Freshness and coverage are different facts and the row only carries the second one. This
    row is the freshest it can be (one second old, `current` at any sane bound) and its answer
    still stops dead at `window_to_utc`: `probed_at` IS that bound, so the instant after it is
    outside the evidence no matter how new the row is.
    """
    row = row_at(ran_at=T0)
    now = T0 + timedelta(seconds=1)
    assert probe_is_current(row, now=now, max_age_s=BOUND_S) is True
    assert row.probed_at == datetime.fromisoformat(row.window_to_utc)
    assert row.probed_at < now, "the row's coverage ends before 'now'; nothing after it is claimed"
    assert datetime.fromisoformat(row.window_from_utc) < row.probed_at, (
        "the coverage pair is a range, not a point"
    )


def test_the_row_type_carries_no_quiet_ever_since_claim() -> None:
    """Five columns, no sixth. A field named `quiet`/`since` would be a claim, not evidence.

    The parent decided `probe_audit` is v8 and additive and must not be reshaped for a
    consumer; the shape that makes that safe is a row with no carrier for an all-time answer.
    If someone adds `quiet_since` to make a suppressor convenient, this fails first.
    """
    fields = tuple(ProbeWindow.__dataclass_fields__)
    assert fields == (
        "device_serial",
        "kind",
        "window_from_utc",
        "window_to_utc",
        "reads",
    ), f"probe_audit grew a claim: {fields}"


def test_a_row_older_than_its_bound_is_never_current_and_says_nothing_about_now() -> None:
    """The card's second clause: past the bound the row must not support anything.

    Two hours old against a ten-minute bound. Its age is 7200 s measured from `window_to_utc`
    (not 10800 s — the window's own width is not elapsed silence), and the only honest thing
    left to read from it is what the device held over its own range, at its own instant.
    """
    row = row_at(ran_at=T0)
    now = T0 + timedelta(hours=2)
    assert probe_age_s(row, now=now) == 7200.0
    assert probe_is_current(row, now=now, max_age_s=BOUND_S) is False


def test_the_bound_is_the_readers_and_its_boundary_is_inclusive() -> None:
    """Exactly-at is still current; a tenth of a second past is not.

    `max_age_s` is a parameter and not a constant on purpose: the bound is the consumer's
    opinion, and this pins the boundary posture (inclusive) so a later `<` cannot quietly make
    every row on the boundary stale.
    """
    row = row_at(ran_at=T0)
    assert probe_is_current(row, now=T0 + timedelta(seconds=BOUND_S), max_age_s=BOUND_S) is True
    assert (
        probe_is_current(row, now=T0 + timedelta(seconds=BOUND_S + 0.1), max_age_s=BOUND_S) is False
    )


def test_a_writer_clock_ahead_of_the_reader_reads_as_a_negative_age_not_zero() -> None:
    """No clamping. A negative age is the reader meeting a writer whose clock is ahead.

    Clamping to 0 would hide a real clock disagreement behind "just now", and the fleet
    already reports device/agent skew as its own warning — a screen that rounds it away is
    worse than one that shows a strange number.
    """
    row = row_at(ran_at=T0)
    assert probe_age_s(row, now=T0 - timedelta(seconds=30)) == -30.0
    assert probe_is_current(row, now=T0 - timedelta(seconds=30), max_age_s=BOUND_S) is True


# --- the operator's read of the table --------------------------------------------------------


def test_all_probe_windows_reads_every_device_and_kind_in_key_order(tmp_path: Path) -> None:
    """Both devices, both would-be kinds, ordered by the primary key.

    The whole point of the read path: a site with two devices used to need two guesses. The
    order is the primary key's, so the table a human reads cannot reorder between calls.
    """
    rows = (
        # Seeded in the ORDER OPPOSITE the primary key sorts, so the assertion below can
        # actually tell `ORDER BY device_serial, kind` from "whatever sqlite felt like":
        # inserted in key order, an unsorted read would pass the same test by accident.
        row_at(serial=SERIAL, ran_at=utc(120)),
        row_at(serial=OTHER_SERIAL, ran_at=utc(60)),
    )
    db_path = seed(tmp_path, *rows)
    conn = connect(db_path)
    found = all_probe_windows(conn)
    # Key order, not insertion order: `GATECLERK-TEST-SN-02` sorts before the scenario serial.
    assert [(r.device_serial, r.kind, r.reads) for r in found] == [
        (OTHER_SERIAL, PROBE_KIND_RESET, 1),
        (SERIAL, PROBE_KIND_RESET, 1),
    ]
    assert [r.window_to_utc for r in found] == [rows[1].window_to_utc, rows[0].window_to_utc]


def test_all_probe_windows_returns_what_the_only_writer_recorded(tmp_path: Path) -> None:
    """Byte-identical stamps through the round trip: the screen shows the asked window.

    The parent's rule was that the row stores the pair actually put on the wire, not a
    re-derivation. Anything here that reformatted a bound would show up as a mismatch.
    """
    row = row_at(ran_at=utc(45), reads=3)
    db_path = seed(tmp_path, row)
    conn = connect(db_path)
    assert all_probe_windows(conn) == (row,)


def test_all_probe_windows_on_a_fresh_store_is_empty_not_an_error(tmp_path: Path) -> None:
    """No agent run yet = no rows, and a read that found nothing is not a failure."""
    conn = connect(tmp_path / "agent.sqlite3")
    assert all_probe_windows(conn) == ()


def test_the_operator_read_writes_nothing(tmp_path: Path) -> None:
    """The read path runs on a read-only connection.

    `agent probe list` is something an operator types while the agent is mid-tick. A write
    here would be a second writer competing with `record_probe_window`'s `BEGIN IMMEDIATE` —
    and on a read-only handle any write attempt raises instead of succeeding silently.
    """
    db_path = seed(tmp_path, row_at(ran_at=utc(30)))
    conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
    conn.row_factory = sqlite3.Row
    now = T0 + timedelta(hours=1)
    rows = all_probe_windows(conn)
    assert len(rows) == 1
    assert probe_age_s(rows[0], now=now) == 3630.0
    conn.close()


# --- what the operator sees ------------------------------------------------------------------


def test_probe_list_shows_the_row_the_quiet_tick_actually_recorded(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """End to end, the evidence that closes the card's WHY.

    A REAL quiet tick from the parent's own harness (`quiet_replacement`, honour-the-filter arm
    included, so the quiet tick is reachable) writes the row; `agent probe list` renders it.
    Before this card the row existed and no screen read it: "the agent is silent" and "the
    agent looked and the ring was empty" were the same db AND the same empty screen.
    """
    h = quiet_replacement(tmp_path, new_serials=[(101, "2026-10-19T10:08:00")], upgraded=False)
    assert h.tick().ok, "the quiet tick that records the probe must itself succeed"
    stored = agent_store.read_probe_window(h.conn, SERIAL, kind=PROBE_KIND_RESET)
    assert stored is not None, "the harness's quiet tick is expected to leave a row"
    # The db the harness actually opened, not the path this file guesses it used.
    db_path = Path(h.conn.execute("PRAGMA database_list").fetchone()[2])

    monkeypatch.setattr(agent_cli, "_now", lambda: h.clock.current)
    cfg = sites_file(tmp_path, db_path)
    exit_code, rows, out = probe_json(cfg, "-o", "json")

    assert exit_code == 0, out
    assert len(rows) == 1, out
    row = rows[0]
    assert row["device_serial"] == SERIAL
    assert row["kind"] == PROBE_KIND_RESET
    assert row["reads"] == stored.reads, "the screen shows the pages the read actually sent"
    assert row["window_from_utc"] == stored.window_from_utc
    assert row["window_to_utc"] == stored.window_to_utc
    assert row["current"] is True, "probed at the frozen now: current for this reader"
    assert row["age_s"] == 0.0


def test_probe_list_filters_to_one_device(tmp_path: Path) -> None:
    """`--device-serial` narrows the screen; the other device's evidence stays in the db."""
    db_path = seed(tmp_path, row_at(ran_at=utc(60)), row_at(serial=OTHER_SERIAL, ran_at=utc(60)))
    cfg = sites_file(tmp_path, db_path)
    exit_code, rows, out = probe_json(cfg, "-o", "json", "--device-serial", OTHER_SERIAL)
    assert exit_code == 0, out
    assert [r["device_serial"] for r in rows] == [OTHER_SERIAL]


def test_the_default_bound_is_the_loops_own_page_budget() -> None:
    """The screen's default asks the natural question: is the loop due another probe by now?

    Pinned against `RESET_PROBE_INTERVAL_S` rather than a second literal, the way GC-P11 pins
    its writer and reader to one constant. If the budget moves and this does not, the operator
    is told "stale" about a loop that is exactly on schedule.
    """
    assert float(RESET_PROBE_INTERVAL_S) == PROBE_STALE_DEFAULT_S


def test_a_stale_row_is_still_shown_and_only_its_current_flag_moves(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Staleness changes the verdict column, never the history on the screen.

    `--max-age-s 0` is the operator saying "only this instant counts". The row must still be
    there with its window and its cost — dropping stale rows would turn the operator's read
    back into the silence the card exists to remove, and would make the table lie about what
    the loop has ever asked.
    """
    db_path = seed(tmp_path, row_at(ran_at=utc(7200)))
    cfg = sites_file(tmp_path, db_path)
    exit_code, rows, out = probe_json(cfg, "-o", "json", monkeypatch=monkeypatch, now=T0)
    assert exit_code == 0, out
    assert len(rows) == 1
    assert rows[0]["age_s"] == 7200.0
    assert rows[0]["current"] is False

    exit_code, current_rows, out = probe_json(
        cfg, "-o", "json", "--max-age-s", "7200", monkeypatch=monkeypatch, now=T0
    )
    assert exit_code == 0, out
    assert current_rows[0]["current"] is True, "the bound is the reader's: moving it is legal"
    assert current_rows[0]["window_to_utc"] == rows[0]["window_to_utc"], "same row, same facts"


def test_a_negative_bound_is_refused_rather_than_making_everything_invisible(
    tmp_path: Path,
) -> None:
    """A typo'd `--max-age-s -5` must not read as "nothing is evidence"."""
    db_path = seed(tmp_path, row_at(ran_at=utc(30)))
    cfg = sites_file(tmp_path, db_path)
    exit_code, _rows, out = probe_json(cfg, "-o", "json", "--max-age-s", "-5")
    assert exit_code == 2, out
    assert "negative" in out


def test_a_store_that_does_not_exist_exits_2_and_names_the_reason(tmp_path: Path) -> None:
    """No store is a site whose agent never ran — a reason, not a traceback and not a table.

    Distinct from the empty-table case on purpose: there the agent runs and never had a quiet
    tick, here nothing ever ran at all.
    """
    cfg = sites_file(tmp_path, tmp_path / "nowhere" / "agent.sqlite3")
    exit_code, _rows, out = probe_json(cfg, "-o", "json")
    assert exit_code == 2, out
    assert "nothing has been probed" in out


def test_no_rows_exits_0_because_a_busy_site_legitimately_has_none(tmp_path: Path) -> None:
    """The honesty rule of this surface, pinned as an exit code.

    The recorded probe runs only on a QUIET tick (the narrow poll returned no records), so a
    busy site earns none and a store full of punches has every right to render zero rows. Exit
    2 here would call a healthy site broken, which is the failure mode this card's whole
    decision is trying to avoid.
    """
    db_path = seed(tmp_path)  # the writer runs, the table stays empty
    cfg = sites_file(tmp_path, db_path)
    exit_code, rows, out = probe_json(cfg)
    assert exit_code == 0, out
    assert rows == []
    assert "(no rows)" in out


def test_the_help_keeps_the_two_probe_surfaces_apart(tmp_path: Path) -> None:
    """`gateclerk status` already shows a "device probe" that is NOT this one.

    GC-P11's `status/device-probe.json` is a site-level doctor verdict cache with a 60 s TTL;
    this table is per-device, per-kind and written by the running loop. The distinction lives
    in the help text an operator actually reads, so it cannot be dropped later without a red
    test.
    """
    result = runner.invoke(app, ["agent", "probe", "list", "--help"])
    assert result.exit_code == 0, result.output
    text = result.output
    assert "device-probe.json" in text, "the help stopped naming the surface this is not"
    assert "doctor" in text
    assert "quiet" in text.lower(), "the busy-site caveat left the help"
