"""Card P2-06: /healthz + metrics — the spec §2e vocabulary, no new concepts.

BINDING SPEC: docs/internal/P2-SITE-AGENT.md §2e (DECIDED 2026-10-19: carry over ALL listed P1
observables; minimal vocabulary; no dashboard). This module is a STATE COLLECTOR +
text/JSON builder — never a server (no socket is opened here; conftest.netoff would
kill the test if one were), and every gauge is read from where P1/P2 already computes
it: the P2-03 `TickResult`, `agent_push`'s queue queries + drain log counters,
`agent_store`'s checkpoint/size reads, the store's own `events` rows, and the live
`IsapiClient` counters. Tests call the builder functions directly.

The six DoD cases, 1:1 to test names below:

(1) the vocabulary IS the contract: sorted-name set equality against the card's list
    (module constants), and — in the /metrics test — against what the rendering of a
    REAL snapshot actually emits (18 lines, nothing invented, nothing dropped).
(2) a healthy fake run (the REAL P2-03 LoopHarness over FakeDevice) -> status ok,
    per-device ages, and every gauge equal to what the loop/store actually did
    (FakeDevice-backed counters and SQL recomputed in the test, not constants).
(3) a circuit-open device -> degraded + the serial NAMED in the reason line; a stuck
    checkpoint -> degraded + named (the card's two degraded triggers, nothing else).
(4) dead-letter depth read from actual store rows (agent_push seeds them through its
    own enqueue+drain against a failing transport; the health value == the COUNT(*)),
    with push_ok/push_failed read off the drain's own log lines.
(5) tz_offset_mismatch + site_labeled_windows: mapped (0 warnings) vs unmapped (1
    warning) fake runs reusing p1-12's mapping shapes — provenance records still
    mismatched in BOTH arms (the p1-12 decision), only the warning policy differs;
    plus the p1-05c fallback label counted per ok tick on the naive_time box.
(6) no secret-shaped strings anywhere in the emitted text (password/secret/lockout
    vocabulary, any IPv4, the fake host, digest material) while the site label is.

Plus the format pins the card names: the full /healthz text byte-pinned on the healthy
run ("stable-ish" means THIS test is the change gate), metric lines carry value+source,
the JSON round-trips for a separate reader (P2-07's socat), and the /metrics text never
contains a payload body, an endpoint ref, or a punch field.

Offline by construction: FakeDevice behind real IsapiClients, tmp sqlite files,
injected clocks; no real host or serial appears (fixtures carry MASKED-SER-1 and
TEST-NET 192.0.2.x).
"""

from __future__ import annotations

import json
import re
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

import httpx
import pytest

import gateclerk.cli as cli_mod
from fakedevice import RETIRE_ENVELOPE_ONLY, invalid_content
from gateclerk import __version__
from gateclerk.agent_health import (
    DEVICE_METRIC_NAMES,
    FALLBACK_MARKER,
    METRIC_NAMES,
    MISMATCH_MARKER,
    SITE_LABELLED,
    SNAPSHOT_ONLY_NAMES,
    AgentHealthCollector,
    device_health,
    healthz_text,
    metrics_text,
    snapshot_from_dict,
    snapshot_to_json,
)
from gateclerk.agent_push import (
    dead_letter_depth,
    dead_letter_rows,
    drain,
    enqueue_events,
    queue_depth,
    replay_dead_letter,
    stub_transport,
)
from gateclerk.agent_store import event_rowid, read_checkpoint
from gateclerk.model import EventRecord
from gateclerk.tz import Skew
from test_p2_03_scheduler import (
    CADENCE_S,
    DEVICE_INFO_PATH,
    EVENT_PATH,
    OVERLAP_S,
    PASSWORD,
    SCENARIOS,
    SITE,
    SITE_TZ,
    SYSTEM_TIME_PATH,
    T0,
    LoopHarness,
    device_event,
    seeded_device,
)

SERIAL = "MASKED-SER-1"

#: The card's §2e list, verbatim — test (1) pins the module's vocabulary against it.
SPEC_METRIC_NAMES = [
    "auth_recoveries",
    "auth_terminal_failures",
    "device_locked_events",
    "circuit_open_gauge",
    "tz_offset_mismatch_records",
    "tz_offset_mismatch_warnings",
    "site_labeled_windows",
    "device_clock_skew_seconds",
    "pages_fetched",
    "records_stored",
    "search_termination",
    "checkpoint_serial",
    "oldest_serial",
    "events_per_day",
    "push_ok",
    "push_failed",
    "dead_letter_depth",
    "db_size_bytes",
]


def locked_401() -> httpx.Response:
    """The device-locked 401 shape (same body test_isapi_transport.py:231 drives)."""
    return httpx.Response(
        401,
        content=(
            b'<?xml version="1.0" encoding="UTF-8"?>\r\n'
            b"<userCheck><statusValue>401</statusValue>"
            b"<lockStatus>locked</lockStatus><unlockTime>1800</unlockTime>"
            b"<retryLoginTime>1800</retryLoginTime></userCheck>"
        ),
    )


def stub_endpoint(tmp_path: Path) -> str:
    """An ABSOLUTE stub ingest target under tmp_path (never cwd-relative writes)."""
    return f"stub://{tmp_path / 'ingest' / 'lines.jsonl'}"


class CollectorHarness:
    """A P2-03 LoopHarness + a collector wired the way P2-07's unit wires it.

    The collector's warn sink IS the loop's warn sink (in the agent process every
    warning line routes through `observe_warn` too — the emitted health text is
    metric lines only, so warnings can never leak into it).
    """

    def __init__(
        self,
        tmp_path: Path,
        device: Any,
        *,
        db_name: str = "agent.sqlite3",
        device_tz: str | None = None,
        tz_mapping_declared: bool | None = None,
        checkpoint_stall_s: float = 900.0,
        client_password: str | None = None,
    ) -> None:
        from gateclerk.agent_loop import DeviceLoop

        self.db_path = tmp_path / db_name
        self.db_path.parent.mkdir(parents=True, exist_ok=True)  # sub-arm dirs (mapped/)
        self.h = LoopHarness(tmp_path, device, client_password=client_password)
        self.collector = AgentHealthCollector(
            site=SITE,
            conn=self.h.conn,
            db_path=str(self.db_path),
            checkpoint_stall_s=checkpoint_stall_s,
            tz_mapping_declared=(
                device_tz is not None if tz_mapping_declared is None else tz_mapping_declared
            ),
            now=self.h.clock,
            monotonic=self.h.monotonic,
            warn=self.h.warns.append,
        )
        if device_tz is not None:
            # The mapped arm (p1-12's sites.toml `device_tz`): the loop resolves records
            # in the declared zone; provenance still carries the device's claim.
            self.h.loop = DeviceLoop(
                client=self.h.client,
                conn=self.h.conn,
                site=SITE,
                site_tz=SITE_TZ,
                device_tz=device_tz,
                cadence_s=CADENCE_S,
                overlap_s=OVERLAP_S,
                inter_page_delay=0.0,
                now=self.h.clock,
                monotonic=self.h.monotonic,
                warn=self.h.warns.append,
            )
        self.results: list[Any] = []
        self.last_tick: Any = None

    def tick(self) -> Any:
        result = self.collector.observe_tick(
            self.h.loop.tick(), device_serial=SERIAL, client=self.h.client
        )
        self.results.append(result)
        self.last_tick = result
        return result

    def ticks(self, n: int, step_s: float = CADENCE_S) -> list[Any]:
        out = []
        for _ in range(n):
            out.append(self.tick())
            self.h.clock.advance(step_s)
            self.h.monotonic.advance(step_s)
        return out

    def collect(self) -> Any:
        return self.collector.collect(
            clients={SERIAL: self.h.client}, ticks={SERIAL: self.last_tick}
        )

    def stats(self) -> Any:
        return self.collector.stats(SERIAL)


def healthy(tmp_path: Path, *, serial106: bool = True, **kw: Any) -> CollectorHarness:
    """The card's healthy fake run: the recorded site-a box (p1-12 mapped), 3 clean ticks.

    Clock state after construction: ticks ran at 10:00/10:05/10:10 and the clock
    advanced once more -> collect() runs at 10:15 wall / monotonic 900, so BOTH ages
    are the derived 300.0 the pins state (last ok poll at 10:10; the checkpoint row was
    last written DURING the 10:10 tick).

    Tick windows (P2-03's math, re-run here so the expected counters are DERIVED, not
    asserted): [09:50,10:00] stores 100,101,102; [09:53,10:05] re-reads 102 FREE and
    stores 103,104; [09:59,10:10] re-reads 103,104 FREE and stores 105 (+106 when
    `serial106`). With `serial106=False` later tick windows hold only FREE re-reads:
    ok ticks whose checkpoint STOPPED advancing — the stall case's engine.
    """
    device = seeded_device()
    events = [
        device_event(100, "2026-10-19T09:52:00"),
        device_event(101, "2026-10-19T09:55:00"),
        device_event(102, "2026-10-19T09:58:00"),
        device_event(103, "2026-10-19T10:01:00"),
        device_event(104, "2026-10-19T10:04:00"),
        device_event(105, "2026-10-19T10:07:00"),
    ]
    if serial106:
        events.append(device_event(106, "2026-10-19T10:10:00"))
    device.add_events(*events)
    kw.setdefault("device_tz", SITE_TZ)  # site-a's production shape (p1-12 mapping)
    h = CollectorHarness(tmp_path, device, **kw)
    h.ticks(3)
    return h


def by_name(snapshot: Any) -> dict[str, Any]:
    """Snapshot-level (site) metric values."""
    return {m.name: m.value for m in snapshot.site_metrics}


def device_by_name(snapshot: Any, serial: str = SERIAL) -> dict[str, Any]:
    dev = next(d for d in snapshot.devices if d.device_serial == serial)
    return {m.name: m.value for m in dev.metrics}


# --- DoD (1): the vocabulary IS the contract ------------------------------------------


def test_metric_vocabulary_is_exactly_the_spec_list() -> None:
    """Sorted-name set equality against the card's §2e list — this IS the contract pin.

    Rename one name in the module, drop one, or invent a nineteenth, and the first
    assertion goes red. The rest pin the device/site split the renderers use (a tuple
    the builders never render is caught by the /metrics name-count test below).
    """
    assert sorted(METRIC_NAMES) == sorted(SPEC_METRIC_NAMES)
    assert set(SNAPSHOT_ONLY_NAMES) == {
        "db_size_bytes",
        "dead_letter_depth",
        "push_ok",
        "push_failed",
    }
    assert sorted(DEVICE_METRIC_NAMES) == sorted(set(SPEC_METRIC_NAMES) - set(SNAPSHOT_ONLY_NAMES))


# --- DoD (2): healthy fake run -> ok, real ages, real gauges ---------------------------


def test_healthy_fake_run_is_ok_with_real_ages_and_gauges(tmp_path: Path) -> None:
    """Every value equals what the loop/store/client actually did — no constants here.

    The asserted numbers are DERIVED in-test from the harness (tick results, SQL over
    the store, the client's own counters), exactly as the card demands: "match
    FakeDevice counters, not constants".
    """
    h = healthy(tmp_path)
    snap = h.collect()

    assert snap.status == "ok"
    assert snap.reasons == ()
    assert snap.site == SITE
    assert snap.agent_version == __version__

    dev = next(d for d in snap.devices if d.device_serial == SERIAL)
    # Ticks ran at 10:00/10:05/10:10, built at 10:15 (wall) / mono 900: last ok poll
    # 10:10 -> 300 s (monotonic seam); checkpoint row last written by the 10:10 tick
    # -> 300 s (wall seam — the two clocks each age their own kind of fact).
    assert dev.last_poll_ok_age_s == pytest.approx(300.0)
    assert dev.checkpoint_age_s == pytest.approx(300.0)
    assert dev.circuit_open is False
    assert dev.circuit_parked_s == 0.0
    cp = read_checkpoint(h.h.conn, SERIAL)
    assert cp is not None and dev.checkpoint_serial == cp.checkpoint_serial == 106

    v = device_by_name(snap)
    # Transport counter, read live from the client the run actually used.
    assert v["auth_recoveries"] == h.h.client.auth_recoveries == 0
    assert v["auth_terminal_failures"] == 0
    assert v["device_locked_events"] == 0
    assert v["circuit_open_gauge"] == 0
    # Store facts, recomputed by SQL in the test (the card: "from actual store rows").
    rows = h.h.conn.execute(
        "SELECT serial_no, tz_offset_mismatch FROM events ORDER BY serial_no"
    ).fetchall()
    assert [r["serial_no"] for r in rows] == [100, 101, 102, 103, 104, 105, 106]
    assert v["oldest_serial"] == 100
    # Cumulative counters EQUAL the tick results the harness recorded (derived, not
    # constants: the window walk re-reads the FREE overlap, so stored > distinct rows).
    assert v["pages_fetched"] == sum(r.pages for r in h.results)
    assert v["records_stored"] == sum(r.stored for r in h.results)
    assert v["search_termination"] == h.last_tick.termination == "OK"
    # The claimed +02:00 vs the +03:00 summer site: every record mismatches (p1-06c).
    assert all(r["tz_offset_mismatch"] == 1 for r in rows)
    assert v["tz_offset_mismatch_records"] == len(rows) == 7
    assert v["tz_offset_mismatch_warnings"] == 0  # mapped run (device_tz declared)
    assert v["site_labeled_windows"] == 0
    assert v["device_clock_skew_seconds"] is None  # nothing observed this run yet
    # events_per_day: count / (now - first event_time_utc), recomputed here.
    first = h.h.conn.execute("SELECT MIN(event_time_utc) m FROM events").fetchone()["m"]
    span = (h.h.clock() - datetime.fromisoformat(first)).total_seconds()
    assert v["events_per_day"] == pytest.approx(len(rows) * 86400.0 / span)

    s = by_name(snap)
    assert s["dead_letter_depth"] == 0 == dead_letter_depth(h.h.conn)
    assert s["push_ok"] == 0 and s["push_failed"] == 0
    assert s["db_size_bytes"] == h.db_path.stat().st_size > 0
    # The db really is the only state (card: a sidecar would be a second truth).
    tables = {r[0] for r in h.h.conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    assert "agent_health" not in tables


def test_healthz_text_is_byte_pinned_on_the_healthy_run(tmp_path: Path) -> None:
    """The /healthz format, byte for byte — "stable-ish" means THIS test is the gate.

    Byte pin, not substring: a renamed key or reordered line is exactly the drift the
    card's "pinned by test" demands be visible. A socat/curl consumer reads these keys.
    """
    h = healthy(tmp_path)
    snap = h.collect()
    dev = next(d for d in snap.devices if d.device_serial == SERIAL)
    lines = [
        "status: ok",
        f"site: {SITE}",
        f"agent_version: {__version__}",
        "devices: 1",
        "dead_letter_depth: 0",
        "last_poll_ok_age_s: 300.0",
        f"device: {SERIAL}",
        "  circuit_open: false",
        "  circuit_parked_s: 0.0",
        "  checkpoint_serial: 106",
        "  checkpoint_age_s: 300.0",
        "  last_poll_ok_age_s: 300.0",
    ]
    lines.extend(f"  {m.render()}" for m in dev.metrics)
    assert healthz_text(snap) == "\n".join(lines) + "\n"


def test_metrics_text_carries_every_name_with_value_and_source(tmp_path: Path) -> None:
    """/metrics: one line per emitted metric, `name value  # source`, full vocabulary.

    Sorted site-level names first, then one commented block per device. The exact
    count (4 site + 14 device = 18) plus set equality means a metric the builders
    never render cannot hide behind a constant, and a source-less line is red.
    """
    snap = healthy(tmp_path).collect()
    text = metrics_text(snap)
    lines = [line for line in text.splitlines() if not line.startswith("#")]
    names = [line.split(" ", 1)[0] for line in lines]
    assert sorted(names) == sorted(SPEC_METRIC_NAMES)
    assert len(names) == len(SPEC_METRIC_NAMES)
    for line in lines:
        assert "  # " in line, f"metric line without a source: {line!r}"
        assert line.split("  # ", 1)[1].strip()
    # The rollout gate's two zeros (docs/internal/P2-SITE-AGENT.md §5) visible as digits:
    assert re.search(r"^tz_offset_mismatch_warnings 0\b", text, re.M)
    assert re.search(r"^site_labeled_windows 0\b", text, re.M)


# --- DoD (3): degraded is named ------------------------------------------------------------


def test_circuit_open_device_makes_degraded_and_names_the_serial(tmp_path: Path) -> None:
    """The transport parks the device (terminal 401); healthz says WHY and WHICH.

    The locked 401 shape (device-locked body, unlockTime 1800) also feeds the two
    auth counters: one terminal failure and one locked event, both observed on the
    tick the loop returned as data (P2-03's never-raises contract, read from the
    health side). The follow-up parked skip adds NOTHING (no double-count) and sends
    zero requests (P2-03's no-hammer pin, re-read here from the health side).
    """
    device = seeded_device()
    device.add_events(device_event(110, "2026-10-19T09:58:00"))
    device.add_raw("GET", DEVICE_INFO_PATH, locked_401())
    h = CollectorHarness(tmp_path, device)

    r1 = h.tick()
    assert not r1.ok and h.h.client.circuit_open()
    mark = len(device.served)
    r2 = h.tick()
    assert r2.skipped and len(device.served) == mark, "a parked tick sends nothing"
    h.h.clock.advance(60)
    h.h.monotonic.advance(60)
    r3 = h.tick()  # a SECOND skip: the park anchor must stay at first-sight, not re-anchor
    assert r3.skipped

    snap = h.collect()
    assert snap.status == "degraded"
    assert any(SERIAL in reason and "circuit" in reason.lower() for reason in snap.reasons)
    v = device_by_name(snap)
    assert v["circuit_open_gauge"] == 1
    assert v["auth_terminal_failures"] == 1
    assert v["device_locked_events"] == 1
    parked = next(d for d in snap.devices if d.device_serial == SERIAL).circuit_parked_s
    assert parked == pytest.approx(60.0), "parked since FIRST sight (anchor never re-set)"

    text = healthz_text(snap)
    assert "status: degraded" in text and SERIAL in text


def test_two_park_episodes_anchor_the_second_at_its_own_first_sight(
    tmp_path: Path,
) -> None:
    """Episode 2's parked age must NOT inherit episode 1's anchor (anti-M2 pin).

    All real, no synthetic ticks: a locked 401 parks the circuit (episode 1's failing
    tick anchors it — `TickResult.circuit_open` is read after the raise, so the tick
    that opened the circuit reports it), the unlock window passes on the injected
    clocks, the next tick is genuinely ok (the armed raw response is one-shot) — that
    ok tick must CLEAR the anchor — then a re-armed locked 401 parks episode 2. Drop
    the ok-branch clear and the middle assert reads 2000.0 (episode 1's anchor
    inherited), not 0.0.
    """
    device = seeded_device()
    device.add_events(device_event(120, "2026-10-19T09:56:00"))
    device.add_raw("POST", EVENT_PATH, locked_401())  # episode 1: the search POST pays it
    h = CollectorHarness(tmp_path, device)

    def parked_now() -> float:
        return next(d for d in h.collect().devices if d.device_serial == SERIAL).circuit_parked_s

    def advance(seconds: float) -> None:
        h.h.clock.advance(seconds)
        h.h.monotonic.advance(seconds)

    r1 = h.tick()  # mono 0: search POST pays the locked 401 -> circuit opens (until 1810)
    assert not r1.ok and h.h.client.circuit_open()
    # Episode 1's anchor is r1 itself: _failure reads circuit_open() AFTER the raise.
    advance(100)
    assert h.tick().skipped  # a later skip must NOT move the anchor
    assert parked_now() == pytest.approx(100.0)

    # unlockTime 1800 (+margin 10): wait the lockout out — the armed raw was one-shot,
    # so this tick really walks and the ok branch must CLEAR the anchor.
    advance(1860)  # mono 2000 > 1810 -> circuit closed again
    r3 = h.tick()
    assert r3.ok, "the armed 401 was one-shot: this tick really walks"

    # Episode 2: park again at mono 2000; the gauge ages from episode 2's FIRST skip.
    device.add_raw("POST", EVENT_PATH, locked_401())
    r4 = h.tick()
    assert not r4.ok and h.h.client.circuit_open()
    assert h.tick().skipped  # episode 2's first skip, at mono 2000
    assert parked_now() == pytest.approx(0.0), "episode 2 did NOT inherit episode 1's anchor"
    advance(30)
    assert h.tick().skipped
    assert parked_now() == pytest.approx(30.0)


def test_checkpoint_stall_makes_degraded_and_names_the_serial(tmp_path: Path) -> None:
    """A checkpoint older than the caller's stall threshold is critical (spec §2c).

    The healthy box WITHOUT serial 106: the next two ticks succeed (their windows
    hold only FREE overlap re-reads — advanced=False) while the checkpoint stays
    frozen at the 10:10 tick's advance. By the 10:25 build it is 900 s old against a
    120 s threshold (P2-07 passes ~2x cadence from config) — ticking-but-stalled, the
    exact state DESIGN.md OQ4 calls critical. Building the snapshot must not touch
    the device (the stall check is a db read, not a probe).
    """
    h = healthy(tmp_path, serial106=False, checkpoint_stall_s=120.0)
    for _ in range(2):  # ticks at 10:15 and 10:20: ok, advanced=False, no new rows
        r = h.tick()
        assert r.ok and not r.advanced
        h.h.clock.advance(CADENCE_S)
        h.h.monotonic.advance(CADENCE_S)

    mark = len(h.h.device.served)
    snap = h.collect()  # built at 10:25; checkpoint row last written during the 10:10 tick
    assert len(h.h.device.served) == mark, "snapshot building must not touch the device"
    assert snap.status == "degraded"
    assert any(SERIAL in reason and "checkpoint" in reason.lower() for reason in snap.reasons)
    assert snap.checkpoint_stall_s == 120.0
    assert SERIAL in healthz_text(snap)


# --- DoD (4): dead-letter depth from actual store rows ---------------------------------


def test_dead_letter_depth_and_push_counters_come_from_the_store(tmp_path: Path) -> None:
    """agent_push seeds the rows; the health side just counts them — and reports push_ok.

    Three stored events are queued; all three fail past the bound into dead_letter
    (failing transport); one is replayed and reaches the stub ingest, whose success
    DELETES its dead-letter row (agent_push's own rule) — depth must follow the SQL,
    not the history. push_ok/push_failed are the drain log's own cumulative counters.
    """
    h = healthy(tmp_path)
    endpoint = stub_endpoint(tmp_path)
    rowids = [r for sn in (100, 101, 102) if (r := event_rowid(h.h.conn, SERIAL, sn)) is not None]
    assert len(rowids) == 3
    enqueue_events(h.h.conn, rowids, endpoint=endpoint, now=T0)
    assert queue_depth(h.h.conn) == 3

    def failing(url: str, body: str) -> int:
        raise ConnectionError("ingest down")

    # Drain 1: everything fails but nothing is past the 1 h bound -> all retried.
    drain(
        h.h.conn,
        endpoint=endpoint,
        transport=failing,
        now=T0 + timedelta(seconds=60),
        rng=lambda: 0.5,
        dead_letter_after_s=3600,
        log=h.collector.observe_push_log,
    )
    # Drain 2 an hour later: past the bound -> all dead-lettered.
    drain(
        h.h.conn,
        endpoint=endpoint,
        transport=failing,
        now=T0 + timedelta(seconds=3660),
        rng=lambda: 0.5,
        dead_letter_after_s=3600,
        log=h.collector.observe_push_log,
    )
    assert dead_letter_depth(h.h.conn) == 3

    # The ingest is back: replay the first dead-letter row, drain accepts it.
    first_row = dead_letter_rows(h.h.conn)[0]
    replay_dead_letter(h.h.conn, first_row.id, now=T0 + timedelta(seconds=3720))
    out = tmp_path / "ingest" / "lines.jsonl"
    drain(
        h.h.conn,
        endpoint=endpoint,
        transport=stub_transport(endpoint),
        now=T0 + timedelta(seconds=3720),
        rng=lambda: 0.5,
        log=h.collector.observe_push_log,
    )

    depth_sql = h.h.conn.execute("SELECT COUNT(*) c FROM dead_letter").fetchone()["c"]
    snap = h.collect()
    s = by_name(snap)
    assert s["dead_letter_depth"] == depth_sql == dead_letter_depth(h.h.conn) == 2
    assert len(dead_letter_rows(h.h.conn)) == 2
    # Cumulative drain counters: 1 accepted; 3 retried + 3 dead-lettered failed.
    assert s["push_ok"] == 1
    assert s["push_failed"] == 6
    assert out.exists() and len(out.read_text().splitlines()) == 1
    assert queue_depth(h.h.conn) == 0
    # Health text never leaks the payload body or the endpoint ref.
    text = metrics_text(snap) + "\n" + healthz_text(snap)
    assert endpoint not in text and "payload" not in text.lower()


# --- DoD (5): mapping shapes decide the warning count, not the records -----------------


def test_mapped_run_is_silent_unmapped_run_warns_once_records_mismatch_in_both(
    tmp_path: Path,
) -> None:
    """p1-12's mapping arms through the health surface (card DoD 5).

    BOTH arms are the site-a summer box: the device claims +02:00, the site resolves
    +03:00, so EVERY record carries tz_offset_mismatch (provenance is a fact about the
    data — the mapping silences the warning, never the flag; p1-12's owner decision).
    The mapped arm (device_tz declared) emits NO once-per-run warning; the unmapped
    arm emits exactly one, and the line is the p1-06c policy's OWN text (delegated to
    `cli._warn_tz_mismatch`, reused not forked). Once-per-run semantics: a SECOND
    collect must not warn again — the count sticks at 1 (the agent's run is its life).
    """
    mapped = healthy(tmp_path / "mapped", device_tz=SITE_TZ)
    unmapped = healthy(tmp_path / "unmapped", device_tz=None, tz_mapping_declared=False)

    m_snap, u_snap = mapped.collect(), unmapped.collect()
    m_dev, u_dev = device_by_name(m_snap), device_by_name(u_snap)

    # Provenance identical in both arms: every record mismatches (7 with serial 106).
    assert m_dev["tz_offset_mismatch_records"] == u_dev["tz_offset_mismatch_records"] == 7
    # The warning policy is the ONLY difference the health surface sees.
    assert m_dev["tz_offset_mismatch_warnings"] == 0
    assert u_dev["tz_offset_mismatch_warnings"] == 1
    # And when it fires, it is the p1-06c line, once (p1-12's bytes for a 7-record run).
    mismatch_lines = [w for w in unmapped.h.warns if MISMATCH_MARKER in w]
    assert len(mismatch_lines) == 1
    assert "7 of 7 events have tz_offset_mismatch=true" in mismatch_lines[0]
    assert "records are correct" in mismatch_lines[0]
    assert not [w for w in mapped.h.warns if MISMATCH_MARKER in w]
    # The collector delegates to the CLI's own policy object (the anti-fork pin).
    assert unmapped.collector.mismatch_policy is cli_mod._warn_tz_mismatch
    # Once-per-run: a second collect warns again NOTHING, and the gauge holds its 1.
    unmapped.collect()
    assert len([w for w in unmapped.h.warns if MISMATCH_MARKER in w]) == 1
    assert device_by_name(unmapped.collect())["tz_offset_mismatch_warnings"] == 1


def test_site_labeled_fallback_run_counts_windows_per_ok_tick(tmp_path: Path) -> None:
    """The p1-05c risky fallback: the naive_time box, the label the loop reports.

    Three ok ticks on a box whose System/time claims nothing -> window_label is the
    site (fallback) label on every one -> site_labeled_windows == 3 (spec: should be
    ~0; this counter is how the §5 rollout gate PROVES it is ~0, so the number must
    come from the loop's own label, not a re-derivation). The fallback marker travels
    through the warn sink too (the loop emits it); the collector must not count it as
    a tz warning, and must not double-emit it.
    """
    device = seeded_device()
    naive = (SCENARIOS / "naive_time" / "system_time.xml").read_text()
    device.reset("GET", SYSTEM_TIME_PATH, httpx.Response(200, text=naive))
    device.add_events(device_event(130, "2026-10-19T09:58:00"))
    h = CollectorHarness(tmp_path, device)
    results = h.ticks(3)
    assert all(r.ok for r in results)
    assert [r.window_label for r in results] == [SITE_LABELLED] * 3

    v = device_by_name(h.collect())
    assert v["site_labeled_windows"] == 3
    assert v["tz_offset_mismatch_warnings"] == 0  # no claim -> None -> never a mismatch
    assert len([w for w in h.h.warns if FALLBACK_MARKER in w]) == 3  # the loop's own lines

    # search_termination fallback: a collect with NO tick in hand still reports what
    # the last OBSERVED tick said — the loop hands it over at observe_tick, the health
    # side never re-walks (a collector whose ticks map was cleared mid-serve must not
    # render "unknown" for a metric it already saw). Derived value: the naive box's
    # last completed chunk ended NOMATCH, and that is exactly what both paths report.
    assert h.last_tick.termination == "NOMATCH"  # the scenario's actual chunk verdict
    no_tick = h.collector.collect(clients={SERIAL: h.h.client}, ticks={})
    assert device_by_name(no_tick)["search_termination"] == h.last_tick.termination


# --- DoD (6): no secrets, no hosts beyond the site label -------------------------------


def test_emitted_text_carries_no_secret_shaped_strings(tmp_path: Path) -> None:
    """The card's NO SECRETS rule, scanned mechanically over every emitted line.

    Deliberately built on the RICH run: stored punches + dead-letter rows (full
    payload bodies with employee_no + name!), a parked circuit whose 401 body carries
    lockout counters, push targets and an absolute db path on disk, plus a
    deliberately secret-shaped line pushed through the collector's warn funnel. If any
    payload, credential, host or lockout detail can reach the health text, it can do
    it here — and none of it may.
    """
    device = seeded_device()
    # Distinctive payload values (the helper's "1"/"User E1" are substrings of
    # ordinary metric text — a scan against them would prove nothing).
    device.add_events(
        {
            **device_event(150, "2026-10-19T09:52:00"),
            "employeeNoString": "EMP90071",
            "name": "Zsocia Kvintal",
        },
        {
            **device_event(151, "2026-10-19T09:55:00"),
            "employeeNoString": "EMP90072",
            "name": "Vexly Quorumbat",
        },
    )
    h = CollectorHarness(tmp_path, device)
    h.ticks(2)  # both punches stored BEFORE the auth fault is armed
    assert [r["serial_no"] for r in h.h.stored_rows()] == [150, 151]

    # The device turns locked mid-life: the next tick's search POST pays the locked 401.
    device.add_raw("POST", EVENT_PATH, locked_401())
    r = h.tick()
    assert not r.ok and h.h.client.circuit_open()
    # A secret-shaped warning pushed through the funnel must never reach the text.
    h.collector.observe_warn("warning: password=admin token=*** digest secret")

    endpoint = stub_endpoint(tmp_path)
    rowids = [
        x
        for x in (event_rowid(h.h.conn, SERIAL, 150), event_rowid(h.h.conn, SERIAL, 151))
        if x is not None
    ]
    assert len(rowids) == 2
    enqueue_events(h.h.conn, rowids, endpoint=endpoint, now=T0)

    def failing(url: str, body: str) -> int:
        raise ConnectionError("ingest down")

    for elapsed in (60, 7260):  # fail past the bound on the second drain
        drain(
            h.h.conn,
            endpoint=endpoint,
            transport=failing,
            now=T0 + timedelta(seconds=elapsed),
            rng=lambda: 0.5,
            dead_letter_after_s=3600,
            log=h.collector.observe_push_log,
        )
    h.collector.observe_skew(SERIAL, Skew(skew_seconds=-7.5))
    snap = h.collect()
    text = healthz_text(snap) + metrics_text(snap)

    assert h.last_tick is not None  # sanity: the scan ran over a real run
    forbidden = [PASSWORD, "fakepw", "192.0.2.10", endpoint, "admin", "Bearer", "digest"]
    offenders = [needle for needle in forbidden if needle.lower() in text.lower()]
    assert offenders == []
    assert re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", text) is None, "an IPv4 in healthz"
    for word in ("password", "passwd", "secret", "token", "unlocktime", "lockstatus"):
        assert word not in text.lower(), word
    # A dead-letter row holds a full punch payload (name + employee no) — it must
    # stay in the store: no payload field appears in the emitted text.
    payload = json.loads(dead_letter_rows(h.h.conn)[0].payload)
    assert payload["employee_no"] not in text and payload["name"] not in text
    # The site label is allowed and present (spec: "no hosts beyond site label").
    assert f"site: {SITE}" in text


# --- collector seams the agent process uses ---------------------------------------------


def test_observed_skew_is_a_gauge_not_a_degraded_trigger(tmp_path: Path) -> None:
    """observe_skew stores the gauge; spec §2c keeps clock skew a WARNING channel.

    The card's degraded rule is circuit-open / checkpoint stall only — a skewed clock
    (even beyond SKEW_WARN_SECONDS) must never flip ok -> degraded here, and the
    warning fires exactly ONCE per process (repeat observe calls update the gauge but
    do not re-warn: repeating warnings train operators out of reading them).
    """
    h = healthy(tmp_path)
    h.collector.observe_skew(SERIAL, Skew(skew_seconds=-130.0, warn_seconds=120.0))
    snap = h.collect()
    assert device_by_name(snap)["device_clock_skew_seconds"] == -130.0
    assert snap.status == "ok"
    assert len([w for w in h.h.warns if "skew" in w]) == 1
    h.collector.observe_skew(SERIAL, Skew(skew_seconds=-131.0, warn_seconds=120.0))
    assert device_by_name(h.collect())["device_clock_skew_seconds"] == -131.0
    assert len([w for w in h.h.warns if "skew" in w]) == 1  # once per process


def test_device_health_builder_is_pure_and_callable_directly(tmp_path: Path) -> None:
    """No sockets, no side effects: the builders are functions over state (card rule).

    device_health() takes conn/stats/client/last_tick/clock directly and reads only —
    running it twice on the same store yields identical blocks, and neither run opens
    a device request.
    """
    h = healthy(tmp_path)
    mark = len(h.h.device.served)
    kwargs: dict[str, Any] = {
        "conn": h.h.conn,
        "device_serial": SERIAL,
        "stats": h.stats(),
        "client": h.h.client,
        "last_tick": h.last_tick,
        "now": h.h.clock,
        "monotonic": h.h.monotonic,
    }
    first = device_health(**{**kwargs, "now": h.h.clock()})
    second = device_health(**{**kwargs, "now": h.h.clock()})
    assert len(h.h.device.served) == mark
    assert [(m.name, m.value) for m in first.metrics] == [(m.name, m.value) for m in second.metrics]
    assert first.last_poll_ok_age_s == pytest.approx(300.0)
    assert first.metrics and all(m.source for m in first.metrics)


def test_auth_recoveries_match_the_clients_own_counter_after_a_recovery(tmp_path: Path) -> None:
    """The gauge must equal IsapiClient.auth_recoveries, not a constant (card DoD 2).

    The fake retires the nonce every N authorized responses in the CHALLENGE-LESS
    envelope-only shape (OBSERVED.md's live repro) — that is the shape the transport
    counts as a recovery (a challenged 401 heals inside httpx and is NOT one). The
    health surface must carry the client's exact number, and a recovery is never a
    degraded trigger (spec §2c: recoveries are info).
    """
    device = seeded_device()
    device.add_events(
        device_event(140, "2026-10-19T09:58:00"),
        # a later punch too: the checkpoint keeps ADVANCING (the collect at 10:20
        # must show a healthy 600 s checkpoint age, not an unrelated stall).
        device_event(141, "2026-10-19T10:08:00"),
    )
    device.retire_after = 5  # bootstrap pays 4 authed GETs; the 5th (event POST) retires
    device.retire_shape = RETIRE_ENVELOPE_ONLY
    h = CollectorHarness(tmp_path, device)
    results = h.ticks(4)
    assert all(r.ok for r in results)
    assert h.h.client.auth_recoveries >= 1, "the scenario must actually rotate the nonce"
    snap = h.collect()
    assert device_by_name(snap)["auth_recoveries"] == h.h.client.auth_recoveries
    assert snap.status == "ok"


def test_snapshot_json_round_trips_for_a_separate_reader(tmp_path: Path) -> None:
    """/healthz JSON serving: P2-07's socat reads state written by the agent loop, so
    the snapshot must survive a JSON round trip (same object, same render) — the
    documented sidecar contract of this card. Every field is plain JSON-typed; no
    datetime or connection leaks in, and the dump passes the same secret scan as the
    text surface.
    """
    snap = healthy(tmp_path).collect()
    blob = snapshot_to_json(snap)
    assert f'"site": "{SITE}"' in blob
    assert '"status": "ok"' in blob
    assert PASSWORD not in blob and "192.0.2.10" not in blob
    restored = snapshot_from_dict(json.loads(blob))
    assert restored == snap
    assert healthz_text(restored) == healthz_text(snap)
    assert metrics_text(restored) == metrics_text(snap)


def test_mismatch_policy_input_is_the_stores_own_rows_never_rederived(
    tmp_path: Path,
) -> None:
    """The policy input is `EventRecord.from_dict` of the stored lines (p1-12's rule:
    a summary that recomputes can disagree with the records it summarizes).

    The handed-over records match the store column for column, and their
    `tz_offset_mismatch` agrees with the column the records gauge counts.
    """
    h = healthy(tmp_path / "records")
    records = h.collector.mismatch_records(SERIAL)
    assert len(records) == 7
    assert all(isinstance(r, EventRecord) and r.tz_offset_mismatch is True for r in records)
    rows = h.h.conn.execute(
        "SELECT serial_no, employee_no, tz_offset_mismatch FROM events ORDER BY serial_no"
    ).fetchall()
    assert [(r.serial_no, r.employee_no) for r in records] == [
        (row["serial_no"], row["employee_no"]) for row in rows
    ]
    assert all(
        (r.tz_offset_mismatch is True) == bool(row["tz_offset_mismatch"])
        for r, row in zip(records, rows, strict=True)
    )


# --- defensive posture: the health surface bends, never breaks ---------------------------


def test_health_surface_survives_a_corrupt_store(tmp_path: Path) -> None:
    """Junk in the store is data, not a crash and not a stall (the collector serves).

    One unparseable contract line is SKIPPED from the policy input; an unparseable or
    naive checkpoint stamp makes the age UNKNOWN (None) — which by rule cannot trigger
    the stall degrade — and a garbage event_time takes events_per_day to None. Every
    other metric of the same run still renders.
    """
    h = healthy(tmp_path / "corrupt")
    h.h.conn.execute("UPDATE events SET jsonl = '{{ not json' WHERE serial_no = 101")
    assert [r.serial_no for r in h.collector.mismatch_records(SERIAL)] == [
        100,
        102,
        103,
        104,
        105,
        106,
    ]

    h.h.conn.execute("UPDATE checkpoint SET updated_at = 'not a stamp'")
    snap = h.collect()
    dev = next(d for d in snap.devices if d.device_serial == SERIAL)
    assert dev.checkpoint_age_s is None and snap.status == "ok"

    h.h.conn.execute("UPDATE checkpoint SET updated_at = '2026-10-19T10:10:00'")  # naive
    dev = next(d for d in h.collect().devices if d.device_serial == SERIAL)
    assert dev.checkpoint_age_s is None

    # ALL rows junked: MIN(event_time_utc) must not find a parseable stamp at all.
    h.h.conn.execute("UPDATE events SET event_time_utc = 'nonsense'")
    values = {m.name: m.value for m in h.collect().devices[0].metrics}
    assert values["events_per_day"] is None


def test_events_per_day_is_none_when_no_rate_is_definable(tmp_path: Path) -> None:
    """No rows, or the store's first punch AT the clock instant: rate is None, not 0/inf.

    0 would claim silence and inf would break the JSON contract (P2-07's reader) — the
    honest answer is 'no rate definable yet'.
    """
    from gateclerk.agent_health import _events_per_day

    h = healthy(tmp_path / "rate")
    assert _events_per_day(h.h.conn, "MASKED-SER-9", h.h.clock()) is None  # no rows
    now = h.h.clock()
    h.h.conn.execute("UPDATE events SET event_time_utc = ?", (now.isoformat(),))
    assert _events_per_day(h.h.conn, SERIAL, now) is None  # span <= 0


def test_wiring_guards_and_unparseable_observations_are_loud_or_silent_as_appropriate(
    tmp_path: Path,
) -> None:
    """Two wiring guards RAISE (they are agent bugs), every observation seam swallows.

    A collector built with a stall threshold <= 0 degrades everything by construction,
    and one collector fed two loops' ticks splits counters invisibly — both crash loudly
    at wiring time. `observe_push_log` on a non-drain or malformed line just does
    nothing: a health counter must never be able to break the drain it watches.
    """
    import types

    h = CollectorHarness(tmp_path / "guards", seeded_device())
    with pytest.raises(ValueError, match="checkpoint_stall_s"):
        AgentHealthCollector(
            site=SITE,
            conn=h.h.conn,
            db_path=str(h.db_path),
            checkpoint_stall_s=0.0,
            tz_mapping_declared=False,
        )
    wrong = types.SimpleNamespace(device_serial="MASKED-SER-9", ok=True)
    with pytest.raises(ValueError, match="one collector per device loop"):
        h.collector.observe_tick(wrong, device_serial=SERIAL, client=None)

    for junk in (
        "totally unrelated line",
        "prefix push drain: sent=1 retried=0 dead_lettered=0",  # not a bare drain line
        "push drain: sent=x retried=1 dead_lettered=0",  # non-integer field
    ):
        h.collector.observe_push_log(junk)
    push = h.collector._push
    assert (push.push_ok, push.push_failed) == (0, 0)


def test_a_crashing_mismatch_policy_cannot_break_a_health_poll(
    tmp_path: Path,
) -> None:
    """The delegated p1-06c policy raising is caught: the poll still renders, count 0."""
    h = healthy(tmp_path / "policy-crash")

    def boom(records: Any, *, mapping_declared: bool) -> None:
        raise RuntimeError("policy exploded")

    h.collector.mismatch_policy = boom  # type: ignore[assignment]
    snap = h.collect()
    assert snap.status == "ok"
    assert h.stats().mismatch_warnings == 0


def test_default_warn_sink_prints_to_stderr(tmp_path: Path) -> None:
    """The default sink is the agent_loop precedent (rich console, stderr, no markup)."""
    import contextlib
    import io

    from gateclerk.agent_health import _stderr_warn

    buffer = io.StringIO()
    with contextlib.redirect_stderr(buffer):
        _stderr_warn("healthz sink probe")
    assert "healthz sink probe" in buffer.getvalue()


def test_warn_stream_never_double_counts_the_fallback_gauge(tmp_path: Path) -> None:
    """`observe_warn` counts the FALLBACK marker only — not the mismatch marker, never
    a second count from the stream when the tick label already counted (p1-05c prints
    the fallback line per risky window; the gauge's source of truth is the loop label).

    This is the anti-M5 pin: if the fallback counter were wired to the warn stream
    instead of the tick label, an ok tick whose label is fallback would count nothing
    here and every fallback line would count double.
    """
    h = CollectorHarness(tmp_path / "warnstream", seeded_device())
    h.collector.observe_warn(f"{FALLBACK_MARKER} duplicate line one")
    h.collector.observe_warn(f"{FALLBACK_MARKER} duplicate line two")
    assert h.stats().site_labeled_windows == 0, "the stream must not seed the gauge"
    h.collector.observe_warn(f"{MISMATCH_MARKER} tz summary")
    assert h.stats().site_labeled_windows == 0, "the mismatch marker is not the fallback"
    assert h.stats().mismatch_warnings is None, "warn observation must not run the policy"


def test_auth_terminal_failures_counts_auth_verdicts_only(
    tmp_path: Path,
) -> None:
    """A WRONG-PASSWORD terminal 401 counts once; a non-auth walk failure counts ZERO.

    The counter is the transport's auth verdict (`IsapiAuthError.terminal`), not
    "tick failed": folding every failure in would page on/off-call noise as credential
    trouble (spec §2c splits the two). The non-auth arm: content error via the same
    harness shape (503 -> IsapiBadContent -> ok=False, exception is NOT auth-shaped).
    """
    device = seeded_device()
    device.add_events(device_event(160, "2026-10-19T09:56:00"))
    h = CollectorHarness(tmp_path, device, client_password="wrongpw")
    r = h.tick()
    assert not r.ok and h.h.client.circuit_open()
    assert device_by_name(h.collect())["auth_terminal_failures"] == 1

    device2 = seeded_device()
    device2.add_events(device_event(170, "2026-10-19T09:56:00"))
    device2.reset_raw("POST", EVENT_PATH, invalid_content())
    h2 = CollectorHarness(tmp_path / "nonauth", device2)
    r2 = h2.tick()
    assert not r2.ok and type(r2.exception).__name__ == "IsapiBadContent"
    assert device_by_name(h2.collect())["auth_terminal_failures"] == 0
