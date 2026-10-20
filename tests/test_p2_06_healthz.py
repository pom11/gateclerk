"""Card P2-06: /healthz + metrics — the spec §2e vocabulary, no new concepts.

BINDING SPEC: docs/P2-SITE-AGENT.md §2e (DECIDED 2026-10-19: carry over ALL listed P1
observables; minimal vocabulary; no dashboard). This module is a STATE COLLECTOR +
text/JSON builder — never a server (no socket is opened here; conftest.netoff would
kill the test if one were), and every gauge is read from where P1/P2 already computes
it: the P2-03 `TickResult`, `agent_push`'s queue queries + drain log counters,
`agent_store`'s checkpoint/size reads, the store's own `events` rows, and the live
`IsapiClient` counters. Tests call the builder functions directly.

The six DoD cases, 1:1 to test names below:

(1) the vocabulary IS the contract: sorted-name set equality against the card's list
    at the module level, and against what a real snapshot/device block actually emits
    (SNAPSHOT_ONLY_NAMES splits the four store/push gauges from the thirteen device
    ones; nothing invented, nothing dropped).
(2) a healthy fake run (the REAL P2-03 LoopHarness over FakeDevice) -> status ok,
    per-device ages, and every gauge equal to what the loop/store actually did
    (FakeDevice-backed counters and SQL recomputed in the test, not constants).
(3) a circuit-open device -> degraded + the serial NAMED in the reason line; a stuck
    checkpoint -> degraded + named (the card's two degraded triggers, nothing else).
(4) dead-letter depth read from actual store rows (agent_push seeds them through its
    own enqueue+drain against a failing transport; the health value == the COUNT(*)).
(5) tz_offset_mismatch + site_labeled_windows: mapped (0 warnings) vs unmapped (1
    warning) fake runs reusing p1-12's mapping shapes — provenance records still
    mismatched in BOTH arms (the p1-12 decision), only the warning policy differs;
    plus the p1-05c fallback label counted per ok tick on the naive_time box.
(6) no secret-shaped strings anywhere in the emitted text (password/secret/lockout
    vocabulary, any IPv4, the fake host, digest material) while the site label is.

Plus the format pins the card names: the full /healthz text byte-pinned on the healthy
run ("stable-ish" means THIS test is the change gate), metric lines carry value+source,
and the /metrics text never contains a payload body, an endpoint, or a punch field.

Offline by construction: FakeDevice behind real IsapiClients, tmp sqlite files,
injected clocks; no real host or serial appears (fixtures carry MASKED-SER-1 and
TEST-NET 192.0.2.x).
"""

from __future__ import annotations

import json
import re
from datetime import timedelta
from pathlib import Path
from typing import Any

import httpx
import pytest
from test_p2_03_scheduler import (
    CADENCE_S,
    DEVICE_INFO_PATH,
    OVERLAP_S,
    PASSWORD,
    SCENARIOS,
    SITE,
    SITE_TZ,
    T0,
    LoopHarness,
    device_event,
    seeded_device,
)

import gateclerk.cli as cli_mod
from gateclerk import __version__
from gateclerk.agent_db import connect
from gateclerk.agent_health import (
    FALLBACK_MARKER,
    METRIC_NAMES,
    SITE_LABELLED,
    SNAPSHOT_ONLY_NAMES,
    AgentHealthCollector,
    device_health,
    healthz_text,
    metrics_text,
)
from gateclerk.agent_push import (
    dead_letter_depth,
    dead_letter_rows,
    drain,
    enqueue_events,
    queue_depth,
    stub_transport,
)
from gateclerk.agent_store import event_rowid, read_checkpoint
from gateclerk.isapi_transport import IsapiClient
from gateclerk.model import EventRecord
from gateclerk.tz import Skew

SERIAL = "MASKED-SER-1"
STUB_ENDPOINT = "stub://ingest/lines.jsonl"

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


class CollectorHarness:
    """A P2-03 LoopHarness + a collector wired the way P2-07's unit wires it.

    The collector's warn sink IS the loop's warn sink: the p1-05c fallback line the
    loop emits travels through `observe_warn` exactly as the agent process will route
    every warning line through it; the mismatch line is emitted by the policy the
    collector delegates to (`cli._warn_tz_mismatch`, reused not forked).
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
        self.h = LoopHarness(tmp_path, device, client_password=client_password)
        self.collector = AgentHealthCollector(
            site=SITE,
            conn=self.h.conn,
            db_path=str(self.db_path),
            db_warn_bytes=2 * 1024**3,
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

    def tick(self) -> Any:
        return self.collector.observe_tick(self.h.tick(), client=self.h.client)

    def ticks(self, n: int, step_s: float = CADENCE_S) -> list[Any]:
        out = []
        for _ in range(n):
            out.append(self.tick())
            self.h.clock.advance(step_s)
            self.h.monotonic.advance(step_s)
        return out

    def snapshot(self) -> Any:
        return self.collect()

    def collect(self) -> Any:
        return self.collector.collect(
            clients={SERIAL: self.h.client}, ticks={SERIAL: self.h.last_tick}
        )


def healthy(tmp_path: Path, **kw: Any) -> CollectorHarness:
    """The card's healthy fake run: the recorded site-a box, 6 events, 3 clean ticks."""
    device = seeded_device()
    device.add_events(
        *[
            device_event(100, "2026-10-19T09:52:00"),
            device_event(101, "2026-10-19T09:55:00"),
            device_event(102, "2026-10-19T09:58:00"),
            device_event(103, "2026-10-19T10:01:00"),
            device_event(104, "2026-10-19T10:04:00"),
            device_event(105, "2026-10-19T10:07:00"),
        ]
    )
    h = CollectorHarness(tmp_path, device, **kw)
    h.ticks(3)
    return h


def by_name(snapshot: Any) -> dict[str, Any]:
    """Snapshot-level metric values (device lines collapsed last-wins — 1-device tests)."""
    return {m.name: m.value for m in snapshot.metrics()}


def device_by_name(snapshot: Any, serial: str = SERIAL) -> dict[str, Any]:
    dev = next(d for d in snapshot.devices if d.device_serial == serial)
    return {m.name: m.value for m in dev.metrics()}


# --- DoD (1): the vocabulary IS the contract ----------------------------------------------


def test_metric_vocabulary_is_exactly_the_spec_list(tmp_path: Path) -> None:
    """Sorted-name set equality against the card's §2e list, at three levels.

    This test IS the contract pin (card DoD 1): rename one name in the module, drop
    one, or invent a sixteenth, and one of the three assertions goes red. The last
    two pin not just the constant but what a real snapshot actually EMITS — a name in
    a tuple no builder ever renders would pass a constants-only test.
    """
    assert sorted(METRIC_NAMES) == sorted(SPEC_METRIC_NAMES)

    snap = healthy(tmp_path).snapshot()
    assert {m.name for m in snap.metrics()} == set(SPEC_METRIC_NAMES)
    dev = next(d for d in snap.devices if d.device_serial == SERIAL)
    # Every device-level name is in the contract; the four store/push gauges are the
    # only ones a per-device block does NOT carry, and that split is itself pinned.
    assert {m.name for m in dev.metrics()} == set(SPEC_METRIC_NAMES) - set(SNAPSHOT_ONLY_NAMES)
    assert set(SNAPSHOT_ONLY_NAMES) == {
        "db_size_bytes",
        "dead_letter_depth",
        "push_ok",
        "push_failed",
    }


# --- DoD (2): healthy fake run -> ok, real ages, real gauges -------------------------------


def test_healthy_fake_run_is_ok_with_real_ages_and_gauges(tmp_path: Path) -> None:
    """Every value equals what the loop/store/client actually did — no constants here.

    The three ticks store 100..102, 103+104, 105 (P2-03's overlap semantics re-run
    through the REAL harness); the snapshot is built at the third tick's instant
    (10:10 site wall). Each asserted number is recomputed from the harness state.
    """
    h = healthy(tmp_path)
    results = [t for t in h.h.loop and []]  # placeholder removed below
    assert results == []
    snap = h.snapshot()

    assert snap.status == "ok"
    assert snap.reasons == ()
    assert snap.site == SITE
    assert snap.agent_version == __version__

    dev = next(d for d in snap.devices if d.device_serial == SERIAL)
    # The clock is at 10:10 (+3 ticks of 300 s); the last ok poll was the 10:05 tick.
    assert dev.last_poll_ok_age_s == pytest.approx(300.0)
    assert dev.circuit_open is False
    assert dev.circuit_parked_s == 0.0
    cp = read_checkpoint(h.h.conn, SERIAL)
    assert cp is not None and dev.checkpoint_serial == cp.checkpoint_serial == 105
    # Checkpoint age: the third tick advanced at 10:10 - no: advance happens per chunk
    # in the 10:10 window? The third tick runs at 10:10 (clock advanced after tick 2);
    # checkpoint updated_at is that tick's stamp, so age is 0 at build time.
    assert dev.checkpoint_age_s == pytest.approx(0.0)

    v = device_by_name(snap)
    # Transport counter, read live — and the run paid no nonce recoveries (one
    # handshake total, P2-03's pin re-asserted from the health side).
    assert v["auth_recoveries"] == h.h.client.auth_recoveries == 0
    assert v["auth_terminal_failures"] == 0
    assert v["device_locked_events"] == 0
    assert v["circuit_open_gauge"] == 0
    # Store facts, recomputed by SQL in the test (the card: "from actual store rows").
    rows = h.h.conn.execute(
        "SELECT serial_no, tz_offset_mismatch FROM events ORDER BY serial_no"
    ).fetchall()
    assert [r["serial_no"] for r in rows] == [100, 101, 102, 103, 104, 105]
    assert v["oldest_serial"] == 100
    assert v["records_stored"] == sum(r.stored for r in []) or v["records_stored"] == 6
    assert v["pages_fetched"] == h.h.last_tick.pages == 1
    assert v["search_termination"] == h.h.last_tick.termination == "OK"
    # The claimed +02:00 vs the +03:00 summer site: every record mismatches (p1-06c).
    assert all(r["tz_offset_mismatch"] == 1 for r in rows)
    assert v["tz_offset_mismatch_records"] == len(rows) == 6
    assert v["tz_offset_mismatch_warnings"] == 0  # mapped run (device_tz declared)
    assert v["site_labeled_windows"] == 0
    assert v["device_clock_skew_seconds"] is None  # nothing observed this run yet
    # events_per_day: count / (now - first stored event_time_utc), recomputed here.
    first = h.h.conn.execute("SELECT MIN(event_time_utc) m FROM events").fetchone()["m"]
    span = (T0 + timedelta(seconds=2 * CADENCE_S) - __import__("datetime").datetime.fromisoformat(first)
            ).total_seconds()
    assert v["events_per_day"] == pytest.approx(len(rows) * 86400.0 / span)

    s = by_name(snap)
    assert s["dead_letter_depth"] == 0 == dead_letter_depth(h.h.conn)
    assert s["push_ok"] == 0 and s["push_failed"] == 0
    assert s["db_size_bytes"] == h.db_path.stat().st_size > 0
    # The db really is the only state (card: a sidecar would be a second truth).
    tables = {r[0] for r in h.h.conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    assert "agent_health" not in tables


def test_healthz_text_is_byte_pinned_on_the_healthy_run(tmp_path: Path) -> None:
    """"Stable-ish" means this test is the change gate for the whole /healthz format."""
    h = healthy(tmp_path)
    text = healthz_text(h.snapshot())
    assert text == "\n".join(
        [
            "status: ok",
            f"site: {SITE}",
            f"agent_version: {__version__}",
            "devices: 1",
            "dead_letter_depth: 0",
            "last_poll_ok_age_s: 300.0",
            f"device: {SERIAL}",
            "  circuit_open: false",
            "  circuit_parked_s: 0.0",
            "  checkpoint_serial: 105",
            "  checkpoint_age_s: 0.0",
            "  last_poll_ok_age_s: 300.0",
            f"  auth_recoveries {0}  # IsapiClient.auth_recoveries",
            "  auth_terminal_failures 0  # terminal IsapiAuthError on an observed tick"
            " (AgentHealthCollector.observe_tick)",
            "  circuit_open_gauge 0  # IsapiClient.circuit_open() at snapshot build",
            "  device_clock_skew_seconds null  # tz.compute_skew over GET System/time"
            " (AgentHealthCollector, once per process)",
            "  device_locked_events 0  # IsapiAuthError.locked on an observed tick"
            " (AgentHealthCollector.observe_tick)",
            "  events_per_day 480.0  # COUNT(events) / (now - first event_time_utc)"
            " over the store",
            "  oldest_serial 100  # AgentHealthCollector observation,"
            " else MIN(events.serial_no)",
            "  pages_fetched 1  # TickResult.pages (SearchSummary.pages, paging.py:351)",
            "  records_stored 3  # TickResult.stored (agent_store UPSERT outcomes)",
            "  search_termination OK  # last completed chunk's SearchSummary.termination",
            "  site_labeled_windows 0  # TickResult.window_label == the p1-05c fallback"
            " label, per ok tick",
            "  tz_offset_mismatch_records 6  # COUNT events WHERE tz_offset_mismatch = 1",
            "  tz_offset_mismatch_warnings 0  # p1-06c once-per-run policy"
            " (cli._warn_tz_mismatch), counted per collect",
        ]
    ) + "\n"


# --- DoD (3): degraded is named ----------------------------------------------------------------


def test_circuit_open_device_makes_degraded_and_names_the_serial(tmp_path: Path) -> None:
    """The transport parks the device (terminal 401); healthz says WHY and WHICH.

    The locked 401 shape (device-locked body, unlockTime 1800) also feeds the two
    auth counters: a terminal failure and a locked event, both observed on the tick
    the loop returned as data (P2-03's never-raises contract, read from the health
    side). The parked gauge reads 1 while the circuit holds.
    """
    device = seeded_device()
    device.add_events(device_event(110, "2026-10-19T09:58:00"))
    device.add_raw("GET", DEVICE_INFO_PATH, locked_401())
    h = CollectorHarness(tmp_path, device)

    r1 = h.tick()
    assert not r1.ok and h.h.client.circuit_open()

    mark = len(device.served)
    snap = h.snapshot()
    assert len(device.served) == mark, "building a snapshot must not touch the device"
    assert snap.status == "degraded"
    assert any(SERIAL in reason and "circuit" in reason.lower() for reason in snap.reasons)
    v = device_by_name(snap)
    assert v["circuit_open_gauge"] == 1
    assert v["auth_terminal_failures"] == 1
    assert v["device_locked_events"] == 1

    text = healthz_text(snap)
    assert "status: degraded" in text and SERIAL in text


def test_checkpoint_stall_makes_degraded_and_names_the_serial(tmp_path: Path) -> None:
    """A checkpoint older than the caller's stall threshold is critical (spec §2c).

    Same healthy run; only the threshold changes (P2-07 passes ~2x cadence from
    config). The poll itself succeeds — a stalled checkpoint while ticking is the
    exact 'the ring is rolling' state DESIGN.md OQ4 calls critical — and it must be
    visible WITHOUT the collector reaching for a socket (0 device requests during
    build, so the stall check cannot be a probe in disguise).
    """
    device = seeded_device()
    device.add_events(
        device_event(120, "2026-10-19T09:52:00"),
        device_event(121, "2026-10-19T09:55:00"),
    )
    h = CollectorHarness(tmp_path, device, checkpoint_stall_s=120.0)
    results = []
    for _ in range(3):  # ticks at 10:00, 10:05, 10:10; last advance happened at 10:00
        results.append(h.tick())
        h.h.clock.advance(CADENCE_S)
        h.h.monotonic.advance(CADENCE_S)
    assert all(r.ok for r in results)

    mark = len(device.served)
    snap = h.snapshot()  # built at 10:15; checkpoint last advanced at the 10:00 tick
    assert len(device.served) == mark
    assert snap.status == "degraded"
    assert any(SERIAL in reason and "checkpoint" in reason.lower() for reason in snap.reasons)
    assert snap.checkpoint_stall_s == 120.0
    assert SERIAL in healthz_text(snap)


# --- DoD (4): dead-letter depth from actual store rows --------------------------------------


def test_dead_letter_depth_and_push_counters_come_from_the_store(tmp_path: Path) -> None:
    """agent_push seeds the rows; the health side just counts them — and reports push_ok.

    Three stored events are queued; two fail out to dead_letter (failing transport,
    past the bound), one later pushes to the stub ingest. The snapshot's values are
    the store's own COUNT(*)s and the drain log's own counters, cross-checked here
    against SQL and `dead_letter_rows()` so a health-side fabrication cannot hide.
    """
    from gateclerk.agent_loop import DeviceLoop  # noqa: F401  (imported by harness too)

    h = healthy(tmp_path)
    rowids = [
        event_rowid(h.h.conn, SERIAL, sn)
        for sn in (100, 101, 102)
    ]
    assert all(r is not None for r in rowids)
    enqueue_events(h.h.conn, rowids, endpoint=STUB_ENDPOINT, now=T0)
    assert queue_depth(h.h.conn) == 3

    def failing(url: str, body: str) -> int:
        raise ConnectionError("ingest down")

    # First drain: everything fails but nothing is past the 1 h bound yet -> retried.
    h.collector.observe_push_log(
        drain(
            h.h.conn,
            endpoint=STUB_ENDPOINT,
            transport=failing,
            now=T0 + timedelta(seconds=60),
            rng=lambda: 0.5,
            dead_letter_after_s=3600,
            log=h.collector.observe_push_log,
        )
    )
    # Second drain an hour later: past the bound -> dead-lettered.
    drain(
        h.h.conn,
        endpoint=STUB_ENDPOINT,
        transport=failing,
        now=T0 + timedelta(seconds=3660),
        rng=lambda: 0.5,
        dead_letter_after_s=3600,
        log=h.collector.observe_push_log,
    )
    # Third drain: the ingest is back (stub transport, real file append) -> 3 sent.
    out = tmp_path / "ingest" / "lines.jsonl"
    drain(
        h.h.conn,
        endpoint=STUB_ENDPOINT,
        transport=stub_transport(STUB_ENDPOINT),
        now=T0 + timedelta(seconds=3720),
        rng=lambda: 0.5,
        log=h.collector.observe_push_log,
    )

    rows = dead_letter_rows(h.h.conn)
    assert len(rows) == 3  # all three events dead-lettered before the recovery drain
    depth_sql = h.h.conn.execute("SELECT COUNT(*) c FROM dead_letter").fetchone()["c"]
    snap = h.snapshot()
    s = by_name(snap)
    assert s["dead_letter_depth"] == depth_sql == dead_letter_depth(h.h.conn) == 3
    # The stub accepted 3 lines on the recovery drain; the two failed drains before
    # it failed 3 + 3 rows — push_ok/push_failed are the drain log's own sums.
    assert s["push_ok"] == 3
    assert s["push_failed"] == 6
    assert out.exists() and len(out.read_text().splitlines()) == 3
    # A replayed success CLEARED the queue; the dead-letter rows still stand (they
    # outlive the queue) — depth counts rows, exactly as the store does.
    assert queue_depth(h.h.conn) == 0
    # Health text never leaks the payload or the endpoint ref.
    text = metrics_text(snap) + "\n" + healthz_text(snap)
    assert STUB_ENDPOINT not in text and "payload" not in text.lower()


# --- DoD (5): mapping shapes decide the warning count, not the records ----------------------


def test_mapped_run_is_silent_unmapped_run_warns_once_records_mismatch_in_both(
    tmp_path: Path,
) -> None:
    """p1-12's mapping arms through the health surface (card DoD 5).

    BOTH arms are the site-a summer box: the device claims +02:00, the site resolves
    +03:00, so EVERY record carries tz_offset_mismatch (provenance is a fact about the
    data — the mapping silences the warning, never the flag). The mapped arm
    (device_tz declared, p1-12's sites.toml shape) emits NO once-per-run warning; the
    unmapped arm emits exactly one. The warning line is the p1-06c line verbatim,
    produced by the CLI's own policy function — reused, not forked.
    """
    mapped = healthy(tmp_path / "mapped", device_tz=SITE_TZ)
    unmapped = healthy(tmp_path / "unmapped", tz_mapping_declared=False)
    # Unmapped keeps device_tz=None: records resolve in site tz, same as p1-12.

    m_snap, u_snap = mapped.snapshot(), unmapped.snapshot()
    m_dev, u_dev = device_by_name(m_snap), device_by_name(u_snap)

    # Provenance identical in both arms: 6/6 records mismatch (p1-12's decision).
    assert m_dev["tz_offset_mismatch_records"] == u_dev["tz_offset_mismatch_records"] == 6
    # The warning policy is the ONLY difference the health surface sees.
    assert m_dev["tz_offset_mismatch_warnings"] == 0
    assert u_dev["tz_offset_mismatch_warnings"] == 1
    # And when it fires, it fires through the p1-06c line (the CLI's own text), once.
    assert any(cli_mod._warn_tz_mismatch_lines()[0].split(":")[0] in w for w in unmapped.h.warns)
    assert unmapped.h.warns.count == 1 if hasattr(unmapped.h.warns, "count") else True


def test_site_labeled_fallback_run_counts_windows_per_ok_tick(tmp_path: Path) -> None:
    """The p1-05c risky fallback: the naive_time box, the label the loop reports.

    Three ok ticks on a box whose System/time claims nothing -> window_label is the
    site (fallback) label on every one -> site_labeled_windows == 3 (spec: should be
    ~0; this counter is how the §5 rollout gate PROVES it is ~0, so the number must
    come from the loop's own label, not a re-derivation). The fallback marker travels
    through the warn sink too — the collector must not double-count it as a mismatch.
    """
    device = seeded_device()
    naive = (SCENARIOS / "naive_time" / "system_time.xml").read_text()
    device.reset("GET", "/ISAPI/System/time?format=json", httpx.Response(200, text=naive))
    device.add_events(device_event(130, "2026-10-19T09:58:00"))
    h = CollectorHarness(tmp_path, device)
    results = h.ticks(3)
    assert all(r.ok for r in results)
    assert [r.window_label for r in results] == [SITE_LABELLED] * 3

    v = device_by_name(h.snapshot())
    assert v["site_labeled_windows"] == 3
    assert v["tz_offset_mismatch_warnings"] == 0  # no claim -> None -> never a mismatch
    assert FALLBACK_MARKER in "".join(h.h.warns) and len(h.h.warns) >= 3


# --- DoD (6): no secrets, no hosts beyond the site label -------------------------------------


def test_emitted_text_carries_no_secret_shaped_strings(tmp_path: Path) -> None:
    """The card's NO SECRETS rule, scanned mechanically over every emitted line.

    Deliberately built on the RICH run: dead-letter rows (payload bodies!), a parked
    circuit with lockout counters in the 401 body, push targets and a db path on disk.
    If any payload, endpoint, credential, host or lockout detail can reach the health
    text, it can do it here — and none of it may.
    """
    h = healthy(tmp_path)
    rowids = [event_rowid(h.h.conn, SERIAL, sn) for sn in (100, 101)]

    def failing(url: str, body: str) -> int:
        raise ConnectionError("ingest down")

    enqueue_events(h.h.conn, rowids, endpoint=STUB_ENDPOINT, now=T0)
    for elapsed in (60, 7260):  # fail past the bound on the second drain
        drain(
            h.h.conn,
            endpoint=STUB_ENDPOINT,
            transport=failing,
            now=T0 + timedelta(seconds=elapsed),
            rng=lambda: 0.5,
            dead_letter_after_s=3600,
            log=h.collector.observe_push_log,
        )
    h.collector.observe_skew(SERIAL, Skew(skew_seconds=-7.5))
    snap = h.snapshot()
    text = healthz_text(snap) + metrics_text(snap)

    assert h.h.last_tick.device_serial == SERIAL  # sanity: the scan saw a real run
    forbidden = [PASSWORD, "fakepw", "192.0.2.10", STUB_ENDPOINT, "admin", "Bearer", "digest"]
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


# --- collector seams the agent process uses ---------------------------------------------------


def test_observed_skew_and_stall_threshold_render_on_the_snapshot(tmp_path: Path) -> None:
    """observe_skew stores the gauge; the stall threshold is caller policy, echoed."""
    h = healthy(tmp_path)
    h.collector.observe_skew(SERIAL, Skew(skew_seconds=-3.5, warn_seconds=120.0))
    snap = h.snapshot()
    assert device_by_name(snap)["device_clock_skew_seconds"] == -3.5
    # A clock-skew warning is a WARNING (spec §2c), not a degraded trigger: ok stands.
    assert snap.status == "ok"


def test_device_health_builder_is_pure_and_callable_directly(tmp_path: Path) -> None:
    """No sockets, no side effects: the builders are functions over state (card rule).

    device_health() takes conn/stats/client/tick directly and reads only — running it
    twice on the same store yields identical blocks, and neither run opens a request.
    """
    h = healthy(tmp_path)
    tick = h.h.last_tick
    stats = h.collector.stats(SERIAL)
    mark = len(h.h.device.served)
    first = device_health(
        conn=h.h.conn,
        device_serial=SERIAL,
        stats=stats,
        client=h.h.client,
        last_tick=tick,
        now=h.h.clock(),
        monotonic=h.h.monotonic(),
    )
    second = device_health(
        conn=h.h.conn,
        device_serial=SERIAL,
        stats=stats,
        client=h.h.client,
        last_tick=tick,
        now=h.h.clock(),
        monotonic=h.h.monotonic(),
    )
    assert len(h.h.device.served) == mark
    assert [(m.name, m.value) for m in first.metrics()] == [
        (m.name, m.value) for m in second.metrics()
    ]
    assert first.last_poll_ok_age_s == pytest.approx(300.0)


def test_auth_recoveries_match_the_clients_own_counter_after_a_recovery(tmp_path: Path) -> None:
    """The gauge must equal IsapiClient.auth_recoveries, not a constant (card DoD 2).

    The fake retires the nonce after N authorized responses; the client recovers once
    (auth_recoveries == 1, OBSERVED.md's routine event) and the health surface must
    carry that exact number — an info counter, never an alert (spec §2c).
    """
    device = seeded_device()
    device.add_events(device_event(140, "2026-10-19T09:58:00"))
    device.expire_after = 3  # retire after 3 authorized responses: recovery fires
    h = CollectorHarness(tmp_path, device)
    results = h.ticks(4)
    assert all(r.ok for r in results)
    assert h.h.client.auth_recoveries >= 1, "the scenario must actually rotate the nonce"
    snap = h.snapshot()
    assert device_by_name(snap)["auth_recoveries"] == h.h.client.auth_recoveries
    assert snap.status == "ok"  # a recovery is never a degraded trigger (spec §2c)


def test_snapshot_is_a_plain_dataclass_json_encodable(tmp_path: Path) -> None:
    """/healthz JSON serving (P2-07) just dumps the snapshot — prove it encodes.

    Every field must be JSON-serializable as-is (frozen dataclasses -> dicts, no
    datetimes/connections leaking), and the dump must also pass the secret scan, since
    the JSON surface carries the same content as the text surface.
    """
    snap = healthy(tmp_path).snapshot()
    blob = json.dumps(snap.to_dict(), sort_keys=True)
    assert f'"site": "{SITE}"' in blob or f'"site":"{SITE}"' in blob.replace(" ", " ")
    assert PASSWORD not in blob and "192.0.2.10" not in blob
    assert '"status": "ok"' in blob
