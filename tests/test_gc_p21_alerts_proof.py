"""GC-P21 — the three alert paths proven against the repo's demo device (G3 evidence).

G3 asks for the alert path to be *observed*, not merely unit-tested. These three tests
drive the real ``gateclerk.demo_device.DemoDevice`` (an HTTP server on loopback with
synthetic ``Demo*`` fixtures only) through the real ``IsapiClient``, the real
``DeviceLoop`` and the real ``AlertPolicy``, and pin three behaviours end to end:

* a ``503`` from the ingest keeps the ``push_queue`` row, counts one push failure and
  reports the class as ``HttpStatus503`` (the GC-P08 transient arm — a 503 retries);
* a demo device that stops answering produces exactly one ``checkpoint_stall`` alert
  after ``STALL_STRIKES`` consecutive failed polls on a stale checkpoint;
* a demo clock one hour off the agent's produces exactly one ``clock_skew`` warning.

Nothing here changes product code: this is the observation half of GC-P04 (the skew
channel) and GC-P08 (the queue's failure accounting). The alert thresholds the card
pins — ``SKEW_WARN_SECONDS == 120`` and ``STALL_STRIKES == 3`` — are asserted, never
tuned, so a later card that moves one fails this proof instead of quietly passing it.

Harness reuse, not re-invention: the queue fixtures (``Flaky``, ``Rng``, ``make_record``,
``queue_rows``) come from ``tests/test_p2_04_pusher.py`` and the live-server fixtures
(``demo_device``, ``demo_client``) from ``tests/test_demo_device.py``, because a copied
harness drifts from the truth it is supposed to model. The demo loop's clock is injected
through the same ``now`` seam ``gateclerk.demo_walkthrough`` drives, so no test here waits
on wall time and no test here opens a socket outside loopback (``socket_allow`` is pulled
in by ``demo_device``; the push test never needs one).
"""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any
from zoneinfo import ZoneInfo

import pytest

import gateclerk.agent_alert as agent_alert
import gateclerk.agent_db as agent_db
import gateclerk.agent_loop as agent_loop
import gateclerk.agent_push as agent_push
import gateclerk.agent_store as agent_store
import gateclerk.demo_device as demo
from gateclerk.demo_walkthrough import DEMO_DAY_START, DEMO_SITE_NAME, DEMO_TICK_S
from gateclerk.exceptions import IsapiAuthError
from gateclerk.isapi_transport import IsapiClient
from gateclerk.pipeline import device_time_reading
from gateclerk.tz import DEFAULT_SITE_TZ, SKEW_WARN_SECONDS
from test_demo_device import (  # fixtures: pytest resolves a fixture's OWN dependencies
    # from the requesting module's namespace too, so `socket_allow` — which
    # `demo_device` asks for — has to be imported alongside it.
    DEMO_PASSWORD,
    DEMO_USER,
    demo_client,
    demo_device,
    socket_allow,
)
from test_p2_04_pusher import ENDPOINT, T0, Flaky, Rng, dead_rows, make_record, queue_rows

# Re-exported so pytest can see them; the tests below take them as arguments.
_ = (demo_client, demo_device, socket_allow)

#: The site the demo box belongs to: tz + cadence exactly as `demo_sites_toml` writes them,
#: so the loop under test is configured the way the demo product configures it.
SITE_TZ = DEFAULT_SITE_TZ
CADENCE_S = DEMO_TICK_S

#: The demo corpus's newest serialNo — what a first tick that walked the whole fixture day
#: must leave in the checkpoint (the same number `gateclerk demo demo` reports).
DEMO_LAST_SERIAL = demo.DEMO_FIRST_SERIAL + demo.DEMO_EVENT_COUNT - 1


def _no_sleep(_seconds: float) -> None:
    """The demo walkthrough's sleep: cadence sleeps are a no-op, so ticks cost ms."""


@dataclass
class Clock:
    """One injected clock for BOTH seams the loop reads: wall (`now`) and monotonic.

    `test_p2_03_scheduler` keeps these separate for a reason the skill names: advancing one
    and not the other silently skips a branch. Here they move together, because the two
    things under test — checkpoint age and the failed-poll streak — are both wall-shaped,
    and the monotonic seam only drives the System/time refresh cadence.
    """

    wall: datetime
    mono: float = 0.0
    advances: list[float] = field(default_factory=list)

    def now(self) -> datetime:
        return self.wall

    def monotonic(self) -> float:
        return self.mono

    def advance(self, seconds: float) -> None:
        self.advances.append(seconds)
        self.wall += timedelta(seconds=seconds)
        self.mono += seconds


def _client_at(box: demo.DemoDevice) -> IsapiClient:
    """The unmodified production client at the box's URL — the fixture's own construction."""
    return IsapiClient(
        box.base_url,
        DEMO_USER,
        DEMO_PASSWORD,
        connect_timeout=5.0,
        read_timeout=10.0,
    )


def _demo_loop(
    *,
    client: Any,
    conn: sqlite3.Connection,
    clock: Clock,
    warn: Any = _no_sleep,
) -> agent_loop.DeviceLoop:
    """A `DeviceLoop` aimed at the live demo box, with every clock seam injected."""
    return agent_loop.DeviceLoop(
        client=client,
        conn=conn,
        site=DEMO_SITE_NAME,
        site_tz=SITE_TZ,
        cadence_s=CADENCE_S,
        overlap_s=CADENCE_S,
        inter_page_delay=0.0,
        now=clock.now,
        monotonic=clock.monotonic,
        sleep=_no_sleep,
        warn=warn,
    )


# --- proof 1: the push queue's failure accounting (GC-P08's transient arm) -------------------


def test_push_failure_keeps_the_row_and_reports_it(tmp_path) -> None:
    """A 503 is an outage, not a rejection: the row stays queued, attempts=1, class pinned.

    This is the arm GC-P08 deliberately did NOT change — 400/422 dead-letter at once, a 5xx
    keeps the jitter ladder and the 24 h bound. A 503 that silently DELETEd the row (or
    dead-lettered it, or lost its error class) fails here on the row, not on a log line.
    """
    conn = agent_db.connect(tmp_path / "agent.sqlite3")
    try:
        record = make_record()  # one granted punch (major=5 / minor=75, outcome=granted)
        stored = agent_store.store_events(conn, [record], now=T0)
        assert len(stored.rowids) == 1
        (event_id,) = stored.rowids.values()
        queued = agent_push.enqueue_events(conn, [event_id], endpoint=ENDPOINT, now=T0)
        assert len(queued) == 1

        transport = Flaky(503)
        result = agent_push.drain(
            conn, endpoint=ENDPOINT, transport=transport, now=T0, rng=Rng(1.0)
        )

        # Reported: one failed push, nothing sent, nothing dead-lettered.
        assert result.push_failed == 1
        assert result.push_ok == 0
        assert result.sent == ()
        assert result.dead_lettered == ()
        assert len(transport.calls) == 1, "one row is one POST, even on a failure"

        # Still there: the queue is a send buffer, and a 503 must not consume the row.
        rows = queue_rows(conn)
        assert [r["id"] for r in rows] == [queued[0]]
        row = rows[0]
        assert row["event_id"] == event_id
        assert row["attempts"] == 1
        assert row["last_error_class"] == "HttpStatus503"
        assert row["first_failed_at"] is not None
        assert dead_rows(conn) == [], "a 503 is not a permanent rejection"
        # Backed off, not hammered: the row is due LATER, which is §1 seam 9.
        assert row["next_attempt_at"] > row["last_attempt_at"]

        print(
            f"GC-P21 push proof: 503 -> push_failed={result.push_failed} "
            f"push_ok={result.push_ok} dead_lettered={len(result.dead_lettered)} "
            f"queue_rows={len(rows)} attempts={row['attempts']} "
            f"error_class={row['last_error_class']}"
        )
    finally:
        conn.close()


# --- proof 2: the device goes away -> exactly one checkpoint_stall ---------------------------


def test_offline_device_raises_checkpoint_stall(tmp_path, demo_device, demo_client) -> None:
    """A demo box that stops answering pages once: k failed polls on a stale checkpoint.

    The device really goes away (`demo_device.stop()` closes the listener) and the alert is
    earned the way the agent earns it — every failed `TickResult` is handed to
    `AlertPolicy.handle_tick`, which owns the streak. The checkpoint unmoved is what makes
    the stall true rather than the box merely quiet (STALL-ALERT-FALSE: a quiet door that
    answers is silence). See the block below the stop for why the client is rebuilt too.
    """
    conn = agent_db.connect(tmp_path / "agent.sqlite3")
    alerts: list[agent_alert.Alert] = []
    clock = Clock(DEMO_DAY_START)
    policy = agent_alert.AlertPolicy(
        site=DEMO_SITE_NAME,
        cadence_s=CADENCE_S,
        now=clock.now,
        conn=conn,
        sink=alerts.append,
    )
    loop = _demo_loop(client=demo_client, conn=conn, clock=clock)
    offline: IsapiClient | None = None
    try:
        first = loop.tick()
        assert first.ok is True, f"the demo box must answer the first walk: {first.error}"
        assert first.advanced is True, "the fixture day must move the checkpoint"
        serial = first.device_serial
        assert serial == demo.DEMO_SERIAL
        assert first.checkpoint_serial == DEMO_LAST_SERIAL
        # A fresh checkpoint is silence, whatever the age arithmetic later becomes.
        assert policy.check_stall(serial, gap_s=0.0) is None

        demo_device.stop()  # the operator unplugs the box

        # `stop()` closes the LISTENING socket, but the demo process outlives it and keeps
        # serving the session that is already open — a dead box cannot do that: its kernel
        # closes every socket it owned, which drops our pooled keep-alive connection with
        # them. So the state an outage really leaves behind is no listener AND no live
        # session, and that is what this models: drop the client the box died with, hand
        # the loop a fresh one on the same dead URL, and every further request must open a
        # NEW connection and is refused (an `IsapiError`, transport exit-4 — never an auth
        # failure, which the policy keeps on its own channel).
        demo_client.close()
        offline = _client_at(demo_device)
        loop.client = offline

        # `check_stall` is stale only STRICTLY past k*cadence, so each strike moves the
        # clock one second past a cadence (the same off-by-one test_p2_05 names).
        strike_gap = CADENCE_S + 1
        fired: agent_alert.Alert | None = None
        failure_class = "none"
        for strike in range(1, agent_alert.STALL_STRIKES + 1):
            clock.advance(strike_gap)
            failed = loop.tick()
            assert failed.ok is False
            assert failed.skipped is False, "the box is gone; this is not a circuit skip"
            assert failed.device_serial == serial, "a failed tick still knows its device"
            exc = failed.exception
            assert exc is not None and not isinstance(exc, IsapiAuthError)
            failure_class = type(exc).__name__
            # A failed poll is a metric, never a page of its own (§2c separates channels).
            assert policy.handle_tick(failed) == []
            assert policy._failed_streak[serial] == strike
            held = agent_store.read_checkpoint(conn, serial)
            assert held is not None and held.checkpoint_serial == DEMO_LAST_SERIAL, (
                "a failed walk must not move the checkpoint"
            )

            fired = policy.check_stall(serial, gap_s=float(strike * strike_gap))
            if strike < agent_alert.STALL_STRIKES:
                assert fired is None, f"{strike} failure(s) is below k — silence"

        assert fired is not None
        assert fired.kind == agent_alert.KIND_CHECKPOINT_STALL
        assert fired.level == "critical"
        assert [a.kind for a in alerts] == ["checkpoint_stall"]
        assert policy.counters["checkpoint_stall"] == 1
        # One page per incident: the next check of the same episode stays silent.
        assert policy.check_stall(serial, gap_s=float(CADENCE_S * 9)) is None
        assert [a.kind for a in alerts] == ["checkpoint_stall"]

        print(
            f"GC-P21 stall proof: listener closed and session dropped, "
            f"offline_failure={failure_class}, strikes={agent_alert.STALL_STRIKES} "
            f"gap_s={strike_gap * agent_alert.STALL_STRIKES} "
            f"alerts={[a.kind + ':' + a.level for a in alerts]} "
            f"checkpoint_serial={first.checkpoint_serial} unmoved=1"
        )
    finally:
        if offline is not None:
            offline.close()
        conn.close()


# --- proof 3: a one-hour demo clock -> exactly one clock_skew --------------------------------


def test_clock_skew_on_the_demo_device_raises_clock_skew(
    tmp_path, demo_device, demo_client
) -> None:
    """The demo box's claimed wall clock, one hour off ours, pages once.

    The instant under the agent's `now` is DERIVED from the live box's own
    `System/time` answer (one real GET through the unmodified client), one hour behind
    it: the skew is therefore exactly +3600 s by construction of the test rather than a
    remembered constant, and it survives a demo fixture that re-stamps its day. The
    threshold itself is asserted at 120 s, because the card forbids tuning it.
    """
    reading, _raw = device_time_reading(demo_client)
    assert reading.naive_local is not None, "the demo box must answer System/time"
    skewed_now = (reading.naive_local - timedelta(hours=1)).replace(tzinfo=ZoneInfo(SITE_TZ))

    conn = agent_db.connect(tmp_path / "agent.sqlite3")
    alerts: list[agent_alert.Alert] = []
    clock = Clock(skewed_now)
    policy = agent_alert.AlertPolicy(
        site=DEMO_SITE_NAME,
        cadence_s=CADENCE_S,
        now=clock.now,
        conn=conn,
        sink=alerts.append,
    )
    loop = _demo_loop(client=demo_client, conn=conn, clock=clock)
    try:
        result = loop.tick()
        assert result.ok is True, f"the walk must still succeed: {result.error}"

        skew = result.clock_skew
        assert skew is not None, "GC-P04: a tick that read System/time hands the skew up"
        assert skew.available is True
        assert skew.skew_seconds == pytest.approx(3600.0)
        assert skew.warn_seconds == SKEW_WARN_SECONDS
        assert SKEW_WARN_SECONDS == 120, "the card forbids tuning the threshold"
        assert skew.warn is True

        fired = policy.observe_skew(skew)
        assert [a.kind for a in fired] == [agent_alert.KIND_CLOCK_SKEW]
        assert [a.level for a in fired] == ["warning"]
        assert [a.kind for a in alerts] == ["clock_skew"]
        assert policy.counters["clock_skew"] == 1
        # One page per episode: still skewed, still silent until it heals.
        assert policy.observe_skew(skew) == []
        assert [a.kind for a in alerts] == ["clock_skew"]

        print(
            f"GC-P21 skew proof: device_wall={reading.naive_local.isoformat()} "
            f"our_wall={skewed_now.astimezone(ZoneInfo(SITE_TZ)).replace(tzinfo=None)} "
            f"skew_seconds={skew.skew_seconds} warn={skew.warn} "
            f"threshold={skew.warn_seconds} alerts={[a.kind for a in alerts]}"
        )
    finally:
        conn.close()
