"""Card GC-P04: the skew GC-P03 reads reaches the alert policy AND the health gauge.

BINDING SPEC: docs/internal/P2-SITE-AGENT.md §2c (clock skew = warning channel) and §2e
(`device_clock_skew_seconds`). `AlertPolicy.observe_skew` and
`AgentHealthCollector.observe_skew` shipped in P2-05/P2-06 unit-tested and with NO caller:
GC-P03 made the running `DeviceLoop` re-read `GET /ISAPI/System/time` on a bounded cadence,
but the reading stopped inside the loop. A terminal whose RTC is hours off therefore never
raised a `clock_skew` alert and `/metrics` never emitted the gauge — while R1 (payroll scans)
depends on exactly that clock.

The four pins below are the card's four DoD cases, and all four drive a real `SiteAgent`
pass (the wiring point) rather than calling the two observers by hand: hand-called observers
were already green and the feature still did not work.

(1) device clock one hour ahead -> exactly one `warning:clock_skew` in the pass report;
(2) 30 s of skew -> silence on the alert surface (the threshold is the rule);
(3) the same tick stores the gauge: `health/agent.json` and the /metrics rendering both
    carry `device_clock_skew_seconds` for the device serial;
(4) System/time answered and the event walk then failed -> the tick is `ok=False` and the
    skew it actually read is still observed (a skewed RTC and a broken search are separate
    facts; §2c's warning channel is independent of the failed-poll arm).

The skew is injected through the fake's `System/time` body ONLY: the digits move, the
claimed offset stays `+02:00`, so the window arithmetic (and every event-window assertion
this harness shape inherits) is untouched — GC-P03's `system_time_body` idiom.

Offline by construction: FakeDevice behind the real IsapiClient, tmp sqlite, the harness's
frozen clock (`T0`), injected sleep/warn/sink. No socket; no real host or serial.
"""

from __future__ import annotations

from datetime import timedelta
from pathlib import Path
from typing import Any

import httpx
import pytest

from fakedevice import invalid_content
from gateclerk.agent_alert import KIND_CLOCK_SKEW
from gateclerk.agent_health import metrics_text, snapshot_from_dict
from test_p2_03_scheduler import (
    EVENT_PATH,
    SYSTEM_TIME_PATH,
    T0,
    device_event,
    seed_events,
    seeded_device,
    system_time_body_at,
)
from test_p2_07b_agent_cli import SERIAL, AgentHarness

#: The metric name §2e gives the reading, spelled once so a rename is one red line here.
GAUGE = "device_clock_skew_seconds"


def system_time_ahead(seconds: float) -> str:
    """The fake's `System/time` body with its wall clock `seconds` off the run clock.

    `AgentHarness` freezes the agent's clock at `T0`, so "the device is one hour ahead" is
    literally "its `localTime` digits are `T0 + 3600`". The digits move through the scheduler
    harness's own seam (`system_time_body_at`), which keeps the recorded `+02:00` stamp — so
    the claimed offset, and with it every window label and every event-window bound, stays
    exactly what GC-P03 pins. This test measures the clock channel and nothing else.
    """
    return system_time_body_at(T0 + timedelta(seconds=seconds))


def device_metric(snapshot: dict[str, Any], name: str, serial: str = SERIAL) -> Any:
    """One device's metric value, read out of the written `health/agent.json` payload."""
    devices = [d for d in snapshot["devices"] if d["device_serial"] == serial]
    assert devices, f"no block for {serial}: {[d['device_serial'] for d in snapshot['devices']]}"
    metrics = devices[0]["metrics"]
    lines = [m for m in metrics if m["name"] == name]
    assert lines, f"{name} absent from the device block: {[m['name'] for m in metrics]}"
    return lines[0]["value"]


def skew_run(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, *, skew_seconds: float
) -> tuple[AgentHarness, Any, Any]:
    """One `--once` pass over a device whose RTC sits `skew_seconds` off the agent's clock.

    Returns (harness, agent, first pass report). The device is otherwise the scheduler's own
    seeded box (recorded deviceInfo/caps/System/time) with one punch inside the cold-start
    window, so an ok tick here means a real walk happened — not a degenerate empty pass. The
    device is built BEFORE the harness on purpose: the harness threads its transport into the
    client factory at construction, so handing it a different device afterwards would silently
    drive the wrong fake.
    """
    device = seeded_device()
    device.reset("GET", SYSTEM_TIME_PATH, httpx.Response(200, text=system_time_ahead(skew_seconds)))
    seed_events(device, [device_event(300, "2026-10-19T09:58:00")])
    h = AgentHarness(tmp_path, device, monkeypatch)
    agent = h.api_agent()
    try:
        run = agent.run(once=True)
    finally:
        agent.close()
    return h, agent, run.tick_reports[0]


# --- DoD (1): over threshold -> exactly one clock_skew warning in the pass -----------------


def test_run_once_emits_clock_skew_alert_over_threshold(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A terminal an hour off must page on the WARNING channel, once, without a restart.

    1 h is far past `SKEW_WARN_SECONDS = 120` and is the OBSERVED.md shape (a box whose RTC
    drifted). The report string is `f"{level}:{kind}"` — the pass's own vocabulary — and the
    policy counter is the live policy's, so "fired once" is counted at the owner rather than
    guessed from the rendered line.
    """
    _h, agent, report = skew_run(tmp_path, monkeypatch, skew_seconds=3600.0)

    assert report.ticks_ok == 1, f"the walk must still succeed: {report.alerts}"
    assert report.records_stored == 1, "a real walk ran (the skew path is not a degenerate pass)"
    assert report.alerts.count(f"warning:{KIND_CLOCK_SKEW}") == 1, report.alerts
    assert agent.policy.counters[KIND_CLOCK_SKEW] == 1, "one alert per episode, at the policy"
    # The injected skew must not have moved the CLAIM: the window label is still the recorded
    # +02:00, so this test measures the clock channel only (GC-P03 owns the claim).
    assert agent._last_tick[SERIAL].window_label == "device-claimed +02:00"
    skew = agent._last_tick[SERIAL].clock_skew
    assert skew is not None and skew.skew_seconds == 3600.0


# --- DoD (2): under threshold -> the alert surface stays silent -----------------------------


def test_run_once_under_threshold_is_silent(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """30 s of drift is a fact, not a warning: the threshold is the rule being wired.

    Without the `skew.warn` gate in the policy this line would fire on every deploy (the
    firmware's normal drift is a few seconds) — which is precisely the noise the card's
    "one alert per episode" rule exists to stop.
    """
    h, agent, report = skew_run(tmp_path, monkeypatch, skew_seconds=30.0)

    assert report.ticks_ok == 1, f"the walk must still succeed: {report.alerts}"
    assert KIND_CLOCK_SKEW not in " ".join(report.alerts), report.alerts
    assert agent.policy.counters.get(KIND_CLOCK_SKEW, 0) == 0
    # The gauge is NOT threshold-gated (a 30 s reading is still the truth about the clock),
    # so test (3) below stays about wiring rather than about the warning rule.
    assert device_metric(h.health_snapshot(), GAUGE) == 30.0


# --- DoD (3): the gauge reaches health/agent.json AND the /metrics rendering ----------------


def test_health_snapshot_carries_device_clock_skew_seconds(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The §2e observable must be emitted for the device serial, by the running agent.

    Both surfaces are asserted on the file the unit actually writes (`health/agent.json`)
    and on `metrics_text` over that same payload — the sidecar's two readers — and the value
    is the reading the device gave, not a re-derived one. The health status stays `ok`: §2c
    keeps skew out of the degraded rule (that rule is circuit-open / stall only).
    """
    h, _agent, report = skew_run(tmp_path, monkeypatch, skew_seconds=3600.0)

    assert f"warning:{KIND_CLOCK_SKEW}" in report.alerts, "alert and gauge share one reading"
    snapshot = h.health_snapshot()
    assert device_metric(snapshot, GAUGE) == 3600.0
    assert snapshot["status"] == "ok", "a skewed clock never degrades the health surface"

    body = metrics_text(snapshot_from_dict(snapshot))
    assert f"# device: {SERIAL}" in body, "the gauge must sit in the serial's own block"
    block = body.split(f"# device: {SERIAL}", 1)[1]
    gauge_line = next((s for s in block.splitlines() if s.startswith(f"{GAUGE} ")), None)
    assert gauge_line is not None, f"{GAUGE} absent from the /metrics body"
    assert gauge_line.split()[1] == "3600.0", gauge_line


# --- DoD (4): a failed walk still reports the skew it read ----------------------------------


def test_a_failed_walk_still_reports_the_skew_it_read(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The two facts are independent: the box answered `System/time`, then the search broke.

    `Invalid Content` (statusCode 6) is the terminal device-fault class the scheduler's own
    failed-tick test uses, and it is NOT an auth fault — so no circuit opens, the pass is a
    FAILED walk rather than a parked skip, and the credential ledger stays clean. The skew
    read before the walk must still reach both surfaces: an operator with a broken search
    still has to learn the RTC is an hour off (R1 scans off that clock either way).
    """
    device = seeded_device()
    device.reset("GET", SYSTEM_TIME_PATH, httpx.Response(200, text=system_time_ahead(3600.0)))
    device.reset_raw("POST", EVENT_PATH, invalid_content())
    h = AgentHarness(tmp_path, device, monkeypatch)
    agent = h.api_agent()
    try:
        report = agent.run(once=True).tick_reports[0]
    finally:
        agent.close()

    assert report.ticks_failed == 1 and report.ticks_ok == 0
    result = agent._last_tick[SERIAL]
    assert result.ok is False and result.skipped is False, "the failed-walk shape, not a skip"
    assert result.clock_skew is not None, "the tick must hand over the reading it did get"
    assert result.clock_skew.skew_seconds == 3600.0
    assert f"warning:{KIND_CLOCK_SKEW}" in report.alerts, report.alerts
    assert agent.policy.counters[KIND_CLOCK_SKEW] == 1
    assert device_metric(h.health_snapshot(), GAUGE) == 3600.0
    assert result.circuit_open is False, "a 400 device fault is not a credential incident"
