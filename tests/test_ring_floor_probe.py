"""Card t_ed9c7e92: the real device ring-floor signal for `checkpoint_stall`.

The signal is spent ONCE at the first ok tick after a real gap in successful polls
(process start or a failed-poll streak), when the gap is long enough for the ~10k
ring to have evicted events after the checkpoint. The probe is ONE read-only AcsEvent
page in the *unread* window `[pre-advance checkpoint time, now]`, oldest-first,
`maxResults=1`, all majors. Its answer is compared with the PRE-advance checkpoint:
a floor above `checkpoint + 1` means events after that checkpoint were evicted
unread, so punches may be lost. A door polled normally is never probed; a quiet
week of successful polls costs zero extra device requests.

No real device is touched: every case runs `FakeDevice` behind the real `IsapiClient`,
through `AgentHarness`'s frozen clock and tmp state root (store + health snapshot).
"""

from __future__ import annotations

import json
import os
from datetime import timedelta
from pathlib import Path
from typing import Any

import httpx
import pytest

from fakedevice import FakeDevice
from test_p2_03_scheduler import (
    EVENT_PATH,
    SYSTEM_TIME_PATH,
    T0,
    device_event,
    seeded_device,
    system_time_body_at,
)
from test_p2_07b_agent_cli import AgentHarness, punch_events, wall_digits


def _probe_conditions(device: FakeDevice) -> list[dict[str, Any]]:
    """Every AcsEvent POST body that was the one-page ring-floor probe.

    GC-P15 added a SECOND one-page probe (the quiet-tick reset read), so `maxResults
    == 1` alone no longer names this one. The discriminator is the direction: the ring
    floor is the OLDEST retained event (no `timeReverseOrder` key, pinned at line ~140
    below), the reset probe is the newest (key present and true).
    """
    out: list[dict[str, Any]] = []
    for served in device.served:
        if served.path != EVENT_PATH or not served.body:
            continue
        try:
            body = json.loads(served.body)
        except ValueError:  # pragma: no cover - every body this suite sends is JSON
            continue
        cond = body.get("AcsEventCond") if isinstance(body, dict) else None
        if (
            isinstance(cond, dict)
            and cond.get("maxResults") == 1
            and "timeReverseOrder" not in cond
        ):
            out.append(cond)
    return out


def _backdate_health(h: AgentHarness, at: Any) -> None:
    """The snapshot's mtime is its write instant; tests pin it to the fake clock."""
    path = h.state_root / "health" / "agent.json"
    assert path.exists(), "the first tick must have written the health snapshot"
    stamp = at.timestamp()
    os.utime(path, (stamp, stamp))


def _alerts_during(h: AgentHarness, alerts: list[Any]) -> Any:
    agent = h.api_agent(sink=alerts.append)
    try:
        return agent, agent.tick()
    except BaseException:
        agent.close()
        raise


def _advance_clock(h: AgentHarness, device: FakeDevice, delta: timedelta) -> None:
    """Move the frozen clock AND the fake's RTC with it — one clock, like a real terminal.

    `h.now` is the agent's clock; the fake answers `System/time` from a body stamped when the
    device was seeded. A real RTC keeps counting, so jumping the agent's clock by hours or days
    and leaving the device's behind would hand GC-P04's newly-wired clock channel an
    artifact-skew to page `clock_skew` on — noise inside the exact-alert assertions these cases
    pin, and physically false: nothing in these scenarios switched the terminal off for a week.
    Both clocks therefore move together, in the one place. (`reset`, not `xml_ok`/`add`: the
    route must be REPLACED, or the stale stamp keeps answering — GC-P03's pitfall.)
    """
    h.now += delta
    h.monotonic.advance(delta.total_seconds())
    device.reset(
        "GET",
        SYSTEM_TIME_PATH,
        httpx.Response(
            200, text=system_time_body_at(h.now), headers={"Content-Type": "application/xml"}
        ),
    )


def test_outage_past_the_ring_pages_before_the_checkpoint_advance_hides_it(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    device = seeded_device()
    device.add_events(*punch_events(T0, -300))  # serial 200; checkpoint reaches 200
    h = AgentHarness(tmp_path, device, monkeypatch, push_target=None, now=T0)

    first_alerts: list[Any] = []
    first_agent, first = _alerts_during(h, first_alerts)
    try:
        assert first.ticks_ok == 1, first
        assert h.conn().execute("SELECT MAX(serial_no) m FROM events").fetchone()["m"] == 200
        _backdate_health(h, T0)
    finally:
        first_agent.close()

    # Eight days down: the ring has recycled. Only events from the new stream survive
    # on the device (the old rows are gone, not merely unread).
    _advance_clock(h, device, timedelta(days=8))
    device._event_store = []
    device.add_events(
        device_event(9000, wall_digits(h.now - timedelta(minutes=2))),
        device_event(9001, wall_digits(h.now - timedelta(minutes=1))),
    )

    alerts: list[Any] = []
    agent, report = _alerts_during(h, alerts)
    try:
        assert report.ticks_ok == 1, report
        # The walk HAS advanced the checkpoint to the new stream before the alert
        # decision; the page must still name the pre-advance evidence.
        checkpoint = h.conn().execute("SELECT checkpoint_serial FROM checkpoint").fetchone()
        assert checkpoint["checkpoint_serial"] == 9001
        assert [a.kind for a in alerts] == ["checkpoint_stall"], alerts
        note = alerts[0].note
        assert "possible loss" in note
        assert "device ring floor" in note
        assert "serials 201..8999" in note
        assert "8.0 days" in note
        assert "all majors" in note
        assert "cannot prove" in note
        assert report.alerts == ("critical:checkpoint_stall",)

        probes = _probe_conditions(device)
        assert len(probes) == 1
        assert probes[0]["major"] == 0, "the floor is all-events, not punch-only"
        assert "timeReverseOrder" not in probes[0], "oldest-first is the default"

        # The next ok tick is not the first after the gap: no second probe, no page.
        _advance_clock(h, device, timedelta(seconds=300))
        later = agent.tick()
        assert later.ticks_ok == 1 and later.alerts == ()
        assert len(_probe_conditions(device)) == 1
        assert len(alerts) == 1
    finally:
        agent.close()


def test_short_restart_does_not_probe(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    device = seeded_device()
    device.add_events(*punch_events(T0, -300))
    h = AgentHarness(tmp_path, device, monkeypatch, push_target=None, now=T0)

    first_alerts: list[Any] = []
    first_agent, first = _alerts_during(h, first_alerts)
    try:
        assert first.ticks_ok == 1, first
        _backdate_health(h, T0)
    finally:
        first_agent.close()

    _advance_clock(h, device, timedelta(hours=1))
    alerts: list[Any] = []
    agent, report = _alerts_during(h, alerts)
    try:
        assert report.ticks_ok == 1, report
        assert _probe_conditions(device) == [], "under a day cannot have evicted a week"
        assert alerts == []
    finally:
        agent.close()


def test_quiet_week_of_successful_polls_sends_no_extra_request_and_no_page(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    device = seeded_device()
    device.add_events(*punch_events(T0, -300))
    h = AgentHarness(tmp_path, device, monkeypatch, push_target=None, now=T0)
    alerts: list[Any] = []
    agent = h.api_agent(sink=alerts.append)
    try:
        assert agent.tick().ticks_ok == 1
        for _ in range(14):  # 7 days, a poll every 12 hours, every one successful
            _advance_clock(h, device, timedelta(hours=12))
            report = agent.tick()
            assert report.ticks_ok == 1, report
        assert _probe_conditions(device) == [], "successful polls never spend the probe"
        assert alerts == []
    finally:
        agent.close()


def test_a_punch_arriving_between_walk_and_probe_cannot_page(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    device = seeded_device()
    device.add_events(*punch_events(T0, -300))  # checkpoint serial 200
    h = AgentHarness(tmp_path, device, monkeypatch, push_target=None, now=T0)

    first_alerts: list[Any] = []
    first_agent, first = _alerts_during(h, first_alerts)
    try:
        assert first.ticks_ok == 1, first
        _backdate_health(h, T0)
    finally:
        first_agent.close()

    # The gap is old enough to be worth a probe, but the device has NOT evicted
    # anything: the next device-wide serial after the checkpoint is 201.
    _advance_clock(h, device, timedelta(hours=25))
    device._event_store = []

    alerts: list[Any] = []
    agent = h.api_agent(sink=alerts.append)
    try:
        loop = agent.loops[0]
        original = loop.probe_ring_floor

        def racing_probe(since_stamp: str) -> int | None:
            # Exactly reviewer point 1's race: a punch lands after the walk read and
            # before the probe asks. It is checkpoint+1, so it is NOT evidence that
            # anything below it was evicted.
            device.add_events(device_event(201, wall_digits(h.now)))
            return original(since_stamp)

        loop.probe_ring_floor = racing_probe  # type: ignore[method-assign]
        report = agent.tick()
        assert report.ticks_ok == 1, report
        assert len(_probe_conditions(device)) == 1, "the probe did run (not vacuously green)"
        assert alerts == [], alerts
    finally:
        agent.close()
