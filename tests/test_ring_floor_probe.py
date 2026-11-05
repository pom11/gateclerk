"""Card t_ed9c7e92: the real device ring-floor signal for `checkpoint_stall`.

The probe is ONE read-only AcsEvent page: window `[our earliest stored event, now]`,
`major=5` (punches only — the 1/min major=3 noise shares the ring), `maxResults=1`,
oldest-first. The device's answer is the oldest punch it still retains; a floor past
the checkpoint means punches in that serial range were evicted before we read them.

No real device is touched: every case runs `FakeDevice` behind the real `IsapiClient`,
with the p2-03/p2-05 harnesses' injected clocks and tmp sqlite store.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import httpx

from fakedevice import FakeDevice
from test_p2_03_scheduler import (
    CADENCE_S,
    EVENT_PATH,
    device_event,
    seed_events,
    seeded_device,
)
from test_p2_05_alerts import PASSWORD_OK, PolicyHarness

NOISE = 1029


def _noise(serial: int, wall: str) -> dict[str, Any]:
    return {
        "serialNo": serial,
        "major": 3,
        "minor": NOISE,
        "type": 0,
        "time": f"{wall}+02:00",
        "currentVerifyMode": "invalid",
    }


def _last_event_cond(device: FakeDevice) -> dict[str, Any]:
    for served in reversed(device.served):
        if served.path == EVENT_PATH and served.body:
            body = json.loads(served.body)
            cond = body.get("AcsEventCond")
            assert isinstance(cond, dict), body
            return cond
    raise AssertionError("no AcsEvent request was served")


def _seeded_harness(tmp_path: Path) -> tuple[PolicyHarness, Any]:
    device = seeded_device()
    seed_events(
        device,
        [
            # Same wall minute as punch 60: the fake sorts wall then serial, so this
            # noise row is FIRST in the page. The client-side major re-filter is what
            # keeps the floor a punch, not this noise row.
            _noise(50, "2026-10-19T09:58:00"),
            device_event(60, "2026-10-19T09:58:00"),
            _noise(71, "2026-10-19T09:59:00"),
            device_event(61, "2026-10-19T10:00:00"),
        ],
    )
    h = PolicyHarness(tmp_path, device, client_password=PASSWORD_OK)
    first = h.tick()
    assert first is not None and first.ok is True
    assert first.device_serial is not None
    return h, first.device_serial


# --- the probe itself -------------------------------------------------------------------


def test_probe_is_one_oldest_first_punch_page_and_ignores_noise(tmp_path: Path) -> None:
    h, _serial = _seeded_harness(tmp_path)
    device = h.device
    before = device.requests_to("POST", EVENT_PATH)

    assert h.loop.probe_ring_floor() == 60
    assert device.requests_to("POST", EVENT_PATH) == before + 1, "exactly one POST"

    cond = _last_event_cond(device)
    assert cond["major"] == 5, "punches only: the noise stream is not the floor"
    assert cond["maxResults"] == 1, "one page is the floor"
    assert cond["searchResultPosition"] == 0
    assert "timeReverseOrder" not in cond, "oldest-first is the documented default"


def test_probe_window_starts_at_the_earliest_stored_event(tmp_path: Path) -> None:
    h, _serial = _seeded_harness(tmp_path)
    assert h.loop.probe_ring_floor() == 60

    cond = _last_event_cond(h.device)
    # The anchor is the DEVICE-LOCAL stamp of the earliest stored event (09:58),
    # localized in the site zone and relabeled with the device's claim (+02:00) —
    # the p1-05c shape, not the event's wrong +02 label converted through UTC.
    assert cond["startTime"] == "2026-10-19T09:58:00+02:00"
    assert cond["endTime"] == "2026-10-19T10:00:00+02:00"


def test_probe_returns_none_and_sends_nothing_without_stored_events(tmp_path: Path) -> None:
    device = seeded_device()
    seed_events(device, [_noise(50, "2026-10-19T09:58:00")])
    h = PolicyHarness(tmp_path, device, client_password=PASSWORD_OK)
    first = h.tick()
    assert first is not None and first.ok is True
    before = device.requests_to("POST", EVENT_PATH)

    assert h.loop.probe_ring_floor() is None
    assert device.requests_to("POST", EVENT_PATH) == before, "no anchor = no request"


def test_probe_failure_is_silent_and_never_breaks_the_alert_path(tmp_path: Path) -> None:
    h, _serial = _seeded_harness(tmp_path)
    warnings: list[str] = []
    h.loop._warn = warnings.append
    h.device.reset_raw("POST", EVENT_PATH, httpx.Response(503, text="busy"))

    assert h.loop.probe_ring_floor() is None
    assert warnings and "ring-floor probe failed" in warnings[0]
    assert "busy" not in warnings[0], "never copy transport text into the warn line"


# --- the alert arm ----------------------------------------------------------------------


def test_device_floor_past_the_checkpoint_pages_possible_loss(tmp_path: Path) -> None:
    h, serial = _seeded_harness(tmp_path)
    # A fresh checkpoint is not stale: the probe must not be spent.
    calls: list[int] = []
    assert h.policy.check_stall(serial, ring_probe=lambda: calls.append(1) or 9999) is None
    assert calls == [], "no probe while the checkpoint is moving"

    h.clock.advance(4 * CADENCE_S)
    h.monotonic.advance(4 * CADENCE_S)
    fired = h.policy.check_stall(serial, ring_probe=lambda: 9999)
    assert fired is not None and fired.kind == "checkpoint_stall"
    assert fired.level == "critical"
    assert "device ring floor" in fired.note
    assert "past our checkpoint" in fired.note
    assert "possible loss" in fired.note
    assert "cannot prove" in fired.note

    # Same floor, same frozen checkpoint: one page per incident, not per check.
    h.clock.advance(3600)
    h.monotonic.advance(3600)
    assert h.policy.check_stall(serial, ring_probe=lambda: 9999) is None
    assert h.kinds().count("checkpoint_stall") == 1


def test_device_floor_at_or_below_the_checkpoint_is_silence(tmp_path: Path) -> None:
    h, serial = _seeded_harness(tmp_path)
    h.clock.advance(4 * CADENCE_S)
    h.monotonic.advance(4 * CADENCE_S)

    # The fake ignores the server-side major filter (its documented lenience), so
    # the checkpoint is the highest serial it returned, noise included: 71.
    assert h.policy.check_stall(serial, ring_probe=lambda: 60) is None
    h.clock.advance(3600)
    h.monotonic.advance(3600)
    assert h.policy.check_stall(serial, ring_probe=lambda: 71) is None, "at the checkpoint"
    h.clock.advance(3600)
    h.monotonic.advance(3600)
    fired = h.policy.check_stall(serial, ring_probe=lambda: 72)
    assert fired is not None and "72" in fired.note


def test_probe_is_throttled_to_the_hourly_cadence(tmp_path: Path) -> None:
    h, serial = _seeded_harness(tmp_path)
    h.clock.advance(4 * CADENCE_S)
    h.monotonic.advance(4 * CADENCE_S)
    calls: list[int] = []

    def probe() -> int:
        calls.append(1)
        return 60

    assert h.policy.check_stall(serial, ring_probe=probe) is None
    assert len(calls) == 1
    h.clock.advance(CADENCE_S)
    h.monotonic.advance(CADENCE_S)
    assert h.policy.check_stall(serial, ring_probe=probe) is None
    assert len(calls) == 1, "one probe per hour, not per stale tick"

    h.clock.advance(3600)
    h.monotonic.advance(3600)
    assert h.policy.check_stall(serial, ring_probe=probe) is None
    assert len(calls) == 2


def test_probe_exception_is_swallowed_and_no_alert_is_invented(tmp_path: Path) -> None:
    h, serial = _seeded_harness(tmp_path)
    h.clock.advance(4 * CADENCE_S)
    h.monotonic.advance(4 * CADENCE_S)

    def boom() -> int:
        raise RuntimeError("device said no")

    assert h.policy.check_stall(serial, ring_probe=boom) is None
    assert h.alerts == []
    assert h.policy.counters["checkpoint_stall"] == 0


def test_no_probe_means_the_old_two_arms_are_unchanged(tmp_path: Path) -> None:
    """The default call (no ring_probe) is still the p2-05 behaviour: a quiet door
    with successful polls is silence, even when the checkpoint is stale.
    """
    h, serial = _seeded_harness(tmp_path)
    for _ in range(4):
        h.clock.advance(CADENCE_S)
        h.monotonic.advance(CADENCE_S)
        quiet = h.tick()
        assert quiet is not None and quiet.ok is True
        assert h.policy.check_stall(serial) is None
    assert h.alerts == []
