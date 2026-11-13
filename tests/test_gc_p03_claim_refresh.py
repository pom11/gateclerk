"""Card GC-P03: the RUNNING loop re-reads the device's claimed UTC offset (DST).

BINDING SPEC: docs/P2-SITE-AGENT.md §2a request math + OBSERVED.md "time/offset bug"
and "Digest nonce use-cap". `DeviceLoop` used to read `GET /ISAPI/System/time` exactly
once per process (inside the `if self._bootstrapped: return` block), so a terminal whose
offset moves at a DST transition kept being stamped with the offset from process start:
every window went out one hour wrong until someone restarted the unit — and windows are
ARITHMETIC on this firmware, so the shift silently drops or duplicates punches at the
edges (the A/B of OBSERVED.md).

The four pins below are the card's four DoD cases:

(1) a `+02:00` -> `+03:00` flip on the device is used by the NEXT tick, no restart;
(2) the clock is read at most every `DEVICE_CLAIM_REFRESH_S`, never every tick (the
    nonce budget is the reason the bootstrap was once-per-process in the first place —
    the fix must not undo that amortization, it must bound it);
(3) a transient System/time failure leaves the LAST GOOD claim in place and the tick
    still runs (a clock read is never a reason to lose a poll);
(4) an auth error on the refresh is NOT swallowed into that fallback — exit-3 territory
    is a human's call, never a silent window relabel.

Offline by construction: FakeDevice behind the real IsapiClient, tmp sqlite, injected
clocks (the wall clock AND the monotonic that drives the cadence), no socket. The
harness and the device seeds are P2-03's own, imported rather than re-derived, so the
scenario cannot drift from the scheduler's truth.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import httpx
import pytest

from gateclerk.agent_loop import DEVICE_CLAIM_REFRESH_S
from gateclerk.exceptions import IsapiAuthError
from test_p2_03_scheduler import (
    CADENCE_S,
    RECORDED,
    SYSTEM_TIME_PATH,
    LoopHarness,
    device_event,
    seed_events,
    seeded_device,
)

#: The recorded fixture's own `localTime` stamp — the seam `system_time_body` swaps.
RECORDED_LOCAL_TIME = "2026-10-15T16:39:32+02:00"


def system_time_body(local_time: str) -> str:
    """The recorded `System/time` body with its `localTime` stamp replaced verbatim.

    Replacing the recorded body (rather than writing a new one) keeps every other field
    the device really sends — `timeMode`, the Hikvision `timeZone` dialect string — so the
    only variable in the test is the claimed offset, exactly as OBSERVED.md records it.
    """
    text = (RECORDED / "system_time.xml").read_text()
    assert RECORDED_LOCAL_TIME in text, (
        "the recorded System/time stamp moved; the seam below would swap nothing and "
        "the test would pass without testing anything"
    )
    return text.replace(RECORDED_LOCAL_TIME, local_time)


def clock_reads(device: Any) -> int:
    """Logical `GET System/time` reads: authenticated requests only, so the digest
    handshake's unauthenticated first hop (one per session) does not count as a read."""
    return sum(1 for s in device.served if s.path == SYSTEM_TIME_PATH and s.had_auth)


# --- DoD (1): the flip is picked up by the next tick, no restart --------------------------


def test_offset_flip_is_used_by_the_next_tick_without_restart(tmp_path: Path) -> None:
    """The card's DST case: a live loop must re-learn the offset from the device.

    One process, one client, one long-lived loop: the ONLY thing that changes between the
    two ticks is what the terminal says its offset is. If the loop still stamps windows
    with the process-start claim, the labels stay `+02:00` and this dies.
    """
    device = seeded_device()  # the recorded box claims +02:00
    seed_events(device, [device_event(140, "2026-10-19T09:58:00")])
    h = LoopHarness(tmp_path, device)

    r1 = h.tick()
    assert r1.ok
    assert r1.window_label == "device-claimed +02:00"
    assert clock_reads(device) == 1, "one read at bootstrap"

    # The DST transition. `reset` REPLACES the route — an `add` would queue behind the
    # +02:00 body, so the fake would keep answering the old stamp. `claimed_offset_min`
    # is the fake's own filter clock and moves with the claim, exactly as a box that just
    # stepped into summer does (the digits it stores keep counting on its own wall).
    device.claimed_offset_min = 180
    device.reset(
        "GET",
        SYSTEM_TIME_PATH,
        httpx.Response(200, text=system_time_body("2026-10-19T10:16:00+03:00")),
    )

    mark = len(device.served)
    h.clock.advance(DEVICE_CLAIM_REFRESH_S)
    h.monotonic.advance(DEVICE_CLAIM_REFRESH_S)
    r2 = h.tick()

    assert r2.ok, r2.error
    conds = h.event_conditions(since_index=mark)
    assert conds, "the refresh tick must still have searched"
    assert conds[-1]["startTime"].endswith("+03:00"), (
        "the stale +02:00 claim is still labeling windows — the loop never re-read it"
    )
    assert conds[-1]["endTime"].endswith("+03:00")
    assert r2.window_label == "device-claimed +03:00"
    assert clock_reads(device) == 2, "exactly the bootstrap read plus this refresh"


# --- DoD (2): one clock GET per interval, never one per tick ------------------------------


def test_clock_is_not_read_before_the_refresh_interval(tmp_path: Path) -> None:
    """The cadence bound, counted the card's way (authenticated GETs on the wire).

    The bootstrap's once-per-client read existed to amortize against the ~190-use nonce
    cap; a refresh on EVERY tick would multiply the cheapest request in the cycle by the
    number of cycles. Two ticks five minutes apart therefore pay exactly one clock read.
    """
    device = seeded_device()
    seed_events(device, [device_event(150, "2026-10-19T09:58:00")])
    h = LoopHarness(tmp_path, device)

    assert h.tick().ok
    h.clock.advance(CADENCE_S)
    h.monotonic.advance(CADENCE_S)
    assert h.tick().ok

    assert clock_reads(device) == 1, (
        "a 5-minute cadence must not read the clock on every tick "
        f"(the interval is {DEVICE_CLAIM_REFRESH_S}s)"
    )


# --- DoD (3): a transient failure keeps the last good claim -------------------------------


def test_a_transient_system_time_failure_keeps_the_last_claim(tmp_path: Path) -> None:
    """System/time is the least important read in the tick: it must never lose the poll.

    The device fault is one logical GET deep (the attempt plus the transport's single
    transparent retry both die), which is how a flaky box fails. The walk still runs on
    the last known claim — the same shape as `device_window_labels`' fallback, except the
    loop now has a previous claim worth keeping.
    """
    device = seeded_device()
    seed_events(device, [device_event(160, "2026-10-19T09:58:00")])
    h = LoopHarness(tmp_path, device)
    assert h.tick().ok
    assert h.loop._claim == 120, "the scenario starts on the recorded +02:00 claim"

    device.add_raw(
        "GET",
        SYSTEM_TIME_PATH,
        httpx.ReadError("simulated device fault"),
        httpx.ReadError("simulated device fault"),
    )
    mark = len(device.served)
    h.clock.advance(DEVICE_CLAIM_REFRESH_S)
    h.monotonic.advance(DEVICE_CLAIM_REFRESH_S)

    r2 = h.tick()
    assert r2.ok, f"the tick must still run on the last claim: {r2.error}"
    assert r2.window_label == "device-claimed +02:00", "the last claim survived the failure"
    conds = h.event_conditions(since_index=mark)
    assert conds and conds[-1]["endTime"].endswith("+02:00"), (
        "the failed refresh must not relabel the window (no invented offset, ever)"
    )

    # The failed read did NOT move `_claim_read_at`, so the next tick retries instead of
    # stranding the claim for another whole interval. The raw queue has drained by now:
    # this read succeeds, which is the "transient" half of the case.
    reads_before = clock_reads(device)
    h.clock.advance(CADENCE_S)
    h.monotonic.advance(CADENCE_S)
    r3 = h.tick()
    assert r3.ok, r3.error
    assert r3.window_label == "device-claimed +02:00"
    assert clock_reads(device) > reads_before, (
        "a failed refresh must retry on the NEXT tick, not wait out another interval"
    )


# --- DoD (4): an auth error on the refresh is never swallowed ------------------------------


def test_auth_error_on_the_refresh_is_not_swallowed(tmp_path: Path) -> None:
    """§2c/pipeline's rule, now on the refresh path: a 401 is a human's problem.

    The transient fallback is for a device that will not ANSWER; a device that will not
    AUTHENTICATE is the other case (a wrong or rotated credential must surface loudly, not
    degrade payroll windows quietly). Two shapes, two loops, so neither assertion borrows
    the other's opened circuit:

    * the refresh method itself re-raises (no last-claim rescue);
    * `tick()` reports it as a FAILED result carrying the `IsapiAuthError` — never an ok
      tick that quietly kept the old label.
    """
    device = seeded_device()
    seed_events(device, [device_event(170, "2026-10-19T09:58:00")])
    h = LoopHarness(tmp_path, device)
    assert h.tick().ok
    device.reset_raw("GET", SYSTEM_TIME_PATH, device.envelope_only_401())
    h.clock.advance(DEVICE_CLAIM_REFRESH_S)
    h.monotonic.advance(DEVICE_CLAIM_REFRESH_S)

    with pytest.raises(IsapiAuthError):
        h.loop._refresh_device_claim()

    device_b = seeded_device()
    seed_events(device_b, [device_event(171, "2026-10-19T09:58:00")])
    hb = LoopHarness(tmp_path, device_b)
    assert hb.tick().ok
    device_b.reset_raw("GET", SYSTEM_TIME_PATH, device_b.envelope_only_401())
    hb.clock.advance(DEVICE_CLAIM_REFRESH_S)
    hb.monotonic.advance(DEVICE_CLAIM_REFRESH_S)

    r = hb.tick()
    assert not r.ok, "an auth error on the clock read is a failed tick, not a quiet one"
    assert isinstance(r.exception, IsapiAuthError)
    assert r.skipped is False, "this is the walk-failed shape, not a parked-device skip"
    assert r.window_label == "device-claimed +02:00", (
        "the last good claim is what the failed tick reports: kept, never invented"
    )
