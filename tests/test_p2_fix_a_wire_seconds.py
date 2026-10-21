"""P2-fix-A: the event wire must never carry fractional seconds in a bound.

LIVE BUG (first real agent tick against site-a, 2026-10-21 ~03:21Z, read-only POST):

    IsapiBadContent: device rejected our request shape on acs_event_search
    http_status=400 statusCode=6 statusString=Invalid Content
    subStatusCode=badJsonContent errorMsg=startTime errorCode=1610612759
    request_body={"AcsEventCond":{... "startTime":"2026-10-21T06:22:06.031165+02:00",
                                  "endTime":"2026-10-21T06:32:06.031165+02:00",
                                  "major":5,"minor":0}}

A/B PROVEN on the device (operator-authorized read-only search POSTs, one request
each): the byte-identical body with the microseconds REMOVED was ACCEPTED
(responseStatusStrg=NO MATCH, totalMatches=0). So this firmware rejects fractional
seconds in startTime/endTime with the SAME badJsonContent/errorMsg=startTime envelope
OBSERVED.md recorded for naive bounds — the offset leg of that finding (p1-05c) is
unaffected; this is only the fractional leg. The agent's window comes from `now`
(agent_loop._window), which always carries microseconds, so the agent could never
store or checkpoint anything.

The fix lives in the ONE funnel that produces every wire pair —
`DeviceWindow.search_pair` (tz.py) — on the two paths that can reach the event wire
(device-offset relabel, and the site-labeled `with_offset=True` fallback). The raw
struct fields (`since_site_iso`, `since_device_local`, ...) are audit/provenance
strings and keep the microseconds verbatim.

FakeDevice gained the matching strictness (fakedevice.py): a bound carrying `.\\d+`
is answered with the recorded 400 envelope. Before this card the fake accepted ANY
offset-bearing string — the permissive-fake lesson of OBSERVED.md "offset REQUIRED",
applied again: 1465 green tests never saw the bug because nothing bit like the device.
"""

from __future__ import annotations

import json
import re
from collections.abc import Mapping
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any
from zoneinfo import ZoneInfo

import pytest

from fakedevice import BASE_URL, FakeDevice
from gateclerk.exceptions import IsapiBadContent
from gateclerk.isapi_transport import IsapiClient
from gateclerk.paging import iter_event_windows
from gateclerk.tz import parse_user_timestamp, window_for_device
from test_p2_03_scheduler import (
    SITE_TZ,
    FakeClock,
    LoopHarness,
    device_event,
    seed_events,
    seeded_device,
)

PASSWORD = "fakepw"  # hygiene placeholder (tests/test_repo_hygiene.py)
DEVICE_CLAIM = 120  # site-a claims +02:00 year-round (OBSERVED.md)

#: The wire shape this firmware accepts: whole seconds + offset label.
SECOND_PRECISION_LABELED = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}[+-]\d{2}:\d{2}")

EVENT_PATH = "/ISAPI/AccessControl/AcsEvent?format=json"

# The dense A/B day reused from test_p1_05c: 20 punches at device wall 14:08-14:20
# on 2026-05-21, stamped with the device's own claimed +02:00.
AB_SINCE_WHOLE = datetime(2026, 5, 21, 13, 0, tzinfo=timezone(timedelta(hours=3)))
AB_UNTIL_WHOLE = datetime(2026, 5, 21, 14, 30, tzinfo=timezone(timedelta(hours=3)))


def _ab_events() -> list[dict]:
    events = []
    for i in range(20):
        minute, second = divmod(8 * 60 + i * 36, 60)
        events.append(
            {
                "serialNo": 28 + i,
                "employeeNoString": "1",
                "major": 5,
                "minor": 0,
                "time": f"2026-05-21T14:{minute:02d}:{second:02d}+02:00",
            }
        )
    return events


def _client(device: FakeDevice) -> IsapiClient:
    return IsapiClient(
        BASE_URL, "admin", PASSWORD, transport=device.transport, sleep=lambda _s: None
    )


# --- 1. the fake must bite like the device -------------------------------------------
#
# These two tests ARE the documented strictness (card test 1). They fail on the old
# permissive FakeDevice (it served the store happily for fractional bounds), which is
# exactly the false-green the card names.


def test_fake_device_400s_a_fractional_second_start_time_like_the_live_device() -> None:
    """The live canary body, replayed verbatim: fractional startTime -> the 400.

    Envelope (recorded canary 2026-10-21, quoted in the module docstring and
    fakedevice.py): HTTP 400, statusCode 6, Invalid Content, badJsonContent,
    errorMsg=startTime. Same class as error_naive_start_time.json.
    """
    device = FakeDevice(password=PASSWORD)
    device.add_events(*_ab_events())
    client = _client(device)
    body = {
        "AcsEventCond": {
            "searchID": "canary-1",
            "searchResultPosition": 0,
            "maxResults": 30,
            "startTime": "2026-10-21T06:22:06.031165+02:00",
            "endTime": "2026-10-21T06:32:06.031165+02:00",
            "major": 5,
            "minor": 0,
        }
    }
    with pytest.raises(IsapiBadContent) as exc:
        client.search("acs_event_search", body)
    err = exc.value
    assert err.status_code == 400
    assert err.envelope.get("subStatusCode") == "badJsonContent"
    assert err.envelope.get("errorMsg") == "startTime"


def test_fake_device_400s_a_fractional_second_end_time_symmetrically() -> None:
    """The symmetric leg (endTime named) — the fake is at least as strict as the device."""
    device = FakeDevice(password=PASSWORD)
    device.add_events(*_ab_events())
    client = _client(device)
    body = {
        "AcsEventCond": {
            "searchID": "canary-2",
            "searchResultPosition": 0,
            "maxResults": 30,
            "startTime": "2026-10-21T06:22:06+02:00",
            "endTime": "2026-10-21T06:32:06.031165+02:00",
            "major": 5,
            "minor": 0,
        }
    }
    with pytest.raises(IsapiBadContent) as exc:
        client.search("acs_event_search", body)
    assert exc.value.envelope.get("errorMsg") == "endTime"


# --- 2. the agent loop: now() with microseconds must still reach the device -----------


def test_agent_loop_tick_with_microsecond_now_posts_second_precision_claimed_pair(
    tmp_path: Path,
) -> None:
    """The canary scenario offline: `now` always carries microseconds (datetime.now
    does), the window comes from `_window`, and the POSTed pair must be second-
    precision AND byte-identical to the relabeled site pair — the p1-05c arithmetic
    (site-wall digits + the device's claimed +02:00 label) must not move by a byte.
    """
    # 10:00:00.123456 Bucharest SUMMER = +03:00 site label vs the device's +02:00 claim
    # — the same disagreement shape as the scheduler suite's T0, microseconds added.
    fract_now = datetime(2026, 10, 19, 10, 0, 0, 123456, tzinfo=ZoneInfo(SITE_TZ))
    device = seeded_device()
    # Device-wall digits inside the cold-start floor (now - (cadence+overlap) = 09:50)
    # and one row past the upper bound (10:00:01 must NOT be stored).
    seed_events(
        device,
        [
            device_event(101, "2026-10-19T09:56:00"),
            device_event(102, "2026-10-19T09:58:30"),
            device_event(103, "2026-10-19T10:00:01"),
        ],
    )
    harness = LoopHarness(tmp_path, device, clock=FakeClock(fract_now))

    result = harness.tick()

    # The canary failure mode was a failed tick (400 -> ok=False, nothing stored).
    assert result.ok is True, f"tick failed: {result.error}"
    assert result.stored == 2
    assert result.checkpoint_serial == 102

    conds = harness.event_conditions()
    assert conds, "the tick posted no event search at all"
    for cond in conds:
        for field in ("startTime", "endTime"):
            value = cond[field]
            assert SECOND_PRECISION_LABELED.fullmatch(value), (
                f"{field}={value!r} is not second-precision+offset — this is the exact "
                "shape the live device 400s (badJsonContent / errorMsg names the bound)"
            )
            assert "." not in value
    # Byte-identical to what the whole-second window produced before the fix: site-wall
    # digits (09:50:00 / 10:00:00) relabeled with the device's claimed +02:00. The
    # floor must not shift a boundary the p1-05c A/B already pinned.
    assert conds[0]["startTime"] == "2026-10-19T09:50:00+02:00"
    assert conds[0]["endTime"] == "2026-10-19T10:00:00+02:00"


# --- 3. the CLI-shaped walk: the rule lives at the seam, not at one caller ------------


def test_cli_shaped_fractional_window_walk_is_second_precision_claimed_pair() -> None:
    """Operator `--since/--until` with fractional offsets (accepted by
    `parse_user_timestamp`) through the same `iter_event_windows` the CLI walks: the
    claim-relabeled pair on every POST must be second-precision, and the dense A/B
    day must still return all 20 serials (the floor moved no boundary the store
    filters on).
    """
    since = AB_SINCE_WHOLE.replace(minute=0, second=1, microsecond=500000)
    until = AB_UNTIL_WHOLE.replace(second=59, microsecond=999999)
    device = FakeDevice(password=PASSWORD)
    device.claimed_offset_min = DEVICE_CLAIM
    device.add_events(*_ab_events())

    serials: list[int] = []
    for chunk in iter_event_windows(
        lambda body: _client(device).search("acs_event_search", body),
        since=since,
        until=until,
        chunk="2h",
        site_tz=SITE_TZ,
        device_offset_min=DEVICE_CLAIM,
        inter_page_delay=0.0,
    ):
        serials.extend(r["serialNo"] for r in chunk.records)

    assert serials == list(range(28, 48)), "the floor must not drop boundary punches"
    posted = [json.loads(s.body) for s in device.served if s.path == EVENT_PATH and s.body]
    assert posted, "the walk posted no event search"
    for body in posted:
        cond = body["AcsEventCond"]
        for field in ("startTime", "endTime"):
            assert SECOND_PRECISION_LABELED.fullmatch(cond[field]) and "." not in cond[field], (
                f"{field}={cond[field]!r} reaches the wire with fractional seconds"
            )
            assert cond[field].endswith("+02:00")


def test_cli_shaped_fractional_window_fallback_pair_is_second_precision_site_labeled() -> None:
    """The `with_offset=True` site-labeled fallback (device claim unreadable,
    `device_offset_min=None`): the OTHER wire path through `search_pair` is floored
    too. The store-side A/B truth stays intact — a +03:00-labeled window answers
    NO MATCH / 0 on this box (OBSERVED.md); the point here is it is a 200 answer,
    not the fractional-seconds 400.
    """
    device = FakeDevice(password=PASSWORD)
    device.claimed_offset_min = DEVICE_CLAIM
    device.add_events(*_ab_events())
    seen: list[Mapping[str, Any]] = []

    for chunk in iter_event_windows(
        lambda body: _client(device).search("acs_event_search", body),
        since=AB_SINCE_WHOLE.replace(microsecond=300),
        until=AB_UNTIL_WHOLE.replace(microsecond=300),
        chunk="2h",
        site_tz=SITE_TZ,  # device_offset_min=None -> the site-labeled fallback
        inter_page_delay=0.0,
    ):
        seen.extend(chunk.records)

    assert seen == [], "the site-labeled A/B leg still shifts the window an hour early"
    posted = [json.loads(s.body) for s in device.served if s.path == EVENT_PATH and s.body]
    assert posted, "the walk posted no event search"
    for body in posted:
        cond = body["AcsEventCond"]
        for field in ("startTime", "endTime"):
            assert SECOND_PRECISION_LABELED.fullmatch(cond[field]) and "." not in cond[field], (
                f"{field}={cond[field]!r} reaches the wire with fractional seconds"
            )
            assert cond[field].endswith("+03:00"), (
                "fallback pair keeps the SITE label (p1-05b) — the fix must not "
                "invent a device claim here"
            )


# --- 4. the floor direction pin + the audit strings stay verbatim --------------------


def test_floor_truncates_toward_the_past_and_never_rolls_a_minute() -> None:
    """`23:59:59.999999` floors to `23:59:59` — same minute, same day, never the
    future. Rounding (instead of flooring) would roll the bound into the next minute
    and could name an instant AHEAD of the requested window: events the caller never
    asked for, on payroll data.
    """
    edge = datetime(2026, 10, 12, 23, 59, 59, 999999, tzinfo=ZoneInfo(SITE_TZ))
    window = window_for_device(edge, edge, site_tz=SITE_TZ)

    claimed = window.search_pair(device_offset_min=DEVICE_CLAIM)
    assert claimed == ("2026-10-12T23:59:59+02:00", "2026-10-12T23:59:59+02:00"), (
        "23:59:59.999999 must floor to 23:59:59 — no minute roll, no day roll, no future rounding"
    )
    site = window.search_pair(with_offset=True)
    assert site == ("2026-10-12T23:59:59+03:00", "2026-10-12T23:59:59+03:00")
    # Truncation, not rounding: every floored digit-leg is <= the requested digits.
    # (The digits are wall strings — comparing them as instants would be the exact
    # p1-05c mistake: the label is arithmetic for the device, not a timezone.)
    for value in (*claimed, *site):
        assert value[11:19] == "23:59:59"

    # The struct's audit/provenance strings keep the microseconds VERBATIM (card:
    # truncate only what goes on the wire).
    assert window.since_site_iso == "2026-10-12T23:59:59.999999+03:00"
    assert window.until_site_iso == "2026-10-12T23:59:59.999999+03:00"
    assert window.since_device_local == "2026-10-12T23:59:59.999999"
    # The naive pair is the raw wall pair (audit/test use — the firmware 400s it
    # regardless, so it never reaches the wire and needs no floor).
    assert window.search_pair() == ("2026-10-12T23:59:59.999999", "2026-10-12T23:59:59.999999")


def test_search_pair_on_whole_second_windows_is_byte_identical_unchanged() -> None:
    """Operators pass whole-minute windows; that CLI shape must not change by a byte
    (the p1-05c pins in test_p1_05c_window_labels.py stay true verbatim).
    """
    since = parse_user_timestamp("2026-05-21T13:00:00", site_tz=SITE_TZ)
    until = parse_user_timestamp("2026-05-21T14:30:00", site_tz=SITE_TZ)
    window = window_for_device(since, until, site_tz=SITE_TZ)
    assert window.search_pair(device_offset_min=DEVICE_CLAIM) == (
        "2026-05-21T13:00:00+02:00",
        "2026-05-21T14:30:00+02:00",
    )
    assert window.search_pair(with_offset=True) == (
        window.since_site_iso,
        window.until_site_iso,
    )


# --- 5. the fake is not merely permissive again (shape-completeness guard) -----------


def test_fake_device_still_serves_second_precision_bounds_in_store_mode() -> None:
    """The strictness is scoped to fractional bounds: the accepted A/B shape (whole
    seconds + label) keeps getting the ARITHMETIC-filtered 200, not a 400 — a fake
    that over-bites just as useless as one that under-bites.
    """
    device = FakeDevice(password=PASSWORD)
    device.add_events(*_ab_events())
    client = _client(device)
    body = {
        "AcsEventCond": {
            "searchID": "ab-1",
            "searchResultPosition": 0,
            "maxResults": 30,
            "startTime": "2026-05-21T13:00:00+02:00",
            "endTime": "2026-05-21T14:30:00+02:00",
            "major": 5,
            "minor": 0,
        }
    }
    answer = client.search("acs_event_search", body)
    assert answer["AcsEvent"]["totalMatches"] == 20


def test_rejected_fractional_bound_is_recorded_on_the_served_request() -> None:
    """When the fake 400s, the offending body is still captured (`served`) — the
    agent-loop/CLI tests read exactly these POSTed bodies to pin the wire shape."""
    device = FakeDevice(password=PASSWORD)
    device.add_events(*_ab_events())
    client = _client(device)
    with pytest.raises(IsapiBadContent):
        client.search(
            "acs_event_search",
            {
                "AcsEventCond": {
                    "searchID": "canary-3",
                    "searchResultPosition": 0,
                    "maxResults": 30,
                    "startTime": "2026-10-21T06:22:06.5+02:00",
                    "endTime": "2026-10-21T06:32:06.5+02:00",
                    "major": 5,
                    "minor": 0,
                }
            },
        )
    event_posts = [s for s in device.served if s.path == EVENT_PATH and s.body]
    assert event_posts, "the rejected POST was not recorded in served"
    cond = json.loads(event_posts[-1].body)["AcsEventCond"]
    assert cond["startTime"] == "2026-10-21T06:22:06.5+02:00", (
        "the fake must keep capturing the body it rejected — every wire-shape pin in "
        "this file reads these captured POSTs"
    )
