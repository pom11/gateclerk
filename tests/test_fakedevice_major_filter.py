"""The shared fake's `major` arm: `FakeDevice.honour_event_major_filter` (card t_22999a8f).

`tests/fakedevice.py` answers the event store with window ARITHMETIC only, and for a good
reason: OBSERVED.md's payroll-grade policy is "never trust a server-side filter you have
not probed", and the pipeline re-filters client-side anyway. That default is right for a
box of unknown filter behaviour — and it made one whole class of device unrepresentable:
a terminal that DOES honour the filter it advertised. That arm is not hypothetical.
OBSERVED.md's event-log census is a per-`major` `AcsEventTotalNum` read over ONE ring:

    major=0 total        10,199 events
    major=3 (operation)  10,169 events
    major=5 (event)          30 events

A silently-ignored filter would answer 10,199 three times. So both arms are device truth
on this family — `AcsEventCond.employeeNo` was the silently-ignored one, `major` was not
— and per-endpoint truth is exactly what this repo refuses to infer across routes.

What the pins below defend:

(1) knob OFF (the default every existing test rides) a `major=5` request still gets the
    unfiltered window answer, and `event_major_hidden` stays 0. This is the current
    policy pinned so nobody "fixes" the fake by defaulting the arm on — a walk that
    trusts a server filter it never verified must keep failing against a filter-blind
    box, because that is what an unprobed box does to it.
(2) knob ON, a mixed `major=5`/`major=3` store answers ONLY the `major=5` rows, with
    `numOfMatches`/`totalMatches` counting the narrowed set and `event_major_hidden`
    counting what the filter swallowed (the self-check the caller asserts non-zero).
(3) knob ON, a punch-only window over heartbeats answers the RECORDED empty-window shape
    verbatim — `"responseStatusStrg": "NO MATCH"` with the space, `numOfMatches`/
    `totalMatches` 0, and NO `InfoList` key at all (OBSERVED.md; not `[]`).
(4) `major: 0` is the "every major" ask (the loop's `include_noise` walk and GC-P15's
    wider reset probe both send it) and narrows NOTHING even with the knob on.
(5) `AcsEventTotalNum` narrows with the same predicate — the census above IS that
    endpoint, so a fake that filtered only the page answer would be lying about it.
(6) the strictness is scoped: outside store mode the knob changes nothing, `minor` is
    never simulated, a row that names no `major` is admitted only by the "every major"
    ask, and a non-int `major` is a loud test bug rather than a silent no-filter.

Offline by construction: `FakeDevice` behind the real `IsapiClient` (digest handshake
included), no socket. Nothing here touches product code — the subject IS the fake.
"""

from __future__ import annotations

from typing import Any

import pytest

from fakedevice import BASE_URL, FakeDevice
from gateclerk.isapi_transport import IsapiClient

PASSWORD = "fakepw"  # hygiene placeholder (tests/test_repo_hygiene.py)

#: The fake's own claimed offset (site-a, +02:00 year-round). Every bound below is
#: labeled with it, so the window DIGITS are the device-wall digits and this file is
#: about the `major` arm only — the label arithmetic is p1-05c's own suite
#: (test_p1_05c_window_labels.py) and must not be re-pinned here.
CLAIM_LABEL = "+02:00"

#: One hour of device wall that contains the mixed seed below.
WINDOW = ("2026-10-19T10:00:00" + CLAIM_LABEL, "2026-10-19T11:00:00" + CLAIM_LABEL)

EVENT_ENDPOINT = "acs_event_search"
TOTAL_NUM_ENDPOINT = "acs_event_total_num"


def punch(serial: int, wall: str) -> dict[str, Any]:
    """One `major=5` punch (the arm the narrow poll asks for)."""
    return {
        "serialNo": serial,
        "employeeNoString": "1",
        "major": 5,
        "minor": 75,
        "time": f"{wall}{CLAIM_LABEL}",
    }


def heartbeat(serial: int, wall: str) -> dict[str, Any]:
    """One `major=3` heartbeat: the noise the device keeps emitting while nobody badges."""
    return {"serialNo": serial, "major": 3, "minor": 1029, "time": f"{wall}{CLAIM_LABEL}"}


def mixed_store() -> list[dict[str, Any]]:
    """Four in-window rows, punches and noise interleaved on the shared serial counter.

    Interleaving matters: on the real box the noise shares the monotonic `serialNo`
    counter with the punches (OBSERVED.md "Event log census"), so a seed that sorted
    punches first would hide a serial-vs-time ordering bug the fake's sort has to get
    right anyway.
    """
    return [
        punch(10, "2026-10-19T10:05:00"),
        heartbeat(11, "2026-10-19T10:06:00"),
        punch(12, "2026-10-19T10:07:00"),
        heartbeat(13, "2026-10-19T10:08:00"),
    ]


def device_with(*events: dict[str, Any], honour: bool = False) -> FakeDevice:
    """A store-mode fake over `events`, with the `major` arm chosen explicitly."""
    device = FakeDevice(password=PASSWORD)
    device.add_events(*events)
    device.honour_event_major_filter = honour
    return device


def client_for(device: FakeDevice) -> IsapiClient:
    return IsapiClient(
        BASE_URL, "admin", PASSWORD, transport=device.transport, sleep=lambda _s: None
    )


def cond(major: int | None, *, window: tuple[str, str] = WINDOW, **extra: Any) -> dict[str, Any]:
    """A posted `AcsEventCond` — whole-second, offset-bearing (the naive 400 is p1-05b's)."""
    body: dict[str, Any] = {
        "searchID": "GC-MAJOR-ARM",
        "searchResultPosition": 0,
        "maxResults": 30,
        "startTime": window[0],
        "endTime": window[1],
    }
    if major is not None:
        body["major"] = major
    body.update(extra)
    return body


def ask(
    device: FakeDevice, major: int | None, *, window: tuple[str, str] = WINDOW
) -> dict[str, Any]:
    """One authenticated event POST through the real client; returns the `AcsEvent` block."""
    answer = client_for(device).search(EVENT_ENDPOINT, {"AcsEventCond": cond(major, window=window)})
    envelope = answer["AcsEvent"]
    assert isinstance(envelope, dict), answer
    return envelope


def total_num(device: FakeDevice, major: int | None) -> int:
    """The same ask against the count endpoint — `AcsEventTotalNumCond`, its own key."""
    answer = client_for(device).search(TOTAL_NUM_ENDPOINT, {"AcsEventTotalNumCond": cond(major)})
    return int(answer["AcsEventTotalNum"]["totalNum"])


def serials(envelope: dict[str, Any]) -> list[int]:
    return [int(row["serialNo"]) for row in envelope.get("InfoList", [])]


# --- (1) the default, pinned so nobody "fixes" it -----------------------------------------


def test_knob_off_a_major_five_request_still_gets_the_unfiltered_window_answer() -> None:
    """The current policy, on purpose: `major` is NOT simulated unless a test asks.

    A mixed store asked for `major=5` answers ALL FOUR rows. That is what the recorded
    device-family policy protects: a client that trusted a server filter it never
    probed would read noise as punches, and the only offline way to keep that honest is
    a fake that does not silently do the filtering for it.
    """
    device = device_with(*mixed_store())  # knob untouched = OFF
    assert device.honour_event_major_filter is False, "the arm must default OFF"

    envelope = ask(device, major=5)

    assert serials(envelope) == [10, 11, 12, 13], "the window answer, unfiltered"
    assert envelope["responseStatusStrg"] == "OK"
    assert (envelope["numOfMatches"], envelope["totalMatches"]) == (4, 4)
    assert device.event_major_hidden == 0, "a filter-blind answer swallowed nothing"


def test_knob_off_is_the_default_for_every_existing_scenario_not_just_this_one() -> None:
    """A plain `FakeDevice()` carries the arm OFF, so pre-existing tests cannot drift.

    The knob is read per request, so a device built by some other helper and never
    touched by this card still answers the window only. This pins the construction, not
    just one use: if `__init__` ever grows a True default, this fails before any suite
    quietly starts trusting a server filter.
    """
    assert FakeDevice().honour_event_major_filter is False
    assert FakeDevice().event_major_hidden == 0


# --- (2) the honouring arm ----------------------------------------------------------------


def test_knob_on_a_mixed_store_answers_only_the_requested_major() -> None:
    """`major=5` over punches + noise: only the punches, and the counts count THOSE."""
    device = device_with(*mixed_store(), honour=True)

    envelope = ask(device, major=5)

    assert serials(envelope) == [10, 12]
    assert envelope["responseStatusStrg"] == "OK"
    assert (envelope["numOfMatches"], envelope["totalMatches"]) == (2, 2), (
        "both counts describe the narrowed set, not the window"
    )
    assert envelope["searchID"] == "GC-MAJOR-ARM", "the echoed searchID survives the filter"
    assert device.event_major_hidden == 2, "the two heartbeats the filter swallowed"


def test_knob_on_a_punch_only_window_over_heartbeats_answers_no_match_in_the_recorded_shape() -> (
    None
):
    """The scenario the shared fake could not express before: quiet poll, noisy box.

    The window holds ONLY `major=3` heartbeats and the poll asks `major=5`, so a
    honouring device says it matched nothing. The answer must be the RECORDED shape —
    `NO MATCH` with the space, both counts 0, and the `InfoList` key ABSENT (OBSERVED.md:
    not `InfoList: []`). A walker that read `[]` and a walker that read a missing key
    disagree about "the device said zero", which is why the spelling is asserted as
    literally as a dict lets it be.
    """
    device = device_with(
        heartbeat(11, "2026-10-19T10:06:00"),
        heartbeat(13, "2026-10-19T10:08:00"),
        honour=True,
    )

    envelope = ask(device, major=5)

    assert envelope["responseStatusStrg"] == "NO MATCH"
    assert "InfoList" not in envelope, "the recorded zero OMITS the record key; never `[]`"
    assert (envelope["numOfMatches"], envelope["totalMatches"]) == (0, 0)
    assert envelope["searchID"] == "GC-MAJOR-ARM"
    assert set(envelope) == {"searchID", "responseStatusStrg", "numOfMatches", "totalMatches"}
    assert device.event_major_hidden == 2, (
        "the quiet branch was EARNED: two in-window rows really were swallowed by the "
        "filter, not absent from the store"
    )


def test_knob_on_still_narrows_when_the_window_holds_both_majors_and_one_row_each() -> None:
    """One punch, one heartbeat: the narrowed answer is one row, not "OK with noise".

    The degenerate 1-of-2 case is where an implementation that filtered AFTER building
    the envelope would still look right and where `numOfMatches` drifts most easily.
    """
    device = device_with(
        punch(20, "2026-10-19T10:05:00"),
        heartbeat(21, "2026-10-19T10:06:00"),
        honour=True,
    )

    envelope = ask(device, major=5)

    assert serials(envelope) == [20]
    assert (envelope["numOfMatches"], envelope["totalMatches"]) == (1, 1)
    assert device.event_major_hidden == 1


# --- (4) `major: 0` is "every major" -------------------------------------------------------


def test_major_zero_never_narrows_even_with_the_knob_on() -> None:
    """The loop's own `include_noise` walk asks `major=0` and must see the whole window.

    If `0` narrowed (to "rows whose major is 0", i.e. nothing), the checkpoint-on-
    device-wide-serial walk would lose its noise and the serial checkpoint would silently
    stop being device-wide.
    """
    device = device_with(*mixed_store(), honour=True)

    envelope = ask(device, major=0)

    assert serials(envelope) == [10, 11, 12, 13]
    assert (envelope["numOfMatches"], envelope["totalMatches"]) == (4, 4)
    assert device.event_major_hidden == 0, "an every-major ask swallowed nothing"


def test_an_absent_major_key_behaves_like_the_every_major_ask() -> None:
    """No `major` in the cond is the same device question as `major: 0`."""
    device = device_with(*mixed_store(), honour=True)

    assert serials(ask(device, major=None)) == [10, 11, 12, 13]
    assert device.event_major_hidden == 0


# --- (5) the count endpoint honours it too --------------------------------------------------


def test_total_num_narrows_with_the_same_predicate_and_zero_counts_everything() -> None:
    """`AcsEventTotalNum` is where the honouring arm was actually PROBED (the census).

    A fake that filtered only the page answer would reproduce the census wrong in the
    one place the census was measured, and a walk that cross-checks its page count
    against the count endpoint would see a contradiction the device never sends.
    """
    narrowed = device_with(*mixed_store(), honour=True)
    assert total_num(narrowed, major=5) == 2
    assert total_num(narrowed, major=0) == 4
    assert narrowed.event_major_hidden == 2

    # Knob off: the count endpoint is as filter-blind as the page answer.
    blind = device_with(*mixed_store())
    assert total_num(blind, major=5) == 4


# --- (6) the strictness is scoped ----------------------------------------------------------


def test_the_knob_changes_nothing_outside_store_mode() -> None:
    """Queue-replay routes are untouched: the arm is a property of the STORE.

    A canned page served by `add`/`reset_json` is the test's own bytes. Silently
    filtering them would be the fake editing a fixture it was told to replay — the same
    class of lenience this file exists to prevent, just pointed the other way.
    """
    device = FakeDevice(password=PASSWORD)
    device.honour_event_major_filter = True
    device.reset_json(
        "POST",
        "/ISAPI/AccessControl/AcsEvent?format=json",
        {
            "AcsEvent": {
                "searchID": "CANNED",
                "responseStatusStrg": "OK",
                "numOfMatches": 1,
                "totalMatches": 1,
                "InfoList": [heartbeat(99, "2026-10-19T10:06:00")],
            }
        },
    )

    envelope = ask(device, major=5)

    assert serials(envelope) == [99], "a canned page is replayed verbatim"
    assert device.event_major_hidden == 0


def test_minor_is_never_simulated() -> None:
    """`minor` stays un-simulated in BOTH arms — no probe recorded it narrowing anything.

    The knob is `major`-only by design; a test that asked for `minor=75` and got fewer
    rows would be believing a device fact nobody measured.
    """
    honours = device_with(*mixed_store(), honour=True)
    envelope = ask(honours, major=5, window=WINDOW)
    # Same store asked with a `minor` that only one punch carries: still every punch.
    assert serials(envelope) == [10, 12]
    narrow_minor = client_for(honours).search(EVENT_ENDPOINT, {"AcsEventCond": cond(5, minor=75)})[
        "AcsEvent"
    ]
    assert serials(narrow_minor) == [10, 12]
    assert honours.event_major_hidden == 4, "two swallowed per request, two requests"


def test_a_row_that_names_no_major_is_admitted_only_by_the_every_major_ask() -> None:
    """A row with no `major` key cannot be shown to satisfy a `major=5` ask.

    Under `major=0` it stays (the device returned it, so it is in the window); under a
    narrow ask the fake drops it rather than guessing — the same posture as `_store_wall`
    returning None for an unparseable stamp.
    """
    odd = {"serialNo": 30, "minor": 75, "time": f"2026-10-19T10:09:00{CLAIM_LABEL}"}

    honours = device_with(*mixed_store(), odd, honour=True)
    assert serials(ask(honours, major=5)) == [10, 12]
    assert honours.event_major_hidden == 3, "two heartbeats plus the row with no major"

    everything = device_with(*mixed_store(), odd, honour=True)
    assert serials(ask(everything, major=0)) == [10, 11, 12, 13, 30]


def test_a_non_integer_major_is_a_loud_test_bug_not_a_silent_no_filter() -> None:
    """With the arm ON, `major: "5"` must raise, not quietly degrade to "every major".

    Degrading would be the exact failure this card is about — a filter that stopped
    filtering and nobody noticed. The loud path is opt-in only: a knob-off fake never
    reads `major`, so the thousands of pre-existing requests stay byte-identical, and the
    guard fires BEFORE an envelope is built, so no caller can consume a wrong answer.
    """
    honours = device_with(*mixed_store(), honour=True)
    body = {"AcsEventCond": {**cond(0), "major": "5"}}
    with pytest.raises(AssertionError, match="broken test"):
        client_for(honours).search(EVENT_ENDPOINT, body)

    blind = device_with(*mixed_store())  # knob OFF: the strict check is never reached
    assert serials(ask(blind, major=5)) == [10, 11, 12, 13]
