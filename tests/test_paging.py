"""The paged-search engine (card p1-05), driven against FakeDevice and scripts.

Definition of done, item by item (each maps to a test below, names cross-
reference the card):

* exact pagination walk MORE/MORE/OK, position advancing by returned
  `numOfMatches` — `test_more_more_ok_walk_advances_position_by_returned_num_of_matches`
* NO_MATCH -> empty, not an error (incl. the `"NO MATCH"`-with-space spelling and
  the absent-`InfoList` shape, both from OBSERVED.md) — `test_no_match_*`
* fw-clamped maxResults: the cursor follows the RETURNED count, never the
  requested page size (the payroll-skip bug) — `test_clamped_pages_*`
* Invalid Content on a missing-bounds query is simulated, and we prove we never
  send an unbounded AcsEvent query (engine raises before the wire) —
  `test_unbounded_event_query_never_reaches_the_wire`
* safety cap raises SearchRunawayError — `test_runaway_cap_*`

Plus the engine-level rules the card lists: searchID stable across a walk and
fresh per logical search (the device silently restarts on a change), 0-based
positions, inter-page delay defaulting to 100 ms (net of request time), UserInfo
on the same engine with the UserInfo/Count cross-check as a warn-not-fail
advisory, and the filter-trust rules (employeeNoString, never the silently-
ignored bare employeeNo; picEnable never sent).

Two layers of fake: `scripted()` is a pure in-memory reader (exact request
sequence, clock injection, zero waiting), and the FakeDevice-backed tests run the
REAL `IsapiClient` underneath — digest handshake and all — to prove the engine
rides one authenticated session across pages instead of re-paying the 401 per
page. The golden fixtures (events_more_noise_page1.json / user_search_page1.json
/ user_count.json) come straight off the masked device capture, so the envelope
shape under test is the device's, not our imagination.
"""

from __future__ import annotations

import json
import re
from collections.abc import Callable, Mapping
from dataclasses import replace
from datetime import timedelta
from pathlib import Path
from typing import Any

import httpx
import pytest

from fakedevice import BASE_URL, FakeDevice
from gateclerk.exceptions import (
    EventBoundsError,
    IsapiBadContent,
    SearchProtocolError,
    SearchRunawayError,
)
from gateclerk.isapi_transport import IsapiClient
from gateclerk.paging import (
    DEFAULT_INTER_PAGE_DELAY,
    ChunkResult,
    PagingLimits,
    acs_event_search,
    build_event_cond,
    chunk_window,
    clamp_page_size,
    collect_users,
    fd_search,
    iter_event_windows,
    iter_users,
    new_search_id,
    normalize_status,
    parse_chunk,
    response_envelope,
)
from gateclerk.tz import (
    DeviceWindow,
    TimestampInputError,
    parse_user_timestamp,
    window_for_device,
)

FIXTURE_DIR = Path(__file__).parent / "fixtures/recorded/site-a-ds-k1t341amf-s"

EVENT_PATH = "/ISAPI/AccessControl/AcsEvent?format=json"
TOTAL_PATH = "/ISAPI/AccessControl/AcsEventTotalNum?format=json"
PASSWORD = "fakepw"  # placeholder policy (tests/test_repo_hygiene.py)

SITE_TZ = "Europe/Bucharest"


def load_fixture(name: str) -> dict[str, Any]:
    return json.loads((FIXTURE_DIR / name).read_text(encoding="utf-8"))


def event_envelope(**fields: Any) -> dict[str, Any]:
    return {"AcsEvent": dict(fields)}


def scripted(
    *responses: dict[str, Any],
) -> tuple[Callable[[Mapping[str, Any]], dict[str, Any]], list[dict[str, Any]]]:
    """A PageReader that replays `responses` in order and records every body sent.

    The last response sticks, like a persistent FakeDevice route — that is what
    makes the runaway scenarios (a device that says MORE forever) expressible.
    """
    sent: list[dict[str, Any]] = []

    def reader(body: Mapping[str, Any]) -> dict[str, Any]:
        sent.append(json.loads(json.dumps(body)))  # deep copy: freeze what was sent
        return responses[len(sent) - 1] if len(sent) <= len(responses) else responses[-1]

    return reader, sent


def no_sleep(_seconds: float) -> None:
    return None


def make_engine(reader: Any, **kw: Any) -> Any:
    """acs_event_search with test defaults: never wait, scripted clock not needed."""
    kw.setdefault("sleep", no_sleep)
    kw.setdefault("inter_page_delay", 0.0)
    return acs_event_search(reader, **kw)


# --- status normalisation (OBSERVED.md: "NO MATCH" has a SPACE) ------------------------


def test_normalize_status_handles_every_observed_spelling() -> None:
    assert normalize_status("OK") == "OK"
    assert normalize_status("MORE") == "MORE"
    # The DESIGN.md normalization: case/space/underscore collapse. The exact
    # collapsed token is irrelevant to the engine — only "MORE" continues — but the
    # OBSERVED.md space MUST collapse, or "NO MATCH" reads as a foreign token.
    assert normalize_status("NO MATCH") == "NOMATCH"
    assert normalize_status(" ok ") == "OK"
    assert normalize_status(None) == ""
    # Card DoD spelling (NO_MATCHES) and device spelling (NO MATCH) both non-continuable.
    from gateclerk.paging import is_more

    assert not is_more(normalize_status("NO_MATCHES"))
    assert not is_more(normalize_status("NO MATCH"))
    assert is_more(normalize_status(" more "))


def test_card_spelling_no_matches_also_terminates_empty() -> None:
    """The card names NO_MATCHES; the fw sends 'NO MATCH'. Whichever arrives, the
    walk ends after one page with empty records — never an error, never a loop."""
    reader, sent = scripted(
        {
            "AcsEvent": {
                "searchID": "s",
                "responseStatusStrg": "NO_MATCHES",
                "totalMatches": 0,
                "numOfMatches": 0,
            }
        },
    )
    pages = list(make_engine(reader).pages({}))
    assert len(pages) == 1 and len(sent) == 1
    assert pages[0].records == () and pages[0].status == "NOMATCHES"


# --- the happy walk: MORE / MORE / OK --------------------------------------------------


def test_more_more_ok_walk_advances_position_by_returned_num_of_matches() -> None:
    reader, sent = scripted(
        event_envelope(
            searchID="s",
            responseStatusStrg="MORE",
            numOfMatches=2,
            totalMatches=5,
            InfoList=[{"serialNo": 1}, {"serialNo": 2}],
        ),
        event_envelope(
            searchID="s",
            responseStatusStrg="MORE",
            numOfMatches=2,
            totalMatches=5,
            InfoList=[{"serialNo": 3}, {"serialNo": 4}],
        ),
        event_envelope(
            searchID="s",
            responseStatusStrg="OK",
            numOfMatches=1,
            totalMatches=5,
            InfoList=[{"serialNo": 5}],
        ),
    )
    pages = list(make_engine(reader).pages({}, search_id="fixed-id-1"))

    assert [p.position for p in pages] == [0, 2, 4], (
        "0-based start, advanced by the RETURNED numOfMatches (2+2), not by "
        "maxResults or totalMatches (OBSERVED.md + DESIGN.md)"
    )
    assert [p.status for p in pages] == ["MORE", "MORE", "OK"]
    assert [p.num_of_matches for p in pages] == [2, 2, 1]
    assert [c["AcsEventCond"]["searchResultPosition"] for c in sent] == [0, 2, 4]
    assert sum(len(p.records) for p in pages) == 5


def test_search_id_is_stable_across_all_pages_and_uuid4_shaped() -> None:
    reader, sent = scripted(
        event_envelope(
            searchID="x", responseStatusStrg="MORE", numOfMatches=1, InfoList=[{"serialNo": 1}]
        ),
        event_envelope(
            searchID="x", responseStatusStrg="OK", numOfMatches=1, InfoList=[{"serialNo": 2}]
        ),
    )
    pages = list(make_engine(reader).pages({}))
    ids = {c["AcsEventCond"]["searchID"] for c in sent}
    assert len(ids) == 1, "device caches the cursor per searchID — it must not change mid-walk"
    sid = ids.pop()
    assert len(sid) == 20 and all(ch in "0123456789abcdef" for ch in sid)
    assert [p.search_id for p in pages] == [sid, sid]


def test_each_logical_search_gets_a_fresh_search_id() -> None:
    ids = {new_search_id() for _ in range(50)}
    assert len(ids) == 50, "uuid4 per logical search — a reused id inherits another walk's cursor"


def test_search_id_is_clamped_to_advertised_length() -> None:
    assert len(new_search_id(20)) == 20
    assert len(new_search_id(64)) == 32, "uuid4 hex is 32 chars; nothing longer exists"
    with pytest.raises(ValueError, match="alias"):
        new_search_id(6)


def test_termination_is_only_on_not_more_or_empty_infolist() -> None:
    """MORE continues, anything else terminates; an empty InfoList ends the walk
    even under MORE (defensive rule, card DoD)."""
    reader, sent = scripted(
        event_envelope(
            searchID="s", responseStatusStrg="MORE", numOfMatches=1, InfoList=[{"serialNo": 1}]
        ),
        event_envelope(
            searchID="s", responseStatusStrg="OK", numOfMatches=1, InfoList=[{"serialNo": 2}]
        ),
    )
    pages = list(make_engine(reader).pages({}))
    assert len(pages) == 2 and len(sent) == 2

    reader2, sent2 = scripted(
        event_envelope(searchID="s", responseStatusStrg="MORE", numOfMatches=0, InfoList=[]),
    )
    pages2 = list(make_engine(reader2).pages({}))
    assert len(pages2) == 1 and len(sent2) == 1, "empty InfoList terminates regardless of status"


def test_unknown_terminal_status_terminates_and_is_recorded() -> None:
    """Only MORE continues — a status nobody has ever seen ends the walk (fail-safe:
    looping on an unknown token is how a firmware change becomes a hang)."""
    reader, _sent = scripted(
        event_envelope(
            searchID="s", responseStatusStrg="WHO KNOWS", numOfMatches=3, InfoList=[{"serialNo": 1}]
        ),
    )
    pages = list(make_engine(reader).pages({}))
    assert len(pages) == 1 and pages[0].status == "WHOKNOWS"


# --- NO MATCH -> empty, not an error ----------------------------------------------------


def test_no_match_with_space_and_missing_infolist_is_empty_not_error() -> None:
    """Byte-exact replay of the recorded empty-window fixture (events_no_match.json):
    status 'NO MATCH' (space!), NO InfoList key at all -> [] and a clean single
    request — never an exception, never a second page."""
    body = load_fixture("events_no_match.json")
    reader, sent = scripted(body)
    pages = list(make_engine(reader).pages({}))
    assert len(pages) == 1
    assert pages[0].status == "NOMATCH"
    assert pages[0].records == ()
    assert pages[0].num_of_matches == 0
    assert len(sent) == 1, "NO MATCH must end the walk after one request"


# --- silently clamped maxResults (the payroll-skip bug) --------------------------------


def test_clamped_pages_advance_by_returned_count_not_requested_size() -> None:
    """We ask for 30 and the fw hands 10 per page (the silent-clamp class, no
    error). Advancing by the REQUESTED 30 would skip records 10..29 — the exact
    payroll bug OBSERVED.md and the research pass warn about. Positions follow
    the data, not the request."""
    reader, sent = scripted(
        event_envelope(
            searchID="s",
            responseStatusStrg="MORE",
            numOfMatches=10,
            totalMatches=30,
            InfoList=[{"serialNo": i} for i in range(10)],
        ),
        event_envelope(
            searchID="s",
            responseStatusStrg="MORE",
            numOfMatches=10,
            totalMatches=30,
            InfoList=[{"serialNo": 10 + i} for i in range(10)],
        ),
        event_envelope(
            searchID="s",
            responseStatusStrg="OK",
            numOfMatches=10,
            totalMatches=30,
            InfoList=[{"serialNo": 20 + i} for i in range(10)],
        ),
    )
    engine = make_engine(reader, page_size=30, limits=PagingLimits(max_results=30))
    got = list(engine.pages({}))
    assert [c["AcsEventCond"]["maxResults"] for c in sent] == [30, 30, 30]
    assert [p.position for p in got] == [0, 10, 20], "by numOfMatches(10), not by maxResults(30)"
    assert sum(len(p.records) for p in got) == 30


def test_engine_clamps_requested_page_size_to_capability() -> None:
    reader, sent = scripted(
        event_envelope(
            searchID="s", responseStatusStrg="OK", numOfMatches=2, InfoList=[{"a": 1}, {"a": 2}]
        ),
    )
    # Ask for 100 on a 30-cap box: we must SEND 30 (never rely on the silent clamp).
    engine = make_engine(reader, page_size=100, limits=PagingLimits(max_results=30))
    list(engine.pages({}))
    assert sent[0]["AcsEventCond"]["maxResults"] == 30
    assert clamp_page_size(PagingLimits(max_results=30), 100) == 30
    assert clamp_page_size(PagingLimits(max_results=30), 5) == 5, "smaller-than-cap is honoured"


def test_capability_limits_are_clamped_at_construction() -> None:
    assert PagingLimits(max_results=10_000).max_results == 150  # MAX_KNOWN_MAX_RESULTS
    assert PagingLimits(search_id_max_len=999).search_id_max_len == 64
    with pytest.raises(ValueError):
        PagingLimits(max_results=0)
    with pytest.raises(ValueError, match="collision-safe"):
        PagingLimits(search_id_max_len=4)


def test_num_of_matches_mismatch_steps_safely_not_skipping() -> None:
    """A firmware that reports numOfMatches=30 but only hands back 10 records must
    not make us jump 30 (that would silently skip 20 punches). The engine steps by
    what it can PROVE left the device; re-reads are free via UPSERT (DESIGN.md)."""
    reader, sent = scripted(
        event_envelope(
            searchID="s",
            responseStatusStrg="MORE",
            numOfMatches=30,
            InfoList=[{"serialNo": i} for i in range(10)],
        ),
        event_envelope(
            searchID="s", responseStatusStrg="OK", numOfMatches=1, InfoList=[{"serialNo": 99}]
        ),
    )
    pages = list(make_engine(reader).pages({}))
    assert pages[1].position == 10, "min(returned, reported) — never forward-skip"
    assert len(sent) == 2


def test_missing_num_of_matches_falls_back_to_records_returned() -> None:
    reader, _sent = scripted(
        event_envelope(searchID="s", responseStatusStrg="MORE", InfoList=[{"a": 1}, {"a": 2}]),
        event_envelope(searchID="s", responseStatusStrg="OK", InfoList=[{"a": 3}]),
    )
    pages = list(make_engine(reader).pages({}))
    assert [p.position for p in pages] == [0, 2]
    assert [p.num_of_matches for p in pages] == [2, 1]


# --- the safety cap ---------------------------------------------------------------------


def test_runaway_cap_raises_search_runaway_error_instead_of_looping() -> None:
    reader, sent = scripted(
        event_envelope(
            searchID="s",
            responseStatusStrg="MORE",
            numOfMatches=5,
            InfoList=[{"serialNo": i} for i in range(5)],
        ),
    )  # last response sticks: this device says MORE forever (the silent-restart class)
    engine = make_engine(reader, max_pages=3)
    with pytest.raises(SearchRunawayError) as excinfo:
        list(engine.pages({}, search_id="runaway-id"))
    err = excinfo.value
    assert err.pages == 3 and err.position == 15 and err.search_id == "runaway-id"
    assert len(sent) == 3, "the cap stops the walk AT the cap — no 4th request to a misbehaving box"


def test_runaway_error_carries_context_for_the_operator() -> None:
    reader, _ = scripted(
        event_envelope(
            searchID="s", responseStatusStrg="MORE", numOfMatches=1, InfoList=[{"a": 1}]
        ),
    )
    with pytest.raises(SearchRunawayError, match="misbehaving"):
        list(make_engine(reader, max_pages=2).pages({}))


# --- never an unbounded AcsEvent query ---------------------------------------------------


def _window(start: str, end: str) -> DeviceWindow:
    since = parse_user_timestamp(start, site_tz=SITE_TZ)
    until = parse_user_timestamp(end, site_tz=SITE_TZ)
    return window_for_device(since, until, site_tz=SITE_TZ)


def test_build_event_cond_sends_bounds_with_the_site_offset_by_default() -> None:
    """The wire form is the offset-bearing site pair (p1-05b, live P0).

    2026-10-17 live proof (OBSERVED.md "Event-window startTime form: offset REQUIRED"):
    `"startTime":"2026-10-10T00:00:00"` -> HTTP 400 `statusCode=6`,
    `subStatusCode=badJsonContent`, `errorMsg=startTime`; the same window stamped
    `+03:00` returned 200. So the offset pair is the DEFAULT here and the naive pair
    is reachable only explicitly — a caller that wants naive must say so.
    """
    cond = build_event_cond(_window("2026-10-12T00:00:00", "2026-10-12T23:59:59"))
    assert cond["startTime"] == "2026-10-12T00:00:00+03:00", (
        "site-tz wall time stamped with the site offset (Bucharest Oct = +03) — the "
        "only form this firmware accepts; a naive default here fails every live pull"
    )
    assert cond["endTime"] == "2026-10-12T23:59:59+03:00"

    naive = build_event_cond(
        _window("2026-10-12T00:00:00", "2026-10-12T23:59:59"), with_offset=False
    )
    assert (
        naive["startTime"] == "2026-10-12T00:00:00" and naive["endTime"] == "2026-10-12T23:59:59"
    ), (
        "the struct still exposes the raw wall pair (audit/test use); it is simply no "
        "longer what the engine puts on the wire"
    )


def test_broken_window_raises_event_bounds_error_before_any_request() -> None:
    good = _window("2026-10-12T00:00:00", "2026-10-12T23:59:59")
    broken = replace(good, since_device_local="")
    with pytest.raises(EventBoundsError):
        build_event_cond(broken)


def _bad_request(payload: dict[str, Any]) -> httpx.Response:
    return httpx.Response(400, json=payload)


class _UnboundedQueryRejector(FakeDevice):
    """FakeDevice that answers ANY AcsEvent POST whose body lacks startTime/endTime
    with the RECORDED Invalid Content envelope (statusCode 6 / badParameters) —
    the firmware behaviour the card says to simulate. Bounded requests proceed and
    every AcsEvent body is recorded for the assertion."""

    def __init__(self) -> None:
        super().__init__()
        self.seen_bodies: list[dict[str, Any]] = []

    def _handle(self, request: Any) -> httpx.Response:
        if request.method == "POST" and request.url.path == "/ISAPI/AccessControl/AcsEvent":
            body = json.loads(request.content.decode() or "{}")
            self.seen_bodies.append(body)
            cond = body.get("AcsEventCond", {})
            if "startTime" not in cond or "endTime" not in cond:
                return _bad_request(
                    {
                        "requestURL": EVENT_PATH,
                        "statusCode": 6,
                        "statusString": "Invalid Content",
                        "subStatusCode": "badParameters",
                        "errorCode": 1610612737,
                        "errorMsg": "0x60000001",
                    }
                )
        return super()._handle(request)


def test_unbounded_event_query_never_reaches_the_wire() -> None:
    """The Invalid-Content simulation from the card, inverted into a guarantee.

    The rejecting fake 400s any AcsEvent query without bounds. We then:
    (a) run the normal bounded chunked walk through the REAL client and prove the
        device only ever saw bodies carrying startTime+endTime, and
    (b) confirm the device-side trap really fires when a bounds-less body IS
        forced onto the wire (a canary proving the guard is not vacuous).
    """
    device = _UnboundedQueryRejector()
    device.json_ok(
        "POST",
        EVENT_PATH,
        event_envelope(
            searchID="s", responseStatusStrg="OK", numOfMatches=1, InfoList=[{"serialNo": 1}]
        ),
    )
    client = IsapiClient(BASE_URL, "admin", PASSWORD, transport=device.transport, sleep=no_sleep)
    since = parse_user_timestamp("2026-10-12T00:00:00", site_tz=SITE_TZ)
    until = parse_user_timestamp("2026-10-12T06:00:00", site_tz=SITE_TZ)

    chunks = list(
        iter_event_windows(
            lambda body: client.search("acs_event_search", body),
            since=since,
            until=until,
            chunk="1d",
            inter_page_delay=0.0,
            sleep=no_sleep,
        )
    )
    assert chunks and chunks[0].records, "the bounded walk works end-to-end through the real client"
    assert device.seen_bodies, "the device did see our requests"
    for body in device.seen_bodies:
        cond = body["AcsEventCond"]
        assert "startTime" in cond and "endTime" in cond, f"engine sent an unbounded query: {cond}"

    # Canary: force a bounds-less body onto the wire — the trap must actually bite
    # (IsapiBadContent carries statusCode 6), i.e. our guard protects a REAL hazard.
    from gateclerk.exceptions import IsapiBadContent

    with pytest.raises(IsapiBadContent):
        client.search("acs_event_search", {"AcsEventCond": {"searchID": "x", "maxResults": 10}})


# --- p1-05b: the offset-bearing window on the wire (live P0, OBSERVED.md 2026-10-17) -------
#
# The device 400s a naive AcsEvent startTime (`badJsonContent`, `errorMsg=startTime`);
# the offset-bearing site pair returns 200. These pins cover the three halves of that
# fact: every body the engine emits carries `+HH:MM` (engine), the fake now REJECTS a
# naive body like the device does (anti-false-green), and the recorded 400 parses into
# IsapiBadContent with errorMsg surfaced (error path).

_OFFSET_BOUND = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}[+-]\d{2}:\d{2}$")


def test_every_event_body_the_engine_sends_carries_offset_bearing_bounds() -> None:
    """Engine-level body pin: through the REAL client, every AcsEvent POST the device
    sees has startTime AND endTime stamped `+HH:MM` (OBSERVED.md, live proof
    2026-10-17). FakeDevice's own strictness makes a regression here fail LOUDLY
    (400 mid-walk) even if this assertion were deleted — that redundancy is the
    point: the old suite was green while every live pull failed."""
    device = FakeDevice()
    device.json_ok(
        "POST",
        EVENT_PATH,
        event_envelope(
            searchID="s", responseStatusStrg="OK", numOfMatches=1, InfoList=[{"serialNo": 1}]
        ),
    )
    client = IsapiClient(BASE_URL, "admin", PASSWORD, transport=device.transport, sleep=no_sleep)
    since = parse_user_timestamp("2026-10-11T00:00:00", site_tz=SITE_TZ)
    until = parse_user_timestamp("2026-10-13T00:00:00", site_tz=SITE_TZ)  # 2 chunks
    list(
        iter_event_windows(
            lambda body: client.search("acs_event_search", body),
            since=since,
            until=until,
            chunk="1d",
            inter_page_delay=0.0,
            sleep=no_sleep,
        )
    )
    posted = [json.loads(s.body) for s in device.served if s.path == EVENT_PATH]
    assert len(posted) >= 2, "two chunks -> both walked through the real digest client"
    for body in posted:
        cond = body["AcsEventCond"]
        for name in ("startTime", "endTime"):
            assert _OFFSET_BOUND.match(cond[name]), (
                f"{name}={cond[name]!r} lacks the site-tz offset — this firmware 400s "
                "a naive bound (OBSERVED.md 'Event-window startTime form: offset REQUIRED')"
            )


def test_fakedevice_rejects_a_naive_event_body_exactly_like_the_device() -> None:
    """The anti-false-green pin: FakeDevice used to answer ANY body shape — that is
    how the offline suite stayed green while every live `gateclerk events` pull failed.
    A hand-built naive body now gets the device's recorded 400 envelope; the offset
    pair is served (the canary that the trap only bites the naive shape)."""
    device = FakeDevice()
    event_ok = event_envelope(
        searchID="s", responseStatusStrg="OK", numOfMatches=1, InfoList=[{"serialNo": 1}]
    )
    device.json_ok("POST", EVENT_PATH, event_ok)
    # The count route must be registered too: the strictness check runs at HANDLER
    # time, after the route lookup — exactly like the firmware, where a MISSING
    # endpoint answers notSupport and a PRESENT one parses the body. Without a route
    # here the naive probe would pin the 404 envelope instead of the 400.
    device.json_ok("POST", TOTAL_PATH, {"AcsEventTotalNum": {"totalNum": 7}})
    client = IsapiClient(BASE_URL, "admin", PASSWORD, transport=device.transport, sleep=no_sleep)

    with pytest.raises(IsapiBadContent) as excinfo:
        client.search(
            "acs_event_search",
            {
                "AcsEventCond": {
                    "searchID": "x",
                    "startTime": "2026-10-10T00:00:00",
                    "endTime": "2026-10-11T00:00:00",
                    "maxResults": 10,
                }
            },
        )
    err = str(excinfo.value)
    assert "statusCode=6" in err and "badJsonContent" in err and "errorMsg=startTime" in err, (
        f"the fake must answer the device's exact envelope: {err}"
    )
    assert excinfo.value.envelope.get("errorMsg") == "startTime"

    with pytest.raises(IsapiBadContent) as excinfo:
        client.search(
            "acs_event_total_num",
            {
                "AcsEventTotalNumCond": {
                    "startTime": "2026-10-10T00:00:00",
                    "endTime": "2026-10-11T00:00:00",
                    "major": 5,
                }
            },
        )
    assert "errorMsg=endTime" not in str(excinfo.value), (
        "startTime is checked first — the device named startTime, so must we"
    )
    assert "errorMsg=startTime" in str(excinfo.value)

    # Canary: the SAME window with offsets is served, so the 400 above bites the
    # naive shape specifically — not every request (a fake that rejects everything
    # is as useless as one that rejects nothing).
    ok = client.search(
        "acs_event_search",
        {
            "AcsEventCond": {
                "searchID": "x",
                "startTime": "2026-10-10T00:00:00+03:00",
                "endTime": "2026-10-11T00:00:00+03:00",
                "maxResults": 10,
            }
        },
    )
    assert ok["AcsEvent"]["responseStatusStrg"] == "OK"


def test_recorded_naive_start_time_400_parses_into_isapi_bad_content() -> None:
    """The owner's live 400 (error_naive_start_time.json, verbatim) must classify as
    IsapiBadContent with errorMsg=startTime surfaced in the message — that pairing is
    how an operator reading a crash knows WHICH field the firmware hated."""
    from gateclerk.isapi_response import envelope_to_error, parse_envelope

    raw = (FIXTURE_DIR / "error_naive_start_time.json").read_bytes()
    err = envelope_to_error(
        http_status=400,
        envelope=parse_envelope(raw, http_status=400),
        endpoint="acs_event_search",
        raw_body=raw,
    )
    assert isinstance(err, IsapiBadContent)
    assert "errorMsg=startTime" in str(err)
    assert err.envelope.get("subStatusCode") == "badJsonContent"


def test_cursor_fields_cannot_be_smuggled_by_caller() -> None:
    """The engine owns the cursor — a caller passing maxResults/searchID in cond
    would break the silent-clamp safety (mid-walk changes restart/skip), so it is
    refused before anything is sent."""
    reader, sent = scripted(
        event_envelope(searchID="s", responseStatusStrg="OK", numOfMatches=0, InfoList=[]),
    )
    engine = make_engine(reader)
    with pytest.raises(SearchProtocolError):
        list(engine.pages({"searchID": "hijack"}))
    with pytest.raises(SearchProtocolError):
        list(engine.pages({"maxResults": 9999}))
    assert sent == [], "the guard fired before any request"


# --- captured FDSearch root dialect (§5.0 capture, bench A 2026-10-22) -------------------

# THE byte-for-byte key set bench A answered on FDSearch. Captured live: there is NO
# `{"FDSearch": ...}` wrapper (the v4 design guess; it failed CLOSED on the real box),
# and the honest zero (FPID of a person with no face) omits `MatchList` ENTIRELY.
CAPTURED_FD_ROW = {
    "statusCode": 1,
    "statusString": "OK",
    "subStatusCode": "ok",
    "responseStatusStrg": "OK",
    "numOfMatches": 1,
    "totalMatches": 1,
    "MatchList": [{"FPID": "1", "faceURL": "…", "modelData": "RlI1MDAwMDUB"}],
}
CAPTURED_FD_ZERO = {
    "statusCode": 1,
    "statusString": "OK",
    "subStatusCode": "ok",
    "responseStatusStrg": "NO MATCH",
    "numOfMatches": 0,
    "totalMatches": 0,
}


def test_response_envelope_root_dialect_accepts_captured_shapes() -> None:
    env = response_envelope(CAPTURED_FD_ROW, "", search_id="cap")
    assert env is CAPTURED_FD_ROW  # the root IS the envelope
    assert response_envelope(CAPTURED_FD_ZERO, "", search_id="cap")["numOfMatches"] == 0


def test_response_envelope_root_dialect_still_fails_closed() -> None:
    """The root dialect must NOT become 'any dict is a search answer': a body without
    the count fields is a protocol break, read as zero records only by the bug §0.7
    exists to stop."""
    with pytest.raises(SearchProtocolError, match="no count fields"):
        response_envelope({"somethingElse": True}, "", search_id="cap")


def test_fd_search_walks_captured_root_dialect_to_zero_page() -> None:
    """A full walk on the CAPTURED dialect: one row page, then the honest zero page
    (record key absent) terminates it — exactly what the real device answered."""
    reader, _sent = scripted(CAPTURED_FD_ROW, CAPTURED_FD_ZERO)
    engine = fd_search(reader, sleep=no_sleep, inter_page_delay=0.0)
    pages = list(engine.pages({"faceLibType": "blackFD", "FDID": "1"}))
    assert [r["FPID"] for p in pages for r in p.records] == ["1"]
    assert engine.summary is not None
    assert engine.summary.pages == 2
    assert engine.summary.termination == "NOMATCH"


# --- AcsEvent windows: chunking, ordering, serial checkpoints ----------------------------


def test_chunk_window_splits_by_default_one_day_and_is_chronological() -> None:
    since = parse_user_timestamp("2026-10-10T00:00:00", site_tz=SITE_TZ)
    until = parse_user_timestamp("2026-10-13T00:00:00", site_tz=SITE_TZ)
    chunks = list(chunk_window(since, until))
    assert len(chunks) == 3, "default --chunk is 1d"
    assert chunks[0][0] < chunks[0][1] == chunks[1][0] < chunks[1][1] == chunks[2][0]
    assert chunks[2][1] == until.value
    assert parse_chunk("1d") == timedelta(days=1)
    assert parse_chunk("12h") == timedelta(hours=12)
    assert parse_chunk(timedelta(hours=6)) == timedelta(hours=6)
    with pytest.raises(TimestampInputError):
        parse_chunk("0d")
    with pytest.raises(TimestampInputError):
        parse_chunk("banana")


def test_iter_event_windows_pages_inside_each_chunk_with_fresh_ids_and_bounds() -> None:
    since = parse_user_timestamp("2026-10-11T00:00:00", site_tz=SITE_TZ)
    until = parse_user_timestamp("2026-10-13T00:00:00", site_tz=SITE_TZ)  # -> 2 chunks
    reader, sent = scripted(
        event_envelope(
            searchID="i",
            responseStatusStrg="MORE",
            numOfMatches=2,
            totalMatches=3,
            InfoList=[{"serialNo": 40}, {"serialNo": 41}],
        ),
        event_envelope(
            searchID="i",
            responseStatusStrg="OK",
            numOfMatches=1,
            totalMatches=3,
            InfoList=[{"serialNo": 42}],
        ),
        event_envelope(
            searchID="i",
            responseStatusStrg="MORE",
            numOfMatches=2,
            totalMatches=2,
            InfoList=[{"serialNo": 90}, {"serialNo": 91}],
        ),
        event_envelope(
            searchID="i",
            responseStatusStrg="OK",
            numOfMatches=1,
            totalMatches=2,
            InfoList=[{"serialNo": 95}],
        ),
    )
    chunks = list(
        iter_event_windows(
            reader,
            since=since,
            until=until,
            chunk="1d",
            inter_page_delay=0.0,
            sleep=no_sleep,
        )
    )
    assert len(chunks) == 2 and all(isinstance(c, ChunkResult) for c in chunks)
    first, second = chunks
    assert [c["AcsEventCond"]["startTime"] for c in sent] == [
        "2026-10-11T00:00:00+03:00",
        "2026-10-11T00:00:00+03:00",
        "2026-10-12T00:00:00+03:00",
        "2026-10-12T00:00:00+03:00",
    ], "every request carries offset-bearing bounds; paging happens INSIDE each chunk"
    assert first.search_id != second.search_id, "new chunk = new logical search = fresh searchID"
    assert [c.max_serial_no for c in chunks] == [42, 95]
    assert [c.pages for c in chunks] == [2, 2]
    assert [len(c.records) for c in chunks] == [3, 3]


def test_runaway_in_a_chunk_never_advances_the_checkpoint() -> None:
    """A chunk that raises must not yield: max() over COMPLETED chunks can only
    cover ground the walk actually finished, or the next run skips its events."""
    since = parse_user_timestamp("2026-10-11T00:00:00", site_tz=SITE_TZ)
    until = parse_user_timestamp("2026-10-13T00:00:00", site_tz=SITE_TZ)
    reader, _sent = scripted(
        event_envelope(
            searchID="i", responseStatusStrg="MORE", numOfMatches=1, InfoList=[{"serialNo": 7}]
        ),
        event_envelope(
            searchID="i", responseStatusStrg="MORE", numOfMatches=1, InfoList=[{"serialNo": 8}]
        ),
    )  # MORE forever
    with pytest.raises(SearchRunawayError):
        list(
            iter_event_windows(
                reader,
                since=since,
                until=until,
                chunk="1d",
                max_pages=2,
                inter_page_delay=0.0,
                sleep=no_sleep,
            )
        )
    # list() raised before collecting any ChunkResult: the failed chunk yielded nothing.


def test_time_reverse_order_and_serial_range_pass_through_verbatim() -> None:
    cond = build_event_cond(
        _window("2026-10-12T00:00:00", "2026-10-12T23:59:59"),
        begin_serial_no=27,
        end_serial_no=5753,
        time_reverse_order=True,
    )
    assert cond["beginSerialNo"] == 27 and cond["endSerialNo"] == 5753
    assert cond["timeReverseOrder"] is True, "device honours newest-first (OBSERVED.md)"
    cond_default = build_event_cond(_window("2026-10-12T00:00:00", "2026-10-12T23:59:59"))
    assert "timeReverseOrder" not in cond_default, "oldest-first backfill is the default (no key)"


def test_employee_filter_uses_employee_no_string_never_bare() -> None:
    cond = build_event_cond(_window("2026-10-12T00:00:00", "2026-10-12T23:59:59"), employee_no="7")
    assert cond["employeeNoString"] == "7"
    assert "employeeNo" not in cond, (
        "bare employeeNo is SILENTLY IGNORED on this fw (OBSERVED.md) — using it "
        "would return everyone and look like filtered data"
    )


def test_pic_enable_is_never_sent() -> None:
    with pytest.raises(SearchProtocolError, match="picEnable"):
        build_event_cond(
            _window("2026-10-12T00:00:00", "2026-10-12T23:59:59"),
            extra={"picEnable": True},
        )


def test_major_minor_are_sent_and_default_to_all() -> None:
    cond = build_event_cond(
        _window("2026-10-12T00:00:00", "2026-10-12T23:59:59"), major=5, minor=75
    )
    assert cond["major"] == 5 and cond["minor"] == 75
    cond_all = build_event_cond(_window("2026-10-12T00:00:00", "2026-10-12T23:59:59"))
    assert cond_all["major"] == 0 and cond_all["minor"] == 0, "0 = all (vendor semantics, decimal)"


# --- inter-page pacing -------------------------------------------------------------------


def test_inter_page_delay_defaults_to_100ms_net_of_request_time() -> None:
    """Card: default 100 ms (small box, serial sessions). The injected clock shows
    the pacing spaces request STARTS by 100 ms: a page that took 40 ms leaves a
    60 ms sleep, not 100 — and there is no sleep before the first page."""

    class Clock:
        def __init__(self) -> None:
            self.t = 1000.0

        def now(self) -> float:
            return self.t

        def advance(self, seconds: float) -> None:
            self.t += seconds

    clock = Clock()
    sleeps: list[float] = []
    state = {"requests": 0}

    def sleep(seconds: float) -> None:
        sleeps.append(seconds)
        clock.advance(seconds)

    def reader(body: Mapping[str, Any]) -> dict[str, Any]:
        state["requests"] += 1
        clock.advance(0.04)  # each request "takes" 40 ms
        if state["requests"] <= 2:
            return event_envelope(
                searchID="s",
                responseStatusStrg="MORE",
                numOfMatches=1,
                InfoList=[{"a": state["requests"]}],
            )
        return event_envelope(
            searchID="s", responseStatusStrg="OK", numOfMatches=1, InfoList=[{"a": 9}]
        )

    engine = acs_event_search(
        reader, inter_page_delay=DEFAULT_INTER_PAGE_DELAY, sleep=sleep, clock=clock.now
    )
    list(engine.pages({}))
    assert state["requests"] == 3
    assert len(sleeps) == 2, "3 pages -> 2 gaps, none before page 1"
    assert sleeps == [pytest.approx(0.06), pytest.approx(0.06)], (
        f"expected 100 ms - 40 ms request time, got {sleeps}"
    )


def test_zero_delay_sleeps_never() -> None:
    reader, _ = scripted(
        event_envelope(
            searchID="s", responseStatusStrg="MORE", numOfMatches=1, InfoList=[{"a": 1}]
        ),
        event_envelope(searchID="s", responseStatusStrg="OK", numOfMatches=1, InfoList=[{"a": 2}]),
    )
    sleeps: list[float] = []
    engine = acs_event_search(reader, inter_page_delay=0.0, sleep=sleeps.append)
    list(engine.pages({}))
    assert sleeps == []


def test_chunk_boundary_is_paced_like_an_inter_page_gap() -> None:
    """The delay is between REQUESTS, not between walks: with one engine across two
    chunks (iter_event_windows reuses it), the first page of chunk 2 must still be
    spaced after the last page of chunk 1 — the device sees a serial, paced stream."""
    since = parse_user_timestamp("2026-10-11T00:00:00", site_tz=SITE_TZ)
    until = parse_user_timestamp("2026-10-13T00:00:00", site_tz=SITE_TZ)  # 2 chunks
    reader, _sent = scripted(
        event_envelope(
            searchID="i", responseStatusStrg="OK", numOfMatches=1, InfoList=[{"serialNo": 1}]
        ),
        event_envelope(
            searchID="i", responseStatusStrg="OK", numOfMatches=1, InfoList=[{"serialNo": 2}]
        ),
    )
    sleeps: list[float] = []
    list(
        iter_event_windows(
            reader,
            since=since,
            until=until,
            chunk="1d",
            inter_page_delay=0.1,
            sleep=sleeps.append,
        )
    )
    assert len(sleeps) == 1, "no sleep before the first request; exactly one at the chunk boundary"
    # Upper bound 0.1 (delay cap); lower bound generous because the default real
    # monotonic clock counts the microseconds the generator itself spent between
    # the two request starts (the delay is net of ALL work between requests).
    assert 0.05 < sleeps[0] <= 0.1, f"expected a ~full 100 ms gap, got {sleeps}"


# --- UserInfo side (same engine) + count cross-check -------------------------------------


def test_user_info_walk_over_golden_fixture() -> None:
    """user_search_page1.json is the recorded real body: envelope key
    UserInfoSearch, record key UserInfo — same engine, different table (card)."""
    body = load_fixture("user_search_page1.json")
    reader, sent = scripted(body)
    users = list(iter_users(reader, inter_page_delay=0.0, sleep=no_sleep))
    assert [u["employeeNo"] for u in users] == ["1", "2", "3", "4"]
    cond = sent[0]["UserInfoSearchCond"]
    assert {"searchID", "searchResultPosition", "maxResults"} <= set(cond)
    assert cond["searchResultPosition"] == 0


def test_user_paging_across_two_pages_and_count_cross_check_advisory() -> None:
    fixture_users = load_fixture("user_search_page1.json")["UserInfoSearch"]["UserInfo"]
    page1 = {
        "UserInfoSearch": {
            "searchID": "u",
            "responseStatusStrg": "MORE",
            "numOfMatches": 2,
            "totalMatches": 4,
            "UserInfo": fixture_users[:2],
        }
    }
    page2 = {
        "UserInfoSearch": {
            "searchID": "u",
            "responseStatusStrg": "OK",
            "numOfMatches": 2,
            "totalMatches": 4,
            "UserInfo": fixture_users[2:],
        }
    }
    reader, _sent = scripted(page1, page2)
    count_body = load_fixture("user_count.json")
    result = collect_users(
        reader, count_get=lambda: count_body, inter_page_delay=0.0, sleep=no_sleep
    )
    assert len(result.users) == 4
    assert result.pages == 2
    assert result.device_count == 4 and result.count_matches is True


def test_count_mismatch_warns_not_fails() -> None:
    """Card: UserInfo/Count is a post-pull SANITY CHECK — mismatch must not raise;
    the roster is the data, the count is advisory (the roster can change between)."""
    body = load_fixture("user_search_page1.json")
    reader, _ = scripted(body)
    result = collect_users(
        reader,
        count_get=lambda: {"UserInfoCount": {"userNumber": 5}},  # device says 5, we got 4
        inter_page_delay=0.0,
        sleep=no_sleep,
    )
    assert result.count_matches is False, "flagged, surfaced"
    assert len(result.users) == 4, "and the data still stands — no exception"


def test_count_shape_drift_is_coerced_or_loud() -> None:
    """OBSERVED.md warns the count shape drifts (int-vs-string). Numeric strings
    coerce; garbage raises — a broken count must never read as zero."""
    body = load_fixture("user_search_page1.json")
    reader, _ = scripted(body)
    result = collect_users(
        reader,
        count_get=lambda: {"UserInfoCount": {"userNumber": "4"}},
        inter_page_delay=0.0,
        sleep=no_sleep,
    )
    assert result.count_matches is True

    reader2, _ = scripted(body)
    with pytest.raises(SearchProtocolError, match="not numeric"):
        collect_users(
            reader2,
            count_get=lambda: {"UserInfoCount": {"userNumber": "four"}},
            inter_page_delay=0.0,
            sleep=no_sleep,
        )


# --- protocol breaks are loud, never empty ------------------------------------------------


def test_missing_root_key_raises_protocol_error_not_empty_result() -> None:
    """A body without the AcsEvent envelope means the device broke protocol. The
    EMPTY-window shape keeps the root key and drops only InfoList (OBSERVED.md),
    so reading rootless as 'zero records' would fabricate 'nobody clocked in'."""
    reader, _ = scripted({"unexpected": {"responseStatusStrg": "OK"}})
    with pytest.raises(SearchProtocolError, match="no 'AcsEvent'"):
        list(make_engine(reader).pages({}))


def test_non_numeric_counts_raise_rather_than_read_as_zero() -> None:
    reader, _ = scripted(
        event_envelope(
            searchID="s", responseStatusStrg="MORE", numOfMatches="lots", InfoList=[{"a": 1}]
        ),
    )
    with pytest.raises(SearchProtocolError, match="numOfMatches"):
        list(make_engine(reader).pages({}))


# --- end-to-end through the REAL transport (digest session reuse) --------------------------


def make_client(device: FakeDevice) -> IsapiClient:
    return IsapiClient(BASE_URL, "admin", PASSWORD, transport=device.transport, sleep=no_sleep)


def _json(payload: dict[str, Any]) -> httpx.Response:
    return httpx.Response(200, json=payload)


def test_walk_rides_one_digest_session_across_all_pages() -> None:
    """The engine reuses ONE IsapiClient for the whole walk, so the 401 is paid
    exactly once for 3 pages (card p1-03: digest state is per-session; re-authing
    per page is both slow and lockout-adjacent)."""
    device = FakeDevice()
    device.add(
        "POST",
        EVENT_PATH,
        _json(
            event_envelope(
                searchID="s",
                responseStatusStrg="MORE",
                numOfMatches=2,
                totalMatches=5,
                InfoList=[{"serialNo": 1}, {"serialNo": 2}],
            )
        ),
        _json(
            event_envelope(
                searchID="s",
                responseStatusStrg="MORE",
                numOfMatches=2,
                totalMatches=5,
                InfoList=[{"serialNo": 3}, {"serialNo": 4}],
            )
        ),
        _json(
            event_envelope(
                searchID="s",
                responseStatusStrg="OK",
                numOfMatches=1,
                totalMatches=5,
                InfoList=[{"serialNo": 5}],
            )
        ),
    )
    client = make_client(device)
    engine = make_engine(lambda body: client.search("acs_event_search", body))
    all_records = engine.collect({})
    assert [r["serialNo"] for r in all_records] == [1, 2, 3, 4, 5]
    assert device.challenges == 1, "three pages, one 401 — one authenticated session"
    posts = [s for s in device.served if s.method == "POST"]
    assert len(posts) == 4, "1 challenge round + 3 pages = 4 POST requests on the wire"


def test_walk_over_recorded_noise_fixture_then_ok_page() -> None:
    """Golden-pair walk: the device's recorded MORE page (major=3 noise — 3 records
    on this capture, numOfMatches=3, totalMatches 10130) followed by an OK page,
    via the real client. Positions must follow the fixture's own numOfMatches."""
    device = FakeDevice()
    noise_page = load_fixture("events_more_noise_page1.json")
    noise = noise_page["AcsEvent"]
    assert noise["responseStatusStrg"] == "MORE"  # fixture sanity
    device.add(
        "POST",
        EVENT_PATH,
        _json(noise_page),
        _json(
            event_envelope(
                searchID="s",
                responseStatusStrg="OK",
                numOfMatches=2,
                totalMatches=32,
                InfoList=[{"serialNo": 5742}, {"serialNo": 5743}],
            )
        ),
    )
    client = make_client(device)
    engine = make_engine(lambda body: client.search("acs_event_search", body))
    pages = list(engine.pages({}, search_id="golden-walk"))
    assert [p.position for p in pages] == [0, noise["numOfMatches"]], (
        "second page starts exactly where the fixture's own numOfMatches says"
    )
    assert len(pages[0].records) == len(noise["InfoList"])
    assert pages[0].total_matches == 10130, "advisory value kept for display"
    assert engine.summary is not None
    assert engine.summary.records == len(pages[0].records) + 2
