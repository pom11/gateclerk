"""P1-05c: event-window labels must carry the DEVICE's claimed offset (payroll-critical).

The A/B this file replays is recorded in docs/internal/OBSERVED.md ("Window offsets are
ARITHMETIC for the device", owner run 2026-10-17, dense day 2026-05-21):

    startTime 13:00:00+03:00, endTime 14:30:00+03:00  -> "NO MATCH", totalMatches 0
    startTime 13:00:00+02:00, endTime 14:30:00+02:00  -> "OK", totalMatches 20

Same digits, same window, opposite answers: the device converts each label to an
instant and back onto its own (mis-stamped) clock, so a `+03:00`-labeled window
arrives one hour EARLY in device terms all summer and boundary punches vanish
silently. The correct shape is site-wall digits labeled with the device's claimed
offset (this fw reports +02:00 year-round); the offset stays REQUIRED on the wire
(the naive 400 from p1-05b stands — nothing here relaxes it).

FakeDevice carries the anti-false-green property (fakedevice.py, "the event store
filters by ARITHMETIC"): a fake that merely required an offset's *presence* would
serve the same pages under both labels and every assertion below would pass on the
broken code. It is seeded with the recorded pattern and filters like the device.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import httpx
import pytest
from typer.testing import CliRunner

from fakedevice import BASE_URL, FakeDevice
from gateclerk.exceptions import IsapiBadContent
from gateclerk.isapi_transport import IsapiClient
from gateclerk.paging import (
    build_event_cond,
    iter_event_windows,
)
from gateclerk.pipeline import (
    RequestLogger,
    compile_run_context,
    device_window_labels,
    event_total_count,
    fetch_events,
)
from gateclerk.tz import (
    parse_user_timestamp,
    window_for_device,
)

SITE_TZ = "Europe/Bucharest"
PASSWORD = "fakepw"  # hygiene placeholder (tests/test_repo_hygiene.py)

#: What site-a claims year-round (OBSERVED.md "time/offset bug" + the A/B).
DEVICE_CLAIM = 120

#: The A/B window: 2026-05-21 13:00-14:30 site wall (Bucharest summer = +03:00).
WINDOW_SINCE = datetime(2026, 5, 21, 13, 0, tzinfo=timezone(timedelta(hours=3)))
WINDOW_UNTIL = datetime(2026, 5, 21, 14, 30, tzinfo=timezone(timedelta(hours=3)))

EVENT_PATH = "/ISAPI/AccessControl/AcsEvent?format=json"
TOTAL_NUM_PATH = "/ISAPI/AccessControl/AcsEventTotalNum?format=json"
SYSTEM_TIME_PATH = "/ISAPI/System/time?format=json"
DEVICE_INFO_PATH = "/ISAPI/System/deviceInfo?format=json"
ACS_CAPS_PATH = "/ISAPI/AccessControl/AcsEvent/capabilities?format=json"
AC_CAPS_PATH = "/ISAPI/AccessControl/capabilities?format=json"


def _device_event(serial: int, wall: str, *, major: int = 5, minor: int = 0) -> dict[str, Any]:
    """One stored event, stamped the way site-a stamps: wall digits + ITS claimed +02:00."""
    return {
        "serialNo": serial,
        "employeeNoString": "1",
        "major": major,
        "minor": minor,
        "time": f"{wall}+02:00",
    }


def dense_ab_events() -> list[dict[str, Any]]:
    """The recorded dense pattern: 20 punches inside device wall 14:08-14:20 (serials 28..47).

    Strictly increasing in wall time (36 s steps from 14:08:00), because on the real
    box serialNo counts events in arrival order (OBSERVED.md) — a seed whose serials
    and wall digits disagreed on order would make the fake's chronological sort
    contradict the walk's page order for a reason the device could not produce.
    """
    events = []
    for i in range(20):
        minute, second = divmod(8 * 60 + i * 36, 60)
        events.append(_device_event(28 + i, f"2026-05-21T14:{minute:02d}:{second:02d}"))
    return events


def ab_device(**kw: Any) -> FakeDevice:
    device = FakeDevice(password=PASSWORD)
    device.claimed_offset_min = kw.pop("claimed", DEVICE_CLAIM)
    device.add_events(*dense_ab_events())
    return device


def make_client(device: FakeDevice) -> IsapiClient:
    return IsapiClient(
        BASE_URL, "admin", PASSWORD, transport=device.transport, sleep=lambda _s: None
    )


def walk(device: FakeDevice, **kw: Any) -> tuple[list[int], str]:
    """One logical walk of the A/B window; returns (serials, termination of the walk)."""
    client = make_client(device)
    kw.setdefault("since", WINDOW_SINCE)
    kw.setdefault("until", WINDOW_UNTIL)
    serials: list[int] = []
    termination = "?"
    for chunk in iter_event_windows(
        lambda body: client.search("acs_event_search", body),
        chunk="2h",
        site_tz=SITE_TZ,
        inter_page_delay=0.0,
        sleep=lambda _s: None,
        **kw,
    ):
        serials.extend(int(r["serialNo"]) for r in chunk.records)
        termination = chunk.termination
    return serials, termination


def event_cond(device: FakeDevice, path: str = EVENT_PATH) -> dict[str, Any]:
    posts = [s for s in device.served if s.path == path]
    assert posts, f"no POST reached {path}"
    key = "AcsEventCond" if path == EVENT_PATH else "AcsEventTotalNumCond"
    return json.loads(posts[0].body)[key]


# --- the pair on the struct (tz.py) -------------------------------------------------------


def _site_window(since: str, until: str):
    a = parse_user_timestamp(since, site_tz=SITE_TZ)
    b = parse_user_timestamp(until, site_tz=SITE_TZ)
    return window_for_device(a, b, site_tz=SITE_TZ)


def test_claimed_label_pair_relabeled_digits_only() -> None:
    """Site-wall digits survive verbatim; ONLY the trailing label changes (the card rule)."""
    w = _site_window("2026-05-21T13:00:00", "2026-05-21T14:30:00")
    assert w.since_site_iso == "2026-05-21T13:00:00+03:00"
    relabeled = w.search_pair(device_offset_min=DEVICE_CLAIM)
    assert relabeled == ("2026-05-21T13:00:00+02:00", "2026-05-21T14:30:00+02:00")
    # The two existing pairs stay reachable for callers + audit (the card's "keep both").
    assert w.search_pair() == (w.since_device_local, w.until_device_local)
    assert w.search_pair(with_offset=True) == (w.since_site_iso, w.until_site_iso)


def test_claimed_label_pair_handles_negative_and_zero_claims() -> None:
    w = _site_window("2026-05-21T13:00:00", "2026-05-21T14:30:00")
    assert w.search_pair(device_offset_min=-330) == (
        "2026-05-21T13:00:00-05:30",
        "2026-05-21T14:30:00-05:30",
    )
    assert w.search_pair(device_offset_min=0)[0].endswith("+00:00")


def test_claimed_label_pair_refuses_an_impossible_claim() -> None:
    """A claim outside ±23:59 is a code/parse bug; it must raise, not label `+99:99`."""
    w = _site_window("2026-05-21T13:00:00", "2026-05-21T14:30:00")
    with pytest.raises(ValueError, match="offset"):
        w.search_pair(device_offset_min=99 * 60 + 99)


# --- cond building (paging.py) -------------------------------------------------------------


def test_build_event_cond_uses_the_claimed_label_when_given() -> None:
    cond = build_event_cond(
        _site_window("2026-05-21T13:00:00", "2026-05-21T14:30:00"),
        device_offset_min=DEVICE_CLAIM,
    )
    assert cond["startTime"] == "2026-05-21T13:00:00+02:00"
    assert cond["endTime"] == "2026-05-21T14:30:00+02:00"


def test_build_event_cond_falls_back_to_the_site_label_without_a_claim() -> None:
    """None means "we do not know" — keep the p1-05b site-labeled pair, never naive."""
    cond = build_event_cond(_site_window("2026-05-21T13:00:00", "2026-05-21T14:30:00"))
    assert cond["startTime"] == "2026-05-21T13:00:00+03:00"
    assert cond["endTime"] == "2026-05-21T14:30:00+03:00"


# --- THE regression test: the recorded A/B, replayed against the fake --------------------


def test_ab_replica_site_labeled_window_finds_nothing_claimed_labeled_finds_all() -> None:
    """Exactly the OBSERVED.md table: same digits, `+03:00` -> NO MATCH/0, `+02:00` -> OK/20.

    The fake filters by arithmetic (label -> instant -> ITS clock), like the device —
    a presence-only fake would serve all 20 records under BOTH labels and this test
    would pass on the broken code. That lenience is the false-green this card exists
    to remove.
    """
    d_site = ab_device()
    site_labeled, term_site = walk(d_site, device_offset_min=None)
    assert site_labeled == []
    assert term_site == "NOMATCH"
    assert event_cond(d_site)["startTime"].endswith("+03:00")

    d_claim = ab_device()
    claimed_labeled, term_claimed = walk(d_claim, device_offset_min=DEVICE_CLAIM)
    assert claimed_labeled == list(range(28, 48)), "all 20 dense-day punches"
    assert term_claimed == "OK"
    assert event_cond(d_claim)["startTime"].endswith("+02:00")


def test_boundary_event_is_lost_by_the_site_label_and_kept_by_the_claimed_label() -> None:
    """The silent-hour pin: an event at device wall 14:00 and one exactly at the 14:30 edge.

    `+03:00`-labeled, the window lands on device wall 12:00-13:30 — both events are
    outside and nothing says so (NO MATCH looks like an empty window). `+02:00`-labeled
    it lands on 13:00-14:30 (inclusive ends, OBSERVED.md) and both arrive. This is the
    payroll loss class, pinned in both directions.
    """
    events = [
        _device_event(101, "2026-05-21T14:00:00"),  # inside the lost hour
        _device_event(102, "2026-05-21T14:30:00"),  # exactly the shifted edge
    ]

    def device() -> FakeDevice:
        d = FakeDevice(password=PASSWORD)
        d.add_events(*events)
        return d

    lost, _ = walk(device(), device_offset_min=None)
    assert lost == [], "the +03:00 label shifts the whole window an hour early in device terms"
    kept, _ = walk(device(), device_offset_min=DEVICE_CLAIM)
    assert kept == [101, 102]


def test_winter_agreement_site_label_equals_claimed_label() -> None:
    """December: the site zone IS +02:00 and the device claims +02:00 — both shapes are
    byte-identical and both find the events (no double shift; the fix is a no-op in winter).
    """
    winter_since = datetime(2026, 12, 10, 12, 0, tzinfo=timezone(timedelta(hours=2)))
    winter_until = winter_since + timedelta(hours=1)
    d_site = FakeDevice(password=PASSWORD)
    d_site.add_events(_device_event(201, "2026-12-10T12:30:00"))
    d_claim = FakeDevice(password=PASSWORD)
    d_claim.add_events(_device_event(201, "2026-12-10T12:30:00"))

    site_serials, _ = walk(d_site, since=winter_since, until=winter_until, device_offset_min=None)
    claim_serials, _ = walk(
        d_claim, since=winter_since, until=winter_until, device_offset_min=DEVICE_CLAIM
    )
    assert site_serials == claim_serials == [201]
    assert event_cond(d_site)["startTime"] == event_cond(d_claim)["startTime"]


def test_fake_claim_is_configurable_other_devices_shift_otherwise() -> None:
    """A box claiming UTC (+00:00) interprets the digits literally: the claimed label is
    `+00:00`, the window keeps its digits, and the site `+03:00` label loses everything.
    """
    utc_claim = ab_device(claimed=0)
    site_labeled, _ = walk(utc_claim, device_offset_min=None)
    assert site_labeled == [], "+03:00 lands 3 h early on a UTC-claiming box"
    d = ab_device(claimed=0)
    kept, _ = walk(d, device_offset_min=0)
    assert kept == list(range(28, 48))
    assert event_cond(d)["startTime"].endswith("+00:00")


# --- the count probe shares the walk's labels (no split-brain) ----------------------------


def test_count_probe_uses_the_same_labels_as_the_walk() -> None:
    """Same window, same label on both POSTs, and the count agrees with the walk."""
    device = ab_device()
    client = make_client(device)
    serials, _ = walk(device, device_offset_min=DEVICE_CLAIM)
    count = event_total_count(
        client,
        since=parse_user_timestamp("2026-05-21T13:00:00", site_tz=SITE_TZ),
        until=parse_user_timestamp("2026-05-21T14:30:00", site_tz=SITE_TZ),
        site_tz=SITE_TZ,
        device_offset_min=DEVICE_CLAIM,
    )
    assert count == len(serials) == 20
    walk_start = event_cond(device, EVENT_PATH)["startTime"]
    count_start = event_cond(device, TOTAL_NUM_PATH)["startTime"]
    assert walk_start == count_start == "2026-05-21T13:00:00+02:00"


def test_count_probe_falls_back_with_the_walk() -> None:
    """No claim -> both paths site-labeled; the fake's arithmetic answers 0 honestly."""
    device = ab_device()
    client = make_client(device)
    walk(device, device_offset_min=None)
    count = event_total_count(
        client,
        since=parse_user_timestamp("2026-05-21T13:00:00", site_tz=SITE_TZ),
        until=parse_user_timestamp("2026-05-21T14:30:00", site_tz=SITE_TZ),
        site_tz=SITE_TZ,
    )
    assert count == 0
    assert event_cond(device, TOTAL_NUM_PATH)["startTime"].endswith("+03:00")


# --- the pipeline read: one GET, and the honest fallback ----------------------------------


SYSTEM_TIME_XML = (
    '<?xml version="1.0" encoding="UTF-8"?>\r\n'
    '<Time version="2.0" xmlns="http://www.isapi.org/ver20/XMLSchema">\r\n'
    "<timeMode>NTP</timeMode>\r\n"
    "<localTime>2026-05-21T16:39:32+02:00</localTime>\r\n"
    "<timeZone>CST-2:00:00DST01:00:00,M3.4.1/00:00:00,M10.5.0/23:00:00</timeZone>\r\n"
    "</Time>"
)


def seeded_device(*, system_time: str = SYSTEM_TIME_XML) -> FakeDevice:
    device = ab_device()
    device.xml_ok("GET", SYSTEM_TIME_PATH, system_time)
    return device


def test_device_window_labels_reads_the_claim_from_one_system_time_get() -> None:
    device = seeded_device()
    labels = device_window_labels(make_client(device))
    assert labels.claimed_offset_min == DEVICE_CLAIM
    assert labels.note is None
    # `had_auth` filters the digest handshake's unauthenticated first hit: the pin is
    # ONE logical GET per run, and the transport's challenge-replay is its own thing.
    reads = [s for s in device.served if s.path == SYSTEM_TIME_PATH and s.had_auth]
    assert len(reads) == 1, "one cheap GET per run, never per chunk"


def test_device_window_labels_survives_an_unreadable_clock_without_inventing_one() -> None:
    """A System/time with no parseable offset is reported, not guessed (card: do NOT invent)."""
    device = seeded_device(
        system_time=SYSTEM_TIME_XML.replace("+02:00</localTime>", "</localTime>")
    )
    labels = device_window_labels(make_client(device))
    assert labels.claimed_offset_min is None
    assert labels.note is not None, "the fallback must be able to say WHY there is no claim"


def test_fetch_events_warns_loudly_when_falling_back_and_never_goes_naive() -> None:
    """Fallback pin: site-labeled pair + a visible warning line; the wire stays offset-bearing.

    The fake would 400 a naive bound exactly like the device (p1-05b stays), so the
    'never naive' half of this assertion is enforced twice on purpose.
    """
    device = seeded_device()
    client = make_client(device)
    logger = RequestLogger()
    context = compile_run_context(logger=logger).with_logger(logger)
    context = context.with_device_claim(None)
    list(
        fetch_events(
            client,
            since=parse_user_timestamp("2026-05-21T13:00:00", site_tz=SITE_TZ),
            until=parse_user_timestamp("2026-05-21T14:30:00", site_tz=SITE_TZ),
            context=context,
            device_serial="MASKED-SER-1",
            chunk="2h",
        )
    )
    warning = [line for line in logger.lines if "device arithmetic" in line]
    assert warning, "the no-claim fallback must surface a visible warning line"
    assert "device time unreadable" in warning[0]
    cond = event_cond(device)
    assert cond["startTime"].endswith("+03:00"), "site-labeled, never naive"


def test_fetch_events_threads_the_claim_into_every_chunk_label() -> None:
    device = seeded_device()
    client = make_client(device)
    context = compile_run_context().with_device_claim(DEVICE_CLAIM)
    list(
        fetch_events(
            client,
            since=parse_user_timestamp("2026-05-21T13:00:00", site_tz=SITE_TZ),
            until=parse_user_timestamp("2026-05-21T14:30:00", site_tz=SITE_TZ),
            context=context,
            device_serial="MASKED-SER-1",
            chunk="1h",
        )
    )
    posts = [s for s in device.served if s.path == EVENT_PATH]
    assert posts, "the walk reached the device"
    for served in posts:
        cond = json.loads(served.body)["AcsEventCond"]
        assert cond["startTime"].endswith("+02:00"), (
            f"chunked walk must relabel EVERY window, got {cond['startTime']}"
        )


def test_naive_bounds_are_still_rejected_by_the_fake() -> None:
    """p1-05b stays: the naive-400 arm is alive even with the arithmetic store installed."""
    device = seeded_device()
    client = make_client(device)
    with pytest.raises(IsapiBadContent) as excinfo:
        client.search(
            "acs_event_search",
            {
                "AcsEventCond": {
                    "searchID": "p1-05c-naive",
                    "searchResultPosition": 0,
                    "maxResults": 30,
                    "startTime": "2026-05-21T13:00:00",
                    "endTime": "2026-05-21T14:30:00",
                    "major": 0,
                    "minor": 0,
                }
            },
        )
    assert excinfo.value.envelope.get("subStatusCode") == "badJsonContent"
    assert excinfo.value.envelope.get("errorMsg") == "startTime"


# --- the CLI run: claim read once for a MULTI-chunk walk ---------------------------------


def test_cli_events_run_reads_the_claim_once_across_all_chunks(monkeypatch) -> None:
    """The card's "one per run, not per chunk" rule, pinned on the whole CLI path.

    A 1h chunk over the 1.5 h window walks TWO chunks; the System/time GET must
    still be a single authorized request for the whole command (the digest
    handshake's unauthenticated probe is the transport's, not a second read). A
    per-chunk read would double the request load on the box that already caps
    digest nonces near 190 uses (OBSERVED.md) — for an answer that cannot change
    mid-walk.
    """
    import gateclerk.cli as cli_mod
    from gateclerk.isapi_transport import IsapiClient as RealClient

    device = seeded_device()
    runner = CliRunner()
    real = RealClient

    def factory(base_url: str, user: str, password: str, **kw: Any) -> IsapiClient:
        return real(base_url, user, password, transport=device.transport, sleep=lambda _s: None)

    from gateclerk import cli_shared

    monkeypatch.setattr(cli_shared, "IsapiClient", factory)
    from gateclerk.capabilities import capability_cache

    capability_cache().clear()
    # The CLI's other reads need answers: identity + both capability endpoints ride
    # the same recorded bodies the p1-08 CLI suite serves, from the same fixtures.
    recorded = Path(__file__).parent / "fixtures/recorded/site-a-ds-k1t341amf-s"
    synth = Path(__file__).parent / "fixtures/synthetic"
    device.xml_ok("GET", DEVICE_INFO_PATH, (recorded / "device_info.xml").read_text("utf-8"))
    device.add(
        "GET",
        ACS_CAPS_PATH,
        httpx.Response(200, content=(recorded / "acs_capabilities.json").read_bytes()),
    )
    device.add(
        "GET",
        AC_CAPS_PATH,
        httpx.Response(
            200, json=json.loads((synth / "access_control_capabilities.json").read_text("utf-8"))
        ),
    )
    result = runner.invoke(
        cli_mod.app,
        [
            "events",
            "--host",
            "192.0.2.10",
            "--user",
            "admin",
            "--password",
            PASSWORD,
            "--since",
            "2026-05-21T13:00:00",
            "--until",
            "2026-05-21T14:30:00",
            "--chunk",
            "1h",
            "--format",
            "jsonl",
        ],
    )
    assert result.exit_code == 0, result.stdout
    reads = [s for s in device.served if s.path == SYSTEM_TIME_PATH and s.had_auth]
    assert len(reads) == 1, "one System/time read per RUN, never per chunk"
    posts = [json.loads(s.body)["AcsEventCond"] for s in device.served if s.path == EVENT_PATH]
    assert len(posts) == 2, "the 1h chunk really walked two chunks (the scenario must bite)"
    for cond in posts:
        assert cond["startTime"].endswith("+02:00") and cond["endTime"].endswith("+02:00")
