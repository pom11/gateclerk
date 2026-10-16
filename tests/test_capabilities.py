"""Capability discovery: JSON->limits, clamping, XML fallback, cache (card p1-04 DoD).

Every claim these tests make is pinned to a fixture or to docs/OBSERVED.md — the device
truth the card implements against. All offline: the only "device" here is FakeDevice.
"""

from __future__ import annotations

import json
from pathlib import Path

import httpx
import pytest

from fakedevice import BASE_URL, FakeDevice
from gateclerk.capabilities import (
    DEFAULT_MAX_RESULTS,
    DEFAULT_SEARCH_ID_MAX,
    CapabilityCache,
    CapabilityDiscoveryError,
    DeviceCapabilities,
    device_identity,
    discover,
    parse_access_control_capabilities,
    parse_acs_event_capabilities,
)
from gateclerk.isapi_transport import IsapiClient

RECORDED = Path(__file__).parent / "fixtures/recorded/site-a-ds-k1t341amf-s"
SYNTH = Path(__file__).parent / "fixtures/synthetic"

CAPS_PATH = "/ISAPI/AccessControl/AcsEvent/capabilities?format=json"
AC_CAPS_PATH = "/ISAPI/AccessControl/capabilities?format=json"
DEVICE_INFO_PATH = "/ISAPI/System/deviceInfo?format=json"
PASSWORD = "fakepw"


def recorded_caps_json() -> bytes:
    return (RECORDED / "acs_capabilities.json").read_bytes()


def caps_device(
    caps_body: bytes | str,
    *,
    caps_content_type: str = "application/json",
    with_ac_caps: bool = True,
    firmware: str = "V3.2.30",
) -> FakeDevice:
    """A FakeDevice serving deviceInfo (XML, like site-a) + the capability bodies."""
    device = FakeDevice()
    device.xml_ok(
        "GET",
        DEVICE_INFO_PATH,
        (RECORDED / "device_info.xml").read_text(encoding="utf-8").replace("V3.2.30", firmware),
    )
    device.add(
        "GET",
        CAPS_PATH,
        httpx.Response(200, content=caps_body, headers={"Content-Type": caps_content_type}),
    )
    if with_ac_caps:
        device.json_ok(
            "GET",
            AC_CAPS_PATH,
            json.loads((SYNTH / "access_control_capabilities.json").read_bytes()),
        )
    return device


def cap_requests(device: FakeDevice) -> list:
    """Requests that actually hit a capability endpoint (the cache-relevant ones)."""
    return [s for s in device.served if s.path.startswith("/ISAPI/AccessControl/")]


def client_for(device: FakeDevice) -> IsapiClient:
    return IsapiClient(
        BASE_URL, "admin", PASSWORD, transport=device.transport, sleep=lambda _s: None
    )


# --- capability JSON -> limits ----------------------------------------------------------


def test_recorded_site_a_capabilities_extract_every_advertised_limit() -> None:
    """docs/OBSERVED.md 'AcsEvent capabilities' section, field for field."""
    caps = parse_acs_event_capabilities(recorded_caps_json())
    assert caps.max_results == 30, "OBSERVED.md: maxResults @max=30"
    assert caps.max_results_min == 1
    assert caps.search_id_max == 64, "OBSERVED.md: searchID @max=64"
    assert caps.majors == frozenset({0, 1, 2, 3, 5}), "OBSERVED.md: major @opt=0,1,2,3,5"
    assert caps.info_list_max_size == 30
    assert 75 in caps.minors[5] and 1 in caps.minors[5], "the face + card passes are advertised"
    assert 1029 in caps.minors[3], "the noise heartbeat is a advertised operation minor"
    assert caps.minors[1] == frozenset(range(1028, 1041)), "minorAlarm 1028..1040"


def test_site_a_advertises_no_event_attribute_capability() -> None:
    """OBSERVED.md: 'No eventAttribute capability on this fw' — the reason the connector
    filters client-side. If this flips on a future device, the raw dump still shows why."""
    caps = parse_acs_event_capabilities(recorded_caps_json())
    assert caps.supports_event_attribute is False
    assert caps.event_attribute_options == frozenset()
    assert "eventAttribute" not in json.dumps(dict(caps.raw))  # the raw body really lacks it


def test_advertised_verify_modes_are_kept_as_data_not_policy() -> None:
    """Site-a's InfoList currentVerifyMode @opt does NOT include cardOrFaceOrFp, yet every
    real pass carries it (OBSERVED.md). Parsing must store the list without letting it
    imply that observed values are invalid."""
    caps = parse_acs_event_capabilities(recorded_caps_json())
    assert "face" in caps.verify_modes
    assert "cardOrFaceOrFp" not in caps.verify_modes, "the fixture really omits it"


def test_max10_box_parses_its_own_smaller_limits_and_event_attribute() -> None:
    """The other half of the card: 'some DS-K1T* advertise 10' — and this synthetic box
    DOES advertise eventAttribute, so support must be data-driven, not constant."""
    caps = parse_acs_event_capabilities((SYNTH / "acs_capabilities_max10.json").read_bytes())
    assert caps.max_results == 10
    assert caps.search_id_max == 20
    assert caps.supports_event_attribute is True
    assert caps.event_attribute_options == frozenset({"attendance", "other"})


# --- clamping ---------------------------------------------------------------------------


def test_clamp_ask_100_on_max_10_box_asks_10() -> None:
    """Card DoD: 'ask 100 on a max-10 box -> request 10'."""
    caps = parse_acs_event_capabilities((SYNTH / "acs_capabilities_max10.json").read_bytes())
    assert caps.clamp_max_results(100) == 10


def test_clamp_never_raises_and_never_exceeds_the_cap() -> None:
    caps30 = parse_acs_event_capabilities(recorded_caps_json())
    assert caps30.clamp_max_results(100) == 30
    assert caps30.clamp_max_results(10) == 10  # below cap: untouched
    assert caps30.clamp_max_results(1) == 1
    assert caps30.clamp_max_results(0) == 1, "floor 1 — a zero-length page is not a request"
    assert caps30.clamp_max_results(-5) == 1


def test_clamp_without_advertisement_uses_the_smallest_known_cap() -> None:
    """No @max advertised -> DEFAULT_MAX_RESULTS (10), the smallest ever reported for this
    family: the only request size that cannot be `badParameters`."""
    caps = DeviceCapabilities()
    assert caps.max_results is None
    assert caps.clamp_max_results(100) == DEFAULT_MAX_RESULTS == 10
    assert caps.clamp_search_id("x" * 100) == "x" * DEFAULT_SEARCH_ID_MAX


def test_search_id_clamped_to_advertised_length() -> None:
    caps64 = parse_acs_event_capabilities(recorded_caps_json())
    assert len(caps64.clamp_search_id("p" * 100)) == 64
    assert caps64.clamp_search_id("short") == "short"
    caps20 = parse_acs_event_capabilities((SYNTH / "acs_capabilities_max10.json").read_bytes())
    assert len(caps20.make_search_id()) <= 20, "generated ids respect the device's own limit"
    ids = {caps64.make_search_id() for _ in range(200)}
    assert len(ids) == 200, "ids must stay unique after clamping (uuid4 tail is what varies)"


# --- XML fallback -----------------------------------------------------------------------


def test_xml_fallback_attribute_idiom_parses_to_the_same_limits_as_json() -> None:
    """Site-a answers this endpoint as JSON, but the same webs server answers System/* as
    XML despite ?format=json (OBSERVED.md) — the fallback must not lose limits to the
    attribute idiom. Fixture carries the same values as the recorded JSON on purpose."""
    xml_caps = parse_acs_event_capabilities(
        (SYNTH / "acs_capabilities_attrs.xml").read_text(encoding="utf-8")
    )
    json_caps = parse_acs_event_capabilities(recorded_caps_json())
    assert xml_caps.format_note == "xml-fallback"
    assert xml_caps.max_results == json_caps.max_results == 30
    assert xml_caps.search_id_max == json_caps.search_id_max == 64
    assert xml_caps.majors == json_caps.majors
    assert xml_caps.minors[5] <= json_caps.minors[5], "synthetic subset of the real set"
    assert xml_caps.info_list_max_size == 30
    assert "face" in xml_caps.verify_modes


def test_xml_fallback_child_node_idiom_parses_too() -> None:
    """The second ISAPI XSD idiom (<max>30</max> as a child node). We refuse to bet the
    fallback on one spelling we never actually observed."""
    caps = parse_acs_event_capabilities(
        (SYNTH / "acs_capabilities_children.xml").read_text(encoding="utf-8")
    )
    assert caps.max_results == 30
    assert caps.search_id_max == 64
    assert caps.majors == frozenset({0, 1, 2, 3, 5})
    assert 75 in caps.minors[5]
    assert caps.info_list_max_size == 30
    assert "checkIn" in caps.attendance_statuses


def test_xml_fallback_still_refuses_dtd_and_entities() -> None:
    """The p1-03 XML guard (size cap + DTD refusal) applies to this fallback path too —
    it goes through parse_isapi_xml, not around it."""
    from gateclerk.exceptions import IsapiPayloadError

    bomb = (
        '<?xml version="1.0"?><!DOCTYPE C [<!ENTITY x "AAAA">'
        ']><AcsEventCap><maxResults max="&x;"/></AcsEventCap>'
    )
    with pytest.raises(IsapiPayloadError, match="DTD or entity"):
        parse_acs_event_capabilities(bomb)


def test_unrecognisable_root_yields_no_limits_and_keeps_the_raw() -> None:
    """A body we cannot locate the cond table in must NOT invent limits: every limit None
    (conservative defaults downstream) and the raw dump still carries the evidence."""
    caps = parse_acs_event_capabilities('{"SomethingElse": {"totally": "different"}}')
    assert caps.max_results is None
    assert caps.clamp_max_results(50) == DEFAULT_MAX_RESULTS
    assert caps.raw == {"SomethingElse": {"totally": "different"}}


# --- AccessControl capabilities (advisory) ------------------------------------------------


def test_access_control_caps_expose_ring_capacity() -> None:
    payload, capacity = parse_access_control_capabilities(
        (SYNTH / "access_control_capabilities.json").read_bytes()
    )
    assert capacity == 300000
    assert "AccessControlCap" in payload


# --- device identity ---------------------------------------------------------------------


def test_device_identity_reads_the_xml_flattened_dict() -> None:
    """System/deviceInfo is XML on this fw (OBSERVED.md); parse_body has already flattened
    it by the time we see it."""
    from gateclerk.isapi_response import parse_body

    body = parse_body((RECORDED / "device_info.xml").read_bytes())
    serial, firmware, model = device_identity(dict(body))
    assert serial == "MASKED-SER-1"
    assert firmware == "V3.2.30"
    assert model == "DS-K1T341AMF-S"


# --- discovery + cache ---------------------------------------------------------------------


def test_discover_reads_caps_once_and_serves_the_second_call_from_cache() -> None:
    """A repeat discover() re-reads only deviceInfo — one small GET whose whole job is
    producing the cache key, which is also how a device swap or firmware upgrade is
    caught. The capability bodies (the expensive/important reads) are NOT re-fetched."""
    device = caps_device(recorded_caps_json())
    client = client_for(device)
    cache = CapabilityCache()

    caps = discover(client, cache=cache)
    assert caps.max_results == 30
    assert caps.serial == "MASKED-SER-1" and caps.firmware == "V3.2.30"
    assert caps.model == "DS-K1T341AMF-S"
    assert caps.acs_event_capacity == 300000
    caps_reads_after_first = len(cap_requests(device))
    assert caps_reads_after_first == 2, "the two capability GETs, once"

    again = discover(client, cache=cache)
    assert again is caps
    assert len(cap_requests(device)) == caps_reads_after_first, "cache hit: zero new cap reads"
    assert len(cache) == 1


def test_firmware_change_invalidates_the_cache_key() -> None:
    """(serial, firmwareVersion) is the key: an upgraded box must not inherit stale caps."""
    cache = CapabilityCache()
    discover(client_for(caps_device(recorded_caps_json())), cache=cache)

    upgraded = caps_device(recorded_caps_json(), firmware="V3.3.0")
    caps2 = discover(client_for(upgraded), cache=cache)
    assert caps2.firmware == "V3.3.0"
    assert len(cache) == 2, "a new firmware is a new cache entry, not an overwrite"


def test_force_refresh_rereads_the_device() -> None:
    device = caps_device(recorded_caps_json())
    cache = CapabilityCache()
    client = client_for(device)
    discover(client, cache=cache)
    served = len(device.served)
    discover(client, cache=cache, force_refresh=True)
    assert len(device.served) > served


def test_missing_access_control_endpoint_is_not_fatal() -> None:
    """Some firmwares 404 /ISAPI/AccessControl/capabilities. The AcsEvent caps are the
    important ones; this one is advisory, so record the reason and carry on."""
    device = caps_device(recorded_caps_json(), with_ac_caps=False)  # route absent -> 404 notSupport
    caps = discover(client_for(device), cache=CapabilityCache())
    assert caps.max_results == 30, "discovery still succeeds"
    assert caps.access_control_error is not None
    assert "notSupport" in caps.access_control_error
    assert caps.access_control_raw is None


def test_missing_acs_event_capabilities_refuses_to_guess() -> None:
    """DESIGN.md's whole reason-for-existing: no caps, no guessed codes. Loud failure."""
    device = caps_device(recorded_caps_json(), with_ac_caps=False)
    device.routes.clear()  # wipe everything, re-add only deviceInfo
    device.add(
        "GET",
        DEVICE_INFO_PATH,
        httpx.Response(
            200,
            text=(RECORDED / "device_info.xml").read_text(encoding="utf-8"),
            headers={"Content-Type": "application/xml"},
        ),
    )
    with pytest.raises(CapabilityDiscoveryError, match="refusing to"):
        discover(client_for(device), cache=CapabilityCache())


def test_raw_dump_contains_the_untouched_bodies() -> None:
    """`gateclerk device capabilities --json` is the OBSERVED.md evidence trail: the raw
    bodies must survive extraction untouched."""
    device = caps_device(recorded_caps_json())
    caps = discover(client_for(device), cache=CapabilityCache())
    dumped = json.loads(caps.as_json())
    assert dumped["raw_acs_event_capabilities"] == json.loads(recorded_caps_json())
    assert (
        dumped["raw_access_control_capabilities"]["AccessControlCap"]["AcsEvent"]["maxCapacity"]
        == 300000
    )
    assert dumped["limits"]["max_results"] == 30
    assert dumped["queryable"]["minor_event"] and 75 in dumped["queryable"]["minor_event"]
