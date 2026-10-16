"""ISAPI response parsing: the three envelope shapes, the XML guard, envelope->error.

Nothing here touches a socket; the transport half lives in test_isapi_transport.py
with FakeDevice. Fixtures from tests/fixtures/recorded/site-a-ds-k1t341amf-s/ are the
recorded truth (docs/OBSERVED.md); invented bodies are labelled as such in the test.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from gateclerk.exceptions import (
    IsapiAuthError,
    IsapiBadContent,
    IsapiBusy,
    IsapiError,
    IsapiNotFound,
    IsapiPayloadError,
)
from gateclerk.isapi_response import (
    MAX_ISAPI_XML_BYTES,
    TEXT_KEY,
    envelope_to_error,
    flatten_xml,
    parse_body,
    parse_envelope,
    parse_isapi_xml,
    strip_ns,
)

FIXTURES = Path(__file__).parent / "fixtures/recorded/site-a-ds-k1t341amf-s"


def fixture(name: str) -> str:
    return (FIXTURES / name).read_text(encoding="utf-8")


# --- XML safety guard -----------------------------------------------------------------


def test_fixture_xml_still_parses() -> None:
    """The guard must not eat real traffic: both recorded System/* XML bodies parse."""
    assert parse_isapi_xml(fixture("device_info.xml")).tag.endswith("DeviceInfo")
    assert parse_isapi_xml(fixture("system_time.xml")).tag.endswith("Time")


def test_bom_prefix_parses_a_dtd_free_body() -> None:
    """`webs` has been seen emitting a UTF-8 BOM. ElementTree tolerates a leading BOM
    on a str, and the DTD scan is whole-payload (position-proof), so a BOM changes
    nothing: no false positive, no hiding place."""
    assert parse_isapi_xml("\ufeff" + fixture("system_time.xml")).tag.endswith("Time")
    with pytest.raises(IsapiPayloadError):
        parse_isapi_xml("\ufeff<!DOCTYPE Time><Time/>")


def test_dtd_and_entity_declarations_are_refused() -> None:
    for payload in (
        "<!DOCTYPE Time [<!ENTITY x SYSTEM 'file:///etc/passwd'>]><Time/>",
        "<!ENTITY evil 'boom'>",
    ):
        with pytest.raises(IsapiPayloadError, match="DTD or entity"):
            parse_isapi_xml(payload)


@pytest.mark.parametrize("pad_len", [0, 5_000, 20_000, 60_000])
def test_guard_catches_a_dtd_past_the_head_window(pad_len: int) -> None:
    """The architect's bypass pin (eec6658), kept on this module's copy of the guard.

    The first version scanned only `payload[:MAX//4]`; a 4x4x4 internal entity bomb
    padded behind 20 kB of comments passed the scan and ElementTree EXPANDED it
    (internal-entity expansion is real even though external resolution is off). The
    scan is whole-payload; this is the regression pin at four offsets.
    """
    bomb = (
        '<!DOCTYPE Time [<!ENTITY a "aaaa">'
        '<!ENTITY b "&a;&a;&a;&a;"><!ENTITY c "&b;&b;&b;&b;">]>'
        "<Time><x>&c;</x></Time>"
    )
    payload = f'<?xml version="1.0"?><!--{"p" * pad_len}-->{bomb}'
    assert len(payload) < MAX_ISAPI_XML_BYTES, pad_len
    with pytest.raises(IsapiPayloadError, match="DTD or entity"):
        parse_isapi_xml(payload)


def test_cdata_mentioning_doctype_is_refused_conservatively() -> None:
    """The guard refuses the *token* anywhere — including inside CDATA. A false
    refusal is a loud IsapiPayloadError; a false accept is expansion on the payroll
    path. (Architect handoff: relaxing this is p1-03's call; we keep the strict side.)"""
    payload = "<Time><x><![CDATA[<!DOCTYPE evil>]]></x></Time>"
    with pytest.raises(IsapiPayloadError, match="DTD or entity"):
        parse_isapi_xml(payload)


def test_read_system_time_shaped_padded_dtd_is_refused() -> None:
    """p1-06 pin ported here (tests/test_tz.py::test_read_system_time_refuses_a_padded_-
    dtd_payload): a System/time body with the DTD behind 20 kB of comment padding is a
    refusal. This module owns parse_isapi_xml, and p1-06's tz.py copy is now retired —
    since t_7b073d11 `gateclerk.tz.parse_isapi_xml` is a re-export of this one, so the tz
    pin and this one exercise the same guard."""
    payload = f'<?xml version="1.0"?><!--{"p" * 20_000}--><!DOCTYPE Time><Time/>'
    with pytest.raises(IsapiPayloadError):
        parse_isapi_xml(payload)
    # And the same wall holds when the body arrives as bytes through the transport's
    # parse entry point (the read_system_time caller's path is parse_body first):
    with pytest.raises(IsapiPayloadError):
        parse_body(payload.encode("utf-8"))


def test_oversize_body_is_refused_before_parsing() -> None:
    with pytest.raises(IsapiPayloadError, match="exceeds"):
        parse_isapi_xml("<Time>" + "x" * MAX_ISAPI_XML_BYTES + "</Time>")


def test_malformed_xml_raises_named_error() -> None:
    with pytest.raises(IsapiPayloadError, match="not well-formed"):
        parse_isapi_xml("<Time><unclosed>")


# --- namespace handling -----------------------------------------------------------------


@pytest.mark.parametrize(
    "xmlns",
    [
        "http://www.hikvision.com/ver20/XMLSchema",  # captured openHAB transcript
        "http://www.isapi.org/ver20/XMLSchema",  # our device + vendor guide
        "http://www.isapi.com/ver20/XMLSchema",  # vendor guide p.278
        "http://www.std-cgi.org/ver20/XMLSchema",  # vendor guide XML_ResponseStatus
    ],
    ids=["hikvision", "isapi-org", "isapi-com", "std-cgi"],
)
def test_all_four_observed_namespaces_stay_readable(xmlns: str) -> None:
    """Live samples use at least four xmlns URIs (gotchas §3.1); a naive find('{ns}tag')
    breaks on every one it does not hardcode, so namespaces get stripped, not matched."""
    body = (
        f'<?xml version="1.0"?><ResponseStatus version="2.0" xmlns="{xmlns}">'
        "<statusCode>4</statusCode><subStatusCode>notSupport</subStatusCode>"
        "</ResponseStatus>"
    )
    env = parse_envelope(body, http_status=400)
    assert env is not None
    assert env.status_code == 4
    assert env.sub_status_code == "notSupport"


def test_strip_ns_leaves_bare_tags_alone() -> None:
    assert strip_ns("{urn:x}statusCode") == "statusCode"
    assert strip_ns("statusCode") == "statusCode"


# --- format sniffing ---------------------------------------------------------------------


def test_empty_body_is_an_empty_dict_not_a_crash() -> None:
    assert parse_body(b"") == {}
    assert parse_body("   ") == {}


def test_json_array_body_is_a_named_error() -> None:
    with pytest.raises(IsapiPayloadError):
        parse_body(b"[1,2,3]")


def test_garbage_body_is_a_named_error_not_silence() -> None:
    """A corrupt body must not read as 'no data' — on a payroll pipeline that is
    indistinguishable from 'nobody clocked in'."""
    with pytest.raises(IsapiPayloadError):
        parse_body(b"\x00\xff garbage that is neither json nor xml")


def test_xml_promised_json_still_parses_as_dict() -> None:
    """OBSERVED.md delta (1): System/* answers XML *despite* ?format=json."""
    parsed = parse_body(fixture("device_info.xml"))
    assert parsed["model"] == "DS-K1T341AMF-S"
    assert parsed["serialNumber"] == "MASKED-SER-1"
    assert parsed["firmwareVersion"] == "V3.2.30"


def test_flatten_xml_nests_repeats_and_empty_nodes() -> None:
    body = "<Root><a>1</a><a>2</a><b><c>x</c></b><d></d></Root>"
    flat = flatten_xml(parse_isapi_xml(body))
    assert flat == {"a": ["1", "2"], "b": {"c": "x"}, "d": None}


# --- attribute convention (review defect #1 of PR #5) --------------------------------
#
# The device puts capability limits in XML attributes (OBSERVED.md: maxResults@max=30,
# searchID@max=64, major@opt=…). Before this fix they flattened to None — a real
# capability read as no-data, the failure class this module's docstring forbids. The
# `@`-prefix spelling is not invented here: the recorded JSON fixtures under
# tests/fixtures/recorded/site-a-ds-k1t341amf-s/ (acs_capabilities.json) already use
# `@max`, and p1-04's clamping reads both paths, so XML must agree on the spelling.


def test_flatten_xml_capability_attributes_become_at_keys() -> None:
    """The exact PR #5 repro: `<maxResults max="30" min="1"/>` used to yield None."""
    flat = flatten_xml(parse_isapi_xml('<Transaction><maxResults max="30" min="1"/></Transaction>'))
    assert flat == {"maxResults": {"@max": "30", "@min": "1"}}
    # And it is readable the way the JSON fixture path exposes it (clamping contract):
    assert flat["maxResults"]["@max"] == "30"


def test_flatten_xml_leaf_with_attrs_and_text_keeps_text_under_text_key() -> None:
    flat = flatten_xml(parse_isapi_xml('<Root><depth mode="auto">4</depth></Root>'))
    assert flat == {"depth": {"@mode": "auto", TEXT_KEY: "4"}}
    assert TEXT_KEY == "#text"


def test_flatten_xml_attrs_on_parent_merge_into_nested_dict() -> None:
    """Attributes live *on that element's dict* — an element with children keeps them."""
    flat = flatten_xml(parse_isapi_xml('<Root><list opt="a,b"><item>1</item></list></Root>'))
    assert flat == {"list": {"@opt": "a,b", "item": "1"}}


def test_flatten_xml_attribute_free_behaviour_unchanged() -> None:
    """Guard against over-application: the text-only/empty/repeat shapes of the pin
    above must survive verbatim when no attributes are present."""
    body = "<Root><a>1</a><a>2</a><b><c>x</c></b><d></d></Root>"
    assert flatten_xml(parse_isapi_xml(body)) == {
        "a": ["1", "2"],
        "b": {"c": "x"},
        "d": None,
    }


def test_content_type_header_is_never_consulted() -> None:
    """parse_body takes only the body — the device sends `application/json;charset="UTF-8"`
    (quoted!) and answers XML where JSON was asked, so the header is worthless (gotchas
    §3.3). This test pins the *signature*: there is no header parameter to pass."""
    import inspect

    assert "content_type" not in inspect.signature(parse_body).parameters
    assert "headers" not in inspect.signature(parse_body).parameters


# --- envelope shapes ----------------------------------------------------------------------


def test_canonical_xml_envelope() -> None:
    body = (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<ResponseStatus version="2.0" xmlns="http://www.hikvision.com/ver20/XMLSchema">'
        "<requestURL>/ISAPI/x</requestURL><statusCode>2</statusCode>"
        "<statusString>Device Busy</statusString><subStatusCode>deviceBusy</subStatusCode>"
        "</ResponseStatus>"
    )
    env = parse_envelope(body, http_status=503)
    assert env is not None
    assert env.status_code == 2
    assert env.sub_status_code == "deviceBusy"
    assert env.request_url == "/ISAPI/x"


def test_flat_json_envelope_int_or_string() -> None:
    """The JSON variant drops the ResponseStatus wrapper and flips int vs string by fw."""
    for body in (
        b'{"statusCode": 6, "subStatusCode": "badParameters"}',
        b'{"statusCode": "6", "subStatusCode": "badParameters"}',
    ):
        env = parse_envelope(body, http_status=400)
        assert env is not None and env.status_code == 6
        assert env.sub_status_code == "badParameters"


def test_user_check_shape_status_value_is_not_status_code() -> None:
    """The 401 body is a payload: userCheck carries `statusValue` (HTTP-ish 401) and
    machine-readable lockout fields (DESIGN.md). statusValue must not be mistaken for
    the canonical statusCode 1..7."""
    body = (
        "<userCheck><statusValue>401</statusValue><statusString>Unauthorized</statusString>"
        "<lockStatus>locked</lockStatus><unlockTime>1722</unlockTime>"
        "<retryLoginTime>0</retryLoginTime></userCheck>"
    )
    env = parse_envelope(body, http_status=401)
    assert env is not None
    assert env.status_value == 401
    assert env.status_code is None
    assert env.locked is True
    assert env.unlock_seconds == 1722
    assert env.retry_login_seconds == 0
    assert env.is_user_check is True


def test_search_payload_is_not_an_envelope() -> None:
    """A search response has no statusCode — parse_envelope must say None, not invent a
    status (and the client must never look for statusCode on a search)."""
    body = fixture("events_major5_page1.json")
    assert parse_envelope(body, http_status=200) is None
    parsed = parse_body(body)
    assert parsed["AcsEvent"]["numOfMatches"] == 30


def test_no_match_envelope_absent_infolist_survives() -> None:
    parsed = parse_body(fixture("events_no_match.json"))
    acs = parsed["AcsEvent"]
    assert acs["responseStatusStrg"] == "NO MATCH"
    assert "InfoList" not in acs


def test_status_ok_envelope_is_not_an_error() -> None:
    env = parse_envelope(b'{"statusCode": 1, "statusString": "OK"}', http_status=200)
    assert env is not None and env.ok and not env.locked


# --- envelope -> typed exception -----------------------------------------------------------


def make(
    *,
    http_status: int = 200,
    body: str = "",
    endpoint: str = "acs_event_search",
    request_body: str | None = None,
) -> IsapiError | None:
    """The transport's decision table in one call: (status, body) -> typed error/None."""
    raw = body.encode("utf-8")
    return envelope_to_error(
        http_status=http_status,
        envelope=parse_envelope(raw, http_status=http_status),
        endpoint=endpoint,
        request_body=request_body,
        raw_body=raw,
    )


def test_404_maps_to_not_found() -> None:
    err = make(http_status=404, body="")
    assert isinstance(err, IsapiNotFound)


def test_notsupport_is_not_found_even_under_http_400() -> None:
    """Our own fixture: `AcsEvent/Total` answers HTTP 400 + subStatusCode notSupport
    (OBSERVED.md). Mapping that to BadContent would send a developer to fix a request
    body that is fine — the endpoint simply does not exist on this firmware."""
    err = make(
        http_status=400,
        body=fixture("error_total_notsupport.json"),
        endpoint="acs_event_total",
    )
    assert isinstance(err, IsapiNotFound)
    assert "notSupport" in str(err)


def test_http_503_device_busy_maps_to_busy() -> None:
    body = (
        "<ResponseStatus><statusCode>2</statusCode><statusString>Device Busy</statusString>"
        "<subStatusCode>deviceBusy</subStatusCode></ResponseStatus>"
    )
    err = make(http_status=503, body=body)
    assert isinstance(err, IsapiBusy)


def test_status_code_6_maps_to_bad_content_with_request_body() -> None:
    sent = '{"AcsEventCond":{"searchID":"abc123","maxResults":30}}'
    err = make(
        http_status=400,
        body='{"statusCode":6,"statusString":"Invalid Message Content",'
        '"subStatusCode":"badParameters","errorMsg":"invalid maxResults"}',
        request_body=sent,
    )
    assert isinstance(err, IsapiBadContent)
    # DESIGN.md: include the request body verbatim — the message is the debug output.
    assert sent in str(err)
    assert err.request_body == sent


def test_status_code_3_under_http_400_is_device_error_not_our_bug() -> None:
    """statusCode drives the class, not the HTTP verb (DESIGN.md: '3 once then alert').
    Mislabelling this BadContent would tell the reader their request is wrong."""
    err = make(http_status=400, body='{"statusCode":3,"subStatusCode":"deviceError"}')
    assert isinstance(err, IsapiError)
    assert not isinstance(err, IsapiBadContent)
    assert "device error" in str(err)


def test_bare_401_maps_to_auth_error() -> None:
    err = make(http_status=401, body="")
    assert isinstance(err, IsapiAuthError)
    assert err.unlock_time is None and err.locked is False


def test_401_user_check_carries_lockout_fields() -> None:
    body = (
        "<userCheck><statusValue>401</statusValue><lockStatus>locked</lockStatus>"
        "<unlockTime>1800</unlockTime><retryLoginTime>0</retryLoginTime></userCheck>"
    )
    err = make(http_status=401, body=body)
    assert isinstance(err, IsapiAuthError)
    assert err.locked is True
    assert err.unlock_time == 1800
    assert err.retry_login_time == 0


def test_unclassified_http_500_is_terminal_isapi_error_with_body_snippet() -> None:
    err = make(http_status=500, body="webs said nope")
    assert isinstance(err, IsapiError)
    assert not isinstance(err, IsapiBusy | IsapiBadContent | IsapiNotFound | IsapiAuthError)
    assert "webs said nope" in str(err)


def test_success_returns_no_error() -> None:
    assert make(http_status=200, body=fixture("user_count.json")) is None
    assert make(http_status=200, body=fixture("events_major5_page1.json")) is None
