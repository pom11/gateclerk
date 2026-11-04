"""DEMO-DEVICE contract: `gateclerk demo device` must be a fake a real client can talk to.

The operator product goal this file pins: a developer must be able to try gateclerk with NO
real door controller. That is only true if the demo box speaks the same ISAPI the client
reads — so these arms do not test a helper in isolation, they point the **unmodified**
`gateclerk.isapi_transport.IsapiClient` at a loopback HTTP server and require it to work:

* ARM A — digest round-trip over a real socket for the three calls the product makes
  (device info, user search, event search), plus the two device-faithful rejections the
  firmware really sends (naive window bound, unregistered path). A demo server that
  skipped the 401 handshake would let a developer's first run succeed in a way the real
  device never does.
* ARM B — SYNTHETIC PROOF: every value the demo box answers must be synthetic. Scanned
  both ways: no demo fixture string may appear in the recorded captures, and no person
  name / serial number / card number / enrollee identity in the captures may be a demo
  value. This is the arm that keeps a copy-paste from `docs/OBSERVED*.md` out of the
  demo corpus.
* ARM C — the pagination contract: the fake windows the way the box windows (silent
  clamp to the advertised cap, `MORE` until the last page, advance-by-`numOfMatches`)
  and `gateclerk.paging.PagedSearch` walks it to the last page over HTTP.

Why a `socket` test when `tests/conftest.py` blocks sockets: the whole point of this
card is a server that answers a *real* client, and `httpx.MockTransport` cannot express
that. `netoff` is an autouse **fixture**, not an import-time patch, so the arms that
need a socket clear it with `socket_allow`. A loopback listener to a process in this
test session is not the danger the guard exists for (a stray socket to site LAN
hardware); anything outside loopback stays blocked — ARM D proves that.
"""

from __future__ import annotations

import json
import re
import socket
from collections.abc import Iterator
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest
from typer.testing import CliRunner

import _socketseam
import gateclerk.cli as cli_mod
import gateclerk.demo_device as demo
from _source_guard import PACKAGE  # noqa: F401  (keeps the tests/ path convention honest)
from fakedevice import REALM, expected_response, parse_digest_header
from gateclerk.endpoints import REGISTRY, SEARCH_ENDPOINTS
from gateclerk.exceptions import IsapiError
from gateclerk.isapi_transport import IsapiClient
from gateclerk.paging import PagedSearch, PagingLimits, build_event_cond

REPO_ROOT = Path(__file__).resolve().parents[1]
CAPTURE_FILES = sorted((REPO_ROOT / "docs").glob("OBSERVED*.md"))
FIXTURE_FILES = sorted(
    p
    for p in (REPO_ROOT / "tests" / "fixtures").rglob("*")
    if p.is_file() and p.suffix in {".json", ".xml"}
)
CAPTURE_PATHS = (*CAPTURE_FILES, *FIXTURE_FILES)

#: The identity keys the reverse scan reads out of the captured corpus.
_IDENTITY_KEYS = ("name", "serialNumber", "cardNo", "employeeNoString", "faceURL")

DEMO_USER = "admin"
DEMO_PASSWORD = "fakepw"  # placeholder policy (tests/test_repo_hygiene.py PLACEHOLDER)

runner = CliRunner()


# --- the socket seam (see the module docstring) -----------------------------------------


@pytest.fixture
def socket_allow(monkeypatch: pytest.MonkeyPatch) -> None:
    """Undo the autouse `netoff` guard for THIS test only, then restore it.

    `monkeypatch.setattr(socket, "socket", socket.socket)` would NOT work: by fixture
    setup time `netoff` has already replaced the attribute, so that "restoration"
    captures the blocker and re-installs it. `tests/_socketseam.py` captured the real
    attributes at import time, before any patch existed; the seam's monkeypatch is
    torn down before `netoff`'s, so the guard is back for every other test.
    """
    _socketseam.release(monkeypatch)


@pytest.fixture
def demo_device(socket_allow: None) -> Iterator[demo.DemoDevice]:
    """A live demo box on 127.0.0.1:0 for the duration of one test."""
    box = demo.DemoDevice(username=DEMO_USER, password=DEMO_PASSWORD)
    box.start()
    try:
        yield box
    finally:
        box.stop()


@pytest.fixture
def demo_client(demo_device: demo.DemoDevice) -> Iterator[IsapiClient]:
    """The real client, unmodified, pointed at the demo box."""
    client = IsapiClient(
        demo_device.base_url,
        DEMO_USER,
        DEMO_PASSWORD,
        connect_timeout=5.0,
        read_timeout=10.0,
    )
    try:
        yield client
    finally:
        client.close()


# --- ARM A: the real client, over a real socket, with a digest round-trip ----------------


def test_demo_answers_device_info_with_the_observed_xml_shape(demo_client: IsapiClient) -> None:
    """`GET /ISAPI/System/deviceInfo?format=json` answers XML, like the box (OBSERVED.md).

    The client's parser is what turns those bytes into a dict, so this arm also proves the
    demo bytes go through the production parser rather than a demo-specific reader.
    """
    body = demo_client.get("device_info")

    # `parse_body` strips the XML root, so the fields arrive flat — exactly the shape the
    # recorded `device_info.xml` produces (which `capabilities.device_identity` reads).
    assert body["model"] == demo.DEMO_MODEL
    assert body["serialNumber"] == demo.DEMO_SERIAL
    assert body["firmwareVersion"] == demo.DEMO_FIRMWARE
    assert body["deviceType"] == demo.DEMO_DEVICE_TYPE
    from gateclerk.capabilities import device_identity

    assert device_identity(body) == (demo.DEMO_SERIAL, demo.DEMO_FIRMWARE, demo.DEMO_MODEL)


def test_demo_answers_system_time_xml_with_the_claimed_offset(
    demo_client: IsapiClient,
) -> None:
    """`GET System/time` is XML too, and carries the offset the demo windows are stamped with.

    Faithful shape (timeMode/localTime/timeZone from the recorded `system_time.xml`);
    synthetic values, including the deliberately wrong-looking +02:00 claim that makes
    the product's tz-mismatch warning demonstrable offline.
    """
    body = demo_client.get("system_time")

    # `+02:00` is hh:mm — the claimed offset in MINUTES is 2*60+0, not int("+02:00").
    label = body["localTime"][-6:]
    assert label[0] in "+-" and label[3] == ":", f"unexpected offset label {label!r}"
    claimed = (1 if label[0] == "+" else -1) * (int(label[1:3]) * 60 + int(label[4:6]))
    assert claimed == demo.DEMO_CLAIMED_OFFSET_MIN
    assert body["timeZone"].startswith("CST-2:00:00DST01:00:00")


def test_demo_answers_user_search_post(demo_client: IsapiClient) -> None:
    """The wrapped-cond roster search the CLI's `users list` posts, over HTTP."""
    body = demo_client.search(
        "user_info_search",
        {
            "UserInfoSearchCond": {
                "searchID": "demo-search-id",
                "searchResultPosition": 0,
                "maxResults": 30,
            }
        },
    )

    search = body["UserInfoSearch"]
    assert search["responseStatusStrg"] == "OK"
    assert search["numOfMatches"] == demo.DEMO_USER_COUNT
    rows = search["UserInfo"]
    assert [row["name"] for row in rows] == demo.demo_user_names()
    # The record shape OBSERVED recorded (RightPlan/Valid/numOfFace), values synthetic.
    first = rows[0]
    assert first["RightPlan"] == [{"doorNo": 1, "planTemplateNo": "1"}]
    assert first["Valid"]["timeType"] == "local"
    assert first["numOfFace"] == 1


def test_demo_event_search_uses_the_paging_envelope(demo_client: IsapiClient) -> None:
    window = _window()
    cond = build_event_cond(window, device_offset_min=demo.DEMO_CLAIMED_OFFSET_MIN)
    body = demo_client.search("acs_event_search", {"AcsEventCond": cond})

    acs = body["AcsEvent"]
    assert acs["responseStatusStrg"] == "OK"
    assert acs["numOfMatches"] == len(demo.demo_events())
    assert acs["InfoList"], "a matching window must carry InfoList"


def test_digest_handshake_is_a_real_challenge_then_an_authorized_get(
    demo_device: demo.DemoDevice,
) -> None:
    """401 + `WWW-Authenticate: Digest` with a realm, then the payload once paid.

    Checked with a bare socket-level client (no httpx auth helper) so the arm cannot be
    satisfied by a library convenience: the challenge must exist and the second request
    must carry credentials the box itself validates.
    """
    path = REGISTRY["device_info"].url_path
    with _RawLoopbackClient(demo_device.host, demo_device.port) as raw:
        status, headers, payload = raw.request("GET", path)
        assert status == 401, "an unauthenticated request must be challenged, like `webs`"
        assert headers["server"] == demo.DEMO_SERVER_HEADER
        challenge = headers["www-authenticate"]
        assert challenge.lower().startswith("digest ")
        fields = parse_digest_header(f"Digest {challenge[len('Digest ') :]}")
        assert fields["realm"] == REALM, "the demo realm is the masked `webs` realm"
        assert fields["qop"] == "auth"
        # `parse_digest_header` lower-cases every KEY; the device spells `nonce`
        # lowercase in its challenge, but an implementation that wrote `Nonce="…"`
        # would land under `nonce` here too — this read is the tolerant one.
        nonce = fields["nonce"]
        assert nonce, "the challenge must advertise a nonce"

        auth = _digest_header(
            username=DEMO_USER,
            password=DEMO_PASSWORD,
            method="GET",
            uri=path,
            nonce=nonce,
        )
        status2, headers2, payload2 = raw.request("GET", path, authorization=auth)

    assert status2 == 200
    assert b"<DeviceInfo" in payload2
    assert b"xmlns" in payload2
    assert headers2["content-type"].startswith("application/xml")
    assert b"<DeviceInfo" not in payload, "the payload must not leak before auth"


def test_demo_rejects_a_wrong_password(demo_device: demo.DemoDevice) -> None:
    """A demo box that accepted any password would teach a developer nothing about digest."""
    with pytest.raises(IsapiError) as exc:
        bad = IsapiClient(demo_device.base_url, DEMO_USER, "wrong" + "pw")
        try:
            bad.get("device_info")
        finally:
            bad.close()
    assert "401" in str(exc.value) or "auth" in str(exc.value).lower()


def test_demo_rejects_a_naive_event_window_like_the_device(
    demo_client: IsapiClient,
) -> None:
    """The recorded `badJsonContent`/errorMsg=startTime rejection (OBSERVED.md 2026-10-17).

    A demo fake more lenient than the device is the false-green machine this repo's
    history keeps naming: a developer who builds a window without an offset must get the
    same 400 here that the real box gives, not a friendly page of rows.
    """
    naive = {
        "AcsEventCond": {
            "startTime": "2026-06-15T08:00:00",
            "endTime": "2026-06-15T18:00:00",
            "major": 0,
            "minor": 0,
        }
    }
    with pytest.raises(IsapiError) as exc:
        demo_client.search("acs_event_search", naive)

    envelope = exc.value.envelope
    assert envelope["statusCode"] == 6
    assert envelope["subStatusCode"] == "badJsonContent"
    assert envelope["errorMsg"] == "startTime"


def test_demo_rejects_a_fractional_event_window_like_the_device(
    demo_client: IsapiClient,
) -> None:
    """The second leg of the same rule: sub-second bounds 400 too (OBSERVED 2026-10-21)."""
    fractional = {
        "AcsEventCond": {
            "startTime": "2026-06-15T08:00:00.123456+02:00",
            "endTime": "2026-06-15T18:00:00.123456+02:00",
            "major": 0,
            "minor": 0,
        }
    }
    with pytest.raises(IsapiError) as exc:
        demo_client.search("acs_event_search", fractional)
    assert exc.value.envelope["errorMsg"] == "startTime"


def test_demo_answers_a_path_it_never_served_with_the_recorded_not_support(
    demo_client: IsapiClient,
) -> None:
    """`AcsEvent/Total` — the name you would guess — is `400 notSupport` on this firmware.

    The demo box answers with the RECORDED envelope shape (statusCode 4 / notSupport /
    errorCode 1073741825), because "not registered anywhere" is a device fact the demo
    must reproduce or a developer's exploratory curl teaches them the wrong lesson.
    """
    import httpx

    response = demo_client.raw.post(
        "/ISAPI/AccessControl/AcsEvent/Total?format=json",
        auth=httpx.DigestAuth(DEMO_USER, DEMO_PASSWORD),
        content=b"{}",
        headers={"Content-Type": "application/json"},
    )

    assert response.status_code == 400
    envelope = response.json()
    assert envelope["statusCode"] == 4
    assert envelope["subStatusCode"] == "notSupport"


def test_demo_serves_only_the_verbs_the_read_only_client_can_use(
    demo_device: demo.DemoDevice,
    demo_client: IsapiClient,
) -> None:
    """The read-only guarantee, checked on the server side of a real socket."""
    demo_client.get("device_info")
    demo_client.get("system_time")
    demo_client.get("user_info_count")
    demo_client.search(
        "user_info_search",
        {"UserInfoSearchCond": {"searchID": "s", "searchResultPosition": 0, "maxResults": 30}},
    )

    verbs = {record.method for record in demo_device.requests}
    assert verbs <= {"GET", "POST"}, f"demo box saw a mutating verb: {verbs}"
    posts = {r.path for r in demo_device.requests if r.method == "POST"}
    # `RequestedCall.path` is the request-target AS RECEIVED (query included, which is
    # what digest HA2 hashes — gotchas §1.4), so compare against the registry's
    # `url_path`, which carries the same `?format=json` suffix.
    allowed_posts = {REGISTRY[name].url_path for name in SEARCH_ENDPOINTS}
    assert posts <= allowed_posts


# --- ARM B: SYNTHETIC PROOF -------------------------------------------------------------


def test_capture_files_exist() -> None:
    assert CAPTURE_FILES, "docs/OBSERVED*.md are the shape truth; without them B is vacuous"


@pytest.mark.parametrize("needle", demo.SYNTHETIC_FIXTURE_STRINGS)
def test_no_demo_fixture_constant_appears_in_the_recorded_captures(needle: str) -> None:
    """Demo values must never be copied out of a capture — scanned string by string."""
    hits = [
        f"{path.relative_to(REPO_ROOT)}:{line}"
        for path in CAPTURE_FILES
        for line, text in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1)
        if needle in text
    ]
    assert not hits, f"demo value {needle!r} appears in the recorded captures at {hits}"


def test_captures_are_scanned_both_ways() -> None:
    """Guard the guard: the reverse direction must be scanning real capture content.

    An empty capture set or a token extractor that finds nothing makes ARM B vacuously
    green — exactly the failure mode this arm exists to prevent.
    """
    tokens = capture_identity_tokens(CAPTURE_PATHS)
    assert len(tokens) > 20, f"only {len(tokens)} capture tokens extracted"
    assert "MASKED-SER-1" in tokens, "the masked serial in the fixtures must be visible"
    assert any(t.startswith("User E") for t in tokens), "captured person names must be visible"


def test_scan_needs_no_short_or_numeric_tokens() -> None:
    """Guard the guard #2: a needle list of `"30"`/`"ACS"` would make ARM B meaningless.

    Caps and vocabulary numbers legitimately appear in both the captures and the demo
    corpus (the demo box clamps to the same advertised cap the device does), so the
    scanned constants are the *identity* strings — long, non-numeric, and unambiguous.
    """
    assert demo.SYNTHETIC_FIXTURE_STRINGS, "the demo corpus must declare its own constants"
    for needle in demo.SYNTHETIC_FIXTURE_STRINGS:
        assert len(needle) >= 6, f"{needle!r} is too short to be a meaningful needle"
        assert not needle.replace(".", "").isdigit(), f"{needle!r} is numeric, not an identity"


@pytest.mark.parametrize("key", ["name", "serialNumber", "cardNo"])
def test_no_capture_identity_value_is_a_demo_value(key: str) -> None:
    """Direction 2 of the synthetic proof: no capture person/serial/card may be demo data.

    Reads the recorded captures (`docs/OBSERVED*.md` **and** every committed fixture) for
    one identity key and requires that NONE of those values is what the demo box answers.
    Reading both directions matters: ARM B1 stops a demo string leaking into a capture,
    this one stops a captured identity leaking into the demo — the copy-paste that would
    ship a real enrollee's name inside a developer-facing fixture.
    """
    values = capture_values_for_key(CAPTURE_PATHS, key)
    assert values, f"no {key!r} found in the recorded captures — scanner is broken"
    offenders = sorted(values & demo.demo_answered_values())
    assert not offenders, f"demo box answers capture-identities for {key}: {offenders}"


def test_demo_identity_values_are_self_labelling() -> None:
    """Every demo identity says it is a demo: serials `DEMO-SERIAL-*`, cards
    `DEMO-CARD-*`, person names built on `Demo`.

    This is what makes the SYNTHETIC-ONLY LAW visible to a human reading `gateclerk users
    list` against the box, not just to this test suite — and it is why the card numbers
    are strings with a `DEMO-` prefix rather than plausible digits: the recorded caps
    describe `cardNo` as a 1..20-character string, so a marker inside the value is
    faithful to the shape while refusing to look like a real credential.
    """
    assert demo.DEMO_SERIAL.startswith("DEMO-SERIAL-")
    assert all(card.startswith("DEMO-CARD-") for card in demo.demo_card_numbers())
    names = demo.demo_user_names()
    assert names, "the demo roster must have people"
    assert all(name.split()[0] in ("Demo", "Demoana") for name in names), names
    assert all(demo.is_synthetic_serial(s) for s in demo.demo_answered_values("serialNumber"))


def test_demo_addresses_are_rfc5737_or_loopback_only() -> None:
    """SYNTHETIC-ONLY LAW for the addresses the demo box puts on the wire."""
    for ip in demo.demo_answered_addresses():
        assert demo.is_synthetic_address(ip), f"{ip} is not RFC 5737 / loopback"
    assert demo.DEMO_BIND_HOST == "127.0.0.1"
    assert demo.DEMO_DOCUMENT_HOST in ("192.0.2.10", "198.51.100.10", "203.0.113.10")


def test_demo_device_module_lives_in_the_product_not_in_tests() -> None:
    """The CLI must be able to serve the box, so the module is product code.

    (The shape constants stay shared with `tests/fakedevice.py`, which imports them —
    one shape source, direction tests -> product, so the offline fake and the demo box
    cannot drift into two dialects.)
    """
    module_path = Path(demo.__file__).resolve()
    assert module_path.is_relative_to(REPO_ROOT / "src" / "gateclerk")
    from fakedevice import REALM as fake_realm  # noqa: N811  (masked-realm constant, two homes)

    assert fake_realm == demo.DEMO_REALM, "one masked realm, two homes would drift"


# --- ARM C: the pagination contract, over the same socket --------------------------------


def test_event_search_pages_over_http_and_terminates_like_the_device(
    demo_client: IsapiClient,
) -> None:
    """The client's own walker against the demo box: MORE, MORE, OK, stop.

    The fake clamps `maxResults` SILENTLY to the advertised cap (both recorded sites do
    this — OBSERVED.md site-B §"Silent maxResults clamp"), answers `MORE` while rows
    remain and `OK` on the last page, and the client advances by the returned
    `numOfMatches`. If the fake returned `OK` on a truncated page, or advanced by the
    requested size, this walk would come up short.
    """
    window = _window()
    cond = build_event_cond(window, device_offset_min=demo.DEMO_CLAIMED_OFFSET_MIN)
    engine = PagedSearch(
        lambda body: demo_client.search("acs_event_search", body),
        endpoint="acs_event_search",
        cond_key="AcsEventCond",
        envelope_key="AcsEvent",
        record_key="InfoList",
        limits=PagingLimits(max_results=demo.DEMO_MAX_RESULTS_CAP),
        page_size=demo.DEMO_MAX_RESULTS_CAP,
        inter_page_delay=0.0,
    )
    pages = list(engine.pages(cond))

    expected_events = demo.demo_events()
    # Exact page count: the fake clamps every page to the advertised cap and only
    # the LAST page is short, so ceil(events / cap) pages — no approx needed.
    assert len(pages) == -(-len(expected_events) // demo.DEMO_MAX_RESULTS_CAP)
    assert [p.status for p in pages[:-1]] == ["MORE"] * (len(pages) - 1)
    assert pages[-1].status == "OK"
    assert sum(p.num_of_matches for p in pages) == len(expected_events)
    collected = [row for page in pages for row in page.records]
    assert [row["serialNo"] for row in collected] == [e["serialNo"] for e in expected_events]
    assert engine.summary is not None
    assert engine.summary.pages == len(pages)
    assert engine.summary.termination == "OK"


def test_event_search_asking_past_the_cap_is_clamped_silently(
    demo_client: IsapiClient,
) -> None:
    """`maxResults:100` on a cap-30 box: no error, no echo — just 30 rows and MORE."""
    window = _window()
    cond = build_event_cond(window, device_offset_min=demo.DEMO_CLAIMED_OFFSET_MIN)
    body = demo_client.search(
        "acs_event_search",
        {
            "AcsEventCond": {
                **cond,
                "searchID": "clamp",
                "searchResultPosition": 0,
                "maxResults": 100,
            }
        },
    )

    acs = body["AcsEvent"]
    assert acs["numOfMatches"] == demo.DEMO_MAX_RESULTS_CAP
    assert acs["responseStatusStrg"] == "MORE"
    assert acs["totalMatches"] == len(demo.demo_events())


def test_empty_window_answers_no_match_with_infolist_absent(demo_client: IsapiClient) -> None:
    """OBSERVED.md's empty shape: `NO MATCH` (with the space) and NO `InfoList` key."""
    window = _window(start="2026-01-01T08:00:00", end="2026-01-01T09:00:00")
    cond = build_event_cond(window, device_offset_min=demo.DEMO_CLAIMED_OFFSET_MIN)
    body = demo_client.search(
        "acs_event_search",
        {
            "AcsEventCond": {
                **cond,
                "searchID": "empty",
                "searchResultPosition": 0,
                "maxResults": 30,
            }
        },
    )

    acs = body["AcsEvent"]
    assert acs["responseStatusStrg"] == "NO MATCH"
    assert acs["numOfMatches"] == 0
    assert "InfoList" not in acs


def test_demo_serves_the_advertised_cap_from_capabilities(demo_client: IsapiClient) -> None:
    """`AcsEvent/capabilities` is what p1-04 reads to learn the cap — it must say 30."""
    body = demo_client.get("acs_event_capabilities")
    assert body["AcsEvent"]["AcsEventCond"]["maxResults"]["@max"] == demo.DEMO_MAX_RESULTS_CAP


def test_demo_total_num_probe_agrees_with_the_paged_count(demo_client: IsapiClient) -> None:
    """`AcsEventTotalNum` is the advisory cross-check the `--count` flag shows."""
    window = _window()
    cond = build_event_cond(window, device_offset_min=demo.DEMO_CLAIMED_OFFSET_MIN)
    body = demo_client.search("acs_event_total_num", {"AcsEventTotalNumCond": {**cond}})
    assert body["AcsEventTotalNum"]["totalNum"] == len(demo.demo_events())


# --- ARM D: the CLI surface + loopback discipline ----------------------------------------


def test_cli_exposes_demo_device_serve_and_urls() -> None:
    from _cli_surface import command_at, declared_flags

    root = command_at(cli_mod.app, ["demo", "device"])
    assert set(getattr(root, "commands", {})) == {"serve", "urls"}
    flags = declared_flags(command_at(cli_mod.app, ["demo", "device", "serve"]))
    assert {"--host", "--port"} <= flags
    help_text = runner.invoke(cli_mod.app, ["demo", "--help"])
    assert help_text.exit_code == 0
    assert "device" in help_text.output


def test_cli_demo_device_serve_binds_loopback_and_answers(demo_device: demo.DemoDevice) -> None:
    """`serve` runs the box; the test drives one instance and reads it back.

    The CLI command owns the serve loop (start + wait + shutdown), so this arm drives
    `serve` itself on a bounded duration and hits the box it chose, which is the only way
    to pin that the flag parsing, the loopback bind and the server share one object.
    """
    with ThreadPoolExecutor(max_workers=1) as pool:
        result = pool.submit(
            runner.invoke,
            cli_mod.app,
            ["demo", "device", "serve", "--port", "0", "--seconds", "3"],
        )
        base_url = _await_box_url(60.0)
        client = IsapiClient(base_url, DEMO_USER, DEMO_PASSWORD, connect_timeout=5.0)
        try:
            body = client.get("device_info")
        finally:
            client.close()
        served = result.result(timeout=60)

    assert served.exit_code == 0, served.output
    # `parse_body` strips the XML root, so deviceInfo arrives FLAT (the same shape
    # ARM A pins for the fixture-driven client) — not `{"model": {"value": ...}}`.
    assert body["model"] == demo.DEMO_MODEL
    assert body["serialNumber"] == demo.DEMO_SERIAL


def test_serve_refuses_a_non_loopback_host_by_default() -> None:
    """SYNTHETIC-ONLY LAW, enforced by the server: no accidental LAN exposure.

    A developer typing a wildcard bind host (all interfaces) must be refused unless they
    also opt in: this box answers ISAPI-shaped data and its default is loopback, not
    "whatever interface the laptop has".
    """
    result = runner.invoke(
        cli_mod.app, ["demo", "device", "serve", "--host", "192.0.2.10", "--seconds", "0.1"]
    )
    assert result.exit_code != 0
    assert "loopback" in (result.output or "").lower()


def test_event_serials_are_advanceable_and_deterministic() -> None:
    """Deterministic by default, advanceable on request (card: "deterministic or
    advanceable event serials") — two builds of the corpus must agree exactly."""
    assert [e["serialNo"] for e in demo.demo_events()] == list(
        range(demo.DEMO_FIRST_SERIAL, demo.DEMO_FIRST_SERIAL + demo.DEMO_EVENT_COUNT)
    )
    assert demo.demo_events() == demo.demo_events()


# --- helpers ----------------------------------------------------------------------------


def capture_identity_tokens(paths: tuple[Path, ...] | list[Path]) -> set[str]:
    """Every identity-shaped token appearing in the recorded captures.

    Two sources, because "the captures" means both the probe transcript and the committed
    fixtures: markdown from `docs/OBSERVED*.md` (scanned for the same token shapes a human
    would recognise) and JSON from `tests/fixtures/**` (read as JSON, so the values under
    the identity keys are extracted rather than guessed at by regex).

    A token qualifies when it is one of the recorded masking conventions (`MASKED-*`,
    `User E<n>`) or is a string the captures store under an identity key. The result only
    ever has to be a superset of what the demo box could have copied — this is a leak
    detector, not a parser.
    """
    tokens: set[str] = set()
    masked = re.compile(r"\b(?:MASKED|DEMO|FAKE|SYNTHETIC)[-_A-Za-z0-9]*\b")
    named = re.compile(r"\bUser (?:E\d+|T90|E\?|Unknown)\b")
    for path in paths:
        text = path.read_text(encoding="utf-8")
        if path.suffix == ".json":
            tokens.update(_json_identity_values(text))
            continue
        tokens.update(masked.findall(text))
        tokens.update(named.findall(text))
    return tokens


def capture_values_for_key(paths: tuple[Path, ...] | list[Path], key: str) -> set[str]:
    """Every string the captures store under `key`, from JSON fixtures and transcripts.

    The markdown leg is a `"key":"value"` scan rather than a parse because the probe
    transcript records JSON inline (OBSERVED.md's sample records) and also names values
    in prose; anything found here is a value a real capture asserted, which is precisely
    what must never be a demo answer. The XML leg (`<key>value</key>`) exists because
    the recorded `device_info.xml` / `system_time.xml` store their identities that way —
    System/* answers XML despite `?format=json` (OBSERVED.md delta 1).
    """
    values: set[str] = set()
    inline = re.compile(rf'"{re.escape(key)}"\s*:\s*"([^"]*)"')
    tag = re.compile(rf"<{re.escape(key)}>([^<]*)</{re.escape(key)}>")
    for path in paths:
        text = path.read_text(encoding="utf-8")
        values.update(inline.findall(text))
        values.update(tag.findall(text))
        if path.suffix == ".json":
            values.update(_walk_strings(json.loads(text), key))
    return {v for v in values if v}


def _json_identity_values(text: str) -> set[str]:
    try:
        blob = json.loads(text)
    except (json.JSONDecodeError, ValueError):
        return set()
    out: set[str] = set()
    for key in _IDENTITY_KEYS:
        out.update(_walk_strings(blob, key))
    return out


def _walk_strings(node: object, key: str) -> Iterator[str]:
    if isinstance(node, dict):
        for k, v in node.items():
            if k == key and isinstance(v, str):
                yield v
            yield from _walk_strings(v, key)
    elif isinstance(node, list):
        for item in node:
            yield from _walk_strings(item, key)


def _window(*, start: str = "2026-06-15T08:00:00", end: str = "2026-06-15T18:00:00"):
    """A DeviceWindow for the demo day, in the demo site tz (Europe/Bucharest)."""
    from gateclerk.tz import parse_user_timestamp, window_for_device

    since = parse_user_timestamp(f"{start}+03:00", site_tz=demo.DEMO_SITE_TZ)
    until = parse_user_timestamp(f"{end}+03:00", site_tz=demo.DEMO_SITE_TZ)
    return window_for_device(since, until, site_tz=demo.DEMO_SITE_TZ)


def _digest_header(*, username: str, password: str, method: str, uri: str, nonce: str) -> str:
    """Build a legal qop=auth Authorization header for the raw client."""
    fields = {"qop": "auth", "nc": "00000001", "cnonce": "raW4Ndj8sdE"}
    response = expected_response(username, password, fields, nonce, method=method, uri=uri)
    return (
        f'Digest username="{username}", realm="{REALM}", nonce="{nonce}", uri="{uri}", '
        f'qop=auth, nc=00000001, cnonce="{fields["cnonce"]}", response="{response}"'
    )


class _RawLoopbackClient:
    """The smallest possible HTTP/1.1 client, so ARM A cannot lean on httpx's auth.

    One fresh connection per request: the client declares `Connection: close`, and the
    server honours it (like `webs` does), so a second request on the same socket would
    write into a closed connection and read an empty status line.
    """

    def __init__(self, host: str, port: int) -> None:
        self._host = host
        self._port = port
        self._sock: socket.socket | None = None

    def __enter__(self) -> _RawLoopbackClient:
        return self

    def __exit__(self, *exc: object) -> None:
        self._close()

    def _close(self) -> None:
        if self._sock is not None:
            self._sock.close()
            self._sock = None

    def request(
        self, method: str, path: str, *, authorization: str | None = None
    ) -> tuple[int, dict[str, str], bytes]:
        self._close()
        self._sock = socket.create_connection((self._host, self._port), timeout=10)
        sock = self._sock
        assert sock is not None
        lines = [f"{method} {path} HTTP/1.1", f"Host: {self._host}:{self._port}"]
        if authorization:
            auth_line = "Authorization: " + authorization
            lines.append(auth_line)
        lines += ["Connection: close", "", ""]
        sock.sendall("\r\n".join(lines).encode("ascii"))
        raw = b"".join(iter(lambda: sock.recv(65536), b""))
        head, _, body = raw.partition(b"\r\n\r\n")
        status_line, *header_lines = head.decode("latin-1").split("\r\n")
        status = int(status_line.split(" ")[1])
        headers = {
            line.split(":", 1)[0].strip().lower(): line.split(":", 1)[1].strip()
            for line in header_lines
            if ":" in line
        }
        return status, headers, body


def _await_box_url(timeout: float) -> str:
    """Read the base URL the `serve` command printed (it holds the bound ephemeral port)."""
    import time

    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        url = demo.last_served_url()
        if url is not None:
            return url
        time.sleep(0.05)
    raise AssertionError("the demo serve command never reported its URL")
