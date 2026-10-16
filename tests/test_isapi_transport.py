"""IsapiClient against FakeDevice: digest session, timeouts, bounded retries, circuit.

Every scenario in the card's Definition of Done is one of these tests:
digest handshake, stale-nonce retry exactly once, 401 stops without a lockout loop,
busy backoff respects its caps, BadContent messages carry the request body, and the
read-only guarantee. All offline: FakeDevice is an httpx.MockTransport, and the
autouse socket guard in conftest still bites if anything here sprouts a real socket.
"""

from __future__ import annotations

import httpx
import pytest

from fakedevice import BASE_URL, FAKE_HOST, NONCE, FakeDevice
from gateclerk.endpoints import REGISTRY, SEARCH_ENDPOINTS
from gateclerk.exceptions import (
    IsapiAuthError,
    IsapiBadContent,
    IsapiBusy,
    IsapiError,
    IsapiLocalNetworkError,
    IsapiNotFound,
    GateclerkError,
)
from gateclerk.isapi_transport import (
    DEFAULT_CONNECT_TIMEOUT,
    DEFAULT_READ_TIMEOUT,
    IsapiClient,
)

DEVICE_INFO = "/ISAPI/System/deviceInfo?format=json"
EVENT_SEARCH = "/ISAPI/AccessControl/AcsEvent?format=json"
PASSWORD = "fakepw"  # matches tests/test_repo_hygiene.py placeholder policy


def make_client(device: FakeDevice, **kw: object) -> IsapiClient:
    kw.setdefault("sleep", lambda _s: None)  # tests never actually wait
    return IsapiClient(
        BASE_URL,
        "admin",
        PASSWORD,
        transport=device.transport,
        **kw,  # type: ignore[arg-type]
    )


# --- digest handshake ----------------------------------------------------------------


def test_digest_handshake_costs_two_requests_then_reuses_nonce() -> None:
    """Unauthenticated call -> 401 challenge -> one authenticated retry (2 requests,
    1 challenge); the NEXT call rides the cached nonce (still 1 challenge total).
    This is the card's 'one client owns the digest state' requirement, and the
    efficiency that 'fresh DigestAuth per call' would double (gotchas §1.7a)."""
    device = FakeDevice()
    device.json_ok("GET", DEVICE_INFO, {"DeviceInfo": {"model": "DS-K1T341AMF-S"}})
    client = make_client(device)

    body = client.get("device_info")
    assert body["DeviceInfo"]["model"] == "DS-K1T341AMF-S"
    assert len(device.served) == 2
    assert device.served[0].had_auth is False
    assert device.served[1].had_auth is True
    assert device.challenges == 1

    client.get("device_info")
    assert len(device.served) == 3
    assert device.challenges == 1, "second call must NOT re-pay the 401"
    auth = device.served[2].digest
    assert auth["nonce"] == NONCE
    assert auth["nc"] == "00000002", "nc climbs monotonically across calls (01 on retry, 02 next)"


def test_digest_uri_includes_format_json_query() -> None:
    """gotchas §1.4: HA2 over path-only is an infinite 401 loop with a CORRECT password.
    The wire header's uri= must carry ?format=json, byte-identical to the request line —
    and FakeDevice only authorises when HA2 matches the real request-target, so a
    query-stripping client would 401-loop here and fail this test."""
    device = FakeDevice()
    device.json_ok("POST", EVENT_SEARCH, {"AcsEvent": {"responseStatusStrg": "OK"}})
    client = make_client(device)
    client.search("acs_event_search", {"AcsEventCond": {"searchID": "x" * 16}})

    authed = [s for s in device.served if s.had_auth]
    assert authed, "expected an authenticated attempt"
    last = authed[-1].digest
    assert last["uri"] == EVENT_SEARCH
    assert last["uri"].endswith("?format=json")
    assert device.challenges == 1, "no 401 loop"


def test_digest_qop_auth_realm_and_server_match_the_recorded_challenge() -> None:
    """The fake mirrors OBSERVED.md (realm DS-39DED0D1, qop=auth, Server: webs); the
    client must complete the flow against exactly that shape."""
    device = FakeDevice()
    device.json_ok("GET", DEVICE_INFO, {"DeviceInfo": {}})
    make_client(device).get("device_info")
    assert device.served[-1].digest["qop"] == "auth"
    assert device.served[-1].digest["realm"] == "DS-39DED0D1"


def test_wrong_password_costs_two_requests_and_raises_auth_error() -> None:
    """A wrong password = one challenge + one rejected retry, then IsapiAuthError.
    Two requests, not a loop (the lockout defence; gotchas §1.5/§2.4)."""
    device = FakeDevice(password="fakepw-wrong")  # fake-prefix: hygiene policy
    device.json_ok("GET", DEVICE_INFO, {"DeviceInfo": {}})
    client = make_client(device)
    with pytest.raises(IsapiAuthError):
        client.get("device_info")
    assert len(device.served) == 2
    assert device.challenges == 2, "the retry with credentials was itself rejected"


def test_client_uses_httpx_digest_auth_and_never_basic() -> None:
    """Structural pins for the auth choice (DESIGN.md/gotchas §1.6: digest-only, no
    Basic fallback — Basic would put the password on the wire). The client's auth is
    an httpx.DigestAuth; and FakeDevice itself proves it is not a pushover: a Basic
    header gets the same 401 challenge as no header at all."""
    device = FakeDevice()
    device.json_ok("GET", DEVICE_INFO, {"DeviceInfo": {}})
    client = make_client(device)
    assert isinstance(client._auth, httpx.DigestAuth)

    probe = httpx.Client(transport=device.transport, base_url=BASE_URL)
    resp = probe.get(DEVICE_INFO, headers={"Authorization": "Basic YWRtaW46ZmF1dHB3"})
    assert resp.status_code == 401, "the fake never accepts Basic — neither may we"
    assert resp.headers["www-authenticate"].lower().startswith("digest")
    probe.close()


# --- stale nonce ------------------------------------------------------------------------


def test_stale_nonce_recovers_in_exactly_one_extra_roundtrip() -> None:
    """Server rotates the nonce mid-session (webs does this). Expected: the request is
    re-paid exactly once (3 requests total: primed 200, 401, authenticated 200) and
    the new nonce is taken with nc reset (gotchas §1.5, card DoD)."""
    device = FakeDevice()
    device.json_ok("GET", DEVICE_INFO, {"DeviceInfo": {"model": "X"}})
    client = make_client(device)
    client.get("device_info")  # prime the nonce
    assert device.challenges == 1

    # Device expires the nonce: new nonce accepted, old one no longer valid.
    device.accepted_nonces = {"FRESH-NONCE-2"}
    device.challenge_nonce = "FRESH-NONCE-2"
    device.stale_flag = "true"

    body = client.get("device_info")
    assert body["DeviceInfo"]["model"] == "X"
    assert len(device.served) == 4, "one stale re-challenge = exactly 2 more requests"
    assert device.challenges == 2, "the stale 401 is the only extra challenge"
    final = device.served[-1]
    assert final.digest["nonce"] == "FRESH-NONCE-2"
    assert final.digest["nc"] == "00000001", "nc resets with the new nonce"


# --- 401 discipline / lockout --------------------------------------------------------------


def test_401_stops_after_two_attempts_no_lockout_loop() -> None:
    """Card DoD: 401 stops after max 2 attempts total, then the circuit opens; ten
    further calls touch the device ZERO times. The device locks accounts after ~5
    failed logins — a loop here is a door-terminal outage (DESIGN.md)."""
    device = FakeDevice(password="fakepw-wrong")
    device.json_ok("GET", DEVICE_INFO, {})
    client = make_client(device)

    with pytest.raises(IsapiAuthError):
        client.get("device_info")
    assert len(device.served) == 2, "exactly challenge + one retry"

    with pytest.raises(IsapiAuthError, match="circuit open"):
        client.get("device_info")
    assert len(device.served) == 2, "second call never reached the device"
    for _ in range(10):
        with pytest.raises(IsapiAuthError):
            client.get("device_info")
    assert len(device.served) == 2, "no lockout loop, ever"


def test_circuit_honours_unlock_time_from_the_401_body() -> None:
    """DESIGN.md: circuit-open for unlockTime + margin, never folklore. A 401 whose
    userCheck body says unlockTime=1800 must keep the circuit closed for ~that long;
    after it expires the client tries again."""
    device = FakeDevice(password="fakepw-wrong")
    device.json_ok("GET", DEVICE_INFO, {})

    def lockout_401() -> httpx.Response:
        return httpx.Response(
            401,
            headers={
                "WWW-Authenticate": (
                    'Digest qop="auth", realm="DS-39DED0D1", nonce="MASKED-NONCE", stale="false"'
                ),
                "Server": "webs",
            },
            content=b"<userCheck><statusValue>401</statusValue>"
            b"<lockStatus>locked</lockStatus><unlockTime>1800</unlockTime></userCheck>",
        )

    # Both the challenge AND the authenticated retry answer locked (raw queue: served
    # regardless of Authorization, drained in order) — the client's LAST sight of the
    # device before giving up is unlockTime=1800.
    device.add_raw("GET", DEVICE_INFO, lockout_401(), lockout_401())
    clock = {"t": 1000.0}
    client = make_client(device, now=lambda: clock["t"], circuit_margin_seconds=10.0)

    with pytest.raises(IsapiAuthError) as excinfo:
        client.get("device_info")
    assert excinfo.value.unlock_time == 1800
    assert excinfo.value.locked is True

    clock["t"] += 1805  # inside the window (1800 + 10 margin)
    with pytest.raises(IsapiAuthError, match="circuit open"):
        client.get("device_info")

    clock["t"] += 10  # past the margin: the client may knock again
    with pytest.raises(IsapiAuthError):
        client.get("device_info")
    assert len(device.served) == 4, "exactly the two pre-window attempts + two post-window"


def test_reset_circuit_reopens_after_operator_verification() -> None:
    device = FakeDevice(password="fakepw-wrong")
    device.json_ok("GET", DEVICE_INFO, {})
    client = make_client(device)
    with pytest.raises(IsapiAuthError):
        client.get("device_info")
    assert client.circuit_open()
    client.reset_circuit()
    assert not client.circuit_open()


# --- timeouts -----------------------------------------------------------------------------


def test_default_timeouts_connect_10_read_30() -> None:
    """Card + DESIGN.md 'Half-open TCP': connect 10 s, read 30 s defaults."""
    device = FakeDevice()
    client = make_client(device)
    assert client.timeout.connect == DEFAULT_CONNECT_TIMEOUT == 10.0
    assert client.timeout.read == DEFAULT_READ_TIMEOUT == 30.0


def test_timeouts_are_configurable() -> None:
    device = FakeDevice()
    client = make_client(device, connect_timeout=2.5, read_timeout=7.5)
    assert client.timeout.connect == 2.5
    assert client.timeout.read == 7.5


def test_read_timeout_surfaces_as_isapi_error_not_raw_httpx() -> None:
    """The public failure vocabulary is IsapiError: callers must not need to import
    httpx to handle a device that stopped answering."""
    device = FakeDevice()
    device.add_raw(
        "GET", DEVICE_INFO, httpx.ReadTimeout("timed out", request=httpx.Request("GET", BASE_URL))
    )
    client = make_client(device, transport_retries=0)
    with pytest.raises(IsapiError):
        client.get("device_info")


def test_dropped_keepalive_retries_once_transparently() -> None:
    """Card: connection reuse stays on, and one dropped keep-alive (the classic
    webs idle-close race) is recovered transparently with ONE retry."""
    device = FakeDevice()
    doomed = httpx.ConnectError(
        "[Errno 54] Connection reset by peer", request=httpx.Request("GET", BASE_URL)
    )
    device.add_raw("GET", DEVICE_INFO, doomed, device.challenge())  # reset, then normal flow
    device.json_ok("GET", DEVICE_INFO, {"DeviceInfo": {"model": "recovered"}})
    client = make_client(device)
    body = client.get("device_info")
    assert body["DeviceInfo"]["model"] == "recovered"


def test_transport_failure_bounded_then_named_error() -> None:
    """Two consecutive resets (transport_retries=1) -> IsapiError mentioning the
    retries. The client does not grind a dead device."""
    device = FakeDevice()
    err1 = httpx.ConnectError("reset A", request=httpx.Request("GET", BASE_URL))
    err2 = httpx.ConnectError("reset B", request=httpx.Request("GET", BASE_URL))
    device.add_raw("GET", DEVICE_INFO, err1, err2)
    client = make_client(device)
    with pytest.raises(IsapiError, match="transport failure"):
        client.get("device_info")
    assert len(device.served) == 2


def test_macos_tcc_no_route_to_host_names_the_permission_fix() -> None:
    """OBSERVED.md delta (4): python gets '[Errno 65] No route to host' where curl
    works — macOS Local Network (TCC). The error must say so; a generic connect error
    sends someone debugging the device instead of the OS."""
    device = FakeDevice()
    err = httpx.ConnectError("[Errno 65] No route to host", request=httpx.Request("GET", BASE_URL))
    device.add_raw("GET", DEVICE_INFO, err, err)
    client = make_client(device)
    with pytest.raises(IsapiLocalNetworkError, match="Local Network"):
        client.get("device_info")


# --- busy / backoff ------------------------------------------------------------------------


def busy_503() -> httpx.Response:
    return httpx.Response(
        503,
        content=b'<?xml version="1.0"?><ResponseStatus><statusCode>2</statusCode>'
        b"<statusString>Device Busy</statusString><subStatusCode>deviceBusy</subStatusCode>"
        b"</ResponseStatus>",
        headers={"Content-Type": "application/xml"},
    )


def test_busy_backoff_is_exponential_capped_and_bounded() -> None:
    """Card DoD: busy backoff respects caps. Fresh client: challenge, then deviceBusy
    x3 with sleeps exactly [1, 2, 4] (base 1 cap 8), then success. The attempt cap is
    honoured too — the fifth request is the success, there is no sixth."""
    device = FakeDevice()
    sleeps: list[float] = []
    device.add_raw("POST", EVENT_SEARCH, device.challenge(), *[busy_503() for _ in range(3)])
    device.json_ok(
        "POST", EVENT_SEARCH, {"AcsEvent": {"responseStatusStrg": "OK", "numOfMatches": 0}}
    )
    client = make_client(
        device,
        sleep=sleeps.append,
        busy_max_attempts=4,
        busy_backoff_base=1.0,
        busy_backoff_cap=8.0,
    )
    out = client.search("acs_event_search", {"AcsEventCond": {"searchID": "s"}})
    assert out["AcsEvent"]["responseStatusStrg"] == "OK"
    assert sleeps == [1.0, 2.0, 4.0], "exponential schedule"
    assert len(device.served) == 5, "challenge + 3 busy + success, and NO extra attempt"


def test_busy_backoff_cap_holds_across_long_bursts() -> None:
    """Every delay stays <= cap even when the burst outlasts the cap's exponent."""
    device = FakeDevice()
    sleeps: list[float] = []
    device.add_raw("POST", EVENT_SEARCH, device.challenge(), *[busy_503() for _ in range(5)])
    device.json_ok("POST", EVENT_SEARCH, {"AcsEvent": {"responseStatusStrg": "OK"}})
    client = make_client(
        device,
        sleep=sleeps.append,
        busy_max_attempts=6,
        busy_backoff_base=1.0,
        busy_backoff_cap=2.0,
    )
    client.search("acs_event_search", {"AcsEventCond": {"searchID": "s"}})
    assert sleeps == [1.0, 2.0, 2.0, 2.0, 2.0], "growth clamps at the cap, never above"


def test_busy_exhaustion_raises_isapi_busy() -> None:
    """A device that never un-busies: give up after busy_max_attempts attempts and
    raise IsapiBusy — the caller decides, we never hammer forever."""
    device = FakeDevice()
    device.add_raw("POST", EVENT_SEARCH, device.challenge(), busy_503(), busy_503())
    client = make_client(device, sleep=lambda _s: None, busy_max_attempts=2)
    with pytest.raises(IsapiBusy):
        client.search("acs_event_search", {"AcsEventCond": {"searchID": "s"}})
    assert len(device.served) == 3, "challenge + 2 busy attempts, then stop"


def test_status_code_3_is_retried_exactly_once() -> None:
    """DESIGN.md retry table: statusCode 3 -> once, then surface (vendor class 3,
    gotchas §7.4). Two deviceError replies = give up after exactly one retry."""
    device = FakeDevice()
    device_error = httpx.Response(
        400,
        content=b'{"statusCode":3,"statusString":"Device Error","subStatusCode":"deviceError"}',
        headers={"Content-Type": "application/json"},
    )
    device.add_raw("GET", DEVICE_INFO, device_error, device_error)
    client = make_client(device)
    with pytest.raises(IsapiError) as excinfo:
        client.get("device_info")
    assert not isinstance(excinfo.value, IsapiBadContent | IsapiBusy)
    assert len(device.served) == 2, "attempt + exactly one retry, then surface"


# --- search POST retry semantics -------------------------------------------------------------


def test_search_retry_reuses_identical_search_id_bytes() -> None:
    """Card: search POSTs are safe to retry with the SAME searchID (stateless search,
    device dedupes by cursor). A transport error mid-search must resend byte-identical
    body — same searchID, same position — or the device sees a different query."""
    device = FakeDevice()
    body = {
        "AcsEventCond": {
            "searchID": "feedfacecafebeef",
            "searchResultPosition": 0,
            "maxResults": 30,
        }
    }
    doomed = httpx.ConnectError("keep-alive died", request=httpx.Request("POST", BASE_URL))
    device.add_raw("POST", EVENT_SEARCH, doomed, device.challenge())
    device.json_ok("POST", EVENT_SEARCH, {"AcsEvent": {"responseStatusStrg": "MORE"}})
    client = make_client(device)

    out = client.search("acs_event_search", body)
    assert out["AcsEvent"]["responseStatusStrg"] == "MORE"

    posted = [s.body for s in device.served if s.method == "POST"]
    assert posted, "search was attempted"
    assert all(p == posted[0] for p in posted), "every POST carries byte-identical body"
    import json

    assert json.loads(posted[-1])["AcsEventCond"]["searchID"] == "feedfacecafebeef"


def test_bad_content_error_message_carries_the_exact_request_body() -> None:
    """Card DoD: BadContent messages contain the request body. The device's own answer
    is our debug output — DESIGN.md: badParameters is almost always our shape."""
    device = FakeDevice()
    sent = {"AcsEventCond": {"searchID": "s1", "maxResults": 32000}}
    device.add_raw("POST", EVENT_SEARCH, device.challenge())
    device.json_ok(
        "POST",
        EVENT_SEARCH,
        {
            "statusCode": 6,
            "statusString": "Invalid Message Content",
            "subStatusCode": "badParameters",
            "errorMsg": "maxResults out of range",
        },
    )
    client = make_client(device)
    with pytest.raises(IsapiBadContent) as excinfo:
        client.search("acs_event_search", sent)
    message = str(excinfo.value)
    assert '"maxResults":32000' in message
    assert "searchID" in message
    assert excinfo.value.request_body is not None
    assert "s1" in excinfo.value.request_body


def test_notsupport_surfaces_as_not_found() -> None:
    """The AcsEvent/Total-shaped failure (OBSERVED.md): 400+notSupport -> IsapiNotFound,
    NOT something to retry."""
    device = FakeDevice()
    device.add_raw("POST", EVENT_SEARCH, device.challenge())
    device.json_ok(
        "POST",
        EVENT_SEARCH,
        {
            "statusCode": 4,
            "statusString": "Invalid Operation",
            "subStatusCode": "notSupport",
            "errorCode": 1073741825,
            "errorMsg": "unknow",
        },
    )
    client = make_client(device)
    with pytest.raises(IsapiNotFound):
        client.search("acs_event_search", {"AcsEventCond": {}})


# --- read-only guarantee (CI-enforced, belt AND braces) ------------------------------------


def test_client_cannot_issue_a_write_even_if_asked() -> None:
    """The registry is closed, and the client double-checks: asking to POST a GET-only
    endpoint (or GET a POST-only one) is a hard GateclerkError BEFORE any request."""
    from gateclerk.endpoints import HttpMethod

    device = FakeDevice()
    client = make_client(device)
    with pytest.raises(GateclerkError, match="registered as GET"):
        client._call("user_info_count", HttpMethod.POST, payload={})
    with pytest.raises(GateclerkError, match="registered as POST"):
        client.get("acs_event_search")
    assert device.served == [], "refused calls must never reach the transport"


def test_every_registry_path_uses_only_get_or_the_two_search_posts() -> None:
    """Card DoD 'read-only guard test green', read from the transport side: the set of
    methods the CLIENT is even capable of constructing is {GET} union {the two POSTs}."""
    methods = {ep.method.value for ep in REGISTRY.values()}
    assert methods == {"GET", "POST"}
    posts = {name for name, ep in REGISTRY.items() if ep.method.value == "POST"}
    assert posts == set(SEARCH_ENDPOINTS) == {"user_info_search", "acs_event_search"}


def test_unknown_endpoint_name_cannot_smuggle_a_path() -> None:
    device = FakeDevice()
    client = make_client(device)
    with pytest.raises(KeyError, match="unknown endpoint"):
        client.get("/ISAPI/System/reboot")
    assert device.served == []


def test_shared_client_refuses_a_second_thread() -> None:
    """gotchas §1.7b: httpx.DigestAuth state is unlocked — a shared client across
    threads races the nc counter and can replay (nonce, nc). The client owns one
    digest session and refuses to be used from a second thread instead."""
    import threading

    device = FakeDevice()
    device.json_ok("GET", DEVICE_INFO, {"DeviceInfo": {}})
    client = make_client(device)
    client.get("device_info")  # binds the owner thread

    errors: list[BaseException] = []

    def intruder() -> None:
        try:
            client.get("device_info")
        except BaseException as exc:  # collected for the assertion below
            errors.append(exc)

    thread = threading.Thread(target=intruder)
    thread.start()
    thread.join()
    assert len(errors) == 1 and isinstance(errors[0], GateclerkError)
    assert "thread" in str(errors[0])
    # The guard refused BEFORE the transport: only the owner-thread call was served.
    assert len(device.served) == 2


# --- offline guarantee ------------------------------------------------------------------------


def test_offline_guard_still_bites_a_real_client(network_blocked: type[Exception]) -> None:
    """Meta-test: if someone points IsapiClient at a real host in a unit test, the
    conftest socket wall intercepts it — the MockTransport path is the only way out."""
    client = IsapiClient(f"http://{FAKE_HOST}", "admin", PASSWORD)  # no transport injected
    try:
        with pytest.raises(network_blocked):
            client.get("device_info")
    finally:
        client.close()
