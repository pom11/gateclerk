"""Nonce-retirement recovery in the 401 path (card t_a3521d8a).

The live symptom (docs/internal/OBSERVED.md "Digest nonce use-cap", owner run 2026-10-17): a
long `--chunk 1h` backfill died with **401 and the CORRECT password** at the ~190th
request, exit 3, device still unlocked. The mechanism was never captured on the wire, so
these tests drive all three candidate 401 shapes through the real client over
`FakeDevice` and pin what the transport does about each.

The shape map (docs/internal/FINDINGS-t_a3521d8a.md F1, established offline against the PRE-fix
client; the two stale shapes are still pinned separately so that "we survive both
spellings" is a tested claim and not an assumption):

  stale="true"     survived inside httpx (one extra request); never reaches our branch
  stale="false"    survived inside httpx, identically — it never reads `stale`
  envelope, no WWW-Authenticate   <-- THE repro; needs our recovery, and the only shape
                                    whose 401 reaches `IsapiClient._call` at all

Everything is offline: `FakeDevice` is an `httpx.MockTransport` and the autouse socket
guard in conftest still bites if anything here sprouts a real socket. The device is never
probed to find out which shape it is — a wrong-shape 401 can count toward lockout
accounting (card hard rule); the owner's re-run after merge is the live proof.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import httpx
import pytest

from fakedevice import (
    BASE_URL,
    REALM,
    RETIRE_ENVELOPE_ONLY,
    RETIRE_STALE_FALSE,
    RETIRE_STALE_TRUE,
    FakeDevice,
)
from gateclerk.exceptions import IsapiAuthError
from gateclerk.isapi_transport import IsapiClient
from gateclerk.paging import PagingLimits, iter_event_windows

DEVICE_INFO = "/ISAPI/System/deviceInfo?format=json"
EVENT_SEARCH = "/ISAPI/AccessControl/AcsEvent?format=json"
PASSWORD = "fakepw"  # hygiene placeholder (tests/test_repo_hygiene.py)

#: Site-tz-aware window for the walk pins: one hour, chunked hourly — the same shape the
#: live failure had (`--chunk 1h`), just short enough to assert page by page.
SITE_TZ = "Europe/Bucharest"
SINCE = datetime(2026, 9, 8, 19, 0, tzinfo=timezone(timedelta(hours=3)))
UNTIL = SINCE + timedelta(hours=1)

#: Walk size for the pins. The fake's per-nonce counter rises only on ACCEPTED requests,
#: so `retire_after=3` accepts three and retires on the next authorized one. Over a
#: 10-page walk that fires three times, with the refused request landing mid-walk rather
#: than at the end — which is the point: the retirement has to interrupt the walk.
#: Retiring every 4th request is deliberately far more aggressive than the live
#: 1-in-~190 cadence: if the budget survives this it certainly survives the real one, and
#: "more requests, same page count" is exactly the property the accounting pin checks.
#: `WALK_RETIREMENTS` is derived from these two constants rather than typed by hand, and
#: `device.retirements` is asserted against it so the scenario cannot silently stop
#: firing (a dead fixture would make every assertion below vacuous).
WALK_PAGES = 10
RETIRE_EVERY = 3
WALK_RETIREMENTS = -(-WALK_PAGES // (RETIRE_EVERY + 1))


def make_client(device: FakeDevice, **kw: object) -> IsapiClient:
    kw.setdefault("sleep", lambda _s: None)  # tests never actually wait
    return IsapiClient(
        BASE_URL,
        "admin",
        PASSWORD,
        transport=device.transport,
        **kw,  # type: ignore[arg-type]
    )


def event_page(index: int, *, last: bool) -> httpx.Response:
    """One 2-record AcsEvent page; the queue's last page terminates the walk."""
    return httpx.Response(
        200,
        json={
            "AcsEvent": {
                "responseStatusStrg": "OK" if last else "MORE",
                "numOfMatches": 2,
                "totalMatches": 2 * WALK_PAGES,
                "searchID": "walk",
                "InfoList": [
                    {"serialNo": 2 * index + 1, "employeeNoString": "1"},
                    {"serialNo": 2 * index + 2, "employeeNoString": "1"},
                ],
            }
        },
    )


def retiring_device(
    shape: str, *, n: int = RETIRE_EVERY, pages: int = WALK_PAGES, password: str = PASSWORD
) -> FakeDevice:
    """A fake that retires each nonce after N authorized uses and answers in `shape`.

    `n=0` means "retire on every authorized request" — the misbehaving box the loop
    guard exists for, and the arming a wrong-password mutant would need to exploit.
    """
    device = FakeDevice(password=password)
    device.retire_after = n
    device.retire_shape = shape
    device.reset("POST", EVENT_SEARCH, *(event_page(i, last=i == pages - 1) for i in range(pages)))
    return device


def run_walk(device: FakeDevice, **kw: object) -> tuple[list[int], IsapiClient, int]:
    """One real event walk over the fake.

    Returns (serialNos collected, the client that ran it, pages the engine counted).
    The client comes back so a test can assert on ITS circuit and recovery counters —
    a fresh client's circuit is always closed, and asserting on that would prove
    nothing (the tautology trap this repo has been bitten by before).
    """
    client = make_client(device, **kw)
    serials: list[int] = []
    pages = 0
    for chunk in iter_event_windows(
        lambda body: client.search("acs_event_search", body),
        since=SINCE,
        until=UNTIL,
        chunk="1h",
        site_tz=SITE_TZ,
        # 2 records/page keeps pages and the fake's authorized-use counter on the same
        # scale, so `retire_after` means "every N pages" and nothing else.
        limits=PagingLimits(max_results=2),
        page_size=2,
        inter_page_delay=0.0,
        sleep=lambda _s: None,
    ):
        serials.extend(int(r["serialNo"]) for r in chunk.records)
        pages += chunk.pages
    return serials, client, pages


# --- the walk pin: a retirement mid-walk must not end the walk -------------------------


@pytest.mark.parametrize("shape", [RETIRE_STALE_TRUE, RETIRE_STALE_FALSE, RETIRE_ENVELOPE_ONLY])
def test_walk_survives_a_nonce_retirement_mid_backfill(shape: str) -> None:
    """A retirement at request N is a hiccup, not a failure (card's walk pin): the walk
    completes, every record arrives exactly once, the circuit stays closed. The pre-fix
    client killed the run at exactly that request in shape (c) — exit 3 + circuit open."""
    device = retiring_device(shape)

    serials, client, pages = run_walk(device)

    assert serials == list(range(1, 2 * WALK_PAGES + 1)), "no record lost, none duplicated"
    assert pages == WALK_PAGES
    assert device.retirements == WALK_RETIREMENTS, "the scenario must retire exactly 3 times"
    assert not client.circuit_open(), "a survived 401 must not open the circuit"


@pytest.mark.parametrize(
    ("shape", "recoveries"),
    [(RETIRE_STALE_TRUE, 0), (RETIRE_STALE_FALSE, 0), (RETIRE_ENVELOPE_ONLY, WALK_RETIREMENTS)],
)
def test_request_count_is_pages_plus_challenges_plus_recoveries(
    shape: str, recoveries: int
) -> None:
    """Request accounting pinned tight (card: 'request count = pages + recoveries +
    challenges'). The two stale shapes cost ONE extra request each (httpx's own replay
    inside the same logical call) and spend none of OUR budget; the envelope-only shape
    costs a challenge plus a replay per retirement and spends exactly one per retirement —
    i.e. exactly one recovery per retirement, which is the card's other half of the pin.

    That asymmetry is the fix's central claim: `auth_recoveries` counts exactly the
    challenge-less retirements survived, so a device that DOES hand us a challenge can
    never eat the budget a no-challenge device needs.
    """
    device = retiring_device(shape)
    client = make_client(device)

    pages = 0
    for chunk in iter_event_windows(
        lambda body: client.search("acs_event_search", body),
        since=SINCE,
        until=UNTIL,
        chunk="1h",
        site_tz=SITE_TZ,
        limits=PagingLimits(max_results=2),
        page_size=2,
        inter_page_delay=0.0,
        sleep=lambda _s: None,
    ):
        pages += chunk.pages

    assert pages == WALK_PAGES
    assert device.retirements == WALK_RETIREMENTS
    assert client.auth_recoveries == recoveries
    expected = pages + device.challenges + client.auth_recoveries
    assert len(device.served) == expected, (
        f"{len(device.served)} requests != {pages} pages + {device.challenges} "
        f"challenges + {client.auth_recoveries} recoveries"
    )


def test_challenge_bearing_retirement_costs_no_recovery_budget() -> None:
    """Shapes (a)/(b) spend ZERO of the recovery budget even when they are the only
    thing that ever goes wrong, and over many retirements. A mutant that re-bootstraps on
    a challenge as well would burn its streak here — and, worse, would be re-authing on
    a refused-credential 401, which is the lockout path."""
    device = retiring_device(RETIRE_STALE_TRUE, n=2, pages=8)
    client = make_client(device)
    list(
        iter_event_windows(
            lambda body: client.search("acs_event_search", body),
            since=SINCE,
            until=UNTIL,
            chunk="1h",
            site_tz=SITE_TZ,
            limits=PagingLimits(max_results=2),
            page_size=2,
            inter_page_delay=0.0,
            sleep=lambda _s: None,
        )
    )
    assert device.retirements >= 2, "scenario must fire the use-cap repeatedly"
    assert client.auth_recoveries == 0
    assert not client.circuit_open()


# --- shape (c): the repro, and the budget that bounds it -------------------------------


def test_envelope_only_retirement_recovery_re_bootstraps_the_session() -> None:
    """The recovery's own mechanics: a retirement costs exactly a challenge plus a
    replay, the fresh nonce ends up in use, `nc` is back at 1 (a new session, not a
    patched-up old one), and — the lockout-safety half — the request the recovery makes
    carries NO credential at all.

    That last assertion is the one worth reading: re-presenting a nonce the device just
    refused is an auth attempt the lockout accounting may count, and it is what a
    recovery that "just resends the request" does. It pins the wire sequence
    probe -> paid 200 -> retirement 401 -> probe -> paid 200."""
    device = FakeDevice()
    device.retire_after = 1
    device.retire_shape = RETIRE_ENVELOPE_ONLY
    device.json_ok("GET", DEVICE_INFO, {"DeviceInfo": {"model": "DS-K1T341AMF-S"}})
    client = make_client(device)

    assert client.get("device_info")["DeviceInfo"]["model"] == "DS-K1T341AMF-S"  # primes
    # Second authorized use exceeds the cap -> envelope-only 401 -> recovered here.
    assert client.get("device_info")["DeviceInfo"]["model"] == "DS-K1T341AMF-S"

    assert client.auth_recoveries == 1
    assert device.retirements == 1
    last = device.served[-1]
    assert last.digest["nonce"] == "MASKED-NONCE-RET1", "the fresh nonce is in use"
    assert last.digest["nc"] == "00000001", "nc restarted with the new session"
    # The recovery's own request must NOT offer the nonce the device just refused:
    # re-presenting a rejected credential is exactly the auth attempt the lockout
    # accounting may count, and it is what a "reset" that only clears one field does.
    # Wire sequence: probe, paid 200, retirement 401, probe, paid 200 — five requests,
    # the fourth of them unauthenticated.
    assert len(device.served) == 5, f"recovery cost more than challenge+replay: {device.served}"
    assert device.served[3].had_auth is False, (
        "the re-bootstrapped request re-presented a credential — a fresh handshake "
        "must start from zero, not from the nonce the device just retired"
    )
    assert not client.circuit_open()


def test_envelope_only_second_consecutive_retirement_is_terminal() -> None:
    """The per-request loop guard (card: 'second consecutive retirement-without-success
    -> IsapiAuthError + circuit, no third try'). `retire_after=0` is a box that retires
    the nonce on EVERY authorized request — unrecoverable by definition, because a
    re-bootstrapped session is instantly dead too. The per-request cap (1) binds first,
    so exactly ONE recovery is spent and the next 401 is terminal; the circuit then stops
    all further requests."""
    device = FakeDevice()
    device.retire_after = 0
    device.retire_shape = RETIRE_ENVELOPE_ONLY
    device.json_ok("GET", DEVICE_INFO, {"DeviceInfo": {}})
    client = make_client(device)

    with pytest.raises(IsapiAuthError):
        client.get("device_info")
    assert client.auth_recoveries == 1, "one recovery per request, never a second"
    assert client.circuit_open()
    served = len(device.served)
    with pytest.raises(IsapiAuthError, match="circuit open"):
        client.get("device_info")
    assert len(device.served) == served, "circuit: nothing further reaches the device"


def test_streak_cap_binds_independently_of_the_per_call_cap() -> None:
    """The second guard is not decoration: raise the per-call allowance and the
    consecutive-recovery streak is what stops the spin. With `auth_recoveries=3` against
    a box that retires every request, the streak cap (2) fires — the third recovery in a
    row with no intervening 200 is refused and the 401 becomes terminal. Without that
    guard, a per-call cap of 3 on such a box is a 3-request spin into a lockout."""
    device = FakeDevice()
    device.retire_after = 0
    device.retire_shape = RETIRE_ENVELOPE_ONLY
    device.json_ok("GET", DEVICE_INFO, {"DeviceInfo": {}})
    client = make_client(device, auth_recovery_budget=3)

    with pytest.raises(IsapiAuthError):
        client.get("device_info")
    assert client.auth_recoveries == 2, "the streak cap stopped it at 2, not 3"
    assert client.circuit_open()


def test_recovery_budget_is_per_call_not_per_client() -> None:
    """A nonce retiring every ~190 requests 'must trivially fit' the budget (card): the
    streak counts only recoveries with NO 200 in between, so a healthy walk may spend one
    recovery as often as the device retires nonces. Here the cap fires on every other
    request — far more often than 1-in-190 — and the walk still finishes."""
    device = FakeDevice()
    device.retire_after = 1  # every 2nd authorized request retires
    device.retire_shape = RETIRE_ENVELOPE_ONLY
    device.json_ok("GET", DEVICE_INFO, {"DeviceInfo": {"model": "X"}})
    client = make_client(device)

    for _ in range(10):
        assert client.get("device_info")["DeviceInfo"]["model"] == "X"

    assert client.auth_recoveries >= 4, "survived repeatedly, not once"
    assert device.retirements >= 4
    assert not client.circuit_open()


def test_locked_account_is_never_treated_as_a_retired_nonce() -> None:
    """A 401 whose body says `locked` is not a nonce problem: re-knocking during a
    lockout is precisely what the circuit exists to prevent. So the no-challenge shape
    must NOT be recoverable when the device says locked, even though it is otherwise the
    exact shape we do recover from — and the device's own unlockTime still sizes the
    circuit."""
    device = FakeDevice()
    device.json_ok("GET", DEVICE_INFO, {"DeviceInfo": {}})
    device.reset_raw(
        "GET",
        DEVICE_INFO,
        httpx.Response(
            401,
            headers={"Server": "webs", "Content-Type": "application/xml"},
            content=b"<ResponseStatus><statusCode>4</statusCode>"
            b"<subStatusCode>authFailed</subStatusCode>"
            b"<lockStatus>locked</lockStatus><unlockTime>1800</unlockTime>"
            b"</ResponseStatus>",
        ),
    )
    client = make_client(device)

    with pytest.raises(IsapiAuthError) as raised:
        client.get("device_info")
    assert raised.value.locked is True
    assert client.auth_recoveries == 0, "locked is never a nonce problem"
    assert client.circuit_open()
    assert raised.value.unlock_time == 1800


def test_zero_budget_restores_the_pre_fix_terminal_behaviour() -> None:
    """The knobs are real: with the budget switched off, the envelope-only retirement is
    terminal and opens the circuit — the pre-fix behaviour is still reachable, so the
    recovery is an *added allowance* rather than a rewrite of the 401 policy. Mutant
    killer for 'someone made a 401 non-terminal wholesale'."""
    device = FakeDevice()
    device.retire_after = 2
    device.retire_shape = RETIRE_ENVELOPE_ONLY
    device.json_ok("GET", DEVICE_INFO, {"DeviceInfo": {}})
    client = make_client(device, auth_recovery_budget=0, auth_recovery_streak=0)

    client.get("device_info")  # primes (1 authorized use)
    client.get("device_info")  # 2nd authorized use
    with pytest.raises(IsapiAuthError):
        client.get("device_info")  # 3rd exceeds the cap -> retirement, now terminal
    assert client.auth_recoveries == 0
    assert client.circuit_open()


# --- the lockout-safety edge: a wrong password must never recover -----------------------


@pytest.mark.parametrize("shape", [RETIRE_STALE_TRUE, RETIRE_STALE_FALSE, RETIRE_ENVELOPE_ONLY])
def test_wrong_password_costs_the_p1_03_budget_and_opens_the_circuit(shape: str) -> None:
    """THE invariant this card must not regress (it is why the owner's live step-9 probe
    behaved normally): wrong password -> challenge + httpx's ONE internal retry, then the
    exit-3 surface, circuit open, ZERO further requests. Every retirement shape is
    installed and ARMED (`retire_after=0`, so any accepted credential would retire
    immediately) — a mutant that lets a bad password re-bootstrap forever dies here."""
    device = retiring_device(shape, n=0, password="fakepw-not-this")
    client = make_client(device)

    with pytest.raises(IsapiAuthError):
        client.get("device_info")

    assert len(device.served) == 2, "exactly challenge + one authenticated retry"
    assert client.auth_recoveries == 0, "a wrong password never spends recovery budget"
    assert client.circuit_open()
    for _ in range(5):
        with pytest.raises(IsapiAuthError, match="circuit open"):
            client.get("device_info")
    assert len(device.served) == 2, "no lockout loop, ever"


@pytest.mark.parametrize("shape", [RETIRE_STALE_TRUE, RETIRE_STALE_FALSE, RETIRE_ENVELOPE_ONLY])
def test_wrong_password_walk_is_terminal_without_spending_recovery(shape: str) -> None:
    """Same invariant on the walk path, which is where a loop would actually grind the
    account: a whole event walk with the wrong password costs exactly one logical call's
    attempt budget (2 requests) and stops, whatever the nonce behaviour is set to."""
    device = retiring_device(shape, n=0, password="fakepw-not-this")
    client = make_client(device)

    with pytest.raises(IsapiAuthError):
        list(
            iter_event_windows(
                lambda body: client.search("acs_event_search", body),
                since=SINCE,
                until=UNTIL,
                chunk="1h",
                site_tz=SITE_TZ,
                limits=PagingLimits(max_results=2),
                page_size=2,
                inter_page_delay=0.0,
                sleep=lambda _s: None,
            )
        )
    assert len(device.served) == 2
    assert client.auth_recoveries == 0
    assert client.circuit_open()


# --- the discriminator itself -----------------------------------------------------------


def _response_with_challenge(headers: tuple[str, ...]) -> httpx.Response:
    """A 401 carrying exactly these `WWW-Authenticate` values (possibly none).

    Built from a list of pairs, not a dict: a dict can only carry one value per name,
    and "two separate header lines, Digest on the second" is one of the cases this file
    has to express (it is where a naive single-value check drifts from httpx's loop).
    """
    return httpx.Response(401, headers=[("WWW-Authenticate", value) for value in headers])


def _httpx_repays(headers: tuple[str, ...]) -> bool:
    """Does httpx.DigestAuth itself re-pay a 401 carrying these header values?

    Ground truth from the library, not from reading its source: drive a bare
    `DigestAuth` over a mock transport and count requests the fake saw. One request
    means httpx returned the 401 untouched (the shape we must recover from); two means
    it paid the challenge itself (the shape we must NOT touch)."""
    seen = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["n"] += 1
        return _response_with_challenge(headers)

    with httpx.Client(transport=httpx.MockTransport(handler), base_url=BASE_URL) as http:
        http.get(DEVICE_INFO, auth=httpx.DigestAuth("admin", PASSWORD))
    return seen["n"] >= 2


@pytest.mark.parametrize(
    "headers",
    [
        # The recorded device shape: a Digest challenge -> httpx pays, we must not.
        (f'Digest qop="auth", realm="{REALM}", nonce="N", stale="true"',),
        # No challenge at all -> nobody pays; this is the shape we re-bootstrap for.
        (),
        # A non-Digest scheme is not something httpx pays (gotchas §1.6: digest-only).
        ('Basic realm="x"',),
        # One value that merely MENTIONS Digest after a Basic scheme: httpx's loop tests
        # `startswith("digest ")` per value, so it does not pay this one.
        ('Basic realm="x", Digest qop="auth", nonce="N"',),
        # Two real header lines, Digest second: the loop scans all values and pays.
        ('Basic realm="x"', f'Digest qop="auth", realm="{REALM}", nonce="N"'),
        # Case of the scheme token is not significant to either side.
        ('digest qop="auth", realm="r", nonce="N"',),
    ],
    ids=[
        "recorded_challenge",
        "no_challenge",
        "basic_only",
        "digest_mentioned",
        "two_headers",
        "lowercase",
    ],
)
def test_discriminator_agrees_with_httpx_on_which_401s_it_pays(headers: tuple[str, ...]) -> None:
    """`_offers_digest_challenge` must agree with httpx on WHICH 401s it re-pays, so both
    sides are pinned against each other rather than against our reading of the source.

    Two of these cases are where a naive implementation drifts: a value that only
    *mentions* Digest after a Basic scheme must read as "not paid" (per-value
    `startswith`, not `\"digest\" in header`), and a Digest value that is merely the
    second header line must read as "paid"."""
    paid = _httpx_repays(headers)
    client = make_client(FakeDevice())
    assert client._offers_digest_challenge(_response_with_challenge(headers)) is paid, (
        f"discriminator disagrees with httpx (which paid={paid}) on {headers!r}"
    )


def test_discriminator_matches_the_two_recorded_401_fixtures() -> None:
    """The two fixtures this card recorded are the ends of the discriminator: the real
    challenge shape (httpx's) and the invented envelope-only shape (ours)."""
    client = make_client(FakeDevice())
    assert client._offers_digest_challenge(FakeDevice().challenge()) is True
    assert client._offers_digest_challenge(FakeDevice().envelope_only_401()) is False


def test_a_challenge_bearing_401_is_still_terminal_with_budget_available() -> None:
    """A full recovery budget, a no-loop 401 that DOES carry a challenge: still terminal,
    circuit open, budget untouched. This is the pre-fix behaviour for a refused
    credential, kept byte-for-byte — the fix added an allowance only for the shape that
    has no challenge to pay."""
    device = FakeDevice()
    device.json_ok("GET", DEVICE_INFO, {"DeviceInfo": {}})
    # Always-401-with-challenge (reset_raw repeats the last item): httpx pays its one
    # re-auth, the second 401 comes back to us, and it must be the end of it.
    device.reset_raw("GET", DEVICE_INFO, FakeDevice().challenge())
    client = make_client(device)

    with pytest.raises(IsapiAuthError):
        client.get("device_info")
    assert len(device.served) == 2
    assert client.auth_recoveries == 0, "a challenge is httpx's business, not ours"
    assert client.circuit_open()
