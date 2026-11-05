"""The IsapiClient credential-provider seam (Slice 2 of D-001, card t_63e9c8fc).

The contract is docs/internal/DECISION-credential-provider-seam.md: the client takes
exactly one credential source and — when that source is a provider — consults it at
exactly three lifetime points, never per request and never per page:

  (1) once in ``__init__`` (fail fast before any socket),
  (2) inside ``_reset_auth_state`` (a retired nonce),
  (3) once when an open auth circuit has expired (or was reset by the operator).

Everything here is offline: ``FakeDevice`` is an ``httpx.MockTransport`` and the
autouse socket guard in conftest still bites. The provider is a local counting fake
holding ``Credentials`` — the same duck-typed callable Slice 3 will pass.
"""

from __future__ import annotations

import pytest

from fakedevice import BASE_URL, RETIRE_ENVELOPE_ONLY, FakeDevice
from gateclerk import pipeline
from gateclerk.config import Credentials, CredentialSource
from gateclerk.exceptions import CredentialUnavailable, IsapiAuthError
from gateclerk.isapi_transport import IsapiClient
from gateclerk.secrets import Secret

DEVICE_INFO = "/ISAPI/System/deviceInfo?format=json"
PASSWORD = "fakepw"  # tests/test_repo_hygiene.py placeholder policy


class CountingProvider:
    """A provider that counts calls and can hand out a rotation or raise on demand."""

    def __init__(self, *passwords: str, user: str = "admin") -> None:
        assert passwords, "give the provider at least one password"
        self._passwords = list(passwords)
        self._user = user
        self.calls = 0
        self.error: Exception | None = None

    def __call__(self) -> Credentials:
        self.calls += 1
        if self.error is not None:
            raise self.error
        # Calls past the scripted list keep the last value — the fail-fast / ordinary
        # request arms need "stable credential", not a rotation.
        value = self._passwords[min(self.calls - 1, len(self._passwords) - 1)]
        return Credentials(
            user=self._user,
            password=Secret(value),
            source=CredentialSource.ENV,
            host="192.0.2.10",
        )


def make_client(
    device: FakeDevice, *, provider: CountingProvider | None = None, **kw: object
) -> IsapiClient:
    kw.setdefault("sleep", lambda _s: None)  # tests never actually wait
    if provider is None:
        return IsapiClient(BASE_URL, "admin", PASSWORD, transport=device.transport, **kw)
    return IsapiClient(
        BASE_URL,
        "",
        "",
        credentials=provider,
        transport=device.transport,
        **kw,
    )


# --- the exactly-one-source rule ---------------------------------------------------------


@pytest.mark.parametrize(
    ("username", "password"),
    [("", ""), ("admin", ""), ("", PASSWORD)],
)
def test_ctor_refuses_no_source(username: str, password: str) -> None:
    """``IsapiClient(url, "", "")`` used to be silently accepted; it is now refused."""
    device = FakeDevice()
    with pytest.raises(ValueError, match="exactly one credential source"):
        IsapiClient(BASE_URL, username, password, transport=device.transport)
    assert device.requests == 0, "refused before a single request"


def test_ctor_refuses_a_provider_plus_positionals() -> None:
    provider = CountingProvider(PASSWORD)
    device = FakeDevice()
    with pytest.raises(ValueError, match="exactly one credential source"):
        IsapiClient(
            BASE_URL,
            "admin",
            PASSWORD,
            credentials=provider,
            transport=device.transport,
        )
    assert provider.calls == 0, "a refused construction must not touch the provider"


def test_ctor_refusal_names_both_sources_and_never_echoes_the_password() -> None:
    """The message names both ways out; it reports presence, never values."""
    device = FakeDevice()
    with pytest.raises(ValueError) as excinfo:
        IsapiClient(BASE_URL, "", "", transport=device.transport)
    # The both-source arm is the interesting one for echo risk: a non-empty password
    # was supplied and must not appear in the text.
    with pytest.raises(ValueError) as both:
        IsapiClient(
            BASE_URL,
            "admin",
            PASSWORD,
            credentials=CountingProvider(PASSWORD),
            transport=device.transport,
        )
    for message in (str(excinfo.value), str(both.value)):
        assert "username+password" in message
        assert "credentials=<provider>" in message
        assert PASSWORD not in message


def test_provider_with_empty_positionals_is_accepted() -> None:
    device = FakeDevice()
    device.json_ok("GET", DEVICE_INFO, {})
    provider = CountingProvider(PASSWORD)
    client = make_client(device, provider=provider)
    assert provider.calls == 1, "point (1): exactly once at construction"
    assert client.get("device_info") == {}
    assert provider.calls == 1


# --- the call-count budget: never per request --------------------------------------------


def test_many_ordinary_requests_do_not_recall_the_provider() -> None:
    device = FakeDevice()
    device.json_ok("GET", DEVICE_INFO, {})
    provider = CountingProvider(PASSWORD)
    client = make_client(device, provider=provider)
    for _ in range(6):
        client.get("device_info")
    assert provider.calls == 1, "one resolve at construction and ZERO per request"


def test_one_provider_call_per_nonce_retirement() -> None:
    """Point (2): every ``_reset_auth_state`` re-reads the source exactly once.

    ``retire_after=1`` with the envelope-only shape forces ``_reset_auth_state`` on
    every other authorized request; three sequential GETs spend two retirements.
    """
    device = FakeDevice()
    device.json_ok("GET", DEVICE_INFO, {})
    device.retire_after = 1
    device.retire_shape = RETIRE_ENVELOPE_ONLY
    provider = CountingProvider(PASSWORD)
    client = make_client(device, provider=provider)

    for _ in range(3):
        assert client.get("device_info") == {}

    assert device.retirements == 2, "the scenario must actually retire twice"
    assert client.auth_recoveries == 2, "one recovery per retirement"
    assert provider.calls == 1 + device.retirements, "ctor once, plus one per retirement"


def test_one_provider_call_per_circuit_episode_and_rotation_self_heals() -> None:
    """Point (3): the first knock after the window re-reads the source.

    The device has already rotated to ``fakepw-new``; the provider still hands out
    ``fakepw-old`` during the failure, then the operator rotates the source. The
    post-window request must use the NEW password and succeed without a restart.
    """
    device = FakeDevice(password="fakepw-new")
    device.json_ok("GET", DEVICE_INFO, {})
    provider = CountingProvider("fakepw-old", "fakepw-new")
    clock = {"t": 1000.0}
    client = make_client(
        device,
        provider=provider,
        now=lambda: clock["t"],
        circuit_fallback_seconds=30.0,
        circuit_margin_seconds=10.0,
    )

    with pytest.raises(IsapiAuthError):
        client.get("device_info")
    assert client.circuit_open()
    assert provider.calls == 1, "opening a circuit is not a provider-read point"

    with pytest.raises(IsapiAuthError, match="circuit open"):
        client.get("device_info")
    assert provider.calls == 1, "the in-window call must not touch the provider"

    clock["t"] += 41  # past fallback 30 + margin 10
    assert client.get("device_info") == {}
    assert provider.calls == 2, "exactly one resolve per circuit episode"

    # Ordinary requests after the healed episode stay free.
    for _ in range(3):
        client.get("device_info")
    assert provider.calls == 2


# --- provider failures propagate unchanged ------------------------------------------------


def test_provider_unavailable_at_construction_propagates_before_any_request() -> None:
    device = FakeDevice()
    provider = CountingProvider(PASSWORD)
    provider.error = CredentialUnavailable("run `gateclerk creds set`")
    with pytest.raises(CredentialUnavailable, match="creds set"):
        make_client(device, provider=provider)
    assert device.requests == 0, "fail-fast is the pre-socket law"


def test_provider_unavailable_at_nonce_reset_propagates_and_keeps_the_spent_counter() -> None:
    device = FakeDevice()
    device.json_ok("GET", DEVICE_INFO, {})
    device.retire_after = 1
    device.retire_shape = RETIRE_ENVELOPE_ONLY
    provider = CountingProvider(PASSWORD)
    client = make_client(device, provider=provider)
    assert client.get("device_info") == {}

    provider.error = CredentialUnavailable("rotation read failed")
    with pytest.raises(CredentialUnavailable, match="rotation read failed"):
        client.get("device_info")

    assert device.retirements == 1, "the retirement happened before the reset"
    assert client.auth_recoveries == 1, "the already-spent recovery stays spent"


def test_provider_unavailable_at_circuit_expiry_propagates_then_recovers() -> None:
    device = FakeDevice(password="fakepw-new")
    device.json_ok("GET", DEVICE_INFO, {})
    provider = CountingProvider("fakepw-old", "fakepw-new")
    clock = {"t": 1000.0}
    client = make_client(
        device,
        provider=provider,
        now=lambda: clock["t"],
        circuit_fallback_seconds=30.0,
        circuit_margin_seconds=10.0,
    )
    with pytest.raises(IsapiAuthError):
        client.get("device_info")

    provider.error = CredentialUnavailable("keychain denied")
    clock["t"] += 41
    with pytest.raises(CredentialUnavailable, match="keychain denied"):
        client.get("device_info")
    assert client._circuit_auth_stale, "a failed refresh leaves the episode open"

    provider.error = None
    assert client.get("device_info") == {}
    assert provider.calls == 3, "failed attempt counted, then the successful re-read"


# --- LoggedClient: ctor kwargs never reach the wrapper ------------------------------------


def test_provider_built_client_survives_the_verbose_loggedclient_wrap() -> None:
    device = FakeDevice()
    device.json_ok("GET", DEVICE_INFO, {})
    provider = CountingProvider(PASSWORD)
    inner = make_client(device, provider=provider)
    logger = pipeline.RequestLogger()
    wrapped = pipeline.LoggedClient(inner, logger)  # what cli_shared does for --verbose

    assert wrapped.get("device_info") == {}
    assert provider.calls == 1, "the wrap neither rebuilds nor re-resolves"
    assert any("GET" in line for line in logger.lines)
