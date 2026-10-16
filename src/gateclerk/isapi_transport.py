"""The ISAPI HTTP transport: digest session, timeouts, bounded retries, typed errors.

This is the only module in the package that opens a socket (or is handed a
`httpx.MockTransport`, which is how every test here exercises it without a device).
Callers pass an **endpoint name** from `gateclerk.endpoints` — never a path, never a
verb. The verb comes from the closed registry, so the read-only guarantee
(DESIGN.md "Constraints / invariants") is enforced here as well as in the registry
test: there is no code path by which this client issues PUT/DELETE, and the only POST
it will make is to one of the two stateless search endpoints.

The rules this implementation encodes, each traceable to docs/DESIGN.md,
docs/OBSERVED.md or docs/references/isapi-client-gotchas.md:

* **Digest, one auth object per client, reused across calls** (card + gotchas §1.7a).
  `httpx.DigestAuth` keeps `_last_challenge` + `_nonce_count`; reusing them is what
  makes a 20-page search cost 21 requests instead of 40. Its state has no lock, so a
  client is **not thread-safe** — one client per worker thread, pinned by a test.
* **`uri=` includes the query** (gotchas §1.4: a path-only HA2 is an infinite 401 loop
  with a *correct* password). httpx hashes `request.url.raw_path`, which includes
  `?format=json`, because every request URL comes from `Endpoint.url_path` — a test
  asserts the wire bytes carry the query.
* **Timeouts**: connect 10 s / read 30 s defaults (DESIGN.md "Half-open TCP"),
  configurable. Connection reuse is on; a dropped keep-alive surfaces as a transport
  error and is retried **once**, transparently (card).
* **401 is terminal after the one re-auth httpx already spends** (DESIGN.md: "max 1
  retry per request and no retry loop on 401"). When a call still ends in 401 the
  client opens a circuit: further calls fail fast without touching the device until
  `unlockTime` (read from the 401 body — it is machine-readable, DESIGN.md) plus a
  margin has elapsed, or a conservative fallback when the body says nothing. That is
  the difference between "surface the failure" and "grind the admin account into a
  door-terminal lockout".
* **Retry classes follow `statusCode`, not the HTTP status** (gotchas §2.2/§7.4):
  `2` / HTTP 503 → exponential backoff, bounded (`busy_max_attempts`, delays capped
  at `busy_backoff_cap`); `3` → exactly one retry; `4/5/6` → terminal, retrying them
  is how polling becomes lockout. No 429 exists on Hikvision (gotchas §2.1).
* **Search POSTs retry with the byte-identical body** — same `searchID`, same cursor,
  which the device dedupes (vendor doc via gotchas §2.5). A mutated body mid-paging
  would be a different query; the retry re-sends the exact bytes (pinned by test).
* **macOS TCC**: `[Errno 65] No route to host` where curl works is Local Network
  permission (OBSERVED.md delta 4), not a device fault — it raises
  `IsapiLocalNetworkError` naming the fix instead of a generic connect error.

Deliberately **not** here: paging/cursor logic (p1-05), credential resolution
(p1-02 — the client receives a password, whoever resolves it decides), the inter-page
delay (p1-05's pacing), and TLS options (P1 is HTTP:80 on the LAN; if TLS ever comes,
pin the device cert into a CA bundle — never `verify=False`, gotchas §4.1).
"""

from __future__ import annotations

import json
import threading
import time
from collections.abc import Callable, Mapping
from typing import Any

import httpx

from gateclerk.endpoints import SEARCH_ENDPOINTS, Endpoint, HttpMethod, endpoint_for
from gateclerk.exceptions import (
    IsapiAuthError,
    IsapiBusy,
    IsapiError,
    IsapiLocalNetworkError,
    GateclerkError,
)
from gateclerk.isapi_response import envelope_to_error, parse_body, parse_envelope

__all__ = [
    "DEFAULT_BUSY_BACKOFF_BASE",
    "DEFAULT_BUSY_BACKOFF_CAP",
    "DEFAULT_BUSY_MAX_ATTEMPTS",
    "DEFAULT_CONNECT_TIMEOUT",
    "DEFAULT_READ_TIMEOUT",
    "IsapiClient",
]

#: DESIGN.md "Half-open TCP": explicit connect/read timeouts, defaults from the card.
DEFAULT_CONNECT_TIMEOUT = 10.0
DEFAULT_READ_TIMEOUT = 30.0

#: DESIGN.md "Throttling" + gotchas §7.4: backoff 1 -> 30 s, ~6 tries on deviceBusy.
#: (The card body's "max 3, cap 8 s" predates the research pass that folded the vendor
#: table into DESIGN.md; DESIGN.md is the contract, so these defaults follow it. Both
#: numbers are constructor parameters, so a stricter policy is one call-site away.)
DEFAULT_BUSY_MAX_ATTEMPTS = 6
DEFAULT_BUSY_BACKOFF_BASE = 1.0
DEFAULT_BUSY_BACKOFF_CAP = 30.0

#: One transparent retry on a transport error covers the dropped-keep-alive case
#: (card). More than one buys nothing against an embedded box and risks load.
DEFAULT_TRANSPORT_RETRIES = 1

#: Circuit-open fallback when a 401 body carries no `unlockTime` (field reports say
#: ~30 min lockouts; that is folklore, so it is only a *floor* for how long we
#: stubbornly refuse to knock again, never a claim about the device).
DEFAULT_CIRCUIT_FALLBACK_SECONDS = 300.0
DEFAULT_CIRCUIT_MARGIN_SECONDS = 10.0

#: Substrings that mean "the OS said no", not "the device said no" (OBSERVED.md
#: delta 4). Errno 65 = EHOSTUNREACH (macOS TCC Local Network gate), Errno 1 = EPERM
#: (seen from the sandbox/TCC path too).
_TCC_MARKERS = ("no route to host", "operation not permitted")


class IsapiClient:
    """Read-only ISAPI client for exactly one device. Not thread-safe by design:
    the digest state below is unlocked, so create one client per worker thread."""

    def __init__(
        self,
        base_url: str,
        username: str,
        password: str,
        *,
        connect_timeout: float = DEFAULT_CONNECT_TIMEOUT,
        read_timeout: float = DEFAULT_READ_TIMEOUT,
        busy_max_attempts: int = DEFAULT_BUSY_MAX_ATTEMPTS,
        busy_backoff_base: float = DEFAULT_BUSY_BACKOFF_BASE,
        busy_backoff_cap: float = DEFAULT_BUSY_BACKOFF_CAP,
        transport_retries: int = DEFAULT_TRANSPORT_RETRIES,
        circuit_fallback_seconds: float = DEFAULT_CIRCUIT_FALLBACK_SECONDS,
        circuit_margin_seconds: float = DEFAULT_CIRCUIT_MARGIN_SECONDS,
        sleep: Callable[[float], None] = time.sleep,
        now: Callable[[], float] = time.monotonic,
        transport: httpx.BaseTransport | None = None,
        client: httpx.Client | None = None,
    ) -> None:
        if not base_url.startswith(("http://", "https://")):
            # ISAPI lives on 80/443. Port 8000 is Hikvision's private SDK protocol
            # (gotchas §4) — a bare "host:8000" here is always the wrong door.
            raise ValueError(
                f"base_url must include the scheme (http:// or https://); got {base_url!r}. "
                "ISAPI is HTTP on 80 / HTTPS on 443 — port 8000 is the SDK protocol port."
            )
        self._auth = httpx.DigestAuth(username, password)
        self._client = client or httpx.Client(
            base_url=base_url,
            transport=transport,
            timeout=httpx.Timeout(
                read=read_timeout,
                connect=connect_timeout,
                write=connect_timeout,
                pool=connect_timeout,
            ),
            headers={"User-Agent": "gateclerk/0.1 (read-only)"},
        )
        self._busy_max_attempts = busy_max_attempts
        self._busy_base = busy_backoff_base
        self._busy_cap = busy_backoff_cap
        self._transport_retries = transport_retries
        self._circuit_fallback = circuit_fallback_seconds
        self._circuit_margin = circuit_margin_seconds
        self._sleep = sleep
        self._now = now
        self._circuit_until: float | None = None
        self._owner_thread: int | None = None

    # --- lifecycle -------------------------------------------------------------------

    def __enter__(self) -> IsapiClient:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def close(self) -> None:
        self._client.close()

    # --- public surface: names in, dicts out ------------------------------------------

    @property
    def timeout(self) -> httpx.Timeout:
        """The effective timeouts, so a caller (and a test) can see what was configured."""
        return self._client.timeout

    def get(self, name: str) -> dict[str, Any]:
        """GET a registered endpoint and return its body parsed (XML or JSON — the
        firmware answers System/* as XML despite `?format=json`, OBSERVED.md)."""
        return self._endpoint_call(name, HttpMethod.GET)

    def search(self, name: str, payload: Mapping[str, Any]) -> dict[str, Any]:
        """POST a stateless-search body to a registered search endpoint.

        `payload` is the complete JSON object (e.g. `{"AcsEventCond": {...}}`) — the
        caller (p1-05) owns `searchID`/cursor semantics; this layer only guarantees the
        bytes are re-sent verbatim if a transport error forces one retry.
        """
        return self._endpoint_call(name, HttpMethod.POST, payload=payload)

    def get_response(self, name: str) -> httpx.Response:
        """Like `get()` but hands back the response (p1-06's skew wants the `Date:`
        header; the body is already buffered either way)."""
        return self._call(name, HttpMethod.GET)

    def search_response(self, name: str, payload: Mapping[str, Any]) -> httpx.Response:
        """Like `search()` but hands back the response."""
        return self._call(name, HttpMethod.POST, payload=payload)

    # --- circuit ------------------------------------------------------------------------

    def circuit_open(self) -> bool:
        return self._circuit_until is not None and self._now() < self._circuit_until

    def reset_circuit(self) -> None:
        """Operator escape hatch: after confirming credentials by hand, close the
        circuit without waiting out the unlock window."""
        self._circuit_until = None

    # --- internals -----------------------------------------------------------------------

    def _guard_thread(self) -> None:
        ident = threading.get_ident()
        if self._owner_thread is None:
            self._owner_thread = ident
        elif self._owner_thread != ident:
            raise GateclerkError(
                "IsapiClient used from a second thread — httpx digest state is unlocked "
                "and sharing it races nc counters (gotchas §1.7b). One client per thread."
            )

    def _open_circuit(self, err: IsapiAuthError) -> None:
        # DESIGN.md: circuit-open for `unlockTime + margin` — read the device's own
        # number, never the folklore. unlockTime == 0 (or absent) means the device gave
        # us nothing to honour, and DESIGN.md's rule for a bare 401 is "surface and
        # stop" — so fall back to a conservative window rather than reopening at once.
        unlock = err.unlock_time
        seconds = unlock if (unlock and unlock > 0) else self._circuit_fallback
        self._circuit_until = self._now() + seconds + self._circuit_margin

    def _endpoint_call(
        self,
        name: str,
        expected: HttpMethod,
        *,
        payload: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        response = self._call(name, expected, payload=payload)
        return parse_body(response.content)

    def _call(
        self,
        name: str,
        expected: HttpMethod,
        *,
        payload: Mapping[str, Any] | None = None,
    ) -> httpx.Response:
        self._guard_thread()
        endpoint = self._check(name, expected)
        # One URL object for hashing and for the wire (gotchas §1.4): httpx computes
        # the digest HA2 over request.url.raw_path, so path and query must never be
        # built twice in two different ways.
        request_path = endpoint.url_path
        content: str | None = None
        headers: dict[str, str] = {}
        if expected is HttpMethod.POST:
            if payload is None:  # defensive; _call's callers always pass a body for POST
                raise GateclerkError(f"{endpoint.name} is a search POST and needs a JSON body")
            content = json.dumps(payload, ensure_ascii=False, separators=(",", ":"))
            headers["Content-Type"] = "application/json"

        transport_left = self._transport_retries
        busy_attempt = 0
        retry_3_done = False
        while True:
            if self.circuit_open():
                raise IsapiAuthError(
                    f"auth circuit open for {endpoint.name} — a prior 401 asked us to "
                    f"stop (device lockout risk); no request was sent. "
                    f"reset_circuit() after verifying credentials by hand."
                )
            try:
                response = self._client.request(
                    expected.value,
                    request_path,
                    auth=self._auth,
                    content=content,
                    headers=headers or None,
                )
            except httpx.TransportError as exc:
                self._raise_if_local_network(exc)
                if transport_left > 0:
                    # Dropped keep-alive / half-open TCP: one retry, same client, same
                    # auth state. For a search POST the body bytes are unchanged, so
                    # the device sees the same searchID/cursor (card: safe to retry).
                    transport_left -= 1
                    continue
                raise IsapiError(
                    f"transport failure calling {endpoint.name} after "
                    f"{self._transport_retries} transparent retries: {exc!r}"
                ) from exc

            envelope = parse_envelope(response.content, http_status=response.status_code)
            error = envelope_to_error(
                http_status=response.status_code,
                envelope=envelope,
                endpoint=endpoint.name,
                request_body=content,
                raw_body=response.content,
            )
            if error is None:
                return response

            if isinstance(error, IsapiAuthError):
                # httpx already spent exactly one re-auth on the challenge. Anything
                # past that is loop-into-lockout territory: open the circuit and stop.
                self._open_circuit(error)
                raise error

            if isinstance(error, IsapiError) and error.envelope.get("statusCode") == 3:
                if not retry_3_done:
                    retry_3_done = True
                    continue
                raise error

            if isinstance(error, IsapiBusy) and busy_attempt + 1 < self._busy_max_attempts:
                delay = min(self._busy_base * (2**busy_attempt), self._busy_cap)
                busy_attempt += 1
                self._sleep(delay)
                continue

            raise error

    def _raise_if_local_network(self, exc: httpx.TransportError) -> None:
        message = str(exc).lower()
        if any(marker in message for marker in _TCC_MARKERS):
            raise IsapiLocalNetworkError(
                f"the operating system refused the connection to "
                f"{self._client.base_url}: {exc}. On macOS this is the Local Network "
                "permission (TCC) gate, not a device fault — curl may work while "
                "python does not. Grant Local Network to the terminal app running "
                "gateclerk (System Settings → Privacy & Security → Local Network) and "
                "retry. (docs/OBSERVED.md, macOS note.)"
            ) from exc

    def _check(self, name: str, expected: HttpMethod) -> Endpoint:
        endpoint = endpoint_for(name)  # unknown names raise; no free-form paths
        if endpoint.method is not expected:
            raise GateclerkError(
                f"{endpoint.name} is registered as {endpoint.method.value}; refusing "
                f"to call it as {expected.value}. The registry is the read-only contract."
            )
        if expected is HttpMethod.POST and name not in SEARCH_ENDPOINTS:
            raise GateclerkError(
                f"{endpoint.name} is a POST outside the stateless-search allowlist — "
                "this client does not make mutating requests (DESIGN.md invariants)."
            )
        return endpoint
