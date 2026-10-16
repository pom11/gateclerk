"""Typed failure surface for the connector.

Split out from the transport so the transport card (p1-03) and its callers can share
one vocabulary without importing httpx. The transport is expected to raise these;
`from_http` is the single place that turns an ISAPI error envelope into one of them.

The shapes are dictated by docs/DESIGN.md ("Failure modes we design for"): a 401 is
terminal (the device locks an account after repeated failures, so we surface it and
stop rather than looping), and a 400/badParameters is almost always our request shape,
so the message has to carry the request body verbatim or the error is useless.

Credential/config failures (p1-02) live here too: they are part of the same surface a
caller has to handle, and `ConfigError` is what `gateclerk` exits 2 on. They must never
carry a password — hence the redaction base64 below: a `security` stderr fragment or a
malformed keychain comment has to be explainable in an error message without possibly
echoing a credential that lives next to it in the same keychain item.
"""

from __future__ import annotations

import re
from typing import Any

__all__ = [
    "ConfigError",
    "CredentialUnavailable",
    "IsapiAuthError",
    "IsapiBadContent",
    "IsapiBusy",
    "IsapiError",
    "IsapiLocalNetworkError",
    "IsapiNotFound",
    "IsapiPayloadError",
    "NotImplementedYet",
    "GateclerkError",
    "redact_b64",
]


class GateclerkError(Exception):
    """Base for everything this package raises deliberately."""


class NotImplementedYet(GateclerkError):
    """Placeholder for a command whose real implementation lands in a later card."""


class IsapiPayloadError(GateclerkError):
    """A device body we refused to parse: too big, declares an XML DTD/entity, or is
    neither JSON nor well-formed XML.

    Lives here rather than in the response module so both the parser and its callers
    can name it without importing XML or httpx. (Also the exception `parse_isapi_xml()`
    raises, so a p1-06 caller gets the same vocabulary.)
    """


class IsapiLocalNetworkError(GateclerkError):
    """The OS refused to let us reach the device at all.

    OBSERVED.md delta (4): on this Mac *curl* reaches the LAN while plain *python* gets
    `[Errno 65] No route to host`, because macOS TCC gates Local Network per-app. A
    generic "connection failed" here sends someone debugging at the wrong layer — the
    fix is a permission grant, not a retry or a credential.
    """


class ConfigError(GateclerkError):
    """Config or credential resolution failed — the request never left the process.

    p1-08 maps this to exit code 2. Subclasses carry the exact command that would have
    worked, because "keychain item missing" is only actionable if it names it.
    """


class CredentialUnavailable(ConfigError):
    """No password could be resolved for a host, or the source refused.

    The message always names the source that was tried and the command or variable that
    would satisfy it (docs/OBSERVED.md + card p1-02), so the fix is a copy-paste away —
    never a guess. Never contains the secret itself.
    """


class IsapiError(GateclerkError):
    """An ISAPI error envelope ({statusCode, statusString, subStatusCode, ...})."""

    def __init__(
        self,
        message: str,
        *,
        status_code: int | None = None,
        envelope: dict[str, Any] | None = None,
        request_body: str | None = None,
    ) -> None:
        self.status_code = status_code
        self.envelope = envelope or {}
        self.request_body = request_body
        super().__init__(self._compose(message))

    def _compose(self, message: str) -> str:
        parts = [message]
        if self.status_code is not None:
            parts.append(f"http_status={self.status_code}")
        for key in ("statusCode", "statusString", "subStatusCode", "errorCode", "errorMsg"):
            value = self.envelope.get(key)
            if value is not None:
                parts.append(f"{key}={value}")
        # DESIGN.md: 'Invalid Content'/'badParameters' is almost always our request
        # shape — the body has to be in the message, not just in the log.
        if self.request_body is not None:
            parts.append(f"request_body={self.request_body}")
        return " ".join(str(p) for p in parts)


class IsapiAuthError(IsapiError):
    """401. Terminal: at most one re-auth on a stale nonce, then stop.

    A Hikvision terminal locks the account after repeated failures, and the locked
    account is the one someone needs at the door. Never retry this in a loop.

    The 401 body is a *payload*, not just a status: it carries the machine-readable
    lockout counters (`lockStatus` / `unlockTime` / `retryLoginTime`, DESIGN.md
    "Account lockout is machine-readable"), and the transport exposes them as
    `unlock_time` / `retry_login_time` so a caller can circuit-open for
    `unlock_time + margin` instead of hardcoding the "~5 tries / 30 minutes" folklore.
    """

    def __init__(
        self,
        message: str,
        *,
        status_code: int | None = None,
        envelope: dict[str, Any] | None = None,
        request_body: str | None = None,
        lock_status: str | None = None,
        unlock_seconds: int | None = None,
        retry_login_seconds: int | None = None,
    ) -> None:
        super().__init__(
            message, status_code=status_code, envelope=envelope, request_body=request_body
        )
        self.lock_status = lock_status
        self.unlock_time = unlock_seconds
        self.retry_login_time = retry_login_seconds

    @property
    def locked(self) -> bool:
        """True when the device says the account is currently locked."""
        return (self.lock_status or "").strip().lower() in {"locked", "lock", "1"}


class IsapiBadContent(IsapiError):
    """400 / statusCode 6 / badParameters — our request shape, so show the body."""


class IsapiBusy(IsapiError):
    """The retryable busy family — deviceBusy / serviceUnavailable / noMemory /
    upgrading / activeOperator (plus the beingExportedByAnotherUser wait) — back off
    and retry, bounded.

    NOT `invalidOperation`: that is vendor `statusCode` 4, terminal per the table in
    docs/references/isapi-client-gotchas.md §2.2 and DESIGN.md's Throttling line —
    retrying a 4-class code is how a polling loop becomes a door-terminal lockout.
    `_BUSY_SUBCODES` in `gateclerk.isapi_response` is the mapping table; both sides of
    the boundary are pinned in tests (test_isapi_response.py + test_isapi_transport.py).
    """


class IsapiNotFound(IsapiError):
    """404 — the endpoint does not exist on this model/firmware."""


# --- error-message redaction ---------------------------------------------------------

#: A best-effort belt, deliberately narrow. A base64 blob of real bytes ~always mixes
#: letters and digits and is long; macOS's own error identifiers (`SecKeychainSearchCopyNext`,
#: `UNIXService`) are CamelCase and digit-free. Requiring a digit inside the run is what
#: keeps this from eating the diagnostic we are trying to show the user — the failure mode
#: a looser `[A-Za-z0-9+/]{16,}` had in this file's first draft, which turned
#: "SecKeychainSearchCopyNext: item could not be found" into "<redacted>: item could not be…".
_B64 = re.compile(r"(?=[A-Za-z0-9+/]*[0-9])(?=[A-Za-z0-9+/]*[A-Za-z])[A-Za-z0-9+/]{20,}={0,2}")


def redact_b64(text: str) -> str:
    """Blank out base64-shaped runs before a foreign string goes into an error message.

    A `security` stderr line can sit right next to the secret it describes. We want the
    shape of what went wrong without the payload. This is belt-and-braces on top of
    `gateclerk.secrets.Secret` (which covers exactly what WE hold, and is the real
    guarantee); it covers what a subprocess or the OS hands back, best-effort.
    """
    return _B64.sub("<redacted>", text)
