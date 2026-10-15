"""Typed failure surface for the connector.

Split out from the transport so the transport card (p1-03) and its callers can share
one vocabulary without importing httpx. The transport is expected to raise these;
`from_http` is the single place that turns an ISAPI error envelope into one of them.

The shapes are dictated by docs/DESIGN.md ("Failure modes we design for"): a 401 is
terminal (the device locks an account after repeated failures, so we surface it and
stop rather than looping), and a 400/badParameters is almost always our request shape,
so the message has to carry the request body verbatim or the error is useless.
"""

from __future__ import annotations

from typing import Any

__all__ = [
    "IsapiAuthError",
    "IsapiBadContent",
    "IsapiBusy",
    "IsapiError",
    "IsapiLocalNetworkError",
    "IsapiNotFound",
    "IsapiPayloadError",
    "NotImplementedYet",
    "GateclerkError",
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
    """deviceBusy / activeOperator / invalidOperation — back off and retry, bounded."""


class IsapiNotFound(IsapiError):
    """404 — the endpoint does not exist on this model/firmware."""
