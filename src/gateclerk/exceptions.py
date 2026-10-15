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
    "IsapiNotFound",
    "NotImplementedYet",
    "GateclerkError",
]


class GateclerkError(Exception):
    """Base for everything this package raises deliberately."""


class NotImplementedYet(GateclerkError):
    """Placeholder for a command whose real implementation lands in a later card."""


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
    """


class IsapiBadContent(IsapiError):
    """400 / statusCode 6 / badParameters — our request shape, so show the body."""


class IsapiBusy(IsapiError):
    """deviceBusy / activeOperator / invalidOperation — back off and retry, bounded."""


class IsapiNotFound(IsapiError):
    """404 — the endpoint does not exist on this model/firmware."""
