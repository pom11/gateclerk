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
    "BundleRepoOutError",
    "ConfigError",
    "CredentialUnavailable",
    "EnrollmentReadAborted",
    "EventBoundsError",
    "IsapiAuthError",
    "IsapiBadContent",
    "IsapiBusy",
    "IsapiError",
    "IsapiLocalNetworkError",
    "IsapiNotFound",
    "IsapiPayloadError",
    "NotImplementedYet",
    "GateclerkError",
    "SearchProtocolError",
    "SearchRunawayError",
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


class BundleRepoOutError(ValueError, ConfigError):
    """A PII-bearing write (bundle, probe document) was refused for landing in a git repo.

    Design §2 ("REFUSE an --out inside the repo") makes this a refusal of WHERE the
    operator pointed the command, not a device fault and not a bug — so it belongs on
    p1-08's config class (exit 2), and `cli._fail` — the single documented mapping —
    converts it there. Before this class existed the guard raised a bare `ValueError`,
    which `_fail` re-raises (unknown class), and the refusal escaped `migrate export`
    as an unhandled traceback with exit 1 (found by E1-09; card t_0d635ee2).

    The `ValueError` base is load-bearing, not decoration: the module-level contract of
    `write_bundle` / `save_matrix` is pinned as `pytest.raises(ValueError)` by E1-01 and
    E1-01b, and E1-09's probe CLI maps `except ValueError` — both keep working against
    the subclass, so the guard's own behavior needed no change.
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


# --- paging (p1-05) -------------------------------------------------------------------


class SearchRunawayError(GateclerkError):
    """A paged search hit its hard page cap while the device still said MORE.

    The loop bound is a safety net (DESIGN.md: 10k pages), not a plan: a real walk
    that reaches it means the device is misbehaving (e.g. serving page 1 forever
    because the `searchID` changed mid-walk — that restarts silently, no error).
    Continuing would hammer a small embedded box forever and pretend the data was
    complete; on a payroll pipeline a truncated pull that *looks* complete is worse
    than a failed one. p1-08 maps this to exit code 5.
    """

    def __init__(
        self,
        message: str,
        *,
        endpoint: str | None = None,
        search_id: str | None = None,
        pages: int | None = None,
        position: int | None = None,
    ) -> None:
        super().__init__(message)
        self.endpoint = endpoint
        self.search_id = search_id
        self.pages = pages
        self.position = position


class EventBoundsError(GateclerkError):
    """An AcsEvent query was asked for without startTime/endTime.

    Some firmware answers an unbounded event search with `Invalid Content`; worse,
    an unbounded walk over the full ~10k history is exactly the slow, page-heavy
    path DESIGN.md tells us never to take. We refuse the query *before* sending it
    (docs/DESIGN.md "Paging + checkpoint": ALWAYS include startTime/endTime).
    """


class SearchProtocolError(GateclerkError):
    """A search response we could not read as a search response (missing root key,
    non-list record list, non-numeric counters).

    Loud on purpose: `parse_body` turns a corrupt body into `IsapiPayloadError`, and
    a well-formed body under the wrong root key means the device changed protocol on
    us. Returning "no records" here would read as "nobody clocked in" — never.
    """


# --- enrollment export (E1) --------------------------------------------------------------


class EnrollmentReadAborted(GateclerkError):
    """A required enrollment read failed CLOSED (design §0.7; card E1-01).

    An enrollment export/diff is only trustworthy if every required read said OK:
    a non-OK `responseStatusStrg` (anything beyond OK/MORE/NO MATCH — FAIL,
    UNKNOWN…), a missing `responseStatusStrg`, or a transport/auth error on
    `UserInfo/Search` / `CardInfo/Search` ABORTS the export. Interpreting any of
    them as "the device has zero people/cards" fabricates an empty state — which on
    E1's rollback-snapshot use (design §0.1) means a snapshot that cannot roll back.

    `endpoint` and `reason` name what failed; `cause` carries the underlying typed
    error when there was one.
    """

    def __init__(
        self,
        message: str,
        *,
        endpoint: str | None = None,
        reason: str | None = None,
        cause: Exception | None = None,
    ) -> None:
        super().__init__(message)
        self.endpoint = endpoint
        self.reason = reason
        self.cause = cause


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
