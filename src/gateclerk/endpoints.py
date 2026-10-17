"""The ISAPI endpoint registry — the read-only guarantee lives here.

Every path this package can call is declared in ONE table with its HTTP method, and
`tests/test_endpoints_registry.py` pins that table to EXACTLY the endpoints
docs/DESIGN.md's call table documents. That is a closed allowlist, not a heuristic:
heuristics on method or path name cannot prove a call is read-only (a write path registered
as GET looks exactly like a read), enumeration can. Adding an endpoint is therefore a named,
reviewed change to that test — never a silent addition.

Method policy (docs/DESIGN.md, "Constraints / invariants"):
  * GET is allowed.
  * POST is allowed ONLY for the stateless search endpoints listed in `SEARCH_ENDPOINTS`,
    which do not mutate device state (the device dedupes a search by searchID/cursor, and the
    count probe returns a number and nothing else).
  * PUT / DELETE / PATCH and any other POST are forbidden. Full stop. If a write path
    is ever needed it gets its own flag, its own module and its own review — it does
    not get folded in here.

Note on the search POSTs: `UserInfo/Search` and `AcsEvent` (bare path, not `AcsEvent/Search`)
are the shapes this firmware family actually accepts; `AcsEvent` takes the time-bounded search
body and is the documented paged event query. `AcsEventTotalNum` is the count probe for the
same window — see `SEARCH_ENDPOINTS` for why it is allowed and `AcsEvent/Total` is not.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

__all__ = [
    "REGISTRY",
    "SEARCH_ENDPOINTS",
    "Endpoint",
    "HttpMethod",
    "allowed_methods_for",
    "endpoint_for",
]


class HttpMethod(StrEnum):
    GET = "GET"
    POST = "POST"


@dataclass(frozen=True, slots=True)
class Endpoint:
    """A callable ISAPI path plus the method it must be called with."""

    name: str
    path: str
    method: HttpMethod
    #: Why this endpoint is in the read-only surface. Kept in code so the reason
    #: travels with the entry instead of rotting in a ticket.
    purpose: str

    @property
    def url_path(self) -> str:
        """Path with the `format=json` suffix that every ISAPI call here needs."""
        sep = "&" if "?" in self.path else "?"
        return f"{self.path}{sep}format=json"


#: POSTs that are stateless reads. The read-only test hard-codes this set: an endpoint
#: may be a POST only if it appears here.
#:
#: Three, not two. `AcsEventTotalNum` is the count probe for the same event query: it takes
#: a search-shaped condition body and mutates nothing (OBSERVED.md VERIFIED: `{major:5,
#: minor:0}` → `{totalNum:30}`, and the paged `AcsEvent` walk over the same window returned
#: those same 30). It was added here rather than in p1-05 because that card's handoff said a
#: third POST is a reviewed registry decision belonging to the `--count` flag, and naming the
#: card that asks for a callable path is what keeps the allowlist a decision rather than
#: drift. `AcsEvent/Total` — the name you would guess — is `400 notSupport` on this firmware
#: and is registered nowhere.
SEARCH_ENDPOINTS = frozenset({"user_info_search", "acs_event_search", "acs_event_total_num"})

REGISTRY: dict[str, Endpoint] = {
    e.name: e
    for e in (
        Endpoint(
            "device_info",
            "/ISAPI/System/deviceInfo",
            HttpMethod.GET,
            "model, serial, firmware version — serial is part of the idempotency key",
        ),
        Endpoint(
            "system_time",
            "/ISAPI/System/time",
            HttpMethod.GET,
            "device clock + tz — used to resolve naive timestamps and measure skew",
        ),
        Endpoint(
            "acs_event_capabilities",
            "/ISAPI/AccessControl/AcsEvent/capabilities",
            HttpMethod.GET,
            "the admissible minorEvent/minorAlarm/minorOperation code sets and "
            "maxResults this model actually accepts — we read it instead of guessing",
        ),
        Endpoint(
            "access_control_capabilities",
            "/ISAPI/AccessControl/capabilities",
            HttpMethod.GET,
            "AccessControl-wide caps (event ring capacity etc.) — advisory context for "
            "the rolling-log question; absent on some firmware, which is not an error",
        ),
        Endpoint(
            "user_info_count",
            "/ISAPI/AccessControl/UserInfo/Count",
            HttpMethod.GET,
            "roster size sanity check against a paged search",
        ),
        Endpoint(
            "user_info_search",
            "/ISAPI/AccessControl/UserInfo/Search",
            HttpMethod.POST,
            "paged employee roster (stateless search)",
        ),
        Endpoint(
            "acs_event_search",
            "/ISAPI/AccessControl/AcsEvent",
            HttpMethod.POST,
            "paged punch events, time-bounded (stateless search)",
        ),
        Endpoint(
            "acs_event_total_num",
            "/ISAPI/AccessControl/AcsEventTotalNum",
            HttpMethod.POST,
            "advisory event count for one window — the `--count` cross-check (p1-08). "
            "Displays a number, never a loop bound (DESIGN.md). The obvious-looking "
            "`AcsEvent/Total` is 400 notSupport on this firmware and is registered nowhere",
        ),
    )
}


def endpoint_for(name: str) -> Endpoint:
    """Look an endpoint up by name. Unknown names raise — no free-form paths."""
    try:
        return REGISTRY[name]
    except KeyError:
        known = ", ".join(sorted(REGISTRY))
        raise KeyError(f"unknown endpoint {name!r}; registered endpoints: {known}") from None


def allowed_methods_for(name: str) -> frozenset[HttpMethod]:
    """The only methods a caller may use for this endpoint."""
    return frozenset({endpoint_for(name).method})
