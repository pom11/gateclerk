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
#:
#: Five more added by card E1-03 (capability probe, design §1/§3), reviewed as a set.
#: Four are plain stateless searches (`CardInfo/Search`, `UserInfoDetail/Search`,
#: `FingerPrint/Search`, `Intelligent/FDLib/FDSearch`). Note `finger_print_upload`:
#: the name is the DEVICE's, and it is misleading — on this firmware
#: FingerPrintUpload?format=json with a `FingerPrintCond` body READS a fingerprint
#: template device→client (OBSERVED.md "E1 enrollment-read probes", live-proven
#: 2026-10-21); the write-direction sibling `FingerPrintDownload` (client→device) is
#: deliberately NOT registered and stays uncallable until E1-04's bench capture
#: clears the §5.0 write gate — registering a POST that mutates is exactly what this
#: allowlist exists to stop.
SEARCH_ENDPOINTS = frozenset(
    {
        "user_info_search",
        "acs_event_search",
        "acs_event_total_num",
        # --- E1-03 probe surfaces (read-only stateless searches / read-direction POST)
        "card_info_search",
        "user_info_detail_search",
        "fingerprint_search",
        "fd_search",
        "finger_print_upload",
    }
)

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
        # --- E1 enrollment-probe surfaces (card E1-03, design §1/§3) ------------------
        # Read-only additions, each justified by a live bench-A read (docs/OBSERVED.md
        # "E1 enrollment-read probes"). The availability of EACH is probed per device
        # and recorded; several of these answers are 404 on bench A, and the registry
        # still carries the path because the probe must be able to ASK (silence is
        # never data — §0.7). No SetUp/Download/write verb exists below.
        Endpoint(
            "user_info_search_capabilities",
            "/ISAPI/AccessControl/UserInfo/Search/capabilities",
            HttpMethod.GET,
            "documented hypothesis for search-shape caps (v3 probe round): 404 on "
            "bench A — probed per device so the fact is discovered, not inherited",
        ),
        Endpoint(
            "user_info_capabilities",
            "/ISAPI/AccessControl/UserInfo/capabilities",
            HttpMethod.GET,
            "the REAL UserInfo caps document (200 on A): maxRecordNum (batch/page "
            "cap, NOT device capacity), password @max, Valid.timeType @opt, userType "
            "@opt, RightPlan bounds, EmployeeNoList maxSize — recorded as device "
            "CLAIMS, never availability",
        ),
        Endpoint(
            "user_info_setup_capabilities",
            "/ISAPI/AccessControl/UserInfo/SetUp/capabilities",
            HttpMethod.GET,
            "capability DOCUMENT describing the SetUp verb's body — GET of a caps "
            "document, not a write (404 on A; E1-04's capture will record the shape). "
            "The SetUp POST itself is registered nowhere",
        ),
        Endpoint(
            "card_info_search",
            "/ISAPI/AccessControl/CardInfo/Search",
            HttpMethod.POST,
            "paged card roster, wrapped CardInfoSearchCond (stateless search; "
            "bench A answered NO MATCH — 0 cards)",
        ),
        Endpoint(
            "card_info_capabilities",
            "/ISAPI/AccessControl/CardInfo/capabilities",
            HttpMethod.GET,
            "CardInfo caps document (200 on A): cardNo @max, cardType enum, "
            "maxRecordNum — recorded as a device claim",
        ),
        Endpoint(
            "user_info_detail_search",
            "/ISAPI/AccessControl/UserInfoDetail/Search",
            HttpMethod.POST,
            "per-person detail search the docs promise — notSupport on A; probing it "
            "per device decides whether B/C have it (door rights live IN UserInfo)",
        ),
        Endpoint(
            "fingerprint_search",
            "/ISAPI/AccessControl/FingerPrint/Search",
            HttpMethod.POST,
            "fingerprint search the docs promise — genuinely notSupport on A; still "
            "probed per device (§3: never assume a firmware answer)",
        ),
        Endpoint(
            "finger_print_upload",
            "/ISAPI/AccessControl/FingerPrintUpload",
            HttpMethod.POST,
            "the PROVEN fingerprint READ (misleading device name: FingerPrintCond "
            "POST returns FingerPrintList device→client — OBSERVED.md 2026-10-21). "
            "Read-direction only; the client→device FingerPrintDownload stays "
            "unregistered until E1-04's §5.0 capture clears the write gate",
        ),
        Endpoint(
            "finger_print_download_capabilities",
            "/ISAPI/AccessControl/FingerPrintDownload/capabilities",
            HttpMethod.GET,
            "caps document for the fingerprint WRITE verb — GET of a document (404 "
            "on A). The FingerPrintDownload POST is registered nowhere",
        ),
        Endpoint(
            "fd_lib",
            "/ISAPI/Intelligent/FDLib",
            HttpMethod.GET,
            "face-library inventory (FDID 1 blackFD, FDID 2 infraredFD on A) — the "
            "FDID values the FDSearch probe must carry to be legal",
        ),
        Endpoint(
            "fd_search",
            "/ISAPI/Intelligent/FDLib/FDSearch",
            HttpMethod.POST,
            "face-record search, FLAT dialect (no cond wrapper — the wrapped shape "
            "is what 400'd; OBSERVED.md). Returns modelData face TEMPLATES (stateless "
            "search); availability is decided by THIS call, never by the caps switch",
        ),
        Endpoint(
            "fd_lib_capabilities",
            "/ISAPI/Intelligent/FDLib/capabilities",
            HttpMethod.GET,
            "FDLib caps document (200 on A): FDMaxNum, FDRecordDataMaxNum, "
            "modelMaxNum, isSupportModelData — and isSuportFDSearch=false DESPITE "
            "FDSearch working: caps under-claim on this fw; recorded as a claim",
        ),
        Endpoint(
            "acs_cfg_capabilities",
            "/ISAPI/AccessControl/AcsCfg/capabilities",
            HttpMethod.GET,
            "ACS behaviour switches (saveFacePic on A); the §3 capacity-discovery "
            "attempt — where it does not expose maxima, that absence is recorded",
        ),
        Endpoint(
            "plan_template",
            "/ISAPI/AccessControl/PlanTemplate1",
            HttpMethod.GET,
            "door-plan preset read — notSupport on A; probed per device so the "
            "templateNo-evidence rule (§3) knows whether richer evidence exists",
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
