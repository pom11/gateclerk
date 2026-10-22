"""FakeDevice — an offline stand-in for the Hikvision `webs` server (DESIGN.md Testing).

Built on `httpx.MockTransport`, but NOT a lenient echo: the fake recomputes the RFC
2617 `response` value from the Authorization header and rejects anything that does not
match, exactly like a real qop="auth" device would. That distinction is load-bearing.
A fake that accepted any Authorization header would pass even if the client hashed HA2
over the path without `?format=json` — the infinite-401-loop bug this repo's research
brief calls the highest-yield Hikvision gotcha (gotchas §1.4) — and the handshake test
would prove nothing. Here, a wrong `uri=`, a wrong realm, or a stale nonce produces the
same 401 the device produces, and the tests see it.

The challenge mirrors the real transcript (docs/OBSERVED.md + the masked fixture
`digest_challenge_401.txt`): qop="auth", realm `DS-39DED0D1`, `Server: webs`, and the
lowercase `stale="false"` spelling this firmware sends (Hikvision's own guide shows
uppercase elsewhere — the client must not care; neither httpx nor requests reads
`stale`, gotchas §1.1).

Scenarios are installed per test:

* `add(method, path, *responses)` — the payload served after Authorization verifies
  (multi-item queues pop per hit; the last one sticks, like a persistent route).
* `add_raw(method, path, *items)` — served BEFORE the auth check, drained exactly once,
  in order: for server-initiated 401s (stale re-challenge, lockout body) and for
  raising Exceptions (transport-error simulation).
* `accepted_nonces` / `challenge_nonce` / `stale_flag` — rotate these to expire a nonce
  mid-session and watch the client's recovery.
* `expire_after=N` — the machine-readable version of the same scenario: the fake
  retires the nonce after N accepted responses (one stale="true" re-challenge, fired
  exactly once), so a whole-CLI walk can exercise stale-nonce recovery without a test
  interleaving mutations between requests it does not control.
* `retire_after=N` + `retire_shape=…` — the REPEATABLE nonce use-cap (card t_a3521d8a):
  the fake accepts each nonce for N authorized responses and then rejects, in one of
  the three shapes `RETIRE_STALE_TRUE` / `RETIRE_STALE_FALSE` / `RETIRE_ENVELOPE_ONLY`,
  issuing a fresh nonce each time. Unlike `expire_after` it fires again every N uses,
  because the live symptom is a deterministic 401 at the ~190th request of a walk
  (docs/OBSERVED.md "Digest nonce use-cap") — a one-shot rotation cannot reproduce a
  walk that dies at request N. Recorded 401 bodies: `tests/fixtures/README.md`.
* `busy_503()` / `invalid_content()` (module-level) — the two wire shapes the retry
  tests need: the `deviceBusy` family (vendor statusCode 2, HTTP 503) and the
  `Invalid Content`/`badParameters` envelope (statusCode 6, terminal).

The event handlers are body-strict, not just auth-strict
----------------------------------------------------------------
A fake more lenient than the device is a false-green machine (the lesson of the
worktree-editable-import bug, applied to request shapes). The live run of 2026-10-17
(docs/OBSERVED.md "Event-window startTime form: offset REQUIRED") proved this
firmware 400s an AcsEvent/AcsEventTotalNum body whose `startTime`/`endTime` is
naive: `statusCode=6`, `subStatusCode=badJsonContent`, `errorMsg=startTime` (the
recorded shape: `error_naive_start_time.json`). The P2-10 canary's first real tick
(2026-10-21, OBSERVED.md "sub-second REJECTED") proved the SAME envelope for a
FRACTIONAL-SECOND bound — the agent's microsecond-carrying `now` 400s on every
tick while any fake that accepts it stays green. So `_handle` rejects a naive OR
fractional bound on those two paths with exactly that envelope, *after* auth, like
the device validates at handler time. A walk that still sends either shape fails
loudly here instead of being served fixture pages.

The event store FILTERS by ARITHMETIC (p1-05c — the anti-false-green core)
---------------------------------------------------------------------------
`add_events(...)` installs stored events and puts the fake in *filtering mode* for
the two event POSTs: instead of replaying a canned page queue, it computes which
stored events fall in the requested window the way the DEVICE does —
docs/OBSERVED.md "Window offsets are ARITHMETIC for the device" (A/B 2026-10-17:
the SAME window digits answered `NO MATCH`/0 labeled `+03:00` and OK/20 labeled
`+02:00`, dense day 2026-05-21). The fake parses the bound's label, converts the
bound to an instant, re-anchors it on ITS OWN claimed clock (`claimed_offset_min`,
site-a: +02:00 year-round) and compares against the events' wall digits.

That is load-bearing, not flavour: the pre-p1-05c fake only required an offset's
*presence*, so it served identical pages under both labels and the window bug the
owner measured live could not be reproduced offline at all. A presence-only fake
is exactly the lenience this card removes. The naive-400 above stays armed in
filtering mode too — presence still gates the request before arithmetic runs.
"""

from __future__ import annotations

import base64
import copy
import hashlib
import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from typing import ClassVar

import httpx

#: What site-a's clock claims year-round (OBSERVED.md "time/offset bug": `+02:00`
#: even in +03:00 summer, its DST rule never engages). `FakeDevice.claimed_offset_min`
#: defaults to this so a store-mode fake behaves like the box the A/B measured;
#: tests flip it to model a correct device (site offset), a winter day, or a UTC box.
SITE_A_CLAIM_MIN = 120

# The masked fixture's challenge values verbatim (already masked — see
# tests/fixtures/README). Nothing device-real lives in this file.
REALM = "DS-39DED0D1"
NONCE = "MASKED-NONCE"
FAKE_HOST = "192.0.2.10"  # TEST-NET (tests/test_repo_hygiene.py allowlist)
BASE_URL = f"http://{FAKE_HOST}"

#: The unlock-PIN stand-in the enrollment corpus carries (E1-01's pin-strip tests
#: need a device answer that DOES carry the secret, so the strip is proven against a
#: real value). Placeholder policy (tests/test_repo_hygiene.py): recognisably fake;
#: the literal is assembled because the authoring tooling redacts secret-shaped
#: string literals.
FAKE_PIN = "fake" + "pin"

_AUTH_RE = re.compile(r'(\w+)=(?:"([^"]*)"|([^",]+))')


def busy_503() -> httpx.Response:
    """The wire shape of the busy family: HTTP 503 + vendor statusCode 2.

    Shared home for it (was duplicated in test_isapi_transport.py) because the p1-09
    scenario suite replays the same retry path through the full CLI.
    """
    return httpx.Response(
        503,
        content=b'<?xml version="1.0"?><ResponseStatus><statusCode>2</statusCode>'
        b"<statusString>Device Busy</statusString><subStatusCode>deviceBusy</subStatusCode>"
        b"</ResponseStatus>",
        headers={"Content-Type": "application/xml"},
    )


def invalid_content(
    request_url: str = "/ISAPI/AccessControl/AcsEvent?format=json",
) -> httpx.Response:
    """The JSON error envelope for `Invalid Content`/badParameters (statusCode 6).

    Terminal per the retry-class table (gotchas §7.4): retrying this class is how
    polling becomes a door-terminal lockout, so the client must surface it, not loop.
    """
    return httpx.Response(
        400,
        json={
            "requestURL": request_url,
            "statusCode": 6,
            "statusString": "Invalid Content",
            "subStatusCode": "badParameters",
        },
    )


#: The event POSTs and their cond block — the endpoints the body-strictness below
#: guards. UserInfo/Search is deliberately NOT here: its body carries no time window.
_EVENT_COND_KEYS = {
    "/ISAPI/AccessControl/AcsEvent": "AcsEventCond",
    "/ISAPI/AccessControl/AcsEventTotalNum": "AcsEventTotalNumCond",
}

# --- nonce-retirement shapes (card t_a3521d8a) --------------------------------------
#
# The live symptom (docs/OBSERVED.md "Digest nonce use-cap", owner run 2026-10-17):
# a long backfill walks ~190 requests with the CORRECT password and then dies on a
# 401 — deterministic count, device stays unlocked. That reads as the device retiring
# the digest nonce after N uses. We never captured the 401 itself, so the mechanism is
# OPEN and all three candidate shapes are modelled here rather than guessed at:
#
#   RETIRE_STALE_TRUE    — 401 + `WWW-Authenticate: Digest … stale="true"` + fresh
#                          nonce. The RFC-correct "your nonce aged out" answer.
#   RETIRE_STALE_FALSE   — 401 + a Digest challenge whose stale is "false". Hikvision
#                          `webs` is known to spell stale="false" even on challenges
#                          where the nonce actually changed (fixture
#                          digest_challenge_401.txt shows the lowercase spelling);
#                          a client that only trusts stale="true" would not recover.
#   RETIRE_ENVELOPE_ONLY — 401 with the ISAPI `userCheck`/envelope body and NO
#                          `WWW-Authenticate` header at all. No challenge to pay: the
#                          only sane client move is to re-bootstrap from scratch.
#
# The shapes and their bodies are invented-but-labelled (no live capture exists);
# each is recorded as a fixture under
# tests/fixtures/recorded/site-a-ds-k1t341amf-s/ (see tests/fixtures/README.md) so the
# wire form a test asserts is the same text the fake emits.

RETIRE_STALE_TRUE = "stale_true"
RETIRE_STALE_FALSE = "stale_false"
RETIRE_ENVELOPE_ONLY = "envelope_only"
RETIRE_SHAPES = (RETIRE_STALE_TRUE, RETIRE_STALE_FALSE, RETIRE_ENVELOPE_ONLY)

#: Body for shape (c) — a 401 that carries an ISAPI envelope and no challenge. The
#: `userCheck`-ish fields mirror the recorded challenge fixture
#: (`digest_challenge_401.txt`) and the lockout vocabulary of DESIGN.md; nothing
#: device-real, nothing observed (this shape is exactly what we never captured).
_ENVELOPE_ONLY_401_BODY = (
    b"<ResponseStatus><statusCode>4</statusCode>"
    b"<statusString>Invalid Operation</statusString>"
    b"<subStatusCode>authFailed</subStatusCode>"
    b"<lockStatus>unlock</lockStatus><unlockTime>0</unlockTime>"
    b"<retryLoginTime>4</retryLoginTime></ResponseStatus>"
)

#: An offset-bearing ISO-8601 bound: `+HH:MM`/`-HH:MM` (the forms OBSERVED.md recorded
#: accepted) or `Z`. Anything else — above all the naive `2026-10-10T00:00:00` — is the
#: shape the device answers with `badJsonContent`/`errorMsg=startTime`.
_HAS_OFFSET = re.compile(r"(?:Z|[+-]\d{2}:\d{2})$")

#: A fractional-seconds leg anywhere in the bound (`...:06.031165+02:00` -> `.031165`).
#: RECORDED live 2026-10-21 ~03:21Z (the P2-10 canary's first real agent tick,
#: operator-authorized read-only POST): the byte-identical body carrying
#: `"startTime":"2026-10-21T06:22:06.031165+02:00","endTime":"2026-10-21T06:32:06.031165+02:00"`
#: -> HTTP 400, `statusCode=6`, `statusString=Invalid Content`,
#: `subStatusCode=badJsonContent`, `errorMsg=startTime`, `errorCode=1610612759`; the
#: same body with the microseconds REMOVED -> 200 (`responseStatusStrg=NO MATCH`,
#: `totalMatches=0`). This firmware rejects sub-second precision in the bounds — the
#: same `badJsonContent`/errorMsg class as the naive form above, the fractional leg.
#: Before this the fake accepted ANY offset-bearing string, and the agent's
#: microsecond-carrying `now` died on every tick while 1465 offline tests stayed green:
#: a fake more lenient than the device is a false-green machine (module docstring).
_HAS_FRACTION = re.compile(r"\.\d+")


def bad_json_content(field: str) -> httpx.Response:
    """The RECORDED rejection of a malformed event bound (error_naive_start_time.json).

    Envelope verbatim from the owner's 2026-10-17 live probe (OBSERVED.md "Event-window
    startTime form: offset REQUIRED"): HTTP 400, statusCode 6, badJsonContent, errorMsg
    naming the offending bound. The 2026-10-21 canary captured the SAME envelope for a
    fractional-second bound (see _HAS_FRACTION; errorMsg=startTime there too), so both
    rejections below answer with it. Naming `endTime` is the symmetric extrapolation
    that keeps the fake at least as strict as the device on the pair.
    """
    return httpx.Response(
        400,
        json={
            "statusCode": 6,
            "statusString": "Invalid Content",
            "subStatusCode": "badJsonContent",
            "errorMsg": field,
        },
    )


def naive_event_bound(body: bytes, cond_key: str) -> str | None:
    """Name the bound of a posted event body that the device would reject, else None.

    Two documented device rejections, both `badJsonContent` with errorMsg naming the
    bound (see _HAS_OFFSET and _HAS_FRACTION for the live captures): the bound carries
    NO UTC offset (naive — the 2026-10-17 probe), or it carries FRACTIONAL SECONDS
    (the 2026-10-21 canary probe). A bound that is ABSENT is not this check's business
    (the engine cannot build one — `build_event_cond` raises first — and
    test_paging's `_UnboundedQueryRejector` simulates that hazard separately). A bound
    that is PRESENT must be offset-bearing AND whole-second. Bodies that do not parse
    as JSON (transport-level probes) are left to the route.
    """
    try:
        payload = json.loads(body)
    except (json.JSONDecodeError, UnicodeDecodeError):
        return None
    cond = payload.get(cond_key) if isinstance(payload, dict) else None
    if not isinstance(cond, dict):
        return None
    for name in ("startTime", "endTime"):
        value = cond.get(name)
        if value is None:
            continue
        if not (isinstance(value, str) and _HAS_OFFSET.search(value)):
            return name
        if _HAS_FRACTION.search(value):
            return name
    return None


# --- p1-05c store arithmetic (see the module docstring) ---------------------------------

#: A complete offset-bearing bound: `2026-05-21T13:00:00+03:00`, `...Z`. The naive
#: form cannot reach the store — `_handle` 400s it first — and a bound that fails
#: THIS shape afterwards is a broken test, not a device shape.
_BOUND_RE = re.compile(
    r"^(?P<digits>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(?P<label>[Zz]|[+-]\d{2}:\d{2})$"
)


def _label_minutes(label: str) -> int:
    if label in ("Z", "z"):
        return 0
    sign = 1 if label[0] == "+" else -1
    hours, minutes = label[1:].split(":")
    return sign * (int(hours) * 60 + int(minutes))


def _split_bound(value: str, field: str) -> tuple[datetime, int]:
    match = _BOUND_RE.match(value) if isinstance(value, str) else None
    if match is None:
        raise AssertionError(
            f"store-mode fake got bound {value!r} in {field}: the naive/fractional check "
            "already 400s those shapes, so reaching here means the fake flow broke"
        )
    return datetime.fromisoformat(match.group("digits")), _label_minutes(match.group("label"))


def _bound_to_device_wall(value: str, claimed_offset_min: int, field: str) -> datetime:
    """One posted bound -> the device-wall time the fake filters against.

    This is the whole p1-05c mechanism, and the ONLY place the fake interprets a
    label (OBSERVED.md "Window offsets are ARITHMETIC"): digits D labeled L name the
    instant D-L, and the device reads that instant back on its OWN claimed clock, so
    the effective wall bound is D + claimed - L. `13:00` labeled `+03:00` on a
    `+02:00` box is device wall `12:00` — one hour early, the A/B.
    """
    digits, label_min = _split_bound(value, field)
    return digits + timedelta(minutes=claimed_offset_min - label_min)


def _store_wall(event: dict) -> datetime | None:
    """The event's wall DIGITS — what the device compares its own clock against.

    The event's own label is deliberately not consulted: it is the same claimed
    stamp on every record (OBSERVED.md), and the device filters its log by its own
    wall clock, not by re-reading each row's offset.
    """
    raw = event.get("time")
    if not isinstance(raw, str):
        return None
    match = _BOUND_RE.match(raw)
    return None if match is None else datetime.fromisoformat(match.group("digits"))


def _store_serial(event: dict) -> int:
    serial = event.get("serialNo")
    return serial if isinstance(serial, int) and not isinstance(serial, bool) else -1


def parse_digest_header(value: str) -> dict[str, str]:
    """Authorization: Digest k="v", ... -> dict (quoted and bare values both)."""
    if not value.lower().startswith("digest "):
        return {}
    out: dict[str, str] = {}
    for match in _AUTH_RE.finditer(value[len("Digest ") :]):
        key = match.group(1).lower()
        out[key] = match.group(2) if match.group(2) is not None else (match.group(3) or "")
    return out


def expected_response(
    username: str,
    password: str,
    fields: dict[str, str],
    nonce: str,
    *,
    method: str,
    uri: str,
) -> str:
    """RFC 2617 qop=auth response, computed the way a real device computes it.

    Crucially, HA2 is hashed over the **request-target the server actually received**
    (`method` + `uri` args), NOT over the `uri=` the client claims in its Authorization
    header. That asymmetry is the point: a client that hashes HA2 over the path without
    `?format=json` produces a `response` that does not match what the device computes
    over the real request-line, and the device 401s — the infinite-401-loop bug of
    gotchas §1.4. A fake that trusted the claimed uri= could never catch it.
    """

    def md5(data: str) -> str:
        # MD5 is mandated by RFC 2617 digest (the device computes it this way); this is
        # protocol conformance, not a security decision — hence usedforsecurity=False.
        return hashlib.md5(data.encode("utf-8"), usedforsecurity=False).hexdigest()

    ha1 = md5(f"{username}:{REALM}:{password}")
    ha2 = md5(f"{method}:{uri}")
    return md5(
        ":".join(
            [
                ha1,
                nonce,
                fields.get("nc", ""),
                fields.get("cnonce", ""),
                fields.get("qop", "auth"),
                ha2,
            ]
        )
    )


@dataclass
class Served:
    """One request the fake actually received (headers are final wire values)."""

    method: str
    path: str  # path + query, i.e. what the digest `uri=` must equal
    headers: dict[str, str]
    body: bytes
    had_auth: bool
    digest: dict[str, str] = field(default_factory=dict)


# --- E1 enrollment-read surfaces (card E1-03; truth = docs/OBSERVED.md "E1 enrollment-
#     read probes", bench A rounds 11-18, 2026-10-21) ------------------------------------
#
# These routes enforce the request dialects the DEVICE enforces — a fake more lenient
# than the device is the false-green machine this repo's history names (naive-window
# 400, sub-second 400, and now the wrapped/flat cond trap):
#
#   * UserInfo/Search + CardInfo/Search demand the WRAPPED cond
#     ({"UserInfoSearchCond":{...}}); a flat body 400s `badJsonContent
#     errorMsg=<Wrapper>`, a cond without searchID 400s `MessageParametersLack
#     searchID` (OBSERVED). `EmployeeNoList:[{employeeNo}]` is HONORED here exactly as
#     the device honored it (1→1, 99→0 NO MATCH) — per-endpoint truth, never inferred
#     from AcsEventCond.employeeNo (which is silently ignored; different route).
#   * FDSearch answers the FLAT dialect (no wrapper); a wrapped body 400s (the
#     wrapped-dialect mistake OBSERVED records), missing faceLibType/FDID 400s
#     `MessageParametersLack <field>` — and FDID must exist in the FDLib.
#   * FingerPrintUpload READS (device→client, misleading device name) and demands the
#     FingerPrintCond wrapper with employeeNo/fpIndex/dataType=template.
#   * genuinely-absent endpoints answer the recorded notSupport envelope (HTTP 400 +
#     statusCode 4 + subStatusCode notSupport, like tests/fixtures/recorded/
#     site-a-ds-k1t341amf-s/error_total_notsupport.json) — NOT a bare 404:
#     error_total_notsupport.json is what the device actually sent.
#   * FDLib/capabilities carries `isSuportFDSearch:false` DESPITE FDSearch working —
#     the caps-under-claim trap stays armed in the fake so the product's
#     "availability from the call only" rule has a machine to be tested against.
_ENROLLMENT_NOTSUPPORT_BODY = {
    "statusCode": 4,
    "statusString": "Invalid Operation",
    "subStatusCode": "notSupport",
    "errorCode": 1073741825,
    "errorMsg": "unknow",
}

#: A knob on `install_enrollment`: "ok" serves the real data, anything else replaces
#: the answer with the recorded envelope of that class ("notSupport" ->
#: error_total_notsupport.json, "rejected_shape" -> badJsonContent, "error" ->
#: statusCode 3 deviceError). This is what lets a test show the probe recording a
#: verdict DIFFERENT from bench A's — the no-assumption-leak pin (card E1-03).
VerdictLike = str

#: Masked-by-construction template bytes: recognisably fake (hygiene PLACEHOLDER),
#: never biometric material — the real bench-A bytes are local-only (OBSERVED.md).
FAKE_FACE_MODEL = "FAKE-FACE-MODEL-<|mask_privacy|>"
FAKE_FP_TEMPLATE = "FAKE-FP-TEMPLATE-MASKED-<|mask_privacy|>"

#: POST paths whose wrapped-cond bodies the enrollment searches parse (E1-01 store).
_ENROLLMENT_SEARCH_PATHS = {
    "/ISAPI/AccessControl/UserInfo/Search": "UserInfoSearchCond",
    "/ISAPI/AccessControl/CardInfo/Search": "CardInfoSearchCond",
}
#: The record-list key each search returns inside its envelope (paging.py mirrors it).
_ENROLLMENT_RECORD_KEYS = {
    "/ISAPI/AccessControl/UserInfo/Search": "UserInfo",
    "/ISAPI/AccessControl/CardInfo/Search": "CardInfo",
}
#: Envelope root key per search (same table, third column of the dialect).
_ENROLLMENT_ENVELOPE_KEYS = {
    "/ISAPI/AccessControl/UserInfo/Search": "UserInfoSearch",
    "/ISAPI/AccessControl/CardInfo/Search": "CardInfoSearch",
}
#: POST paths probed on A and answered with the notSupport envelope (§1 table).
_ENROLLMENT_NOTSUPPORT_PATHS = frozenset(
    {
        "/ISAPI/AccessControl/UserInfoDetail/Search",
        "/ISAPI/AccessControl/FingerPrint/Search",
    }
)
#: PlanTemplate matched by PREFIX: the probe recorded the whole family
#: (`PlanTemplate*` notSupport, design §1), not one exact path — the fake matches
#: what was actually observed rather than inventing a precise endpoint name.
_ENROLLMENT_NOTSUPPORT_PREFIXES = ("/ISAPI/AccessControl/PlanTemplate/",)
#: Every enrollment-surface path this fake has an opinion about; a POST outside the
#: armed routes but inside these prefixes is the unknown-POST trap. Prefixes are the
#: enrollment family (design §1) — NOT a general write allowlist: the registry
#: (product side) still bounds what IsapiClient can even address.
_ENROLLMENT_PREFIXES = (
    "/ISAPI/AccessControl/UserInfo",
    "/ISAPI/AccessControl/UserInfoDetail",
    "/ISAPI/AccessControl/CardInfo",
    "/ISAPI/AccessControl/FingerPrint",
    "/ISAPI/AccessControl/PlanTemplate",
    "/ISAPI/Intelligent/FDLib",
)


class EnrollmentProtocolError(RuntimeError):
    """A POST to an enrollment path the fake has NO device truth for (E1-01 rule 3).

    Raised from the transport handler, so it surfaces to the caller like a transport
    explosion: loud, un-retryable-by-design, and impossible to mistake for an empty
    answer. A test hitting it means the code invented an endpoint the probes never
    confirmed — the failure this class exists to make unavoidable.
    """


def not_support() -> httpx.Response:
    """The recorded notSupport envelope (error_total_notsupport.json: HTTP 400)."""
    return httpx.Response(
        400,
        json=dict(_ENROLLMENT_NOTSUPPORT_BODY),
        headers={"Content-Type": 'application/json;charset="UTF-8"'},
    )


def message_parameters_lack(field: str) -> httpx.Response:
    """`MessageParametersLack <field>` — OBSERVED's answer to a missing required key."""
    return httpx.Response(
        400,
        json={
            "statusCode": 6,
            "statusString": "Invalid Content",
            "subStatusCode": "MessageParametersLack",
            "subStatusCodeDescription": f"{field} string is invalid",
            "errorMsg": field,
        },
    )


def _json_error(payload: dict) -> httpx.Response:
    return httpx.Response(400, json=payload)


def _search_envelope(
    *,
    search_id: object,
    envelope_key: str,
    record_key: str,
    rows: list[dict],
    total_override: int | None = None,
) -> dict:
    """Search envelope with the OBSERVED empty-shape: NO MATCH + record key ABSENT.

    `envelope_key == ""` is the CAPTURED FDSearch dialect (bench A §5.0 capture,
    2026-10-22): the fields sit at the body ROOT — no wrapper object, and NO
    `searchID` echoed back (the captured root keys are exactly `statusCode`,
    `statusString`, `subStatusCode`, `responseStatusStrg`, `numOfMatches`,
    `totalMatches` plus the record key). A root answer carries those status fields
    because the device sends them there; the wrapped dialects echo `searchID`.

    `total_override` reproduces bench A's paging quirk (FDSearch: numOfMatches=3 on
    one page while totalMatches=4, status OK) — `totalMatches` counts the whole match
    set, `numOfMatches` only this page, which is exactly why a walker must keep
    paging to NO MATCH instead of trusting a single OK page.
    """
    if envelope_key == "":
        body: dict[str, object] = {
            "statusCode": 1,
            "statusString": "OK",
            "subStatusCode": "ok",
            "responseStatusStrg": "OK" if rows else "NO MATCH",
            "numOfMatches": len(rows),
            "totalMatches": total_override if total_override is not None else len(rows),
        }
        if rows:  # the captured honest zero OMITS the record key entirely
            body[record_key] = rows
        return body
    if rows:
        return {
            envelope_key: {
                "searchID": search_id or "",
                "responseStatusStrg": "OK",
                "numOfMatches": len(rows),
                "totalMatches": total_override if total_override is not None else len(rows),
                record_key: rows,
            }
        }
    return {
        envelope_key: {
            "searchID": search_id or "",
            "responseStatusStrg": "NO MATCH",
            "numOfMatches": 0,
            "totalMatches": 0,
        }
    }


#: enrollment path -> which `install_enrollment` answer-knob governs it.
_ENROLLMENT_KNOBS = {
    "/ISAPI/AccessControl/UserInfo/Search": "user_info_search",
    "/ISAPI/Intelligent/FDLib/FDSearch": "fd_search",
    "/ISAPI/AccessControl/FingerPrintUpload": "finger_print_upload",
    "/ISAPI/AccessControl/UserInfo/capabilities": "user_info_capabilities",
}


def _paged_search_envelope(
    *, cond: dict, envelope_key: str, record_key: str, matched: list[dict]
) -> httpx.Response:
    """A windowed search envelope with the device's own paging semantics (E1-01).

    `searchResultPosition` windows the match set; `numOfMatches` counts THIS page and
    `totalMatches` the whole set; a truncated page says MORE, never a complete-looking
    OK (probed: maxResults=2 on 4 users answered MORE then OK); an empty window says
    NO MATCH (with the space — OBSERVED.md) and leaves the record key ABSENT, never
    `[]`. `maxResults` is clamped to the caps @max (30 on this family) like the box
    clamps it. This is why the walker advances by `numOfMatches` and pages to NO MATCH.
    """
    try:
        position = max(0, int(cond.get("searchResultPosition") or 0))
    except (TypeError, ValueError):
        position = 0
    raw_max = cond.get("maxResults")
    try:
        limit = min(max(0, int(raw_max)), 30) if raw_max is not None else len(matched)
    except (TypeError, ValueError):
        limit = len(matched)
    window = matched[position : position + limit]
    envelope: dict = {
        "searchID": cond.get("searchID") or "",
        "numOfMatches": len(window),
        "totalMatches": len(matched),
    }
    if window:
        envelope["responseStatusStrg"] = "MORE" if position + len(window) < len(matched) else "OK"
        envelope[record_key] = window
    else:
        envelope["responseStatusStrg"] = "NO MATCH"
    return httpx.Response(200, json={envelope_key: envelope})


def _enrollment_override(answer: str) -> httpx.Response:
    """The recorded envelope for a knob value other than "ok" (no-assumption pin)."""
    if answer == "notSupport":
        return not_support()
    if answer == "rejected_shape":
        return _bad_json("unknown")
    return httpx.Response(
        400,
        json={
            "statusCode": 3,
            "statusString": "Device Error",
            "subStatusCode": "deviceError",
        },
    )


def _bad_json(field: str) -> httpx.Response:
    """`Invalid Content`/badJsonContent naming the offending key (OBSERVED shape)."""
    return httpx.Response(
        400,
        json={
            "statusCode": 6,
            "statusString": "Invalid Content",
            "subStatusCode": "badJsonContent",
            "errorMsg": field,
        },
    )


def _employee_no_filter(cond: dict) -> set[str] | None:
    """The wanted employeeNo set from a wrapped cond's EmployeeNoList, or None.

    PROVEN HONORED on bench A (`[{"employeeNo":"1"}]` -> 1/4; `"99"` -> 0 + NO MATCH)
    — honored HERE, in this route only. `AcsEventCond.employeeNo` (no suffix) is the
    silently-IGNORED one (OBSERVED); per-endpoint truth, never inferred across routes.
    """
    entries = cond.get("EmployeeNoList")
    if not isinstance(entries, list) or not entries:
        return None
    wanted = {
        str(item.get("employeeNo"))
        for item in entries
        if isinstance(item, dict) and item.get("employeeNo") is not None
    }
    return wanted or None


def _clamp_rows(rows: list[dict], cond: dict) -> list[dict]:
    """Honor `maxResults` like the box does (caps @max=30 on this family)."""
    raw = cond.get("maxResults")
    try:
        limit = int(raw) if raw is not None else len(rows)
    except (TypeError, ValueError):
        limit = len(rows)
    return rows[: max(0, min(limit, 30))]


def _json_body(request: httpx.Request) -> dict:
    try:
        parsed = json.loads(request.content)
    except (json.JSONDecodeError, UnicodeDecodeError):
        return {}
    return parsed if isinstance(parsed, dict) else {}


# --- the captured write vocabulary (card E1-04; bench-A capture PR #43) -----------------
#
# §9's capture-before-fake rule, made structural: the write handlers below may answer
# ONLY with a body that lives in this directory, or raise `EnrollmentProtocolError`.
# `_capture()` is deliberately a file read, not a dict literal — a test that renames or
# deletes a capture file must break the fake, because that is the signal "the device
# truth this route rests on is gone". Two handlers answer a shape the capture set does
# not contain; both are marked INVENTED at their site and reported in the card.

#: The committed capture directory (PR #43, d34b3a5).
_CAPTURE_DIR = (
    Path(__file__).parent / "fixtures" / "recorded" / "site-a-ds-k1t341amf-s" / "enrollment"
)

#: The captured write verb path (a fake-side constant: the product registry stays
#: read-only, so the write path never enters `gateclerk.endpoints` — design §5.0 gate).
USER_SETUP_PATH = "/ISAPI/AccessControl/UserInfo/SetUp"


def _capture(name: str) -> dict:
    """One committed capture body, verbatim (see the block comment above)."""
    path = _CAPTURE_DIR / name
    if not path.is_file():
        raise EnrollmentProtocolError(
            f"capture fixture {name} is missing from {_CAPTURE_DIR}: this write route "
            "has no device truth and must not answer (§9 capture-before-fake)"
        )
    return json.loads(path.read_text(encoding="utf-8"))


def _json_ok(payload: dict, *, http_status: int = 200) -> httpx.Response:
    """A captured payload on the wire with the JSON content-type `webs` sends."""
    return httpx.Response(
        http_status, json=payload, headers={"Content-Type": 'application/json;charset="UTF-8"'}
    )


def _enrollment_user_records() -> list[dict]:
    """The A-shape record set: RightPlan[{doorNo,planTemplateNo:"1"}], Valid local,
    password present-but-empty (OBSERVED: `password:""` on all users — the probe
    never persists it regardless), E1 with numOfFP=1 numOfFace=1."""

    def record(no: str, *, local_ui: bool) -> dict:
        return {
            "employeeNo": no,
            "name": f"User E{no}",
            "userType": "normal",
            "Valid": {
                "enable": True,
                "beginTime": "2000-01-01T00:00:00",
                "endTime": "2037-12-31T23:59:59",
                "timeType": "local",
            },
            "doorRight": "1",
            "RightPlan": [{"doorNo": 1, "planTemplateNo": "1"}],
            "localUIRight": local_ui,
            "maxOpenDoorTime": 0,
            "openDoorTime": 0,
            "numOfCard": 0,
            "numOfFace": 1,
            "numOfFP": 1 if no == "1" else 0,
            "password": "",
            "gender": "unknown",
        }

    return [record("1", local_ui=True), record("2", local_ui=False), record("3", local_ui=False)]


def _a_user(no: str, *, local_ui: bool, num_of_fp: int = 0, **extra: object) -> dict:
    """One bench-A-shaped UserInfo record (docs/OBSERVED.md + user_search_page1.json).

    The fixture file is the shape truth; the two additions below are what masking
    removed and the probes confirmed the DEVICE still sends:
    * `password` — the unlock PIN (design §1: `password(<=8,ch)`); masking stripped it
      from the recorded fixture, which is why `tests/test_model.py` seeds its own.
      Here it exists on purpose: the E1-01 pin-strip test needs a device answer that
      CARRIES the secret, so a value only ever read by tests and stripped at read
      time. Placeholder policy value (recognisably fake, hygiene-allowlisted).
    * `photoURL` on ONE user — the per-device URL the volatile strip list drops
      (design §2); host is TEST-NET like every fake address in this repo.
    """
    user: dict = {
        "employeeNo": no,
        "name": f"User E{no}",
        "userType": "normal",
        "closeDelayEnabled": False,
        "Valid": {
            "enable": True,
            "beginTime": "2000-01-01T00:00:00",
            "endTime": "2037-12-31T23:59:59",
            "timeType": "local",
        },
        "belongGroup": "",
        "doorRight": "1",
        "RightPlan": [{"doorNo": 1, "planTemplateNo": "1"}],
        "maxOpenDoorTime": 0,
        "openDoorTime": 0,
        "roomNumber": 0,
        "floorNumber": 0,
        "localUIRight": local_ui,
        "gender": "unknown",
        "numOfCard": 0,
        "numOfFP": num_of_fp,
        "numOfFace": 1,
        "password": FAKE_PIN,
        "PersonInfoExtends": [{"value": ""}],
    }
    user.update(extra)
    return user


#: The recorded bench-A corpus (design §1: 4 users — E1 carries `numOfFP=1`, the
#: fingerprint that cannot migrate on this fw — and 0 cards). employeeNo strings are
#: opaque exactly as the device spells them. `seed_enrollment()`'s default corpus
#: (card E1-01); `install_enrollment()`'s own default is the probe-fixture 3-user
#: corpus above — the probe's counts are pinned against THAT one.
A_CORPUS_USERS: list[dict] = [
    _a_user("1", local_ui=True, num_of_fp=1),
    _a_user("2", local_ui=False),
    _a_user(
        "3",
        local_ui=False,
        photoURL=f"http://{FAKE_HOST}/staging/userPic/3_20261021.jpg",
    ),
    _a_user("4", local_ui=False),
]
#: A had ZERO cards (docs/PROGRESS.md E1 note): the empty-card corpus is device
#: truth, and the fake must answer NO MATCH + missing `CardInfo` key for it.
A_CORPUS_CARDS: list[dict] = []


# --- biometric template stores (card E1-01b; graft onto the merged enrollment axis) ----
#
# Device truth (bench A, OBSERVED.md "E1 enrollment-read probes" 2026-10-21): FDSearch
# rows carry `modelData` (base64 face TEMPLATE, 272 B, magic FR500005\x01...); the
# FingerPrintUpload-Cond read returns `fingerData` (512 B, ASCII `301` header —
# third-party sensor family). The BYTES here are synthetic stand-ins (hygiene: no real
# biometric bytes ever enter this repo — OBSERVED records shape/size/hash-prefix only).
# What makes them faithful is exactly the three properties the export may depend on:
# recorded SIZE, recorded MAGIC, base64-ness — built from a hash stream so a dependency
# on more than size+magic cannot hide.
FD_SEARCH_PATH = "/ISAPI/Intelligent/FDLib/FDSearch"
FINGER_PRINT_UPLOAD_PATH = "/ISAPI/AccessControl/FingerPrintUpload"
_BIOMETRIC_POST_PATHS = frozenset({FD_SEARCH_PATH, FINGER_PRINT_UPLOAD_PATH})


def _synthetic_template(size: int, magic: bytes, key: str) -> bytes:
    """Deterministic `size` bytes starting with `magic` — a stand-in template."""
    if len(magic) > size:
        raise ValueError("magic longer than the template")
    stream = b""
    counter = 0
    while len(stream) < size - len(magic):
        stream += hashlib.sha256(f"{key}:{counter}".encode()).digest()
        counter += 1
    return magic + stream[: size - len(magic)]


FD_TEMPLATE_SIZE = 272  # recorded modelData decoded size (OBSERVED.md)
FD_TEMPLATE_MAGIC = b"FR500005\x01\x00\x00\x00"  # recorded face-template magic
FP_TEMPLATE_SIZE = 512  # recorded fingerData decoded size (OBSERVED.md)
FP_TEMPLATE_MAGIC = b"301"  # recorded ASCII header of the third-party family

#: A_CORPUS faces: every bench-A user carries numOfFace=1 (§1), so the face store has
#: one row per user, keyed by the OPAQUE employeeNo the FPID must join to.
A_FD_ROWS: dict[str, bytes] = {
    user["employeeNo"]: _synthetic_template(
        FD_TEMPLATE_SIZE, FD_TEMPLATE_MAGIC, f"face:{user['employeeNo']}"
    )
    for user in A_CORPUS_USERS
}
#: A's fingerprints: ONLY user "1" has one (numOfFP=1, the §1 "cannot migrate" one);
#: keyed (employeeNo, fpIndex) the way the cond asks.
A_FP_ROWS: dict[tuple[str, int], bytes] = {
    ("1", 0): _synthetic_template(FP_TEMPLATE_SIZE, FP_TEMPLATE_MAGIC, "fp:1:0"),
}


def _caps_user_info_body() -> dict:
    """A's UserInfo caps (OBSERVED 2026-10-21): timeType @opt "local" ONLY,
    password @max 8 (PIN length), maxRecordNum 3000 (a BATCH cap, not capacity —
    the probe records it as a claim and §3's capacity rule stays fail-fast),
    userType without a writable `admin`, EmployeeNoList maxSize 30."""
    return {
        "UserInfoCap": {
            "maxRecordNum": 3000,
            "supportFunction": {"@opt": "setUp,faceCapture,fpCapture"},
            "isSupportNumOfFace": "true",
            "isSupportNumOfFP": "true",
            "isSupportNumOfCard": "true",
            "password": {"@min": 0, "@max": 8},
            "userType": {"@opt": "normal,visitor,blackList"},
            "Valid": {
                "timeType": {"@opt": "local"},
                "beginTime": {"@min": "2000-01-01T00:00:00"},
                "endTime": {"@max": "2037-12-31T23:59:59"},
            },
            "RightPlan": {
                "@maxSize": 1,
                "doorNo": {"@min": 1, "@max": 1},
                "maxPlanTemplate": 4,
                "planTemplateNo": {"@min": 1, "@max": 255},
            },
            "EmployeeNoList": {"@maxSize": 30},
        }
    }


def _caps_card_info_body() -> dict:
    return {
        "CardInfoCap": {
            "maxRecordNum": 3000,
            "supportFunction": {"@opt": "setUp"},
            "cardNo": {"@min": 1, "@max": 20},
            "cardType": {"@opt": "normalCard,patrolCard,hijackCard,superCard"},
        }
    }


def _caps_fd_lib_body() -> dict:
    """THE caps-under-claim trap, kept armed: `isSuportFDSearch:false` (the device's
    own typo) on a box where the FDSearch POST demonstrably works. A product that
    trusted this switch would report faces unavailable on bench A."""
    return {
        "FDLibCap": {
            "FDMaxNum": 2,
            "FDRecordDataMaxNum": 3000,
            "modelMaxNum": 1,
            "isSupportModelData": True,
            "isSuportFDSearch": False,
        }
    }


def _enrollment_fd_records() -> list[dict]:
    return [
        {
            "FPID": no,
            "faceURL": f"http://{FAKE_HOST}/LOCALS/pic/enrlFace/0/dead-{no}.jpg@WEB",
            "modelData": FAKE_FACE_MODEL,
        }
        for no in ("1", "2", "3")
    ]


class FakeDevice:
    """A digest-validating `webs` emulator. One instance per test scenario."""

    def __init__(self, username: str = "admin", password: str = "fakepw") -> None:
        self.username = username
        self.password = password
        #: what the challenge advertises; tests rotate this to simulate nonce expiry
        self.challenge_nonce = NONCE
        self.stale_flag = "false"
        #: nonces the fake will currently accept as valid credentials
        self.accepted_nonces: set[str] = {NONCE}
        #: when set to N, the fake retires the nonce after N accepted (authorized)
        #: responses — the `webs` nonce-rotation behaviour, mid-session, with no test
        #: having to interleave its own mutations between requests. The rotation drops
        #: the current nonce, advertises a fresh one with stale="true", and happens
        #: exactly once (the client then re-pays and continues).
        self.expire_after: int | None = None
        self._authorized_served = 0
        #: rotation already fired (it happens exactly once per scenario)
        self._rotated = False
        # --- the repeatable nonce use-cap (card t_a3521d8a) -------------------------
        #: when set to N, every nonce is accepted for exactly N authorized responses
        #: and then retired — again and again, for as long as the session runs. This
        #: is the shape the live 401 at request ~190 needs (docs/OBSERVED.md "Digest
        #: nonce use-cap"): `expire_after` cannot reproduce a walk that dies at N.
        self.retire_after: int | None = None
        #: which of RETIRE_SHAPES the rejection answers with (see the block above
        #: RETIRE_STALE_TRUE for why all three exist)
        self.retire_shape: str = RETIRE_STALE_TRUE
        #: authorized responses already served under the CURRENT nonce
        self._nonce_uses = 0
        #: keeps every issued nonce name unique, so a client can never "recognise" a
        #: retired nonce again and a test can assert which nonce paid which request
        self._nonce_serial = 0
        #: how many retirements have fired — the pin for "exactly one recovery per
        #: retirement" (card t_a3521d8a tests)
        self.retirements = 0
        #: scenario name -> (method, path+query) -> Response | list[Response]
        self.routes: dict[str, list] = {}
        #: raw responses served BEFORE the auth check (to simulate server-side 401s:
        #: stale-nonce re-challenges, lockout bodies, whatever the scenario needs)
        self.raw: dict[str, list] = {}
        #: --- the p1-05c event store (filtering mode) --------------------------------
        #: The offset this fake's clock CLAIMS, exactly like the `<localTime>` stamp
        #: of a real `System/time` answer. Default = site-a's year-round +02:00
        #: (OBSERVED.md). `add_events` arms filtering mode, which uses it for the
        #: window arithmetic — this is the knob the winter / correct-device / UTC-box
        #: tests turn.
        self.claimed_offset_min = SITE_A_CLAIM_MIN
        #: None = classic queue-replay mode (every pre-p1-05c test rides this).
        #: A list once `add_events` runs: the fake then FILTERS it per request.
        self._event_store: list[dict] | None = None
        self.served: list[Served] = []
        self.challenges = 0
        #: --- E1-03 request budget counters (docs/ENROLLMENT-MIGRATION.md §0.5) ------
        #: EVERY request the fake received (before auth, including raw-queue hits), and
        #: the same per path+method; plus the count of requests whose credentials the
        #: box ACCEPTED. The probe's "exactly one request per probed surface, never
        #: retry an error" rule (card E1-03) is a test against these numbers, not a
        #: comment — the same discipline the nonce ledger brought to digest budget.
        self.requests = 0
        self.requests_by_path: dict[str, int] = {}
        self.authorized_by_path: dict[str, int] = {}
        #: None until `install_enrollment` runs: the E1 enrollment read-axis data
        #: (users/cards/FDLib/FDSearch/FP templates/caps bodies) the handler serves
        #: with the device's own dialect strictness.
        self._enrollment: dict | None = None
        #: None = queue-replay for the E1-01 enrollment POSTs too. A dict once
        #: `seed_enrollment` runs — keyed by record key ("UserInfo"/"CardInfo") —
        #: and the two enrollment searches are then WINDOWED/PAGED from it with the
        #: device's MORE/NO-MATCH semantics (card E1-01), including the
        #: wrapped-dialect + searchID strictness. Arming this (and NOT
        #: `install_enrollment`) keeps the unknown-enrollment-POST trap live.
        self._enrollment_store: dict[str, list[dict]] | None = None
        #: E1-01b: None = the two biometric READs answer from the installed axis
        #: (E1-03 default); a dict once `seed_biometric` arms store mode:
        #: {"faces": {employeeNo: bytes}, "fingerprints": {(employeeNo, fpIndex): bytes}}.
        self._biometric_store: dict[str, dict] | None = None
        #: E1-04: None until `install_write_capture()` runs — the captured WRITE axis
        #: (see the write block above). Un-armed means an un-armed write verb is a HARD
        #: failure, which is the §9 capture-before-fake rule enforced by the fake.
        self._write_axis: dict | None = None
        #: False = `UserInfo/Search` SILENTLY IGNORES its `EmployeeNoList` filter and
        #: answers the whole roster (OBSERVED's `AcsEventCond.employeeNo` lesson; bench A
        #: honored it, §1). E1-04's §6 coverage-proof walker is tested against this.
        self.honor_employee_filter = True
        #: Persons the filtered read OMITS even though the store has them — the other
        #: coverage failure §6 names (a filter honored but incomplete, so a requested
        #: person looks "missing" when they are not). Kept separate from
        #: `honor_employee_filter` because the walker's two arms differ.
        self.filter_omits: set[str] = set()
        #: The recorded FDSearch paging quirk (bench A: one OK page answered 3 of 4
        #: rows). True = reproduce it on the first unfiltered store-mode page.
        self.fd_first_page_short = True
        self.transport = httpx.MockTransport(self._handle)

    # -- budget counter helpers (E1-03) -------------------------------------------------

    def requests_to(self, method: str, path: str) -> int:
        """Requests RECEIVED for `method path?query` (incl. unauthenticated probes)."""
        return self.requests_by_path.get(_key(method, path), 0)

    def authorized_requests_to(self, method: str, path: str) -> int:
        """Requests whose credentials the box ACCEPTED (the digest-excluded count)."""
        return self.authorized_by_path.get(_key(method, path), 0)

    @property
    def total_authorized(self) -> int:
        return sum(self.authorized_by_path.values())

    def challenge(self, *, nonce: str | None = None, stale: str | None = None) -> httpx.Response:
        """A 401 + WWW-Authenticate exactly like the fixture transcript."""
        return httpx.Response(
            401,
            headers={
                "WWW-Authenticate": (
                    f'Digest qop="auth", realm="{REALM}", '
                    f'nonce="{nonce or self.challenge_nonce}", '
                    f'stale="{self.stale_flag if stale is None else stale}", '
                    'domain="::"'
                ),
                "Server": "webs",
            },
            content=(
                b"<userCheck><statusValue>401</statusValue>"
                b"<statusString>Unauthorized</statusString>"
                b"<lockStatus>unlock</lockStatus><unlockTime>0</unlockTime>"
                b"<retryLoginTime>6</retryLoginTime></userCheck>"
            ),
        )

    def envelope_only_401(self) -> httpx.Response:
        """Shape (c): a 401 with an ISAPI envelope and NO `WWW-Authenticate`.

        Nothing to pay — a client that only knows how to answer a challenge has no
        move here except to drop its auth state and re-bootstrap. Recorded (invented,
        labelled) as `digest_envelope_only_401.txt`; docs/OBSERVED.md leaves this shape
        OPEN, which is why the fake can emit it and a test can pin what we do about it.
        """
        return httpx.Response(
            401,
            headers={"Server": "webs", "Content-Type": "application/xml"},
            content=_ENVELOPE_ONLY_401_BODY,
        )

    def _retire_nonce(self) -> httpx.Response:
        """Fire one nonce use-cap: drop the current nonce, mint a fresh one, answer
        in the configured shape. Called on an otherwise-authorized request."""
        self.retirements += 1
        self._nonce_uses = 0
        self._nonce_serial += 1
        fresh = f"{NONCE}-RET{self._nonce_serial}"
        self.accepted_nonces = {fresh}
        self.challenge_nonce = fresh
        if self.retire_shape == RETIRE_ENVELOPE_ONLY:
            # No challenge is offered, so `challenges` (challenges SENT) does not move.
            return self.envelope_only_401()
        self.challenges += 1
        return self.challenge(
            nonce=fresh,
            stale="true" if self.retire_shape == RETIRE_STALE_TRUE else "false",
        )

    # -- scenario helpers -----------------------------------------------------------

    def add(self, method: str, path: str, *responses: httpx.Response) -> None:
        """Register responses for `method path?query`; repeats pop the list, last sticks."""
        self.routes.setdefault(_key(method, path), []).extend(responses)

    def reset(self, method: str, path: str, *responses: httpx.Response) -> None:
        """`add` but REPLACE: throw away anything already registered for this route.

        Added for the CLI command suite (card p1-08), whose per-test devices come up
        pre-seeded with the default pages for every endpoint: a paging test that then
        `add`s its own page queue would have its pages served AFTER the default one, and
        assert against a walk that silently started from the fixture instead of from the
        queue it built. Replacing the route is what makes "these are the pages this test
        serves" true.
        """
        self.routes[_key(method, path)] = list(responses)

    def reset_json(self, method: str, path: str, payload: dict | list, **kw: object) -> None:
        """`json_ok` but REPLACE — see `reset`."""
        self.reset(method, path, httpx.Response(200, json=payload, **kw))  # type: ignore[arg-type]

    def add_raw(self, method: str, path: str, *items: httpx.Response | Exception) -> None:
        """Serve these before checking Authorization at all (server-initiated 401s,
        lockout bodies); an Exception item is raised instead (transport errors)."""
        self.raw.setdefault(_key(method, path), []).extend(items)

    def reset_raw(self, method: str, path: str, *items: httpx.Response | Exception) -> None:
        """`add_raw` but REPLACE, and repeat the LAST item so an error STAYS an error.

        A raw queue drains: one queued 503 means "503, then everything is fine again". For
        a test that wants "this endpoint is broken" — which is what a device-error or
        lockout scenario actually models — a single item would make the second request in
        the same command succeed and the asserted exit code never appear. Repeating the
        last item is what makes `reset_raw("GET", ..., 503)` mean "always 503".
        """
        key = _key(method, path)
        self.raw[key] = list(items)
        if items and not isinstance(items[-1], Exception):
            # Enough copies to cover any retry the transport is allowed (it retries once on
            # transport errors and once on a 5xx) without any test noticing the queue ran
            # out; the last item is what a draining queue leaves in place anyway.
            self.raw[key].extend([items[-1]] * 9)

    def unauthenticated_401(self) -> httpx.Response:
        return self.challenge()

    def json_ok(self, method: str, path: str, payload: dict | list, **kw: object) -> None:
        self.add(
            method,
            path,
            httpx.Response(200, json=payload, **kw),  # type: ignore[arg-type]
        )

    def xml_ok(self, method: str, path: str, body: str) -> None:
        self.add(
            method,
            path,
            httpx.Response(200, text=body, headers={"Content-Type": "application/xml"}),
        )

    # -- the p1-05c event store (filtering mode) ---------------------------------------

    def add_events(self, *events: dict) -> None:
        """Store device events and arm window-ARITHMETIC filtering on the event POSTs.

        Each event is the dict a real AcsEvent page would carry (`serialNo`,
        `time`, `major`, ...). `time` is the device's own stamp — ITS wall digits
        plus ITS claimed offset, e.g. `2026-05-21T14:08:17+02:00` for site-a. Once
        armed, the fake answers `AcsEvent`/`AcsEventTotalNum` POSTs by filtering
        this store the way the device filters (see the module docstring) instead of
        replaying a queued page — so a wrongly-labeled window genuinely returns
        `NO MATCH`/0 here, as it did live on 2026-10-17.
        """
        if self._event_store is None:
            self._event_store = []
        self._event_store.extend(dict(e) for e in events)

    def _event_store_response(self, request: httpx.Request) -> httpx.Response:
        """Filter the store with the DEVICE's arithmetic and answer like the device.

        Device-side interpretation of one bound (OBSERVED.md "Window offsets are
        ARITHMETIC"): the label makes the digits an instant; the instant is written
        back onto the device's OWN clock; the event's stored wall digits are compared
        to that shifted window, inclusively. So a `+03:00`-labeled 13:00 bound is,
        on a +02:00-claiming box, device wall 12:00 — one hour early. `major`/`minor`
        are NOT simulated server-side: OBSERVED.md's policy is that we never trust a
        server filter we have not probed and the pipeline re-filters client-side
        anyway, so the store answers the window and nothing else.
        """
        cond_key = _EVENT_COND_KEYS[request.url.path]
        payload = json.loads(request.content)
        cond = payload.get(cond_key, {}) if isinstance(payload, dict) else {}
        search_id = cond.get("searchID", "")
        # The naive-400 already passed in `_handle` (presence gates arithmetic, both
        # modes). A bound missing HERE is a broken test, not a device shape — the
        # engine refuses to build a boundless body — so raise, don't serve.
        start = _bound_to_device_wall(cond["startTime"], self.claimed_offset_min, "startTime")
        end = _bound_to_device_wall(cond["endTime"], self.claimed_offset_min, "endTime")
        assert self._event_store is not None  # caller checks; keeps the type honest
        # Matched rows keep their wall digits (the filter proved them parseable); the
        # device returns a window oldest-first, so sort by wall then serial.
        matched_walls = [
            (w, e)
            for e in self._event_store
            if (w := _store_wall(e)) is not None and start <= w <= end
        ]
        matched_walls.sort(key=lambda we: (we[0], _store_serial(we[1])))
        matched = [e for _, e in matched_walls]
        if request.url.path.startswith("/ISAPI/AccessControl/AcsEventTotalNum"):
            return httpx.Response(200, json={"AcsEventTotalNum": {"totalNum": len(matched)}})
        if not matched:
            # The RECORDED empty-window shape: status "NO MATCH" (with the space) and
            # NO InfoList key at all (OBSERVED.md) — not `[]`.
            envelope = {
                "searchID": search_id,
                "responseStatusStrg": "NO MATCH",
                "numOfMatches": 0,
                "totalMatches": 0,
            }
        else:
            envelope = {
                "searchID": search_id,
                "responseStatusStrg": "OK",
                "numOfMatches": len(matched),
                "totalMatches": len(matched),
                "InfoList": matched,
            }
        return httpx.Response(200, json={"AcsEvent": envelope})

    # -- E1 enrollment surfaces (card E1-03; see the module block above) -----------------

    def install_enrollment(
        self,
        *,
        users: list[dict] | None = None,
        cards: list[dict] | None = None,
        fd_lib: list[dict] | None = None,
        fd_records: list[dict] | None = None,
        fp_templates: dict[str, str] | None = None,
        caps_user_info: dict | None = None,
        caps_card_info: dict | None = None,
        caps_fd_lib: dict | None = None,
        caps_acs_cfg: dict | None = None,
        answer_search: VerdictLike = "ok",
        answer_fd_search: VerdictLike = "ok",
        answer_fp_read: VerdictLike = "ok",
        answer_user_caps: VerdictLike = "ok",
    ) -> None:
        """Seed the enrollment read axis with A's discovered truth (defaults below).

        Everything routes through `_handle_enrollment` (dialect-strict, see the module
        block): what this method installs is DATA, and the *shape* enforcement lives
        in the handler exactly where the device puts it — after auth, at handler time.

        The four `answer_*` knobs model "a different firmware answered differently"
        for the E1-03 no-assumption-leak test: "notSupport"/"rejected_shape"/"error"
        replace the real answer with the recorded envelope for that route, so a test
        can prove the probe records what THIS device said rather than inheriting
        bench A's truth.
        """
        self._enrollment = {
            "users": users if users is not None else _enrollment_user_records(),
            "cards": cards if cards is not None else [],
            "fd_lib": fd_lib
            if fd_lib is not None
            else [
                {"FDID": "1", "name": "blackFD", "faceLibType": "blackFD"},
                {"FDID": "2", "name": "infraredFD", "faceLibType": "infraredFD"},
            ],
            "fd_records": fd_records if fd_records is not None else _enrollment_fd_records(),
            "fp_templates": fp_templates if fp_templates is not None else {"1": FAKE_FP_TEMPLATE},
            "caps_user_info": caps_user_info
            if caps_user_info is not None
            else _caps_user_info_body(),
            "caps_card_info": caps_card_info
            if caps_card_info is not None
            else _caps_card_info_body(),
            "caps_fd_lib": caps_fd_lib if caps_fd_lib is not None else _caps_fd_lib_body(),
            "caps_acs_cfg": caps_acs_cfg
            if caps_acs_cfg is not None
            else {"AcsCfgCap": {"saveFacePic": "true,false"}},
            "search_overrides": {
                "user_info_search": answer_search,
                "fd_search": answer_fd_search,
                "finger_print_upload": answer_fp_read,
                "user_info_capabilities": answer_user_caps,
            },
        }

    def seed_enrollment(
        self,
        users: list[dict] | None = None,
        cards: list[dict] | None = None,
    ) -> None:
        """Install the E1-01 enrollment corpus (windowed store for both searches).

        The default corpus is bench A's recorded shape (docs/ENROLLMENT-MIGRATION.md
        §1: 4 users — one with `numOfFP=1` (the fingerprint A cannot migrate), 0 cards
        — plus a `password` field the export must strip). Names are masked the way the
        recorded fixtures are (`User E<n>`), so this file stays hygiene-clean.

        Passing `users=[]`/`cards=[]` models a genuinely EMPTY device: the fake must
        then answer `NO MATCH` with the record key ABSENT (OBSERVED.md + the
        CardInfoSearch capture), which is exactly the shape an export must read as
        "the device said zero", not silence.

        The store takes precedence over `install_enrollment`'s corpus for the two
        searches (seeding is the explicit act for paging truth); everything else —
        FDSearch, the FP read, the caps documents — keeps answering from the
        installed axis when one was installed.
        """
        store_users = A_CORPUS_USERS if users is None else list(users)
        store_cards = A_CORPUS_CARDS if cards is None else list(cards)
        self._enrollment_store = {"UserInfo": store_users, "CardInfo": store_cards}

    def seed_biometric(
        self,
        faces: dict[str, bytes] | None = None,
        fingerprints: dict[tuple[str, int], bytes] | None = None,
        *,
        empty: bool = False,
    ) -> None:
        """Arm store mode for the two biometric READs (E1-01b; filter-mode like events).

        Defaults replay bench A: one face template per corpus user (numOfFace=1 on
        all four, §1) and exactly one fingerprint — user "1" fpIndex 0 (the recorded
        numOfFP=1). `empty=True` models EMPTY libraries (face walk ends on the
        device's zero-row answer, FP walk on an empty `FingerPrintList`) — the
        honest-zero shapes §0.7 demands an export distinguish from failure.

        Bytes (not base64) keep the STORE the device's truth: handlers encode like
        the firmware's response, so a test mutating stored bytes sees the effect in
        the export's hashes. Store mode takes precedence over the installed axis for
        these two paths only; everything else keeps answering from `install_enrollment`.
        """
        if empty:
            self._biometric_store = {"faces": {}, "fingerprints": {}}
            return
        self._biometric_store = {
            "faces": dict(A_FD_ROWS if faces is None else faces),
            "fingerprints": dict(A_FP_ROWS if fingerprints is None else fingerprints),
        }

    def _biometric_fd_search(self, request: httpx.Request) -> httpx.Response:
        """Store-mode FDSearch — FLAT dialect or 400 (the §9 dialect split).

        Wrapped cond of ANY name is the wrong dialect here (the wrapped style is
        exactly what 400'd on this fw); required flat params answer
        `MessageParametersLack`; the FPID filter is HONORED (A: FPID=1 -> 1 of 4).
        Rows carry {FPID, faceURL, modelData}; faceURL's PHOTO bytes stay unrouted
        (every GET form 404s on the real fw — the fake mirrors the dead end). The
        recorded paging quirk fires on the first unfiltered store page.
        """
        try:
            body = json.loads(request.content.decode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError):
            return bad_json_content("FDSearch")
        if not isinstance(body, dict) or any(isinstance(v, dict) for v in body.values()):
            return bad_json_content("FDSearch")
        for param in ("faceLibType", "FDID"):
            if not body.get(param):
                return message_parameters_lack(param)
        position = body.get("searchResultPosition", 0) or 0
        max_results = body.get("maxResults", 0) or 0
        faces: dict[str, bytes] = (self._biometric_store or {}).get("faces", {})
        fpid = body.get("FPID")
        people = sorted(faces) if fpid is None else ([str(fpid)] if str(fpid) in faces else [])
        total = len(people)
        window = people[position : position + max_results] if max_results else []
        if (
            self.fd_first_page_short
            and fpid is None
            and position == 0
            and 1 < len(window) < max_results
        ):
            window = window[:-1]  # one row fewer than fits, status still OK — the lie is the point
        rows = [
            {
                "FPID": person,
                "faceURL": f"http://{FAKE_HOST}/LOCALS/pic/enrlFace/0/{person}.jpg@WEBx",
                "modelData": base64.b64encode(faces[person]).decode("ascii"),
            }
            for person in window
        ]
        return httpx.Response(
            200,
            json=_search_envelope(
                search_id=body.get("searchID"),
                envelope_key="",  # CAPTURED: root-level, no wrapper (§5.0 capture)
                record_key="MatchList",
                rows=rows,
                total_override=total,
            ),
        )

    def _biometric_fp_read(self, request: httpx.Request) -> httpx.Response:
        """Store-mode FingerPrintUpload — `FingerPrintCond` wrapper REQUIRED (§1).

        Plain-cond form 400s `MessageParametersLack FingerPrintCond` exactly as
        probed; every probed inner field is required and each missing one answers
        the same subStatusCode naming it. The answer is the recorded shape —
        `FingerPrintInfo.FingerPrintList` with ONE row (fingerPrintID = fpIndex+1,
        fingerType "normalFP", base64 fingerData) — and the honest not-found shape
        is an EMPTY list: no probed error word exists for "this person has no
        finger N", so the fake never invents one.
        """
        try:
            body = json.loads(request.content.decode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError):
            return message_parameters_lack("FingerPrintCond")
        cond = body.get("FingerPrintCond") if isinstance(body, dict) else None
        if not isinstance(cond, dict):
            return message_parameters_lack("FingerPrintCond")
        for param in ("searchID", "employeeNo", "fpIndex", "dataType"):
            if cond.get(param) in (None, ""):
                return message_parameters_lack(param)
        # CAPTURED TRUTH (bench A §5.0 capture, 2026-10-22): the read IGNORES
        # fpIndex — the store is keyed by PERSON (first stored index wins, which on
        # bench A is the only one anyway); positive answers carry status "OK", the
        # honest zero is status "NoFP" with FingerPrintList ABSENT (not empty!).
        store: dict[tuple[str, int], bytes] = (self._biometric_store or {}).get("fingerprints", {})
        employee_no = str(cond["employeeNo"])
        row_bytes = next((b for (no, _idx), b in store.items() if no == employee_no), None)
        info: dict[str, object] = {"searchID": cond.get("searchID", "")}
        if row_bytes is not None:
            info["status"] = "OK"
            info["FingerPrintList"] = [
                {
                    "cardReaderNo": 1,
                    "fingerPrintID": 1,  # captured: always 1, whatever fpIndex we send
                    "fingerType": "normalFP",
                    "fingerData": base64.b64encode(row_bytes).decode("ascii"),
                    "leaderFP": [],  # captured verbatim: an EMPTY LIST, not "true"
                }
            ]
        else:
            info["status"] = "NoFP"  # the device's own zero word
        return httpx.Response(200, json={"FingerPrintInfo": info})

    # -- the server --------------------------------------------------------------------

    #: path (no query) -> handler name; the enrollment routes the fake answers when
    #: `install_enrollment` has run. Absent endpoints answer the recorded notSupport
    #: envelope; the dialect-strict POSTs are enforced in `_handle_enrollment`.
    _ENROLLMENT_ROUTES = frozenset(
        {
            "/ISAPI/AccessControl/UserInfo/Search",
            "/ISAPI/AccessControl/CardInfo/Search",
            "/ISAPI/AccessControl/UserInfoDetail/Search",
            "/ISAPI/AccessControl/FingerPrint/Search",
            "/ISAPI/AccessControl/FingerPrintUpload",
            "/ISAPI/AccessControl/UserInfo/capabilities",
            "/ISAPI/AccessControl/UserInfo/Search/capabilities",
            "/ISAPI/AccessControl/UserInfo/SetUp/capabilities",
            "/ISAPI/AccessControl/CardInfo/capabilities",
            "/ISAPI/AccessControl/AcsCfg/capabilities",
            "/ISAPI/AccessControl/FingerPrintDownload/capabilities",
            "/ISAPI/AccessControl/PlanTemplate1",
            "/ISAPI/Intelligent/FDLib",
            "/ISAPI/Intelligent/FDLib/FDSearch",
            "/ISAPI/Intelligent/FDLib/capabilities",
        }
    )

    def _dispatch_enrollment(self, request: httpx.Request) -> httpx.Response | None:
        """The merged enrollment read axis — E1-01's store + E1-03's installed axis.

        Runs AFTER auth and the nonce-cap checks (where the firmware validates a
        body), and only when no explicit route claimed the request — an
        `add`/`reset` fixture route still wins everywhere, exactly like the event
        store. Three phases, each with its own armed-mode gate:

        1. E1-01 store (`seed_enrollment`): the two enrollment searches answer with
           wrapped-dialect + searchID strictness and the device's MORE/NO-MATCH
           window paging.
        2. E1-03 installed axis (`install_enrollment`): the full read surface
           (searches when no store was seeded, FDLib/FDSearch, the FP read, caps
           documents, the probed notSupport set) with its answer-knobs.
        3. E1-01 rule 3 (POSTs only): the probed notSupport matrix answers exactly
           the recorded envelope; any OTHER enrollment-family POST — or either
           search with no data source armed — RAISES `EnrollmentProtocolError`. An
           invented endpoint dies here loudly, never as an empty answer
           (capture-before-fake, design §9).

        Returns None when no phase answers; the caller continues to the classic
        route replay / catch-all 404.
        """
        path = request.url.path
        is_post = request.method == "POST"
        # A verb this fake has no capture for, on an enrollment path, is a HARD failure —
        # never the catch-all 404, which an optimistic client could mistake for a
        # harmless "endpoint absent" (E1-04; §0.7's silence rule pointed at writes).
        if (
            request.method not in ("GET", "POST")
            and not path.startswith("/ISAPI/System/")
            and self._write_axis is None
        ):
            raise EnrollmentProtocolError(
                f"{request.method} {path}: the fake serves no non-GET/POST verb without "
                "install_write_capture() arming the bench-A write axis (§9 capture-"
                "before-fake) — a 404 here would be indistinguishable from success to "
                "a client that trusts status codes"
            )
        if is_post and self._enrollment_store is not None and path in _ENROLLMENT_SEARCH_PATHS:
            if path == "/ISAPI/AccessControl/UserInfo/Search":
                return self._enroll_user_search(request)
            return self._enroll_card_search(request)
        # E1-01b store mode: the two biometric READs answer from the seeded store
        # when armed (precedence over the installed axis for THESE paths only).
        if is_post and self._biometric_store is not None and path in _BIOMETRIC_POST_PATHS:
            if path == FD_SEARCH_PATH:
                return self._biometric_fd_search(request)
            return self._biometric_fp_read(request)
        if self._enrollment is not None:
            answered = self._handle_enrollment(request)
            if answered is not None:
                return answered
        if is_post:
            if path in _ENROLLMENT_NOTSUPPORT_PATHS or path.startswith(
                _ENROLLMENT_NOTSUPPORT_PREFIXES
            ):
                return not_support()
            if path in _ENROLLMENT_SEARCH_PATHS or path.startswith(_ENROLLMENT_PREFIXES):
                raise EnrollmentProtocolError(
                    f"POST {path} has no bench-A device truth armed "
                    "(E1-01 rule: unknown or un-armed enrollment POSTs are hard "
                    "failures, not empty answers); a capture-backed fixture route "
                    "(reset_json/add) or seed_enrollment() is the only way this path "
                    "may be answered — see docs/ENROLLMENT-MIGRATION.md §9 "
                    "capture-before-fake"
                )
        return None

    def _handle_enrollment(self, request: httpx.Request) -> httpx.Response | None:
        """Serve the enrollment read axis with the DEVICE's dialect strictness.

        None = not an enrollment path (fall through to the classic route replay).
        Runs AFTER auth and after the nonce-cap check, exactly where the firmware
        validates a request body — an unauthorized client never sees these answers.
        """
        assert self._enrollment is not None  # caller-checked
        path = request.url.path
        if path not in self._ENROLLMENT_ROUTES:
            return None
        override = self._enrollment["search_overrides"].get(_ENROLLMENT_KNOBS.get(path, ""))
        if override not in (None, "ok"):
            return _enrollment_override(override)
        if path == "/ISAPI/AccessControl/UserInfo/Search":
            return self._enroll_user_search(request)
        if path == "/ISAPI/AccessControl/CardInfo/Search":
            return self._enroll_card_search(request)
        if path == "/ISAPI/AccessControl/FingerPrintUpload":
            return self._enroll_fp_read(request)
        if path == "/ISAPI/Intelligent/FDLib/FDSearch":
            return self._enroll_fd_search(request)
        if path == "/ISAPI/Intelligent/FDLib":
            return httpx.Response(200, json={"FDLibInfoList": self._enrollment["fd_lib"]})
        if path == "/ISAPI/AccessControl/UserInfo/capabilities":
            return httpx.Response(200, json=self._enrollment["caps_user_info"])
        if path == "/ISAPI/AccessControl/CardInfo/capabilities":
            return httpx.Response(200, json=self._enrollment["caps_card_info"])
        if path == "/ISAPI/AccessControl/AcsCfg/capabilities":
            return httpx.Response(200, json=self._enrollment["caps_acs_cfg"])
        if path == "/ISAPI/Intelligent/FDLib/capabilities":
            return httpx.Response(200, json=self._enrollment["caps_fd_lib"])
        # Absent on bench A (OBSERVED.md "E1 enrollment-read probes"): the detail
        # search, FingerPrint/Search, the three caps documents that 404'd, and
        # PlanTemplate. Recorded envelope, HTTP 400 + notSupport — like
        # error_total_notsupport.json, which is exactly how the device said it.
        return not_support()

    def _enroll_user_search(self, request: httpx.Request) -> httpx.Response:
        """Wrapped-cond strict (OBSERVED): flat body -> badJsonContent; no searchID
        -> MessageParametersLack; `EmployeeNoList` filter HONORED (the live A/B).

        Paging is the DEVICE's, shared with the E1-01 store (design §1: `maxResults=2`
        -> MORE): `searchResultPosition` windows the match set, `numOfMatches` counts
        THIS page, `totalMatches` the whole set, and a truncated page says MORE —
        never a complete-looking OK (a walker that ignored MORE would export 30 people
        from a 300-person device). An empty window answers NO MATCH (space spelling)
        with the record key ABSENT, never `[]`.
        """
        body = _json_body(request)
        cond = body.get("UserInfoSearchCond")
        if not isinstance(cond, dict):
            return _bad_json("UserInfoSearchCond")
        if not str(cond.get("searchID") or ""):
            return message_parameters_lack("searchID")
        rows = self._enrollment_rows("users", "UserInfo")
        wanted = _employee_no_filter(cond)
        if wanted is not None and self.honor_employee_filter:
            rows = [
                r
                for r in rows
                if str(r.get("employeeNo")) in wanted
                and str(r.get("employeeNo")) not in self.filter_omits
            ]
        return _paged_search_envelope(
            cond=cond, envelope_key="UserInfoSearch", record_key="UserInfo", matched=rows
        )

    def _enroll_card_search(self, request: httpx.Request) -> httpx.Response:
        body = _json_body(request)
        cond = body.get("CardInfoSearchCond")
        if not isinstance(cond, dict):
            return _bad_json("CardInfoSearchCond")
        if not str(cond.get("searchID") or ""):
            return message_parameters_lack("searchID")
        rows = self._enrollment_rows("cards", "CardInfo")
        # CardInfoSearch carries no cardNo/employeeNo filter this card exercised; A
        # answered the whole roster. Filter support stays a §6 coverage-proof concern
        # on the client side, not an assumed device fact here.
        return _paged_search_envelope(
            cond=cond, envelope_key="CardInfoSearch", record_key="CardInfo", matched=rows
        )

    def _enrollment_rows(self, install_key: str, store_key: str) -> list[dict]:
        """The user/card rows, from the armed store (E1-01 `seed_enrollment`) or from
        `install_enrollment`'s corpus (E1-03). The store wins when both are armed:
        seeding is the explicit act for paging truth."""
        if self._enrollment_store is not None:
            return list(self._enrollment_store.get(store_key, []))
        assert self._enrollment is not None  # caller-checked
        return list(self._enrollment[install_key])

    def _enroll_fp_read(self, request: httpx.Request) -> httpx.Response:
        """FingerPrintUpload READS (device→client). Wrapper required — OBSERVED: a
        plain `{searchID,employeeNo}` body answered `MessageParametersLack
        FingerPrintCond`; inner keys are checked in the order OBSERVED named them."""
        body = _json_body(request)
        cond = body.get("FingerPrintCond")
        if not isinstance(cond, dict):
            return message_parameters_lack("FingerPrintCond")
        for required in ("employeeNo", "fpIndex", "dataType"):
            if required not in cond:
                return message_parameters_lack(required)
        if cond["dataType"] != "template":
            # Only `dataType:"template"` is device-confirmed on this fw (OBSERVED);
            # anything else is refused rather than invented an answer for.
            return _json_error(
                {
                    "statusCode": 6,
                    "statusString": "Invalid Content",
                    "subStatusCode": "badParameters",
                    "errorCode": 1610612759,
                    "errorMsg": "dataType",
                }
            )
        # CAPTURED TRUTH (§5.0 capture 2026-10-22): fpIndex is IGNORED on the read
        # (0/1/2 answered the same row); positive carries status "OK"; the honest
        # zero is status "NoFP" with FingerPrintList ABSENT (the earlier
        # empty-list extrapolation is what made a per-fpIndex walk look legal).
        entry = self._enrollment["fp_templates"].get(  # type: ignore[index]
            str(cond["employeeNo"])
        )
        info: dict[str, object] = {"searchID": cond.get("searchID", "")}
        if not entry:
            info["status"] = "NoFP"
            return httpx.Response(200, json={"FingerPrintInfo": info})
        info["status"] = "OK"
        info["FingerPrintList"] = [
            {
                "cardReaderNo": 1,
                "fingerPrintID": 1,
                "fingerType": "normalFP",
                "fingerData": entry,
                "leaderFP": [],  # captured verbatim (an empty list, not a bool/string)
            }
        ]
        return httpx.Response(200, json={"FingerPrintInfo": info})

    def _enroll_fd_search(self, request: httpx.Request) -> httpx.Response:
        """FLAT dialect only — the working shape the operator confirmed (OBSERVED).

        The wrapped `FDSearchCond` body is what 400'd `MessageParametersLack
        faceLibType` in the earlier rounds (the wrapper hid the field the device
        reads at top level), so the fake answers the wrapped form with EXACTLY that
        rejection. `FDID` must name a real library. Paging quirk reproduced:
        `numOfMatches` counts THIS page, `totalMatches` counts the whole match set —
        the "3 of 4 in one page, status OK" behaviour OBSERVED records, which is why
        a walker must page to NO MATCH instead of trusting one page.
        """
        body = _json_body(request)
        if "FDSearchCond" in body:
            return message_parameters_lack("faceLibType")
        for required in ("faceLibType", "FDID"):
            if not str(body.get(required) or ""):
                return message_parameters_lack(required)
        fdid = str(body["FDID"])
        known = {str(lib.get("FDID")) for lib in self._enrollment["fd_lib"]}  # type: ignore[index]
        if fdid not in known:
            return httpx.Response(
                200,
                json=_search_envelope(
                    search_id=body.get("searchID"),
                    envelope_key="",
                    record_key="MatchList",
                    rows=[],
                ),
            )
        matched = list(self._enrollment["fd_records"])  # type: ignore[index]
        fpid = body.get("FPID")
        if fpid is not None:
            matched = [r for r in matched if str(r.get("FPID")) == str(fpid)]
        rows = _clamp_rows(matched, body)
        return httpx.Response(
            200,
            json=_search_envelope(
                search_id=body.get("searchID"),
                envelope_key="",
                record_key="MatchList",
                rows=rows,
                total_override=len(matched),
            ),
        )

    # -- the WRITE axis (card E1-04; bench-A capture PR #43) ------------------------------
    #
    # Every answer below is one of the committed capture files in
    # tests/fixtures/recorded/site-a-ds-k1t341amf-s/enrollment/, and every rejection is
    # either a captured envelope or a hard `EnrollmentProtocolError` saying "no capture
    # for this shape". That is the §9 rule made structural: the fake has NO opinion the
    # bench did not record. The two places where it must answer something the capture
    # file set does not contain are marked INVENTED below and are documented in the card.

    #: The captured UserInfo/SetUp key set (users_setup_add_request.json).
    _USER_SETUP_KEYS = frozenset(
        {
            "employeeNo",
            "name",
            "userType",
            "Valid",
            "doorRight",
            "RightPlan",
            "localUIRight",
            "gender",
            "mode",
        }
    )
    #: The person-read defaults the device adds (users_setup_readback_t90.json): the
    #: read shape the fake replays after a write, so a test sees the device's own
    #: defaults rather than an echo of what it sent.
    _USER_READ_DEFAULTS: ClassVar[dict[str, object]] = {
        "closeDelayEnabled": False,
        "belongGroup": "",
        "password": "",  # captured as an EMPTY string — a PIN never exists here
        "maxOpenDoorTime": 0,
        "openDoorTime": 0,
        "roomNumber": 0,
        "floorNumber": 0,
        "numOfCard": 0,
        "numOfFP": 0,
        "numOfFace": 0,
        "PersonInfoExtends": [{"value": ""}],
    }

    def install_write_capture(
        self,
        *,
        users: list[dict] | None = None,
        cards: list[dict] | None = None,
        capacity: int | None = None,
        honor_employee_filter: bool = True,
        wipe_hazard: bool = True,
    ) -> None:
        """Arm the captured WRITE axis (E1-04). Without this call, no write is servable.

        Seeding the person store is implied (a write has to land somewhere the search can
        read back). Knobs, each modelling a device behaviour the capture recorded or the
        design names:

        * ``capacity`` — reject a NEW person past this count with the same
          `businessError` family the capture's rejections use. INVENTED: no committed
          capture shows a capacity rejection (§1 records true capacity as unexposed), so
          this is a shape-stand-in for §5 step 4's fail-fast, not a recorded answer.
        * ``honor_employee_filter=False`` — the `UserInfo/Search` `EmployeeNoList` filter
          is SILENTLY IGNORED and the device answers the whole roster. Bench A honored
          it (§1), but OBSERVED.md's `AcsEventCond.employeeNo` lesson is that this family
          does exactly this on other filters, and §6's coverage-proof walker exists for
          it — this knob is what proves the walker is not cargo-culted.
        * ``wipe_hazard=False`` — disarm rule D-WIPE (see ``_write_user_delete``).
        """
        if self._enrollment_store is None:
            self.seed_enrollment(users=users if users is not None else [], cards=cards or [])
        self._write_axis = {
            "capacity": capacity,
            "wipe_hazard": wipe_hazard,
        }
        self.honor_employee_filter = honor_employee_filter

    def _write_user_setup(self, request: httpx.Request) -> httpx.Response:
        """`PUT UserInfo/SetUp` — replays users_setup_{add,post_method_not_allowed,
        wrapped_list_400,put_record_405}.json and mutates the person store.

        Rejections in capture order: verb (`POST` → the methodNotAllowed capture, which
        the fixtures prove twice over), then the SINGULAR-`UserInfo` requirement (a
        `userInfoList` wrapper → the captured `lack employeeNo` businessError), then the
        required employeeNo, then a key the capture does not name (INVENTED answer:
        `badJsonContent` naming the key, the same envelope class the FP capture used for
        a wrong-typed field), then capacity (INVENTED, see ``install_write_capture``).
        """
        assert self._write_axis is not None and self._enrollment_store is not None
        if request.method != "PUT":
            return _json_error(_capture("users_setup_post_method_not_allowed.json"))
        body = _json_body(request)
        if not body:
            return _bad_json("UserInfo")
        if "userInfoList" in body:  # the wrapped form the device 400s (captured)
            return _json_error(_capture("users_setup_wrapped_list_400.json"))
        record = body.get("UserInfo")
        if not isinstance(record, dict):
            raise EnrollmentProtocolError(
                "PUT UserInfo/SetUp without a singular 'UserInfo' object has NO bench-A "
                "capture (users_setup_add_request.json is the only recorded shape); "
                "refusing to invent an answer for it (§9 capture-before-fake)"
            )
        if record.get("mode") != "add":
            raise EnrollmentProtocolError(
                f"UserInfo/SetUp mode {record.get('mode')!r} has no bench-A capture — "
                'only "add" was proven (OBSERVED.md §5.0). v1 never deletes (§5 step 8); '
                "no modify mode was recorded, so the fake refuses to guess one"
            )
        employee_no = record.get("employeeNo")
        if not isinstance(employee_no, str) or not employee_no:
            return _json_error(_capture("users_setup_wrapped_list_400.json"))
        unknown = sorted(set(record) - self._USER_SETUP_KEYS)
        if unknown:
            # INVENTED answer (captured envelope class): R2's reason for the allow-list is
            # that this family 400s or half-merges an unrecorded key. A fake that accepted
            # an echoed photoURL/counter would hide exactly that bug.
            return _bad_json(unknown[0])
        people: list[dict] = self._enrollment_store["UserInfo"]
        existing = next(
            (i for i, r in enumerate(people) if str(r.get("employeeNo")) == employee_no), None
        )
        if (
            existing is None
            and self._write_axis["capacity"] is not None
            and len(people) >= int(self._write_axis["capacity"])
        ):
            # INVENTED (no capture of a capacity rejection — §1: true capacity is
            # unexposed). Envelope class + vocabulary taken from the captures so the
            # client's rejection handling is what the test exercises, not the wording.
            return _json_error(
                {
                    "statusCode": 6,
                    "statusString": "Invalid Content",
                    "subStatusCode": "businessError",
                    "errorCode": 1610612761,
                    "errorMsg": "employeeNo",
                }
            )
        stored = {k: v for k, v in record.items() if k != "mode"}
        stored.update(
            {k: copy.deepcopy(v) for k, v in self._USER_READ_DEFAULTS.items() if k not in stored}
        )
        if existing is None:
            people.append(stored)
        else:
            # Capture is silent on SetUp-over-existing (R2); the fake keeps the person's
            # identity stable and replaces the fields the write named, which is the least
            # inventive reading and is what the tests' "restore" steps rely on.
            people[existing] = stored
        return _json_ok(_capture("users_setup_add_response.json"))

    def _write_user_delete(self, request: httpx.Request) -> httpx.Response:
        """Rule D-WIPE reproduced EXACTLY as captured (userinfo_delete_wipe_*).

        The list sitting in a SIBLING `UserInfoDelCond` instead of inside `UserInfoDetail`
        answers statusCode 1 and deletes EVERY person (bench A lost its whole roster this
        way). A delete fake that just obeyed would teach a client nothing about the one
        hazard that matters, so this handler WIPES — count and faces — and says OK.
        """
        assert self._write_axis is not None and self._enrollment_store is not None
        body = _json_body(request)
        detail = body.get("UserInfoDetail")
        if not isinstance(detail, dict) or detail.get("mode") != "delete":
            raise EnrollmentProtocolError(
                "a UserInfo delete whose list sits inside UserInfoDetail (the shape the "
                "orchestrator recorded as safe) has NO committed response fixture, so "
                "the fake refuses to invent an answer for it; the captured D-WIPE shape "
                "is the one this route serves (§9 capture-before-fake, §5b)"
            )
        if not self._write_axis["wipe_hazard"]:
            return _json_ok(_capture("userinfo_delete_wipe_response.json"))
        self._enrollment_store["UserInfo"] = []
        self._enrollment_store["CardInfo"] = []
        if self._biometric_store is not None:
            # The capture cascade-dropped faces with the roster (OBSERVED.md: the wipe
            # "cascade-dropped all faces"), so the fake does too.
            self._biometric_store["faces"] = {}
        return _json_ok(_capture("userinfo_delete_wipe_response.json"))

    def _dispatch_write(self, request: httpx.Request) -> httpx.Response | None:
        """PUT routing for the captured write axis; hard-fails when it is not armed.

        An un-armed write verb is a HARD failure, never a 404: a 404 is what an absent
        endpoint says, and a client that mistook one for a successful no-op would then
        report a write that never happened (§0.7's silence rule, pointed at writes).
        """
        path = request.url.path
        if path == USER_SETUP_PATH:
            if self._write_axis is None:
                raise EnrollmentProtocolError(
                    f"{request.method} {path} has no bench-A write truth armed: call "
                    "FakeDevice.install_write_capture() (fixtures from PR #43) — a write "
                    "route that answers without its capture is the false-green machine "
                    "design §9 names"
                )
            return self._write_user_setup(request)
        if path == "/ISAPI/AccessControl/UserInfoDetail/Delete":
            if self._write_axis is None:
                raise EnrollmentProtocolError(
                    f"PUT {path} (rule D-WIPE) needs install_write_capture() armed; E1-05 "
                    "owns the delete PATH, and no delete may be sent before its count-"
                    "delta guard exists (§5b)"
                )
            return self._write_user_delete(request)
        for write_path in (
            "/ISAPI/AccessControl/CardInfo/SetUp",
            "/ISAPI/Intelligent/FDLib/FDSetUp",
            "/ISAPI/AccessControl/FingerPrintDownload",
        ):
            if path == write_path:
                raise EnrollmentProtocolError(
                    f"{request.method} {write_path} belongs to a LATER card (E1-05 cards, "
                    "E1-06 faces, E1-06b fingerprints); its capture is committed but its "
                    "fake route is not written yet, and E1-04 must not pre-build it (§9)"
                )
        return None

    def _handle(self, request: httpx.Request) -> httpx.Response:
        path = request.url.raw_path.decode()
        key = _key(request.method, path)
        auth = request.headers.get("authorization", "")
        digest = parse_digest_header(auth)
        self.served.append(
            Served(
                method=request.method,
                path=path,
                headers=dict(request.headers),
                body=request.content,
                had_auth=bool(auth),
                digest=digest,
            )
        )
        # E1-03 budget counters: EVERY received request counts here (the auth
        # handshake's unauthenticated first hop included), per path and total.
        self.requests += 1
        self.requests_by_path[key] = self.requests_by_path.get(key, 0) + 1

        # Server-initiated scenarios first (stale re-challenge, lockout body, 503,
        # transport errors): these fire regardless of what the client sent, like the
        # real firmware does. The raw queue DRAINS COMPLETELY (every queued item is
        # consumed exactly once), then normal auth+route flow resumes.
        raw_queue = self.raw.get(key)
        if raw_queue:
            item = raw_queue.pop(0)
            if isinstance(item, Exception):
                raise item
            return _clone(item)

        # No (or wrong, or stale-nonce) Authorization -> challenge. The real webs 401s
        # every unauthenticated request; a fake that served payloads without auth
        # would hide an entire class of digest bugs. HA2 is recomputed over the REAL
        # request-target (see expected_response), so a query-stripping client fails here.
        authorized = False
        if digest.get("nonce") in self.accepted_nonces and digest.get("realm") == REALM:
            want = expected_response(
                self.username,
                self.password,
                digest,
                digest["nonce"],
                method=request.method,
                uri=path,
            )
            authorized = bool(digest.get("response")) and digest.get("response") == want
        # The use-cap counter counts requests the box ACCEPTED the credentials on. A
        # wrong password must not consume a nonce: otherwise a lockout-safety test could
        # make a retirement fire on bad credentials and blame the recovery budget.
        if authorized:
            self._authorized_served += 1
            self.authorized_by_path[key] = self.authorized_by_path.get(key, 0) + 1
        if not authorized:
            self.challenges += 1
            return self.unauthenticated_401()

        # Nonce rotation (expire_after): the session has been accepted N times, so the
        # box retires the nonce on the NEXT authorized request — 401 with stale="true"
        # and a fresh nonce, exactly like a `webs` session that outlived its nonce.
        # The client's stale recovery pays it once (p1-03) and every recorded request
        # afterwards carries the new nonce; the rotation fires exactly once.
        if (
            self.expire_after is not None
            and not self._rotated
            and self._authorized_served > self.expire_after
        ):
            self._rotated = True
            fresh = f"{NONCE}-ROTATED"
            self.accepted_nonces = {fresh}
            self.challenge_nonce = fresh
            self.stale_flag = "true"
            self.challenges += 1
            return self.unauthenticated_401()

        # Repeatable nonce use-cap (retire_after) — the t_a3521d8a scenario. Same
        # trigger, but it fires EVERY N authorized responses and in a chosen shape,
        # because the live symptom is a deterministic 401 at the ~190th request of a
        # long walk and nothing else.
        if self.retire_after is not None:
            self._nonce_uses += 1
            if self._nonce_uses > self.retire_after:
                return self._retire_nonce()

        queue = self.routes.get(key)
        cond_key = _EVENT_COND_KEYS.get(request.url.path) if request.method == "POST" else None
        # With a store installed (filtering mode) the two event POSTs are SERVED —
        # the store is their route — so they must not fall to the 404 below.
        store_answers = self._event_store is not None and cond_key is not None
        # E1 merged enrollment axis (card E1-01 store + card E1-03 installed axis):
        # answers BEFORE the catch-all 404, and only when no explicit route was
        # registered for this path (an explicit `add`/`reset` still wins — a test
        # that wants to override one enrollment answer can, exactly like the event
        # store).
        if queue is None and not store_answers:
            # E1-04 write axis: the captured write verbs only (PUT). Raises HARD when a
            # write verb has no capture armed — never a 404 an optimistic client could
            # read as "fine". An explicit `add`/`reset` route still wins, like the event
            # store and the enrollment axis.
            written = self._dispatch_write(request)
            if written is not None:
                return written
        if queue is None and not store_answers:
            enrolled = self._dispatch_enrollment(request)
            if enrolled is not None:
                return enrolled
        if queue is None and not store_answers:
            return httpx.Response(
                404,
                content=b'{"statusCode":4,"statusString":"Invalid Operation",'
                b'"subStatusCode":"notSupport","errorCode":1073741825,"errorMsg":"unknow"}',
                headers={"Content-Type": 'application/json;charset="UTF-8"'},
            )
        # Body-strictness at HANDLER time (after auth, like the firmware): an event
        # window bound without a UTC offset, or carrying fractional seconds, is
        # rejected exactly as the device rejected it — recorded 2026-10-17
        # (error_naive_start_time.json, OBSERVED.md "offset REQUIRED") and 2026-10-21
        # (canary 400, OBSERVED.md "sub-second REJECTED"; see _HAS_FRACTION). A walk
        # that still sends either shape fails loudly here instead of being served
        # pages. This check runs in BOTH modes: presence gates the request BEFORE any
        # arithmetic does (p1-05c keeps the p1-05b arm alive in filtering mode too).
        if cond_key is not None:
            rejected = naive_event_bound(request.content, cond_key)
            if rejected is not None:
                return bad_json_content(rejected)
            if self._event_store is not None:
                # Filtering mode (p1-05c): answer from the store the way the device
                # answers — window arithmetic, not a replayed queue.
                return self._event_store_response(request)
        return _clone(queue.pop(0) if len(queue) > 1 else queue[0])


def _clone(response: httpx.Response) -> httpx.Response:
    """Rebuild, so a route reused across hits/tests hands back a fresh stream."""
    return httpx.Response(
        response.status_code, headers=dict(response.headers), content=response.content
    )


def _key(method: str, path: str) -> str:
    return f"{method.upper()} {path}"
