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
recorded shape: `error_naive_start_time.json`). So `_handle` rejects a naive bound
on those two paths with exactly that envelope, *after* auth, like the device
validates at handler time. A walk that still sends naive now fails loudly instead
of being served fixture pages.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field

import httpx

# The masked fixture's challenge values verbatim (already masked — see
# tests/fixtures/README). Nothing device-real lives in this file.
REALM = "DS-39DED0D1"
NONCE = "MASKED-NONCE"
FAKE_HOST = "192.0.2.10"  # TEST-NET (tests/test_repo_hygiene.py allowlist)
BASE_URL = f"http://{FAKE_HOST}"

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


def bad_json_content(field: str) -> httpx.Response:
    """The RECORDED rejection of a naive event bound (error_naive_start_time.json).

    Envelope verbatim from the owner's 2026-10-17 live probe (OBSERVED.md "Event-window
    startTime form: offset REQUIRED"): HTTP 400, statusCode 6, badJsonContent, errorMsg
    naming the offending bound. Only the startTime case is device-observed; naming
    endTime is the symmetric extrapolation that keeps the fake at least as strict as
    the device on the pair.
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

    A bound that is ABSENT is not this check's business (the engine cannot build one —
    `build_event_cond` raises first — and test_paging's `_UnboundedQueryRejector`
    simulates that hazard separately). A bound that is PRESENT must carry an offset.
    Bodies that do not parse as JSON (transport-level probes) are left to the route.
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
    return None


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
        self.served: list[Served] = []
        self.challenges = 0
        self.transport = httpx.MockTransport(self._handle)

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

    # -- the server --------------------------------------------------------------------

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
        if queue is None:
            return httpx.Response(
                404,
                content=b'{"statusCode":4,"statusString":"Invalid Operation",'
                b'"subStatusCode":"notSupport","errorCode":1073741825,"errorMsg":"unknow"}',
                headers={"Content-Type": 'application/json;charset="UTF-8"'},
            )
        # Body-strictness at HANDLER time (after auth, like the firmware): an event
        # window bound without a UTC offset is rejected exactly as the device rejected
        # it on 2026-10-17 — recorded in error_naive_start_time.json, policy in
        # OBSERVED.md "Event-window startTime form: offset REQUIRED". A walk that
        # still sends naive fails loudly here instead of being served pages.
        if request.method == "POST":
            cond_key = _EVENT_COND_KEYS.get(request.url.path)
            if cond_key is not None:
                rejected = naive_event_bound(request.content, cond_key)
                if rejected is not None:
                    return bad_json_content(rejected)
        return _clone(queue.pop(0) if len(queue) > 1 else queue[0])


def _clone(response: httpx.Response) -> httpx.Response:
    """Rebuild, so a route reused across hits/tests hands back a fresh stream."""
    return httpx.Response(
        response.status_code, headers=dict(response.headers), content=response.content
    )


def _key(method: str, path: str) -> str:
    return f"{method.upper()} {path}"
