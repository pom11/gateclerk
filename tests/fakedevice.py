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
"""

from __future__ import annotations

import hashlib
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
        if not authorized:
            self.challenges += 1
            return self.unauthenticated_401()

        queue = self.routes.get(key)
        if queue is None:
            return httpx.Response(
                404,
                content=b'{"statusCode":4,"statusString":"Invalid Operation",'
                b'"subStatusCode":"notSupport","errorCode":1073741825,"errorMsg":"unknow"}',
                headers={"Content-Type": 'application/json;charset="UTF-8"'},
            )
        return _clone(queue.pop(0) if len(queue) > 1 else queue[0])


def _clone(response: httpx.Response) -> httpx.Response:
    """Rebuild, so a route reused across hits/tests hands back a fresh stream."""
    return httpx.Response(
        response.status_code, headers=dict(response.headers), content=response.content
    )


def _key(method: str, path: str) -> str:
    return f"{method.upper()} {path}"
