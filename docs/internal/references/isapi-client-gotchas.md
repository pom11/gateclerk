# Hikvision ISAPI: Practical Gotchas for a Robust Python Client

**Scope.** Read-only GETs + two stateless POST searches (`UserInfo/Search`, `AcsEvent`) against a
DS-K1T341AMF-S (fw V3.2.30) whose live challenge is:

```
WWW-Authenticate: Digest qop="auth", realm="DS-39DED0D1", nonce="...", stale="false", opaque="", domain="::"
Server: webs
```

Open ports observed: 80, 443, 8000, 554. Payroll accuracy of punch timestamps is the hard requirement.

**Label key.**
- **VERIFIED** — reproduced here against a local harness, read from a library's actual source, or quoted
  from a vendor document / captured device transcript included below.
- **INFERRED** — reasoned from verified evidence or a single third-party report. Not reproduced here.
- **UNVERIFIED** — a claim found in the wild that this pass could **not** substantiate. Flagged as such.

A caveat that applies everywhere below: **no device was contacted for this brief.** Everything device-shaped
comes from vendor documents or third-party transcripts, not from the target terminal. Where the DS-K1T341AMF-S
specifically is concerned, treat the claims as *likely* and confirm with the two cheap probes in §6.

---

## 1. Digest authentication on `webs` / `App-webs`

### 1.1 The handshake, and what Hikvision actually sends

**VERIFIED (vendor doc).** The official *Intelligent Security API (General Application) Developer Guide*
(Hikvision, 2019, 795 pp — `isapi.pdf`, extracted to `isapi.txt`) shows the challenge on a real device
at p.131:

```
HTTP/1.1 401 Unauthorized
Server:
Content-Length: 178
Content-Type: text/html
Connection: keep-alive
Keep-Alive: timeout=10, max=99
WWW-Authenticate: Digest qop="auth", realm="IP Camera(C2183)",
 nonce="4e5468694e7a42694e7a4d364f4449354d7a6b354d54513d", stale="FALSE"
```

Two things to note from that verbatim sample, both matching your device: `qop="auth"` is present, and
`stale` is spelled **`"FALSE"` in uppercase** in Hikvision's own transcript (your device sends lowercase
`"false"`). The guide's other samples show `stale="FALSE"` too (p.116, p.119).

**VERIFIED (library source).** `httpx` never reads `stale` at all — see §1.5. `requests` also never reads it.
So the casing is *inert for both libraries*, but it will bite you if you write your own parser with a
`== "true"` comparison. **INFERRED:** always lowercase before comparing.

**VERIFIED (vendor doc).** Nonces are not opaque random hex — they are hex-of-base64 of a
`counter:random` pair. Decoding the two nonces above:

```
4e5468694e7a42694e7a4d364f4449354d7a6b354d54513d
  -> base64 -> '58b70b73:82939914'
4e6a4d774d6a63304f544936593255335a474d334f54673d
  -> base64 -> '63027492:ce7dc798'
```

**INFERRED:** the leading token is a per-boot counter, not a timestamp. Do not build nonce-expiry logic
around decoding it; react to `stale` and to 401s instead.

### 1.2 qop handling

**VERIFIED (reproduced).** The device's `qop="auth"` means the RFC 2617/7616 form is used:
`response = MD5(HA1:nonce:nc:cnonce:qop:HA2)` with `HA1 = MD5(user:realm:pass)` and
`HA2 = MD5(METHOD:uri)`. Confirmed by re-deriving `httpx`'s own response value byte-for-byte in the harness.

**VERIFIED (library source).** `httpx._auth.DigestAuth._resolve_qop` raises `ProtocolError("Digest qop not supported")`
if the server advertises only `auth-int`, and `_build_auth_header` has a literal `# TODO: implement auth-int`.
Hikvision advertises `auth` only, so this is latent, not live — but it is why a `qop`-less firmware variant
silently changes the algorithm. If `qop` is absent, `httpx` falls back to RFC 2069 (`MD5(HA1:nonce:HA2)`,
no `nc`/`cnonce`), as does `requests` (`if not qop: respdig = KD(HA1, f"{nonce}:{HA2}")`).

**INFERRED / UNVERIFIED as a general rule.** The widely-repeated claim that "a clock drift > 5 minutes
rejects Digest headers" appears in `uchkunr/hikvision-best-practices`. This is **not** true of standard
HTTP Digest (RFC 7616 has no client-clock term — there is no timestamp in the `Authorization` header).
It *is* true of ONVIF WS-Security and of NTTP/NTP-synced HikCentral flows. **Do not rely on it**; treat it
as folklore. What *is* true and matters for payroll is §5: the *device clock* being wrong corrupts punch
timestamps regardless of auth.

### 1.3 MD5 vs MD5-sess

**VERIFIED (device + vendor doc).** Hikvision's `webs`/`App-webs` advertises no `algorithm=` in the 401
challenge in your transcript, and the guide's examples never use `MD5-sess`. `httpx` defaults
`algorithm = header_dict.get("algorithm", "MD5")`; `requests` defaults to `"MD5"`. So plain MD5 is what runs.

**VERIFIED (library source).** Both libraries do support `MD5-SESS` if the server asks for it
(`httpx`: `if challenge.algorithm.lower().endswith("-sess"): HA1 = digest(HA1:nonce:cnonce)`;
`requests`: `if _algorithm == "MD5-SESS": HA1 = hash_utf8(f"{HA1}:{nonce}:{cnonce}")`). You will not hit it.
Note `httpx` also offers SHA-256 etc., which Hikvision never advertises.

**Practical consequence (INFERRED):** MD5 here is mandated by the protocol, not a weakness you chose.
Do not "harden" by forcing a different algorithm — the device will 400/401 you.

### 1.4 Does `uri=` have to include `?format=json`? — **YES.**

This is the single highest-yield gotcha in the whole brief, and it is where hand-rolled clients die.

**VERIFIED (library source, `requests`).** `HTTPDigestAuth.build_digest_header` builds the URI as:

```python
p_parsed = urlparse(url)
path = p_parsed.path or "/"
if p_parsed.query:
    path += f"?{p_parsed.query}"
A2 = f"{method}:{path}"
```

**VERIFIED (library source, `httpx`).** `httpx` uses `path = request.url.raw_path` and sends
`"uri": path` — `raw_path` is the path **plus** query string, percent-encoded exactly as on the wire.

**VERIFIED (reproduced).** Against a local `qop="auth"` server whose challenge realm is `DS-39DED0D1`
(mirroring your device), for `POST /ISAPI/AccessControl/AcsEvent?format=json`:

```
A) httpx shared client  GET 200  POST 200
     GET  /ISAPI/System/time                       -> NO-AUTH (challenge)
     GET  /ISAPI/System/time                       | auth-uri = /ISAPI/System/time
     POST /ISAPI/AccessControl/AcsEvent?format=json | auth-uri = /ISAPI/AccessControl/AcsEvent?format=json
                                                    nc=00000002
C) requests session     GET 200  POST 200     (identical uris)
```

`curl --digest` does the same: `auth-uri= /ISAPI/AccessControl/AcsEvent?format=json`.

**VERIFIED (vendor doc).** Across all 25 `uri=` values in the official guide, every HTTP one is the raw
request-target including its query where one exists, and the RTSP examples carry the full query too
(`uri="rtsp://…/tracks/101?starttime=…&endtime=…"`). The rule is simply *the request-target*, verbatim.

**The trap (INFERRED, and the reason this belongs in a client spec):** if you hand-roll the header and
compute `HA2` over `path` only while the device computes it over `path?query`, you get an *infinite 401
loop* with a valid password — indistinguishable from a wrong password. The tell is that the first
unauthenticated GET succeeds in producing a challenge and the retry is rejected. A real-world instance of
exactly this bug is fixed in `idstein/hikvision_access` commit `fd47125`, whose diff contains the line
`uri = parts.path or "/"` — the query-stripping bug itself.

**Also:** `httpx` uses `raw_path`, so **percent-encoding must match what goes on the wire**. If you build
the URL twice (once normalized, once not), `uri=` and the request-line disagree and you loop. Use one
`httpx.URL` object for both.

### 1.5 stale=true nonce recovery

**VERIFIED (reproduced).** With a server that re-challenges with `stale="true"` after the client already
holds a nonce, both clients recover in exactly **one** extra round-trip, taking the new nonce and resetting
`nc` to 1:

```
G) stale=true recovery: 200 | reqs: 3 | nc after stale: ['00000002']
```

(3 requests = primed request + 401 with `stale=true` + successful retry.)

**VERIFIED (library source) — and this is a real limitation.** Neither library honours the
*meaning* of `stale`:

- `httpx.auth_flow` triggers on `response.status_code == 401 and "www-authenticate" in response.headers`
  and **never parses `stale`**. It unconditionally sets `self._nonce_count = 1` and re-sends.
- `requests.handle_401` triggers on `"digest" in s_auth.lower() and self._thread_local.num_401_calls < 2`
  and also never reads `stale`. Note the `< 2` guard: **`requests` gives up after one retry per request.**

**Consequence (VERIFIED behaviour, INFERRED risk).** A single retry is the right budget for a genuine
stale nonce, and both libraries implement it. But it also means a *wrong password* costs you exactly
2 requests per call and then returns 401 — so a naive `for attempt in range(10): retry()` loop around a
call will issue 20 device requests and march your device straight into lockout (§2.4). Detect 401 with a
*known-good* credential separately from 401 with a stale nonce, and never retry a 401 blindly.

### 1.6 Is Basic auth accepted on DS-K1T* terminals? — Assume **no.**

**VERIFIED (vendor doc, strongest available).** Hikvision's own integration guides state it flatly:

> "The request sent to device should be authenticated by the **Digest Access method of the RFC 2617
> protocol**, so all the devices should support the Digest Access method."
> — *Fast guide for ANPR of TCV camera via ISAPI*, Hikvision Technology Partner Program

**VERIFIED (reproduced).** A digest-only server that advertises only `Digest` rejects a Basic attempt with
401 — as expected, and as your device will do: `E) httpx Basic auth -> 401 | server saw: 'Basic YWRtaW46cG'`.

**VERIFIED (datasheet).** The sibling DS-K1T502DBFWX datasheet lists `ISAPI (80\443 Interface)` in its
protocol list — no separate auth-port notion.

**INFERRED, contested.** `uchkunr/hikvision-best-practices` claims "Digest (default) **or Basic**" and that
Basic "can be enabled under System → Security → Authentication". A third-party DS-K1T setup doc says the
opposite — "uses HTTP Digest Authentication (via httpx.DigestAuth) for all ISAPI requests … more secure
than Basic". **Do not build a Basic fallback for a payroll integration.** Two reasons beyond the
ambiguity: (a) Basic puts the password on the wire, and (b) on modern Hikvision firmware the admin account
is created with a mandatory strong password and web auth is digest-by-default, so a Basic path is either
dead or silently weaker. If you want certainty, run the probe in §6.

### 1.7 Known failure modes of `httpx.DigestAuth` and `requests.HTTPDigestAuth`

**(a) `httpx` PR #2463 — the statefulness regression. VERIFIED (issue + PR + reproduction).**
Before httpx 0.23.1, `DigestAuth` was effectively stateless: every request paid a 401 then retried.
PR [encode/httpx#2463](https://github.com/encode/httpx/pull/2463) ("reuse the digest auth state to avoid
unnecessary requests") made `_last_challenge` sticky, so subsequent requests ride the cached nonce. That
broke Hikvision integrations in the wild — home-assistant/core#85888, "Hikvision intercom stopped working":

> "httpx with its new version introduced a change which altered how digest auth works and eventually led
> to my integration being useless."

and the httpx maintainers' answer in discussion #2549:

> "Are you able to get away with *not* reusing `httpx.DigestAuth()`, i.e. passing a new instance on each request?"

and from the same thread: "It should create `httpx.DigestAuth` for each call, instead of keeping its single instance."

**Reproduced, and the trade-off is now quantified** (local harness, one `httpx.Client`, `qop="auth"`):

```
B) httpx reused client, 5 GETs: [200 x5] | HTTP reqs: 6 | challenges: 1
   nc sequence: 00000001..00000005 | distinct cnonce: 5
D) fresh DigestAuth per call, 5 GETs: [200 x5] | HTTP reqs: 10   <-- 2x request cost
```

Reuse is *more efficient* (6 requests vs 10) and is the correct design **provided the device tolerates a
long-lived nonce**. Hikvision's `webs` does not always: nonces expire, and a client that keeps presenting a
dead nonce with an ever-climbing `nc` produces the classic "worked for an hour, then 401 forever until
restart" report. **Recommendation in §7.**

**(b) Thread-safety asymmetry. VERIFIED (library source).** `requests.HTTPDigestAuth` stores its nonce
state in `threading.local()` (`self._thread_local.last_nonce / nonce_count / chal`), so one shared
`HTTPDigestAuth` object across threads gives *each thread its own nonce* — safe, but it multiplies nonces
and 401 handshakes by the thread count. `httpx.DigestAuth` has plain instance state
(`self._last_challenge`, `self._nonce_count`) with **no lock**, so a shared instance across threads
concurrently increments `nc` and can interleave.

**Reproduced (httpx, 8 threads × 3 requests on one shared client + shared `DigestAuth`):**

```
codes: 200 x23, ConnectError x1 | distinct (nonce,nc) collisions: 0 | distinct nonces used: 7
```

No replay collision materialised — because each thread's fresh challenge overwrote `_last_challenge` and
the harness server accepted any valid `(nonce,nc)`. **This is luck, not safety (INFERRED):** with a strict
server that tracks `nc` per nonce monotonically, the unlocked counter is a live risk of "same nonce, same
`nc` twice" → `invalidOperation`/401. Treat `httpx.DigestAuth` as **not thread-safe**.

**(c) Keep-alive / `Connection: close`. VERIFIED (reproduced + vendor doc).** The Hikvision `webs` server
frequently answers `Connection: close` (the guide's own device responses show `Connection: close` 10 times
vs `Keep-Alive` 9). Emulating that — `Connection: close` on every response — the harness shows **both
libraries survive it**:

```
Device sends 'Connection: close' every response:
  codes: [200 x5] | HTTP reqs: 6 | 401 challenges: 1 | nonces issued: 1
  nc sequence: 00000001..00000005
```

So `Connection: close` alone does *not* break either client (the auth state lives on the auth object, not
the connection). The real keep-alive failure mode is the one in httpx discussion #3309, quoted verbatim:

> "A similar test with curl … shows same server behavior closing connection in packet 17. Curl however
> retries the get on a new connection in packet 21 **including the Digest information received from the
> server**."

i.e. after a connection close, `curl` re-sends the cached Digest header on the new connection; httpx at the
time did not, and re-paid the 401. **VERIFIED here (current httpx 0.28.1) that the 401 re-pay does happen
in one scenario and is harmless in another** — see (a). Pin your httpx version and keep a client
per-worker rather than relying on cross-connection state.

**(d) Non-ASCII passwords. VERIFIED (third-party, single report).** A StackOverflow report
(q/58694358) documents persistent 401s from `requests.HTTPDigestAuth` with a non-ASCII password.
`requests` does `A1 = f"{username}:{realm}:{password}"` then `hashlib.md5(A1.encode("utf-8"))`; the device
hashes whatever byte sequence it stored, and Hikvision's web UI stores UTF-8 from a GBK-era codepath on
older firmware. **INFERRED:** restrict ISAPI service accounts to ASCII, and make it a hard config-validation
error rather than a runtime surprise.

**(e) `verify=False` + redirect/HTTPAdapter interaction — not applicable to you (INFERRED).** ISAPI
endpoints on these terminals do not redirect; skip.

### 1.8 Why people fall back to `curl --digest`

**VERIFIED (reproduced).** `curl --digest` against the emulated device handles GET **and** POST to
`?format=json` correctly, includes the query in `uri=`, and `--anyauth` correctly negotiates Digest rather
than silently downgrading:

```
curl --digest POST ...?format=json -> 200   auth-uri= /ISAPI/AccessControl/AcsEvent?format=json
curl --anyauth -> 200  schemes server saw: ['', 'Digest usernam']   # never falls back to Basic
```

**INFERRED (from the verified facts above) — why curl keeps winning in forum threads:** curl
(1) implements full RFC 2617 nonce/`nc` management with a real `stale` check, (2) treats the auth cache as
connection-independent and replays it after a close (the #3309 quote), (3) is a single-threaded process, so
the thread-safety trap doesn't exist, and (4) has had two decades of device-firmware edge cases hammered
out. The Fibaro HC2 thread is the archetype: the user's scripted client failed and the working answer was
`curl -v --digest -u user:password "http://x.x.x.x/ISAPI/VideoIntercom/..."`.

**Recommendation:** do **not** shell out to curl in a payroll client (you lose error structure, timeouts
become process kills, and you leak credentials via argv where they are visible in `ps`). The failures
people escape with curl are all avoidable in-process — see §7.

---

## 2. Throttling, concurrency limits, and what "overloaded" looks like

### 2.1 There is no 429. **The device answers 503 + an ISAPI envelope.**

**VERIFIED (captured device log, openHAB Hikvision binding).** Full verbatim exchange — note the *HTTP*
status is 503 and the *body* is the ISAPI `ResponseStatus` envelope:

```
[DEBUG] [ipcamera.internal.MyNettyAuthHandler] - Camera at IP:192.0.2.65 gave a reply
        with a response code of :503
[TRACE] [g.ipcamera.internal.HikvisionHandler] - HTTP Result back from camera is
<?xml version="1.0" encoding="UTF-8"?>
<ResponseStatus version="2.0" xmlns="http://www.hikvision.com/ver20/XMLSchema">
<requestURL>/ISAPI/Streaming/channels/101/picture</requestURL>
<statusCode>2</statusCode>
<statusString>Device Busy</statusString>
<subStatusCode>deviceBusy</subStatusCode>
</ResponseStatus>
```

Same thread, on the effect of tighter polling: *"no 503 errors on the 3.1 version. On the M3 snapshot I see
an 503 error about every 2 seconds."*

**Answer to the question as posed (VERIFIED for `deviceBusy`):** no, the device does **not** return 401
when overloaded. It returns **503** with `statusCode=2` / `subStatusCode=deviceBusy`. The deviceBusy
envelope arrives with HTTP **503**, and (from §3.3) a *different* failure mode — auth/account lock — does
surface as 401 with a **different body shape**. Do not conflate them.

**UNVERIFIED:** whether there is a hard concurrent-session ceiling (e.g. "N sessions") documented for the
DS-K1T341AMF-S. No vendor source for a number was found. **Treat any specific concurrency limit you read
as unconfirmed.** What *is* confirmed is that overload manifests as `deviceBusy`, and that Hikvision's own
guides describe the code that way (§2.2).

### 2.2 The official `subStatusCode` taxonomy — your retry table

**VERIFIED (vendor doc).** Hikvision's published "Response Codes of Text Protocol" page
(`enpinfo.hikvision.com`, GUID-C4BA9253-…) defines exactly seven status codes and their sub-codes:

> "7 kinds of status codes are predefined, including 1 (OK), 2 (Device Busy), 3 (Device Error),
> 4 (Invalid Operation), 5 (Invalid Message Format), 6 (Invalid Message Content), and 7 (Reboot Required).
> Each kind of status code contains multiple sub status codes."

The load-bearing rows for a read-only client:

| `statusCode` | Meaning | Example `subStatusCode` | Vendor description | Retry? |
|---|---|---|---|---|
| 1 | OK | `ok` (0x1) | Operation completed. | — |
| 2 | **Device Busy** | `deviceBusy` (0x20000004) | "The device is busy or no response." | **Yes** — backoff |
| 2 | Device Busy | `serviceUnavailable` (0x20000002) | "The service is not available." | **Yes** |
| 2 | Device Busy | `noMemory` (0x20000001) | "Insufficient memory." | **Yes**, long backoff |
| 2 | Device Busy | `upgrading` (0x20000003) | "Upgrading." | **Yes**, very long |
| 3 | Device Error | `deviceError`, `searchDatabaseError` (0x30000010), `updateDatabasError` | "Hardware error." / DB failures | Retry sparingly, then alarm |
| 4 | **Invalid Operation** | `invalidOperation` (0x40000006) | "Invalid operation." | **No** — terminal |
| 4 | Invalid Operation | `lowPrivilege` (0x40000002) | "No permission." | **No** — terminal |
| 4 | Invalid Operation | `badAuthorization` (0x40000003) | "Authentication failed." | **No** — terminal |
| 4 | Invalid Operation | `notSupport` (0x40000001) | "Not supported." | **No** — terminal |
| 4 | Invalid Operation | `beingExportedByAnotherUser` (0x40001012) | "Being exported by others." | **Yes** — wait for other operator |
| 5 | Bad Format | `badXmlFormat` (0x50000001) | "Invalid XML format." | **No** — your bug |
| 6 | Bad Content | `badParameters` (0x60000001) | "Invalid parameter." | **No** — your bug |
| 6 | Bad Content | `badXmlContent` (0x60000003) | "Invalid XML content." | **No** — your bug |
| 6 | Bad Content | `beyondARGSRangeLimit` (0x60000027) | "The parameter value is out of limit." | **No** — your bug |
| 7 | Reboot Required | — | — | Don't; surface to operator |

**Rule of thumb that falls out of the table (INFERRED but safe): `statusCode == 2` is the retryable class;
3 is retry-once-then-alert; 4/5/6 are terminal and indicate your request or your credentials are wrong.**
Retrying a 4-class code is how a polling loop becomes a lockout.

### 2.3 `activeOperator` — I could not verify it

**UNVERIFIED.** `activeOperator` appears in your task's candidate list and is a real-looking Hikvision
sub-code family, but it is **not present** in the vendor "Response Codes of Text Protocol" page captured
here (`grep` for `activeOperator` → 0 matches) and no authoritative table entry was located in this pass.
**Treat `activeOperator` as undocumented-here.** Practical handling: if you ever see it, bucket it with
`statusCode 4` (someone else holds the operator slot) → back off and do not treat it as auth failure. Do
not write your retry logic around a code you cannot cite.

### 2.4 Account lockout is the failure that actually burns you

**VERIFIED (third-party, two independent sources — *not* a Hikvision publication).** The lockout behaviour
is consistently reported but is **not** documented in any Hikvision-authored source I could retrieve, so
weight it as field experience rather than vendor spec:

> "All requests return `401` | Wrong credentials, **account locked after repeated failures**, or user lacks
> the Operator role. **Hikvision locks accounts after ~5 wrong attempts.**" — Harness Automation,
> *Hikvision (ISAPI)* driver doc

> "Repeated failed authentication attempts lock the admin user for **30 minutes** (typically after 5
> failures). Locked responses return `401` with an XML payload containing
> `<lockStatus>locked</lockStatus>` and `<unlockTime>seconds</unlockTime>`. Parse this response to prevent
> request loops." — `uchkunr/hikvision-best-practices`

**VERIFIED (device transcript) — the fields themselves are real.** The `userCheck` body captured in §3.3
contains exactly `<lockStatus>`, `<unlockTime>` and `<retryLoginTime>` on a live Hikvision `webs` server
(there: `lockStatus = unlock`, `unlockTime = 0`, `retryLoginTime = 6` — i.e. the counters are exposed even
when not locked). **INFERRED:** the `~5 attempts / 30 minutes` numbers are device- and
firmware-configurable (Hikvision's "Login Failure Lockout" settings), so read `retryLoginTime`/`unlockTime`
from the response rather than hardcoding either constant.

**This is the mechanism that ties §1 and §2 together:** `requests`/`httpx` each silently spend 2 requests
per 401 (§1.5), so a 10-attempt retry loop on a bad credential is 20 failed logins — lockout, on a device
that controls a door, during a shift. **Parse `lockStatus`/`unlockTime` and treat "locked" as a hard
circuit-open, not a retry.** Never retry a 401 whose body does *not* look like a stale-nonce challenge.

### 2.5 `maxResults`, paging, and pacing for `AcsEvent`

**VERIFIED (vendor doc, Hikvision access-control ISAPI spec, Chinese, `open.hikvision.com`).** Two
directives that settle the `maxResults` question:

> `maxResults`: "如maxResults值大于能力集返回的范围，则设备按照能力集最大值返回，设备不进行报错" —
> *"If the maxResults value exceeds the range returned by the device capability set, the device returns
> according to the capability-set maximum and **does not raise an error**."*

> `searchResultPosition`: "若设备支持的最大totalMatches为M个，但是当前设备已存储的totalMatches为N个
> （N<=M），则该字段的合法范围为0~N-1" — valid range is `0 .. N-1`.

**Consequences for the client:**
1. Oversized `maxResults` fails **silently**, returning fewer rows. If you assume you got `maxResults` and
   advance your cursor by `maxResults`, you will **silently skip punches** — a payroll-losing bug. Always
   advance by the returned `numOfMatches`.
2. The real ceiling is per-device. Read it from `GET /ISAPI/AccessControl/AcsEvent/capabilities` before
   choosing a page size. The spec's own example value is **30**; third-party practice ranges from 100
   (`hikvision-best-practices`) to **2000** (a captured working `AcsEvent` capture, §3.2) to 32 000 on some
   NVR record-search paths — proof only that it varies, not that large is safe on a terminal.

**VERIFIED (working capture).** Pagination contract, verbatim from `hikvision-best-practices`:

> - `searchID`: "Cursor string identifier. Must remain **identical** throughout all subsequent page requests."
> - `searchResultPosition`: "Result offset. Must be incremented by the **`numOfMatches`** value returned in
>   the prior response."
> - `responseStatusStrg`: "Status token (`"OK"` on the final page, `"MORE"` if more records are available,
>   `"NO_MATCHES"` if no records were found)."

and the vendor spec on why `searchID` must be stable — *"若是同一个, 设备记录内存, 下次搜索加快速度"*
(the device caches results for a repeated `searchID` to speed up subsequent pages). **So: keep `searchID`
constant for a paging pass, change it when the query changes, and terminate on `responseStatusStrg != "MORE"`
or `numOfMatches == 0` — never on `numOfMatches == maxResults`.**

**Pacing — INFERRED, no vendor number exists.** No Hikvision document specifies an inter-request interval.
The only quantitative datapoint captured is openHAB's "a 503 about every 2 seconds" under an aggressive
build. Given the terminal is an embedded Linux device (datasheet: 960 MHz CPU, 256 MB RAM), start with
**1 request/second serialised per device, single in-flight request, `deviceBusy` → exponential backoff
(1s, 2s, 4s … cap 30s, max ~6 attempts)** and measure. Do not parallelise per-device to go faster — one
worker per device; parallelise *across* devices.

---

## 3. The error envelope, and the JSON/XML trap

### 3.1 Canonical shape

**VERIFIED (vendor doc).** `XML_ResponseStatus`, verbatim:

```xml
<ResponseStatus version="2.0" xmlns="http://www.std-cgi.org/ver20/XMLSchema">
  <requestURL></requestURL>
  <statusCode></statusCode>
  <statusString></statusString>
  <subStatusCode></subStatusCode>
</ResponseStatus>
```

Success looks the same (`statusCode 1` / `OK` / `ok`) — from the guide, p.278:

```xml
<ResponseStatus version="2.0" xmlns="http://www.isapi.com/ver20/XMLSchema">
  <requestURL>/ISAPI/Security/users</requestURL>
  <statusCode>1</statusCode><statusString>OK</statusString><subStatusCode>ok</subStatusCode>
</ResponseStatus>
```

**VERIFIED (working capture).** The same body with `?format=json` is a flat JSON object — **the
`ResponseStatus` wrapper is dropped in JSON**:

```json
{ "statusCode": 1, "statusString": "OK", "subStatusCode": "ok" }
```

`statusCode` is a **number** in JSON and a **numeric string** in XML; normalise both to `int`.

### 3.2 Envelope ≠ the payload you asked for

`AcsEvent` search results are **not** wrapped in `ResponseStatus` at all — the search-success signal is
`responseStatusStrg` inside `AcsEvent`:

```json
{ "AcsEvent": { "searchID": "b6e1244c-…", "totalMatches": 6, "responseStatusStrg": "OK",
                "numOfMatches": 6, "InfoList": [ … ] } }
```

**So your client must handle three distinct "success" shapes** and must not look for `statusCode` on a
search response, nor `responseStatusStrg` on a plain GET. Check both, plus HTTP status.

### 3.3 The trap: **an error can come back as XML even when you asked for JSON**

**VERIFIED (captured device transcript, verbatim).** The strongest evidence is a `curl -i --digest` against
`.../ISAPI/SecurityCP/Configuration/capabilities?format=json` — a `?format=json` request that got **XML**
back, wrapped in a **third envelope shape**, `<userCheck>`, using `statusValue` where the canonical
envelope uses `statusCode`:

```
HTTP/1.1 401 Unauthorized
Date: Thu, 26 Aug 2021 09:49:08 GMT
Server: Webs
X-Frame-Options: SAMEORIGIN
Cache-Control: no-cache
Content-Length: 231
Content-Type: application/xml; charset="UTF-8"
Connection: keep-alive
Keep-Alive: timeout=60, max=98

<?xml version="1.0" encoding="UTF-8" ?>
<userCheck>
<statusValue>401</statusValue>
<statusString>Unauthorized</statusString>
<lockStatus>unlock</lockStatus>
<unlockTime>0</unlockTime>
<retryLoginTime>6</retryLoginTime>
</userCheck>
```
*(Home Assistant community, "Integration with hikvision ax pro alarm system", post 24 — reporter's own
network-trace paste; the device here is an AX Pro panel, not an access terminal, so treat the envelope
shape as **likely-shared-firmware-lineage** rather than proven on DS-K1T — INFERRED for your model.)*

Three facts to take from it: (1) `?format=json` does **not** bind the error path — the body is
`application/xml`; (2) the status field is named **`statusValue`**, an HTTP-ish number (`401`), *not* the
`statusCode` (1–7) of the canonical envelope; (3) the auth-failure body carries the lockout fields
`lockStatus` / `unlockTime` / `retryLoginTime` (§2.4), so **a 401 body is a data payload you must parse,
not just a status to retry on**. The same response also shows the quoted-charset defect again
(`charset="UTF-8"` with literal quotes) and `Server: Webs`.

So there are **at least three envelope shapes** a client must survive: canonical `ResponseStatus`
(`statusCode`/`statusString`/`subStatusCode`), the JSON-flat variant (§3.1), and `userCheck`
(`statusValue` + lock fields). Corroborating third-party report on an actual DS-K1T terminal: a
DS-K1T804AMF `AcsEvent` retrieval failing with `badParam`/invalid-content where the body could not be
parsed as the requested JSON.

**Also VERIFIED (Stack Overflow, accepted answer):** the device "return[s] the content type incorrectly",
sending `Content-Type: application/json;charset="UTF-8"` with a **quoted** charset parameter — which
some strict parsers reject or mis-type, and which can make a strict client throw before it ever inspects
the body.

**Client rule (INFERRED from the above, and important):** *never trust `Content-Type`, and never assume
the response format matches your `?format=json`.* Parse defensively:

```python
def parse_isapi(body: bytes) -> dict:
    """Hikvision may return XML where you asked for JSON, and quote its charset. Never trust either."""
    t = body.strip()
    if not t:
        return {}
    if t[:1] in (b"{", b"["):
        try:
            return json.loads(t)
        except json.JSONDecodeError:
            pass  # fall through to XML
    root = ET.fromstring(t)  # strips the {ns} prefix below
    return _xml_to_flat_dict(root)  # statusCode/statusString/subStatusCode/requestURL


def isapi_status(payload: dict) -> int | None:
    """`statusCode` in the canonical envelope; `statusValue` in the lock/userCheck variant."""
    for k in ("statusCode", "statusValue"):
        if k in payload:
            try:
                return int(payload[k])
            except (TypeError, ValueError):
                return None
    return None
```

Accept both `statusCode` and `statusValue`. Strip XML namespaces (`{url}tag` → `tag`) before key lookup —
the guide itself shows **three different namespace URIs** in live examples
(`std-cgi.org`, `isapi.com`, `isapi.org`) plus `hikvision.com/ver20/XMLSchema` in the openHAB capture, and
they are **not** interchangeable in a naive `find()`. `hikvision-timesync`'s working reader uses
`el.find(f"{{{HIK_NS}}}{tag}")` with `HIK_NS = 'http://www.hikvision.com/ver20/XMLSchema'` — correct for
that device, brittle as a general rule.

---

## 4. TLS: 443 vs 8000 — and a correction to the premise

**VERIFIED (vendor doc, important).** **Port 8000 is not HTTPS.** Hikvision US support documents the
port map directly:

> "The **Server port**. By default this is set to **8000**." — and this is the **Hikvision private/SDK
> protocol** port, forwarded alongside RTSP 554 for ISUP/SDK traffic, not an HTTP-over-TLS listener.

The DS-K1T502DBFWX datasheet's protocol line confirms the HTTP surface: **`ISAPI (80\443 Interface)`**.
A DS-K1T connection-troubleshooting guide from a Hikvision partner adds the corollary:

> "port **80** must be used for connection to the iVMS-4200 software, and not **8000**."

**So for your terminal: ISAPI is HTTP on 80 and HTTPS on 443. Port 8000 speaks the proprietary SDK
protocol — connecting to `https://device:8000/ISAPI/...` will fail at the TLS handshake or return binary
garbage, and that is expected behaviour, not a bug in your client.** (Reconciling with the open-port list:
80 and 443 are the web server; 8000 is the private protocol; 554 is RTSP.)

### 4.1 Self-signed certificate — yes. Hostname verification — you must handle it.

**VERIFIED (third-party driver doc, not Hikvision-authored).** A production Hikvision ISAPI driver names
the symptom and the port variance directly:

> "Works on http but not https | **Self-signed certs are tolerated by default.** If https still fails, the
> device may only listen on the alternate port (commonly 443 vs 8443)." — Harness Automation,
> *Hikvision (ISAPI)*

and `hikvision-best-practices` states the requirement plainly: `ISAPI (HTTPS)` … "**Requires handling
self-signed certs**".

**VERIFIED (library behaviour, reproduced on this machine).** What turning verification off actually does:

```
httpx verify=False -> verify_mode: 0 (CERT_NONE)   check_hostname: False
httpx default      -> verify_mode: 2 (CERT_REQUIRED) check_hostname: True
requests verify=False -> session.verify = False      (adapters: `if url.startswith("https") and verify:` → else-branch skips CERT_REQUIRED)
```

**This is the key operational fact:** in both libraries, `verify=False` disables **certificate verification
*and* hostname checking together** — they are not independent switches. On a device whose self-signed cert
is issued for a hostname/IP you don't control, that is *why* people reach for `verify=False`, and it is why
it feels necessary. It is also full MITM exposure on a network segment you do not control.

**The safe configuration (INFERRED from the verified API surface, standard practice), which both libraries
support without disabling hostname checks:** take the device's self-signed cert and put it in your own
CA bundle — then `verify="/etc/hik/hik-devices-ca.pem"` keeps `CERT_REQUIRED` **and** `check_hostname=True`.
Two caveats specific to these terminals:
- Self-signed Hikvision device certs typically carry no SAN, or an SAN with the **IP** the cert was minted
  at, which goes stale under DHCP. Prefer pinning by **certificate fingerprint/public key** over hostname
  verification, or reserve the device IP.
- If you must disable verification, do it **per-device and explicitly**, never globally
  (`REQUESTS_CA_BUNDLE`/`SSL_CERT_FILE` env vars and `NODE_TLS_REJECT_UNAUTHORIZED=0` are the anti-patterns
  to refuse in review). `hikvision-isapi-py` ships exactly this footgun as a package-wide
  `VERIFY_SSL` env var — "Set the environment variable `VERIFY_SSL` to `false` (anything but `true` will
  skip the check)" — note the *fail-open* default of "anything but true". Do not inherit that semantic.

---

## 5. Clock, timezone, and getting punch times to UTC **correctly**

This is the payroll-critical section. It has one good answer and several traps.

### 5.1 `GET /ISAPI/System/time` — what it actually returns

**VERIFIED (vendor doc — the single most important citation in this brief).** `XML_Time`, from the official
ISAPI Developer Guide, §16.2.295 (p.724):

```xml
<Time version="2.0" xmlns="http://www.isapi.org/ver20/XMLSchema">
  <timeMode><!--req, xs:string, "manual, NTP, local, satellite, timecorrect"--></timeMode>
  <localTime><!--req, xs:datetime, ISO 8601 time format, device time set manually,
              e.g.: 2018-02-01T19:54:04. Required when <timemode> is "manual" or "local"--></localTime>
  <timeZone><!--req, xs:string, **POSIX time zone string**, required when <timemode> is
             "manual", "local" or "NTP"--></timeZone>
  <satelliteInterval><!--dep, xs:integer, unit: minute--></satelliteInterval>
</Time>
```

And from the capability form, §16.2.77 (p.581), which additionally documents `timeType`:

```xml
<timeType opt="local, UTC">
  <!--opt, xs:string, time type, it can be local, or UTC, or local and UTC.
      If this node is not returned, it indicates that device does not support
      getting or setting time type-->
</timeType>
```

Four consequences:
1. **`timeZone` is a POSIX TZ string**, per Hikvision's own schema — not an IANA name, not a Windows name.
2. **`localTime` in the sample has no offset at all** (`2018-02-01T19:54:04`) — it is *naive local*.
3. `timeType` says whether the device thinks in `local` or `UTC`, and **may be absent entirely.**
4. There are dedicated sub-resources — `/ISAPI/System/time/timeZone` returns "String containing time zone
   information" (guide §15.10.184), and `/ISAPI/System/time/timeType?format=json` exists. Query these
   directly rather than scraping `<Time>`.

### 5.2 The POSIX sign trap — and Hikvision's inverted variant

**VERIFIED (reproduced with `zoneinfo`).** POSIX/IANA `Etc/GMT*` inverts the sign, and this is where
"Etc/GMT-2" comes from:

```
Etc/GMT-2 -> UTC+02:00        Etc/GMT+2 -> UTC-02:00        Etc/GMT-3 -> UTC+03:00
```

So an IANA-style label `Etc/GMT-2` on a device means **UTC+2**, which is what Romania needs in winter —
the string *looks* wrong and *is* right. Anyone who "fixes" it by flipping the sign breaks the clock.

**VERIFIED (third-party, hardware-confirmed for UK, `hikvision-timesync`).** Hikvision devices write a
modified POSIX string whose offset sign is the **opposite of POSIX**:

> "**Sign convention:** Hikvision uses the **opposite** of POSIX. `+1:00:00` means UTC+1 (one hour ahead).
> `-5:00:00` means UTC-5 (five hours behind)."
>
> Format: `STD+H:MM:SS[DST+H:MM:SS,Mmonth.week.day/hh:mm:ss,Mmonth.week.day/hh:mm:ss]`
> e.g. UK: `GMT+0:00:00BST+1:00:00,M3.5.0/01:00:00,M10.5.0/02:00:00`
> EET preset: `EET+2:00:00EEST+3:00:00,M3.5.0/…,M10.5.0/…`

**So there are three mutually-incompatible timezone encodings in the wild on Hikvision hardware** — vendor
schema says POSIX (negative=east), the hardware-confirmed field report says inverted-POSIX (positive=east),
and the UI can present IANA-ish `Etc/GMT-2` or a Windows name (§5.3). The same string `GMT+2:00:00` means
UTC−2 under one reading and UTC+2 under another. **Never parse this string yourself to derive an offset.**
See §5.6 for the strategy that sidesteps the whole mess.

### 5.3 Windows tz names like `GTB Standard Time`

**VERIFIED (Microsoft).** `GTB Standard Time` is a **Windows time-zone ID**, not a Hikvision artefact:

> "| Greece | GR | **GTB Standard Time** | (UTC+02:00) | Athens, **Bucharest** | … |
>  | **Romania** | **RO** | **GTB Standard Time** | (UTC+02:00) | Athens, Bucharest |"
> — *Default Time Zones*, Microsoft Learn

(Confirmable on any Windows box with `tzutil /l`; the same name covers Athens/Bucharest/Istanbul.)

**UNVERIFIED as to Hikvision.** I found **no** source showing a Hikvision device emitting a Windows tz ID
over ISAPI. What is verified is the *plausible channel*: Hikvision's own Windows tools (HikCentral, iVMS-4200)
run on Windows and "select the device time zone" from a Windows-backed list, and HikCentral "will auto
synchronize to device" — so a Windows-named selection can be *translated* on the way into the device, and a
mis-mapping would surface as a wrong `timeZone` string or a wrong `localTime`. **INFERRED:** if you see
`GTB Standard Time` in a `timeZone` field, it is almost certainly a **Windows-derived name persisted by a
Windows management client**, and it maps to `Europe/Bucharest` — but treat that mapping as an assumption to
verify on your device (§6), and know the ID is ambiguous across several IANA zones (Athens/Bucharest/
Istanbul share it; **Istanbul has had no DST since 2014 while Bucharest still switches**, so the Windows
name alone is *insufficient* to compute UTC).

### 5.4 Romania / Europe/Bucharest — the concrete DST facts

**VERIFIED (reproduced, `zoneinfo`, Python 3.13).** For **2026**:

```
spring-forward: Sun 2026-03-29  02:00 -> 03:00   (EET +02:00 -> EEST +03:00)
fall-back:      Sun 2026-10-25  04:00 -> 03:00   (EEST +03:00 -> EET +02:00)

winter 2026-02-15 09:00 -> +02:00 -> UTC 07:00
summer 2026-07-15 09:00 -> +03:00 -> UTC 06:00
2026-10-25 09:00        -> +02:00 -> UTC 07:00   (after fall-back)
```

EU rules apply (last Sunday March / last Sunday October). **Your device's current offset, as of today
(2026-10-15), is +03:00 (EEST)** — it switched to +02:00 ten days from now, on 2026-10-25. Any "Romania is
UTC+2" constant in your code is wrong for roughly eight months of the year.

Note the runtime context in the request header says `EEST, UTC+03:00` — consistent.

### 5.5 Do `AcsEvent` times come back local-with-offset, or naive local?

**VERIFIED (captured real device transcript — this is the decisive evidence).** `AcsEvent` returns
**local time *with* an explicit numeric UTC offset**, on a DS-K1T-series-family terminal, from a working
integration (`garden-gate/HIKVISION.md`):

```
HTTP/1.1 200 OK
Server: webs
Connection: close
Content-Type: application/json

{ "AcsEvent": { "responseStatusStrg": "OK", "numOfMatches": 6, "totalMatches": 6,
  "InfoList": [
    { "major": 5, "minor": 1, "time": "2023-06-09T19:05:47+07:00", "cardNo": "garten-XU7oiAB9AU01t",
      "employeeNoString": "100054", "serialNo": 42970, "cardReaderNo": 1, "doorNo": 1 }, … ] } }
```

`"time": "2023-06-09T19:05:47+07:00"` — wall-clock 19:05:47 with `+07:00`. **Cross-check: the request
`startTime`/`endTime` were generated as *local* ISO-8601 and the device returned matching local times, and
the offset `+07:00` is Asia/Bangkok, i.e. the device's own configured zone.**

Note the same capture also proves two §3/§4 points: `Server: webs`, `Connection: close`, and
`Content-Type: application/json` honoured *for the success path*. The error path is where the format
contract breaks (§3.3).

**VERIFIED (reproduced) — `datetime.fromisoformat` handles this correctly and naively-falls-over:**

```
2023-06-09T19:05:47+07:00 -> aware=True  utc=2023-06-09T12:05:47+00:00   OK
2026-10-15T09:00:00+03:00 -> aware=True  utc=2026-10-15T06:00:00+00:00   OK
2026-10-15T09:00:00       -> aware=False utc=NAIVE-CANNOT-SAFE-CONVERT   <-- must be a hard error
```

**INFERRED (and important):** whether the offset is present is **firmware/configuration dependent**. The
official `localTime` sample is *naive* (`2018-02-01T19:54:04`), and `hikvision-best-practices`' own working
`AcsEventCond` sends naive `startTime: "2026-04-12T00:00:00"`. **So: your parser must accept both, and must
treat a naive value as a data-quality failure for payroll, not as something to guess about.**

**The failure you are defending against (VERIFIED, reproduced).** Silently assuming an offset:

```
punch: 2026-07-15T09:00:00+03:00  -> correct UTC 2026-07-15T06:00:00
if you force +02:00             ->            2026-07-15T07:00:00   <-- 1 hour of every summer punch, wrong
```

And the DST-gap/ambiguity traps if you *do* ever have to localise a naive value (VERIFIED, reproduced):

```
GAP  2026-03-29T02:30 (does not exist) -> replace(tzinfo=BUC) -> 02:30+02:00 -> UTC 00:30
                                          (silently legalised into a non-existent instant)
AMB  2026-10-25T03:30 (occurs twice)   -> fold=0 -> 03:30+03:00 -> UTC 00:30
                                         -> fold=1 -> 03:30+02:00 -> UTC 01:30   <-- 1h apart, same wall clock
```

### 5.6 The safest strategy for punch → UTC

Ordered by preference. **The offset in the payload is the payload's own assertion of its zone — trust it
first, and never let a naive value through.**

```python
from datetime import datetime, timezone
from zoneinfo import ZoneInfo

DEVICE_TZ = ZoneInfo("Europe/Bucharest")  # fallback ONLY, never the primary path


class NaivePunchTime(ValueError):
    """A punch arrived without a UTC offset. Unambiguous conversion is impossible."""


def punch_to_utc(raw: str, *, source: str = "") -> datetime:
    """
    Convert a Hikvision AcsEvent `time` to a UTC-aware datetime.

    Policy (payroll-safe):
      1. Trust the explicit offset in the payload. Verified real-device shape:
         "2023-06-09T19:05:47+07:00".
      2. NEVER guess for a naive value. Raise; let the pipeline quarantine the record.
      3. Never use the *client's* timezone, and never a hardcoded +02:00.
    """
    dt = datetime.fromisoformat(raw)  # py3.11+ handles +07:00
    if dt.tzinfo is None:
        raise NaivePunchTime(f"{source}: naive punch time {raw!r} - refusing to guess")
    return dt.astimezone(timezone.utc)  # offset-aware -> exact, DST-proof
```

Why each rule:

1. **Use the payload's own offset (VERIFIED shape, INFERRED as the policy).** `+07:00` is unambiguous and
   DST-proof; `astimezone(utc)` on an aware datetime is exact arithmetic. This sidesteps §5.2 and §5.3
   entirely, because you never interpret the device's `timeZone` string. **This is the single most
   important recommendation in the brief.**
2. **Never localise a naive value with `ZoneInfo` (VERIFIED traps).** A punch at `03:30` on the fall-back
   Sunday is genuinely ambiguous — two distinct UTC instants an hour apart. For payroll you cannot choose
   silently; quarantine and reconcile against the terminal's event `serialNo` sequence.
3. **Never hardcode `+02:00` / "Romania is UTC+2" (VERIFIED, 1h error reproduced).**
4. **Never use the *client* host's timezone** — the collector may run in a data centre in another zone.
5. **Reconcile the device clock continuously (INFERRED, but cheap and the real payroll risk).** A digest-
   or-format-correct timestamp from a device whose clock is 4 minutes off still costs you a punch. Poll
   `GET /ISAPI/System/time`, compare against your own NTP-disciplined clock, and alert above a threshold
   (start at 30 s). Cross-check the HTTP `Date:` header, which `webs` sends on every response
   (`Date: Fri, 09 Jun 2023 20:07:40 GMT` in the capture above) — it is a second, independent clock signal
   and it costs nothing since you already have the response.
6. **Persist three fields per punch, not one:** the raw string as received, the derived UTC instant, and
   the device's `serialNo`. `serialNo` is monotonic per device (the capture shows 42970, 42976, 42980,
   42984, 42987, 42991) and is your only tool for detecting dropped or duplicated pages and for
   reconstructing order when a clock was adjusted mid-shift.
7. **Keep the device on `timeMode=NTP`** and confirm `timeType` if present. If the device ever reports
   `timeType: UTC` (§5.1) the `time` field may carry a `Z` instead of a local offset — `fromisoformat`
   handles both, and rule 1 still applies.

---

## 6. Two probes that would upgrade several INFERRED → VERIFIED

Cheap, read-only, and each settles a live ambiguity. (Not run here: no device credentials, and the task
forbade contacting the device.)

```bash
# P1 — is Basic ever accepted, and is qop/algorithm ever anything but auth/MD5?
#      Also captures the real nonce shape, `stale` casing, and whether `Date:` is sent.
curl -sv -o /dev/null -u admin:REDACTED 'http://DEVICE/ISAPI/System/time' 2>&1 | grep -i '^< '

# P2 — what does this firmware actually put in timeZone, and is localTime naive or offset-bearing?
#      Settles §5.2 / §5.3 for the DS-K1T341AMF-S specifically. Read the payload's offset too.
curl -s --digest -u admin:REDACTED 'http://DEVICE/ISAPI/System/time'
curl -s --digest -u admin:REDACTED 'http://DEVICE/ISAPI/System/time/timeZone'
curl -s --digest -u admin:REDACTED 'http://DEVICE/ISAPI/AccessControl/AcsEvent/capabilities?format=json'
```

Read `AcsEvent/capabilities` before choosing `maxResults` (§2.5) — it is the only authoritative source for
that device's page-size ceiling.

---

## 7. Client recommendations (consolidated)

1. **Pin `uri=` = path + query, byte-identical to the request-line.** Highest-severity gotcha (§1.4). Prefer
   a library auth handler over hand-rolling; if you must hand-roll, the working recipe is
   `uri = u.pathname + u.search` and `HA2 = MD5(f"{METHOD}:{uri}")`, and you must send the *same* URL object
   you hashed.
2. **One `httpx.DigestAuth` per worker thread, never shared across threads** (§1.7b). Its state is unlocked.
   `requests.HTTPDigestAuth` is thread-safe by accident (`threading.local`) but multiplies nonces.
3. **Reuse the client; bound the nonce lifetime.** Do not adopt the "fresh `DigestAuth` per call" workaround
   permanently — it doubles every request (measured: 10 vs 6 for 5 calls, §1.7a). Instead keep one client and
   treat *any* 401 carrying a `Digest` challenge as a normal nonce refresh. If you see 401 storms, *then*
   shorten auth-object lifetime as a targeted mitigation, and pin your `httpx` version (§1.7a regression).
4. **Retry policy driven by `statusCode`, not HTTP status:** `statusCode==2` (deviceBusy/serviceUnavailable/
   noMemory) → exponential backoff + jitter; `3` → retry once then alert; `4`/`5`/`6` → terminal, do not
   retry. Serialise requests per device; one in-flight at a time; start at ~1 req/s (§2.5).
5. **Never retry a 401 blindly, and circuit-open on lockout.** `requests`/`httpx` already spend 2 requests
   per 401 (§1.5); a retry loop on bad credentials reaches the ~5-attempt lockout fast, and a locked admin
   account on a door terminal is an availability incident. Parse `lockStatus`/`unlockTime` (§2.4) and open
   the circuit for `unlockTime` + margin.
6. **Parse responses format-agnostically.** Never trust `Content-Type` (Hikvision sends the malformed
   `application/json;charset="UTF-8"`, §3.3) and never assume `?format=json` is honoured on the error path —
   errors arrive as XML with `statusCode` **or** `statusValue`, under ≥4 different XML namespaces (§3.1–3.3).
   Handle the three success shapes (`ResponseStatus`, flat JSON status, and the search envelope's
   `responseStatusStrg`) separately.
7. **Advance paging by `numOfMatches`, terminate on `responseStatusStrg`.** An oversized `maxResults` is
   silently clamped by the device (§2.5) — advancing by the requested page size loses punches. Keep
   `searchID` stable within a pass.
8. **Trust the payload's UTC offset; quarantine naive timestamps.** Never localise a naive punch with a
   device or host timezone — the fall-back Sunday makes `03:30` ambiguous by an hour, and the spring-forward
   gap silently legalises non-existent instants (§5.5–5.6). Store raw + UTC + `serialNo`.
9. **Monitor the device clock as a first-class signal.** Compare `GET /ISAPI/System/time` and the response
   `Date:` header against an NTP-disciplined reference; alert on drift. A correctly-parsed timestamp from a
   badly-set clock is still a wrong punch (§5.6.5).
10. **TLS: use 443 for HTTPS — not 8000** (8000 is the private SDK port, §4). Prefer pinning the device
    cert as your own CA bundle (keeps `CERT_REQUIRED` **and** `check_hostname=True`) over `verify=False`,
    which disables both at once (measured, §4.1). If you must skip verification, scope it per-device and
    explicitly; reject fail-open env-var semantics like `VERIFY_SSL` ≠ `"true"`.
11. **ASCII-only service accounts** (§1.7d), and validate at config load. Create a dedicated read-only
    operator user rather than using `admin` — it bounds lockout blast radius and satisfies the
    `lowPrivilege`/`notSupport` (statusCode 4) failure modes cleanly.
12. **Do not shell out to `curl --digest`** (§1.8). Every reason people do it is fixable in-process, and
    shelling out costs you structured errors, real timeouts, and leaks credentials into `ps`.

---

## Sources

Vendor (Hikvision):
1. **Intelligent Security API (General Application) Developer Guide**, Hikvision, 2019, 795 pp. Primary
   vendor reference for §1.1, §1.3, §1.4, §2.2, §3.1, §5.1. Retrieved
   `https://raw.githubusercontent.com/loozhengyuan/hikvision-sdk/master/resources/isapi.pdf` (5,224,806 B,
   SHA-verifiable locally; text extracted to `isapi.txt`, page markers retained). Key locations: p.116/119/131
   (digest challenges), p.178 (`maxResults` transcript), p.278 (`ResponseStatus` samples), p.395
   (`/ISAPI/System/time/timeZone`), p.581 (`XML_Cap_Time`), p.724 (`XML_Time`).
2. **Response Codes of Text Protocol**, Hikvision Integration Documentation (`enpinfo.hikvision.com`,
   GUID-C4BA9253-2E18-4292-942F-7CD65AF6E8B0) — authoritative `statusCode`/`subStatusCode` table, §2.2, §3.1.
3. **XML_ResponseStatus schema**, `enpinfo.hikvision.com` GUID-7568B3DA-6D04-4AD5-A8FD-97A71F4AB8E5 — §3.1.
4. **Fast guide for ANPR of TCV/TCM camera via ISAPI**, Hikvision Technology Partner Program —
   "authenticated by the Digest Access method of the RFC 2617 protocol", §1.6.
   `https://www.hikvisioneurope.com/eu/portal/portal/Technology%20Partner%20Program/02-Solutioins%20of%20Hikvision%20product%20integration/Fast%20guide%20for%20ANPR%20of%20TCV%20camera%20via%20ISAPI.pdf`
5. **What port forwards are required for direct IP remote access**, Hikvision USA support
   (`supportusa.hikvision.com`, article 17000128725) — "The Server port. By default this is set to 8000", §4.
6. **DS-K1T502DBFWX Access Control Terminal datasheet** (`assets.hikvision.com`, m000057915) —
   "ISAPI (80\443 Interface)", "960 MHz CPU / 256 MB RAM", §2.5, §4.
7. **Access control ISAPI command reference (zh)**, `open.hikvision.com` — `maxResults` silent-clamp and
   `searchResultPosition` range, §2.5. Local capture: `_mingmen.txt`.
8. **Hikvision Network Security Hardening Guide** — extraction failed here ("Unprocessable entity"); cited
   for nothing. Listed for completeness; treat as *not consulted*.

Library sources (read directly, this machine: httpx 0.28.1, requests 2.31.0, Python 3.13):
9. `httpx/_auth.py` — `DigestAuth.auth_flow`, `_parse_challenge`, `_build_auth_header`, `_get_client_nonce`,
   `_resolve_qop`. §1.2, §1.3, §1.5, §1.7.
10. `requests/auth.py` — `HTTPDigestAuth.build_digest_header` (`path += f"?{query}"`, `threading.local`),
    `handle_401` (`num_401_calls < 2`). §1.4, §1.5, §1.7.
11. encode/httpx **PR #2463** "reuse the digest auth state" — the regression origin. §1.7a.
12. encode/httpx **discussion #2549** — maintainer's "passing a new instance on each request?" workaround. §1.7a.
13. encode/httpx **discussion #3309** — curl-vs-httpx digest replay after connection close (verbatim quote, §1.7c).
14. home-assistant/core **issue #85888** "Rest sensor - digest issue with the new httpx" — field impact. §1.7a.

Working third-party captures (device transcripts — strongest evidence for §3.2, §3.3, §5.5):
15. **creatorsgarten/garden-gate `HIKVISION.md`** — verbatim `AcsEvent` response with
    `"time": "2023-06-09T19:05:47+07:00"`, `Server: webs`, `Connection: close`; plus `CardInfoSearch`
    pagination and the flat JSON `{statusCode, statusString, subStatusCode}` envelope.
    `https://raw.githubusercontent.com/creatorsgarten/garden-gate/main/HIKVISION.md` (local: `gg.md`).
16. **mmicmanagement/hikvision-timesync** README + `timesync.py` — Hikvision TZ string format, inverted
    sign convention, `localTime` always `+00:00` firmware quirk, `badXmlContent` on PUT without `localTime`,
    working `urllib` `HTTPDigestAuthHandler` reader of `/ISAPI/System/time`. (local: `ts.md`, `ts.py`).
17. **uchkunr/hikvision-best-practices** (community GitHub reference, *not* a Hikvision publication) —
    digest handshake steps, `responseStatusStrg`/`numOfMatches` pagination contract, `maxResults: 100`,
    Basic-auth claim (§1.6, contested), the "30 minutes after ~5 failures" lockout text and the
    `lockStatus`/`unlockTime` parsing recipe (§2.4), and the **unverified** ">5 min clock drift rejects
    Digest" claim (§1.2). (local: `best.md`).
18. **openHAB IP Camera binding**, threads 42771 (p.94) and 126735 (post 12 via `/raw/126735/12`, post 16) —
    verbatim **HTTP 503 + `<statusCode>2</statusCode><subStatusCode>deviceBusy</subStatusCode>`** transcript,
    and "an 503 error about every 2 seconds". §2.1. (local: `oh/p12.txt`).
19. **idstein/hikvision_access** commits `fd47125` / `4761eb5` — the `uri = parts.path or "/"`
    query-stripping bug and its fix ("digest not basic"). §1.4.
20. **Home Assistant community**, "Integration with Hikvision AX Pro" post 24 — 401 with an XML error body
    despite a JSON request; `statusValue` variant. §3.3.
21. **ipcamtalk**, "DS-K1T804AMF ISAPI AccessControl event retrieval fails with invalid content" —
    `AcsEvent` `badParam` / unparseable-body report on a DS-K1T terminal. §3.3.
22. **StackOverflow q/45995307** "Hikvision log search REST API POST giving invalid XML format" — device
    "return[s] the content type incorrectly", `charset="UTF-8"` quoted. §3.3.
23. **StackOverflow q/58694358** "401 response with Python requests" — non-ASCII password digest failure. §1.7d.
24. **Harness Automation**, "Hikvision (ISAPI)" driver doc — "Hikvision locks accounts after ~5 wrong
    attempts"; self-signed certs tolerated; `auth_mode` basic fallback. §2.4, §4.1.
25. **peterbuga/Visiotech support**, "Connection problems with DS-K1T344/DS-K1T502/DS-K1T681" —
    "port 80 must be used … and not 8000". §4.
26. **hikvision-isapi-py (PyPI)** — `VERIFY_SSL` fail-open env-var anti-pattern, §4.1.
27. **MaythamAlshammasi/hik-access-system-open-source** `HIKVISION_SETUP.md` — DS-K1T integration uses
    `httpx.DigestAuth`, "more secure than Basic". §1.6 (counter-evidence to [17]).

Independent / platform references:
28. **Microsoft Learn, "Default Time Zones"** — `GTB Standard Time` = (UTC+02:00) Athens, **Bucharest**;
    Romania→`GTB Standard Time`. §5.3.
29. **IANA tzdata via Python `zoneinfo`** — Europe/Bucharest 2026 DST transitions and offsets, `Etc/GMT±N`
    POSIX sign inversion; all §5.4/§5.5/§5.6 numerics reproduced in-session.
30. **Local reproduction harness** (`digest_battery.json`, this directory) — digest behaviour of
    httpx 0.28.1 / requests 2.31.0 / curl against a `qop="auth"`, realm `DS-39DED0D1`, `Server: webs`
    emulator: `uri=` handling incl. `?format=json`, `nc`/`cnonce` progression, stale-nonce recovery,
    `Connection: close` resilience, concurrent shared-auth state, Basic rejection, curl `--digest`/`--anyauth`.

**Claims NOT substantiated in this pass (do not rely on them):** the ">5 min clock drift rejects Digest"
claim [17]; any specific numeric concurrent-session ceiling for the DS-K1T341AMF-S; the existence/semantics
of an `activeOperator` `subStatusCode`; Basic-auth availability on DS-K1T* terminals ([17] vs [27]); and any
Hikvision device emitting `GTB Standard Time` as a `timeZone` value over ISAPI.
