# gateclerk — Hikvision attendance → Business Central

Goal: read punch events (who / when / in-or-out) off Hikvision access terminals and land
them in Business Central as timesheet data. `gateclerk` = time attendance (RO).

Status: **P1 only — read-only connector + CLI, device side** (owner scope-lock,
2026-10-15): prove we can connect and pull events correctly from the real device.
**Out of scope until P1 is proven working on the device:** anything Business Central
— no design, no cards, no endpoint choices; it stays exactly one open question below.
P2 (site agent) is a sketch only, kept to keep P1's seams honest — not scheduled.

**Device-verified facts live in [OBSERVED.md](OBSERVED.md)** (probe of site-a
DS-K1T341AMF-S, 2026-10-15: capabilities, paging quirks, the time-offset bug, the
major=3 noise stream, `attendanceStatus` = null). Where this doc and OBSERVED.md
disagree, OBSERVED.md wins — it was read off the box. Deep background research
(with source citations, marked VERIFIED/INFERRED): `docs/references/`.

## Constraints / invariants

- **Read-only.** Only `GET` and the two stateless search `POST`s
  (`UserInfo/Search`, `AcsEvent`). No `PUT`/`POST` that writes users, faces, cards,
  doors, schedules. No reboots/upgrades. Nothing in this repo may issue a mutating
  verb; enforced by a test that walks the client's endpoint table and asserts method
  ∈ {GET, search POSTs}. If we ever need a write path, it gets its own flag + its own
  review — not folded into the connector.
- **Credentials: keychain default, gitignored `.env` fine (private repo, owner
  relaxed 2026-10-15).** Never paste creds into chat, code, docs, or commit anything
  secret — but no ceremony beyond that: `.env` (gitignored since commit 1) is a valid
  source when it's simpler than keychain. Device password default: macOS Keychain
  (`security find-generic-password -s gateclerk-hikvision -a <host>`); P2 site agents
  take an env var / systemd credential — the connector takes a *callable* that returns
  the password, so the credential source is never baked into the ISAPI code. No
  dedicated secret-hygiene work (guards, scanners, ceremonies): hygiene stays a
  side-effect of normal engineering (redaction in repr/logs, masked fixtures), never
  a card.
- **Timestamps are payroll data.** Every event keeps the device's original local string,
  the resolved UTC instant, and the device tz/offset we used to resolve it. We never
  discard the raw. If we can't resolve a timestamp unambiguously we store it and flag it,
  we don't guess.

## Architecture

Target-state sketch only — the agent/push layers are **not scheduled and not carded**
(owner locked current scope to the device-side connector; see Phase plan). It's drawn
here so P1's seams (credential callable, normalized record, capability cache) don't
paint the future into a corner.

```
[site A LAN]                    [site B LAN]                    [site C LAN]
 DS-K1T341AMF-S                  terminal                       terminal
      ↑ ISAPI HTTP:80                 ↑                              ↑
      │ (digest)                      │                              │
 [agent A]                      [agent B]                      [agent C]
   poll → sqlite(checkpoint)    poll → sqlite                  poll → sqlite
      └──────── outbound HTTPS push (agent → ingest endpoint) ────────┘
                                     ↓
                          [BC ingestion endpoint — TBD]
```

One small agent per site because the three devices are on three different networks.
Agent **polls its local device and pushes outbound** — no inbound ports, no site VPN,
no Tailscale needed as a prerequisite (it stays an option if a site's egress rules
become a problem). Polling with a checkpoint beats the `alertStream` push mode for P1:
a restart resumes from the checkpoint instead of having missed everything while down,
and the device can't drop events because nobody had a stream open. `alertStream` stays
a P2+ latency optimisation on top, not a replacement — we'd still need the poll path to
heal gaps.

## Endpoints (P1 surface)

| Call | Method | Notes |
|---|---|---|
| `/ISAPI/System/deviceInfo` | GET | returns **XML on this fw even with ?format=json** — parser needs both. model, serial, fw. Serial is part of the idempotency key. |
| `/ISAPI/System/time` | GET | XML here too. device clock + tz; drift/offset is our problem, not the device's (see Time handling) |
| `/ISAPI/AccessControl/UserInfo/Count` | GET | GET only — POST → `methodNotAllowed` on this fw |
| `/ISAPI/AccessControl/UserInfo/Search` | POST (JSON body) | employee roster, paged. Records carry a `password` hash key — strip before storing |
| `/ISAPI/AccessControl/AcsEvent` | POST (JSON body) | events, paged |
| `/ISAPI/AccessControl/AcsEvent/capabilities` | GET | **the important one** — see below |
| `/ISAPI/AccessControl/capabilities` | GET | AccessControl-wide caps (per-group `maxCapacity`; the `AcsEvent` group's is the event-ring capacity — advisory for open question 4). Absent on some firmware: a 404 `notSupport` here is recorded as data, not failure. |
| `/ISAPI/AccessControl/AcsEventTotalNum` | POST (JSON body) | the real count endpoint (works: `totalNum` int); advisory cross-check vs `totalMatches`, never a loop bound |
| `/ISAPI/AccessControl/AcsEvent/Total` | — | **not supported on site-a fw (400 notSupport)** — implemented nowhere |

Everything returns `401 + WWW-Authenticate: Digest qop="auth"` unauthenticated,
confirmed on `192.0.2.10` (realm `DS-39DED0D1`, `Server: webs`). So: HTTP digest,
`qop=auth`. Digest auth is per-request-challenge stateful (nonce/nc), so the client must
reuse one authenticated session across paged requests, not rebuild auth per request.

### Why we read `/capabilities` instead of hardcoding event codes

Hikvision's `major`/`minor` event codes are model- and firmware-dependent, and the
documented tables disagree with each other in the community sources. The device tells us
its own truth: `AcsEvent/capabilities?format=json` returns, per field, the admissible
`minorEvent` / `minorAlarm` / `minorOperation` code **sets** plus the `maxResults` limit
that model actually accepts. So P1 does this on first contact:

1. read capabilities → cache in the local store;
2. build the event-code table from what *this* device advertises;
3. fall back to a curated static table (with a `unknown_code` pass-through that keeps
   the raw event rather than dropping it) only for codes the capability response
   doesn't enumerate.

We will not guess which minor is "face pass" and "card pass" on the DS-K1T341AMF-S. We'll
read it from the device and record the observed mapping in `docs/OBSERVED.md` after the
first live smoke run, with the raw capability JSON attached.

`maxResults` in particular: some models advertise 10, others 30/100+. We clamp to the
advertised max and never assume — sending more is silently clamped on some firmware,
`badParameters` on others.

## Event model (normalized)

```
site                 str   config-level: 'site-a' — the agent knows its own site
device_serial        str   from deviceInfo, part of idempotency key
serial_no            int   device's own monotonic event counter, part of key.
                           Counts ALL events incl. noise → checkpoint on it device-wide
employee_no          str   employeeNoString (preferred; employeeNo is the int form and
                           truncates leading zeros / alphanumeric employee ids)
name                 str   display name as the device reports it (strip UserInfo
                           'password' hash key; never store it)
event_time_utc       datetime (tz-aware UTC)  — site-tz policy, see Time handling
event_time_local     str   verbatim device string, e.g. 2026-10-12T14:11:16+02:00
tz_offset_min_device int   the offset the device claimed (WRONG on site-a — audit only)
tz_source            enum  site-tz (primary) | unresolved
tz_offset_mismatch   bool  device offset ≠ site offset at that instant (flag, don't fix)
direction            enum  in | out | unknown   — derived, see below
attendance_status    str   device's own attendanceStatus if non-null (site-a: always null)
direction_source     enum  device | inferred | none
verify_mode          str   currentVerifyMode verbatim (on this fw: 'cardOrFaceOrFp' for
                           every real pass — it does NOT distinguish face vs card;
                           'invalid' on door/noise events — no silent normalisation)
major / minor        int   raw codes, always kept
outcome              enum  granted | denied | info   (info = noise/door/button/unknown)
raw                  json  the untouched device record
```

**Noise filter is part of the contract:** site-a logs `major=3,minor=1029` every
minute on the minute (10,169 of 10,199 events — a remote-op/cloud heartbeat). Only
`major=5, outcome=granted, employee_no present` (minor 75 here; 38 card-pass if it ever
appears) are punch candidates. Everything is still *stored* (raw + flags); filtering is
a query-time property, so a misclassification never loses data.

Idempotency key = `(device_serial, serial_no)`. `UPSERT` on it, so re-polling an overlap
window is free — which is how we heal a crash mid-page or a device clock step.
Secondary guard: `(employee_no, event_time_local, minor)` dedupe for devices whose
`serialNo` resets after a firmware upgrade / log clear.

### in/out: the two real options (device probe settled the first one — see OBSERVED.md)

Observed on site-a: the `attendanceStatus` field exists in the record schema but is
**null on every event** — the terminal is in pure access-control mode. So today every
punch arrives direction-less. Two ways to get direction, both planned-for:

**Option A — turn on attendance mode on the device(s) (recommended, owner decision).**
Device UI: attendance mode + attendance plan, then `attendanceStatus` comes back
`checkIn`/`checkOut` on every pass and direction is ground truth from the terminal.
- + Correct in/out semantics per employee, handles re-entry the way HR expects.
- + Zero inference logic to defend; our output stays `direction_source=device`.
- − It's a device **write** (web UI, maintenance window, per site) — never via this
  connector; it also changes door behaviour (attendance plan gates the relay), so it
  needs a test pass at the door with the people who use it.
- − Historical events (before the switch) stay direction-less forever.

**Option B — infer from passes, in the consumer (BC/P3), never silently here.**
Connector keeps `direction=unknown, direction_source=none`; P3 derives per
(site, employee, local-day): first granted pass = in, last granted pass = out.
- + No device change; works with the existing 10k-event history.
- − Only a *span*, not worked hours: mid-day exits/re-entries are invisible, someone
  who badges in once and forgets to badge out gets a one-punch day, and night-shift
  days need a day-boundary rule (e.g. 05:00 local) agreed with HR.
- − The inference has to live *somewhere* anyway; baking it into BC keeps this
  connector honest (it only reports what the device said) but makes the BC side own
  the ambiguity.
- Variant B2 (alternate in/out strictly) is **rejected**: it turns every forgotten
  badge-out into a fake overnight shift.

Whichever is chosen is recorded per event in `direction_source`
(`device | inferred | none`) so a mixed history (site switched mid-year) stays
auditable. Until a decision: **Option B semantics, direction=unknown in our store** —
this connector will not write an inferred direction into the record.

## Paging + checkpoint

Verified against site-a (OBSERVED.md): `searchResultPosition` is **0-based**; advance
by `numOfMatches`; terminate when `responseStatusStrg` normalized (`.upper().replace(
" ","").replace("_","")`) ∉ {`MORE`} — note the empty-window value is **`"NO MATCH"`
with a space**, so raw `== "NO_MATCHES"` comparisons are wrong; and the empty response
has **no `InfoList` key at all** (not an empty list). `totalMatches` (30 = our full
major=5 history, 10,199 = all) is advisory — never a loop bound. `searchID` stable
across pages of one logical search (≤64 chars on this fw), fresh uuid per new search.
`timeReverseOrder:true` honored (newest-first). `AcsEvent/Total` is **not supported**
on this fw (`400 notSupport`) — don't implement it.

`maxResults` clamped to the capability (`@max=30` on site-a); we request 30 and never
more. Inter-page delay 100 ms default.

Checkpoint = `(last_serial_no, last_event_time_local)` where `serial_no` counts **all**
events (the noise major=3 shares the counter — proven by serials 5742..5753 interleaved
with punches), so checkpointing on max serialNo device-wide is sound even while
filtering noise out of results. Next poll window: `[last_event_time_local - overlap,
now_device_wall]`, `overlap` default 5 min, `UPSERT` on `(device_serial, serial_no)`
makes the re-read free. Windows chunked (default 1 day — the full 7-month window works
on this fw too, but chunking bounds a mid-search failure) and **always** with
`startTime`/`endTime` + offsets. Times sent to the device must be in **device-wall
terms** (it filters on its own naive clock), and given the offset bug that means:
derive the query window in site-tz wall time, stamp the device's claimed offset on it —
test this round-trip with a fixture, it's the subtle one. Never send `picEnable:true`.

## Time handling (the part that matters for payroll)

**Verified on site-a (OBSERVED.md): the device stamps the wrong offset.** `localTime`
came back `2026-10-15T16:39:32+02:00` at real wall time 16:39 **+03:00** — the tz rule
`CST-2:00:00DST01:00:00,M3.4.1/00:00:00,M10.5.0/23:00:00` never engages DST. Wall clock
is fine; the label on it is not. So the device's self-reported offset is **never
trusted**:

> Note on the common advice ("trust the payload's own offset, quarantine naive") —
> it's the right general rule, and it is *wrong for this device*: the offset is
> present, well-formed, and off by an hour half the year. We deviate **because we
> measured it** (device wall vs NTP-disciplined clock at probe time), not as a guess.
> Research confirms the general hazard zoo: Hikvision emits at least three
> incompatible tz encodings, some fw stamp `+00:00` on local time, `Etc/GMT-2` carries
> the POSIX-inverted sign (it means UTC+2 — "fixing" the sign breaks the clock), and
> Bucharest flips +02/+03 (the naive "Romania=+2" is wrong ~8 months a year). Site-tz +
> wall clock is immune to all of it *provided the wall clock itself is right* — hence
> the skew monitor below.

1. **Primary policy:** take the naive wall-clock part of the timestamp
   (`YYYY-MM-DDTHH:MM:SS`) and interpret it in the **site timezone from config**
   (`Europe/Bucharest` → zoneinfo → correct ±03:00/±02:00 incl. real DST rules) → UTC.
   Applies whether the string carries an offset or not.
2. Keep the raw string verbatim + the device's claimed offset
   (`tz_offset_min_device`) for audit; set `tz_offset_mismatch=true` whenever
   device-offset ≠ site-offset-at-that-instant (in summer: always, until the device
   tz/NTP is fixed by the owner — a device write, not ours). If the owner later fixes
   the device, the flag stops firing and the math doesn't change — that's the point.
3. Naive string (no offset at all) → same site-tz path, `tz_source=site-tz`.
4. Site tz missing/unresolvable → store raw, `tz_unresolved=true`, alert. Never
   silently assume UTC.
5. Hikvision tz dialect (`GTB Standard Time`, `Etc/GMT-2` with POSIX-inverted sign,
   `CST-2:00:00DST…` POSIX rules) lives in a validator/parser table for *diagnostics
   only* (explain what the device thinks) — never in the UTC math. Config stores IANA
   names per site, nothing derived from these strings.

We also record `device_clock_skew` (device `System/time` wall part vs our clock) per
poll. Skew over a threshold is a log line, not an auto-fix — setting device time is a
write. NTP config on the device is likewise the owner's call (its DST bug would survive
NTP anyway; only the tz rule is wrong).

## Failure modes we design for

- **401 storms / nonce expiry**: digest nonce goes stale (`stale="true"`); retry the
  request once after re-auth. Persistent 401 with right creds = lockout risk: Hikvision
  terminals lock an account after repeated failures, so max 1 retry per request and no
  retry loop on 401 — surface it and stop. (Real risk at 3 sites: a wrong password in a
  deployed agent locks the admin account nobody can then use at the door.)
- **Throttling**: these devices have a small concurrent-session limit and prefer serial
  requests. P1 is single-connection, serial, with a small inter-page delay (default
  100 ms) and backoff on `deviceBusy` / `activeOperator` / `invalidOperation`.
- **`Invalid Content` / `badParameters`**: almost always our request shape, not the
  device's. Include the request body verbatim in the error we raise.
- **Half-open TCP**: the device drops idle keep-alives; set an explicit read timeout
  (default 30 s) and `Connection: close` rather than pooling aggressively to a box that
  will RST us.
- **Encrypted person data**: RESOLVED for site-a — the 2026-10-15 probe returned plain
  readable names + `employeeNoString` "1".."4" (no `security=1&iv=` blob scheme in play).
  Keep the `encrypted_person_data` flag in the model: sites B/C (or a firmware change)
  could still enable it, and if blobs appear the connector must detect (high-entropy
  no-space strings in `name`) and flag rather than store garbage as a name.
- **macOS Local Network permission (TCC)**: on this Mac, *curl* reaches the LAN fine but
  plain *python* gets `[Errno 65] No route to host` — macOS gates per-app. The CLI must
  surface this exact case with a pointer ("grant Local Network to your terminal app")
  instead of a generic connect error; the P2 site agent on Linux/Windows won't have it.
- **TLS / port map (corrected by research)**: ISAPI lives on **80 (HTTP) and 443
  (HTTPS, self-signed)**. **8000 is Hikvision's private SDK protocol port, not HTTPS** —
  `https://device:8000/ISAPI` failing a TLS handshake is expected behaviour, not a bug
  (554 = RTSP). P1 stays HTTP:80 on the LAN. If we ever move to TLS: pin the device
  cert into our own CA bundle (`verify=/path/hik-ca.pem`) — note httpx `verify=False`
  disables `CERT_REQUIRED` **and** `check_hostname` together, so it's full MITM
  exposure, not a small exemption. Never a fail-open env toggle.
- **Error envelopes come in three shapes** (research, matches our 401-XML observation):
  canonical XML `<ResponseStatus statusCode>`; JSON flat `{"statusCode":…}` **without**
  the wrapper (and int vs string flips between formats); and auth/lock replies as
  `<userCheck><statusValue>` — `statusValue` is NOT `statusCode`. Parse: sniff first
  byte (`{`/`[`) else XML, accept both field names, strip namespaces (live samples use
  4 different xmlns). Retry classes: HTTP 503/`statusCode 2` (deviceBusy family) →
  backoff 1→30s ≈6 tries; `3` once then alert; `4/5/6` (badParameters, notSupport,
  badXmlFormat…) terminal — our request is wrong, retrying turns polling into lockout.
- **Account lockout is machine-readable**: the 401 body carries
  `<lockStatus>/<unlockTime>/<retryLoginTime>` — parse them and circuit-open for
  `unlockTime + margin` instead of hardcoding folklore ("~5 tries/30 min"). Digest
  gotchas that bind the client: `uri=` in the digest must include `?format=json`
  (path-only HA2 = infinite 401 loop with a correct password); one `httpx.DigestAuth`
  per thread, never shared (unlocked state); pin the httpx version (PR #2463 broke
  digest for HA users); never shell out to `curl --digest` from the client (argv
  leak + no structured errors).
- **`maxResults` is SILENTLY clamped** to the capability when oversized (vendor text) —
  so cursor arithmetic must use the returned `numOfMatches`, never the requested
  page size. (Our paging rule already does this; keep it.)

## Credential plumbing

Config (`sites.toml`, committed — hosts are not secret, passwords never appear):

```toml
[[site]]
name = "site-a"
host = "192.0.2.10"
port = 80
iana_tz = "Europe/Bucharest"
isapi_user = "admin"                      # overridable; keychain comment also carries user=
keychain_service = "gateclerk-hikvision"    # macOS; = account is the host
```

New sites = one more block; the keychain account is the host (`security
find-generic-password -s gateclerk-hikvision -a <host>`), so `security add-generic-password
-s gateclerk-hikvision -a <ip> -U` plugs site B/C in identically. Resolution order:
`--user/--password` flags (debug only, discouraged) → env (`GATECLERK_<HOST>_USER/_PASSWORD`)
→ Keychain. The client receives a credential *callable*, never a baked-in source.
`.env` stays gitignored; `docs/` and fixtures must never contain a real password,
nonce, serial or employee name (fixtures mask them — see tests/fixtures/README).

## Testing

- **Unit tests against recorded fixtures — CI never touches a device.** A `FakeDevice`
  transport serves canned JSON (incl. the digest 401 challenge, multi-page `MORE`
  sequences, `Invalid Content` errors, naive-vs-offset timestamps, encrypted-name
  blobs) so paging, retry, idempotency, tz and classification logic are all covered
  offline. Fixtures are recorded responses with creds stripped.
- **Property-ish tests** for the tz resolver (every Hik tz dialect string → a
  deterministic offset) and for the `MORE`/`OK`/`NO_MATCHES` paging termination.
- **Live smoke tests, opt-in, run by a human only**: `pytest -m live`, skipped by
  default, guarded by an explicit `GATECLERK_LIVE=1` env so a stray CI run or an agent
  can never hit the device by accident.

## Open questions

1. **P3 / BC — OUT OF SCOPE (owner, 2026-10-15) until P1 is proven on the real
  device.** No design, no cards, no ingestion/auth/mapping work. Kept as a question
  only, for when it becomes in-scope: which BC table/page + fields receive a punch, and
  who owns the `employeeNoString` (auto-assigned "1".."4" on site-a, so not BC-safe) →
  BC employee mapping. Answering it is the owner's go-signal, not a task.
2. **Attendance mode** — device-confirmed null today → see "in/out: the two real
  options" above (A = owner enables attendance mode per site, recommended; B = infer in
  BC). Owner decision, per site, with a door-side test pass. Not blocking P1.
3. **Site identity** — `site` is agent config today (`site-a`...). Once a punch joins to
  a BC location code we need the canonical mapping. Same owner question as (1).
4. **Retention / gaps** — partially answered by probe: oldest retained event is
   serial 27 @ 2026-05-21 (device started counting ~then; no rolling observed in ~5
   months of history). BUT site-a's noise stream runs 1/min ≈ 1,440 events/day, so
   whatever the real ring capacity is, noise will dominate it. **Operational
   consequence:** the agent must record oldest-serialNo per poll (a monotonic increase
   of the minimum = rolling started = punches are being lost) and the owner should kill
   the noise source at its client (looks like a Hik-Connect/remote poll — device-side
   config is off-limits to us, but the *polling* client is theirs to stop). Poll
   interval must be minutes, not days.
5. **Multi-reader ambiguity** — one device per door means one direction signal per door.
  If a site ends up with a reader on each side of the same door, `direction` may need to
  come from the reader/door number rather than `attendanceStatus`. Worth confirming now.
6. **Realtime** — is sub-minute latency ever a requirement (e.g. a live "who's in the
  office" board)? If not, polling stays the right choice. If yes, `alertStream` as an
  add-on, poll still the source of truth for completeness.
7. **Device tz fix (owner, optional)** — the DST rule on site-a never engages (+02:00 in
  summer). We're immune (site-tz policy) but every query-window we send is in the
  device's naive-wall terms; if the owner fixes tz/NTP later, our UTC math is unchanged
  and `tz_offset_mismatch` stops firing. Worth fixing anyway so the web UI logs read
  sanely during incident triage.

## Phase plan

**P1 — connector + CLI (now).** `uv` + py3.12 package. ISAPI client (digest, timeouts,
bounded retries, capability discovery), `gateclerk device info`, `gateclerk device time`,
`gateclerk users list`, `gateclerk events --since/--until` (paged + checkpointed), `json`/
`table` output, offline unit tests on fixtures, one opt-in live smoke suite.
Exit: reads a full day of punches off `192.0.2.10`, correct UTC, idempotent re-run
adds zero rows, `docs/OBSERVED.md` records the real event-code table.

**P2 — site agent + local store (SKETCH ONLY — not scheduled, not carded).** Listed
so P1's seams stay honest; becomes cards only after P1 is demonstrated working on
site-a: sqlite store keyed `(device_serial, serial_no)`, checkpoint + overlap,
systemd/launchd unit, outbound pusher with retry + dead-letter, config for N devices
per site (3 sites = 1 codebase + 3 configs, not 3 forks), `/healthz`, metrics, alerts
on clock skew and auth failure. Optional `alertStream` later.

**P3 — Business Central side (OUT OF SCOPE, owner-decided).** No design and no cards
until the owner has seen P1 working end-to-end on the real device. The only artifact
kept anywhere is open question 1. P1's entire job is making the raw side boring and
trustworthy — nothing beyond it is ours to pre-decide.
