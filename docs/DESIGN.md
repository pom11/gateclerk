# gateclerk — Hikvision attendance → Business Central

Goal: read punch events (who / when / in-or-out) off Hikvision access terminals and land
them in Business Central as timesheet data. `gateclerk` = time attendance (RO).

Status: **P1 — read-only connector to one device.** BC mapping is deliberately not
designed yet (open questions below).

## Constraints / invariants

- **Read-only.** Only `GET` and the two stateless search `POST`s
  (`UserInfo/Search`, `AcsEvent`). No `PUT`/`POST` that writes users, faces, cards,
  doors, schedules. No reboots/upgrades. Nothing in this repo may issue a mutating
  verb; enforced by a test that walks the client's endpoint table and asserts method
  ∈ {GET, search POSTs}. If we ever need a write path, it gets its own flag + its own
  review — not folded into the connector.
- **No credentials in the repo, ever.** `.env` is gitignored from commit 1 (already is).
  Device password comes from macOS Keychain (`security find-generic-password -s
  gateclerk-hikvision -a <host>`); for the site agents in P2 it comes from an env var or
  a systemd credential — the connector takes a *callable* that returns the password, so
  the credential source is never baked into the ISAPI code.
- **Timestamps are payroll data.** Every event keeps the device's original local string,
  the resolved UTC instant, and the device tz/offset we used to resolve it. We never
  discard the raw. If we can't resolve a timestamp unambiguously we store it and flag it,
  we don't guess.

## Architecture

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
| `/ISAPI/System/deviceInfo?format=json` | GET | model, serial, fw. Serial is part of the idempotency key. |
| `/ISAPI/System/time?format=json` | GET | device clock + tz; drift is our problem, not the device's |
| `/ISAPI/AccessControl/UserInfo/Search?format=json` | POST | employee roster, paged |
| `/ISAPI/AccessControl/AcsEvent?format=json` | POST | events, paged |
| `/ISAPI/AccessControl/AcsEvent/capabilities?format=json` | GET | **the important one** — see below |
| `/ISAPI/AccessControl/UserInfo/Count?format=json` | GET | sanity check on roster size |

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
serial_no            int   device's own monotonic event counter, part of key
employee_no          str   employeeNoString (preferred; employeeNo is the int form and
                           truncates leading zeros / alphanumeric employee ids)
name                 str   display name as the device reports it
event_time_utc       datetime (tz-aware UTC)  — what BC wants
event_time_local     str   verbatim device string, e.g. 2026-10-15T07:46:48+03:00
tz_offset_min        int   offset parsed out of the device string
direction            enum  in | out | unknown   — derived, see below
attendance_status    str   device's own attendanceStatus, if it sent one
verify_mode          str   currentVerifyMode: face / card / faceOrCard / … — device's
                           own vocabulary, kept verbatim, no silent normalisation
major / minor        int   raw codes, always kept
raw                  json  the untouched device record
```

Idempotency key = `(device_serial, serial_no)`. `UPSERT` on it, so re-polling an overlap
window is free — which is how we heal a crash mid-page or a device clock step.
Secondary guard: `(employee_no, event_time_local, minor)` dedupe for devices whose
`serialNo` resets after a firmware upgrade / log clear.

### in/out: device says it, or we infer it — and we tell you which

`attendanceStatus` (`checkIn` / `checkOut`) **does exist** in the AcsEvent record on this
firmware family, and it's confirmed present on a DS-K1T341AMF specifically in a field
report. But it is only populated when the terminal is configured in attendance mode with
an attendance plan; in pure access-control mode it's absent and every punch arrives
`unknown`. So the rule is:

- `attendanceStatus` present → use it. `direction` = device's answer. `source=device`.
- absent → we don't invent a direction. `direction=unknown`, `source=none`, and the
  consumer (BC, P3) decides: a day's first/last punch per person per site is a
  reasonable span but *not* worked hours, and we refuse to pretend otherwise in the data.
- A `timeReverseOrder`/`major=5,minor=0` query returns *everything* including door-forced,
  exit-button, invalid-card and remote-unlock events. The connector classifies
  `outcome` ∈ {granted, denied, info} and only granted-auth events are punch
  candidates. Filtering this wrong is how you get ghost timesheet lines.

The **open question that decides P3**: get the terminals into attendance mode so
`attendanceStatus` is real (a device config change — needs a human, on purpose, in the
web UI, and it's out of P1's read-only scope), *or* accept first/last-inference in BC.
Recommend attendance mode: inference is lossy for anyone who badges out and back in.

## Paging + checkpoint

`searchResultPosition` is **0-based**; advance by `numOfMatches` from the previous
response. Loop until `responseStatusStrg != "MORE"` (values: `OK`, `MORE`, `NO_MATCHES`)
— do not use `totalMatches` as the loop bound, it's advisory and lies on some firmware.
`searchID` must be **stable across pages of one search** (device caches the cursor) but
**unique per new search**; we use a per-search uuid and reuse it for every page of it.

Checkpoint = `(last_serial_no, last_event_time_local)`. Next poll window:
`[last_event_time_local - overlap, now]`, `overlap` default 5 min. We re-read the overlap
and let the `UPSERT` de-dupe — cheaper than trusting a cursor that a device log rotation
can invalidate. Time window is chunked (`startTime`/`endTime`, default 1 day) because
large windows are the thing that makes these devices return `Invalid Content`.

Always send `startTime`+`endTime` even when querying "everything": at least one DS-K1T*
firmware returns `statusCode 6 / Invalid Content / badParameters` on a time-less query
while accepting the same query with bounds. Never send `picEnable: true` — we don't want
face snapshots of staff leaving on the wire or in a sqlite file.

## Time handling (the part that matters for payroll)

`AcsEvent.time` comes back **local-with-offset** in the observed reports
(`2026-10-15T07:46:48+03:00`), which is ideal — it's self-describing and DST-safe. But
some firmware returns naive local (`2026-10-15T07:46:48`) with no offset. Resolution:

1. offset in string → parse it, done. This is the expected path.
2. naive string → combine with the device tz from `GET /ISAPI/System/time`, which for a
   Romanian site should resolve to `Europe/Bucharest` (EEST/+03:00 in summer, EET/+02:00
   in winter — the offset flip happens in the string, so path 1 handles it automatically).
3. Hikvision tz strings are their own dialect (`GTB Standard Time` Windows names,
   `Etc/GMT-2`, `CST-8`, and `Etc/GMT-2` inverts sign vs POSIX) — we keep a small
   explicit mapping table validated against the device, never `str.replace("GMT","")`.
4. If we can't resolve → store raw, `tz_unresolved=true`, alert. Never silently assume UTC.

We also record `device_clock_skew` (device `System/time` vs our clock) per poll. Skew
over a threshold is a log line, not an auto-fix — setting device time is a write.

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
- **Encrypted person data**: some Hikvision deployments return `name`/`employeeNoString`
  as opaque encrypted blobs (`security=1&iv=…` scheme). If the first smoke run shows
  hex/base64-looking names instead of readable ones, that's this — it changes the whole
  employee-mapping approach and goes in the open questions.
- **Self-signed TLS on 443/8000**: P1 targets **HTTP:80** on the LAN, TLS deliberately
  out of scope (do not silently disable cert verification and call it done). Note the
  trade-off honestly: digest over plaintext HTTP on a trusted VLAN is acceptable for a
  read-only LAN poll; it is not acceptable if a site's LAN is untrusted. If we ever move
  to TLS we pin the device cert, we don't `verify=False`.

## Credential plumbing

- `security find-generic-password -s gateclerk-hikvision -a <device-ip>` → password;
  `-a` value = the device host. Comment field carries `user=admin`.
- CLI resolves credentials in order: explicit `--user/--password` flags (for one-off
  debugging, and we will *not* encourage it), then `GATECLERK_<HOST>_USER/PASSWORD` env,
  then macOS Keychain.
- `.env` stays gitignored; `docs/` and fixtures must never contain a real password,
  nonce, or a device serial that isn't already public.

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

1. **P3 / BC** — deferred on purpose, do not design until asked. Shape we already know
  we'll need: the BC table/page + fields for a punch, and how a Hikvision
  `employeeNoString` maps to the BC employee key (BC employee no.? payroll no.? a
  mapping table we maintain?). Device employee numbers look auto-assigned, so a manual
  or HR-driven mapping table is likely.
2. **Attendance mode** — can/should the three terminals be put in attendance mode (and
  are the attendance plans per-shift or per-person?) so `attendanceStatus` is real
  instead of inferred. Needs a human + a maintenance window. Read-only P1 can't and
  won't do it.
3. **Site identity** — `site` is agent config today. Fine for P1; once a punch must join
  to a BC location/site code we need the canonical mapping. Who owns it: IT or HR/BC?
4. **Retention / gaps** — how far back does the DS-K1T341AMF-S event buffer go before it
   rolls? Determines the size of the very first backfill pull and whether a site that's
   offline for a week silently loses punches.
5. **Multi-reader ambiguity** — one device per door means one direction signal per door.
  If a site ends up with a reader on each side of the same door, `direction` may need to
  come from the reader/door number rather than `attendanceStatus`. Worth confirming now.
6. **Realtime** — is sub-minute latency ever a requirement (e.g. a live "who's in the
  office" board)? If not, polling stays the right choice. If yes, `alertStream` as an
  add-on, poll still the source of truth for completeness.

## Phase plan

**P1 — connector + CLI (now).** `uv` + py3.12 package. ISAPI client (digest, timeouts,
bounded retries, capability discovery), `gateclerk device info`, `gateclerk device time`,
`gateclerk users list`, `gateclerk events --since/--until` (paged + checkpointed), `json`/
`table` output, offline unit tests on fixtures, one opt-in live smoke suite.
Exit: reads a full day of punches off `192.0.2.10`, correct UTC, idempotent re-run
adds zero rows, `docs/OBSERVED.md` records the real event-code table.

**P2 — site agent + local store.** sqlite store keyed `(device_serial, serial_no)`,
checkpoint + overlap, systemd/launchd unit, outbound pusher with retry + dead-letter,
config for N devices per site (the 3 sites are one codebase + 3 configs, not 3 forks),
`/healthz`, metrics, alerting on clock skew and auth failure. Optional `alertStream`.

**P3 — Business Central side.** Only after open Q1 is answered. Expect: an ingestion
endpoint + auth, an employee-mapping table, a BC AL extension or a direct API/batch
writer, and reconciliation (what happens to a punch that arrives after a timesheet is
approved). This is where the real ambiguity lives; P1's job is to make the raw side
boring and trustworthy so P3 has one clean input to design against.
