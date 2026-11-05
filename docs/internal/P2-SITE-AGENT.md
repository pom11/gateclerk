# P2 — site agent: decision spec (docs only)

STATUS: **SIGNED OFF — decided 2026-10-19 (owner, via review).** All seams (a)–(f)
are decided AS RECOMMENDED (see §6 checklist); P2 is now scheduled and carded on the
gateclerk board, and the recommendations below are BINDING for P2 cards. Rollout order
(owner, same review): site-a (the proven box) first as canary, ≥7 days clean (no checkpoint
stall, no terminal 401, tz_offset_mismatch warning-count 0, site_labeled_windows 0),
then sites B and C ONE AT A TIME, each gated on a read-only §5 probe card that first
needs the operator's host + keychain item. Push target stays ABSTRACT: cards build
against a local stub ingest + JSONL — never invent a real endpoint. Where this file and
docs/OBSERVED.md disagree about device behaviour, OBSERVED.md wins (it was read off
the box). Every device-behaviour claim below cites OBSERVED.md or DESIGN.md — no
invented device facts.

## 1. Fixed seams (restated; rationale in one line each)

These are DESIGN.md decisions P1 already honored; the list exists so a P2 card can
never quietly re-open one.

1. **sqlite store keyed `(device_serial, serial_no)`, UPSERT semantics** — re-polling
   an overlap window must be free, which is how a crash mid-page heals
   (DESIGN.md "Event model": idempotency key + `model.idempotency_key_hash`).
2. **Checkpoint = `max(serialNo)` device-wide, advanced only over completed chunks**
   — the noise stream shares the serial counter (OBSERVED.md "Event log census":
   serials 5742..5753 interleave with punches), and paging.py only hands the caller
   `ChunkResult.max_serial_no` for *completed* chunks (paging.py:612-615), so a
   half-failed walk cannot skip events.
3. **Overlap window on every poll** — `[checkpoint_time − overlap, now]`; with the
   UPSERT key this is the gap-healer after clock steps or mid-page crashes
   (DESIGN.md "Paging + checkpoint", overlap default 5 min).
4. **Poll + outbound push only; no inbound ports, no site VPN** — three devices on
   three networks; the agent dials out (DESIGN.md "Architecture").
5. **N devices per site = 1 codebase + configs, never forks** — sites are data
   (`[[site]]` blocks, config.py), not branches (DESIGN.md "Phase plan" P2 line).
6. **Reuse the P1 modules; do not fork them** — `isapi_transport` (digest session,
   busy backoff, 401 circuit, bounded nonce-retirement recovery), `config`'s
   credential *callable* seam (config.py:13-16 — explicitly built for P2 to hand it
   a systemd-credential provider), `paging` (`window_for_device`, cursor rules),
   `model.RECORD_JSON_KEYS` (the frozen 27-key contract, stored verbatim).
7. **Windows go out site-wall digits labeled with the device's claimed offset** —
   the A/B proved the device does offset arithmetic; a site-labeled window silently
   loses boundary events (OBSERVED.md "Window offsets are ARITHMETIC"). The
   site-labeled fallback stays allowed only with the p1-05c warning (pipeline.py
   `_warn_site_labeled`), never naive (OBSERVED.md "offset REQUIRED": naive → 400).
8. **Read-only invariant carries over** — only GETs + the search POSTs in
   `endpoints.SEARCH_ENDPOINTS`; any device write (tz fix, attendance mode, killing
   the noise source) stays the owner's, never the agent's (DESIGN.md "Constraints").
9. **Never hammer** — one retry per request on 401, circuit-open on terminal auth,
   busy-family backoff 1→30 s (DESIGN.md "Failure modes"; OBSERVED.md "lockout
   accounting": wrong-shape 401s count against lockout).

## 2. Open questions — the owner decides each

Format: options, then **Recommendation**. P2 gets scheduled only after (a)–(f) are
marked decided (edit this file or comment on the card).

### (a) Scheduler cadence + overlap, given the ~190-request nonce use-cap

The device retires a digest nonce after ≈190 uses (OBSERVED.md "Digest nonce
use-cap", observed at the ~190th request on site-a fw V3.2.30). Cadence must not
*force* a fresh challenge per pull.

Request math per device (site-a-shaped traffic: noise ≈1/min when firing,
punches tens/day — OBSERVED.md "Event log census"):

```
cadence 5 min → 288 cycles/day; each window (5-min + 5-min overlap) is ~10-20
events → 1 page of 30 → ~1 POST per cycle (+1 every time a page fills)
→ ≈ 300-600 requests/day → nonce retirement every ~8-16 h of wall time.
```

Retirement is therefore **routine at any minutes-scale cadence, not an incident** —
and the shipped recovery (budget 1 per logical call, streak ≤2; isapi_transport.py,
FINDINGS-t_a3521d8a F1/F2) already fits, because a 200 always lands between
retirements.

- Options: cadence 1 / 5 / 15 min; overlap 5 min (DESIGN default) / 15 min / 1 h.
- **Recommendation: 5 min cadence, 5 min overlap** (DESIGN open question 4: "Poll
  interval must be minutes, not days", because noise dominates the device ring).
  One long-lived `IsapiClient` **per device** kept alive across cycles so digest
  state amortizes — rebuilding the client per poll would pay 2 requests per pull
  (401+replay) and hit the cap ~3× faster. `auth_recoveries` is an info counter,
  never an alert (see (e)).

### (b) sqlite growth/retention, and what the dead-letter holds

Growth, worst case (noise 1,440/day + punches, ≈0.5–1 KB/row with `raw`):
**≈1–1.5 MB/day ≈ 0.4–0.5 GB/year per device** — bounded and fine on any agent box.
Honest note: OBSERVED.md's *census* averages ~70 events/day over ~5 months while its
probe found noise firing every minute; size for the worst case, observe the real
rate via `events_per_day` (see (e)).

- Store options: (i) keep everything forever incl. noise `raw` (DESIGN.md "Event
  model": "Everything is still stored… filtering is a query-time property");
  (ii) drop `raw` past N days; (iii) purge noise rows past N days. (ii)/(iii)
  relax "we never discard the raw" (DESIGN.md "Constraints") → owner's call.
- **Recommendation: (i) keep-everything, plus a disk-watermark alert** (e.g. db
  > 2 GB → warning). Revisit only with growth evidence. Purging must never touch
  the checkpoint or the UNIQUE key columns.
- Dead-letter: **recommend a table in the same sqlite db**, not a side file, one
  row per failed push holding: the complete JSONL payload line (a
  `model.EventRecord.to_jsonl()` line is self-contained — normalized fields + `raw`
  + both key digests), target endpoint tag, error class, attempt count,
  first/last-attempt timestamps. Replay = re-push existing rows; UPSERT makes it
  safe. Rows are deleted only by an owner-run command.

### (c) Pusher backoff; alerting on auth-fail vs lockout

Two different failure channels — keep them separate:

- **Pusher → ingest endpoint** (our side, ordinary internet): exponential backoff
  with cap + jitter (reuse the busy-family numbers as defaults: base 1 s, cap
  30 s; isapi_transport.py), queue in sqlite meanwhile, dead-letter after a bound
  (recommend: 24 h of continuous failure → dead-letter the batch, keep retrying
  the queue at cap).
- **Agent → device** (the sacred one): device-side lockout accounting is real
  (OBSERVED.md "lockout accounting"; DESIGN.md "Failure modes": "a wrong password
  in a deployed agent locks the admin account nobody can then use at the door").
  The shipped rule — max 1 retry on 401, circuit-open for `unlockTime + margin`
  parsed from the 401 body — carries over unchanged.
- **Alert semantics (recommendation):**
  - terminal 401 *with* a challenge (wrong/rotated creds) → **critical page**, and
    the device loop **parks** (no automatic re-probe under a few minutes; slow
    re-probe e.g. every 30 min only after operator acknowledgement — options:
    park-forever vs slow re-probe; recommend slow re-probe so a transient creds
    rotation self-heals without a site visit).
  - 401 body says `lockStatus=lock` → **critical page + operator on site**; the
    circuit already waits out `unlockTime` (never present creds while locked —
    FINDINGS-t_a3521d8a F3).
  - nonce recoveries → **not an alert at all** (routine per (a); a growing
    counter is a metric line).
  - clock skew over threshold → warning (DESIGN.md "Time handling": log, not
    auto-fix; `tz.compute_skew` + `SKEW_WARN_SECONDS` carry over).
  - checkpoint stall / oldest-seen serialNo rising → **critical**: the ring has
    started rolling and punches are being lost (DESIGN.md open question 4).

### (d) How the three site configs differ (1 codebase + 3 configs)

A site block adds exactly what DESIGN.md "Credential plumbing" already defines:
`name`, `host`, `port`, `iana_tz`, `isapi_user`, credential **reference** — plus
P2's per-site extras. Deltas per site:

- `iana_tz`: required, never defaulted — config.py's `DEFAULT_IANA_TZ =
  "Europe/Bucharest"` is a *site-a* value; a P2 config validator should refuse a
  site block without an explicit IANA zone (site tz is payroll truth, DESIGN.md
  "Time handling" 1).
- device list: one entry per device (host/port/creds ref); N devices share the
  site's tz and push target.
- credential ref per device: no secrets in configs anywhere. macOS dev box keeps
  keychain (`-s gateclerk-hikvision -a <host>`); agent hosts (Linux/Windows —
  DESIGN.md TCC note) use the credential callable seam: systemd `LoadCredential=`
  unit-per-site (`gateclerk-agent@<site>.service`), naming convention
  `gateclerk-<site>-<host>`, or the existing `GATECLERK_<HOST>_PASSWORD` env — the
  resolver picks by ref scheme; configs carry refs only.
- push target URL + site label: per site (the ingest endpoint learns the site from
  the record's `site` field, which is config-level per DESIGN.md "Event model").

### (e) `/healthz` + metrics vocabulary

Recommend the smallest vocabulary that maps 1:1 to P1 observables (no dashboard,
no new concepts):

- `/healthz` (liveness/readiness): ok/degraded + agent version + per-device
  `last_poll_ok_age_s` + circuit state + dead-letter depth. No secrets, no hosts
  beyond site label.
- metrics (counters/gauges, snake_case carrying P1 names):
  `auth_recoveries` (IsapiClient counter, info), `auth_terminal_failures`,
  `device_locked_events`, `circuit_open_gauge`, `tz_offset_mismatch` count
  (per-record flag, pipeline.py:463) + the once-per-run warning (p1-06c),
  `site_labeled_windows` (p1-05c risky-fallback count — should be ~0),
  `device_clock_skew_seconds` (gauges from `compute_skew`), `pages_fetched` /
  `records_stored` / `search_termination` (per `SearchSummary`, paging.py:351),
  `checkpoint_serial`, `oldest_serial` (rolling detector per DESIGN.md OQ4),
  `events_per_day` (feeds (b) sizing), `push_ok/push_failed/dead_letter_depth`,
  `db_size_bytes`.
- Which P1 observables carry over is a *decision*: **recommend all of the above** —
  every one already exists as a value P1 logs or counts; P2 only persists them.

### (f) `alertStream`: deferred or not

**Recommendation: DEFER — do not build in P2.** Reasons, all on-record:

1. Poll + checkpoint already guarantees completeness; alertStream is a latency
   optimisation on top, never a replacement (DESIGN.md "Architecture").
2. Wiring it needs device-side config (`/ISAPI/Event/notification/httpHosts` is a
   write — references/acs-event-codes.md §1.4 names it as the push route) and
   device writes are owner-only, out-of-scope to this repo (DESIGN.md "Constraints").
3. Nobody has asked for sub-minute latency: DESIGN.md open question 6 is still
   unanswered, and with `attendanceStatus` null (OBSERVED.md) there is no
   direction-aware consumer that could use a hot stream today.
4. It adds a long-lived second connection per device — more digest/auth surface
   against the ~190-use nonce cap (OBSERVED.md).
   Revisit trigger: owner answers DESIGN.md OQ6 "yes" (e.g. a live occupancy board).

## 3. NON-GOALS (explicit)

- **No Business Central / P3 integration design** — out of scope, owner's call
  (DESIGN.md "Open questions" 1 + "Phase plan" P3). The pusher's target is an
  abstract ingest endpoint; what lives behind it is not ours.
- **No UI / dashboard** — `/healthz` + metrics text only.
- **No multi-site orchestration daemon** — agents are independent; only the
  ingest endpoint sees all sites.
- No device writes of any kind (tz/NTP fix, attendance mode, noise-source kill —
  all owner-side).
- No TLS migration for the device leg (HTTP:80 on the LAN per DESIGN.md "Failure
  modes"); the push leg is ordinary HTTPS to our own endpoint.

## 4. What P1 proved, so P2 can lean on it

- Offset-bearing windows are mandatory; naive `startTime` → HTTP 400 (OBSERVED.md
  "offset REQUIRED", live 2026-10-17).
- Window labels are **arithmetic** on the device; site-wall digits labeled with the
  device's claimed offset is the only shape that doesn't lose boundary events
  (OBSERVED.md "ARITHMETIC", A/B + live dense-window pass: 20 vs 0, PROGRESS.md
  2026-10-18 night).
- `serialNo` is device-wide monotonic (noise interleaves) → checkpoint on it is
  sound (OBSERVED.md "Event log census").
- Paging contract verified: 0-based position, advance by returned `numOfMatches`
  (maxResults is silently clamped), `"NO MATCH"`-with-space, missing `InfoList`
  ≠ error (OBSERVED.md "Paging envelope").
- Nonce use-cap ~190 requests; challenge-less-401 recovery is offline-proven in
  all three shapes with hard budgets (OBSERVED.md + FINDINGS-t_a3521d8a F1–F4).
- Lockout is machine-readable (`lockStatus`/`unlockTime`/`retryLoginTime`) and the
  circuit respects it (DESIGN.md "Failure modes"; shipped in transport).
- The 27-key record contract round-trips, keys are published as stable digests,
  and JSONL is the push payload format (model.py; DESIGN.md "Event model").
- Credential plumbing is a callable seam with flag>env>keychain precedence — the
  P2 provider plugs in without touching ISAPI code (config.py).
- Client-side filtering is mandatory: `employeeNo`/`eventAttribute` are silently
  ignored on this fw — trust only probed server filters (OBSERVED.md "filter truth").
- Offline test discipline: FakeDevice must be as strict as the device (a lenient
  mock = false-green machine; OBSERVED.md consequence 1).

## 5. What P1 did NOT prove / needs a live check per site

- The nonce cap's exact value per firmware (≈190 is site-a/V3.2.30, observed not
  modeled; **the recovery arm has never fired live** — OBSERVED.md honest caveat).
- Dense-window acceptance at sites B/C (the payroll-critical A/B was proven on
  site-a's one dense day only).
- `maxResults` cap per device (30 is site-a's advertised max; read each device's
  capabilities first — that is the P1 capability-cache rule).
- Sites B/C firmware family entirely: XML-despite-json on System/*, tz dialect,
  noise stream presence/rate, `AcsEvent/Total` absence, silent clamps — all are
  site-a observations; probe before believing (OBSERVED.md header).
- Encrypted person data (resolved plaintext on site-a; B/C or a fw change could
  still flip it — model keeps the flag).
- `serialNo` reset behaviour after fw upgrade / log clear (the fingerprint
  secondary guard is untested live).
- Whether the device counts our polling against lockout under stress — never
  hammer; debug offline (OBSERVED.md reproduction discipline).
- Each site LAN's egress rules for outbound HTTPS push (DESIGN.md Architecture
  assumes outbound; unverified per site).
- Concurrent-session behaviour when the owner's Hik-Connect/remote client polls
  the same device as the agent (the 1/min noise source; DESIGN.md OQ4).

## 6. Decision checklist (owner)

| Seam | Question | Recommendation | Decided? |
|---|---|---|---|
| (a) | cadence + overlap | 5 min / 5 min; long-lived client per device | Decided 2026-10-19 (owner, via review) ✓ |
| (b) | retention + dead-letter | keep-everything + watermark; dead-letter = sqlite table w/ full JSONL payload | Decided 2026-10-19 (owner, via review) ✓ |
| (c) | pusher backoff + auth alerting | park-on-bad-creds w/ acked slow re-probe; lockout = critical + on-site; recoveries = info | Decided 2026-10-19 (owner, via review) ✓ |
| (d) | site config deltas | explicit `iana_tz` required; refs-only creds; `gateclerk-<site>-<host>` naming | Decided 2026-10-19 (owner, via review) ✓ |
| (e) | /healthz + metrics | carry over all listed P1 observables, minimal vocabulary | Decided 2026-10-19 (owner, via review) ✓ |
| (f) | alertStream | DEFER (reasons 1–4) | Decided 2026-10-19 (owner, via review) ✓ |
