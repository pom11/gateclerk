# Progress

Short milestone notes for humans. (Board truth: `hermes kanban --board gateclerk list`;
device truth: docs/OBSERVED.md.)

## 2026-10-15 — P1 kickoff → mid-flight

- **P1-01 scaffold merged** (PR #1): uv/py3.12 package, `gateclerk` CLI stub, read-only
  endpoint registry + its guard test, offline CI (78 tests green, network-blocked).
- **Device probed (read-only) by orchestrator**: capabilities (maxResults≤30), paging
  envelope incl. `"NO MATCH"`-with-space + missing InfoList, `attendanceStatus` null on
  all 30 major=5 punches, noise = major=3/minor=1029 1×/min (10,169 of 10,199 events),
  `System/*` answers XML despite format=json, `AcsEvent/Total` not supported. **Time
  bug confirmed**: device stamps +02:00 during Bucharest summer; UTC math now uses
  site-tz policy (Europe/Bucharest), device offset kept as audit-only flag. All in
  docs/OBSERVED.md; 10 masked fixtures recorded for offline CI.
- **Owner scope-lock**: device side only. BC (P3) not designed/carded; P2 = sketch.
  Creds policy relaxed (private repo; keychain default, gitignored .env fine, no
  hygiene machinery).
- **Process rules**: subatomic cards (≤~100 lines, 1 module, minutes not hours);
  workers open PRs, gateclerk-orch reviews + merges, never worker-merge; orchestrator
  monitors board + per-branch git activity, reclaims/re-splits anything quiet 10 min.
- **Board state**: P1-06 (tz core) running but ballooned to ~1100 lines in one file →
  steered to prune+PR what it has; dialect/mismatch/resolver carved into p1-06b/c/d
  (atomic). p1-03/p1-07 held transiently to avoid file collisions with tz work.
  P1-02/04/05/08/09 queued in dependency order. P1-10 live smoke = human-only.

## Next expected
- P1-12 (device_tz mapping) gate + merge -> orchestrator live read-only re-run
  (2026-05-21 13:00-14:30, expect no warning + 20 records) -> tz axis closed.
- Owner decisions still pending: P2-00 spec sign-off (docs/P2-SITE-AGENT.md),
  3-site rollout order. BC/P3 stays closed.

## 2026-10-19 — P1-12 merged (PR #27 -> b2ca061) + live acceptance PASSED (mapping silences warning, records identical)

- Gate: 1150 passed / 5 skipped / 1 deselected merged-tree, ruff clean, CI green. My 4
  mutants all killed (neuter suppression return -> 7 red; ignore device_tz -> 7 red;
  always-declared keying -> 4 red; drop from _KNOWN_KEYS -> 14 red), restored clean.
- LIVE (orchestrator, read-only, on b2ca061): `--site site-a --config <scratch>` with
  device_tz=Europe/Bucharest. rc 0. chunk 13-14 NOMATCH/0; chunk 14-14:30 200 records=20
  OK max_serial=47. **stderr: ZERO tz warning lines**; stderr still shows
  `window_label=device-claimed +02:00` (p1-05c unchanged). Records byte-equivalent to
  owner's faa1f52 unmapped run: 20 rows serials 27..47, wall 14:08:22..14:20:04, UTC
  11:08:22+00:00 (site-tz math NOT moved). Provenance intact: tz_offset_mismatch=true
  20/20, claim 120 vs site 180. `device time` shows tz_mapped_via=Europe/Bucharest.
  Unmapped counterfactual = owner's own faa1f52 run (one warning line) -> switch proven
  both sides without extra device calls. Raw jsonl (names) stays in scratch, never in git.
- tz axis CLOSED. Note for owner: DESIGN.md:356 says sites.toml is committed + "hosts
  are not secret"; this repo is public — recommend keeping real-IP sites.toml local /
  committed config with placeholder hosts, or adding sites.toml to .gitignore. Your call.

## 2026-10-21 — E1 (enrollment migration) opened: canary skipped by operator, design v2 after dual adversarial review.

- Operator skipped P2-10 (site-a = bench device, 7 clean days prove nothing): all 3
  launchd jobs unloaded, plists kept in ~/gateclerk/launchd/, card closed with the
  P2-fix-A catch as its receipt. Canary re-arms for free if a real site appears.
- NEW FEATURE E1 — enrollment migration device↔device (first feature that WRITES):
  operator dropped the sign-off gate ("you own the design end to end"). Design doc
  docs/ENROLLMENT-MIGRATION.md v1 written FROM LIVE PROBES of bench A (read-only,
  ~15 requests total across 8 rounds): UserInfo/CardInfo search work (4 users, 0
  cards, record shape incl. RightPlan+Valid+password); UserInfoDetail/FingerPrint/
  PlanTemplate all notSupport on this fw; FDSearch rejects ~8 body shapes (R1, both
  face ends unconfirmed); no caps endpoint for max-counts on A. Two adversarial
  reviewer subagents (write-path correctness / ISAPI realism + fake strictness), both
  FIX-FIRST → v2: endpoint-confirmation MERGE gate (§5.0), freshness contract +
  fail-closed reads (TOCTOU — found independently by both), PINs never persisted to
  bundles, journal lifecycle planned→applied→confirmed with restore-before-delete
  undo, cross-device card-uniqueness + employeeNo-normalization conflict classes,
  timeType local-vs-UTC semantics, derived batch caps + explicit nonce-budget math,
  fail-closed unknown-field verify, byte-stability round-trip test. §11 logs what was
  applied vs rejected-with-reason.
- Next: E1-01 (bundle+export) + E1-03 (probe) dispatch; bench-A snapshot is the
  first live write-adjacent step; write code merges only after §5.0 captures.

## 2026-10-21 — Canary started (operator: orchestrator runs P2-10 itself). Live smoke found a real device bug.

- Operator unblocked P2-10 from human-run: the orchestrator now runs the site-a canary
  as launchd user agent `com.gateclerk.agent.site-a` (rendered from the shipped template:
  KeepAlive + Throttle 5, TZ=UTC, logs + state under ~/gateclerk/site-a,
  sites.toml local + chmod 600 OUTSIDE the repo, creds keychain rung only). Daily
  snapshot job `com.gateclerk.p2-10-snapshot` (07:05 local) reads health/agent.json +
  store, evaluates the four CLEAN criteria, and posts one comment on t_e6cdb2e9 per day
  (JSONL history in the state dir). Day-7 verdict `com.gateclerk.p2-10-verdict` (07:40,
  self-waiting until 7 snapshots exist) posts PASS/FAIL with every day quoted and
  completes/re-blocks the card. Tooling versioned in its own local repo ~/
  gateclerk (no remote; device host redacted from committed files). Two launchd teething
  bugs caught + fixed the same evening: first 07:05 run crashed FileNotFoundError
  'hermes' (launchd PATH is minimal -> absolute path), and the snapshot job now refuses
  to count a day while the agent job is not loaded (no phantom days during the fix wait).
- LIVE SMOKE caught what 1465 offline tests could not (FakeDevice accepts any
  startTime string): the agent's `now`-derived window carries microseconds and the
  device 400s them — `badJsonContent errorMsg=startTime` — while the byte-identical
  body WITHOUT microseconds is ACCEPTED (one read-only A/B POST each; the p1-05c
  +02:00 relabel itself was correct). CLI never hit this: operator windows are
  whole-minute strings. Fix card t_48c6dd44 (search_pair floors to whole seconds;
  FakeDevice gains the strictness so this class can't hide again). **Agent launch is
  blocked on that merge** — the launchd job is rendered and waiting. Tick failure was
  clean: checkpoint unmoved, zero loss, no 401 (400 = shape answer, not credential).
- Noted, not carded (owner's call later): tick_reports drops TickResult.error, so a
  failed tick is silent on stderr — the reason the 400 needed an in-process probe to
  name. Minor observability gap, no payroll risk (checkpoint/overlap semantics correct).

## 2026-10-21 — P2 CODE COMPLETE (PR #35 -> 32dbfd8). Board holds only the 3 HUMAN-RUN cards.

- PR #35 (agent CLI run|ack|deadletter + PushLedger) merged: gate 1465 passed / 5
  skipped / ruff / CI green. cli.py addition-only (existing commands byte-identical);
  clock seam used-not-re-derived (injected now; mutant leaking real clock -> red);
  lockout park = disk state across processes, second run refused with NOT even a
  credential presented (mutant bypassing P2-05 guarded_tick -> 3 red); PushLedger
  disclosed-new, poller-side only (P2-04/agent_db untouched, TEMP-table exclusion so
  the migration guard never sees it; mutant neutering the ledger -> 2 red). One
  non-blocking blemish flagged on the PR: a tautological assert line (dead, real pin
  below it) — polish-pass candidate, not worth a card.
- P2 code wave (01-07b, eight PRs #28..#35): config validator, store/checkpoint,
  scheduler, pusher/dead-letter, alerts/park, healthz/metrics, deploy templates +
  agent CLI. Every merge: my own full-suite gate on the merged tree + mutation probes
  (every owner-decision rule killed at least one mutant; at least 3 mutants per merge
  across all eight, every survivor re-anchored and re-killed — each time it was my
  anchor, not their test).
  Process hiccups owned on-record: P2-07 wedge at 9.7h -> reclaimed + split (07a/07b);
  one unverified merge sha I quoted and self-corrected.
- What remains is HUMAN, not code: **P2-10 site-a canary >=7 clean days** (run
  `gateclerk agent run --site site-a` per deploy/README; the four CLEAN metrics are on
  the card), then **P2-11 (site-B)** and **P2-12 (site-C)** probes — each blocked on
  YOU: device host + keychain item (`security add-generic-password -s
  gateclerk-hikvision -a <ip> -U`). Nothing dispatches without the operator; nothing
  left to build.
- Main: `32dbfd8`, 1465 tests green, ruff clean. P3/BC still out of scope (owner).

## 2026-10-20 — P2-07a templates merged (PR #34 -> 7a2553f); P2-07b queued for next slot

- 1429 passed / ruff / CI green; 4 files, zero runtime Python (pinned). Mutants:
  Restart=always directive dropped -> 1 red; LoadCredential naming broken -> 3 red;
  password= injected into README -> secret-scan pin red. Template catches its own
  trap: no --once under Restart=always (crash-loop). Salvage disclosure honest.
- Self-caught process error: I posted merge sha a58b5f5 unverified (nonexistent);
  corrected on-card with real sha 7a2553f. Rule holds: verify sha from git log BEFORE
  quoting it anywhere.

## 2026-10-20 — P2-06 merged (#33 -> 89e10d1); P2-07 STALLED 9.7h -> reclaimed + split (P2-07a/b running)

- PR #33 (healthz/metrics) merged: 1369 passed / ruff / CI green. Vocab contract =
  sorted-name set equality vs spec (rename mutant -> red); no-fabrication (events_per_day
  None; fabricate-0 mutant -> red); degraded real (neuter circuit-open -> red). 8-line
  agent_loop touch = additive TickResult.termination (accepted; only way to carry
  search_termination without re-walking).
- P2-07 (deploy+CLI) RECLAIMED after 9.7h: 0 commits; last write 18:47 (heartbeats
  alive = wedged, not dead); kanban log shows the loop: 20+ min re-deriving how to seed
  FakeDevice wall digits vs real now for `agent run --once`. Partial (agent_deploy.py
  1194L, templates, cli +261L) snapshotted to scratch/p2-07-partial/. Split:
  **P2-07a templates-only** (t_5253d2ba, no runtime code) + **P2-07b agent CLI**
  (t_ea27e604, clock seam PRE-DECIDED: injected now + wall = UTC + claimed, timebox +
  BLOCK-instead-of-loop). Both running; canary now gated on both halves.
- Lesson for cards: when a DoD test needs fake-clock coordination, the card must
  STATE the seam (worker re-deriving foundations = wedge). Also: 0-commit + live
  heartbeats + stale mtimes = wedged reasoning loop -> steer/reclaim at ~2h, not 9.

## 2026-10-19 — P2-05 alerts/park merged (PR #32 -> e5eddd4)

- 1345 passed / ruff / CI green. Lockout-safety core = attempt_allowed hard gate:
  unacked park -> NEVER allowed (grid absent, not long; served-count frozen across
  days; survives restart; cross-site park files refused). Acked -> grid starts at
  ack+1800s, success un-parks. lockStatus=lock -> CRITICAL device_locked, creds wait
  out unlockTime (F3). Nonce recoveries = counter only (monotone max). Mutants:
  hard-gate neuter -> 4 red, REPROBE->0 -> 1 red, recoveries-escalate -> pin red.
- P2-07 (deploy) stays todo, correctly gated: parents = P2-05 (done) + P2-06 (running).
  Auto-dispatches when #healthz lands. Main 1345 green.

## 2026-10-19 — P2 wave 2 merged: #30 (c0b8ba0) + #31 (9b7af27); 05/06 dispatched

- PR #30 (scheduler) merged first per owner: 1267 passed; ONE IsapiClient/device
  structural (handshakes==1 across many ticks, had_auth accounting); window =
  checkpoint-overlap pinned ON THE WIRE device-claimed-labelled; cold start =
  cadence+overlap; seam-7 only via WARNED site fallback (never naive); circuit-open
  skip = ZERO requests (never-hammer pin). Mutants: overlap-drop 3 red, skip-neuter 1
  red, completed-flag flip 8 red.
- PR #31 (pusher) merged on top: 1324 passed. Backoff = busy-family ladder IMPORTED
  from transport, cap-before-jitter, 1s floor (never-hammer-by-arithmetic), bound
  caller-supplied inclusive-at-threshold; stub://+https only, never defaulted; replay
  clears both tables, no double-send; logs never carry payloads; FK guards queue->events.
  Mutants: cap-removed 4 red, bound-strict-> 14 red, stub-scheme-bypass 1 red.
  agent_db v3/v4 additive on #29's reserved seam; P2-02 downgrade-wall test
  strengthened (literal 3 -> len(MIGRATIONS)+1), not weakened.
- Dispatcher auto-released P2-05 (alerts/park) + P2-06 (healthz/metrics) — both
  running. P2-07 (deploy) todo, held by parents; canary + B/C probes behind it.
- Main: 1324 tests green, ruff clean.

## 2026-10-19 later — P2 roots merged: #28 (fdd2f32) + #29 (ed02860); DAG auto-dispatching

- P2-01 (config validator) merged fdd2f32: 1206 passed; mutants 6/2/9 red (required-zone,
  http:// push target, unknown-key refusal). P2-02 (store) merged ed02860: 1254 passed;
  completed-only checkpoint guard pin + UPSERT idempotence verified incl. free-overlap
  WHERE-guard; mutants: guard-removal -> exact refusal pin red, DO-NOTHING -> 14 red,
  WHERE-drop -> 3 red. v3+ migration seam reserved for P2-04. Zero trailers, sockets
  blocked, no real hosts.
- Dispatcher auto-released P2-03 + P2-04 (running) the moment both roots completed —
  todo-flip correction doing its job. Then 05/06 (parents done) -> 07 -> canary.
- Note: one of my own mutations hit a docstring comment not the SQL (false green);
  retried anchored in the statement -> 14 red. Anchor mutants in code, grep-verify
  the anchor location, then trust the color.

## 2026-10-19 — PRs #26 + #25 merged; owner tz decision carded (P1-12 t_e37dfd68, running)

- PR #26 (P1-11 device-time verdict) -> `99d0c65`: 1128 passed / ruff clean; the None
  pin renders "no evidence (device claims nothing)", never agreement (mutant documented).
- PR #25 (P2-00 decision spec, docs-only) -> `e97d8fe`: 264 lines, 23 OBSERVED/DESIGN
  citations; ~190 nonce figure correctly attributed to OBSERVED + fw V3.2.30; P2 stays
  NOT scheduled pending OWNER SIGN-OFF on docs/P2-SITE-AGENT.md.
- OWNER DECISION: no physical device-clock fix -> per-device `device_tz` mapping in
  sites.toml (claims +02:00, actually Europe/Bucharest); mapped zone authoritative,
  warning silenced for the known-wrong claim, provenance fields untouched. Carded
  **t_e37dfd68 (P1-12)** (config.py SiteConfig/_KNOWN_KEYS, cli warning + verdict
  surfaces; tz.py/tz_mismatch.py/paging/model NOT touched; tests: mapped/unmapped/DST
  both sides + mutants). Note: gateway dispatcher idle ~3min; `hermes kanban dispatch`
  manually spawned it (dry-run first, then spawn confirmed + worktree up).
- AFTER MERGE (orchestrator, read-only per standing rule): live re-run of
  2026-05-21 13:00-14:30 against .243 with the mapping configured -> expect NO warning
  + same 20 records (serials 27..47).

## 2026-10-18 night — P1 CLOSED: dense-window live re-run passed on faa1f52

- Owner ran `events --since 2026-05-21T13:00 --until 2026-05-21T14:30 --chunk 1h -v
  --output json` (read-only): **rc 0, 20 records**. Chunk 13:00-14:00 -> NOMATCH/0;
  chunk 14:00-14:30 -> 200, 20 records, termination=OK, max_serial=47.
  ORCHESTRATOR JUDGMENT: the empty 13-14 chunk is EXACTLY what p1-05c expects —
  recorded dense cluster = device wall 14:08:22..14:20:04, serials 27..47 (fixture +
  my A/B); nothing exists in 13:00-14:00. Counterfactual: the same window under the
  retired +03:00 label returned 0 (my A/B: NO MATCH/0) -> **20 vs 0 = the payroll fix
  proven live**. Live jsonl parsed clean (20/20 rows, serials 27..47,
  tz_offset_mismatch true 20/20): independently proves PR #24's stdout byte-clean
  property on a real run + the one stderr warning line fired exactly once.
- Board: ALL cards done (P1-01..P1-10 + every fix/re-scope). Watcher stopped on owner
  instruction after one full review wave. Main 1120 tests / ruff clean.
- P1 close-out truths (OBSERVED.md): naive startTime -> 400; digest nonce use-cap ~190
  reqs (recovery offline-proven, live arm not exercised); window labels are ARITHMETIC.
  Owner-side optional: device tz fix stops the mismatch warning without touching math.

## 2026-10-18 evening — P1 review wave closed: PR #23 (tz_dialect tighten) + #24 (run warning) merged

- PR #23 -> `f8a06e9` (t_29318514): gate 1086 passed / ruff clean / CI green. My probes
  (cleared bytecode cache): ±14:00 -> HikTzInfo(std=840), ±14:01 + CST-15:00:00 ->
  HikTzUnknown "±14 h", CST-2:00:30 -> HikTzUnknown "sub-minute", refusals are values
  never exceptions; TYPE-pin via refused() isinstance. Mutations (sub-minute neutered,
  bound 13h/16h): 13 reds each. ci.yml touch legit (new file into tz coverage gate).
- PR #24 -> `7aa0148` (t_b4c71443): gate 1120 passed / 5 skipped (5th = the file's own
  delegated error-box skip, accepted) / ruff clean. stdout-byte-clean audit: emitter-seam
  byte-identity + from_jsonl parse + MY mutation (print -> stdout) = 26 reds. One line
  per run (multi-chunk), all-None silence (three-valued rule), rc 0, --verbose no dup.
- Combined main: **1120 passed / 5 skipped / 1 deselected**, ruff clean, tree clean,
  worktrees pruned. P1 board state: all cards done; OPEN for owner = the p1-05c
  dense-window live re-run on main (expect +02:00-labeled windows returning events).
- Review-hygiene lesson (my own false alarm): rapid mutate/restore of a module inside a
  review worktree left STALE .pyc -> 13 spurious reds on a clean tree. Purge
  __pycache__ before trusting any post-mutation pytest reading; direct-interpreter probe
  is the tiebreaker.

## 2026-10-18 — p1-05c merged (PR #22 -> b174150); blocked trio adjudicated + re-dispatched

- PR #22 gate: own merged-tree run **1049 passed / 4 skipped / 1 deselected**, ruff
  clean, CI green at head. A/B-replay audit PASSED on the real numbers:
  `+03:00`-labeled -> `[]` + NOMATCH (wire label pinned), `+02:00` -> serials **28..47
  all 20** + OK, seeded at device wall 14:08+ (OBSERVED.md table), against an
  arithmetically-filtering fake (label->instant->its claimed clock) whose docstring
  names the presence-only false-green it kills; boundary pin covers the inclusive
  14:30 edge; one-GET-per-run pinned (had_auth-filtered); unreadable-claim fallback
  warns, never goes naive; cli.py touch = pure threading. Review posted on PR #22.
  AWAITING OWNER: dense-window live re-run (13:00-14:30-style pair showing +02:00
  label returns the events).
- **Blocked trio rulings** (all three had verified worker blocks from 10-16 awaiting
  orchestrator input — the review-wave backlog, not live stalls):
  - t_7a0cb61e (p1-06b) CLOSED as duplicate: tz_dialect shipped via PR #3; the 4 spec
    divergences = accepted merged design (cards don't re-litigate merged code). Its 2
    REAL tightenings (sub-minute offsets rounded at tz_dialect.py:179; ±16h bound at
    :44) re-scoped + dispatched as **t_29318514**.
  - t_e26227b1 (p1-06c) CLOSED split-3: per-record column shipped (model.py:395,
    pipeline.py:461, tz_mismatch.py + 13 tests), validator = t_b5308f3f (done), and the
    ONE piece never built — the run-level warning line (verified: nothing prints it on
    b174150) — re-scoped + dispatched as **t_b4c71443** (stderr, warn-don't-fail
    precedent, stdout byte-clean, one line not per-record).
  - t_c9c62093 (p1-06d) CLOSED superseded: t_7b073d11 (done) is the post-review dedupe
    (isapi_response sole guard, tz.py re-export, read_system_time stays).
- Both new cards: backend-engineer, worktree branches, no file overlap -> parallel OK.
  Board: 0 todo/ready-stranded, 2 running-soon, 0 blocked, done 26.
- INCIDENT (owner-caught): both cards died spawn_failed x3 -> gave_up — I created them
  with bare `--workspace worktree` while the board had no default_workdir. Owner set
  default_workdir=~/dev/gateclerk + unblocked; both now RUNNING with worktrees.
  Standing rule: always pass `--workspace worktree:<abs-path>` on this board. Watcher
  patched (blocked cards alarm, never report "idle") + restarted tracked (was a blind
  spot: it printed "board idle" over a spawn_failed pair).

## 2026-10-17 night — P1-03b accepted (4af4398); A/B settles window semantics -> NEW payroll bug carded (p1-05c)

- PR #21 (nonce recovery) merged by owner after live acceptance: 1104 chunks / 1108
  200s / zero non-200 / same 10 events / 177s through the old wall. Retro-review on
  t_a3521d8a: budget/streak design sound, wrong-password invariant double-pinned,
  locked-account case separate; gates on main 1031 passed. Honest caveat recorded in
  OBSERVED: **recovery arm proven offline only** (no 401 materialized live this run).
- **A/B done by orchestrator (2 read-only curl POSTs, dense day 2026-05-21): the
  device does offset ARITHMETIC.** `+03:00`-labeled 13:00-14:30 -> 0; `+02:00` -> 20.
  Our current p1-05b shape (site-wall digits + site offset) is WRONG in DST: windows
  land an hour early, boundary punches lost silently. Sparse runs hide it — the
  acceptance passing does NOT clear it. Correct = site-wall digits labeled with the
  DEVICE's claimed offset (the original DESIGN.md rule, reinstated). Recorded in
  OBSERVED ("Window offsets are ARITHMETIC"); fix carded **t_56d8b09d (P1-05c)** incl.
  A/B-replica pin + FakeDevice filtering arithmetically. Raw A/B responses contained
  employee names -> deleted locally, never committed.
- P1-10: acceptance for the digest bug passed; card closed by owner per their plan —
  but see p1-05c, which the acceptance cannot cover (sparse window). P1-05c re-run
  acceptance ask: one dense-day chunk pair (13:00-14:30 style) showing the +02:00
  label returns the events.

## 2026-10-17 late — p1-05b merged by owner with live proof (e75e3a3); digest nonce bug carded

- PR #20 merged by OWNER after a live run on the branch (steps 5,6,7 pass: startTime
  goes out as `+03:00`, idempotent re-run, clean empty). Retro-review posted on
  t_12286c0d: scope exact, strict-fake pin good, gates re-run on main (1003 passed /
  4 skipped, ruff clean). Step 9 passed too: wrong password -> rc 3, ONE request,
  device stayed unlocked — lockout-safety proven on the real device.
- **Step 8 = new bug, carded t_a3521d8a (P1-03b)**: deterministic 401 with the CORRECT
  password at ~190th request (`--chunk 1h`), same window twice, exit 3, device
  unlocked -> nonce use-cap + our 401-terminal policy kills the walk. Mechanism OPEN
  (challenge stale=true / stale=false / envelope-only — never captured): reproduce
  offline via FakeDevice seams, fix = bounded re-challenge recovery while wrong
  password still exits 3 after one try. OBSERVED.md section added (6e67863), explicit
  NO-device-re-probe rule (lockout accounting).
- P1-10 closes after this fix + owner's 1h-chunk backfill re-run. Still owed by owner
  at that re-run: the +02:00-vs-+03:00 dense-window A/B (interpret vs require).

## 2026-10-17 evening — P1-10 live run: P0 found + dispatched (device REQUIRES offset startTime)

- Owner ran steps 1-4 green (model/serial/fw OK, skew -0.9s, count agrees, names
  plaintext). **Step 5 = P0**: device rejects our naive `startTime` → 400
  badJsonContent errorMsg=startTime; +03:00/+02:00 both 200. Every live events pull
  fails today. Offline missed it because FakeDevice accepts any body — mock lenience =
  false green.
- Evidence on main: OBSERVED.md "Event-window startTime form: offset REQUIRED"
  (67d29a5). DESIGN.md's "+ offsets" was right; p1-05's naive-pair default retired.
- Fix card t_12286c0d (p1-05b, running): flip build_event_cond + count probe to
  site-offset pair, make FakeDevice reject naive like the device, body-pin test +
  recorded 400 fixture. I review+merge → owner re-runs 5-8 + the +02/+03 A/B (does the
  device INTERPRET the offset or merely require it — sparse window couldn't tell).
- p1-06c UI gap noted: `device time` shows no mismatch flag (compute_skew exists; the
  flag display belongs to the p1-08 surface — small follow-up card after p1-05b merges).
- Step 9 (auth-negative) = owner by hand. Card t_353633f8 stays open until owner
  completes it post-5-8.

## 2026-10-17 afternoon — p1-09 merged (PR #19 -> b3a271a). P1 offline work COMPLETE; P1-10 = owner

- Gate on merged tree: **986 passed / 4 skipped / 1 deselected** (exactly as claimed),
  ruff clean, CI green, tz coverage 98.23% vs 95 floor reproduced. Fixture hygiene
  verified (TEST-NET, MASKED serials/nonces); corpus README pin test present; CI proxy
  blackhole is a documented SECOND wall behind netoff. Honest-run bug (Bucharest fold
  03:xx) caught by the suite itself.
- **NEXT = P1-10 live smoke (owner-run, human-only).** Everything merged; CLI is the
  thing under test. Steps + gotchas in t_353633f8 (TCC Local-Network permission,
  auth-negative once then web-UI check, never commit out/, redact per card rules).

## 2026-10-17 morning — p1-08 CLI merged (PR #18 -> 79ab6ff); "stall" was a dispatcher bug

- The 03:49-quiet card was DONE: PR #18 open since 00:41, branch pushed, worktree clean,
  last commit 03:39. What repeated at 03:50-03:53: dispatcher relaunches a `review`-status
  card into the worker's own session -> ~60s crash x3 -> gave_up -> blocked. Worker's
  reasoning in its last output was correct (kept review-not-done so p1-09 couldn't false-
  release before merge). **Pattern: review-status + no orchestrator action = crash-loop.**
  Heartbeats + worktree git are the truth; a quiet RUNNING after a PR is pushed = waiting.
- Reviewed + merged PR #18 with full gate: 841 passed on merged tree, ruff clean, CI green.
  Verified: stderr-only verbose w/ Authorization fully dropped, --count advisory (never a
  loop bound), third POST (AcsEventTotalNum) added in the open — DESIGN.md invariant +
  both guard tests moved two->three together, still falsifiable.
- Now: p1-09 (ready, dispatcher has it), then P1-10 live smoke = owner.

## 2026-10-16 late evening — PR #17 source guard merged (d40eef8); watching p1-08

- `pytest` now **exits 4 pre-collection** if `gateclerk` would import from outside the
  checkout (main's editable install used to make worktree runs falsely green — the
  t_7b073d11 episode). Reproduced both directions by orchestrator before merging.
  Use `uv run --frozen pytest` in worktrees from now on (CI already does).
- Running: p1-08 CLI (healthy, ~1h in, editing cli.py). Then p1-09 suite, then P1-10
  live smoke (owner). Fleet note: 3 serving nodes since 21:26 — slower turns only.

## 2026-10-16 evening — review cycle 4: PRs #7/#8/#9/#14/#15/#16 merged, main at 743 tests

- **Queue had gone stale 3h** — watcher fired `!WATCH` but a background process attached to
  an idle REPL cannot wake it (no gateway delivery here). Known limit; owner to decide fix.
- **PR #14 IsapiBusy docstring -> `cdad256`**: `invalidOperation` is vendor class-4 =
  terminal, never backoff (retrying it is the door-terminal-lockout path); verified against
  gotchas §2.2 + `_BUSY_SUBCODES`, boundary pinned both directions incl. the
  class-4-but-wait `beingExportedByAnotherUser` row.
- **PR #15 flatten_xml `@`-attrs -> `f31bdc4`**: capability limits live in XML attributes;
  `@`-prefix + `#text` convention now matches the recorded JSON fixtures. Probe:
  `<maxResults max="30"/>` -> `{"@max":"30"}`, attrs+text leaf -> dict, fixture snapshots
  byte-identical (root-attr scope unchanged).
- **PR #16 DESIGN.md digest clause -> `a37f3a8`**: the "close forces 401 re-pay" line was
  wrong per gotchas §1.7c (auth state lives on the auth object; 1 challenge/6 reqs under
  `Connection: close`). Real cost is fresh-auth-per-call doubling (10 vs 6) + stale-nonce
  on the long-lived auth object. Design doc now states the true reason reuse stays ON.
- **PR #8 p1-05 paging -> `b420329`** (1,896 lines, 38 tests): cursor advances by RETURNED
  `numOfMatches` only (the fw silent-clamp payroll bug), `NO MATCH`-with-space + missing
  InfoList handled, 10k-page runaway cap raises instead of looping, AcsEvent always
  bounded via `window_for_device`, checkpoint yielded only for completed chunks,
  `employeeNoString` only, `picEnable` refused, cursor-smuggling refused pre-wire.
  `AcsEventTotalNum` deliberately NOT added here — third POST = named registry decision,
  belongs with p1-08 `--count`.
- **PR #9 p1-06d facade -> `1ac9392`**: thin `resolve_event_time` over `TimeResolver` +
  `is_offset_mismatch`, no policy duplicated. Card state was lagging the PR (blocked);
  completed by orchestrator with gates on the merged tree.
- **PR #7 p1-04 capabilities+classifier -> `fc87204`** (5,069 lines — big, but the
  substance justified it): the catch of the day — (5,34)/(5,105) were catalog-named GRANTED
  passes shipped as INFO, i.e. **real punches silently dropped**; now sourced from two
  vendored catalogs with per-row `src:`, doc §3 generated + byte-pinned by guard,
  `AUTH_PASS_MINORS` derived not hand-listed. Also: malformed-host exit-2 contract, `--json`
  always machine-readable, IDNA UnicodeError -> transport class, subprocess socket-guard for
  CLI tests. No POST added; registry guard extended for the documented GET only.
- **Process**: afternoon PRs #10-#13 (p1-07 contract + doc/chore fixes) were merged by
  kanban runs, not by me — same self-merge hazard as PR #6; content spotless on spot-check
  this time. Reminder stands: **merges are orchestrator-only**.
- **Main**: 743 tests, ruff clean, offline CI green. P1 remaining: p1-08 CLI (ready),
  p1-09 suite (todo), then owner's P1-10 live smoke. Blocked-duplicate cards left blocked.

## 2026-10-16 morning — review cycle 2: all four open PRs merged, main at 401 tests

- **PR #4 p1-02 credentials -> `ac6c91d`.** flag>env>keychain verified vs DESIGN.md
  Credential plumbing; `Secret` masks in repr/str + identity-equality (closes the
  pytest-assertion-diff leak path); `security ... -w` + exit-44 -> actionable
  `CredentialUnavailable`; p1-03 gets a *callable* provider, never a baked plaintext.
  Committed config example uses TEST-NET hosts — no device IP, no password literals (grepped).
- **PR #5 p1-03 transport -> `5df152b`.** Card policy all verified in code: `uri=` carries
  query (the HA2/401-loop trap), digest session reuse + one-client-per-thread pinned, 401
  terminal + `lockStatus/unlockTime` circuit breaker, busy backoff capped, 10/30s timeouts,
  search retries byte-identical with same `searchID`, read-only registry guard. Conflict
  with #4 in `exceptions.py` (both added classes at same anchor) resolved on-branch by
  orchestrator (`b86dd44`); merged tree gated before merge.
- **PR #6 p1-06c mismatch -> `6f00c7e` — merged WRONG on process.** The card was assigned
  to `gateclerk-orch` (me) as a *worker*, and the session that "reviewed" it merged its own
  PR — the self-merge the policy forbids. Content re-verified by me post-merge (probe:
  summer +02 flags, missing claim -> None not False, GTB winter agrees), so the merge
  stands. **Fix: workers are backend-engineer/qa/reviewer — never gateclerk-orch; merges
  are orchestrator-only.**
- **PR #2 p1-06 tz core -> `58650e0`.** The "no push since 22:12" reading was stale: the
  worker HAD pushed the review fixes at 01:08 (`eec6658`: unpadded clock components
  accepted — my ask #2 — plus a real find: the DTD scan head-window was bypassable via
  padding, now whole-payload). I merged main into the branch, gated (401 tests, ruff,
  probes: unpadded OK / range still refused / padded-DTD refused) and merged. Scope ask
  (five concerns in one module) handled as planned via ownership cards, not a rewrite.
- **Card hygiene**: t_c9c62093 (worker-written, stale pre-review plan) blocked as
  superseded by t_7b073d11 (tz.py re-exports isapi_response's guard;
  `read_system_time` stays in tz.py). p1-06d correctly blocked itself pre-merge and is
  now re-scoped + unblocked as the thin `resolve_event_time` wrapper over
  `TimeResolver` + `is_offset_mismatch` — do not re-implement policy there.
- **Main**: 401 tests, ruff check+format clean, offline CI green. Ready queue: p1-04,
  p1-05, p1-07, p1-06d, t_7b073d11 dedupe, t_d1c511fc docs. Next review wave = their PRs;
  then p1-08 CLI -> p1-09 suite -> owner's P1-10 live smoke.

### 2026-10-16 evening — review cycle 3: PR #10 (p1-07 output contract) merged → `3a45790`

- **PR #10 p1-07 EventRecord/UserRecord -> `3a45790`.** Round 1 requested changes
  (fixture `attendance_status_events.json` was dead data while the README claimed it was
  asserted); round 2 (execution lens) approved at `f3bb1f3`. Verified myself: 523 tests
  green (test_model.py 119), ruff check+format clean, CI pass at head, diff still exactly
  the 6 card files, model/fixtures/DESIGN byte-identical to the round-1 head I had
  already probed. My own 20-probe mutation run (scratch copy, never the worktree):
  strip-test falsifiable, expectation keys can't vanish silently, status-table mutations
  all fail — **one real gap**: the entry-count floor is `>= 6` against 9 entries, so
  deleting one fixture entry keeps the suite green while the comment + handoff claim it
  is caught. Non-blocking (every status is also covered inline); filed as **t_ca64f6c2**,
  merged before the card so the contract isn't held hostage by one line of prose.
  Worker self-report discipline held again: two of my three "SURVIVED" readings were
  probe bugs on my side (operator precedence; a neutered-duplicate assertion) — re-probed
  before believing them, same lesson the worker recorded for their S2.
- **Contract now on main, P2/P3 read it**: `RECORD_JSON_KEYS` (27 keys) pinned by
  enumeration vs DESIGN.md; tz block consumed verbatim from `as_record()` (rename fails
  CI); `direction` derivable only from `attendanceStatus`, contradicting attribution
  rejected; `employee_no` NFC-normalized (fingerprint identity); password hash stripped
  before storage; JSONL lossless for the p1-08 CLI.
- **Hotspot standing**: `docs/DESIGN.md` touched by PR #7 (open) + PR #11 (open) + this
  merged cycle — sequence the next DESIGN.md edits.

### 2026-10-16 evening — follow-up: t_ca64f6c2 (loose fixture floor) merged → `7cecaa7`

- **PR #13 -> `7cecaa7`** (worker backend-engineer, reviewed by orchestrator, execution
  lens). The `>= 6` floor gap filed above is closed the stronger way: exact serialNo
  inventory `{7001..7009}` (ordered-list equality + count), not a `== 9` count. My own
  5-mutation probe on a scratch copy: drop-one (the F6 repro), duplicate-keeping-count-9,
  renumber, order-swap, and drop-three-to-6 (what the old floor survived) — all now fail;
  unmutated green. A bare `== 9` would have survived the duplicate mutation. Merged tree:
  524 passed / ruff clean. Worker hygiene clean (fixture restored + `git status` checked
  after every leg, worktree untouched by review). Non-blocking notes: the count assertion
  after the serialNo equality is logically dead (kept for a clearer message), and the
  ordered-list pin also freezes entry order — stricter than the docstring wording, fine
  for an audit baseline, easy to relax intentionally if the fixture is ever reordered.
- **PR #10 body wording fixed** (merged prose, orchestrator edit): it claimed the guard
  was "an entry-count floor ... a silently shrunk fixture stops reading as green" — now
  corrected on the PR itself: what shipped there was the loose floor, tightened to an
  exact inventory in #13. This was the only stale claim left; no repo file carried it.

### 2026-10-16 00:15 — first review cycle (PR #2 + PR #3)
- **PR #3 (p1-06b tz dialect) reviewed + merged** → main `b1c7bd6`. Verified on the
  worktree, not from the PR body: 99 tests green, ruff clean, and all four dialects decode
  to the offsets OBSERVED.md records (`CST-2:00:00DST01:00:00`→+120/+180, `CST-8`→+480,
  `Etc/GMT-2`→+120 POSIX-inverted, `GTB Standard Time`→+120/+180); IANA/empty → Unknown
  with a reason (never a confidently wrong number). Diagnostics-only rule (DESIGN item 5)
  is *mechanically* pinned by an ast+tokenize test — good pattern, reused elsewhere.
- **CI format gate was red on main for every PR** since the docs merge (ruff-format on
  python blocks inside `docs/references/isapi-client-gotchas.md`). Reproduced on a clean
  `origin/main` worktree before blaming the branch; fix landed as the worker's own
  whitespace-only commit (78b0b6e). If CI is red, check it against main first.
- **PR #2 (p1-06 tz core) = changes requested, NOT merged.** Policy is correct: all five
  DESIGN.md "Time handling" points implemented + pinned; the device-naive query window
  (`window_for_device`) kills a bug p1-05 would have shipped silently (UTC windows drop
  ~1h of summer punches per boundary). Two asks: (1) scope — 1,526 lines vs the ~100
  ceiling, five concerns in one card; (2) `_TIME_RE` requires a zero-padded hour, so an
  unpadded fw string lands as `unresolved` (safe but an invisible payroll gap).
- **Split handled by ownership, not by moving code**: I deliberately did NOT create
  carve-out cards (a branch that rewrites a merged PR + five new branches = merge pain).
  Instead each piece has a named owner in a card comment — `parse_isapi_xml`/
  `read_system_time`→p1-03 (import, don't reimplement a 2nd XML security policy),
  `window_for_device`→p1-05, `as_record()` keys→p1-07, `compute_skew`→p1-08. p1-06c/d
  re-linked as children of p1-06 so nothing claims against the resolver.
- **Sizing warning (2nd card in a row over budget: 330, then 1,526 lines)**: workers
  overshoot when a card names a *concern* instead of a file+function. Card smaller still.
- **Board**: p1-06b done; p1-06 running (worker addressing review, heartbeats alive);
  p1-02 claimed 23:59; p1-03 `ready` but *stranded* 1.5h — not a dead dispatcher, a
  concurrency cap (it claimed p1-02 the moment a slot freed).

### 2026-10-15 late — research folded in (second probe round)
- The two research briefs (docs/references/) corrected three of my own claims, each
  re-verified against the live device before writing: **AcsEventTotalNum** is the real
  count endpoint (works, totalNum=30 — we'd probed a wrong path name); **port 8000 is
  the SDK protocol port, not HTTPS**; **minor 38 = fingerprint, not card** (card pass
  is minor 1). New device finding: **`employeeNo` filter is silently ignored** (returns
  everything) while `employeeNoString` works → policy: filter client-side, trust only
  probed server filters. Also added: three error-envelope shapes + machine-readable
  lockout fields (`lockStatus/unlockTime`), silent maxResults clamping rationale,
  digest uri=/thread-safety/version-pin rules. Card comments updated for p1-03/04/05/08/09.

## 2026-10-21 (afternoon) — E1 v4: operator scope correction — faces + fingerprints are THE PRODUCT.

- Operator review of v3: keep the safety spine; faces can't be "report-only,
  re-enroll on site"; supplied K1T-family shapes for FDSearch + FingerPrintUpload
  from memory and ordered ONE capture session for users+card+FP+face fixtures.
- Every supplied shape VERIFIED LIVE on bench A (read-only rounds 11-18, one attempt
  per shape, no retries — raw facts + masking in docs/OBSERVED.md, design in v4 §1):
  * FDSearch RESOLVED (FLAT dialect!): rows carry `modelData` = the face TEMPLATE
    (272 B, FR500005 magic) — portable bytes; faceURL PHOTO bytes dead (404s).
    v3's "faces unexportable" was my wrong-dialect mistake, not a device limit.
  * FP read RESOLVED via FingerPrintUpload+FingerPrintCond (512 B template for E1);
    FingerPrint/Search notSupport was the wrong door.
  * UserInfo/Search truth: wrapped UserInfoSearchCond + searchID REQUIRED;
    EmployeeNoList filter PROVEN honored (coverage discipline kept anyway);
    paging MORE/OK quirk. Caps GETs work (v3 said 404) and UNDER-CLAIM
    (isSuportFDSearch=false while FDSearch works) → no inference from caps.
  * templateNo "1" default-carried now (all bench users use it; caps
    maxPlanTemplate=4) — v3's blanket report-only would ship migrated people with
    NO door right.
- Design v4 committed `2007681` (v4 delta log §11), OBSERVED.md `81655af`, pushed.
- Cards: E1-01b t_18a670bd created (faces+FP export, child of E1-01, reads proven
  so it builds offline NOW); steering comments posted on t_bd1faed8 (scope trim),
  t_9c5732ff (fake matrix corrections BEFORE it lands), t_0fd87e2f (templateNo-1 +
  set-diff), t_bbddb8f5 (§5.0 = ONE session, four fixtures; capture-before-fake
  unchanged). E1-06 = critical path; E1-06b (FP port) added to the DAG in §10.
- Next: gate E1-01 + E1-03 PRs as they land (with v4 lens); then E1-02; then the
  ONE-session bench-A capture (export snapshot → users/card/FP/face fixtures →
  restore); then E1-04/05/06/06b/07. No write fake route before its fixture.

## 2026-10-21 (evening) — E1-01b shipped as STACKED PR (biometric template export).

- Card t_18a670bd: the two PROVEN reads became code — `export_faces()` (FDSearch
  FDID 1, FLAT dialect via new `paging.fd_search` engine: no searchID in body,
  page-until-zero-row because bench A answered 3-of-4 on one OK page) and
  `export_fingerprints()` (FingerPrintUpload, FingerPrintCond wrapper required,
  fpIndex 0..N to the empty-`FingerPrintList` stop shape; runaway abort at
  MAX_FP_TEMPLATES_PER_PERSON, never a silent truncation).
- Bundle SCHEMA_VERSION → `gateclerk-enrollment-bundle/2`: faces/*.b64 + AVAILABLE
  faces/INDEX (FDID/FPID/sha256/len + the faceURL-404 photo_bytes recorded fact),
  fingerprints/<emp>-<idx>.b64 + INDEX (301-header sensor-family NOTE), manifest
  face/FP sections + INDEX digests + REPORT-ONLY numOfFace/numOfFP counters.
  Templates opaque everywhere (device base64 verbatim on disk; digests over decoded
  bytes = transport, never parsing). E1-01's `export_bundle` untouched — its
  UNAVAILABLE-absence regression still ships (new composite is `export_full_bundle`).
- Registry: `fd_search` + `finger_print_upload` registered as stateless-search POSTs
  (names ALIGNED with E1-03 PR #37 — one path, one name fleet-wide). FakeDevice grew
  `seed_biometric()` (rule-3 trap armed until then), flat-vs-wrapper dialect
  strictness, MessageParametersLack shapes, FPID filter honored, the paging quirk
  reproduced. FingerPrint/Search stays notSupport; face photo GETs stay unrouted 404s.
- Tests: 35 new in tests/test_e1_01b_biometric_export.py (byte-stability, opaque
  mutation, "007"≠"7" join, orphan-row abort, empty-honest-zeros, reader tamper
  verify, no-photo-GET pin). Full offline suite 1567 passed / 5 skipped; ruff clean.
- Stack note resolved by the orchestrator at merge time (see the 2026-10-22 merge-wave
  entry below): merged after #37/#38 as PR #40 onto main; the biometric store was
  grafted onto the unified fake rather than reconciled one-line.
## 2026-10-22 00:25-02:45 — E1 read-axis code wave merged: PR #37/#38/#40/#39 (probe, bundle, faces/FP export, diff engine).

- Operator ping: 4 open PRs. Gated + merged all four in stack order 37 -> 38 -> 40 -> 39
  (full evidence in scratch/e1-gate-log.md; per-merge gate = fresh worktree full pytest
  + ruff + >=3 mutation probes + tree-identity proof vs merged sha).
  * #37 E1-03 probe -> 6dcc06f (1508 suite; freshness/future-stamp/availability mutants red).
  * #38 E1-01 bundle -> 2436dbc (1561; password-strip/repo-out mutants red; one
    mutant judged dead-code belt with reasoning recorded).
  * #40 E1-01b faces+FP export -> aeb8dc7 (1597; biometric-store/paging-quirk/wrapper
    mutants red). Stack conflict resolved by grafting the biometric store onto main's
    unified fake (seed_biometric + two store-mode handlers), NOT by clobbering E1-03's axis.
  * #39 E1-02 diff engine -> d66b922 (1635; UNKNOWN-not-zero, card pair-identity,
    template-1-carried mutants red).
- main green at d66b922: 1635 passed / 5 skipped / 1 deselected, ruff clean, 0 open PRs.
- Next (operator-ordered): ONE-session bench-A capture (§5.0) — export snapshot via
  merged code, then user/card/FP/face write round-trips + read-backs, restore, fixtures
  committed -> unblocks E1-04 t_bbddb8f5 (capture-before-fake: no write fake route
  before its fixture).


## 2026-10-22 — E1 §5.0 write-path capture session (orchestrator, bench A)

Operator-ordered session ran AFTER the four-PR stack merged (#37 #38 #40 #39, all
squash-merged with tree-identity proof; two capture-found reader bugs fixed and
merged first — PR #41 FDSearch root dialect `MatchList`, PR #42 FingerPrintUpload
one-shot read; main green at 1640).

- Phase 0: pre-capture bundle via MERGED `export_full_bundle` (4 users / 4 faces /
  1 FP / 0 cards) — the rollback source. Landed OUTSIDE every git repo (the
  repo-out guard correctly refused `~/gateclerk/bundles`; root is `~/gateclerk-data`).
- Captured (details + bodies in OBSERVED.md "E1 §5.0 WRITE-PATH CAPTURE"): users
  `PUT UserInfo/SetUp` flat+mode:add PROVEN; cards `PUT CardInfo/SetUp` PROVEN;
  **faces `PUT FDSetUp` flat {faceLibType,FDID,FPID,modelData} PROVEN — R1 works**,
  read-back template identical; FP write accepted-but-never-applied
  (`FingerPrintProgress cardReaderRecvStatus:5` — bench reader rejects the
  third-party-family template): E1-06b = report-only on this class.
- INCIDENT (honest, in OBSERVED.md + design §5b D-WIPE): the accepted-shape person
  delete wiped EVERY user (device ignored the wrong-slot EmployeeNoList).
  RESTORE from the phase-0 bundle via the captured write shapes: post-restore
  export has identical per-person content hashes + identical faces index digest;
  person-1's single FP is the only unrecoverable record (bench reader rejects
  re-applying it — it came from the device's own capture originally). 10,351
  events untouched (separate log). Zero auth errors all session; no lockout axis
  touched. E1's own export→restore loop is now PROVEN on the real box.
- Next: E1-04 t_bbddb8f5 unblocked (fixtures exist) — dispatch with the §5b D-WIPE
  rule + captured bodies as fixtures; E1-06 report-only-fallback condition NOT
  triggered (face fixture exists); E1-06b built to accept/reject captured shapes.

## 2026-10-22 (later) — E1-04 merged; user-delete axis CLOSED; 05/06/06b dispatched

PR #44 (E1-04 write foundation) gated (1720 passed, ruff + format clean; 4/5
mutation probes killed, the two survivors proven dead-defensive/redundant like #38's
MutC) and squash-merged as d2086b8. E1-04 done closes the whole foundation chain
(01/01b/02/03/04).

A bounded second capture session (throwaway person 91) CLOSED the targeted-user-delete
axis with a second reproduced WIPE: even the documented mode:"deleteByEmployeeNo" with
the list in the sibling UserInfoDelCond returns ok and deletes EVERY user; the
list-inside wrapper 400s under every mode. No accepted targeted user-delete exists on
this fw → design rule §5b.1 (user delete banned outright; users-phase undo is
report-only; card/face deletes remain targeted+guarded). Bench A restored a third
time from the pre-capture bundle (re-export: 4 users/4 faces, hashes + face bytes
identical; person-1 FP archived in the bundle, un-re-applicable on bench A by the
accepted-not-applied rule). OBSERVED + design committed 1ccc6e6.

Dispatched the three E1-04 children (all parents satisfied, fixtures merged via #43):
E1-05 cards t_8ed04ad5, E1-06 faces t_d2487aef (critical path), E1-06b fingerprints
t_c3f04cfe — running. E1-07 CLI wiring follows after those three merge.

## 2026-10-23 — E1-05/06/06b merged; E1-07 (CLI + composer) dispatched

Gated the three write-phase PRs in stack order #45 (fingerprints) → #47 (faces,
stacked) → #46 (cards): all three FakeDevice-strict, diffs clean of hosts/creds/
names/real template bytes. Gate caught one real gap — #45's headline confirm gate
(post-read sha equality) survived a mutation probe because the fake's applies-mode
stores verbatim; added the pin test (doctored reader: ack + PRESENT + wrong sha
never confirms) on the branch before merging. #46's fakedevice.py conflict (both
branches grew the write axis in disjoint regions) resolved by transplanting the
card delta onto main's canonical fake; the "LATER card" §9 pin becomes the
un-armed refusal now that all three families route from captures. Merged: #45
d6c3e08, #47 4748c71, #46 19f0f5e; main verified 1867 passed + ruff + format clean.

Carded E1-07 t_56394a64 (CLI group + the missing §5 phase composer in a new
migrate_apply.py + PII-free -o json) — running. Last E1 build card; the §5.0
capture spine is fully paid off (nothing to capture for a CLI over merged seams).

## 2026-10-23 — E1-07 merged (PR #48 = 2311aed) + E1-08 LIVE VALIDATION PASSED on bench A

Gate on a fresh worktree: 1891 passed, ruff + format clean, hygiene diff scan 0 hits.
Mutation probe Mut3 survived on the apply report's forward undo preview (it could show
`journal` for users while `undo` refuses per §5b.1) — added the pin on the branch
before merging; report legibility is now tested, and live use confirmed the real
dispatch (report_only + the §5b.1 note, roster untouched).

E1-08 ran end-to-end as the orchestrator (HUMAN-RUN card; workers never touch the
device): probe -> export B1 -> workload via captured shapes (person 90 + card + face)
-> export B2 -> deliberate §5b wipe -> **product `migrate apply B2 --apply` onto the
empty box** (users 5 / cards 1 / faces 5 landed; fresh export byte-identical to B2) ->
undo cards 1->0, undo faces 25 calls with per-employee deltas 5..0, undo users refused
report-only -> wipe + **product apply B1** restored the baseline (diff all-same,
people+faces == B1). Events store survived both wipes (serial 27 and 5753 readable).
Dry-run-before-apply held every time. Bench A = baseline; B/C untouched, read-only.

Findings recorded in design §9.1: probe persistence bypasses the repo-out guard
(PII-bearing probe JSON landed inside the local, remote-less ops repo `~/gateclerk`;
moved out by hand, ops repo now gitignores `bundles/` and its old `probe/` dump moved
to ~/gateclerk-data/capture/). Fix carded as a small product card.

## 2026-10-23 — E1-09: probe persist now honors the repo-out guard (§9.1 finding 1)

One-seam fix: `migrate_probe.save_matrix` runs the target dir through the SHARED
`migrate_bundle._refuse_repo_out` before the first mkdir — the same guard `export
--out` refuses with (§2), reused not re-expressed (§5a; the call goes through the
module attribute, so stubbing the shared guard stubs this seam too). The CLI maps
the refusal onto the config class: exit 2 + the guard's own message naming the repo
root, and no file appears anywhere under the repo tree (the refusal precedes the
first mkdir). Journals' own `_refuse_repo_path` untouched (non-goal).

Pinned by tests/test_e1_09_probe_repo_guard.py (8 tests, FakeDevice-strict offline,
reusing the E1-07 harness): refusals through the module (checkout + linked-worktree
`.git` spellings), the reuse spy (guard consulted with the probes/ DIR, real guard
still running), the stub-to-no-op mutation probe (duplication would keep refusing
and go red), CLI exit-2 for both `--bundles-root` and the `GATECLERK_BUNDLE_ROOT`
default rung (the incident path, without touching real home), zero writes under the
repo, and the outside-a-repo happy path unchanged (0700/0600 + round-trip).
Self-ran the guard-removal mutation too: exactly the 4 refusal tests went red.
Full offline suite 1900 passed / 5 skipped; ruff check + format clean.

## 2026-10-23 — first LIVE cross-device migration A->B (operator-run) -> E1-10 t_4ede732f

Operator ran the product CLI on efc91a2 against real hardware: export A (4u/4f) +
B snapshot (site-b-20261023-1250) under ~/gateclerk-bundles (OUTSIDE the repo —
export's repo-out guard is why; README line folded into E1-10 acceptance). Diff
add=3 conflict=1 (emp 1 on B with own face + localUIRight -> skipped, correct).
Run 1250: users LANDED 3 (emp 2-4) then "verify disagreed" — only differing field
was `picID`, a device-assigned row handle site-B answers on every UserInfo/Search
row and site-A never sends -> §6 unknown-field rule fail-closes a LANDED write.
Run 1300: users OK; faces aborted BEFORE any write: AttributeError 'IsapiClient'
object has no attribute 'post' — FaceWriteTransport.post_face_search reaches
`client._client.post(...)`; bare IsapiClient works (inner httpx.Client) but the
--verbose path hands seams a LoggedClient whose ._client is the INNER IsapiClient,
which has no .post — orchestrator reproduced the operator's EXACT error string with
httpx.MockTransport. _request/.request has the same latent shape bug for every
write verb. FakeDevice-strict structurally cannot see either (duck-typed fakes).

E1-10 (t_4ede732f, spawned): one atomic fix — (1) IsapiClient.raw property, seams
go through it (LoggedClient forwards; bare+verbose one path; registry untouched),
(2) DEVICE_ASSIGNED_FIELDS={"picID"} excluded at COMPARE time in BOTH verify
_compare and E1-02 diff (NOT VOLATILE_FIELDS — that set is frozen into bundle
manifest digests; touching it would refuse the operator's existing bundles,
including the rerun bundle). Acceptance includes the faces phase driven over the
REAL IsapiClient class + MockTransport (bare + LoggedClient-wrapped), picID
same-class fixtures, and the old-bundle-still-reads digest pin.

B state after operator runs: emp 1-4 users, faces emp 1 only — operator reruns the
same A bundle onto B once E1-10 merges (faces carry to 2-4; verify no longer trips
on picID).


## 2026-10-23 — t_0d635ee2: export's repo-out refusal now exits 2 (was an unhandled traceback)

Found by E1-09: the card body claimed probe must exit 2 "exactly like export does" —
verified false. `_refuse_repo_out` raised a bare `ValueError`, which escapes
`_Guard`/`_fail` (unknown class -> re-raise) and crashed `migrate export --out <repo>`
as a traceback with exit 1. Fix shape: one new class, `BundleRepoOutError(ValueError,
ConfigError)`, in the shared exception vocabulary — the ConfigError base puts the
refusal on p1-08's documented exit-2 class through the ONE existing `_fail` mapping
(no cli.py change; `_fail`'s docstring rule: "a new exception class has exactly one
place to be added"), and the ValueError base keeps the module-level contract pinned by
E1-01/E1-01b intact plus E1-09's probe `except ValueError` seam when that branch
merges. No behavior change to the guard (same message, still refuses before the first
mkdir).

Audited the other write_bundle/journal seams while here: `migrate export` is the only
CLI path that reaches `_refuse_repo_out`; journals go through `migrate_write.
_refuse_repo_path`/`JournalError`, which is mapped consistently by `undo` (exit 2) but
lands on exit 4 via `_Guard`/`_fail` on the `apply` path — same class of mismatch,
different guard, deliberately left to its own card rather than scope-crept here.

Pinned by tests/test_t_0d635ee2_export_repo_out_exit2.py (8 FakeDevice-strict offline
tests on the E1-07 harness): CLI exit 2 for `--out` under `git init` in both
`-o table` and `-o json`, the json error names the repo root and carries exit_code 2,
no bundle/partial/manifest anywhere under the repo (the refusal still precedes the
first mkdir; the read pass still ran), outside-a-repo export still exits 0, the
call-through spy (guard consulted with the `--out` dir), the stub-to-no-op mutation
probe (a second copy of the rule in the CLI would keep refusing and go red, §5a), and
the exception contract (ValueError + ConfigError; `_fail` converts instead of
re-raising). TDD: 6 of the 8 were red against c624e62 before the fix.


## 2026-10-23 — t_cf2ad3c5: apply's journal repo-out refusal now exits 2 (was the device class)

The audit half of t_0d635ee2 found the same class of mismatch on the JOURNAL guard and
carded it here. `_refuse_repo_path` raised a bare `JournalError` (a plain `GateclerkError`):
`undo`'s own try/except mapped it to exit 2 ("undo refused: …"), but `apply --apply` opens
its per-phase journals inside the composer under `_Guard`/`_fail`, whose catch-all
`GateclerkError` arm filed the refusal under exit 4 — "the box said no" for a run that never
contacted a box. Fix shape, same seam class as the parent card: one new class,
`JournalRepoOutError(JournalError, ConfigError)`, at the refusal site in migrate_write —
the ConfigError base puts it on p1-08's exit-2 class through the ONE existing `_fail`
mapping (zero cli.py change; `_fail`'s "exactly one place to be added" rule honored), and
the `JournalError` base keeps E1-04's and E1-05's `pytest.raises(JournalError, match=
"inside the repository")` pins plus undo's `except JournalError` arm valid. The card's
design decision: hygiene (WHERE the operator pointed the journal) is the config class;
replay CORRUPTION (unknown schema/state) stays plain `JournalError` — an unreadable journal
is state a human adjudicates (§0.7), never "fix your input". Guard behavior unchanged: same
message, same refusal-before-first-mkdir (the composer's `_ensure_private_dir` lands first,
then the journal guard refuses before the journal file is created).

Pinned by tests/test_t_cf2ad3c5_journal_repo_out_exit2.py (13 FakeDevice-strict offline
tests on the E1-07 harness): apply exits 2 — never 4 — for `--run-dir` under `git init` in
both `-o table` and `-o json` (guard's message survives, json names the repo root), and
same when only `--bundles-root` resolves under a repo (the DEFAULT run dir); zero journal
bytes anywhere under the repo and zero authenticated write requests on the fake's wire
(refusal structurally precedes the transport); undo's own seam pass (`--undo-journal`
inside a repo, the second `_Guard` arm) also exits 2; undo's existing exit-2 refusals
pinned unchanged (repo-stray journal + mixed-phase neighbour); a private run dir still runs
to the harness's FP abort with all three phase journals (no over-refusal); the call-through
spy + stub-to-no-op mutation probe (the SHARED journal guard is the single seam — a CLI-side
copy of the rule would keep refusing with the guard stubbed and go red, §5a); the exception
contract (JournalError + ConfigError) and `_fail` converting rather than re-raising. TDD:
8 of the 13 red against the pre-fix tree (6941378), the 5 green ones pin behavior this card
must not change; verified by re-running the battery in a detached worktree at the red
commit (the repo's own false-green guard forces PYTHONPATH there — it caught the editable
install pointing at the wrong tree before any test ran).

## 2026-10-23 — E1-11 groundwork: face-write capture on site-B — PORTABILITY WALL, not body shape

Operator rerun (main dbeeefb): dry run matched (users 0, faces 3, conflict 1 = emp 1),
snapshot site-b-20261023-2053, --apply -> users/cards/fps clean (no-ops), faces STOP
at first upload: 400 badJsonContent, 0 of 3 landed, journal'd (run-b-20261023-2053).
Orchestrator sanctioned capture (snapshot site-b-20261023-2120 first, then ONE
product attempt -v journal'd run-b-20261023-2135 seq1 planned->rejected; then one-
attempt-per-shape curl discrimination; probe FPID 2 created+deleted; B restored):
P1 B's own FR702706 template -> own FPID 1, captured flat body: ok (zero state change).
E1 B's own template -> NEW FPID 2, same body, no faceURL: ok + read-back sha match +
captured FDSearch/Delete ok. E2 A's FR500005 emp-2 template -> FPID 2, byte-identical
body SHAPE: 400 {"subStatusCode":"badJsonContent","errorMsg":"faceURL"} (statusCode 6,
Invalid Content). => Body builder VERIFIED CORRECT on V4.13.0; the wall is TEMPLATE
GENERATION (V3.2.30 FR500005 rejected by V4.13.0, B native FR702706). Picture route
dead both ends (A faceURL JPEG export 404; B isSupportFDSearchDataPackage:false).
Cross-generation face carry = firmware wall -> faces need re-enrollment on B (operator
decision). Truth in docs/OBSERVED-site-B.md (0a2c6a9, pushed). E1-11 carded: capture-
backed template_rejected class + pre-apply facePortability warning (report-only) +
real-client tests; NO body-builder change (provably right), NO new device shapes
without operator-sanctioned capture (lockout budget). Separate observability gap
noted (NOT in this card): --verbose does not log write-seam requests (seams use
client.raw -> bypasses LoggedClient) — journal carries the intent, CLI -v shows reads
only; card if operator wants -v completeness for writes.

## 2026-10-24 — E1-11 done: template_rejected class + report-only facePortability warning

Capture truth is now code: the faces phase classifies the EXACT captured pair
(subStatusCode badJsonContent + errorMsg faceURL — never bare badJsonContent, which
stays shape_rejected) as RejectKind.template_rejected, journals it under the unchanged
schema as the additive `rejectClass` key (old journals read with class None; unknown
values fail closed), and aborts naming the wall and the human step ("faces require
re-enrollment on the target — docs/OBSERVED-site-B.md"); zero retry unchanged (§0.6).
Pre-apply, plan/diff compare readable template families (first 8 bytes, `FR\d{6}` —
transport, never a parse): source family the target has never held earns a REPORT-ONLY
facePortability note per person (table notes + `-o json` field), silence — never a
guess — when either side is unreadable/empty (a faceless target has never rejected
anything). Body builder untouched (capture E1 proves it correct on V4.13.0); users/
cards/fp phases untouched. A->B face carry remains blocked BY DEVICE until templates
are re-enrolled on B or a sanctioned capture finds an accepted cross-generation shape.
Tests: test_e1_11_template_portability (19; real IsapiClient+MockTransport bare+
LoggedClient; the four card mutation probes each kill red); site-B sanitized fixtures
under tests/fixtures/recorded/site-b-ds-k1t344mbfwx-e1/ and the hygiene lock now
globs every recorded site.
