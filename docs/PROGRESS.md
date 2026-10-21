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
