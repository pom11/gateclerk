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
- Review queue: PRs for p1-06 (+b/c/d), then p1-02/03/04/05 land → p1-08 CLI → p1-09
  suite → hand to owner for P1-10 live smoke against 192.0.2.10.

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
