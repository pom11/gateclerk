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
