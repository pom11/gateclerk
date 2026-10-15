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
