# gateclerk

Hikvision face/card terminals → Business Central timesheets. Details in docs/DESIGN.md.

**Scope (owner, 2026-10-15): device side only.** Prove the connector + CLI (P1)
against the real device. Nothing BC is designed or carded until P1 is seen working;
P2 stays a sketch.

## Now (P1 — read-only connector + CLI)
- [x] uv + py3.12 package scaffold, CLI `gateclerk`, offline tests in CI
- [x] read-only device probe → docs/OBSERVED.md (event codes, paging, tz bug, noise) + masked fixtures
- [ ] ISAPI client: digest auth, timeouts, bounded retries, capability discovery
- [ ] `device info|time|capabilities`, `users list`, `events --since/--until` (paged, normalized)
- [ ] Live smoke run vs 192.0.2.10 **with our CLI** (fixtures already recorded)

## Sketch only (P2 — site agent; not scheduled until P1 is proven)
- [ ] sqlite store, checkpoint + overlap, outbound pusher, systemd unit, 3 sites = 1 codebase + 3 configs

## Out of scope (P3 — Business Central; owner go-signal after P1 works)
- [ ] nothing designed, nothing carded. Open question only (DESIGN.md Q1): BC
      table/fields + who owns the employeeNoString→BC-employee mapping

## Hard rules
- read-only against devices; no writes/reboots ever unless explicitly ordered
- no creds in the repo (`.env` gitignored; password lives in macOS Keychain, service `gateclerk-hikvision`)
