# gateclerk

Hikvision face/card terminals → Business Central timesheets. Details in docs/DESIGN.md.

## Now (P1 — read-only connector)
- [x] uv + py3.12 package scaffold, CLI `gateclerk`, offline tests in CI
- [ ] ISAPI client: digest auth, timeouts, bounded retries, capability discovery
- [ ] `device info|time`, `users list`, `events --since/--until` (paged, normalized)
- [ ] Live smoke run vs 192.0.2.10 → docs/OBSERVED.md (real event codes)

## Next (P2 — site agent)
- [ ] sqlite store, checkpoint + overlap, outbound pusher, systemd unit, 3 sites = 1 codebase + 3 configs

## Later (P3 — Business Central)
- [ ] ingestion endpoint + employee mapping + timesheet write (blocked on open Q1 in DESIGN.md — do not design yet)

## Hard rules
- read-only against devices; no writes/reboots ever unless explicitly ordered
- no creds in the repo (`.env` gitignored; password lives in macOS Keychain, service `gateclerk-hikvision`)
