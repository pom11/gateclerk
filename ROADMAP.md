# gateclerk

Hikvision face/card terminals → Business Central timesheets. Details in docs/DESIGN.md.

**Scope (owner, 2026-10-15): device side only.** P1 is PROVEN on the real device
(2026-10-18, dense-window live pass). P2 signed off 2026-10-19 — the decision spec
docs/P2-SITE-AGENT.md §6 is binding for P2 cards.

## Done (P1 — read-only connector + CLI) — closed 2026-10-18
- [x] uv + py3.12 package scaffold, CLI `gateclerk`, offline tests in CI (1150 green)
- [x] read-only device probe → docs/OBSERVED.md (event codes, paging, tz bug, noise) + masked fixtures
- [x] ISAPI client: digest auth, timeouts, bounded retries, nonce-retirement recovery, circuit, capability discovery
- [x] `device info|time|capabilities`, `users list`, `events --since/--until` (paged, normalized)
- [x] Live smoke run vs the site-a device **with our CLI** (PROGRESS.md 2026-10-18:
      20 records vs 0 counterfactual, idempotent, rc 0)

## Now (P2 — site agent; signed off 2026-10-19)
Board truth: `hermes kanban --board gateclerk list`. One module per card:
- [ ] P2-01 config validator (iana_tz required, refs-only creds, naming) — root
- [ ] P2-02 store: sqlite (device_serial,serial_no) UPSERT + checkpoint + overlap — root
- [ ] P2-03 scheduler loop (5 min / 5 min overlap, one long-lived client per device)
- [ ] P2-04 pusher + dead-letter (backoff 1→30 s, 24 h bound, replay; stub ingest only)
- [ ] P2-05 alerts + park-on-bad-creds (acked 30-min re-probe; lockout = critical on-site)
- [ ] P2-06 /healthz + metrics (spec §2e vocabulary)
- [ ] P2-07 systemd unit template + launchd example (gateclerk-agent@<site>)
- [ ] P2-10 site-a canary ≥7 days clean — gates B/C (no checkpoint stall, no terminal
      401, tz warning-count 0 with the device_tz mapping, site_labeled_windows 0)
- [ ] P2-11 site-B probe (blocked — needs operator host + keychain item)
- [ ] P2-12 site-C probe (blocked — same, and one-at-a-time after B)

Push target stays ABSTRACT: cards build against a local stub ingest + JSONL —
never invent a real BC endpoint (P3 out of scope).

## Out of scope (P3 — Business Central; owner go-signal required)
- [ ] nothing designed, nothing carded. Open question only (DESIGN.md Q1): BC
      table/fields + who owns the employeeNoString→BC-employee mapping

## Hard rules
- read-only against devices; no writes/reboots ever unless explicitly ordered
- never hammer: a wrong-shape 401 counts toward device lockout — debug offline (FakeDevice)
- no secrets in commits/chat; real device hosts never committed (sites.toml is
  gitignored local-only; docs use TEST-NET placeholders)
