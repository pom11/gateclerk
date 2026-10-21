# gateclerk

Hikvision face/card terminals → Business Central timesheets. Details in docs/DESIGN.md.

**Scope (owner, 2026-10-15): device side only.** P1 PROVEN on the real device
(2026-10-18, dense-window live pass). P2 signed off 2026-10-19 (docs/P2-SITE-AGENT.md
§6 binding). E1 (enrollment migration) opened 2026-10-21 — operator delegated the
design end-to-end to the orchestrator (docs/ENROLLMENT-MIGRATION.md).

## Done
- [x] **P1** read-only connector + CLI (probe → OBSERVED.md; ISAPI client w/ digest,
      nonce recovery, circuit, caps; `device|users|events`; live smoke pass) — 2026-10-18
- [x] **P2** site agent code complete (PRs #28..#35, 1475 tests green on main):
      config validator, store/checkpoint UPSERT, scheduler (5min/5min, one client per
      device), pusher + dead-letter (stub:// only), alerts + park-on-bad-creds,
      /healthz + metrics vocabulary, deploy templates (systemd + launchd example) +
      `gateclerk agent run|ack|deadletter` CLI. Every merge: orchestrator gate (full
      suite + mutation probes). P2-fix-A (live canary smoke catch: device rejects
      sub-second startTime, #36) folded in.
- [ ] P2-10 site-a canary — **SKIPPED by operator 2026-10-21**: site-a is a bench
      device (nobody punches); 7 days would prove nothing. Its live smoke still paid
      for itself (P2-fix-A). Launchd renders kept in ~/gateclerk/launchd/.
- [ ] P2-11 site-B probe / P2-12 site-C probe — blocked on **operator: device host +
      keychain item** each; read-only §5 probe, then (for writes) explicit OK.

## Now (E1 — enrollment migration; first WRITE feature; design v2 2026-10-21)
Board truth: `hermes kanban --board gateclerk list`. Design: docs/ENROLLMENT-MIGRATION.md
(DAG E1-01..07 there). Users+cards port; faces report-only until R1 confirmed BOTH
ends on bench; fingerprints never portable; PINs never persisted.
- [ ] E1-01 bundle + export (users/cards, hashes, PII hygiene, fail-closed reads)
- [ ] E1-03 capability probe + staleness gate (parallel root)
- [ ] E1-02 diff engine (+freshness contract, conflict classes) ← 01
- [ ] E1-04 write foundation (endpoint-confirmation capture FIRST, journal, users
      phase, verify) ← 02,03
- [ ] E1-05 cards phase + undo (restore-before-delete) ← 04
- [ ] E1-07 `gateclerk migrate` CLI wiring ← 05
- [ ] E1-06 faces (R1: confirm FDSearch export + picture-import endpoints on bench A;
      additive, ships report-only until then) ← 04

Hard rules for E1 (full list §0 of the design): writes ONLY on bench A after its
export snapshot; B/C read-only until operator OK; no write verb merges without a
bench-confirmed capture; probe-gated + fresh-diff before every write phase;
read-back verify is terminal on mismatch; no deletions except journal-scoped undo.

Push target stays ABSTRACT: cards build against a local stub ingest + JSONL —
never invent a real BC endpoint (P3 out of scope).

## Out of scope (P3 — Business Central; owner go-signal required)
- [ ] nothing designed, nothing carded. Open question only (DESIGN.md Q1): BC
      table/fields + who owns the employeeNoString→BC-employee mapping

## Hard rules
- read-only against devices EXCEPT bench A under E1's §0 (operator-authorized);
  no writes to B/C ever until explicit per-site OK; no reboots ever
- never hammer: a wrong-shape 401 counts toward device lockout — debug offline
  (FakeDevice); device budget ~190 authed requests per client (OBSERVED.md)
- no secrets in commits/chat; real device hosts never committed (sites.toml is
  gitignored local-only; docs use TEST-NET placeholders); person data (names, cards,
  PINs, photos) never committed — bundles live outside the repo, 0600
