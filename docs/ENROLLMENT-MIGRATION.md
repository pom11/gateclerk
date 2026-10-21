# Enrollment migration between devices — design (E1)

Status: **ORCHESTRATOR-AUTHORED, operator-delegated 2026-10-21** ("you own the design
end to end" — self-review + adversarial reviewer pass, then atomic cards straight
through; no human sign-off gate). Track name **E1** (deliberately not "P3" — P3/BC
stays out of scope, owner decision).
This is the FIRST feature that WRITES to devices; every rule below exists because of
that.

## 0. Safety rules (binding, non-negotiable)

1. **Bench device A only** for write testing, and only **after** its full state has
   been exported to a snapshot bundle (the export IS the rollback source). A is ours;
   nobody punches on it (operator 2026-10-21).
2. **B and C are read-only** until the operator explicitly OKs writes per site. When
   their creds arrive: read-only §5 probe + dry-run diff first, then the real write.
3. **Never write to a device we have not probed** (capability matrix, §5) and never
   write a record the diff did not classify (§4).
4. **No device credentials in bundles, logs, output, or commits** (unchanged rule:
   flag > env > keychain). Bundles contain personal data → written 0600 under a
   gitignored dir outside the repo (`~/gateclerk/bundles/<site>-<host>/`), never
   committed, never printed in full.
5. **Device abuse budget** (OBSERVED.md): one long-lived `IsapiClient` per phase,
   ≤ ~190 authed requests per client lifetime → batch + re-bootstrap at budget, small
   sleep between write batches, **never retry a 401** (lockout accounting).
6. Read-back verify after every write batch (§6); a verify mismatch is reported as
   data, never "fixed" by blind re-write.

## 1. What migrates per person (grounded in the live probe of A, 2026-10-21)

Probe facts (bench A = DS-K1T341AMF-S, fw V3.2.30; masked; GETs + search POSTs only):

| surface | endpoint (JSON form) | result on A |
|---|---|---|
| users | POST `UserInfo/Search` | 200 — 4 users; record carries `employeeNo,name,userType,Valid{enable,beginTime,endTime,timeType},doorRight,RightPlan[],belongGroup,localUIRight,maxOpenDoorTime,numOfCard,numOfFace,numOfFP,password,gender,...` |
| cards | POST `CardInfo/Search` | 200 — works (0 cards currently) |
| per-person detail | POST `UserInfoDetail/Search` | **404/400 notSupport** — door rights live IN the UserInfo record (`RightPlan`), no separate endpoint on this fw |
| face libs | GET `Intelligent/FDLib` | 200 — FDID 1 `blackFD`, FDID 2 `infraredFD` |
| face records | POST `Intelligent/FDLib/FDSearch` | **400 `MessageParametersLack` errorMsg=faceLibType on every body variant tried (6)** — UNRESOLVED, see §8 risk R1 |
| fingerprints | POST `AccessControl/FingerPrint/Search` | **notSupport** — template read NOT available on this fw (one user shows `numOfFP=1` enrolled via the terminal UI → that person's FP cannot migrate) |
| plan templates | `PlanTemplate*` | **notSupport** — `RightPlan[].templateNo` references are device-local presets |
| acs caps | GET `AcsCfg/capabilities` | 200 (JSON) — `saveFacePic=true,false` etc. |

Consequences for scope (first cut):
- **Users: full port** (identity + validity + door rights as the record carries them).
- **Cards: port** (`cardNo` is portable data; `CardInfo/Search` proves read; write via
  `CardInfo/SetUp` mode=merge).
- **Faces: photos only, IF FDSearch is cracked (R1)** — export `faceURL` picture bytes;
  re-import via picture upload lets the TARGET re-extract its own template. Face
  *templates* are never transferred (not portable across models, per operator +
  Hikvision reality). If R1 stays unresolved: faces are **reported, skipped** —
  migration must say "1 face on source, needs on-site re-enrollment", never fail
  silently.
- **Fingerprints: never portable** (probe says not even readable on this family).
  Report only.
- **Unlock PINs (the `password` field on UserInfo): dropped by default.** It is a
  person-level secret, not a device credential; carrying it is a security choice the
  operator makes explicitly per run (`--carry-pins` opt-in, never on by default).
- **Plan template references: carried by number; conflict if target lacks the
  template** (capability matrix records each device's supported template range).

## 2. Portable bundle format (on disk)

```
bundles/<site>-<host>/
  manifest.json          # bundle schema version, source identity (model, fw,
                         #   serial prefix), exported_at UTC (injected clock),
                         #   counts, per-person content-hash, capability matrix (§5)
  people.jsonl           # one normalized UserInfo record per line (volatile fields
                         #   stripped, `password` stripped unless --carry-pins)
  cards.jsonl            # normalized CardInfo records (employeeNo, cardNo, type)
  faces/<employeeNo>.jpg # picture bytes IF export available (R1); absent otherwise
  faces/INDEX.json       # employeeNo -> file + sha256 + source faceURL shape
```

- **Content hash** = sha256 over canonical JSON (sorted keys, UTF-8) of the record
  with the VOLATILE set stripped: `openDoorTime`, `numOfCard/numOfFace/numOfFP`
  counters, `password`, plus any per-device ids that don't survive (`photoURL`/`faceURL`
  host parts). The hash is what diff (§4) and verify (§6) compare — never raw bytes.
- Bundle dir 0700, files 0600, path always under the configured bundles root (never
  inside the repo; a `--out` inside the repo is REFUSED — public-repo hygiene).
- A bundle names real people = PII: logs may print counts and hashes, never names.

## 3. Capability probe (gate for every export AND apply)

`gateclerk migrate probe --site S [--device H]` → capability matrix persisted in every
bundle and required in the apply target:
- identity (model, fw, serial prefix);
- endpoint availability matrix (the §1 table, computed per device — B/C firmwares are
  unknown until creds arrive; **notSupport is a discovered fact, never assumed**);
- limits: maxResults per search (reuse P1's `capabilities.discover`), user/card counts;
- face situation: FDSearch shape works? FDID list? picture bytes exportable?
An apply to a device whose probe is missing or older than N days (default 7) is
refused.

## 4. Diff / dry-run (the default mode of `apply`)

`gateclerk migrate diff --bundle B --target S` and `apply` (which IS diff + gated write):

- Target current state is READ fresh (never trust a stale bundle of the target).
- Classification per `employeeNo`:
  - **add** — source-only;
  - **update** — on both, content-hash differs;
  - **same** — hash equal (no-op; makes re-runs idempotent BY CONSTRUCTION);
  - **conflict** — exists on target with different data AND the update would destroy
    target-only facts (e.g. target has cards/faces the bundle lacks — a bundle is a
    snapshot, not a live view). Conflict is a SEPARATE class from update precisely so
    `--on-conflict` can be decided per run.
- **Default policy: conflicts are REPORTED AND SKIPPED** (never auto-merged, never
  auto-overwritten). `--on-conflict=skip|overwrite|abort` (skip = default; abort
  refuses the whole run; overwrite replaces ONLY the overlapping fields the bundle
  owns — cards/faces the target has extra are LEFT ALONE, migration never deletes
  target-side enrollments it did not create).
- Diff output: per-person table (classification + hash-diff of changed field NAMES,
  values never printed — the console is not the place for PII), totals line, and an
  explicit "would write N" count. Exit codes: 0 no changes, 1 changes pending
  (dry-run default), 2 config/creds problem (p1-08 contract).

## 5. Write path (idempotent, ordered, probe-gated)

`apply --target S --apply` (missing `--apply` ⇒ dry-run; the flag that writes must
appear twice in spirit: `diff` is default, `--apply` is explicit):

1. require fresh probe (§3) + **pre-write snapshot of the target** (an export bundle
   of the target itself, written before any mutation — the rollback source);
2. order: users → cards → faces (a card/face needs its person);
3. users: batched SetUp (merge/overwrite per classification; exact endpoint + mode
   semantics CONFIRMED by read-only capability GETs before the first write card
   ships — probe of `UserInfo/SetUp` capabilities is GET, harmless), batches ≤ 40
   records (nonce budget, §0.5), digest client re-bootstrap at budget;
4. cards: `CardInfo/SetUp` merge; skip cardNos already on target (re-run idempotency);
5. faces: picture upload per person (only if R1 cracked and bundle has bytes);
6. read-back verify (§6) after EACH phase, not just at the end;
7. **no deletions ever** in v1. Undo = explicit `gateclerk migrate undo --journal J`
   (§6), which removes only what THIS run added, identified from the journal.

ISAPI has no transactions: a mid-run crash leaves partial state — that is exactly why
the journal (every write, its classification, its read-back verdict, appended before
the batch) + verify + undo-by-journal exist, and why re-runs are safe (diff re-
classifies from live state, `same` records are skipped).

## 6. Read-back verify (never trust the write's status code)

After each phase, re-`Search` the target for exactly the employeeNos touched and
compare content-hashes (§2). Per-person verdict `ok | mismatch | missing`. The run
report is the artifact: counts per classification/verdict, journal path, bundle
hashes — posted, not narrated. Mismatches are terminal for the run (stop the next
phase; report; human decides) — the "BLOCK, don't fabricate" rule from the canary
metrics applies to payroll identity data too.

## 7. CLI surface (typer group `gateclerk migrate`)

```
gateclerk migrate probe  --site S                     # capability matrix -> bundles/probes/
gateclerk migrate export --site S [--out DIR]         # snapshot bundle (read-only)
gateclerk migrate diff   --bundle B --target T        # classification table, no writes
gateclerk migrate apply  --bundle B --target T [--apply] [--on-conflict=...]
gateclerk migrate undo   --journal J                  # remove only what J added
```

Creds: `gateclerk.config` resolver unchanged (flag > env > keychain); `--site` selects
both endpoints and target. Machine-readable: `-o json` on all (stable schema, same
discipline as `events`).

## 8. Open risks

- **R1 — FDSearch body unresolved (face export).** ~8 documented shapes rejected
  (all `MessageParametersLack: faceLibType` for JSON; XML bodies rejected at the
  envelope, incl. ver10/ver20 WITHOUT `format=json` — probe rounds 2026-10-21).
  Remaining options for the export card (all read-only): fetch the device's
  `FDSearch/capabilities` schema doc even though the A probe 404s (other fw may
  serve it); search vendor docs for this fw family's exact envelope; or accept
  **faces stay on-device** (the terminal keeps its own copies; target re-enrolls
  faces on-site). **Face migration is explicitly OPTIONAL and additive**: E1 ships
  users+cards with faces as "reported, skipped" until R1 falls.
- **R2 — SetUp write semantics** (merge vs overwrite per field, batch caps) must be
  confirmed on bench A first-write: one person, read back, then batch (orchestrator-
  run; bench writes pre-authorized by operator 2026-10-21, "export/snapshot it first"
  honored by §5 step 1).
- **R3 — `password` (unlock PIN) exposure in searches.** The read returns it; the
  bundle strips it by default; logs never print record bodies. Re-checked in tests.
- **R4 — B/C firmware unknown** → the probe-gate (§3) exists so no B/C write can
  inherit A's assumptions.

## 9. Test strategy (FakeDevice-strict — the standing rule)

- FakeDevice gains the enrollment endpoints **with A's discovered truth**, including
  the notSupport matrix (UserInfoDetail, FingerPrint/Search, PlanTemplate) and the
  FDSearch body strictness (rejects what the device rejects) — the permissive-fake
  lesson from the sub-second-400 canary catch, applied up front.
- Diff engine: injected clock; dense fixtures (same person different validity, target
  extras, hash-stable re-run = zero writes, conflict classification, volatile
  stripping).
- Write path: transport fake asserts request order, batch caps, nonce-budget
  re-bootstrap, journal append-before-write, verify-mismatch stops the next phase.
- Live validation (post-merge, standing operator OK): export A (snapshot), mutate one
  person via A itself, diff detects it, apply restores from the snapshot, verify
  passes, undo journal exercises. B/C: nothing until creds + explicit write OK.

## 10. Atomic card plan (post sign-off, DAG-linked)

| card | scope (one module + tests) |
|---|---|
| E1-01 | bundle format + export reader (users/cards) + manifest/hashes + probe reader |
| E1-02 | diff engine + classification + console/json report (no writes) |
| E1-03 | capability probe + gate (matrix persisted, staleness refusal) |
| E1-04 | write path (users+cards): SetUp, batching/nonce budget, journal, verify, undo |
| E1-05 | faces: FDSearch crack (R1) + picture upload (blocked until R1 probed; additive) |

E1-01 → E1-02 → {E1-03, E1-04}; E1-05 child of E1-03. Each card: FakeDevice-strict
offline tests, NEVER touch the device from a worker card (live validation is the
orchestrator's post-merge step), PR + orchestrator gate (full suite + mutants) + merge.
