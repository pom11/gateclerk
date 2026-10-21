# Enrollment migration between devices — design (E1)

Status: **ORCHESTRATOR-AUTHORED v2, operator-delegated 2026-10-21** ("you own the
design end to end" — self-review + adversarial reviewer pass DONE, both FIX-FIRST
verdicts applied here; see §11 review log). Track name **E1** (deliberately not "P3" —
P3/BC stays out of scope, owner decision).
This is the FIRST feature that WRITES to devices; every rule below exists because of
that.

## 0. Safety rules (binding, non-negotiable)

1. **Bench device A only** for write testing, and only **after** its full state has
   been exported to a snapshot bundle (the export IS the rollback source). A is ours;
   nobody punches on it (operator 2026-10-21).
2. **B and C are read-only** until the operator explicitly OKs writes per site. When
   their creds arrive: read-only §3 probe + dry-run diff first, then the real write.
3. **Never write to a device we have not probed** (§3) and never write a record the
   diff did not classify (§4). No endpoint whose request shape we have not CONFIRMED
   on a real device may exist in the write path (§5 step 0).
4. **No device credentials or person secrets in bundles, logs, output, or commits**
   (unchanged rule: flag > env > keychain). Bundles contain personal data → written
   0600 under a gitignored dir outside the repo (`~/gateclerk/bundles/<site>-<host>/`),
   never committed, never printed in full. **Unlock PINs never touch a bundle file at
   all** (§2): `--carry-pins` transfers in-memory within one live run, or not at all.
5. **Device abuse budget** (OBSERVED.md): one long-lived `IsapiClient` per phase,
   ~190 authed requests per client lifetime (digest = up to 2 requests per authed
   call at worst; nonce-per-request mode) → budget math in §5, re-bootstrap before
   exhaustion (P1's recovery arm, offline-proven; OBSERVED records it was never
   exercised live — E1 will be its first live use), small sleep between batches,
   **never retry a 401** (lockout accounting).
6. **Read-back verify after every write phase** (§6); a verify mismatch is terminal
   for the run: stop, report as data, human decides. Never "fix" a mismatch with a
   blind re-write.
7. **Fail closed on device reads**: any error response (400/404/notSupport) on a
   required enrollment read ABORTS export/diff — silence is never interpreted as
   "empty". A zero-count result is only "zero" when the device said OK.

## 1. What migrates per person (grounded in the live probe of A, 2026-10-21)

Probe facts (bench A = DS-K1T341AMF-S, fw V3.2.30; masked; GETs + search POSTs only).
Each row says what the probe PROVES and what it does not:

| surface | endpoint (JSON form) | proven | NOT proven (gap) |
|---|---|---|---|
| users | POST `UserInfo/Search` | read works — 4 users; record carries `employeeNo,name,userType,Valid{enable,beginTime,endTime,timeType},doorRight,RightPlan[],belongGroup,localUIRight,maxOpenDoorTime,numOfCard,numOfFace,numOfFP,password,gender,...` | that `UserInfo/SetUp` exists/accepts this shape (write-confirm step, §5.0) |
| cards | POST `CardInfo/Search` | query shape answers (device had 0 cards — read path exercised, data not) | that export returns real cardNo values (verify during A snapshot) or `CardInfo/SetUp` accepts them |
| per-person detail | POST `UserInfoDetail/Search` | **404/400 notSupport** on this fw — door rights live IN the UserInfo record (`RightPlan`), no separate endpoint | — |
| face libs | GET `Intelligent/FDLib` | FDID 1 `blackFD`, FDID 2 `infraredFD` | — |
| face records | POST `Intelligent/FDLib/FDSearch` | **400 `MessageParametersLack: faceLibType` on ~8 body shapes** — UNRESOLVED (R1) | face export entirely; ALSO unproven: which endpoint accepts a face PICTURE on the target (`FDLib/pictureUpload` vs `FDLib/FDSetUp` vs person-photo endpoint) — R1 now covers BOTH ends (§8) |
| fingerprints | POST `AccessControl/FingerPrint/Search` | **notSupport** — templates not even readable on this fw (one user `numOfFP=1` enrolled via UI → cannot migrate) | — |
| plan templates | `PlanTemplate*` | **notSupport** — `RightPlan[].templateNo` are device-local preset references | the preset table's meaning on each device (probe records templateNo range discovered from UserInfo records only) |
| caps | GET `AcsCfg/capabilities` | works (JSON); `saveFacePic=true,false` | user/card MAX counts (`UserInfo/Search/capabilities` 404s on A) → capacity: fail-fast strategy §5 step 3 |

Scope cut (first ship): **users full port; cards port; faces report-only optional
(§8 R1); fingerprints report-only never portable; PINs never persisted (§2);
plan-template refs carried by number with conflict when target lacks the preset.**

`employeeNo` is an OPAQUE BYTE STRING — exact match, never int-cast, never
case-normalized (leading zeros are data: `"007"` ≠ `"7"`; two terminals must not be
allowed to disagree silently — a source/target pair differing only by such a
normalization is a CONFLICT, skipped by default).

## 2. Portable bundle format (on disk)

```
bundles/<site>-<host>/
  manifest.json     # schema version, source identity (model, fw, serial prefix),
                    # exported_at UTC (injected clock), counts, per-person hash,
                    # capability matrix (§3), volatile-field list (frozen here)
  people.jsonl      # normalized UserInfo records, one per line. `password` NEVER
                    # written — not even with --carry-pins (see below)
  cards.jsonl       # normalized CardInfo records (employeeNo, cardNo)
  faces/<employeeNo>.jpg   # only if R1 cracked; absent otherwise (faces/INDEX.json
  faces/INDEX.json         # then states faces=UNAVAILABLE with the reason)
```

- **The volatile strip list is FROZEN in the manifest**: `openDoorTime`,
  `numOfCard/numOfFace/numOfFP` counters, `password` (stripped unconditionally),
  per-device URL fields (host part of `photoURL`/`faceURL`). Everything else —
  **including `name`, `Valid`, `RightPlan`, `doorRight`** — is hashed verbatim. The
  same normalization function runs on both sides (bundle and live-target read); it
  lives in one module so the two sides cannot drift.
- **PINs (`password`) never enter a bundle in any mode, encrypted or not.** If the
  operator passes `--carry-pins`, the value is read from source and written to target
  in-memory inside ONE live apply (source read happens again in-run); a dry-run or a
  from-bundle apply CANNOT carry pins. Rationale: bundles are long-lived PII files on
  a developer laptop; an unlock PIN there is a standing secret leak.
- **Content hash** = sha256 over canonical JSON (sorted keys, UTF-8, numbers
  normalized) of the record with ONLY the manifest's volatile set stripped. Diff (§4)
  and verify (§6) compare hashes computed by the same function over live reads.
- Bundle dir 0700, files 0600, always under the configured root (`--out` inside the
  repo is REFUSED — public-repo hygiene). Reports print hashes/counts, never names.

## 3. Capability probe (gate for every export AND apply)

`gateclerk migrate probe --site S [--device H]` → matrix persisted in bundles and
required on apply targets:
- identity (model, fw, serial prefix);
- endpoint availability matrix (§1, computed per device — **notSupport is a
  discovered fact, never assumed**; B/C firmwares unknown until creds arrive);
- counts (users/cards from Search totals with OK check per §0.7); max-capacity:
  probed where discoverable (`deviceInfo`/`AcsCfg`), and where it is NOT discoverable
  (true on A) capacity enforcement drops to fail-fast §5 step 4;
- **templateNo evidence (PlanTemplate is notSupport on this family)**: the only
  existence evidence for a plan template is the union of templateNos OBSERVED in the
  target's own UserInfo `RightPlan` records; a referenced templateNo absent from that
  evidence set is a §4 conflict-skip — never a guess, never a silent zero;
- face situation: FDSearch shape works? FDID list? picture bytes exportable?
- applied probes older than 7 days are stale; staleness is not trusted (§4 freshness).

## 4. Diff / dry-run (the default mode of `apply`) — with a FRESHNESS CONTRACT

`gateclerk migrate diff --bundle B --target S`; `apply` = diff + gated write.

- Target state is READ FRESH at diff time (never a cached/bundled target view).
- Classification per `employeeNo` (opaque-match, §1):
  - **add** — source-only;
  - **update** — on both, hashes differ;
  - **same** — hashes equal (no-op → idempotent re-runs BY CONSTRUCTION);
  - **conflict** — any of: hash differs AND write would destroy target-only facts
    (target's card set ⊄ bundle's card set; target `numOfFP`/`numOfFace` > what the
    bundle can re-create); templateNo referenced but absent on target; employeeNo
    collides only after normalization (§1); card already bound to a DIFFERENT
    employeeNo on target (cross-device card uniqueness — silent payroll corruption
    if migrated).
- **Default policy: conflicts REPORTED AND SKIPPED.** `--on-conflict=skip|overwrite|
  abort`; overwrite replaces only fields the bundle owns — target-side extras
  (cards/faces we cannot see) are never removed (no deletions in v1).
- **Freshness contract (the TOCTOU hole both reviewers found):** `apply` re-diffs
  immediately before EACH write phase against a fresh target read; if any pending
  record's classification changed since plan time, the phase ABORTS and the run
  exits 1 with the changed list — the operator re-diffs. A target read that FAILS
  before the first write ABORTS the whole apply (exit 2): an unverified target is
  never overwritten.
- Output: per-person line = employeeNo **hash prefix + classification + changed
  field NAMES only** (no PII values on console), totals, "would write N". Exit:
  0 no changes / 1 changes pending / 2 config-problem (p1-08 contract).

## 5. Write path (idempotent, ordered, probe-gated)

`apply --bundle B --target T --apply` (without `--apply`: dry-run only — the writing
flag must be explicit).

**Step 0 — endpoint confirmation (a MERGE GATE, not a runtime hope).** Before any
code containing a write verb merges: every write verb's exact endpoint+shape is
CONFIRMED against bench A — capabilities GETs (read-only) + one operator-recorded
live capture (orchestrator-run, post-E1-01 snapshot): one-person SetUp round-trip
(write → read back → restore), response bodies recorded as fixtures, fake replays
them. Unconfirmed verb ⇒ the phase ships REPORT-ONLY. This step is E1-04's first
deliverable.

1. require fresh probe (§3) + **pre-write snapshot of the target** (full export
   bundle of the target written before ANY mutation — the rollback source; on A this
   is the same export the operator mandated);
   1a. **clock-skew gate**: target `System/time` vs real now (GET, read-only); if the
   target clock is off > 60 s, `timeType=local` validity strings would land on wrong
   wall clocks (payroll-critical): ABORT the apply naming the skew — we never touch
   device clocks (standing rule), we refuse to write relative validity into a lying
   clock. `timeType=absolute` runs may proceed (wall digits are explicit).
2. order: users phase → **verify users** → cards phase → verify cards (a card needs
   its person; verify between phases so a bad person batch never compounds);
3. batching + budget math (explicit, tested): per person worst case = 1 user write +
   ≤1 card write + 1 read-back ≈ 3 authed calls ≈ ≤6 digest requests; client
   re-bootstraps at **80 authed calls** (well inside the ~190 cap, OBSERVED.md;
   re-bootstrap is the offline-proven P1 recovery arm — §0.5 note); sleep 1s between
   batches. Batch size from the device's own `@max` where discoverable, else 10
   (the ≤40 figure was invented; it is now derived, not asserted);
4. **capacity fail-fast**: where max counts are not discoverable (§1), a batch is
   still attempted, but the FIRST capacity-rejection response aborts the phase
   (partial-batch rollback = undo-journal of that phase) and reports which records
   were written — never a silent partial write;
5. faces: only if R1 confirmed BOTH ends (§8);
6. verify (§6) after each phase; mismatch = terminal (§0.6);
7. **no deletions ever** in v1. Undo (§5a) is the only removal path.

**§5a Journal + undo.** Journal is append-only JSONL; each entry has lifecycle:
`planned` (append BEFORE the request) → `applied` (device accepted) → `confirmed`
(read-back hash matches) → `restored`/`reverted` (undo). Undo:
- removes ONLY `confirmed` `add`-class records this journal added (planned/applied
  without confirmed are never touched — no phantom deletes);
- for `overwrite`-class entries, undo RESTORES the target's pre-write record (the
  full prior object is stored in the journal entry, sourced from the pre-write
  snapshot) — undo is restore-before-add-delete;
- undo is itself budgeted (§5.3 math), verified by re-read, and gets its own journal.

## 6. Read-back verify (never trust the write's status code)

After each phase, re-`Search` the target for exactly the touched employeeNos and
compare content-hashes (§2) computed by the SAME normalization both sides use.
Per-person verdict `ok | mismatch | missing`. **Fail-closed on unknown fields**: a
target record carrying fields outside the volatile list that the source record lacks
is `mismatch`, not `ok` (a device that silently rejected/mangled data is exactly
what verify is for). PIN comparisons are never part of verify (PINs aren't hashed).
Mismatches stop the next phase; run report = the artifact (counts per
classification/verdict, journal path, bundle hashes, hashes/counts only).

## 7. CLI surface (typer group `gateclerk migrate`)

```
gateclerk migrate probe  --site S                      # capability matrix -> bundles/probes/
gateclerk migrate export --site S [--out DIR]          # snapshot bundle (read-only)
gateclerk migrate diff   --bundle B --target T         # classification table, no writes
gateclerk migrate apply  --bundle B --target T [--apply] [--on-conflict=skip|overwrite|abort]
gateclerk migrate undo   --journal J                   # restore/remove only per §5a
```

Creds: existing resolver unchanged (flag > env > keychain). `-o json` on all
commands: stable schema, PII-free (hashes/counts only, §4).

## 8. Open risks

- **R1 — faces: BOTH ends unconfirmed (face export AND import).** Export: ~8
  FDSearch shapes rejected (`MessageParametersLack: faceLibType`; XML variants
  rejected at envelope — probe rounds 2026-10-21). Import: which endpoint accepts a
  face picture for a person on this family (`FDLib/pictureUpload`? `FDLib/FDSetUp`?
  person-photo endpoint?) is documented-hypothesis only — the claim "target
  re-extracts its own template" is UNVERIFIED and gets its own bench-A capture under
  E1-06 before any upload code merges. Remaining read-only options: device's
  `FDSearch/capabilities` doc on other fw; vendor docs for this family; Hikvision
  Web SDK samples. **Faces are OPTIONAL and additive; E1 ships users+cards with faces
  "reported, skipped" — if either end stays unconfirmed, faces stay on-site enrolled.**
- **R2 — write-verb semantics** (SetUp merge vs overwrite per field, batch caps,
  response envelopes): resolved by §5 step 0 bench-A capture as E1-04's FIRST
  deliverable; code merges after, fake replays the captured fixtures.
- **R3 — `password` in UserInfo/Search responses**: stripped at READ time (bundle
  never sees it, §2); the live in-memory pin carry is opt-in per run; read-back
  never compares pins; no log/report ever prints it.
- **R4 — B/C firmware unknown** → probe-gate (§3) + freshness (§4) mean no B/C write
  can inherit A's assumptions.

## 9. Test strategy (FakeDevice-strict — the standing rule)

FakeDevice gains enrollment endpoints **with A's discovered truth**, and its
strictness must mirror each live-learned axis:
- notSupport matrix exactly as probed (UserInfoDetail, FingerPrint/Search,
  PlanTemplate, capabilities GETs 404);
- FDSearch rejects what the device rejects (R1 shapes);
- **write endpoints implement the bench-A CAPTURED semantics** (fixture replay from
  §5 step 0): merge-vs-overwrite per field, person-must-exist for cards, card
  uniqueness rejection, capacity rejection at the captured threshold — a fake that
  accepts everything is the false-green machine the sub-second-400 lesson named;
- nonce ledger: fake tracks challenges/requests per client so §5.3 budget +
  re-bootstrap-before-80 is a tested number, not a comment;
- **byte-stability test**: seed the fake with the 4-user A corpus + boundary corpus
  (leading-zero employeeNo, mixed case, timeType local vs absolute, validity DST
  edges); export → import-into-fresh-fake → re-export must be byte-identical;
- timeType semantics: export stores BOTH raw pair and normalized absolute UTC;
  apply writes target-side wall digits when target `timeType=local` (payroll-critical,
  the p1-05 class bug applied up front);
- freshness/drift: plan → concurrent target mutation → phase re-diff ABORTS;
  journal lifecycle: kill between `planned` and `applied` → undo touches nothing;
  undo of overwrite restores prior record; card bound to different employeeNo =
  conflict-skipped.
Live validation (post-merge, standing operator OK for bench A): export A snapshot →
orchestrator capture writes (§5 step 0) → mutate one person via A UI-equivalent →
diff detects → apply restores → verify passes → undo exercised. B/C: nothing until
creds + explicit write OK (dry-run + read-only first).

## 10. Atomic card plan (DAG; each = one module + tests; workers NEVER touch the
device — live bench steps are the orchestrator's, per fleet rule)

| card | scope | parents |
|---|---|---|
| E1-01 | bundle format + export (users/cards) + hashes + PII hygiene (pin-strip at read, 0600, no-repo-out) + fail-closed reads | — |
| E1-02 | diff engine + classification (incl. card-uniqueness/normalization conflicts) + freshness re-diff helper + report | 01 |
| E1-03 | capability probe + matrix + staleness gate | — |
| E1-04 | write foundation: **endpoint confirmation capture (orchestrator bench step, feeds fixtures)** + journal lifecycle + users phase + users verify | 02, 03 |
| E1-05 | cards phase + undo (restore-before-delete) + capacity fail-fast wiring | 04 |
| E1-06 | faces (R1: confirm BOTH ends on bench; additive; ships report-only until then) | 04 |
| E1-07 | `gateclerk migrate` CLI group wiring 01-05 + `-o json` schema | 05 |

Dispatch order: 01 + 03 now → 02 after 01 → (orchestrator: bench-A snapshot via
merged E1-01 + §5 step-0 capture) → 04 → 05 → 07; 06 whenever R1 falls.

## 11. Review log (v1 → v2)

Two independent adversarial reviews (write-path correctness; ISAPI realism + fake
strictness), both FIX-FIRST. Applied: endpoint-confirmation merge gate (§5.0/R2),
freshness contract + fail-closed target reads (§4/§0.7 — both reviewers hit this
independently), PINs never persisted (§2/R3), journal lifecycle + restore-based
undo (§5a), cross-device card uniqueness + normalization conflicts (§4), timeType
semantics (§1/§9), batch size derived not invented + explicit nonce-budget math
(§5.3), fail-closed unknown-field verify (§6), byte-stability + write-semantics
fixtures (§9), face import also-unconfirmed (R1 widened). **Rejected, with reason**:
"hash strips `name`" (it does not — volatile list is explicit and both-sides),
"re-bootstrap is an unsupported claim" (P1 shipped it, offline-proven; OBSERVED
honestly records it was never live-exercised — now stated as E1's first live use),
"undo gets its own budget note" (folded into §5a).
