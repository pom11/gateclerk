# Enrollment migration between devices — design (E1)

Status: **ORCHESTRATOR-AUTHORED v3, operator-delegated 2026-10-21** ("you own the
design end to end"). Two adversarial reviews returned (write-path correctness; ISAPI
realism + fake strictness), **both FIX-FIRST**; §11 is the real reconciliation log —
v3 applies their new findings on top of v2's pre-hardening. Track name **E1**
(deliberately not "P3" — P3/BC stays out of scope, owner decision).
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

Scope cut (first ship): **users identity/validity port; cards port (ownership-checked,
§4); RightPlan/doorRight REPORT-ONLY by default (§1a); fingerprints report-only never
portable; PINs never persisted (§2); faces report-only optional (§8 R1).**

`employeeNo` is an OPAQUE BYTE STRING — exact match, never int-cast, never
case-normalized (leading zeros are data: `"007"` ≠ `"7"`; two terminals must not be
allowed to disagree silently — a source/target pair differing only by such a
normalization is a CONFLICT, skipped by default).

**§1a — doorRight/RightPlan are REPORT-ONLY by default (reviewer BLOCKER: silent
access corruption).** `RightPlan[].templateNo` names a DEVICE-LOCAL preset whose
content is **unprovable on this family** (PlanTemplate is notSupport, §1): copying
`templateNo=3` from A to B can install a DIFFERENT access schedule under the same
number — worse than data loss, it is silently wrong ACCESS CONTROL, and neither diff
nor verify can see it (the numbers match, the meaning differs). The only existence
evidence is the union of templateNos observed in the target's own UserInfo records,
and existence ≠ content. Therefore: `RightPlan`/`doorRight` are carried in the bundle
+ diffed + **reported as needing on-site application**, and only written when the
operator passes `--carry-templates` AND the target probe's evidence set contains the
number — and the run report then states in terms: **template content UNVERIFIED —
verify the schedule on-site**. `userType` (admin/normal) is likewise a security field:
carried, but every carried `admin`/`localUIRight` value is listed in the report for
explicit operator acknowledgement before apply.

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
  (true on A) capacity enforcement drops to fail-fast §5 step 4 — the probe records
  the discovery attempt and its outcome, so a future fw that DOES expose caps upgrades
  automatically and A's silence stays a recorded fact (reviewer: `AcsCfg` carries
  behavior switches like `saveFacePic`, not user/card maxima);
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
   **write-field set ≠ bundle record**: SetUp bodies carry ONLY the writable
   allow-list (employeeNo, name, userType, Valid, — door fields only per §1a — cards
   via CardInfo, password only live with --carry-pins). Device-generated/read-only
   keys (`photoURL`/`faceURL`, `gender`, `localUIRight`, counters, `numOf*`) are
   NEVER echoed back: a read-shape echo risks 400 badJsonContent or silent partial
   merges on unrecorded per-field semantics (R2). The allow-list is frozen from the
   §5.0 bench capture, not from the search response;
4. **capacity fail-fast**: where max counts are not discoverable (§1), a batch is
   still attempted, but the FIRST capacity-rejection response aborts the phase
   (partial-batch rollback = undo-journal of that phase) and reports which records
   were written — never a silent partial write;
5. cards: `CardInfo/SetUp` merge. **Ownership-checked, not presence-checked**
   (reviewer BLOCKER): a `cardNo` already on the target bound to a DIFFERENT
   `employeeNo` is a §4 CONFLICT — never silently skipped (that person would never
   get their card) and never silently reassigned (that strips someone else's).
   Re-run idempotency is `(cardNo, employeeNo)` PAIR identity, not cardNo presence.
   **No card fixture exists yet** (A had 0 cards, §1): before the card phase's fake is
   written, the bench capture must write one card to a test person and record the
   NONZERO `CardInfo/Search` response as a fixture (E1-05 prerequisite); until then
   card export is shape-strict (unseen keys/shape → abort, never guess);
6. faces: only if R1 confirmed BOTH ends (§8); the face phase needs its OWN verify
   arm — a face upload does NOT change the UserInfo content-hash, so §6's user verify
   proves nothing about it (reviewer MAJOR). Face verify = the recorded read
   (FDSearch row / per-FDID count delta) captured in the same bench step;
7. verify (§6) after each phase; mismatch = terminal (§0.6);
8. **no deletions ever** in v1. Undo (§5a) is the only removal path.

**§5a Journal + undo.** Journal is append-only JSONL; each entry carries lifecycle
state: `planned` (append BEFORE the request, fsync'd — an entry that can be lost to a
crash is not a journal) → `applied` (device accepted) → `confirmed` (read-back hash
matches) → `restored`/`reverted` (undo). Entry fields: classification, pre-write
record (full object, from the pre-write snapshot), intended record, post-write
content-hash. Undo (reviewer: "removes only what this run added" needs PROOF, not
trust):
- deletes ONLY `confirmed` `add`-class entries whose LIVE re-read hash still equals
  the journal's post-write hash (proof-of-add) — a record modified by anyone else
  since is NOT touched: undo refuses and escalates (someone else's edit wins);
- `planned`/`applied` without `confirmed` are never deleted (unknown state = human);
- for `overwrite`-class entries, undo RESTORES the journal's pre-write record
  (restore-before-delete), re-verified by read-back;
- undo is itself budgeted (§5.3 math), verified by re-read, and gets its own journal.

## 6. Read-back verify (never trust the write's status code)

After each phase, re-`Search` the target for the touched employeeNos and compare
content-hashes (§2) computed by the SAME normalization both sides use. **The
server-side `employeeNoList` filter is UNPROVEN on this fw** (reviewer MAJOR): the
verify walker must be pinned BOTH ways — try the filtered search, verify the returned
set actually covers the requested list (the "filter is a hint, not a promise" rule
from OBSERVED: the suffixless `employeeNo` form is SILENTLY IGNORED), and fall back
to full paging + CLIENT-SIDE exact-match filtering whenever coverage is incomplete.
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
  accepts everything is the false-green machine the sub-second-400 lesson named.
  **Hard rule from reviewer task-1 (their BLOCKER): no write-shaped fake route may
  exist before its capture exists.** For the WRITE axis A has discovered NOTHING yet
  (the §1 table is GETs/search-POSTs only), so a SetUp fake written today would
  encode a guess and make "offline suite green" structurally meaningless on the only
  axis that matters. Sequence is therefore: bench capture (E1-04 deliverable 1) →
  fixtures committed → fake routes written against fixtures → write code. A PR that
  contains a write verb without a committed capture fixture fails the gate by rule.
  Card routes additionally wait for the NONZERO `CardInfo/Search` capture (§5 step 5):
  today there is no card fixture at all (A had 0 cards).
- nonce ledger: fake tracks challenges/requests per client so §5.3 budget +
  re-bootstrap-before-80 is a tested number, not a comment;
- **byte-stability test**: seed the fake with the 4-user A corpus + boundary corpus
  (leading-zero employeeNo, mixed case, timeType local vs absolute, validity DST
  edges); export → import-into-fresh-fake → re-export must be byte-identical;
- timeType semantics: export stores BOTH raw pair and normalized absolute UTC;
  apply writes target-side wall digits when target `timeType=local` (payroll-critical,
  the p1-05 class bug applied up front);
- **Target face/FP state is UNKNOWN, not zero** (reviewer MAJOR): FDSearch is broken
  on this family, so a target person's face set cannot be read. Face/FP presence is
  therefore taken from the `numOfFace`/`numOfFP` counters in the UserInfo record and
  marked `UNKNOWN(unreadable, counter=N)`: if N > 0 and the bundle cannot account for
  those enrollments, the person is a §4 **conflict** (skipped by default), never an
  `update`. A count is not a set — the design never pretends otherwise. Same
  treatment for `saveFacePic`-shaped capability switches: they are recorded as
  discovered values with no inference about what the device will accept.
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

Dispatch order (capture-before-fake is the spine, §9): **01 + 03 now** → 02 after 01
→ **orchestrator bench-A step** (export snapshot via merged E1-01 first, then the
§5.0 captures: one-person user SetUp round-trip fixture + one NONZERO `CardInfo/
Search` fixture from a test-person card) → 04 (fake routes from fixtures, then code)
→ 05 → 07; 06 whenever R1 falls. No PR containing a write verb is gated before its
capture fixture exists in the tree.

## 11. Review log (v1 → v2 → v3)

Two independent adversarial reviews ran on v2 — write-path correctness (3 BLOCKERs)
and ISAPI realism + fake strictness (2 BLOCKERs, 1 MAJOR). Both verdicts FIX-FIRST.
Transcripts: cache/delegation/live/deleg_6c47234f/.

**New from the reviewers, applied in v3** (these were NOT in my v2):
1. `templateNo` silent-copy = silently wrong ACCESS CONTROL (numbers match, meaning
   differs; unprovable on this fw) → §1a: door fields REPORT-ONLY by default,
   `--carry-templates` + evidence-set + UNVERIFIED-in-report wording.
2. Card re-run idempotency keyed on presence, not ownership → §5 step 5: `(cardNo,
   employeeNo)` pair identity; cardNo bound to another person = conflict, never
   silent skip/reassign.
3. Undo's "removes only what this run added" was trust, not proof → §5a: deletes only
   `confirmed` add-entries whose live re-read hash still equals the journal's
   post-write hash (proof-of-add); anyone-else-modified → refuse + escalate.
4. A write fake written today would encode a GUESS (A has discovered nothing on the
   write axis) → §9 hard rule: no write-shaped fake route before its bench capture
   fixture is committed; write-verb PR without fixture fails the gate by rule.
5. No card fixture exists (A has 0 cards — my §1 table proved the query answers, not
   the data) → §5 step 5: NONZERO `CardInfo/Search` capture from a bench test-person
   is a prerequisite for the card fake; export shape-strict until then.
6. `employeeNoList` server-side filter unproven (OBSERVED's "suffixless form is
   SILENTLY IGNORED" applies) → §6: filtered search must prove coverage, else full
   paging + client-side exact-match.
7. Face phase had no verify arm (a face upload leaves the UserInfo hash unchanged) →
   §5 step 6: own verify = the recorded FDSearch/count-delta read from the same bench
   capture.
8. Read-shape echo into SetUp risks 400/silent partial merges → §5 step 3:
   writable-allow-list frozen from the capture; device-generated keys never echoed.
9. `AcsCfg` carries behavior switches, not capacity maxima (my §3 claimed it as a
   caps source) → §3: probe records the discovery attempt + outcome; fail-fast stays.
10. Target face/FP state is UNKNOWN (unreadable), not zero → §9: counter-derived
    `UNKNOWN(counter=N)` and N>0-unaccounted = conflict, never `update`.

**Kept from my v2 pre-hardening** (reviewers did not raise them; they survive):
endpoint-confirmation merge gate, freshness/TOCTOU contract, PINs-never-persisted,
journal lifecycle, timeType local-vs-UTC, derived batch caps + nonce math,
unknown-field fail-closed verify.

**Rejected with reason** (both rounds): "hash strips `name`" (it does not — volatile
list is explicit, both sides, one module); "re-bootstrap is an unsupported claim"
(P1 shipped it offline-proven; OBSERVED honestly says never live-exercised — E1 is
its first live use).
