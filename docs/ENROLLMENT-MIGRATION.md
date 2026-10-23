# Enrollment migration between devices — design (E1)

Status: **ORCHESTRATOR-AUTHORED v4, operator-delegated 2026-10-21** ("you own the
design end to end"). Two adversarial reviews returned (write-path correctness; ISAPI
realism + fake strictness), **both FIX-FIRST**; §11 is the real reconciliation log —
v3 applies their new findings on top of v2's pre-hardening. **v4 = operator scope
correction + the read-axis probes it triggered** (faces and fingerprints are THE
PRODUCT, not an optional tail; both READS are now PROVEN on bench A, so v3's
report-only verdicts on them are replaced by capture-gated ports). Track name **E1**
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
| users | POST `UserInfo/Search` (cond **wrapped**: `{"UserInfoSearchCond":{searchID,…}}` — flat bodies 400 `badJsonContent`; `searchID` REQUIRED) | read works — 4 users; record carries `employeeNo,name,userType,Valid{enable,beginTime,endTime,timeType:"local"},doorRight,RightPlan[{doorNo,planTemplateNo}],belongGroup,localUIRight,maxOpenDoorTime,numOfCard,numOfFace,numOfFP,password(≤8,ch),gender,…`; `EmployeeNoList:[{employeeNo}]` filter **PROVEN HONORED** (1→1, 99→0 NO MATCH); paging `maxResults=2`→MORE | that `UserInfo/SetUp` exists/accepts this shape (write-confirm step, §5.0; caps `supportFunction @opt` DOES list `setUp`) |
| cards | POST `CardInfo/Search` (wrapped `CardInfoSearchCond`) | query shape answers (device had 0 cards — read path exercised, data not); caps: `supportFunction` lists `setUp`, `cardNo` ≤20, `cardType ∈ normalCard,patrolCard,hijackCard,superCard`, `maxRecordNum=3000` | that export returns real cardNo values (verify during A snapshot) or `CardInfo/SetUp` accepts them |
| per-person detail | POST `UserInfoDetail/Search` | **404/400 notSupport** on this fw — door rights live IN the UserInfo record (`RightPlan`), no separate endpoint | — |
| face libs | GET `Intelligent/FDLib` | FDID 1 `blackFD`, FDID 2 `infraredFD` | — |
| face records | POST `Intelligent/FDLib/FDSearch` — **FLAT body (no wrapper! device dialect differs per endpoint)**: `{searchResultPosition,maxResults,faceLibType:"blackFD",FDID:"1"[,FPID:"<employeeNo>"]}` | **RESOLVED 2026-10-21 (operator shape confirmed):** rows carry `FPID` (= employeeNo, the ACS binding), `faceURL` and **`modelData`** (base64 face TEMPLATE, 272 B, magic `FR500005\x01…`; `FDLib/capabilities isSupportModelData=true`). Paging quirk: maxResults=30 returned 3 of totalMatches=4 → walker must page to NO MATCH. `FDLib/FDSetUp` EXISTS (GET → `methodNotAllowed`, not 404) | face **photo bytes**: `faceURL` GETs 404 (with `@WEB…` token, %-encoded, fresh-cookie — dead on this fw; capture session gets one bounded retry of alternatives). face **upload**: which of `FDLib/FDSetUp` / `FaceDataRecord` accepts a `modelData` (± JPEG) is UNVERIFIED → §5.0 capture (R1 now = upload end only) |
| fingerprints | READ: POST `AccessControl/FingerPrintUpload?format=json` `{"FingerPrintCond":{searchID,employeeNo,fpIndex,dataType:"template"}}` (misleading name = device→client) | **RESOLVED 2026-10-21 (operator shape confirmed):** emp 1 `fpID=1 normalFP` template returned (512 B, header `30 31 31`-style ASCII "301" = third-party sensor family, NOT self-identified). `FingerPrint/Search` really is notSupport; `FingerPrintDownload/capabilities` 404 | WRITE via `FingerPrintDownload` (client→device) is documented-hypothesis → §5.0 capture. Cross-device portability only claimable WITHIN the same sensor family; target fw unknown until B/C creds |
| plan templates | `PlanTemplate*` + GET `UserInfo/capabilities` | notSupport (no content read); caps DO expose `RightPlan{maxSize:1,doorNo:1,maxPlanTemplate:4,planTemplateNo 1..255}`; **every UserInfo record on A uses `planTemplateNo:"1"`** | preset CONTENT still unreadable; `templateNo 1` = Hikvision all-day built-in is vendor convention + bench-evidence (all users), see §1a v4 rule |
| caps | GET `UserInfo/capabilities`, `CardInfo/capabilities`, `FDLib/capabilities`, `AcsCfg/capabilities` | all four work (JSON). UserInfo: `maxRecordNum=3000`, `password ≤8`, `Valid timeType @opt "local"` ONLY, `userType @opt normal,visitor,blackList` (no admin option), time range 2000-01-01…2037-12-31. FDLib: `FDMaxNum=2`, `FDRecordDataMaxNum=3000`, `modelMaxNum=1`, **`isSuportFDSearch=false` while FDSearch demonstrably WORKS** — caps under-claim too | true device CAPACITY (max enrolled users/cards) still unexposed → capacity: fail-fast §5 step 4 (`maxRecordNum` is a batch/page cap, NOT capacity) |

Scope cut (v4 — faces + FP templates are THE PRODUCT, operator 2026-10-21): **users
identity/validity port; cards port (ownership-checked, §4); face migration =
`modelData` template port (export PROVEN, upload = critical-path capture §5.0);
fingerprint template port (export PROVEN, write capture §5.0, same-sensor-family
rule); RightPlan/doorRight carried per §1a v4 (templateNo 1 default-allowed);
PINs never persisted (§2); face PHOTO bytes out of scope (faceURL 404 on this fw —
the template is what makes a face work, not the JPEG).**

`employeeNo` is an OPAQUE BYTE STRING — exact match, never int-cast, never
case-normalized (leading zeros are data: `"007"` ≠ `"7"`; two terminals must not be
allowed to disagree silently — a source/target pair differing only by such a
normalization is a CONFLICT, skipped by default).

**§1a — doorRight/RightPlan: templateNo 1 default-allowed, custom numbers
REPORT-ONLY (v4, operator + reviewer).** `RightPlan[].templateNo` names a
DEVICE-LOCAL preset whose content is unreadable on this family (PlanTemplate
notSupport, §1). v4 evidence change: on bench A **every** UserInfo record references
`planTemplateNo:"1"` and caps expose `maxPlanTemplate:4` — Hikvision ACS convention
is that plan template 1 is the built-in all-day schedule, identical on every device
of the family (v3's blanket report-only made every migrated person land with NO door
right, which is its own failure mode). v4 rule, three tiers:
- `planTemplateNo == "1"` → **carried by default** (built-in all-day; the bench
  capture §5.0 includes one read-back assertion that a carried template-1 person
  shows the identical RightPlan on read-back);
- any custom number (2..255) → REPORT-ONLY unless `--carry-templates` AND the number
  appears in the target probe's evidence set (union of target UserInfo RightPlan
  numbers); carried customs print in the report as **content UNVERIFIED — verify the
  schedule on-site**;
- `doorRight`/`belongGroup`/`doorNo` follow the same device-local-ID rule.
`userType` (admin/normal) is likewise a security field: carried, but every carried
`localUIRight=true` or non-`normal` userType is listed in the report for explicit
operator acknowledgement before apply (note: A's caps only offer
`normal,visitor,blackList` — no `admin` writable on this fw).

## 2. Portable bundle format (on disk)

```
bundles/<site>-<host>/
  manifest.json     # schema version, source identity (model, fw, serial prefix),
                    # exported_at UTC (injected clock), counts, per-person hash,
                    # capability matrix (§3), volatile-field list (frozen here)
  people.jsonl      # normalized UserInfo records, one per line. `password` NEVER
                    # written — not even with --carry-pins (see below)
  cards.jsonl       # normalized CardInfo records (employeeNo, cardNo)
  faces/<employeeNo>.b64       # FDSearch `modelData` = the face TEMPLATE (base64 as
                               # the device gave it; opaque bytes, never parsed)
  faces/INDEX.json             # per-person: FDID, FPID, template sha256+length, and
                               # the faceURL-404 note (photo bytes NOT exportable on
                               # this fw — recorded fact, not an omission)
  fingerprints/<employeeNo>-<fpIndex>.b64  # FingerPrintUpload-read templates
                               # (opaque bytes + sensor-family note from header)
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
- **E1-01b (template export) is IMPLEMENTED** on the stack branch (E1-01's shipped
  state was `faces/INDEX.json` = UNAVAILABLE + FP absent, which its tests keep
  pinned). `export_faces()` walks FDSearch FDID 1 in the proven FLAT dialect via the
  `paging.fd_search` engine (flat body, no `searchID`, page-until-zero for the
  3-of-4-on-one-OK-page quirk); `export_fingerprints()` reads FingerPrintUpload per
  employee fpIndex-by-fpIndex to the pinned empty-`FingerPrintList` stop shape (no
  probed device word exists for "no more" — recorded as engine label
  `OK-EMPTY-LIST`, PR reviewer question); `export_full_bundle()` composites the four
  reads. Bundle schema bumped to `gateclerk-enrollment-bundle/2`: AVAILABLE-state
  INDEX.json files (per-person FDID/FPID/sha256/length + the faceURL-404
  `photo_bytes` recorded fact), manifest face/FP sections + INDEX digests +
  REPORT-ONLY `numOfFace`/`numOfFP` counters (counter-vs-set §9: reported, never
  resolved), `fingerprints/` dir. Template bytes stay OPAQUE end to end: files carry
  the device's base64 verbatim; digests are over the decoded bytes (transport, not
  parsing); the sensor-family value is a header-bytes NOTE.

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

> **§5.0 RESULTS (capture session 2026-10-22, bench A; OBSERVED.md "E1 §5.0
> WRITE-PATH CAPTURE"):** users `PUT UserInfo/SetUp` flat-under-wrapper +
> `mode:"add"` **PROVEN**; cards `PUT CardInfo/SetUp` same dialect **PROVEN**;
> faces `PUT FDSetUp` FLAT `{faceLibType,FDID,FPID,modelData}` **PROVEN** (R1 —
> read-back template identical, incl. a full wipe→restore round-trip with
> matching content hashes); FP write `POST FingerPrintDownload`
> `{"FingerPrintCfg":{"enableCardReader":[1],…,"fingerData":…}}` **accepted but
> NEVER APPLIED** — `FingerPrintProgress` shows `cardReaderRecvStatus:5` (bench
> reader rejects the third-party-family template): E1-06b is report-only on this
> evidence class, write-fake may only be built to the captured accept/reject
> shapes. **The capture also found a SILENT-WIPE hazard: `UserInfoDetail/Delete`
> with `mode:"delete"` and the employee list in the WRONG slot deleted EVERY
> user.** See §5b rule D-WIPE before any delete code is written.

`apply --bundle B --target T --apply` (without `--apply`: dry-run only — the writing
flag must be explicit).

**Step 0 — endpoint confirmation (a MERGE GATE, not a runtime hope).** Before any
code containing a write verb merges: every write verb's exact endpoint+shape is
CONFIRMED against bench A — capabilities GETs (read-only, DONE 2026-10-21: UserInfo/
CardInfo/FDLib/AcsCfg caps recorded in §1; `UserInfo/SetUp/capabilities` and
`FingerPrintDownload/capabilities` are 404, so the remaining verbs are confirmed only
by live capture) + ONE operator-recorded live capture session (orchestrator-run,
after the E1-01 export snapshot of A): users SetUp round-trip (one test person:
write → read back → restore), one card write → NONZERO `CardInfo/Search` fixture,
FP write via `FingerPrintDownload` → `FingerPrintUpload`-Cond read-back, face upload
(`FDLib/FDSetUp` vs `FaceDataRecord`, modelData ± JPEG) → FDSearch read-back. The
operator's instruction is ONE device session for all of it (export snapshot first,
then round-trips, then restore) — fewer sessions, same fixtures. Response bodies
recorded as fixtures; fake replays them. Unconfirmed verb ⇒ the phase ships
REPORT-ONLY. This step is E1-04's first deliverable.

1. require fresh probe (§3) + **pre-write snapshot of the target** (full export
   bundle of the target written before ANY mutation — the rollback source; on A this
   is the same export the operator mandated);
   1a. **clock-skew gate**: target `System/time` vs real now (GET, read-only); if the
   target clock is off > 60 s, `timeType=local` validity strings would land on wrong
   wall clocks (payroll-critical): ABORT the apply naming the skew — we never touch
   device clocks (standing rule), we refuse to write relative validity into a lying
   clock. `timeType=absolute` runs may proceed (wall digits are explicit).
2. order: users phase → **verify users** → cards phase → verify cards → fingerprints
   phase → verify FP → faces phase → verify faces (a card/face/FP needs its person;
   verify between phases so a bad person batch never compounds);
3. batching + budget math (explicit, tested): per person worst case = 1 user write +
   ≤1 card write + 1 FP template write + 1 FP read-back + 1 face upload + 1 FDSearch
   read-back ≈ 6 authed calls ≈ ≤12 digest requests (v4: FP/face phases added to the
   ledger); client re-bootstraps at **80 authed calls** (well inside the ~190 cap,
   OBSERVED.md; re-bootstrap is the offline-proven P1 recovery arm — §0.5 note);
   sleep 1s between
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
6. faces: **template port is the product (v4)** — export is PROVEN (FDSearch
   `modelData`, §1); the upload endpoint (`FDLib/FDSetUp` — exists per
   `methodNotAllowed` — vs `FaceDataRecord`) + exact multipart/body shape comes from
   the §5.0 capture BEFORE any upload code or fake route merges (capture-before-fake,
   §9). The face phase needs its OWN verify arm — a face upload does NOT change the
   UserInfo content-hash, so §6's user verify proves nothing about it (reviewer
   MAJOR). **Face verify = re-run FDSearch for the FPID and compare `modelData`
   hash + length against the journal's intended template** (FDSearch read is proven
   on A; the capture must record the read-back pair). §6's user verify stays
   hash-based; FP verify = re-read via `FingerPrintUpload` Cond, compare template
   hash. `modelMaxNum=1` + `FDMaxNum=2` are recorded probe facts, not guessed
   semantics; capacity rejects are fail-fast (§5 step 4). Face PHOTO bytes are out of
   scope on this fw (faceURL 404s, §1); if a target fw serves photo bytes the
   bundle format has room for them later;
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

**§5b rule D-WIPE (capture 2026-10-22; bench A lost every user TWICE to this).** A delete
request whose target-list is NOT in the slot the device reads is not a no-op — the
device ignores the unknown slot and deletes ALL. Therefore no delete may be sent
until its EXACT list-slot shape has been captured on that device class, and every
delete is wrapped: (a) `UserInfo/Count` before + after, (b) read-back of the named
employeeNos, (c) if the after-count dropped by MORE than the named list, treat as an
incident: stop everything, restore from the pre-run bundle (§2 export runs before
any write, always), escalate. The fake enforces the hazard: a delete body whose list
sits in a slot the captured shape does not name must answer statusCode 1 AND wipe the
whole store — a delete fake that only ever deletes what it is told teaches nothing.
Face/card deletes (captured-safe shapes) carry the same count-delta guard.

**§5b.1 — USER DELETE IS BANNED OUTRIGHT (CLOSED on evidence, second session).** The
axis was driven to exhaustion: both bodies this fw *accepts* (`mode:"delete"` and the
documented targeted `mode:"deleteByEmployeeNo"`, list in sibling `UserInfoDelCond`)
each returned `ok` and wiped the ENTIRE roster; every list-inside-`UserInfoDetail`
body 400s. There is no accepted targeted user-delete shape on DS-K1T341AMF-S
V3.2.30 (OBSERVED.md "USER DELETE IS NOT TARGETABLE"). So this is not a "verify
harder" problem — the verb does not exist on this fw. Consequences, binding:
1. no code path may PUT `UserInfoDetail/Delete` against a real device, ever, not
   even wrapped — the count-delta guard would only discover the wipe after it;
2. **undo of a user ADD has no API path**: `restored`/`reverted` for the users phase
   is REPORT-ONLY ("re-enroll/restore manually from the pre-run bundle") — E1-04's
   journal still records intent, E1-05 must not fake a user-undo verb;
3. face and card deletes ARE targeted and capture-proven (list slot verified safe),
   so card-phase undo may use the card delete with the §5b count-delta wrapper;
4. the fake reproduces BOTH accepted wipe shapes (any mode value, sibling slot ⇒
   wipe-all) and 400s every inside-list shape — tests must pin that even a
   correctly-shaped-by-analogy user delete hits the wipe branch.

## 6. Read-back verify (never trust the write's status code)

After each phase, re-`Search` the target for the touched employeeNos and compare
content-hashes (§2) computed by the SAME normalization both sides use. **The
server-side `EmployeeNoList` filter is PROVEN HONORED on A (2026-10-21 A/B:
`[{"employeeNo":"1"}]` → 1/4, `"99"` → 0/NO MATCH)** — but the coverage-proof
discipline stays (OBSERVED: some Hikvision filters ARE silently ignored, e.g.
`AcsEventCond.employeeNo`): the walker asserts the returned set covers the requested
list and falls back to full paging + CLIENT-SIDE exact-match whenever it doesn't.
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

- **R1 — faces: export end RESOLVED 2026-10-21 (operator's shape was right); the
  upload end is the critical path, not an optional tail.** `FDSearch` (FLAT body,
  `faceLibType:"blackFD"`, `FDID:"1"`, optional `FPID:"<employeeNo>"`) returns per
  person a `modelData` face TEMPLATE (272 B, magic `FR500005\x01…`) — the thing that
  actually makes face unlock work. Photo bytes via `faceURL` are DEAD on this fw
  (404 with token, %-encoded and fresh-cookie alike, §1) — so v4 migrates the
  TEMPLATE, and the JPEG is a nice-to-have, not the product. Remaining unknown:
  which write verb accepts it (`FDLib/FDSetUp` exists per `methodNotAllowed`;
  `FaceDataRecord` unprobed at write) and whether it takes modelData directly or
  demands a JPEG for re-modeling (`modelMaxNum=1` hints the device models from
  picture). **This is the §5.0 capture's first experiment, and E1-06 is therefore on
  the critical path (v4, operator: "FACES ARE THE PRODUCT")** — E1-06's fake routes
  and code both wait on the capture fixtures. If the capture shows the device only
  accepts a JPEG it cannot obtain (photo bytes unexportable), faces fall back to
  report-only WITH the reason recorded; that outcome is decided by evidence in the
  capture, not by optimism.
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
  PlanTemplate, `UserInfo/SetUp/capabilities` + `FingerPrintDownload/capabilities`
  404) — while the PROVEN-WORKING routes stay demanding: `UserInfo/Search` requires
  the WRAPPED `UserInfoSearchCond` + `searchID` (flat body → `badJsonContent`,
  missing searchID → `MessageParametersLack` — the device rejects BOTH ways, §1);
  `FDSearch` requires the FLAT operator shape (`faceLibType`,`FDID`; FPID optional
  filter) and rejects the wrapped style the users endpoint demands — **the per-
  endpoint dialect split is itself a fake-strictness test**, because a client that
  "helpfully" normalizes bodies across endpoints would pass a naive fake and die on
  the device;
- FDSearch behaves as discovered: FPID filter honored, `modelData` present on every
  row, paging quirk (a page may return fewer than totalMatches with OK) — walker
  must page to NO MATCH, the fake must be able to reproduce the quirk;
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
- **Target face/FP state is UNKNOWN only when the READ fails** (v4 update — the
  reviewer's MAJOR was written when both reads were thought dead; both now WORK on
  A): face set = FDSearch rows for the person (compare against `numOfFace`), FP set =
  `FingerPrintUpload`-Cond reads (compare against `numOfFP`). On a target fw where
  either read 400s/404s mid-run, presence falls back to the counter and is marked
  `UNKNOWN(counter=N)`: if N > 0 and the bundle cannot account for those
  enrollments, the person is a §4 **conflict** (skipped by default), never an
  `update`. A count is not a set — the design never pretends otherwise. Capability
  switches (`saveFacePic`, `isSuportFDSearch=false`-despite-working) are recorded as
  discovered values with NO inference either direction — this fw's caps under-claim.
- freshness/drift: plan → concurrent target mutation → phase re-diff ABORTS;
  journal lifecycle: kill between `planned` and `applied` → undo touches nothing;
  undo of overwrite restores prior record; card bound to different employeeNo =
  conflict-skipped.
Live validation (post-merge, standing operator OK for bench A): export A snapshot →
orchestrator capture writes (§5 step 0) → mutate one person via A UI-equivalent →
diff detects → apply restores → verify passes → undo exercised. B/C: nothing until
creds + explicit write OK (dry-run + read-only first).

### 9.1 LIVE VALIDATION RESULT — bench A, 2026-10-23 (E1-08, orchestrator-run) ✅

First real use of the product transport against a device. Full session log:
`~/gateclerk-data/live/*.json` (PII-free CLI report envelopes).

- **probe** → schema-2 document, exit 0 (surfaces, counts, caps, clock).
- **export B1** → baseline 4 users / 4 faces (272 B each) / 0 cards / 0 FP;
  termination `OK / NOMATCH / NOMATCH / ONE-SHOT-COMPLETE` — honest zeros.
- **workload** (captured shapes only, throwaway person 90 + card + face) → export
  **B2**: 5 / 5 / 1 / 0.
- **wipe** (deliberate, the one accepted `UserInfoDetail/Delete` shape §5b; B1+B2
  on disk first) → `userNumber: 0`.
- **product `migrate apply B2 --apply` onto the empty box** → users 5 landed,
  cards 1 landed, faces 5 landed, clean, exit 0, journal `runs/20261023T083534Z`.
  **Verified by fresh product export: people set AND face (employee, sha256) set
  byte-identical to B2.** The migration product really migrates a real terminal.
- **undo arms against the same journal**: cards → 1→0 targeted, exit 0; faces →
  25 delete calls, per-employee count deltas 5→4→3→2→1→0, zero incidents, FDSearch
  then NOMATCH; users → refused report-only with the §5b.1 note, roster untouched
  at 5. Exactly the designed behavior of all three modes.
- **restore**: wipe again + **product `apply B1`** (the product restores its own
  baseline) → diff vs B1 all-same exit 0; final export people+faces == B1.
  Events store survived both wipes untouched (earliest serial 27 and newest 5753
  readable post-wipe; separate storage). Bench A = baseline, person-1 FP absent as
  before (never re-appliable by design).
- Dry-run-before-apply held every time (journal dir exists only after `--apply`).

Findings (filed on card E1-08, fixes = small cards):
1. **probe persistence bypasses the repo-out guard** — `probe` persists to
   `bundle_root()/probes/` (default `~/gateclerk/bundles`), and `_refuse_repo_out`
   guards only `export --out`; PII-bearing probe JSON landed *inside* the local
   ops git repo `~/gateclerk` (device host in the filename, identity hashes inside).
   Mitigating facts verified during the run: that repo has NO remotes and the file
   was untracked, so nothing left the machine; it was moved out by hand. Fix card:
   apply the same refusal in the probe persist path (+ a hygiene test), and add
   `bundles/` to the ops repo's .gitignore (local ops action, not a product card).
2. **undo journal path is `<journal>.json` for cards/faces but `<stem>.undo.jsonl`
   for faces... ** — actually observed: cards `cards.undo.jsonl`, faces
   `faces.undo.jsonl` — consistent. Correction: no defect; earlier confusion was
   my report-key assumption (`countBefore/countAfter` exist only in the cards
   report; faces report uses `deltas`). Recorded here so the next reader doesn't
   re-trip on it.
2b. **events `--since/--until` whole-history window is slow** (~10k rows: minutes
    through the CLI paging at maxResults=30) — noted, not a defect.

## 10. Atomic card plan (DAG; each = one module + tests; workers NEVER touch the
device — live bench steps are the orchestrator's, per fleet rule)

| card | scope | parents |
|---|---|---|
| E1-01 | bundle format + export (users/cards/**faces modelData/FP templates**) + hashes + PII hygiene (pin-strip at read, 0600, no-repo-out) + fail-closed reads | — |
| E1-02 | diff engine + classification (incl. card-uniqueness/normalization conflicts) + freshness re-diff helper + report | 01 |
| E1-03 | capability probe + matrix + staleness gate | — |
| E1-04 | write foundation: **endpoint confirmation capture (orchestrator bench step — ONE session for users+card+FP+face fixtures per operator), feeds fixtures** + journal lifecycle + users phase + users verify | 02, 03 |
| E1-05 | cards phase + undo (restore-before-delete) + capacity fail-fast wiring | 04 |
| E1-06 | **faces: FDSearch template export (already PROVEN) + upload capture → fake → port + FDSearch-hash verify (critical path, v4; report-only ONLY if the capture proves the device cannot accept what export can produce)** | 04 |
| E1-06b | fingerprints: template port (`FingerPrintDownload` write capture → fake → port + re-read verify; same-sensor-family rule) | 04 |
| E1-07 | `gateclerk migrate` CLI group wiring 01-06b + `-o json` schema | 05, 06, 06b |

Dispatch order (capture-before-fake is the spine, §9): **01 + 03 now** (01's body
updated to include faces/FP export — FDSearch + FingerPrintUpload reads are proven,
so their NORMALIZERS are buildable offline against the recorded probe shapes) → 02
after 01 → **orchestrator bench-A step, ONE session** (export snapshot via merged
E1-01 first, then §5.0 captures in one device session: user SetUp round-trip +
test-person card → NONZERO `CardInfo/Search` + FP write via `FingerPrintDownload` →
read-back + face upload (`FDLib/FDSetUp` vs `FaceDataRecord`) → FDSearch read-back;
restore everything at session end) → 04 (fake routes from fixtures, then code) → 05,
06, 06b (06 gated on its face-upload fixture; report-only fallback recorded if the
fixture can't exist) → 07. No PR containing a write verb is gated before its capture
fixture exists in the tree.

## 11. Review log (v1 → v2 → v3 → v4)

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

**v4 deltas (operator review + read-axis probes, 2026-10-21).** Operator: "FACES ARE
THE PRODUCT… make R1 the critical path"; supplied the FDSearch and FingerPrintUpload
shapes from K1T-family memory. Every supplied shape was verified live on A before
being written into this doc (probe rounds 11-18, read-only, one attempt per shape):
1. **FDSearch RESOLVED** — flat body, `faceLibType:"blackFD"`, `FDID`, optional
   `FPID=employeeNo`; rows carry `modelData` (the portable face TEMPLATE) — face
   export was never actually broken; v3's "8 shapes rejected" died on using the
   users-endpoint's wrapped dialect on this endpoint (§9: dialect-split strictness).
   `faceURL` photo bytes confirmed DEAD (404 every way). Faces port the template;
   E1-06 moves from optional tail to critical path (§8 R1).
2. **FP read RESOLVED** — `FingerPrintUpload` + `FingerPrintCond` returns real
   templates (512 B, third-party sensor header); `FingerPrint/Search` notSupport was
   the wrong door, not the only door. New card E1-06b; portability claim stays
   same-sensor-family until B/C fw known (§1).
3. **templateNo 1 default-carried** (§1a v4): every UserInfo on A uses
   `planTemplateNo:"1"`, caps expose `maxPlanTemplate:4` — v3's blanket report-only
   would have shipped every migrated person with no door right. Custom numbers keep
   the v3 evidence-set discipline. Read-back assertion added to §5.0.
4. **`UserInfo/Search` truth pinned**: wrapped `UserInfoSearchCond`, `searchID`
   required, `EmployeeNoList` filter PROVEN honored (coverage discipline stays
   anyway, §6), paging MORE/OK quirk recorded. `UserInfo/capabilities` +
   `CardInfo/capabilities` + `FDLib/capabilities` all work (v3 claimed caps 404'd) —
   `setUp` appears in both `supportFunction @opt`s, which is vocabulary evidence not
   semantics evidence: R2 still waits on the §5.0 capture. Caps UNDER-claim
   (`isSuportFDSearch=false` while FDSearch works) → §9: no inference from caps
   either direction.
5. **§5.0 capture = ONE orchestrator device session** (operator): export snapshot →
   users round-trip → card → FP → face upload → read-backs → restore. E1-01 gains
   faces/FP export (reads are proven, so normalizers build offline now).
Not changed by v4 (operator: "rest of v3 stands"): §0 safety spine, capture-before-
fake, journal/undo proof-of-add, freshness contract, PINs-never-persisted, card
pair-identity.
