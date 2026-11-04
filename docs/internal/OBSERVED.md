# OBSERVED — device truth (read-only probe, 2026-10-15)

Everything here was captured from the real device with read-only calls only
(GETs + the two stateless search POSTs). Recorded via `curl --digest` against
`http://100.64.0.1`-style documented placeholder — the real site-a host lives only in
the gitignored local `sites.toml` and the keychain account (`site-a`). Nothing on the
device was changed. This file is
the reference card p1-04/p1-05/p1-06/p1-07 implement against; recorded masked
fixtures live in `tests/fixtures/recorded/site-a-ds-k1t341amf-s/`.

## Device identity

```
model              DS-K1T341AMF-S        deviceType  ACS
firmwareVersion    V3.2.30 (build 220729)
serialNumber       MASKED-SER… (masked here; fixture: MASKED-SER-1)
deviceName         Access Controller
```

Auth: HTTP digest, `qop="auth"`, realm `DS-39DED0D1`, `Server: webs`. Verified working
with the Keychain account (`user=admin`). One digest session reused across requests.

## Endpoint quirks (VERIFIED on this unit)

| Endpoint | Format actually returned | Notes |
|---|---|---|
| `GET /ISAPI/System/deviceInfo?format=json` | **XML** | ignores `format=json` → parser must handle XML for System/* |
| `GET /ISAPI/System/time?format=json` | **XML** | same |
| `GET /ISAPI/AccessControl/AcsEvent/capabilities?format=json` | JSON | |
| `GET /ISAPI/AccessControl/UserInfo/Count?format=json` | JSON | `{"UserInfoCount":{"userNumber":4}}`; GET only |
| `POST /ISAPI/AccessControl/UserInfo/Search?format=json` | JSON | works; response contains a `password` key per user (hash) — **strip it, never store** |
| `POST /ISAPI/AccessControl/AcsEvent?format=json` | JSON | works |
| `POST /ISAPI/AccessControl/AcsEvent/Total` | — | **NOT supported**: `400 subStatusCode:notSupport`. |
| `POST /ISAPI/AccessControl/AcsEventTotalNum?format=json` | JSON | **THE count endpoint** (correct name): `{"AcsEventTotalNumCond":{"major":5,"minor":0,"startTime":…,"endTime":…}}` → `{"AcsEventTotalNum":{"totalNum":30}}` (VERIFIED; equals the 30 major=5 we paged). Advisory cross-check only — research reports int-vs-string/nested shape drift across fw; never a loop bound. |
| `GET /ISAPI/System/time/timeType` | 404 notSupport | absent on this fw |
| `GET /ISAPI/System/time/timeZone` | XML raw string | bare POSIX-ish rule string (no wrapper) — same value as System/time `<timeZone>` |
| `GET /ISAPI/AccessControl/attendanceStatusModeCfg` | 404 notSupport | this model has no attendance-status-mode config via ISAPI (T&A-mode doc applies to other lines) |
| `GET /ISAPI/Security/encryption/capabilities` | 404 notSupport | no encryption scheme on this fw — matches plaintext names observed |

## AcsEvent capabilities (what the device advertises)

```
maxResults     @max = 30          ← clamp all requests to this
searchID       @max = 64          (we use 16-char hex anyway)
major          @opt = 0,1,2,3,5
minorEvent     1,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,
               29,30,31,32,33,34,35,36,37,38,39,49,51,75,76,80,104,105,112,113,114,
               115,116,142,151,152,155,193,153,154
minorAlarm     1028..1040
minorOperation 80,90,112,113,118,119,121,122,123,126,134,135,1024..1031,1034,1035,1036,1038,1049,1050
```

No `eventAttribute` capability on this fw. Raw JSON in fixture `acs_capabilities.json`.

## Event log census (all history as of probe)

```
major=0 total        10,199 events   (earliest serial 27, 2026-05-21T14:08 → retention ≥ ~5 months, ring ≈ 10k)
major=3 (operation)  10,169 events   ← NOISE: minor=1029 every minute on the minute
major=5 (event)          30 events   ← the punches
major=1 / major=2           0
```

major=5 census (all 30): `18× minor=75` (auth pass — carries `employeeNoString` + `name`),
`6× minor=21` (door open), `6× minor=22` (door close) — 21/22 carry no employee.
Noise major=3/minor=1029 shares the same monotonic `serialNo` counter (values interleave
5742..5753 with punches) → **checkpoint on serialNo is valid device-wide**, but the
connector must exclude major=3 noise from punch output.

Employees on device: 4 (`employeeNoString` "1","2","3","4"; auto-assigned small ints →
BC mapping table will be needed). Face/card auth always shows
`currentVerifyMode: "cardOrFaceOrFp"` — the device does not tell face vs card apart in
this field on this fw; keep verbatim, do not fake a finer value.

## Masked sample records (verbatim shape)

```json
{"major":5,"minor":75,"time":"2026-10-12T14:11:16+02:00","cardType":1,"name":"User E1",
 "cardReaderNo":1,"doorNo":1,"employeeNoString":"1","type":0,"serialNo":5742,
 "userType":"normal","currentVerifyMode":"cardOrFaceOrFp","mask":"no"}
```

```json
{"major":3,"minor":1029,"time":"2026-10-08T15:42:45+02:00","type":0,"serialNo":77,"currentVerifyMode":"invalid"}
```

```json
{"major":5,"minor":21,"time":"2026-10-12T14:11:20+02:00","doorNo":1,"type":0,"serialNo":5744,"currentVerifyMode":"invalid"}
```

Paging envelope observed:

```json
{"AcsEvent":{"searchID":"…","totalMatches":30,"responseStatusStrg":"OK","numOfMatches":30,"InfoList":[ … ]}}
```

`responseStatusStrg` values observed (exact strings): `"OK"`, `"MORE"`, `"NO MATCH"`
(note: **space, not underscore** — compare normalized). `searchResultPosition` is
0-based; advance by `numOfMatches`; `timeReverseOrder:true` honored (newest first).
Empty window → `{"responseStatusStrg":"NO MATCH","totalMatches":0,"numOfMatches":0}` and
the `InfoList` key is **absent** (not empty list) — handle both.

## Event-window `startTime` form: offset REQUIRED (owner live probe 2026-10-17, VERIFIED)

The AcsEvent search **rejects a naive `startTime`**: body `"startTime":"2026-10-10T00:00:00"`
→ HTTP 400, `statusCode=6 Invalid Content`, `subStatusCode=badJsonContent`,
`errorMsg=startTime`. Stamping the site-tz offset (`+03:00`) on the same window returns
200; the device's claimed offset (`+02:00`) is accepted too. One read-only POST per form
(owner, P1-10 step 5, fw V3.2.30): Sep 1..Oct 17 → 10 major=5 events, both offset forms.

Consequences, both load-bearing:
1. `DeviceWindow.search_pair()`'s naive default (p1-05) fails **every** live events pull,
   and also the `--count` probe (same body shape). The offline suite missed it because
   FakeDevice accepted naive — a mock more lenient than the device is a false-green
   machine (same class as the worktree-editable-import bug). FakeDevice must reject naive.
2. Send the **offset-bearing site pair** (`since_site_iso`/`until_site_iso`): site-tz wall
   time stamped with the site offset. DESIGN.md's "always with `startTime`/`endTime` +
   offsets" was right; the "prefer the naive pair unless a live run proves otherwise"
   clause in tz.py/paging.py notes is hereby retired by this live proof.

OPEN (cheap A/B during the P1-10 re-run): does the device *interpret* the offset when
filtering or merely require presence? `+02:00` vs `+03:00` returned the same count on a
sparse 6-week window; a dense-window A/B (one read-only POST pair on a busy day) settles
whether the label shifts the effective window by an hour. Until proven otherwise we send
site `+03:00` — self-consistent with site-tz-is-truth.

## Event-window `startTime` form: sub-second REJECTED (canary live 2026-10-21, VERIFIED)

The same endpoint also **rejects fractional seconds** in the bounds. The P2-10 canary's
first real agent tick (operator-authorized read-only POST, ~03:21Z): body
`"startTime":"2026-10-21T06:22:06.031165+02:00","endTime":"2026-10-21T06:32:06.031165+02:00"`
→ HTTP 400, `statusCode=6 Invalid Content`, `subStatusCode=badJsonContent`,
`errorMsg=startTime`, `errorCode=1610612759`. The **byte-identical body with the
microseconds removed** → 200 (`responseStatusStrg=NO MATCH`, `totalMatches=0`). One
request per form, no retry loop (owner-authorized A/B). Same error class as the naive
form above — the fractional leg of "bounds must be whole-second, offset-bearing".

Consequences, both load-bearing:
1. `DeviceWindow.search_pair()` floors the `.ffffff` leg (toward the past — never round
   up, never roll a minute) on both wire paths (claimed-offset relabel AND the
   site-labeled fallback). The struct's raw fields keep the microseconds verbatim:
   audit strings are not wire bytes. The **agent** hits this every tick — its window
   comes from `datetime.now`, which always carries microseconds — while operator
   `--since/--until` windows are whole-minute strings, which is why 1465 offline tests
   and every CLI run missed it and only the live canary bit it.
2. FakeDevice rejects fractional bounds with the same recorded envelope (its docstring
   quotes this capture). The permissive fake was the false-green machine again: it
   accepted ANY offset-bearing string, so the pre-fix wire shape was never once seen.

## Digest nonce use-cap → deterministic 401 mid-backfill (owner live 2026-10-17; fix MERGED, live recovery path NOT exercised)

Long `--chunk 1h` backfill hit **401 Unauthorized with the correct password** at exactly
the same window on two runs (2026-09-08T21:00, ~190th request of the walk), exit 3.
The device stayed **unlocked**: `lockStatus=unlock`, `retryLoginTime=4` — NOT a lockout.

**Mechanism DETERMINED offline (t_a3521d8a, docs/FINDINGS-t_a3521d8a.md F1): shape (c)**
— 401 carrying the ISAPI error envelope and NO `WWW-Authenticate`. httpx re-pays any 401
that offers a challenge (stale flag irrelevant), so shapes (a)/(b) were always survivable;
the challenge-less 401 fell to our 401-terminal rule and killed the walk. Fix = bounded
challenge-less re-bootstrap (`DEFAULT_AUTH_RECOVERY_BUDGET=1` per logical call, streak ≤2
without an intervening 200; `IsapiClient.auth_recoveries` counts spend), merged as
PR #21 → `4af4398` after the owner's live acceptance.

**Acceptance (owner, main 4af4398, read-only):** rc 0, **1104 chunks / 1108×HTTP 200 /
zero non-200 / 10 events (identical to pre-fix) / 177 s**, sailed through the old
2026-09-08T21:00 wall. HONEST CAVEAT: **no 401 occurred at all this run** — the device
did not retire the nonce (or httpx absorbed it below the `-v` log), so the recovery arm
is **proven offline only** (FakeDevice retire-after-N in all three shapes; 1031 green).
The live trigger remains empirical: the ~190-request cap is observed, not modeled.
Reproduction discipline stands: NEVER hammer the device for digest debugging — wrong-shape
401s can count toward lockout accounting.

## Window offsets are ARITHMETIC for the device — bounds must be site-wall stamped with the DEVICE's claimed offset (A/B 2026-10-17, VERIFIED, payroll-critical)

The OPEN question from "startTime form: offset REQUIRED" (does the device interpret the
offset or merely require presence?) is **settled: it does offset arithmetic.**
Decisive A/B (orchestrator, 2 read-only POSTs, dense day 2026-05-21, window
`13:00–14:30` per run; device wall = events at 14:08–14:20):

```
startTime 13:00:00+03:00, endTime 14:30:00+03:00  -> "NO MATCH", totalMatches 0
startTime 13:00:00+02:00, endTime 14:30:00+02:00  -> "OK", totalMatches 20 (serials 27..47)
```

Digits-only comparison is refuted: the `+03:00` run carries the SAME digits inside the
same window and returns zero. The device converts label→instant→its own clock, so
during DST a `+03:00`-labeled window arrives **one hour early in device terms**. Sparse
windows hide this (Sep 1–Oct 17 "same 10 events" under both labels; the 1104-chunk
acceptance is sparse too — the shift is invisible there); dense windows at boundaries
lose/misplace events — payroll-critical, same class as the p1-05 clamp bug.

**Consequence:** we currently send site-wall stamped `+03:00` (p1-05b) — WRONG shape for
this device in summer. Correct = **site-wall digits labeled with the device's claimed
offset** (`+02:00`, which this fw reports year-round — its DST rule never engages).
This is DESIGN.md's original "derive the window in site-tz wall time, stamp the
device's claimed offset" — retired by the naive-400 discovery, now reinstated by
arithmetic proof, with the offset REQUIRED (never naive — p1-05b's FakeDevice rejection
stays). Fix carded: t_56d8b09d (DeviceWindow pair + pipeline wiring + FakeDevice must
FILTER arithmetically, not just require presence — the current lenience is what let
this through). Do not trust presence-checking mocks for window semantics.

## Server-side filter truth (probe 2026-10-15, second round) — filter CLIENT-side

`AcsEventCond.employeeNo` (no suffix) is **SILENTLY IGNORED** on this fw:
`employeeNo:"1"` returned totalMatches=30 (everything). `employeeNoString:"1"` works
(→15, exactly employee 1's events). `eventAttribute:"attendance"` is accepted but also
ignored (returns all 30) — consistent with it being absent from capabilities. Long
searchID (64 chars) is tolerated despite sibling models rejecting >20 with
`badParameters` — but stay ≤64 and stable per search anyway.

**Policy (payroll-grade): never trust a server-side filter you have not probed.**
The connector filters by employee/eventAttribute CLIENT-side; only
`startTime/endTime/major/minor/employeeNoString` are trusted server filters on this fw.
A silently-ignored filter is the worst bug class: it looks like data, isn't filtered,
and nobody notices until payroll is wrong.

## attendanceStatus: field exists, values null → terminal is NOT in attendance mode

All 30 major=5 events: `attendanceStatus` absent/null. Confirmed: this device is in
pure access-control mode. No `checkIn`/`checkOut` will ever appear until someone
enables attendance mode + plan in the device UI (a write — explicitly out of scope;
owner decision, see DESIGN.md "in/out options"). Until then every punch is
`direction=unknown, direction_source=none`.

## The time/offset bug (payroll-critical, VERIFIED)

```
GET /ISAPI/System/time → <localTime>2026-10-15T16:39:32+02:00</localTime>
real local wall time at probe:  16:39:36 +03:00 (EEST, Europe/Bucharest)
<timeZone>CST-2:00:00DST01:00:00,M3.4.1/00:00:00,M10.5.0/23:00:00</timeZone>   (no tzType node)
```

Wall clock is correct (skew ~4 s) but the **UTC offset it stamps is wrong**: it labels
+02:00 in summer when the zone is +03:00 (its DST rule `M3.4.1/00:00:00,M10.5.0/23:00:00`
is not the EU rule and apparently never engages — in October it still reports the
standard offset). Every event `time` string therefore carries the wrong offset.

**Connector policy (decided):** the device's self-reported offset is *not* trusted.
Interpret the wall-clock part (naive `YYYY-MM-DDTHH:MM:SS`) in the **site timezone**
from config (`Europe/Bucharest`) → compute UTC with `zoneinfo`. Keep the raw string +
the device's claimed offset in `raw`/`tz_offset_min_device` for audit. If
`device_offset != site_offset_at_that_moment` (always, in summer, until fixed), do not
alter the device — log/flag `tz_offset_mismatch=true`. Changing the device tz/NTP is an
owner decision; when fixed on-device, the mismatch flag simply stops firing and nothing
in the pipeline changes.

POSIX rule parsing note for the config validator: in Hikvision's `CST-2:00:00…` form the
sign is POSIX (west-negative): `CST-2:00:00` = UTC+2 standard, `DST01:00:00` adds an
hour. Do not `str.replace("GMT","")`; map site names (IANA) in config instead.

## What each card must take from this file

- p1-02: config schema `site → {host, iana_tz, keychain_service, keychain_account=host, user}`; site-a = `192.0.2.10`, `Europe/Bucharest`.
- p1-03: XML-or-JSON response parsing (System/* is XML); digest session reuse; keep the `AcsEvent/Total` endpoint out of the client entirely.
- p1-04: build the code table from the capability JSON above; treat major=3 as non-punch (info/noise); unknown codes → keep + flag.
- p1-05: clamp `maxResults` to 30 (advertised cap); terminate on `responseStatusStrg` normalized ∈ {ok, "no match"}; handle missing `InfoList`; advance by `numOfMatches`; checkpoint = `max(serialNo)` device-wide (noise included) + overlap window.
- p1-06: site-tz policy + `tz_offset_mismatch` flag; fixture `system_time.xml` + `events_major5_page1.json` are the golden pairs.
- p1-07: `verify_mode` verbatim `cardOrFaceOrFp`; `attendanceStatus` null → `direction=unknown`; strip `password` key from UserInfo records before storing; employee_no = `employeeNoString` as string.
- p1-09: fixtures under `tests/fixtures/recorded/site-a-ds-k1t341amf-s/` are the corpus (masked: names→`User E<n>`, serial→`MASKED-SER-1`, mac zeroed, password keys removed, nonce masked). No CI leak-guard — build FakeDevice scenarios on these, nothing hygiene-related.

## E1 enrollment-read probes — bench A, 2026-10-21 (read-only rounds 11-18)

Device DS-K1T341AMF-S fw V3.2.30, same masked conventions as above. These facts fed
design v4 (docs/ENROLLMENT-MIGRATION.md §1). Biometric BYTES (face modelData, FP
fingerData) are never committed here or in fixtures — shape/size/hash-prefix only.

- **UserInfo/Search dialect**: body MUST be `{"UserInfoSearchCond":{searchID,
  searchResultPosition,maxResults,…}}` — flat cond → 400 `badJsonContent
  errorMsg=UserInfoSearchCond`; missing searchID → 400 `MessageParametersLack
  searchID`. Response wraps under `UserInfoSearch` (record list `UserInfo`,
  `responseStatusStrg` OK/MORE/NO MATCH, `numOfMatches`/`totalMatches`).
  `maxResults` cap 30 (caps @max=30). **Server-side filter HONORED**:
  `EmployeeNoList:[{"employeeNo":"1"}]` → 1/4 returned, `"99"` → 0 + NO MATCH
  (contrast AcsEventCond.employeeNo, silently ignored — per-endpoint, never infer).
  UserInfo record for User E1 carries `numOfFace:1 numOfFP:1 numOfCard:0`,
  `RightPlan:[{doorNo:1,planTemplateNo:"1"}]` (ALL users use templateNo "1"),
  `Valid.timeType:"local"`, `password:""` (empty on all users), localUIRight true on
  E1 only.
- **FDSearch WORKS — FLAT body** (no cond wrapper; the wrapped dialect is what 400'd
  in earlier rounds): `{"searchResultPosition":0,"maxResults":30,"faceLibType":
  "blackFD","FDID":"1"[,"FPID":"<employeeNo>"]}` → rows `{FPID, faceURL, modelData}`.
  modelData = base64 face TEMPLATE, 272 B, magic `FR500005\x01\x00\x00\x00`, sha256
  prefixes cb2755c7cfb9 / 4723b080f1c5 / ad7ee907920c for E1/E2/E3 (distinct per
  person). FPID filter honored (FPID=1 → 1/4). Paging quirk: FDID=1 all-search
  returned numOfMatches=3 totalMatches=4 in ONE page with status OK — walker must
  keep paging to NO MATCH, not trust one page. FDID 2 = infraredFD exists.
  **faceURL photo bytes DEAD**: `http://<device-a>/LOCALS/pic/enrlFace/0/…jpg@WEB…`
  404s (plain, %-encoded @, fresh-cookie same-session alike). Not retry-spamming:
  5 GETs total across rounds.
- **FDSearch RESPONSE shape CAPTURED** (§5.0 capture session, 2026-10-22, during the
  first live `export_full_bundle` — the read failed CLOSED and named the gap, which
  is §0.7 working as designed): there is **no `{"FDSearch": ...}` wrapper** —
  `statusCode/statusString/subStatusCode/responseStatusStrg/numOfMatches/totalMatches`
  sit at the body ROOT (root keys captured verbatim: `MatchList,numOfMatches,
  responseStatusStrg,statusCode,statusString,subStatusCode,totalMatches`), rows under
  **`MatchList`**, and the honest zero (FPID of a person with no face: 1 request,
  FPID=99) answers `NO MATCH` with **`MatchList` absent entirely** — same
  empty-is-absence rule as the P1 windows. The design's `FDSearch`/`Records` guess is
  retired; `paging.fd_search` carries the captured values (`envelope_key=""`).
  FingerPrintUpload zero shape re-confirmed the same day: `FingerPrintInfo:{searchID,
  status:"NoFP"}` with `FingerPrintList` absent (the probed full shape is unchanged).
- **FingerPrintUpload READ ignores `fpIndex`** (§5.0 capture, 2026-10-22, employeeNo
  "1"): fpIndex **0, 1 and 2 all answered the IDENTICAL** row — same 512 B template
  (b64 len 684, sha 91c0878623c2), same `fingerPrintID: 1`, `status: "OK"`. The
  per-fpIndex "read until empty list" walk is therefore a FALSE PREMISE: for a person
  WITH a finger it never terminates (bench A never returns the empty list we
  extrapolated as the stop shape — the real zero word is `status:"NoFP"` with the
  list ABSENT, and only for people WITHOUT one). Correct model: ONE read per person,
  `fingerPrintID` is a captured constant 1, `leaderFP` verbatim is an empty list
  (not a bool). Multi-finger reads on this endpoint shape are UNPROVEN — the export
  fails closed if any read answers `fingerPrintID != 1` instead of guessing.
- **FingerPrint read WORKS** (misleading name, device→client): POST
  `/ISAPI/AccessControl/FingerPrintUpload?format=json`
  `{"FingerPrintCond":{"searchID":"…","employeeNo":"1","fpIndex":0,"dataType":"template"}}`
  → `FingerPrintInfo.FingerPrintList:[{cardReaderNo,fingerPrintID,fingerType:
  "normalFP",fingerData,leaderFP}]`; E1 fpID 1 = 512 B template, sha256 prefix
  3b7b3bd273b3 (bytes local-only). Plain `{searchID,employeeNo}` → 400
  `MessageParametersLack FingerPrintCond` (wrapper required).
  `FingerPrint/Search` genuinely notSupport; `FingerPrintDownload/capabilities` 404.
- **Capability GETs**: `UserInfo/capabilities`, `CardInfo/capabilities`,
  `FDLib/capabilities`, `AcsCfg/capabilities` all 200 JSON. `UserInfo/SetUp/
  capabilities` and `UserInfo/Search/capabilities` (and FingerPrintDownload caps)
  404 notSupport. UserInfo caps: supportFunction @opt includes `setUp`;
  maxRecordNum 3000 (batch/page cap, NOT device capacity); password @max 8 (PIN
  length — another reason pins are never logged); Valid timeType @opt `"local"` ONLY;
  Valid range 2000-01-01…2037-12-31; userType @opt `normal,visitor,blackList` (no
  `admin` writable); RightPlan {maxSize 1, doorNo 1, maxPlanTemplate 4,
  planTemplateNo 1..255}; EmployeeNoList maxSize 30; isSupportNumOfFace/FP/Card true.
  CardInfo caps: setUp listed; cardNo @max 20; cardType normalCard/patrolCard/
  hijackCard/superCard. FDLib caps: FDMaxNum 2, FDRecordDataMaxNum 3000,
  modelMaxNum 1, **isSuportFDSearch=false while FDSearch demonstrably WORKS** —
  caps UNDER-claim on this fw; record caps as values, infer availability only from
  the call itself.

## E1 §5.0 WRITE-PATH CAPTURE (bench A, 2026-10-22, orchestrator session)

One session, bounded attempts (the device PARSED every write attempt — zero 401s,
lockout axis clean). Artifacts: `~/gateclerk-data/capture/*.json` + three bundles
(pre-capture / post-restore / restored). Test person 90 / card 90000090 only.

- **Users WRITE — PROVEN (R0):** `PUT /ISAPI/AccessControl/UserInfo/SetUp?format=json`
  body `{"UserInfo":{"employeeNo":…,"name":…,"userType":…,"Valid":{…},"doorRight":…
  ,"RightPlan":[…],"localUIRight":…,"gender":…,"mode":"add"}}` — fields DIRECT under
  `UserInfo` (NOT a `userInfoList`), `mode` REQUIRED (capital "Add" 400s, lowercase
  `add` ok — same dialect lesson as users-search wrapper). POST SetUp →
  `methodNotAllowed`; POST/PUT `UserInfo/Record` → 400/405. Read-back exact.
- **Cards WRITE — PROVEN:** `PUT CardInfo/SetUp?format=json`
  `{"CardInfo":{"employeeNo":"90","cardNo":"90000090","cardType":"normalCard","mode":"add"}}`
  — flat-under-wrapper + `mode:"add"`, first try. Read-back CardInfo/Search OK 1.
- **Faces WRITE — PROVEN (R1, the product):** `PUT /ISAPI/Intelligent/FDLib/FDSetUp
  ?format=json` FLAT body `{"faceLibType":"blackFD","FDID":"1","FPID":"<emp>",
  "modelData":"<b64>"}` → statusCode 1; FDSearch FPID read-back returned the
  **identical** template. 4/4 re-added during restore with identical sha12 per
  person (cef00e3b92d4/ce61e7037d5a/3a494b0ffdc5/5cd40292445e) — face port
  end-to-end works on the bench.
- **Fingerprints WRITE — API-ACCEPTED, NEVER APPLIED (bench A).**
  `POST FingerPrintDownload` `{"FingerPrintCfg":{"enableCardReader":[1],
  "employeeNo":…,"fingerPrintID":1,"fingerType":"normalFP","fingerData":<b64>}}`
  answers statusCode 1 (`enableCardReader` = **list of reader numbers**; int/str
  both `badJsonContent`; caps `FingerPrintCfg/capabilities` works and is the
  vocabulary source — `FingerPrint/capabilities` and …/Download/capabilities 404).
  But read-back stays `NoFP`, `numOfFP` stays 0, and the doc-listed progress
  endpoint `GET FingerPrintProgress?format=json` answers
  `StatusList:[{id:1,cardReaderRecvStatus:5,errorMsg:"1"}] totalStatus:1` — the
  **attached reader REJECTS the template** (third-party "301" sensor family, §1;
  bench A's own enrolled FP came from the device's own capture). E1-06b verdict:
  port stays same-sensor-family-AND-same-capture-path; on bench A the honest
  outcome is report-only. `FingerPrintCfg` (GET/POST) and delete-caps: notSupport.
- **DELETE — THE SILENT-WIPE HAZARD (the session's worst lesson):** the accepted
  person-delete shape is `PUT UserInfoDetail/Delete?format=json`
  `{"UserInfoDetail":{"mode":"delete"},"UserInfoDelCond":{"EmployeeNoList":[…]}}`
  — but bench A **IGNORED the sibling `UserInfoDelCond` and deleted EVERY user**
  (and cascade-dropped all faces; the just-added 90 was collateral): `UserInfo/
  Count → 0`, FDSearch → 0 rows. Any `mode:"delete"` shape with the list in the
  WRONG slot is a wipe, not a no-op. RESTORE: re-added 4 users + 4 face templates
  from the pre-capture bundle via the captured write shapes; post-restore export
  has **identical per-person content hashes and faces index digest** (cards were 0
  pre-session anyway; the one FP never re-applies — bench reader rejects it).
  10,351 events survived untouched (separate log). RECOVERY PROOF: this is E1's
  restore path proven on the real box, with the export→verify loop doing the check.
- **Other delete verbs (captured):** face `PUT FDSearch/Delete?format=json&FDID=1
  &faceLibType=blackFD` body `{"FPID":[{"value":"90"}]}` (verified NO MATCH after);
  card `PUT CardInfo/Delete?format=json` `{"CardInfoDelCond":{"CardNoList":[…],
  "EmployeeNoList":[…]}}` (verified 0 after — wrapper + DelCond keys from caps).
  UserInfoDetail/DeleteProcess → 404 deviceError (no progress surface).
- **USER DELETE IS NOT TARGETABLE ON THIS FW (CLOSED, 2026-10-22 second session).**
  Two accepted shapes, both wiped the WHOLE roster (count→0, faces→0), both returned
  `statusCode 1 ok`: `{UserInfoDetail:{mode:"delete"}, UserInfoDelCond:{…}}` and
  `{UserInfoDetail:{mode:"deleteByEmployeeNo"}, UserInfoDelCond:{…}}`. The device
  accepts the sibling `UserInfoDelCond`, ignores its contents AND the targeted mode
  value, then deletes everyone. Every list-INSIDE-`UserInfoDetail` shape 400s
  (`badJsonContent: EmployeeNoList`) — including the documented `deleteByEmployeeNo`
  + inside-list form. Vocabulary is fully mapped (caps: `UserInfoDelCond`
  `EmployeeNoList.maxSize=30`); no accepted targeted form exists. **Consequence:**
  there is NO safe per-person user delete on DS-K1T341AMF-S V3.2.30 → v1 stays
  no-deletions (already §5 step 8), and undo of a user ADD is impossible via API: the
  only "undo" is wipe-and-restore-from-bundle, which must NEVER be automatic. Face and
  card deletes ARE targeted (verified above). Recovery is proven a 3rd time:
  `site-a-restored-2c-20261022` re-export = 4 users / 4 faces, per-person content
  hashes + face template bytes identical to baseline; the person-1 FP (512 B,
  301-family) is archived in the baseline bundle (sha256 9784837e…) but cannot be
  re-applied on bench A (reader rejects third-party family) — data preserved, device
  enrollment lost, exactly the accepted-not-applied class.
- Test-person hygiene: person 90 + card 90000090 were the only writes; both gone
  by session end (90 via the wipe + re-add path: it was NOT re-added after — the
  roster is exactly the original 1,2,3,4).
- Policy reaffirmed: no device re-probes on a settled axis (lockout accounting);
  the 404-faceURL question is CLOSED as dead-end after the bounded rounds above.
