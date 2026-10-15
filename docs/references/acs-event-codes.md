# Hikvision ISAPI — AccessControl AcsEvent retrieval: technical brief

Target device: **DS-K1T341AMF-S**, firmware **V3.2.30 build 220729** (Value-Series MinMoe face terminal,
"person-based access control" firmware family, closest public doc: *ISAPI Developer Guide — Access Control,
Face Recognition Terminals, Value Series*). All claims below are labeled **[VERIFIED]** (vendor doc text or
working code / real device dumps quoted from a public source) or **[INFERRED]** (cross-source assumption —
must be confirmed on the live device).

---

## 1. POST /ISAPI/AccessControl/AcsEvent?format=json

### 1.1 Request envelope — every `AcsEventCond` field

Top-level wrapper is exactly `{"AcsEventCond": { ... }}` with `Content-Type: application/json` and HTTP
Digest auth (RFC 2617/7616). **[VERIFIED]** across every source examined.

Field list (vendor annotation text quoted from the Hikvision access-control ISAPI doc, reproduced in the
Home Assistant community thread by pergolafabio, and corroborated by the `AcsEvent/capabilities` dump a user
posted for the sibling DS-K1T804AMF):

| Field | Req/Opt | Type | Meaning / constraint |
|---|---|---|---|
| `searchID` | req | string | Search-session ID. "used to confirm the upper-level platform… if the same platform searches twice, the search history is saved in memory to speed up the next search". Length capability-limited: `@min 1, @max 20` on DS-K1T804AMF (ipcamtalk capability dump); many guides show `[1,32]`. **A 36-char GUID exceeded `@max 20` on that firmware and produced `Invalid Content / badParameters`** [VERIFIED ipcamtalk]. |
| `searchResultPosition` | req | int | Start position of the result slice. **0-based** — see §1.3. |
| `maxResults` | req | int | Page size. "If maxResults exceeds the range returned by the device capability, the device will return the maximum number according to device capability and will **not** return error" [VERIFIED, vendor text]. Observed caps: `@max 10` (DS-K1T804AMF capability), 30 (hikvision-isapi-python author's device), 150 (Hikvision-API-Reference author); other code posts 100/2000 and simply gets the clamp. Capability-driven — never hardcode. |
| `major` | req | int | Major event type, **decimal** (not hex!). `0` = all. Capability `@opt "0,1,2,3,5"`. [VERIFIED] |
| `minor` | req | int | Minor event type, decimal, `0` = all. Valid values per capability groups `minorEvent / minorAlarm / minorException / minorOperation`. [VERIFIED] |
| `startTime` | opt | string | ISO-8601 local/UTC-with-offset, e.g. `2023-10-02T00:00:00+03:00`. |
| `endTime` | opt | string | Same format. |
| `cardNo` | opt | string | Card-number filter (capability `@max 20–32` depending on model). |
| `name` | opt | string | Cardholder-name filter. |
| `picEnable` | opt | bool | Include snapshot pictures (`pictureURL` populated). |
| `beginSerialNo` | opt | int | Serial-range filter (capability `@max 3000000000`). Not safe as a paging key, see §1.4. |
| `endSerialNo` | opt | int | ″ |
| `employeeNoString` | opt | string | Employee/person ID filter. Capability `@max 8` on DS-K1T804AMF, `[1,32]` in MinMoe docs. |
| `employeeNo` | opt | string | Same filter in older doc revisions (Value-Series doc lists both `employeeNoString` and `employeeNo`). [VERIFIED that both appear in the vendor body template; which one this firmware honors → confirm on device] |
| `eventAttribute` | opt | enum | `"attendance"` = valid-authentication (T&A) events, `"other"` = the rest. Capability `@opt "attendance,other"`. **This is the vendor-intended punch-log filter.** [VERIFIED] |
| `timeReverseOrder` | opt | bool | Newest-first ordering ("later events returned first"). [VERIFIED vendor text] |

There is **no `isPagination` node** in the `AcsEventCond` schema or in the `AcsEvent/capabilities` dumps
examined [INFERRED from absence — pagination is driven implicitly by `searchResultPosition`/`maxResults`].
Full working request body used in production code (garden-gate, MAGNAT12, cnblogs ge yee, Stack Overflow):

```json
{
  "AcsEventCond": {
    "searchID": "acs-0001",
    "searchResultPosition": 0,
    "maxResults": 30,
    "major": 0,
    "minor": 0,
    "startTime": "2026-10-01T00:00:00+03:00",
    "endTime": "2026-10-15T23:59:59+03:00",
    "timeReverseOrder": true
  }
}
```

Gotcha [VERIFIED, ipcamtalk DS-K1T804AMF]: a body omitting required nodes (e.g. `minor`) or with an
over-long `searchID` returns

```json
{"requestURL":"/ISAPI/AccessControl/AcsEvent?format=json","statusCode":6,
 "statusString":"Invalid Content","subStatusCode":"badParameters",
 "errorCode":1610612737,"errorMsg":"0x60000001"}
```

### 1.2 searchID semantics

- Required; a unique-ish opaque string, **keep it byte-identical across all pages of one walk**.
  [VERIFIED vendor text]
- The device caches the search state per `searchID` ("search history saved in memory"). Changing it
  mid-walk makes the device **silently restart serving page 1 — no error is returned**; you loop forever
  on plausible records. [VERIFIED — `shaykhnazar/hikvision-isapi` README: "a device given a new one starts
  over and serves page one again. Nothing errors."]
- Length limit is capability `@max` (20 on one observed model, 32 in other docs). Safe rule: ASCII ≤ 20
  chars. [INFERRED safe-common from conflict; confirm via capabilities.]

### 1.3 searchResultPosition is 0-based

- Every vendor example and every working implementation starts the first page at `0` [VERIFIED — AC Gateway
  API guide, Value-Series doc, HA rest-sensor example, garden-gate, SO, use-ip, cnblogs].
- The vendor text for the sibling `UserInfoSearchCond` states the legal range explicitly: *"if the device's
  max totalMatches is M but N records are currently stored (N ≤ M), the legal range of this field is
  0 ~ N-1"* — i.e. **0-based offset into the matched list** [VERIFIED, open.hikvision.com MinMoe page §12.2].
- Advance the cursor by `numOfMatches` from the previous response (`position += numOfMatches`), not by
  `maxResults` (a page may return fewer) [VERIFIED in working code: ge yee, uchkunr best-practices].

### 1.4 Paging termination in practice

Response envelope [VERIFIED — dozens of independent real dumps]:

```json
{"AcsEvent": {
  "searchID": "acs-0001",
  "totalMatches": 72,
  "responseStatusStrg": "MORE",
  "numOfMatches": 30,
  "InfoList": [ … ]
}}
```

- `responseStatusStrg` enum per vendor: `"OK"` = search ended (last page), `"MORE"` = more records,
  `"NO MATCH"` = nothing matched. [VERIFIED — AC Gateway API A.2 "OK-search ended, MORE-searching,
  NO MATCH-no matched data"; FDSearch schema shows the same enum.] Some firmwares are reported returning
  `NO_MATCHES`/`NO_MATCH` spelling variants [INFERRED — doc-vs-field reports differ; match case-insensitively
  on a prefix].
- `numOfMatches` = records in *this* page; `totalMatches` = records matching the condition for the whole
  search (usable as expected total; can move if new events arrive mid-walk — re-anchor with a fixed
  `endTime`).
- `isLastMatch` **does not exist** in the AcsEvent schema [INFERRED from absence — no doc/capability/code
  source ever shows it; termination is `responseStatusStrg` + `numOfMatches`].
- Robust loop [INFERRED best-practice, matches what working code does]:
  1. `pos = 0`; loop: post with same `searchID`, `searchResultPosition = pos`.
  2. Collect `InfoList`; `pos += numOfMatches`.
  3. Stop when `responseStatusStrg` is `OK`/`NO MATCH*` **or** `numOfMatches == 0` **or** `pos >= totalMatches`
     (any one; devices are inconsistent).
- `serialNo` is **not** a reliable paging/density key: it is shared with internal (non-public) events so
  gaps are normal; it wraps to 1 when the event capacity (≈300 000 on this class) is reached, so serials
  repeat over time [VERIFIED — ipcamtalk thread by an integrator of "most" Hik AC devices + Stack Overflow
  answer]. Dedupe by `serialNo` + `time` within a bounded window, page by `searchResultPosition`, and prefer
  push (`/ISAPI/Event/notification/httpHosts` + `alertStream`) for real-time.

### 1.5 maxResults maxima by device generation

No single vendor-wide number exists; it is **capability-declared** and the device clamps silently [VERIFIED].
Observed: **10** (DS-K1T804AMF V1.4.1 capability `"maxResults":{"@min":1,"@max":10}`), **30** (common value in
working Value-series code), **100–150** (other integrations). [INFERRED] V3.2.x MinMoe commonly reports 30.
Action: `GET /ISAPI/AccessControl/AcsEvent/capabilities?format=json` at connector startup and use `@max`.

---

## 2. The "total" endpoint

There is **no `/ISAPI/AccessControl/AcsEvent/Total`** in any Hikvision document [VERIFIED by absence across
all guides/transparent-transmission pages]. The real endpoint (what that name refers to) is:

```
GET  /ISAPI/AccessControl/AcsEventTotalNum/capabilities?format=json
POST /ISAPI/AccessControl/AcsEventTotalNum?format=json
```

Request (vendor schema, `major`+`minor` are the only req fields; values decimal) [VERIFIED —
open.hikvision.com 明眸门禁 §5 + Device Network SDK guide Appendix A.2/B.2]:

```json
{
  "AcsEventTotalNumCond": {
    "major": 5,
    "minor": 0,
    "startTime": "2026-10-01T00:00:00+03:00",
    "endTime": "2026-10-15T23:59:59+03:00",
    "cardNo": "",
    "name": "",
    "picEnable": false,
    "beginSerialNo": 1,
    "endSerialNo": 3000000000,
    "employeeNoString": ""
  }
}
```

Response [VERIFIED, same sources]:

```json
{"AcsEventTotalNum": {"totalNum": 1234}}
```

Reliability: **treat as advisory only**. A production integration reports: "An event count comes back under
`AcsEventTotalNum` on some firmware and flat on others, sometimes as a string. Read one shape and you get a
confident zero forever" (`shaykhnazar/hikvision-isapi` README) [VERIFIED quote]. The endpoint can also be
absent (404 `notSupport`) on locked-down/older builds. Primary count source should be `totalMatches` from
the AcsEvent search response itself; probe the capabilities URL before trusting `totalNum`, and coerce
string→int [INFERRED guidance from the quoted failure mode].

---

## 3. major/minor event code table

Major types [VERIFIED — capability `@opt "0,1,2,3,5"`, node-red-contrib-hikvision-ultimate code tables,
mmisobuj catalog]:

| major | name | scope |
|---|---|---|
| 0 | MAJOR_ALL | all categories (filter-off value) |
| 1 | MAJOR_ALARM | alarmIn/Out, tamper, stress, linkage |
| 2 | MAJOR_EXCEPTION | device power-on/off, net broken, reader offline, login lock |
| 3 | MAJOR_OPERATION | logins, config ops, **remote door open**, upgrades |
| 5 | MAJOR_EVENT | **authentication & door events — the T&A payload** |

Minor codes under **major = 5** (decimal = hex shown in vendor headers) [VERIFIED —
node-red `MAJOR_EVENT-0x5.json` (hex names) cross-checked against `mmisobuj/HikvisionIsupServer`
`config/acs-event-types.json` (decimal names); both agree]:

| major | minor (dec) | hex | vendor name | meaning (relevance) |
|---|---:|---|---|---|
| 5 | 1  | 0x01 | MINOR_LEGAL_CARD_PASS | **card passed** (valid card, right OK) |
| 5 | 2  | 0x02 | CARD_AND_PSW_PASS | card+PIN pass |
| 5 | 3  | 0x03 | CARD_AND_PSW_FAIL | card+PIN fail |
| 5 | 6  | 0x06 | CARD_NO_RIGHT | card valid, **no permission at this door** |
| 5 | 7  | 0x07 | CARD_INVALID_PERIOD | card outside allowed time period |
| 5 | 8  | 0x08 | CARD_OUT_OF_DATE | expired card |
| 5 | 9  | 0x09 | MINOR_INVALID_CARD | **invalid card** — "Card No. Not Exist" (unregistered) |
| 5 | 12 | 0x0C | NOT_BELONG_MULTI_GROUP | not in multi-auth group |
| 5 | 16 | 0x10 | MULTI_VERIFY_SUCCESS | multi-person auth pass |
| 5 | 21 | 0x15 | MINOR_LOCK_OPEN | **unlock success** — "Door Unlocked" (relay fired) |
| 5 | 22 | 0x16 | MINOR_LOCK_CLOSE | door locked |
| 5 | 23 | 0x17 | DOOR_BUTTON_PRESS | exit button |
| 5 | 25 | 0x19 | DOOR_OPEN_NORMAL | door opened (contact sensor) |
| 5 | 26 | 0x1A | DOOR_CLOSE_NORMAL | door closed (contact) |
| 5 | 27 | 0x1B | DOOR_OPEN_ABNORMAL | door open w/o unlock (tailgate/forced) |
| 5 | 28 | 0x1C | DOOR_OPEN_TIMEOUT | open too long |
| 5 | 38 | 0x26 | FINGERPRINT_COMPARE_PASS | fingerprint matched |
| 5 | 39 | 0x27 | FINGERPRINT_COMPARE_FAIL | fingerprint mismatch |
| 5 | 40 | 0x28 | CARD_FINGERPRINT_VERIFY_PASS | card+finger pass |
| 5 | 54 | 0x36 | FACE_AND_FP_VERIFY_PASS | face+finger pass |
| 5 | 57 | 0x39 | FACE_AND_PW_VERIFY_PASS | face+PIN pass |
| 5 | 60 | 0x3C | FACE_AND_CARD_VERIFY_PASS | **card+face combined pass** |
| 5 | 61 | 0x3D | FACE_AND_CARD_VERIFY_FAIL | card+face failed |
| 5 | 66 | 0x42 | FACE_CARD_AND_FP_VERIFY_PASS | face+card+finger pass |
| 5 | 75 | 0x4B | MINOR_FACE_VERIFY_PASS | **face recognized/verified pass** |
| 5 | 76 | 0x4C | MINOR_FACE_VERIFY_FAIL | **invalid face** (mismatch against matched person) |
| 5 | 77 | 0x4D | EMPLOYEENO_AND_FACE_VERIFY_PASS | employeeID+face pass |
| 5 | 80 | 0x50 | MINOR_FACE_RECOGNIZE_FAIL | **no face matched** (1:N miss) |
| 5 | 113| 0x71 | CERTIFICATE_BLACKLIST | blacklist person detected |
| 5 | 151| 0x97 | PASSWORD_MISMATCH | PIN mismatch |
| 5 | 152| 0x98 | EMPLOYEE_NO_NOT_EXIST | employee ID not found |
| 5 | 153| 0x99 | COMBINED_VERIFY_PASS | combined authentication completed (generic combo pass) |
| 5 | 155| 0x9B | VERIFY_MODE_MISMATCH | wrong auth type used |
| 5 | 156| 0x9C | ORCODE_VERIFY_PASS | QR/one-code pass (per catalog) |
| 5 | 159| 0x9F | BLUETOOTH_VERIFY_PASS | Bluetooth pass |
| 5 | 162| 0xA2 | INFORMAL_MIFARE_CARD_VERIFY_FAIL | non-original Mifare rejected |
| 5 | 179| 0xB3 | DYNAMICCODE_VERIFY_PASS | dynamic QR pass |
| 5 | 181| 0xB5 | PASSWD_VERIFY_PASS | PIN alone pass |
| 5 | 190| 0xBE | IRIS_VERIFY_PASS | iris pass (ultra models) |
| 5 | 196-198 | | meeting sign-in/late | (minor T&A-ish, ignore) |

Remote / app open + platform operations are **major = 3** (MAJOR_OPERATION) [VERIFIED — mmisobuj catalog
`"3": {"1024": remoteOpenDoor, "1025": remoteCloseDoor, …}` + hubitat driver comment "subEventTypeid 1024 —
Remote Unlock"]:

| major | minor | name | meaning |
|---|---:|---|---|
| 3 | 1024 | REMOTE_OPEN_DOOR | **door opened by remote/app/platform** (Hik-Connect, web UI, ISAPI RemoteControl) |
| 3 | 1025 | REMOTE_CLOSE_DOOR | remote close |
| 3 | 1026/1027 | REMOTE_ALWAYS_OPEN/CLOSE | always-open/close toggled remotely |
| 3 | 1039 | UNLOCK_PASSWORD_OPEN_DOOR | unlock-by-password open |
| 3 | 80/112/113 | local/remote login/out | admin ops |
| 3 | 1035 | REMOTE_CAPTURE_PIC | capture |

Alarms/exceptions worth surfacing in an attendance UI [VERIFIED — same two catalogs]: (1,1034) stress/duress
alarm, (1,1036) card max authenticate fails, (2,1024/1025) device power on/off, (2,1033/1034) card reader
offline/resume, (2,1064/1065) local login lock/unlock, (1,1090) legal-event storage nearly full.

Note on a circulating error: a public "best-practices" repo labels minor 38 as "card authentication success"
and minor 113 as fingerprint — **wrong against the vendor hex table** (38=0x26 fingerprint matched; 1 is the
valid-card pass; 113=0x71 is blacklist). Trust the hex-named tables [VERIFIED conflict resolution].

**Filtering rule of thumb [INFERRED]:** punches = `major:5` AND `minor ∈ {1, 2, 40, 54, 57, 60, 66, 75, 77, 153, 179, 181, …}`
(granted set — outcome "granted" in the mmisobuj catalog) — or simply `eventAttribute:"attendance"`;
exceptions = `major:5` with outcome denied (6, 7, 8, 9, 76, 80, 151, 152, 155, …). Door-state noise
(21, 22, 25, 26) follows every pass and should be excluded from punches (a single face pass generates
`75 → 21 → 22` triples — VERIFIED in the DS-K1T341AMF forum dump, serials 575/576/577 at the same second).

---

## 4. attendanceStatus

**Yes — the AcsEvent response carries `attendanceStatus` on this firmware family.** [VERIFIED: (a) Hikvision
*AC Gateway API* Appendix A.2 documents `attendanceStatus` + `label` + `statusValue` inside every event
record; (b) the official *Hikvision T&A integrate solution* PDF shows `"attendanceStatus":""` inside the
`POST /ISAPI/AccessControl/AcsEvent` `InfoList` template **and** in the `alertStream` `AccessControllerEvent`
template; (c) a real DS-K1T341AMF owner's response dump (use-ip.co.uk thread, same hardware family as the
-S variant) contains `"attendanceStatus": "checkIn", "label": "Check In"` on the minor=75 record.]

Value enum (vendor): `"undefined"`, `"checkIn"`, `"checkOut"`, `"breakIn"`, `"breakOut"`, `"overtimeIn"`,
`"overtimeOut"` [VERIFIED — AC Gateway API A.2 wording]. Custom values are possible when "Attendance Status
on Device" is customized (then `label` carries the display text).

**It is only populated when attendance mode is enabled on the terminal** — otherwise every record comes back
`"undefined"` (observed in the Stack Overflow DS-K1T804 dump where all records are `undefined`; and
mmisobuj: "Terminals not configured for attendance mode report no status, and every punch comes through as
Unknown"). [VERIFIED both] Where attendance status is *configured*:
- `/ISAPI/AccessControl/attendanceStatusModeCfg?format=json` — mode `manual` / `auto` / `manualAndAuto`
  (+ "Attendance Status Required" on/off) [VERIFIED URI — Device Network SDK guide Appendix A.3/A.4 &
  B.3/B.6; semantics VERIFIED — HikCentral/HCP "Customize Attendance Status on Device" doc].
- `/ISAPI/AccessControl/attendanceStatusRuleCfg?attendanceStatus=<x>&format=json` — per-status rules [VERIFIED URI].
- HikCentral/HCP: Attendance → Basic Configuration → Custom Attendance Status on Device.
- `/ISAPI/AccessControl/Attendance/weekPlan/<PlanNo>?format=json`, `.../Attendance/planTemplate` —
  T&A **schedules** (which plan/status applies per weekday), not punch records [VERIFIED URI — ISAPI
  Access-Control Face Recognition Terminals guide TOC]. These drive *auto* mode status attribution.
- `UserInfo` / `UserInfoSearch` records do **not** carry attendanceStatus [INFERRED from absence — the full
  MinMoe UserInfo schema (open.hikvision.com §12/§13) has employeeNo/name/userType/Valid/doorRight/
  userVerifyMode/… but no attendance field].

**Deriving in/out when attendanceStatus is `undefined`** (device in pure-access mode) [INFERRED options, in
order of robustness]:
1. Turn on T&A status on the device (HikCentral "T&A Status on Device" / manual selection / auto plan) and
   read `attendanceStatus` — the only semantically correct source.
2. Physical-direction mapping: each `doorNo`/`cardReaderNo` is wired either entrance or exit; direction =
   f(door/reader) — a per-installation config table. (One reader per side ⇒ constant direction.)
3. Pair events: a genuine pass = `minor∈granted` at time t followed ≤ ~5 s by `(5,21)` door-unlocked and
   `(5,25)` contact-open; remote/app opens are `(3,1024)` and must be excluded from punches.
4. Day-boundary heuristic when nothing else exists: per employee/day, earliest record = in, latest = out
   (this is exactly the documented fallback in `mmisobuj/HikvisionIsupServer` — "daily summary falls back to
   first/last punch … a span, not worked hours").
5. `employeeNoString`+`time` sorted ascending with a state machine ("first punch of the day = checkIn") —
   same idea, per-shift, fragile across night shifts.

---

## 5. Exact AcsEventRecord field names (InfoList entry)

Annotated record assembled from real device dumps (use-ip DS-K1T341AMF; Stack Overflow; garden-gate;
ipcamtalk DS-K1T320EWX) against the vendor `JSON_AcsEventSearchResult`/`JSON_AcsEvent` schema [VERIFIED field
names; per-firmware presence → §6]:

```jsonc
{
  "major": 5,                       // int — major type
  "minor": 75,                      // int — minor type (0x4B face verify pass)
  "time": "2023-10-02T07:46:48+07:00", // ISO-8601 with device-local offset
  "serialNo": 575,                  // int — device event serial; SPARSE & WRAPS (32-bit-ish; do not treat as contiguous)
  "type": 0,                        // int — zone/event type (0 on terminals)
  "doorNo": 1,                      // int — door/lock number (1-based)
  "cardReaderNo": 1,                // int — reader number (0 when not applicable)
  "cardReaderKind": 0,              // int — 1=IC,2=ID card,3=QR,4=finger+card
  "employeeNoString": "99",         // string — person ID. THIS is the employee field in InfoList records
  "name": "test schedule",          // string — person display name (no "longName" field exists here)
  "userType": "normal",             // enum: normal | visitor | blacklist | administrators
  "cardNo": "",                     // string — card number if presented (decimal string of Wiegand/MIFARE UID; can exceed 2^32 — keep as string, e.g. "18446744073609552366")
  "cardType": 1,                    // int: 1-normal,2-disabled,3-blocklist,4-patrol,5-duress,6-super,7-visitor,8-dismiss
  "swipeCardType": 0,               // int: 0-invalid, 1-QR code
  "verifyNo": 0,                    // int — multi-auth sequence number (NOT the verification mode)
  "currentVerifyMode": "cardOrFaceOrFp", // enum — the mode that actually authenticated; ~30 values incl.
                                     // card, cardAndPw, cardOrPw, cardOrFace, cardOrFaceOrFp, fp, fpAndPw,
                                     // fpOrCard, fpAndCard, fpAndCardAndPw, fpOrPw, fpOrface, face, faceAndFp,
                                     // faceAndPw, faceAndCard, faceOrFpOrCardOrPw, faceAndFpAndCard,
                                     // faceAndPwAndFp, employeeNoAndPw, employeeNoAndFp, employeeNoAndFace,
                                     // employeeNoAndFpAndPw, faceOrfaceAndCard, cardOrfaceOrPw, invalid …
                                     // "invalid" is sent on records where no credential applied (e.g. (5,21)/(5,22))
  "attendanceStatus": "checkIn",    // enum undefined|checkIn|checkOut|breakIn|breakOut|overtimeIn|overtimeOut
  "label": "Check In",              // string — display label for the attendance status (custom names)
  "statusValue": 0,                 // int — numeric status code (device-internal)
  "mask": "no",                     // enum yes|no|unknown — mask detection
  "pictureURL": "http://192.0.2.11:8/LOCALS/pic/acsLinkCap/...jpeg@WEB000000000619",
                                     // string — snapshot URL (only with picEnable:true; needs auth too)
  "picturesNumber": 1,              // int
  "netUser": "",                    // string — operator for operation events
  "remoteHostAddr": "0.0.0.0",      // string — operator host for operation events
  "reportChannel": 0, "alarmInNo": 0, "alarmOutNo": 0, "caseSensorNo": 0,
  "RS485No": 0, "multiCardGroupNo": 0, "deviceNo": 0, "InternetAccess": 0,
  "MACAddr": ""                     // boilerplate fields present on older firmwares, all 0/"" on terminals
}
```

Key naming decisions for the connector [VERIFIED]:
- **`employeeNoString` (string), not `employeeNo`** — `employeeNo` appears in *alertStream*/SDK/legacy
  templates (`AccessControllerEvent.employeeNo` int-style) but InfoList search records carry
  `employeeNoString`. Accept both defensively (hubitat driver does `employeeNoString ?: employeeNo`).
- **`name`, not `longName`** — `longName` does not appear anywhere in the AcsEvent schema or dumps.
- **`currentVerifyMode`, not `verifyMode`** — no plain `verifyMode` key in AcsEvent records (vendor schema
  A.2; every dump). `verifyMode` exists in some *alertStream* payloads on newer firmware — if seen live,
  alias it [INFERRED].
- `serialNo` present and int-typed; on JSON-string-typed readers some firmwares return `cardReaderNo` as a
  JSON string — coerce to int (idstein/hikvision_access does exactly this).
- **Sensitive-field encryption caveat** [VERIFIED — cnblogs ge yee + ipcamtalk DS-K1T320EWX dump]: on
  firmwares where the session-login/security channel is enforced, `name` and `employeeNoString` come back as
  32-hex-char AES-128-CBC blobs (`"name":"b7aa4245ab0652c7e5ab1a8696d38021"`), decrypted with a key derived
  from the `Security/sessionLogin` handshake (POST `?timeStamp=`, iv passed as `&iv=` query param). If the
  connector sees 32-hex "names", this is why. Plain digest-auth may or may not trigger it on V3.2.30 →
  confirm on device.

---

## 6. Model/firmware-dependent items — MUST confirm on <device-ip> (once creds exist)

1. `GET /ISAPI/AccessControl/AcsEvent/capabilities?format=json` → real `maxResults @max`,
   `searchID @max`, `employeeNoString @max`, supported `minorEvent/minorAlarm/minorException/minorOperation`
   lists, presence of `eventAttribute`.
2. `responseStatusStrg` spelling actually returned (`NO MATCH` vs `NO_MATCHES`).
3. `AcsEventTotalNum` presence + response shape (nested vs flat, int vs string).
4. Whether `attendanceStatus` is populated (requires T&A status mode on) and its custom labels.
5. Whether `name`/`employeeNoString` are AES-encrypted on V3.2.30 (sessionLogin required?) — the V3.2.x
   Value-series builds are known to enable field encryption on siblings.
6. Whether both `employeeNo` and `employeeNoString` filters are accepted in `AcsEventCond`.
7. Whether `timeReverseOrder`, `picEnable`, `beginSerialNo/endSerialNo` are honored or rejected.
8. Event-capacity/serialNo wrap point (spec says 300 000 for DS-K1T341 class).
9. The exact minor codes the unit emits for card+face mode (faceAndCard=60 vs generic combined=153 depends
   on configured verify mode).
10. Whether the digest realm rejects `?format=json` variants or requires `X-Requested-With: XMLHttpRequest`
    (ge yee's scraper adds it).

## Sources

- https://community.home-assistant.io/t/ds-kd8003-ds-kv8113-ds-kv8213-ds-kv6113-ds-kv8413-and-integration-hikvision-hikconnect-video-intercom-doorbell/238535/52 — verbatim vendor `AcsEventCond` annotations (Value-Series doc)
- https://ipcamtalk.com/threads/hikvision-ds-k1t804amf-isapi-accesscontrol-event-retrieval-fails-with-invalid-content-error.80201 — real `AcsEvent/capabilities` JSON + badParameters case
- https://raw.githubusercontent.com/Supergiovane/node-red-contrib-hikvision-ultimate/master/nodes/utils/AccessControlEvents/MAJOR_EVENT-0x5.json — vendor hex minor table
- https://raw.githubusercontent.com/mmisobuj/HikvisionIsupServer/main/config/acs-event-types.json — full decimal major/minor catalog with outcomes
- https://open.hikvision.com/hardware/v2/08%E5%8D%8F%E8%AE%AE%E9%80%8F%E4%BC%A0/%E6%98%8E%E7%9C%B8%E9%97%A8%E7%A6%81.html — MinMoe transparent-transmission ISAPI schemas (AcsEventTotalNum, UserInfoSearch 0-based note, searchID semantics)
- https://pdfcoffee.com/hik-ac-gateway-api-v150-20211208-pdf-free.html — *Hik AC Gateway API V1.5.0* A.1/A.2 (AcsEventCond/SearchResult incl. attendanceStatus/label/currentVerifyMode enum) and Appendix B event types
- http://www.hikvisioneurope.com/za/portal/portal/02-Technical%20Materials/04-Training%20materials/03-HIK-League%202022/Technical%28Thursday%29/20220526%20Hikvision%20T%26A%20integrate%20solution/20220526%20Hikvision%20T%26A%20integrate%20solution.pdf — official T&A integration PDF (AcsEvent + alertStream attendanceStatus)
- https://www.use-ip.co.uk/forum/threads/get-access-event-filtered-to-show-only-valid-authenticated-check-in-and-check-out.10500/ — real DS-K1T341AMF response with attendanceStatus/label
- https://stackoverflow.com/questions/70825974/perl-external-json-api-hikvision-face-scan — real full-field InfoList dump
- https://github.com/creatorsgarten/garden-gate/blob/main/HIKVISION.md — working Postman/HTTP capture (major 5 minor 1)
- https://stackoverflow.com/questions/79926430/how-to-paginate-hikvision-api-results — serialNo gaps/wrap + paging guidance
- https://ipcamtalk.com/threads/hikvision-isapi-acseventcond-%E2%80%93-missing-records-serial-gaps-issue-pagination-serialno-logic.85371/ — serialNo semantics, ANR/push alternative
- https://packagist.org/packages/shaykhnazar/hikvision-isapi — searchID-session paging gotcha, AcsEventTotalNum shape variance
- https://github.com/uchkunr/hikvision-best-practices — pagination pattern (contains one mislabeled minor: 38)
- https://github.com/MAGNAT12/hikvision-isapi-python — maxResults=30 clamp behavior, real MORE response
- https://cnblogs.com/geyee/p/19267668 — sessionLogin+AES field encryption, position-loop extractor
- https://github.com/hhorigian/hubitat_Hikvision/blob/master/Hikvision_Controller_Driver.groovy — employeeNoString?:employeeNo defensiveness, remote-unlock 1024
- https://github.com/idstein/hikvision_access/blob/main/custom_components/hikvision_access/api/events.py — alertStream normalization, cardReaderNo string coercion
- https://enpinfo.hikvision.com/hkwsen/unzip/20230830144955_12918_doc/GUID-25FBC7DB-5D0D-458C-8883-A89D12FF1029.html — "Customize Attendance Status on Device" (manual/auto/manualAndAuto)
- https://www.scribd.com/document/743947473/Device-Network-SDK-Card-Based-Access-Control-Developer-Guide-V6-1-5-X-20230330 — AcsEventTotalNum + attendanceStatusModeCfg/RuleCfg URI list
- https://www.scribd.com/document/930639487/ISAPI-Developer-Guide-Access-Control-Face-Recognition-Terminals-2022-04-27 — Attendance/weekPlan URIs
- https://tpp.hikvision.com/download — canonical (NDA-gated) guide location for the exact V3.2.30 manual
