# OBSERVED — device truth (read-only probe, 2026-10-15)

Everything here was captured from the real device with read-only calls only
(GETs + the two stateless search POSTs). Recorded via `curl --digest` against
`http://192.0.2.10` (site-a). Nothing on the device was changed. This file is
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

## Digest nonce use-cap → deterministic 401 mid-backfill (owner live run 2026-10-17, VERIFIED symptom / OPEN mechanism)

Long `--chunk 1h` backfill hit **401 Unauthorized with the correct password** at exactly
the same window on two runs (2026-09-08T21:00, ~190th request of the walk), exit 3.
The device stayed **unlocked**: `lockStatus=unlock`, `retryLoginTime=4` (the step-9
wrong-password probe afterwards behaved normally) — so this is NOT a lockout. Reading:
the device retires a digest nonce after N uses; our client does not survive the
re-challenge (httpx spends exactly one re-auth; our 401-is-terminal rule + circuit then
kill the run). **MECHANISM OPEN — we never captured the 401 response itself**: was a
`WWW-Authenticate` challenge present? `stale="true"` or `"false"`? Or error-envelope-only?
Three shapes have different fixes. Debug OFFLINE with FakeDevice nonce-expiry seams
(all three shapes) — do NOT re-probe the device to find out: every wrong-shape 401 can
count toward lockout accounting. Card t_12286c0d's sibling tracks the fix.
Any backfill over ~190 requests fails until fixed.

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
