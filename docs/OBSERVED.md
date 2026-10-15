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
| `POST /ISAPI/AccessControl/AcsEvent/Total` | — | **NOT supported**: `400 {"statusCode":4,"statusString":"Invalid Operation","subStatusCode":"notSupport"}`. Do not use for counting; page instead. |

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
- p1-09: fixtures under `tests/fixtures/recorded/site-a-ds-k1t341amf-s/` are the corpus (masked: names→`User E<n>`, serial→`MASKED-SER-1`, mac zeroed, password keys removed, nonce masked); keep the leak-check grep in CI.
