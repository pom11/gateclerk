# Recorded fixtures — site-a DS-K1T341AMF-S (fw V3.2.30)

Captured read-only from the real device on 2026-10-15, then **masked**:
real employee names → `User E<employeeNo>` (map lives only in this README),
serial → `MASKED-SER-1`, mac → `00:11:22:33:44:55`, digest `nonce`/`opaque` →
`MASKED-NONCE`/`MASKED`, `password` keys in UserInfo removed entirely.

| File | What it simulates |
|---|---|
| `digest_challenge_401.txt` | unauthenticated 401 + `WWW-Authenticate: Digest qop="auth"` |
| `device_info.xml` | System/deviceInfo — **XML despite ?format=json** on this fw |
| `system_time.xml` | System/time — wrong-offset bug specimen (`+02:00` in Bucharest summer), tz rule `CST-2:00:00DST01:00:00,M3.4.1/00:00:00,M10.5.0/23:00:00` |
| `acs_capabilities.json` | advertised `maxResults @max=30`, `searchID @max=64`, major opts `0,1,2,3,5`, minorEvent/Alarm/Operation sets |
| `user_count.json` | `{"UserInfoCount":{"userNumber":4}}` (GET-only endpoint) |
| `user_search_page1.json` | 4 users, status OK; `password` key stripped |
| `events_major5_page1.json` | **all 30 punches device-wide**: 18× minor=75 (granted, employeeNoString+name), 6× minor=21 open, 6× minor=22 close; `attendanceStatus` absent on every one |
| `events_more_noise_page1.json` | major=3/minor=1029 heartbeat, `responseStatusStrg:"MORE"`, total 10130 |
| `events_no_match.json` | empty window: `"NO MATCH"` (space!), **InfoList key absent** |
| `events_reverse_order.json` | `timeReverseOrder:true` → newest-first |
| `error_total_notsupport.json` | `AcsEvent/Total` → 400 `subStatusCode:"notSupport"` |

Mask map (real names → `User E<n>`) is deliberately **not** in this repo; it lives only
in the operator's local capture (`~/.hermes/.../device-probe/raw_capture.json`). If the
un-masked values are ever needed for reconciliation, the operator holds them.

CI note (policy 2026-10-15): no leak-guard machinery is built — fixtures stay masked
because masked is simply the right default (staff names are PII), not because CI has
to police it. If you add fixtures, mask names/serial/mac and move on.
