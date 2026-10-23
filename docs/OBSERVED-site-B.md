# OBSERVED — site-B (DS-K1T344MBFWX-E1, fw V4.13.0 build 260316, deviceType ACS)

Probe session 2026-10-23 (P2-11 t_5c0d82f0). Device host = `<device-b>` (192.0.2.x
LAN, deliberately not committed here), keychain `gateclerk-hikvision` acct=host,
user=admin (same creds as site-a). All reads read-only GETs/search POSTs; the ONE
write made was the operator-requested clock fix (System/Time, see §Clock).
Operator ran the info/time/caps/users/events half and posted the receipt on the
card; this file records what the remaining legs (dense-window acceptance, egress,
/Total, clamps) showed, plus the history re-label finding.

## Same as site-a (no action)
- `POST /ISAPI/AccessControl/AcsEvent/Total` → `400 subStatusCode:"notSupport"`
  (statusCode 4, errorCode 1073741825). Keep the endpoint out of the client
  (OBSERVED main table row applies verbatim to this newer fw family).
- **Silent maxResults clamp to 30**: request `maxResults:50` and `maxResults:100`
  over a 38-event history both returned `responseStatusStrg:"MORE"` with
  `numOfMatches:30`, `totalMatches:38` — clamp is SILENT (no error, no echo of the
  reduced cap), exactly site-a's p1-05 failure mode. Client stays clamped to the
  advertised cap (caps say 30; searchID ≤ 64; InfoList ≤ 30).
- `System/*` still answers **XML despite `format=json`** (Time body verified).
- Event noise model unchanged: every scan emits a burst (major 2/5 pairs, door
  records 1028/1031/1032 etc.); product-side filtering behaved as on site-a.
- Digest auth, paging dialect (`InfoList` under `AcsEvent`, advance by
  `numOfMatches`, terminate on ok/no-match) — no new shape.

## DIFFERS from site-a
### 1. The clock DST rule actually ENGAGES — claimed offset is DYNAMIC
site-a claims `+02:00` year-round (its DST rule never fires → needs the
`device_tz` mapping). site-b after the operator's fix runs
`timeMode:NTP`, ntp `time.google.com:123` interval 60, IANA `Europe/Bucharest`,
POSIX `CST-2:00:00DST01:00:00,M3.5.0/03:00:00,M10.5.0/04:00:00`,
`isSummerTime:true`, `localTime` carries `+03:00`, skew −1.2 s, verdict `agrees`.
**No `device_tz` mapping needed (or wanted) for site-b.** Consequence: the claimed
offset flips to `+02:00` at the next DST end (last Sunday of October — days away at
record time). The p1-05c mechanism (windows stamped with the claim READ ONCE PER RUN
via `pipeline.device_window_labels`) handles this automatically; **nothing may cache
the claim across runs** — the flip lands **Sun 2026-10-25 04:00→03:00 local** (two
days after this record), so winter acceptance is imminent, not hypothetical.

### 2. Dense-window ARITHMETIC acceptance on the new fw — PASSED (2 read-only POSTs)
Same decisive shape as the site-a A/B (OBSERVED main "ARITHMETIC" section), run over
the 12:44–12:46 local window containing the 12:45 test scans:

```
startTime 12:44:00+03:00, endTime 12:46:00+03:00  -> "OK",   totalMatches 6 (serials 31..36)
startTime 12:44:00+02:00, endTime 12:46:00+02:00  -> 0 matches (totalMatches 0)
```

Same digits, different label, different answer → this fw family also does
label→instant→device-clock ARITHMETIC, not mere presence. The winning label is the
device's CURRENT claim (+03:00 now), NOT a constant — the inverse of site-a's
summer result, which is exactly what the claim-based stamping predicts. A client
that hard-coded either offset would be wrong half the year on this device.

### 3. Pre-fix history is re-LABELED, not re-stamped — worse than the caveat says
Factory clock was `Asia/Shanghai` manual (digits +5 h from Bucharest wall). The
operator fixed it 2026-10-23 12:48:38 local (clock-change device events serials
37–38, major 3 / minor 1029). BUT the device re-renders stored wall digits with the
*current* tz config: the June pre-fix events (serials 1–10, stored as China digits
13:19) now come back as `2026-06-08T13:19:16+03:00` — a clean Bucharest label on
China digits (true local 08:19). So after a tz change the `+08:00` marker is GONE
from the raw payload and pre-fix events are indistinguishable by label alone.
**Rule: the site-b agent cursor must start after 12:48:38 local / serial > 38; the
pre-fix history (serials 1–36) must never be ingested as-is, and a "−5 h if label
is +08:00" heuristic does NOT work here.** General lesson: any future tz change on
ANY site silently re-labels all stored history — record the change boundary
(serial + wall) as operator metadata at the moment of the change.

### 4. History shape
38 serials total (1–10 June test batch, 11–38 today). No gaps observed. `more`-style
paging (`MORE`) exercised across the 30-cap.

## Outbound egress (spec §5 step 4) — PASS
One POST from the intended agent box (this Mac) to a public https echo endpoint:
HTTP 200, body echoed. The push leg can dial out. (Public egress IP deliberately not
recorded.)

## Users
1 user (emp 1), plaintext names — `encrypted_person_data:false` in event rows too.
Same resolution as site-a; the model's flag stays.

## Consequences / checklist
- sites.toml `[[site]] name="site-b"`: `iana_tz="Europe/Bucharest"`,
  **`device_tz` intentionally unset** (device claims honestly post-fix); push_target
  currently a local stub until the config card opens.
- Site-B config card opens only after this probe is green AND the owner okays the
  write rotation (canary step retired 2026-10-21). E1 `migrate apply` on B remains
  gated per owner 2026-10-23: dry-run diff + export snapshot FIRST, diff shown to
  owner before any `--apply`.
- Winter acceptance task: after Oct 25 (DST end) confirm the claim flips to +02:00
  and `device time` still says `agrees`; windows follow automatically.
