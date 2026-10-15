# p1-06 — time/tz resolution → UTC

Scope per the orchestrator's scope-lock (2026-10-15): **one module** (`src/gateclerk/tz.py`)
of the core resolution policy. The Hikvision tz-dialect zoo and the `tz_offset_mismatch`
flag were cut out of this card and split into p1-06b/c (see "Split out" below).

Truth source for every decision here: `docs/OBSERVED.md` → "The time/offset bug
(payroll-critical, VERIFIED)". That section overrides the offset-trusting wording in
`docs/DESIGN.md` "Time handling".

## The bug being closed

```
GET /ISAPI/System/time -> <localTime>2026-10-15T16:39:32+02:00</localTime>
real local wall time    16:39:36 +03:00 (EEST, Europe/Bucharest)
```

The device's **wall clock is correct** (~4 s skew) but the **UTC offset it stamps is
wrong**: it labels `+02:00` in summer when the zone is `+03:00`, because its DST rule
`CST-2:00:00DST01:00:00,M3.4.1/00:00:00,M10.5.0/23:00:00` is not the EU rule and never
engages. Every `AcsEvent.time` therefore carries a wrong offset. Trusting it — which is
what DESIGN.md originally described — moves every summer punch by one hour.

## Policy implemented (`src/gateclerk/tz.py`)

1. The **site IANA zone** from config decides the UTC instant. Take the naive wall-clock
   part of the device string, interpret it in that zone with `zoneinfo`. DST comes from
   the tz database, not from us.
2. The verbatim device string (`device_local`) and the offset the device *claimed*
   (`device_offset_minutes`) are both kept. The claim is never used for math.
3. Unresolvable → `tz_source="unresolved"`, `utc=None`, `reason` set. **Kept and
   flagged**, never dropped, never defaulted to UTC.

`tz_source ∈ {"site-tz", "string-offset", "unresolved"}`. The card body listed
`{"string-offset","device-tz","unresolved"}`; `"site-tz"` is the new primary per
OBSERVED.md. `"device-tz"` is gone with the dialect parser (p1-06b) — nothing here can
interpret a Hikvision `timeZone` string, so there is no device-tz path to name.

## Two things that are easy to get wrong, both pinned by tests

**Query windows are device-naive-wall, not UTC.** The device filters `startTime`/
`endTime` against its *own* wall clock, which is the healthy part. So
`window_for_device()` converts to the site zone and drops the tzinfo. Sending the UTC
value instead shifts every window by the device's offset error and silently drops ~an
hour of punches at each boundary in summer. `test_window_round_trips_through_the_resolver`
and `test_window_round_trip_across_both_dst_transitions` are the round-trip proof.

**Skew compares wall clocks in the site zone, not self-labelled instants.** The device's
self-labelled instant is an hour off purely because of its tz bug; comparing instants
would report that as ~3596 s of "clock skew" and fire the warning on every run, blaming
NTP for a tz mistake. `test_skew_is_a_wall_clock_comparison_not_an_instant_comparison`
states both numbers side by side.

## Deliberate decisions

* **Autumn fold → `fold=0` = first occurrence = the DST offset**, flagged
  `tz_ambiguous`. Chosen over "latest possible instant" deliberately: crediting the later
  pass would hand a worker the extra daylight hour as time worked. Flagged so a human
  adjudicates rather than us picking silently.
* **Spring gap is not silently shifted.** `tz_nonexistent=True`; UTC still computed
  (zoneinfo's fold=0 answer) so the punch is not lost. A device emitting a timestamp from
  inside a skipped hour has a broken clock — that deserves a finding, not a correction.
* **A date with no time component is unresolved, not midnight.** `fromisoformat`
  accepts `"2026-10-12"`; resolving a punch to local midnight is a guess. The CLI is
  deliberately more lenient (`--since 2026-10-12` → midnight in the site zone, which is
  what a human means) — different input, different contract, and both are tested.
* **Zoneinfo only, no dateutil/pytz.** py3.12 `fromisoformat` already handles `Z`,
  `+HHMM` and fractions (probed against the interpreter this package pins).
* **Fold-affected instants are compared via `astimezone(UTC)`.** On CPython 3.12 with
  this tzdata, the two fold variants of one Bucharest wall time compare `==` while
  `astimezone(UTC)` shows them an hour apart, and `a == utc_instant` is False while
  `a - utc_instant` is zero. A test that picked whichever operator happened to pass would
  assert nothing, so the convention is stated in
  `test_timestamps_are_compared_via_astimezone_not_across_zones`.
* **DST fixtures are on measured edges.** Romania's 2026 transitions land at local
  03:00–03:59 (gap on 29 Mar, fold on 25 Oct), *not* the folk-rule 02:00. A 02:30 fixture
  would silently test nothing; `test_gap_and_fold_are_the_2026_edges` guards the premise
  so a future tzdb move fails loudly instead of neutering the DST cases.
* **`site_tz=None` is a supported config state** meaning "unresolved", checked with
  `is not None` — a site may legitimately be UTC, and an empty `--tz ''` must not
  quietly become UTC either.
* **XML parse is bounded, not delegated.** `parse_isapi_xml` refuses any DTD/ENTITY and
  caps body size; `ElementTree` resolves no external entities itself. S314 is suppressed
  at the one call with that reasoning. (Also the shared entry point p1-03 wants for
  `deviceInfo`, which this firmware returns as XML despite `?format=json`.)

## Split out of this card (created as children of it)

* **p1-06b — Hikvision `timeZone` dialect table.** Windows names (`'GTB Standard Time'` →
  `Europe/Bucharest`), `Etc/GMT±N` (sign inverted vs POSIX), POSIX `CST-2:00:00`
  (west-positive) with `DST01:00:00` as the amount *added*. Explicit mapping, never
  `str.replace("GMT","")`. `DeviceTime.tz_raw` already carries the raw dialect string so
  that card needs no change here.
* **p1-06c — `tz_offset_mismatch` flag.** `as_record()` already emits both
  `tz_offset_min` (used) and `tz_offset_min_device` (claimed), so the flag is a
  comparison of two columns that already exist. No change to tz.py required.

## Out of scope, deliberately

Nothing in this module issues a request; `read_system_time()` takes a response body so
p1-03 owns the transport. No device contact, ever, from this card.

## Test bar

`tests/test_tz.py` — 88 tests. Golden pairs are
`tests/fixtures/recorded/site-a-ds-k1t341amf-s/{system_time.xml,events_major5_page1.json}`;
all 30 punches resolve, all 30 show claimed `+02:00` against used `+03:00`, and the first
and last punch are pinned to concrete UTC instants (sorting alone cannot catch an offset
error, so the anchors matter).
