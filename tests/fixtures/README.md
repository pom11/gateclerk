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
| `user_search_page1.json` | 4 users, status OK; `password` key **removed by masking**, so this file cannot demonstrate the strip — `tests/test_model.py::test_password_hash_is_stripped_before_anything_can_store_it` uses an inline body that still carries one |
| `events_major5_page1.json` | **all 30 punches device-wide**: 18× minor=75 (granted, employeeNoString+name), 6× minor=21 open, 6× minor=22 close; `attendanceStatus` absent on every one |
| `events_more_noise_page1.json` | major=3/minor=1029 heartbeat, `responseStatusStrg:"MORE"`, total 10130 |
| `events_no_match.json` | empty window: `"NO MATCH"` (space!), **InfoList key absent** |
| `events_reverse_order.json` | `timeReverseOrder:true` → newest-first |
| `error_total_notsupport.json` | `AcsEvent/Total` → 400 `subStatusCode:"notSupport"` |
| `error_naive_start_time.json` | AcsEvent with a **naive** `startTime` → 400 `statusCode:6`, `subStatusCode:"badJsonContent"`, `errorMsg:"startTime"` (owner live probe 2026-10-17, OBSERVED.md "Event-window startTime form: offset REQUIRED" — the shape FakeDevice now answers any naive event bound with) |
| `nonce_retired_stale_true_401.txt` | **INVENTED, not captured** (t_a3521d8a). Shape (a) of a retired digest nonce: 401 + `WWW-Authenticate … stale="true"` + fresh nonce. httpx re-pays it, so the walk survives inside the library. Emitted by `FakeDevice(retire_shape=RETIRE_STALE_TRUE)`. |
| `nonce_retired_stale_false_401.txt` | **INVENTED, not captured** (t_a3521d8a). Shape (b): same, but the challenge spells `stale="false"` — the spelling a client that trusts `stale` would get wrong. Also survived inside httpx, which never reads the flag. `FakeDevice(retire_shape=RETIRE_STALE_FALSE)`. |
| `nonce_retired_envelope_only_401.txt` | **INVENTED, not captured** (t_a3521d8a). Shape (c): 401 + ISAPI envelope, **no `WWW-Authenticate`**. The one shape that reproduces the live "401 at request ~190 with the correct password" (OBSERVED.md "Digest nonce use-cap"): with no challenge, httpx does not re-pay and the dead nonce sticks. `FakeDevice(retire_shape=RETIRE_ENVELOPE_ONLY)`. |

The three `nonce_retired_*` files are **models, not recordings** — the live 401 was never
captured, which is why all three shapes exist (OBSERVED.md leaves the mechanism OPEN).
Each file carries its own INVENTED-BUT-LABELLED block; do not cite them as device truth.

Mask map (real names → `User E<n>`) is deliberately **not** in this repo; it lives only
in the operator's local capture (`~/.hermes/.../device-probe/raw_capture.json`). If the
un-masked values are ever needed for reconciliation, the operator holds them.

CI note (policy 2026-10-15): no leak-guard machinery is built — fixtures stay masked
because masked is simply the right default (staff names are PII), not because CI has
to police it. If you add fixtures, mask names/serial/mac and move on.

## Synthetic fixtures — `synthetic/`

Shapes the device cannot give us today, so they are authored rather than recorded, and
labelled as such in each file's `_comment`. Recorded fixtures stay the source of truth
for anything the device actually emits; these exist so a rule is covered offline before
it can be observed.

| File | Why it is synthetic |
|---|---|
| `attendance_status_events.json` | site-a's terminal is in pure access-control mode, so `attendanceStatus` is absent on every real event (OBSERVED.md). The checkIn/checkOut/breakIn shape only appears if the owner enables attendance mode (DESIGN.md option A). `expected_direction` / `expected_source` are the asserted `EventRecord` values. |
| `encrypted_person_data.json` | site-a returned plaintext names and has no encryption capability at all (`/ISAPI/Security/encryption/capabilities` → 404), so the base64-blob name cannot be captured here. `expect_encrypted` is the asserted `encrypted_person_data` value; names are always stored verbatim. |
| `user_search_page_b_dialect.json` | the second terminal's `UserInfo/Search` dialect: every row carries a device-assigned `picID` site-A's rows never had (live A->B, card E1-10). Shape is site-A's recorded page verbatim + `picID`, so the ONE difference is the one `DEVICE_ASSIGNED_FIELDS` must absorb. Authored from the operator's live run record, not a masked capture (no B capture is committed). |

The first two are used by `tests/test_model.py` (card p1-07); the third by
`tests/test_e1_10_picid_dialect.py`. If a later live probe shows the device really does
emit one of these shapes, replace the synthetic file with a masked recording and say so in
`docs/internal/OBSERVED.md`.

## Scenario corpus — `scenarios/` (card p1-09)

Each `scenarios/<name>/` directory is one whole fake box (roster, event pages, clock)
driven end-to-end through the full CLI by `tests/test_cli_e2e.py` (goldens in
`tests/golden/`) and audited by `tests/test_cli_e2e_battery.py`. The registry lives in
`tests/e2e_harness.py::SCENARIOS`; `test_corpus_matches_the_readme_table` pins that
this table and that registry contain exactly the same names. All contents are
synthetic and clearly fake (serials 9xxx, `User E<n>`/RO placeholder names, `fakepw`).

| Scenario | What the box simulates |
|---|---|
| `happy_day` | attendance mode ON: checkIn/checkOut + face/card passes, offset-bearing time strings with site-a's +02:00-in-+03:00 stamp (the payroll happy path) |
| `happy_day_chunked` | same day walked `--chunk 12h`: fresh searchID per chunk, cursor restarts at 0, and the noon boundary punch (serial 9013) arrives from BOTH half-day pages — the inclusive-bounds overlap P2's UPSERT makes free |
| `naive_time` | fw variant that stamps NO offset on any time string (events and System/time alike): same site-tz resolution, and `tz_offset_mismatch` is None (no claim), never False |
| `dst_day` | Bucharest 2026 DST edges: spring gap 29 Mar 03:30 (nonexistent, kept+flagged) and autumn fold 25 Oct 03:30 occurring TWICE (two employees, same stamp — both take the FIRST occurrence, +03:00) |
| `max10_box` | device advertises `maxResults @max=10` (some DS-K1T* boxes): six pages of exactly ten, walked at the advertised cap |
| `clamped_maxresults` | device SILENTLY serves 7 of the 30 asked (vendor text): the cursor must follow the returned numOfMatches — advancing by 30 would skip the last 4 with no error (THE payroll bug) |
| `ignored_employee_filter` | device ignores `employeeNoString` and serves everyone (OBSERVED.md): the client-side filter must still yield exactly employee 2 |
| `attendance_absent` | site-a's REAL mode (serves the recorded masked capture): `attendanceStatus` absent on every event → direction=unknown / direction_source=none |
| `encrypted_person_data` | site variant whose `name` is a base64 blob (DESIGN.md open question): flagged `encrypted_person_data`, kept verbatim, never decoded or dropped |
| `unicode_names` | RO diacritic names stored NFD by the device (different bytes than NFC for the same person): the MODEL composes to NFC, `raw` keeps the device's NFD bytes |
| `digest_stale_nonce` | `webs` rotates the session nonce mid-walk: exactly one `stale="true"` re-challenge, zero lost records, new nonce on every later request |
| `busy_then_retry` | two `deviceBusy` (HTTP 503 / statusCode 2) answers mid-session: transport backs off and the output is byte-identical to the same box served healthy |
| `invalid_content` | events endpoint answers `Invalid Content`/`badParameters` (statusCode 6) and stays there: terminal class — CLI exits 4 quoting the body, prints no records, never loops (retrying it is the lockout path) |

The error-payload box (`invalid_content`) has no byte golden: its error quotes the
request body, which carries a fresh uuid4 searchID per run. Its contract is pinned
structurally instead — see the docstring on `test_events_jsonl_matches_golden`.

Regenerate goldens deliberately: `GATECLERK_UPDATE_GOLDEN=1 uv run pytest
tests/test_cli_e2e.py`, READ the `git diff tests/golden`, commit only what you meant
to change. A golden that changed because a record field changed is the review
artifact; one that changed for no reason is the bug goldens exist to catch.
