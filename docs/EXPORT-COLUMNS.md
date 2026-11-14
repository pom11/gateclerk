# Export Columns — `gateclerk export scans` & `gateclerk export config`

Single source of truth: `src/gateclerk/export_cli.py` (`SCAN_EXPORT_COLUMNS`,
`SCAN_EXPORT_REDACTED_COLUMNS`, `CONFIG_EXPORT_COLUMNS`).

## Personal-data & secret-redaction rules

- **Attendance scans (`gateclerk export scans`) are personal data** (GDPR-adjacent
  workforce attendance records). By default, output goes to `stdout` **only** when
  `stdout` is not an interactive terminal (piped/redirected). On an interactive TTY,
  `--output <path>` (`-o <path>`) is required so the CLI never dumps personal data to a
  terminal by surprise and never invents a file path.
- Passing `--redact` on `gateclerk export scans` drops `employee_no`, `cardNo`, and `name`
  from the CSV header/rows and strips `employee_no` / `employeeNo` / `employeeNoString` /
  `cardNo` / `card_no` / `name` from the `raw` JSON object (and from `--format jsonl`
  lines) so exports can be shared for diagnostics without personal identifiers.
- **Configuration inventory (`gateclerk export config`) exports reference names only,
  never secret values.** Unknown keys at top level, in `[[site]]`, or in `[[site.sink]]`
  are dropped and counted in the `dropped_keys` audit line on `stderr`.

---

## 1. `gateclerk export scans` (`--format csv` | `--format jsonl`)

- **Ordering:** `ORDER BY event_time_utc ASC, serial_no ASC, id ASC` (streamed in chunks
  via `cursor.fetchmany(SCAN_EXPORT_CHUNK_SIZE)` with zero full-table list
  materialization).
- **Encoding:** UTF-8 without BOM by default; pass `--bom` to prepend a UTF-8 BOM
  (`U+FEFF`) on CSV output for Excel-on-Windows compatibility.
- **JSONL (`--format jsonl`):** emits each stored `EventRecord` JSONL line verbatim
  (27 contract keys in `model.RECORD_JSON_KEYS` order), or with personal identifiers
  removed when `--redact` is set.

### CSV column order (`SCAN_EXPORT_COLUMNS` — 28 columns)

| # | Column | Source / Meaning | Included with `--redact`? |
|---|--------|------------------|---------------------------|
| 1 | `site` | Site code (`events.site`) | Yes |
| 2 | `device_serial` | Device serial (`events.device_serial`) | Yes |
| 3 | `serial_no` | Monotonic device event serial (`events.serial_no`) | Yes |
| 4 | `employee_no` | Employee / device user number (`events.employee_no`) | **Dropped** |
| 5 | `cardNo` | Card number from device payload (`raw.cardNo`, if any) | **Dropped** |
| 6 | `name` | Person name (`events.name`) | **Dropped** |
| 7 | `event_time_utc` | Resolved UTC instant (`YYYY-MM-DDTHH:MM:SS+00:00`) | Yes |
| 8 | `event_time_local` | Device local timestamp string verbatim | Yes |
| 9 | `tz_offset_min` | Offset (minutes east of UTC) used for UTC conversion | Yes |
| 10 | `tz_offset_min_device` | Offset claimed by the device | Yes |
| 11 | `tz_source` | `site-tz`, `string-offset`, or `unresolved` | Yes |
| 12 | `iana_tz` | Site IANA timezone | Yes |
| 13 | `tz_unresolved` | `true` / `false` | Yes |
| 14 | `tz_ambiguous` | `true` / `false` (DST fall-back fold) | Yes |
| 15 | `tz_nonexistent` | `true` / `false` (DST spring-forward gap) | Yes |
| 16 | `tz_reason` | Resolution failure note (empty when resolved) | Yes |
| 17 | `tz_offset_mismatch` | `true`, `false`, or empty when no claim | Yes |
| 18 | `direction` | `in`, `out`, or `unknown` | Yes |
| 19 | `attendance_status` | Verbatim device `attendanceStatus` | Yes |
| 20 | `direction_source` | `device`, `inferred`, or `none` | Yes |
| 21 | `verify_mode` | Verbatim device `currentVerifyMode` | Yes |
| 22 | `major` | Hikvision major event code | Yes |
| 23 | `minor` | Hikvision minor event code | Yes |
| 24 | `outcome` | `granted`, `denied`, or `info` | Yes |
| 25 | `unknown_code` | `true` / `false` | Yes |
| 26 | `encrypted_person_data` | `true` / `false` | Yes |
| 27 | `raw` | Untouched device event JSON (PII keys stripped under `--redact`) | Yes (redacted) |
| 28 | `captured_at` | Agent capture UTC timestamp | Yes |

---

## 2. `gateclerk export config` (`CONFIG_EXPORT_COLUMNS` — 24 columns)

Fixed allowlist order:
`site`, `enabled`, `state_dir`, `db_path`, `db_warn_bytes`, `host`, `port`,
`isapi_user`, `device_code`, `serial`, `iana_tz`, `device_tz`, `timeout_s`,
`page_delay_ms`, `cadence_s`, `overlap_s`, `push_dead_letter_after_s`,
`device_cred_keychain_service`, `device_cred_env_var`, `device_cred_ref`,
`push_target`, `ingest_token_keychain_service`, `ingest_token_env_var`, `sinks`.

---

## 3. `gateclerk export non-punches` (`NON_PUNCH_EXPORT_COLUMNS` — 1 column)

The fingerprints of the scans this site's poller already handed to the ingest that were **not**
granted punches — a repair input for the ingest, not a second record of attendance. Which
fingerprints appear is decided by exactly two inputs: the poller's own push ledger and the
punch rule, negated.

- **The one column:** `fingerprint`, holding `events.fingerprint_hash` **verbatim**. It is the
  ingest's dedupe key, so it is deliberately not hashed a second time — a second hash would
  join to nothing on the receiving side. Same value, byte for byte, or the join it exists for
  breaks.
- **Only what was pushed:** an event is considered only if the poller recorded it as sent in its
  own `push-ledger.jsonl` (the ledger file beside the store), read through
  `PushLedger.sent_event_ids` across every endpoint and sink; a `gone` line counts as pushed
  exactly as a `sent` line does. An event the ledger does not name is not in the report — it is
  not known to have left the building.
- **A missing ledger is an empty report, not an error:** zero rows, a note on `stderr`, exit `0`.
  Nothing is known to be pushed, and guessing is not this command's job.
- **What is excluded:** a granted punch candidate — `major = 5`, `outcome = 'granted'`,
  `unknown_code = 0`, a non-empty `employee_no`, and a `verify_mode` that is not one of the
  non-authentication modes. Every arm must hold for a row to count as a punch.
- **What is included:** denied, informational, unknown-code, unattributed (empty `employee_no`)
  and non-auth-verify-mode rows. A row whose verdict columns are `NULL` is included as well:
  `NULL` is not provably a punch, so it belongs on the list.
- **Deduplication:** `DISTINCT` — one line per fingerprint, ordered by fingerprint. The same
  scan read twice on two serial numbers produces one line.
- **Identity-free by design:** no employee number, name, card number or raw payload appears
  anywhere in the output, so the file is safe to hand across the boundary. There is
  deliberately no `--employee` filter: the report names scans, never people.
- **Read-only:** the store is opened SQLite read-only (`mode=ro`), so writing it is impossible
  rather than merely unintended; the ledger is never written and the ingest is never contacted.
  A missing store or an unusable `--format` exits `2`, like the other exports.
- **Output:** on an interactive TTY, `--output <path>` (`-o <path>`) is required (the same rule
  as the other exports — a repair input meant for another system belongs in a file, and this
  command never invents a path). Piping stdout is fine. `--format jsonl` writes one
  `{"fingerprint": "..."}` object per line.

### Column order (`NON_PUNCH_EXPORT_COLUMNS` — 1 column)

| # | Column | Source / Meaning |
|---|--------|------------------|
| 1 | `fingerprint` | `events.fingerprint_hash` verbatim — the ingest's dedupe key |
