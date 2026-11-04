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
