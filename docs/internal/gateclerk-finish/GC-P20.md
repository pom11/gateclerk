# GC-P20 — Read-only report: pushed events that were not granted punches

BOARD: gateclerk   DEPENDS ON: GC-P16a, GC-P12   GATED: no   COVERS: GC-01 / E22

## WHY

The operator needs the list of scans already pushed to BC that were not granted punches, so
BC-P30 can mark them ignored and recalculate. The report must come from the local store, be
read-only, and carry fingerprints only: no employee number, no name, no card number, no raw
payload. R1: BC remains the store; this is a repair input, not a second record.

## VERIFY

```bash
uv run --frozen gateclerk export --help
```

Still missing while the help lists only `config` and `scans` (no `non-punches` command).
The underlying data is present: `events.outcome`, `events.unknown_code`,
`events.fingerprint_hash` (`src/gateclerk/agent_db.py:113-127`) and the ledger lines
`{"e", "t", "k", "s"}` (`src/gateclerk/agent_cli.py:149-265`).

## FILES

- `src/gateclerk/export_cli.py:903-1043` — `export_scans_stream` is the pattern for a
  streaming export: resolve the store, open SQLite, write CSV/JSONL, never `fetchall`.
- `src/gateclerk/export_cli.py:903-925` — `resolve_scan_store_path(config_path=...,
  site=..., state_root=..., db_path=...)` returns `(site, site_tz, db_path)`.
- `src/gateclerk/export_cmds.py:174-220` — the `export scans` Typer command and its
  `_resolve_fmt_and_output` helper.
- `src/gateclerk/agent_cli.py:149-265` — `PushLedger(path)`, `sent_event_ids()` added by
  GC-P16a.
- `src/gateclerk/agent_db.py:119-120` — `outcome TEXT`, `unknown_code INTEGER`;
  `fingerprint_hash` is at `:91`.
- `tests/test_export_scans.py:167` — the store/export test setup to copy.

## CHANGE

1. Add `export_non_punch_fingerprints(...)` to `src/gateclerk/export_cli.py`:
   ```python
   def export_non_punch_fingerprints(
       *,
       config_path: Path | str = cfg.DEFAULT_SITES_FILE,
       site: str | None = None,
       state_root: Path | str | None = None,
       fmt: str = "csv",
       output_path: Path | str | None = None,
       dest_stream: TextIO | None = None,
       is_tty: bool | None = None,
   ) -> tuple[int, str]:
       """Write DISTINCT fingerprints of pushed non-punch events; no PII columns."""
   ```
   Resolve the store with `resolve_scan_store_path`; resolve the ledger at
   `Path(resolved_db).parent / "push-ledger.jsonl"` via
   `agent_cli.PUSH_LEDGER_FILE_NAME`. If the ledger is missing, return `(0, "no
   push-ledger.jsonl at ...; nothing is known to be pushed")`.
   Open SQLite, create a temp table of the ledger ids, and select (the mode list is
   rendered from `NON_AUTH_VERIFY_MODES`, so the query is an f-string with `?` values):
   ```python
   mode_marks = ", ".join("?" for _ in NON_AUTH_VERIFY_MODES)
   sql = f"""
   SELECT DISTINCT fingerprint_hash
     FROM events
    WHERE id IN (SELECT event_id FROM temp.pushed_events)
      AND NOT (
            major = 5 AND outcome = 'granted' AND unknown_code = 0
        AND employee_no IS NOT NULL AND employee_no <> ''
        AND verify_mode IS NOT NULL
        AND lower(trim(verify_mode)) NOT IN ({mode_marks})
      )
    ORDER BY fingerprint_hash
   """
   cursor = conn.execute(sql, tuple(sorted(NON_AUTH_VERIFY_MODES)))
   ```
   The query has no user input; the only interpolated text is the constant placeholder
   list. The output is one column, header `fingerprint`
   for CSV and `{"fingerprint": "..."}` for JSONL. Use the same TTY rule as
   `export scans`: refuse an interactive TTY without `--output`; but because this report
   has no PII, it may print to a pipe.
   The temp table insert uses `executemany` in chunks; if the ledger has more ids than
   SQLite's parameter limit, insert one row at a time in a transaction.
2. Add the Typer command in `src/gateclerk/export_cmds.py`:
   ```python
   @export_app.command("non-punches")
   def export_non_punches(
       config: ExportConfigFileOpt = cfg.DEFAULT_SITES_FILE,
       site: ExportSiteOpt = None,
       state_root: ExportStateRootOpt = None,
       fmt: ExportFormatOpt = "csv",
       output: ExportOutputOpt = None,
   ) -> None:
       """Read-only fingerprint list of pushed events that were not granted punches."""
       effective_fmt, effective_output, err_fmt = _resolve_fmt_and_output(fmt, output)
       try:
           count, message = export_cli.export_non_punch_fingerprints(
               config_path=config, site=site, state_root=state_root,
               fmt=effective_fmt, output_path=effective_output,
           )
       except ConfigError as exc:
           raise _config_exit(err_fmt, str(exc)) from exc
       if message:
           sys.stderr.write(message + "\n")
   ```
   Use the existing `ExportConfigFileOpt`/`ExportSiteOpt`/`ExportStateRootOpt` aliases.
3. Do not write to the store, the ledger or BC. The report is read-only.

What must NOT change:

- `export scans` and `export config`; no output column is added to them.
- The ledger format; this card reads it through `PushLedger`.
- No employee number, name, card number or raw payload in the report. Only
  `fingerprint_hash`.
- The fingerprint is the BC dedupe key; do not hash it a second time.

## TESTS

Write `tests/test_gc_p20_non_punch_report.py` first and run:

```bash
uv run --frozen pytest -q tests/test_gc_p20_non_punch_report.py
```

Copy the store fixture from `tests/test_export_scans.py:167` and the ledger writer from
`tests/test_p2_07b_agent_cli.py:909`.

Tests:

- `test_report_lists_only_pushed_non_punch_fingerprints` — store four events: granted
  punch, denied, info, unknown-code. Ledger records the denied and the granted; the info
  and unknown are not in the ledger. Output contains only the denied fingerprint.
- `test_report_has_one_column_and_no_pii` — CSV header is exactly `fingerprint`; the
  output contains no employee number, name or card number from the seeded rows.
- `test_report_is_empty_when_the_ledger_is_missing` — no ledger file; count 0 and a
  stderr note, exit 0.
- `test_report_reads_the_store_without_writing` — compare file mtime/size and row count
  before/after; unchanged.
- `test_report_matches_the_granted_punch_rule` — a granted event with `verify_mode =
  "invalid"` (not a punch) appears; a granted event with a real mode does not.

## GATE

```bash
uv run --frozen pytest -q
uv run --frozen ruff check src/gateclerk
```

## ACCEPT

- [ ] `gateclerk export non-punches` exists and is read-only.
- [ ] Output has one `fingerprint` column and no PII.
- [ ] Only events recorded as sent in the ledger are considered.
- [ ] Granted punch candidates are excluded; denied/info/unknown/non-auth-mode are
  included.
- [ ] A missing ledger yields an empty report, not a crash.
- [ ] Full pytest and ruff are green.

## OUT

BC-P30 (the repair writes in the BC repo), the ingest function, `export scans`, and the
store schema. Do not add a `--employee` filter: the report is deliberately identity-free.

## HANDOFF

Branch base `origin/main`; PR target `feat/gateclerk-finish`.

1. Run the GATE.
2. Open the PR against `feat/gateclerk-finish`.
3. When the gate is green and the PR is mergeable, run `gh pr merge <number> --squash`
   yourself.
4. Never merge into `main`/`master`; never force-push.
5. If the PR is not mergeable (conflict), rebase on `origin/feat/gateclerk-finish`, re-run
   the GATE, then merge. If that fails twice, stop and report `LEFT:`.

The card is complete only after the merge.

DONE: PR URL and merge commit.
LEFT: anything not merged, with the reason.
