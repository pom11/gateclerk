# GC-P16b — Mask card numbers in the Excel import results CSV

BOARD: gateclerk   DEPENDS ON: GC-P16a   GATED: no   COVERS: GC-14 / —

## WHY

`users_import.write_results_csv()` writes the full `cardNo` to `<xlsx>.results.csv` next
to the workbook. BC Tables 70605/70606 already own the card assignment, and the results CSV
is a shareable audit file. GC-14 requires the full card number to stop leaking to disk.
R1/R2: BC owns the identity data; the local artifact is a report, not a second register.

## VERIFY

```bash
grep -n '"cardNo": item.row.card_no' src/gateclerk/users_import.py
```

Still broken while the line exists:

```text
888:                    "cardNo": item.row.card_no,
```

If the value already goes through `mask_card_no`, stop and close the card.

## FILES

- `src/gateclerk/users_import.py:170-176` — `mask_card_no(card_no)` keeps at most the last
  four characters and uses `*` for shorter values.
- `src/gateclerk/users_import.py:864-895` — `write_results_csv`; line 888 writes the raw
  card number. The docstring says "the ONLY place a full card number appears".
- `src/gateclerk/users_import.py:628` — the dry-run summary already uses
  `mask_card_no(self.row.card_no)`; copy that idiom.
- `tests/test_users_import.py:371-430` — the apply test that reads `results.csv`.

## CHANGE

1. Change line 888 to:
   ```python
   "cardNo": mask_card_no(item.row.card_no),
   ```
2. Update the docstring: the file is a masked audit file; the full card number never
   leaves the terminal write path and the Excel source. Do not change the column name or
   the CSV layout; operators have scripts that read `cardNo`.
3. Do not change `mask_card_no` itself. Short numbers (`<= 4`) stay fully masked; longer
   numbers expose the last four only.

What must NOT change:

- The `users import` journal, the terminal write payload and the plan/dry-run output.
- The results CSV path, mode `0600`, header order and action/reason columns.
- The full card number in the input workbook; that is the operator's source file.

## TESTS

Write `tests/test_gc_p16b_masked_results.py` first and run:

```bash
uv run --frozen pytest -q tests/test_gc_p16b_masked_results.py
```

Copy the apply test from `tests/test_users_import.py:371` (`run_import` with
`apply=True`, `expect_serial=TARGET_SERIAL`, `results_path=...`).

Tests:

- `test_results_csv_carries_only_the_masked_card` — after an applied import, read
  `results.csv`; assert the full `90000090` is absent and `******90` (or the exact
  `mask_card_no` output) is present.
- `test_results_csv_has_no_unmasked_digits_for_any_row` — iterate every `cardNo` cell;
  assert `len(cell.lstrip("*")) <= 4`.
- `test_short_card_is_fully_masked` — a card of four characters becomes `****`.
- `test_results_file_mode_stays_0600` — `stat().st_mode & 0o777 == 0o600`.

## GATE

```bash
uv run --frozen pytest -q
uv run --frozen ruff check src/gateclerk
```

## ACCEPT

- [ ] `write_results_csv` uses `mask_card_no`.
- [ ] The full card number is absent from `results.csv`.
- [ ] The CSV header, path and `0600` mode are unchanged.
- [ ] Short cards are fully masked.
- [ ] Full pytest and ruff are green.

## OUT

`src/gateclerk/users_import.py`'s write/journal path, `mask_card_no`, the workbook reader,
and `src/gateclerk/migrate_bundle.py` (GC-P16c).

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
