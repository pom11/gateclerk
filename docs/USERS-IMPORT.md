# Importing users and cards from Excel

`gateclerk users import` enrolls persons **with cards** onto one Hikvision terminal from
an `.xlsx` workbook. It is a gated device write: the default is a zero-byte dry run, and
`--apply` is the second opt-in write exception in the README (the first is
`gateclerk migrate apply --apply`).

The write path is the captured one from `docs/OBSERVED.md` — flat `UserInfo` /
`CardInfo` wrappers with `mode:"add"` — and it reuses the journal, pacing and read-back
seams from `migrate_write.py` / `migrate_write_cards.py`. No new transport is invented.

## Install the optional Excel extra

`openpyxl` is optional so the rest of the package works without it:

```bash
pip install 'gateclerk[excel]'
# or, from a checkout:
uv sync --extra excel
```

Without it, `users import` and `users template` exit 2 with the install hint.

## Header columns (settled mapping)

Default header row:

| Column | Required | Meaning |
| --- | --- | --- |
| `employeeNo` | yes | The device's employee number string — the join key. |
| `name` | yes | Display name stored on the terminal. |
| `cardNo` | yes | The card number string written to `CardInfo/SetUp`. |
| `cardType` | no | Defaults to `normalCard`; must be in the device's caps vocabulary. |
| `validFrom` | no | Local wall time, e.g. `2026-01-01T00:00:00`; default `2000-01-01T00:00:00`. |
| `validTo` | no | Local wall time, e.g. `2037-12-31T23:59:59`; default `2037-12-31T23:59:59`. |

Write a blank template:

```bash
gateclerk users template users.xlsx
```

If your workbook uses different header names, map them explicitly (repeatable):

```bash
gateclerk users import users.xlsx \
  --map 'Emp No=employeeNo' --map 'Full Name=name' --map 'Card=cardNo'
```

Only the first sheet is read unless you pass `--sheet NAME`.

## Business Central and Matricol

`employeeNo` **must equal the identifier Business Central links the device user to**.
The device stores only that string; the BC device-user link is what resolves a scan to a
person.

The operator must confirm how that same string maps to **Matricol**. This tool does not
create or alter the BC link table; if the BC link is created separately (BC UI or an
existing `exportSites`/links path), do that through the normal BC process before or after
this import, and keep the `employeeNo` value identical on both sides.

## What a run does

1. Reads the device's UserInfo and CardInfo capabilities and **refuses to write** unless
   both confirm the captured `SetUp` verb and flat wrapper. A newer model that needs the
   Record-style shape is a STOP with evidence, never a fallback guess.
2. Reads the current user roster (`UserInfo/Search`) and card roster (`CardInfo/Search`).
3. Classifies every row:
   - `add-user` — person is absent; the person and their card are written.
   - `add-card` — person is present with the same name/validity; only the card is added.
   - `skip-present` — person and `(cardNo, employeeNo)` pair are already on the device.
   - `skip-update-needed` — person exists but a field differs; the update shape is
     uncaptured, so the row is reported and skipped.
   - `refuse` — missing/duplicate data, a card already bound to another employee, a
     capacity overflow, or a dialect/shape refusal. The reason is printed.
4. With `--apply`, writes through the append-only journal and verifies each write by
   reading it back. A rejection or auth failure stops the run; nothing is retried. A
   re-run reads first and skips what already landed, so an interrupted run is safe to
   resume.

Every plan prints the target's model and serial (read from `System/deviceInfo`).
`--apply` requires `--expect-serial SERIAL`: copy the serial from the dry run, and a
different terminal is refused before any write with a non-zero exit. This is the guard
against enrolling cards on the wrong door when both the old and new units are reachable.

Card numbers are masked to the last four characters in plans and logs. The per-row audit
CSV (`--results`, default next to the workbook) is the only output with full card numbers.

`employeeNo` and `cardNo` cells must be **Text** in Excel. A numeric cell is refused with
a "format the column as Text" reason rather than silently rounding a 19-digit card
number or dropping leading zeros. `gateclerk users template` pre-formats both columns as
Text. Date/datetime cells in `validFrom`/`validTo` are converted to the device's
`YYYY-MM-DDTHH:MM:SS` form; text cells must already use that form, and
`validFrom >= validTo` is refused.

## Examples

Dry run (default — no device write):

```bash
gateclerk users import users.xlsx --host <device-host> --user admin
```

Apply (the serial is the one the dry run printed):

```bash
gateclerk users import users.xlsx --host <device-host> --user admin \
  --apply --expect-serial <serial-from-the-dry-run>
```

Choose where the journal and audit file go:

```bash
gateclerk users import users.xlsx --apply --expect-serial <serial> \
  --journal ./private/users.journal.jsonl \
  --results ./private/users.results.csv
```

The first real run on a production terminal is operator-gated: start with a few test rows
and confirm the read-back before importing the full roster.
