"""GC-P16b — the results CSV must carry masked card numbers, never the full value.

WHY (docs/internal/go-live-finish/GC-P16b.md; R1/R2: BC owns the identity data, the
local artifact is a report and not a second register). `write_results_csv` wrote
`item.row.card_no` straight to `<xlsx>.results.csv`, so every applied import dropped a
plaintext card credential next to the workbook — in a file the operator shares as an
audit artifact. Tables 70605/70606 already own the card assignment, so nothing here
needed the full number.

The number was masked everywhere else already (`ImportPlanRow.summary`, hence the dry
run and `--json`; the terminal write payload belongs to the device). This file is the
disk leak, so it pins the disk artifact:

* the full number is absent from the written file and the masked form is present,
* NO row escapes — the assertion iterates every `cardNo` cell, so a long card, a
  19-digit card and a short card are all covered, not just the sample's one row,
* a card of four characters or fewer is fully masked (no visible tail at all),
* the file's shape and permissions are untouched: operators read `cardNo` from it with
  scripts, and the file stays `0600` for the employee/name columns that remain in it.

Offline by construction: FakeDevice plus tmp workbooks. The harness shapes are imported
from the module that owns them rather than copied (the GC-P16a idiom).
"""

from __future__ import annotations

import csv
from pathlib import Path
from typing import Any

import pytest

from gateclerk.users_import import (
    ImportAction,
    ImportPlan,
    ImportPlanRow,
    ImportRow,
    default_results_path,
    mask_card_no,
    run_import,
    write_results_csv,
)
from test_users_import import (
    SAMPLE,
    TARGET_SERIAL,
    _device,
    _factory,
    _ok_dialect,
    _workbook,
)

#: The sample workbook's card. `mask_card_no` keeps the last FOUR characters, so its
#: mask is `****0090` — the tail is "0090", not the bare "90".
FULL_CARD = "90000090"
MASKED_FULL = "****0090"

#: The header order `write_results_csv` has always written. Operators have scripts that
#: read these columns by name, which is why the mask is the only thing allowed to change.
HEADER = ["line", "employeeNo", "name", "cardNo", "cardType", "action", "reason"]


def _plan(rows: list[tuple[str, str, str]]) -> ImportPlan:
    """A minimal plan over (employeeNo, name, cardNo) triples, for the writer directly.

    Every row is REFUSE on purpose: it keeps the plan off the write path so the writer
    is exercised on the values it is handed, including the empty card a refused row
    carries.
    """
    return ImportPlan(
        rows=tuple(
            ImportPlanRow(
                ImportRow(line=index, employee_no=no, name=name, card_no=card),
                ImportAction.REFUSE,
                "pinned by GC-P16b",
            )
            for index, (no, name, card) in enumerate(rows, start=2)
        ),
        dialect=_ok_dialect(),
    )


def _applied_results(tmp_path: Path, xlsx: Path) -> Path:
    """The real applied import (the shape test_users_import.py:410 uses); returns the file."""
    pytest.importorskip("openpyxl")
    device = _device()
    factory = _factory(device)
    client = factory()
    try:
        report = run_import(
            xlsx,
            client=client,
            client_factory=factory,
            apply=True,
            expect_serial=TARGET_SERIAL,
            journal_path=tmp_path / "private/journal.jsonl",
            results_path=tmp_path / "private/results.csv",
            sleep=lambda _s: None,
        )
    finally:
        client.close()
    assert report.clean and not report.aborted
    assert report.result_path is not None
    return Path(report.result_path)


def _card_column(path: Path) -> list[str]:
    """Every `cardNo` cell of a written file, in file order."""
    with path.open(encoding="utf-8", newline="") as handle:
        return [str(row["cardNo"]) for row in csv.DictReader(handle)]


def _header(path: Path) -> list[Any]:
    with path.open(encoding="utf-8", newline="") as handle:
        return next(csv.reader(handle))


def test_results_csv_carries_only_the_masked_card(tmp_path: Path) -> None:
    """The applied run's audit file must not hold the credential it used to."""
    results = _applied_results(tmp_path, SAMPLE)
    text = results.read_text()
    assert FULL_CARD not in text, "the full card number leaked to the results CSV"
    assert mask_card_no(FULL_CARD) == MASKED_FULL
    assert MASKED_FULL in text
    # The rest of the row survives the mask — this is still a usable audit file.
    assert "90,User T90" in text and "add-user" in text


def test_results_csv_has_no_unmasked_digits_for_any_row(tmp_path: Path) -> None:
    """Every row, not just the sample's: no cell may expose more than the last four."""
    pytest.importorskip("openpyxl")
    workbook = _workbook(
        tmp_path / "roster.xlsx",
        [
            ["90", "User T90", FULL_CARD, "normalCard"],
            ["91", "User T91", "1234567890123456789", "normalCard"],
            ["92", "User T92", "12345", "normalCard"],
            ["93", "User T93", "ABCD", "normalCard"],
            ["94", "User T94", "X", "normalCard"],
        ],
    )
    results = _applied_results(tmp_path, workbook)
    cells = _card_column(results)
    assert cells == ["****0090", "***************6789", "*2345", "****", "*"]
    for cell in cells:
        assert len(cell.lstrip("*")) <= 4, f"{cell!r} exposes more than the last four"
    text = results.read_text()
    for card in (FULL_CARD, "1234567890123456789"):
        assert card not in text, f"{card} leaked to the results CSV"


def test_short_card_is_fully_masked(tmp_path: Path) -> None:
    """A card of four characters or fewer has no tail worth showing: all `*`."""
    pytest.importorskip("openpyxl")
    workbook = _workbook(tmp_path / "short.xlsx", [["95", "User T95", "ABCD", "normalCard"]])
    assert _card_column(_applied_results(tmp_path, workbook)) == ["****"]

    direct = write_results_csv(tmp_path / "direct.csv", _plan([("96", "A", ""), ("97", "B", "A")]))
    assert _card_column(direct) == ["", "*"]
    assert mask_card_no("ABCD") == "****"


def test_results_file_mode_stays_0600(tmp_path: Path) -> None:
    """Masking is not a licence to loosen the file: it still carries names."""
    assert _applied_results(tmp_path, SAMPLE).stat().st_mode & 0o777 == 0o600


def test_header_order_and_default_path_are_unchanged(tmp_path: Path) -> None:
    """Operators' scripts read `cardNo` by name; the default path is documented behaviour."""
    assert _header(_applied_results(tmp_path, SAMPLE)) == HEADER

    workbook = tmp_path / "work" / "users.xlsx"
    assert default_results_path(workbook) == workbook.parent / "users.results.csv"

    direct = write_results_csv(tmp_path / "direct.csv", _plan([("90", "User T90", FULL_CARD)]))
    assert _header(direct) == HEADER


#: The exact sentences that used to promise an unmasked card number, in the order they
#: were written. Each is now false; each was operator-facing, which is how a PII claim
#: survives a green suite — nothing in the code reads it.
_FULL_CARD_PROMISES = (
    "the audit CSV holds the full values",
    "the audit CSV keeps",  # …the full values for the operator (the CLI docstring)
    "the only output with full card numbers",
    "the ONLY place a full card number appears",
)


def test_no_shipped_text_still_promises_an_unmasked_audit_file() -> None:
    """The mask is only real if the text that points at the file says so.

    Scoped to what ships and what an operator reads — `src/` and the public `docs/`.
    `docs/internal/` is deliberately out: the audit report and the card spec both quote
    the old wording as the defect they are describing, and rewriting a finding to make a
    test pass would be the worse lie.
    """
    repo = Path(__file__).resolve().parents[1]
    scanned = sorted((repo / "src" / "gateclerk").glob("*.py")) + sorted(
        path for path in (repo / "docs").glob("*.md")
    )
    assert scanned, "nothing scanned — the guard would pass vacuously"
    offenders = [
        f"{path.relative_to(repo)}: {promise!r}"
        for path in scanned
        for text in [path.read_text(encoding="utf-8")]
        for promise in _FULL_CARD_PROMISES
        if promise in text
    ]
    assert offenders == [], "text promises an unmasked cardNo: " + "; ".join(offenders)
