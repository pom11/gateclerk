"""USERS-IMPORT-XLSX: Excel enrollment as a gated device WRITE.

The write path is the one already proved on the DS-K1T341AMF-S (fw V3.2.30) and
implemented by :mod:`gateclerk.migrate_write` / :mod:`gateclerk.migrate_write_cards`:
``PUT UserInfo/SetUp`` and ``PUT CardInfo/SetUp`` with the flat ``UserInfo`` /
``CardInfo`` wrapper and ``mode:"add"`` LOWERCASE. This module is a FRONT END to
those seams — it owns no transport, no journal and no verify walker of its own.

Three rules shape the front end:

* **Read before writing.** ``mode:"add"`` against an EXISTING employeeNo is unproven
  (``migrate_write``'s "Adds only" note), so every run walks ``UserInfo/Search`` and
  ``CardInfo/Search`` first and classifies each row as add / add-card / skip-present /
  skip-update-needed / refuse. A present person is never written blind.
* **Dialect first.** The first step reads the device's UserInfo and CardInfo caps and
  refuses to write unless both confirm the captured flat ``SetUp`` wrapper. A newer
  model that needs the Record-style shape is a STOP with evidence, not a fallback.
* **Dry run is the default.** ``--apply`` opens the journal and performs the writes;
  without it this module issues zero write requests and prints the exact plan with
  card numbers masked to their last four characters.

The Excel dependency is optional: the package imports without ``openpyxl`` and the
commands fail with a clean ``gateclerk[excel]`` install hint when the extra is absent.
"""

from __future__ import annotations

import csv
import os
import re
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, replace
from datetime import UTC, date, datetime
from enum import StrEnum
from pathlib import Path
from time import sleep as _sleep
from typing import Any

from gateclerk.capabilities import device_identity
from gateclerk.exceptions import GateClerkError
from gateclerk.migrate_apply import CardWriteTransport, UserWriteTransport, reader_for
from gateclerk.migrate_diff import DEFAULT_CARRIED_TEMPLATE_NO
from gateclerk.migrate_export import collect_enrollment_state
from gateclerk.migrate_probe import CapabilityMatrix
from gateclerk.migrate_write import (
    BudgetedWriteTransport,
    PersonVerdict,
    UsersPhaseResult,
    UsersVerifyReport,
    UserWrite,
    WriteAbortedError,
    WriteJournal,
    WriteRejectedError,
    build_user_setup_body,
    person_hash,
    run_users_phase,
    verify_users,
)
from gateclerk.migrate_write_cards import (
    CardsPhaseResult,
    CardVerdict,
    CardVerifyReport,
    CardWrite,
    build_card_setup_body,
    run_cards_phase,
    verify_cards,
)

__all__ = [
    "ALL_COLUMNS",
    "DEFAULT_CARD_TYPE",
    "DEFAULT_COLUMNS",
    "DEFAULT_VALID_FROM",
    "DEFAULT_VALID_TO",
    "DEVICE_TIME_FORMAT",
    "DEVICE_TIME_HUMAN",
    "JOURNAL_PHASE",
    "OPTIONAL_COLUMNS",
    "TEMPLATE_TEXT_ROWS",
    "DeviceMismatchError",
    "DeviceSerialRequiredError",
    "DialectVerdict",
    "ExcelExtraMissingError",
    "ImportAction",
    "ImportFileError",
    "ImportPlan",
    "ImportPlanRow",
    "ImportReport",
    "ImportRow",
    "UsersImportError",
    "assess_dialect",
    "build_card_record",
    "build_user_record",
    "card_capacity_from_caps",
    "default_journal_path",
    "default_results_path",
    "dialect_verdict",
    "mask_card_no",
    "plan_import",
    "read_device_caps",
    "read_import_rows",
    "render_plan_rows",
    "run_import",
    "write_results_csv",
    "write_template",
]

DEFAULT_COLUMNS: tuple[str, ...] = ("employeeNo", "name", "cardNo")
OPTIONAL_COLUMNS: tuple[str, ...] = ("cardType", "validFrom", "validTo")
ALL_COLUMNS: tuple[str, ...] = DEFAULT_COLUMNS + OPTIONAL_COLUMNS

DEFAULT_CARD_TYPE = "normalCard"
DEFAULT_VALID_FROM = "2000-01-01T00:00:00"
DEFAULT_VALID_TO = "2037-12-31T23:59:59"

#: The device's own wall-time spelling (`Valid.beginTime`/`endTime`).
DEVICE_TIME_FORMAT = "%Y-%m-%dT%H:%M:%S"
DEVICE_TIME_HUMAN = "YYYY-MM-DDTHH:MM:SS"
_DEVICE_TIME_RE = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\Z")

#: How far down the template pre-formats employeeNo/cardNo as Text. Excel's default
#: for a general cell is Number, and a 19-digit card silently rounds past 2^53.
TEMPLATE_TEXT_ROWS = 1000

JOURNAL_PHASE = "users-import"

#: The captured user vocabulary (users_setup_add_request.json). Only these values
#: reach the writer; words the device already proved are not re-invented here.
DEFAULT_USER_TYPE = "normal"
DEFAULT_DOOR_RIGHT = "1"
DEFAULT_GENDER = "unknown"


class UsersImportError(GateClerkError):
    """Base class for a refused import (file, gate or write trouble)."""


class ExcelExtraMissingError(UsersImportError):
    """``openpyxl`` is not installed — the optional extra is the fix."""


class ImportFileError(UsersImportError):
    """The workbook cannot be read as the mapped header/row shape."""


class DialectRefusedError(UsersImportError):
    """The device caps did not confirm the captured flat SetUp wrapper."""


class DeviceSerialRequiredError(UsersImportError):
    """``--apply`` was requested without the serial guard that names the target."""


class DeviceMismatchError(UsersImportError):
    """The target device is not the serial the operator expected; nothing written."""


def _require_openpyxl() -> Any:
    """Import openpyxl lazily; the package itself must work without it."""
    try:
        import openpyxl
    except ImportError as exc:  # pragma: no cover - exercised by the missing-extra test
        raise ExcelExtraMissingError(
            "reading or writing .xlsx needs the optional Excel extra: install it with "
            "`pip install 'gateclerk[excel]'` (or `uv sync --extra excel`) and re-run"
        ) from exc
    return openpyxl


def mask_card_no(card_no: str) -> str:
    """Card numbers are a credential: show at most the last four characters."""
    text = str(card_no)
    if len(text) <= 4:
        return "*" * len(text)
    return "*" * (len(text) - 4) + text[-4:]


def _cell_text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, float) and value.is_integer():
        return str(int(value))
    return str(value).strip()


def _text_identity_cell(value: Any, field: str) -> tuple[str, str | None]:
    """employeeNo/cardNo must be TEXT; a numeric cell has already lost digits.

    Excel stores a general cell as a float, so 1234567890123456789 becomes
    1234567890123457024 (and leading zeros vanish) before this code sees it. There is
    no safe way to recover the operator's intent, so the row is refused, never guessed.
    """
    if value is None:
        return "", None
    if isinstance(value, str):
        return value.strip(), None
    return (
        "",
        f"{field} cell is not text (Excel type {type(value).__name__}); format the "
        f"{field} column as Text before importing so digits and leading zeros survive",
    )


def _device_time_cell(value: Any, field: str) -> tuple[str | None, str | None]:
    """An Excel date/datetime cell -> the device's ``YYYY-MM-DDTHH:MM:SS`` form.

    Text is accepted only in exactly that form and must be a real calendar instant.
    Anything else is a row problem: a silently mangled validity window can disable a
    card without an error at write time.
    """
    if value is None:
        return None, None
    if isinstance(value, datetime):
        return value.strftime(DEVICE_TIME_FORMAT), None
    if isinstance(value, date):
        return f"{value.strftime('%Y-%m-%d')}T00:00:00", None
    if isinstance(value, str):
        text = value.strip()
        if not text:
            return None, None
        if not _DEVICE_TIME_RE.fullmatch(text):
            return (
                None,
                f"{field} {text!r} is not {DEVICE_TIME_HUMAN}; format the cell as Text "
                "using that form",
            )
        try:
            datetime.strptime(text, DEVICE_TIME_FORMAT).replace(tzinfo=UTC)
        except ValueError:
            return (
                None,
                f"{field} {text!r} is not a real date/time; format the cell as Text "
                f"using {DEVICE_TIME_HUMAN}",
            )
        return text, None
    return (
        None,
        f"{field} cell is neither text nor an Excel date; format the column as Text "
        f"using {DEVICE_TIME_HUMAN}",
    )


@dataclass(frozen=True, slots=True)
class ImportRow:
    """One sheet row, already mapped to canonical columns."""

    line: int
    employee_no: str
    name: str
    card_no: str
    card_type: str = DEFAULT_CARD_TYPE
    valid_from: str | None = None
    valid_to: str | None = None
    problem: str | None = None


def _column_map(header: Sequence[Any], mapping: Mapping[str, str] | None) -> dict[str, str]:
    """Map this sheet's header cells onto canonical fields.

    Default header names are accepted as-is (case-insensitive). ``mapping`` renames a
    source header to a canonical field (``--map "Employee No=employeeNo"``); the
    canonical side is validated so a typo cannot silently drop a column.
    """
    source_to_field: dict[str, str] = {}
    for source, target in (mapping or {}).items():
        field_name = str(target).strip()
        if field_name not in ALL_COLUMNS:
            raise ImportFileError(
                f"--map target {field_name!r} is not one of {list(ALL_COLUMNS)}; "
                "refusing a mapping the writer cannot use"
            )
        source_to_field[str(source).strip()] = field_name

    columns: dict[str, str] = {}
    seen_fields: set[str] = set()
    for cell in header:
        text = _cell_text(cell)
        if not text:
            continue
        field_name = source_to_field.get(text)
        if field_name is None:
            for canonical in ALL_COLUMNS:
                if text.lower() == canonical.lower():
                    field_name = canonical
                    break
        if field_name is None:
            continue
        if field_name in seen_fields:
            raise ImportFileError(
                f"two columns map to {field_name!r}; each canonical field may appear once"
            )
        columns[text] = field_name
        seen_fields.add(field_name)

    missing = [name for name in DEFAULT_COLUMNS if name not in seen_fields]
    if missing:
        raise ImportFileError(
            f"the sheet is missing required column(s) {missing}; accepted headers are "
            f"{list(ALL_COLUMNS)} (or use --map SOURCE=HEADER for your names)"
        )
    return columns


def read_import_rows(
    path: str | os.PathLike[str],
    *,
    sheet: str | None = None,
    mapping: Mapping[str, str] | None = None,
) -> tuple[ImportRow, ...]:
    """Read sheet 1 (or ``--sheet``) by header name, collecting per-row problems."""
    openpyxl = _require_openpyxl()
    workbook = openpyxl.load_workbook(filename=Path(path), read_only=True, data_only=True)
    try:
        if sheet is None:
            worksheet = workbook.worksheets[0]
        else:
            try:
                worksheet = workbook[sheet]
            except KeyError as exc:
                raise ImportFileError(
                    f"sheet {sheet!r} does not exist; this workbook has {workbook.sheetnames}"
                ) from exc
        rows = worksheet.iter_rows(values_only=True)
        try:
            header = next(rows)
        except StopIteration as exc:
            raise ImportFileError("the workbook is empty; no header row") from exc
        columns = _column_map(header, mapping)
        index_of: dict[str, int] = {}
        for index, cell in enumerate(header):
            text = _cell_text(cell)
            field_name = columns.get(text)
            if field_name is not None and field_name not in index_of:
                index_of[field_name] = index
        parsed: list[ImportRow] = []
        for line, values in enumerate(rows, start=2):
            if not any(_cell_text(value) for value in values):
                continue
            raw = {
                name: values[index] if index < len(values) else None
                for name, index in index_of.items()
            }
            employee_no, employee_problem = _text_identity_cell(raw.get("employeeNo"), "employeeNo")
            card_no, card_problem = _text_identity_cell(raw.get("cardNo"), "cardNo")
            name = _cell_text(raw.get("name"))
            valid_from, from_problem = _device_time_cell(raw.get("validFrom"), "validFrom")
            valid_to, to_problem = _device_time_cell(raw.get("validTo"), "validTo")
            problems = [
                problem
                for problem in (
                    employee_problem,
                    card_problem,
                    from_problem,
                    to_problem,
                )
                if problem
            ]
            missing = [
                label
                for label, value, problem in (
                    ("employeeNo", employee_no, employee_problem),
                    ("name", name, None),
                    ("cardNo", card_no, card_problem),
                )
                if not value and problem is None
            ]
            if missing:
                problems.append("missing " + ", ".join(missing))
            if from_problem is None and to_problem is None:
                effective_from = valid_from or DEFAULT_VALID_FROM
                effective_to = valid_to or DEFAULT_VALID_TO
                if effective_from >= effective_to:
                    problems.append("validFrom must be before validTo")
            parsed.append(
                ImportRow(
                    line=line,
                    employee_no=employee_no,
                    name=name,
                    card_no=card_no,
                    card_type=_cell_text(raw.get("cardType")) or DEFAULT_CARD_TYPE,
                    valid_from=valid_from,
                    valid_to=valid_to,
                    problem="; ".join(problems) if problems else None,
                )
            )
    finally:
        workbook.close()

    counts: dict[str, int] = {}
    for row in parsed:
        if row.employee_no:
            counts[row.employee_no] = counts.get(row.employee_no, 0) + 1
    duplicates = {no for no, count in counts.items() if count > 1}
    card_counts: dict[str, int] = {}
    for row in parsed:
        if row.card_no:
            card_counts[row.card_no] = card_counts.get(row.card_no, 0) + 1
    duplicate_cards = {no for no, count in card_counts.items() if count > 1}

    result: list[ImportRow] = []
    for row in parsed:
        problems = [row.problem] if row.problem else []
        if row.employee_no in duplicates:
            problems.append("duplicate employeeNo in file")
        if row.card_no in duplicate_cards:
            problems.append("duplicate cardNo in file")
        result.append(replace(row, problem="; ".join(problems) if problems else None))
    return tuple(result)


def write_template(path: str | os.PathLike[str]) -> Path:
    """Write a blank workbook whose first row is the accepted default header."""
    openpyxl = _require_openpyxl()
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    workbook = openpyxl.Workbook()
    worksheet = workbook.active
    worksheet.title = "users"
    worksheet.append(list(ALL_COLUMNS))
    # Text-format the join key and credential columns far enough down that an
    # operator pasting a roster cannot silently float a 19-digit card number.
    for row in range(1, TEMPLATE_TEXT_ROWS + 1):
        worksheet.cell(row=row, column=1).number_format = "@"
        worksheet.cell(row=row, column=3).number_format = "@"
    workbook.save(target)
    return target


def build_user_record(row: ImportRow) -> dict[str, Any]:
    """The captured user write shape, seeded from one Excel row."""
    return {
        "employeeNo": row.employee_no,
        "name": row.name,
        "userType": DEFAULT_USER_TYPE,
        "Valid": {
            "enable": True,
            "beginTime": row.valid_from or DEFAULT_VALID_FROM,
            "endTime": row.valid_to or DEFAULT_VALID_TO,
            "timeType": "local",
        },
        "doorRight": DEFAULT_DOOR_RIGHT,
        "RightPlan": [{"doorNo": 1, "planTemplateNo": DEFAULT_CARRIED_TEMPLATE_NO}],
        "localUIRight": False,
        "gender": DEFAULT_GENDER,
        # Device-added read defaults (users_setup_readback_t90.json). They are not in
        # the write body (the builder drops extras) but the §6 read-back compare is
        # field-set exact, so the intent record must carry them too.
        "closeDelayEnabled": False,
        "belongGroup": "",
        "maxOpenDoorTime": 0,
        "openDoorTime": 0,
        "roomNumber": 0,
        "floorNumber": 0,
        "PersonInfoExtends": [{"value": ""}],
    }


def build_card_record(row: ImportRow) -> dict[str, Any]:
    """The captured card identity projection, seeded from one Excel row."""
    return {
        "employeeNo": row.employee_no,
        "cardNo": row.card_no,
        "cardType": row.card_type or DEFAULT_CARD_TYPE,
    }


@dataclass(frozen=True, slots=True)
class DialectVerdict:
    """What the device's own caps said about the captured write dialect."""

    ok: bool
    user_caps: bool
    card_caps: bool
    user_setup: bool
    card_setup: bool
    note: str

    def summary(self) -> dict[str, Any]:
        return {
            "confirmed": self.ok,
            "userCaps": self.user_caps,
            "cardCaps": self.card_caps,
            "userSetUp": self.user_setup,
            "cardSetUp": self.card_setup,
            "note": self.note,
        }


def _caps_section(
    caps: Mapping[str, Any] | None, section_name: str, *keys: str
) -> Mapping[str, Any] | None:
    """The real device documents wrap the body as ``{"UserInfo": {...}}`` /
    ``{"CardInfo": {...}}`` (captured docs, not the invented ``*Cap`` spelling)."""
    if not isinstance(caps, Mapping):
        return None
    bodies: list[Mapping[str, Any]] = []
    for key in keys:
        body = caps.get(key)
        if isinstance(body, Mapping):
            bodies.append(body)
    if any(name in caps for name in ("UserInfo", "CardInfo")):
        bodies.append(caps)
    for body in bodies:
        section = body.get(section_name)
        if isinstance(section, Mapping):
            return section
    return None


def dialect_verdict(caps_raw: Mapping[str, Any] | None) -> DialectVerdict:
    """Confirm the captured flat ``SetUp`` wrapper from the device's caps claims."""
    user_section = _caps_section(caps_raw, "UserInfo", "user_info_capabilities", "caps_user_info")
    card_section = _caps_section(caps_raw, "CardInfo", "card_info_capabilities", "caps_card_info")

    def _set_up(section: Mapping[str, Any] | None) -> bool:
        if section is None:
            return False
        support = section.get("supportFunction")
        if not isinstance(support, Mapping):
            return False
        words = support.get("@opt")
        if not isinstance(words, str):
            return False
        return "setup" in {word.strip().lower() for word in words.split(",")}

    user_setup = _set_up(user_section)
    card_setup = _set_up(card_section)
    ok = user_section is not None and card_section is not None and user_setup and card_setup
    if ok:
        note = (
            "device caps confirm UserInfo/SetUp and CardInfo/SetUp (flat wrapper, "
            'mode:"add"). If this newer model requires the Record-style shape, that is '
            "a STOP with evidence: our capture says Record answered 400/405 on the "
            "proved model, so it is never used as a fallback guess."
        )
    else:
        note = (
            "REFUSING TO WRITE: this device's capabilities did not confirm both "
            "UserInfo/SetUp and CardInfo/SetUp (flat wrapper). A newer model may need "
            "the Record-style shape; if a device genuinely requires Record, that is a "
            "STOP with evidence — our capture answered 400/405 for Record on the "
            "proved model, so no fallback guess is made."
        )
    return DialectVerdict(
        ok=ok,
        user_caps=user_section is not None,
        card_caps=card_section is not None,
        user_setup=user_setup,
        card_setup=card_setup,
        note=note,
    )


def read_device_caps(client: Any) -> tuple[Mapping[str, Any], str | None]:
    """Read the two caps documents the dialect gate needs (registered reads only)."""
    caps: dict[str, Any] = {}
    notes: list[str] = []
    for key, endpoint in (
        ("user_info_capabilities", "user_info_capabilities"),
        ("card_info_capabilities", "card_info_capabilities"),
    ):
        try:
            body = client.get(endpoint)
        except GateClerkError as exc:
            notes.append(f"{key}: {exc}")
            continue
        caps[key] = dict(body)
    return caps, "; ".join(notes) or None


def assess_dialect(caps_raw: Mapping[str, Any] | None, note: str | None = None) -> DialectVerdict:
    verdict = dialect_verdict(caps_raw)
    if note:
        return replace(verdict, note=f"{verdict.note} (caps read note: {note})")
    return verdict


def card_capacity_from_caps(probe: CapabilityMatrix | None) -> int | None:
    """Per-person card capacity where the caps advertise it; None when they do not.

    No committed real capture names a per-person card maximum (``CardInfo``'s
    ``maxRecordNum`` is the search page cap, not capacity), so silence stays None and
    the plan says so. A device that DOES advertise ``numOfCard``/``maxCardNum`` is
    enforced before any write.
    """
    caps = getattr(probe, "caps_raw", None)
    user_section = _caps_section(caps, "UserInfo", "user_info_capabilities", "caps_user_info")
    card_section = _caps_section(caps, "CardInfo", "card_info_capabilities", "caps_card_info")
    for section, name in (
        (user_section, "numOfCard"),
        (user_section, "maxCardNum"),
        (card_section, "numOfCard"),
        (card_section, "maxCardNum"),
    ):
        if section is None:
            continue
        node = section.get(name)
        value = node.get("@max") if isinstance(node, Mapping) else node
        if isinstance(value, int) and not isinstance(value, bool) and value >= 0:
            return value
    return None


class ImportAction(StrEnum):
    ADD_USER = "add-user"
    ADD_CARD = "add-card"
    SKIP_PRESENT = "skip-present"
    SKIP_UPDATE_NEEDED = "skip-update-needed"
    REFUSE = "refuse"


@dataclass(frozen=True, slots=True)
class ImportPlanRow:
    """One row's verdict plus the write objects that verdict would send."""

    row: ImportRow
    action: ImportAction
    reason: str | None = None
    user_write: UserWrite | None = None
    card_write: CardWrite | None = None

    def summary(self) -> dict[str, Any]:
        return {
            "line": self.row.line,
            "employeeNo": self.row.employee_no,
            "cardNo": mask_card_no(self.row.card_no),
            "action": str(self.action),
            "reason": self.reason,
        }


@dataclass(frozen=True, slots=True)
class ImportPlan:
    rows: tuple[ImportPlanRow, ...]
    dialect: DialectVerdict
    card_capacity: int | None = None
    users_skipped: tuple[tuple[str, str], ...] = ()
    notes: tuple[str, ...] = ()
    device_model: str | None = None
    device_serial: str | None = None

    @property
    def users(self) -> tuple[UserWrite, ...]:
        return tuple(r.user_write for r in self.rows if r.user_write is not None)

    @property
    def cards(self) -> tuple[CardWrite, ...]:
        return tuple(r.card_write for r in self.rows if r.card_write is not None)

    @property
    def refused(self) -> tuple[ImportPlanRow, ...]:
        return tuple(r for r in self.rows if r.action is ImportAction.REFUSE)

    def counts(self) -> dict[str, int]:
        counts = {action.value: 0 for action in ImportAction}
        for row in self.rows:
            counts[str(row.action)] += 1
        return counts

    def summary(self) -> dict[str, Any]:
        return {
            "rows": len(self.rows),
            "counts": self.counts(),
            "dialect": self.dialect.summary(),
            "cardCapacity": self.card_capacity,
            "device": {"model": self.device_model, "serial": self.device_serial},
            "notes": list(self.notes),
        }


def _existing_card_count(target_cards: Sequence[Mapping[str, Any]], employee_no: str) -> int:
    return sum(
        1
        for row in target_cards
        if str(row.get("employeeNo") or "") == employee_no and row.get("cardNo") is not None
    )


def _card_owner(target_cards: Sequence[Mapping[str, Any]]) -> dict[str, str]:
    owners: dict[str, str] = {}
    for row in target_cards:
        if row.get("cardNo") is not None:
            owners[str(row["cardNo"])] = str(row.get("employeeNo") or "")
    return owners


def _update_reason(row: ImportRow, live: Mapping[str, Any]) -> str | None:
    if live.get("name") is not None and str(live.get("name")) != row.name:
        return "name differs from the device (update shape is uncaptured)"
    valid = live.get("Valid")
    if isinstance(valid, Mapping):
        if row.valid_from and str(valid.get("beginTime") or "") != row.valid_from:
            return "validFrom differs from the device (update shape is uncaptured)"
        if row.valid_to and str(valid.get("endTime") or "") != row.valid_to:
            return "validTo differs from the device (update shape is uncaptured)"
    return None


def plan_import(
    rows: Sequence[ImportRow],
    *,
    target_users: Sequence[Mapping[str, Any]],
    target_cards: Sequence[Mapping[str, Any]],
    probe: CapabilityMatrix | None = None,
    dialect: DialectVerdict | None = None,
    capacity: int | None = None,
    device_model: str | None = None,
    device_serial: str | None = None,
) -> ImportPlan:
    """Classify every row against the device's CURRENT users and cards.

    The classification is intentionally read-before-write: an employeeNo already on
    the device is never sent through ``mode:"add"`` (its merge/overwrite semantics are
    unproven); a card already bound to someone else is refused, never reassigned.
    """
    verdict = dialect or dialect_verdict(getattr(probe, "caps_raw", None))
    cap = capacity if capacity is not None else card_capacity_from_caps(probe)
    users_by_no = {
        str(record["employeeNo"]): record
        for record in target_users
        if record.get("employeeNo") is not None
    }
    owners = _card_owner(target_cards)
    planned: list[ImportPlanRow] = []
    skipped_users: list[tuple[str, str]] = []

    for row in rows:
        if row.problem:
            planned.append(ImportPlanRow(row, ImportAction.REFUSE, row.problem))
            continue
        if not verdict.ok:
            planned.append(ImportPlanRow(row, ImportAction.REFUSE, "dialect-not-confirmed"))
            continue

        card_record = build_card_record(row)
        try:
            build_card_setup_body(card_record, probe=probe)
        except GateClerkError as exc:
            planned.append(ImportPlanRow(row, ImportAction.REFUSE, f"card-shape-refused:{exc}"))
            continue

        live = users_by_no.get(row.employee_no)
        owner = owners.get(row.card_no)
        if owner is not None and owner != row.employee_no:
            planned.append(
                ImportPlanRow(
                    row,
                    ImportAction.REFUSE,
                    "cardNo is already bound to a different employeeNo on the device",
                )
            )
            continue

        if live is None:
            count = _existing_card_count(target_cards, row.employee_no)
            if cap is not None and count + 1 > cap:
                planned.append(
                    ImportPlanRow(
                        row,
                        ImportAction.REFUSE,
                        f"card capacity exceeded (present={count}, max={cap})",
                    )
                )
                continue
            user_record = build_user_record(row)
            try:
                build_user_setup_body(user_record, probe=probe)
            except GateClerkError as exc:
                planned.append(ImportPlanRow(row, ImportAction.REFUSE, f"user-shape-refused:{exc}"))
                continue
            planned.append(
                ImportPlanRow(
                    row,
                    ImportAction.ADD_USER,
                    None,
                    UserWrite(
                        employee_no=row.employee_no,
                        employee_hash=person_hash(row.employee_no),
                        record=user_record,
                    ),
                    CardWrite(
                        employee_no=row.employee_no,
                        employee_hash=person_hash(row.employee_no),
                        card_no=row.card_no,
                        card_type=card_record["cardType"],
                        record=card_record,
                    ),
                )
            )
            continue

        reason = _update_reason(row, live)
        if reason is not None:
            skipped_users.append((person_hash(row.employee_no), reason))
            planned.append(ImportPlanRow(row, ImportAction.SKIP_UPDATE_NEEDED, reason))
            continue

        if owner == row.employee_no:
            planned.append(ImportPlanRow(row, ImportAction.SKIP_PRESENT, "user and card present"))
            continue

        count = _existing_card_count(target_cards, row.employee_no)
        if cap is not None and count + 1 > cap:
            planned.append(
                ImportPlanRow(
                    row,
                    ImportAction.REFUSE,
                    f"card capacity exceeded (present={count}, max={cap})",
                )
            )
            continue
        planned.append(
            ImportPlanRow(
                row,
                ImportAction.ADD_CARD,
                None,
                None,
                CardWrite(
                    employee_no=row.employee_no,
                    employee_hash=person_hash(row.employee_no),
                    card_no=row.card_no,
                    card_type=card_record["cardType"],
                    record=card_record,
                ),
            )
        )

    notes = [
        "card numbers are masked in the plan; the audit CSV holds the full values",
    ]
    if cap is None:
        notes.append(
            "the device did not advertise a per-person card capacity; no capacity "
            "refusal was possible from caps"
        )
    return ImportPlan(
        rows=tuple(planned),
        dialect=verdict,
        card_capacity=cap,
        users_skipped=tuple(skipped_users),
        notes=tuple(notes),
        device_model=device_model,
        device_serial=device_serial,
    )


def default_journal_path(xlsx: str | os.PathLike[str]) -> Path:
    path = Path(xlsx)
    return path.with_name(path.name + ".journal.jsonl")


def default_results_path(xlsx: str | os.PathLike[str]) -> Path:
    path = Path(xlsx)
    return path.with_name(path.stem + ".results.csv")


def render_plan_rows(plan: ImportPlan) -> list[dict[str, Any]]:
    """The dry-run/JSON table: employeeNo may print, cardNo is masked."""
    return [row.summary() for row in plan.rows]


def write_results_csv(path: str | os.PathLike[str], plan: ImportPlan) -> Path:
    """Write the operator's audit file — the ONLY place a full card number appears."""
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    with target.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=(
                "line",
                "employeeNo",
                "name",
                "cardNo",
                "cardType",
                "action",
                "reason",
            ),
        )
        writer.writeheader()
        for item in plan.rows:
            writer.writerow(
                {
                    "line": item.row.line,
                    "employeeNo": item.row.employee_no,
                    "name": item.row.name,
                    "cardNo": item.row.card_no,
                    "cardType": item.row.card_type,
                    "action": str(item.action),
                    "reason": item.reason or "",
                }
            )
    target.chmod(0o600)
    return target


@dataclass(frozen=True, slots=True)
class ImportReport:
    """One run's outcome: dry-run plan, or the applied phases plus their verify."""

    confirm: bool
    plan: ImportPlan
    users_result: UsersPhaseResult | None = None
    cards_result: CardsPhaseResult | None = None
    users_verify: UsersVerifyReport | None = None
    cards_verify: CardVerifyReport | None = None
    journal_path: str | None = None
    result_path: str | None = None
    aborted: bool = False
    abort_reason: str | None = None

    @property
    def clean(self) -> bool:
        return not self.aborted and not self.plan.refused

    def exit_code(self) -> int:
        return 0 if self.clean else 1

    def summary(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "schema": "gateclerk-users-import/1",
            "confirm": self.confirm,
            "plan": self.plan.summary(),
            "rows": render_plan_rows(self.plan),
            "journal": self.journal_path,
            "results": self.result_path,
            "aborted": self.aborted,
            "abortReason": self.abort_reason,
        }
        if self.users_result is not None:
            payload["users"] = self.users_result.summary()
        if self.cards_result is not None:
            payload["cards"] = self.cards_result.summary()
        if self.users_verify is not None:
            payload["usersVerify"] = self.users_verify.summary()
        if self.cards_verify is not None:
            payload["cardsVerify"] = self.cards_verify.summary()
        return payload


def _card_entry(journal: WriteJournal, card_no: str, employee_no: str) -> Any:
    for entry in reversed(journal.entries):
        if (
            entry.op == "card_setup"
            and entry.card_no == card_no
            and entry.employee_no == employee_no
        ):
            return entry
    return None


def _confirm_users(
    journal: WriteJournal,
    result: UsersPhaseResult,
    writes: Sequence[UserWrite],
    verify: UsersVerifyReport,
) -> UsersPhaseResult:
    confirmed: list[str] = []
    wanted = {write.employee_no: write for write in writes}
    for item in verify.items:
        write = wanted.get(item.employee_no)
        if write is None:
            continue
        entry = journal.by_employee(item.employee_no)
        if entry is None or entry.op != "user_setup":
            continue
        if item.verdict is PersonVerdict.OK and item.target_hash == entry.intended_hash:
            journal.confirmed(entry, post_write_hash=str(item.target_hash))
            confirmed.append(item.employee_hash)
    return replace(result, confirmed=tuple(confirmed))


def _confirm_cards(
    journal: WriteJournal,
    result: CardsPhaseResult,
    verify: CardVerifyReport,
) -> CardsPhaseResult:
    confirmed: list[str] = []
    for item in verify.items:
        entry = _card_entry(journal, item.card_no, item.employee_no)
        if entry is None:
            continue
        if item.verdict is CardVerdict.OK and item.target_hash == entry.intended_hash:
            journal.confirmed(entry, post_write_hash=str(item.target_hash))
            confirmed.append(item.card_hash)
    return replace(result, confirmed=tuple(confirmed))


def _auth_failure(exc: BaseException) -> bool:
    if isinstance(exc, WriteRejectedError):
        return exc.http_status == 401
    cause = exc.__cause__
    return isinstance(cause, WriteRejectedError) and cause.http_status == 401


def run_import(
    xlsx: str | os.PathLike[str],
    *,
    client: Any,
    client_factory: Callable[[], Any],
    sheet: str | None = None,
    mapping: Mapping[str, str] | None = None,
    apply: bool = False,
    expect_serial: str | None = None,
    journal_path: str | os.PathLike[str] | None = None,
    results_path: str | os.PathLike[str] | None = None,
    sleep: Callable[[float], None] = _sleep,
) -> ImportReport:
    """Read the workbook and the target, plan, and (only with ``apply``) write."""
    if apply and not (expect_serial and expect_serial.strip()):
        raise DeviceSerialRequiredError(
            "--apply requires --expect-serial SERIAL: run the dry run first and copy "
            "the target serial it prints, so an import cannot land on the wrong terminal"
        )
    rows = read_import_rows(xlsx, sheet=sheet, mapping=mapping)
    try:
        identity_body = client.get("device_info")
    except GateClerkError as exc:
        raise UsersImportError(f"cannot read deviceInfo to guard the target: {exc}") from exc
    serial, _firmware, model = device_identity(identity_body)
    serial = serial.strip() if serial else None
    expected = expect_serial.strip() if expect_serial else None
    if apply:
        if serial is None:
            raise DeviceMismatchError(
                "deviceInfo carried no serialNumber, so the --expect-serial guard cannot "
                "confirm this is the intended terminal; nothing was written"
            )
        if serial != expected:
            raise DeviceMismatchError(
                f"refusing to write: target serial {serial!r} does not match "
                f"--expect-serial {expected!r}; nothing was written"
            )
    caps_raw, caps_note = read_device_caps(client)
    verdict = assess_dialect(caps_raw, caps_note)
    probe = CapabilityMatrix(
        caps_raw=caps_raw,
        site="",
        host="",
        probed_at=datetime.now(UTC).isoformat(),
    )
    state = collect_enrollment_state(client, inter_page_delay=0.0, sleep=sleep)
    plan = plan_import(
        rows,
        target_users=state.users,
        target_cards=state.cards,
        probe=probe,
        dialect=verdict,
        device_model=model,
        device_serial=serial,
    )
    if not apply:
        return ImportReport(confirm=False, plan=plan)

    if not verdict.ok:
        raise DialectRefusedError(verdict.note)

    journal_file = Path(journal_path) if journal_path else default_journal_path(xlsx)
    journal = WriteJournal.open(journal_file, phase=JOURNAL_PHASE)
    results_file = Path(results_path) if results_path else default_results_path(xlsx)
    users_result: UsersPhaseResult | None = None
    cards_result: CardsPhaseResult | None = None
    users_verify: UsersVerifyReport | None = None
    cards_verify: CardVerifyReport | None = None
    aborted = False
    abort_reason: str | None = None

    users_reader = reader_for(client, "user_info_search")
    cards_reader = reader_for(client, "card_info_search")

    if plan.users:
        budgeted = BudgetedWriteTransport(lambda: UserWriteTransport(client_factory()))
        try:
            users_result = run_users_phase(
                budgeted,
                journal,
                plan.users,
                probe=probe,
                sleep=sleep,
            )
        except WriteAbortedError as exc:
            users_result = exc.result
            aborted = True
            abort_reason = (
                "auth failure on the first refused write (401): the run stopped and "
                "nothing was retried — fix credentials, then re-run to resume"
                if _auth_failure(exc)
                else str(exc)
            )
        except GateClerkError as exc:
            aborted = True
            abort_reason = f"users phase stopped: {exc}"
        finally:
            budgeted.close()
        if users_result is not None:
            try:
                users_verify = verify_users(users_reader, plan.users, sleep=sleep)
            except GateClerkError as exc:
                aborted = True
                abort_reason = abort_reason or f"users verify failed: {exc}"
            if users_verify is not None:
                users_result = _confirm_users(journal, users_result, plan.users, users_verify)

    if not aborted and plan.cards:
        budgeted_cards = BudgetedWriteTransport(lambda: CardWriteTransport(client_factory()))
        try:
            cards_result = run_cards_phase(
                budgeted_cards,
                journal,
                plan.cards,
                target_cards=state.cards,
                probe=probe,
                sleep=sleep,
            )
        except WriteAbortedError as exc:
            cards_result = exc.result
            aborted = True
            abort_reason = (
                "auth failure on the first refused card write (401): the run stopped "
                "and nothing was retried — fix credentials, then re-run to resume"
                if _auth_failure(exc)
                else str(exc)
            )
        except GateClerkError as exc:
            aborted = True
            abort_reason = f"cards phase stopped: {exc}"
        finally:
            budgeted_cards.close()
        if cards_result is not None:
            try:
                cards_verify = verify_cards(cards_reader, plan.cards, sleep=sleep)
            except GateClerkError as exc:
                aborted = True
                abort_reason = abort_reason or f"cards verify failed: {exc}"
            if cards_verify is not None:
                cards_result = _confirm_cards(journal, cards_result, cards_verify)

    result_file = write_results_csv(results_file, plan)
    return ImportReport(
        confirm=True,
        plan=plan,
        users_result=users_result,
        cards_result=cards_result,
        users_verify=users_verify,
        cards_verify=cards_verify,
        journal_path=str(journal.path),
        result_path=str(result_file),
        aborted=aborted,
        abort_reason=abort_reason,
    )
