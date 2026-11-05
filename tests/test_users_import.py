"""USERS-IMPORT-XLSX: Excel enrollment front end, FakeDevice-strict and offline.

The module under test reuses the captured write seams (``migrate_write`` users phase,
``migrate_write_cards`` cards phase); these tests pin the front-end contract the card
adds: read-before-write classification, dry-run masking, journal/read-back apply,
resume safety, the dialect gate and the optional openpyxl extra.
"""

from __future__ import annotations

import json
import sys
from datetime import date, datetime
from pathlib import Path
from typing import Any

import pytest
from typer.testing import CliRunner

import gateclerk.cli as cli_mod
from e2e_harness import DEVICE_INFO_PATH, FAKE_PW
from fakedevice import BASE_URL, FakeDevice
from gateclerk.isapi_transport import IsapiClient
from gateclerk.migrate_probe import CapabilityMatrix
from gateclerk.users_import import (
    TEMPLATE_TEXT_ROWS,
    DeviceMismatchError,
    DeviceSerialRequiredError,
    DialectRefusedError,
    DialectVerdict,
    ExcelExtraMissingError,
    ImportAction,
    ImportFileError,
    ImportRow,
    build_user_record,
    card_capacity_from_caps,
    dialect_verdict,
    plan_import,
    read_import_rows,
    render_plan_rows,
    run_import,
    write_template,
)

RECORDED = Path(__file__).parent / "fixtures/recorded/site-a-ds-k1t341amf-s"
SAMPLE = Path(__file__).parent / "fixtures/users_import_sample.xlsx"
REAL_CAPS = json.loads((Path(__file__).parent / "fixtures/users_import_real_caps.json").read_text())
TARGET_MODEL = "DS-K1T341AMF-S"
TARGET_SERIAL = "MASKED-SER-1"
runner = CliRunner()


def _device(*, users: list[dict] | None = None, cards: list[dict] | None = None, **caps: Any):
    device = FakeDevice(password=FAKE_PW)
    device.xml_ok("GET", DEVICE_INFO_PATH, (RECORDED / "device_info.xml").read_text())
    device.install_enrollment(
        users=users or [],
        cards=cards or [],
        caps_user_info=caps.pop("caps_user_info", REAL_CAPS["user_info_capabilities"]),
        caps_card_info=caps.pop("caps_card_info", REAL_CAPS["card_info_capabilities"]),
        **caps,
    )
    device.install_write_capture(users=users or [], cards=cards or [])
    return device


def _factory(device: FakeDevice, *, password: str = FAKE_PW):
    def build() -> IsapiClient:
        return IsapiClient(
            BASE_URL, "admin", password, transport=device.transport, sleep=lambda _s: None
        )

    return build


def _workbook(path: Path, rows: list[list[Any]], headers: list[str] | None = None) -> Path:
    openpyxl = pytest.importorskip("openpyxl")
    workbook = openpyxl.Workbook()
    worksheet = workbook.active
    worksheet.title = "users"
    worksheet.append(headers or ["employeeNo", "name", "cardNo", "cardType"])
    for row in rows:
        worksheet.append(row)
    workbook.save(path)
    return path


def _ok_dialect() -> DialectVerdict:
    return DialectVerdict(True, True, True, True, True, "caps confirm SetUp")


# --- template and optional extra ---------------------------------------------------------------


def test_missing_extra_message_is_clean(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setitem(sys.modules, "openpyxl", None)
    with pytest.raises(ExcelExtraMissingError, match=r"gateclerk\[excel\]"):
        read_import_rows(tmp_path / "does-not-need-to-exist.xlsx")


def test_template_headers_text_formats_and_reload(tmp_path: Path) -> None:
    openpyxl = pytest.importorskip("openpyxl")
    template = write_template(tmp_path / "template.xlsx")
    assert read_import_rows(template) == ()

    workbook = openpyxl.load_workbook(template)
    worksheet = workbook.active
    assert list(next(worksheet.iter_rows(values_only=True))) == [
        "employeeNo",
        "name",
        "cardNo",
        "cardType",
        "validFrom",
        "validTo",
    ]
    for coordinate in ("A2", "C2", f"A{TEMPLATE_TEXT_ROWS}", f"C{TEMPLATE_TEXT_ROWS}"):
        assert worksheet[coordinate].number_format == "@"

    worksheet["A2"] = "000123"
    worksheet["B2"] = "User E123"
    worksheet["C2"] = "00123456789012345678"
    workbook.save(template)
    workbook.close()

    rows = read_import_rows(template)
    assert len(rows) == 1
    assert rows[0].employee_no == "000123"
    assert rows[0].card_no == "00123456789012345678"
    assert rows[0].problem is None


def test_cli_help_and_template_command(tmp_path: Path) -> None:
    pytest.importorskip("openpyxl")
    help_result = runner.invoke(cli_mod.app, ["users", "import", "--help"])
    assert help_result.exit_code == 0
    assert "--apply" in help_result.stdout
    assert "--expect-serial" in help_result.stdout
    assert "--map" in help_result.stdout

    out = tmp_path / "blank.xlsx"
    result = runner.invoke(cli_mod.app, ["users", "template", str(out)])
    assert result.exit_code == 0, result.stdout
    assert out.exists()


def test_cli_apply_without_expect_serial_exits_nonzero(tmp_path: Path) -> None:
    result = runner.invoke(
        cli_mod.app,
        [
            "users",
            "import",
            str(tmp_path / "not-read.xlsx"),
            "--host",
            "127.0.0.1",
            "--apply",
        ],
    )
    assert result.exit_code == 2
    assert "--expect-serial" in result.output


# --- reading and mapping -----------------------------------------------------------------------


def test_read_rows_maps_headers_and_reports_bad_rows(tmp_path: Path) -> None:
    path = _workbook(
        tmp_path / "mapped.xlsx",
        [
            ["91", "User E91", "90000091"],
            ["92", "User E92", ""],
            ["93", "User E93", "90000093"],
            ["93", "User E93", "90000094"],
        ],
        headers=["Emp No", "Full Name", "Card"],
    )
    rows = read_import_rows(
        path, mapping={"Emp No": "employeeNo", "Full Name": "name", "Card": "cardNo"}
    )
    assert [row.employee_no for row in rows] == ["91", "92", "93", "93"]
    assert rows[1].problem == "missing cardNo"
    assert rows[2].problem == "duplicate employeeNo in file"
    assert rows[3].problem == "duplicate employeeNo in file"

    with pytest.raises(ImportFileError, match="missing required column"):
        read_import_rows(_workbook(tmp_path / "thin.xlsx", [], headers=["employeeNo", "name"]))


def test_numeric_identity_cells_are_refused_not_rounded(tmp_path: Path) -> None:
    path = _workbook(
        tmp_path / "numeric.xlsx",
        [
            [1234567890123456789, "User E91", "90000091"],
            ["92", "User E92", 1.23456789012e15],
            ["00123", "User E123", "000456"],
        ],
    )
    rows = read_import_rows(path)
    assert rows[0].employee_no == ""
    assert "employeeNo cell is not text" in (rows[0].problem or "")
    assert "format the employeeNo column as Text" in (rows[0].problem or "")
    assert "1234567890123457024" not in (rows[0].problem or "")
    assert rows[1].card_no == ""
    assert "cardNo cell is not text" in (rows[1].problem or "")
    assert "format the cardNo column as Text" in (rows[1].problem or "")
    assert rows[2].employee_no == "00123"
    assert rows[2].card_no == "000456"
    assert rows[2].problem is None


def test_date_cells_normalize_and_invalid_windows_are_refused(tmp_path: Path) -> None:
    path = _workbook(
        tmp_path / "dates.xlsx",
        [
            [
                "91",
                "User E91",
                "90000091",
                "normalCard",
                datetime(2026, 1, 1),  # noqa: DTZ001 - Excel dates are naive wall time
                datetime(2026, 1, 2, 3, 4, 5),  # noqa: DTZ001 - Excel wall time
            ],
            ["92", "User E92", "90000092", "normalCard", "bad-date", "2037-12-31T23:59:59"],
            [
                "93",
                "User E93",
                "90000093",
                "normalCard",
                "2026-02-01T00:00:00",
                "2026-01-01T00:00:00",
            ],
            ["94", "User E94", "90000094", "normalCard", date(2026, 3, 4), None],
        ],
        headers=["employeeNo", "name", "cardNo", "cardType", "validFrom", "validTo"],
    )
    rows = read_import_rows(path)
    assert rows[0].valid_from == "2026-01-01T00:00:00"
    assert rows[0].valid_to == "2026-01-02T03:04:05"
    assert rows[0].problem is None
    assert "validFrom 'bad-date'" in (rows[1].problem or "")
    assert "YYYY-MM-DDTHH:MM:SS" in (rows[1].problem or "")
    assert "validFrom must be before validTo" in (rows[2].problem or "")
    assert rows[3].valid_from == "2026-03-04T00:00:00"
    assert rows[3].problem is None


# --- plan classification -----------------------------------------------------------------------


def test_plan_classifies_add_present_update_and_refusals() -> None:
    present_row = ImportRow(10, "90", "User E90", "90000090")
    update_row = ImportRow(11, "92", "Renamed", "90000092")
    add_row = ImportRow(12, "91", "User E91", "90000091")
    missing_row = ImportRow(13, "94", "User E94", "", problem="missing cardNo")
    capacity_row = ImportRow(14, "93", "User E93", "90000093")
    foreign_row = ImportRow(15, "95", "User E95", "90000099")

    target_users = [
        build_user_record(present_row),
        build_user_record(ImportRow(11, "92", "Old Name", "90000092")),
        build_user_record(ImportRow(14, "93", "User E93", "90000093")),
    ]
    target_cards = [
        {"employeeNo": "90", "cardNo": "90000090", "cardType": "normalCard"},
        {"employeeNo": "93", "cardNo": "90000098", "cardType": "normalCard"},
        {"employeeNo": "99", "cardNo": "90000099", "cardType": "normalCard"},
    ]
    plan = plan_import(
        [add_row, present_row, update_row, missing_row, capacity_row, foreign_row],
        target_users=target_users,
        target_cards=target_cards,
        dialect=_ok_dialect(),
        capacity=1,
    )
    actions = {(row.row.employee_no, row.row.card_no): row for row in plan.rows}
    assert actions[("91", "90000091")].action is ImportAction.ADD_USER
    assert actions[("91", "90000091")].card_write is not None
    assert actions[("90", "90000090")].action is ImportAction.SKIP_PRESENT
    assert actions[("92", "90000092")].action is ImportAction.SKIP_UPDATE_NEEDED
    assert "name differs" in (actions[("92", "90000092")].reason or "")
    assert actions[("94", "")].action is ImportAction.REFUSE
    assert actions[("93", "90000093")].action is ImportAction.REFUSE
    assert "capacity" in (actions[("93", "90000093")].reason or "")
    assert actions[("95", "90000099")].action is ImportAction.REFUSE
    assert "bound to a different employeeNo" in (actions[("95", "90000099")].reason or "")
    assert len(plan.users) == 1
    assert len(plan.cards) == 1


def test_real_caps_confirm_dialect_and_have_no_per_person_capacity() -> None:
    verdict = dialect_verdict(REAL_CAPS)
    assert verdict.ok
    assert verdict.user_caps and verdict.card_caps
    assert verdict.user_setup and verdict.card_setup

    probe = CapabilityMatrix(
        caps_raw={
            "user_info_capabilities": REAL_CAPS["user_info_capabilities"],
            "card_info_capabilities": REAL_CAPS["card_info_capabilities"],
        }
    )
    assert card_capacity_from_caps(probe) is None
    plan = plan_import(
        [ImportRow(2, "91", "User E91", "90000091")],
        target_users=[],
        target_cards=[],
        probe=probe,
    )
    assert plan.card_capacity is None
    assert plan.rows[0].action is ImportAction.ADD_USER
    assert any("did not advertise a per-person card capacity" in note for note in plan.notes)


def test_capacity_is_enforced_when_the_device_advertises_it() -> None:
    probe = CapabilityMatrix(
        caps_raw={"user_info_capabilities": {"UserInfo": {"numOfCard": {"@max": 0}}}}
    )
    plan = plan_import(
        [ImportRow(2, "91", "User E91", "90000091")],
        target_users=[],
        target_cards=[],
        probe=probe,
        dialect=_ok_dialect(),
    )
    assert plan.card_capacity == 0
    assert plan.rows[0].action is ImportAction.REFUSE
    assert "capacity" in (plan.rows[0].reason or "")


# --- dry run, apply, re-run --------------------------------------------------------------------


def test_dry_run_masks_card_and_writes_nothing(tmp_path: Path) -> None:
    pytest.importorskip("openpyxl")
    device = _device()
    factory = _factory(device)
    client = factory()
    try:
        report = run_import(
            SAMPLE,
            client=client,
            client_factory=factory,
            apply=False,
            journal_path=tmp_path / "journal.jsonl",
            results_path=tmp_path / "results.csv",
            sleep=lambda _s: None,
        )
    finally:
        client.close()
    assert report.plan.counts()[ImportAction.ADD_USER.value] == 1
    assert report.summary()["plan"]["device"] == {
        "model": TARGET_MODEL,
        "serial": TARGET_SERIAL,
    }
    payload = json.dumps(report.summary())
    assert "90000090" not in payload
    assert "0090" in payload
    assert "90000090" not in json.dumps(render_plan_rows(report.plan))
    assert not (tmp_path / "journal.jsonl").exists()
    assert not (tmp_path / "results.csv").exists()


def test_apply_refuses_wrong_serial_before_writing(tmp_path: Path) -> None:
    pytest.importorskip("openpyxl")
    device = _device()
    factory = _factory(device)
    journal = tmp_path / "private/journal.jsonl"
    results = tmp_path / "private/results.csv"
    client = factory()
    try:
        with pytest.raises(DeviceMismatchError, match="does not match"):
            run_import(
                SAMPLE,
                client=client,
                client_factory=factory,
                apply=True,
                expect_serial="SOME-OTHER-DOOR",
                journal_path=journal,
                results_path=results,
                sleep=lambda _s: None,
            )
    finally:
        client.close()
    assert not journal.exists()
    assert not results.exists()


def test_apply_requires_expect_serial(tmp_path: Path) -> None:
    device = _device()
    factory = _factory(device)
    journal = tmp_path / "private/journal.jsonl"
    client = factory()
    try:
        with pytest.raises(DeviceSerialRequiredError, match="expect-serial"):
            run_import(
                tmp_path / "not-read.xlsx",
                client=client,
                client_factory=factory,
                apply=True,
                journal_path=journal,
                sleep=lambda _s: None,
            )
    finally:
        client.close()
    assert not journal.exists()


def test_apply_writes_via_journal_and_rerun_skips_present(tmp_path: Path) -> None:
    pytest.importorskip("openpyxl")
    device = _device()
    factory = _factory(device)
    journal = tmp_path / "private/journal.jsonl"
    results = tmp_path / "private/results.csv"
    client = factory()
    try:
        report = run_import(
            SAMPLE,
            client=client,
            client_factory=factory,
            apply=True,
            expect_serial=TARGET_SERIAL,
            journal_path=journal,
            results_path=results,
            sleep=lambda _s: None,
        )
    finally:
        client.close()
    assert report.clean and not report.aborted
    assert report.users_result is not None and len(report.users_result.confirmed) == 1
    assert report.cards_result is not None and len(report.cards_result.confirmed) == 1
    text = journal.read_text()
    assert '"planned"' in text and '"applied"' in text and '"confirmed"' in text
    assert "90000090" in results.read_text()
    assert results.stat().st_mode & 0o777 == 0o600

    client = factory()
    try:
        rerun = run_import(
            SAMPLE,
            client=client,
            client_factory=factory,
            apply=True,
            expect_serial=TARGET_SERIAL,
            journal_path=journal,
            results_path=results,
            sleep=lambda _s: None,
        )
    finally:
        client.close()
    assert rerun.plan.counts()[ImportAction.SKIP_PRESENT.value] == 1
    assert rerun.users_result is None and rerun.cards_result is None


def test_auth_failure_aborts_and_journal_resumes(tmp_path: Path) -> None:
    pytest.importorskip("openpyxl")
    device = _device()
    read_factory = _factory(device)
    write_factory = _factory(device, password="fakepw-wrong")
    journal = tmp_path / "private/journal.jsonl"
    results = tmp_path / "private/results.csv"
    client = read_factory()
    try:
        report = run_import(
            SAMPLE,
            client=client,
            client_factory=write_factory,
            apply=True,
            expect_serial=TARGET_SERIAL,
            journal_path=journal,
            results_path=results,
            sleep=lambda _s: None,
        )
    finally:
        client.close()
    assert report.aborted
    assert "auth failure" in (report.abort_reason or "")
    assert report.cards_result is None
    assert journal.exists()
    assert '"planned"' in journal.read_text()

    client = read_factory()
    try:
        resumed = run_import(
            SAMPLE,
            client=client,
            client_factory=read_factory,
            apply=True,
            expect_serial=TARGET_SERIAL,
            journal_path=journal,
            results_path=results,
            sleep=lambda _s: None,
        )
    finally:
        client.close()
    assert resumed.clean and not resumed.aborted
    assert resumed.plan.counts()[ImportAction.ADD_USER.value] == 1
    assert '"confirmed"' in journal.read_text()


# --- dialect gate ------------------------------------------------------------------------------


def test_dialect_refusal_blocks_all_writes(tmp_path: Path) -> None:
    pytest.importorskip("openpyxl")
    device = _device(
        caps_user_info={
            "UserInfo": {
                "maxRecordNum": 3000,
                "supportFunction": {"@opt": "faceCapture,fpCapture"},
            }
        }
    )
    factory = _factory(device)
    journal = tmp_path / "private/journal.jsonl"
    client = factory()
    try:
        with pytest.raises(DialectRefusedError, match="Record-style"):
            run_import(
                SAMPLE,
                client=client,
                client_factory=factory,
                apply=True,
                expect_serial=TARGET_SERIAL,
                journal_path=journal,
                results_path=tmp_path / "private/results.csv",
                sleep=lambda _s: None,
            )
    finally:
        client.close()
    assert not journal.exists()
