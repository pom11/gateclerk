"""Hikvision tz dialect: offsets, the POSIX sign trap, and the diagnostics-only rule.

Golden case is site-a's real `<timeZone>` from
tests/fixtures/recorded/site-a-ds-k1t341amf-s/system_time.xml. Everything asserted here is
what the *device claims*; none of it feeds an event's UTC instant — which the last test
enforces mechanically.
"""

from __future__ import annotations

import ast
import dataclasses
import io
import tokenize
from pathlib import Path

import pytest

from gateclerk.tz_dialect import HikTzInfo, HikTzUnknown, parse_hik_timezone

SITE_A = "CST-2:00:00DST01:00:00,M3.4.1/00:00:00,M10.5.0/23:00:00"
MODULE = Path(__file__).resolve().parents[1] / "src" / "gateclerk" / "tz_dialect.py"


def parsed(raw: str | None) -> HikTzInfo:
    result = parse_hik_timezone(raw)
    assert isinstance(result, HikTzInfo), f"expected a parse, got {result!r}"
    return result


def test_site_a_reads_std_plus_two_dst_plus_three() -> None:
    """The payroll-relevant diagnostic: the device thinks it is EET/EEST."""
    info = parsed(SITE_A)
    assert info.std_offset_min == 120, "POSIX sign: 'CST-2' is west-positive, so UTC+2"
    assert info.dst_offset_min == 180, "Hikvision DST01:00:00 is the amount ADDED (OBSERVED.md)"
    assert (info.source, info.name, info.raw) == ("posix", "CST", SITE_A)


def test_site_a_rule_is_explained_in_plain_words() -> None:
    desc = parsed(SITE_A).rule_desc
    assert "fourth Monday of Mar" in desc and "last Sunday of Oct" in desc


def test_site_a_matches_the_recorded_fixture() -> None:
    """The fixture is the truth source; if the recording changes, this test says so."""
    xml = (
        Path(__file__).parent / "fixtures/recorded/site-a-ds-k1t341amf-s/system_time.xml"
    ).read_text(encoding="utf-8")
    assert parsed(xml.split("<timeZone>")[1].split("</timeZone>")[0]).std_offset_min == 120


def test_bare_posix_forms_use_the_inverted_sign() -> None:
    assert parsed("CST-8").std_offset_min == 480, "bare 'CST-8' is UTC+8, not UTC-8"
    assert parsed("CST-8").dst_offset_min is None
    assert parsed("Etc/GMT-2").std_offset_min == 120
    assert parsed("Etc/GMT+2").std_offset_min == -120, "the inversion must be symmetric"


def test_gtb_standard_time_is_athens_bucharest() -> None:
    info = parsed("GTB Standard Time")
    assert (info.std_offset_min, info.dst_offset_min, info.source) == (120, 180, "windows")
    assert "Bucharest" in info.rule_desc
    assert parsed("  gtb  standard TIME ").std_offset_min == 120, "lookup tolerates mess"


def test_classic_posix_us_form_still_reads_america() -> None:
    """'EST5EDT4' is the absolute west-positive reading; it must not become UTC+4."""
    est = parsed("EST5EDT4")
    assert (est.std_offset_min, est.dst_offset_min) == (-300, -240)
    assert parsed("EST5EDT").dst_offset_min == -240, "a bare DST name means the usual +1 h"


def test_transition_rule_without_dst_still_parses() -> None:
    info = parsed("CST-8,M3.4.1/00:00:00")
    assert (info.std_offset_min, info.dst_offset_min) == (480, None)
    assert "fourth Monday of Mar" in info.rule_desc


@pytest.mark.parametrize(
    "raw",
    [
        "",
        "   ",
        None,
        "Europe/Bucharest",
        "Bucharest",
        "GMT+02:00:00:00:00",
        "CST-99",
        "CST-2:00:00DST99:00:00",
        "3am-ish",
        "--CST",
    ],
    ids=[
        "empty",
        "spaces",
        "none",
        "iana",
        "city",
        "bad-clock",
        "std-out-of-range",
        "dst-out-of-range",
        "not-a-tz",
        "no-name",
    ],
)
def test_unknown_never_raises_and_always_keeps_the_raw(raw: str | None) -> None:
    result = parse_hik_timezone(raw)
    assert isinstance(result, HikTzUnknown)
    assert result.raw == (raw or "").strip() and result.reason


def test_iana_name_is_rejected_because_zoneinfo_owns_it() -> None:
    """Accepting IANA here would invite this module into the UTC math. It must not."""
    reason = parse_hik_timezone("Europe/Bucharest").reason  # type: ignore[attr-defined]
    assert "zoneinfo" in reason


def test_parse_is_deterministic_and_results_are_frozen() -> None:
    assert parsed(SITE_A) == parsed(SITE_A), "no clock, no state: same string, same answer"
    with pytest.raises(dataclasses.FrozenInstanceError):
        parsed(SITE_A).std_offset_min = 0  # type: ignore[misc]


def test_module_imports_nothing_that_can_talk_to_a_clock() -> None:
    """The diagnostics-only rule, enforced instead of commented (DESIGN.md item 5).

    A module that imports datetime/zoneinfo drifts into the UTC math eventually, so its
    import set is pinned to pure text handling. NAME tokens are checked too, so this test's
    own prose can *mention* the banned words while the module's code cannot use them.
    """
    source = MODULE.read_text(encoding="utf-8")
    imported: set[str] = set()
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Import):
            imported.update(a.name.split(".")[0] for a in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            imported.add(node.module.split(".")[0])
    assert imported <= {"__future__", "re", "dataclasses"}, f"unexpected import: {imported}"

    names = {
        t.string
        for t in tokenize.generate_tokens(io.StringIO(source).readline)
        if t.type == tokenize.NAME
    }
    clock = {"datetime", "zoneinfo", "astimezone", "utcnow", "fromtimestamp", "now", "today"}
    assert not names & clock, f"clock access in a diagnostics-only module: {names & clock}"
