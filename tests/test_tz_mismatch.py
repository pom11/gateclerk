"""The tz_offset_mismatch detector: card P1-06c golden pair plus its policy pins.

Golden pair is site-a's real case from docs/internal/OBSERVED.md: the device stamps +02:00 on
2026-10-15T16:39 Bucharest wall time, where Europe/Bucharest is really +03:00 ->
mismatch. The same +02:00 claim in January is correct -> no mismatch. Everything here is
offline arithmetic on a wall time; no clock, no device, no UTC instant.
"""

from __future__ import annotations

import ast
from datetime import UTC, datetime, timedelta, timezone
from pathlib import Path
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

import pytest

from gateclerk.tz_dialect import HikTzInfo, HikTzUnknown, parse_hik_timezone
from gateclerk.tz_mismatch import (
    claimed_offset_minutes,
    is_offset_mismatch,
    site_offset_minutes,
)

BUCHAREST = "Europe/Bucharest"
SITE_A = "CST-2:00:00DST01:00:00,M3.4.1/00:00:00,M10.5.0/23:00:00"
REPO = Path(__file__).resolve().parents[1]

# The card's golden wall time verbatim from OBSERVED.md / the recorded fixture.
SUMMER_WALL = "2026-10-15T16:39"
WINTER_WALL = "2026-01-20T09:00"


def wall(text: str, fold: int = 0) -> datetime:
    """Naive wall time — the only shape the detector accepts (fromisoformat stays naive)."""
    return datetime.fromisoformat(text).replace(fold=fold)


def test_golden_summer_claim_plus_two_is_a_mismatch() -> None:
    """The payroll finding itself: claim +02:00, real +03:00 (OBSERVED.md 'time bug')."""
    assert is_offset_mismatch(120, wall(SUMMER_WALL), BUCHAREST) is True


def test_golden_winter_claim_plus_two_is_no_mismatch() -> None:
    """Same claim, correct season: Bucharest is +02:00 in January, so it agrees."""
    assert is_offset_mismatch(120, wall(WINTER_WALL), BUCHAREST) is False


def test_golden_pair_via_the_device_dialect_string() -> None:
    """Raw Hikvision tz string as the claim -> p1-06b parses it; std is the claim.

    The device stamps its STANDARD offset all year (its DST rule never engages —
    OBSERVED.md), so HikTzInfo.std_offset_min is what 'the device claims' means.
    """
    assert is_offset_mismatch(SITE_A, wall(SUMMER_WALL), BUCHAREST) is True
    assert is_offset_mismatch(SITE_A, wall(WINTER_WALL), BUCHAREST) is False
    # POSIX-inverted sign must not be "fixed" on the way through (p1-06b rule).
    assert is_offset_mismatch("Etc/GMT-2", wall(WINTER_WALL), BUCHAREST) is False
    assert is_offset_mismatch("Etc/GMT+2", wall(WINTER_WALL), BUCHAREST) is True


def test_golden_summer_stamp_from_localtime_string() -> None:
    """+02:00 stamp read straight off `...T16:39:32+02:00` (the fixture form)."""
    assert is_offset_mismatch("+02:00", wall(SUMMER_WALL), BUCHAREST) is True
    assert is_offset_mismatch("UTC+02:00", wall(SUMMER_WALL), BUCHAREST) is True
    assert is_offset_mismatch("+03:00", wall(SUMMER_WALL), BUCHAREST) is False, (
        "once the owner fixes the device tz, the flag stops firing — nothing else moves"
    )


def test_site_offset_matches_zoneinfo_at_both_walls() -> None:
    assert site_offset_minutes(wall(SUMMER_WALL), BUCHAREST) == 180
    assert site_offset_minutes(wall(WINTER_WALL), BUCHAREST) == 120
    assert site_offset_minutes(wall(SUMMER_WALL), ZoneInfo(BUCHAREST)) == 180, "tzinfo accepted"


def test_ambiguous_autumn_wall_uses_the_first_occurrence() -> None:
    """03:30 on the last Sunday of Oct happens twice; the resolver keeps fold=0 (+03:00).

    The flag must speak about THAT instant: +02:00 is the second occurrence's offset,
    so against the kept record it IS a mismatch. A fold=1 wall would flip the verdict.
    """
    fold_wall = wall("2026-10-25T03:30")
    assert is_offset_mismatch(120, fold_wall, BUCHAREST) is True
    assert is_offset_mismatch(180, fold_wall, BUCHAREST) is False
    assert site_offset_minutes(wall("2026-10-25T03:30", fold=1), BUCHAREST) == 120


@pytest.mark.parametrize(
    ("claim", "at_wall", "zone"),
    [
        (330, "2026-07-04T12:00", "Asia/Kolkata"),  # +05:30: minute-exact, no DST there
        (-300, "2026-01-08T09:00", "America/New_York"),  # negative sign, winter
        (-240, "2026-07-08T09:00", "America/New_York"),  # and its summer value
        (0, "2026-01-08T09:00", "Etc/UTC"),
    ],
    ids=["kolkata-330", "ny-winter", "ny-summer", "utc"],
)
def test_other_zones_compare_minute_exactly_and_signed(claim: int, at_wall: str, zone: str) -> None:
    w = wall(at_wall)
    assert is_offset_mismatch(claim, w, zone) is False
    assert is_offset_mismatch(claim + 60, w, zone) is True


@pytest.mark.parametrize(
    "claim",
    [
        None,
        "",
        "   ",
        "Europe/Bucharest",
        "nonsense",
        "3am-ish",
        "+02:00:30",
        HikTzUnknown("x", "unreadable"),
    ],
    ids=[
        "none",
        "empty",
        "spaces",
        "iana-as-claim",
        "gibberish",
        "not-a-tz",
        "seconds-granular",
        "unknown",
    ],
)
def test_no_claim_is_none_not_false(claim: object) -> None:
    """Missing data must not masquerade as 'the offsets agree' (t_e26227b1: document None)."""
    assert is_offset_mismatch(claim, wall(SUMMER_WALL), BUCHAREST) is None  # type: ignore[arg-type]
    assert claimed_offset_minutes(claim) is None  # type: ignore[arg-type]


def test_parsed_hiktzinfo_is_usable_as_the_claim_directly() -> None:
    info = parse_hik_timezone("GTB Standard Time")
    assert isinstance(info, HikTzInfo)
    assert is_offset_mismatch(info, wall(SUMMER_WALL), BUCHAREST) is True  # std 120 vs 180
    assert claimed_offset_minutes("+05:30") == 330
    assert claimed_offset_minutes("-03:30") == -210


def test_aware_wall_time_and_bad_zone_are_errors_not_silent_verdicts() -> None:
    """Both mean caller misconfiguration; a bool answer would hide a broken site tz."""
    aware = datetime(2026, 10, 15, 16, 39, tzinfo=timezone(timedelta(hours=2)))
    with pytest.raises(ValueError, match="naive"):
        is_offset_mismatch(120, aware, BUCHAREST)
    with pytest.raises(ZoneInfoNotFoundError):
        is_offset_mismatch(120, wall(SUMMER_WALL), "Bucharest/Nowhere")


def test_verdicts_are_bool_never_int_like() -> None:
    """bool-or-None is the whole API contract (a 3rd state exists; a 4th must not)."""
    for verdict in (
        is_offset_mismatch(120, wall(SUMMER_WALL), BUCHAREST),
        is_offset_mismatch(120, wall(WINTER_WALL), BUCHAREST),
        is_offset_mismatch(None, wall(SUMMER_WALL), BUCHAREST),
    ):
        assert verdict is None or isinstance(verdict, bool)


def test_dialect_module_stays_a_leaf_and_clock_free() -> None:
    """The p1-06b invariant this card deliberately did NOT weaken.

    tz_dialect.py must not import tz_mismatch (the dialect stays pure text; see
    test_tz_dialect's own pin), and tz.py must not import tz_mismatch **at module
    level** — resolution reaching the detector is what must never happen; the flag is an
    observation on the record, never an input to resolution. p1-06d's `resolve_event_time`
    façade is the sanctioned exception: a *function-local* import inside the façade, after
    the instant is already fixed. The relaxation is two-sided on purpose — the façade
    branch only holds while test_tz.py's ordering pins stay green (flag computed from the
    resolved result; a mismatch never moves the instant). A future module-level edge would
    let any resolver code path consult the flag, which is exactly what this pin forbids.
    """
    dialect = (REPO / "src/gateclerk/tz_dialect.py").read_text(encoding="utf-8")
    assert "tz_mismatch" not in dialect

    resolver = REPO / "src/gateclerk/tz.py"
    if resolver.exists():
        tree = ast.parse(resolver.read_text(encoding="utf-8"))
        top_level: set[str] = set()
        for node in tree.body:  # module body only — function-local imports are the façade's
            if isinstance(node, ast.ImportFrom) and node.module:
                top_level.add(node.module)
            elif isinstance(node, ast.Import):
                top_level.update(a.name for a in node.names)
        assert "gateclerk.tz_mismatch" not in top_level, (
            "tz.py imports the mismatch detector at module level: resolution must never "
            "be able to consult the flag (p1-06d façade uses a function-local import)"
        )
        # And the delegation must be REAL: the p1-06d façade has to route the flag
        # through this module, not re-derive a comparison beside the resolver it wraps.
        facade = next(
            (
                node
                for node in tree.body
                if isinstance(node, ast.FunctionDef) and node.name == "resolve_event_time"
            ),
            None,
        )
        if facade is not None:  # p1-06d may not have landed on this revision yet
            delegated = any(
                isinstance(node, ast.ImportFrom) and node.module == "gateclerk.tz_mismatch"
                for node in ast.walk(facade)
            )
            assert delegated, "resolve_event_time inlined the mismatch comparison"


def test_utc_instant_is_untouched_by_a_mismatch() -> None:
    """Detection is independent of resolution: same wall, mismatching claim, the UTC the
    site zone dictates is what zoneinfo says — the claim never moves it (OBSERVED.md)."""
    utc = wall(SUMMER_WALL).replace(tzinfo=ZoneInfo(BUCHAREST)).astimezone(UTC)
    assert utc.isoformat() == "2026-10-15T13:39:00+00:00"  # the +03:00 reading, not +02:00
    assert is_offset_mismatch(120, wall(SUMMER_WALL), BUCHAREST) is True  # and still flagged
