"""tz_dialect must REFUSE implausible offsets, never round or clamp them into a number.

Two lenient acceptances found by the P1-06b audit (t_7a0cb61e) and re-scoped here
(t_29318514): `_mm()` used to round seconds to the nearest minute, so `CST-2:00:30` came
back as +121; and `_MAX_OFFSET_MIN` was ±16 h, so `CST-15:00:00` came back as +900. Both
turn a misconfigured device into a plausible-looking offset with no signal — on the
payroll path that is a silent minute-or-hour shift. Sub-minute precision is not a real
zone rule and no real zone leaves ±14 h, so both must be `HikTzUnknown`.

Every assertion pins the result TYPE as well as the reason: "not +121" would also be
satisfied by a crash, and the merged contract is that the parser is total (DESIGN.md
item 5; the module never raises).
"""

from __future__ import annotations

import pytest

from gateclerk.tz_dialect import (
    WINDOWS_TZ,
    HikTz,
    HikTzInfo,
    HikTzUnknown,
    parse_hik_timezone,
)

#: The audit's four specimens, verbatim (t_7a0cb61e comment, divergence 1 + 2).
SUB_MINUTE = ["CST-2:00:30", "CST-0:00:30"]
OUT_OF_RANGE = ["CST-15:00:00", "CST-16:00:00"]


def refused(raw: str | None) -> HikTzUnknown:
    """The parser's refusal as a *value* — a traceback here fails the test, not passes it."""
    result: HikTz = parse_hik_timezone(raw)
    assert isinstance(result, HikTzUnknown), (
        f"{raw!r} must be refused as HikTzUnknown (a value, never an exception and never "
        f"a plausible offset); got {type(result).__name__} {result!r}"
    )
    return result


# --- RULE 1: sub-minute offsets are rejected, not rounded ---------------------------------


def test_sub_minute_seconds_are_refused_and_say_so() -> None:
    """The card's specimens: rounding invented a minute of shift (+121, +1)."""
    for raw, invented in zip(SUB_MINUTE, (121, 1), strict=True):
        result = refused(raw)
        assert "sub-minute" in result.reason, (
            f"{raw!r} refused for the wrong reason: {result.reason!r}"
        )
        assert raw in result.reason or raw.strip() in result.reason, (
            f"the refusal must name the text it refused: {result.reason!r}"
        )
        assert result.raw == raw
        # The specific wrong answers the rounding produced must not be reachable at all:
        # this assertion is meaningless alone (a crash passes it too), which is why the
        # TYPE pin in refused() comes first.
        assert not isinstance(result, HikTzInfo)
        assert getattr(result, "std_offset_min", None) != invented


@pytest.mark.parametrize(
    "raw",
    [
        "CST-2:00:01",  # one second is still not a zone rule
        "CST-2:00:30",  # the specimen that used to round UP to +121
        "CST-2:00:29",  # and one that used to round DOWN to +120 — both are refusals
        "CST+0:00:30",
        "CST-2:00:30DST01:00:00",  # std sub-minute
        "CST-2:00:00DST01:00:30",  # dst sub-minute
        "EST5EDT4:00:30",  # classic-POSIX dst field
        "Etc/GMT-2:00:30",  # Etc/GMT is a dialect, not a zoneinfo pass-through
        "CST-8:30:30,M3.4.1/00:00:00",  # sub-minute with a rule tail
    ],
)
def test_sub_minute_is_refused_on_every_field(raw: str) -> None:
    assert "sub-minute" in refused(raw).reason


def test_whole_minute_clocks_still_parse() -> None:
    """The refusal is about the seconds FIELD, not about a 3-part clock."""
    info = parse_hik_timezone("CST-2:00:00DST01:00:00,M3.4.1/00:00:00,M10.5.0/23:00:00")
    assert isinstance(info, HikTzInfo), f"the golden specimen must still parse: {info!r}"
    assert (info.std_offset_min, info.dst_offset_min) == (120, 180)


# --- RULE 2: the bound is ±14 h, and it applies to every path that yields an offset --------


@pytest.mark.parametrize("raw", OUT_OF_RANGE)
def test_offsets_past_14h_are_refused_and_say_so(raw: str) -> None:
    """The audit's specimens: +900 and +960 were accepted as if they were zones."""
    result = refused(raw)
    assert "14 h" in result.reason, f"{raw!r} refused for the wrong reason: {result.reason!r}"
    assert "sub-minute" not in result.reason, "an out-of-range refusal must not blame seconds"


def test_offset_bound_is_the_real_world_limit_inclusive() -> None:
    """Off-by-one bound is the likely mistake: 14:00 in, 14:01 out, both signs."""
    east = parse_hik_timezone("CST-14:00")
    west = parse_hik_timezone("CST+14:00")
    assert isinstance(east, HikTzInfo) and isinstance(west, HikTzInfo), (
        f"exactly ±14:00 are real zones and must parse: {east!r} / {west!r}"
    )
    assert (east.std_offset_min, west.std_offset_min) == (840, -840)
    assert refused("CST-14:01").reason
    assert refused("CST+14:01").reason
    assert refused("CST-14:00:59")  # seconds make it sub-minute as well as out of range
    for raw in ("CST-14:01", "CST+14:01"):
        assert "14 h" in refused(raw).reason


@pytest.mark.parametrize(
    "raw",
    [
        "CST+15:00:00",  # the west side of the specimen
        "CST-15:30",  # no minutes-only escape hatch
        "Etc/GMT-15:00",  # Etc/GMT is parsed here, so it is bound here too
        "Etc/GMT+15:00",
        "UTC-16:00:00",  # the UTC alias branch carries an offset once one is written
        "CST-15:00:00,M3.4.1/00:00:00",  # bound holds with a rule tail
    ],
)
def test_offset_bound_applies_to_every_path_that_yields_an_offset(raw: str) -> None:
    assert "14 h" in refused(raw).reason


def test_dst_cannot_smuggle_a_15_hour_offset_past_the_std_bound() -> None:
    """std+dst is its own path: std is in range, only the DST number is impossible."""
    result = refused("CST-13:00:00DST02:00:00")
    assert "14 h" in result.reason, f"the bound must also catch the DST side: {result.reason!r}"


def test_windows_table_is_already_inside_the_bound_and_stays_usable() -> None:
    """The Windows lookup returns offsets directly — the bound must not silently skip it."""
    for ident, (std, dst, _who) in WINDOWS_TZ.items():
        assert all(o is None or -840 <= o <= 840 for o in (std, dst)), (
            f"Windows id {ident!r} is off-planet: {std}/{dst}"
        )
    info = parse_hik_timezone("GMT Standard Time")
    assert isinstance(info, HikTzInfo) and (info.std_offset_min, info.dst_offset_min) == (0, 60)


def test_the_bound_guards_the_windows_branch_too(monkeypatch: pytest.MonkeyPatch) -> None:
    """Table entries are in range today, so without a synthetic entry the check is unproved.

    A bound wired only into the POSIX branch would pass every other test in this file.
    """
    monkeypatch.setitem(WINDOWS_TZ, "fake standard time", (900, None, "synthetic +15 h"))
    assert "14 h" in refused("Fake Standard Time").reason
    monkeypatch.setitem(WINDOWS_TZ, "fake standard time", (780, 900, "synthetic +15 h DST"))
    assert "14 h" in refused("Fake Standard Time").reason


# --- the failure mode itself ---------------------------------------------------------------


@pytest.mark.parametrize("raw", SUB_MINUTE + OUT_OF_RANGE)
def test_refusals_never_raise_and_always_keep_the_raw(raw: str) -> None:
    """A rejection must reach the CLI as a value, never as a traceback (merged contract)."""
    result = parse_hik_timezone(raw)
    assert isinstance(result, HikTzUnknown)
    assert result.raw == raw and result.reason.strip()
