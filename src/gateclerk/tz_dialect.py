"""Hikvision timezone dialect -> diagnostics only, never UTC math.

Explains what the device *thinks* its offset is, for `tz_offset_min_device` and to make a
`tz_offset_mismatch` flag readable. The site's IANA zone via zoneinfo stays the only
source of truth for event UTC (docs/DESIGN.md "Time handling" item 5), so this module must
never see a clock or an instant — tests/test_tz_dialect.py pins its import set so the rule
cannot rot into a comment.

Dialects: POSIX-ish ("CST-2:00:00DST01:00:00,M3.4.1/00:00:00,M10.5.0/23:00:00"), bare POSIX
("CST-8", "Etc/GMT-2"), Windows ids ("GTB Standard Time"). Anything else — IANA names
included, resolving those is zoneinfo's job — is HikTzUnknown.

Two traps, both unit-tested:
  SIGN  POSIX offsets are west-positive, so "CST-2:00:00" and "Etc/GMT-2" are UTC+**2**.
        Never `str.replace("GMT", "")`.
  DST   Hikvision writes the amount ADDED to std ("DST01:00:00 adds an hour", OBSERVED.md);
        classic POSIX writes an absolute west-positive value ("EST5EDT4" = UTC-4). Both
        readings are tried and a sane +1 h shift wins — which is what makes site-a read
        +03:00 instead of a nonsense UTC+1.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

__all__ = ["WINDOWS_TZ", "HikTz", "HikTzInfo", "HikTzUnknown", "parse_hik_timezone"]

#: Windows ids -> (std minutes EAST of UTC, dst minutes east of UTC or None, who they are).
#: Hikvision ships hundreds of these; an unlisted id is HikTzUnknown (a diagnostic miss),
#: never a confidently wrong payroll number.
WINDOWS_TZ: dict[str, tuple[int, int | None, str]] = {
    "gtb standard time": (120, 180, "Athens, Bucharest"),
    "e. europe standard time": (120, 180, "Chișinău"),
    "fle standard time": (120, 180, "Helsinki, Kyiv"),
    "central europe standard time": (60, 120, "Budapest, Prague, Warsaw"),
    "w. europe standard time": (60, 120, "Berlin, Paris"),
    "gmt standard time": (0, 60, "London, Lisbon"),
    "turkey standard time": (180, None, "Istanbul, no DST since 2016"),
    "eastern standard time": (-300, -240, "US/Canada east"),
    "utc": (0, None, "UTC"),
}

_MAX_OFFSET_MIN = 16 * 60  # real zones span -12 h..+14 h; wider means it was never a zone
_DST_SHIFT_MIN = 60  # conventional shift, and the tie-breaker between the two DST readings
_HMS = r"\d{1,2}(?::\d{1,2}){0,2}"
_POSIX = re.compile(
    rf"""
    (?P<name><[^>]+>|[A-Za-z][A-Za-z0-9_+/-]*?)                       # CST | Etc/GMT | <AEST-10>
    (?: (?P<sign>[+-])(?P<std>{_HMS})                                  # CST-8, Etc/GMT-2
      | (?P<std_bare>{_HMS})(?P<dstname>[A-Za-z]{{2,5}})(?P<dstn>{_HMS})? )?  # EST5EDT[4]
    (?: \s*DST\s*(?P<dstsign>[+-])?(?P<dst>{_HMS})? )?                 # DST01:00:00 (Hikvision)
    (?P<rules>,.*)?
    """,
    re.VERBOSE,
)
_M_RULE = re.compile(r"M(?P<month>\d{1,2})\.(?P<week>\d)\.(?P<dow>\d)(?:\s*/\s*(?P<at>[\d:]+))?")
_UTC_ALIAS = re.compile(r"(?:etc/)?(?:utc|gmt|z)", re.IGNORECASE)
_MONTHS = ("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec")
_DOW = ("Sunday", "Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday")
_OCC = ("first", "second", "third", "fourth", "last")  # POSIX week 5 == last


@dataclass(frozen=True, slots=True)
class HikTzInfo:
    """What the device's own string claims. Audit data, never an input to UTC math."""

    raw: str
    source: str  # "posix" | "windows"
    name: str  # the zone name as the device wrote it
    std_offset_min: int  # minutes EAST of UTC at std, POSIX sign applied: "CST-8" -> 480
    dst_offset_min: int | None  # minutes east during DST; None = the string has no DST
    rule_desc: str  # one-line human explanation for the CLI/log


@dataclass(frozen=True, slots=True)
class HikTzUnknown:
    """Unreadable string. The caller keeps it raw and flags it — it never guesses."""

    raw: str
    reason: str


HikTz = HikTzInfo | HikTzUnknown


def parse_hik_timezone(raw: str | None) -> HikTz:
    """Parse one Hikvision `timeZone` value. Total: unreadable -> HikTzUnknown, never raises.

    The string is whitespace-stripped and otherwise kept as the device sent it.
    """
    text = (raw or "").strip()
    if not text:
        return HikTzUnknown("", "empty timezone string")
    entry = WINDOWS_TZ.get(" ".join(text.split()).casefold())
    if entry:
        std, dst, who = entry
        tail = f"DST UTC{_h(dst)}" if dst is not None else "no DST"
        return HikTzInfo(
            text, "windows", text, std, dst, f"Windows id, {who}: std UTC{_h(std)}, {tail}"
        )
    match = _POSIX.fullmatch(text)
    if match is None or not match["name"]:
        return HikTzUnknown(text, f"unrecognised timezone dialect {text!r}")
    return _posix(text, match)


def _posix(text: str, match: re.Match[str]) -> HikTz:
    name = match["name"]
    written = match["std"] or match["std_bare"]
    if written is None:  # no numbers: only the UTC aliases have a defensible offset
        if not _UTC_ALIAS.fullmatch(name.strip("<>")):
            return HikTzUnknown(
                text,
                f"{name!r} carries no numeric offset; IANA names such as 'Europe/Bucharest' "
                "are resolved by zoneinfo in the resolver, not here",
            )
        std, dst = 0, None
    else:
        # West-positive -> minutes east of UTC means negating the written number:
        # EST5 -> -300, CST-2:00:00 -> +120, Etc/GMT-2 -> +120.
        std = _mm(written) if match["sign"] == "-" else -_mm(written)
        dst = _dst(std, match)
        if dst is False:  # both readings of the DST field are senseless
            return HikTzUnknown(text, f"no plausible DST offset in {text!r}")
    if any(isinstance(o, int) and abs(o) > _MAX_OFFSET_MIN for o in (std, dst)):
        return HikTzUnknown(text, f"offset outside ±{_MAX_OFFSET_MIN // 60} h is not a real zone")

    desc = f"POSIX dialect, west-positive sign so {name} = std UTC{_h(std)}" + (
        f", DST UTC{_h(dst)} ({dst - std:+d} min)" if dst is not None else ", no DST"
    )
    if match["rules"]:
        desc += f"; {_rules(match['rules'])}"
    if match["sign"] == "+":
        desc += " [CAVEAT: explicit '+' read POSIX-style = west of UTC; trust the raw string]"
    return HikTzInfo(text, "posix", name, std, dst, desc)


def _dst(std: int, match: re.Match[str]) -> int | bool | None:
    """DST offset as an int, False (senseless), or None (the string has no DST).

    The written number is ambiguous — a Hikvision delta added to std, or a classic POSIX
    absolute west-positive value — so both are computed and the plausible shift wins: +1 h
    first (what nearly every zone does), else the smallest sane shift. A bare DST name
    ("EST5EDT", no number) is classic POSIX for +1 h.
    """
    written = match["dst"] or match["dstn"]
    if written is None:
        return std + _DST_SHIFT_MIN if match["dstname"] or match["dst"] is not None else None
    value = -_mm(written) if match["dstsign"] == "-" else _mm(written)
    shifts = {
        c - std
        for c in (std + value, -value)
        if abs(c) <= _MAX_OFFSET_MIN and 0 < c - std <= 2 * _DST_SHIFT_MIN
    }
    if not shifts:
        return False
    return std + (_DST_SHIFT_MIN if _DST_SHIFT_MIN in shifts else min(shifts))


def _rules(rules: str) -> str:
    """',M3.4.1/00:00:00,M10.5.0/23:00:00' -> 'DST starts ..., ends ...' in plain words."""
    parts = []
    for kind, part in zip(("starts", "ends"), (p for p in rules.split(",") if p), strict=False):
        rule = _M_RULE.fullmatch(part.strip())
        if rule is None:
            parts.append(f"{kind} {part!r} (rule form not understood)")
            continue
        parts.append(
            f"{kind} the {_OCC[min(int(rule['week']), 5) - 1]} {_DOW[int(rule['dow']) % 7]} of "
            f"{_MONTHS[int(rule['month']) - 1]} at {rule['at'] or '02:00:00'}"
        )
    return "DST " + ", ".join(parts)


def _mm(clock: str) -> int:
    """'2:00:00' | '2' | '5:30' -> magnitude in minutes (seconds rounded to the minute)."""
    hh, mm, *rest = (*clock.split(":"), "0", "0")
    return int(hh) * 60 + int(mm) + (int(rest[0]) + 30) // 60


def _h(minutes: int) -> str:
    sign, (hours, mins) = ("+" if minutes >= 0 else "-"), divmod(abs(minutes), 60)
    return f"{sign}{hours:02d}:{mins:02d}"
