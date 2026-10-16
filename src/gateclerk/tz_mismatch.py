"""`tz_offset_mismatch`: does the device's claimed offset disagree with the site zone?

Payroll-critical, and diagnostic-only at the same time (docs/DESIGN.md "Time handling"
item 2, docs/OBSERVED.md "The time/offset bug"): site-a stamps `+02:00` on a summer wall
time that Europe/Bucharest holds at +03:00. The flag makes that visible on the record.
The resolved instants it describes are produced elsewhere and stay untouched — the flag
is an observation, never a correction.

Why this is its own module and not more of tz_dialect.py: that file is pinned
clock-free by tests/test_tz_dialect.py (no `datetime`/`zoneinfo` NAME may appear in it)
so that *explaining* a Hikvision dialect can never drift into UTC math — the enforced
form of DESIGN.md item 5. This comparison is the one legitimate consumer of a wall time
plus a zone; it lives here so that pin keeps guarding the dialect. Nothing in the
resolution path imports this module (pinned by tests/test_tz_mismatch.py): the site IANA
zone via zoneinfo stays the only source of truth for event UTC.

Claimed side: minutes east of UTC (the `tz_offset_min_device` number), the `+HH:MM`
offset stamp of a `localTime` string, or the device's tz dialect string — which is
resolved through p1-06b's `parse_hik_timezone` (its standard offset, per that card's
rule-ignored decision). An unreadable claim is `None`, never a guess. Ambiguous autumn
wall times compare against the FIRST occurrence (fold=0) — the same offset
`tz._localize` resolves them with — so the flag speaks about the instant the record
actually carries.
"""

from __future__ import annotations

import re
from datetime import datetime, tzinfo
from zoneinfo import ZoneInfo

from gateclerk.tz_dialect import HikTzInfo, HikTzUnknown, parse_hik_timezone

__all__ = ["claimed_offset_minutes", "is_offset_mismatch", "site_offset_minutes"]

#: What a caller may hand us as "what the device thinks its offset is".
DeviceClaim = int | str | HikTzInfo | HikTzUnknown | None

#: `+02:00` / `UTC+02:00` / `+03:00:00` — the offset stamp of a localTime string.
_OFFSET_STAMP = re.compile(r"(?:UTC|GMT)?([+-])(\d{1,2}):(\d{2})(?::(\d{2}))?$")


def site_offset_minutes(wall_naive: datetime, iana_tz: str | tzinfo) -> int:
    """Minutes EAST of UTC that `iana_tz` holds at the naive wall time `wall_naive`.

    The offset a zone holds is a property of the wall time the device stamped, which is
    what makes this comparison immune to the device's own wrong label. `wall_naive` must
    be naive (the device's wall part); an aware value would smuggle a second, trusted
    offset into the comparison, so it raises instead.
    """
    if wall_naive.tzinfo is not None or wall_naive.utcoffset() is not None:
        raise ValueError(f"the device wall part is naive by definition; got aware {wall_naive!r}")
    zone = iana_tz if isinstance(iana_tz, tzinfo) else ZoneInfo(str(iana_tz).strip())
    offset = wall_naive.replace(tzinfo=zone).utcoffset()  # fold propagates; default 0 (first)
    if offset is None:  # pragma: no cover - a real zone always answers
        raise ValueError(f"zone {zone!r} gives no offset at {wall_naive!r}")
    return int(offset.total_seconds() // 60)


def claimed_offset_minutes(claim: DeviceClaim) -> int | None:
    """The offset a device claim asserts, or None when it asserts nothing.

    `HikTzUnknown`, `None`, and empty/unparseable strings all mean "no claim" — the
    caller must read that as absence, not as agreement or as a mismatch. A plain int is
    already minutes east of UTC and is taken as given. Anything else is treated as a tz
    string of the dialects p1-06b knows.
    """
    if claim is None or isinstance(claim, (bool, HikTzUnknown)):
        return None
    if isinstance(claim, int):
        return claim
    if isinstance(claim, HikTzInfo):
        return claim.std_offset_min
    text = str(claim).strip()
    stamp = _OFFSET_STAMP.fullmatch(text)
    if stamp and (stamp[4] or "00") == "00":  # a seconds-granular claim is not a real stamp
        minutes = int(stamp[2]) * 60 + int(stamp[3])
        return minutes if stamp[1] == "+" else -minutes
    parsed = parse_hik_timezone(text)
    return claimed_offset_minutes(parsed)


def is_offset_mismatch(
    claimed_offset_min: DeviceClaim, wall_naive: datetime, iana_tz: str | tzinfo
) -> bool | None:
    """True when the device's claimed offset and the site zone disagree at `wall_naive`.

    False means the claim agrees. None — not False — means there was no claim to compare
    (naive `localTime`, unreadable dialect): reporting "agrees" for missing data would be
    a false reassurance in payroll output. A bad zone name or an aware `wall_naive`
    raises, because returning anything there would hide a misconfigured site tz.
    """
    claimed = claimed_offset_minutes(claimed_offset_min)
    if claimed is None:
        return None
    return claimed != site_offset_minutes(wall_naive, iana_tz)
