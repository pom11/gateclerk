"""Time / timezone resolution for punch events — this output is payroll data.

docs/OBSERVED.md ("The time/offset bug", device-verified 2026-10-15) **overrides** the
offset-trusting wording in DESIGN.md "Time handling": on our site-a DS-K1T341AMF-S
(fw V3.2.30) the wall clock is right (skew ~4 s) but the UTC *offset label* is wrong —
it stamps `+02:00` in Bucharest summer. Trusting the string offset would shift every
punch by an hour for half the year.

Policy (operator decision, 2026-10-15):

1. The **site IANA zone** from config decides the UTC instant: take the naive wall-clock
   part of the device string, interpret it in that zone with `zoneinfo`. DST comes from
   the real tz database, not from us.
2. The verbatim device string and the offset the device *claimed* are both kept.
3. Anything unresolvable is **kept and flagged** (`tz_source="unresolved"`, `utc=None`).
   Never dropped, never defaulted to UTC.

Out of scope here (split out of this card, 2026-10-15): the Hikvision `timeZone` dialect
table (Windows names / `Etc/GMT±N` / POSIX) and the `tz_offset_mismatch` flag. The seam
is deliberate — `as_record()` already carries both `tz_offset_min` (the offset we used)
and `tz_offset_min_device` (the claim), so the card that adds the flag compares two
columns that are already present and needs no change here. `DeviceTime.tz_raw` carries
the dialect string unparsed for the same reason.

Two consequences that are easy to get wrong, both pinned by tests:

* **Query windows are built in device-naive-wall terms** (`window_for_device`) because
  the device filters `startTime`/`endTime` against its own wall clock. Sending UTC would
  shift every window by the device's offset error.
* **Skew compares wall clocks in the site zone** (`compute_skew`), not self-labelled
  instants — comparing instants would report the offset bug as a 3600 s "skew".

Parsing only: nothing here touches the network. `read_system_time()` takes the body of a
`GET /ISAPI/System/time` response (this firmware returns **XML** even for `?format=json`
— OBSERVED.md endpoint table) so the caller owns the transport.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import UTC, datetime, tzinfo
from enum import StrEnum
from typing import Any
from xml.etree import ElementTree as ET
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from gateclerk.exceptions import GateclerkError

__all__ = [
    "DEFAULT_SITE_TZ",
    "SKEW_WARN_SECONDS",
    "DeviceTime",
    "DeviceWindow",
    "IsapiPayloadError",
    "ResolvedTime",
    "Skew",
    "TimeResolver",
    "TimestampInputError",
    "TzSource",
    "UserTimestamp",
    "compute_skew",
    "parse_isapi_xml",
    "parse_user_timestamp",
    "read_system_time",
    "window_for_device",
]

#: Default site zone. p1-02's config owns the real value per site
#: (`site → {host, iana_tz, ...}`); this fallback only stops a naive CLI value being
#: read as UTC. `cli.DEFAULT_TZ` holds the same value — whoever next edits cli.py
#: should point that option at this constant instead.
DEFAULT_SITE_TZ = "Europe/Bucharest"

#: DESIGN.md/OBSERVED.md: skew over this many seconds is a warning *line*, never a write.
SKEW_WARN_SECONDS = 120.0

#: ISAPI System/* answers are small (< 4 kB observed). The cap bounds the XML path: we
#: parse XML from a box on the LAN, so bound the input rather than trust it.
MAX_ISAPI_XML_BYTES = 64 * 1024

# `UTC` is `datetime.UTC` (imported above; an alias of `timezone.utc`). It is used by
# name at every conversion site in this module so the payroll invariant — every stored
# instant is UTC — is visible at each call site.


class TimestampInputError(GateclerkError):
    """A `--since`/`--until` value the operator typed that we cannot interpret."""


class IsapiPayloadError(GateclerkError):
    """A device payload we refused to parse (too big, or declares an XML DTD/entity)."""


class TzSource(StrEnum):
    """How a resolved timestamp got its UTC instant. Kept on every record."""

    #: The policy path: naive wall clock + site IANA zone (docs/OBSERVED.md).
    SITE_TZ = "site-tz"
    #: A CLI value the operator gave *with* an offset — honoured exactly as written.
    STRING_OFFSET = "string-offset"
    #: Kept + flagged. Never defaulted to UTC, never dropped.
    UNRESOLVED = "unresolved"


# --- device clock (GET /ISAPI/System/time) -----------------------------------------


@dataclass(frozen=True, slots=True)
class DeviceTime:
    """One reading of `GET /ISAPI/System/time`.

    `naive_local` is the part we use — the device's wall clock, which OBSERVED.md
    confirms is correct. `claimed_offset_minutes` is the offset the `localTime` string
    labels, which on this firmware is wrong; we keep it for audit and for the p1-06c
    mismatch flag, and never compute with it. `tz_raw` is the Hikvision dialect string,
    stored unparsed (that parser is p1-06b).
    """

    local_time_raw: str | None
    naive_local: datetime | None
    claimed_offset_minutes: int | None
    tz_raw: str | None = None
    #: Why a field could not be read, when that happened. Surfaced, never swallowed.
    note: str | None = None


def read_system_time(payload: str | bytes) -> DeviceTime:
    """Parse a `System/time` body (this firmware answers XML despite `?format=json`).

    Never raises for a missing field — a device that omits `localTime` is a fact to
    report (`naive_local=None`, `note` explains), not an exception on the punch path.
    """
    text = payload.decode("utf-8", "replace") if isinstance(payload, bytes) else payload
    if not text.strip():
        return DeviceTime(None, None, None, note="empty System/time payload")
    root = parse_isapi_xml(text)
    local_raw = _xml_text(root, "localTime")
    parsed, offset, note = _parse_time_string(local_raw, field="localTime")
    return DeviceTime(
        local_time_raw=local_raw,
        naive_local=None if parsed is None else parsed.replace(tzinfo=None),
        claimed_offset_minutes=offset,
        tz_raw=_xml_text(root, "timeZone"),
        note=note,
    )


def parse_isapi_xml(payload: str) -> ET.Element:
    """Parse an ISAPI XML body with two bounds (shared entry point for p1-03).

    `xml.etree.ElementTree` does not resolve external entities, so the remaining hazards
    are size and entity expansion — both refused here rather than delegated to a
    dependency that would buy a claim, not a control.
    """
    if len(payload.encode("utf-8", "replace")) > MAX_ISAPI_XML_BYTES:
        raise IsapiPayloadError(
            f"ISAPI XML body exceeds {MAX_ISAPI_XML_BYTES} bytes — refusing to parse"
        )
    head = payload[: MAX_ISAPI_XML_BYTES // 4]
    if "<!DOCTYPE" in head or "<!ENTITY" in head:
        raise IsapiPayloadError("ISAPI XML body declares a DTD or entity — refusing to parse")
    try:
        # S314 is suppressed on the line below. defusedxml's controls are DTD/entity
        # expansion and size, both of which this function refuses explicitly above (any
        # DOCTYPE/ENTITY is rejected before parsing, and the byte cap is enforced).
        # ElementTree resolves no external entities on its own, so an extra dependency
        # would add a claim, not a control.
        return ET.fromstring(payload)  # noqa: S314
    except ET.ParseError as exc:
        raise IsapiPayloadError(f"ISAPI XML body is not well-formed XML: {exc}") from exc


def _xml_text(root: ET.Element, name: str) -> str | None:
    """First text of a named node, namespace-stripped (the device emits an ISAPI default ns)."""
    for node in root.iter():
        tag = node.tag.rsplit("}", 1)[-1] if isinstance(node.tag, str) else ""
        if tag == name and (text := (node.text or "").strip()):
            return text
    return None


# --- the one string parser ---------------------------------------------------------

#: `2026-10-15T07:46:48`, `...+03:00`, `...Z`, `...+0300`, `....123`, space or `T`.
#: py3.12 `fromisoformat` handles all of these (probed), so no third-party parser.
_TIME_RE = re.compile(
    r"^(?P<date>\d{4}-\d{2}-\d{2})[T ](?P<time>\d{2}:\d{2}(?::\d{2})?(?:\.\d{1,6})?)"
    r"(?P<off>[Zz]|[+-]\d{2}:?\d{2})?$"
)


def _parse_time_string(
    raw: str | None, *, field: str = "time"
) -> tuple[datetime | None, int | None, str | None]:
    """(parsed datetime, offset minutes, reason) for one time string. Never raises.

    A date with no time component is a **failure**, not midnight: `fromisoformat`
    accepts `'2026-10-12'` and would resolve it to local midnight, which is a guess about
    when a punch happened. (The CLI is deliberately more lenient — `parse_user_timestamp`.)
    """
    if raw is None or not (text := raw.strip()):
        return None, None, f"missing {field}"
    if _TIME_RE.match(text) is None:
        return None, None, f"{field} {raw!r} is not 'YYYY-MM-DDTHH:MM:SS[±HH:MM]'"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError as exc:
        # Reachable for strings that match the shape but are not real, e.g.
        # '2026-13-45T99:99:99' or '...+99:99'. Crashing here would lose the punch.
        return None, None, f"{field} {raw!r} is not a valid timestamp ({exc})"
    offset = parsed.utcoffset()
    return parsed, None if offset is None else int(offset.total_seconds() // 60), None


# --- resolution --------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class ResolvedTime:
    """What we record per event. `device_local` is always kept, verbatim.

    `offset_minutes` is the offset actually used for the UTC math (the site zone's offset
    at that wall time); `device_offset_minutes` is what the device claimed. They differ
    on our firmware every summer.
    """

    device_local: str | None
    utc: datetime | None
    offset_minutes: int | None
    tz_source: TzSource
    iana_tz: str | None = None
    device_offset_minutes: int | None = None
    #: The local time happens twice (autumn fold). We take the FIRST occurrence.
    ambiguous: bool = False
    #: The local time does not exist (spring gap). Kept, flagged, not shifted.
    nonexistent: bool = False
    #: The raw string carried no offset (the reason a site zone is needed at all).
    device_string_naive: bool = False
    reason: str | None = None

    @property
    def resolved(self) -> bool:
        return self.utc is not None

    def as_record(self) -> dict[str, Any]:
        """Flat dict for p1-07's EventRecord / jsonl. Stable key names.

        Both offsets are emitted so the mismatch flag (p1-06c) is a comparison of two
        columns that already exist, not a change to this module.
        """
        return {
            "event_time_utc": None if self.utc is None else self.utc.isoformat(),
            "event_time_local": self.device_local,
            "tz_offset_min": self.offset_minutes,
            "tz_offset_min_device": self.device_offset_minutes,
            "tz_source": self.tz_source.value,
            "iana_tz": self.iana_tz,
            "tz_unresolved": self.tz_source is TzSource.UNRESOLVED,
            "tz_ambiguous": self.ambiguous,
            "tz_nonexistent": self.nonexistent,
            "tz_reason": self.reason,
        }


@dataclass(frozen=True, slots=True)
class TimeResolver:
    """Turn one device time string into a `ResolvedTime`.

    `site_tz` is the operator's config value (p1-02: `site → {iana_tz}`). `None` means
    "no site zone configured" — a real state whose honest result is `unresolved`, not UTC
    (DESIGN.md: "we store it and flag it, we don't guess").
    """

    site_tz: str | tzinfo | None = DEFAULT_SITE_TZ
    _zone: tzinfo | None = field(default=None, repr=False, compare=False)

    def __post_init__(self) -> None:
        object.__setattr__(self, "_zone", _coerce_zone(self.site_tz))

    @property
    def zone(self) -> tzinfo | None:
        return self._zone

    @property
    def iana_name(self) -> str | None:
        return None if self._zone is None else getattr(self._zone, "key", str(self._zone))

    def resolve(self, raw_time: str | None) -> ResolvedTime:
        parsed, claimed, note = _parse_time_string(raw_time)
        verbatim = raw_time.strip() if isinstance(raw_time, str) else None
        if parsed is None:
            return ResolvedTime(
                device_local=verbatim,
                utc=None,
                offset_minutes=None,
                tz_source=TzSource.UNRESOLVED,
                iana_tz=self.iana_name,
                reason=note,
            )
        if self._zone is None:
            # Keep and flag. This is the branch that must never fall back to UTC.
            return ResolvedTime(
                device_local=verbatim,
                utc=None,
                offset_minutes=None,
                tz_source=TzSource.UNRESOLVED,
                device_offset_minutes=claimed,
                device_string_naive=parsed.tzinfo is None,
                reason="no site tz configured",
            )
        local, ambiguous, nonexistent = _localize(parsed.replace(tzinfo=None), self._zone)
        used = local.utcoffset()  # never None for a localized datetime; typed as Optional
        return ResolvedTime(
            device_local=verbatim,
            utc=local.astimezone(UTC),
            # The offset we USED — not the one the device claimed.
            offset_minutes=None if used is None else int(used.total_seconds() // 60),
            tz_source=TzSource.SITE_TZ,
            iana_tz=self.iana_name,
            device_offset_minutes=claimed,
            ambiguous=ambiguous,
            nonexistent=nonexistent,
            device_string_naive=parsed.tzinfo is None,
        )


def _coerce_zone(zone: str | tzinfo | None) -> tzinfo | None:
    if zone is None or (isinstance(zone, str) and not zone.strip()):
        return None
    if isinstance(zone, tzinfo):
        return zone
    try:
        return ZoneInfo(zone.strip())
    except (ZoneInfoNotFoundError, ValueError, KeyError) as exc:
        raise TimestampInputError(f"unknown site timezone {zone!r}: {exc}") from None


def _localize(wall: datetime, zone: tzinfo) -> tuple[datetime, bool, bool]:
    """Attach `zone` to a naive wall time; report fold/gap by comparing the two folds.

    `fold=0` for the ambiguous autumn hour is deliberate: it is the *first* occurrence,
    i.e. the DST offset, so a 03:30 punch on the last Sunday of October is the 00:30 UTC
    one. For attendance the ordering matters — crediting the later occurrence would hand
    a worker the extra daylight hour as time worked. Flagged either way.

    Detection is the only honest probe available: build the same wall time at both folds
    and compare UTC. fold-0 earlier ⇒ the time occurs twice (fold); fold-1 earlier ⇒ the
    time was skipped (gap); equal ⇒ an ordinary hour.
    """
    low = wall.replace(tzinfo=zone, fold=0)
    high = wall.replace(tzinfo=zone, fold=1)
    if low.utcoffset() == high.utcoffset():
        return low, False, False
    utc_low, utc_high = low.astimezone(UTC), high.astimezone(UTC)
    if utc_low < utc_high:
        return low, True, False
    if utc_high < utc_low:
        # A gap: zoneinfo keeps the wall time and applies the pre-transition offset. We
        # do NOT shift it into a real hour — a punch cannot legitimately carry a
        # timestamp from a skipped hour, so if one does, the device clock is broken and
        # the flag is the finding, not a correction.
        return low, False, True
    return low, False, False  # pragma: no cover - same wall time cannot differ here


# --- clock skew --------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class Skew:
    """Device wall clock minus our wall clock, in seconds. A log line, never a write."""

    skew_seconds: float | None
    our_wall: datetime | None = None
    device_wall: datetime | None = None
    warn_seconds: float = SKEW_WARN_SECONDS
    reason: str | None = None

    @property
    def available(self) -> bool:
        return self.skew_seconds is not None

    @property
    def warn(self) -> bool:
        return self.skew_seconds is not None and abs(self.skew_seconds) > self.warn_seconds

    @property
    def message(self) -> str | None:
        """The CLI warning line, or None when there is nothing to warn about."""
        if not self.warn:
            return None
        device = self.device_wall.isoformat() if self.device_wall else "?"
        return (
            f"device clock skew {self.skew_seconds:+.1f}s exceeds {self.warn_seconds:.0f}s "
            f"(device wall {device}); not correcting it — setting device time is a device "
            "write and out of P1 scope"
        )


def compute_skew(
    device_time: DeviceTime | None,
    *,
    our_now: datetime | None = None,
    site_tz: str | tzinfo | None = DEFAULT_SITE_TZ,
    warn_seconds: float = SKEW_WARN_SECONDS,
) -> Skew:
    """Compare the device's wall clock to ours, in the site zone.

    Deliberately a *wall-clock* comparison. The device's self-labelled UTC instant is
    built from the offset OBSERVED.md proves is wrong, so comparing instants would report
    that ~1 h tz bug as a 3600 s "clock skew" — a permanent false alarm blaming NTP for a
    tz mistake. The wall clock is the thing verified healthy (~4 s), and the thing whose
    drift actually corrupts punch order.

    `our_now` is injectable so the golden-fixture skew number is a test, not a timestamp.
    """
    now = datetime.now(UTC) if our_now is None else our_now
    if now.tzinfo is None:
        raise TimestampInputError("compute_skew needs a tz-aware our_now")
    zone = _coerce_zone(site_tz)
    our_wall = None if zone is None else now.astimezone(zone).replace(tzinfo=None)
    device_wall = None if device_time is None else device_time.naive_local
    if device_wall is None or our_wall is None:
        reason = (
            "no readable System/time localTime"
            if device_wall is None
            else "no site tz configured, cannot place our clock on the device's wall"
        )
        return Skew(None, our_wall=our_wall, warn_seconds=warn_seconds, reason=reason)
    return Skew(
        skew_seconds=(device_wall - our_wall).total_seconds(),
        our_wall=our_wall,
        device_wall=device_wall,
        warn_seconds=warn_seconds,
    )


# --- CLI-facing timestamps + the device query window -------------------------------


@dataclass(frozen=True, slots=True)
class UserTimestamp:
    """One `--since`/`--until` value, resolved to a tz-aware instant.

    `value` is always tz-aware and always expressed in the site zone when one is
    configured (an offset-given value is converted, not re-interpreted), so p1-08 prints
    one shape for every input. Comparisons are instant-based regardless.
    """

    value: datetime
    source: TzSource
    iana_tz: str | None = None
    ambiguous: bool = False
    input_text: str | None = None


def parse_user_timestamp(
    text: str | None,
    *,
    site_tz: str | tzinfo | None = DEFAULT_SITE_TZ,
    field_name: str = "timestamp",
) -> UserTimestamp:
    """Interpret one operator-supplied timestamp.

    Accepted: ISO-8601 with an offset or `Z` (honoured exactly — the operator said what
    they meant), a naive ISO value (interpreted in the site zone; `--tz` overrides), and
    a bare date (`2026-10-15` → midnight in the site zone, which is what a human means).

    Raises `TimestampInputError` — p1-08 maps that to the config-error exit code. A typo
    in a flag should stop the run, which is why this does not degrade to `unresolved` the
    way event resolution does.
    """
    if text is None or not (value := text.strip()):
        raise TimestampInputError(f"{field_name} is required")
    if len(value) == 10 and _TIME_RE.match(f"{value}T00:00:00"):
        value = f"{value}T00:00:00"
    parsed, offset, note = _parse_time_string(value, field=field_name)
    if parsed is None:
        raise TimestampInputError(f"{field_name} {text!r}: {note}")
    zone = _coerce_zone(site_tz)
    if offset is not None:
        # The operator stated the offset, so it is honoured exactly. Localised into the
        # site zone for display only — `value` is one instant either way, and keeping
        # every UserTimestamp in the same zone means p1-08 never prints two shapes.
        if zone is None:
            return UserTimestamp(parsed.astimezone(UTC), TzSource.STRING_OFFSET, input_text=value)
        return UserTimestamp(
            parsed.astimezone(zone),
            TzSource.STRING_OFFSET,
            getattr(zone, "key", str(zone)),
            input_text=value,
        )
    if zone is None:
        raise TimestampInputError(
            f"{field_name} {text!r} has no UTC offset and no site timezone is configured "
            "(pass --tz, or give the value with an offset)"
        )
    local, ambiguous, nonexistent = _localize(parsed.replace(tzinfo=None), zone)
    if nonexistent:
        raise TimestampInputError(
            f"{field_name} {text!r} is a local time that does not exist in {site_tz!r} "
            "(it falls in the spring DST gap); give an unambiguous value"
        )
    return UserTimestamp(local, TzSource.SITE_TZ, getattr(zone, "key", str(zone)), ambiguous, value)


@dataclass(frozen=True, slots=True)
class DeviceWindow:
    """A `--since/--until` pair in every form the pipeline needs.

    `since_device_local`/`until_device_local` go in the AcsEvent search body:
    **device-naive-wall**, because that is what the device compares `startTime`/`endTime`
    against. The `_site_iso` pair is the same wall time with the *site* offset appended,
    for firmware that insists on an explicit offset (p1-05 should prefer the naive pair
    unless a live run proves otherwise).
    """

    since_utc: datetime
    until_utc: datetime
    since_device_local: str
    until_device_local: str
    since_site_iso: str
    until_site_iso: str
    site_tz: str | None = None

    def search_pair(self, *, with_offset: bool = False) -> tuple[str, str]:
        return (
            (self.since_site_iso, self.until_site_iso)
            if with_offset
            else (self.since_device_local, self.until_device_local)
        )


def window_for_device(
    since: UserTimestamp | datetime,
    until: UserTimestamp | datetime,
    *,
    site_tz: str | tzinfo | None = DEFAULT_SITE_TZ,
) -> DeviceWindow:
    """Build the device query window from two resolved user timestamps.

    Both instants are converted to the site zone and their tzinfo dropped. That is the
    whole trick: the device matches on its own wall clock, and the site zone is where the
    device's (correct) wall clock lives. Sending UTC instead would shift every window by
    the device's offset error and silently drop ~an hour of punches at each boundary.
    """
    zone = _coerce_zone(site_tz)
    if zone is None:
        raise TimestampInputError("cannot build a device window without a site timezone")
    since_dt = _as_aware(since, zone, "--since")
    until_dt = _as_aware(until, zone, "--until")
    if until_dt < since_dt:
        raise TimestampInputError(
            f"--until ({until_dt.isoformat()}) is before --since ({since_dt.isoformat()})"
        )
    since_local, until_local = since_dt.astimezone(zone), until_dt.astimezone(zone)
    return DeviceWindow(
        since_utc=since_dt.astimezone(UTC),
        until_utc=until_dt.astimezone(UTC),
        since_device_local=since_local.replace(tzinfo=None).isoformat(),
        until_device_local=until_local.replace(tzinfo=None).isoformat(),
        since_site_iso=since_local.isoformat(),
        until_site_iso=until_local.isoformat(),
        site_tz=getattr(zone, "key", str(zone)),
    )


def _as_aware(value: UserTimestamp | datetime, zone: tzinfo, field_name: str) -> datetime:
    if isinstance(value, UserTimestamp):
        return value.value
    if value.tzinfo is None:
        # A naive datetime from a caller means "site wall clock", matching the CLI rule.
        local, _amb, nonexistent = _localize(value.replace(tzinfo=None), zone)
        if nonexistent:
            raise TimestampInputError(f"{field_name} {value.isoformat()} falls in a DST gap")
        return local
    return value
