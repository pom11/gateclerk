"""p1-06 — time/tz resolution. Highest test bar in the repo: this is payroll data.

Groups: the policy (device offset never decides UTC), the DST edges, the unresolved
path, the golden device corpus, clock skew, and the device query window round-trip.

Europe/Bucharest DST edges are taken from the tz database as *measured*, not from the
"last Sunday at 02:00" folk rule: in 2026 the gap is local 03:00-03:59 on 29 March and
the fold is local 03:00-03:59 on 25 October (both transitions land at 01:00Z / 02:00Z).
A fixture at 02:30 would silently test nothing — `test_gap_and_fold_are_the_2026_edges`
pins the premise so a future tzdb move fails loudly instead of quietly neutering these.
"""

from __future__ import annotations

import json
import re
from datetime import UTC, datetime, timedelta, timezone
from pathlib import Path
from zoneinfo import ZoneInfo

import pytest

from gateclerk.tz import (
    DEFAULT_SITE_TZ,
    SKEW_WARN_SECONDS,
    DeviceTime,
    DeviceWindow,
    EventTimeResult,
    IsapiPayloadError,
    ResolvedTime,
    Skew,
    TimeResolver,
    TimestampInputError,
    TzSource,
    UserTimestamp,
    compute_skew,
    parse_isapi_xml,
    parse_user_timestamp,
    read_system_time,
    resolve_event_time,
    window_for_device,
)

# `UTC` comes straight from `datetime` (imported above) — the py3.11+ spelling ruff's
# DTZ/UP017 rules push you toward, and an alias of `timezone.utc`.
BUCHAREST = ZoneInfo("Europe/Bucharest")


def naive(
    year: int, month: int, day: int, hour: int = 0, minute: int = 0, second: int = 0
) -> datetime:
    """A deliberately NAIVE wall-clock datetime.

    DTZ001 bans naive datetimes because they are almost always an accident, and in this
    repo a naive timestamp really is a bug — so the rule stays on for tests. But several
    behaviours here are *about* naive input (the site-tz policy interprets a device's
    naive wall clock; `window_for_device` accepts a naive `--since` and reads it in the
    site zone; a DST-gap value must be rejected; `DeviceTime.naive_local` is naive by
    design). Those tests need to construct the naive value on purpose, so they say so
    through this one named helper instead of scattering `# noqa` across call sites and
    hiding which inputs are intentional.
    """
    return datetime(year, month, day, hour, minute, second)  # noqa: DTZ001  -- intentional


FIXTURES = Path(__file__).parent / "fixtures" / "recorded" / "site-a-ds-k1t341amf-s"
SYSTEM_TIME_XML = (FIXTURES / "system_time.xml").read_text(encoding="utf-8")
EVENTS = json.loads((FIXTURES / "events_major5_page1.json").read_text(encoding="utf-8"))


@pytest.fixture
def device_time() -> DeviceTime:
    """The golden `System/time` specimen: correct wall clock, wrong offset label."""
    return read_system_time(SYSTEM_TIME_XML)


@pytest.fixture
def resolver() -> TimeResolver:
    return TimeResolver(site_tz=DEFAULT_SITE_TZ)


# --- 1. the policy: the device's offset never decides UTC --------------------------

POLICY_CASES = [
    # (device string, expected UTC, site offset used, device claim)
    # The bug specimen: device says +02:00 in Bucharest October; the zone says +03:00.
    ("2026-10-12T14:11:16+02:00", "2026-10-12T11:11:16+00:00", 180, 120),
    # Same wall time, different claimed offset -> SAME instant. The label is ignored.
    ("2026-10-12T14:11:16+03:00", "2026-10-12T11:11:16+00:00", 180, 180),
    ("2026-10-12T14:11:16+00:00", "2026-10-12T11:11:16+00:00", 180, 0),
    ("2026-10-12T14:11:16-05:00", "2026-10-12T11:11:16+00:00", 180, -300),
    # Naive string (the other firmware) resolves to the same instant.
    ("2026-10-12T14:11:16", "2026-10-12T11:11:16+00:00", 180, None),
    # Winter: the device label happens to be right.
    ("2026-01-15T14:11:16+02:00", "2026-01-15T12:11:16+00:00", 120, 120),
    # High summer, device still claims its standard offset.
    ("2026-07-01T12:00:00+02:00", "2026-07-01T09:00:00+00:00", 180, 120),
    # A Z-suffixed string is still just a wall time to us.
    ("2026-07-01T12:00:00Z", "2026-07-01T09:00:00+00:00", 180, 0),
]


@pytest.mark.parametrize(("raw", "want_utc", "want_offset", "want_claim"), POLICY_CASES)
def test_policy_site_zone_decides_utc_not_the_device(
    resolver: TimeResolver, raw: str, want_utc: str, want_offset: int, want_claim: int | None
) -> None:
    resolved = resolver.resolve(raw)
    assert resolved.utc is not None
    assert resolved.utc.isoformat() == want_utc
    assert resolved.utc.tzinfo is UTC, "event_time_utc must be tz-aware UTC"
    assert resolved.offset_minutes == want_offset, "the offset we USED"
    assert resolved.device_offset_minutes == want_claim, "the offset the device claimed"
    assert resolved.tz_source is TzSource.SITE_TZ
    assert resolved.iana_tz == "Europe/Bucharest"


def test_policy_both_raws_are_kept_verbatim(resolver: TimeResolver) -> None:
    """DESIGN.md: 'we never discard the raw'. Nothing here is recomputed-and-discarded."""
    raw = "2026-10-12T14:11:16+02:00"
    resolved = resolver.resolve(raw)
    assert resolved.device_local == raw, "the device's exact string, unmodified"
    assert resolved.device_offset_minutes == 120, "and the offset it claimed, for audit"
    assert resolved.utc == datetime(2026, 10, 12, 11, 11, 16, tzinfo=UTC)


def test_trusting_the_device_offset_would_shift_the_punch_by_an_hour(
    resolver: TimeResolver,
) -> None:
    """The regression this card exists for, stated as an inequality.

    OBSERVED.md measured the device stamping +02:00 while the zone was +03:00. An
    implementation that trusted that offset yields 12:11:16Z — one hour late — for every
    summer punch. This fails loudly if anyone reintroduces it.
    """
    resolved = resolver.resolve("2026-10-12T14:11:16+02:00")
    naive_trust = datetime.fromisoformat("2026-10-12T14:11:16+02:00").astimezone(UTC)
    assert resolved.utc is not None and naive_trust != resolved.utc
    assert naive_trust - resolved.utc == timedelta(hours=1)


def test_naive_and_offset_strings_agree_when_intended(resolver: TimeResolver) -> None:
    """DoD: 'naive vs offset fixtures -> same UTC when intended'."""
    forms = [
        "2026-10-12T14:11:16",
        "2026-10-12T14:11:16+02:00",
        "2026-10-12T14:11:16+03:00",
        "2026-10-12T14:11:16-11:00",
        "2026-10-12 14:11:16",
        "2026-10-12T14:11:16.000+02:00",
        "2026-10-12T14:11:16+0200",
    ]
    instants = {resolver.resolve(form).utc for form in forms}
    assert len(instants) == 1, (
        f"one wall time must mean one instant, got {sorted(map(str, instants))}"
    )
    assert instants.pop() == datetime(2026, 10, 12, 11, 11, 16, tzinfo=UTC)


def test_fractional_seconds_are_preserved_not_truncated(resolver: TimeResolver) -> None:
    resolved = resolver.resolve("2026-07-01T12:00:00.250+02:00")
    assert resolved.utc == datetime(2026, 7, 1, 9, 0, 0, 250000, tzinfo=UTC)


def test_site_tz_overrides_to_another_zone() -> None:
    """A site is not hardcoded: the same wall time in another zone is a different instant."""
    resolver = TimeResolver(site_tz="Etc/UTC")
    resolved = resolver.resolve("2026-07-01T12:00:00+02:00")
    assert resolved.utc == datetime(2026, 7, 1, 12, 0, tzinfo=UTC)
    assert resolved.iana_tz == "Etc/UTC"
    assert resolved.offset_minutes == 0


def test_resolver_is_reusable_and_stateless(resolver: TimeResolver) -> None:
    """One resolver per run, used for every event; no bleed between calls."""
    first = resolver.resolve("2026-10-12T14:11:16+02:00")
    _other = resolver.resolve("2026-01-10T09:00:00+02:00")
    assert resolver.resolve("2026-10-12T14:11:16+02:00") == first


def test_record_dict_shape_is_stable_for_p1_07(resolver: TimeResolver) -> None:
    """p1-07/p1-08 consume these keys; renaming one silently drops a payroll column."""
    record = resolver.resolve("2026-10-12T14:11:16+02:00").as_record()
    assert set(record) == {
        "event_time_utc",
        "event_time_local",
        "tz_offset_min",
        "tz_offset_min_device",
        "tz_source",
        "iana_tz",
        "tz_unresolved",
        "tz_ambiguous",
        "tz_nonexistent",
        "tz_reason",
    }
    assert record["event_time_utc"] == "2026-10-12T11:11:16+00:00"
    assert record["event_time_local"] == "2026-10-12T14:11:16+02:00"
    # Both offsets are present so the p1-06c mismatch flag is a comparison of two
    # columns that already exist, not a change to tz.py.
    assert record["tz_offset_min"] == 180
    assert record["tz_offset_min_device"] == 120


# --- 2. DST transition pairs -------------------------------------------------------

DST_PAIRS = [
    pytest.param("2026-03-28T12:00:00", "2026-03-30T12:00:00", id="spring-each-side"),
    pytest.param("2026-10-24T12:00:00", "2026-10-26T12:00:00", id="autumn-each-side"),
]


@pytest.mark.parametrize(("before", "after"), DST_PAIRS)
def test_same_wall_time_different_day_offset(
    resolver: TimeResolver, before: str, after: str
) -> None:
    """A March and an October sample straddling the flip must not get one offset."""
    a, b = resolver.resolve(before), resolver.resolve(after)
    assert a.offset_minutes != b.offset_minutes, (
        f"{before} and {after} both resolved to offset {a.offset_minutes}: "
        "the DST flip is not being exercised"
    )
    assert a.ambiguous is False and b.ambiguous is False
    assert a.nonexistent is False and b.nonexistent is False


def test_march_summer_sample_is_three(resolver: TimeResolver) -> None:
    resolved = resolver.resolve("2026-03-30T12:00:00")
    assert resolved.offset_minutes == 180
    assert resolved.utc == datetime(2026, 3, 30, 9, 0, tzinfo=UTC)


def test_october_winter_sample_is_two(resolver: TimeResolver) -> None:
    resolved = resolver.resolve("2026-10-26T12:00:00")
    assert resolved.offset_minutes == 120
    assert resolved.utc == datetime(2026, 10, 26, 10, 0, tzinfo=UTC)


def test_autumn_fold_picks_the_first_occurrence_and_flags_it(resolver: TimeResolver) -> None:
    """03:30 on 2026-10-25 happens twice. We take the summer (+03:00) pass and flag it.

    Chosen over 'latest possible instant' on purpose: crediting the later pass would hand
    a worker the extra daylight hour as time worked. The flag lets a human adjudicate a
    genuinely ambiguous payroll record instead of us picking silently.
    """
    resolved = resolver.resolve("2026-10-25T03:30:00+02:00")
    assert resolved.ambiguous is True
    assert resolved.offset_minutes == 180, "fold=0 -> the first (DST) pass through 03:30"
    assert resolved.utc == datetime(2026, 10, 25, 0, 30, tzinfo=UTC)
    later = datetime(2026, 10, 25, 3, 30, tzinfo=BUCHAREST, fold=1).astimezone(UTC)
    assert resolved.utc is not None and later - resolved.utc == timedelta(hours=1)


def test_spring_gap_is_flagged_not_silently_shifted(resolver: TimeResolver) -> None:
    """03:30 on 2026-03-29 does not exist in Bucharest. Flag it; do not invent one.

    zoneinfo keeps the wall time and applies the pre-transition offset. We record that
    UTC (a punch must not vanish over a bookkeeping oddity) and set `nonexistent`: a
    device emitting a timestamp from inside a skipped hour has a broken clock, which
    deserves a finding rather than a quiet correction.
    """
    resolved = resolver.resolve("2026-03-29T03:30:00+02:00")
    assert resolved.nonexistent is True
    assert resolved.ambiguous is False
    assert resolved.utc is not None, "kept, not dropped"
    assert resolved.offset_minutes == 120, "pre-transition offset (zoneinfo's fold=0 answer)"
    assert resolved.utc == datetime(2026, 3, 29, 1, 30, tzinfo=UTC)


def test_gap_and_fold_are_the_2026_edges(resolver: TimeResolver) -> None:
    """Guard the fixtures' premise: 02:30 is a normal hour, 03:30 is the edge.

    If a future tzdb moves the Romanian transition, this fails and the DST cases above
    get re-derived — instead of quietly becoming no-ops that assert nothing.
    """
    assert resolver.resolve("2026-03-29T02:30:00+02:00").nonexistent is False
    assert resolver.resolve("2026-03-29T03:30:00+02:00").nonexistent is True
    assert resolver.resolve("2026-10-25T02:30:00+03:00").ambiguous is False
    assert resolver.resolve("2026-10-25T03:30:00+03:00").ambiguous is True


def test_noon_punch_is_never_flagged_across_a_year(resolver: TimeResolver) -> None:
    """Midday is never ambiguous in any real zone — a cheap sweep for false flags."""
    day = naive(2026, 1, 1, 12)
    while day.year == 2026:
        resolved = resolver.resolve(day.isoformat())
        assert resolved.utc is not None, day
        assert resolved.ambiguous is False and resolved.nonexistent is False, day
        day += timedelta(days=1)


def test_tz_is_per_instant_not_per_read() -> None:
    """A January punch is +02 even if we read System/time in October."""
    resolver = TimeResolver(site_tz=DEFAULT_SITE_TZ)
    assert resolver.resolve("2026-01-10T09:00:00+02:00").offset_minutes == 120
    assert resolver.resolve("2026-08-10T09:00:00+02:00").offset_minutes == 180


# --- 3. the unresolved path: keep and flag, never guess ----------------------------

UNPARSABLE = [
    pytest.param("not-a-time", id="garbage"),
    pytest.param("2026-13-45T99:99:99", id="impossible-fields"),
    pytest.param("2026-10-12T14:11:16+99:99", id="absurd-offset"),
    pytest.param("15/10/2026 14:11", id="wrong-order"),
    pytest.param("1760000000", id="epoch-int"),
    pytest.param("2026-10-12", id="date-only-is-not-a-punch"),
    pytest.param("2026-10-12T14", id="partial-time"),
    pytest.param("", id="empty"),
    pytest.param("   ", id="spaces"),
    pytest.param(None, id="none"),
]


@pytest.mark.parametrize("raw", UNPARSABLE)
def test_unparsable_time_is_kept_and_flagged_not_dropped(
    resolver: TimeResolver, raw: str | None
) -> None:
    """DESIGN.md: 'we store it and flag it, we don't guess' — and never default to UTC.

    Also pins that the parser *raises nothing*: an escaping ValueError here would lose
    the punch, which is the failure mode the DoD is written against.
    """
    resolved = resolver.resolve(raw)
    assert resolved.tz_source is TzSource.UNRESOLVED
    assert resolved.utc is None, "never defaulted to UTC"
    assert resolved.resolved is False
    assert resolved.reason, "the operator gets a reason, not a blank"
    if raw:
        assert resolved.device_local == raw.strip(), "the raw is retained even when useless"


def test_date_only_is_unresolved_because_midnight_would_be_a_guess(
    resolver: TimeResolver,
) -> None:
    """`fromisoformat('2026-10-12')` succeeds and means midnight. For a punch that is a lie.

    The CLI is deliberately more lenient (`parse_user_timestamp` accepts a bare date,
    because a human writing `--since 2026-10-12` means midnight) — but an event string
    with no time component is data we must not silently complete.
    """
    resolved = resolver.resolve("2026-10-12")
    assert resolved.utc is None
    assert "not 'YYYY-MM-DDTHH:MM:SS" in (resolved.reason or "")


def test_unresolved_record_marks_the_flag_for_p1_07(resolver: TimeResolver) -> None:
    record = resolver.resolve("nonsense").as_record()
    assert record["tz_unresolved"] is True
    assert record["event_time_utc"] is None
    assert record["event_time_local"] == "nonsense"
    assert record["tz_source"] == "unresolved"


def test_no_site_tz_configured_is_unresolved_not_utc() -> None:
    """`site_tz=None` is a real config state; UTC is the one answer that must not appear."""
    resolver = TimeResolver(site_tz=None)
    resolved = resolver.resolve("2026-10-12T14:11:16+02:00")
    assert resolved.tz_source is TzSource.UNRESOLVED
    assert resolved.utc is None
    assert "no site tz" in (resolved.reason or "")
    # The device's claim is still preserved for audit even though we could not use it.
    assert resolved.device_offset_minutes == 120


def test_empty_string_site_tz_is_unconfigured_not_utc() -> None:
    """`--tz ''` must not become ZoneInfo('') nor silently mean UTC."""
    resolver = TimeResolver(site_tz="")
    assert resolver.zone is None
    assert resolver.resolve("2026-10-12T14:11:16").tz_source is TzSource.UNRESOLVED


def test_unknown_site_tz_is_an_explicit_error_not_a_fallback() -> None:
    """A typo'd --tz should stop the run, not quietly resolve in some other zone."""
    with pytest.raises(TimestampInputError):
        TimeResolver(site_tz="Europe/Bucuresti")


def test_device_naive_punch_string_resolves_via_site_tz(resolver: TimeResolver) -> None:
    """The 'some firmware returns naive local' branch, built from the golden row."""
    real = EVENTS["AcsEvent"]["InfoList"][0]["time"]  # 2026-05-21T14:08:22+02:00
    naive = real[:19]  # what a different firmware would have sent
    a, b = resolver.resolve(real), resolver.resolve(naive)
    assert a.utc == b.utc, "naive and offset forms of the same wall time agree"
    assert b.device_string_naive is True
    assert b.device_offset_minutes is None, "a naive string claims nothing"


# --- 4. the golden device corpus ---------------------------------------------------


def test_all_thirty_golden_punches_resolve() -> None:
    """The whole recorded punch set end to end: no exceptions, no unresolved rows."""
    resolver = TimeResolver(site_tz=DEFAULT_SITE_TZ)
    events = EVENTS["AcsEvent"]["InfoList"]
    assert len(events) == 30
    resolved = [resolver.resolve(e["time"]) for e in events]
    assert all(r.resolved for r in resolved), [r.reason for r in resolved if not r.resolved]
    assert all(r.tz_source is TzSource.SITE_TZ for r in resolved)


def test_every_golden_punch_shows_the_offset_error() -> None:
    """All 30 punches run 2026-05-21..10-12 — entirely inside EEST.

    The device claims +02:00 on every one (OBSERVED.md: its DST rule never engages), so
    used-offset 180 against claimed 120 on 30/30 is the device bug, visible in data.
    When someone fixes the device the claim becomes 180 and nothing else changes — which
    is why the policy records rather than corrects.
    """
    resolver = TimeResolver(site_tz=DEFAULT_SITE_TZ)
    resolved = [resolver.resolve(e["time"]) for e in EVENTS["AcsEvent"]["InfoList"]]
    assert {r.device_offset_minutes for r in resolved} == {120}, "device claims +02:00 always"
    assert {r.offset_minutes for r in resolved} == {180}, "we use +03:00 (EEST)"


def test_golden_punch_utc_order_matches_device_serial_order() -> None:
    """A wrong offset keeps UTC *sorted*, so sorting alone cannot catch the bug.

    Hence the concrete anchors: serial 27 is 2026-05-21T14:08:22 wall -> 11:08:22Z under
    the site policy, and would be 12:08:22Z if anyone trusted the device offset again.
    """
    resolver = TimeResolver(site_tz=DEFAULT_SITE_TZ)
    events = sorted(EVENTS["AcsEvent"]["InfoList"], key=lambda e: e["serialNo"])
    utc = [r for e in events if (r := resolver.resolve(e["time"]).utc) is not None]
    assert len(utc) == len(events), "every golden punch must resolve"
    assert utc == sorted(utc), "punch order must not invert"
    assert utc[0] == datetime(2026, 5, 21, 11, 8, 22, tzinfo=UTC)
    assert utc[-1] == datetime(2026, 10, 12, 11, 12, 35, tzinfo=UTC)


def test_golden_noise_heartbeat_resolves_too() -> None:
    """major=3 noise carries the same broken offset. Classification is p1-04's job; the
    time layer must simply not choke on it."""
    resolver = TimeResolver(site_tz=DEFAULT_SITE_TZ)
    noise = json.loads((FIXTURES / "events_more_noise_page1.json").read_text())["AcsEvent"][
        "InfoList"
    ]
    assert noise, "fixture must have rows"
    resolved = [resolver.resolve(n["time"]) for n in noise]
    assert all(r.utc is not None for r in resolved)
    assert all(r.device_offset_minutes == 120 for r in resolved)


# --- 5. System/time parsing --------------------------------------------------------


def test_golden_system_time_specimen_parsed(device_time: DeviceTime) -> None:
    """The exact specimen OBSERVED.md calls the proof of the offset bug."""
    assert device_time.local_time_raw == "2026-10-15T16:39:32+02:00"
    assert device_time.claimed_offset_minutes == 120, "device claims +02:00 in summer"
    assert device_time.naive_local == naive(2026, 10, 15, 16, 39, 32)
    assert device_time.tz_raw == "CST-2:00:00DST01:00:00,M3.4.1/00:00:00,M10.5.0/23:00:00"
    assert device_time.note is None


def test_system_time_keeps_the_dialect_string_unparsed(device_time: DeviceTime) -> None:
    """The Hikvision tz dialect table is p1-06b; this module only carries the string."""
    assert isinstance(device_time.tz_raw, str) and "CST" in device_time.tz_raw


def test_system_time_missing_fields_degrade_to_a_note_not_an_exception() -> None:
    """A device that omits localTime is a finding to report, not a crash on the punch path."""
    parsed = read_system_time("<?xml version='1.0'?><Time><timeMode>manual</timeMode></Time>")
    assert parsed.naive_local is None
    assert parsed.local_time_raw is None
    assert parsed.note is not None


def test_system_time_bad_time_keeps_what_it_can() -> None:
    parsed = read_system_time(
        "<?xml version='1.0'?><Time><localTime>soon-ish</localTime><timeZone>UTC</timeZone></Time>"
    )
    assert parsed.naive_local is None
    assert parsed.claimed_offset_minutes is None
    assert parsed.tz_raw == "UTC", "the dialect string survives an unparseable clock"
    assert parsed.note is not None


def test_empty_system_time_payload_is_reported() -> None:
    parsed = read_system_time("   ")
    assert parsed.naive_local is None and parsed.note is not None


def test_bytes_payload_is_decoded() -> None:
    parsed = read_system_time(SYSTEM_TIME_XML.encode())
    assert parsed.naive_local == naive(2026, 10, 15, 16, 39, 32)


def test_xml_namespace_is_stripped_when_reading_nodes() -> None:
    """The device emits an ISAPI default namespace; a naive .find('localTime') misses it."""
    parsed = read_system_time(
        '<?xml version="1.0"?><Time version="2.0" '
        'xmlns="http://www.isapi.org/ver20/XMLSchema">'
        "<localTime>2026-01-15T10:00:00+02:00</localTime></Time>"
    )
    assert parsed.claimed_offset_minutes == 120
    assert parsed.naive_local == naive(2026, 1, 15, 10)


def test_xml_guards_refuse_dtd_and_oversize() -> None:
    """We parse XML from a box on the LAN: bound size, refuse entity declarations."""
    with pytest.raises(IsapiPayloadError):
        parse_isapi_xml("<!DOCTYPE Time [<!ENTITY x SYSTEM 'file:///etc/passwd'>]><Time/>")
    with pytest.raises(IsapiPayloadError):
        parse_isapi_xml("<Time>" + "x" * (64 * 1024) + "</Time>")
    with pytest.raises(IsapiPayloadError):
        parse_isapi_xml("<Time><unclosed>")


# --- 6. clock skew -----------------------------------------------------------------

# OBSERVED.md: device said 16:39:32 at real wall time 16:39:36 +03:00.
PROBE_UTC = datetime(2026, 10, 15, 13, 39, 36, tzinfo=UTC)  # == 16:39:36 Bucharest


def test_skew_against_the_live_probe_is_four_seconds(device_time: DeviceTime) -> None:
    """The measured skew was ~4 s: the wall clock is fine, the *label* is wrong."""
    skew = compute_skew(device_time, our_now=PROBE_UTC)
    assert skew.available is True
    assert skew.skew_seconds == pytest.approx(-4.0, abs=0.5)
    assert skew.warn is False, "a healthy clock must not warn"


def test_skew_is_a_wall_clock_comparison_not_an_instant_comparison(
    device_time: DeviceTime,
) -> None:
    """Comparing instants would report the tz bug as a 3600 s skew and page someone.

    The device's self-labelled instant is 14:39:32Z (it believes it is +02:00); ours is
    13:39:36Z. That gap is ~3596 s of *tz config*, not clock drift. The number this
    function returns must be the -4 s wall difference.
    """
    device_instant = datetime(2026, 10, 15, 14, 39, 32, tzinfo=UTC)
    assert (device_instant - PROBE_UTC).total_seconds() == pytest.approx(3596.0)
    assert compute_skew(device_time, our_now=PROBE_UTC).skew_seconds == pytest.approx(-4.0, abs=0.5)


def test_skew_warns_past_the_threshold(device_time: DeviceTime) -> None:
    """A 3-minute-slow device is real drift and must warn (>120 s per the card)."""
    skew = compute_skew(device_time, our_now=datetime(2026, 10, 15, 13, 36, tzinfo=UTC))
    assert skew.skew_seconds == pytest.approx(212.0, abs=0.5)
    assert skew.warn is True
    assert "212" in (skew.message or "")


def test_skew_warns_for_a_device_ahead_and_behind(device_time: DeviceTime) -> None:
    ahead = compute_skew(device_time, our_now=datetime(2026, 10, 15, 13, 30, tzinfo=UTC))
    behind = compute_skew(device_time, our_now=datetime(2026, 10, 15, 14, 50, tzinfo=UTC))
    assert ahead.skew_seconds is not None and ahead.skew_seconds > SKEW_WARN_SECONDS
    assert behind.skew_seconds is not None and behind.skew_seconds < -SKEW_WARN_SECONDS
    assert ahead.warn and behind.warn
    assert ahead.message is not None and behind.message is not None


def test_skew_threshold_is_the_documented_120_seconds(device_time: DeviceTime) -> None:
    assert SKEW_WARN_SECONDS == 120.0
    exact = compute_skew(device_time, our_now=datetime(2026, 10, 15, 13, 39, 32, tzinfo=UTC))
    assert exact.skew_seconds == pytest.approx(0.0, abs=0.5)
    assert exact.warn is False
    boundary = compute_skew(device_time, our_now=PROBE_UTC, warn_seconds=4.0)
    assert boundary.warn is False, "exactly at the threshold is not 'over' it"


def test_skew_message_never_promises_a_fix(device_time: DeviceTime) -> None:
    """Setting device time is a write — DESIGN.md forbids it in P1. The text must say so."""
    message = compute_skew(device_time, our_now=datetime(2026, 10, 15, 12, 0, tzinfo=UTC)).message
    assert message is not None
    assert "write" in message and "out of P1 scope" in message


def test_skew_without_a_readable_clock_is_unavailable_not_zero() -> None:
    """A device we cannot read must not look perfectly in-sync."""
    for device in (None, read_system_time("<Time></Time>")):
        skew = compute_skew(device, our_now=PROBE_UTC)
        assert skew.available is False
        assert skew.skew_seconds is None
        assert skew.warn is False
        assert skew.reason


def test_skew_with_no_site_tz_refuses_to_guess(device_time: DeviceTime) -> None:
    """Without the site zone we cannot place our clock on the device's wall."""
    skew = compute_skew(device_time, our_now=PROBE_UTC, site_tz=None)
    assert skew.available is False and skew.skew_seconds is None


def test_skew_rejects_a_naive_our_now(device_time: DeviceTime) -> None:
    with pytest.raises(TimestampInputError):
        compute_skew(device_time, our_now=naive(2026, 10, 15, 13, 39))


def test_skew_reads_our_clock_when_not_given(device_time: DeviceTime) -> None:
    """`our_now=None` is the production path; it must read the clock in the SITE zone.

    Asserted against an independent computation rather than a bound: the fixture's wall
    time is a fixed historical instant, so 'how far off is it from now' grows all day and
    any magnitude bound would be a flaky test. What must hold is that our side of the
    subtraction is the site-zone wall clock.
    """
    skew = compute_skew(device_time)
    assert isinstance(skew, Skew) and skew.available and skew.skew_seconds is not None
    expected_wall = datetime.now(UTC).astimezone(BUCHAREST).replace(tzinfo=None)
    assert device_time.naive_local is not None
    independent = (device_time.naive_local - expected_wall).total_seconds()
    assert abs(independent - skew.skew_seconds) < 2.0


def test_skew_our_clock_is_placed_in_the_site_zone(device_time: DeviceTime) -> None:
    """Reading our clock in UTC instead of the site zone shifts the skew by the offset.

    That mistake would make every correctly-synced Romanian device look ~2-3 hours slow
    and fire the warning on every run.
    """
    at_site = compute_skew(device_time, our_now=PROBE_UTC, site_tz=DEFAULT_SITE_TZ)
    in_utc = compute_skew(device_time, our_now=PROBE_UTC, site_tz="Etc/UTC")
    assert at_site.skew_seconds is not None and in_utc.skew_seconds is not None
    assert in_utc.skew_seconds - at_site.skew_seconds == pytest.approx(3 * 3600.0)


# --- 7. CLI timestamps + the device query window round-trip ------------------------


@pytest.mark.parametrize(
    ("text", "want_instant", "source"),
    [
        # An offset in the argument is honoured exactly, not re-read in the site zone.
        (
            "2026-10-12T14:11:16+05:00",
            datetime(2026, 10, 12, 9, 11, 16, tzinfo=UTC),
            TzSource.STRING_OFFSET,
        ),
        (
            "2026-10-12T14:11:16Z",
            datetime(2026, 10, 12, 14, 11, 16, tzinfo=UTC),
            TzSource.STRING_OFFSET,
        ),
        # A naive value is read in the site zone: July is EEST (+03), January is EET (+02).
        ("2026-07-01T12:00:00", datetime(2026, 7, 1, 9, 0, tzinfo=UTC), TzSource.SITE_TZ),
        ("2026-01-15T12:00:00", datetime(2026, 1, 15, 10, 0, tzinfo=UTC), TzSource.SITE_TZ),
        # A bare date means midnight in the site zone — what a human writing it means.
        ("2026-07-01", datetime(2026, 6, 30, 21, 0, tzinfo=UTC), TzSource.SITE_TZ),
    ],
)
def test_cli_timestamp_forms(text: str, want_instant: datetime, source: TzSource) -> None:
    parsed = parse_user_timestamp(text)
    # Compare in UTC, never across zones with `==`: for a zoneinfo fold-affected wall time
    # CPython's `==` and `-` disagree (see test_fold_aware_comparison_trap below), so
    # cross-zone equality is not a safe payroll assertion.
    assert parsed.value.astimezone(UTC) == want_instant, text
    assert parsed.value.tzinfo is not None, "always tz-aware"
    assert parsed.source is source


def test_timestamps_are_compared_via_astimezone_not_across_zones() -> None:
    """The convention every instant assertion here follows.

    Observed on this interpreter (CPython 3.12, tzdata 2026): for the two fold variants of
    one Bucharest wall time, `==` returns True while `astimezone(UTC)` shows they are an
    hour apart, and `a == utc_instant` returns False while `a - utc_instant` is zero.
    Whether or not that is ever "fixed", this repo compares payroll instants only after
    normalising to a fixed-offset zone, and discriminates a fold by `utcoffset()`. The
    assertions below state exactly what the tests rely on, so a CPython change cannot
    make this suite lie — or fail for no reason.
    """
    first_pass = datetime(2026, 10, 25, 3, 30, tzinfo=BUCHAREST, fold=0)
    second_pass = datetime(2026, 10, 25, 3, 30, tzinfo=BUCHAREST, fold=1)
    expected = datetime(2026, 10, 25, 0, 30, tzinfo=UTC)
    # The two fold variants are genuinely one hour apart...
    assert first_pass.astimezone(UTC) == expected
    assert second_pass.astimezone(UTC) == expected + timedelta(hours=1)
    # ...and `utcoffset()` is the reliable discriminator between them.
    assert first_pass.utcoffset() == timedelta(hours=3)
    assert second_pass.utcoffset() == timedelta(hours=2)


def test_cli_tz_overrides_the_default_zone() -> None:
    parsed = parse_user_timestamp("2026-07-01T12:00:00", site_tz="Etc/UTC")
    assert parsed.value.isoformat() == "2026-07-01T12:00:00+00:00"
    assert parsed.iana_tz == "Etc/UTC"


@pytest.mark.parametrize("text", ["", "   ", None, "yesterday", "2026-13-01T00:00:00", "garbage"])
def test_cli_rejects_junk_with_a_config_error(text: str | None) -> None:
    """A typo in a flag must stop the run — unlike a weird device string."""
    with pytest.raises(TimestampInputError):
        parse_user_timestamp(text)


def test_cli_rejects_a_spring_gap_value() -> None:
    """An operator cannot ask for a window that starts in a skipped hour."""
    with pytest.raises(TimestampInputError) as exc:
        parse_user_timestamp("2026-03-29T03:30:00")
    assert "does not exist" in str(exc.value)


def test_cli_flags_an_ambiguous_window_start() -> None:
    """The autumn fold is accepted (it is a real instant) but flagged, not silently picked."""
    parsed = parse_user_timestamp("2026-10-25T03:30:00")
    assert parsed.ambiguous is True
    # `utcoffset()` is the unambiguous discriminator here; `==` against a UTC instant is
    # not, for fold-affected zoneinfo wall times (see test_fold_aware_comparison_trap).
    assert parsed.value.utcoffset() == timedelta(hours=3), "fold=0 -> the first, DST pass"
    assert parsed.value.astimezone(UTC) == datetime(2026, 10, 25, 0, 30, tzinfo=UTC)


def test_cli_naive_value_without_a_site_tz_is_an_error() -> None:
    with pytest.raises(TimestampInputError) as exc:
        parse_user_timestamp("2026-07-01T12:00:00", site_tz=None)
    assert "--tz" in str(exc.value)


def test_window_is_built_in_device_naive_wall_terms() -> None:
    """The device filters startTime/endTime against its own wall clock.

    So the query strings are the site-zone wall times with tzinfo dropped. Sending UTC
    (or the site-offset-corrected instant) would shift every window by the device's
    offset error — ~an hour of punches silently missing at each boundary in summer.
    """
    since = parse_user_timestamp("2026-10-12T00:00:00")
    until = parse_user_timestamp("2026-10-12T23:59:59")
    window = window_for_device(since, until)
    assert isinstance(window, DeviceWindow)
    assert window.since_device_local == "2026-10-12T00:00:00"
    assert window.until_device_local == "2026-10-12T23:59:59"
    # The UTC pair is 3 h earlier: those are NOT what we send.
    assert window.since_utc.isoformat() == "2026-10-11T21:00:00+00:00"
    # The with-offset form carries the *site* offset, and the same wall clock reading.
    assert window.since_site_iso == "2026-10-12T00:00:00+03:00"
    assert window.search_pair() == (window.since_device_local, window.until_device_local)
    assert window.search_pair(with_offset=True) == (window.since_site_iso, window.until_site_iso)


def test_window_round_trips_through_the_resolver() -> None:
    """The round-trip the operator asked for.

    A punch whose wall time is inside the window we send must also resolve (via the
    site zone) to an instant inside the same window's UTC span. This is the property
    that breaks if the window is built in UTC, or if the resolver ever trusts the
    device's +02:00 label: the two would drift an hour apart in summer and the device
    would return rows our own filter then discards.
    """
    resolver = TimeResolver(site_tz=DEFAULT_SITE_TZ)
    since = parse_user_timestamp("2026-10-12T00:00:00")
    until = parse_user_timestamp("2026-10-12T23:59:59")
    window = window_for_device(since, until)

    # The window strings sent to the device, taken as device wall times, must be exactly
    # the site-zone wall times of the UTC bounds.
    assert datetime.fromisoformat(window.since_device_local) == since.value.astimezone(
        BUCHAREST
    ).replace(tzinfo=None)
    assert datetime.fromisoformat(window.until_device_local) == until.value.astimezone(
        BUCHAREST
    ).replace(tzinfo=None)

    # Every golden punch inside the device-window lands inside the UTC window too.
    inside = 0
    for event in EVENTS["AcsEvent"]["InfoList"]:
        wall = datetime.fromisoformat(event["time"]).replace(tzinfo=None)
        if window.since_device_local <= wall.isoformat() <= window.until_device_local:
            resolved = resolver.resolve(event["time"])
            assert resolved.utc is not None
            assert window.since_utc <= resolved.utc <= window.until_utc, event["time"]
            inside += 1
    assert inside > 0, "the round-trip test must actually cover rows"


def test_window_round_trip_across_both_dst_transitions() -> None:
    """Same property on the two days where an offset mistake is most likely to bite."""
    resolver = TimeResolver(site_tz=DEFAULT_SITE_TZ)
    for day, utc_start, wall_probe in (
        # Springs forward at 03:00 local: midnight is still EET (+02) -> 22:00Z prev day.
        ("2026-03-29", "2026-03-28T22:00:00+00:00", "2026-03-29T12:00:00+02:00"),
        # Falls back at 03:00 local: midnight is still EEST (+03) -> 21:00Z prev day.
        ("2026-10-25", "2026-10-24T21:00:00+00:00", "2026-10-25T12:00:00+02:00"),
    ):
        since = parse_user_timestamp(day)
        until = parse_user_timestamp(f"{day}T23:59:59")
        window = window_for_device(since, until)
        assert window.since_utc.isoformat() == utc_start, day
        assert window.since_device_local == f"{day}T00:00:00", day
        # The device would echo a wall time like `wall_probe`; it must fall inside the
        # window we sent AND resolve inside the same window's UTC span.
        resolved = resolver.resolve(wall_probe)
        assert resolved.utc is not None
        wall = datetime.fromisoformat(wall_probe).replace(tzinfo=None).isoformat()
        assert window.since_device_local <= wall <= window.until_device_local, wall_probe
        assert window.since_utc <= resolved.utc <= window.until_utc, wall_probe


def test_window_rejects_a_reversed_range() -> None:
    since = parse_user_timestamp("2026-10-12")
    until = parse_user_timestamp("2026-10-11")
    with pytest.raises(TimestampInputError) as exc:
        window_for_device(since, until)
    assert "before --since" in str(exc.value)


def test_window_rejects_a_naive_datetime_in_a_dst_gap() -> None:
    since = naive(2026, 3, 29, 3, 30)
    until = naive(2026, 3, 29, 12)
    with pytest.raises(TimestampInputError):
        window_for_device(since, until)


def test_window_without_a_site_tz_is_an_error() -> None:
    with pytest.raises(TimestampInputError):
        window_for_device(naive(2026, 10, 12), naive(2026, 10, 13), site_tz=None)


# --- 8. offline + hygiene invariants this module must not break --------------------


def test_module_never_opens_a_socket(device_time: DeviceTime) -> None:
    """conftest's autouse netoff makes any socket use raise; resolve everything here."""
    resolver = TimeResolver(site_tz=DEFAULT_SITE_TZ)
    assert resolver.resolve("2026-10-12T14:11:16+02:00").utc is not None
    assert read_system_time(SYSTEM_TIME_XML).naive_local is not None
    assert compute_skew(device_time).available is True


def test_public_surface_is_what_the_downstream_cards_need() -> None:
    """Names p1-05/p1-07/p1-08 import. Renaming one is a cross-card break, so pin them."""
    for name in (
        TimeResolver,
        ResolvedTime,
        DeviceTime,
        DeviceWindow,
        Skew,
        UserTimestamp,
        TzSource,
        TimestampInputError,
        read_system_time,
        parse_isapi_xml,
        compute_skew,
        parse_user_timestamp,
        window_for_device,
    ):
        assert name is not None


def test_default_site_tz_matches_the_card_and_config_plan() -> None:
    assert DEFAULT_SITE_TZ == "Europe/Bucharest"
    assert TimeResolver().site_tz == DEFAULT_SITE_TZ


# --- 9. unpadded clock components (review #1 on PR #2) -----------------------------
#
# `2026-10-15T7:46:48` used to land as `unresolved` purely because of a zero-padding
# quirk. OBSERVED.md has never *seen* unpadded output, so this is defensive — but the
# failure mode is the one we cannot see later: a payroll gap that presents as
# `tz_source=unresolved` and silently shrinks the set. Relaxing the shape test is only
# half the fix; the second half (padding before `fromisoformat`) is pinned below,
# because without it the relaxation changes nothing.


def test_fromisoformat_alone_cannot_take_an_unpadded_time() -> None:
    """Why `_normalize_time_string` exists: the stdlib parser is stricter than we are.

    `datetime.fromisoformat` accepts `2026-10-15T07:46:48` and raises ValueError on
    `2026-10-15T7:46:48` (measured on the CI interpreter, py3.12). So widening `_TIME_RE`
    without padding first would hand the string to a parser that rejects it and leave the
    punch `unresolved` all the same — the one-line fix this review asked for is a no-op
    without the padding step. If CPython ever relaxes this, the test still passes: it only
    pins that *we* never hand it an unpadded value.
    """
    with pytest.raises(ValueError):
        datetime.fromisoformat("2026-10-15T7:46:48")
    # And the padded form is fine — the difference is padding, not the wall time.
    assert datetime.fromisoformat("2026-10-15T07:46:48") == naive(2026, 10, 15, 7, 46, 48)


def test_unpadded_hour_is_not_an_unresolved_punch(resolver: TimeResolver) -> None:
    """The operator's exact specimen must resolve, with the site offset applied."""
    resolved = resolver.resolve("2026-10-15T7:46:48+02:00")
    assert resolved.resolved is True, resolved.reason
    assert resolved.tz_source is TzSource.SITE_TZ
    assert resolved.offset_minutes == 180  # 15 Oct is EEST (+03)
    assert resolved.utc == datetime(2026, 10, 15, 4, 46, 48, tzinfo=UTC)
    assert resolved.device_offset_minutes == 120, "the claim is still recorded"


def test_unpadded_forms_agree_with_the_padded_form(resolver: TimeResolver) -> None:
    """One wall time, one instant — padding is a rendering detail, never a reading."""
    padded = resolver.resolve("2026-10-15T07:46:48+02:00")
    for form in (
        "2026-10-15T7:46:48+02:00",
        "2026-10-15T7:46:48",
        "2026-10-15 7:46:48",
        "2026-10-15T7:46:48.000+02:00",
        "2026-10-15T07:46:48.0+02:00",
    ):
        resolved = resolver.resolve(form)
        assert resolved.resolved is True, (form, resolved.reason)
        assert resolved.utc == padded.utc, form
    # Minutes and seconds go either way too, and HH:MM still means :00 seconds.
    assert resolver.resolve("2026-10-15T7:6:5").utc == datetime(2026, 10, 15, 4, 6, 5, tzinfo=UTC)
    assert resolver.resolve("2026-10-15T7:6").utc == datetime(2026, 10, 15, 4, 6, tzinfo=UTC)


def test_unpadded_components_never_shift_a_reading(resolver: TimeResolver) -> None:
    """`7:46` is 07:46, not a re-reading of the field. Guarded per digit, not by trust.

    Padding is `int(x)` then `%02d`, so a single digit cannot land in the neighbouring
    field ('7:6' -> 07:06). Asserting each component separately keeps a future
    normalizer rewrite from passing on a wrong-but-plausible instant.
    """
    resolved = resolver.resolve("2026-10-15T7:6:5+03:00")
    assert resolved.utc is not None
    as_utc = resolved.utc
    assert (as_utc.hour, as_utc.minute, as_utc.second) == (4, 6, 5)
    assert resolved.device_local == "2026-10-15T7:6:5+03:00", "verbatim, unpadded as sent"


def test_fractional_seconds_survive_the_padding(resolver: TimeResolver) -> None:
    """Padding touches h/m/s only — the fraction is passed through untouched."""
    assert resolver.resolve("2026-10-15T7:46:48.25+02:00").utc == datetime(
        2026, 10, 15, 4, 46, 48, 250000, tzinfo=UTC
    )
    assert resolver.resolve("2026-10-15T7:46:48.000123+02:00").utc == datetime(
        2026, 10, 15, 4, 46, 48, 123, tzinfo=UTC
    )


def test_out_of_range_components_are_still_unresolved(resolver: TimeResolver) -> None:
    r"""Loosening the SHAPE must not loosen the RANGES — fromisoformat still validates.

    Without this, `\d{1,2}` plus sloppy padding could quietly start accepting `25:00`
    or `12:99` as a punch. They stay `unresolved`, for the *value* reason, not the
    shape reason.
    """
    for bad in (
        "2026-10-15T25:00:00",
        "2026-10-15T12:60:00",
        "2026-10-15T12:00:60",
        "2026-13-01T07:00:00",
        "2026-10-32T07:00:00",
    ):
        resolved = resolver.resolve(bad)
        assert resolved.tz_source is TzSource.UNRESOLVED, (bad, resolved.utc)
        assert resolved.utc is None, bad
        assert "valid timestamp" in (resolved.reason or ""), (bad, resolved.reason)


def test_unpadded_golden_corpus_resolves_to_the_same_instants(resolver: TimeResolver) -> None:
    """Every recorded punch, with leading zeros stripped, means the same instant.

    Built from the golden rows rather than a hand-written example, so a firmware that
    ever emits `9:08:22` or `14:8:22` cannot cost us a payroll row. Rows whose components
    are all two-digit (14:18:36) have nothing to strip and are asserted unchanged; the
    coverage guard below proves the unpadded path really is exercised by this corpus.
    """
    events = EVENTS["AcsEvent"]["InfoList"]
    assert len(events) == 30
    # Rebuild h/m/s through int() so a leading zero is dropped and nothing else moves.
    # Deliberately NOT a blanket '0' strip: the same pattern would eat the offset
    # ('+02:00' -> '+02:0') and test a string shape no firmware emits.
    shape = re.compile(
        r"^(?P<date>\d{4}-\d{2}-\d{2})(?P<sep>[T ])"
        r"(?P<h>\d{1,2}):(?P<m>\d{1,2}):(?P<s>\d{1,2})(?P<rest>.*)$"
    )
    exercised = 0
    mangled_rows = []
    for event in events:
        raw = event["time"]  # e.g. 2026-05-21T14:08:22+02:00
        want = resolver.resolve(raw)
        assert want.utc is not None, raw
        match = shape.match(raw)
        assert match is not None, raw
        parts = match.groupdict()
        mangled = (
            f"{parts['date']}{parts['sep']}"
            f"{int(parts['h'])}:{int(parts['m'])}:{int(parts['s'])}{parts['rest']}"
        )
        if mangled != raw:
            exercised += 1
            mangled_rows.append(mangled)
        got = resolver.resolve(mangled)
        assert got.utc == want.utc, (raw, mangled, got.reason)
        assert got.device_local == mangled, "the row keeps the string the device sent"
    assert exercised > 0, "the corpus must actually exercise the unpadded path"
    # A named specimen rather than a magic count: the first golden row has minute '08',
    # so it is guaranteed to be one of the rewritten ones. Pinning the row survives a
    # corpus swap without hardcoding how many rows happen to have a leading zero.
    assert "2026-05-21T14:8:22+02:00" in mangled_rows


def test_cli_accepts_an_unpadded_window_bound() -> None:
    """The CLI uses the same parser, so `--since 2026-10-15T7:00` works too.

    It was a hard `TimestampInputError` before (typo-or-not is undecidable in a flag),
    which would have made the operator's own command line fail on a value that is not a
    typo. The spring-gap rejection still wins over leniency.
    """
    parsed = parse_user_timestamp("2026-10-15T7:46:48")
    assert parsed.value.astimezone(UTC) == datetime(2026, 10, 15, 4, 46, 48, tzinfo=UTC)
    assert parsed.source is TzSource.SITE_TZ
    with pytest.raises(TimestampInputError):
        parse_user_timestamp("2026-03-29T3:30:00")  # still the DST gap, still refused


def test_window_for_device_survives_unpadded_bounds() -> None:
    """A window built from unpadded input still goes out in the device's padded form."""
    since = parse_user_timestamp("2026-10-15T7:00:00")
    until = parse_user_timestamp("2026-10-15T23:59:59")
    window = window_for_device(since, until)
    assert window.since_device_local == "2026-10-15T07:00:00"
    assert window.since_site_iso == "2026-10-15T07:00:00+03:00"


# --- 10. the XML guard has to be complete (reviewer finding on PR #2) ---------------


def test_xml_guard_catches_a_dtd_past_the_head_window() -> None:
    """A DTD after 16 kB of padding used to walk straight into the parser.

    The first version scanned `payload[:MAX//4]` for `<!DOCTYPE`/`<!ENTITY` and the
    reviewer's probe put the bomb at offset 20 000: it passed the guard and ElementTree
    EXPANDED the internal entities (a 4x4x4 nesting came back as 64 characters, so the
    expansion is real, not theoretical). The scan is now over the whole payload; this is
    the regression pin.
    """
    bomb = (
        '<!DOCTYPE Time [<!ENTITY a "aaaa">'
        '<!ENTITY b "&a;&a;&a;&a;"><!ENTITY c "&b;&b;&b;&b;">]>'
        "<Time><x>&c;</x></Time>"
    )
    for pad_len in (0, 5_000, 20_000, 60_000):
        payload = f'<?xml version="1.0"?><!--{"p" * pad_len}-->{bomb}'
        assert len(payload) < 64 * 1024, pad_len
        with pytest.raises(IsapiPayloadError) as exc:
            parse_isapi_xml(payload)
        assert "DTD or entity" in str(exc.value), pad_len


def test_read_system_time_refuses_a_padded_dtd_payload() -> None:
    """Same wall, one level up: the System/time reader must not parse it either."""
    payload = f'<?xml version="1.0"?><!--{"p" * 20_000}--><!DOCTYPE Time><Time/>'
    with pytest.raises(IsapiPayloadError):
        read_system_time(payload)


# --- 11. resolve_event_time: the p1-06d façade (thin view, no second policy) --------

#: site-a's real summer punch shape (OBSERVED.md): wall 16:39, claim +02:00, real +03:00.
SUMMER_OFFSET_BEARING = "2026-10-15T16:39:00+02:00"


def test_facade_utc_is_bit_for_bit_the_resolvers_answer() -> None:
    """The façade must not re-decide anything: same wall+zone -> identical instant."""
    inner = TimeResolver(site_tz=BUCHAREST).resolve(SUMMER_OFFSET_BEARING)
    result = resolve_event_time(SUMMER_OFFSET_BEARING, BUCHAREST, claimed_offset_min=120)
    assert isinstance(result, EventTimeResult)
    assert result.utc == inner.utc
    assert result.tz_source is inner.tz_source
    assert result.utc == datetime(2026, 10, 15, 13, 39, tzinfo=UTC)


def test_wall_naive_is_the_naive_wall_part_the_utc_was_built_from() -> None:
    """The field exists so a reviewer can see which wall time produced the instant."""
    result = resolve_event_time(SUMMER_OFFSET_BEARING, BUCHAREST)
    assert result.wall_naive == naive(2026, 10, 15, 16, 39)
    assert result.wall_naive is not None and result.wall_naive.tzinfo is None
    # The claimed +02:00 is NOT what produced the instant: the site zone said +03:00.
    assert result.utc == datetime(2026, 10, 15, 13, 39, tzinfo=UTC)


def test_site_a_golden_case_flags_the_mismatch_without_moving_the_instant() -> None:
    """OBSERVED.md's real bug through the façade: claim +02:00, zone +03:00.

    The point of the whole card: the flag fires *and* the math is untouched. If a future
    edit made the façade trust the claim, both assertions cannot hold at once.
    """
    result = resolve_event_time(SUMMER_OFFSET_BEARING, BUCHAREST, claimed_offset_min=120)
    assert result.mismatch is True
    assert result.claimed_offset_min == 120
    assert result.tz_source is TzSource.SITE_TZ
    assert result.utc == datetime(2026, 10, 15, 13, 39, tzinfo=UTC)


def test_claimed_offset_defaults_to_the_strings_own_stamp() -> None:
    """No caller claim -> the string's +02:00 IS the claim, so the flag still fires.

    Silently treating "no caller claim" as "no claim" would report `mismatch=None` for
    site-a's exact bug — the one thing this flag exists to surface.
    """
    from_string = resolve_event_time(SUMMER_OFFSET_BEARING, BUCHAREST)
    assert from_string.claimed_offset_min == 120
    assert from_string.mismatch is True
    explicit = resolve_event_time(SUMMER_OFFSET_BEARING, BUCHAREST, claimed_offset_min=120)
    assert from_string.utc == explicit.utc


def test_winter_claim_that_agrees_is_false_not_none() -> None:
    """+02:00 is correct in January: agreement must be distinguishable from absence."""
    result = resolve_event_time("2026-01-15T10:00:00+02:00", BUCHAREST)
    assert result.mismatch is False
    assert result.utc == datetime(2026, 1, 15, 8, 0, tzinfo=UTC)


def test_naive_string_has_no_claim_so_the_flag_is_none() -> None:
    """Naive wall time -> nothing was claimed -> None, never False (payroll honesty)."""
    result = resolve_event_time("2026-10-15T16:39:00", BUCHAREST)
    assert result.mismatch is None
    assert result.claimed_offset_min is None
    assert result.tz_source is TzSource.SITE_TZ
    assert result.utc == datetime(2026, 10, 15, 13, 39, tzinfo=UTC)


def test_garbage_input_is_unresolved_and_never_assumes_utc() -> None:
    """Card's garbage case: kept as text, no instant invented, nothing compared."""
    for raw in ("", "not-a-time", "2026-13-45T99:99:99"):
        result = resolve_event_time(raw, BUCHAREST, claimed_offset_min=120)
        assert result.tz_source is TzSource.UNRESOLVED, raw
        assert result.utc is None, raw
        assert result.wall_naive is None, raw
        assert result.mismatch is None, raw


def test_missing_site_tz_stays_unresolved_without_raising() -> None:
    """DESIGN.md item 4: no site zone -> flag it, don't guess UTC and don't crash.

    An unknown zone NAME is different: the operator misconfigured the site, and
    `_coerce_zone` raises — silence there would hide a broken payroll config.
    """
    for zone in (None, ""):
        result = resolve_event_time(SUMMER_OFFSET_BEARING, zone, claimed_offset_min=120)
        assert result.tz_source is TzSource.UNRESOLVED, zone
        assert result.utc is None and result.mismatch is None, zone
    with pytest.raises(TimestampInputError):
        resolve_event_time(SUMMER_OFFSET_BEARING, "Mars/Olympus_Mons")


def test_facade_honours_the_fold_0_choice_through_the_wrapper() -> None:
    """The p1-06 fold=0 pin, seen through the façade rather than only at the resolver.

    A wrapper that re-derived its own instant could silently pick the *second* pass
    through the autumn fold and hand a worker a free daylight hour.
    """
    result = resolve_event_time("2026-10-25T03:30:00", BUCHAREST)
    assert result.utc == datetime(2026, 10, 25, 0, 30, tzinfo=UTC)
    assert result.wall_naive == naive(2026, 10, 25, 3, 30)
    assert result.mismatch is None, "naive string: nothing claimed, nothing to compare"


def test_non_iana_zone_object_is_passed_through_intact() -> None:
    """A fixed-offset tzinfo must reach the detector as an object, not a stringified key."""
    result = resolve_event_time(SUMMER_OFFSET_BEARING, timezone(timedelta(hours=4)), 120)
    assert result.utc == datetime(2026, 10, 15, 12, 39, tzinfo=UTC)
    assert result.mismatch is True, "claim +02:00 vs a +04:00 site zone"
