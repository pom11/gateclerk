"""Round-trip: window_for_device() -> device filter -> resolver -> punch survives (p1-04).

Orchestrator note (2026-10-16): p1-06 owns `gateclerk.tz.window_for_device()` and has
boundary tests for ordinary days and both DST edges; THIS file covers the same contract
over **real AcsEvent bodies** — the recorded site-a `InfoList` records — because the
seam where punches get lost is exactly between the two modules:

    user instants --window_for_device--> device-naive wall strings
        --(device filters on its naive clock)--> records survive
    record `time` string --TimeResolver(site tz)--> UTC

The device's wall clock is correct and its offset label is wrong (OBSERVED.md), so the
window MUST be built in device-naive-wall terms; a UTC-based window would shift every
query by the offset error and silently drop ~an hour of punches per boundary. These
tests assert the naive pair is what we send and that golden punches land inside it.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

from gateclerk.event_codes import classify_batch
from gateclerk.tz import TimeResolver, parse_user_timestamp, window_for_device

RECORDED = Path(__file__).parent / "fixtures/recorded/site-a-ds-k1t341amf-s"
SITE_TZ = "Europe/Bucharest"


def golden_events() -> list[dict]:
    page = json.loads((RECORDED / "events_major5_page1.json").read_text(encoding="utf-8"))
    return page["AcsEvent"]["InfoList"]


def naive_of(time_str: str) -> str:
    """The wall part the device compares startTime/endTime against.

    Mirrors the device's own server-side filter: it compares the naive wall clock, so we
    filter the same way to predict which records the search would return. (All device
    strings here are ISO with seconds, so lexicographic compare is wall-time compare.)
    """
    return time_str[:19]


def survives(record: dict, since_naive: str, until_naive: str) -> bool:
    return since_naive <= naive_of(record["time"]) <= until_naive


# --- the golden window ---------------------------------------------------------------------


def test_golden_october_window_in_device_naive_terms_keeps_the_triple_and_resolves_utc() -> None:
    since = parse_user_timestamp("2026-10-12T14:11:00", site_tz=SITE_TZ)
    until = parse_user_timestamp("2026-10-12T14:11:16", site_tz=SITE_TZ)
    window = window_for_device(since, until, site_tz=SITE_TZ)

    # What we put on the wire: naive wall strings, no offset — the pair DESIGN.md/p1-06
    # say to prefer; the device compares these against its own naive clock.
    start, end = window.search_pair()
    assert start == "2026-10-12T14:11:00" and end == "2026-10-12T14:11:16"

    kept = [e for e in golden_events() if survives(e, start, end)]
    assert kept, "the golden 14:11:16 pass + lock-open must be inside the window"
    # 5742 (pass, 75) and 5743 (lock-open, 21) are at 14:11:16; the next record is 14:11:20.
    assert {e["serialNo"] for e in kept} == {5742, 5743}

    results = classify_batch(kept)
    punches = [r for r in results if r.punch_candidate]
    assert len(punches) == 1
    resolved = TimeResolver(site_tz=SITE_TZ).resolve(punches[0].event_time)
    # Wall 14:11:16 Bucharest in October is +03:00 — NOT the +02:00 the device claims.
    assert resolved.utc == datetime(2026, 10, 12, 11, 11, 16, tzinfo=UTC)
    assert resolved.device_offset_minutes == 120, "device claimed +02:00 (wrong)"
    assert resolved.offset_minutes == 180, "we used the site offset"
    # The punch lands inside the user's requested UTC window — nothing shifted across it.
    assert resolved.utc is not None
    assert window.since_utc <= resolved.utc <= window.until_utc


def test_window_ending_at_the_punch_instant_is_inclusive() -> None:
    """An off-by-one here drops exactly one punch per window edge — the subtle failure
    the card calls out. Boundary-inclusive on both ends, matching our naive filter."""
    since = parse_user_timestamp("2026-10-12T14:11:16", site_tz=SITE_TZ)
    until = parse_user_timestamp("2026-10-12T14:11:16", site_tz=SITE_TZ)
    start, end = window_for_device(since, until, site_tz=SITE_TZ).search_pair()
    kept = [e for e in golden_events() if survives(e, start, end)]
    assert [e["serialNo"] for e in kept] == [5742, 5743]


def test_a_utc_based_window_would_drop_the_punch_and_we_do_not_send_one() -> None:
    """Negative control proving the naive-wall rule is load-bearing: the same wall hour
    expressed in UTC is a *different* naive string, and filtering with it loses the day."""
    since = parse_user_timestamp("2026-10-12T11:11:00Z", site_tz=SITE_TZ)
    until = parse_user_timestamp("2026-10-12T11:12:00Z", site_tz=SITE_TZ)
    window = window_for_device(since, until, site_tz=SITE_TZ)
    naive_start, naive_end = window.search_pair()
    assert naive_start.startswith("2026-10-12T14:11"), (
        "window_for_device converts to site wall time — the naive pair, not the UTC one"
    )
    # The UTC-shaped strings would match nothing on the device's naive clock:
    assert not [
        e for e in golden_events() if survives(e, "2026-10-12T11:11:00", "2026-10-12T11:12:00")
    ]
    # ...while the naive pair we actually send keeps them:
    assert [e for e in golden_events() if survives(e, naive_start, naive_end)]


# --- DST edges over AcsEvent bodies --------------------------------------------------------------


def _event(time_str: str, serial: int) -> dict:
    return {
        "major": 5,
        "minor": 75,
        "time": time_str,
        "name": "User E1",
        "employeeNoString": "1",
        "doorNo": 1,
        "serialNo": serial,
        "currentVerifyMode": "cardOrFaceOrFp",
    }


def test_spring_gap_punch_is_kept_and_flagged_never_dropped() -> None:
    """2026-03-29 03:00 Bucharest jumps to 04:00 — a device punch at 03:30 carries a
    timestamp that does not exist in the site zone. Payroll rule: keep + flag."""
    event = _event("2026-03-29T03:30:00+02:00", 9001)
    since = parse_user_timestamp("2026-03-29T00:00:00", site_tz=SITE_TZ)
    until = parse_user_timestamp("2026-03-29T12:00:00", site_tz=SITE_TZ)
    window = window_for_device(since, until, site_tz=SITE_TZ)
    start, end = window.search_pair()
    assert survives(event, start, end), "the device (naive filter) returns it; so must we"

    [result] = classify_batch([event])
    assert result.punch_candidate is True  # still an auth pass — kept as a candidate
    resolved = TimeResolver(site_tz=SITE_TZ).resolve(result.event_time)
    assert resolved.resolved and resolved.nonexistent is True
    assert resolved.utc is not None
    assert (
        window.since_utc - timedelta(hours=1)
        <= resolved.utc
        <= window.until_utc + timedelta(hours=1)
    )


def test_autumn_fold_punch_resolves_to_the_first_occurrence_and_survives() -> None:
    """2026-10-25 03:30 Bucharest happens twice. tz.py takes the FIRST occurrence
    (the DST offset) so nobody gains an unworked hour; the punch must still be inside a
    window covering that hour."""
    event = _event("2026-10-25T03:30:00+03:00", 9101)
    since = parse_user_timestamp("2026-10-25T00:00:00", site_tz=SITE_TZ)
    until = parse_user_timestamp("2026-10-25T04:00:00", site_tz=SITE_TZ)
    window = window_for_device(since, until, site_tz=SITE_TZ)
    start, end = window.search_pair()
    assert survives(event, start, end)

    [result] = classify_batch([event])
    resolved = TimeResolver(site_tz=SITE_TZ).resolve(result.event_time)
    assert resolved.ambiguous is True
    assert resolved.utc == datetime(2026, 10, 25, 0, 30, tzinfo=UTC), "first occurrence (fold=0)"
    assert resolved.utc is not None
    assert window.since_utc <= resolved.utc <= window.until_utc


def test_every_golden_record_survives_its_own_full_history_window() -> None:
    """The full-history window (2026-05-21 .. after the probe) must keep ALL 30 records —
    18 punch candidates and 12 door events, none lost to window math."""
    since = parse_user_timestamp("2026-05-21T00:00:00", site_tz=SITE_TZ)
    until = parse_user_timestamp("2026-10-15T23:59:59", site_tz=SITE_TZ)
    start, end = window_for_device(since, until, site_tz=SITE_TZ).search_pair()
    events = golden_events()
    kept = [e for e in events if survives(e, start, end)]
    assert len(kept) == len(events) == 30
    results = classify_batch(kept)
    assert sum(r.punch_candidate for r in results) == 18
