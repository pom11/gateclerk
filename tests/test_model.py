"""The p1-07 output contract: what a record must contain and how it survives a round trip.

Everything here is offline and synthetic. The recorded fixtures (masked site-a responses)
are the input corpus; the two synthetic fixtures under `tests/fixtures/synthetic/` cover
the shapes the real device could not give us today — `attendanceStatus` populated (only
observable if the owner enables attendance mode, DESIGN.md option A) and an encrypted
name blob (site-a returned plaintext names and advertises no encryption capability).

Three groups, matching the card's DoD:
  * roundtrip losslessness (unicode names, missing attendanceStatus, blob fixture);
  * key stability (the digests P2 will put in UNIQUE columns);
  * the no-inference / redaction invariants that make a record safe to store.
"""

from __future__ import annotations

import hashlib
import json
import unicodedata
from datetime import UTC, datetime, timedelta, timezone
from pathlib import Path
from zoneinfo import ZoneInfo

import pytest

from gateclerk.model import (
    EVENT_TZ_KEYS,
    KEY_ALGORITHM,
    RECORD_JSON_KEYS,
    Direction,
    DirectionSource,
    EventRecord,
    ModelFieldError,
    Outcome,
    TzSource,
    UserRecord,
    canonical_json,
    canonical_status,
    direction_for_status,
    event_keys,
    fingerprint_key_hash,
    fingerprint_key_json,
    from_jsonl,
    idempotency_key_hash,
    idempotency_key_json,
    is_encrypted_person_data,
    iter_jsonl,
    to_jsonl,
    tz_fields_from_record,
)
from gateclerk.tz import TimeResolver

REPO_ROOT = Path(__file__).resolve().parents[1]
RECORDED = REPO_ROOT / "tests" / "fixtures" / "recorded" / "site-a-ds-k1t341amf-s"
SYNTHETIC = REPO_ROOT / "tests" / "fixtures" / "synthetic"

SITE = "site-a"
DEVICE_SERIAL = "MASKED-SER-1"
BUCHAREST = ZoneInfo("Europe/Bucharest")

#: Realistic-looking but recognisably fake, so tests/test_repo_hygiene.py's placeholder
#: rule keeps holding. The prefix is assembled to keep this file free of a literal
#: password assignment; the value never leaves this test.
BCRYPT_PREFIX = "$2a$10$"
PASSWORD_HASH = BCRYPT_PREFIX + "x" * 53


def load_recorded(name: str) -> dict:
    return json.loads((RECORDED / name).read_text(encoding="utf-8"))


def load_synthetic(name: str) -> dict:
    return json.loads((SYNTHETIC / name).read_text(encoding="utf-8"))


def resolve(time_string: str | None):
    """The p1-06 resolver, configured the way site-a's config would be."""
    return TimeResolver(site_tz="Europe/Bucharest").resolve(time_string)


def record_from_event(event: dict, **overrides: object) -> EventRecord:
    """One device event → EventRecord, assembled the way p1-08's pipeline will."""
    payload: dict[str, object] = {
        "site": SITE,
        "device_serial": DEVICE_SERIAL,
        "serial_no": event.get("serialNo"),
        "employee_no": event.get("employeeNoString") or event.get("employeeNo"),
        "name": event.get("name"),
        "attendance_status": event.get("attendanceStatus"),
        "verify_mode": event.get("currentVerifyMode"),
        "major": event.get("major"),
        "minor": event.get("minor"),
        "raw": event,
        "captured_at": datetime(2026, 10, 16, 7, 0, tzinfo=UTC),
        **tz_fields_from_record(resolve(event.get("time")).as_record()),
    }
    payload.update(overrides)
    return EventRecord.from_dict(payload)


def recorded_events() -> list[dict]:
    return load_recorded("events_major5_page1.json")["AcsEvent"]["InfoList"]


# --- the contract surface ---------------------------------------------------------------


def test_record_key_set_is_the_documented_contract() -> None:
    """The field names ARE the P2/P3 contract: a rename must be a spec discussion.

    Pinned by enumeration, not by a count, so the intent of any addition or removal is
    visible in the diff of whatever commit touches this test.
    """
    assert RECORD_JSON_KEYS == (
        "site",
        "device_serial",
        "serial_no",
        "employee_no",
        "name",
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
        "tz_offset_mismatch",
        "direction",
        "attendance_status",
        "direction_source",
        "verify_mode",
        "major",
        "minor",
        "outcome",
        "unknown_code",
        "encrypted_person_data",
        "raw",
        "captured_at",
    )


def test_tz_keys_are_consumed_from_as_record_verbatim() -> None:
    """The card's ownership note: EventRecord takes `as_record()`'s keys as-is.

    `ResolvedTime.as_record()` is p1-06's output and DESIGN.md's event model is the
    superset around it. This is the seam: if p1-06 renames a key, this fails here rather
    than a payroll column silently going blank.
    """
    record = resolve("2026-10-12T14:11:16+02:00").as_record()
    assert set(EVENT_TZ_KEYS) == set(record)
    assert list(tz_fields_from_record(record)) == [*EVENT_TZ_KEYS, "tz_offset_mismatch"]
    # tz_offset_mismatch is p1-06c's comparison of two columns already present here,
    # so the resolver is not required to provide it.
    assert record["tz_offset_min"] == 180 and record["tz_offset_min_device"] == 120


def test_tz_block_missing_a_key_raises_and_names_it() -> None:
    """A renamed or hand-built time block must fail loudly, not default to empty."""
    block = resolve("2026-10-12T14:11:16+02:00").as_record()
    renamed = {("tz_src" if k == "tz_source" else k): v for k, v in block.items()}
    with pytest.raises(ModelFieldError, match="tz_source"):
        tz_fields_from_record(renamed)


def test_enum_spellings_match_the_upstream_vocabulary() -> None:
    """These values are what a P2 query and a P3 mapping compare against; a divergence
    between the resolver's spelling and the record's would be a silent no-rows-returned.

    `tz_source` is pinned against `gateclerk.tz` (merged). `outcome` is pinned to the
    literal DESIGN.md event-model spellings, which is what p1-04's `Outcome` is
    required to use; the two enums are the same three strings by contract.
    """
    assert {member.value for member in Outcome} == {"granted", "denied", "info"}
    from gateclerk.tz import TzSource as ResolverTzSource

    assert {m.value for m in TzSource} == {m.value for m in ResolverTzSource}
    for member in TzSource:
        assert ResolverTzSource(member.value) is ResolverTzSource[member.name]


def test_unknown_key_is_rejected_not_ignored() -> None:
    """A typo'd key would vanish and the record would then look legitimately empty."""
    with pytest.raises(ModelFieldError, match="serial_nno"):
        EventRecord.from_dict({"site": SITE, "device_serial": DEVICE_SERIAL, "serial_nno": 3})


@pytest.mark.parametrize(
    "kwargs",
    [
        {"site": "", "device_serial": "d"},
        {"site": "s", "device_serial": ""},
        {"site": None, "device_serial": "d"},
    ],
)
def test_required_fields_must_say_something(kwargs: dict) -> None:
    with pytest.raises(ModelFieldError):
        EventRecord(**kwargs)  # type: ignore[arg-type]


def test_recorded_shaped_payload_is_accepted_whole() -> None:
    """`from_dict` accepts a `to_dict()` payload and a resolver-shaped block alike."""
    record = record_from_event(recorded_events()[0])
    assert EventRecord.from_dict(record.to_dict()) == record


# --- roundtrip losslessness ---------------------------------------------------------------


def test_roundtrip_is_lossless_over_every_recorded_event() -> None:
    """Every one of site-a's 30 events survives dict → JSON → dict unchanged."""
    for event in recorded_events():
        record = record_from_event(event)
        text = record.to_json()
        assert EventRecord.from_json(text).to_dict() == record.to_dict()
        assert EventRecord.from_json(text).raw == event
        assert "attendanceStatus" not in event  # the OBSERVED.md fact, re-checked


def test_roundtrip_keeps_raw_identical_including_nested_structures() -> None:
    """`raw` is the recovery path (DESIGN.md "We never discard the raw"), so it must
    come back identical — nested dicts and lists included, not flattened."""
    raw = {
        "major": 5,
        "minor": 75,
        "time": "2026-10-12T14:11:16+02:00",
        "employeeNoString": "1",
        "serialNo": 5742,
        "pictureURL": None,
        "RightPlan": [{"doorNo": 1, "planTemplateNo": "1"}],
        "Valid": {"enable": True, "mask": "no"},
    }
    record = EventRecord(
        site=SITE, device_serial=DEVICE_SERIAL, serial_no=5742, employee_no="1", raw=raw
    )
    back = EventRecord.from_json(record.to_json())
    assert back.raw == raw
    assert back.raw["RightPlan"] == [{"doorNo": 1, "planTemplateNo": "1"}]
    assert back.raw["Valid"]["enable"] is True


@pytest.mark.parametrize(
    "name",
    [
        "Andrei Popescu-Ionescu",
        "Gheorghe Dumitrescu",
        "ĐẶNG THỊ HOÀNG YẾN",
        "José Ángel Núñez",
        "Böhme",
        "İstanbul",  # dotted capital I: the classic case-folding trap
        "Женя",
        "Łukasz",
        "Zoë",
        "Kowalski",
        "  Müller  ",  # padded whitespace is trimmed once, not mangled per hop
    ],
)
def test_unicode_names_survive_the_roundtrip(name: str) -> None:
    """Names are the one human-readable field on a payroll record: escaping them to
    \\uXXXX makes a stored payload unreadable during triage, and mangling one puts the
    wrong name on a timesheet.

    Expected spelling is NFC-normalized here for the same reason the model normalizes:
    the test file's own bytes have a normalization form, and comparing against them
    directly would make the result depend on an editor's choice.
    """
    expected = unicodedata.normalize("NFC", name.strip())
    record = EventRecord(
        site=SITE, device_serial=DEVICE_SERIAL, serial_no=1, employee_no="1", name=name
    )
    text = record.to_json()
    assert "\\u" not in text
    assert expected in text  # stored as itself, not as escapes
    back = EventRecord.from_json(text)
    assert back.name == expected
    assert back.raw == {}


def test_nfc_normalization_makes_two_spellings_one_person() -> None:
    """`e` + combining diaeresis and precomposed `ë` must be one employee in the store.

    Otherwise one person becomes two half-attendance people — and the fingerprint key,
    which is built from normalized strings, would fork them into two rows.

    Spellings here are explicit escapes on purpose: the source file's own bytes have a
    normalization form too, and a test that compared against a literal copied from an
    editor would be asserting on the editor's choice rather than on the code.
    """
    precomposed, decomposed_text = "Zo\u00eb", "Zoe\u0308"
    composed = EventRecord(
        site=SITE, device_serial=DEVICE_SERIAL, name=precomposed, employee_no="1"
    )
    decomposed = EventRecord(
        site=SITE, device_serial=DEVICE_SERIAL, name=decomposed_text, employee_no="1"
    )
    assert composed.name == decomposed.name == precomposed
    assert fingerprint_key_hash("1", precomposed, 75) == fingerprint_key_hash(
        "1", decomposed_text, 75
    )


def test_missing_attendance_status_is_the_default_shape() -> None:
    """OBSERVED.md: `attendanceStatus` is absent/null on all 30 events today, so
    (unknown, none) is not an edge case — it is 100% of site-a's history."""
    record = record_from_event(recorded_events()[0])
    assert record.attendance_status is None
    assert record.direction is Direction.UNKNOWN
    assert record.direction_source is DirectionSource.NONE
    back = EventRecord.from_json(record.to_json())
    assert (back.direction, back.direction_source) == (Direction.UNKNOWN, DirectionSource.NONE)


@pytest.mark.parametrize("value", [None, "", "   "])
def test_absent_and_blank_attendance_status_collapse_to_none(value: str | None) -> None:
    record = EventRecord(site=SITE, device_serial=DEVICE_SERIAL, attendance_status=value)
    assert record.attendance_status is None
    assert record.direction is Direction.UNKNOWN
    assert record.direction_source is DirectionSource.NONE


def test_undefined_attendance_status_is_kept_as_the_device_said_it() -> None:
    """Other firmware families return the literal string `undefined` where site-a omits
    the key (docs/references §4). It is not a direction and we do not erase it."""
    record = EventRecord(site=SITE, device_serial=DEVICE_SERIAL, attendance_status="undefined")
    assert record.attendance_status == "undefined"
    assert record.direction is Direction.UNKNOWN


def test_jsonl_roundtrip_and_batch_concatenation() -> None:
    """JSONL is the future push payload (DESIGN.md architecture), so a pushed batch must
    reassemble into identical records — including when two batches are concatenated."""
    records = [record_from_event(event) for event in recorded_events()]
    text = to_jsonl(records)
    assert text.endswith("\n")
    assert len(text.splitlines()) == len(records)
    assert [r.to_dict() for r in from_jsonl(text)] == [r.to_dict() for r in records]
    rejoined = from_jsonl(to_jsonl(records[:3]) + to_jsonl(records[3:]))
    assert [r.to_dict() for r in rejoined] == [r.to_dict() for r in records]


def test_to_dict_returns_a_payload_the_caller_may_mutate_freely() -> None:
    """The copy in `to_dict` is load-bearing, not decoration.

    A caller that annotates the payload before writing it (P2 adds store columns, a
    log line adds a timestamp) must not be able to reach into the record's `raw`
    through the dict it was handed — a frozen record whose `raw` can be edited
    through `to_dict()` is not a frozen record. The copy is deliberately *shallow*
    (see `to_dict`), so this pins the top-level guarantee and nothing deeper.
    """
    record = record_from_event(recorded_events()[0])
    payload = record.to_dict()
    payload["raw"]["minor"] = 999
    payload["raw"]["injected"] = True
    payload["employee_no"] = "hacked"
    assert record.raw["minor"] == 75
    assert "injected" not in record.raw
    assert record.employee_no == "1"
    # and the record still serializes to its own truth afterwards
    assert EventRecord.from_json(record.to_json()).raw == record.raw


def test_employee_no_normalization_makes_two_spellings_one_id() -> None:
    """Same reason as the name, and a sharper edge: `employee_no` is in the fingerprint
    key, so two spellings of one id would fork one person's punches into two rows.

    Alphanumeric ids with diacritics are the case that matters — site-a's "1".."4"
    cannot show it, so the id here is deliberately non-ASCII. The decomposed form is
    built with `chr(0x308)` (combining diaeresis) after an `e`, which is exactly how a
    macOS filename or an IME produces it.
    """
    combining_diaeresis = chr(0x308)
    precomposed, decomposed_text = "Za" + chr(0xEB), "Zae" + combining_diaeresis
    first = EventRecord(
        site=SITE, device_serial=DEVICE_SERIAL, employee_no=precomposed, serial_no=1
    )
    second = EventRecord(
        site=SITE, device_serial=DEVICE_SERIAL, employee_no=decomposed_text, serial_no=1
    )
    assert first.employee_no == second.employee_no == precomposed
    assert first.fingerprint_hash == second.fingerprint_hash
    assert EventRecord.from_json(first.to_json()).employee_no == precomposed


def test_to_jsonl_records_are_independent_of_the_records_they_came_from() -> None:
    """A pushed line must not change if the caller reuses the record afterwards — the
    payload is a snapshot, which is what makes a retried push safe."""
    record = record_from_event(recorded_events()[0])
    line = to_jsonl([record])
    assert json.loads(line)["raw"]["minor"] == 75
    assert json.loads(to_jsonl([record])) == json.loads(line)


def test_jsonl_skips_blank_lines_and_names_a_bad_line() -> None:
    records = [record_from_event(recorded_events()[0])]
    # blank lines are skipped but still counted, so the reported number stays grep-able
    with pytest.raises(ModelFieldError, match="line 3"):
        from_jsonl(to_jsonl(records) + "\n" + '{"site": "x"}\n')
    assert len(list(iter_jsonl("\n\n" + to_jsonl(records) + "\n\n"))) == 1


def test_jsonl_kind_selects_the_record_type() -> None:
    """Default is event; a user line parsed as an event must raise, not half-parse."""
    user = UserRecord(employee_no="0007A", name="Ionescu", user_type="normal")
    assert from_jsonl(to_jsonl([user]), kind="user")[0].to_dict() == user.to_dict()
    with pytest.raises(ModelFieldError):
        from_jsonl(to_jsonl([user]))


def test_non_finite_numbers_never_enter_a_written_payload() -> None:
    """`allow_nan=False`: NaN/Infinity are not JSON, so a line we wrote would be
    unparseable by the strict reader on the other end of the push."""
    record = EventRecord(site=SITE, device_serial=DEVICE_SERIAL, raw={"x": float("nan")})
    with pytest.raises(ValueError, match="Out of range float"):
        record.to_json()


# --- direction: no inference anywhere ------------------------------------------------------


@pytest.mark.parametrize(
    ("status", "direction", "source"),
    [
        ("checkIn", Direction.IN, DirectionSource.DEVICE),
        ("checkOut", Direction.OUT, DirectionSource.DEVICE),
        ("Check In", Direction.IN, DirectionSource.DEVICE),
        ("checkin", Direction.IN, DirectionSource.DEVICE),
        ("check_out", Direction.OUT, DirectionSource.DEVICE),
        (None, Direction.UNKNOWN, DirectionSource.NONE),
        ("", Direction.UNKNOWN, DirectionSource.NONE),
        ("undefined", Direction.UNKNOWN, DirectionSource.NONE),
        ("breakIn", Direction.UNKNOWN, DirectionSource.NONE),
        ("breakOut", Direction.UNKNOWN, DirectionSource.NONE),
        ("overtimeIn", Direction.UNKNOWN, DirectionSource.NONE),
        ("overtimeOut", Direction.UNKNOWN, DirectionSource.NONE),
        ("Vacation", Direction.UNKNOWN, DirectionSource.NONE),  # site-customized label
    ],
)
def test_direction_comes_only_from_attendance_status(
    status: str | None, direction: Direction, source: DirectionSource
) -> None:
    assert direction_for_status(status) == (direction, source)


@pytest.mark.parametrize("status", ["breakIn", "breakOut", "overtimeIn", "overtimeOut"])
def test_non_direction_statuses_are_kept_verbatim(status: str) -> None:
    """Kept as data, direction left unknown — the policy call is P3's, not ours."""
    record = EventRecord(site=SITE, device_serial=DEVICE_SERIAL, attendance_status=status)
    assert record.attendance_status == status
    assert record.direction is Direction.UNKNOWN
    assert record.direction_source is DirectionSource.NONE
    assert EventRecord.from_json(record.to_json()).attendance_status == status


#: Keys the attendance fixture uses to say what the model must produce. They are test
#: annotations, not device fields, so they are stripped before the entry becomes `raw` —
#: `raw` is the untouched *device* record (field contract, DESIGN.md).
FIXTURE_ANNOTATION_KEYS = frozenset({"expected_direction", "expected_source", "_note", "id"})


def device_event(case: dict) -> dict:
    """One fixture entry with its test annotations removed — the record's `raw`."""
    return {k: v for k, v in case.items() if k not in FIXTURE_ANNOTATION_KEYS}


@pytest.mark.parametrize(
    "case",
    load_synthetic("attendance_status_events.json")["InfoList"],
    ids=lambda case: str(case["serialNo"]),
)
def test_attendance_fixture_matches_its_expected_columns(case: dict) -> None:
    """The attendance-mode shape, asserted — not merely shipped.

    This fixture is the only place in the repo where `attendanceStatus` is populated:
    site-a is in access-control mode, so every recorded event has it absent (OBSERVED.md).
    A fixture nobody loads would read as coverage for the direction rule while proving
    nothing, so each entry is built through the same helper p1-08's pipeline will use and
    checked against the `expected_*` columns the fixture declares.
    """
    event = device_event(case)
    record = record_from_event(event)
    who = f"serialNo={case['serialNo']} attendanceStatus={case.get('attendanceStatus')!r}"
    assert record.direction.value == case["expected_direction"], who
    assert record.direction_source.value == case["expected_source"], who
    # Verbatim except the empty/absent collapse and a known vendor spelling: the model
    # must not rewrite a site-customized label, and must not invent one either.
    assert record.attendance_status == (case.get("attendanceStatus") or None), who
    # The fixture's own _comment promises the round trip, and `raw` stays the device entry.
    back = EventRecord.from_json(record.to_json())
    assert back.direction.value == case["expected_direction"], who
    assert back.direction_source.value == case["expected_source"], who
    assert back.raw == event, who


def test_attendance_fixture_annotations_never_reach_raw() -> None:
    """Pins the strip itself, which the test above cannot pin from inside its own body.

    Without this, a broken `device_event` filter would post `expected_direction` into the
    store's `raw` column — an audit trail carrying a value the device never sent — and the
    per-entry assertions would still pass, because they read the same filtered dict.
    """
    cases = load_synthetic("attendance_status_events.json")["InfoList"]
    assert len(cases) >= 6, "the fixture lost entries; the direction table is under-covered"
    for case in cases:
        annotated = case.keys() & FIXTURE_ANNOTATION_KEYS
        assert annotated, f"fixture entry {case['serialNo']} declares no expectation"
        assert not device_event(case).keys() & FIXTURE_ANNOTATION_KEYS, case["serialNo"]
        assert case.keys() - device_event(case).keys() == annotated, case["serialNo"]


def test_direction_without_a_source_is_rejected() -> None:
    """The no-inference rule, made mechanical: a direction nobody attributed is exactly
    the first/last-punch inference this card forbids."""
    with pytest.raises(ModelFieldError, match="never infers"):
        EventRecord(site=SITE, device_serial=DEVICE_SERIAL, direction=Direction.IN)


def test_direction_is_derived_not_trusted() -> None:
    """A caller may omit direction entirely and still get the device's answer.

    The rule "direction comes ONLY from attendanceStatus" is implemented as a
    derivation, so the field cannot drift from the value it is supposed to be read off
    — a validator that only checked consistency would let a caller pass `in`+`checkIn`
    and store an accident.
    """
    derived = EventRecord(site=SITE, device_serial=DEVICE_SERIAL, attendance_status="checkIn")
    assert derived.direction is Direction.IN
    assert derived.direction_source is DirectionSource.DEVICE
    # and the explicit form agrees, so either call style is correct
    explicit = EventRecord(
        site=SITE,
        device_serial=DEVICE_SERIAL,
        attendance_status="checkIn",
        direction=Direction.IN,
        direction_source=DirectionSource.DEVICE,
    )
    assert explicit.to_dict() == derived.to_dict()


def test_direction_contradicting_the_device_value_is_rejected() -> None:
    for status in ("breakIn", "checkOut"):
        with pytest.raises(ModelFieldError, match="attendance_status"):
            EventRecord(
                site=SITE,
                device_serial=DEVICE_SERIAL,
                direction=Direction.IN,
                direction_source=DirectionSource.DEVICE,
                attendance_status=status,
            )


def test_device_source_without_a_stating_status_is_rejected() -> None:
    """`device` claims the terminal decided; a status that says nothing cannot back it.

    The counterpart case is deliberately *not* an error: `checkIn` + `device` with no
    `direction` argument derives `in` (see test_direction_is_derived_not_trusted), which
    is why the derivation is the implementation and not a consistency check.
    """
    with pytest.raises(ModelFieldError, match="states no direction"):
        EventRecord(
            site=SITE,
            device_serial=DEVICE_SERIAL,
            direction=Direction.IN,
            direction_source=DirectionSource.DEVICE,
        )
    with pytest.raises(ModelFieldError, match="states no direction"):
        EventRecord(
            site=SITE,
            device_serial=DEVICE_SERIAL,
            direction_source=DirectionSource.DEVICE,
            attendance_status="breakOut",
            direction=Direction.OUT,
        )


def test_an_inferred_record_is_representable_but_only_when_attributed() -> None:
    """Two-sided: the connector may not write an unattributed direction, and a record a
    consumer wrote back (P3's first/last rule) must be representable at all — else a
    mixed history could not survive the store round trip (DESIGN.md: "Whichever is
    chosen is recorded per event in direction_source ... so a mixed history stays
    auditable")."""
    with pytest.raises(ModelFieldError, match="never infers"):
        EventRecord(site=SITE, device_serial=DEVICE_SERIAL, direction=Direction.OUT)
    with pytest.raises(ModelFieldError, match="claims a decision"):
        EventRecord(
            site=SITE,
            device_serial=DEVICE_SERIAL,
            direction_source=DirectionSource.INFERRED,
        )
    inferred = EventRecord(
        site=SITE,
        device_serial=DEVICE_SERIAL,
        direction=Direction.IN,
        direction_source=DirectionSource.INFERRED,
    )
    back = EventRecord.from_json(inferred.to_json())
    assert (back.direction, back.direction_source) == (Direction.IN, DirectionSource.INFERRED)
    # an inference contradicted by the device's own word cannot claim to be an inference
    with pytest.raises(ModelFieldError, match="attendanceStatus states the direction"):
        EventRecord(
            site=SITE,
            device_serial=DEVICE_SERIAL,
            direction=Direction.IN,
            direction_source=DirectionSource.INFERRED,
            attendance_status="checkIn",
        )
    # ...and cannot claim to be one that contradicts it either
    with pytest.raises(ModelFieldError, match="contradicts"):
        EventRecord(
            site=SITE,
            device_serial=DEVICE_SERIAL,
            direction=Direction.IN,
            direction_source=DirectionSource.INFERRED,
            attendance_status="checkOut",
        )


def test_canonical_status_never_invents_a_value() -> None:
    assert canonical_status("Check In") == "checkIn"
    assert canonical_status("check_out") == "checkOut"
    assert canonical_status("Zzz") == "Zzz"  # unknown label survives verbatim
    assert canonical_status(None) is None
    assert canonical_status(7) is None


# --- the resolver seam: what tz.py already decided -----------------------------------------


def test_resolver_record_lands_in_the_record_verbatim() -> None:
    """The offset we used vs the offset the device claimed: both kept (payroll audit)."""
    record = record_from_event({"time": "2026-10-12T14:11:16+02:00", "serialNo": 1})
    assert record.event_time_utc == datetime(2026, 10, 12, 11, 11, 16, tzinfo=UTC)
    assert record.event_time_local == "2026-10-12T14:11:16+02:00"  # untouched string
    assert record.tz_offset_min == 180  # Europe/Bucharest in October
    assert record.tz_offset_min_device == 120  # the wrong claim, kept for audit
    assert record.tz_source is TzSource.SITE_TZ
    assert record.iana_tz == "Europe/Bucharest"
    assert record.tz_unresolved is False


@pytest.mark.parametrize("bad", [None, "", "not-a-time", "2026-13-45T99:99:99"])
def test_unresolvable_time_stays_a_record_with_utc_none(bad: str | None) -> None:
    """DESIGN.md item 4: store it and flag it, never guess. Dropping the record would be
    the actual data loss; `tz_unresolved` + `tz_reason` are the flag."""
    record = record_from_event({"time": bad, "serialNo": 7}, unknown_code=True)
    assert record.event_time_utc is None
    assert record.tz_unresolved is True
    assert record.tz_reason
    back = EventRecord.from_json(record.to_json())
    assert back.tz_unresolved is True and back.event_time_utc is None


def test_a_record_from_the_no_site_zone_path_is_still_storable() -> None:
    unresolved = TimeResolver(site_tz=None).resolve("2026-10-12T14:11:16")
    record = record_from_event(
        {"serialNo": 1, "time": "2026-10-12T14:11:16"},
        **tz_fields_from_record(unresolved.as_record()),
    )
    assert record.tz_source is TzSource.UNRESOLVED
    assert record.tz_unresolved is True
    assert record.event_time_utc is None
    assert EventRecord.from_json(record.to_json()).tz_unresolved is True


def test_naive_utc_is_refused_rather_than_assumed() -> None:
    """The one case where "assume UTC" would be tempting and wrong (DESIGN.md item 4)."""
    naive = datetime(2026, 1, 1)  # noqa: DTZ001 - deliberately naive: this is the input under test
    with pytest.raises(ModelFieldError, match="carries no offset"):
        EventRecord(site=SITE, device_serial=DEVICE_SERIAL, event_time_utc=naive)
    with pytest.raises(ModelFieldError, match="no offset"):
        EventRecord.from_dict(
            {"site": SITE, "device_serial": DEVICE_SERIAL, "event_time_utc": "2026-01-01T00:00:00"}
        )


def test_offsets_are_normalized_to_utc_and_captured_at_travels() -> None:
    plus3 = timezone(timedelta(hours=3))
    moment = datetime(2026, 10, 12, 14, 11, 16, tzinfo=plus3)
    record = EventRecord(site=SITE, device_serial=DEVICE_SERIAL, event_time_utc=moment)
    assert record.to_dict()["event_time_utc"] == "2026-10-12T11:11:16+00:00"
    assert EventRecord.from_json(record.to_json()).event_time_utc == moment

    stamp = datetime(2026, 10, 16, 7, 0, tzinfo=UTC)
    assert (
        EventRecord.from_json(
            EventRecord(site=SITE, device_serial=DEVICE_SERIAL, captured_at=stamp).to_json()
        ).captured_at
        == stamp
    )
    # a 'Z' spelling is the same instant and must not be rejected
    assert (
        EventRecord.from_dict(
            {"site": SITE, "device_serial": DEVICE_SERIAL, "captured_at": "2026-10-16T07:00:00Z"}
        ).captured_at
        == stamp
    )


def test_stringified_numbers_from_odd_firmware_still_type_correctly() -> None:
    """`minor: "75"` is real on some fw (references §5); reading it as 0 would rename a
    granted pass into an unknown code and silently drop it from punch candidates."""
    record = EventRecord.from_dict(
        {
            "site": SITE,
            "device_serial": DEVICE_SERIAL,
            "serial_no": "5742",
            "major": "5",
            "minor": "75",
            "outcome": "granted",
            "employee_no": "1",
        }
    )
    assert (record.serial_no, record.major, record.minor) == (5742, 5, 75)
    assert record.is_punch_candidate is True


@pytest.mark.parametrize(
    ("key", "value"),
    [
        ("tz_source", "site_tz"),
        ("direction", "IN"),
        ("outcome", "Granted"),
        ("direction_source", "dev"),
    ],
)
def test_unknown_enum_spelling_is_a_contract_error_not_a_coercion(key: str, value: str) -> None:
    with pytest.raises(ModelFieldError, match=key):
        EventRecord.from_dict({"site": SITE, "device_serial": "d", key: value})


# --- encrypted person data -----------------------------------------------------------------


def test_encrypted_blob_fixture_is_flagged_and_stored_verbatim() -> None:
    """The card's DoD case: a base64-looking name is kept untouched + flagged.

    Stored because `raw` must come back byte-equal and a consumer holding the key can
    still decrypt it; the flag is what stops it being printed as a person's name.
    """
    for case in load_synthetic("encrypted_person_data.json")["cases"]:
        event = case["event"]
        record = record_from_event(event)
        assert record.encrypted_person_data is case["expect_encrypted"], case["id"]
        assert record.name == event.get("name")  # verbatim, never rewritten
        assert record.raw == event
        assert (
            EventRecord.from_json(record.to_json()).encrypted_person_data
            is (case["expect_encrypted"])
        )


@pytest.mark.parametrize(
    ("name", "expected"),
    [
        ("VGhpc0lzQ0lwaGVyTm90QVBlcnNvbk5hbWU=", True),
        ("3kD9xv2Qm7Zp4Ln8Yb6Tc1Rs0We5", True),
        ("YWJjZGVmZ2hpamtsbW5vcHFyc3R1", True),
        # names that merely LOOK like base64 must not be flagged away:
        ("Popescu-Ionescu", False),
        ("Mariacostache", False),
        ("Annemariel", False),
        ("AbCdEfGhIjKlMnOpQrStUvWx", False),  # base64-shaped but no digit
        ("dGVzdA==", False),  # too short to call
        ("Gheorghe", False),
        ("ĐẶNG THỊ HOÀNG YẾN", False),
        (None, False),
        ("", False),
    ],
)
def test_encrypted_person_data_detection(name: str | None, expected: bool) -> None:
    assert is_encrypted_person_data(name) is expected


def test_flag_is_recomputed_on_load_so_an_old_row_cannot_lie() -> None:
    """A row written before the detector tightened still tells the truth about its name.

    Monotone on purpose: loading may turn False into True, never True into False — a
    stored True can rest on evidence the current detector dropped, and un-flagging a
    name nobody can read is the dangerous direction.
    """
    blob = "VGhpc0lzQ0lwaGVyTm90QVBlcnNvbk5hbWU="
    row = {
        "site": SITE,
        "device_serial": DEVICE_SERIAL,
        "name": blob,
        "encrypted_person_data": False,
    }
    assert EventRecord.from_dict(row).encrypted_person_data is True
    assert EventRecord.from_dict({**row, "encrypted_person_data": True}).encrypted_person_data is (
        True
    )


# --- keys for the P2 store ------------------------------------------------------------------


def test_idempotency_key_is_the_documented_pair() -> None:
    """(device_serial, serial_no) is the UPSERT target that makes overlap re-polling
    free (DESIGN.md "Paging + checkpoint")."""
    record = record_from_event({"serialNo": 5742, "time": "2026-10-12T14:11:16+02:00"})
    assert record.idempotency_hash == idempotency_key_hash(DEVICE_SERIAL, 5742)
    assert idempotency_key_json(DEVICE_SERIAL, 5742) == (
        f'{{"device_serial":"{DEVICE_SERIAL}","serial_no":5742}}'
    )


def test_fingerprint_key_is_the_documented_triple() -> None:
    """(employee_no, event_time_local, minor) — the guard for a device whose `serialNo`
    resets after a firmware upgrade or a log clear."""
    record = record_from_event(
        {
            "serialNo": 5742,
            "employeeNoString": "1",
            "minor": 75,
            "time": "2026-10-12T14:11:16+02:00",
        }
    )
    assert record.fingerprint_hash == fingerprint_key_hash("1", "2026-10-12T14:11:16+02:00", 75)
    assert json.loads(fingerprint_key_json("1", "2026-10-12T14:11:16+02:00", 75)) == {
        "employee_no": "1",
        "event_time_local": "2026-10-12T14:11:16+02:00",
        "minor": 75,
    }


def test_keys_ignore_everything_outside_their_tuple() -> None:
    """The same punch read twice — different page, different `captured_at`, different
    `raw`, even a relabelled `site` — must produce the same digests, or the UPSERT
    misses and payroll counts the day twice."""
    base = {
        "device_serial": DEVICE_SERIAL,
        "serial_no": 5742,
        "employee_no": "1",
        "event_time_local": "2026-10-12T14:11:16+02:00",
        "minor": 75,
    }
    first = EventRecord(site=SITE, captured_at=datetime(2026, 10, 16, tzinfo=UTC), **base)  # type: ignore[arg-type]
    second = EventRecord(
        site="site-a-renamed",
        raw={"different": True},
        outcome=Outcome.DENIED,
        tz_offset_min=120,
        captured_at=datetime(2026, 10, 17, tzinfo=UTC),
        **base,  # type: ignore[arg-type]
    )
    assert first.idempotency_hash == second.idempotency_hash
    assert first.fingerprint_hash == second.fingerprint_hash


def test_keys_distinguish_the_records_they_must_distinguish() -> None:
    """The complement of the previous test. Without it, "stable" and "constant" are
    indistinguishable from inside a passing suite."""
    assert idempotency_key_hash(DEVICE_SERIAL, 5742) != idempotency_key_hash(DEVICE_SERIAL, 5743)
    assert idempotency_key_hash("MASKED-SER-2", 5742) != idempotency_key_hash(DEVICE_SERIAL, 5742)
    # leading zeros are identity: "007" and "7" are two different people
    assert fingerprint_key_hash("007", "T", 75) != fingerprint_key_hash("7", "T", 75)
    assert fingerprint_key_hash("1", "T", 75) != fingerprint_key_hash("1", "T", 76)
    assert fingerprint_key_hash("1", "T", 75) != fingerprint_key_hash("1", "U", 75)
    assert fingerprint_key_hash(None, "T", 75) != fingerprint_key_hash("1", "T", 75)


def test_digests_are_order_independent_and_pinned_to_a_hand_computed_sha256() -> None:
    """These digests become UNIQUE columns: a canonicalization that drifted with dict
    insertion order would re-key the whole store on a refactor."""
    assert (
        canonical_json({"b": 1, "a": {"d": [1, 2], "c": "x"}})
        == canonical_json({"a": {"c": "x", "d": [1, 2]}, "b": 1})
        == '{"a":{"c":"x","d":[1,2]},"b":1}'
    )
    text = '{"device_serial":"MASKED-SER-1","serial_no":27}'
    assert idempotency_key_json(DEVICE_SERIAL, 27) == text
    assert (
        idempotency_key_hash(DEVICE_SERIAL, 27) == hashlib.sha256(text.encode("utf-8")).hexdigest()
    )
    # and the record-level helper agrees with the standalone one for a recorded event
    assert (
        idempotency_key_hash(DEVICE_SERIAL, 27)
        == record_from_event({"serialNo": 27, "time": "2026-05-21T14:08:22+02:00"}).idempotency_hash
    )


def test_key_columns_carry_the_algorithm_tag_and_both_forms() -> None:
    """A future hash change must not be conflatable with these digests in the same
    column, and `(hash, json)` pairs make a collision visible to a human."""
    record = record_from_event(recorded_events()[0])
    columns = event_keys(record)
    assert set(columns) == {
        "algorithm",
        "idempotency_json",
        "idempotency_hash",
        "fingerprint_json",
        "fingerprint_hash",
    }
    assert columns["algorithm"] == KEY_ALGORITHM
    assert len(columns["idempotency_hash"]) == 64
    assert json.loads(columns["idempotency_json"])["serial_no"] == record.serial_no


def test_canonical_json_refuses_what_it_cannot_stably_encode() -> None:
    class Opaque:
        pass

    with pytest.raises(ModelFieldError, match="cannot canonicalize"):
        canonical_json({"x": Opaque()})
    with pytest.raises(ModelFieldError, match="float"):
        canonical_json({"x": float("inf")})
    assert canonical_json({"t": datetime(2026, 1, 1, tzinfo=UTC)}) == (
        '{"t":"2026-01-01T00:00:00+00:00"}'
    )


def test_records_are_shareable_but_deliberately_not_hashable() -> None:
    """Frozen (so a poll loop cannot mutate a row it already handed to the store) and
    unhashable (because `raw` is a dict) — keying goes through `canonical_json`, whose
    stability the test above pins, never through `hash()` of a dataclass."""
    record = record_from_event(recorded_events()[0])
    with pytest.raises(TypeError, match="unhashable"):
        hash(record)
    assert isinstance(record.raw, dict)


# --- user records ---------------------------------------------------------------------------


def test_password_hash_is_stripped_before_anything_can_store_it() -> None:
    """OBSERVED.md: the device really sends a `password` hash per user — "strip it,
    never store". Stripping in the model (not in each consumer) is what makes the rule
    hold for sqlite, JSONL and a log line all at once."""
    body = {
        "employeeNo": "1",
        "employeeNoString": "0007A",
        "name": "User E1",
        "userType": "normal",
        "password": PASSWORD_HASH,
        "Valid": {
            "enable": True,
            "beginTime": "2000-01-01T00:00:00",
            "endTime": "2037-12-31T23:59:59",
        },
    }
    user = UserRecord.from_device_user(body)
    assert "password" not in user.raw
    assert "password" not in user.to_json()
    assert "password" not in to_jsonl([user])
    assert user.employee_no == "0007A"  # employeeNoString wins over the int-ish form
    # a payload that re-injects one into raw is cleaned on the way in too
    smuggled = UserRecord.from_dict(
        {**user.to_dict(), "raw": {**user.raw, "password": PASSWORD_HASH}}
    )
    assert "password" not in smuggled.raw


def test_user_record_roundtrip_and_validity_window() -> None:
    users = load_recorded("user_search_page1.json")["UserInfoSearch"]["UserInfo"]
    records = [UserRecord.from_device_user(entry) for entry in users]
    assert [r.employee_no for r in records] == ["1", "2", "3", "4"]
    for r in records:
        assert r.user_type == "normal"
        assert r.valid_from == "2000-01-01T00:00:00"
        assert r.valid_to == "2037-12-31T23:59:59"
        assert r.valid_enabled is True
        assert "password" not in r.raw
        assert UserRecord.from_json(r.to_json()).to_dict() == r.to_dict()


@pytest.mark.parametrize(
    ("body", "expected"),
    [
        ({"employeeNo": 7}, "7"),
        ({"employeeNo": "0007"}, "0007"),
        ({"employeeNoString": "0007A", "employeeNo": 7}, "0007A"),
        ({"employeeNo": " 12 "}, "12"),
        ({"employeeNo": "1", "employeeNoString": ""}, "1"),
    ],
)
def test_user_record_employee_no_is_always_a_string(body: dict, expected: str) -> None:
    assert UserRecord.from_device_user(body).employee_no == expected


def test_user_record_without_an_employee_no_raises() -> None:
    with pytest.raises(ModelFieldError, match="employeeNo"):
        UserRecord.from_device_user({"name": "nobody"})


def test_user_record_accepts_a_wrapped_entry() -> None:
    entry = {"employeeNo": "1", "name": "User E1"}
    assert UserRecord.from_device_user({"UserInfo": entry}).employee_no == "1"
    assert UserRecord.from_device_user(entry).employee_no == "1"


def test_user_record_flags_an_encrypted_name_without_losing_it() -> None:
    blob = "VGhpc0lzQ0lwaGVyTm90QVBlcnNvbk5hbWU="
    user = UserRecord.from_device_user({"employeeNo": "1", "name": blob})
    assert user.encrypted_person_data is True
    assert user.name == blob  # stored verbatim, never decoded or dropped


def test_user_record_rejects_unknown_keys_and_a_blank_employee_no() -> None:
    with pytest.raises(ModelFieldError, match="unknown key"):
        UserRecord.from_dict({"employee_no": "1", "employeeNo": "1"})
    with pytest.raises(ModelFieldError, match="employee_no is required"):
        UserRecord.from_dict({"employee_no": ""})


# --- the punch property ----------------------------------------------------------------------


def test_punch_candidate_rule_over_the_recorded_census() -> None:
    """DESIGN.md's punch filter expressed as a *property*: 18x minor=75 with an employee
    are candidates; the 12 door-state partners are not; and all 30 records survive."""
    records = [
        record_from_event(event, outcome="granted" if event["minor"] == 75 else "info")
        for event in recorded_events()
    ]
    candidates = [r for r in records if r.is_punch_candidate]
    assert len(records) == 30  # nothing dropped on the way through the model
    assert len(candidates) == 18
    assert {r.minor for r in candidates} == {75}
    assert all(r.employee_no for r in candidates)
    assert sum(1 for r in records if r.minor in (21, 22) and not r.is_punch_candidate) == 12


def test_an_unnamed_code_is_never_a_punch_candidate() -> None:
    """A code we cannot name stays info + unknown_code + non-candidate — and stays
    stored (dropping unknowns is how punches go missing silently)."""
    record = record_from_event(
        {"serialNo": 1, "major": 5, "minor": 999, "time": "2026-10-12T14:11:16+02:00"},
        outcome="granted",
        employee_no="1",
        unknown_code=True,
    )
    assert record.unknown_code is True
    assert record.is_punch_candidate is False
    assert record.raw["minor"] == 999


def test_noise_heartbeat_shape_is_stored_keyed_and_unattributed() -> None:
    """(3,1029) carries no employee: it must arrive as a full record with
    employee_no=None, still idempotency-keyed by serial_no."""
    noise = load_recorded("events_more_noise_page1.json")["AcsEvent"]["InfoList"]
    assert noise, "fixture must carry the heartbeat"
    record = record_from_event(noise[0], outcome="info")
    assert record.employee_no is None
    assert record.name is None
    assert record.is_punch_candidate is False
    assert record.idempotency_hash  # keyed even when unattributed
    assert EventRecord.from_json(record.to_json()) == record


# --- guard the guards ------------------------------------------------------------------------


def test_timezones_are_what_the_tz_assertions_claim() -> None:
    """If zoneinfo silently resolved Bucharest to UTC, every offset assertion above
    would pass while proving nothing."""
    assert datetime(2026, 10, 12, 12, 0, tzinfo=BUCHAREST).utcoffset() == timedelta(hours=3)
    assert datetime(2026, 1, 12, 12, 0, tzinfo=BUCHAREST).utcoffset() == timedelta(hours=2)


def test_device_local_string_is_never_rewritten_by_the_model() -> None:
    """`event_time_local` is the verbatim device string, including its WRONG offset —
    rewriting it would erase the evidence of the device's tz bug."""
    claimed = "2026-10-12T14:11:16+02:00"
    record = record_from_event({"serialNo": 1, "time": claimed})
    assert record.event_time_local == claimed
    assert EventRecord.from_json(record.to_json()).event_time_local == claimed
