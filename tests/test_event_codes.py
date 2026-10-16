"""The major/minor classifier over a fixture corpus (card p1-04 DoD).

Load-bearing properties these tests pin:
  * unknown codes classify info + unknown_code and are KEPT (never dropped);
  * the same-second triple (5,75)+(5,21)+(5,22) yields exactly ONE punch candidate;
  * major=3 (the 1/min heartbeat and remote opens) is fully non-punch;
  * currentVerifyMode stays verbatim — the classifier never invents face vs card;
  * the curated table names 38 as fingerprint (NOT card) — the circulating mislabel.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from gateclerk.capabilities import DeviceCapabilities, parse_acs_event_capabilities
from gateclerk.event_codes import (
    AUTH_PASS_MINORS,
    EVENT_CODE_TABLE,
    NON_AUTH_VERIFY_MODES,
    CodeInfo,
    Outcome,
    classify_batch,
    classify_event,
    name_for,
    outcome_for,
)

SYNTH = Path(__file__).parent / "fixtures/synthetic"
RECORDED = Path(__file__).parent / "fixtures/recorded/site-a-ds-k1t341amf-s"

SITE_A_CAPS = parse_acs_event_capabilities((RECORDED / "acs_capabilities.json").read_bytes())


def corpus() -> list[dict]:
    return json.loads((SYNTH / "classifier_corpus.json").read_text(encoding="utf-8"))["records"]


# --- corpus-driven expectations -------------------------------------------------------------


@pytest.mark.parametrize(
    "case", corpus(), ids=lambda c: f"{c['record']['major']},{c['record']['minor']}"
)
def test_corpus_case_classifies_as_expected(case: dict) -> None:
    got = classify_event(case["record"], capabilities=SITE_A_CAPS)
    want = case["expect"]
    assert got.outcome.value == want["outcome"]
    assert got.code_name == want["code_name"]
    assert got.unknown_code == want["unknown_code"]
    assert got.punch_candidate == want["punch_candidate"], got.reason


def test_corpus_covers_the_rules_it_claims_to() -> None:
    """A guard on the corpus itself: if someone prunes cases to make the suite pass, this
    notices. Each of these outcomes must exist in the corpus."""
    results = [classify_event(c["record"], capabilities=SITE_A_CAPS) for c in corpus()]
    assert any(r.punch_candidate for r in results)
    assert any(r.unknown_code for r in results)
    assert any(r.outcome is Outcome.DENIED for r in results)
    assert any(r.operation_stream for r in results)
    assert len(results) >= 15


# --- unknown-code passthrough ----------------------------------------------------------------


def test_unknown_code_is_info_flagged_and_kept() -> None:
    """The card's hard rule: unknown -> info with unknown_code=true, NEVER dropped.
    A 999 nobody has ever seen must come back classified, intact, with its raw record."""
    weird = {
        "major": 5,
        "minor": 999,
        "employeeNoString": "1",
        "serialNo": 9,
        "time": "2026-10-12T09:00:00+02:00",
    }
    got = classify_event(weird, capabilities=SITE_A_CAPS)
    assert got.outcome is Outcome.INFO
    assert got.unknown_code is True
    assert got.code_name is None
    assert got.punch_candidate is False
    assert got.raw == weird, "the untouched record rides along — nothing may be lost"
    assert got.reason is not None, "a kept unknown must say why"


def test_batch_never_drops_any_record() -> None:
    records = [c["record"] for c in corpus()]
    out = classify_batch(records, capabilities=SITE_A_CAPS)
    assert len(out) == len(records), "classification is total: input records == output records"
    assert all(isinstance(r.raw, dict) for r in out), "every output carries its raw record"


def test_every_event_advertised_by_site_a_gets_an_outcome() -> None:
    """Walk the device's own advertised code sets: every (major, minor) it can return has
    an outcome, and every unnamed one is flagged — no code can fall through a crack."""
    for major, minors in SITE_A_CAPS.minors.items():
        for minor in minors:
            got = classify_event({"major": major, "minor": minor, "serialNo": 1})
            assert got.outcome in Outcome
            if got.code_name is None:
                assert got.unknown_code is True


# --- the same-second triple -------------------------------------------------------------------


def test_a_real_pass_triple_produces_exactly_one_punch_candidate() -> None:
    """OBSERVED.md: one pass emits (5,75)+(5,21)+(5,22) at the same second. Counting the
    door codes would triple-count the day (references §3 confirms the 75->21->22 triple)."""
    triple = [
        {
            "major": 5,
            "minor": 75,
            "time": "2026-10-12T14:11:16+02:00",
            "name": "User E1",
            "employeeNoString": "1",
            "doorNo": 1,
            "serialNo": 5742,
            "currentVerifyMode": "cardOrFaceOrFp",
        },
        {
            "major": 5,
            "minor": 21,
            "time": "2026-10-12T14:11:16+02:00",
            "doorNo": 1,
            "serialNo": 5743,
            "currentVerifyMode": "invalid",
        },
        {
            "major": 5,
            "minor": 22,
            "time": "2026-10-12T14:11:31+02:00",
            "doorNo": 1,
            "serialNo": 5747,
            "currentVerifyMode": "invalid",
        },
    ]
    results = classify_batch(triple, capabilities=SITE_A_CAPS)
    assert sum(r.punch_candidate for r in results) == 1
    assert [r.code_name for r in results] == ["FACE_VERIFY_PASS", "LOCK_OPEN", "LOCK_CLOSE"]
    assert all(not r.unknown_code for r in results)


def test_recorded_major5_page_classifies_to_18_punches_and_12_door_events() -> None:
    """The recorded all-30 page: 18x minor 75 (granted, employee-bearing) + 6x 21 + 6x 22.
    Punch candidates must be exactly the 18 — the OBSERVED.md census as an executable test."""
    page = json.loads((RECORDED / "events_major5_page1.json").read_text(encoding="utf-8"))
    results = classify_batch(page["AcsEvent"]["InfoList"], capabilities=SITE_A_CAPS)
    assert len(results) == 30
    punches = [r for r in results if r.punch_candidate]
    assert len(punches) == 18
    assert all(r.code_name == "FACE_VERIFY_PASS" and r.outcome is Outcome.GRANTED for r in punches)
    door = [r for r in results if r.code_name in ("LOCK_OPEN", "LOCK_CLOSE")]
    assert len(door) == 12
    assert all(r.outcome is Outcome.INFO and not r.punch_candidate for r in door)


def test_recorded_noise_page_is_non_punch_info_and_kept() -> None:
    """major=3/minor=1029, 10,169 of 10,199 events: info, non-punch, and STORED (raw kept).
    Excluding it from punches must never mean deleting it."""
    page = json.loads((RECORDED / "events_more_noise_page1.json").read_text(encoding="utf-8"))
    results = classify_batch(page["AcsEvent"]["InfoList"], capabilities=SITE_A_CAPS)
    assert len(results) == 3
    for r in results:
        assert r.outcome is Outcome.INFO
        assert r.punch_candidate is False
        assert r.operation_stream is True
        assert r.major_class == "OPERATION"
        assert r.raw["minor"] == 1029, "raw preserved — the noise stays auditable"


# --- verify mode discipline --------------------------------------------------------------------


def test_verify_mode_is_verbatim_and_never_invented() -> None:
    """OBSERVED.md: cardOrFaceOrFp does not distinguish face from card. We keep it as-is;
    a consumer that wants face-vs-card must not get a fabricated answer from us."""
    rec = {
        "major": 5,
        "minor": 75,
        "employeeNoString": "1",
        "serialNo": 1,
        "currentVerifyMode": "cardOrFaceOrFp",
    }
    got = classify_event(rec)
    assert got.verify_mode == "cardOrFaceOrFp"
    assert got.punch_candidate is True


def test_granted_pass_without_a_real_verify_mode_is_not_a_punch() -> None:
    """A (5,75) carrying currentVerifyMode 'invalid' is anomalous: kept, granted, but NOT
    a timesheet candidate (card: 'verifyMode is a real auth mode' is part of the rule)."""
    rec = {
        "major": 5,
        "minor": 75,
        "employeeNoString": "1",
        "serialNo": 1,
        "currentVerifyMode": "invalid",
    }
    got = classify_event(rec)
    assert got.outcome is Outcome.GRANTED
    assert got.punch_candidate is False
    assert "not an authentication mode" in (got.reason or "")


@pytest.mark.parametrize("mode", sorted(NON_AUTH_VERIFY_MODES - {""}))
def test_non_auth_modes_disqualify(mode: str) -> None:
    rec = {
        "major": 5,
        "minor": 75,
        "employeeNoString": "1",
        "serialNo": 1,
        "currentVerifyMode": mode,
    }
    assert classify_event(rec).punch_candidate is False


def test_a_verify_mode_we_have_never_seen_still_counts_as_auth() -> None:
    """Refusing an unknown-but-plausible mode would DROP a punch — the failure mode this
    card ranks above everything. Only the explicit non-auth set disqualifies."""
    rec = {
        "major": 5,
        "minor": 75,
        "employeeNoString": "1",
        "serialNo": 1,
        "currentVerifyMode": "faceAndPwAndFpAndCardAndSomethingNew",
    }
    assert classify_event(rec).punch_candidate is True


# --- employee attribution -----------------------------------------------------------------------


def test_pass_without_employee_number_is_not_a_punch_but_is_kept() -> None:
    rec = {"major": 5, "minor": 75, "doorNo": 1, "serialNo": 1, "currentVerifyMode": "face"}
    got = classify_event(rec)
    assert got.punch_candidate is False
    assert got.employee_no is None
    assert "employeeNoString" in (got.reason or "")
    assert got.raw == rec


def test_employee_no_string_beats_the_int_form() -> None:
    """employeeNo truncates leading zeros / alphanumeric ids — DESIGN.md says the string
    form is preferred; both present means the string wins."""
    rec = {
        "major": 5,
        "minor": 1,
        "employeeNoString": "007A",
        "employeeNo": 7,
        "serialNo": 1,
        "currentVerifyMode": "card",
    }
    assert classify_event(rec).employee_no == "007A"


# --- table correctness ----------------------------------------------------------------------------


def test_minor_38_is_fingerprint_not_card() -> None:
    """docs/references/acs-event-codes.md §3: a circulating table mislabels 38 as card
    success. The curated table follows the vendor hex table; card pass is minor 1."""
    assert name_for(5, 38) == "FINGERPRINT_PASS"
    assert name_for(5, 1) == "CARD_PASS"
    assert name_for(5, 113) == "CERTIFICATE_BLACKLIST"


def test_door_state_minors_are_never_in_the_auth_pass_set() -> None:
    assert not {21, 22, 23, 25, 26, 27, 28} & AUTH_PASS_MINORS
    assert {1, 38, 60, 75, 153} <= AUTH_PASS_MINORS


def test_punch_rule_consults_the_auth_minors_set_directly(monkeypatch: pytest.MonkeyPatch) -> None:
    """The auth-minors check is normally shadowed by the outcome check (door codes are
    INFO). If a future table edit ever marks a door code GRANTED, the rule must still
    refuse it — this proves the check bites instead of being decorative."""
    import gateclerk.event_codes as ec

    monkeypatch.setattr(ec, "AUTH_PASS_MINORS", frozenset({75}))
    # (5,21) forced granted via a table override would still not be a candidate...
    monkeypatch.setitem(ec.EVENT_CODE_TABLE, (5, 21), CodeInfo("LOCK_OPEN", Outcome.GRANTED))
    got = classify_event(
        {
            "major": 5,
            "minor": 21,
            "employeeNoString": "1",
            "serialNo": 1,
            "currentVerifyMode": "cardOrFaceOrFp",
        }
    )
    assert got.outcome is Outcome.GRANTED  # the (hypothetical) table says so
    assert got.punch_candidate is False
    assert "not an authentication pass" in (got.reason or "")


def test_outcome_for_unknown_code_is_info() -> None:
    assert outcome_for(5, 999) is Outcome.INFO
    assert outcome_for(9, 1) is Outcome.INFO
    assert outcome_for(5, 75) is Outcome.GRANTED


def test_table_covers_only_majors_the_family_uses_and_matches_the_derived_sets() -> None:
    """Guard the guard: AUTH_PASS_MINORS/DENIED_MINORS are derived from the table, so a
    hand-edit that makes them disagree (or a row under a major outside the vendor's
    0/1/2/3/5) fails here instead of mislabelling punches in production."""
    assert {major for major, _ in EVENT_CODE_TABLE} <= {1, 2, 3, 5}
    for (major, minor), info in EVENT_CODE_TABLE.items():
        assert outcome_for(major, minor) is info.outcome
        if major == 5 and info.outcome is Outcome.GRANTED:
            assert minor in AUTH_PASS_MINORS


def test_capability_advertisement_marks_not_advertised_without_disqualifying() -> None:
    """A granted pass whose minor is absent from the device's advertised set is still a
    punch candidate (the device can under-advertise) — but it is marked."""
    capped = DeviceCapabilities(minors={5: frozenset({75})})
    card_pass = {
        "major": 5,
        "minor": 1,
        "employeeNoString": "1",
        "serialNo": 1,
        "currentVerifyMode": "card",
    }
    got = classify_event(card_pass, capabilities=capped)
    assert got.not_advertised is True
    assert got.punch_candidate is True
    assert "not in the device's advertised set" in (got.reason or "")
    assert classify_event(card_pass, capabilities=SITE_A_CAPS).not_advertised is False
    assert classify_event(card_pass).not_advertised is None, "no caps given: no verdict"


def test_classification_is_serialisable_for_downstream_storage() -> None:
    rec = {
        "major": 5,
        "minor": 75,
        "time": "2026-10-12T14:11:16+02:00",
        "employeeNoString": "1",
        "serialNo": 5742,
        "currentVerifyMode": "cardOrFaceOrFp",
    }
    row = classify_event(rec, capabilities=SITE_A_CAPS).as_dict()
    assert json.dumps(row)  # p1-07/p1-08 will serialise exactly this shape
    assert row["punch_candidate"] is True and row["outcome"] == "granted"
    assert row["serial_no"] == 5742 and row["event_time"] == "2026-10-12T14:11:16+02:00"
