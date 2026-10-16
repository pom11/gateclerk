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
import re
import sys
from dataclasses import replace
from pathlib import Path
from types import ModuleType

import pytest

from gateclerk.capabilities import DeviceCapabilities, parse_acs_event_capabilities
from gateclerk.event_codes import (
    AUTH_PASS_MINORS,
    EVENT_CODE_TABLE,
    NON_AUTH_VERIFY_MODES,
    PUNCH_MAJOR,
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


# --- provenance: no guessed codes, mechanically enforced (review round 1, finding 2) -------
#
# The card's premise is "no guessed codes". These tests make that a machine-checked
# property instead of a docstring promise: every shipped row must carry catalog
# provenance (`src`), must appear in the generated §3.1 table of
# docs/references/acs-event-codes.md, and that table must agree with the vendored
# catalogs under tests/fixtures/vendor/. A row no catalog names cannot survive: it has
# no src and no doc row, and an unnamed code behaves correctly anyway
# (info + unknown_code + kept).

VENDOR = Path(__file__).parent / "fixtures/vendor"
REFERENCE_DOC = Path(__file__).resolve().parents[1] / "docs/references/acs-event-codes.md"

_DOC_ROW = re.compile(
    r"^\|\s*(\d+)\s*\|\s*(\d+)\s*\|\s*([^|]*)\|\s*([^|]*)\|\s*([a-z]+)\s*\|\s*([A-Z0-9_]+)\s*\|\s*([a-z]+)\s*\|\s*`([^`]+)`\s*\|"
)


def vendor_catalogs() -> tuple[dict[int, str], dict[tuple[int, int], dict[str, str]]]:
    """(node-red major-5 hex names, mmisobuj (major,minor) -> {name, outcome})."""
    nodered = json.loads((VENDOR / "node-red-MAJOR_EVENT-0x5.json").read_text(encoding="utf-8"))
    nr: dict[int, str] = {}
    for entry in nodered:
        value = entry["Value"].strip()
        if " to " in value:  # the CUSTOM1..64 range entry, not a single code
            continue
        nr[int(value, 16)] = entry["ShortDescription"]
    mmi_raw = json.loads((VENDOR / "hikvision-acs-event-types.json").read_text(encoding="utf-8"))
    mmi: dict[tuple[int, int], dict[str, str]] = {}
    for major, minors in mmi_raw.items():
        for minor, meta in minors.items():
            mmi[(int(major), int(minor))] = meta
    return nr, mmi


def reference_doc_rows() -> dict[tuple[int, int], dict[str, str]]:
    """Parse the generated §3.1 table out of the reference doc (a data file like any
    fixture — the reviewer must not be able to edit the doc into agreement by hand)."""
    rows: dict[tuple[int, int], dict[str, str]] = {}
    for line in REFERENCE_DOC.read_text(encoding="utf-8").splitlines():
        m = _DOC_ROW.match(line)
        if not m:
            continue
        rows[(int(m.group(1)), int(m.group(2)))] = {
            "nr": m.group(3).strip(),
            "mmi_name": m.group(4).strip(),
            "mmi_outcome": m.group(5),
            "gateclerk_name": m.group(6),
            "gateclerk_outcome": m.group(7),
            "src": m.group(8),
        }
    return rows


def test_every_table_row_carries_catalog_provenance() -> None:
    """No row may exist without a `src:` naming the catalog identifier it was read from.

    This is the direct enforcement of 'no guessed codes': the earlier draft shipped ~20
    rows whose names appear in NO catalog, and nothing failed. Now the provenance is
    data on the row and a test reads it."""
    for (major, minor), info in EVENT_CODE_TABLE.items():
        assert info.src, f"({major},{minor}) {info.name} has no catalog provenance"
        assert info.src.startswith(("nr:", "mmi:", "nr+mmi:")), (
            f"({major},{minor}) src {info.src!r} must be prefixed nr:/mmi:/nr+mmi:"
        )


def test_every_table_row_is_reproduced_in_the_reference_doc() -> None:
    """Every (major, minor) we name — GRANTED, DENIED or INFO — must appear in the
    reference doc's generated §3.1 table, with our exact name and outcome. A reviewer
    reading that table can tell vendor-cited from curated; an unsourced row cannot hide
    in either place."""
    doc_rows = reference_doc_rows()
    assert doc_rows, "the generated §3.1 table must exist in the reference doc"
    missing = [k for k in EVENT_CODE_TABLE if k not in doc_rows]
    assert not missing, f"rows missing from docs/references/acs-event-codes.md §3.1: {missing}"
    for (major, minor), info in EVENT_CODE_TABLE.items():
        row = doc_rows[(major, minor)]
        assert row["gateclerk_name"] == info.name, (major, minor)
        assert row["gateclerk_outcome"] == info.outcome.value, (major, minor)
        assert row["src"] == info.src, (major, minor)


def test_named_codes_trace_to_a_vendored_catalog() -> None:
    """The doc table itself is checked against the vendored catalog fixtures: every row
    we name must be a code the catalogs actually contain. This closes the doc so that a
    fabricated label cannot be laundered into existence by adding it to the .md."""
    nr, mmi = vendor_catalogs()
    for (major, minor), info in EVENT_CODE_TABLE.items():
        in_mmi = (major, minor) in mmi
        in_nr = major == 5 and minor in nr
        assert in_mmi or in_nr, (
            f"({major},{minor}) {info.name} named in EVENT_CODE_TABLE but present in "
            "neither vendored catalog — an unnamed code stays info+unknown_code instead"
        )


def gen_reference() -> ModuleType:
    """Import `scripts/gen_code_reference.py` as a module (same trick as the
    byte-identical pin below) so the provenance guard is checked by the SAME code the
    generator runs — a guard that only exists in this file could be bypassed by
    `gen_code_reference.py --write`."""
    import importlib.util

    spec = importlib.util.spec_from_file_location(
        "gen_code_reference",
        Path(__file__).resolve().parents[1] / "scripts" / "gen_code_reference.py",
    )
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def src_audit() -> list[str]:
    """Every provenance defect in the shipped table, as computed by the generator's own
    `audit_src` over the vendored fixtures."""
    mod = gen_reference()
    return mod.audit_src(EVENT_CODE_TABLE, *mod.load_catalogs())


def test_src_provenance_resolves_in_the_catalog_it_claims() -> None:
    """The identifier inside `src` must exist *in the catalog the token names*.

    Review round 2 found the hole behind the pair-existence check above: five rows
    (5,54/57/60/61/66) claimed `nr+mmi:` for minors the node-red table does not contain,
    and nothing failed — because the earlier guard only asked "does some catalog have this
    (major,minor)?", never "does the cited catalog call it what `src` says?". `audit_src`
    recomputes the only admissible `src` per row from the fixtures (a two-source row cites
    the node-red identifier; a single-source row cites that catalog's own name) and
    compares exactly, so both a wrong catalog token and a wrong identifier are defects.
    """
    problems = src_audit()
    assert not problems, "EVENT_CODE_TABLE provenance does not resolve:\n  " + "\n  ".join(problems)


def test_src_audit_catches_a_fabricated_identifier() -> None:
    """Negative control for the guard above — the reviewer's exact repro.

    Without this, `audit_src` could pass by being vacuous. Each mutant keeps a REAL
    (major,minor) pair and changes only the citation, which is the class of defect that
    survived the previous round's checks."""
    mod = gen_reference()
    nr, mmi = mod.load_catalogs()
    mutations = {
        # claims node-red + mmisobuj, with a name neither catalog has
        (5, 16): "nr+mmi:MINOR_TOTALLY_INVENTED_NAME_NOT_IN_ANY_CATALOG",
        # the round-2 defect verbatim: mmisobuj-only minor cited as node-red
        (5, 54): "nr+mmi:MINOR_FACE_AND_FP_VERIFY_PASS",
        # a real mmisobuj identifier under the wrong catalog token
        (5, 105): "nr+mmi:peopleAndIdCardComparePass",
        # a real pair downgraded to a catalog that does not have it
        (5, 75): "mmi:faceVerifyPass",
        # and no provenance at all
        (5, 1): None,
    }
    for (major, minor), src in mutations.items():
        mutated = dict(EVENT_CODE_TABLE)
        mutated[(major, minor)] = replace(EVENT_CODE_TABLE[(major, minor)], src=src)
        problems = mod.audit_src(mutated, nr, mmi)
        assert problems, f"fabricated src on ({major},{minor}) was not caught: {src!r}"
        assert any(f"({major},{minor})" in p for p in problems), problems


def test_src_audit_catches_a_code_no_catalog_names() -> None:
    """The other direction: an invented (major,minor) row must be refused by the audit,
    so `--write` can never publish a code the catalogs do not contain."""
    mod = gen_reference()
    nr, mmi = mod.load_catalogs()
    mutated = dict(EVENT_CODE_TABLE)
    mutated[(5, 4242)] = CodeInfo(name="INVENTED_PASS", outcome=Outcome.GRANTED, src="mmi:x")
    problems = mod.audit_src(mutated, nr, mmi)
    assert any("(5,4242)" in p for p in problems), problems


def test_generator_refuses_to_write_unresolvable_provenance() -> None:
    """The laundering path, closed: `--write` regenerates §3.1 *from* the row's own `src`,
    so a fabricated citation would otherwise become self-corroborating documentation.
    `require_clean_provenance` runs before anything is printed or written."""
    mod = gen_reference()
    mutated = dict(EVENT_CODE_TABLE)
    mutated[(5, 16)] = replace(
        EVENT_CODE_TABLE[(5, 16)],
        src="nr+mmi:MINOR_TOTALLY_INVENTED_NAME_NOT_IN_ANY_CATALOG",
    )
    with pytest.raises(SystemExit) as raised:
        mod.require_clean_provenance(mutated)
    assert "(5,16)" in str(raised.value)
    # and the shipped table passes it, so the refusal is not unconditional
    mod.require_clean_provenance(EVENT_CODE_TABLE)


def test_write_command_refuses_before_touching_the_doc(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The wiring, not just the helper — the reviewer's repro inverted.

    His probe: set (5,16)'s `src` to a fabricated identifier, run
    `gen_code_reference.py --write`, whole suite stayed green (the doc is generated from
    the same string, so regeneration *corroborated* the lie). The suite now fails on that
    mutation regardless; this pins the other half — that the `--write` command itself
    refuses, rather than only the test noticing afterwards. Runs the real `main()` with a
    patched table and a redirected doc path, then asserts the doc was never written."""
    mod = gen_reference()
    target = tmp_path / "acs-event-codes.md"
    target.write_text("SENTINEL\n", encoding="utf-8")
    mutated = dict(EVENT_CODE_TABLE)
    mutated[(5, 16)] = replace(EVENT_CODE_TABLE[(5, 16)], src="mmi:notWhatTheCatalogSays")
    monkeypatch.setattr(mod, "EVENT_CODE_TABLE", mutated)
    monkeypatch.setattr(mod, "DOC", target)
    monkeypatch.setattr(sys, "argv", ["gen_code_reference.py", "--write"])
    with pytest.raises(SystemExit):
        mod.main()
    assert target.read_text(encoding="utf-8") == "SENTINEL\n", "--write edited the doc anyway"


def test_doc_node_red_column_agrees_with_the_src_token() -> None:
    """The self-contradiction the reviewer read off the generated table: a row whose `src`
    claims node-red must show a node-red name in §3.1, and a row that does not claim it
    must show the em dash. Pairs the .md's own columns against the row's provenance."""
    for (major, minor), row in reference_doc_rows().items():
        src = row["src"]
        claims_nr = src.startswith(("nr:", "nr+mmi:"))
        shows_nr = row["nr"] not in {"", "—"}
        assert claims_nr == shows_nr, (
            f"({major},{minor}) src={src!r} claims node-red={claims_nr} but the doc's "
            f"node-red column reads {row['nr']!r}"
        )


def test_five_face_combo_rows_are_mmisobuj_only() -> None:
    """Pin the round-2 correction itself: these five minors exist in mmisobuj and NOT in
    the node-red hex table, so they must be cited single-source."""
    nr, mmi = vendor_catalogs()
    for minor in (54, 57, 60, 61, 66):
        assert minor not in nr, f"node-red unexpectedly has minor {minor}"
        assert (5, minor) in mmi
        info = EVENT_CODE_TABLE[(5, minor)]
        assert info.src == f"mmi:{mmi[(5, minor)]['name']}", (minor, info.src)


def test_outcome_follows_the_catalog_except_where_declared() -> None:
    """The mmisobuj catalog is the only source that states an outcome per code. Our
    outcome must equal it, unless the row's deviation is declared in the doc's §3.2
    table (which records the reason — majors 1/2 are never DENIED, invalid-card is,
    etc.). The deviations list is parsed from the doc, so both the deviation and its
    justification live where a reviewer reads them."""
    _, mmi = vendor_catalogs()
    declared = declared_deviations()
    for (major, minor), info in EVENT_CODE_TABLE.items():
        meta = mmi.get((major, minor))
        if meta is None:
            continue  # single-source row (node-red only): no catalog outcome to compare
        if meta["outcome"] != info.outcome.value:
            assert (major, minor) in declared, (
                f"({major},{minor}) outcome {info.outcome.value} deviates from "
                f"mmisobuj's {meta['outcome']!r} without a §3.2 declaration"
            )


def declared_deviations() -> set[tuple[int, int]]:
    """(major, minor) pairs listed in the doc's generated §3.2 deviations table."""
    pairs: set[tuple[int, int]] = set()
    in_32 = False
    for line in REFERENCE_DOC.read_text(encoding="utf-8").splitlines():
        if line.startswith("### 3.2"):
            in_32 = True
            continue
        if in_32 and line.startswith("### "):
            break
        if in_32:
            m = re.match(
                r"^\|\s*(\d+)\s*\|\s*(\d+)\s*\|\s*[a-z]+\s*\|\s*[a-z]+\s*\|\s*.+\|\s*$", line
            )
            if m:
                pairs.add((int(m.group(1)), int(m.group(2))))
    return pairs


def test_generated_block_is_byte_identical_to_the_generator_output() -> None:
    """The §3.1/§3.2 block in the doc must equal `scripts/gen_code_reference.py`'s
    output right now. This pins the doc against hand-edits from BOTH directions: edit a
    row's catalog name in the .md and this fails; edit the code table and re-generation
    is the only sanctioned way to move the doc. (Tampering the generator itself is a
    code-review problem, same as tampering a test.)"""
    import importlib.util

    spec = importlib.util.spec_from_file_location(
        "gen_code_reference",
        Path(__file__).resolve().parents[1] / "scripts" / "gen_code_reference.py",
    )
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    block = mod.build_block()
    text = REFERENCE_DOC.read_text(encoding="utf-8")
    assert block in text, (
        "the generated block in docs/references/acs-event-codes.md has drifted from "
        "`uv run python scripts/gen_code_reference.py --write` — re-run the generator"
    )


def test_deviations_are_exactly_the_declared_ones() -> None:
    """The other direction: a §3.2 row whose reason no longer applies (because the code
    table came back into agreement) must be pruned, not left claiming a deviation."""
    _, mmi = vendor_catalogs()
    for major, minor in declared_deviations():
        info = EVENT_CODE_TABLE.get((major, minor))
        assert info is not None, f"§3.2 declares ({major},{minor}) but the table has no such row"
        meta = mmi.get((major, minor))
        assert meta is not None and meta["outcome"] != info.outcome.value, (
            f"§3.2 still declares a deviation for ({major},{minor}) that no longer exists"
        )


def test_alarms_and_exceptions_are_never_granted_or_denied() -> None:
    """Majors 1/2 never carry an auth outcome for us, even where mmisobuj stamps a code
    `denied` by name-matching (e.g. (1,1036)). An alarm is not a refused credential."""
    for (major, minor), info in EVENT_CODE_TABLE.items():
        if major in (1, 2):
            assert info.outcome is Outcome.INFO, (major, minor, info.name)


def test_granted_rows_are_catalog_pass_or_success_codes() -> None:
    """`granted` may only be imported for codes the catalogs actually name PASS/SUCCESS.

    mmisobuj's `granted` column is name-matched and marks even a firmware upgrade
    `granted` ((5,175) remoteExtendModuleUpgradeSucc); a bulk import of that column
    would turn an upgrade into a timesheet punch. This pins the rule that whatever we
    mark GRANTED, the catalog word for it contains pass/success."""
    nr, mmi = vendor_catalogs()
    for (major, minor), info in EVENT_CODE_TABLE.items():
        if major != PUNCH_MAJOR or info.outcome is not Outcome.GRANTED:
            continue
        words = ""
        if (major, minor) in mmi:
            words += mmi[(major, minor)]["name"].lower()
        if minor in nr:
            words += " " + nr[minor].lower()
        assert "pass" in words or "success" in words, (
            f"({major},{minor}) {info.name} marked GRANTED but no catalog calls it a "
            "pass/success — GRANTED is only ever imported for real auth passes"
        )


def test_catalog_granted_upgrades_are_not_in_our_table() -> None:
    """The concrete counter-example: (5,175) is `granted` in mmisobuj but is a firmware
    upgrade. If it ever enters our table, this fires — it must stay unnamed
    (info + unknown_code), never a punch."""
    for major, minor in ((5, 175), (5, 177), (5, 224), (5, 219)):
        assert (major, minor) not in EVENT_CODE_TABLE
        got = classify_event(
            {
                "major": 5,
                "minor": minor,
                "employeeNoString": "1",
                "serialNo": 1,
                "currentVerifyMode": "cardOrFaceOrFp",
            }
        )
        assert got.unknown_code and not got.punch_candidate


def test_renamed_rows_keep_their_corrected_names() -> None:
    """Names that were invented in the first draft (they appear in NO catalog) must come
    back corrected, not 'helpfully' restored: (5,154) is a TIMEOUT in both catalogs,
    (5,34) and (5,105) are catalog-named PASSES the earlier INFO label silently dropped,
    and (3,90) is localUpgrade — LOCAL_LOGOUT is (3,81)."""
    assert name_for(5, 154) == "COMBINED_VERIFY_TIMEOUT"
    assert outcome_for(5, 154) is Outcome.DENIED
    assert name_for(3, 90) == "LOCAL_UPGRADE"
    assert name_for(3, 81) == "LOCAL_LOGOUT"
    # The silent-drop class: both are GRANTED catalog passes now.
    assert outcome_for(5, 34) is Outcome.GRANTED
    assert outcome_for(5, 105) is Outcome.GRANTED
    assert {34, 105} <= AUTH_PASS_MINORS
    rec = {
        "major": 5,
        "minor": 34,
        "employeeNoString": "1",
        "serialNo": 1,
        "currentVerifyMode": "cardOrFaceOrFp",
    }
    assert classify_event(rec).punch_candidate is True


def test_no_row_names_a_code_that_only_our_own_table_invents() -> None:
    """Cross-check every shipped NAME against the catalogs' wording, not just the code.

    A row like (5,142) DEVICE_TAMPER passes a code-existence check while still inventing
    a label (the catalogs call 142 localFaceModelingFail), so name agreement is required
    too: our name must share at least one word (case-insensitive) with a catalog name for
    the same code. No abbreviation table: every shipped name already shares a stem with
    the catalog wording, which is exactly what this guard is for."""
    nr, mmi = vendor_catalogs()

    def words(name: str) -> set[str]:
        return {tok for tok in name.upper().split("_") if len(tok) > 2}

    for (major, minor), info in EVENT_CODE_TABLE.items():
        ours = {w.lower() for w in words(info.name)}
        candidates: set[str] = set()
        if (major, minor) in mmi:
            candidates |= {
                w.lower() for w in re.split(r"(?=[A-Z])", mmi[(major, minor)]["name"]) if len(w) > 2
            }
        if major == 5 and minor in nr:
            candidates |= {w.lower() for w in nr[minor].split("_") if len(w) > 2}
        assert ours & candidates, (
            f"({major},{minor}) {info.name} shares no word with any catalog name for "
            f"this code ({mmi.get((major, minor), {}).get('name')} / {nr.get(minor)})"
        )
