"""Card E1-02 definition of done: the diff engine, offline and FakeDevice-strict.

Layers of proof (all offline — `netoff` autouse; device reads ONLY through the
injected search-fn, which the end-to-end test wires to `collect_enrollment_state`
over the real `IsapiClient` + FakeDevice):

* the four classes (add/update/same/conflict) and EVERY reason code the card names:
  card_no_bound_to_other_employee (pair identity), target_only_cards,
  unknown_enrollments (numOfFace=1 + failed read -> CONFLICT not update, §9),
  template_ref_unproven (gated on --carry-templates + the evidence set, §1a),
  normalization_collision ("007" vs "7" kept apart, both skipped, §1),
  validity_unparseable (unparseable + DST-gap wall time refused; DST-fold usable+flagged);
* §1a v4: a planTemplateNo-"1" add is NOT a door-field conflict (scope note 1);
  customs are report-only by default, carried-UNVERIFIED with evidence, unproven when
  --carry-templates names an absent number;
* face/FP set identity by template sha (scope note 2): source-has-target-lacks is
  add-side, target-has-bundle-lacks is conflict, counter cross-check is report-only;
* the freshness helper `plan_still_valid` (changed / vanished / appeared -> abort
  list) and the E1-03 staleness gate wired into `plan()` with an injected clock;
* same-after-apply re-run -> ZERO writes by construction (§4);
* the report: employeeNo hash prefix only, field NAMES only (no-PII assertion on the
  rendered text), byte-stable JSON schema, exit mapping 0/1/2; the skip / overwrite /
  abort policies; and the merged fake keeping E1-01's unknown-POST trap armed.
"""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import httpx
import pytest

from fakedevice import BASE_URL, EnrollmentProtocolError, FakeDevice
from gateclerk.isapi_transport import IsapiClient
from gateclerk.migrate_bundle import BundleData, BundleManifest, FacesIndex, read_bundle
from gateclerk.migrate_diff import (
    Classification,
    ConflictPolicy,
    DiffAbortedError,
    DiffClass,
    DiffPolicy,
    Plan,
    Reason,
    TargetBiometrics,
    TemplateRef,
    classify,
    employee_hash,
    plan,
    plan_still_valid,
    read_target_state,
    render_report,
)
from gateclerk.migrate_export import EnrollmentState, export_bundle
from gateclerk.migrate_probe import CapabilityMatrix, ProbeStaleError, probe_device

FIXTURES = Path(__file__).parent / "fixtures/recorded/site-a-ds-k1t341amf-s"
SYNTH = Path(__file__).parent / "fixtures/synthetic"
DEVICE_INFO_PATH = "/ISAPI/System/deviceInfo?format=json"
PASSWORD = "fake" + "pw"  # placeholder policy (tests/test_repo_hygiene.py)
SITE_TZ = "Europe/Bucharest"
NOW = datetime(2026, 10, 21, 9, 0, 0, tzinfo=UTC)

_UNSET = object()


# --- fixture builders ---------------------------------------------------------------


def user(no: str, **extra: Any) -> dict[str, Any]:
    """A bench-A-shaped UserInfo record, overridable field by field."""
    record: dict[str, Any] = {
        "employeeNo": no,
        "name": f"User E{no}",
        "userType": "normal",
        "Valid": {
            "enable": True,
            "beginTime": "2000-01-01T00:00:00",
            "endTime": "2037-12-31T23:59:59",
            "timeType": "local",
        },
        "doorRight": "1",
        "RightPlan": [{"doorNo": 1, "planTemplateNo": "1"}],
        "localUIRight": False,
        "numOfCard": 0,
        "numOfFace": 0,
        "numOfFP": 0,
    }
    record.update(extra)
    return record


def card(emp: str, no: str) -> dict[str, str]:
    return {"employeeNo": emp, "cardNo": no, "cardType": "normalCard"}


def bundle_of(people: list[dict], cards: list[dict]) -> BundleData:
    """A BundleData for classification (the diff never reads the manifest — hashes are
    recomputed from the record bytes through the ONE migrate_bundle function)."""
    manifest = BundleManifest(
        schema_version="gateclerk-enrollment-bundle/1",
        exported_at="2026-10-21T12:00:00+00:00",
        identity={"model": "DS-K1T341AMF-S", "firmware": "V3.2.30", "serial_prefix": "ab12cd"},
        counts={"users": len(people), "cards": len(cards), "faces": 0},
        people_hashes={},
        volatile_fields_digest="",
        faces={"state": "UNAVAILABLE", "reason": "test"},
        termination={},
    )
    return BundleData(
        manifest=manifest, people=tuple(people), cards=tuple(cards), faces=FacesIndex()
    )


def biometrics_of(faces: Any = _UNSET, fps: Any = _UNSET) -> TargetBiometrics:
    """The biometric seam: an explicit dict = the read SUCCEEDED (rows by employeeNo);
    None = the read FAILED (UNKNOWN, §9); unset = succeeded EMPTY."""
    faces_v = {} if faces is _UNSET else faces
    fps_v = {} if fps is _UNSET else fps
    return TargetBiometrics(
        faces=faces_v if faces_v is not None else None,
        faces_error=None if faces_v is not None else "read refused",
        fingerprints=fps_v if fps_v is not None else None,
        fingerprints_error=None if fps_v is not None else "read refused",
    )


def state_of(people: list[dict], cards: list[dict]) -> EnrollmentState:
    return EnrollmentState(
        users=tuple(people),
        cards=tuple(cards),
        identity={},
        termination={"UserInfo/Search": "OK", "CardInfo/Search": "OK"},
    )


def classify_case(
    bundle_people: list[dict],
    target_people: list[dict],
    bundle_cards: list[dict] | None = None,
    target_cards: list[dict] | None = None,
    *,
    policy: DiffPolicy | None = None,
    faces: Any = _UNSET,  # dict = read-OK rows; None = read FAILED; _UNSET = OK-empty
    fps: Any = _UNSET,
    bundle_faces: dict | None = None,
    bundle_fingerprints: dict | None = None,
) -> list[Classification]:
    """One-shot classify with default-succeeded-empty biometric reads (§9 axes only
    get exercised when a test says `faces=None` / `fps=None` explicitly)."""
    return classify(
        bundle_people,
        target_people,
        bundle_cards or [],
        target_cards or [],
        None,
        policy=policy or DiffPolicy(site_tz=SITE_TZ),
        bundle_faces=bundle_faces,
        bundle_fingerprints=bundle_fingerprints,
        biometrics=biometrics_of(faces, fps),
    )


def by_no(items: list[Classification], no: str) -> Classification:
    h = employee_hash(no)
    return next(i for i in items if i.employee_hash == h)


def reclassify(
    item: Classification, kind: DiffClass, reasons: tuple[Reason, ...] = ()
) -> Classification:
    from dataclasses import replace

    return replace(item, classification=kind, reasons=reasons)


# --- the four classes -----------------------------------------------------------------


def test_add_update_same_across_the_four_user_corpus() -> None:
    bundle = [user("1"), user("2"), user("3"), user("4")]
    target = [user("1"), user("2", name="Changed")]
    items = classify_case(bundle, target)
    assert by_no(items, "1").classification is DiffClass.SAME
    assert by_no(items, "1").notes[-1] == "hash_equal"
    upd = by_no(items, "2")
    assert upd.classification is DiffClass.UPDATE
    assert upd.fields == ("name",)  # NAMES only (§4)
    assert upd.would_write == 1
    assert by_no(items, "3").classification is DiffClass.ADD
    assert by_no(items, "3").would_write == 1
    assert by_no(items, "4").classification is DiffClass.ADD


def test_target_only_person_is_same_never_a_deletion() -> None:
    items = classify_case([user("1")], [user("1"), user("ghost")])
    ghost = by_no(items, "ghost")
    assert ghost.classification is DiffClass.SAME
    assert "target_only_person(kept;v1_never_deletes)" in ghost.notes
    assert ghost.would_write == 0


# --- §1 opaque employeeNo: normalization collisions ------------------------------------


def test_leading_zero_pair_is_a_conflict_not_a_merge() -> None:
    # "007" vs "7" — the card's own example: leading zeros ARE data (§1).
    items = classify_case([user("007")], [user("7")])
    src = by_no(items, "007")
    assert src.classification is DiffClass.CONFLICT
    assert src.reasons == (Reason.NORMALIZATION_COLLISION,)
    assert src.would_write == 0  # skipped
    # ...and the twin stays untouched: BOTH kept, both skipped (§1).
    tgt = by_no(items, "7")
    assert tgt.classification is DiffClass.SAME
    assert tgt.would_write == 0


def test_case_mix_pair_is_a_conflict_not_a_merge() -> None:
    items = classify_case([user("e1")], [user("E1")])
    assert by_no(items, "e1").reasons == (Reason.NORMALIZATION_COLLISION,)
    assert by_no(items, "E1").classification is DiffClass.SAME


def test_exact_match_never_collides_across_families() -> None:
    # "7" matching "7" exactly is normal even with a sloppy neighbour present, and
    # the int family must not swallow a non-digit ("7" vs "07a" is not a collision).
    items = classify_case([user("7")], [user("07a"), user("7")])
    assert by_no(items, "7").classification is DiffClass.SAME


# --- §5 step 5 card pair identity ---------------------------------------------------------


def test_card_bound_to_other_employee_is_a_sticky_conflict() -> None:
    # The card the bundle wants for "1" already belongs to "9" on the target.
    items = classify_case(
        [user("1")],
        [user("1"), user("9")],
        bundle_cards=[card("1", "c-07")],
        target_cards=[card("9", "c-07")],
    )
    one = by_no(items, "1")
    assert one.classification is DiffClass.CONFLICT
    assert one.reasons == (Reason.CARD_BOUND_TO_OTHER,)
    assert one.would_write == 0
    # Sticky: even --on-conflict=overwrite never REASSIGNS (that would strip person 9).
    forced = classify_case(
        [user("1")],
        [user("1"), user("9")],
        bundle_cards=[card("1", "c-07")],
        target_cards=[card("9", "c-07")],
        policy=DiffPolicy(on_conflict=ConflictPolicy.OVERWRITE, site_tz=SITE_TZ),
    )
    assert by_no(forced, "1").classification is DiffClass.CONFLICT


def test_card_pair_identity_makes_re_runs_idempotent() -> None:
    # The (cardNo, employeeNo) PAIR already exists -> zero writes. (Presence alone
    # would also pass this one; the different-owner test above is the pair half.)
    items = classify_case(
        [user("1")], [user("1")], bundle_cards=[card("1", "c-07")], target_cards=[card("1", "c-07")]
    )
    assert by_no(items, "1").classification is DiffClass.SAME
    assert by_no(items, "1").would_write == 0


def test_new_card_alone_is_an_update_needing_one_write() -> None:
    items = classify_case([user("1")], [user("1")], bundle_cards=[card("1", "c-new")])
    one = by_no(items, "1")
    assert one.classification is DiffClass.UPDATE  # no field diff, but a card to write
    assert one.would_write == 1
    assert "card_adds:1" in one.notes


def test_target_only_cards_conflict_and_overwrite_path() -> None:
    # Target holds a card the bundle does not carry: §4 conflict (skipped by default)...
    people_b = [user("1", name="Wanted")]
    people_t = [user("1")]
    items = classify_case(
        people_b,
        people_t,
        bundle_cards=[card("1", "c-07")],
        target_cards=[card("1", "c-07"), card("1", "extra")],
    )
    one = by_no(items, "1")
    assert one.classification is DiffClass.CONFLICT
    assert one.reasons == (Reason.TARGET_ONLY_CARDS,)
    assert one.would_write == 0
    # ...overwrite resolves exactly THIS class (the write never REMOVES "extra"):
    # the person's name diff becomes an actionable update again.
    forced = classify_case(
        people_b,
        people_t,
        bundle_cards=[card("1", "c-07")],
        target_cards=[card("1", "c-07"), card("1", "extra")],
        policy=DiffPolicy(on_conflict=ConflictPolicy.OVERWRITE, site_tz=SITE_TZ),
    )
    upd = by_no(forced, "1")
    assert upd.classification is DiffClass.UPDATE
    assert upd.fields == ("name",)
    assert upd.would_write == 1


# --- §9 UNKNOWN-not-zero biometrics -------------------------------------------------------


def test_unreadable_face_with_counter_is_conflict_not_update() -> None:
    # The card's own boundary: numOfFace=1 and the read FAILED -> CONFLICT, not update.
    items = classify(
        [user("1", name="Wanted")],
        [user("1", numOfFace=1)],
        [],
        [],
        None,
        policy=DiffPolicy(site_tz=SITE_TZ),
        biometrics=biometrics_of(faces=None),
    )
    one = by_no(items, "1")
    assert one.classification is DiffClass.CONFLICT
    assert one.reasons == (Reason.UNKNOWN_ENROLLMENTS,)
    assert "unknown_faces:counter=1" in one.notes
    assert one.would_write == 0


def test_unreadable_with_zero_counter_is_not_a_conflict() -> None:
    # Nothing claims to exist (counter 0) -> UNKNOWN is noted, the update may proceed.
    items = classify_case(
        [user("1", name="Wanted")], [user("1", numOfFace=0, numOfFP=0)], faces=None, fps=None
    )
    one = by_no(items, "1")
    assert one.classification is DiffClass.UPDATE
    assert one.would_write == 1
    assert "face_read_failed(unknown_not_zero)" in one.notes


def test_add_person_with_failed_biometric_reads_is_not_blocked() -> None:
    # No target person -> no counter claim -> UNKNOWN cannot conflict (§9 needs N>0).
    items = classify_case([user("1")], [], faces=None, fps=None)
    assert by_no(items, "1").classification is DiffClass.ADD


def test_face_set_identity_rules() -> None:
    # source-has / target-lacks = add-side upload (not a conflict)...
    items = classify_case(
        [user("1")], [user("1")], bundle_faces={"1": (ref("1", "a" * 64),)}, faces={}
    )
    one = by_no(items, "1")
    assert one.classification is DiffClass.UPDATE  # no field diff, one upload
    assert one.would_write == 1
    assert "face_uploads:1" in one.notes
    # ...target-has / bundle-lacks = conflict (§4 + scope note 2).
    items = classify_case(
        [user("1")],
        [user("1")],
        bundle_faces={"1": (ref("1", "a" * 64),)},
        faces={"1": (ref("1", "a" * 64), ref("1", "b" * 64))},
    )
    one = by_no(items, "1")
    assert one.classification is DiffClass.CONFLICT
    assert one.reasons == (Reason.TARGET_ONLY_FACES,)
    assert "target_only_faces:1" in one.notes
    # set identity by sha: same COUNT, different sha -> still target-only.
    items = classify_case(
        [user("1")],
        [user("1")],
        bundle_faces={"1": (ref("1", "c" * 64),)},
        faces={"1": (ref("1", "d" * 64),)},
    )
    assert by_no(items, "1").reasons == (Reason.TARGET_ONLY_FACES,)
    # counter cross-check on a SUCCESSFUL read is report-only, never a conflict.
    items = classify_case(
        [user("1")],
        [user("1", numOfFace=2)],
        bundle_faces={"1": (ref("1", "a" * 64),)},
        faces={"1": (ref("1", "a" * 64),)},
    )
    one = by_no(items, "1")
    assert one.classification is DiffClass.SAME
    assert "face_counter_cross_check:counter=2,rows=1" in one.notes


def test_fp_axis_mirrors_faces() -> None:
    items = classify_case(
        [user("1")],
        [user("1")],
        bundle_fingerprints={"1": (ref("1", "e" * 64, index=1),)},
        fps={"1": (ref("1", "f" * 64, index=1),)},
    )
    assert by_no(items, "1").reasons == (Reason.TARGET_ONLY_FINGERPRINTS,)


def ref(emp: str, sha: str, *, index: int | None = None) -> TemplateRef:
    return TemplateRef(employee_no=emp, index=index, sha256=sha, length=272)


# --- §1a door fields -----------------------------------------------------------------------


def test_template_1_add_is_carried_not_a_door_conflict() -> None:
    # Scope note 1 (v4): planTemplateNo "1" is carried by DEFAULT — the classifier
    # must NOT file a template-1 add as a door-field conflict.
    items = classify_case([user("1")], [])
    one = by_no(items, "1")
    assert one.classification is DiffClass.ADD
    assert one.reasons == ()
    assert not [n for n in one.notes if n.startswith(("template_", "report_only_diff"))]


def test_custom_template_defaults_report_only_never_actionable() -> None:
    # Target evidence = what the TARGET's own records reference (here only "1"); the
    # bundle person references "2": report-only note, RightPlan NEVER in fields.
    items = classify_case(
        [user("1", RightPlan=[{"doorNo": 1, "planTemplateNo": "2"}])], [user("1")]
    )
    one = by_no(items, "1")
    assert one.classification is DiffClass.SAME  # door-only diff -> zero-write (§1a)
    assert one.fields == ()
    assert "template_report_only:2" in one.notes
    assert "report_only_diff:RightPlan" in one.notes


def test_custom_template_carry_paths() -> None:
    carry = DiffPolicy(carry_templates=True, site_tz=SITE_TZ)
    # (a) the number IS in the target's evidence set -> carried, flagged UNVERIFIED.
    items = classify_case(
        [user("1", RightPlan=[{"doorNo": 1, "planTemplateNo": "2"}]), user("2")],
        [user("1"), user("2", RightPlan=[{"doorNo": 1, "planTemplateNo": "2"}])],
        policy=carry,
    )
    one = by_no(items, "1")
    assert "template_carried_unverified:2" in one.notes
    # (b) --carry-templates naming a number ABSENT from the evidence set -> the
    # operator asked for the impossible: template_ref_unproven CONFLICT (§3/§1a).
    items = classify_case(
        [user("1", RightPlan=[{"doorNo": 1, "planTemplateNo": "3"}])],
        [user("1")],
        policy=carry,
    )
    one = by_no(items, "1")
    assert one.classification is DiffClass.CONFLICT
    assert one.reasons == (Reason.TEMPLATE_REF_UNPROVEN,)
    assert "unproven_template_refs:3" in one.notes


def test_door_right_diff_is_report_only_never_actionable() -> None:
    items = classify_case([user("1", doorRight="1,2")], [user("1")])
    one = by_no(items, "1")
    assert one.classification is DiffClass.SAME
    assert "report_only_diff:doorRight" in one.notes
    assert "doorRight" not in one.fields


# --- Valid: unparseable, DST gap, DST fold ----------------------------------------------------


def test_validity_unparseable_conflict() -> None:
    broken = user(
        "1", Valid={"enable": True, "beginTime": "not-a-date", "endTime": "x", "timeType": "local"}
    )
    items = classify_case([broken], [])
    one = by_no(items, "1")
    assert one.classification is DiffClass.CONFLICT
    assert one.reasons == (Reason.VALIDITY_UNPARSEABLE,)
    assert "validity:beginTime:unparseable" in one.notes


def test_validity_dst_gap_wall_time_is_refused() -> None:
    # Europe/Bucharest springs forward 2026-03-29 at 03:00 -> 04:00, so 03:30 does
    # not exist. A stamp inside the gap means a broken device clock; payroll validity
    # must not be written off one (p1-06d: the flag is the finding, not a correction).
    gap = user(
        "1",
        Valid={
            "enable": True,
            "beginTime": "2026-03-29T03:30:00",
            "endTime": "2037-12-31T23:59:59",
            "timeType": "local",
        },
    )
    items = classify_case([gap], [])
    one = by_no(items, "1")
    assert one.reasons == (Reason.VALIDITY_UNPARSEABLE,)
    assert "validity:beginTime:nonexistent_wall_time" in one.notes


def test_validity_dst_fold_is_usable_and_flagged() -> None:
    # 2026-10-25 03:30 Bucharest occurs TWICE (autumn fold): usable under the
    # documented fold=0 (first occurrence) rule, flagged report-only.
    fold = user(
        "1",
        Valid={
            "enable": True,
            "beginTime": "2026-10-25T03:30:00",
            "endTime": "2037-12-31T23:59:59",
            "timeType": "local",
        },
    )
    items = classify_case([fold], [])
    one = by_no(items, "1")
    assert one.classification is DiffClass.ADD
    assert "validity_ambiguous(site_tz;fold=0_first_occurrence)" in one.notes


# --- §1a security ack ------------------------------------------------------------------------


def test_security_fields_are_listed_for_ack() -> None:
    items = classify_case([user("1", localUIRight=True, userType="visitor")], [])
    one = by_no(items, "1")
    assert one.classification is DiffClass.ADD  # carried, but ack-listed
    assert one.security_flags == ("localUIRight=true", "userType=visitor")


# --- same-after-apply: zero writes BY CONSTRUCTION (§4) ---------------------------------------


def test_rerun_after_apply_writes_is_all_same_zero_writes() -> None:
    # Writable content diff (§5 line-216 allow-list: name is a bundle-owned field)
    # + two adds. `userVersion` stays as the volatile-counter-proof check: it is NOT
    # in the volatile strip set, so it participates in the diff like any content field.
    bundle_people = [user("1"), user("2", name="Wanted"), user("3")]
    target_people = [user("1"), user("2")]
    first = classify_case(bundle_people, target_people)
    assert sum(i.would_write for i in first) == 2  # 1 add (person 3) + 1 name update
    assert {i.classification for i in first if i.employee_hash == employee_hash("2")} == {
        DiffClass.UPDATE
    }
    # "Apply" = the target now carries exactly the bundle rows (everything the plan
    # named written). Re-diffing that state MUST be zero-write — idempotent by §4.
    applied = [dict(p) for p in bundle_people]
    again = classify_case(applied, applied)
    assert all(i.classification is DiffClass.SAME for i in again)
    assert sum(i.would_write for i in again) == 0


# --- the plan seam + freshness contract ----------------------------------------------------------


def test_plan_reads_target_through_the_injected_fn_once() -> None:
    calls: list[int] = []

    def search_fn() -> EnrollmentState:
        calls.append(1)
        return state_of([user("1")], [])

    result = plan(bundle_of([user("1"), user("2")], []), search_fn, DiffPolicy(site_tz=SITE_TZ))
    assert calls == [1]
    assert len(result.adds) == 1 and len(result.same) == 1
    assert result.would_write == 1
    assert result.exit_code == 1
    assert result.target_termination["UserInfo/Search"] == "OK"
    assert result.source_counts == {
        "bundle_people": 2,
        "bundle_cards": 0,
        "target_people": 1,
        "target_cards": 0,
    }


def test_plan_exit_codes_zero_one_two() -> None:
    same = plan(bundle_of([user("1")], []), state_of([user("1")], []), DiffPolicy(site_tz=SITE_TZ))
    assert same.exit_code == 0
    changed = plan(
        bundle_of([user("1"), user("9")], []),
        state_of([user("1")], []),
        DiffPolicy(site_tz=SITE_TZ),
    )
    assert changed.exit_code == 1
    # conflicts pending, nothing writable -> config-problem (2)
    conflict = plan(
        bundle_of([user("007")], []), state_of([user("7")], []), DiffPolicy(site_tz=SITE_TZ)
    )
    assert conflict.exit_code == 2 and conflict.would_write == 0


def test_plan_abort_policy_raises_with_the_conflicts() -> None:
    abort = DiffPolicy(on_conflict=ConflictPolicy.ABORT, site_tz=SITE_TZ)
    with pytest.raises(DiffAbortedError) as excinfo:
        plan(bundle_of([user("007")], []), state_of([user("7")], []), abort)
    assert [c.reasons for c in excinfo.value.conflicts] == [(Reason.NORMALIZATION_COLLISION,)]
    # No conflicts -> no raise.
    plan(bundle_of([user("1")], []), state_of([user("1")], []), abort)


def _probe_device() -> FakeDevice:
    """Bench-A-shaped box with the E1-03 probe's classic routes installed."""
    d = FakeDevice(password=PASSWORD)
    d.xml_ok("GET", DEVICE_INFO_PATH, (FIXTURES / "device_info.xml").read_text())
    d.xml_ok("GET", "/ISAPI/System/time?format=json", (FIXTURES / "system_time.xml").read_text())
    d.add(
        "GET",
        "/ISAPI/AccessControl/AcsEvent/capabilities?format=json",
        httpx.Response(200, content=(FIXTURES / "acs_capabilities.json").read_text().encode()),
    )
    d.json_ok(
        "GET",
        "/ISAPI/AccessControl/capabilities?format=json",
        json.loads((SYNTH / "access_control_capabilities.json").read_text()),
    )
    d.install_enrollment()
    return d


def test_plan_refuses_a_stale_probe_via_the_freshness_gate() -> None:
    device = _probe_device()
    client = IsapiClient(
        BASE_URL, "admin", PASSWORD, transport=device.transport, sleep=lambda _s: None
    )
    matrix = probe_device(client, now=NOW, site="site-a", host="192.0.2.10")
    with pytest.raises(ProbeStaleError, match="stale"):
        plan(
            bundle_of([user("2")], []),
            state_of([user("1")], []),
            DiffPolicy(site_tz=SITE_TZ),
            probe=matrix,
            now=NOW + timedelta(days=7, seconds=1),
        )
    # ...and the same matrix is honoured inside the 7-day window.
    result = plan(
        bundle_of([user("2")], []),
        state_of([user("1")], []),
        DiffPolicy(site_tz=SITE_TZ),
        probe=matrix,
        now=NOW + timedelta(days=6),
    )
    assert len(result.adds) == 1


def test_freshness_helper_reports_changed_vanished_and_new() -> None:
    p = plan(
        bundle_of([user("1"), user("2")], []),
        state_of([user("1")], []),
        DiffPolicy(site_tz=SITE_TZ),
    )
    assert plan_still_valid(p, list(p.items)) == []  # unchanged -> still valid
    drifted = [
        reclassify(by_no(list(p.items), "1"), DiffClass.CONFLICT, (Reason.UNKNOWN_ENROLLMENTS,)),
        by_no(list(p.items), "2"),
    ]
    assert plan_still_valid(p, drifted) == [employee_hash("1")]  # classification changed
    assert plan_still_valid(p, []) == sorted([employee_hash("1"), employee_hash("2")])  # vanished
    stranger = Classification(employee_hash=employee_hash("x"), classification=DiffClass.SAME)
    assert plan_still_valid(p, [*list(p.items), stranger]) == [employee_hash("x")]  # new mid-run
    # a reason-set change alone is drift too (same class is not enough)
    reasons_drift = [
        reclassify(i, i.classification, (Reason.UNKNOWN_ENROLLMENTS,))
        if i.employee_hash == employee_hash("2")
        else i
        for i in p.items
    ]
    assert plan_still_valid(p, reasons_drift) == [employee_hash("2")]


# --- end-to-end through the real reader + FakeDevice ----------------------------------------------


def seeded_device() -> FakeDevice:
    device = FakeDevice(password=PASSWORD)
    device.xml_ok("GET", DEVICE_INFO_PATH, (FIXTURES / "device_info.xml").read_text())
    device.seed_enrollment()
    return device


def make_client(device: FakeDevice) -> IsapiClient:
    return IsapiClient(
        BASE_URL, "admin", PASSWORD, transport=device.transport, sleep=lambda _s: None
    )


def export_from(device: FakeDevice, out: Path) -> BundleData:
    """Export a real bundle with the E1-01 engine and read it back: the diff consumes
    bundles exactly as export produces them — no fixture shortcut."""
    result = export_bundle(
        out / "snapshot",
        client=make_client(device),
        clock=lambda: NOW,
        inter_page_delay=0.0,
        sleep=lambda _s: None,
        pacing_clock=lambda: 0.0,
    )
    return read_bundle(result.bundle_dir)


def test_end_to_end_diff_reads_the_target_fresh(tmp_path: Path) -> None:
    device = seeded_device()
    data = export_from(device, tmp_path)  # bundle == the device's current truth
    client = make_client(device)
    # §9 with the HONEST default first: nobody read the template sets yet (E1-01b
    # unmerged) and the A corpus claims numOfFace/numOfFP > 0 -> every person is
    # UNKNOWN-not-zero: conflict, zero writes, exit 2 (no writable path). The diff
    # refuses to call a person "same" on the strength of a counter it cannot see.
    p0 = plan(data, read_target_state(client), DiffPolicy(site_tz=SITE_TZ))
    assert len(p0.conflicts) == 4 and p0.would_write == 0 and p0.exit_code == 2
    assert all(Reason.UNKNOWN_ENROLLMENTS in i.reasons for i in p0.conflicts)
    # Same diff with the template reads SUCCEEDED (empty result = the axis was
    # read): counters demote to report-only cross-check notes; persons read `same`
    # (counters are not sets — §9), the plan is zero-write, exit 0 (§4).
    bio_ok = TargetBiometrics(faces={}, fingerprints={})
    p = plan(data, read_target_state(client), DiffPolicy(site_tz=SITE_TZ), biometrics=bio_ok)
    assert p.would_write == 0 and p.exit_code == 0 and len(p.adds) == 0
    assert len(p.same) == 4
    # Operator edits one person on the device: the FRESH read catches it as an update
    # (the bundle is stale on purpose — §4 "never a cached/bundled target view").
    assert device._enrollment_store is not None
    edited = dict(device._enrollment_store["UserInfo"][0])
    edited["name"] = "Renamed On Device"
    device._enrollment_store["UserInfo"][0] = edited
    p2 = plan(data, read_target_state(client), DiffPolicy(site_tz=SITE_TZ), biometrics=bio_ok)
    assert len(p2.updates) == 1 and p2.would_write == 1 and p2.exit_code == 1
    assert p2.updates[0].fields == ("name",)
    # The target losing a person turns that person into an add (source-only) on the
    # next diff — the plan is per-target-state, not per-bundle.
    device._enrollment_store["UserInfo"] = device._enrollment_store["UserInfo"][1:]
    p3 = plan(data, read_target_state(client), DiffPolicy(site_tz=SITE_TZ), biometrics=bio_ok)
    assert len(p3.adds) == 1 and p3.would_write == 1


def test_unknown_enrollment_post_stays_a_hard_failure_with_the_diff_armed() -> None:
    # The merged fake keeps E1-01's capture-before-fake trap even though E1-03's axis
    # exists: a write-shaped POST in the enrollment family must still explode.
    device = seeded_device()
    with (
        pytest.raises(EnrollmentProtocolError),
        httpx.Client(
            transport=device.transport,
            auth=httpx.DigestAuth("admin", PASSWORD),
            base_url=BASE_URL,
        ) as raw,
    ):
        raw.post("/ISAPI/AccessControl/UserInfo/SetUp?format=json", json={})


# --- the report (§4: hash prefixes + field names only) -------------------------------------------


def test_report_contains_no_pii_ever() -> None:
    p = plan(
        bundle_of([user("007", localUIRight=True), user("two", name="Wanted")], []),
        state_of([user("7"), user("two"), user("ghosty")], []),
        DiffPolicy(site_tz=SITE_TZ),
        biometrics=biometrics_of(),
    )
    for fmt in ("table", "json"):
        out = render_report(p, fmt=fmt)
        for banned in ("007", "two", "ghosty", "User E", "Wanted", "employeeNo"):
            assert banned not in out, f"{fmt} leaked {banned!r}"
        assert employee_hash("007") in out  # the hash prefix IS the identity
        assert employee_hash("ghosty") in out
    # The table may show field NAMES (that's the design) — the names stay, values go.
    assert "field:name" in render_report(p, fmt="table")


def test_report_totals_and_exit_line() -> None:
    p = plan(
        bundle_of([user("1"), user("9")], []),
        state_of([user("1")], []),
        DiffPolicy(site_tz=SITE_TZ),
    )
    table = render_report(p, fmt="table")
    assert "totals: add=1 update=0 same=1 conflict=0 | would write 1" in table
    assert table.endswith(f"exit: {p.exit_code}\n")
    with pytest.raises(ValueError, match="unknown report format"):
        render_report(p, fmt="yaml")


def test_json_report_is_the_pinned_stable_schema() -> None:
    """The `-o json` contract (E1-07 renders through here): schema token, key set,
    sorted-key byte formatting — pinned. Changing any of it is an API change: review,
    do not casually re-pin."""
    items = classify_case(
        [user("007"), user("2", name="Wanted")], [user("7"), user("2"), user("extra")]
    )
    p = Plan(items=tuple(items), policy=DiffPolicy(site_tz=SITE_TZ))
    rendered = render_report(p, fmt="json")
    payload = json.loads(rendered)
    assert payload["schema"] == "gateclerk-migrate-diff/1"
    # "7" and "extra" are both target-only persons (kept, v1 never deletes) -> same=2
    assert payload["totals"] == {"add": 0, "conflict": 1, "same": 2, "update": 1}
    assert payload["would_write"] == 1
    assert payload["reasons"] == {"normalization_collision": 1}
    assert set(payload) == {
        "people",
        "reasons",
        "schema",
        "source_counts",
        "target_termination",
        "totals",
        "would_write",
    }
    # byte-stability + sorted-key formatting are part of the pin
    assert rendered == render_report(p, fmt="json")
    assert rendered.startswith('{\n  "people"')
    assert rendered.endswith("\n")
    rows = {row["employee"]: row for row in payload["people"]}
    assert rows[employee_hash("007")]["reasons"] == ["normalization_collision"]
    assert rows[employee_hash("007")]["classification"] == "conflict"
    assert rows[employee_hash("007")]["would_write"] == 0
    assert rows[employee_hash("2")]["classification"] == "update"
    assert rows[employee_hash("2")]["fields"] == ["name"]  # NAME only, never "Wanted"
    assert "Wanted" not in rendered and "007" not in rendered and "extra" not in rendered


def test_table_renders_the_same_payload_as_json() -> None:
    items = classify_case([user("1", name="Wanted")], [user("1")])
    p = Plan(items=tuple(items), policy=DiffPolicy(site_tz=SITE_TZ))
    table = render_report(p, fmt="table")
    assert f"{employee_hash('1'):<12} update" in table
    assert "field:name" in table
    assert "would write 1" in table


def test_employee_hash_prefix_is_stable_12_hex() -> None:
    assert employee_hash("007") == hashlib.sha256(b"007").hexdigest()[:12]
    assert len(employee_hash("x")) == 12


# --- classify signature sanity -------------------------------------------------------------------


def test_classify_notes_a_stale_probe_evidence_set() -> None:
    # A probe whose recorded template set disagrees with the fresh target read is a
    # REPORT-ONLY note (the live read is truth; §3 keeps the probe as point-in-time).
    stale_probe = CapabilityMatrix(site="s", host="h", template_nos=("9",))
    items = classify(
        [user("1")],
        [user("1")],
        [],
        [],
        stale_probe,
        policy=DiffPolicy(site_tz=SITE_TZ),
        biometrics=biometrics_of(),
    )
    assert any(
        n.startswith("probe_evidence_stale_vs_target(live=1;probe=9)")
        for n in by_no(items, "1").notes
    )


def test_plain_dict_inputs_classify_identically() -> None:
    # JSON round-tripped plain dicts (not Mappings) classify exactly the same.
    items = classify_case([dict(user("1"))], [dict(user("1"))])
    assert items[0].classification is DiffClass.SAME
    assert all(isinstance(i, Classification) for i in items)
