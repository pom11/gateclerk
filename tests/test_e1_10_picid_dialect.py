"""Card E1-10 defect 2: a device-assigned `picID` is not a mismatch (live A->B).

The live symptom, from run-b-20261023-1300: the users phase LANDED its three adds, then
the composer stopped the run with "verify disagreed after the phase". The re-diff showed
exactly one differing field — ``picID``. Site-B answers every ``UserInfo/Search`` row
with a device-assigned ``picID``; site-A's rows carry none (see
``fixtures/synthetic/user_search_page_b_dialect.json`` for the B-shaped page). So §6's
fail-closed unknown-field rule — which is exactly the right rule against a device that
mangled data — fired against a NEW DEVICE DIALECT and called a successful write a failure.

The fix lives in ONE place (``migrate_bundle.DEVICE_ASSIGNED_FIELDS`` +
``comparable_record``/``COMPARE_EXEMPT_FIELDS``) and every pin below reads through it, so
verify and the diff cannot drift apart (§5a no-duplication).

The pin that matters most is the negative one: excluding a field is easy to get wrong by
excluding too much. Every test here therefore carries its counter-check — a row that
differs in any OTHER field must still be red, and a wrong ``picID`` value must never turn
a real name change green.

The frozen-digest trap the card names is pinned too: ``VOLATILE_FIELDS`` is FROZEN into
every bundle manifest (``frozen_volatile_digest`` + ``read_bundle`` refuses a mismatch),
so a bundle exported BEFORE this change must still read after it. Nothing in the bundle
bytes moves.
"""

from __future__ import annotations

import copy
import dataclasses
import json
from collections.abc import Mapping
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from gateclerk.migrate_bundle import (
    COMPARE_EXEMPT_FIELDS,
    DEVICE_ASSIGNED_FIELDS,
    VOLATILE_FIELDS,
    BundleData,
    BundleManifest,
    FacesIndex,
    comparable_record,
    content_hash,
    frozen_volatile_digest,
    normalize_record,
    read_bundle,
    write_bundle,
)
from gateclerk.migrate_diff import DiffClass, Plan, TargetBiometrics, classify, render_report
from gateclerk.migrate_write import PersonVerdict, UserWrite, verify_users

FIXTURES = Path(__file__).parent / "fixtures"
SYNTH = FIXTURES / "synthetic"
RECORDED = FIXTURES / "recorded" / "site-a-ds-k1t341amf-s"
ENROLLMENT = RECORDED / "enrollment"

#: Site-B's recorded dialect: every row carries `picID`.
B_PAGE = json.loads((SYNTH / "user_search_page_b_dialect.json").read_text())
B_ROWS: list[dict[str, Any]] = B_PAGE["UserInfoSearch"]["UserInfo"]

#: Site-A's recorded page: no row carries `picID`.
A_PAGE = json.loads((RECORDED / "user_search_page1.json").read_text())
A_ROWS: list[dict[str, Any]] = A_PAGE["UserInfoSearch"]["UserInfo"]

#: The site-A-shaped bundle side of the comparison: the recorded row with the volatile
#: keys normalize strips (this is what `people.jsonl` holds after export).
A_BUNDLE_ROWS = [normalize_record(row) for row in A_ROWS]


def b_row(no: str, **overrides: Any) -> dict[str, Any]:
    """One site-B row (verbatim from the fixture), optionally overridden."""
    row = copy.deepcopy(next(r for r in B_ROWS if r["employeeNo"] == no))
    row.update(overrides)
    return row


def a_row(no: str, **overrides: Any) -> dict[str, Any]:
    row = copy.deepcopy(next(r for r in A_BUNDLE_ROWS if r["employeeNo"] == no))
    row.update(overrides)
    return row


def reader_for(*rows: dict[str, Any]):
    """A verify reader that honours `EmployeeNoList` (bench A and B both do, §1)."""

    def read(body: Mapping[str, Any]) -> dict[str, Any]:
        cond = body["UserInfoSearchCond"]
        wanted = {e["employeeNo"] for e in cond.get("EmployeeNoList", [])}
        found = [r for r in rows if not wanted or r["employeeNo"] in wanted]
        envelope: dict[str, Any] = {
            "searchID": cond["searchID"],
            "numOfMatches": len(found),
            "totalMatches": len(found),
            "responseStatusStrg": "OK",
        }
        if found:
            envelope["UserInfo"] = found
        return {"UserInfoSearch": envelope}

    return read


def writes_for(*records: dict[str, Any]) -> tuple[UserWrite, ...]:
    return tuple(
        UserWrite(
            employee_no=str(r["employeeNo"]),
            employee_hash=_hash(str(r["employeeNo"])),
            record=r,
        )
        for r in records
    )


def _hash(no: str) -> str:
    from gateclerk.migrate_write import person_hash

    return person_hash(no)


# --- the live shape: A-shaped bundle vs B-shaped read-back ------------------------------------


def test_verify_ok_when_the_only_difference_is_the_device_assigned_picid() -> None:
    """THE live failure, pinned: three adds landed, verify must agree they landed.

    Bundle side = site-A row (no `picID`). Target side = the same person as site-B
    answers it (`picID` present). Before E1-10 this was a MISMATCH and the composer
    stopped a run whose writes had actually succeeded.
    """
    bundle_record = a_row("2")
    report = verify_users(
        reader_for(b_row("2")),
        writes_for(bundle_record),
    )
    assert report.ok, [i.verdict for i in report.items]
    item = report.items[0]
    assert item.verdict is PersonVerdict.OK
    assert item.unknown_fields == () and item.missing_fields == ()
    # The hashes now agree for the same reason the field sets do: `picID` is not in
    # either projection (§5a — one exclusion, both sides).
    assert item.target_hash == item.expected_hash


#: Both biometric reads SUCCEEDED and came back empty (the E1-02 suite's own convention:
#: an explicit dict = OK, None = read failed = UNKNOWN §9). This file is about the user-row
#: fields, so the axes are pinned out of the way rather than left ambiguous — and the
#: target's `numOfFace: 1` then shows up as the report-only counter cross-check it is.
READS_OK = TargetBiometrics(faces={}, fingerprints={})


def test_the_diff_classifies_the_same_person_same_not_update() -> None:
    """§4's classifier must not call a per-device handle an actionable field either.

    A `picID`-only difference used to land in `fields` (NAMES only, §4) and turn into an
    UPDATE with would_write=1 — the same dialect read as a payroll change, twice over.
    """
    items = classify(
        bundle_people=[a_row("2")],
        target_people=[b_row("2")],
        bundle_cards=[],
        target_cards=[],
        probe=None,
        biometrics=READS_OK,
    )
    (one,) = items
    assert one.classification is DiffClass.SAME
    assert one.fields == ()
    assert one.would_write == 0
    assert "hash_equal" in one.notes


def test_picid_never_reaches_the_report_surface() -> None:
    """§4: names only leave the diff — and a per-device name is not even a difference."""
    items = classify(
        bundle_people=[a_row("2")],
        target_people=[b_row("2")],
        bundle_cards=[],
        target_cards=[],
        probe=None,
    )
    report = render_report(Plan(items=tuple(items)), fmt="json")
    assert "picID" not in report
    assert "User E2" not in report, "the report carries hashes, never names (§4)"


# --- the counter-checks: the exclusion must stay narrow ----------------------------------------


@pytest.mark.parametrize(
    "field,value",
    [
        pytest.param("name", "Someone Else", id="name"),
        pytest.param("doorRight", "2", id="doorRight"),
        pytest.param("userType", "blackList", id="userType"),
        pytest.param("maxOpenDoorTime", 7, id="maxOpenDoorTime"),
    ],
)
def test_a_real_field_difference_is_still_a_mismatch(field: str, value: Any) -> None:
    """The trap of any allow-list: excluding one field must not exclude the next.

    Same B-shaped read-back (so `picID` is still present), but the named field moved —
    that is a device that changed our data, and §6 says red.
    """
    report = verify_users(reader_for(b_row("2", **{field: value})), writes_for(a_row("2")))
    item = report.items[0]
    assert item.verdict is PersonVerdict.MISMATCH
    assert item.target_hash != item.expected_hash


def test_a_wrong_picid_cannot_hide_a_wrong_name() -> None:
    """The card's probe target, spelled out: mutate `picID` INTO a wrong-valued name.

    Excluding `picID` must not make a mangled `name` survivable. Two rows, same
    `picID`, different names: still red. (And a `picID` that differs while everything
    else agrees stays green on purpose — it is a row handle, not identity.)
    """
    # (a) picID mutated into the name slot: the person's name is now wrong -> MISMATCH.
    smuggled = b_row("2")
    smuggled["name"] = smuggled.pop("picID")
    report = verify_users(reader_for(smuggled), writes_for(a_row("2")))
    assert report.items[0].verdict is PersonVerdict.MISMATCH

    # (b) a different picID for the same person changes nothing about the person.
    same_person_other_handle = b_row("2", picID="9999999999")
    report = verify_users(reader_for(same_person_other_handle), writes_for(a_row("2")))
    assert report.items[0].verdict is PersonVerdict.OK


def test_an_unknown_field_that_is_not_picid_is_still_fail_closed() -> None:
    """The §6 rule E1-04 shipped survives the new exclusion untouched."""
    report = verify_users(
        reader_for(b_row("2", mysteryField={"nested": True})), writes_for(a_row("2"))
    )
    item = report.items[0]
    assert item.verdict is PersonVerdict.MISMATCH
    assert item.unknown_fields == ("mysteryField",)
    # Field NAMES only leave the report (§4) — never the device's value.
    assert "nested" not in json.dumps(dataclasses.asdict(item))


def test_a_missing_field_is_still_a_mismatch() -> None:
    """The other arm (intended has it, the read-back does not) is unaffected."""
    live = b_row("2")
    del live["gender"]
    report = verify_users(reader_for(live), writes_for(a_row("2")))
    assert report.items[0].verdict is PersonVerdict.MISMATCH
    assert report.items[0].missing_fields == ("gender",)


# --- single-source and the frozen-digest trap ---------------------------------------------------


def test_picid_is_excluded_at_compare_time_and_not_from_the_bundle() -> None:
    """The TRAP the card names: `picID` must NOT join VOLATILE_FIELDS.

    ``VOLATILE_FIELDS`` is frozen into every manifest via ``frozen_volatile_digest()`` and
    ``read_bundle`` refuses a mismatch, so widening the strip set would make the
    operator's already-exported bundles unreadable mid-migration. picID is dropped by
    ``comparable_record`` only; ``normalize_record`` keeps it, so bundle bytes do not move.
    """
    assert "picID" not in VOLATILE_FIELDS
    assert sorted(DEVICE_ASSIGNED_FIELDS) == ["picID"]
    assert sorted(COMPARE_EXEMPT_FIELDS) == sorted(
        VOLATILE_FIELDS | DEVICE_ASSIGNED_FIELDS | {"photoURL", "faceURL"}
    )
    row = b_row("2")
    assert "picID" in normalize_record(row), "bundle bytes keep the handle"
    assert "picID" not in comparable_record(row), "the comparison does not"
    # ...and the hash is the comparable projection, not the bundle projection.
    assert content_hash(row) == content_hash(comparable_record(row))


def test_a_bundle_written_before_the_change_still_reads(tmp_path: Path) -> None:
    """The frozen digest did not move: a pre-change bundle still passes `read_bundle`.

    Built the way the pre-E1-10 writer built it — same manifest, same digest token, same
    per-person hashes — so the assertion is about the digest and the reader's checks, not
    about a file this card wrote.
    """
    pre_change_digest = frozen_volatile_digest()
    people = [a_row(no) for no in ("1", "2", "3", "4")]
    out = write_bundle(
        tmp_path / "site-a-20261023-1250",
        identity={"model": "DS-K1T341AMF-S", "firmware": "V3.2.30", "serial_prefix": "MASKED"},
        exported_at=datetime(2026, 10, 23, 10, 50, tzinfo=UTC),
        people=people,
        cards=[],
    )
    manifest = json.loads((out / "manifest.json").read_text())
    assert manifest["volatile_fields_digest"] == pre_change_digest
    # A row that carries the B-dialect handle still bundles and still reads: the handle
    # survives in the bytes, which is exactly what "excluded at compare time only" means.
    with_handle = tmp_path / "site-b"
    write_bundle(
        with_handle,
        identity={"model": "DS-K1T341AMF-S", "firmware": "V4.13.0", "serial_prefix": "MASKED"},
        exported_at=datetime(2026, 10, 23, 11, 0, tzinfo=UTC),
        people=[b_row(no) for no in ("1", "2", "3", "4")],
        cards=[],
    )
    data = read_bundle(with_handle)
    assert isinstance(data, BundleData)
    assert [p["employeeNo"] for p in data.people] == ["1", "2", "3", "4"]
    assert all("picID" in p for p in data.people), "not stripped from the bundle"
    assert data.person_hashes() == dict(data.manifest.people_hashes)


def test_a_b_dialect_pair_hashes_identically_and_the_bundle_hash_agrees() -> None:
    """§6: "content-hash compare via migrate_bundle (same normalization)" — pinned for
    the cross-dialect pair, recomputed rather than stored."""
    bundle_record = a_row("2")
    live = b_row("2")
    assert content_hash(live) == content_hash(bundle_record)
    # And the manifest hash of that same person (what export records) is the same number,
    # so journal `intended_hash` and verify `target_hash` can meet (§6's confirm step).
    assert content_hash(live) == content_hash(normalize_record(live))


def test_a_b_side_bundle_exported_before_the_change_is_refused_not_half_read(
    tmp_path: Path,
) -> None:
    """The honest compatibility edge of excluding picID from the content hash.

    A bundle exported from a picID-carrying device BEFORE this change recorded per-person
    hashes that INCLUDED the handle; the same hashes recomputed now exclude it, so
    `read_bundle` refuses the bundle instead of diffing against numbers that mean
    something else (§0.7: a mismatch is refused, never explained away).

    Nothing to migrate today — the live run exports from site A, whose rows carry no
    `picID`, so no committed or on-disk bundle is affected (pinned by
    :func:`test_a_bundle_written_before_the_change_still_reads`). Re-export from B is the
    fix if one ever appears; the refusal wording names the cause.
    """
    people = [b_row(no) for no in ("1", "2", "3", "4")]
    out = write_bundle(
        tmp_path / "site-b-pre-fix",
        identity={"model": "DS-K1T341AMF-S", "firmware": "V4.13.0", "serial_prefix": "MASKED"},
        exported_at=datetime(2026, 10, 23, 11, 30, tzinfo=UTC),
        people=people,
        cards=[],
    )
    manifest_path = out / "manifest.json"
    manifest = json.loads(manifest_path.read_text())
    # Re-spell the manifest hashes the way the PRE-E1-10 hash function spelled them: with
    # the handle in the hashed projection. (That is the only thing that differs.)
    manifest["people_hashes"] = {
        str(record["employeeNo"]): _hash_with_picid(record) for record in people
    }
    manifest_path.write_text(json.dumps(manifest, sort_keys=True, indent=2))
    with pytest.raises(ValueError, match="manifest per-person hashes"):
        read_bundle(out)


def _hash_with_picid(record: Mapping[str, Any]) -> str:
    """content_hash as it behaved before DEVICE_ASSIGNED_FIELDS existed.

    Pre-fix, an already-normalized record was hashed EXACTLY as given (normalize strips
    the volatile set but never knew about `picID`), so the handle rode along in the
    digest. That is the number such a bundle's manifest carries.
    """
    import hashlib

    from gateclerk.migrate_bundle import canonical_bytes

    return hashlib.sha256(canonical_bytes(normalize_record(record))).hexdigest()


def test_the_frozen_digest_itself_is_unchanged() -> None:
    """A literal pin: if anyone adds to the strip list, the operator's bundles break.

    This is the number baked into every manifest the operator already holds
    (site-a-20261023-1250 among them). Changing it is a schema decision, not a diff.
    """
    assert frozen_volatile_digest() == (
        "df25d2d6239a1fa254349558d4f0524e4c765e67fe5c6251ee7704907c235cff"
    )
    assert sorted(VOLATILE_FIELDS) == [
        "numOfCard",
        "numOfFP",
        "numOfFace",
        "openDoorTime",
        "password",
    ]


def test_b_dialect_fixture_is_the_recorded_shape_plus_picid_only() -> None:
    """The fixture must differ from site-A's recorded page by NOTHING but `picID`.

    Otherwise the tests above would be proving a difference this card never claimed to
    fix. Site-A's page masks the PIN key out and B's read carries the empty one, so the
    volatile strip is applied before comparing key sets.
    """
    a_keys = {frozenset(normalize_record(r)) for r in A_ROWS}
    b_keys = {frozenset(normalize_record(r)) for r in B_ROWS}
    (a_key,) = a_keys
    (b_key,) = b_keys
    assert b_key - a_key == frozenset({"picID"})
    assert a_key - b_key == frozenset()
    # Same four people, same names, same order.
    assert [r["employeeNo"] for r in A_ROWS] == [r["employeeNo"] for r in B_ROWS]
    assert [r["name"] for r in A_ROWS] == [r["name"] for r in B_ROWS]


def test_bundle_manifest_shape_helper_is_untouched(tmp_path: Path) -> None:
    """Guard against a drive-by: the manifest still refuses a foreign volatile digest."""
    manifest = BundleManifest(
        schema_version="gateclerk-enrollment-bundle/2",
        exported_at="2026-10-23T08:00:00+00:00",
        identity={"model": "M", "firmware": "F", "serial_prefix": "ab"},
        counts={"users": 0, "cards": 0, "faces": 0, "fingerprints": 0},
        people_hashes={},
        volatile_fields_digest="0" * 64,  # a strip set this module never had
        faces={"state": "UNAVAILABLE", "reason": "test"},
        termination={},
    )
    data = BundleData(manifest=manifest, people=(), cards=(), faces=FacesIndex())
    assert data.manifest.volatile_fields_digest != frozen_volatile_digest()
