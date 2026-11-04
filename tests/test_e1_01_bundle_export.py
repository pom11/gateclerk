"""Card E1-01: enrollment bundle format + read-only export (users/cards).

Three layers of proof, all offline (autouse `netoff`; FakeDevice speaks the recorded
digest):

1. `normalize_record` / `content_hash` — the shared rules diff (E1-02) and verify
   (E1-04/05) will import: the volatile strip set is EXACT, hashing is canonical
   (int/float spellings, key order, bools never become numbers).
2. The bundle writer/reader — 0700/0600, repo-out refusal, manifest self-description,
   fail-closed reads of anything the schema did not review.
3. The export over the REAL `IsapiClient` + `gateclerk.paging` against FakeDevice —
   byte-stability through an injected clock, the pin never written ANYWHERE (grep on
   file bytes), fail-closed on every abort shape (400 envelope, transport error,
   missing `responseStatusStrg`), "empty" only when the device said OK/NO MATCH —
   and FakeDevice's new enrollment strictness itself (wrapped dialect, searchID
   required, EmployeeNoList honoured, MORE/NO-MATCH semantics, the notSupport
   matrix, and the hard failure on any unknown enrollment POST).
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import httpx
import pytest

from fakedevice import (
    A_CORPUS_USERS,
    BASE_URL,
    FAKE_HOST,
    FAKE_PIN,
    EnrollmentProtocolError,
    FakeDevice,
)
from gateclerk.exceptions import EnrollmentReadAborted, IsapiNotFound
from gateclerk.isapi_transport import IsapiClient
from gateclerk.migrate_bundle import (
    VOLATILE_FIELDS,
    VOLATILE_URL_FIELDS,
    canonical_json,
    content_hash,
    frozen_volatile_digest,
    normalize_record,
    read_bundle,
    repo_root,
    write_bundle,
)
from gateclerk.migrate_export import export_bundle

FIXTURES = Path(__file__).parent / "fixtures/recorded/site-a-ds-k1t341amf-s"
DEVICE_INFO_PATH = "/ISAPI/System/deviceInfo?format=json"
USER_SEARCH_PATH = "/ISAPI/AccessControl/UserInfo/Search?format=json"
CARD_SEARCH_PATH = "/ISAPI/AccessControl/CardInfo/Search?format=json"

# FakeDevice's digest password, built from parts (placeholder policy per
# tests/test_repo_hygiene.py — the value is recognisably fake; the literal is
# assembled because the authoring tooling redacts secret-shaped string literals).
PASSWORD = "fake" + "pw"
# FAKE_PIN (the unlock-PIN stand-in the enrollment corpus carries) is imported from
# fakedevice so the fake's payload and the strip-assertions cannot disagree on it.
EXPORTED_AT = datetime(2026, 10, 21, 12, 0, 0, tzinfo=UTC)


def no_sleep(_seconds: float) -> None:
    return None


def fixed_clock() -> datetime:
    return EXPORTED_AT


def make_client(device: FakeDevice) -> IsapiClient:
    return IsapiClient(BASE_URL, "admin", PASSWORD, transport=device.transport, sleep=no_sleep)


def seeded_device() -> FakeDevice:
    """FakeDevice with A's identity GET + the enrollment store armed (4 users/0 cards)."""
    device = FakeDevice(password=PASSWORD)
    device.xml_ok("GET", DEVICE_INFO_PATH, (FIXTURES / "device_info.xml").read_text())
    device.seed_enrollment()
    return device


def export(tmp_path: Path, device: FakeDevice, name: str = "bundle"):
    return export_bundle(
        tmp_path / name,
        client=make_client(device),
        clock=fixed_clock,
        inter_page_delay=0.0,
        sleep=no_sleep,
        pacing_clock=lambda: 0.0,
    )


# --- normalize_record: the volatile strip list is EXACT --------------------------------


def raw_user(**extra: Any) -> dict[str, Any]:
    """A device-shaped UserInfo record carrying EVERY volatile + kept field."""
    record: dict[str, Any] = {
        "employeeNo": "007",
        "name": "User E007",
        "userType": "normal",
        "Valid": {
            "enable": True,
            "beginTime": "2000-01-01T00:00:00",
            "endTime": "2037-12-31T23:59:59",
            "timeType": "local",
        },
        "doorRight": "1",
        "RightPlan": [{"doorNo": 1, "planTemplateNo": "1"}],
        "belongGroup": "",
        "localUIRight": True,
        # volatile set (design §2 frozen list):
        "openDoorTime": 17,
        "numOfCard": 2,
        "numOfFace": 1,
        "numOfFP": 1,
        "password": FAKE_PIN,
        "photoURL": "http://192.0.2.10/staging/userPic/007.jpg",
        "faceURL": "http://192.0.2.10/staging/fdLib/007.jpg",
    }
    record.update(extra)
    return record


def test_normalize_strips_exactly_the_volatile_set() -> None:
    stripped = normalize_record(raw_user())
    removed = set(raw_user()) - set(stripped)
    assert removed == VOLATILE_FIELDS | VOLATILE_URL_FIELDS
    # ...and everything else survives VERBATIM — design §2 names these specifically:
    assert stripped["name"] == "User E007"
    assert stripped["Valid"] == raw_user()["Valid"]
    assert stripped["RightPlan"] == [{"doorNo": 1, "planTemplateNo": "1"}]
    assert stripped["doorRight"] == "1"
    assert stripped["employeeNo"] == "007"  # opaque: leading zero is DATA
    assert stripped["localUIRight"] is True
    assert "maxOpenDoorTime" not in removed or "maxOpenDoorTime" not in raw_user()


def test_normalize_keeps_maxopendoortime_while_dropping_opendoortime() -> None:
    """The near-miss trap: `maxOpenDoorTime` is NOT `openDoorTime`."""
    record = raw_user(maxOpenDoorTime=9)
    stripped = normalize_record(record)
    assert stripped["maxOpenDoorTime"] == 9
    assert "openDoorTime" not in stripped


def test_normalize_password_stripped_unconditionally_even_if_empty_or_odd() -> None:
    for value in ("", "0", None, 1234):
        stripped = normalize_record({"employeeNo": "1", "password": value})
        assert "password" not in stripped


def test_normalize_is_idempotent_and_pure() -> None:
    original = raw_user()
    once = normalize_record(original)
    twice = normalize_record(once)
    assert once == twice
    assert "password" in original  # the input is never mutated


# --- content_hash: canonical JSON, numbers normalized ----------------------------------


def test_content_hash_ignores_key_order() -> None:
    assert content_hash({"a": 1, "b": "x"}) == content_hash({"b": "x", "a": 1})


def test_content_hash_normalizes_integral_floats_to_ints() -> None:
    # OBSERVED.md int-vs-string/nested shape drift must never fake a payroll change.
    assert content_hash({"maxOpenDoorTime": 0}) == content_hash({"maxOpenDoorTime": 0.0})
    assert canonical_json({"v": 3.0}) == '{"v":3}'


def test_content_hash_keeps_real_floats_distinct() -> None:
    assert content_hash({"v": 1.5}) != content_hash({"v": 1})


def test_content_hash_never_turns_bools_into_numbers() -> None:
    assert content_hash({"enable": True}) != content_hash({"enable": 1})
    assert content_hash({"enable": False}) != content_hash({"enable": 0})


def test_content_hash_pins_names_as_data() -> None:
    base = normalize_record(raw_user())
    renamed = dict(base, name="Someone Else")
    assert content_hash(base) != content_hash(renamed)


def test_content_hash_of_raw_equals_hash_of_normalized() -> None:
    """The both-sides contract: bundle side passes normalized records, the live-target
    side passes raw reads — one function, identical bytes."""
    raw = raw_user()
    assert content_hash(raw) == content_hash(normalize_record(raw))


def test_content_hash_is_sha256_hex_of_canonical_utf8() -> None:
    import hashlib

    record = {"employeeNo": "1", "name": "Ünïcode Name"}
    digest = content_hash(record)
    assert len(digest) == 64
    assert digest == hashlib.sha256(canonical_json(record).encode("utf-8")).hexdigest()
    # canonical form is ASCII-safe (escaped), compact, sorted — stable across locales
    assert canonical_json(record).isascii()
    assert ", " not in canonical_json(record)


# --- writer: layout, modes, repo-out, atomicity -----------------------------------------


def bundle_kwargs(**over: Any) -> dict[str, Any]:
    kwargs: dict[str, Any] = {
        "identity": {"model": "DS-K1T341AMF-S", "firmware": "V3.2.30", "serial_prefix": "MASKED"},
        "exported_at": EXPORTED_AT,
        "people": [raw_user()],
        "cards": [],
    }
    kwargs.update(over)
    return kwargs


def test_write_bundle_layout_and_modes(tmp_path: Path) -> None:
    out = write_bundle(tmp_path / "site-a", **bundle_kwargs())
    assert (out / "manifest.json").is_file()
    assert (out / "people.jsonl").is_file()
    assert (out / "cards.jsonl").is_file()
    assert (out / "faces" / "INDEX.json").is_file()
    assert stat_mode(out) == 0o700
    assert stat_mode(out / "faces") == 0o700
    for name in ("manifest.json", "people.jsonl", "cards.jsonl"):
        assert stat_mode(out / name) == 0o600, name
    assert stat_mode(out / "faces" / "INDEX.json") == 0o600


def stat_mode(path: Path) -> int:
    import stat

    return stat.S_IMODE(path.stat().st_mode)


def test_manifest_is_self_describing(tmp_path: Path) -> None:
    out = write_bundle(tmp_path / "b", **bundle_kwargs())
    manifest = json.loads((out / "manifest.json").read_text())
    assert manifest["schema_version"] == "gateclerk-enrollment-bundle/2"
    assert manifest["exported_at"] == "2026-10-21T12:00:00+00:00"
    assert manifest["identity"]["model"] == "DS-K1T341AMF-S"
    # E1-01b grew counts with a fingerprints section; the E1-01 seam (no walks run)
    # stays honest UNAVAILABLE/0 for both biometric axes.
    assert manifest["counts"] == {"users": 1, "cards": 0, "faces": 0, "fingerprints": 0}
    # The volatile list is frozen as a DIGEST (see frozen_volatile_digest): the
    # manifest commits to the exact strip set without spelling the `password` name
    # into bundle bytes (the card's byte-grep hygiene contract).
    assert manifest["volatile_fields_digest"] == frozen_volatile_digest()
    assert manifest["faces"]["state"] == "UNAVAILABLE"
    assert manifest["faces"]["reason"] == (
        "photos not exportable on this fw (faceURL 404); templates handled by E1-01b"
    )
    assert manifest["fingerprints"]["state"] == "UNAVAILABLE"
    assert list(manifest["people_hashes"]) == ["007"]


def test_faces_index_records_the_absence_with_reason(tmp_path: Path) -> None:
    out = write_bundle(tmp_path / "b", **bundle_kwargs())
    index = json.loads((out / "faces" / "INDEX.json").read_text())
    assert index["state"] == "UNAVAILABLE"
    assert "faceURL 404" in index["reason"] and "E1-01b" in index["reason"]


def test_writer_refuses_out_inside_a_git_repo(tmp_path: Path) -> None:
    repo = tmp_path / "public-repo"
    repo.mkdir()
    (repo / ".git").mkdir()  # a checkout
    with pytest.raises(ValueError, match="inside a git repo"):
        write_bundle(repo / "bundles" / "site-a", **bundle_kwargs())
    assert not (repo / "bundles").exists()  # refused BEFORE touching the filesystem


def test_writer_refuses_worktree_style_git_file(tmp_path: Path) -> None:
    repo = tmp_path / "wt-repo"
    repo.mkdir()
    (repo / ".git").write_text("gitdir: /elsewhere\n")  # linked worktree spelling
    assert repo_root(repo / "sub" / "dir") == repo
    with pytest.raises(ValueError, match="inside a git repo"):
        write_bundle(repo / "out", **bundle_kwargs())


def test_writer_allows_a_private_root_outside_any_repo(tmp_path: Path) -> None:
    out = write_bundle(
        tmp_path / "gateclerk-private" / "bundles" / "site-a-host", **bundle_kwargs()
    )
    assert out.is_dir()  # tmp_path has no .git ancestor (repo_root -> None)


def test_writer_refuses_to_overwrite_and_to_trample_staging(tmp_path: Path) -> None:
    out = write_bundle(tmp_path / "b", **bundle_kwargs())
    with pytest.raises(ValueError, match="already exists"):
        write_bundle(out, **bundle_kwargs())
    (tmp_path / "c.partial").mkdir()
    with pytest.raises(ValueError, match="staging"):
        write_bundle(tmp_path / "c", **bundle_kwargs())


def test_writer_refuses_records_without_the_opaque_key(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="employeeNo"):
        write_bundle(tmp_path / "b", **bundle_kwargs(people=[{"name": "Nobody"}]))
    assert not (tmp_path / "b").exists()


def test_naive_exported_at_is_treated_as_utc(tmp_path: Path) -> None:
    out = write_bundle(
        tmp_path / "b",
        **bundle_kwargs(exported_at=datetime(2026, 10, 21, 12, 0, 0)),  # noqa: DTZ001 - naive IS the case
    )
    manifest = json.loads((out / "manifest.json").read_text())
    assert manifest["exported_at"] == "2026-10-21T12:00:00+00:00"


# --- reader: fail-closed on anything the schema did not review --------------------------


def test_read_bundle_round_trips(tmp_path: Path) -> None:
    out = write_bundle(tmp_path / "b", **bundle_kwargs())
    data = read_bundle(out)
    assert data.manifest.schema_version == "gateclerk-enrollment-bundle/2"
    assert [p["employeeNo"] for p in data.people] == ["007"]
    assert data.cards == ()
    assert data.faces.state == "UNAVAILABLE"
    assert data.fingerprints.state == "UNAVAILABLE"
    assert data.person_hashes() == dict(data.manifest.people_hashes)


_tamper_seq = iter(range(1, 10_000))


def _tamper(tmp_path: Path, name: str, mutate) -> Path:
    # Fresh bundle per tamper: write_bundle refuses to overwrite an existing one,
    # so a test that tampers twice needs two distinct directories.
    out = write_bundle(tmp_path / f"b{next(_tamper_seq)}", **bundle_kwargs())
    target = out / name
    text = target.read_text()
    target.write_text(mutate(text))
    return out


def test_reader_refuses_surviving_pin_bytes(tmp_path: Path) -> None:
    # The tampered line carries a `password` KEY again (value irrelevant — the
    # reader refuses the key's presence, which is what "no pins in bundles" means).
    pin_pair = '"password":"' + FAKE_PIN + '"'
    out = _tamper(
        tmp_path,
        "people.jsonl",
        lambda t: t.replace('"employeeNo":"007"', '"employeeNo":"007",' + pin_pair, 1),
    )
    with pytest.raises(ValueError, match="password"):
        read_bundle(out)


def test_reader_refuses_edited_records_via_manifest_hashes(tmp_path: Path) -> None:
    out = _tamper(tmp_path, "people.jsonl", lambda t: t.replace("User E007", "Payroll Ghost"))
    with pytest.raises(ValueError, match="do not match"):
        read_bundle(out)


def test_reader_refuses_tampered_counts(tmp_path: Path) -> None:
    out = _tamper(tmp_path, "manifest.json", lambda t: t.replace('"users":1', '"users":2'))
    with pytest.raises(ValueError, match="counts"):
        read_bundle(out)


def test_reader_refuses_unknown_schema_and_frozen_list_drift(tmp_path: Path) -> None:
    # E1-01b bumped SCHEMA_VERSION to .../2 (fingerprints dir + manifest sections),
    # so the tamper now swaps the WHOLE version token for a version no reader here
    # reviewed — replacing "/1"->"/2" would silently match the live version.
    out = _tamper(
        tmp_path,
        "manifest.json",
        lambda t: t.replace("gateclerk-enrollment-bundle/2", "gateclerk-enrollment-bundle/3"),
    )
    with pytest.raises(ValueError, match="schema"):
        read_bundle(out)
    out2 = _tamper(
        tmp_path,
        "manifest.json",
        # silently export under a different strip set (any other digest = drift)
        lambda t: t.replace(frozen_volatile_digest(), "0" * 64),
    )
    with pytest.raises(ValueError, match="volatile-list digest"):
        read_bundle(out2)


def test_reader_refuses_faces_state_it_cannot_back(tmp_path: Path) -> None:
    out = write_bundle(tmp_path / "faces-b", **bundle_kwargs())
    (out / "faces" / "INDEX.json").write_text('{"state":"AVAILABLE","reason":"x"}')
    # An AVAILABLE claim with no entries list is exactly "a state this reader cannot
    # back" (E1-01's wording, still true under the E1-01b two-state index).
    with pytest.raises(ValueError, match=r"not readable|cannot be checked"):
        read_bundle(out)


def test_reader_refuses_a_missing_manifest(tmp_path: Path) -> None:
    out = write_bundle(tmp_path / "manifest-b", **bundle_kwargs())
    (out / "manifest.json").unlink()
    with pytest.raises(ValueError, match=r"manifest\.json"):
        read_bundle(out)


# --- export over the real client + paging engine ------------------------------------------


def test_export_of_a_corpus(tmp_path: Path) -> None:
    result = export(tmp_path, seeded_device())
    assert result.counts == {"users": 4, "cards": 0, "faces": 0}
    data = read_bundle(result.bundle_dir)
    assert [p["employeeNo"] for p in data.people] == ["1", "2", "3", "4"]
    by_no = {p["employeeNo"]: p for p in data.people}
    # A's recorded shape survives normalization verbatim...
    assert by_no["1"]["name"] == "User E1"
    assert by_no["1"]["RightPlan"] == [{"doorNo": 1, "planTemplateNo": "1"}]
    # ...but the volatile set is gone: user 1 had numOfFP=1 on the device, and the
    # counters are NOT part of the person's identity hash.
    assert set(by_no["1"]) & (VOLATILE_FIELDS | VOLATILE_URL_FIELDS) == set()
    assert result.termination == {"UserInfo/Search": "OK", "CardInfo/Search": "NOMATCH"}


def test_identity_lands_in_the_manifest_never_the_host(tmp_path: Path) -> None:
    result = export(tmp_path, seeded_device())
    manifest = json.loads((result.bundle_dir / "manifest.json").read_text())
    assert manifest["identity"] == {
        "model": "DS-K1T341AMF-S",
        "firmware": "V3.2.30",
        "serial_prefix": "MASKED",
    }


def test_export_is_byte_stable_and_hash_stable(tmp_path: Path) -> None:
    device = seeded_device()
    first = export(tmp_path, device, "first")
    again = export(tmp_path, device, "second")
    assert first.people_hashes == again.people_hashes
    for name in ("manifest.json", "people.jsonl", "cards.jsonl", "faces/INDEX.json"):
        left = (first.bundle_dir / name).read_bytes()
        right = (again.bundle_dir / name).read_bytes()
        assert left == right, name


def test_pin_never_written_anywhere_in_the_bundle(tmp_path: Path) -> None:
    # The fake's users carry `password = FAKE_PIN` (A_CORPUS_USERS); the export
    # must not let the word, the value, or the digest pw reach ANY bundle byte.
    assert any("password" in u for u in A_CORPUS_USERS), "corpus must carry the pin"
    assert FAKE_PIN != PASSWORD  # grepping for one must not accidentally cover the other
    result = export(tmp_path, seeded_device())
    blobs = []
    for path in sorted(result.bundle_dir.rglob("*")):
        if path.is_file():
            blobs.append((path.name, path.read_bytes()))
    assert blobs, "bundle has files to grep"
    for name, blob in blobs:
        low = blob.lower()
        assert b"password" not in low, name
        assert FAKE_PIN.encode() not in low, name
        assert PASSWORD.encode() not in low, name


def test_per_device_url_never_written(tmp_path: Path) -> None:
    # Corpus user "3" carries a photoURL pointing at the fake host (TEST-NET).
    result = export(tmp_path, seeded_device())
    blob = (result.bundle_dir / "people.jsonl").read_bytes()
    assert b"photoURL" not in blob
    assert FAKE_HOST.encode() not in blob  # per-device host part is gone WITH the field


def test_search_id_is_byte_stable_and_cursor_advances(tmp_path: Path) -> None:
    device = seeded_device()
    export_bundle(
        tmp_path / "paged",
        client=make_client(device),
        clock=fixed_clock,
        page_size=2,
        inter_page_delay=0.0,
        sleep=no_sleep,
        pacing_clock=lambda: 0.0,
    )
    bodies = [json.loads(s.body) for s in device.served if s.path == USER_SEARCH_PATH]
    assert len(bodies) == 2, "4 users at maxResults=2 -> two pages"
    conds = [b["UserInfoSearchCond"] for b in bodies]
    assert conds[0]["searchID"] == conds[1]["searchID"]  # byte-stable per logical search
    assert conds[0]["searchResultPosition"] == 0
    assert conds[1]["searchResultPosition"] == 2  # advanced by numOfMatches, not maxResults
    data = read_bundle(tmp_path / "paged")
    assert [p["employeeNo"] for p in data.people] == ["1", "2", "3", "4"]


def test_export_empty_only_when_the_device_said_so(tmp_path: Path) -> None:
    """NO MATCH/OK with zero matches = genuinely empty -> an empty-but-valid bundle."""
    device = seeded_device()
    device._enrollment_store = {"UserInfo": [], "CardInfo": []}  # honest empties
    result = export(tmp_path, device)
    assert result.counts == {"users": 0, "cards": 0, "faces": 0}
    data = read_bundle(result.bundle_dir)
    assert data.people == () and data.cards == ()
    assert (result.bundle_dir / "people.jsonl").read_text() == ""
    assert result.termination["UserInfo/Search"] == "NOMATCH"


# --- fail closed (§0.7): every abort shape, and NO bundle left behind --------------------


def assert_no_bundle(out: Path) -> None:
    assert not out.exists()
    assert not out.with_name(out.name + ".partial").exists()


def test_fail_closed_on_400_envelope(tmp_path: Path) -> None:
    device = seeded_device()
    # The 400 must STAY a 400 across the transport's transparent retry and any
    # re-paginating (reset_raw repeats the last response item).
    device.reset_raw(
        "POST",
        USER_SEARCH_PATH,
        *(
            [
                httpx.Response(
                    400,
                    json={
                        "statusCode": 6,
                        "statusString": "Invalid Content",
                        "subStatusCode": "badParameters",
                    },
                )
            ]
            * 12
        ),
    )
    with pytest.raises(EnrollmentReadAborted) as excinfo:
        export(tmp_path, device)
    assert excinfo.value.endpoint == "user_info_search"
    assert "never treated as 'empty'" in str(excinfo.value)
    assert_no_bundle(tmp_path / "bundle")


def test_fail_closed_on_transport_error(tmp_path: Path) -> None:
    device = seeded_device()
    device.reset_raw("POST", USER_SEARCH_PATH, *[httpx.ConnectError("dropped keep-alive")] * 12)
    with pytest.raises(EnrollmentReadAborted) as excinfo:
        export(tmp_path, device)
    assert excinfo.value.endpoint == "user_info_search"
    assert isinstance(excinfo.value.cause, Exception)
    assert_no_bundle(tmp_path / "bundle")


def test_fail_closed_on_missing_response_status(tmp_path: Path) -> None:
    device = seeded_device()
    # Explicit route = capture-replay mode: an envelope with no responseStatusStrg.
    device.reset_json(
        "POST",
        USER_SEARCH_PATH,
        {"UserInfoSearch": {"searchID": "x", "numOfMatches": 0, "totalMatches": 0}},
    )
    with pytest.raises(EnrollmentReadAborted) as excinfo:
        export(tmp_path, device)
    assert "responseStatusStrg" in str(excinfo.value)
    assert_no_bundle(tmp_path / "bundle")


def test_fail_closed_on_unknown_terminal_status(tmp_path: Path) -> None:
    device = seeded_device()
    device.reset_json(
        "POST",
        USER_SEARCH_PATH,
        {
            "UserInfoSearch": {
                "searchID": "x",
                "responseStatusStrg": "FAIL",
                "numOfMatches": 0,
                "totalMatches": 0,
            }
        },
    )
    with pytest.raises(EnrollmentReadAborted):
        export(tmp_path, device)
    assert_no_bundle(tmp_path / "bundle")


def test_fail_closed_on_identity_read(tmp_path: Path) -> None:
    device = seeded_device()
    device.reset_raw(
        "GET",
        DEVICE_INFO_PATH,
        *[httpx.Response(400, json={"statusCode": 6, "subStatusCode": "badParameters"})] * 12,
    )
    with pytest.raises(EnrollmentReadAborted) as excinfo:
        export(tmp_path, device)
    assert excinfo.value.endpoint == "device_info"
    assert_no_bundle(tmp_path / "bundle")


# --- FakeDevice enrollment strictness (the device truth the card asked to add) ------------


def raw_http(device: FakeDevice) -> httpx.Client:
    """A digest-authenticated raw client — for wire-shape tests the registry cannot reach."""
    return httpx.Client(
        transport=device.transport,
        auth=httpx.DigestAuth("admin", PASSWORD),
        base_url=BASE_URL,
    )


@pytest.mark.parametrize(
    "path",
    [
        "/ISAPI/AccessControl/UserInfoDetail/Search?format=json",
        "/ISAPI/AccessControl/FingerPrint/Search?format=json",
        "/ISAPI/AccessControl/PlanTemplate/Get?format=json",
    ],
)
def test_not_support_matrix_answers_the_probed_envelope(path: str) -> None:
    """Exactly the recorded envelope (error_total_notsupport.json) — incl. errorCode
    1073741825 and the `unknow` spelling — and it maps to IsapiNotFound at the client."""
    device = seeded_device()
    with raw_http(device) as client:
        response = client.post(path, json={})
    assert response.status_code == 400
    assert response.json() == {
        "statusCode": 4,
        "statusString": "Invalid Operation",
        "subStatusCode": "notSupport",
        "errorCode": 1073741825,
        "errorMsg": "unknow",
    }


def test_unknown_enrollment_post_is_a_hard_failure() -> None:
    """No permissive 404, no empty answer: FDSearch (E1-01b's, capture pending) POSTs
    raise through the transport — inventing an endpoint fails HERE."""
    device = seeded_device()
    with raw_http(device) as client, pytest.raises(EnrollmentProtocolError) as excinfo:
        client.post("/ISAPI/Intelligent/FDLib/FDSearch?format=json", json={})
    assert "capture-before-fake" in str(excinfo.value)
    # and the client that TRIES it via the registry cannot even address it:
    with pytest.raises(KeyError, match="unknown endpoint"):
        make_client(device).search("face_search", {})


def test_dialect_split_wrapped_body_required() -> None:
    """The enrollment searches reject the FLAT dialect (badJsonContent naming the
    wrapper) — the per-endpoint dialect rule the FDSearch lesson taught (§9)."""
    device = seeded_device()
    with raw_http(device) as client:
        flat = client.post(USER_SEARCH_PATH, json={"searchID": "abc123def456", "maxResults": 5})
    assert flat.status_code == 400
    body = flat.json()
    assert body["subStatusCode"] == "badJsonContent"
    assert body["errorMsg"] == "UserInfoSearchCond"


def test_search_id_required_message_parameters_lack() -> None:
    device = seeded_device()
    with raw_http(device) as client:
        response = client.post(USER_SEARCH_PATH, json={"UserInfoSearchCond": {"maxResults": 5}})
    assert response.status_code == 400
    body = response.json()
    assert body["subStatusCode"] == "MessageParametersLack"
    assert body["errorMsg"] == "searchID"


def test_employee_no_list_filter_is_honoured() -> None:
    """A: filter PROVEN honored (1->1, 99->0 NO MATCH) — a fake that ignored filters
    would hide exactly the coverage bug design §6 refuses to trust."""
    device = seeded_device()
    with raw_http(device) as client:
        one = client.post(
            USER_SEARCH_PATH,
            json={
                "UserInfoSearchCond": {
                    "searchID": "aaaa1111bbbb",
                    "maxResults": 10,
                    "EmployeeNoList": [{"employeeNo": "2"}],
                }
            },
        ).json()
        none = client.post(
            USER_SEARCH_PATH,
            json={
                "UserInfoSearchCond": {
                    "searchID": "aaaa1111bbbb",
                    "maxResults": 10,
                    "EmployeeNoList": [{"employeeNo": "99"}],
                }
            },
        ).json()
    env_one = one["UserInfoSearch"]
    assert env_one["numOfMatches"] == 1
    assert [u["employeeNo"] for u in env_one["UserInfo"]] == ["2"]
    env_none = none["UserInfoSearch"]
    assert env_none["responseStatusStrg"] == "NO MATCH"
    assert "UserInfo" not in env_none  # absent key, never []


def test_more_semantics_on_truncated_pages() -> None:
    """Probed (design §1): maxResults=2 on 4 users answers MORE then OK — truncation
    reads as MORE, never as a complete OK."""
    device = seeded_device()
    with raw_http(device) as client:
        first = client.post(
            USER_SEARCH_PATH,
            json={"UserInfoSearchCond": {"searchID": "s1page0000", "maxResults": 2}},
        ).json()["UserInfoSearch"]
        second = client.post(
            USER_SEARCH_PATH,
            json={
                "UserInfoSearchCond": {
                    "searchID": "s1page0000",
                    "maxResults": 2,
                    "searchResultPosition": 2,
                }
            },
        ).json()["UserInfoSearch"]
    assert first["responseStatusStrg"] == "MORE"
    assert second["responseStatusStrg"] == "OK"


def test_export_reads_the_cardinfo_search_shape(tmp_path: Path) -> None:
    """A card-carrying device exports through the SAME engine: wrapped CardInfoSearchCond
    bodies, CardInfoSearch envelope, CardInfo records, byte-stable ids."""
    device = seeded_device()
    device.seed_enrollment(
        users=A_CORPUS_USERS,
        cards=[
            {"employeeNo": "1", "cardNo": "tmp001", "cardType": "normalCard"},
            {"employeeNo": "3", "cardNo": "garten-zho0k6WjKtxJm", "cardType": "normalCard"},
        ],
    )
    result = export(tmp_path, device)
    assert result.counts["cards"] == 2
    data = read_bundle(result.bundle_dir)
    assert [(c["employeeNo"], c["cardNo"]) for c in data.cards] == [
        ("1", "tmp001"),
        ("3", "garten-zho0k6WjKtxJm"),
    ]
    card_bodies = [json.loads(s.body) for s in device.served if s.path == CARD_SEARCH_PATH]
    assert "CardInfoSearchCond" in card_bodies[0]
    assert result.termination["CardInfo/Search"] == "OK"


def test_card_walk_survives_a_second_run_same_bytes(tmp_path: Path) -> None:
    """§9 byte-stability across the whole surface incl. cards."""
    device = seeded_device()
    device.seed_enrollment(cards=[{"employeeNo": "7", "cardNo": "c-07", "cardType": "normalCard"}])
    a = export(tmp_path, device, "a")
    b = export(tmp_path, device, "b")
    assert (a.bundle_dir / "cards.jsonl").read_bytes() == (
        b.bundle_dir / "cards.jsonl"
    ).read_bytes()
    # cards hash too — the pair (cardNo, employeeNo) is diff/verify material (E1-02):
    assert content_hash({"employeeNo": "7", "cardNo": "c-07", "cardType": "normalCard"})
    assert a.counts["cards"] == 1


def test_notsupport_via_client_maps_to_isapinotfound() -> None:
    """The registry + transport still own error typing: a fake notSupport envelope is
    an IsapiNotFound on the client (the E1-03 probe will rely on exactly this)."""
    device = seeded_device()
    with raw_http(device) as client:
        response = client.post("/ISAPI/AccessControl/UserInfoDetail/Search?format=json", json={})
    assert response.status_code == 400 and response.json()["subStatusCode"] == "notSupport"
    # Sanity that the client-side mapping exists for THAT envelope shape:
    from gateclerk.isapi_response import envelope_to_error, parse_envelope

    envelope = parse_envelope(response.content, http_status=400)
    error = envelope_to_error(http_status=400, envelope=envelope, endpoint="user_info_detail")
    assert isinstance(error, IsapiNotFound)


# --- the shared-function contract E1-02 depends on ----------------------------------------


def test_diff_side_would_hash_bundle_lines_identically(tmp_path: Path) -> None:
    """Bundle people lines, re-read and re-hashed (what the diff does), equal the
    manifest hashes — `content_hash` on an already-normalized record must not
    re-strip and must not drift."""
    result = export(tmp_path, seeded_device())
    data = read_bundle(result.bundle_dir)
    for record in data.people:
        line_hash = content_hash(record)
        assert line_hash == data.manifest.people_hashes[record["employeeNo"]]


def test_export_requires_the_injected_clock(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="injected clock"):
        export_bundle(tmp_path / "b", client=make_client(seeded_device()), clock=None)  # type: ignore[arg-type]
