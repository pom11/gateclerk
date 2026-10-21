"""Card E1-01b: face + fingerprint TEMPLATE export (the addendum to E1-01).

Everything runs offline (autouse `netoff`, FakeDevice replaying bench-A truth from
docs/ENROLLMENT-MIGRATION.md §1 / OBSERVED.md E1 rounds 11-18). Layers of proof:

1. The FDSearch walk: FLAT dialect only (the wrapped style 400s — the §9 dialect
   split pinned from BOTH sides), required flat params, the FPID filter honoured,
   the recorded paging quirk (3 of 4 rows on ONE OK page) reproduced by the fake and
   survived by the walker, the FPID->employeeNo join as OPAQUE string equality.
2. The FingerPrintUpload read: `FingerPrintCond` wrapper REQUIRED (probed 400),
   empty `FingerPrintList` as the pinned stop shape (PR-body reviewer question #2),
   the runaway guard aborting rather than truncating, `FingerPrint/Search` STILL
   notSupport (the old door really is dead).
3. Templates are OPAQUE: bytes are stored exactly as the device sent them, sha256/
   length are over the decoded form, a mutated byte changes only hashes, and the
   export never depends on template structure (a non-magic face, a non-301 finger
   header export fine; the sensor-family NOTE is a label, not a parse).
4. The v2 bundle: AVAILABLE two-state indexes, the faceURL-404 photo_bytes recorded
   fact, manifest face/FP sections + index digests + REPORT-ONLY counters, reader
   re-verification, and the E1-01 regressions (modes 0700/0600, repo-out refusal)
   pinned against the new writer path.
"""

from __future__ import annotations

import base64
import json
import stat
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import httpx
import pytest

from fakedevice import (
    BASE_URL,
    FD_SEARCH_PATH,
    FD_TEMPLATE_MAGIC,
    FD_TEMPLATE_SIZE,
    FINGER_PRINT_UPLOAD_PATH,
    FP_TEMPLATE_MAGIC,
    FP_TEMPLATE_SIZE,
    EnrollmentProtocolError,
    FakeDevice,
    _a_user,
    _synthetic_template,
)
from gateclerk.exceptions import EnrollmentReadAborted
from gateclerk.isapi_transport import IsapiClient
from gateclerk.migrate_bundle import (
    PHOTO_BYTES_ABSENT_REASON,
    SCHEMA_VERSION,
    index_digest,
    read_bundle,
)
from gateclerk.migrate_export import (
    MAX_FP_TEMPLATES_PER_PERSON,
    export_faces,
    export_fingerprints,
    export_full_bundle,
)

FIXTURES = Path(__file__).parent / "fixtures/recorded/site-a-ds-k1t341amf-s"
DEVICE_INFO_PATH = "/ISAPI/System/deviceInfo?format=json"
FD_PATH = FD_SEARCH_PATH + "?format=json"
FP_PATH = FINGER_PRINT_UPLOAD_PATH + "?format=json"

# FakeDevice's digest password, built from parts (placeholder policy per
# tests/test_repo_hygiene.py — same convention as the E1-01 test module).
PASSWORD = "fake" + "pw"
EXPORTED_AT = datetime(2026, 10, 21, 12, 0, 0, tzinfo=UTC)


def no_sleep(_seconds: float) -> None:
    return None


def fixed_clock() -> datetime:
    return EXPORTED_AT


def make_client(device: FakeDevice) -> IsapiClient:
    return IsapiClient(BASE_URL, "admin", PASSWORD, transport=device.transport, sleep=no_sleep)


def raw_http(device: FakeDevice) -> httpx.Client:
    return httpx.Client(
        transport=device.transport,
        auth=httpx.DigestAuth("admin", PASSWORD),
        base_url=BASE_URL,
    )


def seeded_device(biometric: bool = True) -> FakeDevice:
    """A's identity + enrollment corpus (4 users/0 cards) + bench-A biometric store."""
    device = FakeDevice(password=PASSWORD)
    device.xml_ok("GET", DEVICE_INFO_PATH, (FIXTURES / "device_info.xml").read_text())
    device.seed_enrollment()
    if biometric:
        device.seed_biometric()
    return device


def export(tmp_path: Path, device: FakeDevice, name: str = "bundle"):
    return export_full_bundle(
        tmp_path / name,
        client=make_client(device),
        clock=fixed_clock,
        inter_page_delay=0.0,
        sleep=no_sleep,
        pacing_clock=lambda: 0.0,
    )


def assert_no_bundle(out: Path) -> None:
    assert not out.exists()
    assert not out.with_name(out.name + ".partial").exists()


def tree_bytes(root: Path) -> dict[str, bytes]:
    """Every file under `root` keyed by relative path — the byte-stability unit."""
    return {
        str(p.relative_to(root)): p.read_bytes() for p in sorted(root.rglob("*")) if p.is_file()
    }


# --- the v2 bundle layout over the real client + fake (design §2) ------------------------


def test_full_bundle_layout_round_trips(tmp_path: Path) -> None:
    result = export(tmp_path, seeded_device())
    out = result.bundle_dir
    # v4 §2: faces/<employeeNo>.b64 + INDEX, fingerprints/<employeeNo>-<fpIndex>.b64 + INDEX.
    for person in ("1", "2", "3", "4"):
        assert (out / "faces" / f"{person}.b64").is_file()
    assert (out / "faces" / "INDEX.json").is_file()
    assert (out / "fingerprints" / "1-0.b64").is_file()  # A's only fingerprint: user 1 fpIndex 0
    assert (out / "fingerprints" / "INDEX.json").is_file()
    assert not (out / "fingerprints" / "2-0.b64").exists()  # nobody else has one (§1 numOfFP)

    data = read_bundle(out)
    assert data.manifest.schema_version == SCHEMA_VERSION == "gateclerk-enrollment-bundle/2"
    assert data.faces.state == "AVAILABLE" and len(data.faces.entries) == 4
    assert data.fingerprints.state == "AVAILABLE" and len(data.fingerprints.entries) == 1
    assert [e.employee_no for e in data.fingerprints.entries] == ["1"]
    assert data.fingerprints.entries[0].fp_index == 0
    assert result.counts == {"users": 4, "cards": 0, "faces": 4, "fingerprints": 1}


def test_faces_and_fp_export_is_byte_stable(tmp_path: Path) -> None:
    """Two runs, same injected clock, same device state -> IDENTICAL bundle bytes."""
    a = export(tmp_path, seeded_device(), "a").bundle_dir
    b = export(tmp_path, seeded_device(), "b").bundle_dir
    tree_a, tree_b = tree_bytes(a), tree_bytes(b)
    assert tree_a.keys() == tree_b.keys()
    assert all(tree_a[k] == tree_b[k] for k in tree_a)
    # the biometric files are actually in there (a vacuous compare would prove nothing)
    assert any(k.startswith("faces/") for k in tree_a) and any(
        k.startswith("fingerprints/") for k in tree_a
    )


def test_manifest_records_photo_bytes_absence_reason(tmp_path: Path) -> None:
    """v4 §2: the faceURL-404 note is a RECORDED FACT that travels with every walk."""
    out = export(tmp_path, seeded_device()).bundle_dir
    manifest = json.loads((out / "manifest.json").read_text())
    assert manifest["faces"]["photo_bytes"]["reason"] == PHOTO_BYTES_ABSENT_REASON
    assert "faceURL photo bytes NOT exportable" in PHOTO_BYTES_ABSENT_REASON
    index = json.loads((out / "faces" / "INDEX.json").read_text())
    assert index["state"] == "AVAILABLE"
    assert index["photo_bytes"]["reason"] == PHOTO_BYTES_ABSENT_REASON


def test_manifest_sections_digests_and_report_only_counters(tmp_path: Path) -> None:
    """Counts + digests in the manifest, NEVER raw bytes; counters reported, not resolved."""
    out = export(tmp_path, seeded_device()).bundle_dir
    manifest = json.loads((out / "manifest.json").read_text())
    data = read_bundle(out)
    assert manifest["counts"] == {"users": 4, "cards": 0, "faces": 4, "fingerprints": 1}
    # The manifest commits to the INDEX entries with digests (single source of truth).
    assert manifest["faces_index_digest"] == index_digest([e.to_dict() for e in data.faces.entries])
    assert manifest["fingerprints_index_digest"] == index_digest(
        [e.to_dict() for e in data.fingerprints.entries]
    )
    # No template PAYLOAD in the manifest (the card's "NO raw bytes in manifest"):
    # the device's actual base64 strings appear nowhere in it — only counts, hashes
    # and labels do. (The word "modelData" may legitimately appear in reason prose.)
    dumped = json.dumps(manifest)
    device_sample = _fd_first_page(seeded_device())
    for row in device_sample["MatchList"]:
        assert row["modelData"][:32] not in dumped
    assert FD_TEMPLATE_MAGIC.decode(errors="ignore") not in dumped
    # v4 §9 counter-vs-set: reported per person, disagreement left for E1-02 to classify.
    counters = manifest["enrollment_counters"]
    assert counters["1"] == {
        "numOfFace": 1,
        "numOfFP": 1,
        "exported_faces": 1,
        "exported_fingerprints": 1,
    }
    assert counters["2"]["numOfFP"] == 0 and counters["2"]["exported_fingerprints"] == 0
    # Audit trail: the FDSearch walk's terminal status + the FP engine stop label.
    assert manifest["termination"]["FDSearch"] == "NOMATCH"
    assert manifest["termination"]["FingerPrintUpload"] == "OK-EMPTY-LIST"


def test_bundle_modes_and_repo_out_refusal_survive_the_v2_writer(tmp_path: Path) -> None:
    """E1-01's file-hygiene regression, pinned against the NEW writer path (§2)."""
    out = export(tmp_path, seeded_device()).bundle_dir
    assert stat.S_IMODE(out.stat().st_mode) == 0o700
    for directory in (out / "faces", out / "fingerprints"):
        assert stat.S_IMODE(directory.stat().st_mode) == 0o700
    for file in out.rglob("*"):
        if file.is_file():
            assert stat.S_IMODE(file.stat().st_mode) == 0o600, file
    # repo-out refusal unchanged (E1-01 §2 rule, now through the v2 writer path)…
    repo = tmp_path / "public-repo"
    (repo / ".git").mkdir(parents=True)
    with pytest.raises(ValueError, match="inside a git repo"):
        export(repo, seeded_device(), "leak")
    # ...and overwrite refusal still fires for a biometric bundle.
    first = export(tmp_path, seeded_device(), "twice").bundle_dir
    with pytest.raises(ValueError, match="refusing to overwrite"):
        export_full_bundle(
            first,
            client=make_client(seeded_device()),
            clock=fixed_clock,
            inter_page_delay=0.0,
            sleep=no_sleep,
            pacing_clock=lambda: 0.0,
        )


# --- opaque templates: the export never PARSES (card §1/§2 rule) -------------------------


def test_template_files_are_the_devices_own_base64_verbatim(tmp_path: Path) -> None:
    """faces/<no>.b64 == the device's `modelData` string exactly (trailing newline aside)."""
    out = export(tmp_path, seeded_device()).bundle_dir
    device = seeded_device()
    body = _fd_first_page(device)
    for row in body["MatchList"]:
        person = row["FPID"]
        on_disk = (out / "faces" / f"{person}.b64").read_text().rstrip("\n")
        assert on_disk == row["modelData"]


def _fd_first_page(device: FakeDevice) -> dict[str, Any]:
    with raw_http(device) as client:
        response = client.post(
            FD_PATH,
            json={
                "searchResultPosition": 0,
                "maxResults": 30,
                "faceLibType": "blackFD",
                "FDID": "1",
            },
        )
    assert response.status_code == 200
    return response.json()


def test_mutated_template_byte_changes_only_the_hashes(tmp_path: Path) -> None:
    """One stored byte flipped -> faces digest + that file change; people hashes cannot move."""
    from fakedevice import A_FD_ROWS

    flipped = dict(A_FD_ROWS)
    mutated = bytearray(flipped["2"])
    mutated[40] ^= 0x01  # one byte, middle of the template
    flipped["2"] = bytes(mutated)

    device = seeded_device()
    device.seed_biometric(faces=flipped)
    out = export(tmp_path, device).bundle_dir
    data = read_bundle(out)  # still self-consistent: the index pins THE MUTATED bytes
    base = read_bundle(export(tmp_path, seeded_device(), "base").bundle_dir)

    assert {e.sha256 for e in data.faces.entries} != {e.sha256 for e in base.faces.entries}
    assert data.person_hashes() == base.person_hashes()  # people axis untouched (opaque bytes)
    assert (out / "faces" / "2.b64").read_bytes() != (
        (out.parent / "base" / "faces" / "2.b64").read_bytes()
    )
    # The mutated template never breaks the reader — it only changes what is pinned.
    assert data.faces.entries[1].length == FD_TEMPLATE_SIZE


def test_export_never_depends_on_template_structure(tmp_path: Path) -> None:
    """A face WITHOUT the recorded magic and a finger WITHOUT the 301 header export fine.

    This is the opaque rule as a test: if any code parsed modelData/fingerData (or
    keyed behaviour on their contents beyond the sensor-family NOTE), these fixtures
    would break it.
    """
    device = seeded_device()
    faces = {
        no: _synthetic_template(FD_TEMPLATE_SIZE, FD_TEMPLATE_MAGIC, f"face:{no}")
        for no in ("2", "3", "4")
    }
    faces["1"] = _synthetic_template(FD_TEMPLATE_SIZE, b"NOPE1234", "weird-face")
    device.seed_biometric(faces=faces)
    result = export(tmp_path, device)
    assert result.counts["faces"] == 4  # magic-less bytes still export, un-parsed


def test_sensor_family_note_is_a_label_not_a_parse(tmp_path: Path) -> None:
    """301-header bytes label the recorded family; anything else labels unknown (§1)."""
    device = seeded_device()
    device.seed_biometric(
        fingerprints={("1", 0): _synthetic_template(FP_TEMPLATE_SIZE, b"999", "other-family")}
    )
    data = read_bundle(export(tmp_path, device).bundle_dir)
    entry = data.fingerprints.entries[0]
    assert entry.sensor_family.startswith("unknown")
    assert entry.length == FP_TEMPLATE_SIZE  # size + base64-ness are all the export needed

    normal = read_bundle(export(tmp_path, seeded_device(), "normal").bundle_dir)
    assert "301-header" in normal.fingerprints.entries[0].sensor_family


# --- the FDSearch walk: dialect, filter, quirk, join (bench-A truth) ---------------------


def test_fd_search_wrapped_style_is_rejected() -> None:
    """The §9 dialect split pinned from the fake side: the UserInfo-style wrapper 400s."""
    device = seeded_device()
    with raw_http(device) as client:
        wrapped = client.post(
            FD_PATH,
            json={"FDSearchCond": {"maxResults": 30, "faceLibType": "blackFD", "FDID": "1"}},
        )
    assert wrapped.status_code == 400
    assert wrapped.json()["subStatusCode"] == "badJsonContent"


@pytest.mark.parametrize("missing", ["faceLibType", "FDID"])
def test_fd_search_required_params_message_parameters_lack(missing: str) -> None:
    body: dict[str, Any] = {"searchResultPosition": 0, "maxResults": 30}
    body.update({"faceLibType": "blackFD", "FDID": "1"})
    del body[missing]
    with raw_http(seeded_device()) as client:
        response = client.post(FD_PATH, json=body)
    assert response.status_code == 400
    payload = response.json()
    assert payload["subStatusCode"] == "MessageParametersLack"
    assert payload["errorMsg"] == missing


def test_fd_search_fpid_filter_honored_and_rows_carry_model_data() -> None:
    """FPID=1 -> exactly 1 row (§1: honoured, 1 of 4); FPID=99 -> the device's own NO MATCH."""
    device = seeded_device()
    device.fd_first_page_short = False  # this test is about the FILTER, not the quirk
    with raw_http(device) as client:
        hit = client.post(
            FD_PATH,
            json={
                "searchResultPosition": 0,
                "maxResults": 30,
                "faceLibType": "blackFD",
                "FDID": "1",
                "FPID": "1",
            },
        ).json()
        miss = client.post(
            FD_PATH,
            json={
                "searchResultPosition": 0,
                "maxResults": 30,
                "faceLibType": "blackFD",
                "FDID": "1",
                "FPID": "99",
            },
        ).json()
    assert hit["numOfMatches"] == 1 and hit["totalMatches"] == 1
    # (totalMatches counts the FILTERED set — the same reviewed convention the
    # E1-01 users/cards fake uses; "FPID=1 -> 1/4" on the device side means "1 of the
    # 4-person library", which the numOfMatches above is the honest answer to.)
    row = hit["MatchList"][0]
    assert row["FPID"] == "1"
    assert base64.b64decode(row["modelData"], validate=True).startswith(FD_TEMPLATE_MAGIC)
    assert len(base64.b64decode(row["modelData"])) == FD_TEMPLATE_SIZE
    assert miss["responseStatusStrg"] == "NO MATCH" and "MatchList" not in miss


def test_fd_search_paging_quirk_walk_still_exports_every_person(tmp_path: Path) -> None:
    """Bench A answered 3 of 4 rows on ONE OK page; the walker must not trust OK.

    The fake reproduces the quirk by default, so a walker that terminated on the
    first OK page (paging.py's `terminate_on_non_more` default) would export 3 faces
    with no error anywhere — this test is the reason the fd_search engine pages to
    the zero-row page.
    """
    device = seeded_device()
    result = export(tmp_path, device)
    assert result.counts["faces"] == 4
    pages = [s for s in device.served if s.path.startswith(FD_SEARCH_PATH)]
    assert len(pages) == 3  # page 1 (quirk), page 2 (last person), page 3 (NO MATCH -> stop)


def test_export_faces_collects_model_data_without_the_composite(tmp_path: Path) -> None:
    """export_faces() stands alone over the roster it is handed (unit of the walk)."""
    walk = export_faces(
        make_client(seeded_device()),
        employee_nos=["1", "2", "3", "4"],
        inter_page_delay=0.0,
        sleep=no_sleep,
        clock=lambda: 0.0,
    )
    assert sorted(walk.templates) == ["1", "2", "3", "4"]
    assert walk.termination == "NOMATCH"
    entry = walk.entries[0]
    assert (entry.fdid, entry.face_lib_type) == ("1", "blackFD")
    assert entry.length == FD_TEMPLATE_SIZE
    assert len(entry.sha256) == 64


def test_fpid_joins_employee_no_by_opaque_string_equality(tmp_path: Path) -> None:
    """Fixture from the card: FPID "007" joins employeeNo "007" — never "7"."""
    device = FakeDevice(password=PASSWORD)
    device.xml_ok("GET", DEVICE_INFO_PATH, (FIXTURES / "device_info.xml").read_text())
    device.seed_enrollment(users=[_a_user("007", local_ui=False)], cards=[])
    device.seed_biometric(
        faces={"007": _synthetic_template(FD_TEMPLATE_SIZE, FD_TEMPLATE_MAGIC, "007")}
    )
    data = read_bundle(export(tmp_path, device).bundle_dir)
    assert (data.faces.entries[0].employee_no, data.faces.entries[0].length) == (
        "007",
        FD_TEMPLATE_SIZE,
    )
    assert (data.manifest.counts["faces"], data.faces.entries[0].fdid) == (1, "1")


def test_orphan_face_row_aborts_the_export(tmp_path: Path) -> None:
    """A row whose FPID is not on the roster is a join bug/tampered row: fail closed.

    The numeric-collision case: roster holds "007" (leading zeros ARE data, §1); a
    device row spelling it "7" must NOT be accepted as the same person.
    """
    device = FakeDevice(password=PASSWORD)
    device.xml_ok("GET", DEVICE_INFO_PATH, (FIXTURES / "device_info.xml").read_text())
    device.seed_enrollment(users=[_a_user("007", local_ui=False)], cards=[])
    device.seed_biometric(
        faces={"7": _synthetic_template(FD_TEMPLATE_SIZE, FD_TEMPLATE_MAGIC, "7")}
    )
    with pytest.raises(EnrollmentReadAborted) as excinfo:
        export(tmp_path, device)
    assert excinfo.value.endpoint == "fd_search"
    assert "not on the exported roster" in str(excinfo.value)
    assert_no_bundle(tmp_path / "bundle")


# --- the FingerPrintUpload read: wrapper, stop shape, runaway ----------------------------


def test_fingerprint_plain_cond_is_rejected_exactly_as_probed() -> None:
    """The probed 400: plain cond -> MessageParametersLack naming FingerPrintCond (§1)."""
    with raw_http(seeded_device()) as client:
        plain = client.post(
            FP_PATH, json={"searchID": "abc123def456", "employeeNo": "1", "fpIndex": 0}
        )
    assert plain.status_code == 400
    payload = plain.json()
    assert payload["subStatusCode"] == "MessageParametersLack"
    assert payload["errorMsg"] == "FingerPrintCond"


@pytest.mark.parametrize("missing", ["searchID", "employeeNo", "fpIndex", "dataType"])
def test_fingerprint_wrapper_fields_required(missing: str) -> None:
    cond: dict[str, Any] = {
        "searchID": "abc123def456",
        "employeeNo": "1",
        "fpIndex": 0,
        "dataType": "template",
    }
    del cond[missing]
    with raw_http(seeded_device()) as client:
        response = client.post(FP_PATH, json={"FingerPrintCond": cond})
    assert response.status_code == 400
    payload = response.json()
    assert payload["subStatusCode"] == "MessageParametersLack"
    assert payload["errorMsg"] == missing


def test_fingerprint_answer_is_the_recorded_shape() -> None:
    """One row: fingerPrintID = fpIndex+1, fingerType normalFP, base64 fingerData (§1)."""
    with raw_http(seeded_device()) as client:
        body = client.post(
            FP_PATH,
            json={
                "FingerPrintCond": {
                    "searchID": "abc123def456",
                    "employeeNo": "1",
                    "fpIndex": 0,
                    "dataType": "template",
                }
            },
        ).json()
    rows = body["FingerPrintInfo"]["FingerPrintList"]
    assert len(rows) == 1
    row = rows[0]
    assert row["fingerPrintID"] == 1 and row["fingerType"] == "normalFP"
    decoded = base64.b64decode(row["fingerData"], validate=True)
    assert decoded.startswith(FP_TEMPLATE_MAGIC) and len(decoded) == FP_TEMPLATE_SIZE


def test_fp_walk_reads_index_by_index_until_the_empty_list(tmp_path: Path) -> None:
    """Two stored fingers on user "1": fpIndex 0,1 answered, index 2 hits the empty list."""
    device = seeded_device()
    device.seed_biometric(
        fingerprints={
            ("1", 0): _synthetic_template(FP_TEMPLATE_SIZE, FP_TEMPLATE_MAGIC, "a"),
            ("1", 1): _synthetic_template(FP_TEMPLATE_SIZE, FP_TEMPLATE_MAGIC, "b"),
        }
    )
    walk = export_fingerprints(
        make_client(device),
        employee_nos=["1"],
        inter_request_delay=0.0,
        sleep=no_sleep,
        pacing_clock=lambda: 0.0,
    )
    assert [f[1] for f in walk.files] == [0, 1]  # stopped on the device's own empty list
    assert walk.termination == "OK-EMPTY-LIST"
    # One read per stored index + ONE more that returned the stop shape — no skipping.
    # (`had_auth` filters the digest handshake request, which has no path authority.)
    fp_posts = [
        s for s in device.served if s.path.startswith(FINGER_PRINT_UPLOAD_PATH) and s.had_auth
    ]
    assert len(fp_posts) == 3


def test_fp_runaway_device_aborts_instead_of_truncating(tmp_path: Path) -> None:
    """A device that answers EVERY fpIndex never said stop: abort, never truncate."""
    device = seeded_device()
    endless = {
        ("1", i): _synthetic_template(FP_TEMPLATE_SIZE, FP_TEMPLATE_MAGIC, f"x{i}")
        for i in range(MAX_FP_TEMPLATES_PER_PERSON + 1)
    }
    device.seed_biometric(fingerprints=endless)
    with pytest.raises(EnrollmentReadAborted) as excinfo:
        export(tmp_path, device)
    assert excinfo.value.endpoint == "finger_print_upload"
    assert "never says stop" in str(excinfo.value)
    assert_no_bundle(tmp_path / "bundle")


def test_fp_multi_row_answer_aborts(tmp_path: Path) -> None:
    """The probed shape is ONE row per read; two rows is a protocol break, not a choice."""
    device = seeded_device()
    row = {
        "cardReaderNo": 1,
        "fingerPrintID": 1,
        "fingerType": "normalFP",
        "fingerData": base64.b64encode(b"x" * 64).decode("ascii"),
        "leaderFP": "true",
    }
    device.reset_json("POST", FP_PATH, {"FingerPrintInfo": {"FingerPrintList": [row, row]}})
    with pytest.raises(EnrollmentReadAborted) as excinfo:
        export(tmp_path, device)
    assert excinfo.value.endpoint == "finger_print_upload"
    assert "exactly one" in str(excinfo.value)
    assert_no_bundle(tmp_path / "bundle")


def test_finger_print_search_stays_notsupport() -> None:
    """The OLD door really is dead (§1): arming the read must not resurrect the search."""
    with raw_http(seeded_device()) as client:
        response = client.post("/ISAPI/AccessControl/FingerPrint/Search?format=json", json={})
    assert response.status_code == 400
    assert response.json()["subStatusCode"] == "notSupport"


# --- fail closed (§0.7): abort shapes on the new reads ------------------------------------


def test_fail_closed_on_fdsearch_error_envelope(tmp_path: Path) -> None:
    device = seeded_device()
    device.reset_raw(
        "POST",
        FD_PATH,
        *[
            httpx.Response(
                400,
                json={
                    "statusCode": 6,
                    "statusString": "Invalid Content",
                    "subStatusCode": "badParameters",
                },
            )
        ]
        * 12,
    )
    with pytest.raises(EnrollmentReadAborted) as excinfo:
        export(tmp_path, device)
    assert excinfo.value.endpoint == "fd_search"
    assert "never treated as 'empty'" in str(excinfo.value)
    assert_no_bundle(tmp_path / "bundle")


def test_fail_closed_on_fdsearch_transport_error(tmp_path: Path) -> None:
    device = seeded_device()
    device.reset_raw("POST", FD_PATH, *[httpx.ConnectError("dropped keep-alive")] * 12)
    with pytest.raises(EnrollmentReadAborted) as excinfo:
        export(tmp_path, device)
    assert excinfo.value.endpoint == "fd_search"
    assert_no_bundle(tmp_path / "bundle")


def test_fail_closed_on_fingerprint_transport_error(tmp_path: Path) -> None:
    device = seeded_device()
    device.reset_raw("POST", FP_PATH, *[httpx.ConnectError("socket died")] * 12)
    with pytest.raises(EnrollmentReadAborted) as excinfo:
        export(tmp_path, device)
    assert excinfo.value.endpoint == "finger_print_upload"
    assert_no_bundle(tmp_path / "bundle")


def test_fail_closed_on_rootless_fingerprint_envelope(tmp_path: Path) -> None:
    """A FingerPrintInfo-less 200 is a protocol break — NEVER read as 'no more fingers'."""
    device = seeded_device()
    device.reset_json("POST", FP_PATH, {"SomethingElse": {}})
    with pytest.raises(EnrollmentReadAborted) as excinfo:
        export(tmp_path, device)
    assert excinfo.value.endpoint == "finger_print_upload"
    assert "FingerPrintInfo" in str(excinfo.value)
    assert_no_bundle(tmp_path / "bundle")


def test_empty_device_exports_honest_zeros(tmp_path: Path) -> None:
    """Empty biometric libraries: AVAILABLE + zero entries, NOT failure, NOT silence."""
    device = FakeDevice(password=PASSWORD)
    device.xml_ok("GET", DEVICE_INFO_PATH, (FIXTURES / "device_info.xml").read_text())
    device.seed_enrollment(users=[], cards=[])
    device.seed_biometric(empty=True)
    result = export(tmp_path, device)
    assert result.counts == {"users": 0, "cards": 0, "faces": 0, "fingerprints": 0}
    assert result.faces.state == "AVAILABLE" and result.faces.entries == ()
    assert result.fingerprints.state == "AVAILABLE"
    assert result.faces.photo_bytes["reason"] == PHOTO_BYTES_ABSENT_REASON
    data = read_bundle(result.bundle_dir)
    assert data.faces.state == "AVAILABLE"
    assert data.manifest.termination["FDSearch"] == "NOMATCH"


def test_unarmed_biometric_post_is_still_a_hard_failure() -> None:
    """E1-01 rule 3 survives E1-01b: no seed_biometric() -> the trap, not emptiness."""
    device = seeded_device(biometric=False)
    with raw_http(device) as client, pytest.raises(EnrollmentProtocolError):
        client.post(FD_PATH, json={"faceLibType": "blackFD", "FDID": "1", "maxResults": 10})
    with raw_http(device) as client, pytest.raises(EnrollmentProtocolError):
        client.post(
            FP_PATH,
            json={
                "FingerPrintCond": {
                    "searchID": "x",
                    "employeeNo": "1",
                    "fpIndex": 0,
                    "dataType": "template",
                }
            },
        )


def test_export_never_gets_face_photo_bytes(tmp_path: Path) -> None:
    """The faceURL dead-end (§1): the walk reads rows ONLY — zero GETs to /LOCALS/."""
    device = seeded_device()
    export(tmp_path, device)
    served = {(s.method, s.path.split("?")[0]) for s in device.served}
    assert served == {
        ("GET", "/ISAPI/System/deviceInfo"),
        ("POST", "/ISAPI/AccessControl/UserInfo/Search"),
        ("POST", "/ISAPI/AccessControl/CardInfo/Search"),
        ("POST", FD_SEARCH_PATH),
        ("POST", FINGER_PRINT_UPLOAD_PATH),
    }
    assert not any("/LOCALS" in p for _, p in served)


def test_reader_refuses_tampered_fingerprint_bytes(tmp_path: Path) -> None:
    """The v2 reader re-verifies EVERY .b64 against the index — post-export edits die here."""
    out = export(tmp_path, seeded_device()).bundle_dir
    victim = out / "fingerprints" / "1-0.b64"
    body = bytearray(base64.b64decode(victim.read_text().strip()))
    body[100] ^= 0x01
    victim.write_text(base64.b64encode(bytes(body)).decode("ascii") + "\n")
    with pytest.raises(ValueError, match="do not match the index"):
        read_bundle(out)
