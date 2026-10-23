"""Card E1-06 definition of done: the faces phase, offline and FakeDevice-strict.

Everything runs under the autouse `netoff` guard — the real device is NEVER contacted;
the six facesetup_*/fdsearch_delete_* captures (plus the FDSearch read axis E1-01b
shipped) are the only device truth the fake may answer from. The headlines this suite
exists to keep true (bench A, OBSERVED.md + design §5 step 6):

    The face TEMPLATE is the product. `PUT FDSetUp` accepts the flat four-key body
    (facesetup_add_request.json → statusCode 1) and `FDSearch` then answers the SAME
    FPID with byte-identical `modelData` (facesetup_readback_fpid90.json). Confirmation
    is ONLY that read-back — the sha256 AND the length of the returned template equal
    the journal's intent — never the ack. And the undo that makes the whole loop safe
    is the capture-proven TARGETED delete (fdsearch_delete_*: one FPID in, NO MATCH
    back, other people's faces untouched), wrapped in the §5b count-delta guard.

Pins (card §Tests): the upload body is byte-equal to the capture; `confirmed` requires
the read-back (an accepted-but-landed-nothing box — the `faces_applies=False`
counterfactual — ends TERMINAL with the journal at `applied`); an idempotent re-run
writes nothing and JOURNALS nothing (decision 1: an already-present face must never
become undo-able evidence of a write we never made); a different-hash target row is a
CONFLICT and is never overwritten; the first rejection aborts the phase and the carried
result names who landed (nothing is retried, §0.6); §5a order — the journal line is on
disk before the request arrives; undo removes only confirmed adds whose LIVE hash still
matches (proof-of-add), refuses non-confirmed and drifted entries, is idempotent on a
second run, and the count-delta guard turns an over-delete into an incident that stops
the run; no request for `UserInfoDetail/Delete` leaves either side (§5b.1); the budget
ledger and the fake's own authed-request counters agree (three authed calls per person,
one ledger, re-bootstrap at 80).
"""

from __future__ import annotations

import base64
import hashlib
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import httpx
import pytest

from fakedevice import (
    BASE_URL,
    FD_TEMPLATE_MAGIC,
    EnrollmentProtocolError,
    FakeDevice,
)
from gateclerk.isapi_transport import IsapiClient
from gateclerk.migrate_bundle import FacesIndex, FaceTemplate
from gateclerk.migrate_faces import (
    ABSENT_SHA,
    BUNDLE_FACES_DIR,
    CAPTURED_FACE_DELETE_KEYS,
    CAPTURED_FACE_SETUP_KEYS,
    FACE_DELETE_PARAMS,
    FACE_DELETE_PATH,
    FACE_SEARCH_PATH,
    FACE_SETUP_PATH,
    BudgetedFaceReader,
    BudgetedWriteTransport,
    FaceIntent,
    FacePhaseAbortedError,
    FaceShapeError,
    FacesPhaseResult,
    FacesUndoReport,
    FaceUndoIncidentError,
    FaceVerdict,
    FaceWrite,
    ReaderCaller,
    RejectKind,
    RowState,
    WriteJournal,
    WriteRejectedError,
    apply_faces_phase,
    build_face_delete_body,
    build_face_setup_body,
    count_face_rows,
    decode_template,
    face_template_path,
    faces_report,
    journal_fingerprint,
    load_face_writes,
    person_hash,
    plan_face_writes,
    read_face_row,
    run_faces_phase,
    undo_faces,
    verify_faces,
    verify_journal_faces,
)
from gateclerk.migrate_probe import CapabilityMatrix, ProbeStaleError, SurfaceProbe, Verdict

FIXTURES = Path(__file__).parent / "fixtures/recorded/site-a-ds-k1t341amf-s"
ENROLLMENT = FIXTURES / "enrollment"
PASSWORD = "fake" + "pw"  # placeholder policy (tests/test_repo_hygiene.py)

#: The six captures this card rests on, loaded once (they are the contract).
FACE_CAPTURE_REQUEST = json.loads((ENROLLMENT / "facesetup_add_request.json").read_text())
FACE_CAPTURE_ACK = json.loads((ENROLLMENT / "facesetup_add_response.json").read_text())
FACE_CAPTURE_READBACK = json.loads((ENROLLMENT / "facesetup_readback_fpid90.json").read_text())
FACE_DELETE_REQUEST = json.loads((ENROLLMENT / "fdsearch_delete_request.json").read_text())
FACE_DELETE_ACK = json.loads((ENROLLMENT / "fdsearch_delete_response.json").read_text())
FACE_DELETE_NOMATCH = json.loads((ENROLLMENT / "fdsearch_delete_verified_nomatch.json").read_text())

#: A synthetic template of the RECORDED face family: 272 B, magic `FR500005\x01...`
#: (OBSERVED.md; the fake's own FD_TEMPLATE_MAGIC, so a seeded store and a bundle
#: disagreeing about the family is impossible by construction). Bytes, never a parse.
TPL_BYTES = FD_TEMPLATE_MAGIC + bytes(
    (i * 7 + 3) % 251 for i in range(272 - len(FD_TEMPLATE_MAGIC))
)
TPL_B64 = base64.b64encode(TPL_BYTES).decode("ascii")
TPL_SHA = hashlib.sha256(TPL_BYTES).hexdigest()

OTHER_BYTES = FD_TEMPLATE_MAGIC + b"\xff" * (272 - len(FD_TEMPLATE_MAGIC))
OTHER_B64 = base64.b64encode(OTHER_BYTES).decode("ascii")
OTHER_SHA = hashlib.sha256(OTHER_BYTES).hexdigest()

SETUP_URL = FACE_SETUP_PATH + "?format=json"
DELETE_URL = FACE_DELETE_PATH + "?format=json"
DELETE_CAPTURE_URL = FACE_DELETE_PATH + "?format=json&FDID=1&faceLibType=blackFD"
SEARCH_URL = FACE_SEARCH_PATH + "?format=json"

NOW = datetime(2026, 10, 22, 12, 0, 0, tzinfo=UTC)


# --- builders ---------------------------------------------------------------------------


def face_device(
    *,
    faces: dict[str, bytes] | None = None,
    empty: bool = False,
    **knobs: Any,
) -> FakeDevice:
    """A box with BOTH face axes armed: the FDSearch READ store and the FDSetUp write.

    ``faces`` seeds who ALREADY has a template (the read axis); the write knob
    ``faces_applies`` (passed through ``**knobs``) decides whether an accepted upload is
    APPLIED — the default True replays bench A (accept, and the read-back capture shows
    the same bytes back); False is the counterfactual an honest client must survive.
    ``empty=True`` models a face library the device says is empty (the honest zero).
    """
    d = FakeDevice(password=PASSWORD)
    d.install_enrollment()
    if faces is not None or empty:
        d.seed_biometric(faces=faces, empty=empty)
    d.install_write_capture(users=[], **knobs)
    return d


def client_for(device: FakeDevice) -> IsapiClient:
    return IsapiClient(
        BASE_URL, "admin", PASSWORD, transport=device.transport, sleep=lambda _s: None
    )


def raw_request(
    device: FakeDevice, method: str, path: str, *, json_body: Any = None
) -> httpx.Response:
    """One digest-authed request straight into the fake's transport (E1-04 pattern:
    an unauthenticated call gets the 401 challenge, not the route answer)."""
    with httpx.Client(
        transport=device.transport, auth=httpx.DigestAuth("admin", PASSWORD), base_url=BASE_URL
    ) as raw:
        return raw.request(method, path, json=json_body)


def face_entry(no: str, *, sha: str = TPL_SHA, length: int = len(TPL_BYTES), **over: Any):
    return FaceTemplate(
        employee_no=no,
        fdid=str(over.get("fdid", "1")),
        face_lib_type=str(over.get("faceLibType", "blackFD")),
        sha256=sha,
        length=length,
    )


def bundle_with(tmp_path: Path, *entries: tuple[str, bytes]) -> Path:
    """A bundle directory holding one `faces/<no>.b64` per entry (files match INDEX)."""
    root = tmp_path / "bundle"
    (root / BUNDLE_FACES_DIR).mkdir(parents=True, exist_ok=True)
    for no, raw in entries:
        (root / BUNDLE_FACES_DIR / f"{no}.b64").write_text(
            base64.b64encode(raw).decode("ascii"), encoding="ascii"
        )
    return root


def index_of(*entries: FaceTemplate) -> FacesIndex:
    return FacesIndex(
        state="AVAILABLE",
        reason="",
        entries=entries,
        photo_bytes={"faceURL": "404 on this fw — photo bytes not exportable (recorded)"},
    )


def write_for(no: str, *, b64: str = TPL_B64, **over: Any) -> FaceWrite:
    return FaceWrite.build(no, b64, **over)


def face_journal(tmp_path: Path, name: str = "faces.jsonl") -> WriteJournal:
    return WriteJournal.open(tmp_path / name, phase="faces")


class FaceSeam:
    """The injected faces transport over the real IsapiClient digest stack.

    Records what left the process (the shape/budget tests read those records, never a
    comment), refuses the users verb outright (`put_setup`), and — the §5b.1 pin — has
    NO verb that could address `UserInfoDetail/Delete`. `BudgetedWriteTransport.call`
    is the single counter for all three face verbs (E1-06b's seam precedent, parent
    instruction: reuse, never fork).
    """

    def __init__(self, client: IsapiClient, *, journal: WriteJournal | None = None) -> None:
        self.client = client
        self.journal = journal
        self.searches: list[tuple[str, dict]] = []
        self.setup_writes: list[tuple[str, dict]] = []
        self.deletes: list[tuple[str, dict, dict]] = []
        self.calls = 0
        self.closed = 0
        #: journal states observed AT REQUEST TIME (the §5a journal-before-request pin).
        self.request_time_states: list[str | None] = []
        #: test hooks: verb -> exception (or body->exception|None callable) to raise
        #: instead of sending (fail-fast pins).
        self.fail_on: dict[str, Any] = {}

    # -- the three verbs this phase owns -------------------------------------------------

    def post_face_search(self, path: str, body: Any) -> dict:
        self.calls += 1
        self.searches.append((path, json.loads(json.dumps(body))))
        if "post_face_search" in self.fail_on:
            raise self.fail_on["post_face_search"]
        response = self.client._client.post(
            path, params={"format": "json"}, json=body, auth=self.client._auth
        )
        return self._envelope(response, "FDSearch")

    def put_face_setup(self, path: str, body: Any) -> dict:
        self.calls += 1
        self.setup_writes.append((path, json.loads(json.dumps(body))))
        if self.journal is not None and self.journal.entries:
            self.request_time_states.append(str(self.journal.entries[-1].state))
        hook = self.fail_on.get("put_face_setup")
        if hook is not None:
            # A bare Exception raises; a callable decides per-body (per-person rejects)
            # and returns None to let the request through.
            if isinstance(hook, Exception):
                raise hook
            failure = hook(body)
            if failure is not None:
                raise failure
        response = self.client._client.put(
            path, params={"format": "json"}, json=body, auth=self.client._auth
        )
        return self._envelope(response, "FDSetUp")

    def put_face_delete(self, path: str, params: Any, body: Any) -> dict:
        self.calls += 1
        self.deletes.append((path, dict(params), json.loads(json.dumps(body))))
        if "put_face_delete" in self.fail_on:
            raise self.fail_on["put_face_delete"]
        response = self.client._client.put(
            path, params=dict(params), json=body, auth=self.client._auth
        )
        return self._envelope(response, "FDSearch/Delete")

    # -- refusals and lifecycle ------------------------------------------------------------

    def put_setup(self, path: str, body: Any) -> dict:
        raise AssertionError("the faces phase must never use the users verb")

    def close(self) -> None:
        self.closed += 1

    @staticmethod
    def _envelope(response: httpx.Response, verb: str) -> dict:
        envelope = json.loads(response.content)
        if response.status_code != 200 or envelope.get("statusCode") != 1:
            raise WriteRejectedError(
                f"{verb} answered {response.status_code} {envelope.get('subStatusCode')}",
                sub_status=envelope.get("subStatusCode"),
                http_status=response.status_code,
                envelope=envelope,
            )
        return envelope


def _fpid_rejector(fpid: str, error: Exception):
    """A put_face_setup hook that rejects ONLY the named FPID's body (fail-fast pins)."""

    def hook(body: Any) -> Exception | None:
        return error if str(body.get("FPID")) == fpid else None

    return hook


def probe_ok(**changes: Any) -> CapabilityMatrix:
    """A fresh matrix — the faces apply gate only needs it to be FRESH (§3/§4)."""
    base: dict[str, Any] = {
        "site": "site-a",
        "host": "192.0.2.10",
        "clock_skew_s": 0.5,
        "template_nos": ("1",),
        "caps_raw": {},
        "surfaces": (
            SurfaceProbe(
                key="faces",
                endpoint="fd_search",
                method="POST",
                path=FACE_SEARCH_PATH,
                verdict=Verdict.OK,
            ),
        ),
        "probed_at": NOW.isoformat(),
    }
    base.update(changes)
    return CapabilityMatrix(**base)


# --- the captured bodies (shape is the contract) ---------------------------------------------


def test_the_upload_body_is_byte_equal_to_the_capture() -> None:
    """facesetup_add_request.json is the ONE proven FDSetUp body — four flat keys."""
    write = write_for("90", b64=FACE_CAPTURE_REQUEST["modelData"])
    assert build_face_setup_body(write) == FACE_CAPTURE_REQUEST
    assert set(FACE_CAPTURE_REQUEST) == CAPTURED_FACE_SETUP_KEYS
    assert "mode" not in FACE_CAPTURE_REQUEST  # invented keys are the v3 mistake class


def test_the_delete_body_is_the_captured_single_value_list() -> None:
    assert build_face_delete_body("90") == FACE_DELETE_REQUEST
    assert set(FACE_DELETE_REQUEST) == CAPTURED_FACE_DELETE_KEYS
    # The library identity rides the URL QUERY in the capture, not the body.
    assert {
        "format": "json",
        "FDID": FACE_CAPTURE_REQUEST["FDID"],
        "faceLibType": FACE_CAPTURE_REQUEST["faceLibType"],
    } == FACE_DELETE_PARAMS


@pytest.mark.parametrize("bad", ["", None, 90, b"90"])
def test_a_delete_naming_no_valid_fpid_is_refused_before_it_is_sent(bad: Any) -> None:
    with pytest.raises(FaceShapeError):
        build_face_delete_body(bad)


def test_a_template_that_is_not_clean_base64_is_refused() -> None:
    with pytest.raises(FaceShapeError, match="not clean base64"):
        decode_template("9", "!!! not base64 !!!")
    with pytest.raises(FaceShapeError, match="no usable modelData"):
        decode_template("9", "")
    with pytest.raises(FaceShapeError, match="no usable modelData"):
        decode_template("9", "   ")


def test_a_bundle_that_lies_about_its_own_bytes_is_refused() -> None:
    """The .b64 must still hash to what faces/INDEX.json recorded (§0.7 fail-closed)."""
    with pytest.raises(FaceShapeError, match="the bundle index records"):
        FaceWrite.build("9", TPL_B64, expect_sha256="0" * 64, expect_length=len(TPL_BYTES))
    with pytest.raises(FaceShapeError, match="is 272 B but"):
        FaceWrite.build("9", TPL_B64, expect_sha256=TPL_SHA, expect_length=271)


# --- the plan pass is bundle-only, zero device calls ------------------------------------------


def test_an_index_that_never_ran_ports_nothing() -> None:
    writes, skipped = plan_face_writes(bundle_dir="/nonexistent", faces=FacesIndex())
    assert writes == ()
    assert len(skipped) == 1 and skipped[0][0] == "*"
    assert "unavailable" in skipped[0][1]  # an unread index is never a zero (§0.7)


def test_plan_pass_reads_the_bundle_narrows_by_roster_and_skips_holes(tmp_path: Path) -> None:
    root = bundle_with(tmp_path, ("90", TPL_BYTES), ("91", OTHER_BYTES))
    index = index_of(face_entry("90"), face_entry("91", sha=OTHER_SHA), face_entry("92"))
    writes, skipped = plan_face_writes(bundle_dir=root, faces=index)
    assert [w.intent.employee_no for w in writes] == ["90", "91"]  # sorted send order
    assert writes[0].intent.sha256 == TPL_SHA and writes[0].intent.length == len(TPL_BYTES)
    assert skipped == ((person_hash("92"), "missing_template_file"),)  # never a zero upload
    # The diff plan's roster narrows the walk (bundle-only, no device touched).
    scoped, _ = plan_face_writes(bundle_dir=root, faces=index, employee_nos=["91"])
    assert [w.intent.employee_no for w in scoped] == ["91"]
    assert face_template_path(root, "90").name == "90.b64"
    assert load_face_writes(root, [face_entry("90")])[0][0].intent.employee_hash == person_hash(
        "90"
    )


# --- the fake serves the captures, and nothing else --------------------------------------------


def test_accepted_upload_replays_the_captured_ack_and_the_readback_capture() -> None:
    device = face_device(empty=True)
    response = raw_request(device, "PUT", SETUP_URL, json_body=FACE_CAPTURE_REQUEST)
    assert response.status_code == 200
    assert json.loads(response.content) == FACE_CAPTURE_ACK  # byte-for-byte
    # facesetup_readback_fpid90.json is the capture PAIR: the same FPID reads back with
    # byte-identical modelData. The fake must reproduce that linkage from its stores.
    read = raw_request(
        device,
        "POST",
        SEARCH_URL,
        json_body={
            "faceLibType": "blackFD",
            "FDID": "1",
            "FPID": "90",
            "maxResults": 30,
            "searchResultPosition": 0,
        },
    )
    body = json.loads(read.content)
    assert body["responseStatusStrg"] == "OK" and body["numOfMatches"] == 1
    row = body["MatchList"][0]
    assert row["FPID"] == "90"
    assert row["modelData"] == FACE_CAPTURE_REQUEST["modelData"]  # the capture's identity


def test_the_captured_readback_fixture_itself_agrees_with_the_upload_capture() -> None:
    """Guard the guard: the two fixtures we replay are mutually consistent."""
    assert FACE_CAPTURE_READBACK["MatchList"][0]["modelData"] == FACE_CAPTURE_REQUEST["modelData"]
    assert FACE_CAPTURE_READBACK["MatchList"][0]["FPID"] == FACE_CAPTURE_REQUEST["FPID"]
    assert FACE_DELETE_NOMATCH["responseStatusStrg"] == "NO MATCH"
    assert "MatchList" not in FACE_DELETE_NOMATCH  # the honest zero omits the record key


def test_an_unarmed_face_write_is_a_hard_error_never_a_404() -> None:
    device = FakeDevice(password=PASSWORD)  # write axis NOT armed
    with pytest.raises(EnrollmentProtocolError, match="install_write_capture"):
        raw_request(device, "PUT", SETUP_URL, json_body=FACE_CAPTURE_REQUEST)
    with pytest.raises(EnrollmentProtocolError, match="install_write_capture"):
        raw_request(device, "PUT", DELETE_URL, json_body=FACE_DELETE_REQUEST)


def test_wrong_verb_answers_the_captured_method_not_allowed() -> None:
    """Design §1: a non-PUT on FDSetUp is the methodNotAllowed family, never silence."""
    device = face_device(empty=True)
    response = raw_request(device, "POST", SETUP_URL, json_body=FACE_CAPTURE_REQUEST)
    assert response.status_code == 400
    assert json.loads(response.content)["subStatusCode"] == "methodNotAllowed"


def test_an_unrecorded_key_answers_badjson_naming_it() -> None:
    device = face_device(empty=True)
    body = dict(FACE_CAPTURE_REQUEST)
    body["mode"] = "add"  # invented key: the capture has NO mode
    response = raw_request(device, "PUT", SETUP_URL, json_body=body)
    assert response.status_code == 400
    payload = json.loads(response.content)
    assert payload["subStatusCode"] == "badJsonContent" and payload["errorMsg"] == "mode"


def test_a_missing_required_key_answers_badjson_naming_it() -> None:
    device = face_device(empty=True)
    body = {k: v for k, v in FACE_CAPTURE_REQUEST.items() if k != "FDID"}
    response = raw_request(device, "PUT", SETUP_URL, json_body=body)
    payload = json.loads(response.content)
    assert response.status_code == 400 and payload["errorMsg"] == "FDID"


def test_a_wrapped_face_setup_body_is_a_protocol_error() -> None:
    """§9: no capture exists for a wrapped FDSetUp — the fake refuses to pick a side of
    the per-endpoint dialect split for a verb the bench only ever saw FLAT."""
    device = face_device(empty=True)
    with pytest.raises(EnrollmentProtocolError, match="NO bench-A capture"):
        raw_request(device, "PUT", SETUP_URL, json_body={"FDSetUp": FACE_CAPTURE_REQUEST})


def test_a_multivalue_face_delete_is_refused_not_executed() -> None:
    """The capture holds ONE FPID value; a 2-value list is the R2/D-WIPE class (§5b) —
    the fake must refuse it AND leave the store untouched."""
    device = face_device(faces={"90": TPL_BYTES, "91": OTHER_BYTES})
    two = {"FPID": [{"value": "90"}, {"value": "91"}]}
    with pytest.raises(EnrollmentProtocolError, match="EXACTLY one"):
        raw_request(device, "PUT", DELETE_CAPTURE_URL, json_body=two)
    assert set(device._biometric_store["faces"]) == {"90", "91"}  # nobody was deleted


def test_a_delete_without_the_query_identity_is_refused() -> None:
    """fdsearch_delete_request.json carries the library in the URL, not the body; an
    unqualified delete has no captured answer (§9)."""
    device = face_device(faces={"90": TPL_BYTES})
    with pytest.raises(EnrollmentProtocolError, match="QUERY"):
        raw_request(device, "PUT", FACE_DELETE_PATH, json_body={"FPID": [{"value": "90"}]})


def test_a_delete_naming_an_unknown_slot_is_refused() -> None:
    """The D-WIPE shape for this verb: a list outside the captured slot gets NO answer."""
    device = face_device(faces={"90": TPL_BYTES})
    with pytest.raises(EnrollmentProtocolError, match="NO bench-A capture"):
        raw_request(device, "PUT", DELETE_CAPTURE_URL, json_body={"FPIDD": [{"value": "90"}]})


def test_an_upload_to_the_infrared_library_is_a_hard_refusal() -> None:
    """FDID 2 exists (FDLib capture) but FDSetUp was ONLY ever captured for FDID
    1/blackFD — the fake has no device truth for the other library (§9)."""
    device = face_device(empty=True)
    body = dict(FACE_CAPTURE_REQUEST)
    body["FDID"] = "2"
    body["faceLibType"] = "infraredFD"
    with pytest.raises(EnrollmentProtocolError, match="NO bench-A capture"):
        raw_request(device, "PUT", SETUP_URL, json_body=body)


def test_the_face_delete_leaves_a_targeting_audit() -> None:
    """The card's audit: every served delete records the named FPID and the exact keys
    before/after — proof the captured shape is TARGETED, not trust in the ack."""
    device = face_device(faces={"90": TPL_BYTES, "91": OTHER_BYTES, "92": TPL_BYTES})
    response = raw_request(device, "PUT", DELETE_CAPTURE_URL, json_body=FACE_DELETE_REQUEST)
    assert response.status_code == 200 and json.loads(response.content) == FACE_DELETE_ACK
    audit = device._write_axis["face_delete_audit"]
    assert audit == [{"fpid": "90", "before": ["90", "91", "92"], "after": ["91", "92"]}]
    # exactly one row touched, nobody else's


# --- the phase: journal-before-request, read-back or nothing ------------------------------------


def test_journal_line_is_on_disk_before_the_request_arrives(tmp_path: Path) -> None:
    """§5a order, pinned for THIS phase: at request time the journal already carries
    the planned (and ONLY planned) line for the person being written."""
    device = face_device(empty=True)
    journal = face_journal(tmp_path)
    seam = FaceSeam(client_for(device), journal=journal)
    result = run_faces_phase(
        BudgetedWriteTransport(lambda: seam), journal, [write_for("90")], sleep=lambda _s: None
    )
    assert result.confirmed == (person_hash("90"),)
    assert seam.request_time_states == ["planned"]


def test_a_confirmed_upload_is_planned_applied_confirmed_in_order(tmp_path: Path) -> None:
    device = face_device(empty=True)
    journal = face_journal(tmp_path)
    seam = FaceSeam(client_for(device), journal=journal)
    result = run_faces_phase(
        BudgetedWriteTransport(lambda: seam), journal, [write_for("90")], sleep=lambda _s: None
    )
    lines = [json.loads(line) for line in journal.path.read_text().splitlines()]
    assert [line["state"] for line in lines] == ["planned", "applied", "confirmed"]
    assert lines[-1]["postWriteHash"] == TPL_SHA  # the §6 identity, not the ack
    assert lines[0]["op"] == "face_setup"
    assert result.applied == result.confirmed == (person_hash("90"),)
    assert result.clean and not result.aborted
    # The upload the fake served IS the capture shape for person 90.
    assert seam.setup_writes[0][1] == build_face_setup_body(write_for("90"))


def test_three_authed_calls_per_person_and_one_ledger(tmp_path: Path) -> None:
    """§5.3's faces maths (1 pre-read + 1 upload + 1 read-back) — and the fake's OWN
    authorized counters agree with the budget class, per path."""
    device = face_device(empty=True)
    journal = face_journal(tmp_path)
    seam = FaceSeam(client_for(device), journal=journal)
    transport = BudgetedWriteTransport(lambda: seam)
    result = run_faces_phase(
        transport, journal, [write_for("90"), write_for("91")], sleep=lambda _s: None
    )
    assert result.confirmed and len(result.confirmed) == 2
    assert seam.calls == transport.total_calls == 6  # 2 persons x 3 authed calls
    assert device.authorized_requests_to("POST", SEARCH_URL) == 4
    assert device.authorized_requests_to("PUT", SETUP_URL) == 2
    assert device.authorized_requests_to("PUT", DELETE_CAPTURE_URL) == 0


def test_budget_rebootstraps_at_the_limit_and_closes(tmp_path: Path) -> None:
    """One client per phase, re-bootstrapped at the limit, closed at the end (§5.3)."""
    device = face_device(empty=True)
    journal = face_journal(tmp_path)
    seam = FaceSeam(client_for(device), journal=journal)
    transport = BudgetedWriteTransport(lambda: seam, limit=4)
    run_faces_phase(
        transport, journal, [write_for(no) for no in ("90", "91")], sleep=lambda _s: None
    )
    assert seam.calls == 6 and transport.rebootstraps == 1
    assert seam.closed == 1  # the rotated-away client was closed, not leaked
    transport.close()
    assert seam.closed == 2  # and the phase's final close releases the live one


def test_an_empty_writes_list_touches_the_device_zero_times(tmp_path: Path) -> None:
    device = face_device(empty=True)
    journal = face_journal(tmp_path)
    seam = FaceSeam(client_for(device), journal=journal)
    result = run_faces_phase(BudgetedWriteTransport(lambda: seam), journal, [])
    assert seam.calls == 0 and result.planned == () and result.clean
    assert journal.path.read_text() == ""


# --- the ack is not a confirm (the faces_applies counterfactual) ---------------------------------


def test_accepted_but_landing_nothing_is_terminal_and_stays_applied(tmp_path: Path) -> None:
    """THE pin of the face-verify arm: the device answers the captured `statusCode 1`,
    the FDSearch read-back says the row is simply not there — the ONLY honest terminal
    state is an abort with the journal left at `applied` (unknown state = human, §5a).
    """
    device = face_device(empty=True, faces_applies=False)  # accept, store NOTHING
    journal = face_journal(tmp_path)
    seam = FaceSeam(client_for(device), journal=journal)
    with pytest.raises(FacePhaseAbortedError) as raised:
        run_faces_phase(
            BudgetedWriteTransport(lambda: seam),
            journal,
            [write_for("90")],
            sleep=lambda _s: None,
        )
    result: FacesPhaseResult = raised.value.result
    assert result.applied == (person_hash("90"),)  # the device DID ack
    assert result.confirmed == ()  # and nothing is confirmed
    assert len(result.unconfirmed) == 1 and "read-back" in result.unconfirmed[0][1]
    assert result.aborted and "TERMINAL" in result.abort_reason
    assert "never 'fixed' by a re-write" in result.abort_reason  # §0.6 in the words
    lines = [json.loads(line) for line in journal.path.read_text().splitlines()]
    assert [line["state"] for line in lines] == ["planned", "applied"]  # no confirmed
    # The counterfactual spent exactly the same 3 calls — the budget is per-person.
    assert seam.calls == 3


def test_readback_pair_mismatch_is_never_confirmed(tmp_path: Path) -> None:
    """§6 confirms on the PAIR (sha256 AND length). An intent whose length lies can
    never reach `confirmed`: the phase's pre-read already refuses to skip or confirm
    on a hash alone — the differing length makes it a CONFLICT, and no write is sent."""
    device = face_device(faces={"90": TPL_BYTES})  # live row hashes to TPL_SHA
    lying = FaceIntent(
        employee_no="90",
        employee_hash=person_hash("90"),
        fdid="1",
        face_lib_type="blackFD",
        sha256=TPL_SHA,
        length=len(TPL_BYTES) + 1,
    )
    journal = face_journal(tmp_path)
    seam = FaceSeam(client_for(device), journal=journal)
    result = run_faces_phase(
        BudgetedWriteTransport(lambda: seam),
        journal,
        [FaceWrite(intent=lying, model_data=TPL_B64)],
        sleep=lambda _s: None,
    )
    assert result.confirmed == () and seam.setup_writes == []
    assert len(result.conflicts) == 1 and "existing_template_differs" in result.conflicts[0][1]
    # And the verify arm says the same thing about the same lying intent (§6 pair rule).
    report = verify_faces(BudgetedFaceReader(BudgetedWriteTransport(lambda: seam)), [lying])
    assert report.verdict_of("90") is FaceVerdict.MISMATCH


def test_readback_hash_match_with_lying_length_never_confirms(tmp_path: Path) -> None:
    """The read-back arm of the pair rule: the pre-read is ABSENT (so a write IS sent),
    the upload lands the REAL bytes, and the read-back row hashes equal but its length
    disagrees with the intent — `confirmed` requires the PAIR, so this is TERMINAL and
    the journal stays at `applied` (a hash alone is never a confirmation, §6)."""
    device = face_device(empty=True)  # pre-read ABSENT -> the phase writes
    lying = FaceIntent(
        employee_no="90",
        employee_hash=person_hash("90"),
        fdid="1",
        face_lib_type="blackFD",
        sha256=TPL_SHA,
        length=len(TPL_BYTES) + 1,
    )
    journal = face_journal(tmp_path)
    seam = FaceSeam(client_for(device), journal=journal)
    with pytest.raises(FacePhaseAbortedError) as raised:
        run_faces_phase(
            BudgetedWriteTransport(lambda: seam),
            journal,
            [FaceWrite(intent=lying, model_data=TPL_B64)],
            sleep=lambda _s: None,
        )
    result = raised.value.result
    assert result.applied == (person_hash("90"),) and result.confirmed == ()
    assert "hash/length" in result.abort_reason  # the mismatch names itself
    lines = [json.loads(line)["state"] for line in journal.path.read_text().splitlines()]
    assert lines == ["planned", "applied"]  # never confirmed (§5a: unknown = human)


class _TamperedAckSeam(FaceSeam):
    """Answers the upload with a non-OK envelope the fake never produces."""

    def put_face_setup(self, path: str, body: Any) -> dict:
        self.calls += 1
        self.setup_writes.append((path, dict(body)))
        return {"statusCode": 2, "statusString": "Device Error", "subStatusCode": "deviceError"}


def test_a_non_ok_ack_is_a_rejection_never_an_accept(tmp_path: Path) -> None:
    """`_require_ok_ack`: statusCode != 1 inside the transport's happy path is the SAME
    event as a raising transport — journal `rejected`, classify, abort. An optimistic
    client that trusted HTTP 200 would land a write the device refused."""
    device = face_device(empty=True)
    journal = face_journal(tmp_path)
    with pytest.raises(FacePhaseAbortedError) as raised:
        run_faces_phase(
            BudgetedWriteTransport(lambda: _TamperedAckSeam(client_for(device), journal=journal)),
            journal,
            [write_for("90")],
            sleep=lambda _s: None,
        )
    result = raised.value.result
    assert result.applied == () and result.confirmed == ()
    assert result.rejected[0][1] is RejectKind.OTHER and result.rejected[0][2] == "deviceError"
    lines = [json.loads(line)["state"] for line in journal.path.read_text().splitlines()]
    assert lines == ["planned", "rejected"]


class _NoopDeleteSeam(FaceSeam):
    """Answers the delete with the captured ack but removes NOTHING (ack != applied, §6)."""

    def put_face_delete(self, path: str, params: Any, body: Any) -> dict:
        self.calls += 1
        self.deletes.append((path, dict(params), dict(body)))
        return dict(FACE_DELETE_ACK)  # statusCode 1, store untouched


def test_a_delete_that_acks_but_removes_nothing_is_refused_not_confirmed(tmp_path: Path) -> None:
    """The read-back-after-delete arm of undo: an `ok` ack whose FPID still reads PRESENT
    must land `deleteNotApplied` in the undo journal and a refusal in the report —
    never a confirmed removal (the same ack-is-not-confirm rule, pointed at deletes)."""
    device, journal, _seam = _confirmed_pair(tmp_path)
    transport = BudgetedWriteTransport(lambda: _NoopDeleteSeam(client_for(device), journal=journal))
    undo = WriteJournal.open(tmp_path / "u.jsonl", phase="faces-undo")
    report = undo_faces(transport, journal, undo, employee_nos=["90"], sleep=lambda _s: None)
    transport.close()
    assert report.removed == () and len(report.refused) == 1
    assert "still present after delete" in report.refused[0][1]
    lines = [json.loads(line) for line in undo.path.read_text().splitlines()]
    assert [line["state"] for line in lines] == ["planned", "applied", "rejected"]
    assert lines[-1]["deviceSubStatus"] == "deleteNotApplied"
    assert device._biometric_store["faces"]["90"] == TPL_BYTES  # nothing was removed


# --- idempotency and conflict (the no-silent-overwrite rule) -------------------------------------


def test_already_present_writes_nothing_and_journals_nothing(tmp_path: Path) -> None:
    """Decision 1: face undo is REAL, so an already-present face must NOT become
    undo-able evidence of a write that never happened. Skip, report, no journal line."""
    device = face_device(faces={"90": TPL_BYTES})
    journal = face_journal(tmp_path)
    seam = FaceSeam(client_for(device), journal=journal)
    result = run_faces_phase(
        BudgetedWriteTransport(lambda: seam), journal, [write_for("90")], sleep=lambda _s: None
    )
    assert result.already_present == (person_hash("90"),)
    assert seam.setup_writes == [] and journal.path.read_text() == ""
    assert seam.calls == 1  # just the pre-read


def test_a_different_target_template_is_a_conflict_never_overwritten(tmp_path: Path) -> None:
    """Re-enrolling over someone else's face is a human decision (§5 step 6): report and
    skip; the target's bytes stay exactly what the bench had."""
    device = face_device(faces={"90": OTHER_BYTES})
    journal = face_journal(tmp_path)
    seam = FaceSeam(client_for(device), journal=journal)
    result = run_faces_phase(
        BudgetedWriteTransport(lambda: seam), journal, [write_for("90")], sleep=lambda _s: None
    )
    assert len(result.conflicts) == 1
    assert result.conflicts[0][0] == person_hash("90")
    assert "existing_template_differs" in result.conflicts[0][1]
    assert seam.setup_writes == [] and journal.path.read_text() == ""
    assert device._biometric_store["faces"]["90"] == OTHER_BYTES


def test_a_row_without_model_data_is_an_unknown_conflict() -> None:
    """The §6 'UNKNOWN field': a row that carries no modelData is never an OK and
    never a license to upload over it."""
    rowless = {
        "responseStatusStrg": "OK",
        "numOfMatches": 1,
        "totalMatches": 1,
        "MatchList": [{"FPID": "90", "faceURL": "http://192.0.2.1/x.jpg"}],
    }
    row = read_face_row(ReaderCaller(lambda _body: dict(rowless)), "90")
    assert row.state is RowState.UNKNOWN


def test_a_filtered_row_for_the_wrong_fpid_is_an_error_never_a_zero() -> None:
    """§0.7: an ignored filter would make every verdict a lie, so a mismatched FPID is
    an ERROR — which the phase turns into an abort before any write."""
    wrong = {
        "responseStatusStrg": "OK",
        "numOfMatches": 1,
        "totalMatches": 1,
        "MatchList": [{"FPID": "91", "modelData": TPL_B64}],
    }
    row = read_face_row(ReaderCaller(lambda _body: dict(wrong)), "90")
    assert row.state is RowState.ERROR and "FPID" in row.note


def test_a_root_without_count_fields_is_a_protocol_break_not_a_zero() -> None:
    row = read_face_row(ReaderCaller(lambda _body: {"statusString": "OK"}), "90")
    assert row.state is RowState.ERROR and "count fields" in row.note


def test_an_unreadable_pre_read_aborts_before_any_write(tmp_path: Path) -> None:
    device = face_device(empty=True)
    journal = face_journal(tmp_path)
    seam = FaceSeam(client_for(device), journal=journal)
    seam.fail_on["post_face_search"] = WriteRejectedError(
        "FDSearch answered 400 deviceError", sub_status="deviceError"
    )
    with pytest.raises(FacePhaseAbortedError) as raised:
        run_faces_phase(
            BudgetedWriteTransport(lambda: seam),
            journal,
            [write_for("90")],
            sleep=lambda _s: None,
        )
    assert "pre-read failed" in raised.value.result.abort_reason
    assert seam.setup_writes == [] and journal.path.read_text() == ""  # §0.7: never absent


# --- fail-fast (capacity rejects are fail-fast, §5 step 4; nothing retried, §0.6) -------------


def test_the_first_rejection_ends_the_phase_and_names_who_landed(tmp_path: Path) -> None:
    device = face_device(empty=True)
    journal = face_journal(tmp_path)
    seam = FaceSeam(client_for(device), journal=journal)
    # Reject ONLY person 91's upload (fail-fast fires at the SECOND person, so the
    # carried result can prove who landed BEFORE the refusal).
    seam.fail_on["put_face_setup"] = _fpid_rejector(
        "91", WriteRejectedError("device answered 400 businessError", sub_status="businessError")
    )
    with pytest.raises(FacePhaseAbortedError) as raised:
        run_faces_phase(
            BudgetedWriteTransport(lambda: seam),
            journal,
            [write_for("90"), write_for("91"), write_for("92")],
            sleep=lambda _s: None,
        )
    result = raised.value.result
    assert result.applied == (person_hash("90"),)  # who landed, in the carried result
    assert len(result.rejected) == 1
    hashed, kind, sub = result.rejected[0]
    assert hashed == person_hash("91") and kind is RejectKind.OTHER and sub == "businessError"
    assert result.aborted
    lines = [json.loads(line) for line in journal.path.read_text().splitlines()]
    assert [line["state"] for line in lines] == [
        "planned",
        "applied",
        "confirmed",  # person 90 finished
        "planned",
        "rejected",  # person 91 stopped HERE
    ]
    assert lines[-1]["deviceSubStatus"] == "businessError"
    # Person 92 was never touched: fail-fast means fail-FAST, not best-effort.
    # (5 ledger calls: 3 for person 90, 91's pre-read, and 91's rejected upload — the
    # budget counts what was ISSUED, and the fake never saw that 5th request.)
    assert len(seam.setup_writes) == 2 and seam.calls == 5
    assert device.authorized_requests_to("PUT", SETUP_URL) == 1  # only person 90's landed


def test_a_synthetic_capacity_rejection_is_other_verbatim_and_aborts(tmp_path: Path) -> None:
    """The `faces_capacity` knob (INVENTED stand-in — no face capacity rejection was ever
    captured; §1 records true capacity as unexposed) answers a CLEARLY-LABELED synthetic
    subcode. This test pins the HONEST handling of that vocabulary: it classifies OTHER —
    never coerced into shape/user-absent/capacity-full — rides the journal line verbatim,
    and aborts the phase fail-fast (§5 step 4), exactly like the mapped vocabulary does."""
    device = face_device(empty=True, faces_capacity=1)
    journal = face_journal(tmp_path)
    seam = FaceSeam(client_for(device), journal=journal)
    with pytest.raises(FacePhaseAbortedError) as raised:
        run_faces_phase(
            BudgetedWriteTransport(lambda: seam),
            journal,
            [write_for("90"), write_for("91")],
            sleep=lambda _s: None,
        )
    result = raised.value.result
    hashed, kind, sub = result.rejected[0]
    assert hashed == person_hash("91")
    assert kind is RejectKind.OTHER  # unmapped vocabulary is reported, never guessed
    assert sub == "syntheticFaceCapacityFull"  # verbatim, exactly what the box said
    assert result.applied == (person_hash("90"),) and result.aborted
    lines = [json.loads(line) for line in journal.path.read_text().splitlines()]
    assert lines[-1]["state"] == "rejected"
    assert lines[-1]["deviceSubStatus"] == "syntheticFaceCapacityFull"
    # Both uploads REACHED the box (this rejection is a device ANSWER, not a refusal to
    # serve) — person 91 got the synthetic "full" answer at the device itself.
    assert device.authorized_requests_to("PUT", SETUP_URL) == 2
    assert len(device._write_axis["face_store"]) == 1  # ...and only person 90's face stored


def test_a_shape_rejection_classifies_as_shape_not_other(tmp_path: Path) -> None:
    device = face_device(empty=True)
    journal = face_journal(tmp_path)
    seam = FaceSeam(client_for(device), journal=journal)
    seam.fail_on["put_face_setup"] = WriteRejectedError(
        "device answered 400 badJsonContent", sub_status="badJsonContent"
    )
    with pytest.raises(FacePhaseAbortedError) as raised:
        run_faces_phase(
            BudgetedWriteTransport(lambda: seam),
            journal,
            [write_for("90")],
            sleep=lambda _s: None,
        )
    assert raised.value.result.rejected[0][1] is RejectKind.SHAPE


# --- §6 verify (the arm the users verify cannot cover) ----------------------------------------


def test_verify_ok_requires_sha_and_length_and_reads_no_bytes(tmp_path: Path) -> None:
    device = face_device(faces={"90": TPL_BYTES})
    seam = FaceSeam(client_for(device))
    intent = FaceIntent(
        employee_no="90",
        employee_hash=person_hash("90"),
        fdid="1",
        face_lib_type="blackFD",
        sha256=TPL_SHA,
        length=len(TPL_BYTES),
    )
    report = verify_faces(BudgetedFaceReader(BudgetedWriteTransport(lambda: seam)), [intent])
    assert report.ok and report.verdict_of("90") is FaceVerdict.OK
    assert report.calls_sent == 1
    assert not hasattr(report.items[0], "modelData")  # hashes and lengths only, §4


def test_verify_a_missing_face_is_terminal_not_a_shrug(tmp_path: Path) -> None:
    device = face_device(empty=True)  # device says NO MATCH for everyone
    seam = FaceSeam(client_for(device))
    intent = FaceIntent(
        employee_no="90",
        employee_hash=person_hash("90"),
        fdid="1",
        face_lib_type="blackFD",
        sha256=TPL_SHA,
        length=len(TPL_BYTES),
    )
    report = verify_faces(BudgetedFaceReader(BudgetedWriteTransport(lambda: seam)), [intent])
    assert not report.ok
    assert report.verdict_of("90") is FaceVerdict.MISSING
    assert report.terminal and "terminal" in report.items[0].note  # §0.6 words


def test_verify_a_failed_read_is_mismatch_never_missing(tmp_path: Path) -> None:
    """§0.7: a read that failed is not evidence of absence."""
    seam = FaceSeam(client_for(face_device(empty=True)))
    seam.fail_on["post_face_search"] = WriteRejectedError("boom", sub_status="deviceError")
    intent = FaceIntent(
        employee_no="90",
        employee_hash=person_hash("90"),
        fdid="1",
        face_lib_type="blackFD",
        sha256=TPL_SHA,
        length=len(TPL_BYTES),
    )
    report = verify_faces(BudgetedFaceReader(BudgetedWriteTransport(lambda: seam)), [intent])
    assert report.verdict_of("90") is FaceVerdict.MISMATCH
    assert "failed read" in report.items[0].note


def test_verify_journal_faces_rebuilds_the_intent_after_a_phase(tmp_path: Path) -> None:
    """The audit path: a run that already finished, verified from its journal alone."""
    device = face_device(empty=True)
    journal = face_journal(tmp_path)
    seam = FaceSeam(client_for(device), journal=journal)
    run_faces_phase(
        BudgetedWriteTransport(lambda: seam), journal, [write_for("90")], sleep=lambda _s: None
    )
    reader = BudgetedFaceReader(BudgetedWriteTransport(lambda: seam))
    report = verify_journal_faces(reader, journal)
    assert report.ok and report.verdict_of("90") is FaceVerdict.OK
    # And the honest negative: someone swapped the template after our run.
    device._biometric_store["faces"]["90"] = OTHER_BYTES
    assert verify_journal_faces(reader, journal).verdict_of("90") is FaceVerdict.MISMATCH


# --- §5a undo: proof-of-add, targeted delete, count-delta guard ------------------------------


def _confirmed_pair(tmp_path: Path) -> tuple[FakeDevice, WriteJournal, FaceSeam]:
    device = face_device(empty=True)
    journal = face_journal(tmp_path)
    seam = FaceSeam(client_for(device), journal=journal)
    run_faces_phase(
        BudgetedWriteTransport(lambda: seam),
        journal,
        [write_for("90"), write_for("91")],
        sleep=lambda _s: None,
    )
    return device, journal, seam


def test_undo_removes_the_confirmed_add_it_can_prove(tmp_path: Path) -> None:
    device, journal, seam = _confirmed_pair(tmp_path)
    undo = WriteJournal.open(tmp_path / "undo.jsonl", phase="faces-undo")
    reader_transport = BudgetedWriteTransport(lambda: seam)
    report = undo_faces(reader_transport, journal, undo, employee_nos=["90"], sleep=lambda _s: None)
    reader_transport.close()
    assert isinstance(report, FacesUndoReport) and report.clean
    assert report.removed == (person_hash("90"),)
    # The OTHER face survives — targeted, exactly as fdsearch_delete_verified_nomatch
    # proved on the bench ("other people's faces untouched").
    assert set(device._biometric_store["faces"]) == {"91"}
    lines = [json.loads(line) for line in undo.path.read_text().splitlines()]
    assert [line["state"] for line in lines] == ["planned", "applied", "confirmed"]
    assert lines[-1]["postWriteHash"] == ABSENT_SHA  # 'confirmed gone' in hash vocabulary
    assert lines[0]["op"] == "face_delete"
    # The SOURCE journal is untouched — no reverted transition exists yet (decision 2;
    # that journal member is E1-05's addition, this module must not pre-empt it).
    source_states = [json.loads(line)["state"] for line in journal.path.read_text().splitlines()]
    assert source_states[-1] == "confirmed"
    # The delete carried the captured query identity AND the captured body.
    path, params, body = seam.deletes[0]
    assert path == FACE_DELETE_PATH and params == dict(FACE_DELETE_PARAMS)
    assert body == {"FPID": [{"value": "90"}]}


def test_undo_refuses_what_this_run_did_not_confirm(tmp_path: Path) -> None:
    device, _, _ = _confirmed_pair(tmp_path)
    journal = WriteJournal.open(tmp_path / "half.jsonl", phase="faces")
    entry = journal.planned(
        employee_no="90",
        classification="add",
        pre_write_record=None,
        intended_record=FaceIntent(
            employee_no="90",
            employee_hash=person_hash("90"),
            fdid="1",
            face_lib_type="blackFD",
            sha256=TPL_SHA,
            length=len(TPL_BYTES),
        ).metadata(),
        op="face_setup",
    )
    journal.applied(entry)  # the device acked; nobody ever confirmed it
    seam = FaceSeam(client_for(device), journal=journal)
    transport = BudgetedWriteTransport(lambda: seam)
    report = undo_faces(
        transport,
        journal,
        WriteJournal.open(tmp_path / "u.jsonl", phase="faces-undo"),
        employee_nos=["90"],
        sleep=lambda _s: None,
    )
    transport.close()
    assert report.removed == () and len(report.refused) == 1
    assert "not confirmed" in report.refused[0][1]
    assert seam.deletes == []  # unknown state = human, never a delete (§5a)


def test_undo_refuses_a_drifted_row_someone_else_touched(tmp_path: Path) -> None:
    """Proof-of-add means the LIVE hash must still equal the journal's — a record
    modified by anyone else since is NOT touched (§5a: someone else's edit wins)."""
    device, journal, seam = _confirmed_pair(tmp_path)
    device._biometric_store["faces"]["90"] = OTHER_BYTES  # a human re-enrolled them
    transport = BudgetedWriteTransport(lambda: seam)
    report = undo_faces(
        transport,
        journal,
        WriteJournal.open(tmp_path / "u.jsonl", phase="faces-undo"),
        employee_nos=["90"],
        sleep=lambda _s: None,
    )
    transport.close()
    assert report.removed == () and len(report.refused) == 1
    assert "proof-of-add FAILED" in report.refused[0][1]
    assert seam.deletes == [] and device._biometric_store["faces"]["90"] == OTHER_BYTES


def test_undo_is_idempotent_on_a_second_run(tmp_path: Path) -> None:
    device, journal, seam = _confirmed_pair(tmp_path)
    first = undo_faces(
        BudgetedWriteTransport(lambda: seam),
        journal,
        WriteJournal.open(tmp_path / "u1.jsonl", phase="faces-undo"),
        employee_nos=["90"],
        sleep=lambda _s: None,
    )
    assert first.removed == (person_hash("90"),)
    assert set(device._biometric_store["faces"]) == {"91"}  # only the named one left
    deletes_after_first = len(seam.deletes)
    second = undo_faces(
        BudgetedWriteTransport(lambda: seam),
        journal,
        WriteJournal.open(tmp_path / "u2.jsonl", phase="faces-undo"),
        employee_nos=["90"],
        sleep=lambda _s: None,
    )
    assert second.removed == () and second.already_absent == (person_hash("90"),)
    assert len(seam.deletes) == deletes_after_first  # ZERO deletes on the re-run


def test_the_count_delta_guard_turns_an_over_delete_into_an_incident(tmp_path: Path) -> None:
    """§5b: we named ONE person; if the library dropped by MORE, the run STOPS. The
    fake would never do this (it refuses uncaptured shapes) — so the seam acts out the
    device misbehaving, and the guard's arithmetic must catch it anyway."""
    device, journal, seam = _confirmed_pair(tmp_path)

    class WildDeleteSeam(FaceSeam):
        def put_face_delete(self, path: str, params: Any, body: Any) -> dict:
            del params, body  # the rogue device deletes EVERYTHING and says ok
            self.calls += 1
            self.deletes.append((path, {}, {}))
            device._biometric_store["faces"].clear()
            return dict(FACE_DELETE_ACK)

    transport = BudgetedWriteTransport(lambda: WildDeleteSeam(client_for(device), journal=journal))
    with pytest.raises(FaceUndoIncidentError) as raised:
        undo_faces(
            transport,
            journal,
            WriteJournal.open(tmp_path / "u.jsonl", phase="faces-undo"),
            employee_nos=["90"],
            sleep=lambda _s: None,
        )
    report = raised.value.report
    assert "COUNT-DELTA GUARD" in str(raised.value)
    assert report.incidents and report.incidents[0][0] == person_hash("90")
    assert report.deltas == ((person_hash("90"), 2, 0),)  # the guard's evidence
    # Stop means STOP: the remaining confirmed person was never touched by a delete.
    assert len(report.removed) == 0 and len(seam.deletes) == 0
    assert journal_fingerprint(journal)  # source journal readable and untouched by undo


def test_undo_walks_the_paging_quirk_before_counting(tmp_path: Path) -> None:
    """Bench A answered 3 of 4 rows on ONE OK page (§1). A guard that trusted
    totalMatches-or-one-page would under-count the library and mis-read the delta —
    the count must come from ROWS the E1-01b engine actually walked."""
    device = face_device(faces={str(n): TPL_BYTES for n in range(1, 5)})
    seam = FaceSeam(client_for(device))
    transport = BudgetedWriteTransport(lambda: seam)
    assert count_face_rows(BudgetedFaceReader(transport)) == 4
    transport.close()


def test_no_user_delete_request_ever_leaves_either_side(tmp_path: Path) -> None:
    """§5b.1 pin: the faces phase AND its undo touch only the face family. The seam has
    no verb for UserInfoDetail/Delete, the module never calls the users verb, and the
    fake's own counters prove nothing was sent there across a full apply+undo."""
    device, journal, seam = _confirmed_pair(tmp_path)
    transport = BudgetedWriteTransport(lambda: seam)
    undo = undo_faces(
        transport,
        journal,
        WriteJournal.open(tmp_path / "u.jsonl", phase="faces-undo"),
        sleep=lambda _s: None,
    )
    transport.close()
    assert undo.clean and undo.removed  # real removals happened...
    for path, count in device.authorized_by_path.items():
        assert "UserInfoDetail" not in path and "UserInfo" not in path, path
        assert count >= 0
    with pytest.raises(AssertionError, match="users verb"):
        seam.put_setup("/ISAPI/AccessControl/UserInfo/SetUp", {})


# --- the composed apply (probe gate, budget closure, report) ---------------------------------


def test_apply_refuses_a_stale_probe_before_touching_the_journal(tmp_path: Path) -> None:
    device = face_device(empty=True)
    seam = FaceSeam(client_for(device))
    journal_path = tmp_path / "faces.jsonl"
    stale = probe_ok(probed_at=(NOW - timedelta(days=7, seconds=1)).isoformat())
    with pytest.raises(ProbeStaleError):
        apply_faces_phase(
            transport_factory=lambda: seam,
            journal_path=journal_path,
            writes=[write_for("90")],
            probe=stale,
            now=NOW,
            sleep=lambda _s: None,
        )
    assert not journal_path.exists() and seam.calls == 0  # §3: probe first, always


def test_apply_closes_the_budget_even_on_a_terminal_abort(tmp_path: Path) -> None:
    device = face_device(empty=True, faces_applies=False)  # terminal read-back mismatch
    seam = FaceSeam(client_for(device))
    with pytest.raises(FacePhaseAbortedError):
        apply_faces_phase(
            transport_factory=lambda: seam,
            journal_path=tmp_path / "f.jsonl",
            writes=[write_for("90")],
            probe=probe_ok(),
            now=NOW,
            sleep=lambda _s: None,
        )
    assert seam.closed >= 1  # §5.3: the phase owns its client; nothing writes on a closed one


def test_apply_confirm_true_walks_the_independent_verify(tmp_path: Path) -> None:
    device = face_device(empty=True)
    seam = FaceSeam(client_for(device))
    result, journal, verify = apply_faces_phase(
        transport_factory=lambda: seam,
        journal_path=tmp_path / "f.jsonl",
        writes=[write_for("90")],
        probe=probe_ok(),
        now=NOW,
        sleep=lambda _s: None,
        confirm=True,
    )
    assert result.confirmed == (person_hash("90"),)
    assert verify is not None and verify.ok and verify.calls_sent == 1
    # 3 phase calls + 1 independent verify call, all on one ledger.
    assert seam.calls == 4
    report = faces_report(result, journal, verify=verify)
    assert report["phase"] == "faces" and report["verify"]["counts"]["ok"] == 1
    # §4 PII: the report carries hashes and counts — never employee numbers or bytes.
    # The journal PATH is a filesystem location the CALLER chose (here, a pytest tmp dir
    # whose counter can happen to spell "90"), not device data, so it is out of scope for
    # the sweep; everything the phase itself produced is still swept.
    flat = json.dumps({k: v for k, v in report.items() if k != "journal"})
    assert (
        "90" not in flat
        and TPL_B64 not in flat
        and TPL_SHA not in flat.replace(result.confirmed[0], "")
    )  # the hash appears only AS the person hash, never as a template field
    assert report["writes"]["confirmed"] == 1
