"""Card E1-11: the faces phase must know the DEVICE WALL we captured on site-B.

Why this file exists (the sanctioned capture, 2026-10-23, docs/internal/OBSERVED-site-B.md
"Face WRITE capture"): applying our exported face templates to site-B (V4.13.0)
answered HTTP 400 with::

    {"statusCode": 6, "statusString": "Invalid Content", "subStatusCode":
     "badJsonContent", "errorCode": 1610612759, "errorMsg": "faceURL"}

and the discriminating controls proved the cause is the TEMPLATE, not our body:
B's OWN FR702706 template, through our own flat four-key FDSetUp shape, at a NEW
FPID, answers ``ok`` (capture E1). A's FR500005 template, same shape, is refused
(capture E2). So the old reading — bare ``badJsonContent`` means OUR shape bug
(:class:`RejectKind.SHAPE`) — is WRONG for this envelope pair, and an operator
hunting the body builder for it wastes the lockout budget retrying a wall.

This file uses the E1-10 harness (real ``IsapiClient`` over ``httpx.MockTransport``,
bare AND ``LoggedClient``; no FakeDevice) because the live failure class this card
addresses was invisible to duck-typed seams. The envelopes replayed here are the
COMMITTED sanitized captures under
``tests/fixtures/recorded/site-b-ds-k1t344mbfwx-e1/enrollment/`` — the reject is
byte-equal to what the device actually answered (modulo the SYNTH placeholder
template), so the classifier is tested against the device's words, not a summary
of them (§6).

Acceptance this file owns (card E1-11):

1. the E2 envelope -> journal entry ``rejected`` WITH ``rejectClass``
   ``template_rejected``, abort, ZERO retry, message names the wall + "re-enroll"
   (and mutation probe (c): if the class flipped abort->continue, the tests below
   that assert the abort would go red);
2. mutation probe (a): bare ``badJsonContent`` WITHOUT ``errorMsg: faceURL`` stays
   the old ``shape_rejected`` class verbatim — the classifier matching ANY
   badJsonContent would make the pinned journal class here go red;
3. mutation probe (d): a journal read that drops ``rejectClass`` fails the
   round-trip pins (the class is asserted on disk after reopen, not in memory);
4. old journals (no class key) still read, class ``None`` — E1-04's read-back
   contract preserved by an ADDITIVE key;
5. the accept path (E1 shape, native magic) lands, read-back-confirms, and the
   journal carries NO class key at all for a non-rejection;
6. the report-only pre-apply warning (diff): source-vs-target magic note on the
   table AND ``-o json``, and mutation probe (b): with an EMPTY target the note
   must be silence — a helper that invented a warning from nothing goes red;
7. ``template_magic`` reads at most 8 bytes and never invents a family (§0.7).
"""

from __future__ import annotations

import base64
import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import httpx
import pytest

from gateclerk.isapi_transport import IsapiClient
from gateclerk.migrate_apply import ApplySeams, FaceWriteTransport
from gateclerk.migrate_bundle import BundleData
from gateclerk.migrate_diff import (
    DiffPolicy,
    Plan,
    TargetBiometrics,
    classify,
    employee_hash,
    face_portability_notes,
    render_report,
    template_magic,
)
from gateclerk.migrate_export import EnrollmentState
from gateclerk.migrate_faces import (
    FACE_PORTABILITY_NOTE_PREFIX,
    FACE_SEARCH_PATH,
    FACE_SETUP_PATH,
    FacePhaseAbortedError,
    FaceWrite,
    WriteJournal,
    apply_faces_phase,
    is_template_portability_rejection,
    reject_kind_for,
)
from gateclerk.migrate_probe import CapabilityMatrix, SurfaceProbe, Verdict
from gateclerk.migrate_write import (
    RejectKind,
    WriteRejectedError,
)
from gateclerk.pipeline import LoggedClient, RequestLogger
from test_e1_02_diff_engine import user

PASSWORD = "fake" + "pw"  # placeholder policy (tests/test_repo_hygiene.py)
BASE_URL = "http://192.0.2.10"  # TEST-NET (tests/test_repo_hygiene.py allowlist)

RECORDED = Path(__file__).parent / "fixtures/recorded/site-b-ds-k1t344mbfwx-e1"
ENROLLMENT = RECORDED / "enrollment"

#: The captured accept ack (P1/E1) and the captured E2 rejection envelope — replayed
#: verbatim from disk so a future edit to this file cannot quietly soften them.
OK_ACK = json.loads((ENROLLMENT / "facesetup_native_accept_response.json").read_text())
E2_REJECT = json.loads((ENROLLMENT / "facesetup_crossgen_reject_400.json").read_text())
E2_REQUEST = json.loads((ENROLLMENT / "facesetup_crossgen_request.json").read_text())
NATIVE_REQUEST = json.loads((ENROLLMENT / "facesetup_native_accept_request.json").read_text())
DELETE_ACK = json.loads((ENROLLMENT / "fdsearch_delete_response.json").read_text())

#: The two SYNTH placeholder templates from the fixtures, one per firmware family.
#: ``modelData`` b64 -> bytes, because FaceWrite.build wants the device's base64
#: string and the magic reader wants bytes; both spellings stay in sync by decoding.
NATIVE_B64: str = NATIVE_REQUEST["modelData"]  # FR702706 head (site-B's own family)
FOREIGN_B64: str = E2_REQUEST["modelData"]  # FR500005 head (site-A's family)
FOREIGN_SHA = hashlib.sha256(base64.b64decode(FOREIGN_B64)).hexdigest()
NATIVE_SHA = hashlib.sha256(base64.b64decode(NATIVE_B64)).hexdigest()

#: A rejection shape the captures DO show and it is NOT the wall: bare badJsonContent
#: (a wrong key / wrapped body — our bug, SHAPE). Fixture-grounded: site-A's
#: fpdownload_badjson_scalar_enable_400.json carries no errorMsg of faceURL.
BARE_BADJSON = {
    "statusCode": 6,
    "statusString": "Invalid Content",
    "subStatusCode": "badJsonContent",
    "errorCode": 1610612759,
}

NOW = datetime(2026, 10, 24, 12, 0, 0, tzinfo=UTC)


# --- the site-B mock box ---------------------------------------------------------------------


class SiteBBox:
    """V4.13.0's answered truth: accepts the NATIVE magic, rejects the FOREIGN one.

    The reject route replays the committed E2 envelope byte-for-byte; the accept route
    stores the modelData so the FDSearch read-back echoes it (§6: the read-back, not
    the ack, is what confirms). Foreign-magic uploads are refused with the captured
    pair whether it is the first attempt or the fifth — one attempt, one answer, and
    this box counts so "no retry" is read from the device's side of the wire (§0.6).
    """

    def __init__(self) -> None:
        self.authed = 0
        self.hops: list[tuple[str, str]] = []
        self.faces: dict[str, str] = {}  # FPID -> modelData the box is holding
        self.setup_attempts: list[str] = []  # modelData per FDSetUp attempt, in order

    @property
    def transport(self) -> httpx.MockTransport:
        return httpx.MockTransport(self._handle)

    def _handle(self, request: httpx.Request) -> httpx.Response:
        if "authorization" not in request.headers:
            return httpx.Response(
                401,
                headers={
                    "Server": "webs",
                    "WWW-Authenticate": (
                        'Digest qop="auth", realm="DS-TESTREALM", '
                        'nonce="MASKED-NONCE", stale="false", opaque="MASKED"'
                    ),
                },
                content=b"",
            )
        self.authed += 1
        method = request.method.upper()
        path = request.url.path
        self.hops.append((method, path))
        body = json.loads(request.content) if request.content else None
        if request.url.params.get("format") != "json":
            return self._reject(path, "this family is asked with ?format=json")
        if method == "POST" and path == FACE_SEARCH_PATH:
            return self._face_search(body)
        if method == "PUT" and path == FACE_SETUP_PATH:
            return self._face_setup(body)
        if method == "PUT" and path.startswith(FACE_SEARCH_PATH):  # FDSearch/Delete
            fpids = [str(item["value"]) for item in body["FPID"]]
            for fpid in fpids:
                self.faces.pop(fpid, None)
            return httpx.Response(200, json=DELETE_ACK)
        return self._reject(path, "route not armed by this card")

    def _face_setup(self, body: Any) -> httpx.Response:
        assert set(body) == {"faceLibType", "FDID", "FPID", "modelData"}, (
            "FDSetUp may only carry the captured four keys — this card changed NOTHING "
            "about the body builder (the capture proves it correct on V4.13.0)"
        )
        model_data = body["modelData"]
        self.setup_attempts.append(model_data)
        if template_magic(base64.b64decode(model_data)) == "FR500005":
            # The wall: byte-for-byte the captured E2 envelope, EVERY attempt (a fw
            # does not change its mind, and the box must not either).
            return httpx.Response(400, json=E2_REJECT)
        self.faces[str(body["FPID"])] = model_data
        return httpx.Response(200, json=OK_ACK)

    def _face_search(self, body: Any) -> httpx.Response:
        stored = self.faces.get(str(body.get("FPID")))
        if stored is None:  # the captured honest zero: NO MATCH, MatchList ABSENT
            return httpx.Response(
                200,
                json={
                    "statusCode": 1,
                    "responseStatusStrg": "NO MATCH",
                    "numOfMatches": 0,
                    "totalMatches": 0,
                },
            )
        return httpx.Response(
            200,
            json={
                "statusCode": 1,
                "responseStatusStrg": "OK",
                "numOfMatches": 1,
                "totalMatches": 1,
                "MatchList": [
                    {
                        "FPID": body.get("FPID"),
                        "faceURL": "http://<device-b>/LOCALS/pic/enrlFace/0/0000000001.jpg",
                        "modelData": stored,
                    }
                ],
            },
        )

    @staticmethod
    def _reject(path: str, why: str) -> httpx.Response:
        return httpx.Response(
            404,
            json={
                "statusCode": 4,
                "statusString": "ERROR",
                "subStatusCode": "notSupport",
                "errorMsg": f"{path}: {why}",
            },
        )


def bare_client(box: SiteBBox, clients: list[Any]) -> IsapiClient:
    client = IsapiClient(
        BASE_URL, "admin", PASSWORD, transport=box.transport, sleep=lambda _s: None
    )
    clients.append(client)
    return client


def verbose_client(box: SiteBBox, clients: list[Any]) -> LoggedClient:
    """`--verbose` shape: LoggedClient over the real client (the shape E1-10 crashed)."""
    client = LoggedClient(
        IsapiClient(BASE_URL, "admin", PASSWORD, transport=box.transport, sleep=lambda _s: None),
        RequestLogger(),
    )
    clients.append(client)
    return client


SHAPES = (
    pytest.param(bare_client, id="bare"),
    pytest.param(verbose_client, id="verbose-LoggedClient"),
)


def probe_ok() -> CapabilityMatrix:
    return CapabilityMatrix(
        site="site-b",
        host="192.0.2.10",
        clock_skew_s=0.4,
        template_nos=("1",),
        caps_raw={},
        surfaces=(
            SurfaceProbe(
                key="faces",
                endpoint="fd_search",
                method="POST",
                path=FACE_SEARCH_PATH,
                verdict=Verdict.OK,
            ),
        ),
        probed_at=NOW.isoformat(),
    )


def _phase(
    shape: Any, box: SiteBBox, clients: list[Any], tmp_path: Path, writes: tuple[FaceWrite, ...]
):
    """Drive the real phase over the real client with this card's fixtures."""
    return apply_faces_phase(
        transport_factory=lambda: FaceWriteTransport(shape(box, clients)),
        journal_path=tmp_path / "faces.jsonl",
        writes=writes,
        probe=probe_ok(),
        now=NOW,
        sleep=lambda _s: None,
        batch_delay=0.0,
    )


# --- 1+2+3: the E2 wall through the real client, both shapes ---------------------------------


@pytest.mark.parametrize("shape", SHAPES)
def test_the_captured_wall_rejects_classifies_aborts_and_never_retries(
    shape, tmp_path: Path
) -> None:
    """A's FR500005 template against site-B: rejected WITH a class, aborted, not retried.

    Everything the capture proved about the device's answer must reach the journal and
    the operator: the class on disk (mutation probe (d): the class is asserted AFTER a
    reopen, so a writer that drops the key fails here), the abort (mutation probe (c):
    if the class made the phase continue, the raises below fail), and one attempt only
    (mutation: a transport that retried the refused write would show 2+ attempts here
    and burn the lockout budget the capture says is at risk).
    """
    box = SiteBBox()
    clients: list[Any] = []

    with pytest.raises(FacePhaseAbortedError) as raised:
        _phase(shape, box, clients, tmp_path, (FaceWrite.build("90", FOREIGN_B64),))

    message = str(raised.value)
    assert "re-enroll" in message, "the abort must name the human next step"
    assert "generation mismatch" in message
    # The abort cites the capture by SECTION, not by path. This string is printed inside a
    # container/wheel that has no `docs/` tree to open, so a path there is a dead end by
    # construction — `tests/test_doc_citations.py` pins that no printed string names one.
    # The invariant is unchanged (the abort must point at the capture that proved this
    # wall); only its carrier moved, from a filename no shipped reader can resolve to the
    # section title that a developer can grep out of the probe record.
    assert "Face WRITE capture" in message, "the abort must cite the capture"
    assert raised.value.result.aborted is True
    # NO retry: the device saw exactly ONE FDSetUp for a refusal it will repeat (§0.6).
    assert box.setup_attempts == [FOREIGN_B64]
    assert len(clients) == 1

    # On disk, reopened: the §5a sequence + the E1-11 class (probe (d): reading back
    # is the only way to pin what a future payload refactor must not silently drop).
    journal = WriteJournal.open(tmp_path / "faces.jsonl", phase="faces")
    entries = journal.latest()
    assert [e.state.value for e in entries] == ["rejected"]
    assert entries[0].reject_class is RejectKind.TEMPLATE_REJECTED
    assert entries[0].device_sub_status == "badJsonContent"
    lines = [json.loads(line) for line in journal.path.read_text().splitlines()]
    rejected_lines = [ln for ln in lines if ln["state"] == "rejected"]
    assert [ln["rejectClass"] for ln in rejected_lines] == ["template_rejected"]


@pytest.mark.parametrize("shape", SHAPES)
def test_bare_badjson_without_the_faceurl_pair_stays_the_shape_class(shape, tmp_path) -> None:
    """Mutation probe (a): ANY-badJsonContent matching would make this red.

    The committed site-A captures show bare ``badJsonContent`` (no ``errorMsg``)
    answering OUR own mis-shaped bodies — that is ``shape_rejected`` and this card
    left it that way, verbatim. Only the captured PAIR is the wall.
    """
    box = SiteBBox()
    clients: list[Any] = []
    # Arm a one-shot shape bug: the next FDSetUp answers the BARE badJsonContent.
    attempts: list[Any] = []

    def _one_shot_setup(body: Any) -> httpx.Response:
        attempts.append(body)
        return httpx.Response(400, json=BARE_BADJSON)

    box._face_setup = _one_shot_setup  # the ONLY deviation: a route that answers 400

    with pytest.raises(FacePhaseAbortedError):
        _phase(shape, box, clients, tmp_path, (FaceWrite.build("90", NATIVE_B64),))

    journal = WriteJournal.open(tmp_path / "faces.jsonl", phase="faces")
    entries = journal.latest()
    assert entries[0].reject_class is RejectKind.SHAPE, (
        "bare badJsonContent is OUR bug class — matching the wall on any badJsonContent "
        "would have classified this template_rejected and sent the operator hunting the "
        "wrong wall"
    )
    assert [
        json.loads(line).get("rejectClass")
        for line in journal.path.read_text().splitlines()
        if json.loads(line)["state"] == "rejected"
    ] == ["shape_rejected"]
    assert len(attempts) == 1, "the phase still never retried the refused write (§0.6)"


def test_the_classifier_reads_the_pair_never_one_half() -> None:
    """Unit-level teeth for probes (a): each half alone, and the pair, in words."""
    pair = WriteRejectedError(
        "x", sub_status="badJsonContent", http_status=400, envelope=dict(E2_REJECT)
    )
    assert is_template_portability_rejection(pair)
    assert reject_kind_for(pair) is RejectKind.TEMPLATE_REJECTED

    sub_only = WriteRejectedError(
        "x",
        sub_status="badJsonContent",
        envelope={
            "statusCode": 6,
            "subStatusCode": "badJsonContent",
            "errorCode": 1610612759,
        },
    )
    assert not is_template_portability_rejection(sub_only)
    assert reject_kind_for(sub_only) is RejectKind.SHAPE  # the OLD mapping, verbatim

    msg_only = WriteRejectedError(
        "x", sub_status=None, envelope={"statusCode": 6, "errorMsg": "faceURL"}
    )
    assert not is_template_portability_rejection(msg_only)
    assert reject_kind_for(msg_only) is RejectKind.OTHER

    no_envelope = WriteRejectedError("x", sub_status="badJsonContent")
    assert not is_template_portability_rejection(no_envelope), (
        "the classifier reads the ENVELOPE; inferring the pair from message text is guessing (§0.7)"
    )
    assert reject_kind_for(no_envelope) is RejectKind.SHAPE


# --- the accept path keeps working (E1 shape, native magic) ----------------------------------


@pytest.mark.parametrize("shape", SHAPES)
def test_the_native_template_lands_and_the_journal_carries_no_class(shape, tmp_path: Path) -> None:
    """Capture E1 replayed: the flat body + B's own magic = accepted, read-back proven.

    Also the journal-schema back-compat direction of E1-11: a NON-rejection writes no
    ``rejectClass`` key at all, so journals written before this card and journals
    written after it have identical shapes for the untouched paths.
    """
    box = SiteBBox()
    clients: list[Any] = []

    result, _journal, verify = _phase(
        shape, box, clients, tmp_path, (FaceWrite.build("90", NATIVE_B64),)
    )

    assert verify is None and result.aborted is False and result.clean
    assert result.confirmed == (employee_hash("90"),)
    assert box.faces["90"] == NATIVE_B64
    lines = [json.loads(line) for line in (tmp_path / "faces.jsonl").read_text().splitlines()]
    assert all("rejectClass" not in ln for ln in lines)
    # §5a's append-only lifecycle for the one person: planned -> applied -> confirmed.
    assert [ln["state"] for ln in lines] == ["planned", "applied", "confirmed"]


# --- 4: the journal's old-file contract (E1-04 read-back pins stay true) ----------------------


def test_a_pre_e111_journal_without_the_class_key_still_reads(tmp_path: Path) -> None:
    """The key is ADDITIVE: a journal written before E1-11 (no rejectClass anywhere)
    replays with class None — never an error, never an invented class (§0.7)."""
    path = tmp_path / "old.jsonl"
    entry = {
        "schema": "gateclerk-migrate-journal/1",
        "seq": 1,
        "state": "rejected",
        "phase": "faces",
        "op": "face_setup",
        "employeeNo": "90",
        "employeeHash": employee_hash("90"),
        "classification": "add",
        "cardNo": None,
        "preWriteHash": None,
        "intendedHash": None,
        "postWriteHash": None,
        "deviceSubStatus": "badJsonContent",
        "intendedRecord": None,
        "preWriteRecord": None,
        # NOTE: no rejectClass key — that is the point of the test.
    }
    path.write_text(json.dumps(entry) + "\n", encoding="utf-8")

    journal = WriteJournal.open(path, phase="faces")
    latest = journal.latest()
    assert [e.state.value for e in latest] == ["rejected"]
    assert latest[0].reject_class is None
    assert latest[0].device_sub_status == "badJsonContent"
    assert not journal.truncated


def test_an_unknown_class_value_fails_closed_never_guesses(tmp_path: Path) -> None:
    """A rejectClass the vocabulary does not know is corruption, read as fail-closed."""
    journal = WriteJournal.open(tmp_path / "faces.jsonl", phase="faces")
    entry = journal.planned(
        employee_no="90",
        classification="add",
        pre_write_record=None,
        intended_record={"employeeNo": "90", "FDID": "1", "faceLibType": "blackFD"},
        op="face_setup",
    )
    journal.rejected(entry, sub_status="badJsonContent", reject_class=RejectKind.TEMPLATE_REJECTED)
    lines = journal.path.read_text().splitlines()
    tampered = [json.loads(line) for line in lines]
    for ln in tampered:
        if ln.get("rejectClass"):
            ln["rejectClass"] = "definitely_not_a_captured_class"
    journal.path.write_text("\n".join(json.dumps(ln) for ln in tampered) + "\n", encoding="utf-8")

    with pytest.raises(Exception, match="rejectClass"):
        WriteJournal.open(tmp_path / "faces.jsonl", phase="faces").latest()


# --- 6+7: the REPORT-ONLY pre-apply warning (the operator's actual pain) -----------------------


def _biometrics(magics: tuple[str, ...]) -> TargetBiometrics:
    return TargetBiometrics(target_face_magics=magics)


def _face_plan(*, source_magics: tuple[str, ...], target_magics: tuple[str, ...]) -> Plan:
    """One add-classified person whose SOURCE family is ``source_magics``.

    classify() takes the readable families via ``bundle_face_magics`` (the plan pass
    fills it from the bundle's ``faces/*.b64`` heads through
    :func:`gateclerk.migrate_faces.bundle_face_magics`) and the target families via
    ``biometrics.target_face_magics`` (from the FDSearch rows). No TemplateRefs are
    needed to exercise the note leg — the portability comparison is family-vs-family.
    """
    items = classify(
        [user("7")],
        [],
        [],
        [],
        None,
        policy=DiffPolicy(site_tz="Europe/Istanbul"),
        bundle_face_magics={"7": source_magics},
        biometrics=_biometrics(target_magics),
    )
    return Plan(items=tuple(items), policy=DiffPolicy(site_tz="Europe/Istanbul"))


def test_the_plan_warns_when_the_target_has_never_seen_the_source_family() -> None:
    """FR500005 source vs FR702706-only target: exactly capture E2, warned up front."""
    plan = _face_plan(source_magics=("FR500005",), target_magics=("FR702706",))
    (item,) = plan.items
    notes = [n for n in item.notes if n.startswith(FACE_PORTABILITY_NOTE_PREFIX)]
    assert len(notes) == 1
    assert "FR500005" in notes[0] and "FR702706" in notes[0]
    assert "re-enroll" in notes[0]
    # REPORT-ONLY: the warning never touches what would write or how it exits.
    assert item.classification.value == "add"


def test_a_family_the_target_already_holds_is_silent() -> None:
    plan = _face_plan(source_magics=("FR702706",), target_magics=("FR702706",))
    (item,) = plan.items
    assert not [n for n in item.notes if n.startswith(FACE_PORTABILITY_NOTE_PREFIX)]


def test_an_empty_target_produces_no_warning_never_a_guess() -> None:
    """Mutation probe (b): silence, not a warning conjured from an empty target.

    A target with zero face rows has never rejected anything — inventing a portability
    warning from "target has no faces" is exactly the guess §0.7 forbids (and would
    alarm operators whose new, empty target is perfectly able to accept templates
    once re-enrolled)."""
    for target in ((), ("",)):
        plan = _face_plan(source_magics=("FR500005",), target_magics=target)
        (item,) = plan.items
        assert not [n for n in item.notes if n.startswith(FACE_PORTABILITY_NOTE_PREFIX)]


def test_unreadable_source_family_is_silence_too() -> None:
    plan = _face_plan(source_magics=(), target_magics=("FR702706",))
    (item,) = plan.items
    assert not [n for n in item.notes if n.startswith(FACE_PORTABILITY_NOTE_PREFIX)]


def test_the_json_report_carries_face_portability_and_cannot_move_the_exit_code() -> None:
    """Legibility pin (card §Acceptance 5): the warning is lifted into its own field
    for machine readers, byte-identical in text to the table note, and report-only —
    totals/would_write/exit_code computed from classes+reasons+writes as before."""
    plan = _face_plan(source_magics=("FR500005",), target_magics=("FR702706",))
    payload = json.loads(render_report(plan, fmt="json"))
    (item,) = plan.items
    (warn,) = [n for n in item.notes if n.startswith(FACE_PORTABILITY_NOTE_PREFIX)]
    assert payload["facePortability"] == [{"employee": employee_hash("7"), "warnings": [warn]}]
    assert payload["totals"] == {"add": 1, "update": 0, "same": 0, "conflict": 0}
    assert payload["would_write"] == 1
    assert payload["schema"] == "gateclerk-migrate-diff/1"
    # table view carries the SAME note text (one computation, two renderings, §7)
    assert warn in render_report(plan, fmt="table")


def test_the_shared_helper_is_the_same_function_on_both_paths() -> None:
    """One helper, both paths (card §2): faces re-exports migrate_diff's objects."""
    import gateclerk.migrate_diff as diff_mod
    import gateclerk.migrate_faces as faces_mod

    assert faces_mod.face_portability_notes is face_portability_notes
    assert faces_mod.template_magic is template_magic
    assert faces_mod.face_portability_notes is diff_mod.face_portability_notes
    assert faces_mod.FACE_PORTABILITY_NOTE_PREFIX == FACE_PORTABILITY_NOTE_PREFIX


# --- the PRODUCT wiring: migrate_plan(bundle_dir=...) end to end ------------------------------


def _bundle(tmp_path: Path) -> tuple[BundleData, Path]:
    """A bundle whose one face template is site-A's family (FR500005 head)."""
    bundle_dir = tmp_path / "site-a-bundle"
    (bundle_dir / "faces").mkdir(parents=True)
    (bundle_dir / "faces" / "90.b64").write_text(FOREIGN_B64 + "\n", encoding="utf-8")
    from gateclerk.migrate_bundle import (
        BundleManifest,
        FacesIndex,
        FaceTemplate,
        FingerprintIndex,
    )

    manifest = BundleManifest(
        schema_version="1",
        exported_at=NOW.isoformat(),
        identity={"model": "DS-TEST", "firmware": "V3.2.30", "serial_prefix": "MASKED"},
        counts={"users": 1, "cards": 0, "faces": 1, "fingerprints": 0},
        people_hashes={},
        volatile_fields_digest="0" * 64,
        faces={"state": "AVAILABLE", "reason": ""},
        termination={},
    )
    bundle = BundleData(
        manifest=manifest,
        people=(user("90"),),
        cards=(),
        faces=FacesIndex(
            state="AVAILABLE",
            reason="",
            entries=(
                FaceTemplate(
                    employee_no="90",
                    fdid="1",
                    face_lib_type="blackFD",
                    sha256=FOREIGN_SHA,
                    length=len(base64.b64decode(FOREIGN_B64)),
                ),
            ),
            photo_bytes={"reason": "faceURL export 404s on this fw (recorded fact)"},
        ),
        fingerprints=FingerprintIndex(),
    )
    return bundle, bundle_dir


def _target_state() -> EnrollmentState:
    """Target holds ONE person ("1") whose face is the target's OWN family."""
    return EnrollmentState(
        users=(user("1"),),
        cards=(),
        identity={"model": "DS-TEST", "firmware": "V4.13.0", "serial_prefix": "MASKED"},
        termination={},
    )


def _seams(tmp_path: Path) -> ApplySeams:
    """Reader-only seams: the target's person "1" answers FDSearch with FR702706 bytes."""
    from gateclerk.migrate_apply import ApplySeams

    def faces_reader(body: Any) -> dict[str, Any]:
        if str(body.get("FPID")) == "1":
            return {
                "statusCode": 1,
                "responseStatusStrg": "OK",
                "numOfMatches": 1,
                "totalMatches": 1,
                "MatchList": [{"FPID": "1", "modelData": NATIVE_B64}],
            }
        return {
            "statusCode": 1,
            "responseStatusStrg": "NO MATCH",
            "numOfMatches": 0,
            "totalMatches": 0,
        }

    def fp_reader(body: Any) -> dict[str, Any]:
        return {"FingerPrintInfo": {"status": "NoFP"}}

    def _no_write_seam() -> Any:
        raise AssertionError("the plan pass is READS only — no write transport may exist")

    return ApplySeams(
        read_target_state=_target_state,
        users_transport_factory=_no_write_seam,
        cards_transport_factory=_no_write_seam,
        fp_transport_factory=_no_write_seam,
        faces_transport_factory=_no_write_seam,
        users_reader=lambda _b: {"UserInfoSearch": {"UserInfo": []}},
        cards_reader=lambda _b: {"CardInfoSearch": {"CardInfo": []}},
        fp_reader=fp_reader,
        faces_reader=faces_reader,
    )


def test_migrate_plan_warns_before_any_write_is_attempted(tmp_path: Path) -> None:
    """The operator's actual pain (card §2): plan time must see the wall the device gives.

    Person 90 (bundle, FR500005 family) is an `add`; the target's one face row is
    FR702706. The plan pass — through the PRODUCTION seams and migrate_plan, not a
    hand-rolled classify — must surface the report-only warning, and the plan's
    write ledger and exit code must be EXACTLY what they would be without the note
    (report-only proven at the product seam, not just at the helper).
    """
    from gateclerk.migrate_apply import migrate_plan

    bundle, bundle_dir = _bundle(tmp_path)
    planned = migrate_plan(
        bundle=bundle,
        seams=_seams(tmp_path),
        policy=DiffPolicy(site_tz="Europe/Istanbul"),
        probe=None,
        now=NOW,
        bundle_dir=bundle_dir,
    )
    by_hash = {i.employee_hash: i for i in planned.plan.items}
    (item,) = [i for i in planned.plan.items if i.employee_hash == employee_hash("90")]
    notes = [n for n in item.notes if n.startswith(FACE_PORTABILITY_NOTE_PREFIX)]
    assert len(notes) == 1 and "FR500005" in notes[0] and "FR702706" in notes[0]
    assert item.classification.value == "add"
    payload = json.loads(render_report(planned.plan, fmt="json"))
    assert payload["facePortability"] == [{"employee": employee_hash("90"), "warnings": notes}]
    # The person the warning is NOT about (target-only "1") carries nothing.
    assert all(w["employee"] != employee_hash("1") for w in payload["facePortability"])
    assert by_hash  # sanity: the plan covers both persons


def test_migrate_plan_without_bundle_dir_is_silence_not_a_guess(tmp_path: Path) -> None:
    """The same plan without bundle_dir: the leg is ABSENT, the plan identical (§0.7)."""
    from gateclerk.migrate_apply import migrate_plan

    bundle, _bundle_dir = _bundle(tmp_path)
    planned = migrate_plan(
        bundle=bundle,
        seams=_seams(tmp_path),
        policy=DiffPolicy(site_tz="Europe/Istanbul"),
        probe=None,
        now=NOW,
    )
    assert all(
        not n.startswith(FACE_PORTABILITY_NOTE_PREFIX) for i in planned.plan.items for n in i.notes
    )
    payload = json.loads(render_report(planned.plan, fmt="json"))
    assert payload["facePortability"] == []


def test_bundle_face_magics_skips_people_whose_files_are_broken(tmp_path: Path) -> None:
    """A missing/garbage .b64 is ABSENCE (no invented family, §0.7), never a crash."""
    from gateclerk.migrate_bundle import FaceTemplate
    from gateclerk.migrate_faces import bundle_face_magics

    faces = tmp_path / "faces"
    faces.mkdir()
    (faces / "ok.b64").write_text(NATIVE_B64 + "\n")
    (faces / "garbage.b64").write_text("!!! not base64 !!!\n")
    entries = (
        FaceTemplate("ok", "1", "blackFD", NATIVE_SHA, len(base64.b64decode(NATIVE_B64))),
        FaceTemplate("garbage", "1", "blackFD", "0" * 64, 10),
        FaceTemplate("missing", "1", "blackFD", "0" * 64, 10),
    )
    assert bundle_face_magics(tmp_path, entries) == {"ok": ("FR702706",)}


# --- 7: template_magic's own contract ----------------------------------------------------------


def test_template_magic_reads_eight_bytes_and_never_invents() -> None:
    assert template_magic(b"FR702706\x01garbage") == "FR702706"
    assert template_magic(b"FR500005\x01garbage") == "FR500005"
    assert template_magic(b"FR123456") == "FR123456"
    assert template_magic(b"FR12345") is None  # too short: NO family, not a guess
    assert template_magic(b"AB123456") is None  # not FR
    assert template_magic(b"FR12345a") is None  # 7th char non-digit
    assert template_magic(b"") is None
    assert template_magic(b"\x00\x01\x02\x03\x04\x05\x06\x07") is None
    # a non-ASCII byte in the first 8 can never match (regex is byte-classed)
    assert template_magic(b"\xffR123456") is None
