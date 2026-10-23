"""Card E1-06b definition of done: the fingerprints phase, offline and FakeDevice-strict.

Everything runs under the autouse `netoff` guard — the real device is NEVER contacted;
the five fpdownload_*/fpcfg captures are the only device truth the fake may answer
from. The headline this suite exists to keep true (bench A, OBSERVED.md §5.0):

    FingerPrintDownload answers `statusCode 1 ok` (the capture) and the SAME read that
    returned `NoFP` before the write returns `NoFP` after it (the capture) while
    `FingerPrintProgress` says `cardReaderRecvStatus:5` (the capture). The ack is worth
    nothing. Confirmation is ONLY a post-write one-shot read whose template sha256
    equals the journal's intended sha.

Pins (card §Tests): ack-is-not-confirm ends `rejected` OTHER with the device's progress
words visible; confirmed requires the post-read sha match (the `fp_applies=True`
same-family target); already_present skips via the one-shot read WITHOUT writing; a
different-hash target template is a CONFLICT and is never overwritten; the FIRST
non-applied answer aborts the phase with the landed list and spends no further writes
or reads; `enableCardReader` must be an array (the 400 fixture, byte-equal); the
one-shot read ignores `fpIndex` (PR #42, no regression); NO FP delete verb is reachable
from either side; the budget ledger and the fake's own authed-request counters agree.
"""

from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path
from typing import Any

import httpx
import pytest

from fakedevice import (
    BASE_URL,
    EnrollmentProtocolError,
    FakeDevice,
)
from gateclerk.isapi_transport import IsapiClient
from gateclerk.migrate_bundle import (
    FingerprintIndex,
    FingerprintTemplate,
)
from gateclerk.migrate_fingerprints import (
    FP_DOWNLOAD_PATH,
    FP_DOWNLOAD_RESPONSE_OK,
    FP_PROGRESS_PATH,
    FP_READ_PATH,
    FP_TEMPLATE_KEYS,
    FP_UNDO_REPORT_ONLY,
    MAX_FINGER_PRINT_ID,
    BudgetedWriteTransport,
    FpAbortedError,
    FpFleetReport,
    FpPhaseResult,
    FpReadError,
    FpReadOutcome,
    FpShapeError,
    FpVerdictKind,
    FpWrite,
    RejectKind,
    SensorFamily,
    WriteJournal,
    WriteRejectedError,
    apply_fingerprints_phase,
    build_fingerprint_download_body,
    classify_progress_rejection,
    decode_template,
    family_decision,
    parse_fingerprint_progress,
    parse_fingerprint_read,
    person_hash,
    plan_fingerprint_writes,
    read_fingerprint_template,
    report_only_fingerprint_undo,
    run_fingerprints_phase,
    verify_fingerprints,
)
from gateclerk.migrate_write import REBOOTSTRAP_AT_AUTHED_CALLS, JournalState

FIXTURES = Path(__file__).parent / "fixtures/recorded/site-a-ds-k1t341amf-s"
ENROLLMENT = FIXTURES / "enrollment"
PASSWORD = "fake" + "pw"  # placeholder policy (tests/test_repo_hygiene.py)

#: The five captures this card rests on, loaded once (they are the contract).
FP_CAPTURE_REQUEST = json.loads((ENROLLMENT / "fpdownload_accept_request.json").read_text())
FP_CAPTURE_ACK = json.loads((ENROLLMENT / "fpdownload_accept_response.json").read_text())
FP_CAPTURE_SCALAR_400 = json.loads(
    (ENROLLMENT / "fpdownload_badjson_scalar_enable_400.json").read_text()
)
FP_CAPTURE_PROGRESS = json.loads(
    (ENROLLMENT / "fpdownload_progress_reader_reject.json").read_text()
)
FP_CAPTURE_READBACK = json.loads((ENROLLMENT / "fpdownload_readback_still_nofp.json").read_text())
FP_CAPTURE_CFG = json.loads((ENROLLMENT / "fpcfg_capabilities.json").read_text())

#: A tiny synthetic template of the recorded third-party family (ASCII "301" header,
#: §1). Bytes, not a parse — the payload is opaque (§2).
TPL_BYTES = b"301" + bytes((i * 7 + 3) % 251 for i in range(40))  # deterministic, hygiene-clean
TPL_B64 = base64.b64encode(TPL_BYTES).decode("ascii")
TPL_SHA = hashlib.sha256(TPL_BYTES).hexdigest()

OTHER_BYTES = b"301" + b"\xff" * 40  # a DIFFERENT template, same header family
OTHER_B64 = base64.b64encode(OTHER_BYTES).decode("ascii")
OTHER_SHA = hashlib.sha256(OTHER_BYTES).hexdigest()

FAMILY_NOTE = "301-header (third-party sensor family, not self-identified — OBSERVED.md)"

DOWNLOAD_URL = FP_DOWNLOAD_PATH + "?format=json"
PROGRESS_URL = FP_PROGRESS_PATH + "?format=json"
UPLOAD_URL = FP_READ_PATH + "?format=json"


# --- builders ---------------------------------------------------------------------------


def fp_device(*, fp_templates: dict[str, str] | None = None, **knobs: Any) -> FakeDevice:
    """A box with BOTH axes armed: the FP one-shot READ and the captured FP WRITE.

    ``fp_templates`` seeds who ALREADY has a template (the read axis); the write knob
    ``fp_applies`` (passed through ``**knobs``) decides whether an accepted write is
    APPLIED — the default False replays bench A (accept, store nothing, progress says
    5); True models the unobserved same-sensor-family target.
    """
    d = FakeDevice(password=PASSWORD)
    d.install_enrollment(fp_templates=fp_templates if fp_templates is not None else {})
    d.install_write_capture(**knobs)
    return d


def client_for(device: FakeDevice) -> IsapiClient:
    return IsapiClient(
        BASE_URL, "admin", PASSWORD, transport=device.transport, sleep=lambda _s: None
    )


def reader_for(device: FakeDevice):
    """The one-shot read seam: the registry-guarded FingerPrintUpload POST (§1)."""
    client = client_for(device)

    def read(body: Any) -> dict:
        return client.search("finger_print_upload", body)

    return read


def raw_request(
    device: FakeDevice, method: str, path: str, *, json_body: Any = None
) -> httpx.Response:
    """One digest-authed request straight into the fake's transport (E1-04 pattern:
    handle_request() without auth gets the 401 challenge, not the route answer)."""
    with httpx.Client(
        transport=device.transport, auth=httpx.DigestAuth("admin", PASSWORD), base_url=BASE_URL
    ) as raw:
        return raw.request(method, path, json=json_body)


def fp_cfg_body(**over: Any) -> dict[str, Any]:
    """A captured-shape write body, overridable field by field."""
    cfg = dict(FP_CAPTURE_REQUEST["FingerPrintCfg"])
    cfg["fingerData"] = TPL_B64
    cfg.update(over)
    return {"FingerPrintCfg": cfg}


def bundle_with(tmp_path: Path, *entries: FingerprintTemplate) -> Path:
    """A bundle directory holding one .b64 per entry (files match the INDEX bytes)."""
    root = tmp_path / "bundle"
    (root / "fingerprints").mkdir(parents=True, exist_ok=True)
    for entry in entries:
        raw = OTHER_BYTES if entry.sha256 == OTHER_SHA else TPL_BYTES
        (root / "fingerprints" / f"{entry.employee_no}-{entry.fp_index}.b64").write_text(
            base64.b64encode(raw).decode("ascii"), encoding="ascii"
        )
    return root


def index_of(*entries: FingerprintTemplate) -> FingerprintIndex:
    return FingerprintIndex(state="AVAILABLE", reason="", entries=entries)


def fp_entry(no: str, *, sha: str = TPL_SHA, length: int = len(TPL_BYTES), **over: Any):
    payload: dict[str, Any] = {
        "employeeNo": no,
        "fpIndex": 0,
        "sha256": sha,
        "length": length,
        "sensor_family": FAMILY_NOTE,
    }
    payload.update(over)
    return FingerprintTemplate.from_dict(payload)


def write_for(no: str, *, b64: str = TPL_B64, raw: bytes = TPL_BYTES, **over: Any) -> FpWrite:
    digest = hashlib.sha256(raw).hexdigest()
    probe = over.pop("probe", None)
    template: dict[str, Any] = {
        "enableCardReader": [1],
        "employeeNo": no,
        "fingerPrintID": 1,
        "fingerType": "normalFP",
        "fingerData": b64,
    }
    template.update(over)
    return FpWrite(
        employee_no=no,
        employee_hash=person_hash(no),
        template=template,
        finger_data_b64=template["fingerData"] if isinstance(template["fingerData"], str) else b64,
        intended_sha256=digest,
        sensor_family=FAMILY_NOTE,
        probe=probe,
    )


def fp_journal(tmp_path: Path, name: str = "fp.jsonl") -> WriteJournal:
    return WriteJournal.open(tmp_path / name, phase="fingerprints")


class FpSeam:
    """The injected FP transport over the real IsapiClient digest stack.

    Records what left the process (the shape/budget tests read those records, never a
    comment), and refuses `put_setup` outright — the users verb on this phase's seam
    is a programming error the type would rather not compile (E1-04's seam is reused,
    never re-implemented; `BudgetedWriteTransport.call` is the counter).
    """

    def __init__(self, client: IsapiClient, *, journal: WriteJournal | None = None) -> None:
        self.client = client
        self.journal = journal
        self.downloads: list[tuple[str, dict]] = []
        self.progress_reads = 0
        self.closed = 0
        #: journal states observed AT REQUEST TIME (the §5a journal-before-request pin).
        self.request_time_states: list[str | None] = []

    def post_download(self, path: str, body: Any) -> dict:
        self.downloads.append((path, json.loads(json.dumps(body))))
        if self.journal is not None and self.journal.entries:
            self.request_time_states.append(str(self.journal.entries[-1].state))
        response = self.client._client.post(
            path, params={"format": "json"}, json=body, auth=self.client._auth
        )
        envelope = json.loads(response.content)
        if response.status_code != 200 or envelope.get("statusCode") != FP_DOWNLOAD_RESPONSE_OK:
            raise WriteRejectedError(
                f"device answered {response.status_code} {envelope.get('subStatusCode')}",
                sub_status=envelope.get("subStatusCode"),
                http_status=response.status_code,
                envelope=envelope,
            )
        return envelope

    def get_progress(self, path: str) -> dict:
        self.progress_reads += 1
        response = self.client._client.get(path, params={"format": "json"}, auth=self.client._auth)
        return json.loads(response.content)

    def put_setup(self, path: str, body: Any) -> dict:
        raise AssertionError("the fingerprints phase must never use the users verb")

    def close(self) -> None:
        self.closed += 1


# --- the headline: an ack is not a confirm --------------------------------------------------


def test_accepted_but_not_applied_ends_rejected_with_the_device_words(tmp_path: Path) -> None:
    """THE pin of the card. Device answers statusCode 1, the post-write read stays `NoFP`
    (the capture `fpdownload_readback_still_nofp.json`), progress says 5 (the capture).
    The only honest terminal state is `rejected` / OTHER / the device's own words."""
    device = fp_device()  # fp_applies defaults False = bench A reality
    journal = fp_journal(tmp_path)
    seam = FpSeam(client_for(device), journal=journal)
    with pytest.raises(FpAbortedError) as raised:
        run_fingerprints_phase(
            BudgetedWriteTransport(lambda: seam), journal, [write_for("9")], reader_for(device)
        )
    result: FpPhaseResult = raised.value.result
    assert result.aborted and result.applied == (person_hash("9"),)  # device DID ack
    assert result.confirmed == () and result.landed == ()  # but NOTHING landed
    assert len(result.rejected) == 1
    hashed, kind, words = result.rejected[0]
    assert hashed == person_hash("9") and kind is RejectKind.OTHER
    assert words is not None  # the device's words ride along, never dropped
    assert "statusCode=1" in words and "NoFP" in words
    # The device's own progress words — verbatim, not paraphrased (§6).
    assert "cardReaderRecvStatus=5" in words and "errorMsg=1" in words
    assert "accepted but not applied" in words
    # The report says it in plain words for the operator.
    assert "ackIsNotConfirm" in result.summary()


def test_journal_for_the_aborted_person_reads_rejected_with_the_progress_words(
    tmp_path: Path,
) -> None:
    """§5a/§6: the journal is the durable record — `planned → applied → rejected`, the
    rejected line carrying the device's progress words (an unknown state = human)."""
    device = fp_device()
    journal = fp_journal(tmp_path)
    seam = FpSeam(client_for(device), journal=journal)
    with pytest.raises(FpAbortedError):
        run_fingerprints_phase(
            BudgetedWriteTransport(lambda: seam), journal, [write_for("9")], reader_for(device)
        )
    raw_lines = [json.loads(line) for line in journal.path.read_text().splitlines()]
    assert [line["state"] for line in raw_lines] == ["planned", "applied", "rejected"]
    assert (
        raw_lines[-1]["deviceSubStatus"]
        and "cardReaderRecvStatus=5" in raw_lines[-1]["deviceSubStatus"]
    )
    resumed = WriteJournal.open(journal.path, phase="fingerprints")
    entry = resumed.by_employee("9")
    assert entry is not None and entry.state is JournalState.REJECTED
    assert entry.device_sub_status and "cardReaderRecvStatus=5" in entry.device_sub_status
    assert "errorMsg=1" in entry.device_sub_status
    # No person may sit in `applied` — an ack never survives as a terminal state.
    assert resumed.latest(state=JournalState.APPLIED) == ()


def test_journal_line_is_on_disk_before_the_request_arrives(tmp_path: Path) -> None:
    """§5a order, pinned for THIS phase: at request time the journal already carries the
    planned (and only planned) line for the person being written."""
    device = fp_device()
    journal = fp_journal(tmp_path)
    seam = FpSeam(client_for(device), journal=journal)
    with pytest.raises(FpAbortedError):
        run_fingerprints_phase(
            BudgetedWriteTransport(lambda: seam), journal, [write_for("9")], reader_for(device)
        )
    assert seam.request_time_states == ["planned"]


# --- confirmation: only a post-write read by sha ------------------------------------------


def test_confirmed_requires_the_post_read_sha_match_applies_true(tmp_path: Path) -> None:
    """The same-family target (§1's hypothetical, modelled by `fp_applies=True`): the
    post-write one-shot read returns the written bytes → sha match → `confirmed`.
    This is the ONLY route to `confirmed` for a fresh write."""
    device = fp_device(fp_applies=True)
    journal = fp_journal(tmp_path)
    seam = FpSeam(client_for(device), journal=journal)
    result = run_fingerprints_phase(
        BudgetedWriteTransport(lambda: seam), journal, [write_for("9")], reader_for(device)
    )
    assert not result.aborted and result.clean
    assert result.confirmed == (person_hash("9"),) and result.landed == result.confirmed
    assert result.writes_sent == 1 and result.reads_sent == 2  # before + after, never a walk
    resumed = WriteJournal.open(journal.path, phase="fingerprints")
    entry = resumed.by_employee("9")
    assert entry is not None and entry.state is JournalState.CONFIRMED
    assert entry.post_write_hash == TPL_SHA  # the READ's hash, not an echo of the ack


def test_post_read_present_but_different_sha_never_confirms(tmp_path: Path) -> None:
    """The confirm gate's ONLY positive arm, pinned: an ack PLUS a PRESENT post-read is
    still not enough — the read's sha must EQUAL the intended sha. A device that
    "applied" DIFFERENT bytes (the pathological answer the fake can't produce:
    applies-mode stores verbatim) lands rejected-not-applied, never `confirmed`
    (§6: the only moment that means anything is the sha comparison itself)."""
    device = fp_device(fp_applies=True)
    journal = fp_journal(tmp_path)
    seam = FpSeam(client_for(device), journal=journal)
    reads = [
        {"FingerPrintInfo": {"status": "NoFP"}},  # before: nothing there
        {  # after: something IS there — but it is NOT the template we sent
            "FingerPrintInfo": {
                "status": "OK",
                "FingerPrintList": [{"fingerPrintID": 1, "fingerData": OTHER_B64}],
            }
        },
    ]

    def doctored_reader(_body: Any) -> dict:
        return reads.pop(0)

    with pytest.raises(FpAbortedError) as raised:
        run_fingerprints_phase(
            BudgetedWriteTransport(lambda: seam), journal, [write_for("9")], doctored_reader
        )
    result = raised.value.result
    assert not result.confirmed and not result.clean
    assert "not applied" in (result.abort_reason or "")
    resumed = WriteJournal.open(journal.path, phase="fingerprints")
    entry = resumed.by_employee("9")
    assert entry is not None and entry.state is JournalState.REJECTED
    assert entry.post_write_hash != TPL_SHA  # never stamped with the intended echo


def test_already_present_skips_the_write_entirely(tmp_path: Path) -> None:
    """One-shot read BEFORE matches the intended sha → `already_present`: journal the
    intent, confirm by the read, send NOTHING. An idempotent re-run writes nothing."""
    device = fp_device(fp_templates={"9": TPL_B64})
    journal = fp_journal(tmp_path)
    seam = FpSeam(client_for(device), journal=journal)
    result = run_fingerprints_phase(
        BudgetedWriteTransport(lambda: seam), journal, [write_for("9")], reader_for(device)
    )
    assert result.writes_sent == 0 and seam.downloads == []
    assert result.confirmed == (person_hash("9"),) and result.reads_sent == 1
    assert any(reason.startswith("already_present") for _h, reason in result.skipped)
    assert device.authorized_requests_to("POST", DOWNLOAD_URL) == 0


def test_different_hash_target_is_a_conflict_and_is_never_overwritten(tmp_path: Path) -> None:
    """§0.6 made structural: the target holds a DIFFERENT template → CONFLICT report,
    no write, no journal line, and the target's bytes are still exactly its own."""
    device = fp_device(fp_templates={"9": OTHER_B64}, fp_applies=True)
    journal = fp_journal(tmp_path)
    seam = FpSeam(client_for(device), journal=journal)
    result = run_fingerprints_phase(
        BudgetedWriteTransport(lambda: seam), journal, [write_for("9")], reader_for(device)
    )
    assert result.writes_sent == 0 and seam.downloads == []
    assert any(
        reason.startswith("conflict_target_has_different_template") for _h, reason in result.skipped
    )
    assert journal.entries == ()  # nothing was sent, so nothing was journalled
    # The device's own template survives untouched (read it back directly).
    answer = json.loads(
        raw_request(
            device,
            "POST",
            UPLOAD_URL,
            json_body={
                "FingerPrintCond": {
                    "searchID": "conflict-check",
                    "employeeNo": "9",
                    "fpIndex": 0,
                    "dataType": "template",
                }
            },
        ).content
    )
    row = answer["FingerPrintInfo"]["FingerPrintList"][0]
    assert row["fingerData"] == OTHER_B64


def test_first_non_applied_answer_aborts_and_spends_no_further_calls(tmp_path: Path) -> None:
    """§5 step 4 fail-fast: person 1 gets acked-and-not-applied; the phase ABORTS. The
    fake must have seen exactly ONE write, TWO reads (before+after) and ONE progress
    pull — persons 2 and 3 are never touched at all."""
    device = fp_device()  # reality mode: nobody ever gets applied
    journal = fp_journal(tmp_path)
    seam = FpSeam(client_for(device), journal=journal)
    with pytest.raises(FpAbortedError) as raised:
        run_fingerprints_phase(
            BudgetedWriteTransport(lambda: seam),
            journal,
            [write_for("1"), write_for("2"), write_for("3")],
            reader_for(device),
        )
    result = raised.value.result
    assert result.writes_sent == 1 and result.progress_reads == 1
    assert result.reads_sent == 2  # person 1 only: before + after
    assert result.aborted and "landed" in (result.abort_reason or "")
    assert device.authorized_requests_to("POST", DOWNLOAD_URL) == 1
    assert device.authorized_requests_to("POST", UPLOAD_URL) == 2
    assert device.authorized_requests_to("GET", PROGRESS_URL) == 1
    # Persons 2/3 are untouched: no reads, no journal lines.
    resumed = WriteJournal.open(journal.path, phase="fingerprints")
    assert resumed.by_employee("2") is None and resumed.by_employee("3") is None


# --- the captured write vocabulary ----------------------------------------------------------


def test_the_download_body_is_the_captured_shape() -> None:
    """Byte-shape lock against `fpdownload_accept_request.json`: same keys, same nesting,
    `enableCardReader` an array, `fingerPrintID` the slot key, data verbatim."""
    body = build_fingerprint_download_body(write_for("9"))
    cfg = body["FingerPrintCfg"]
    assert set(cfg) == set(FP_CAPTURE_REQUEST["FingerPrintCfg"]) == FP_TEMPLATE_KEYS
    assert cfg["enableCardReader"] == [1] and isinstance(cfg["enableCardReader"], list)
    assert cfg["fingerPrintID"] == 1 and cfg["fingerType"] == "normalFP"
    assert cfg["fingerData"] == TPL_B64  # verbatim — never re-encoded (§2)


def test_scalar_enable_card_reader_is_refused_before_the_request() -> None:
    """Our own builder refuses the scalar spelling — catching it is FREE; letting the
    device say it costs a budget call and the captured 400."""
    with pytest.raises(FpShapeError, match="ARRAY"):
        build_fingerprint_download_body(write_for("9", enableCardReader=1))
    with pytest.raises(FpShapeError, match="ARRAY"):
        build_fingerprint_download_body(write_for("9", enableCardReader="1"))


def test_the_device_answers_the_scalar_body_with_the_captured_400() -> None:
    """Byte-for-byte `fpdownload_badjson_scalar_enable_400.json` — the ONE rejection
    captured verbatim for this verb (errorMsg names enableCardReader)."""
    device = fp_device()
    response = raw_request(device, "POST", DOWNLOAD_URL, json_body=fp_cfg_body(enableCardReader=1))
    assert response.status_code == 400
    assert json.loads(response.content) == FP_CAPTURE_SCALAR_400


def test_fp_index_is_not_the_slot_key_on_either_side() -> None:
    """The builder refuses an `fpIndex` key (§9 unrecorded shape); the DEVICE answers
    the substitution with badJsonContent naming `fpIndex` — the fake never accepts a
    body the capture never showed."""
    with pytest.raises(FpShapeError, match="fpIndex"):
        build_fingerprint_download_body(write_for("9", fpIndex=0))
    device = fp_device()
    body = fp_cfg_body()
    del body["FingerPrintCfg"]["fingerPrintID"]
    body["FingerPrintCfg"]["fpIndex"] = 0
    response = raw_request(device, "POST", DOWNLOAD_URL, json_body=body)
    answered = json.loads(response.content)
    assert answered["subStatusCode"] == "badJsonContent" and answered["errorMsg"] == "fpIndex"


def test_missing_finger_type_is_refused_by_the_builder_and_the_device() -> None:
    with pytest.raises(FpShapeError, match="fingerType"):
        build_fingerprint_download_body(write_for("9", fingerType=None))
    device = fp_device()
    body = fp_cfg_body()
    del body["FingerPrintCfg"]["fingerType"]
    response = raw_request(device, "POST", DOWNLOAD_URL, json_body=body)
    answered = json.loads(response.content)
    assert answered["subStatusCode"] == "badJsonContent" and answered["errorMsg"] == "fingerType"


def test_wrong_verb_answers_the_captured_method_not_allowed() -> None:
    """PUT is not this verb (the capture is a POST); the fake replays the captured
    methodNotAllowed envelope, never a 404 an optimist could read as fine."""
    device = fp_device()
    response = raw_request(device, "PUT", DOWNLOAD_URL, json_body=fp_cfg_body())
    assert response.status_code == 400
    assert json.loads(response.content)["subStatusCode"] == "methodNotAllowed"


def test_a_valid_body_always_gets_the_captured_accept_in_both_modes() -> None:
    """Acceptance itself is captured: statusCode 1 in reality mode AND applies mode.
    What DIFFERS is everything after — which is the module docstring's whole point."""
    for applies in (False, True):
        device = fp_device(fp_applies=applies)
        response = raw_request(device, "POST", DOWNLOAD_URL, json_body=fp_cfg_body())
        assert json.loads(response.content) == FP_CAPTURE_ACK


def test_unarmed_write_and_unearned_progress_are_hard_failures(tmp_path: Path) -> None:
    """§9 from the fake's side: without the write axis a POST FingerPrintDownload is a
    hard protocol error (never a 404); the progress route answers its ONE capture only
    after an accepted-not-applied write — a phase that polled it elsewhere is
    misbehaving against the auth budget (§0.5) and the fake says so."""
    device = FakeDevice(password=PASSWORD)
    with pytest.raises(EnrollmentProtocolError, match="no bench-A write truth armed"):
        raw_request(device, "POST", DOWNLOAD_URL, json_body=fp_cfg_body())
    armed = fp_device()
    with pytest.raises(EnrollmentProtocolError, match="ONLY after an accepted"):
        raw_request(armed, "GET", PROGRESS_URL)
    # Earned: accept-without-apply arms the progress answer — the captured body.
    raw_request(armed, "POST", DOWNLOAD_URL, json_body=fp_cfg_body())
    response = raw_request(armed, "GET", PROGRESS_URL)
    assert json.loads(response.content) == FP_CAPTURE_PROGRESS
    # ...and the fingerprint CAPS capture proves the vocabulary the fake bounds by.
    assert FP_CAPTURE_CFG["FingerPrintCfg"]["fingerPrintID"]["@max"] == MAX_FINGER_PRINT_ID


# --- the one-shot read (PR #42: fpIndex is ignored; no walk) --------------------------------


def test_one_shot_read_ignores_fp_index() -> None:
    """PR #42's semantics, non-regressable: the SAME person answered the identical row
    for fpIndex 0/1/2. The phase therefore spends ONE read per person per step."""
    device = fp_device(fp_templates={"1": TPL_B64})
    rows = []
    for fp_index in (0, 1, 2):
        answer = json.loads(
            raw_request(
                device,
                "POST",
                UPLOAD_URL,
                json_body={
                    "FingerPrintCond": {
                        "searchID": f"walk{fp_index}",
                        "employeeNo": "1",
                        "fpIndex": fp_index,
                        "dataType": "template",
                    }
                },
            ).content
        )
        rows.append(answer["FingerPrintInfo"])
    assert all(r["status"] == "OK" for r in rows)
    assert rows[0]["FingerPrintList"] == rows[1]["FingerPrintList"] == rows[2]["FingerPrintList"]
    assert rows[0]["FingerPrintList"][0]["fingerPrintID"] == 1


def test_honest_zero_is_no_fp_with_the_list_absent() -> None:
    """The capture `fpdownload_readback_still_nofp.json`: `NoFP` with NO list key. The
    parser reads exactly that as NO_FP; any OTHER listless answer raises (§0.7)."""
    assert FP_CAPTURE_READBACK == {"FingerPrintInfo": {"searchID": "capf9rb", "status": "NoFP"}}
    zero = parse_fingerprint_read("9", FP_CAPTURE_READBACK)
    assert zero.outcome is FpReadOutcome.NO_FP and zero.device_status == "NoFP"
    with pytest.raises(FpReadError, match="not the captured zero word"):
        parse_fingerprint_read("9", {"FingerPrintInfo": {"status": "OK"}})
    with pytest.raises(FpReadError, match="no 'FingerPrintInfo' envelope"):
        parse_fingerprint_read("9", {"Other": 1})


def test_parse_refuses_multi_row_and_unproven_slot_answers() -> None:
    """Exactly-one row and fingerPrintID==1 are the probed shape; anything else means
    THAT box reads fingerprints differently than bench A — refuse, don't guess."""
    two = {
        "FingerPrintInfo": {
            "status": "OK",
            "FingerPrintList": [
                {"fingerPrintID": 1, "fingerData": TPL_B64},
                {"fingerPrintID": 2, "fingerData": TPL_B64},
            ],
        }
    }
    with pytest.raises(FpReadError, match="row"):
        parse_fingerprint_read("9", two)
    other_slot = {
        "FingerPrintInfo": {
            "status": "OK",
            "FingerPrintList": [{"fingerPrintID": 3, "fingerData": TPL_B64}],
        }
    }
    with pytest.raises(FpReadError, match="UNPROVEN"):
        parse_fingerprint_read("9", other_slot)


def test_read_fails_closed_on_broken_payloads() -> None:
    """§0.7: empty/unclean/zero-byte fingerData is a protocol break, never 'no finger'
    and never an enrolled template."""
    with pytest.raises(FpReadError, match="empty"):
        parse_fingerprint_read(
            "9",
            {
                "FingerPrintInfo": {
                    "status": "OK",
                    "FingerPrintList": [{"fingerPrintID": 1, "fingerData": ""}],
                }
            },
        )
    with pytest.raises(FpReadError, match="not clean base64"):
        # Padding-only garbage: `validate=True` refuses it — the "zero bytes" line
        # below is a defensive belt, the only input that decodes to zero bytes is the
        # empty string and that is caught one check earlier as "empty".
        parse_fingerprint_read(
            "9",
            {
                "FingerPrintInfo": {
                    "status": "OK",
                    "FingerPrintList": [{"fingerPrintID": 1, "fingerData": "===="}],
                }
            },
        )
    with pytest.raises(FpReadError, match="not clean base64"):
        parse_fingerprint_read(
            "9",
            {
                "FingerPrintInfo": {
                    "status": "OK",
                    "FingerPrintList": [{"fingerPrintID": 1, "fingerData": "!!!not-b64!!!"}],
                }
            },
        )
    raw, digest = decode_template(TPL_B64, employee_no="9")
    assert raw == TPL_BYTES and digest == TPL_SHA


def test_read_seam_sends_the_captured_cond_and_a_raising_reader_is_never_a_zero() -> None:
    """The read-before/after body carries the captured wrapper keys (fpIndex included —
    the capture's body carries it) and a transport explosion is an FpReadError, never
    'this person has no fingerprint'."""
    sent: list[dict] = []

    def capture_reader(body: Any) -> dict:
        sent.append(json.loads(json.dumps(body)))
        raise RuntimeError("socket died")

    with pytest.raises(FpReadError, match="never 'no fingerprint'"):
        read_fingerprint_template("9", capture_reader)
    cond = sent[0]["FingerPrintCond"]
    assert set(cond) == {"searchID", "employeeNo", "fpIndex", "dataType"}
    assert cond["dataType"] == "template"


# --- the progress surface: the honest word, pulled only where it is earned -------------------


def test_progress_words_are_verbatim_and_classify_other() -> None:
    """`errorMsg:"1"` is not a code we own — it rides the report verbatim. The progress
    vocabulary has never been mapped by any capture, so EVERY answer is OTHER (§1 caps
    as vocabulary, §5 step 3)."""
    progress = parse_fingerprint_progress(FP_CAPTURE_PROGRESS)
    assert progress.rejected and progress.recv_status == (5,) and progress.error_msg == ("1",)
    kind, words = classify_progress_rejection(progress)
    assert kind is RejectKind.OTHER
    assert "cardReaderRecvStatus=5" in words and "errorMsg=1" in words
    assert "reader refused" in words  # the OBSERVED note, quoted not invented
    unknown = parse_fingerprint_progress(
        {
            "FingerPrintStatus": {
                "StatusList": [{"cardReaderRecvStatus": 3, "errorMsg": "?"}],
                "totalStatus": 1,
            }
        }
    )
    kind3, words3 = classify_progress_rejection(unknown)  # never-observed value stays verbatim
    assert kind3 is RejectKind.OTHER and "cardReaderRecvStatus=3" in words3


def test_progress_budget_is_one_call_and_only_on_the_failure_path(tmp_path: Path) -> None:
    """§5.3's per-person worst case: the progress probe is spent ONLY where the write
    did not land. A confirming phase must leave the progress route unpolled — the fake
    hard-fails an unearned poll, so if this test runs green the budget rule held."""
    device = fp_device(fp_applies=True)
    journal = fp_journal(tmp_path)
    seam = FpSeam(client_for(device), journal=journal)
    result = run_fingerprints_phase(
        BudgetedWriteTransport(lambda: seam), journal, [write_for("9")], reader_for(device)
    )
    assert result.progress_reads == 0 and seam.progress_reads == 0
    assert device.requests_to("GET", PROGRESS_URL) == 0


# --- planning (bundle-only; the target is read fresh at execution) ---------------------------


def test_unavailable_index_refuses_everything_as_never_read(tmp_path: Path) -> None:
    """§0.7: an index that never ran is NOT a zero — nothing is portable."""
    writes, skipped = plan_fingerprint_writes(
        bundle_dir=tmp_path,
        fingerprints=FingerprintIndex(),  # defaults UNAVAILABLE
        employee_nos=["1", "2"],
    )
    assert writes == ()
    assert skipped[0][0] == "*" and "not a zero" in skipped[0][1]


def test_missing_family_note_is_refused_and_family_rides_every_line(tmp_path: Path) -> None:
    """Card rule 5 (§1): a template with no sensor-family NOTE is REFUSED — we will not
    port bytes whose family we cannot even state. With a note, the claim is CLAIMED
    (never MATCHED) and the family string travels on every report line."""
    entries = (fp_entry("1"), fp_entry("2", sensor_family=""))
    bundle = bundle_with(tmp_path, *entries)
    writes, skipped = plan_fingerprint_writes(
        bundle_dir=bundle, fingerprints=index_of(*entries), employee_nos=["1", "2"]
    )
    assert [w.employee_no for w in writes] == ["1"]
    assert writes[0].sensor_family == FAMILY_NOTE
    assert writes[0].family is SensorFamily.CLAIMED
    assert skipped[0][1].startswith("family_refused") and "no sensor-family NOTE" in skipped[0][1]
    decision = family_decision(entries[1], None)
    assert decision.kind is SensorFamily.ABSENT
    assert "REFUSED" in decision.reason.upper()


def test_plan_is_device_free_and_refuses_digest_drift(tmp_path: Path) -> None:
    """The plan pass opens NO connection (freshness contract §4: the target is read at
    EXECUTION time only) and refuses a bundle whose .b64 no longer matches its INDEX —
    a rollback source that cannot vouch for its bytes is refused, not ported."""
    entry = fp_entry("1")
    bundle = bundle_with(tmp_path, entry)
    # Swap the file's content for a DIFFERENT template (same valid base64 discipline):
    # the INDEX sha/length no longer vouch for the bytes on disk.
    path = bundle / "fingerprints" / "1-0.b64"
    path.write_text(OTHER_B64, encoding="ascii")
    writes, skipped = plan_fingerprint_writes(
        bundle_dir=bundle, fingerprints=index_of(entry), employee_nos=["1"]
    )
    assert writes == ()
    assert skipped[0][1].startswith("bundle_digest_drift")
    # Missing file: unreadable is a skip, not a crash.
    path.unlink()
    _w, skipped2 = plan_fingerprint_writes(
        bundle_dir=bundle, fingerprints=index_of(entry), employee_nos=["1"]
    )
    assert skipped2[0][1].startswith("bundle_unreadable")


def test_plan_refuses_an_unrecorded_slot_immediately() -> None:
    """fingerPrintID != 1 (the captured constant) is a shape error at the door — the
    phase writes no slot no capture ever read."""
    with pytest.raises(FpShapeError, match="unrecorded slot"):
        plan_fingerprint_writes(
            bundle_dir=Path("/nonexistent"),
            fingerprints=FingerprintIndex(state="AVAILABLE", reason=""),
            employee_nos=[],
            finger_print_id=2,
        )


# --- §6 verify: re-read by sha; mismatch after an ack is terminal -----------------------------


def test_verify_verdicts_come_from_reads_never_from_acks(tmp_path: Path) -> None:
    """After an acked-and-applied write: confirmed. After an ack the device never
    applied: MISSING (terminal — the bench-A result made structural). A foreign
    template: MISMATCH (terminal). A failing read: UNREADABLE, never collapsed into
    missing (§0.7)."""
    journal = fp_journal(tmp_path)
    write = write_for("9")

    report = verify_fingerprints(
        journal=journal,
        writes=[write],
        reader=_reader_returning(
            {
                "FingerPrintInfo": {
                    "status": "OK",
                    "FingerPrintList": [{"fingerPrintID": 1, "fingerData": TPL_B64}],
                }
            }
        ),
    )
    assert report.items[0].verdict is FpVerdictKind.CONFIRMED and not report.terminal

    report = verify_fingerprints(
        journal=journal, writes=[write], reader=_reader_returning(FP_CAPTURE_READBACK)
    )  # the capture: NoFP after the ack
    assert report.items[0].verdict is FpVerdictKind.MISSING and report.terminal
    assert "accepted-not-applied" in report.items[0].note

    report = verify_fingerprints(
        journal=journal,
        writes=[write],
        reader=_reader_returning(
            {
                "FingerPrintInfo": {
                    "status": "OK",
                    "FingerPrintList": [{"fingerPrintID": 1, "fingerData": OTHER_B64}],
                }
            }
        ),
    )
    assert report.items[0].verdict is FpVerdictKind.MISMATCH and report.terminal

    def raise_reader(_body: Any) -> dict:
        raise RuntimeError("device unreachable")

    report = verify_fingerprints(journal=journal, writes=[write], reader=raise_reader)
    assert report.items[0].verdict is FpVerdictKind.UNREADABLE and not report.terminal
    assert "never verdicted as missing" in report.items[0].note
    # Every verify line carries the family note (card rule 5) and reports HASHES only
    # (§4): the summary JSON names no raw employee number, and says ack-is-not-confirm.
    summary = report.summary()
    assert summary["items"][0]["sensorFamily"] == FAMILY_NOTE
    assert summary["items"][0]["employee"] == person_hash("9")
    assert all("employeeNo" not in item for item in summary["items"])
    assert "ackIsNotConfirm" in summary


def _reader_returning(payload: dict):
    def read(_body: Any) -> dict:
        return payload

    return read


# --- composed phase ---------------------------------------------------------------------------


def test_apply_reports_terminal_verify_on_the_bench_a_reality(tmp_path: Path) -> None:
    """The composed run on bench-A reality: the abort surfaces AND verify still runs —
    the operator's next question is exactly `what is actually on the device`, and the
    honest answer is MISSING/terminal, not a silent partial success."""
    device = fp_device()
    seam_holder: list[FpSeam] = []

    def factory() -> FpSeam:
        seam_holder.append(FpSeam(client_for(device)))
        return seam_holder[-1]

    with pytest.raises(FpAbortedError) as raised:
        apply_fingerprints_phase(
            writes=[write_for("9")],
            skipped=(),
            transport_factory=factory,
            reader=reader_for(device),
            journal_path=tmp_path / "fp.jsonl",
        )
    report = raised.value.result
    assert isinstance(report, FpFleetReport)
    assert report.verify.terminal
    assert report.verify.items[0].verdict is FpVerdictKind.MISSING
    assert report.writes.aborted
    assert seam_holder[0].closed == 1  # one client per phase, closed at the end (§5.3)
    as_dict = report.as_dict()
    assert as_dict["undo"]["mode"] == "report_only"
    assert "manual removal at the device" in as_dict["undo"]["action"]
    assert any("TERMINAL verify" in note for note in report.notes)


def test_apply_confirms_end_to_end_on_a_same_family_target(tmp_path: Path) -> None:
    """applies=True target: write → post-read sha match → confirmed → verify re-reads and
    AGREES (confirmed count survives verify; nothing is terminal)."""
    device = fp_device(fp_applies=True)

    def factory() -> FpSeam:
        return FpSeam(client_for(device))

    report = apply_fingerprints_phase(
        writes=[write_for("9")],
        skipped=(),
        transport_factory=factory,
        reader=reader_for(device),
        journal_path=tmp_path / "fp.jsonl",
    )
    assert report.writes.confirmed == (person_hash("9"),)
    assert report.verify.items[0].verdict is FpVerdictKind.CONFIRMED
    assert not report.verify.terminal and not report.writes.aborted
    assert "ackIsNotConfirm" in report.as_dict()["writes"]


def test_ledger_and_fakes_counters_agree_across_re_bootstraps(tmp_path: Path) -> None:
    """§5.3: our budget ledger, the seams' per-client counts, and the fake's OWN
    authed-request counters must all tell the same story — five writes over a 2-call
    client budget = 5 downloads, 3 clients, 2 re-bootstraps, and reads stay on the
    read client (before+after per person), progress stays at zero."""
    device = fp_device(fp_applies=True)
    made: list[FpSeam] = []

    def factory() -> FpSeam:
        made.append(FpSeam(client_for(device)))
        return made[-1]

    budgeted = BudgetedWriteTransport(factory, limit=2)
    result = run_fingerprints_phase(
        budgeted,
        fp_journal(tmp_path),
        [write_for(str(n)) for n in range(1, 6)],
        reader_for(device),
    )
    assert result.writes_sent == 5 and result.confirmed and budgeted.total_calls == 5
    assert budgeted.rebootstraps == 2 and len(made) == 3
    assert max(len(seam.downloads) for seam in made) == 2
    assert device.authorized_requests_to("POST", DOWNLOAD_URL) == 5
    assert device.authorized_requests_to("POST", UPLOAD_URL) == 10  # 2 reads per person
    assert REBOOTSTRAP_AT_AUTHED_CALLS == 80  # the shared §5.3 constant, un-forked


# --- no FP delete verb exists, on either side --------------------------------------------------


def test_no_delete_verb_is_reachable_from_the_module() -> None:
    """The card's grep-style pin, two-sided. Product side: no *PATH constant names a
    delete, no delete-mode body shape exists, and the ONLY undo name is report-only.
    (The word 'delete' appears in this module's PROSE precisely to say it was never
    captured — the pin is on verbs and shapes, not on dictionary suppression.)"""
    import gateclerk.migrate_fingerprints as module

    paths = [getattr(module, name) for name in dir(module) if name.endswith("_PATH")]
    assert paths and not any("elete" in p for p in paths), paths
    source = Path(module.__file__).read_text()
    assert '"mode": "delete"' not in source and "'mode': 'delete'" not in source
    assert ".delete(" not in source and '"DELETE"' not in source and "'DELETE'" not in source
    undoish = [name for name in module.__all__ if "undo" in name.lower()]
    assert undoish and all("report_only" in name.lower() for name in undoish)


def test_the_fake_hard_refuses_any_fingerprint_delete_verb() -> None:
    """Device side of the same pin: FingerPrintCfg GET/POST and the delete caps are
    notSupport (OBSERVED), so a DELETE against the family gets a HARD protocol error —
    never a plausible answer a rollback feature could build on. FP undo stays
    'manual removal at the device' (§5b.1)."""
    device = fp_device()
    for path in (
        "/ISAPI/AccessControl/FingerPrint/1?format=json",
        "/ISAPI/AccessControl/FingerPrintCfg/9?format=json",
    ):
        with pytest.raises(EnrollmentProtocolError, match="NO fingerprint delete"):
            raw_request(device, "DELETE", path)
    # The three captured FP paths carry no delete and the undo report requests nothing.
    undo = report_only_fingerprint_undo()
    assert undo["mode"] == "report_only" and "request" not in json.dumps(undo)
    assert "MANUAL AT THE DEVICE" in FP_UNDO_REPORT_ONLY
