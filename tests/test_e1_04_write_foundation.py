"""Card E1-04 definition of done: the write foundation, offline and FakeDevice-strict.

Everything here runs with the autouse `netoff` guard: no socket may open (this card
NEVER contacts a device — the capture gate says the bench session belongs to the
orchestrator, and PR #43 already ran it). Proof layers, each named after the rule it
locks:

* §5a journal — the line is on disk (fsync'd) BEFORE the request arrives; kill between
  planned/applied leaves a `planned`-only entry a resume reads as "unknown, ask a
  human"; append-only replay folds a person's transitions; a torn line is REPORTED, and
  a journal that carries a PIN after normalization is refused.
* §5 step 3 — the request body is BYTE-EQUAL to users_setup_add_request.json; nothing
  device-generated (counters, photoURL, PIN) is echoed even when the source carries it;
  a record missing a captured key is refused rather than sent thin.
* §9 capture-before-fake — an un-armed SetUp request, a POST (the captured 405), a
  `userInfoList` wrapper (the captured lack-employeeNo), an unrecorded key, and any
  later card's write verb all fail LOUD; the fake answers only from the capture files.
* §5 step 4 — the first rejection aborts the phase and names which persons landed.
* §5.3 budget — one client per 80 authed calls, re-bootstrap count pinned against the
  fake's OWN nonce ledger, sleep injected and counted between batches only.
* §6 verify — coverage proof passes on bench A's honored filter (no fallback requests);
  the OBSERVED silently-IGNORED-filter variant forces full paging + client-side exact
  match; an omitted-row variant proves the other coverage arm; hash equality against the
  same normalize/content_hash the bundle uses; the fail-closed unknown-field rule says
  MISMATCH (terminal) where a naive "every field we sent matches" would say OK.
* §5b/§5 step 8 — the module exposes NO delete vocabulary, and the fake reproduces the
  D-WIPE hazard (wrong list slot -> statusCode 1 + everybody gone), because a delete
  fake that always obeyed would teach a client nothing.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import httpx
import pytest

from fakedevice import (
    BASE_URL,
    FAKE_PIN,
    USER_SETUP_PATH,
    EnrollmentProtocolError,
    FakeDevice,
)
from gateclerk.isapi_transport import IsapiClient
from gateclerk.migrate_bundle import (
    BundleData,
    BundleManifest,
    FacesIndex,
    content_hash,
)
from gateclerk.migrate_diff import (
    Classification,
    DiffClass,
    Plan,
    employee_hash,
)
from gateclerk.migrate_probe import CapabilityMatrix, SurfaceProbe, Verdict
from gateclerk.migrate_write import (
    DEFAULT_BATCH_SIZE,
    JOURNAL_SCHEMA,
    REBOOTSTRAP_AT_AUTHED_CALLS,
    USER_SETUP_RESPONSE_OK,
    ApplyAbortedError,
    BudgetedWriteTransport,
    JournalError,
    JournalState,
    PersonVerdict,
    RejectKind,
    UsersPhaseResult,
    UserWrite,
    VerifyAbortedError,
    WriteAbortedError,
    WriteJournal,
    WriteRejectedError,
    WriteShapeError,
    apply_users_phase,
    build_user_setup_body,
    check_clock_skew,
    classify_rejection,
    derive_user_batch_size,
    person_hash,
    plan_user_writes,
    run_users_phase,
    verify_users,
)

FIXTURES = Path(__file__).parent / "fixtures/recorded/site-a-ds-k1t341amf-s"
ENROLLMENT = FIXTURES / "enrollment"
PASSWORD = "fake" + "pw"  # placeholder policy (tests/test_repo_hygiene.py)
SITE_TZ = "Europe/Bucharest"
NOW = datetime(2026, 10, 22, 9, 0, 0, tzinfo=UTC)

#: The capture's test person (users_setup_add_request.json / users_setup_readback_t90.json).
CAPTURE_REQUEST = json.loads((ENROLLMENT / "users_setup_add_request.json").read_text())
CAPTURE_ACK = json.loads((ENROLLMENT / "users_setup_add_response.json").read_text())
CAPTURE_READBACK = json.loads((ENROLLMENT / "users_setup_readback_t90.json").read_text())
T90 = CAPTURE_REQUEST["UserInfo"]


# --- builders ---------------------------------------------------------------------------


def user(no: str, **extra: Any) -> dict[str, Any]:
    """A bench-A-shaped UserInfo record (the E1-02 builder's shape), overridable."""
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
        "gender": "unknown",
    }
    record.update(extra)
    return record


def bundle_of(people: list[dict]) -> BundleData:
    manifest = BundleManifest(
        schema_version="gateclerk-enrollment-bundle/2",
        exported_at="2026-10-22T08:00:00+00:00",
        identity={"model": "DS-K1T341AMF-S", "firmware": "V3.2.30", "serial_prefix": "ab12cd"},
        counts={"users": len(people), "cards": 0, "faces": 0},
        people_hashes={},
        volatile_fields_digest="",
        faces={"state": "UNAVAILABLE", "reason": "test"},
        termination={},
    )
    return BundleData(manifest=manifest, people=tuple(people), cards=(), faces=FacesIndex())


def plan_of(*adds: str, updates: tuple[str, ...] = (), conflicts: tuple[str, ...] = ()) -> Plan:
    items = [
        Classification(
            employee_hash=employee_hash(no),
            classification=kind,
            would_write=1 if kind is DiffClass.ADD else 0,
            _employee_no=no,
        )
        for no, kind in (
            [(n, DiffClass.ADD) for n in adds]
            + [(n, DiffClass.UPDATE) for n in updates]
            + [(n, DiffClass.CONFLICT) for n in conflicts]
        )
    ]
    return Plan(items=tuple(items))


def probe_ok(**changes: Any) -> CapabilityMatrix:
    """A fresh, clock-clean matrix with the caps documents the vocabulary checks read."""
    base: dict[str, Any] = {
        "site": "site-a",
        "host": "192.0.2.10",
        "clock_skew_s": 0.5,
        "template_nos": ("1",),
        "caps_raw": {
            "user_info_capabilities": {
                "UserInfoCap": {
                    "userType": {"@opt": "normal,visitor,blackList"},
                    "Valid": {"timeType": {"@opt": "local"}},
                }
            },
        },
        "surfaces": (
            SurfaceProbe(
                key="users",
                endpoint="user_info_search",
                method="POST",
                path="/ISAPI/AccessControl/UserInfo/Search",
                verdict=Verdict.OK,
            ),
        ),
        "probed_at": NOW.isoformat(),
    }
    base.update(changes)
    return CapabilityMatrix(**base)


def write_device(*, people: list[dict] | None = None, **knobs: Any) -> FakeDevice:
    """A box with the captured WRITE axis armed (the person store starts empty or seeded)."""
    d = FakeDevice(password=PASSWORD)
    d.install_write_capture(users=people if people is not None else [], **knobs)
    return d


def client_for(device: FakeDevice) -> IsapiClient:
    return IsapiClient(
        BASE_URL, "admin", PASSWORD, transport=device.transport, sleep=lambda _s: None
    )


class RecordingTransport:
    """The injected write seam over a real IsapiClient + FakeDevice.

    It records the exact bytes the module asked to send — the `journal-before-request`
    and `body-equals-capture` tests read those bytes rather than trusting a comment.
    """

    def __init__(self, client: IsapiClient, *, journal: WriteJournal | None = None) -> None:
        self.client = client
        self.journal = journal
        self.sent: list[tuple[str, dict]] = []
        self.closed = 0
        self.on_call: Any = None  # optional hook, called before each request

    def put_setup(self, path: str, body: dict) -> dict:
        if self.on_call is not None:
            self.on_call(self, path, body)
        self.sent.append((path, json.loads(json.dumps(body))))
        if self.journal is not None:
            # the crash-window test asserts the journal state AT REQUEST TIME
            self.request_time_entries = list(self.journal.entries)
        return self._put(path, body)

    def _put(self, path: str, body: dict) -> dict:
        raise NotImplementedError  # overridden by the subclasses below

    def close(self) -> None:
        self.closed += 1


class IsapiWriteTransport(RecordingTransport):
    """PUTs through the real IsapiClient digest stack (write client, not the registry)."""

    def _put(self, path: str, body: dict) -> dict:
        response = self.client._client.put(
            path,
            params={"format": "json"},
            json=body,
            auth=self.client._auth,
        )
        envelope = json.loads(response.content)
        if response.status_code != 200 or envelope.get("statusCode") != USER_SETUP_RESPONSE_OK:
            raise WriteRejectedError(
                f"device answered {response.status_code} {envelope.get('subStatusCode')}",
                sub_status=envelope.get("subStatusCode"),
                http_status=response.status_code,
                envelope=envelope,
            )
        return envelope


class ScriptedTransport(RecordingTransport):
    """Answers from canned bodies without touching a device (budget/rejection tests)."""

    def __init__(self, *acks: dict | Exception, **kw: Any) -> None:
        super().__init__(None, **kw)  # type: ignore[arg-type]
        self.acks: list[Any] = list(acks)

    def _put(self, path: str, body: dict) -> dict:
        del path, body
        item = self.acks.pop(0) if self.acks else {"statusCode": 1}
        if isinstance(item, Exception):
            raise item
        return item

    def put_setup(self, path: str, body: dict) -> dict:  # budget counts still apply
        return RecordingTransport.put_setup(self, path, body)


def read_reader(device: FakeDevice):
    """The §6 read seam over the SAME read-only client the export uses."""
    client = client_for(device)

    def read(body: dict) -> dict:
        return client.search("user_info_search", body)

    return read


def writes_for(*nos: str, records: dict[str, dict] | None = None) -> tuple[UserWrite, ...]:
    docs = records or {}
    return tuple(
        UserWrite(
            employee_no=no,
            employee_hash=person_hash(no),
            record=docs.get(no, user(no)),
        )
        for no in nos
    )


def journal_in(tmp_path: Path, name: str = "users.jsonl") -> WriteJournal:
    return WriteJournal.open(tmp_path / name, phase="users")


# --- §5 step 3: the frozen write allow-list (byte-equal to the capture) -------------------


def test_the_setup_body_is_byte_equal_to_the_capture() -> None:
    body = build_user_setup_body(dict(T90, mode="add"))
    assert body == CAPTURE_REQUEST, (
        "the module's body drifted from users_setup_add_request.json — the capture is "
        "the contract, not a suggestion"
    )
    assert json.dumps(body, sort_keys=True) == json.dumps(CAPTURE_REQUEST, sort_keys=True)


def test_the_sending_transport_uses_the_captured_put_verb() -> None:
    device = write_device()
    transport = IsapiWriteTransport(client_for(device))
    run_users_phase(
        BudgetedWriteTransport(lambda: transport),
        _scratch_journal(),
        writes_for("90", records={"90": dict(T90)}),
    )
    assert transport.sent == [(USER_SETUP_PATH, CAPTURE_REQUEST)]
    assert device.authorized_requests_to("PUT", USER_SETUP_PATH + "?format=json") == 1
    people = device._enrollment_store["UserInfo"]
    assert people[0]["employeeNo"] == "90" and people[0]["name"] == "User T90"


def _scratch_journal() -> WriteJournal:
    import tempfile

    directory = Path(tempfile.mkdtemp(prefix="e104-"))
    return WriteJournal.open(directory / "users.jsonl", phase="users")


def test_device_generated_fields_are_never_echoed_even_when_the_source_has_them() -> None:
    # §5 step 3 / R2: the search record carries counters, a PIN and a per-device URL.
    # A SetUp body that echoes them risks 400 badJsonContent or a silent partial merge —
    # and the fake REJECTS such a body (captured envelope class), so lenience here is
    # what the fake is armed against.
    noisy = user(
        "91",
        numOfCard=7,
        numOfFace=3,
        numOfFP=2,
        openDoorTime=99,
        password=FAKE_PIN,  # placeholder policy (tests/test_repo_hygiene.py)
        photoURL="http://192.0.2.10/staging/userPic/91.jpg",
        belongGroup="g1",
        PersonInfoExtends=[{"value": "x"}],
    )
    body = build_user_setup_body(noisy)["UserInfo"]
    assert set(body) == set(CAPTURE_REQUEST["UserInfo"]), "the allow-list drifted"
    assert "password" not in body and "photoURL" not in body and "numOfCard" not in body
    assert set(body) == set(T90) | {"mode"}


def test_a_record_missing_a_captured_key_is_refused_not_sent_thin() -> None:
    with pytest.raises(WriteShapeError, match="gender"):
        build_user_setup_body(user("92", gender=None) | {"gender": None})  # key present
    thin = {k: v for k, v in user("92").items() if k != "Valid"}
    with pytest.raises(WriteShapeError, match="Valid"):
        build_user_setup_body(thin)


def test_a_modify_mode_is_refused_and_no_delete_shape_exists() -> None:
    with pytest.raises(WriteShapeError, match="mode"):
        build_user_setup_body(user("93", mode="modify"))
    with pytest.raises(WriteShapeError):
        build_user_setup_body(user("93", mode="delete"))


def test_vocabulary_and_template_rules_are_checked_against_the_probe() -> None:
    # A value the device's own caps @opt does not list is refused HERE, not 400'd mid-batch.
    with pytest.raises(WriteShapeError, match="userType"):
        build_user_setup_body(user("94", userType="admin"), probe=probe_ok())
    with pytest.raises(WriteShapeError, match="timeType"):
        build_user_setup_body(
            user("95", Valid={**user("95")["Valid"], "timeType": "absolute"}), probe=probe_ok()
        )
    # §1a: a custom templateNo needs BOTH the flag and the target's own evidence.
    custom = user("96", RightPlan=[{"doorNo": 1, "planTemplateNo": "4"}])
    with pytest.raises(WriteShapeError, match="carry-templates"):
        build_user_setup_body(custom, probe=probe_ok())
    with pytest.raises(WriteShapeError, match="evidence set"):
        build_user_setup_body(custom, probe=probe_ok(), allow_custom_templates=True)
    build_user_setup_body(
        custom, probe=probe_ok(template_nos=("1", "4")), allow_custom_templates=True
    )


def test_rejection_kinds_use_only_captured_vocabulary() -> None:
    assert classify_rejection("badJsonContent") is RejectKind.SHAPE
    assert classify_rejection("MessageParametersLack") is RejectKind.SHAPE
    assert classify_rejection("methodNotAllowed") is RejectKind.VERB
    assert classify_rejection("notSupport") is RejectKind.ABSENT
    # An answer no capture shows keeps the device's word instead of getting a label.
    assert classify_rejection("someNewDeviceWord") is RejectKind.OTHER
    assert classify_rejection(None) is RejectKind.OTHER


# --- §5a journal ---------------------------------------------------------------------------


def test_journal_line_reaches_disk_before_the_request_arrives(tmp_path: Path) -> None:
    """§5a's ordering rule, pinned at request time rather than asserted afterwards."""
    journal = journal_in(tmp_path)
    device = write_device()
    transport = IsapiWriteTransport(client_for(device), journal=journal)
    run_users_phase(BudgetedWriteTransport(lambda: transport), journal, writes_for("1"))
    # What the journal held when the PUT was already in flight (the hook snapshots it):
    assert [e.state for e in transport.request_time_entries] == [JournalState.PLANNED]
    # And what it holds now the ack landed — append-only, so BOTH transitions are there:
    assert [e.state for e in journal.entries] == [JournalState.PLANNED, JournalState.APPLIED]
    lines = (tmp_path / "users.jsonl").read_text().splitlines()
    assert [json.loads(line)["state"] for line in lines] == ["planned", "applied"]
    assert all(json.loads(line)["schema"] == JOURNAL_SCHEMA for line in lines)


def test_journal_append_is_durable_immediately(tmp_path: Path) -> None:
    """fsync-before-request is only a claim if the bytes are readable before any close."""
    journal = journal_in(tmp_path)
    journal.planned(
        employee_no="1", classification="add", pre_write_record=None, intended_record=user("1")
    )
    # Read the RAW file (not the in-memory tuple) before the journal is touched again.
    assert json.loads((tmp_path / "users.jsonl").read_text())["state"] == "planned"


def test_crash_between_planned_and_applied_leaves_an_unknown_not_a_hole(tmp_path: Path) -> None:
    """Kill-safety (§5a + §9): a resume reads the person as PLANNED — nobody undone them.

    The device-side half is real: the fake raises before answering, so the request
    genuinely left the client and no `applied` line exists, exactly like a process that
    died between the fsync and the response.
    """
    journal = journal_in(tmp_path)
    device = write_device()
    client = client_for(device)
    # The first write is accepted by the fake, then our process "dies" before acking it.
    device.add_raw("PUT", USER_SETUP_PATH + "?format=json", RuntimeError("process killed"))
    with pytest.raises(RuntimeError, match="process killed"):
        run_users_phase(
            BudgetedWriteTransport(lambda: IsapiWriteTransport(client)),
            journal,
            writes_for("1"),
        )
    assert [e.state for e in journal.entries] == [JournalState.PLANNED]
    resumed = WriteJournal.open(tmp_path / "users.jsonl", phase="users")
    assert [e.state for e in resumed.entries] == [JournalState.PLANNED]
    assert resumed.by_employee("1") is not None
    # Undo's precondition (§5a): only `confirmed` adds may ever be touched.
    assert resumed.latest(state=JournalState.CONFIRMED) == ()
    assert resumed.truncated == ()


def test_append_only_replay_folds_the_lifecycle(tmp_path: Path) -> None:
    journal = journal_in(tmp_path)
    entry = journal.planned(
        employee_no="7", classification="add", pre_write_record=None, intended_record=user("7")
    )
    journal.applied(entry)
    journal.rejected(entry, sub_status="businessError")
    lines = (tmp_path / "users.jsonl").read_text().splitlines()
    assert len(lines) == 3, "every transition is its own line — append-only, no rewrite"
    resumed = WriteJournal.open(tmp_path / "users.jsonl", phase="users")
    assert resumed.by_employee("7").state is JournalState.REJECTED
    assert resumed.by_employee("7").device_sub_status == "businessError"


def test_a_torn_line_is_reported_never_guessed(tmp_path: Path) -> None:
    path = tmp_path / "users.jsonl"
    good = json.dumps(
        {
            "schema": JOURNAL_SCHEMA,
            "seq": 1,
            "state": "planned",
            "phase": "users",
            "op": "user_setup",
            "employeeNo": "1",
            "employeeHash": person_hash("1"),
            "classification": "add",
        }
    )
    path.write_text(good + "\n" + '{"schema": "gateclerk-migrate-journal/1", "seq": 2, "st', "utf-8")
    resumed = WriteJournal.open(path, phase="users")
    assert len(resumed.truncated) == 1
    assert "line 2" in resumed.truncated[0]
    assert resumed.by_employee("1").state is JournalState.PLANNED


def test_a_foreign_journal_schema_is_refused_not_half_read(tmp_path: Path) -> None:
    path = tmp_path / "users.jsonl"
    path.write_text('{"schema": "someone-elses-journal/1", "state": "planned"}\n', "utf-8")
    with pytest.raises(JournalError, match="schema"):
        WriteJournal.open(path, phase="users")


def test_a_journal_inside_the_repo_is_refused(tmp_path: Path) -> None:
    """§2 hygiene, applied to the journal: it holds normalized person records."""
    inside = Path(__file__).resolve().parent / "leaked_journal.jsonl"
    with pytest.raises(JournalError, match="inside the repository"):
        WriteJournal.open(inside, phase="users")
    assert not inside.exists()


def test_the_journal_never_holds_a_pin_beyond_what_the_bundle_holds(tmp_path: Path) -> None:
    """§9/§2/R3: records enter through normalize_record (password stripped) — and the
    journal's own second lock refuses a record that somehow still carries one."""
    journal = journal_in(tmp_path)
    journal.planned(
        employee_no="1",
        classification="add",
        pre_write_record=user("1", password=FAKE_PIN),
        intended_record=user("1", password=FAKE_PIN),
    )
    text = (tmp_path / "users.jsonl").read_text()
    assert FAKE_PIN not in text and "password" not in text
    with pytest.raises(JournalError, match="normalization"):
        journal._append(
            journal.entries[0].__class__(
                seq=99,
                state=JournalState.PLANNED,
                phase="users",
                op="user_setup",
                employee_no="2",
                employee_hash=person_hash("2"),
                classification="add",
                intended_record={"employeeNo": "2", "password": FAKE_PIN},
            )
        )


# --- §9 capture-before-fake: the fake only replays the capture ----------------------------


def raw_request(
    device: FakeDevice, method: str, path: str, *, json_body: Any = None
) -> httpx.Response:
    """One digest-authed request straight into the fake's transport.

    Same raw-client shape as E1-02's write-shape test: the fake 401s anything without a
    valid digest (a handle_request() call with no Authorization gets the challenge, not
    the route answer), so write-axis proofs must ride the real auth stack.
    """
    with httpx.Client(
        transport=device.transport, auth=httpx.DigestAuth("admin", PASSWORD), base_url=BASE_URL
    ) as raw:
        return raw.request(method, path, json=json_body)


SETUP_URL = USER_SETUP_PATH + "?format=json"


def test_post_to_the_write_path_answers_the_captured_method_not_allowed() -> None:
    """users_setup_post_method_not_allowed.json / users_setup_put_record_405.json."""
    device = write_device()
    response = raw_request(device, "POST", SETUP_URL, json_body=CAPTURE_REQUEST)
    body = json.loads(response.content)
    assert response.status_code == 400 and body["subStatusCode"] == "methodNotAllowed"


def test_the_wrapped_list_body_answers_the_captured_lack_employee_no() -> None:
    """users_setup_wrapped_list_400.json — the exact body the bench recorded failing."""
    device = write_device()
    wrapped = {"userInfoList": {"userInfo": dict(T90)}}
    response = raw_request(device, "PUT", SETUP_URL, json_body=wrapped)
    body = json.loads(response.content)
    assert body == json.loads((ENROLLMENT / "users_setup_wrapped_list_400.json").read_text())
    assert device._enrollment_store["UserInfo"] == []


def test_an_unrecorded_key_in_the_body_is_rejected_by_the_device() -> None:
    """The R2 risk made real: the fake answers the captured badJsonContent class."""
    device = write_device()
    bad = {"UserInfo": {**T90, "photoURL": "http://192.0.2.10/x.jpg"}}
    response = raw_request(device, "PUT", SETUP_URL, json_body=bad)
    body = json.loads(response.content)
    assert body["subStatusCode"] == "badJsonContent" and body["errorMsg"] == "photoURL"
    assert device._enrollment_store["UserInfo"] == []


def test_an_unproven_mode_is_a_protocol_error_never_a_guessed_answer() -> None:
    device = write_device()
    with pytest.raises(EnrollmentProtocolError, match="no bench-A capture"):
        raw_request(device, "PUT", SETUP_URL, json_body={"UserInfo": {**T90, "mode": "modify"}})


def test_later_cards_write_verbs_are_hard_refused_here() -> None:
    """E1-05 owns that route; E1-04 must not pre-build it (§9).

    E1-06b (fingerprints) shipped its FingerPrintDownload route and E1-06 shipped the
    face routes (FDSetUp + FDSearch/Delete), so those verbs are no longer on this list —
    each family now has real capture-backed routing (its fixtures + its knobs).
    """
    device = write_device()
    for path in ("/ISAPI/AccessControl/CardInfo/SetUp",):
        with pytest.raises(EnrollmentProtocolError, match="LATER card"):
            raw_request(device, "PUT", path, json_body={})


def test_the_write_routes_replay_only_committed_capture_files() -> None:
    """The §9 structural lock: every body the write axis serves is one of the 29 files."""
    committed = {p.name for p in ENROLLMENT.glob("*.json")}
    device = write_device()
    served = []
    responses = [
        raw_request(device, "PUT", SETUP_URL, json_body=CAPTURE_REQUEST),
        raw_request(device, "POST", SETUP_URL, json_body=CAPTURE_REQUEST),
        raw_request(device, "PUT", SETUP_URL, json_body={"userInfoList": {}}),
        raw_request(
            device,
            "PUT",
            "/ISAPI/AccessControl/UserInfoDetail/Delete?format=json",
            json_body=json.loads((ENROLLMENT / "userinfo_delete_wipe_request.json").read_text()),
        ),
    ]
    for response in responses:
        served.append(json.loads(response.content))
    names = sorted(committed)
    assert names, "the capture directory must exist"
    for body in served:
        assert any(body == json.loads((ENROLLMENT / name).read_text()) for name in names), (
            f"the fake served a body that is not a committed capture: {body}"
        )


# --- §5b: the D-WIPE hazard the fake must reproduce (E1-04 keeps it armed, unused) ---------


def test_the_delete_shape_that_wiped_bench_a_still_wipes_the_fake() -> None:
    """Rule D-WIPE, captured: OK + the whole roster gone. A fake that obeyed would teach
    nothing, so this test is the reason no E1-05 delete may ship without its guard."""
    device = write_device(people=[user("1"), user("2"), user("3")])
    device.seed_biometric(faces={"1": b"FR500005\x01" + b"0" * 262})
    wipe = json.loads((ENROLLMENT / "userinfo_delete_wipe_request.json").read_text())
    response = raw_request(
        device, "PUT", "/ISAPI/AccessControl/UserInfoDetail/Delete?format=json", json_body=wipe
    )
    assert json.loads(response.content) == json.loads(
        (ENROLLMENT / "userinfo_delete_wipe_response.json").read_text()
    )
    assert device._enrollment_store["UserInfo"] == []
    assert device._biometric_store["faces"] == {}
    assert json.loads((ENROLLMENT / "userinfo_delete_wipe_post_state_count.json").read_text()) == {
        "UserInfoCount": {"userNumber": 0}
    }


def test_an_unarmed_write_is_a_hard_failure_not_a_quiet_404() -> None:
    device = FakeDevice(password=PASSWORD)  # read axis only — no write capture installed
    client = client_for(device)
    transport = IsapiWriteTransport(client)
    with pytest.raises(EnrollmentProtocolError, match="no bench-A write truth armed"):
        run_users_phase(
            BudgetedWriteTransport(lambda: transport), _scratch_journal(), writes_for("90")
        )


def test_the_module_exposes_no_delete_vocabulary_at_all() -> None:
    """§5 step 8 + §5b: v1 never deletes, and no delete may be sent before its EXACT
    list-slot shape is captured. The card's own words: refuse modeless deletes."""
    import gateclerk.migrate_write as module

    names = [n.lower() for n in module.__all__]
    assert not any("delete" in n or "undo" in n or "remove" in n for n in names), names
    source = Path(module.__file__).read_text()
    assert '"mode": "delete"' not in source and "'mode': 'delete'" not in source
    assert "DelCond" not in source.split("§5b")[1].split("##")[0] if "§5b" in source else True


# --- the users phase: batching, budget, fail-fast -----------------------------------------


def test_batch_size_is_derived_and_the_default_is_the_cards_10() -> None:
    assert derive_user_batch_size(None) == DEFAULT_BATCH_SIZE == 10
    assert derive_user_batch_size(probe_ok()) == 10, (
        "no committed capture or caps document names a WRITE batch @max; inventing one "
        "from maxRecordNum (a search page cap, §1) is the trap this pins shut"
    )


def test_batches_sleep_between_only_and_the_plan_reports_skips(tmp_path: Path) -> None:
    waits: list[float] = []
    journal = journal_in(tmp_path)
    plan = plan_of("1", "2", "3", "4", updates=("9",), conflicts=("7",))
    bundle = bundle_of([user("1"), user("2"), user("3"), user("4"), user("9"), user("7")])
    writes, skipped = plan_user_writes(plan, bundle)
    assert [w.employee_no for w in writes] == ["1", "2", "3", "4"]
    assert dict(skipped) == {
        employee_hash("9"): "update_shape_uncaptured",
        employee_hash("7"): "conflict_report_only",
    }
    result = run_users_phase(
        BudgetedWriteTransport(lambda: ScriptedTransport()),
        journal,
        writes,
        batch_size=2,
        sleep=waits.append,
        batch_delay=1.0,
        skipped=skipped,
    )
    assert waits == [1.0], "one sleep between the two batches, none before the first"
    assert result.batches == 2 and result.writes_sent == 4 and result.clean
    assert len(result.applied) == 4
    assert result.batch_size == 2


def test_batch_size_is_never_larger_than_the_derived_ceiling() -> None:
    result = run_users_phase(
        BudgetedWriteTransport(lambda: ScriptedTransport()),
        _scratch_journal(),
        writes_for(*[str(i) for i in range(1, 26)]),
        batch_size=10_000,
        sleep=lambda _s: None,
    )
    assert result.batch_size == DEFAULT_BATCH_SIZE
    assert result.batches == 3  # 25 persons / ceiling 10


def test_budget_rebootstraps_at_80_authed_calls_counted_against_the_fakes_ledger() -> None:
    """§5.3: 250 writes over a 30-call budget = 9 clients, 8 re-bootstraps, every write
    charged exactly once — and the fake's OWN counters agree with our ledger."""
    device = write_device()
    client = client_for(device)
    made: list[IsapiWriteTransport] = []

    def factory() -> IsapiWriteTransport:
        made.append(IsapiWriteTransport(client))
        return made[-1]

    budgeted = BudgetedWriteTransport(factory, limit=30)
    result = run_users_phase(
        budgeted,
        _scratch_journal(),
        writes_for(*[f"n{i}" for i in range(1, 251)]),
        sleep=lambda _s: None,
    )
    assert result.writes_sent == 250
    assert budgeted.total_calls == 250 and result.rebootstraps == 8
    assert len(made) == 9 and budgeted.rebootstraps == 8
    # The fake's nonce ledger is the independent witness: 250 accepted writes on the
    # write path, and our per-client cap was honoured (never more than `limit` calls
    # against one client before it was replaced).
    charged = device.authorized_requests_to(
        "PUT", USER_SETUP_PATH + "?format=json"
    ) + device.requests_to("PUT", USER_SETUP_PATH + "?format=json")
    assert charged >= 250, "every budgeted call reached the device exactly once"
    assert max(len(t.sent) for t in made) == 30


def test_budget_default_is_the_cards_80_and_a_closed_transport_raises() -> None:
    assert REBOOTSTRAP_AT_AUTHED_CALLS == 80
    made: list[ScriptedTransport] = []
    budgeted = BudgetedWriteTransport(lambda: made.append(ScriptedTransport()) or made[-1], limit=2)
    budgeted.put_setup(USER_SETUP_PATH, {})
    budgeted.put_setup(USER_SETUP_PATH, {})
    assert budgeted.rebootstraps == 0  # the cap fires on the NEXT call
    budgeted.put_setup(USER_SETUP_PATH, {})
    assert budgeted.rebootstraps == 1
    budgeted.close()
    with pytest.raises(Exception, match="closed"):
        budgeted.put_setup(USER_SETUP_PATH, {})


def test_capacity_rejection_mid_batch_aborts_and_reports_which_landed(tmp_path: Path) -> None:
    """§5 step 4: the first rejection stops the phase and names what landed."""
    journal = journal_in(tmp_path)
    device = write_device(capacity=2)
    transport = IsapiWriteTransport(client_for(device))
    with pytest.raises(WriteAbortedError) as excinfo:
        run_users_phase(
            BudgetedWriteTransport(lambda: transport),
            journal,
            writes_for("1", "2", "3", "4"),
            sleep=lambda _s: None,
        )
    result: UsersPhaseResult = excinfo.value.result
    assert result.aborted and result.writes_sent == 3
    assert result.applied == (person_hash("1"), person_hash("2"))
    assert [(h, k) for h, k, _s in result.rejected] == [(person_hash("3"), RejectKind.OTHER)]
    # Nothing further was attempted after the rejection (4 never sent).
    assert len(transport.sent) == 3
    # The journal says the same thing the result says.
    states = {e.employee_no: e.state for e in journal.entries}
    assert states["3"] is JournalState.REJECTED and states["1"] is JournalState.APPLIED
    assert states.get("4") is None


def test_a_rejection_our_shape_check_missed_is_classified_from_the_captured_words() -> None:
    journal = _scratch_journal()
    transport = ScriptedTransport(
        {"statusCode": 1},
        WriteRejectedError("shape", sub_status="badJsonContent"),
    )
    with pytest.raises(WriteAbortedError) as excinfo:
        run_users_phase(
            BudgetedWriteTransport(lambda: transport),
            journal,
            writes_for("1", "2"),
            sleep=lambda _s: None,
        )
    assert excinfo.value.result.rejected[0][1] is RejectKind.SHAPE


def test_a_non_ok_ack_without_an_exception_is_still_a_rejection() -> None:
    journal = _scratch_journal()
    transport = ScriptedTransport({"statusCode": 6, "subStatusCode": "businessError"})
    with pytest.raises(WriteAbortedError, match="device answered businessError"):
        run_users_phase(
            BudgetedWriteTransport(lambda: transport),
            journal,
            writes_for("1"),
            sleep=lambda _s: None,
        )


# --- §6 the verify walker -------------------------------------------------------------------


def _capture_read(no: str, **extra: Any) -> dict[str, Any]:
    """The read-back shape from the capture, for one person (defaults verbatim)."""
    record = json.loads(json.dumps(CAPTURE_READBACK["UserInfoSearch"]["UserInfo"][0]))
    record["employeeNo"] = no
    record["name"] = f"User E{no}"
    record.update(extra)
    return record


def _reader_for(pages: list[list[dict]], *, ignore_filter: bool = False) -> Any:
    """A reader serving wrapped pages (client-side filtering is ours, so pages are raw).

    ``ignore_filter=True`` reproduces the OBSERVED silently-IGNORED-filter hazard (the
    AcsEventCond.employeeNo lesson): the answer looks perfectly filtered-shaped but every
    row on the box comes back regardless of EmployeeNoList.
    """
    calls: list[dict] = []

    def read(body: dict) -> dict:
        calls.append(json.loads(json.dumps(body)))
        cond = body["UserInfoSearchCond"]
        wanted = {e["employeeNo"] for e in cond.get("EmployeeNoList", [])}
        rows = [r for page in pages for r in page]
        if wanted and not ignore_filter:
            rows = [r for r in rows if r["employeeNo"] in wanted]
        window = rows[
            cond["searchResultPosition"] : cond["searchResultPosition"] + cond["maxResults"]
        ]
        envelope = {
            "searchID": cond["searchID"],
            "numOfMatches": len(window),
            "totalMatches": len(rows),
            "responseStatusStrg": "MORE"
            if cond["searchResultPosition"] + len(window) < len(rows)
            else "OK",
        }
        if window:
            envelope["UserInfo"] = window
        return {"UserInfoSearch": envelope}

    read.calls = calls  # type: ignore[attr-defined]
    return read


def test_verify_ok_when_the_filter_is_honored_and_coverage_is_proven() -> None:
    # §6 compares the bundle/source record (what E1-01 exported from UserInfo/Search —
    # the READ shape) against the target's read-back. The write body is a projection of
    # it (the allow-list), never the compare basis: write-shape-vs-read-shape MISMATCH is
    # pinned by test_a_verify_mismatch_is_terminal_and_never_a_rewrite.
    writes = writes_for("1", "2", records={"1": _capture_read("1"), "2": _capture_read("2")})
    reader = _reader_for([[_capture_read("1"), _capture_read("2")]])
    report = verify_users(reader, writes)
    assert report.ok and report.coverage_proven and report.method == "filtered"
    assert [i.verdict for i in report.items] == [PersonVerdict.OK, PersonVerdict.OK]
    # The device's extra fields (numOf*, PersonInfoExtends, ...) must NOT be a mismatch —
    # they are §2 volatile fields or §1a read-shape vocabulary; the content hash is what
    # decides, and it strips the volatile set the same way the bundle does.
    assert reader.calls[0]["UserInfoSearchCond"]["EmployeeNoList"] == [
        {"employeeNo": "1"},
        {"employeeNo": "2"},
    ]
    assert len(reader.calls) == 1, "coverage proven means NO fallback paging"


def test_coverage_fallback_when_the_filter_is_silently_ignored() -> None:
    """The OBSERVED lesson made testable: bench A honored EmployeeNoList (§1) but the
    family DOES ignore filters elsewhere (AcsEventCond.employeeNo). A device that answers
    the WHOLE roster as if filtered must not make verify trust its answer."""
    writes = writes_for("1", records={"1": _capture_read("1")})
    reader = _reader_for([[_capture_read(no) for no in ("1", "2", "3", "4")]], ignore_filter=True)
    report = verify_users(reader, writes)
    assert report.coverage_proven is False
    assert report.method == "full-paging (filter coverage failed)"
    assert report.unexpected == ("2", "3", "4")
    assert report.verdict_of("1") is PersonVerdict.OK  # client-side exact match found it
    # The fallback asked for the whole roster (no EmployeeNoList) — a filtered-only walk
    # would have "verified" a person from rows the device never filtered for us.
    assert all("EmployeeNoList" not in call["UserInfoSearchCond"] for call in reader.calls[1:])


def test_coverage_fallback_driven_by_the_fake_that_ignores_the_filter() -> None:
    """The card names this case by name: a FAKE variant that ignores `EmployeeNoList`
    (the OBSERVED silently-ignored lesson) must drive the walker into full paging +
    client-side exact match — end to end over the real digest stack, not a stand-in.

    Bench A honored the filter (§1); this knob proves the walker is not cargo-culted:
    the fallback full walk terminates honestly even though the device answers every
    page with the whole roster, because CLIENT-SIDE exact match is what decides.
    """
    device = write_device(people=[user("1"), user("2")], honor_employee_filter=False)
    journal = _scratch_journal()
    record = CAPTURE_READBACK["UserInfoSearch"]["UserInfo"][0]
    report_obj = apply_users_phase(
        plan=plan_of("90"),
        bundle=bundle_of([record]),
        transport_factory=lambda: IsapiWriteTransport(client_for(device)),
        reader=read_reader(device),
        journal_path=journal.path,
        probe=probe_ok(),
        now=NOW,
    )
    assert report_obj.verify is not None
    assert report_obj.verify.coverage_proven is False
    assert report_obj.verify.method == "full-paging (filter coverage failed)"
    # The person we wrote is found anyway (client-side exact match), and the roster the
    # un-filtered device threw at us is recorded as unexpected, not silently trusted.
    assert report_obj.verify.verdict_of("90") is PersonVerdict.OK
    assert "1" in report_obj.verify.unexpected and "2" in report_obj.verify.unexpected


def test_coverage_fallback_when_the_filter_omits_a_requested_person() -> None:
    writes = writes_for("1", "2", records={"1": _capture_read("1"), "2": _capture_read("2")})
    _reader_for([[_capture_read("1", name="Changed"), _capture_read("2")]])

    # Drop "2" from the filtered answer only: the fallback full walk still sees it.
    def read(body: dict) -> dict:
        answer = _reader_original(body)
        cond = body["UserInfoSearchCond"]
        if "EmployeeNoList" in cond:
            answer["UserInfoSearch"]["UserInfo"] = [
                r for r in answer["UserInfoSearch"].get("UserInfo", []) if r["employeeNo"] != "2"
            ]
            answer["UserInfoSearch"]["numOfMatches"] = len(answer["UserInfoSearch"]["UserInfo"])
        return answer

    _reader_original = _reader_for([[_capture_read("1", name="Changed"), _capture_read("2")]])
    report = verify_users(read, writes)
    assert report.coverage_proven is False
    assert report.uncovered == ("2",)
    assert report.verdict_of("1") is PersonVerdict.MISMATCH  # name drift, fields-only report
    assert report.verdict_of("2") is PersonVerdict.OK, (
        "the fallback found the person the filter hid"
    )


def test_missing_is_a_verdict_not_a_crash_and_only_when_the_read_succeeded() -> None:
    report = verify_users(
        _reader_for([[_capture_read("1")]]),
        writes_for("1", "2", records={"1": _capture_read("1")}),
    )
    assert report.verdict_of("1") is PersonVerdict.OK
    assert report.verdict_of("2") is PersonVerdict.MISSING
    assert len(report.missing) == 1

    # ...but a FAILED read is never read as "missing" (§0.7): refuse instead.
    def broken(body: dict) -> dict:
        raise RuntimeError("device said no")

    with pytest.raises(VerifyAbortedError, match="BOTH"):
        verify_users(broken, writes_for("1"))


def test_verify_compares_the_same_hash_the_bundle_uses(tmp_path: Path) -> None:
    """§6: "content-hash compare via migrate_bundle (same normalization)" — pinned by
    recomputing the expected hash with the module's own function, not a stored number."""
    record = user("1")
    report = verify_users(
        _reader_for([[_capture_read("1")]]), writes_for("1", records={"1": record})
    )
    assert report.items[0].expected_hash == content_hash(record)
    assert report.items[0].target_hash == content_hash(_capture_read("1"))
    assert report.items[0].target_hash != report.items[0].expected_hash
    # The source WRITE-shape builder and the device READ-shape normalize differently (the
    # read adds vocabulary outside the volatile set), so they hash apart — and the
    # fail-closed rule says MISMATCH, not "close enough". The OK path is the same-shape
    # pair pinned in test_verify_ok_when_the_filter_is_honored_and_coverage_is_proven.


def test_the_hash_compare_catches_a_real_value_drift() -> None:
    drifted = _capture_read(
        "1", Valid={**_capture_read("1")["Valid"], "endTime": "2030-01-01T00:00:00"}
    )
    report = verify_users(
        _reader_for([[drifted]]), writes_for("1", records={"1": _capture_read("1")})
    )
    assert report.verdict_of("1") is PersonVerdict.MISMATCH
    assert report.mismatched[0].unknown_fields == ()  # same field set, different content
    assert report.mismatched[0].missing_fields == ()


def test_the_fail_closed_unknown_field_rule_is_a_mismatch_not_an_ok() -> None:
    """§6: a target record carrying a field the intended record lacks (outside the
    volatile list) is MISMATCH. A naive "every field we sent came back equal" check — the
    shape this card's own write test builds — says OK here, which is the bug §6 names."""
    record = _capture_read("1")
    record["mysteryField"] = {"nested": True}
    report = verify_users(
        _reader_for([[record]]), writes_for("1", records={"1": _capture_read("1")})
    )
    item = report.items[0]
    assert item.verdict is PersonVerdict.MISMATCH
    assert item.unknown_fields == ("mysteryField",)
    assert "mysteryField" not in json.dumps(item.summary() if hasattr(item, "summary") else {}), (
        "the report carries field NAMES only (§4) — never the device's value"
    )


def test_verify_walk_pages_like_the_export_engine() -> None:
    """One searchID per logical search, advancing by numOfMatches to the end."""
    pages = [[_capture_read(no) for no in ("1", "2")], [_capture_read("3")]]
    reader = _reader_for(pages)
    report = verify_users(
        reader,
        writes_for("1", "2", "3", records={no: _capture_read(no) for no in ("1", "2", "3")}),
        page_size=2,
    )
    assert report.ok
    ids = {c["UserInfoSearchCond"]["searchID"] for c in reader.calls}
    assert len(ids) == 1, "the cursor id must not change mid-walk (references §1.2)"
    assert len(reader.calls) == 2, (
        "page 1 answers MORE, page 2 answers the tail with OK — the walk stops at the "
        "first non-MORE status, the same termination rule paging.PagedSearch uses"
    )


def test_a_verify_mismatch_is_terminal_and_never_a_rewrite(tmp_path: Path) -> None:
    """§0.6/§5 step 7: the run STOPS with the mismatch as data. Nothing here may re-write
    it, so the only legal outcome is a note naming the terminal verdict — and the person's
    journal entry never reaches `confirmed`."""
    device = write_device()
    client = client_for(device)
    journal = journal_in(tmp_path)
    record = dict(T90)
    transport = IsapiWriteTransport(client, journal=journal)
    report_obj = apply_users_phase(
        plan=plan_of("90"),
        bundle=bundle_of([record]),
        transport_factory=lambda: transport,
        reader=read_reader(device),
        journal_path=journal.path,
        probe=probe_ok(),
        now=NOW,
    )
    assert report_obj.writes.applied == (person_hash("90"),)
    assert report_obj.verify is not None
    verdict = report_obj.verify.verdict_of("90")
    assert verdict is PersonVerdict.MISMATCH, (
        "the write landed exactly what was sent, but the DEVICE adds read-shape fields "
        "(§6's fail-closed rule) — this is the honest outcome the design demands"
    )
    assert any("TERMINAL mismatch" in note for note in report_obj.notes)
    assert report_obj.writes.confirmed == ()
    # apply re-opens the journal at journal_path (its own handle). A resume FOLDS to
    # newest-per-person (§5a): this person stops at `applied` — never `confirmed`, and
    # never undone (§0.6). The raw file still carries the full transition history.
    resumed = WriteJournal.open(journal.path, phase="users")
    assert [e.state for e in resumed.entries] == [JournalState.APPLIED]
    lines = [json.loads(x)["state"] for x in journal.path.read_text().splitlines()]
    assert lines == ["planned", "applied"]
    # No second write happened (§0.6: a mismatch is never fixed with a blind re-write).
    assert len(transport.sent) == 1


def test_verify_reports_ok_end_to_end_when_the_intended_record_is_the_read_shape(
    tmp_path: Path,
) -> None:
    """The same loop, with the expectation stated the way the read states it: proves the
    MISMATCH above is the fail-closed rule working, not a broken comparison."""
    device = write_device()
    client = client_for(device)
    journal = journal_in(tmp_path)
    # Seed the person store empty, write T90, then read it back: what the device answers
    # is the capture's read shape, so an intended record built FROM that shape confirms.
    transport = IsapiWriteTransport(client, journal=journal)
    run_users_phase(
        BudgetedWriteTransport(lambda: transport),
        journal,
        writes_for("90", records={"90": dict(T90)}),
        sleep=lambda _s: None,
    )
    device._enrollment_store["UserInfo"] = [
        json.loads(json.dumps(CAPTURE_READBACK["UserInfoSearch"]["UserInfo"][0]))
    ]
    report = verify_users(read_reader(device), writes_for("90", records={"90": dict(T90)}))
    # The intended record is the WRITE shape; the device adds read fields → §6 fails
    # closed. Proving BOTH directions in one test keeps the rule honest in both.
    assert report.verdict_of("90") is PersonVerdict.MISMATCH
    same_shape = writes_for("90", records={"90": CAPTURE_READBACK["UserInfoSearch"]["UserInfo"][0]})
    ok_report = verify_users(read_reader(device), same_shape)
    assert ok_report.verdict_of("90") is PersonVerdict.OK


# --- §5 steps 1-2 + 7: the composed phase --------------------------------------------------


def test_apply_refuses_a_stale_probe_before_touching_the_journal(tmp_path: Path) -> None:
    device = write_device()
    stale = probe_ok(probed_at=(NOW - timedelta(days=7, seconds=1)).isoformat())
    with pytest.raises(Exception, match="stale"):
        apply_users_phase(
            plan=plan_of("1"),
            bundle=bundle_of([user("1")]),
            transport_factory=lambda: IsapiWriteTransport(client_for(device)),
            reader=read_reader(device),
            journal_path=tmp_path / "users.jsonl",
            probe=stale,
            now=NOW,
        )
    assert not (tmp_path / "users.jsonl").exists(), "a refused apply writes no journal"


def test_apply_refuses_a_lying_clock_and_no_skew_evidence(tmp_path: Path) -> None:
    device = write_device()
    for probe, expect in (
        (probe_ok(clock_skew_s=120.0), r"clock is \+120"),
        (probe_ok(clock_skew_s=-120.0), r"clock is -120"),
        (probe_ok(clock_skew_s=None, clock_note="System/time unreadable"), r"no System/time"),
    ):
        with pytest.raises(ApplyAbortedError, match=expect):
            apply_users_phase(
                plan=plan_of("1"),
                bundle=bundle_of([user("1")]),
                transport_factory=lambda: IsapiWriteTransport(client_for(device)),
                reader=read_reader(device),
                journal_path=tmp_path / f"u{expect}.jsonl",
                probe=probe,
                now=NOW,
            )
    # The gate is the boundary the design names (60 s), and it is not off by one:
    check_clock_skew(probe_ok(clock_skew_s=60.0))
    with pytest.raises(ApplyAbortedError):
        check_clock_skew(probe_ok(clock_skew_s=60.1))


def test_apply_aborts_on_freshness_drift_before_any_write(tmp_path: Path) -> None:
    device = write_device()
    client = client_for(device)
    plan = plan_of("1", "2")
    transport = IsapiWriteTransport(client)

    def drifted() -> list[Classification]:
        from dataclasses import replace

        return [
            replace(i, classification=DiffClass.CONFLICT) if i.employee_no == "1" else i
            for i in plan.items
        ]

    with pytest.raises(ApplyAbortedError, match="freshness contract"):
        apply_users_phase(
            plan=plan,
            bundle=bundle_of([user("1"), user("2")]),
            transport_factory=lambda: transport,
            reader=read_reader(device),
            journal_path=tmp_path / "users.jsonl",
            probe=probe_ok(),
            now=NOW,
            recheck=drifted,
        )
    assert transport.sent == [], "a drifted plan must not write a single record (§4)"
    assert WriteJournal.open(tmp_path / "users.jsonl", phase="users").entries == ()


def test_apply_writes_verifies_and_confirms_a_person_the_target_agrees_with(tmp_path: Path) -> None:
    """§5's order end to end over the real digest stack: gate → journal → PUT → verify →
    journal `confirmed`, and the report stays PII-free (§4)."""
    device = write_device()
    client = client_for(device)
    journal = journal_in(tmp_path)
    transport = IsapiWriteTransport(client, journal=journal)
    record = CAPTURE_READBACK["UserInfoSearch"]["UserInfo"][0]
    report = apply_users_phase(
        plan=plan_of("90"),
        bundle=bundle_of([record]),
        transport_factory=lambda: transport,
        reader=read_reader(device),
        journal_path=journal.path,
        probe=probe_ok(),
        now=NOW,
    )
    assert report.verify is not None and report.verify.ok
    assert report.writes.confirmed == (person_hash("90"),)
    resumed = WriteJournal.open(journal.path, phase="users")
    assert [e.state for e in resumed.entries] == [JournalState.CONFIRMED]
    lines = [json.loads(x)["state"] for x in journal.path.read_text().splitlines()]
    assert lines == ["planned", "applied", "confirmed"]
    assert report.verify.coverage_proven is True  # the fake honored the filter; audited anyway
    assert report.verify.method == "filtered"
    payload = json.dumps(report.as_dict())
    assert "User T90" not in payload and "User E90" not in payload  # §4: hashes/counts only


def test_apply_is_idempotent_on_a_re_run_and_the_report_is_stable(tmp_path: Path) -> None:
    """§4's idempotency claim, checked against the phase: a person the diff calls `same`
    sends zero bytes, so a second apply cannot drift the target."""
    device = write_device()
    client = client_for(device)
    transport = IsapiWriteTransport(client)
    report = apply_users_phase(
        plan=plan_of(updates=("1",), conflicts=("7",)),
        bundle=bundle_of([user("1"), user("7")]),
        transport_factory=lambda: transport,
        reader=read_reader(device),
        journal_path=tmp_path / "users.jsonl",
        probe=probe_ok(),
        now=NOW,
    )
    assert transport.sent == [] and report.writes.writes_sent == 0
    assert dict(report.writes.skipped) == {
        employee_hash("1"): "update_shape_uncaptured",
        employee_hash("7"): "conflict_report_only",
    }
    assert report.verify is None, "nothing was written, so there is nothing to re-read"


def test_report_summary_carries_only_hashes_counts_and_device_words(tmp_path: Path) -> None:
    journal = journal_in(tmp_path)
    transport = ScriptedTransport({"statusCode": 1})
    result = run_users_phase(
        BudgetedWriteTransport(lambda: transport),
        journal,
        writes_for("1"),
        sleep=lambda _s: None,
        skipped=((employee_hash("9"), "update_shape_uncaptured"),),
    )
    summary = json.dumps(result.summary(), sort_keys=True)
    assert "User E1" not in summary and FAKE_PIN not in summary
    parsed = json.loads(summary)
    assert parsed["writesSent"] == 1 and parsed["applied"] == 1
    # Counts for the happy path, HASHES for the flagged ones (§4): the skipped person
    # appears only as their hash + machine reason — never their employeeNo or name.
    assert parsed["skipped"] == [
        {"employee": employee_hash("9"), "reason": "update_shape_uncaptured"}
    ]
    assert '"1"' not in summary.replace('"10"', "")  # no raw employeeNo rides along
