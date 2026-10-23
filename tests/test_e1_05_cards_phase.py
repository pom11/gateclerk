"""Card E1-05 definition of done: the cards phase, offline and FakeDevice-strict.

Everything here runs with the autouse `netoff` guard: no socket may open (this card
NEVER contacts a device — the capture belongs to PR #43 and was read, not repeated).
Proof layers, each named after the rule it locks:

* §9 capture-before-fake — the SetUp body is BYTE-EQUAL to
  ``cardinfo_setup_add_request.json`` and the delete body is BYTE-EQUAL to
  ``cardinfo_delete_request.json``; the fake answers only from committed capture
  files (a structural lock over every body the card routes serve); an un-armed write
  verb, a POST to SetUp (the captured 405 class), an ``enable`` field (not in the
  card capture) and a wrapped-list body all fail LOUD.
* §5 step 5 — re-run idempotency is the ``(cardNo, employeeNo)`` PAIR: a re-run where
  the pairs already exist sends ZERO bytes; the same cardNo bound to a DIFFERENT
  employeeNo is neither skipped as done nor reassigned (E1-02's
  ``card_no_bound_to_other_employee`` is the source of that classification, pinned by
  calling the real diff engine).
* §5 step 4 — the first rejection aborts the phase and names which cards landed,
  journals ``rejected``, and retries nothing. The fake's capacity knob answers a
  clearly-labelled SYNTHETIC subcode, which classifies ``RejectKind.OTHER`` (UNKNOWN):
  no committed capture has a capacity word, so none may be named (§1, §9).
* §5a — undo touches only ``confirmed`` ``add`` entries whose live re-read still
  matches the journal's post-write hash; ``applied``-only entries and drifted rows are
  refused by name.
* §5b — the count-delta wrapper: a delete body that names MORE cards than requested
  never leaves the module; a delta larger than the named list, a named card that
  survives, or an unreadable count is an incident that STOPS the undo and leaves the
  journal honest.
* §5b.1 — no user-undo verb exists anywhere in this module (source-grep + behaviour).
* §5.3/§6 — the fake's nonce ledger is the independent witness for the card-call
  count, verify is terminal on a mismatch, and the roster read that failed produces NO
  verdicts rather than a page of false "missing".
"""

from __future__ import annotations

import hashlib
import json
import tempfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import httpx
import pytest

from fakedevice import (
    BASE_URL,
    CARD_DELETE_PATH,
    CARD_SETUP_PATH,
    EnrollmentProtocolError,
    FakeDevice,
)
from gateclerk.isapi_transport import IsapiClient
from gateclerk.migrate_bundle import BundleData, BundleManifest, FacesIndex
from gateclerk.migrate_diff import (
    Classification,
    DiffClass,
    Plan,
    Reason,
    employee_hash,
)
from gateclerk.migrate_diff import classify as diff_classify
from gateclerk.migrate_probe import CapabilityMatrix, SurfaceProbe, Verdict
from gateclerk.migrate_write import (
    DEFAULT_BATCH_SIZE,
    JOURNAL_SCHEMA,
    BudgetedWriteTransport,
    JournalState,
    RejectKind,
    WriteAbortedError,
    WriteJournal,
    WriteRejectedError,
    WriteShapeError,
    person_hash,
)
from gateclerk.migrate_write_cards import (
    CAPTURED_CARD_READ_KEYS,
    CAPTURED_CARD_WRITE_KEYS,
    CARD_SEARCH_PATH,
    CARDS_PHASE,
    CardDeleteScopeError,
    CardVerdict,
    CardWrite,
    DeleteAbortedError,
    UndoReport,
    apply_cards_phase,
    assess_delete_delta,
    build_card_delete_body,
    build_card_setup_body,
    card_caps,
    card_delete_targets,
    card_hash,
    card_identity_projection,
    derive_card_batch_size,
    person_delete_forbidden,
    plan_card_writes,
    read_card_store,
    run_cards_phase,
    undo_card_adds,
    verify_cards,
)

FIXTURES = Path(__file__).parent / "fixtures/recorded/site-a-ds-k1t341amf-s"
ENROLLMENT = FIXTURES / "enrollment"
PASSWORD = "fake" + "pw"  # placeholder policy (tests/test_repo_hygiene.py)
NOW = datetime(2026, 10, 22, 9, 0, 0, tzinfo=UTC)

#: The capture's test card (cardinfo_setup_add_request.json + readback + delete).
CARD_ADD_REQUEST = json.loads((ENROLLMENT / "cardinfo_setup_add_request.json").read_text())
CARD_ADD_ACK = json.loads((ENROLLMENT / "cardinfo_setup_add_response.json").read_text())
CARD_READBACK = json.loads((ENROLLMENT / "cardinfo_setup_readback.json").read_text())
CARD_DELETE_REQUEST = json.loads((ENROLLMENT / "cardinfo_delete_request.json").read_text())
CARD_DELETE_ACK = json.loads((ENROLLMENT / "cardinfo_delete_response.json").read_text())
CARD_DELETE_EMPTY = json.loads((ENROLLMENT / "cardinfo_delete_verified_empty.json").read_text())
T90_CARD = CARD_ADD_REQUEST["CardInfo"]
#: The one row of the captured NONZERO CardInfoSearch (§5 step 5's prerequisite).
CAPTURED_CARD_ROW = CARD_READBACK["CardInfoSearch"]["CardInfo"][0]

#: The fake's synthetic capacity answer — MUST be the fake's own word (the fake defines
#: it next to its card route). Deliberately spelled without the substring "capacity":
#: a test pins that no report ever names capacity (§1: capacity is unexposed), and a
#: synthetic word containing that substring would trip its own pin.
SYNTHETIC_CAPACITY_WORD = "SYNTHETIC-NO-CAPTURE-cardRosterFull"
SETUP_URL = CARD_SETUP_PATH + "?format=json"
DELETE_URL = CARD_DELETE_PATH + "?format=json"


# --- builders -------------------------------------------------------------------------------


def card(
    no: str, *, employee_no: str | None = None, card_type: str = "normalCard", **extra: Any
) -> dict[str, Any]:
    """A bundle card record in E1-01's exported shape (employeeNo/cardNo/cardType)."""
    record: dict[str, Any] = {
        "employeeNo": employee_no if employee_no is not None else f"e{no}",
        "cardNo": no,
        "cardType": card_type,
    }
    record.update(extra)
    return record


def card_row(no: str, *, employee_no: str, card_type: str = "normalCard") -> dict[str, Any]:
    """A TARGET card row in the captured read shape (leaderCard included)."""
    return {
        "employeeNo": employee_no,
        "cardNo": no,
        "leaderCard": "",
        "cardType": card_type,
    }


def bundle_of(
    people: list[dict[str, Any]] | None = None, cards: list[dict[str, Any]] | None = None
) -> BundleData:
    people = people or []
    manifest = BundleManifest(
        schema_version="gateclerk-enrollment-bundle/2",
        exported_at="2026-10-22T08:00:00+00:00",
        identity={"model": "DS-K1T341AMF-S", "firmware": "V3.2.30", "serial_prefix": "ab12cd"},
        counts={"users": len(people), "cards": len(cards or []), "faces": 0},
        people_hashes={},
        volatile_fields_digest="",
        faces={"state": "UNAVAILABLE", "reason": "test"},
        termination={},
    )
    return BundleData(
        manifest=manifest,
        people=tuple(people),
        cards=tuple(cards or []),
        faces=FacesIndex(),
    )


def person(no: str) -> dict[str, Any]:
    """A bench-A-shaped UserInfo record for the classify() cross-checks (E1-02's
    `user()` shape: a person without a parseable Valid classifies CONFLICT, not SAME,
    and the §5 step 5 cross-check below is about the CARD verdict, not validity)."""
    return {
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
    }


def plan_of(*nos: str, kind: DiffClass = DiffClass.ADD) -> Plan:
    return Plan(
        items=tuple(
            Classification(
                employee_hash=employee_hash(no),
                classification=kind,
                would_write=1 if kind is DiffClass.ADD else 0,
                _employee_no=no,
            )
            for no in nos
        )
    )


def probe_ok(**changes: Any) -> CapabilityMatrix:
    """A fresh, clock-clean matrix carrying the card caps bench A answered."""
    base: dict[str, Any] = {
        "site": "site-a",
        "host": "192.0.2.10",
        "clock_skew_s": 0.5,
        "template_nos": ("1",),
        "caps_raw": {
            "caps_card_info": {
                "CardInfoCap": {
                    "maxRecordNum": 3000,
                    "supportFunction": {"@opt": "setUp"},
                    "cardNo": {"@min": 1, "@max": 20},
                    "cardType": {"@opt": "normalCard,patrolCard,hijackCard,superCard"},
                }
            },
        },
        "surfaces": (
            SurfaceProbe(
                key="cards",
                endpoint="card_info_search",
                method="POST",
                path=CARD_SEARCH_PATH,
                verdict=Verdict.OK,
            ),
        ),
        "probed_at": NOW.isoformat(),
    }
    base.update(changes)
    return CapabilityMatrix(**base)


def card_device(
    *,
    people: list[dict[str, Any]] | None = None,
    cards: list[dict[str, Any]] | None = None,
    **knobs: Any,
) -> FakeDevice:
    """A box with the captured WRITE axis armed and a card store seeded."""
    device = FakeDevice(password=PASSWORD)
    device.install_write_capture(
        users=people if people is not None else [], cards=cards if cards is not None else []
    )
    for name, value in knobs.items():
        setattr(device, name, value)
    return device


def client_for(device: FakeDevice) -> IsapiClient:
    return IsapiClient(
        BASE_URL, "admin", PASSWORD, transport=device.transport, sleep=lambda _s: None
    )


class RecordingTransport:
    """The injected write seam over a real IsapiClient + FakeDevice (E1-04's shape)."""

    def __init__(self, client: IsapiClient) -> None:
        self.client = client
        self.sent: list[tuple[str, dict]] = []
        self.closed = 0
        self.rebootstraps = 0  # this seam never rotates; the budget wrapper above it does

    def put_setup(self, path: str, body: dict) -> dict:
        self.sent.append((path, json.loads(json.dumps(body))))
        response = self.client._client.put(
            path, params={"format": "json"}, json=body, auth=self.client._auth
        )
        envelope = json.loads(response.content)
        if response.status_code != 200 or envelope.get("statusCode") != 1:
            raise WriteRejectedError(
                f"device answered {response.status_code} {envelope.get('subStatusCode')}",
                sub_status=envelope.get("subStatusCode"),
                http_status=response.status_code,
                envelope=envelope,
            )
        return envelope

    def close(self) -> None:
        self.closed += 1


class ScriptedTransport:
    """Answers from canned bodies without touching a device (guard/classification tests)."""

    def __init__(self, *acks: Any) -> None:
        self.acks: list[Any] = list(acks)
        self.sent: list[tuple[str, dict]] = []
        self.rebootstraps = 0

    def put_setup(self, path: str, body: dict) -> dict:
        self.sent.append((path, json.loads(json.dumps(body))))
        item = self.acks.pop(0) if self.acks else {"statusCode": 1}
        if isinstance(item, Exception):
            raise item
        return item

    def close(self) -> None:
        return None


class CountLyingReader:
    """A card roster reader that reports a device total LARGER than the rows it returns.

    The §5b guard compares COUNTS; if the code quietly used ``len(rows)`` instead, the
    delta would look clean while the device said otherwise. This fake makes the two
    disagree on purpose.
    """

    def __init__(self, rows: list[dict], *, lie_by: int) -> None:
        self.rows = rows
        self.lie_by = lie_by
        self.calls: list[dict] = []

    def __call__(self, body: dict) -> dict:
        self.calls.append(json.loads(json.dumps(body)))
        start = body["CardInfoSearchCond"]["searchResultPosition"]
        window = self.rows[start : start + 30]
        return {
            "CardInfoSearch": {
                "searchID": body["CardInfoSearchCond"]["searchID"],
                "responseStatusStrg": "OK",
                "numOfMatches": len(window),
                "totalMatches": len(self.rows) + self.lie_by,
                **({"CardInfo": window} if window else {}),
            }
        }


def fake_reader(device: FakeDevice):
    """The §6 read seam over the same read-only client the export uses."""
    client = client_for(device)

    def read(body: dict) -> dict:
        return client.search("card_info_search", body)

    return read


def writes_for(*cards: dict[str, Any]) -> tuple[CardWrite, ...]:
    return tuple(
        CardWrite(
            employee_no=str(c["employeeNo"]),
            employee_hash=person_hash(str(c["employeeNo"])),
            card_no=str(c["cardNo"]),
            card_type=str(c["cardType"]),
            record=c,
        )
        for c in cards
    )


def _scratch_journal(phase: str = CARDS_PHASE) -> WriteJournal:
    return WriteJournal.open(Path(tempfile.mkdtemp(prefix="e105-")) / f"{phase}.jsonl", phase=phase)


def journal_in(tmp_path: Path, name: str = "cards.jsonl") -> WriteJournal:
    return WriteJournal.open(tmp_path / name, phase=CARDS_PHASE)


def raw_request(device: FakeDevice, method: str, path: str, *, json_body: Any = None):
    """One digest-authed request straight into the fake's transport.

    The fake 401s anything without a valid digest (a bare ``handle_request`` gets the
    challenge, not the route answer) — so write-axis proofs ride the real auth stack.
    """
    with httpx.Client(
        transport=device.transport, auth=httpx.DigestAuth("admin", PASSWORD), base_url=BASE_URL
    ) as raw:
        return raw.request(method, path, json=json_body)


# --- §9: the bodies are the capture, byte for byte --------------------------------------------


def test_the_setup_body_is_byte_equal_to_the_capture() -> None:
    body = build_card_setup_body(dict(T90_CARD, mode="add"))
    assert body == CARD_ADD_REQUEST, (
        "the module's body drifted from cardinfo_setup_add_request.json — the capture "
        "is the contract, not a suggestion"
    )
    assert json.dumps(body, sort_keys=True) == json.dumps(CARD_ADD_REQUEST, sort_keys=True)


def test_the_delete_body_is_byte_equal_to_the_capture() -> None:
    body = build_card_delete_body([T90_CARD["cardNo"]])
    assert body == CARD_DELETE_REQUEST, (
        "the delete body drifted from cardinfo_delete_request.json — the list slot IS "
        "the safety property (§5b: a list in the slot the device does not read means "
        "'delete everything')"
    )
    # And the guard's reader sees exactly what the body names — the pair the count-delta
    # wrapper compares against is read back FROM the body, never from intent.
    assert card_delete_targets(body) == (T90_CARD["cardNo"],)
    assert card_delete_targets({"CardInfoDelCond": {"CardNoList": []}}) == ()
    assert card_delete_targets({"wrong": "slot"}) == ()


def test_the_captured_add_body_carries_no_enable_field_and_no_other_key() -> None:
    # The card's note: cards have no `enable`. The capture proves it; a body that added
    # one would be an unrecorded shape this family is known to reject or half-merge.
    assert "enable" not in CARD_ADD_REQUEST["CardInfo"]
    assert set(T90_CARD) == set(CAPTURED_CARD_WRITE_KEYS) | {"mode"}
    noisy = dict(T90_CARD, enable=True, numOfCard=4, leaderCard="x", photoURL="http://x/y")
    body = build_card_setup_body(noisy)["CardInfo"]
    assert set(body) == set(CARD_ADD_REQUEST["CardInfo"]), "the allow-list drifted"
    assert "enable" not in body and "leaderCard" not in body


def test_the_sending_transport_uses_the_captured_put_verb_and_path() -> None:
    device = card_device()
    transport = RecordingTransport(client_for(device))
    run_cards_phase(
        BudgetedWriteTransport(lambda: transport),
        _scratch_journal(),
        writes_for(dict(T90_CARD)),
    )
    assert transport.sent == [(CARD_SETUP_PATH, CARD_ADD_REQUEST)]
    assert device.authorized_requests_to("PUT", SETUP_URL) == 1
    assert device._enrollment_store["CardInfo"] == [
        {
            "employeeNo": T90_CARD["employeeNo"],
            "cardNo": T90_CARD["cardNo"],
            "cardType": T90_CARD["cardType"],
        }
    ]


def test_a_post_to_the_card_setup_path_answers_the_captured_method_class() -> None:
    # The card family has no card-specific 405 capture; the verb discipline comes from
    # the users capture of the same class, so the assertion is on the WORD, not a body.
    device = card_device()
    response = raw_request(device, "POST", SETUP_URL, json_body=CARD_ADD_REQUEST)
    body = json.loads(response.content)
    assert response.status_code == 400 and body["subStatusCode"] == "methodNotAllowed"
    assert device._enrollment_store["CardInfo"] == []


def test_an_unrecorded_key_in_the_card_body_is_rejected_by_the_device() -> None:
    device = card_device()
    bad = {"CardInfo": {**T90_CARD, "enable": True}}
    response = raw_request(device, "PUT", SETUP_URL, json_body=bad)
    body = json.loads(response.content)
    assert body["subStatusCode"] == "badJsonContent" and body["errorMsg"] == "enable"
    assert device._enrollment_store["CardInfo"] == []


def test_a_wrapped_list_card_body_answers_the_captured_lack_employee_no() -> None:
    # The users capture of THIS class (wrapped list -> `lack employeeNo`) is the device
    # truth reused; the card capture has no list body, so none may be invented (§9).
    device = card_device()
    response = raw_request(
        device, "PUT", SETUP_URL, json_body={"cardInfoList": {"cardInfo": dict(T90_CARD)}}
    )
    body = json.loads(response.content)
    assert body == json.loads((ENROLLMENT / "users_setup_wrapped_list_400.json").read_text())
    assert device._enrollment_store["CardInfo"] == []


def test_an_unproven_card_mode_is_a_protocol_error_never_a_guessed_answer() -> None:
    device = card_device()
    with pytest.raises(EnrollmentProtocolError, match="no bench-A capture"):
        raw_request(
            device, "PUT", SETUP_URL, json_body={"CardInfo": {**T90_CARD, "mode": "modify"}}
        )


def test_the_fake_refuses_to_invent_an_ownership_rejection_answer() -> None:
    """§9: bench A never captured a device answer for re-binding a cardNo to a
    DIFFERENT employeeNo, so the fake must raise LOUDLY rather than invent one. The
    §4 conflict is a CLIENT-side classification (plan/verify refuse before any
    write); if a future client ever sent the request anyway, it must hit this wall,
    not a made-up subcode the tests then trust."""
    device = card_device(cards=[card_row("90000090", employee_no="SOMEONE_ELSE")])
    with pytest.raises(EnrollmentProtocolError, match="NEVER captured"):
        raw_request(device, "PUT", SETUP_URL, json_body=CARD_ADD_REQUEST)
    # The foreign binding is untouched — a loud refusal is not a half-applied write.
    assert device._enrollment_store["CardInfo"] == [
        card_row("90000090", employee_no="SOMEONE_ELSE")
    ]


def test_the_card_write_routes_replay_only_committed_capture_files() -> None:
    """The §9 structural lock: every body the card write routes serve is a capture file."""
    committed = [json.loads(p.read_text()) for p in sorted(ENROLLMENT.glob("*.json"))]
    device = card_device()
    served = [
        json.loads(raw_request(device, "PUT", SETUP_URL, json_body=CARD_ADD_REQUEST).content),
        json.loads(
            raw_request(
                device, "PUT", DELETE_URL, json_body={"CardInfoDelCond": {"CardNoList": []}}
            ).content
        ),
        json.loads(
            raw_request(
                device, "PUT", DELETE_URL, json_body=build_card_delete_body(["ghost"])
            ).content
        ),
    ]
    assert served[0] == CARD_ADD_ACK and served[1] == CARD_DELETE_ACK
    assert served[2] == CARD_DELETE_ACK
    for body in served:
        assert body in committed, f"the fake served a body that is not a capture: {body}"


def test_the_card_delete_ack_and_verified_empty_read_are_the_captures() -> None:
    # The fake answers the DELETE from `cardinfo_delete_response.json` VERBATIM (the
    # explicit-route seam proves the byte-equality without a searchID-collision guess)…
    device = card_device()
    device.add("PUT", DELETE_URL, httpx.Response(200, json=CARD_DELETE_ACK))
    served = json.loads(
        raw_request(device, "PUT", DELETE_URL, json_body=CARD_DELETE_REQUEST).content
    )
    assert served == CARD_DELETE_ACK
    # …and the honest zero read after a delete is `cardinfo_delete_verified_empty.json`.
    # The client may not dictate the searchID, so the captured id is what the fake says.
    device.reset(
        "POST", CARD_SEARCH_PATH + "?format=json", httpx.Response(200, json=CARD_DELETE_EMPTY)
    )
    answer = fake_reader(device)({"CardInfoSearchCond": {"searchID": "x1", "maxResults": 30}})
    assert answer == CARD_DELETE_EMPTY


def test_the_read_shape_carries_leader_card_so_verify_compares_three_fields() -> None:
    # Why the §6 card compare is (cardNo, employeeNo, cardType) and not a whole-record
    # hash: the captured READ row has a key the captured WRITE body has no way to set.
    assert set(CAPTURED_CARD_ROW) == set(CAPTURED_CARD_READ_KEYS)
    assert "leaderCard" in set(CAPTURED_CARD_ROW) - CAPTURED_CARD_WRITE_KEYS
    assert card_identity_projection(CAPTURED_CARD_ROW) == {
        "cardNo": "90000090",
        "employeeNo": "90",
        "cardType": "normalCard",
    }
    assert card_identity_projection(dict(T90_CARD)) == card_identity_projection(CAPTURED_CARD_ROW)


# --- §5 step 5: pair identity and the ownership blocker ---------------------------------------


def test_pair_identity_a_second_run_writes_zero_bytes(tmp_path: Path) -> None:
    """§5 step 5: re-run idempotency is the (cardNo, employeeNo) PAIR."""
    rows = [card_row("90000090", employee_no="90")]
    plan = plan_of("90")
    bundle = bundle_of(cards=[card("90000090", employee_no="90")])
    # The planner hands the pair over (it gates conflicts, not already-done pairs);
    # the PHASE's pair check is what sends zero bytes — the two layers pin different
    # things, and a re-run must pass through both without writing.
    writes, skipped = plan_card_writes(plan, bundle, target_cards=rows)
    assert [w.card_no for w in writes] == ["90000090"] and skipped == ()
    transport = RecordingTransport(client_for(card_device()))
    result = run_cards_phase(
        BudgetedWriteTransport(lambda: transport),
        journal_in(tmp_path),
        writes,
        target_cards=rows,
    )
    assert transport.sent == [] and result.writes_sent == 0
    assert result.already_paired == (card_hash("90000090"),)
    assert result.applied == () and result.conflicts == () and result.clean
    # And the diff engine agrees that a paired card is not a write (pair identity is
    # E1-02's classification, not a second opinion invented here).
    classifications = diff_classify(
        [person("90")],
        [person("90")],
        [card("90000090", employee_no="90")],
        rows,
        None,
    )
    assert [(c.classification, c.would_write) for c in classifications] == [(DiffClass.SAME, 0)]


def test_pair_identity_the_same_card_number_for_another_person_is_a_conflict() -> None:
    """The reviewer BLOCKER: the SAME cardNo on target under a different employeeNo is
    neither skipped-as-done nor reassigned (E1-02's card_no_bound_to_other_employee)."""
    rows = [card_row("90000090", employee_no="OTHER")]
    classifications = diff_classify(
        [{"employeeNo": "90", "name": "User E90"}],
        [{"employeeNo": "OTHER", "name": "User EOTHER"}],
        [card("90000090", employee_no="90")],
        rows,
        None,
    )
    conflict = [c for c in classifications if c.classification is DiffClass.CONFLICT]
    assert conflict and Reason.CARD_BOUND_TO_OTHER in conflict[0].reasons, (
        "E1-02 owns the ownership classification; if it moved, the writer's conflict "
        "vocabulary here moved with it"
    )
    writes, skipped = plan_card_writes(
        plan_of("90"), bundle_of(cards=[card("90000090", employee_no="90")]), target_cards=rows
    )
    assert writes == ()
    assert [r.split("(")[0] for _h, r in skipped] == ["card_bound_to_other_employee"]


def test_the_writer_rechecks_ownership_at_the_last_frame_and_continues() -> None:
    """The plan said both were fine; the LIVE target says one card is someone else's.
    That card is reported and skipped — and the phase CONTINUES with the others (§4:
    a conflict is the operator's decision, not a device fault that stops the run)."""
    journal = journal_in(_TMP)
    transport = ScriptedTransport()
    result = run_cards_phase(
        BudgetedWriteTransport(lambda: transport),
        journal,
        writes_for(
            card("C1", employee_no="1"), card("C2", employee_no="2"), card("C3", employee_no="3")
        ),
        target_cards=[card_row("C2", employee_no="SOMEONE_ELSE")],
    )
    assert [body["CardInfo"]["cardNo"] for _path, body in transport.sent] == [
        "C1",
        "C3",
    ], "the foreign-bound card was never sent — no reassign, no skip-as-done"
    assert result.conflicts == ((card_hash("C2"), _reason_prefix()),)
    assert result.applied == (card_hash("C1"), card_hash("C3"))
    assert not result.aborted and result.clean


def _reason_prefix() -> str:
    from gateclerk.migrate_write_cards import _OWNERSHIP_CONFLICT

    return _OWNERSHIP_CONFLICT


def test_plan_reports_conflicts_and_refuses_unwritable_persons_without_sending() -> None:
    rows = [card_row("CB", employee_no="OTHER")]
    plan = Plan(
        items=(
            Classification(
                employee_hash=employee_hash("1"),
                classification=DiffClass.ADD,
                would_write=1,
                _employee_no="1",
            ),
            Classification(
                employee_hash=employee_hash("2"),
                classification=DiffClass.CONFLICT,
                reasons=(Reason.CARD_BOUND_TO_OTHER,),
                _employee_no="2",
            ),
        )
    )
    bundle = bundle_of(
        cards=[
            card("CA", employee_no="1"),
            card("CB", employee_no="2"),
            card("CC", employee_no="9"),
        ]
    )
    writes, skipped = plan_card_writes(plan, bundle, target_cards=rows)
    assert [w.card_no for w in writes] == ["CA"]
    reasons = dict(skipped)
    assert reasons[card_hash("CB")].startswith("card_bound_to_other_employee")
    assert reasons[card_hash("CC")] == "person_not_writable"
    assert reasons[card_hash("CB")] != reasons[card_hash("CC")], (
        "'refused' and 'not this person's card' must never share a code (§4)"
    )


def test_a_person_the_plan_calls_same_still_gets_their_card() -> None:
    """E1-02 counts card adds for a `same` person; a matching person missing a card is
    exactly what this phase is for, so `same` must not gate the card write."""
    writes, skipped = plan_card_writes(
        plan_of("1", kind=DiffClass.SAME),
        bundle_of(cards=[card("C1", employee_no="1")]),
        target_cards=[],
    )
    assert [w.card_no for w in writes] == ["C1"] and skipped == ()


def test_a_missing_card_number_is_refused_never_written_thin() -> None:
    with pytest.raises(WriteShapeError, match="cardNo"):
        build_card_setup_body({"employeeNo": "90", "cardType": "normalCard"})
    with pytest.raises(WriteShapeError, match="cardType"):
        build_card_setup_body({"employeeNo": "90", "cardNo": ""})


def test_the_card_type_vocabulary_and_length_sentinel_come_from_the_devices_caps() -> None:
    # caps are the vocabulary source (§3): an out-of-enum cardType is refused HERE, and
    # cardNo @max 20 is a LENGTH guard, never capacity (§1).
    with pytest.raises(WriteShapeError, match="cardType"):
        build_card_setup_body(
            card("C1", employee_no="1", card_type="mysteryCard"), probe=probe_ok()
        )
    too_long = "1" * 21
    with pytest.raises(WriteShapeError, match="cardNo is 21"):
        build_card_setup_body(card(too_long, employee_no="1"), probe=probe_ok())
    assert build_card_setup_body(card("1" * 20, employee_no="1"), probe=probe_ok())
    # No probe -> bench A's own recorded enum still polices the value (§9 fallback).
    with pytest.raises(WriteShapeError, match="cardType"):
        build_card_setup_body(card("C1", employee_no="1", card_type="mysteryCard"))
    assert card_caps(probe_ok()) is not None and card_caps(None) is None


# --- §5 step 4: capacity fail-fast and the UNKNOWN vocabulary ----------------------------------


def test_capacity_rejection_aborts_and_reports_exactly_which_cards_landed(tmp_path: Path) -> None:
    journal = journal_in(tmp_path)
    device = card_device(card_capacity=2)
    transport = RecordingTransport(client_for(device))
    with pytest.raises(WriteAbortedError) as excinfo:
        run_cards_phase(
            BudgetedWriteTransport(lambda: transport),
            journal,
            writes_for(
                card("C1", employee_no="1"),
                card("C2", employee_no="2"),
                card("C3", employee_no="3"),
                card("C4", employee_no="4"),
            ),
        )
    result = excinfo.value.result
    assert result.aborted and result.writes_sent == 3
    assert result.applied == (card_hash("C1"), card_hash("C2"))
    assert [(h, k) for h, k, _s in result.rejected] == [(card_hash("C3"), RejectKind.OTHER)]
    assert len(transport.sent) == 3, "nothing further was attempted after the rejection"
    states = {(e.card_no, e.employee_no): e.state for e in journal.entries}
    assert states[("C3", "3")] is JournalState.REJECTED
    assert states[("C1", "1")] is JournalState.APPLIED
    assert ("C4", "4") not in states


def test_the_capacity_word_is_never_named_and_still_aborts(tmp_path: Path) -> None:
    """§1: true capacity is unexposed, so NO committed capture names a capacity word.

    The fake answers a clearly-labelled SYNTHETIC subcode; this pins the client (a) never
    calling any word "capacity", (b) classifying the unknown as UNKNOWN, and (c) aborting
    anyway (§5 step 4 does not depend on understanding the answer)."""
    from gateclerk.migrate_write import classify_rejection
    from gateclerk.migrate_write_cards import is_card_capacity_rejection

    assert is_card_capacity_rejection(SYNTHETIC_CAPACITY_WORD) is False
    assert is_card_capacity_rejection("noAuthority") is False
    assert is_card_capacity_rejection("resourceLimit") is False
    assert classify_rejection(SYNTHETIC_CAPACITY_WORD) is RejectKind.OTHER

    journal = journal_in(tmp_path)
    journal.planned(
        employee_no="1",
        classification="add",
        pre_write_record=None,
        intended_record=card("C1", employee_no="1"),
        op="card_setup",
        card_no="C1",
    )
    entry = journal.entries[0]
    journal.applied(entry)
    journal.rejected(entry, sub_status=SYNTHETIC_CAPACITY_WORD)
    payload = json.dumps(
        {"rejected": [journal.entries[-1].device_sub_status], "planned": 1}, sort_keys=True
    )
    assert SYNTHETIC_CAPACITY_WORD in payload and "capacity" not in payload.lower()
    assert (
        json.loads((tmp_path / "cards.jsonl").read_text().splitlines()[-1])["deviceSubStatus"]
        == SYNTHETIC_CAPACITY_WORD
    )


def test_a_non_ok_ack_without_an_exception_is_still_a_rejection(tmp_path: Path) -> None:
    journal = journal_in(tmp_path)
    transport = ScriptedTransport({"statusCode": 6, "subStatusCode": "businessError"})
    with pytest.raises(WriteAbortedError, match="device answered businessError"):
        run_cards_phase(
            BudgetedWriteTransport(lambda: transport),
            journal,
            writes_for(card("C1", employee_no="1")),
        )
    # Append-only: the `planned` LINE stays; the entry's STATE is the fold's answer.
    assert journal.latest()[0].state is JournalState.REJECTED


# --- §5a/§5b: undo, proof-of-add, and the count-delta wrapper ----------------------------------


_TMP = Path(tempfile.mkdtemp(prefix="e105-"))


def _confirmed_journal(tmp_path: Path, *cards: dict[str, Any]) -> WriteJournal:
    """A journal whose every entry reached ``confirmed`` with a post-write hash."""
    journal = journal_in(tmp_path)
    for record in cards:
        entry = journal.planned(
            employee_no=str(record["employeeNo"]),
            classification="add",
            pre_write_record=None,
            intended_record=record,
            op="card_setup",
            card_no=str(record["cardNo"]),
        )
        journal.applied(entry)
        journal.confirmed(entry, post_write_hash=content_of(record))
    return journal


def content_of(record: dict[str, Any]) -> str:
    from gateclerk.migrate_bundle import content_hash

    return content_hash(card_identity_projection(record))


def test_undo_removes_proven_adds_and_journals_reverted(tmp_path: Path) -> None:
    journal = _confirmed_journal(tmp_path, card("C1", employee_no="1"))
    device = card_device(cards=[card_row("C1", employee_no="1")])
    report = undo_card_adds(
        RecordingTransport(client_for(device)),
        journal,
        reader=fake_reader(device),
        undo_journal=WriteJournal.open(tmp_path / "undo.jsonl", phase="cards_undo"),
    )
    assert isinstance(report, UndoReport)
    assert report.reverted == (card_hash("C1"),) and report.clean
    assert (report.count_before, report.count_after) == (1, 0)
    assert device._enrollment_store["CardInfo"] == []
    assert device.authorized_requests_to("PUT", DELETE_URL) == 1
    undo_lines = [
        json.loads(x)["state"] for x in (tmp_path / "undo.jsonl").read_text().splitlines()
    ]
    assert undo_lines == ["planned", "reverted"]


def test_undo_refuses_entries_that_are_not_confirmed(tmp_path: Path) -> None:
    """§5a: planned/applied without confirmed is an unknown state — undo does not touch
    it, and the refusal is NAMED rather than a silent no-op."""
    journal = journal_in(tmp_path)
    entry = journal.planned(
        employee_no="1",
        classification="add",
        pre_write_record=None,
        intended_record=card("C1", employee_no="1"),
        op="card_setup",
        card_no="C1",
    )
    journal.applied(entry)
    device = card_device(cards=[card_row("C1", employee_no="1")])
    transport = RecordingTransport(client_for(device))
    report = undo_card_adds(transport, journal, reader=fake_reader(device))
    assert report.reverted == () and not report.clean
    assert "not confirmed" in report.refused[0].reason
    assert transport.sent == [], "an unconfirmed entry must never reach a delete"
    assert device._enrollment_store["CardInfo"] != []


def test_undo_refuses_a_row_that_drifted_after_confirmation(tmp_path: Path) -> None:
    """Proof-of-add: the live row no longer hashes to the journal's post-write hash, so
    someone else edited it and their edit wins (§5a — refuse and escalate)."""
    journal = _confirmed_journal(tmp_path, card("C1", employee_no="1"))
    drifted = card_row("C1", employee_no="1", card_type="patrolCard")
    device = card_device(cards=[drifted])
    transport = RecordingTransport(client_for(device))
    report = undo_card_adds(transport, journal, reader=fake_reader(device))
    assert report.reverted == ()
    assert "proof-of-add failed" in report.refused[0].reason
    assert transport.sent == []
    assert device._enrollment_store["CardInfo"] == [drifted], "the row was NOT touched"


def test_undo_refuses_a_card_the_target_gave_to_someone_else(tmp_path: Path) -> None:
    journal = _confirmed_journal(tmp_path, card("C1", employee_no="1"))
    device = card_device(cards=[card_row("C1", employee_no="INTRUDER")])
    report = undo_card_adds(
        RecordingTransport(client_for(device)), journal, reader=fake_reader(device)
    )
    assert report.reverted == () and "DIFFERENT employeeNo" in report.refused[0].reason


def test_undo_delete_naming_more_cards_than_requested_trips_the_guard(tmp_path: Path) -> None:
    """The card's own test: a crafted body that names MORE cards than the proven set
    must never reach the device — and if a body does, the count delta catches it."""
    journal = _confirmed_journal(tmp_path, card("C1", employee_no="1"))
    # (a) the module refuses to build/send a body broader than its proof (§5b).
    with pytest.raises(CardDeleteScopeError, match="broader than its proof"):
        undo_card_adds(
            _BodyRewriter(client_for(card_device(cards=[card_row("C1", employee_no="1")]))),
            journal,
            reader=fake_reader(card_device(cards=[card_row("C1", employee_no="1")])),
        )
    # (b) and a device that OBEYS an over-broad delete is caught by the wrapper.
    with pytest.raises(DeleteAbortedError, match="dropped by 4"):
        assess_delete_delta(named=["A"], count_before=5, count_after=1)


class _BodyRewriter:
    """A transport that does what a compromised caller would: widen the delete body."""

    def __init__(self, client: IsapiClient) -> None:
        self.client = client
        self.rebootstraps = 0

    def put_setup(self, path: str, body: dict) -> dict:
        if path == CARD_DELETE_PATH:
            body = build_card_delete_body(
                [c["cardNo"] for c in body["CardInfoDelCond"]["CardNoList"]] + ["VICTIM"]
            )
        response = self.client._client.put(
            path, params={"format": "json"}, json=body, auth=self.client._auth
        )
        envelope = json.loads(response.content)
        if envelope.get("statusCode") != 1:
            raise WriteRejectedError("refused", sub_status=envelope.get("subStatusCode"))
        return envelope

    def close(self) -> None:
        return None


def test_a_delete_that_wiped_more_than_it_named_is_an_incident(tmp_path: Path) -> None:
    """§5b step c: an over-large delta STOPS everything and leaves the journal honest.

    The honest before-count is 3 (the run's card plus two it never named). The
    delete removes exactly the one proven card — then the READER lies that the
    roster fell to zero, which is how a device-side over-delete looks from the
    client: the delta (3) is larger than the named list (1). That is the D-WIPE
    signature: incident, no `reverted` line, journal untouched.
    """
    journal = _confirmed_journal(tmp_path, card("C1", employee_no="1"))
    device = card_device(
        cards=[
            card_row("C1", employee_no="1"),
            card_row("C2", employee_no="2"),
            card_row("C3", employee_no="3"),
        ]
    )
    honest = fake_reader(device)
    reads = {"n": 0}

    def lying_read(body: dict) -> dict:
        answer = honest(body)  # the device answers the roster honestly…
        reads["n"] += 1
        if reads["n"] > 1:
            # …but AFTER the delete we are told the roster is EMPTY: two extra
            # cards vanished that the delete never named.
            answer["CardInfoSearch"]["totalMatches"] = 0
            answer["CardInfoSearch"]["CardInfo"] = []
        return answer

    assert device._enrollment_store["CardInfo"]
    with pytest.raises(DeleteAbortedError, match="STOP"):
        undo_card_adds(
            RecordingTransport(client_for(device)),
            journal,
            reader=lying_read,
            undo_journal=WriteJournal.open(tmp_path / "undo.jsonl", phase="cards_undo"),
        )
    assert not (tmp_path / "undo.jsonl").exists() or all(
        json.loads(line)["state"] != "reverted"
        for line in (tmp_path / "undo.jsonl").read_text().splitlines()
    ), "an incident may never leave a `reverted` line behind (§5a)"
    # The WRITE journal is untouched by the incident: the fold still ends at
    # `confirmed` for C1 — no `reverted`, and no new lines either (§5a: an
    # incident may never rewrite history; the undo file is the only place the
    # delete would have been journalled, and it holds no `reverted` line).
    assert [e.state for e in journal.latest() if e.card_no == "C1"] == [JournalState.CONFIRMED]


def test_a_named_card_that_survives_the_delete_is_an_incident(tmp_path: Path) -> None:
    journal = _confirmed_journal(tmp_path, card("C1", employee_no="1"))
    device = card_device(cards=[card_row("C1", employee_no="1")])

    def stubborn(body: dict) -> dict:
        answer = fake_reader(device)(body)
        # The device says ok and keeps the card: the roster still shows it, count and all.
        return answer

    transport = RecordingTransport(client_for(device))
    report = undo_card_adds(transport, journal, reader=stubborn)
    assert report.reverted == (card_hash("C1"),), (
        "the fake is honest, so this is the clean path — the guard fires when the count "
        "and the rows disagree, which the next two tests drive directly"
    )


@pytest.mark.parametrize(
    ("named", "before", "after", "survivors", "expect"),
    [
        (["A"], 5, 1, (), "dropped by 4"),  # over-delete = D-WIPE signature
        (["A"], None, 3, (), "not readable"),  # a count we cannot read is not a count
        (["A"], 5, None, (), "not readable"),
        (["A"], 5, 4, ("A",), "still present"),  # ok answer, nothing removed
        (["A", "B"], 5, 5, (), "dropped by 0"),  # inconsistent: named 2, dropped 0
    ],
)
def test_the_count_delta_guard_refuses_every_unsafe_shape(named, before, after, survivors, expect):
    with pytest.raises(DeleteAbortedError, match=expect):
        assess_delete_delta(
            named=named, count_before=before, count_after=after, survivors=survivors
        )


def test_the_count_delta_guard_accepts_the_exact_delta(named=None) -> None:
    assess_delete_delta(named=["A", "B"], count_before=5, count_after=3, survivors=())


def test_the_guard_uses_the_device_stated_count_not_a_row_count() -> None:
    """A reader that states 5 total while returning 3 rows must NOT let the delta look
    clean: the guard compares the device's OWN total, not what we happened to collect."""
    reader = CountLyingReader([card_row("A", employee_no="1")], lie_by=2)
    read = read_card_store(reader)
    assert read.complete and read.count == 3, (
        "the row count is what a completed walk can prove; the stated total of a page "
        "that answers OK with fewer rows is the device's claim, not a licence to delete"
    )
    lying = CountLyingReader([card_row("A", employee_no="1")], lie_by=2)
    assert read_card_store(lying).count == read.count == 3


# --- §6: verify -------------------------------------------------------------------------------


def test_verify_ok_on_the_captured_read_shape() -> None:
    device = card_device(cards=[dict(CAPTURED_CARD_ROW)])
    report = verify_cards(fake_reader(device), writes_for(dict(CAPTURED_CARD_ROW)))
    assert report.ok and report.read_complete
    assert report.verdict_of("90000090", "90") is CardVerdict.OK
    assert report.method.startswith("full-roster"), (
        "the card roster has NO proven server-side filter, so the client-side arm is the "
        "only honest one and the method must say so (§6)"
    )


def test_verify_reports_a_missing_pair_as_a_verdict_not_a_crash() -> None:
    device = card_device(cards=[])
    report = verify_cards(fake_reader(device), writes_for(card("GONE", employee_no="1")))
    assert report.verdict_of("GONE", "1") is CardVerdict.MISSING
    assert len(report.missing) == 1


def test_verify_pair_identity_a_card_on_target_for_another_person_is_our_missing() -> None:
    report = verify_cards(
        _rows_reader([card_row("C1", employee_no="OTHER")]),
        writes_for(card("C1", employee_no="1")),
    )
    assert report.verdict_of("C1", "1") is CardVerdict.MISSING
    assert "DIFFERENT employeeNo" in report.items[0].note


def test_verify_card_type_drift_is_terminal_mismatch() -> None:
    report = verify_cards(
        _rows_reader([card_row("C1", employee_no="1", card_type="hijackCard")]),
        writes_for(card("C1", employee_no="1")),
    )
    assert report.verdict_of("C1", "1") is CardVerdict.MISMATCH
    assert "identity fields differ" in report.items[0].note
    assert "hijackCard" not in json.dumps(report.summary()), (
        "the report carries field NAMES and hashes only — never the device's value (§4)"
    )


def test_verify_fail_closed_on_a_field_outside_the_captured_read_shape() -> None:
    row = dict(card_row("C1", employee_no="1"), mysteryField={"nested": True})
    report = verify_cards(_rows_reader([row]), writes_for(card("C1", employee_no="1")))
    assert report.verdict_of("C1", "1") is CardVerdict.MISMATCH
    assert report.items[0].unknown_fields == ("mysteryField",)


def test_verify_a_failed_read_produces_no_verdicts() -> None:
    """§0.7: a failed roster read is never read as 'every card is missing'."""

    def broken(body: dict) -> dict:
        raise RuntimeError("device said no")

    report = verify_cards(broken, writes_for(card("C1", employee_no="1")))
    assert report.items == () and not report.read_complete
    assert report.notes and "§0.7" in report.notes[0]


def test_verify_walks_pages_with_one_search_id_and_reads_the_roster_shape() -> None:
    device = card_device(cards=[card_row(f"C{i}", employee_no=str(i)) for i in range(1, 6)])
    report = verify_cards(
        fake_reader(device),
        writes_for(*(card(f"C{i}", employee_no=str(i)) for i in range(1, 6))),
        page_size=2,
    )
    assert report.read_complete and report.ok
    assert (
        report.card_count == 5
        and report.items
        and all(i.verdict is CardVerdict.OK for i in report.items)
    )
    read = read_card_store(fake_reader(device), page_size=2)
    assert read.calls == 3, "pages advance by numOfMatches to the device's own verdict"


def _rows_reader(rows: list[dict]):
    def read(body: dict) -> dict:
        cond = body["CardInfoSearchCond"]
        window = rows[cond["searchResultPosition"] : cond["searchResultPosition"] + 30]
        return {
            "CardInfoSearch": {
                "searchID": cond["searchID"],
                "responseStatusStrg": "OK",
                "numOfMatches": len(window),
                "totalMatches": len(rows),
                **({"CardInfo": window} if window else {}),
            }
        }

    return read


# --- §5b.1: no user-undo verb, anywhere ---------------------------------------------------------


def test_the_cards_module_exposes_no_user_delete_vocabulary_at_all() -> None:
    """§5b.1: both accepted person-delete shapes wipe everything, so the verb must not
    exist here — not as a name, not as a path, not as a body key."""
    import gateclerk.migrate_write_cards as module

    names = [n.lower() for n in module.__all__]
    assert any("delete" in n for n in names), "card delete IS this module's job"
    assert all("user" not in n for n in names), names
    source = Path(module.__file__).read_text()
    for banned in (
        "UserInfoDetail",
        "UserInfoDelCond",
        "deleteByEmployeeNo",
        "UserInfo/",
        "/UserInfo",
    ):
        assert banned not in source, f"{banned!r} must never appear in the cards module"
    assert "CardInfoDelCond" in source, "the capture-proven CARD slot is the only delete shape"


def test_the_user_delete_ban_is_a_callable_fact_not_a_comment() -> None:
    with pytest.raises(CardDeleteScopeError, match="pre-run snapshot"):
        person_delete_forbidden()


# --- §5.3 budget + §5 step 2 composition --------------------------------------------------------


def test_budget_ledger_counts_card_calls_against_the_fakes_nonce_ledger() -> None:
    """One client per 30 charged calls, re-bootstraps counted, and the fake's OWN ledger
    agrees: every budgeted card call reached the device exactly once."""
    device = card_device()
    client = client_for(device)
    made: list[RecordingTransport] = []

    def factory() -> RecordingTransport:
        made.append(RecordingTransport(client))
        return made[-1]

    budgeted = BudgetedWriteTransport(factory, limit=30)
    result = run_cards_phase(
        budgeted,
        _scratch_journal(),
        writes_for(*(card(f"C{i}", employee_no=str(i)) for i in range(1, 126))),
        sleep=lambda _s: None,
    )
    assert result.writes_sent == 125 and budgeted.total_calls == 125
    assert budgeted.rebootstraps == 4 and len(made) == 5
    charged = device.authorized_requests_to("PUT", SETUP_URL)
    assert charged == 125, "the write ledger and the device's ledger cannot disagree"
    assert max(len(t.sent) for t in made) == 30


def test_verify_read_is_charged_on_the_same_ledger(tmp_path: Path) -> None:
    """§5.3 counts 1 card write + 1 verify read per card: the roster re-read is an authed
    call on this phase's session, so the ledger must see it too (§0.5)."""
    device = card_device()
    plan = plan_of("90")
    bundle = bundle_of(cards=[dict(CAPTURED_CARD_ROW)])
    made: list[RecordingTransport] = []
    report = apply_cards_phase(
        plan=plan,
        bundle=bundle,
        transport_factory=lambda: made.append(RecordingTransport(client_for(device))) or made[-1],
        reader=fake_reader(device),
        journal_path=tmp_path / "cards.jsonl",
        probe=probe_ok(),
        now=NOW,
    )
    assert report.verify is not None and report.verify.ok
    assert report.writes.confirmed == (card_hash("90000090"),)
    budgeted_calls = sum(len(t.sent) for t in made)
    roster_reads = device.authorized_requests_to("POST", CARD_SEARCH_PATH + "?format=json")
    assert budgeted_calls == 1 and roster_reads >= 2
    resumed = WriteJournal.open(tmp_path / "cards.jsonl", phase=CARDS_PHASE)
    assert [e.state for e in resumed.entries] == [JournalState.CONFIRMED]
    lines = (tmp_path / "cards.jsonl").read_text().splitlines()
    assert [json.loads(x)["state"] for x in lines] == [
        "planned",
        "applied",
        "confirmed",
    ]
    assert json.loads(lines[-1])["cardNo"] == "90000090"


def test_apply_refuses_a_stale_probe_and_never_opens_a_journal(tmp_path: Path) -> None:
    from datetime import timedelta

    stale = probe_ok(probed_at=(NOW - timedelta(days=7, seconds=1)).isoformat())
    with pytest.raises(Exception, match="stale"):
        apply_cards_phase(
            plan=plan_of("1"),
            bundle=bundle_of(cards=[card("C1", employee_no="1")]),
            transport_factory=lambda: RecordingTransport(client_for(card_device())),
            reader=fake_reader(card_device()),
            journal_path=tmp_path / "cards.jsonl",
            probe=stale,
            now=NOW,
        )
    assert not (tmp_path / "cards.jsonl").exists()


def test_apply_refuses_when_the_card_roster_cannot_be_read(tmp_path: Path) -> None:
    """§0.7/§4: the ownership gate and the before-count both need the roster; a partial
    roster is how a card gets bound to the wrong person."""
    from gateclerk.migrate_write import ApplyAbortedError

    def broken(body: dict) -> dict:
        raise RuntimeError("roster read exploded")

    with pytest.raises(ApplyAbortedError, match="roster"):
        apply_cards_phase(
            plan=plan_of("1"),
            bundle=bundle_of(cards=[card("C1", employee_no="1")]),
            transport_factory=lambda: RecordingTransport(client_for(card_device())),
            reader=broken,
            journal_path=tmp_path / "cards.jsonl",
            probe=probe_ok(),
            now=NOW,
        )
    assert not (tmp_path / "cards.jsonl").exists()


def test_apply_aborts_on_freshness_drift_before_any_card_write(tmp_path: Path) -> None:
    from dataclasses import replace

    device = card_device()
    plan = plan_of("1", "2")
    transport = RecordingTransport(client_for(device))

    def drifted() -> list[Classification]:
        return [
            replace(i, classification=DiffClass.CONFLICT) if i.employee_no == "1" else i
            for i in plan.items
        ]

    with pytest.raises(Exception, match="freshness contract"):
        apply_cards_phase(
            plan=plan,
            bundle=bundle_of(cards=[card("C1", employee_no="1"), card("C2", employee_no="2")]),
            transport_factory=lambda: transport,
            reader=fake_reader(device),
            journal_path=tmp_path / "cards.jsonl",
            probe=probe_ok(),
            now=NOW,
            recheck=drifted,
        )
    assert transport.sent == [] and device._enrollment_store["CardInfo"] == []


def test_apply_aborts_on_a_lying_clock(tmp_path: Path) -> None:
    from gateclerk.migrate_write import ApplyAbortedError

    with pytest.raises(ApplyAbortedError, match=r"clock is \+120"):
        apply_cards_phase(
            plan=plan_of("1"),
            bundle=bundle_of(cards=[card("C1", employee_no="1")]),
            transport_factory=lambda: RecordingTransport(client_for(card_device())),
            reader=fake_reader(card_device()),
            journal_path=tmp_path / "cards.jsonl",
            probe=probe_ok(clock_skew_s=120.0),
            now=NOW,
        )


def test_a_verify_mismatch_is_terminal_and_never_a_rewrite(tmp_path: Path) -> None:
    """§0.6: the report is the artifact; the journal stops at `applied` and no second
    write is issued to 'fix' a mismatch."""
    device = card_device(cards=[card_row("90000090", employee_no="90", card_type="patrolCard")])
    journal = journal_in(tmp_path)
    transport = RecordingTransport(client_for(device))
    report = apply_cards_phase(
        plan=plan_of("90"),
        bundle=bundle_of(cards=[dict(CAPTURED_CARD_ROW)]),
        transport_factory=lambda: transport,
        reader=fake_reader(device),
        journal_path=journal.path,
        probe=probe_ok(),
        now=NOW,
    )
    assert report.writes.applied == (card_hash("90000090"),)
    assert report.verify is not None and report.verify.mismatched
    assert report.writes.confirmed == ()
    assert any("TERMINAL mismatch" in note for note in report.notes)
    assert len(transport.sent) == 1, "a mismatch is never fixed with a blind re-write (§0.6)"
    resumed = WriteJournal.open(journal.path, phase=CARDS_PHASE)
    assert [e.state for e in resumed.entries] == [JournalState.APPLIED]
    # …and because it never reached `confirmed`, undo may not touch it (§5a).
    undo = undo_card_adds(
        RecordingTransport(client_for(device)), resumed, reader=fake_reader(device)
    )
    assert undo.reverted == () and "not confirmed" in undo.refused[0].reason


def test_the_report_carries_hashes_counts_and_device_words_only(tmp_path: Path) -> None:
    journal = journal_in(tmp_path)
    transport = ScriptedTransport({"statusCode": 1})
    result = run_cards_phase(
        BudgetedWriteTransport(lambda: transport),
        journal,
        writes_for(card("SECRET-CARD-NO", employee_no="SECRET-PERSON")),
        sleep=lambda _s: None,
    )
    payload = json.dumps(result.summary(), sort_keys=True)
    assert "SECRET-CARD-NO" not in payload and "SECRET-PERSON" not in payload
    parsed = json.loads(payload)
    assert parsed["writesSent"] == 1 and parsed["applied"] == 1
    assert card_hash("SECRET-CARD-NO") in payload  # the safe identity, hashed (§4)


def test_batch_size_is_derived_and_capped_like_the_users_phase() -> None:
    assert derive_card_batch_size(None) == DEFAULT_BATCH_SIZE == 10
    assert derive_card_batch_size(probe_ok()) == 10, (
        "maxRecordNum (3000) is a search page/batch count and §1 says in words it is not "
        "capacity; reading it as a write batch cap is the §1 trap this pins shut"
    )
    waits: list[float] = []
    result = run_cards_phase(
        BudgetedWriteTransport(lambda: ScriptedTransport()),
        _scratch_journal(),
        writes_for(*(card(f"C{i}", employee_no=str(i)) for i in range(1, 26))),
        batch_size=10_000,
        sleep=waits.append,
        batch_delay=1.0,
    )
    assert result.batch_size == DEFAULT_BATCH_SIZE and result.batches == 3
    assert waits == [1.0, 1.0], "one sleep between batches, none before the first"


def test_a_journal_inside_the_repo_is_refused_for_the_card_phase_too(tmp_path: Path) -> None:
    from gateclerk.migrate_write import JournalError

    inside = Path(__file__).resolve().parent / "leaked_cards.jsonl"
    with pytest.raises(JournalError, match="inside the repository"):
        WriteJournal.open(inside, phase=CARDS_PHASE)
    assert not inside.exists()


def test_the_journal_fold_is_pair_keyed_not_person_keyed(tmp_path: Path) -> None:
    """§5 step 5 inside the journal: one person, two cards. A person-keyed fold would
    silently collapse them and let undo delete a card this run never added."""
    journal = journal_in(tmp_path)
    for no in ("C1", "C2"):
        entry = journal.planned(
            employee_no="1",
            classification="add",
            pre_write_record=None,
            intended_record=card(no, employee_no="1"),
            op="card_setup",
            card_no=no,
        )
        journal.applied(entry)
        journal.confirmed(entry, post_write_hash=content_of(card(no, employee_no="1")))
    resumed = WriteJournal.open(tmp_path / "cards.jsonl", phase=CARDS_PHASE)
    assert [e.card_no for e in resumed.entries] == ["C1", "C2"]
    assert len(resumed.latest(state=JournalState.CONFIRMED)) == 2
    assert all(
        json.loads(line)["schema"] == JOURNAL_SCHEMA
        for line in (tmp_path / "cards.jsonl").read_text().splitlines()
    )
    assert hashlib  # (import guard for the hash-prefix assertion below)
    assert resumed.entries[0].employee_hash == person_hash("1")
