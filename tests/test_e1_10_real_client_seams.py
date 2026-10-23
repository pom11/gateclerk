"""Card E1-10 defect 1: the production write seams over the REAL client, both shapes.

Why this file exists (the live A->B run, 2026-10-23): the faces phase died before its
first write with::

    AttributeError: 'IsapiClient' object has no attribute 'post'

FakeDevice-strict could not catch that by construction: every injected seam in the other
E1 suites is a duck-typed stand-in that happens to hold a convenient `._client`, so the
seams' private reach `client._client.post(...)` was never tested against the shapes the
CLI actually hands it. This file therefore uses NO FakeDevice and NO test seam: the real
``IsapiClient`` class over ``httpx.MockTransport``, and BOTH transport shapes the CLI can
produce —

* **bare** — what `--verbose` off gives the seams (`IsapiClient`, whose ``_client`` is an
  ``httpx.Client``, so the old private reach happened to work);
* **verbose** — ``pipeline.LoggedClient`` wrapping it, whose ``_client`` is the INNER
  ``IsapiClient`` (``pipeline.py:677``), which is what produced the operator's exact
  string. The orchestrator's refinement is pinned here rather than trusted: the bare
  shape passes on its own, so a suite that tested only bare would have gone green on the
  code that crashed.

Acceptance this file owns (card E1-10 §Acceptance 1-2):

1. the faces phase driven END-TO-END (FDSearch pre-read -> FDSetUp upload -> FDSearch
   read-back) over the real client, with one client per phase and the §5.3 budget intact,
   for BOTH shapes;
2. every other phase's verbs over the same two shapes — users ``put_setup``, cards
   ``put_setup``/``put_delete``, fingerprints ``post_download``/``get_progress`` — the
   same latent bug class, all of which reached into ``_client``;
3. both shapes built through the PRODUCT seam factories (``write_seams_for`` and the CLI's
   ``_migrate_seams``), not just by hand.

The mock box is deliberately minimal: a real digest handshake (401 + ``WWW-Authenticate``
exactly as ``digest_challenge_401.txt`` records it, paid through ``httpx.DigestAuth``),
the captured envelopes for each write verb, and a face store that ECHOES the uploaded
``modelData`` — because ``facesetup_readback_fpid90.json`` proves that linkage on bench A
and the read-back, never the ack, is what confirms (§6).
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

import gateclerk.cli as cli_mod
from gateclerk.isapi_transport import IsapiClient
from gateclerk.migrate_apply import (
    CardWriteTransport,
    FaceWriteTransport,
    FpWriteTransport,
    UserWriteTransport,
    write_seams_for,
)
from gateclerk.migrate_faces import (
    FACE_SEARCH_PATH,
    FACE_SETUP_PATH,
    BudgetedWriteTransport,
    FaceWrite,
    WriteJournal,
    apply_faces_phase,
)
from gateclerk.migrate_fingerprints import FP_DOWNLOAD_PATH, FP_PROGRESS_PATH
from gateclerk.migrate_probe import CapabilityMatrix, SurfaceProbe, Verdict
from gateclerk.migrate_write import (
    USER_SETUP_PATH,
    UserWrite,
    person_hash,
    run_users_phase,
)
from gateclerk.migrate_write_cards import CARD_DELETE_PATH, CARD_SETUP_PATH
from gateclerk.pipeline import LoggedClient, RequestLogger

PASSWORD = "fake" + "pw"  # placeholder policy (tests/test_repo_hygiene.py)
BASE_URL = "http://192.0.2.10"  # TEST-NET (tests/test_repo_hygiene.py allowlist)

RECORDED = Path(__file__).parent / "fixtures/recorded/site-a-ds-k1t341amf-s"
ENROLLMENT = RECORDED / "enrollment"

#: The captured write ack — the ONLY accepted ack in any committed capture (§6).
OK_ACK = {"statusCode": 1, "statusString": "OK", "subStatusCode": "ok"}

#: The registered READ endpoints the CLI's seams factory reads through — spelled here so
#: this file proves the read door is a DIFFERENT door from `raw` (registry-guarded), and
#: that fixing the write path left it exactly as pinned.
USER_SEARCH_PATH = "/ISAPI/AccessControl/UserInfo/Search"
CARD_SEARCH_PATH = "/ISAPI/AccessControl/CardInfo/Search"
FP_UPLOAD_PATH = "/ISAPI/AccessControl/FingerPrintUpload"

#: The captured FDSearch read-back dialect (root envelope, no wrapper). ``modelData`` is
#: filled in from whatever this box was asked to store, so read-back == upload by
#: construction — the linkage the capture proves and the seam must not break.
READBACK_TEMPLATE = "RlI1MDAwMDUBAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

#: A synthetic template (not a device capture): 128 B, decodes clean, well under the
#: sanity ceiling. The seam must carry it VERBATIM — this file checks exactly that.
TPL_BYTES = bytes((i * 11 + 5) % 251 for i in range(128))
TPL_B64 = base64.b64encode(TPL_BYTES).decode("ascii")
TPL_SHA = hashlib.sha256(TPL_BYTES).hexdigest()

NOW = datetime(2026, 10, 23, 12, 0, 0, tzinfo=UTC)

USER_SETUP_BODY = json.loads((ENROLLMENT / "users_setup_add_request.json").read_text())


# --- the mock box ----------------------------------------------------------------------------


class MockBox:
    """One ISAPI-shaped box: the real digest handshake + the captured write verbs.

    Records every authenticated hop it served (``authed``) and every body it accepted
    (``bodies``), so the budget and one-client-per-phase claims are read from what the
    device saw, not from a comment. Un-armed routes 404 loudly: a seam that invents a
    verb has to be visible, and a route that answered everything would hide a wrong path.
    """

    def __init__(self) -> None:
        self.authed = 0
        self.challenges = 0
        self.hops: list[tuple[str, str]] = []  # (method, path-without-query)
        self.bodies: list[Any] = []
        self.faces: dict[str, str] = {}  # FPID -> modelData the box is now holding
        self.users: list[dict[str, Any]] = []  # persons the box accepted

    # -- the transport -----------------------------------------------------------------------

    @property
    def transport(self) -> httpx.MockTransport:
        return httpx.MockTransport(self._handle)

    def _handle(self, request: httpx.Request) -> httpx.Response:
        if "authorization" not in request.headers:
            # The recorded 401 (digest_challenge_401.txt): qop="auth", webs' realm,
            # stale="false". httpx pays it and re-sends with the same body.
            self.challenges += 1
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
        return self._serve(method, path, dict(request.url.params), body)

    def _serve(self, method: str, path: str, params: dict[str, str], body: Any) -> httpx.Response:
        if params.get("format") != "json":
            return self._reject(path, "this family is asked with ?format=json")
        self.bodies.append(body)
        if method == "POST" and path == USER_SEARCH_PATH:
            return httpx.Response(
                200,
                json={
                    "UserInfoSearch": {
                        "searchID": "e110",
                        "responseStatusStrg": "OK",
                        "numOfMatches": 0,
                        "totalMatches": 0,
                    }
                },
            )
        if method == "POST" and path == CARD_SEARCH_PATH:
            return httpx.Response(
                200,
                json={
                    "CardInfoSearch": {
                        "searchID": "e110",
                        "responseStatusStrg": "OK",
                        "numOfMatches": 0,
                        "totalMatches": 0,
                    }
                },
            )
        if method == "POST" and path == FP_UPLOAD_PATH:
            return httpx.Response(
                200,
                json={
                    "FingerPrintUpload": {"employeeNo": "90", "fingerPrintID": 1, "status": "NoFP"}
                },
            )
        if method == "POST" and path == FACE_SEARCH_PATH:
            return self._face_search(body)
        if method == "PUT" and path == FACE_SETUP_PATH:
            assert set(body) == {"faceLibType", "FDID", "FPID", "modelData"}, (
                "FDSetUp may only carry the captured four keys (facesetup_add_request)"
            )
            self.faces[str(body["FPID"])] = body["modelData"]
            return httpx.Response(200, json=OK_ACK)
        if method == "PUT" and path == USER_SETUP_PATH:
            self.users.append(body["UserInfo"])
            return httpx.Response(200, json=OK_ACK)
        if method == "PUT" and path == CARD_SETUP_PATH:
            return httpx.Response(200, json=OK_ACK)
        if method == "PUT" and path == CARD_DELETE_PATH:
            return httpx.Response(200, json=OK_ACK)
        if method == "POST" and path == FP_DOWNLOAD_PATH:
            return httpx.Response(200, json=OK_ACK)
        if method == "GET" and path == FP_PROGRESS_PATH:
            progress = (ENROLLMENT / "fpdownload_progress_reader_reject.json").read_text()
            return httpx.Response(200, json=json.loads(progress))
        return self._reject(path, "route not armed by this card")

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


# --- the two client shapes -------------------------------------------------------------------


def bare_client(box: MockBox, clients: list[Any]) -> IsapiClient:
    client = IsapiClient(
        BASE_URL, "admin", PASSWORD, transport=box.transport, sleep=lambda _s: None
    )
    clients.append(client)
    return client


def verbose_client(box: MockBox, clients: list[Any]) -> LoggedClient:
    """What `--verbose` hands the seams: LoggedClient over the real client (cli.py:438)."""
    client = LoggedClient(
        IsapiClient(BASE_URL, "admin", PASSWORD, transport=box.transport, sleep=lambda _s: None),
        RequestLogger(),
    )
    clients.append(client)
    return client


#: Both shapes, named after how the operator reaches them — a test that runs only one of
#: them is the suite that missed the live crash.
SHAPES = (
    pytest.param(bare_client, id="bare"),
    pytest.param(verbose_client, id="verbose-LoggedClient"),
)


def probe_ok() -> CapabilityMatrix:
    """A fresh matrix; the faces apply gate only needs freshness (§3/§4)."""
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


# --- acceptance 1: the faces phase end-to-end, both shapes -----------------------------------


@pytest.mark.parametrize("shape", SHAPES)
def test_faces_phase_end_to_end_over_the_real_client(shape, tmp_path: Path) -> None:
    """FDSearch pre-read -> FDSetUp -> FDSearch read-back, all through the seam.

    The live crash happened on the FIRST of those three calls, so "the phase completes"
    is the only honest pin. Three more facts ride along because §5/§6 make them
    requirements rather than nice-to-haves: one client for the whole phase (§5.3), the
    budget ledger agreeing with what the box actually served, and `confirmed` earned by
    the read-back rather than the ack.
    """
    box = MockBox()
    clients: list[Any] = []
    journal_path = tmp_path / "faces.jsonl"

    result, journal, verify = apply_faces_phase(
        transport_factory=lambda: FaceWriteTransport(shape(box, clients)),
        journal_path=journal_path,
        writes=(FaceWrite.build("90", TPL_B64), FaceWrite.build("91", TPL_B64)),
        probe=probe_ok(),
        now=NOW,
        sleep=lambda _s: None,
        batch_delay=0.0,
    )

    assert verify is None  # §5.3: the phase's own read-back IS §6 for faces
    assert result.aborted is False and result.clean
    assert len(result.applied) == 2 and len(result.confirmed) == 2
    assert result.already_present == () and result.conflicts == () and result.rejected == ()
    # 1 client for the phase, not one per person (§5.3).
    assert len(clients) == 1, type(clients[0]).__name__
    # The budget: 3 authed calls per person, and the box agrees with our ledger.
    assert result.calls_sent == 6
    assert box.authed == 6, box.hops
    assert box.challenges == 1, "one 401 handshake for the phase's session, not per call"
    # Journal: the §5a terminal sequence for both people, on disk.
    states = [e.state.value for e in journal.latest()]
    assert states == ["confirmed"] * 2
    assert [e.employee_hash for e in journal.latest()] == [
        person_hash("90"),
        person_hash("91"),
    ]
    # The template bytes reached the box verbatim (the seam is transport, not a parser).
    assert box.faces["90"] == TPL_B64
    # Call ORDER for one person: read, write, read (§5a).
    kinds = [h for h in box.hops if h[0] != "PUT" or h[1] != FACE_SETUP_PATH]
    assert kinds[0] == ("POST", FACE_SEARCH_PATH)
    assert box.hops[1] == ("PUT", FACE_SETUP_PATH)


@pytest.mark.parametrize("shape", SHAPES)
def test_the_faces_upload_is_the_captured_four_key_body(shape, tmp_path: Path) -> None:
    """The seam may change HOW it sends, never WHAT it sends (capture-before-fake)."""
    box = MockBox()
    apply_faces_phase(
        transport_factory=lambda: FaceWriteTransport(shape(box, [])),
        journal_path=tmp_path / "faces.jsonl",
        writes=(FaceWrite.build("90", TPL_B64),),
        probe=probe_ok(),
        now=NOW,
        sleep=lambda _s: None,
        batch_delay=0.0,
    )
    uploads = [b for b in box.bodies if isinstance(b, dict) and "modelData" in b]
    assert uploads == [{"faceLibType": "blackFD", "FDID": "1", "FPID": "90", "modelData": TPL_B64}]


# --- acceptance 2: the other phases' verbs, same bug class ------------------------------------


@pytest.mark.parametrize("shape", SHAPES)
def test_users_write_verb_reaches_the_transport(shape, tmp_path: Path) -> None:
    """``UserWriteTransport.put_setup`` -> ``raw.request`` (the live run's users phase)."""
    box = MockBox()
    seam = UserWriteTransport(shape(box, []))
    assert seam.put_setup(USER_SETUP_PATH, USER_SETUP_BODY) == OK_ACK
    assert box.users == [USER_SETUP_BODY["UserInfo"]]
    assert seam.calls == 1


@pytest.mark.parametrize("shape", SHAPES)
def test_users_phase_end_to_end_journals_and_lands(shape, tmp_path: Path) -> None:
    """The same seam driven by the phase: journal ``planned`` -> request -> ``applied``."""
    box = MockBox()
    journal = WriteJournal.open(tmp_path / "users.jsonl", phase="users")
    write = UserWrite(
        employee_no="90", employee_hash=person_hash("90"), record=dict(USER_SETUP_BODY["UserInfo"])
    )
    result = run_users_phase(
        BudgetedWriteTransport(lambda: UserWriteTransport(shape(box, []))),
        journal,
        (write,),
        sleep=lambda _s: None,
        batch_delay=0.0,
    )
    assert result.applied == (person_hash("90"),) and result.writes_sent == 1
    assert [e.state.value for e in journal.latest()] == ["applied"]
    assert box.hops == [("PUT", USER_SETUP_PATH)]


@pytest.mark.parametrize("shape", SHAPES)
def test_cards_verbs_reach_the_transport(shape) -> None:
    """The cards phase's two capture-proven verbs (`put_setup`, `put_delete`)."""
    box = MockBox()
    seam = CardWriteTransport(shape(box, []))
    assert seam.put_setup(CARD_SETUP_PATH, {"CardInfo": {"cardNo": "1"}}) == OK_ACK
    assert seam.put_delete(CARD_DELETE_PATH, {"CardInfoDelCond": {"CardNoList": []}}) == OK_ACK
    assert box.hops == [("PUT", CARD_SETUP_PATH), ("PUT", CARD_DELETE_PATH)]


@pytest.mark.parametrize("shape", SHAPES)
def test_fingerprint_verbs_reach_the_transport(shape) -> None:
    """The FP phase's download POST and its progress GET (the third verb shape)."""
    box = MockBox()
    seam = FpWriteTransport(shape(box, []))
    assert seam.post_download(FP_DOWNLOAD_PATH, {"FingerPrintCfg": {"employeeNo": "90"}}) == OK_ACK
    progress = seam.get_progress(FP_PROGRESS_PATH)
    assert progress["FingerPrintStatus"]["StatusList"][0]["cardReaderRecvStatus"] == 5
    assert box.hops == [("POST", FP_DOWNLOAD_PATH), ("GET", FP_PROGRESS_PATH)]


@pytest.mark.parametrize("shape", SHAPES)
def test_a_rejection_is_still_a_rejection_through_the_new_transport(shape) -> None:
    """The seam's error contract moved with the transport: an unreadable or refused
    answer is a ``WriteRejectedError``, never a silently-missing write (§0.7)."""
    box = MockBox()
    seam = UserWriteTransport(shape(box, []))
    with pytest.raises(Exception) as raised:  # route not armed -> 404/notSupport
        seam.put_setup("/ISAPI/AccessControl/UserInfo/NeverRecorded", {})
    assert "notSupport" in str(raised.value) or "unparseable" in str(raised.value)


# --- acceptance 3: BOTH shapes through the PRODUCT seam factories ------------------------------


@pytest.mark.parametrize("shape", SHAPES)
def test_write_seams_for_hands_every_phase_a_working_seam(shape, tmp_path: Path) -> None:
    """``write_seams_for`` (the composer's factory) must work for both client shapes."""
    box = MockBox()
    clients: list[Any] = []

    def _never_read() -> Any:
        raise AssertionError("this test drives write seams only")

    seams = write_seams_for(
        lambda: shape(box, clients),
        read_target_state=_never_read,
        users_reader=lambda _body: {"UserInfoSearch": {"UserInfo": []}},
        cards_reader=lambda _body: {"CardInfoSearch": {"CardInfo": []}},
        fp_reader=lambda _body: {"FingerPrintUpload": {}},
        faces_reader=lambda _body: {
            "numOfMatches": 0,
            "totalMatches": 0,
            "responseStatusStrg": "NO MATCH",
        },
    )
    for factory, verb, args in (
        (seams.users_transport_factory, "put_setup", (USER_SETUP_PATH, USER_SETUP_BODY)),
        (seams.cards_transport_factory, "put_setup", (CARD_SETUP_PATH, {"CardInfo": {}})),
        (seams.fp_transport_factory, "post_download", (FP_DOWNLOAD_PATH, {"FingerPrintCfg": {}})),
        (seams.faces_transport_factory, "post_face_search", (FACE_SEARCH_PATH, {"FPID": "90"})),
    ):
        seam = factory()
        result = getattr(seam, verb)(*args)
        assert isinstance(result, dict) and seam.calls == 1
        seam.close()  # §5.3: closing a phase's transport closes only its own client
    assert len(clients) == 4, "one client per phase, never one shared across four (§5.3)"


@pytest.mark.parametrize("shape", SHAPES)
def test_the_cli_seams_factory_builds_the_same_working_seams(shape, monkeypatch) -> None:
    """``cli._migrate_seams`` is the path the operator actually ran — mirror it here.

    The read seams go through the registry (``user_info_search`` / ``card_info_search`` /
    ``fd_search`` / ``finger_print_upload``), so this also pins that fixing the WRITE path
    did not widen or break the read-only registry: these reads work because they are
    registered endpoints, and the write verbs work because of ``raw`` — two different
    doors, both exercised over one real client.
    """
    box = MockBox()
    clients: list[Any] = []
    read_client = shape(box, clients)
    seams = cli_mod._migrate_seams(read_client, lambda: shape(box, clients), writable=True)

    # Registry reads on the command's client.
    for reader in (seams.users_reader, seams.cards_reader, seams.faces_reader):
        assert isinstance(reader({"maxResults": 30, "searchResultPosition": 0}), dict)
    # Write seams from the factories.
    assert seams.users_transport_factory().put_setup(USER_SETUP_PATH, USER_SETUP_BODY) == OK_ACK
    assert (
        seams.faces_transport_factory()
        .post_face_search(FACE_SEARCH_PATH, {"FPID": "90"})
        .get("statusCode")
        == 1
    )
    read_client.close()


# --- the regression that used to be the crash ---------------------------------------------------


def test_the_old_private_reach_is_gone_from_the_seams() -> None:
    """Pin the fix at the source level: no seam may name the client's private transport.

    ``client._client`` worked ONLY because the bare client's own ``_client`` is an
    httpx.Client. A test that merely exercises the verbs can pass on both shapes; this one
    fails the moment someone writes ``._client`` back into a seam, which is the difference
    between a green run and a green run that means something.
    """
    import inspect

    from gateclerk import migrate_apply

    source = inspect.getsource(migrate_apply._PhaseWriteTransport)
    source += inspect.getsource(migrate_apply.FaceWriteTransport)
    source += inspect.getsource(migrate_apply.FpWriteTransport)
    # The DOCSTRING names `._client` on purpose (it explains why the private is banned);
    # what must not exist any more is the code that used it.
    assert "self.client._client" not in source, "the seams must go through `client.raw` (E1-10)"
    assert "self.client.raw." in source
    assert "self.client._auth" in source, "the seam still authorizes with the client's digest"


def test_a_wrapper_that_hides_raw_still_fails_loudly() -> None:
    """The seam's contract is `raw`, so a client WITHOUT it raises a NAMED failure.

    This is the honest boundary: `raw` is an explicit escape hatch, not duck typing. A
    future client that cannot expose its transport must fail here, not mid-write with a
    confusing httpx error (and not silently, which would be worse).
    """

    class NoRaw:
        _auth = httpx.DigestAuth("admin", PASSWORD)

        def close(self) -> None:
            return None

    seam = UserWriteTransport(NoRaw())
    with pytest.raises(AttributeError) as raised:
        seam.put_setup(USER_SETUP_PATH, USER_SETUP_BODY)
    assert "raw" in str(raised.value)
    # Nothing reached a device: the seam never got a transport.
    assert "post" not in str(raised.value)


def test_logged_client_forwards_raw_to_the_httpx_transport() -> None:
    """``LoggedClient.__getattr__`` is what makes bare and verbose ONE code path."""
    box = MockBox()
    inner = IsapiClient(BASE_URL, "admin", PASSWORD, transport=box.transport, sleep=lambda _s: None)
    wrapper = LoggedClient(inner, RequestLogger())
    assert wrapper.raw is inner.raw
    assert isinstance(wrapper.raw, httpx.Client)
    inner.close()


def test_face_write_transport_holds_no_verb_beyond_its_phase() -> None:
    """§5.3's structural guarantee survives the fix: the faces seam has no users verb,
    and ``BudgetedWriteTransport`` refuses a verb the transport lacks."""
    box = MockBox()
    seam = FaceWriteTransport(bare_client(box, []))
    assert not hasattr(seam, "put_setup"), "the faces phase must never own the users verb"
    budgeted = BudgetedWriteTransport(lambda: seam)
    with pytest.raises(TypeError):
        budgeted.call("put_setup", USER_SETUP_PATH, {})
    assert box.authed == 0, "a refused verb sends nothing (§0.6)"
    budgeted.close()
