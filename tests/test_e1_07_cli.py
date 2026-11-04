"""Card E1-07: the `gateclerk migrate` CLI group, offline, FakeDevice-strict.

Five commands (§7): probe / export / diff / apply / undo. This file pins what the card
asks for, in the card's own order:

* the five commands exist and their ``--help`` renders;
* ``-o json`` is a stable schema and carries no PII (names, PINs, template bodies — §4);
* ``apply`` WITHOUT ``--apply`` writes zero bytes, proven structurally: the fake's write
  axis is un-armed, where ANY write attempt raises loudly — a green dry run therefore
  proves zero write calls reached the device;
* the phase ORDER — an FP-phase abort (bench A's reality: ack, then the captured
  reader-rejection) stops faces from running at all: the fake sees users + cards writes
  and the FP write, and NO FDSetUp;
* a stopped run is legible: exit != 0 AND the json report names what landed and which
  phases remain (§5 step 4);
* one client (hence one 80-call budget ledger) per phase, never one shared across
  four (§5.3);
* ``undo`` dispatches on the journal's OWN phase, and a journal whose phase has no verb
  (users, fingerprints — §5b.1) is answered with the report-only wording, zero bytes and
  zero device requests;
* ``--on-conflict=abort`` refuses before a write client exists.

Offline by construction: the same redirection the p1-09 harness uses (the REAL
``IsapiClient`` over ``FakeDevice``'s MockTransport), re-pointed per fake box, plus the
autouse ``netoff`` guard that blocks every real socket.

Box discipline: every ``Box()`` re-points the CLI's client factory at ITS device, so the
box constructed LAST is the device the next command talks to. Tests that apply/diff build
their TARGET box immediately before the ``run(...)``.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

import httpx
import pytest
from typer.testing import CliRunner

import gateclerk.cli as cli_mod
from e2e_harness import (
    AC_CAPS_PATH,
    CAPS_PATH,
    DEVICE_INFO_PATH,
    FAKE_PW,
    HOST,
    SYNTH,
    SYSTEM_TIME_PATH,
    fresh_system_time,
)
from fakedevice import (
    CARD_DELETE_PATH,
    CARD_SETUP_PATH,
    USER_SETUP_PATH,
    FakeDevice,
)
from gateclerk.capabilities import capability_cache
from gateclerk.isapi_transport import IsapiClient
from gateclerk.migrate_faces import FACE_DELETE_PATH, FACE_SETUP_PATH
from gateclerk.migrate_fingerprints import FP_DOWNLOAD_PATH, FP_PROGRESS_PATH

RECORDED = Path(__file__).parent / "fixtures/recorded/site-a-ds-k1t341amf-s"

runner = CliRunner()

#: The five §7 commands, spelled once so a rename fails every pin here at once.
COMMANDS = ("probe", "export", "diff", "apply", "undo")

WRITE_PATHS = {
    USER_SETUP_PATH,
    CARD_SETUP_PATH,
    CARD_DELETE_PATH,
    FACE_SETUP_PATH,
    FACE_DELETE_PATH,
    FP_DOWNLOAD_PATH,
    FP_PROGRESS_PATH,
}


# --- the harness -------------------------------------------------------------------------------


class Box:
    """One fake box with the CLI routed at it, recording every client built over it."""

    def __init__(self, monkeypatch: pytest.MonkeyPatch) -> None:
        self.device = FakeDevice(password=FAKE_PW)
        self.clients: list[Any] = []
        self.built_under: list[str] = []
        self._tag = "read"
        self._seed_reads()
        self._wire(monkeypatch)
        global _LATEST_BOX
        _LATEST_BOX = self

    # -- seeding --------------------------------------------------------------------------------

    def _seed_reads(self) -> None:
        """Classic identity/caps routes (recorded bytes), like every enrollment suite."""
        d = self.device
        d.xml_ok("GET", DEVICE_INFO_PATH, (RECORDED / "device_info.xml").read_text())
        d.xml_ok("GET", SYSTEM_TIME_PATH, fresh_system_time())
        d.add(
            "GET",
            CAPS_PATH,
            httpx.Response(200, content=(RECORDED / "acs_capabilities.json").read_bytes()),
        )
        d.json_ok(
            "GET",
            AC_CAPS_PATH,
            json.loads((SYNTH / "access_control_capabilities.json").read_text()),
        )

    # -- the redirection -------------------------------------------------------------------------

    def _wire(self, monkeypatch: pytest.MonkeyPatch) -> None:
        real = IsapiClient
        device = self.device
        harness = self

        def factory(base_url: str, user: str, password: str, **kw: Any) -> IsapiClient:
            client = real(
                base_url, user, password, transport=device.transport, sleep=lambda _s: None
            )
            harness.clients.append(client)
            harness.built_under.append(harness._tag)
            return client

        from gateclerk import cli_shared

        monkeypatch.setattr(cli_shared, "IsapiClient", factory)
        capability_cache().clear()

    def tag(self, label: str) -> None:
        """Label the clients the NEXT command builds (which phase built what)."""
        self._tag = label

    # -- witnesses -------------------------------------------------------------------------------

    def served(self) -> list[str]:
        return [f"{s.method} {s.path}" for s in self.device.served]

    def served_count(self) -> int:
        return len(self.device.served)

    def write_calls(self) -> list[str]:
        """Write-axis paths the fake actually RECEIVED, in arrival order.

        `served.path` is the RAW path — it carries the `?format=json` query this family
        demands — so the match is on the path part only. And the digest handshake puts an
        UNAUTHENTICATED first hop on the wire for every write (the 401 challenge), so the
        witness counts only requests that carried auth (`had_auth`) — like E1-04's
        `authorized_requests_to`. Without both strips every pin on this witness would
        miscount or pass silently.
        """
        return [
            s.path.split("?", 1)[0]
            for s in self.device.served
            if s.had_auth and s.path.split("?", 1)[0] in WRITE_PATHS
        ]


#: The box the CLI is currently wired to (the last Box built — see module docstring).
_LATEST_BOX: Box | None = None


def a_users() -> list[dict]:
    """Bench A's corpus (4 users, full device shape — `seed_enrollment`'s own default).

    The FULL-shape records matter: the write body is built off the bundle's normalized
    person, and the fake's SetUp stores the same full shape, so verify compares like with
    like (the reduced probe-fixture corpus would verify as an unknown-field mismatch).
    """
    from fakedevice import A_CORPUS_USERS

    return [dict(u) for u in A_CORPUS_USERS]


def card_for(no: str, card_no: str) -> dict:
    return {"employeeNo": no, "cardNo": card_no, "cardType": "normalCard"}


@pytest.fixture
def root(tmp_path: Path) -> Path:
    """The private bundles root: OUTSIDE the repo (the modules refuse otherwise, §2)."""
    base = tmp_path / "gateclerk-private"
    base.mkdir()
    base.chmod(0o700)
    return base


def conn() -> list[str]:
    return ["--host", HOST, "--user", "admin", "--password", FAKE_PW]


def run(args: list[str]) -> tuple[int, str]:
    result = runner.invoke(cli_mod.app, args)
    if result.exception is not None and not isinstance(result.exception, SystemExit):
        raise result.exception
    return result.exit_code, result.stdout or ""


def rows(out: str) -> list[dict[str, Any]]:
    return [json.loads(line) for line in out.strip().splitlines() if line.strip()]


# --- the five commands exist and render ---------------------------------------------------------


@pytest.mark.parametrize("name", COMMANDS)
def test_command_exists_and_help_renders(name: str) -> None:
    code, out = run(["migrate", name, "--help"])
    assert code == 0, f"migrate {name} --help exited {code}:\n{out}"
    assert out.strip(), f"migrate {name} --help printed nothing"


def test_group_is_registered_like_device_app() -> None:
    """`migrate` is a group of the root app with exactly the five §7 commands."""
    import typer

    root_cmd = typer.main.get_command(cli_mod.app)
    group = root_cmd.commands["migrate"]  # type: ignore[attr-defined]
    assert sorted(group.commands) == sorted(COMMANDS)


# --- -o json: stable schema, PII-free (§4) ------------------------------------------------------


def test_probe_json_is_stable_and_pii_free(monkeypatch: pytest.MonkeyPatch, root: Path) -> None:
    box = Box(monkeypatch)
    box.device.install_enrollment()
    code, out = run(["migrate", "probe", *conn(), "--bundles-root", str(root), "-o", "json"])
    assert code == 0, out
    (payload,) = rows(out)
    for key in ("site", "host", "surfaces", "probed_at", "persisted_to"):
        assert key in payload, f"probe json lost the stable key {key!r}"
    _assert_pii_free(out, roster_names=a_users())


def test_export_json_is_stable_and_pii_free(monkeypatch: pytest.MonkeyPatch, root: Path) -> None:
    box = Box(monkeypatch)
    _source_seed(box.device)
    code, out = run(["migrate", "export", *conn(), "--bundles-root", str(root), "-o", "json"])
    assert code == 0, out
    (payload,) = rows(out)
    assert payload["schema"] == "gateclerk-migrate-export/1"
    assert payload["counts"]["users"] == len(a_users())
    assert Path(payload["bundle"]).is_dir()
    _assert_pii_free(out, roster_names=a_users())


def test_diff_json_is_stable_and_pii_free(monkeypatch: pytest.MonkeyPatch, root: Path) -> None:
    box = Box(monkeypatch)
    _source_seed(box.device)
    bundle = _export(box, root, name="snapshot")
    # diff against the SAME box: probe then diff (the fresh-probe gate, §3/§4).
    code, _ = run(["migrate", "probe", *conn(), "--bundles-root", str(root), "-o", "json"])
    assert code == 0
    code, out = run(
        ["migrate", "diff", "--bundle", bundle, *conn(), "--bundles-root", str(root), "-o", "json"]
    )
    assert code == 0, out  # source == target: nothing pending
    (diff,) = rows(out)
    assert diff["schema"] == "gateclerk-migrate-diff-cli/1"
    assert diff["exitCode"] == 0
    people = diff["diff"]["people"]
    assert people and all(set(p) >= {"classification", "employee", "would_write"} for p in people)
    _assert_pii_free(out, roster_names=a_users())


def test_diff_builds_no_write_client(monkeypatch: pytest.MonkeyPatch, root: Path) -> None:
    """§7: `diff` constructs no write client and puts no write on the wire.

    Enforced in the product (``_migrate_seams(writable=False)`` factories raise
    AssertionError, they do not build), pinned here on the wire: diff over a bundle with
    real pending adds, write axis UN-armed, exits normally — a write path would hit the
    raise (nonzero + traceback) or the fake's loud refusal.
    """
    _export_pending_box(monkeypatch, root)
    _pending_target_box(monkeypatch, root, armed=False)
    code, out = run(
        [
            "migrate",
            "diff",
            "--bundle",
            _last_bundle(root),
            *conn(),
            "--bundles-root",
            str(root),
            "-o",
            "json",
        ]
    )
    assert code == 1, out  # person 3 pending -> exit 1, still zero writes
    (diff,) = rows(out)
    assert diff["exitCode"] == 1
    box = _current_box()
    assert box.write_calls() == [], f"diff put writes on the wire: {box.write_calls()}"


# --- apply without --apply: zero bytes, structurally --------------------------------------------


def test_apply_without_flag_writes_zero_bytes_even_with_work_pending(
    monkeypatch: pytest.MonkeyPatch, root: Path
) -> None:
    """A plan with real pending writes + an UN-ARMED write axis + exit 1 + zero writes.

    The fake refuses every write verb loudly when `install_write_capture` was never
    called (EnrollmentProtocolError, not a 404), so a green dry run proves no write
    request reached the transport: `confirm=False` opens no journal, builds no
    transport, constructs no write client (composer short-circuit).
    """
    _export_pending_box(monkeypatch, root)
    target = _pending_target_box(monkeypatch, root, armed=False)
    code, out = run(
        [
            "migrate",
            "apply",
            "--bundle",
            _last_bundle(root),
            *conn(),
            "--bundles-root",
            str(root),
            "-o",
            "json",
        ]
    )
    assert code == 1, out  # changes pending (§4's dry-run exit); NO --apply => no writes
    (report,) = rows(out)
    assert report["mode"] == "dry_run"
    assert report["wouldRun"] == ["users", "cards", "fingerprints", "faces"]
    assert report["ranPhases"] == []
    assert report["stoppedAt"] is None
    assert target.write_calls() == [], "a dry run touched the write axis"
    # The report's forward undo preview must be as honest as `undo` itself: this
    # project has already been burned by an `ok` that meant something else, so the
    # dry-run report may NEVER promise an undo verb for a phase that has no safe
    # verb (§5b.1: users delete wipes everyone, FP delete was never captured).
    undo = report["undo"]
    assert undo["users"]["mode"] == "report_only", undo["users"]
    assert undo["fingerprints"]["mode"] == "report_only", undo["fingerprints"]
    assert undo["cards"]["mode"] == "journal" and undo["faces"]["mode"] == "journal"


def test_dry_run_names_planned_writes_per_phase(
    monkeypatch: pytest.MonkeyPatch, root: Path
) -> None:
    """The dry run reports EXACTLY which phases would run and what each would write."""
    _export_pending_box(monkeypatch, root)
    _pending_target_box(monkeypatch, root, armed=False)
    code, out = run(
        [
            "migrate",
            "apply",
            "--bundle",
            _last_bundle(root),
            *conn(),
            "--bundles-root",
            str(root),
            "-o",
            "json",
        ]
    )
    assert code == 1, out
    (report,) = rows(out)
    assert report["plannedWrites"] == {
        "users": 1,
        "cards": 1,
        "fingerprints": 1,
        "faces": 1,
    }, f"person 3 is the one pending add on every axis: {report['plannedWrites']}"


# --- the composer: phase order, first-stop, legible refusal ------------------------------------


def test_fp_abort_stops_faces_from_running_and_run_is_legible(
    monkeypatch: pytest.MonkeyPatch, root: Path
) -> None:
    """The card's centre pin, end to end through the CLI.

    bench-A reality: FingerPrintDownload answers statusCode 1, then the captured
    `cardReaderRecvStatus:5` progress rejection — the FP phase aborts on the FIRST such
    answer (§5 step 4). The composer must then NOT run faces: the fake sees users, cards
    and the FP write, and NO FDSetUp upload ever arrives. The exit is nonzero AND the
    json names what landed (user, card) and which phases remain (faces).
    """
    _export_pending_box(monkeypatch, root)
    target = _pending_target_box(monkeypatch, root, armed=True)
    target.tag("apply")
    code, out = run(
        [
            "migrate",
            "apply",
            "--bundle",
            _last_bundle(root),
            *conn(),
            "--bundles-root",
            str(root),
            "--apply",
            "-o",
            "json",
        ]
    )
    assert code == 1, f"an aborted run must exit nonzero with the report printed:\n{out}"
    calls = target.write_calls()
    assert calls.count(USER_SETUP_PATH) == 1, calls
    assert calls.count(CARD_SETUP_PATH) == 1, calls
    assert calls.count(FP_DOWNLOAD_PATH) == 1, calls
    assert FACE_SETUP_PATH not in calls, f"faces ran after the FP abort: {calls}"
    assert FACE_DELETE_PATH not in calls

    (report,) = rows(out)
    assert report["stoppedAt"] == "fingerprints"
    assert report["remainingPhases"] == ["faces"]
    assert report["clean"] is False
    assert report["exitCode"] == 1
    landed = report["landed"]
    assert landed.get("users"), f"report must name landed users: {landed}"
    assert landed.get("cards"), f"report must name landed cards: {landed}"
    assert report["journalDir"]
    _assert_pii_free(out, roster_names=a_users())


def test_apply_writes_journals_one_per_phase(monkeypatch: pytest.MonkeyPatch, root: Path) -> None:
    """§5a: one journal per phase under the run dir, 0600 each, named by phase."""
    _export_pending_box(monkeypatch, root)
    target = _pending_target_box(monkeypatch, root, armed=True)
    target.tag("apply")
    code, out = run(
        [
            "migrate",
            "apply",
            "--bundle",
            _last_bundle(root),
            *conn(),
            "--bundles-root",
            str(root),
            "--apply",
            "-o",
            "json",
        ]
    )
    assert code == 1, out
    report = rows(out)[0]
    run_dir = Path(report["journalDir"])
    assert run_dir.is_dir() and run_dir.is_relative_to(root)
    for phase in ("users", "cards", "fingerprints"):
        journal = run_dir / f"{phase}.jsonl"
        present = sorted(p.name for p in run_dir.iterdir())
        assert journal.is_file(), f"no journal for phase {phase}: {present}"
        assert (journal.stat().st_mode & 0o777) == 0o600, f"{phase} journal not 0600"
    assert not (run_dir / "faces.jsonl").exists(), (
        "the faces phase never ran, so it gets no journal (§5a: a journal means a phase)"
    )


def test_one_client_per_phase_never_shared(monkeypatch: pytest.MonkeyPatch, root: Path) -> None:
    """§5.3: each phase pulled its OWN client from the factory (own 80-call ledger).

    Identity, not counting: no object appears twice, and the number is at least the read
    pass plus the three phases that ran — so the phases demonstrably did not reuse the
    command's read client or each other's.
    """
    _export_pending_box(monkeypatch, root)
    target = _pending_target_box(monkeypatch, root, armed=True)
    target.tag("apply")
    code, _out = run(
        [
            "migrate",
            "apply",
            "--bundle",
            _last_bundle(root),
            *conn(),
            "--bundles-root",
            str(root),
            "--apply",
            "-o",
            "json",
        ]
    )
    assert code == 1
    apply_clients = [
        c for c, tag in zip(target.clients, target.built_under, strict=True) if tag == "apply"
    ]
    assert len(set(map(id, apply_clients))) == len(apply_clients) >= 4, (
        f"expected >=4 distinct clients (read + users + cards + fingerprints), got "
        f"{len(apply_clients)} / {len(set(map(id, apply_clients)))} distinct"
    )


# --- undo: dispatch by the journal's own phase (§5a/§5b.1) --------------------------------------


def test_undo_users_journal_is_report_only_with_zero_device_requests(
    monkeypatch: pytest.MonkeyPatch, root: Path
) -> None:
    """§5b.1: a users journal gets the owning module's words, zero bytes, zero requests."""
    journal, target = _apply_to_fingerprint_abort(monkeypatch, root)
    users_journal = journal / "users.jsonl"
    assert users_journal.is_file(), sorted(p.name for p in journal.iterdir())
    before = target.served_count()
    code, out = run(["migrate", "undo", "--journal", str(users_journal), "-o", "json"])
    assert code == 0, out
    assert target.served_count() == before, "a report-only undo must not touch the device"
    (report,) = rows(out)
    assert report["phase"] == "users"
    assert report["mode"] == "report_only"
    assert report["ok"] is True and report["exitCode"] == 0
    text = json.dumps(report).lower()
    assert "report-only" in text and "restore" in text, f"report-only wording missing: {report}"
    # §5b.1 vocabulary ban: the answer never offers a person-delete verb.
    assert "delete the user" not in text and "remove the person" not in text


def test_undo_fingerprints_journal_is_report_only(
    monkeypatch: pytest.MonkeyPatch, root: Path
) -> None:
    journal, target = _apply_to_fingerprint_abort(monkeypatch, root)
    fp_journal = journal / "fingerprints.jsonl"
    assert fp_journal.is_file()
    before = target.served_count()
    code, out = run(["migrate", "undo", "--journal", str(fp_journal), "-o", "json"])
    assert code == 0, out
    assert target.served_count() == before, "FP undo is manual at the device (bench A)"
    (report,) = rows(out)
    assert report["phase"] == "fingerprints"
    assert report["mode"] == "report_only"
    assert report["ok"] is True


def test_undo_dispatches_on_journal_content_not_file_name(
    monkeypatch: pytest.MonkeyPatch, root: Path
) -> None:
    """A users journal renamed to `cards.jsonl` still answers users (§5a: content wins)."""
    journal, _target = _apply_to_fingerprint_abort(monkeypatch, root)
    disguised = journal / "cards.jsonl"
    (journal / "users.jsonl").rename(disguised)
    code, out = run(["migrate", "undo", "--journal", str(disguised), "-o", "json"])
    assert code == 0, out
    (report,) = rows(out)
    assert report["phase"] == "users", "undo guessed the phase from the file name"


def test_undo_refuses_a_journal_it_cannot_read(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    torn = tmp_path / "faces.jsonl"
    torn.write_text('{"phase": "faces", "state": "confirmed"\n', encoding="utf-8")
    code, out = run(["migrate", "undo", "--journal", str(torn), "-o", "json"])
    assert code == 2, out
    (payload,) = rows(out)
    assert "undo refused" in payload["error"]


def test_undo_cards_journal_uses_the_capture_proven_verb(
    monkeypatch: pytest.MonkeyPatch, root: Path
) -> None:
    """The cards journal gets its targeted delete + its OWN undo journal (§5a)."""
    journal, target = _apply_to_fingerprint_abort(monkeypatch, root)
    cards_journal = journal / "cards.jsonl"
    assert cards_journal.is_file()
    before_writes = len(target.write_calls())
    code, out = run(["migrate", "undo", "--journal", str(cards_journal), *conn(), "-o", "json"])
    assert code == 0, out
    (report,) = rows(out)
    assert report["phase"] == "cards"
    assert report["mode"] == "journal"
    assert report["ok"] is True, report
    assert CARD_DELETE_PATH in target.write_calls()[before_writes:], (
        "cards undo must use the capture-proven CardInfo/Delete"
    )
    undo_journal = journal / "cards.undo.jsonl"
    assert undo_journal.is_file(), "undo must journal into its OWN file (§5a)"
    # The write journal itself is append-only history: undo never rewrote it.
    assert cards_journal.stat().st_size > 0


# --- --on-conflict=abort refuses before any write client exists --------------------------------


def test_on_conflict_abort_refuses_before_any_write_client(
    monkeypatch: pytest.MonkeyPatch, root: Path
) -> None:
    """The bundle binds a card to person 2; the TARGET binds it to person 1.

    That is E1-02's `card_no_bound_to_other_employee` conflict (§4). With
    ``--on-conflict=abort`` the run exits 2 at PLAN time — the composed refusal names
    plan as the stop, lands nothing, and the fake (write axis un-armed) receives no
    write verb.
    """
    _conflict_bundle(monkeypatch, root)  # rival box: card 10000001 -> person 2
    target = _pending_target_box(monkeypatch, root, armed=False, rival_card=True)  # -> person 3
    code, out = run(
        [
            "migrate",
            "apply",
            "--bundle",
            _last_bundle(root),
            *conn(),
            "--bundles-root",
            str(root),
            "--on-conflict",
            "abort",
            "--apply",
            "-o",
            "json",
        ]
    )
    assert code == 2, f"conflict-abort must be the config-class exit 2:\n{out}"
    (report,) = rows(out)
    assert report["stoppedAt"] == "plan"
    assert report["remainingPhases"] == ["users", "cards", "fingerprints", "faces"]
    assert report["landed"] == {}
    assert target.write_calls() == [], "abort path must not touch the write axis"


# --- table rendering: the human view of the same computation -----------------------------------


def test_apply_dry_run_table_reports_phase_order(
    monkeypatch: pytest.MonkeyPatch, root: Path
) -> None:
    _export_pending_box(monkeypatch, root)
    _pending_target_box(monkeypatch, root, armed=False)
    code, out = run(
        ["migrate", "apply", "--bundle", _last_bundle(root), *conn(), "--bundles-root", str(root)]
    )
    assert code == 1, out
    assert "DRY RUN (zero bytes written)" in out
    assert "users -> cards -> fingerprints -> faces" in out
    assert "phases that did NOT run" not in out  # a dry run stopped at nothing


# --- helpers ------------------------------------------------------------------------------------


def _source_seed(device: FakeDevice) -> None:
    """Bench-A-shaped SOURCE: 3 users, and person "1" carries card + face + FP.

    Store mode (`seed_enrollment`/`seed_biometric`) — the paging-honest seeding every
    export suite uses: the FDSearch walker must be able to terminate (the installed-axis
    handler ignores `searchResultPosition` and would trip the runaway cap). Every user
    carries a face template (bench A: `numOfFace=1` on all, §1 — leaving one unseeded
    would classify that person `unknown_enrollments`, not `same`), and bench A recorded
    exactly ONE fingerprint holder (user "1", the §1 "cannot migrate" one), so the whole
    migration payload rides on that person.
    """
    from fakedevice import A_FD_ROWS, A_FP_ROWS

    users = a_users()
    nos = [str(u["employeeNo"]) for u in users]
    device.install_enrollment()  # caps documents + identity axis
    device.seed_enrollment(users=users, cards=[card_for("1", "30000003")])
    device.seed_biometric(
        faces={no: A_FD_ROWS[no] for no in nos},
        fingerprints={("1", 0): A_FP_ROWS[("1", 0)]},
    )


def _target_seed(device: FakeDevice, *, armed: bool, rival_card: bool = False) -> None:
    """The migration TARGET: everyone EXCEPT person "1"; no cards/faces/FP of theirs.

    Person "1" is therefore a pure add on every axis (1 user + 1 card + 1 face + 1 FP).
    The people who ARE here carry the same face template bytes as the source, so they
    classify `same` and the run's only work is person "1".
    ``armed=True`` arms the captured write axis with bench A's FP reality
    (``fp_applies=False``: ack, store nothing, progress answers the captured
    reader-rejection) and faces applying. ``rival_card=True`` binds card 10000001 to
    person "3" here (the conflict scenario; the rival SOURCE binds it to person "2").
    """
    from fakedevice import A_FD_ROWS

    users = a_users()[1:]  # drop "1" — the pending person
    nos = [str(u["employeeNo"]) for u in users]
    device.install_enrollment()
    device.seed_enrollment(
        users=users,
        cards=[card_for("3", "10000001")] if rival_card else [],
    )
    device.seed_biometric(faces={no: A_FD_ROWS[no] for no in nos}, fingerprints={})
    if armed:
        device.install_write_capture(users=users, cards=[], fp_applies=False, faces_applies=True)


def _export(box: Box, root: Path, *, name: str) -> str:
    """`gateclerk migrate export` against whatever box is currently wired."""
    out_dir = root / "bundles" / name
    code, out = run(
        [
            "migrate",
            "export",
            *conn(),
            "--bundles-root",
            str(root),
            "--out",
            str(out_dir),
            "-o",
            "json",
        ]
    )
    assert code == 0, out
    return rows(out)[0]["bundle"]


def _last_bundle(root: Path) -> str:
    """Path of the most recent export (the helpers export into fixed names)."""
    candidates = sorted((root / "bundles").glob("*"), key=lambda p: p.stat().st_mtime)
    return str(candidates[-1])


def _export_pending_box(monkeypatch: pytest.MonkeyPatch, root: Path) -> Box:
    """A SOURCE box exported to a bundle (person "1" carries the migration payload)."""
    box = Box(monkeypatch)
    _source_seed(box.device)
    _export(box, root, name="source-snapshot")
    return box


def _conflict_bundle(monkeypatch: pytest.MonkeyPatch, root: Path) -> Box:
    """A SOURCE box whose card 10000001 belongs to person 2 (the target will disagree).

    Both rivals are people the TARGET also has, so the disagreement is PURELY a card
    pair-identity conflict (`card_no_bound_to_other_employee`, §5 step 5) — not an
    artifact of a person existing on only one side.
    """
    from fakedevice import A_FD_ROWS

    box = Box(monkeypatch)
    users = a_users()
    nos = [str(u["employeeNo"]) for u in users]
    box.device.install_enrollment()
    box.device.seed_enrollment(users=users, cards=[card_for("2", "10000001")])
    box.device.seed_biometric(faces={no: A_FD_ROWS[no] for no in nos}, fingerprints={})
    _export(box, root, name="rival-snapshot")
    return box


def _pending_target_box(
    monkeypatch: pytest.MonkeyPatch, root: Path, *, armed: bool, rival_card: bool = False
) -> Box:
    """The TARGET box + a fresh probe for this host (the gate artifact diff/apply need).

    ``armed`` decides whether write verbs are servable (see ``_target_seed``).
    """
    box = Box(monkeypatch)
    _target_seed(box.device, armed=armed, rival_card=rival_card)
    code, _ = run(["migrate", "probe", *conn(), "--bundles-root", str(root), "-o", "json"])
    assert code == 0
    return box


def _apply_to_fingerprint_abort(monkeypatch: pytest.MonkeyPatch, root: Path) -> tuple[Path, Box]:
    """Run `apply --apply` to the FP abort; return (journal dir, the target box)."""
    _export_pending_box(monkeypatch, root)
    target = _pending_target_box(monkeypatch, root, armed=True)
    target.tag("apply")
    code, out = run(
        [
            "migrate",
            "apply",
            "--bundle",
            _last_bundle(root),
            *conn(),
            "--bundles-root",
            str(root),
            "--apply",
            "-o",
            "json",
        ]
    )
    assert code == 1, f"the FP phase must abort the run:\n{out}"
    run_dir = Path(rows(out)[0]["journalDir"])
    return run_dir, target


def _current_box() -> Box:
    """The box the CLI currently talks to (the last one built; see module docstring)."""
    assert _LATEST_BOX is not None, "no Box wired yet"
    return _LATEST_BOX


def _assert_pii_free(text: str, *, roster_names: list[dict]) -> None:
    """§4: no roster name, no record-form PIN/template keys, no base64 bodies.

    The banned set follows the E1-03 precedent (test_migrate_probe): the caps documents
    legitimately carry field CLAIMS (`"password":{"@min":0...}` is a range, not a PIN),
    so the pin is on RECORD forms — a key carrying a value — plus the fake's template
    markers and any long base64 run.
    """
    for record in roster_names:
        name = str(record.get("name", ""))
        assert not name or name not in text, f"roster name {name!r} leaked into output"
    for banned in (
        '"employeeNo"',
        '"password": "',
        '"password":"',
        '"fingerData"',
        '"modelData"',
        "FAKE-FP-TEMPLATE",
        "FAKE-FACE-MODEL",
        "LOCALS/pic",
    ):
        assert banned not in text, f"machine output leaked the record-form key {banned!r}"
    # A base64 body must never ride machine output. Token-level: 60+ chars of base64
    # charset, excluding paths (contain '/') and sha256 index hex (pure [0-9a-f]{64},
    # which the bundle index legitimately carries as content-address identity).
    for token in re.split(r"[^A-Za-z0-9+/=]+", text):
        if len(token) < 60 or "/" in token:
            continue
        if re.fullmatch(r"[0-9a-f]{64}", token):
            continue
        raise AssertionError(
            f"a 60+ char base64 run appeared in machine output — template bytes never "
            f"travel in CLI output (§4): {token[:24]}…"
        )
