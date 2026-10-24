"""E1-07: the §5 step-2 phase composer — one run, four phases, ordered, one journal each.

Every write module before this card shipped its own ``apply_*_phase`` seam and none of
them composed §5's order::

    users → cards → fingerprints → faces      (§5 step 2: "a card/face/FP needs its person")

Each phase already verifies ITSELF (§6 lives inside ``apply_users_phase`` /
``apply_cards_phase`` / ``apply_fingerprints_phase`` / ``apply_faces_phase``), so what
was missing is only the run around them: which phase goes next, whether the phase
before it gave permission to continue, where its journal lives, and what the operator
sees when the run stops half-way. That is this module, and it adds **no policy**:

* no gate is re-implemented — the clock-skew gate (§5.1a), the stale-probe gate
  (§3/§4) and the freshness re-diff (§4) are the users phase's own first moves and are
  not repeated for the phases below it (a face template carries no wall-clock string,
  so §5.1a cannot corrupt it, and the users phase already refused a lying clock);
* no conflict handling is invented — ``--on-conflict`` lands on E1-02's
  :class:`~gateclerk.migrate_diff.ConflictPolicy` in the plan handed in;
* no journal rules are duplicated — one journal per phase (§5a), 0600 and the repo-out
  refusal come from :class:`~gateclerk.migrate_write.WriteJournal` itself;
* no second budget: every phase gets its **own** :class:`BudgetedWriteTransport` over
  its **own** factory (§5.3 — "one long-lived client per phase"). The composer holds no
  client, read or write, of its own.

Three decisions this module had to make, and why:

1. **A phase with zero writes still RUNS, it is not skipped.** An empty write list is a
   fact about the diff, not about the phase; the user/card splitters return a
   zero-write result without touching a transport, and the biometric phases' pre-read
   is what decides ``already_present`` vs ``conflict``. So every phase gets its slot,
   its journal and its line in the report (a phase with nothing to write costs no
   authed call).
2. **A verify that disagrees stops the run even when the phase reports "clean".**
   §0.6/§5 step 7 make a verify mismatch terminal for the RUN, while each phase
   result's ``clean`` means "no abort and no rejection" — it cannot see a mismatch that
   was journalled ``rejected`` (fingerprints) or reported terminal by its own verify
   (users/cards/faces). The composer therefore reads each phase's verify verdict too:
   a phase does not get to define its own passing grade.
3. **``confirm=False`` (no ``--apply``) is zero-byte structurally, not by convention:**
   the dry run opens no journal, builds no transport and constructs no write client.
   The write lists come from the pure ``plan_*_writes`` splitters over one fresh target
   read, so there is no code path from a dry run to a write verb. The test proves it by
   leaving the fake's write axis un-armed, where any write would raise loudly.

Undo (:func:`undo_journal`) dispatches on the JOURNAL'S OWN PHASE, read from the
lines' ``phase`` field — never from a file name. Cards and faces have capture-proven
targeted deletes and get their verbs; users and fingerprints have none on this
firmware (§5b.1) and get the owning module's REPORT-ONLY wording and zero bytes.
"""

from __future__ import annotations

import contextlib
import json
import os
import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from gateclerk.migrate_bundle import BundleData
from gateclerk.migrate_diff import (
    ConflictPolicy,
    DiffPolicy,
    Plan,
    TargetBiometrics,
    TemplateRef,
    plan_still_valid,
)
from gateclerk.migrate_diff import plan as build_plan
from gateclerk.migrate_diff import (
    render_report as render_diff_report,
)
from gateclerk.migrate_export import EnrollmentState
from gateclerk.migrate_faces import (
    FacePhaseAbortedError,
    FacesUndoReport,
    FaceWrite,
    ReaderCaller,
    apply_faces_phase,
    bundle_face_magics,
    faces_report,
    plan_face_writes,
    undo_faces,
)
from gateclerk.migrate_fingerprints import (
    FP_UNDO_REPORT_ONLY,
    FpAbortedError,
    FpFleetReport,
    FpReadError,
    FpReadOutcome,
    FpWrite,
    apply_fingerprints_phase,
    plan_fingerprint_writes,
    read_fingerprint_template,
    report_only_fingerprint_undo,
)
from gateclerk.migrate_probe import CapabilityMatrix
from gateclerk.migrate_write import (
    ApplyAbortedError,
    BudgetedWriteTransport,
    SearchReader,
    UsersVerifyReport,
    UserWrite,
    WriteAbortedError,
    WriteJournal,
    WriteRejectedError,
    apply_users_phase,
    person_hash,
    plan_user_writes,
)
from gateclerk.migrate_write_cards import (
    CARDS_PHASE,
    UNDO_PHASE,
    CardsApplyReport,
    apply_cards_phase,
    plan_card_writes,
    undo_card_adds,
)

__all__ = [
    "BUNDLES_DIR_NAME",
    "JOURNAL_SUFFIX",
    "PHASES",
    "PROBES_DIR_NAME",
    "REPORT_SCHEMA",
    "RUNS_DIR_NAME",
    "UNDO_PHASES",
    "UNDO_SCHEMA",
    "USER_UNDO_REPORT_ONLY",
    "ApplySeams",
    "BundleApplyReport",
    "MigratePlan",
    "PhaseInputs",
    "PhaseRun",
    "UndoRunReport",
    "apply_bundle",
    "bundle_root",
    "default_journal_dir",
    "dry_run_writes",
    "journal_file_name",
    "migrate_plan",
    "person_report_only_undo",
    "phase_order",
    "plan_phase_inputs",
    "probes_root",
    "render_undo_report",
    "runs_root",
    "undo_journal",
]

#: The machine-report schema token, spelled like the diff's ``gateclerk-migrate-diff/1``
#: and the journal's ``gateclerk-migrate-journal/1``: a consumer that does not know this
#: exact value should refuse the document rather than half-read it (§0.7).
REPORT_SCHEMA = "gateclerk-migrate-apply/1"

#: The same token for the undo report (`gateclerk migrate undo`).
UNDO_SCHEMA = "gateclerk-migrate-undo/1"

#: §5 step 2's phase order, verbatim — the only order this module runs.
PHASES: tuple[str, ...] = ("users", "cards", "fingerprints", "faces")

#: The journal phase tokens undo may dispatch on. ``users`` and ``fingerprints`` are in
#: here because undo must be able to READ such a journal and answer in words (§5b.1).
UNDO_PHASES = frozenset({"users", CARDS_PHASE, "fingerprints", "faces"})

#: §5a's journal naming. §5a names the rules (append-only, one journal per phase, undo
#: gets its own) but not the file names, so the decision is stated here once:
#: ``<run-dir>/<phase>.jsonl`` and ``<run-dir>/<phase>.undo.jsonl`` — the directory is
#: the run identity, the file name is the phase, so `undo --journal` can be pointed at
#: exactly the phase a human names.
JOURNAL_SUFFIX = "jsonl"

#: §2's private root. The refusal that keeps PII out of the repo lives in
#: ``migrate_bundle``/``WriteJournal``; this module only decides where the private root
#: is, so no command invents a default and two commands cannot invent different ones.
BUNDLES_DIR_NAME = "bundles"
PROBES_DIR_NAME = "probes"  # `migrate_probe.probes_dir` owns the layout under it
RUNS_DIR_NAME = "runs"

#: §5b.1's users-axis wording. The callable fact behind it is
#: ``migrate_write_cards.person_delete_forbidden``; the words live in the module that
#: owns the ban so this file never has to spell a person-delete verb.
USER_UNDO_REPORT_ONLY = (
    "user undo is REPORT-ONLY: this firmware has no targeted person delete — both "
    "shapes it accepts answered ok and removed the WHOLE roster (§5b.1, OBSERVED.md, "
    "reproduced twice on bench A). Restore or re-enroll that person from the pre-run "
    "snapshot bundle; this run removes nothing."
)


# --- the seams --------------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class ApplySeams:
    """Every device-facing seam the composer may use, injected as one object.

    Four write factories rather than one, because §5.3's budget is per phase: a shared
    factory would make four phases share one ledger. The readers are registry-guarded
    read endpoints (the same clients the export uses) — the plan pass and every verify
    read are READS, so the diff command can honestly say no write client was built.
    """

    read_target_state: Callable[[], EnrollmentState]
    """Fresh full target read — §4: the target is never a cached/bundled view."""

    users_transport_factory: Callable[[], Any]
    cards_transport_factory: Callable[[], Any]
    fp_transport_factory: Callable[[], Any]
    faces_transport_factory: Callable[[], Any]

    users_reader: SearchReader
    """``user_info_search`` — the users phase's §6 verify read."""

    cards_reader: SearchReader
    """``card_info_search`` — the cards roster read (ownership gate + verify)."""

    fp_reader: Callable[[Mapping[str, Any]], Mapping[str, Any]]
    """``finger_print_upload`` — the only route to an FP ``confirmed``."""

    faces_reader: Callable[[Mapping[str, Any]], dict[str, Any]]
    """``fd_search`` — the plan pass's target face set (read axis only)."""


@dataclass(frozen=True, slots=True)
class PhaseInputs:
    """What each phase will be asked to write — derived from plan + bundle, device-free."""

    users: tuple[UserWrite, ...] = ()
    users_skipped: tuple[tuple[str, str], ...] = ()
    cards: tuple[Any, ...] = ()
    cards_skipped: tuple[tuple[str, str], ...] = ()
    fingerprints: tuple[FpWrite, ...] = ()
    fingerprints_skipped: tuple[tuple[str, str], ...] = ()
    faces: tuple[FaceWrite, ...] = ()
    faces_skipped: tuple[tuple[str, str], ...] = ()

    def counts(self) -> dict[str, int]:
        return {
            "users": len(self.users),
            "cards": len(self.cards),
            "fingerprints": len(self.fingerprints),
            "faces": len(self.faces),
        }


@dataclass(frozen=True, slots=True)
class MigratePlan:
    """A plan plus the PII-free template references the diff was fed (§4)."""

    plan: Plan
    bundle_faces: Mapping[str, tuple[TemplateRef, ...]]
    bundle_fingerprints: Mapping[str, tuple[TemplateRef, ...]]


@dataclass(frozen=True, slots=True)
class PhaseRun:
    """One phase's outcome: the module's own report object, or the refusal it raised."""

    phase: str
    ok: bool
    #: hash prefixes this phase got onto the device (person hashes for users/faces,
    #: card hashes for cards) — §5 step 4's "which records landed".
    landed: tuple[str, ...] = ()
    #: what ``landed`` is keyed by, so a reader never guesses.
    landed_kind: str = "employee"
    journal_path: str | None = None
    error: str | None = None
    #: the phase's own PII-free report (each module's summary/rendering).
    report: Mapping[str, Any] | None = None
    #: a verify that disagreed is terminal for the run even when the phase did not abort.
    verify_terminal: bool = False

    def as_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "phase": self.phase,
            "ok": self.ok,
            "journal": self.journal_path,
            "landed": list(self.landed),
            "landedKind": self.landed_kind,
            "verifyTerminal": self.verify_terminal,
        }
        if self.error is not None:
            payload["error"] = self.error
        if self.report is not None:
            payload["report"] = dict(self.report)
        return payload


@dataclass(frozen=True, slots=True)
class BundleApplyReport:
    """The composed run report — §5 step 4's artifact and §7's ``-o json`` body."""

    confirm: bool
    journal_dir: str
    phases: tuple[PhaseRun, ...]
    would_run: tuple[str, ...]
    stopped_at: str | None
    remaining: tuple[str, ...]
    landed: Mapping[str, tuple[str, ...]]
    plan: Plan
    inputs: PhaseInputs = field(default_factory=PhaseInputs)
    notes: tuple[str, ...] = ()

    @property
    def clean(self) -> bool:
        return self.stopped_at is None and all(p.ok for p in self.phases)

    @property
    def exit_code(self) -> int:
        """0 clean / 1 the run stopped somewhere (a partial write is reported, not hidden).

        A dry run uses the diff's own 0/1/2 (§4: 0 no changes, 1 changes pending, 2
        conflicts with no writable path), so ``diff`` and ``apply`` without ``--apply``
        agree about what "work pending" means.
        """
        if not self.confirm:
            return self.plan.exit_code
        return 0 if self.clean else 1

    def as_dict(self) -> dict[str, Any]:
        """The stable, PII-free machine form (§4: hashes, counts, device words)."""
        return {
            "schema": REPORT_SCHEMA,
            "mode": "apply" if self.confirm else "dry_run",
            "phaseOrder": list(phase_order()),
            "wouldRun": list(self.would_run),
            "ranPhases": [p.phase for p in self.phases],
            "stoppedAt": self.stopped_at,
            "remainingPhases": list(self.remaining),
            "journalDir": self.journal_dir,
            "plannedWrites": self.inputs.counts(),
            "landed": {phase: list(hashes) for phase, hashes in self.landed.items()},
            "phases": [p.as_dict() for p in self.phases],
            "totals": self.totals(),
            "diff": json.loads(render_diff_report(self.plan, fmt="json")),
            "clean": self.clean,
            "exitCode": self.exit_code,
            "notes": list(self.notes),
            "undo": {phase: undo_mode(phase) for phase in phase_order()},
        }

    def totals(self) -> dict[str, Any]:
        return {
            "add": len(self.plan.adds),
            "update": len(self.plan.updates),
            "same": len(self.plan.same),
            "conflict": len(self.plan.conflicts),
            "wouldWrite": self.plan.would_write,
        }

    def render(self, *, fmt: str = "table") -> str:
        if fmt == "json":
            return json.dumps(self.as_dict(), sort_keys=True, indent=2) + "\n"
        lines = [
            f"mode: {'apply' if self.confirm else 'DRY RUN (zero bytes written)'}",
            f"phase order: {' -> '.join(phase_order())}",
            f"would run: {', '.join(self.would_run) or '(nothing)'}",
            f"planned writes: {self.inputs.counts()}",
        ]
        for run in self.phases:
            state = "ok" if run.ok else "STOP"
            lines.append(f"  {run.phase:<14} {state:<5} journal={run.journal_path or '-'}")
            if run.landed:
                lines.append(f"    landed({run.landed_kind})={len(run.landed)}")
            if run.error:
                lines.append(f"    {run.error}")
        if self.confirm:
            lines.append(
                "run finished every phase"
                if self.stopped_at is None
                else f"run STOPPED at {self.stopped_at}"
            )
            if self.remaining:
                lines.append(f"  phases that did NOT run: {', '.join(self.remaining)}")
        lines.append(
            "landed: "
            + (
                "; ".join(
                    f"{phase}={len(hashes)}" for phase, hashes in self.landed.items() if hashes
                )
                or "(nothing)"
            )
        )
        totals = self.totals()
        lines.append(
            "diff totals: "
            + " ".join(f"{k}={totals[k]}" for k in ("add", "update", "same", "conflict"))
            + f" | would write {totals['wouldWrite']}"
        )
        for note in self.notes:
            lines.append(f"note: {note}")
        lines.append(f"exit: {self.exit_code}")
        return "\n".join(lines) + "\n"


# --- roots (§2/§3: private dirs outside the repo) --------------------------------------------


def bundle_root(explicit: str | os.PathLike[str] | None = None) -> Path:
    """§2's bundle root: ``--out``/arg, else ``GATECLERK_BUNDLE_ROOT``, else ``~/gateclerk``."""
    if explicit:
        return Path(explicit).expanduser()
    env = os.environ.get("GATECLERK_BUNDLE_ROOT")
    if env:
        return Path(env).expanduser()
    return Path.home() / "gateclerk" / BUNDLES_DIR_NAME


def probes_root(root: str | os.PathLike[str]) -> Path:
    """§3's probe directory under the same private root (``migrate_probe`` owns the file)."""
    return Path(root) / PROBES_DIR_NAME


def runs_root(root: str | os.PathLike[str]) -> Path:
    """Where §5a's per-phase journals go: one subdirectory per run."""
    return Path(root) / RUNS_DIR_NAME


def default_journal_dir(now: datetime, *, root: Path) -> Path:
    """A run directory named by the INJECTED clock (§5a).

    ``now`` is injected rather than read here because every timestamp this feature
    writes is injected (the export's clock rule): a run directory that raced the wall
    clock would make a report unreproducible.
    """
    stamp = now.astimezone(UTC).strftime("%Y%m%dT%H%M%SZ")
    return Path(runs_root(root)) / stamp


def journal_file_name(phase: str) -> str:
    return f"{phase}.{JOURNAL_SUFFIX}"


def undo_mode(phase: str) -> dict[str, Any]:
    """What undo can do for one phase — in the report, before anyone asks (§5a/§5b.1)."""
    if phase == "users":
        return {
            "mode": "report_only",
            "action": "restore or re-enroll from the pre-run snapshot bundle",
            "why": USER_UNDO_REPORT_ONLY,
        }
    if phase == "fingerprints":
        return report_only_fingerprint_undo()
    return {
        "mode": "journal",
        "action": f"gateclerk migrate undo --journal <journalDir>/{journal_file_name(phase)}",
        "why": "this phase has a capture-proven targeted delete, wrapped in §5b's "
        "count-delta guard and gated on proof-of-add (§5a)",
    }


# --- the plan seam ----------------------------------------------------------------------------


def template_refs(index: Any) -> dict[str, tuple[TemplateRef, ...]]:
    """Bundle template INDEX -> E1-02's ``TemplateRef`` map (sha256/length identity only).

    An UNAVAILABLE section yields an empty mapping, which is what §4 reads as "the
    bundle carries none for this axis" — a fact rather than a silence, because the
    index's own ``state`` says so.
    """
    refs: dict[str, tuple[TemplateRef, ...]] = {}
    if getattr(index, "state", None) != "AVAILABLE":
        return refs
    for entry in getattr(index, "entries", ()):
        slot = getattr(entry, "fp_index", None)
        if slot is None:
            slot = getattr(entry, "fdid", None)
        ref = TemplateRef(
            employee_no=entry.employee_no,
            index=slot if isinstance(slot, int) else None,
            sha256=str(entry.sha256),
            length=int(entry.length),
        )
        refs[entry.employee_no] = (*refs.get(entry.employee_no, ()), ref)
    return refs


def _roster(state: EnrollmentState) -> list[str]:
    return sorted(
        {
            str(record["employeeNo"])
            for record in state.users
            if isinstance(record.get("employeeNo"), str) and record["employeeNo"] != ""
        }
    )


def read_target_faces(
    state: EnrollmentState, faces_reader: SearchReader
) -> tuple[
    Mapping[str, tuple[TemplateRef, ...]] | None,
    str | None,
    tuple[str, ...],
]:
    """The target's live face set per person (by template sha, §9) + the E1-11 magic union.

    Reuses the faces module's own ``read_face_row`` (one request per person, the
    captured FLAT filter, and its coverage rules), so the plan and the phase can never
    disagree about what a face row means. ``(None, why, ())`` on any read failure:
    E1-02 turns that into UNKNOWN / ``unknown_enrollments``, never "has none" (§0.7).

    The third element is the REPORT-ONLY device-wide set of readable template
    families (``FR\\d{6}`` markers) across every PRESENT row this walk saw — the
    "target's native magic where the target has ≥1 face" the capture recorded
    (V4.13.0 -> FR702706, docs/OBSERVED-site-B.md). It rides the ``modelData`` decode
    ``read_face_row`` already performs for the hash (``template_magic`` reads at most
    8 of those bytes — transport, never a parse, §2), costs zero extra requests, and
    feeds ONLY the report-only ``facePortability`` note. Empty on a failed read (and
    for a target with no readable rows) — which the note helper answers with SILENCE:
    never a guess (§0.7), never an abort.
    """
    from gateclerk.migrate_faces import RowState, read_face_row

    caller = ReaderCaller(faces_reader)
    refs: dict[str, tuple[TemplateRef, ...]] = {}
    magics: set[str] = set()
    for employee_no in _roster(state):
        row = read_face_row(caller, employee_no)
        if row.state is RowState.ERROR:
            return (
                None,
                (
                    f"FDSearch read failed for {person_hash(employee_no)}: {row.note} — "
                    "UNKNOWN, never zero (§0.7)"
                ),
                (),
            )
        if row.magic:
            magics.add(row.magic)
        if row.state is RowState.PRESENT and row.sha256 is not None and row.length is not None:
            refs[employee_no] = (
                TemplateRef(
                    employee_no=employee_no,
                    index=None,
                    sha256=row.sha256,
                    length=row.length,
                ),
            )
    return refs, None, tuple(sorted(magics))


def read_target_fingerprints(
    state: EnrollmentState, fp_reader: Callable[[Mapping[str, Any]], Mapping[str, Any]]
) -> tuple[Mapping[str, tuple[TemplateRef, ...]] | None, str | None]:
    """The target's live FP set per person (the one-shot read; ``NoFP`` is a real zero)."""
    refs: dict[str, tuple[TemplateRef, ...]] = {}
    for employee_no in _roster(state):
        try:
            read = read_fingerprint_template(employee_no, fp_reader)
        except FpReadError as exc:
            return None, (
                f"FingerPrintUpload read failed for {person_hash(employee_no)}: {exc} — "
                "UNKNOWN, never zero (§0.7)"
            )
        if read.outcome is FpReadOutcome.PRESENT and read.sha256 is not None:
            refs[employee_no] = (
                TemplateRef(
                    employee_no=employee_no,
                    index=None,
                    sha256=read.sha256,
                    length=read.length or 0,
                ),
            )
    return refs, None


def migrate_plan(
    *,
    bundle: BundleData,
    seams: ApplySeams,
    policy: DiffPolicy,
    probe: CapabilityMatrix | None,
    now: datetime,
    state: EnrollmentState | None = None,
    bundle_dir: Path | None = None,
) -> MigratePlan:
    """§4's diff over a FRESH target read — the ONE computation ``diff`` and ``apply`` share.

    ``state`` lets a caller that already read the target hand it over (the composer
    reads once and reuses it for classify *and* both biometric set reads: one instant,
    not three, so the axes cannot disagree with each other). The write phases still
    re-read the target themselves — §4's per-phase freshness is theirs, not this one.

    ``bundle_dir`` (E1-11) enables the REPORT-ONLY ``facePortability`` leg: the
    bundle's own ``faces/*.b64`` are the source-magic read
    (``bundle_face_magics`` — transport decode, never a parse), compared against the
    target magic union the face walk already rode. ``None`` (a caller without the
    directory on hand) simply yields silence for that leg — §0.7: no family is
    invented from absence, and nothing in the plan or the exit code changes either
    way (the notes are report-only by construction).
    """
    target = seams.read_target_state() if state is None else state
    faces_refs, faces_error, target_face_magics = read_target_faces(target, seams.faces_reader)
    fp_refs, fp_error = read_target_fingerprints(target, seams.fp_reader)
    bundle_faces = template_refs(bundle.faces)
    bundle_fingerprints = template_refs(bundle.fingerprints)
    source_magics = (
        None if bundle_dir is None else bundle_face_magics(bundle_dir, bundle.faces.entries)
    )
    plan = build_plan(
        bundle,
        target,
        policy,
        probe,
        now=now,
        biometrics=TargetBiometrics(
            faces=faces_refs,
            faces_error=faces_error,
            fingerprints=fp_refs,
            fingerprints_error=fp_error,
            target_face_magics=target_face_magics,
        ),
        bundle_faces=bundle_faces,
        bundle_fingerprints=bundle_fingerprints,
        bundle_face_magics=source_magics,
    )
    return MigratePlan(
        plan=plan, bundle_faces=bundle_faces, bundle_fingerprints=bundle_fingerprints
    )


def phase_order() -> tuple[str, ...]:
    """§5 step 2's order — the one authority the composer and the report both use."""
    return PHASES


def ported_roster(plan: Plan) -> list[str]:
    """The persons whose templates may be ported: add/update only.

    A ``same`` person's records already match the fresh target read, and a ``conflict``
    person is E1-02's report-and-skip decision (§4) — the phase's own pre-read remains
    what decides ``already_present`` vs ``conflict`` per template.
    """
    return [
        item.employee_no
        for item in plan.items
        if item.classification.value in ("add", "update") and item.employee_no
    ]


def plan_phase_inputs(
    *,
    plan: Plan,
    bundle: BundleData,
    bundle_dir: Path,
    target: EnrollmentState,
    probe: CapabilityMatrix,
    confirm: bool,
) -> PhaseInputs:
    """Split the plan into per-phase write lists — the pure splitters, both modes.

    These are the same functions the phases use (users/cards) or the bundle-only passes
    the biometric phases run at execution time (fingerprints/faces), so the composer's
    report and the phase's own numbers come from one implementation. Nothing here
    builds a client: ``target`` is the plan pass's own fresh read.
    """
    users, users_skipped = (
        plan_user_writes(plan, bundle, probe=probe)
        if confirm
        else dry_run_writes(plan, bundle, probe=probe)
    )
    cards, cards_skipped = plan_card_writes(plan, bundle, target_cards=target.cards, probe=probe)
    roster = ported_roster(plan)
    fingerprints, fingerprints_skipped = plan_fingerprint_writes(
        bundle_dir=bundle_dir,
        fingerprints=bundle.fingerprints,
        employee_nos=roster,
        probe=probe,
    )
    faces, faces_skipped = plan_face_writes(
        bundle_dir=bundle_dir,
        faces=bundle.faces,
        employee_nos=roster,
    )
    return PhaseInputs(
        users=users,
        users_skipped=users_skipped,
        cards=cards,
        cards_skipped=cards_skipped,
        fingerprints=fingerprints,
        fingerprints_skipped=fingerprints_skipped,
        faces=faces,
        faces_skipped=faces_skipped,
    )


def dry_run_writes(
    plan: Plan, bundle: BundleData, *, probe: CapabilityMatrix | None = None
) -> tuple[tuple[UserWrite, ...], tuple[tuple[str, str], ...]]:
    """The zero-byte users write list (``plan_user_writes`` is pure — no client exists).

    Named separately from the phase module so the suite can pin "the dry run used this
    and only this", rather than trusting that a later edit did not add I/O to a splitter.
    """
    return plan_user_writes(plan, bundle, probe=probe)


# --- the composer -----------------------------------------------------------------------------


def apply_bundle(
    *,
    bundle: BundleData,
    bundle_dir: Path,
    plan: Plan,
    target: EnrollmentState,
    seams: ApplySeams,
    probe: CapabilityMatrix,
    now: datetime,
    journal_dir: Path,
    confirm: bool,
    batch_delay: float = 1.0,
    sleep: Callable[[float], None] = time.sleep,
    recheck: Callable[[], Sequence[Any]] | None = None,
) -> BundleApplyReport:
    """Run §5 step 2's phase order over one plan, stopping at the first refusal.

    * ``confirm=False`` (no ``--apply``) is §4's default: a zero-byte dry run that
      reports exactly which phases WOULD run. It opens no journal and builds no
      transport, so "no write happened" is a structural fact, not a hope.
    * ``confirm=True`` runs the four phases in order, each with its own journal under
      ``journal_dir`` and its own budgeted transport over its own factory (§5.3).
    * The FIRST abort or terminal verify stops the run: no phase after it runs, and the
      report still names what landed and which phases remain (§5 step 4).

    ``recheck`` is E1-02's freshness seam (§4): the users phase re-diffs against it
    before its first write. It is passed through, never re-implemented.
    """
    order = phase_order()
    inputs = plan_phase_inputs(
        plan=plan,
        bundle=bundle,
        bundle_dir=Path(bundle_dir),
        target=target,
        probe=probe,
        confirm=confirm,
    )

    if not confirm:
        return BundleApplyReport(
            confirm=False,
            journal_dir=str(journal_dir),
            phases=(),
            would_run=order,
            stopped_at=None,
            remaining=(),
            landed={},
            plan=plan,
            inputs=inputs,
            notes=(
                "dry run: no journal opened, no transport built, no write client "
                "constructed — every number above comes from the bundle plus ONE fresh "
                "target read (§4)",
            ),
        )

    _ensure_private_dir(Path(journal_dir))
    runs: list[PhaseRun] = []
    landed: dict[str, tuple[str, ...]] = {}
    notes: list[str] = []
    stopped_at: str | None = None
    remaining: tuple[str, ...] = ()

    # §4's freshness gate exists for EXTERNAL drift; this run's own confirmed writes are
    # not drift. A person who moved `add` -> `same` because the users phase LANDED them
    # (§6 verify, journal `confirmed`) is the plan coming true — without this, phase 2
    # would abort on phase 1's success and the order §5 fixes could never complete. Only
    # the composer knows what the run landed, so the excusal lives here and nowhere else:
    # a landed person keeps their PLAN-TIME classification inside every later recheck
    # (the phase modules still own and call `plan_still_valid` untouched), and every
    # other person re-diffs for real. Before the first write nothing is landed, so the
    # users phase's gate is exactly E1-04's; a person who VANISHED after our write stays
    # flagged (external delete of a fresh write is real drift, never excused).
    own_landed: set[str] = set()
    phase_recheck: Callable[[], Sequence[Any]] | None = recheck
    if recheck is not None:

        def _own_write_aware_recheck() -> Sequence[Any]:
            fresh = {c.employee_hash: c for c in recheck()}
            for planned in plan.items:
                if planned.employee_hash in own_landed and planned.employee_hash in fresh:
                    fresh[planned.employee_hash] = planned
            return list(fresh.values())

        phase_recheck = _own_write_aware_recheck

    for index, phase in enumerate(order):
        run = _run_phase(
            phase,
            plan=plan,
            bundle=bundle,
            inputs=inputs,
            seams=seams,
            probe=probe,
            now=now,
            journal_dir=Path(journal_dir),
            batch_delay=batch_delay,
            sleep=sleep,
            recheck=phase_recheck,
        )
        runs.append(run)
        if run.landed:
            landed[run.phase] = run.landed
        if run.ok and run.landed_kind == "employee":
            own_landed.update(run.landed)
        if not run.ok:
            stopped_at = phase
            remaining = order[index + 1 :]
            if run.error:
                notes.append(f"{phase}: {run.error}")
            break

    if stopped_at is not None:
        notes.append(
            f"run stopped at {stopped_at}; phases that did NOT run: "
            f"{', '.join(remaining) or '(none)'} — a partial write is reported as data, "
            "never papered over, and nothing was retried (§5 step 4, §0.6)"
        )
    return BundleApplyReport(
        confirm=True,
        journal_dir=str(journal_dir),
        phases=tuple(runs),
        would_run=order,
        stopped_at=stopped_at,
        remaining=remaining,
        landed=landed,
        plan=plan,
        inputs=inputs,
        notes=tuple(notes),
    )


def _ensure_private_dir(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)
    with contextlib.suppress(OSError):  # exotic filesystems; the files are still 0600
        path.chmod(0o700)


def _run_phase(
    phase: str,
    *,
    plan: Plan,
    bundle: BundleData,
    inputs: PhaseInputs,
    seams: ApplySeams,
    probe: CapabilityMatrix,
    now: datetime,
    journal_dir: Path,
    batch_delay: float,
    sleep: Callable[[float], None],
    recheck: Callable[[], Sequence[Any]] | None,
) -> PhaseRun:
    journal_path = journal_dir / journal_file_name(phase)
    if phase == "users":
        return _run_users(
            plan, bundle, seams, probe, now, journal_path, batch_delay, sleep, recheck
        )
    if phase == "cards":
        return _run_cards(
            plan, bundle, seams, probe, now, journal_path, batch_delay, sleep, recheck
        )
    if phase == "fingerprints":
        return _run_fingerprints(inputs, seams, journal_path, sleep)
    if phase == "faces":
        return _run_faces(inputs, seams, probe, now, journal_path, batch_delay, sleep)
    raise ValueError(f"unknown phase {phase!r}: the composer runs {PHASES} only (§5 step 2)")


def _run_users(
    plan: Plan,
    bundle: BundleData,
    seams: ApplySeams,
    probe: CapabilityMatrix,
    now: datetime,
    journal_path: Path,
    batch_delay: float,
    sleep: Callable[[float], None],
    recheck: Callable[[], Sequence[Any]] | None,
) -> PhaseRun:
    """§5.1a's clock gate, the stale-probe gate and the freshness re-diff are this
    phase's own first moves — reused, never duplicated (§4)."""
    try:
        report = apply_users_phase(
            plan=plan,
            bundle=bundle,
            transport_factory=seams.users_transport_factory,
            reader=seams.users_reader,
            journal_path=journal_path,
            probe=probe,
            now=now,
            recheck=recheck,
            sleep=sleep,
            batch_delay=batch_delay,
            confirm=True,
        )
    except (WriteAbortedError, ApplyAbortedError) as exc:
        return PhaseRun(
            phase="users",
            ok=False,
            landed=_hashes(getattr(exc, "result", None), "applied"),
            error=str(exc),
            journal_path=str(journal_path),
            report=_phase_payload(getattr(exc, "result", None)),
        )
    terminal = _users_verify_terminal(report)
    return PhaseRun(
        phase="users",
        ok=report.writes.clean and not terminal,
        landed=report.writes.landed,
        journal_path=report.journal_path,
        report=json.loads(json.dumps(report.as_dict(), default=str)),
        verify_terminal=terminal,
        error="verify disagreed after the phase (§0.6): terminal for the run, never "
        "'fixed' by a re-write"
        if terminal
        else None,
    )


def _run_cards(
    plan: Plan,
    bundle: BundleData,
    seams: ApplySeams,
    probe: CapabilityMatrix,
    now: datetime,
    journal_path: Path,
    batch_delay: float,
    sleep: Callable[[float], None],
    recheck: Callable[[], Sequence[Any]] | None,
) -> PhaseRun:
    try:
        report: CardsApplyReport = apply_cards_phase(
            plan=plan,
            bundle=bundle,
            transport_factory=seams.cards_transport_factory,
            reader=seams.cards_reader,
            journal_path=journal_path,
            probe=probe,
            now=now,
            recheck=recheck,
            sleep=sleep,
            batch_delay=batch_delay,
            confirm=True,
        )
    except (WriteAbortedError, ApplyAbortedError) as exc:
        return PhaseRun(
            phase=CARDS_PHASE,
            ok=False,
            landed=_hashes(getattr(exc, "result", None), "applied"),
            landed_kind="card",
            error=str(exc),
            journal_path=str(journal_path),
            report=_phase_payload(getattr(exc, "result", None)),
        )
    terminal = report.verify is not None and not report.verify.ok
    return PhaseRun(
        phase=CARDS_PHASE,
        ok=report.writes.clean and not terminal,
        landed=report.writes.landed,
        landed_kind="card",
        journal_path=report.journal_path,
        report=json.loads(json.dumps(report.as_dict(), default=str)),
        verify_terminal=terminal,
        error="verify disagreed after the phase (§0.6): terminal for the run, never "
        "'fixed' by a re-write"
        if terminal
        else None,
    )


def _run_fingerprints(
    inputs: PhaseInputs,
    seams: ApplySeams,
    journal_path: Path,
    sleep: Callable[[float], None],
) -> PhaseRun:
    """The bench-A reality lives here: an ack is not a confirm, and the FIRST
    accepted-but-not-applied answer aborts the phase (§5 step 4)."""
    try:
        report: FpFleetReport = apply_fingerprints_phase(
            writes=inputs.fingerprints,
            skipped=inputs.fingerprints_skipped,
            transport_factory=seams.fp_transport_factory,
            reader=seams.fp_reader,
            journal_path=journal_path,
            sleep=sleep,
            batch_delay=0.0,
        )
    except FpAbortedError as exc:
        carried = exc.result if isinstance(exc.result, FpFleetReport) else None
        return PhaseRun(
            phase="fingerprints",
            ok=False,
            landed=carried.writes.landed if carried is not None else (),
            error=str(exc),
            journal_path=carried.journal_path if carried is not None else str(journal_path),
            report=json.loads(json.dumps(carried.as_dict(), default=str))
            if carried is not None
            else None,
            verify_terminal=bool(carried is not None and carried.verify.terminal),
        )
    return PhaseRun(
        phase="fingerprints",
        ok=report.writes.clean and not report.verify.terminal,
        landed=report.writes.landed,
        journal_path=report.journal_path,
        report=json.loads(json.dumps(report.as_dict(), default=str)),
        verify_terminal=report.verify.terminal,
        error="verify disagreed after the phase (§0.6): terminal for the run"
        if report.verify.terminal
        else None,
    )


def _run_faces(
    inputs: PhaseInputs,
    seams: ApplySeams,
    probe: CapabilityMatrix,
    now: datetime,
    journal_path: Path,
    batch_delay: float,
    sleep: Callable[[float], None],
) -> PhaseRun:
    try:
        result, journal, verify = apply_faces_phase(
            transport_factory=seams.faces_transport_factory,
            journal_path=journal_path,
            writes=inputs.faces,
            probe=probe,
            now=now,
            sleep=sleep,
            batch_delay=batch_delay,
            skipped=inputs.faces_skipped,
            # §5.3: the phase's own per-person read-back IS §6 for faces (3 authed
            # calls/person). An extra independent walk would double-spend the budget to
            # re-read what the journal already proved; audit runs can ask for it directly.
            confirm=False,
        )
    except FacePhaseAbortedError as exc:
        return PhaseRun(
            phase="faces",
            ok=False,
            landed=tuple(exc.result.applied),
            error=str(exc),
            journal_path=str(journal_path),
            report=faces_report(exc.result, WriteJournal.open(journal_path, phase="faces")),
        )
    terminal = verify is not None and bool(verify.terminal)
    return PhaseRun(
        phase="faces",
        ok=result.clean and not terminal,
        landed=tuple(result.applied),
        journal_path=str(journal.path),
        report=faces_report(result, journal, verify=verify),
        verify_terminal=terminal,
        error="verify disagreed after the phase (§0.6): terminal for the run" if terminal else None,
    )


def _users_verify_terminal(report: Any) -> bool:
    verify: UsersVerifyReport | None = report.verify
    if verify is None:
        return False
    return bool(verify.mismatched or verify.missing)


def _hashes(result: Any, attribute: str) -> tuple[str, ...]:
    value = getattr(result, attribute, None)
    return tuple(value) if isinstance(value, tuple) else ()


def _phase_payload(result: Any) -> Mapping[str, Any] | None:
    summary = getattr(result, "summary", None)
    if not callable(summary):
        return None
    return json.loads(json.dumps(summary(), default=str))


# --- the undo composer (§5a/§5b.1) ------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class UndoRunReport:
    """What undo did — the same PII-free shape as the apply report."""

    phase: str
    mode: str  # "journal" (a verb exists) | "report_only" (§5b.1) | "refused"
    ok: bool
    journal_path: str
    report: Mapping[str, Any] | None = None
    note: str | None = None

    @property
    def exit_code(self) -> int:
        """0 for a clean undo AND for report-only (§5b.1 says words are the outcome);
        1 for an incident or a refusal — both need a human."""
        return 0 if self.ok else 1

    def as_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "schema": UNDO_SCHEMA,
            "phase": self.phase,
            "mode": self.mode,
            "ok": self.ok,
            "exitCode": self.exit_code,
            "journal": self.journal_path,
        }
        if self.report is not None:
            payload["report"] = dict(self.report)
        if self.note:
            payload["note"] = self.note
        return payload


def person_report_only_undo() -> dict[str, Any]:
    """The users axis in words, quoting the module that owns the ban.

    Reached through ``migrate_write_cards.person_delete_forbidden`` so the wording
    cannot drift from the ban, and so no code path in this module can grow into a
    person delete.
    """
    from gateclerk.migrate_write_cards import CardDeleteScopeError, person_delete_forbidden

    try:
        person_delete_forbidden()
    except CardDeleteScopeError as exc:
        reason = str(exc)
    return {
        "mode": "report_only",
        "action": "restore or re-enroll from the pre-run snapshot bundle",
        "why": USER_UNDO_REPORT_ONLY,
        "because": reason,
    }


def undo_journal(
    journal_path: str | os.PathLike[str],
    *,
    cards_transport_factory: Callable[[], Any] | None = None,
    cards_reader: SearchReader | None = None,
    faces_transport_factory: Callable[[], Any] | None = None,
    undo_journal_dir: str | os.PathLike[str] | None = None,
    sleep: Callable[[float], None] = lambda _s: None,
) -> UndoRunReport:
    """Dispatch undo on the JOURNAL'S OWN PHASE — never on the file name (§5a).

    Every journal line carries the phase its writer stamped, so the phase is read from
    the data and a mis-named file changes nothing. A phase with no undo verb (users,
    fingerprints — §5b.1) gets the owning module's REPORT-ONLY wording and writes zero
    bytes; cards and faces get their capture-proven targeted deletes, each gated on
    proof-of-add and wrapped in §5b's count-delta guard by its own module.

    Undo gets its own journal (§5a): ``<phase>.undo.jsonl`` next to the source file
    unless ``undo_journal_dir`` says otherwise. Nothing here retries or re-writes.
    """
    path = Path(journal_path)
    phase = journal_phase(path)
    if phase == "users":
        return UndoRunReport(
            phase=phase,
            mode="report_only",
            ok=True,
            journal_path=str(path),
            report=person_report_only_undo(),
            note=USER_UNDO_REPORT_ONLY,
        )
    if phase == "fingerprints":
        return UndoRunReport(
            phase=phase,
            mode="report_only",
            ok=True,
            journal_path=str(path),
            report=report_only_fingerprint_undo(),
            note=FP_UNDO_REPORT_ONLY,
        )
    if phase == CARDS_PHASE:
        return _undo_cards(path, cards_transport_factory, cards_reader, undo_journal_dir, sleep)
    if phase == "faces":
        return _undo_faces(path, faces_transport_factory, undo_journal_dir, sleep)
    return UndoRunReport(
        phase=phase,
        mode="refused",
        ok=False,
        journal_path=str(path),
        note=(
            f"journal phase {phase!r} is not one this tool knows, so undo writes nothing "
            "— an unrecognised phase is refused, not guessed (§0.7)"
        ),
    )


def _undo_cards(
    path: Path,
    transport_factory: Callable[[], Any] | None,
    reader: SearchReader | None,
    undo_dir: str | os.PathLike[str] | None,
    sleep: Callable[[float], None],
) -> UndoRunReport:
    if transport_factory is None or reader is None:
        return _undo_needs_seams(CARDS_PHASE, path, "cards")
    source = WriteJournal.open(path, phase=CARDS_PHASE)
    undo_path = _undo_journal_path(path, undo_dir, CARDS_PHASE)
    transport = BudgetedWriteTransport(transport_factory)
    try:
        report = undo_card_adds(
            transport,
            source,
            reader=reader,
            undo_journal=WriteJournal.open(undo_path, phase=UNDO_PHASE),
            sleep=sleep,
        )
    finally:
        transport.close()
    payload = json.loads(json.dumps(report.summary(), default=str))
    return UndoRunReport(
        phase=CARDS_PHASE,
        mode="journal",
        ok=report.clean,
        journal_path=str(path),
        report=payload,
        note=None
        if report.clean
        else "undo refused entries and/or flagged an incident (§5a/§5b): unknown states "
        "and drifted rows are a human decision, never an automatic delete",
    )


def _undo_faces(
    path: Path,
    transport_factory: Callable[[], Any] | None,
    undo_dir: str | os.PathLike[str] | None,
    sleep: Callable[[float], None],
) -> UndoRunReport:
    if transport_factory is None:
        return _undo_needs_seams("faces", path, "faces")
    source = WriteJournal.open(path, phase="faces")
    undo_path = _undo_journal_path(path, undo_dir, "faces")
    transport = BudgetedWriteTransport(transport_factory)
    report: FacesUndoReport | None = None
    incident: str | None = None
    try:
        report = undo_faces(
            transport,
            source,
            WriteJournal.open(undo_path, phase="faces_undo"),
            sleep=sleep,
            inter_page_delay=0.0,
        )
    except Exception as exc:
        incident = f"{type(exc).__name__}: {exc}"
    finally:
        transport.close()
    if report is None:
        return UndoRunReport(
            phase="faces",
            mode="journal",
            ok=False,
            journal_path=str(path),
            report={"incident": incident},
            note="the §5b count-delta guard stopped the undo — stop everything, restore "
            "from the pre-run bundle, escalate (§5b: a delete that removed more than it "
            "named is an incident, never a retry)",
        )
    payload = json.loads(json.dumps(report.summary(), default=str))
    return UndoRunReport(
        phase="faces",
        mode="journal",
        ok=report.clean,
        journal_path=str(path),
        report=payload,
        note=None
        if report.clean
        else "undo refused entries or hit the guard (§5a): non-confirmed adds and "
        "post-run drift are a human decision",
    )


def _undo_needs_seams(phase: str, path: Path, axis: str) -> UndoRunReport:
    return UndoRunReport(
        phase=phase,
        mode="refused",
        ok=False,
        journal_path=str(path),
        note=(
            f"undo of {axis} needs its write seam; none was injected, so nothing was "
            "sent — an undo that cannot verify is an undo that must not run (§5a)"
        ),
    )


def _undo_journal_path(path: Path, override: str | os.PathLike[str] | None, phase: str) -> Path:
    name = f"{phase}.{JOURNAL_SUFFIX}".replace(f".{JOURNAL_SUFFIX}", f".undo.{JOURNAL_SUFFIX}")
    if override is None:
        return path.parent / name
    target = Path(override).expanduser()
    return target / name if target.is_dir() or not target.suffix else target


def journal_phase(path: Path) -> str:
    """The phase the journal's OWN lines declare — fail closed when they do not agree.

    ``WriteJournal.open`` takes a phase argument so a caller can resume a file; that
    argument is not evidence about the file. The evidence is the ``phase`` field of
    every line, so an empty journal, a torn line, or a file that mixes phases is
    refused rather than resolved by the file name (§5a: unknown state = human).
    """
    if not path.is_file():
        raise FileNotFoundError(
            f"no journal at {path} — undo removes only records a journal named (§5a)"
        )
    replayed = WriteJournal.open(path, phase="")
    if replayed.truncated:
        raise ValueError(
            f"journal {path} has unreadable line(s) ({', '.join(replayed.truncated)}); "
            "undo refuses a journal it cannot fully read (§5a)"
        )
    phases = {entry.phase for entry in replayed.entries if entry.phase}
    if not phases:
        raise ValueError(
            f"journal {path} records nothing, so its phase is unknown — undo never "
            "guesses a phase from a file name (§5a)"
        )
    if len(phases) > 1:
        raise ValueError(
            f"journal {path} mixes phases {sorted(phases)} — one journal per phase is "
            "§5a's rule, so undo refuses to choose"
        )
    return next(iter(phases))


def render_undo_report(report: UndoRunReport, *, fmt: str = "table") -> str:
    if fmt == "json":
        return json.dumps(report.as_dict(), sort_keys=True, indent=2) + "\n"
    lines = [
        f"phase: {report.phase}",
        f"mode: {report.mode}",
        f"ok: {'yes' if report.ok else 'no'}",
        f"journal: {report.journal_path}",
    ]
    if report.report:
        for key, value in report.report.items():
            lines.append(f"  {key}: {json.dumps(value, sort_keys=True)}")
    if report.note:
        lines.append(f"note: {report.note}")
    return "\n".join(lines) + "\n"


# --- the production write seams (§5.3: one client, one budget, one verb family) ---------------


class _PhaseWriteTransport:
    """One phase's raw write seam over ONE ``IsapiClient`` (its own digest session).

    Deliberately minimal and deliberately phase-specific: each subclass names only the
    verbs its phase owns, and :meth:`BudgetedWriteTransport.call` raises ``TypeError``
    for any verb it lacks — so "the faces phase must never use the users verb" stays a
    structural fact (the same guarantee E1-06/E1-06b's test seams assert).

    Why it reaches past the client's registry-guarded ``get``/``search``: the read-only
    registry is P1's guarantee and this card must not widen it (``gateclerk.endpoints``
    stays exactly as its test pins it). The write verbs are the captured constants the
    phase modules already own (``USER_SETUP_PATH`` etc.), sent over the client's digest
    session — one long-lived session per phase (§5.3), re-bootstrapped by the budget
    rather than retried on failure: **a write is never re-sent** (§0.6), which is why
    none of the read client's busy-retry or circuit machinery is reproduced here.

    The transport is reached through ``client.raw`` — ``IsapiClient``'s one sanctioned
    escape hatch — never through ``client._client`` (E1-10). That distinction is what
    makes the seam shape-agnostic: under ``--verbose`` the CLI hands seams a
    ``pipeline.LoggedClient`` whose ``_client`` is the INNER ``IsapiClient``, so
    ``client._client.post(...)`` asks an ``IsapiClient`` for an httpx verb and dies with
    ``AttributeError: 'IsapiClient' object has no attribute 'post'`` before a single byte
    is written (the operator's live crash, reproduced verbatim). ``LoggedClient``
    forwards ``raw`` transparently, so the bare and verbose paths are one code path.
    """

    #: What the envelope words name in an error line.
    family = "enrollment"

    def __init__(self, client: Any) -> None:
        self.client = client
        self.calls = 0
        self.closed = 0

    # -- the verbs each subclass opts into ------------------------------------------------

    def _request(
        self,
        method: str,
        path: str,
        body: Mapping[str, Any] | None,
        *,
        params: Mapping[str, Any] | None = None,
        who: str = "the phase",
    ) -> dict[str, Any]:
        self.calls += 1
        response = self.client.raw.request(
            method,
            path,
            params=dict(params or {"format": "json"}),
            json=dict(body) if body is not None else None,
            auth=self.client._auth,
        )
        try:
            envelope = json.loads(response.content)
        except ValueError as exc:
            raise WriteRejectedError(
                f"{self.family} {method} {path} for {who} answered HTTP "
                f"{response.status_code} with an unparseable body — an answer we cannot "
                "read is never treated as an accepted write (§0.7)",
                http_status=response.status_code,
            ) from exc
        if response.status_code != 200 or envelope.get("statusCode") != _OK_STATUS:
            sub = envelope.get("subStatusCode")
            raise WriteRejectedError(
                f"{self.family} {method} {path} for {who} answered HTTP "
                f"{response.status_code} statusCode={envelope.get('statusCode')!r} "
                f"subStatusCode={sub!r}; only statusCode {_OK_STATUS} is an accepted ack "
                "in any committed capture (§6: even that proves nothing on its own — the "
                "read-back is the proof)",
                sub_status=None if sub is None else str(sub),
                http_status=response.status_code,
                envelope=envelope,
            )
        return dict(envelope)

    def close(self) -> None:
        self.closed += 1
        self.client.close()


_OK_STATUS = 1


class UserWriteTransport(_PhaseWriteTransport):
    """The users phase's seam: ``PUT UserInfo/SetUp`` and nothing else."""

    family = "UserInfo/SetUp"

    def put_setup(self, path: str, body: Mapping[str, Any]) -> dict[str, Any]:
        return self._request("PUT", path, body, who="this user row")


class CardWriteTransport(_PhaseWriteTransport):
    """The cards phase's seam: ``PUT CardInfo/SetUp`` (+ the capture-proven delete)."""

    family = "CardInfo"

    def put_setup(self, path: str, body: Mapping[str, Any]) -> dict[str, Any]:
        return self._request("PUT", path, body, who="this card pair")

    def put_delete(self, path: str, body: Mapping[str, Any]) -> dict[str, Any]:
        """``PUT CardInfo/Delete`` — the capture-proven targeted delete E1-05's undo uses."""
        return self._request("PUT", path, body, who="the named cards")


class FpWriteTransport(_PhaseWriteTransport):
    """The fingerprints seam: ``POST FingerPrintDownload`` + ``GET FingerPrintProgress``."""

    family = "FingerPrintDownload"

    def post_download(self, path: str, body: Mapping[str, Any]) -> dict[str, Any]:
        return self._request("POST", path, body, who="this template")

    def get_progress(self, path: str) -> dict[str, Any]:
        self.calls += 1
        response = self.client.raw.get(path, params={"format": "json"}, auth=self.client._auth)
        try:
            return dict(json.loads(response.content))
        except ValueError as exc:
            raise WriteRejectedError(
                f"{self.family} progress read answered HTTP {response.status_code} with "
                "an unparseable body — the only surface that could prove an accepted "
                "template was applied is unreadable (§0.7)"
            ) from exc


class FaceWriteTransport(_PhaseWriteTransport):
    """The faces seam: FDSearch read, ``PUT FDSetUp``, ``PUT FDSearch/Delete``."""

    family = "FDLib"

    def post_face_search(self, path: str, body: Mapping[str, Any]) -> dict[str, Any]:
        self.calls += 1
        response = self.client.raw.post(
            path, params={"format": "json"}, json=dict(body), auth=self.client._auth
        )
        try:
            return dict(json.loads(response.content))
        except ValueError as exc:
            raise WriteRejectedError(
                f"{self.family} FDSearch answered HTTP {response.status_code} with an "
                "unparseable body — a face read we cannot parse is an ERROR, never a "
                "missing face (§0.7)"
            ) from exc

    def put_face_setup(self, path: str, body: Mapping[str, Any]) -> dict[str, Any]:
        return self._request("PUT", path, body, who="this face template")

    def put_face_delete(
        self, path: str, params: Mapping[str, Any], body: Mapping[str, Any]
    ) -> dict[str, Any]:
        return self._request("PUT", path, body, params=params, who="the named FPID")


def write_seams_for(
    client_factory: Callable[[], Any],
    *,
    read_target_state: Callable[[], EnrollmentState],
    users_reader: SearchReader,
    cards_reader: SearchReader,
    fp_reader: Callable[[Mapping[str, Any]], Mapping[str, Any]],
    faces_reader: SearchReader,
) -> ApplySeams:
    """Wire production seams over a client factory (one fresh client per phase/budget).

    ``client_factory`` is called per phase AND on every re-bootstrap, which is exactly
    §5.3's design: a fresh digest session is the recovery arm, and the composer never
    shares a client across phases.
    """
    return ApplySeams(
        read_target_state=read_target_state,
        users_transport_factory=lambda: UserWriteTransport(client_factory()),
        cards_transport_factory=lambda: CardWriteTransport(client_factory()),
        fp_transport_factory=lambda: FpWriteTransport(client_factory()),
        faces_transport_factory=lambda: FaceWriteTransport(client_factory()),
        users_reader=users_reader,
        cards_reader=cards_reader,
        fp_reader=fp_reader,
        faces_reader=faces_reader,
    )


def reader_for(client: Any, endpoint: str) -> SearchReader:
    """A registry-guarded read seam (the same client the export uses)."""

    def read(body: Mapping[str, Any]) -> dict[str, Any]:
        return dict(client.search(endpoint, body))

    return read


def policy_for(
    on_conflict: str, *, carry_templates: bool = False, site_tz: str | None = None
) -> DiffPolicy:
    """``--on-conflict`` -> E1-02's policy. No new vocabulary is invented here (§4)."""
    return DiffPolicy(
        on_conflict=ConflictPolicy(on_conflict),
        carry_templates=carry_templates,
        site_tz=site_tz,
    )


def freshness_recheck(
    bundle: BundleData,
    seams: ApplySeams,
    policy: DiffPolicy,
    probe: CapabilityMatrix,
    now: datetime,
    bundle_dir: Path | None = None,
) -> Callable[[], Sequence[Any]]:
    """E1-02's §4 seam, wired: re-read the target NOW and re-classify.

    ``apply_*_phase`` calls the result and compares it with ``plan_still_valid``; the
    composer only supplies the closure, it never re-implements the comparison. The
    bundle-side template refs are identical on both passes, so only the target read
    moves — which is the whole point of the gate. ``bundle_dir`` (E1-11) threads the
    report-only facePortability source read so a re-diff renders the same warnings as
    the plan pass; the gate itself is unchanged (it compares classification + reasons,
    never notes).
    """

    def recheck() -> Sequence[Any]:
        fresh = migrate_plan(
            bundle=bundle,
            seams=seams,
            policy=policy,
            probe=probe,
            now=now,
            bundle_dir=bundle_dir,
        )
        return fresh.plan.items

    return recheck


def changed_people(plan: Plan, reclassified: Sequence[Any]) -> list[str]:
    """The drift list §4 wants reported (hash prefixes only) — ``plan_still_valid`` itself."""
    return plan_still_valid(plan, reclassified)


def plan_employee_hashes(plan: Plan) -> tuple[str, ...]:
    """Every person identity the report may name (hash prefixes only, §4)."""
    return tuple(item.employee_hash for item in plan.items)
