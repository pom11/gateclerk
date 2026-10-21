"""The diff engine (card E1-02): classification + report, NO device writes.

Design docs/ENROLLMENT-MIGRATION.md v4 §4 (freshness contract), §1a (door fields),
§9 (UNKNOWN-not-zero biometrics), + the orchestrator scope note on card t_0fd87e2f.
The default mode of `apply` IS this diff, so the module's one absolute rule is the
§0 rule inverted: nothing here may ever *cause* a write — the plan says "would write
N", and only E1-04's apply phase turns the plan into requests.

What this module imports and NEVER re-expresses (card rule):
* `gateclerk.migrate_bundle` — normalization + content hashes (the SAME functions the
  export hashed the bundle with; re-expressing them here is how two sides drift).
* `gateclerk.migrate_export.collect_enrollment_state` — the fail-closed target read.
  Device reads go through `plan()`'s target argument: an already-read
  `EnrollmentState` or a zero-arg search-fn that returns one (FakeDevice-backed in
  tests; NEVER the real device from a worker card). No second read path exists here.
* `gateclerk.migrate_probe.require_fresh` — the staleness gate E1-03 built.
* `gateclerk.tz.TimeResolver` — Valid-bound parsing (the p1-06 payroll class).

Classification per `employeeNo` (opaque match, §1 — exact bytes, never int-cast,
never case-folded; near-matches are a CONFLICT, never a silent merge):

  add       source-only person
  update    on both sides, ACTIONABLE content differs (door fields never are;
            biometric/card adds alone count as an update needing writes)
  same      nothing to write (zero-write re-runs BY CONSTRUCTION, §4)
  conflict  see `Reason`; conflicts are REPORTED AND SKIPPED by default (§4)

Conflict reason codes (one code per class, per the card):
  card_no_bound_to_other_employee  card pair identity — §5 step 5 (silent reassign
                                   strips someone else's card; silent skip strands
                                   this one: payroll corruption either way)
  target_only_cards                target's card set ⊄ bundle's (§4)
  target_only_faces                target face templates the bundle cannot re-create
                                   (scope note: target-has-face-bundle-lacks = conflict)
  target_only_fingerprints         same for FP templates
  unknown_enrollments              face/FP READ failed AND the volatile counter says
                                   N>0 — UNKNOWN not zero (§9), never an update
  template_ref_unproven            --carry-templates asked for a template number
                                   absent from the target's evidence set (§1a/§3)
  normalization_collision          employeeNos equal ONLY after int/case coercion
                                   (§1) — both records kept, both skipped
  validity_unparseable             source `Valid` missing/unparseable, or a wall time
                                   that does not exist in the site zone

§1a v4 door fields: `planTemplateNo == "1"` is CARRIED by default (bench A: every
user uses it; caps maxPlanTemplate=4 — the built-in all-day schedule). A template-1
add is therefore NOT a door-field conflict (scope note 1). Custom numbers (2..255)
are REPORT-ONLY unless `carry_templates` AND the number appears in the evidence set
(union of templateNos OBSERVED in the target's own RightPlan records); carried
customs are noted "content UNVERIFIED — verify the schedule on-site". `doorRight`/
`belongGroup` follow the same device-local-ID rule: report-only names, never an
actionable update.

Freshness (§4): `plan_still_valid(plan, reclassified)` is what apply calls before
EACH write phase — every pending record whose classification or reason set changed
since plan time (or vanished) is returned as the abort signal; empty = still valid.

Report (§4): employeeNo **hash prefix only**, field NAMES only, table + totals +
"would write N" — no name, no value, no raw employeeNo anywhere. `fmt="json"` is
the byte-pinned machine schema (E1-07's `-o json` renders through here). Exit-code
mapping (p1-08 contract): 0 no changes / 1 changes pending / 2 config-problem —
conflicts pending with no writable path (the operator changes policy or fixes data).
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum
from typing import Any

from gateclerk.exceptions import GateclerkError
from gateclerk.migrate_bundle import BundleData, content_hash, normalize_record
from gateclerk.migrate_export import EnrollmentState, collect_enrollment_state
from gateclerk.migrate_probe import CapabilityMatrix, require_fresh
from gateclerk.tz import DEFAULT_SITE_TZ, TimeResolver

__all__ = [
    "DEFAULT_CARRIED_TEMPLATE_NO",
    "DOOR_FIELDS",
    "REPORT_SCHEMA",
    "Classification",
    "ConflictPolicy",
    "DiffAbortedError",
    "DiffClass",
    "DiffPolicy",
    "Plan",
    "Reason",
    "TargetBiometrics",
    "TemplateRef",
    "classify",
    "employee_hash",
    "plan",
    "plan_still_valid",
    "read_target_state",
    "render_report",
]

#: Device-local door/security fields (§1a): a diff in them is NEVER an actionable
#: update, whatever the template rules below decide to carry.
DOOR_FIELDS: frozenset[str] = frozenset({"doorRight", "belongGroup", "RightPlan"})

#: The one plan-template number carried by default (§1a v4 — built-in all-day).
DEFAULT_CARRIED_TEMPLATE_NO = "1"

#: The JSON report schema token — part of the byte-pinned contract.
REPORT_SCHEMA = "gateclerk-migrate-diff/1"


class DiffClass(StrEnum):
    """Per-person diff verdict (§4)."""

    ADD = "add"
    UPDATE = "update"
    SAME = "same"
    CONFLICT = "conflict"


class Reason(StrEnum):
    """Conflict reason codes — one code per conflict class (card E1-02)."""

    CARD_BOUND_TO_OTHER = "card_no_bound_to_other_employee"
    TARGET_ONLY_CARDS = "target_only_cards"
    TARGET_ONLY_FACES = "target_only_faces"
    TARGET_ONLY_FINGERPRINTS = "target_only_fingerprints"
    UNKNOWN_ENROLLMENTS = "unknown_enrollments"
    TEMPLATE_REF_UNPROVEN = "template_ref_unproven"
    NORMALIZATION_COLLISION = "normalization_collision"
    VALIDITY_UNPARSEABLE = "validity_unparseable"


#: Reasons `--on-conflict=overwrite` may resolve: the write replaces only fields the
#: bundle OWNS and never removes target-side extras (no deletions in v1, §4), so a
#: target-only-extras conflict becomes an actionable update. Every OTHER reason is
#: sticky — reassigning a card, guessing a template, or writing over UNKNOWN
#: enrollments or a normalization collision is a human decision (§0 safety spine).
OVERWRITE_RESOLVABLE: frozenset[Reason] = frozenset(
    {
        Reason.TARGET_ONLY_CARDS,
        Reason.TARGET_ONLY_FACES,
        Reason.TARGET_ONLY_FINGERPRINTS,
    }
)


class ConflictPolicy(StrEnum):
    """`--on-conflict` (§4)."""

    SKIP = "skip"
    OVERWRITE = "overwrite"
    ABORT = "abort"


@dataclass(frozen=True, slots=True)
class DiffPolicy:
    """Everything the diff may be told to do differently — no secrets, no paths."""

    on_conflict: ConflictPolicy = ConflictPolicy.SKIP
    #: `--carry-templates` (§1a): carry custom plan-template numbers when — and only
    #: when — they appear in the target's own evidence set.
    carry_templates: bool = False
    #: Site zone for Valid parsing (p1-02 config value; payroll-critical class).
    site_tz: str | None = DEFAULT_SITE_TZ


class DiffAbortedError(GateclerkError):
    """`--on-conflict=abort` and the plan found conflicts: refuse to plan writes.

    The conflicts ride on the exception so the CLI still prints them (data, not a
    stack trace); the run maps to the config-problem exit (2).
    """

    def __init__(self, conflicts: Sequence[Classification]):
        self.conflicts = tuple(conflicts)
        nos = ", ".join(c.employee_hash for c in self.conflicts)
        super().__init__(
            f"diff aborted on --on-conflict=abort: {len(self.conflicts)} conflict(s) "
            f"(employee hash prefixes: {nos}) — nothing was planned for write"
        )


# --- biometric set inputs (scope note 2: compared by template SET identity) ---------------


@dataclass(frozen=True, slots=True)
class TemplateRef:
    """One template by identity ONLY (sha256 + length). The bytes themselves never
    enter a plan or report — PII-free by construction (§4 "hashes/counts only")."""

    employee_no: str
    index: int | None  # fpIndex for fingerprints, FDID for faces (audit only)
    sha256: str
    length: int


@dataclass(frozen=True, slots=True)
class TargetBiometrics:
    """What the TARGET device really has per person, from the proven v4 reads
    (FDSearch rows / FingerPrintUpload-Cond). None on either axis means the READ
    FAILED — UNKNOWN, never empty (§9: "a count is not a set")."""

    faces: Mapping[str, tuple[TemplateRef, ...]] | None = None
    faces_error: str | None = None
    fingerprints: Mapping[str, tuple[TemplateRef, ...]] | None = None
    fingerprints_error: str | None = None

    @classmethod
    def both_unknown(cls, faces_error: str, fingerprints_error: str) -> TargetBiometrics:
        """Both template reads failed (e.g. a target fw that rejects both shapes)."""
        return cls(
            faces=None,
            faces_error=faces_error,
            fingerprints=None,
            fingerprints_error=fingerprints_error,
        )


def employee_hash(employee_no: str, *, prefix_len: int = 12) -> str:
    """The report identity: stable sha256 PREFIX of the opaque employeeNo (§4)."""
    return hashlib.sha256(employee_no.encode("utf-8")).hexdigest()[:prefix_len]


# --- the classification record --------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class Classification:
    """One person's diff verdict. Carries NO name, NO raw employeeNo (in any rendered
    form), NO field values — hash prefix, names, codes, tokens only (§4)."""

    employee_hash: str  # sha256(employeeNo) prefix — the only identity rendered
    classification: DiffClass
    reasons: tuple[Reason, ...] = ()
    #: Field NAMES that differ AND are actionable (an update would write exactly these).
    fields: tuple[str, ...] = ()
    #: Report-only observations: §1a door tokens, counter cross-checks, ambiguity
    #: flags, carried-template caveats. Names/tokens, never values.
    notes: tuple[str, ...] = ()
    #: §1a security fields carried — listed for explicit operator ack before apply.
    security_flags: tuple[str, ...] = ()
    #: Device WRITES this person would trigger (0/1 user row + card/face/FP adds);
    #: 0 for a skipped conflict. Person granularity of the `would_write` ledger.
    would_write: int = 0

    #: Raw employeeNo for freshness matching ONLY — excluded from repr and compare,
    #: and `render_report` never reads it.
    _employee_no: str = field(default="", repr=False, compare=False)

    @property
    def employee_no(self) -> str:
        """Internal matching key for the freshness helper (never rendered)."""
        return self._employee_no


# --- §1 normalization-collision key ----------------------------------------------------------


def _normalization_key(employee_no: str) -> str:
    """The key two sloppier spellings WOULD collide on — computed ONLY to DETECT the
    collision, NEVER to match records (§1: matching stays exact bytes).

    Family-tagged so the int and case families can't mix: "007"/"7" collide as the
    int family, "e1"/"E1" as the case family; "7" never collides with "seven".
    """
    if employee_no.isdigit():
        return f"int:{int(employee_no)}"
    return f"case:{employee_no.casefold()}"


# --- Valid parsing (payroll-critical; reuses tz, re-expresses nothing) ----------------------


def _validity_problem(record: Mapping[str, Any], site_tz: str | None) -> str | None:
    """None when `Valid` is usable; else the report token naming the bound.

    `validity_unparseable` covers: `Valid` absent; a bound that will not parse at all
    (TimeResolver's unresolved verdict); a bound naming a wall time that does NOT
    EXIST in the site zone (a gap — p1-06d established such a stamp means a broken
    device clock, and payroll validity must not be written off one). An AMBIGUOUS
    wall time (autumn fold) stays usable under the fold=0 rule and is flagged as a
    note by the caller instead.
    """
    valid = record.get("Valid")
    if not isinstance(valid, Mapping):
        return "missing"
    resolver = TimeResolver(site_tz=site_tz)
    for bound in ("beginTime", "endTime"):
        raw = valid.get(bound)
        if not isinstance(raw, str) or not raw.strip():
            return f"{bound}:missing"
        resolved = resolver.resolve(raw)
        if resolved.utc is None:
            return f"{bound}:unparseable"
        if resolved.nonexistent:
            return f"{bound}:nonexistent_wall_time"
    return None


def _validity_ambiguous(record: Mapping[str, Any], site_tz: str | None) -> bool:
    valid = record.get("Valid")
    if not isinstance(valid, Mapping):
        return False
    resolver = TimeResolver(site_tz=site_tz)
    for bound in ("beginTime", "endTime"):
        raw = valid.get(bound)
        if isinstance(raw, str) and raw.strip() and resolver.resolve(raw).ambiguous:
            return True
    return False


# --- §1a door-field rules ---------------------------------------------------------------------


def _template_nos(record: Mapping[str, Any]) -> tuple[str, ...]:
    """planTemplateNo values the record references, stringified exactly as spelled."""
    plan = record.get("RightPlan")
    if not isinstance(plan, (list, tuple)):
        return ()
    out: list[str] = []
    for entry in plan:
        if isinstance(entry, Mapping) and entry.get("planTemplateNo") is not None:
            out.append(str(entry["planTemplateNo"]))
    return tuple(out)


def _door_field_verdict(
    source: Mapping[str, Any], evidence: frozenset[str], policy: DiffPolicy
) -> tuple[tuple[str, ...], tuple[str, ...]]:
    """(report-only notes, unproven template numbers) for one person's door data.

    "1" is carried silently (§1a v4). A custom number in the evidence set is carried
    only with --carry-templates (noted UNVERIFIED), otherwise report-only. A custom
    number OUTSIDE the evidence set is report-only (default) or `template_ref_unproven`
    (only if the operator explicitly asked to carry it — §3: never a guess).
    """
    notes: list[str] = []
    unproven: list[str] = []
    for no in _template_nos(source):
        if no == DEFAULT_CARRIED_TEMPLATE_NO:
            continue
        if no in evidence:
            if policy.carry_templates:
                notes.append(f"template_carried_unverified:{no}")
            else:
                notes.append(f"template_report_only:{no}")
        elif policy.carry_templates:
            unproven.append(no)
        else:
            notes.append(f"template_report_only:{no}")
    return tuple(notes), tuple(unproven)


# --- the per-person verdict builders -----------------------------------------------------------


class _Missing:
    """Sentinel so 'key absent' never equals 'value is None' in the field diff."""

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return "<missing>"


_MISSING = _Missing()


def _actionable_field_names(
    source: Mapping[str, Any], target: Mapping[str, Any]
) -> tuple[str, ...]:
    """Sorted NAMES of normalized fields that differ, door fields excluded (§4: only
    names ever leave this function — values are compared here and discarded)."""
    src = normalize_record(source)
    tgt = normalize_record(target)
    differing = {k for k in set(src) | set(tgt) if src.get(k, _MISSING) != tgt.get(k, _MISSING)}
    return tuple(sorted(differing - DOOR_FIELDS))


def _door_only_field_names(source: Mapping[str, Any], target: Mapping[str, Any]) -> tuple[str, ...]:
    src = normalize_record(source)
    tgt = normalize_record(target)
    differing = {k for k in set(src) | set(tgt) if src.get(k, _MISSING) != tgt.get(k, _MISSING)}
    return tuple(sorted(differing & DOOR_FIELDS))


def _security_flags(record: Mapping[str, Any]) -> tuple[str, ...]:
    """§1a: carried security fields the operator must explicitly ack before apply."""
    flags: list[str] = []
    if record.get("localUIRight") is True:
        flags.append("localUIRight=true")
    user_type = record.get("userType")
    if user_type is not None and str(user_type) != "normal":
        flags.append(f"userType={user_type}")
    return tuple(flags)


def _card_verdicts(
    *,
    employee_no: str,
    bundle_cards_for: Sequence[Mapping[str, Any]],
    target_cards_for: Sequence[Mapping[str, Any]],
    target_card_owner: Mapping[str, str],
) -> tuple[tuple[str, ...], tuple[Reason, ...], int]:
    """Pair-identity card rules (§5 step 5 + §4).

    - bundle cardNo already owned by a DIFFERENT employeeNo on the target ->
      `card_no_bound_to_other_employee` (sticky conflict; the person would never get
      the card if skipped, someone else would lose it if reassigned);
    - target cards the bundle does not carry -> `target_only_cards` (overwrite-
      resolvable: our write never removes them, §4 "no deletions in v1");
    - bundle cards the target has in NO ownership at all -> card writes (add count;
      a card already paired with THIS person is a no-op — pair identity is the
      re-run idempotency key).
    """
    notes: list[str] = []
    reasons: list[Reason] = []
    bundle_owned = {str(c.get("cardNo")) for c in bundle_cards_for}
    bound_elsewhere = sorted(
        no
        for no in bundle_owned
        if no in target_card_owner and target_card_owner[no] != employee_no
    )
    if bound_elsewhere:
        reasons.append(Reason.CARD_BOUND_TO_OTHER)
        notes.append(f"cards_bound_to_other_employee:{len(bound_elsewhere)}")
    target_only = [
        str(c.get("cardNo")) for c in target_cards_for if str(c.get("cardNo")) not in bundle_owned
    ]
    if target_only:
        reasons.append(Reason.TARGET_ONLY_CARDS)
        notes.append(f"target_only_cards:{len(target_only)}")
    adds = sum(1 for no in bundle_owned if no not in target_card_owner)
    if adds:
        notes.append(f"card_adds:{adds}")
    return tuple(notes), tuple(reasons), adds


def _biometric_verdicts(
    *,
    employee_no: str,
    kind: str,
    bundle_refs: Mapping[str, Sequence[TemplateRef]] | None,
    target_refs: Mapping[str, Sequence[TemplateRef]] | None,
    read_error: str | None,
    target_record: Mapping[str, Any] | None,
) -> tuple[tuple[str, ...], tuple[Reason, ...], int]:
    """One biometric axis: set identity by template sha256 (scope note 2), UNKNOWN
    handled per §9. `kind` is "face" or "fp" (note vocabulary, and the counter field
    the §9 fallback consults: numOfFace / numOfFP).

    - target read OK: target set ⊄ bundle set -> conflict (target holds templates the
      bundle cannot re-create — a write that mangles the store could destroy them,
      R2 semantics unproven); bundle set ⊄ target set -> uploads (add-side).
    - target read FAILED: UNKNOWN, never empty. If the volatile counter on the
      (existing) target person says N>0 the person is `unknown_enrollments` —
      NEVER an update (§9). A failed read where nothing claims to exist (no target
      person, or counter 0) is noted, not conflicted.
    - read OK + counter present: cross-check runs as REPORT-ONLY note (a count is
      not a set; counters are volatile and may legitimately disagree).
    """
    notes: list[str] = []
    reasons: list[Reason] = []
    counter_field = "numOfFace" if kind == "face" else "numOfFP"
    only_reason = Reason.TARGET_ONLY_FACES if kind == "face" else Reason.TARGET_ONLY_FINGERPRINTS

    if target_refs is None:  # read failed -> UNKNOWN
        if read_error:
            notes.append(f"{kind}_read_failed(unknown_not_zero)")
        if target_record is not None:
            counter = target_record.get(counter_field)
            if isinstance(counter, int) and counter > 0:
                reasons.append(Reason.UNKNOWN_ENROLLMENTS)
                notes.append(f"unknown_{kind}s:counter={counter}")
        return tuple(notes), tuple(reasons), 0

    target_set = {r.sha256 for r in target_refs.get(employee_no, ())}
    bundle_set = {r.sha256 for r in (bundle_refs.get(employee_no, ()) if bundle_refs else ())}
    extra = target_set - bundle_set
    if extra:
        reasons.append(only_reason)
        notes.append(f"target_only_{kind}s:{len(extra)}")
    adds = len(bundle_set - target_set)
    if adds:
        notes.append(f"{kind}_uploads:{adds}")
    if target_record is not None:
        counter = target_record.get(counter_field)
        if isinstance(counter, int) and counter != len(target_set):
            notes.append(f"{kind}_counter_cross_check:counter={counter},rows={len(target_set)}")
    return tuple(notes), tuple(reasons), adds


# --- classify ------------------------------------------------------------------------------------


def classify(
    bundle_people: Sequence[Mapping[str, Any]],
    target_people: Sequence[Mapping[str, Any]],
    bundle_cards: Sequence[Mapping[str, Any]],
    target_cards: Sequence[Mapping[str, Any]],
    probe: CapabilityMatrix | None,
    *,
    policy: DiffPolicy | None = None,
    bundle_faces: Mapping[str, Sequence[TemplateRef]] | None = None,
    bundle_fingerprints: Mapping[str, Sequence[TemplateRef]] | None = None,
    biometrics: TargetBiometrics | None = None,
) -> list[Classification]:
    """Classify every employeeNo across bundle and target — PURE (no I/O, no clock).

    Device I/O is `plan()`'s job through the injected search-fn; this signature is
    the card's (`classify(bundle_people, target_people, bundle_cards, target_cards,
    probe)`) plus the E1-01b/§9 keyword seams.

    The template evidence set (§3) is computed LIVE from `target_people`; when a
    probe is supplied its recorded set is CROSS-CHECKED and a disagreement becomes a
    report-only note (the probe is a point-in-time record, this read is fresh).

    `bundle_faces` / `bundle_fingerprints`: template sets the BUNDLE carries per
    person (E1-01b export seam; absent until E1-01b merges — E1-01 ships faces as a
    RECORDED UNAVAILABLE, which means "the bundle carries none", a fact not a
    silence). `biometrics`: the target's face/FP sets, or None per axis = read
    failed = UNKNOWN (§9).

    `policy.on_conflict=abort` does NOT raise here — classify is the pure verdict
    table; `plan()` raises `DiffAbortedError` and builds the write ledger.
    """
    policy = policy or DiffPolicy()
    biometrics = biometrics or TargetBiometrics()

    source = _records_by_employee(bundle_people)
    target = _records_by_employee(target_people)
    target_card_owner: dict[str, str] = {}
    for card in target_cards:
        if card.get("cardNo") is not None:
            target_card_owner[str(card["cardNo"])] = str(card.get("employeeNo") or "")
    bundle_cards_by_person = _records_by_employee(bundle_cards)
    target_cards_by_person = _records_by_employee(target_cards)

    evidence = frozenset(
        no for records in target.values() for record in records for no in _template_nos(record)
    )
    probe_note = _probe_evidence_note(evidence, probe)

    target_norm: dict[str, list[str]] = {}
    for no in target:
        target_norm.setdefault(_normalization_key(no), []).append(no)

    results: list[Classification] = []
    for no in sorted(set(source) | set(target)):
        src_records = source.get(no, [])
        tgt_records = target.get(no, [])
        if src_records and not tgt_records:
            twins = [t for t in target_norm.get(_normalization_key(no), []) if t != no]
            if twins:
                # §1: "007" vs "7" — refusing to merge IS the point; both stay.
                results.append(
                    Classification(
                        employee_hash=employee_hash(no),
                        classification=DiffClass.CONFLICT,
                        reasons=(Reason.NORMALIZATION_COLLISION,),
                        notes=tuple(
                            pnote
                            for pnote in ([probe_note] if probe_note else [])
                            + ["collides_with_target_record_only_after_coercion"]
                        ),
                        _employee_no=no,
                    )
                )
                continue
            results.append(
                _classify_add(
                    employee_no=no,
                    record=src_records[0],
                    bundle_cards_for=bundle_cards_by_person.get(no, ()),
                    target_card_owner=target_card_owner,
                    evidence=evidence,
                    policy=policy,
                    bundle_faces=bundle_faces,
                    bundle_fingerprints=bundle_fingerprints,
                    biometrics=biometrics,
                    probe_note=probe_note,
                )
            )
        elif tgt_records and not src_records:
            results.append(
                Classification(
                    employee_hash=employee_hash(no),
                    classification=DiffClass.SAME,
                    notes=tuple(
                        pnote
                        for pnote in ([probe_note] if probe_note else [])
                        + ["target_only_person(kept;v1_never_deletes)"]
                    ),
                    _employee_no=no,
                )
            )
        else:
            results.append(
                _classify_both(
                    employee_no=no,
                    src=src_records[0],
                    tgt=tgt_records[0],
                    bundle_cards_for=bundle_cards_by_person.get(no, ()),
                    target_cards_for=target_cards_by_person.get(no, ()),
                    target_card_owner=target_card_owner,
                    evidence=evidence,
                    policy=policy,
                    bundle_faces=bundle_faces,
                    bundle_fingerprints=bundle_fingerprints,
                    biometrics=biometrics,
                    probe_note=probe_note,
                )
            )
    return results


def _records_by_employee(
    records: Sequence[Mapping[str, Any]],
) -> dict[str, list[Mapping[str, Any]]]:
    out: dict[str, list[Mapping[str, Any]]] = {}
    for record in records:
        if record.get("employeeNo") is not None:
            out.setdefault(str(record["employeeNo"]), []).append(record)
    return out


def _probe_evidence_note(evidence: frozenset[str], probe: CapabilityMatrix | None) -> str | None:
    if probe is None or frozenset(probe.template_nos) == evidence:
        return None
    live = ",".join(sorted(evidence)) or "-"
    recorded = ",".join(sorted(probe.template_nos)) or "-"
    return f"probe_evidence_stale_vs_target(live={live};probe={recorded})"


def _classify_add(
    *,
    employee_no: str,
    record: Mapping[str, Any],
    bundle_cards_for: Sequence[Mapping[str, Any]],
    target_card_owner: Mapping[str, str],
    evidence: frozenset[str],
    policy: DiffPolicy,
    bundle_faces: Mapping[str, Sequence[TemplateRef]] | None,
    bundle_fingerprints: Mapping[str, Sequence[TemplateRef]] | None,
    biometrics: TargetBiometrics,
    probe_note: str | None,
) -> Classification:
    """Source-only person: the `add` class plus its own conflict gates."""
    notes: list[str] = [probe_note] if probe_note else []
    reasons: list[Reason] = []

    validity = _validity_problem(record, policy.site_tz)
    if validity is not None:
        reasons.append(Reason.VALIDITY_UNPARSEABLE)
        notes.append(f"validity:{validity}")
    elif _validity_ambiguous(record, policy.site_tz):
        notes.append("validity_ambiguous(site_tz;fold=0_first_occurrence)")

    door_notes, unproven = _door_field_verdict(record, evidence, policy)
    notes.extend(door_notes)
    if unproven:
        reasons.append(Reason.TEMPLATE_REF_UNPROVEN)
        notes.append(f"unproven_template_refs:{','.join(unproven)}")

    card_notes, card_reasons, card_adds = _card_verdicts(
        employee_no=employee_no,
        bundle_cards_for=bundle_cards_for,
        target_cards_for=(),
        target_card_owner=target_card_owner,
    )
    notes.extend(card_notes)
    reasons.extend(card_reasons)

    face_notes, face_reasons, face_adds = _biometric_verdicts(
        employee_no=employee_no,
        kind="face",
        bundle_refs=bundle_faces,
        target_refs=biometrics.faces,
        read_error=biometrics.faces_error,
        target_record=None,  # no target person -> no counter claim -> no UNKNOWN (§9)
    )
    fp_notes, fp_reasons, fp_adds = _biometric_verdicts(
        employee_no=employee_no,
        kind="fp",
        bundle_refs=bundle_fingerprints,
        target_refs=biometrics.fingerprints,
        read_error=biometrics.fingerprints_error,
        target_record=None,
    )
    notes.extend(face_notes)
    notes.extend(fp_notes)
    reasons.extend(face_reasons)
    reasons.extend(fp_reasons)

    hash_prefix = employee_hash(employee_no)
    security = _security_flags(record)
    if reasons:
        return Classification(
            employee_hash=hash_prefix,
            classification=DiffClass.CONFLICT,
            reasons=tuple(sorted(set(reasons), key=lambda r: r.value)),
            notes=tuple(notes),
            security_flags=security,
            _employee_no=employee_no,
        )
    return Classification(
        employee_hash=hash_prefix,
        classification=DiffClass.ADD,
        notes=tuple(notes),
        security_flags=security,
        would_write=1 + card_adds + face_adds + fp_adds,
        _employee_no=employee_no,
    )


def _classify_both(
    *,
    employee_no: str,
    src: Mapping[str, Any],
    tgt: Mapping[str, Any],
    bundle_cards_for: Sequence[Mapping[str, Any]],
    target_cards_for: Sequence[Mapping[str, Any]],
    target_card_owner: Mapping[str, str],
    evidence: frozenset[str],
    policy: DiffPolicy,
    bundle_faces: Mapping[str, Sequence[TemplateRef]] | None,
    bundle_fingerprints: Mapping[str, Sequence[TemplateRef]] | None,
    biometrics: TargetBiometrics,
    probe_note: str | None,
) -> Classification:
    """Person on BOTH sides: update / same / conflict (§4)."""
    notes: list[str] = [probe_note] if probe_note else []
    reasons: list[Reason] = []

    fields = _actionable_field_names(src, tgt)
    validity = _validity_problem(src, policy.site_tz)
    if validity is not None:
        reasons.append(Reason.VALIDITY_UNPARSEABLE)
        notes.append(f"validity:{validity}")
    elif _validity_ambiguous(src, policy.site_tz):
        notes.append("validity_ambiguous(site_tz;fold=0_first_occurrence)")

    door_notes, unproven = _door_field_verdict(src, evidence, policy)
    notes.extend(door_notes)
    if unproven:
        reasons.append(Reason.TEMPLATE_REF_UNPROVEN)
        notes.append(f"unproven_template_refs:{','.join(unproven)}")
    # §1a: a door-field difference is reported by NAME, never made actionable — even
    # when nothing is carried, the person's door data stays target-owned.
    for name in _door_only_field_names(src, tgt):
        notes.append(f"report_only_diff:{name}")

    card_notes, card_reasons, card_adds = _card_verdicts(
        employee_no=employee_no,
        bundle_cards_for=bundle_cards_for,
        target_cards_for=target_cards_for,
        target_card_owner=target_card_owner,
    )
    notes.extend(card_notes)
    reasons.extend(card_reasons)

    face_notes, face_reasons, face_adds = _biometric_verdicts(
        employee_no=employee_no,
        kind="face",
        bundle_refs=bundle_faces,
        target_refs=biometrics.faces,
        read_error=biometrics.faces_error,
        target_record=tgt,
    )
    fp_notes, fp_reasons, fp_adds = _biometric_verdicts(
        employee_no=employee_no,
        kind="fp",
        bundle_refs=bundle_fingerprints,
        target_refs=biometrics.fingerprints,
        read_error=biometrics.fingerprints_error,
        target_record=tgt,
    )
    notes.extend(face_notes)
    notes.extend(fp_notes)
    reasons.extend(face_reasons)
    reasons.extend(fp_reasons)

    hash_prefix = employee_hash(employee_no)
    security = _security_flags(src)
    reasons_sorted = tuple(sorted(set(reasons), key=lambda r: r.value))
    if reasons_sorted:
        overwrite_ok = (
            policy.on_conflict is ConflictPolicy.OVERWRITE
            and set(reasons_sorted) <= OVERWRITE_RESOLVABLE
        )
        if not overwrite_ok:
            # Conflicts: reported AND skipped (would_write 0, §4 default).
            return Classification(
                employee_hash=hash_prefix,
                classification=DiffClass.CONFLICT,
                reasons=reasons_sorted,
                fields=fields,
                notes=tuple(notes),
                security_flags=security,
                _employee_no=employee_no,
            )
        # overwrite: only bundle-owned fields are written, target extras survive —
        # fall through and classify on the actionable diff below.
    actionable = bool(fields)
    would = (1 if actionable else 0) + card_adds + face_adds + fp_adds
    if actionable or would:
        return Classification(
            employee_hash=hash_prefix,
            classification=DiffClass.UPDATE,
            fields=fields,
            notes=tuple(notes),
            security_flags=security,
            would_write=would,
            _employee_no=employee_no,
        )
    # Nothing to write: hash-equal, OR differing only in report-only (§1a) fields —
    # a write would change nothing the bundle owns. Zero-write re-runs by construction.
    if content_hash(src) == content_hash(tgt):
        notes.append("hash_equal")
    return Classification(
        employee_hash=hash_prefix,
        classification=DiffClass.SAME,
        notes=tuple(notes),
        security_flags=security,
        _employee_no=employee_no,
    )


# --- the plan -------------------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class Plan:
    """The diff's only output: class lists + the write ledger (§4).

    Field VALUES never exist in this object — only names, codes, tokens, hash
    prefixes. `would_write` counts device WRITES (user rows + card/face/FP adds),
    the number §5's budget math plans against.
    """

    items: tuple[Classification, ...]
    policy: DiffPolicy = field(default_factory=DiffPolicy)
    target_termination: Mapping[str, str] = field(default_factory=dict)
    source_counts: Mapping[str, int] = field(default_factory=dict)

    def _of(self, kind: DiffClass) -> tuple[Classification, ...]:
        return tuple(i for i in self.items if i.classification is kind)

    @property
    def adds(self) -> tuple[Classification, ...]:
        return self._of(DiffClass.ADD)

    @property
    def updates(self) -> tuple[Classification, ...]:
        return self._of(DiffClass.UPDATE)

    @property
    def same(self) -> tuple[Classification, ...]:
        return self._of(DiffClass.SAME)

    @property
    def conflicts(self) -> tuple[Classification, ...]:
        return self._of(DiffClass.CONFLICT)

    @property
    def would_write(self) -> int:
        return sum(i.would_write for i in self.items)

    @property
    def security_ack(self) -> tuple[Classification, ...]:
        """Persons carrying security fields that need explicit operator ack (§1a)."""
        return tuple(i for i in self.items if i.security_flags)

    @property
    def exit_code(self) -> int:
        """§4 / p1-08 mapping: 0 no changes / 1 changes pending / 2 config-problem —
        here: conflicts pending with NO writable path (fix the data or change
        --on-conflict; the engine refuses to guess a way through)."""
        if self.would_write:
            return 1
        if self.conflicts:
            return 2
        return 0


def plan(
    bundle: BundleData,
    target_state: EnrollmentState | Callable[[], EnrollmentState],
    policy: DiffPolicy,
    probe: CapabilityMatrix | None = None,
    *,
    now: datetime | None = None,
    biometrics: TargetBiometrics | None = None,
    bundle_faces: Mapping[str, Sequence[TemplateRef]] | None = None,
    bundle_fingerprints: Mapping[str, Sequence[TemplateRef]] | None = None,
) -> Plan:
    """The dry-run plan: fresh target read -> classify -> policy -> ledger (§4).

    `target_state` is the card's injected search-fn seam: an `EnrollmentState` (reuse
    one read across tests/apply steps) or a zero-arg callable that READS the target
    NOW — production wires `read_target_state(client)`; tests wire FakeDevice.
    Target state is read at plan time, NEVER taken from a cached/bundled view (§4).

    `probe` + injected `now`: when both are given, E1-03's `require_fresh` gate runs
    first (a stale/naive/future probe refuses the plan with `ProbeStaleError` — no
    B/C write may inherit assumptions from a probe the device outgrew, §3/§4).

    Bundle faces/FPs ride the E1-01b seam (`bundle_faces`/`bundle_fingerprints`);
    E1-01 bundles carry neither (faces/INDEX.json says so — extend the seam, don't
    fork it). `policy.on_conflict=abort` raises `DiffAbortedError` with the conflicts.
    """
    state = target_state() if callable(target_state) else target_state
    if probe is not None and now is not None:
        require_fresh(probe, now)  # ProbeStaleError is E1-03's contract, unchanged

    items = classify(
        bundle.people,
        state.users,
        bundle.cards,
        state.cards,
        probe,
        policy=policy,
        bundle_faces=bundle_faces,
        bundle_fingerprints=bundle_fingerprints,
        biometrics=biometrics,
    )
    if policy.on_conflict is ConflictPolicy.ABORT:
        conflicts = [i for i in items if i.classification is DiffClass.CONFLICT]
        if conflicts:
            raise DiffAbortedError(conflicts)
    return Plan(
        items=tuple(items),
        policy=policy,
        target_termination=dict(state.termination),
        source_counts={
            "bundle_people": len(bundle.people),
            "bundle_cards": len(bundle.cards),
            "target_people": len(state.users),
            "target_cards": len(state.cards),
        },
    )


def read_target_state(client: Any, **kwargs: Any) -> Callable[[], EnrollmentState]:
    """The production search-fn: re-read the target FAIL-CLOSED via E1-01's own reader.

    A thin closure over `collect_enrollment_state` — the SAME reader the export uses,
    so diff and snapshot can never read the device differently. Any required-read
    failure raises `EnrollmentReadAborted` (an unverified target aborts the apply,
    §4 exit-2 territory) — never partial state.
    """
    return lambda: collect_enrollment_state(client, **kwargs)


# --- the freshness contract (§4) ----------------------------------------------------------------


def plan_still_valid(plan: Plan, reclassified: Sequence[Classification]) -> list[str]:
    """Apply-phase TOCTOU check: the ABORT SIGNAL, not a boolean (§4).

    Apply re-diffs immediately before EACH write phase and calls this with the fresh
    classifications. Returns the employee-hash prefixes whose classification OR
    reason set changed since plan time — a person VANISHING from the re-diff is also
    a change (someone deleted/renamed them mid-flight). Empty list = every pending
    record still means what the plan said. Non-empty: the phase ABORTS, run exits 1
    with the changed list, the operator re-diffs. Nobody "fixes" drift with a blind
    re-write (§0.6).
    """
    fresh_by_hash = {c.employee_hash: c for c in reclassified}
    changed: list[str] = []
    for planned in plan.items:
        fresh = fresh_by_hash.get(planned.employee_hash)
        if (
            fresh is None
            or fresh.classification is not planned.classification
            or fresh.reasons != planned.reasons
        ):
            changed.append(planned.employee_hash)
    changed.extend(h for h in fresh_by_hash if h not in {c.employee_hash for c in plan.items})
    return sorted(set(changed))


# --- the report renderer (§4) -----------------------------------------------------------------


def _payload(plan: Plan) -> dict[str, Any]:
    totals = {
        "add": len(plan.adds),
        "update": len(plan.updates),
        "same": len(plan.same),
        "conflict": len(plan.conflicts),
    }
    reasons: dict[str, int] = {}
    for item in plan.conflicts:
        for r in item.reasons:
            reasons[r.value] = reasons.get(r.value, 0) + 1
    return {
        "people": [
            {
                "classification": i.classification.value,
                "employee": i.employee_hash,
                "fields": list(i.fields),
                "notes": list(i.notes),
                "reasons": [r.value for r in i.reasons],
                "security_flags": list(i.security_flags),
                "would_write": i.would_write,
            }
            for i in plan.items
        ],
        "reasons": reasons,
        "schema": REPORT_SCHEMA,
        "source_counts": dict(plan.source_counts),
        "target_termination": dict(plan.target_termination),
        "totals": totals,
        "would_write": plan.would_write,
    }


def render_report(plan: Plan, *, fmt: str = "table") -> str:
    """The report: per-person hash prefix + classification + FIELD NAMES only, totals,
    "would write N". Never a name, never a value, never the raw employeeNo (§4).

    `fmt="json"` is the byte-pinned machine contract — `json.dumps(..., sort_keys=True,
    indent=2)` over `_payload` (E1-07's `-o json` renders through here verbatim; the
    E1-02 test pins these bytes). `fmt="table"` is the human default rendering the
    SAME payload — the two views of one computation can never disagree.
    """
    if fmt == "json":
        return json.dumps(_payload(plan), sort_keys=True, indent=2) + "\n"
    if fmt != "table":
        raise ValueError(f"unknown report format {fmt!r} (expected 'table' or 'json')")
    lines = [f"{'EMPLOYEE':<12} {'CLASS':<8} {'WRITE':>5}  REASONS / FIELDS / NOTES"]
    for item in plan.items:
        detail = "; ".join(
            [
                *(f"field:{n}" for n in item.fields),
                *(f"reason:{r.value}" for r in item.reasons),
                *item.notes,
                *(f"ack:{n}" for n in item.security_flags),
            ]
        )
        lines.append(
            f"{item.employee_hash:<12} {item.classification.value:<8} "
            f"{item.would_write:>5}  {detail}"
        )
    totals = {
        "add": len(plan.adds),
        "update": len(plan.updates),
        "same": len(plan.same),
        "conflict": len(plan.conflicts),
    }
    lines.append(
        "totals: "
        + " ".join(f"{k}={totals[k]}" for k in ("add", "update", "same", "conflict"))
        + f" | would write {plan.would_write}"
    )
    if plan.security_ack:
        lines.append(
            "security ack required before apply (§1a): "
            + ", ".join(i.employee_hash for i in plan.security_ack)
        )
    lines.append(f"exit: {plan.exit_code}")
    return "\n".join(lines) + "\n"
