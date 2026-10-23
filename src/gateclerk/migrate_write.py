"""E1-04 write foundation: apply journal, users phase, users read-back verify.

Design contract: docs/ENROLLMENT-MIGRATION.md — §5 (steps 0-3, 7), §5a (journal
lifecycle), §5b (rule D-WIPE), §6 (read-back verify), §0 (safety rules), §9
(capture-before-fake). Every write shape here exists ONLY because it sits in a
committed bench-A capture fixture under
``tests/fixtures/recorded/site-a-ds-k1t341amf-s/enrollment/`` (PR #43, d34b3a5):

    users_setup_add_request.json           PUT, SINGULAR "UserInfo", "mode":"add"
    users_setup_add_response.json          statusCode 1
    users_setup_readback_t90.json          the read shape verify compares against
    users_setup_wrapped_list_400.json      {"userInfoList":{…}} -> lack employeeNo
    users_setup_post_method_not_allowed.json / users_setup_put_record_405.json

This module issues ZERO device requests by itself and registers NOTHING in
``gateclerk.endpoints``: the read-only registry stays exactly as
``tests/test_endpoints_registry.py`` pins it (that test IS the §5.0 merge gate, and
E1-04 does not touch it). The captured write path is a string constant here — a path
string is not a callable path — and the transport is INJECTED. Production wires a
live write client behind the operator's explicit ``--apply`` (E1-07's CLI); tests wire
the fixture-replaying FakeDevice. There is no code path from this module to a socket.

Safety rules honoured here, each with the test that proves it
(tests/test_e1_04_write_foundation.py):

* §5a journal — append-only JSONL, fsync BEFORE the request; lifecycle
  ``planned -> applied -> confirmed``. A record that can be lost to a crash is not a
  journal (``test_journal_line_reaches_disk_before_the_request_arrives``).
* §5.3 budget — one transport per phase, re-bootstrap at 80 authed calls (OBSERVED
  ~190/request cap), sleep injected between batches, never a retry of a refused write
  (§0.5/§0.6: the device answered, the answer stands).
* §5 step 3 — write-field set != bundle record: a SetUp body is EXACTLY the captured
  key set (nothing device-generated or read-only is echoed, R2), and the value
  vocabulary is checked against the probe's caps document (caps are the vocabulary
  source — OBSERVED.md — so a value outside it is refused here, not 400'd mid-batch).
* §5 step 4 — the first rejection aborts the phase and reports which records landed.
  The rejection kinds are only the subStatusCodes the captures contain
  (``badJsonContent``, ``MessageParametersLack``, ``methodNotAllowed``, ``notSupport``);
  anything else is ``other_rejected`` carrying the device's own word verbatim. No
  invented device vocabulary.
* §5 step 8 — **no deletions ever in v1**. This module has no delete route, no
  ``mode:"delete"`` builder and no way to reach the wipe hazard §5b names; the rule is
  pinned by a test that asserts the module exposes no delete vocabulary at all.
* §6 verify — never trust the write's status code: re-search the touched persons with
  COVERAGE PROOF and compare content hashes through migrate_bundle's own normalization
  (the same function both sides, so the two cannot drift).
* §9 — no PII in the journal or reports beyond what the bundle already holds: records
  enter normalized (``normalize_record`` strips ``password`` unconditionally, §2/R3)
  and a record that still carries a secret key is refused at append time.

Two scope decisions this card owns (both forced by §0.3/§9 capture-before-fake, both
flagged to the orchestrator in the completion metadata):

1. **Adds only.** The capture proves ONE write shape — a person that did not exist
   (``mode:"add"``, test person 90). What ``UserInfo/SetUp``+``mode:"add"`` does to an
   EXISTING employeeNo (merge? overwrite? duplicate?) is R2 and unproven, so
   ``update``-class records are REPORTED AND SKIPPED with reason
   ``update_shape_uncaptured`` rather than written on a guess. The same reasoning
   refuses a multi-record body: the only list-shaped request we have is the one that
   400'd (``users_setup_wrapped_list_400.json``), so a "batch" here is a *group of
   single-record requests between two sleeps*, never a batched body.
2. **Batch size is derived, never asserted** (§5 step 3). Neither the captures nor any
   caps document this card may read names a write-batch ``@max``
   (``maxRecordNum`` is the search page cap and §1 forbids reading it as capacity;
   ``EmployeeNoList.@maxSize`` bounds the *search filter* list). So the fallback the
   card names — 10 — ships, and the absence is recorded as a fact instead of a silence.
"""

from __future__ import annotations

import hashlib
import json
import os
import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field, replace
from enum import StrEnum
from pathlib import Path
from typing import Any, Protocol

from gateclerk.exceptions import GateclerkError
from gateclerk.migrate_bundle import (
    VOLATILE_FIELDS,
    BundleData,
    content_hash,
    normalize_record,
    repo_root,
)
from gateclerk.migrate_diff import (
    DEFAULT_CARRIED_TEMPLATE_NO,
    Classification,
    DiffClass,
    Plan,
    plan_still_valid,
)
from gateclerk.migrate_probe import CapabilityMatrix, require_fresh

__all__ = [
    "CAPTURED_USER_READ_KEYS",
    "CAPTURED_USER_WRITE_KEYS",
    "DEFAULT_BATCH_SIZE",
    "JOURNAL_SCHEMA",
    "MAX_CLOCK_SKEW_S",
    "REBOOTSTRAP_AT_AUTHED_CALLS",
    "REQUIRED_USER_WRITE_KEYS",
    "USER_SETUP_PATH",
    "USER_SETUP_RESPONSE_OK",
    "ApplyAbortedError",
    "ApplyReport",
    "BudgetedWriteTransport",
    "JournalEntry",
    "JournalError",
    "JournalState",
    "PersonVerdict",
    "RejectKind",
    "TransportClosedError",
    "UserWrite",
    "UsersPhaseResult",
    "UsersVerifyReport",
    "VerifyAbortedError",
    "VerifyItem",
    "WriteAbortedError",
    "WriteJournal",
    "WriteRejectedError",
    "WriteShapeError",
    "apply_users_phase",
    "build_user_setup_body",
    "check_clock_skew",
    "classify_rejection",
    "derive_user_batch_size",
    "frozen_write_allow_list",
    "person_hash",
    "plan_user_writes",
    "run_users_phase",
    "verify_users",
]

#: The captured write endpoint (OBSERVED.md "E1 §5.0 WRITE-PATH CAPTURE":
#: ``PUT /ISAPI/AccessControl/UserInfo/SetUp?format=json``). A constant, not a
#: registry entry — see the module docstring for why the registry stays untouched.
USER_SETUP_PATH = "/ISAPI/AccessControl/UserInfo/SetUp"

#: The journal's format token — a reader that does not know this exact value refuses
#: the file instead of half-reading it (same discipline as the bundle schema, §2).
JOURNAL_SCHEMA = "gateclerk-migrate-journal/1"

#: §5.3: "client re-bootstraps at 80 authed calls (well inside the ~190 cap,
#: OBSERVED.md)". One number, tested against the fake's nonce ledger.
REBOOTSTRAP_AT_AUTHED_CALLS = 80

#: §5 step 3: "batch size from the device's own @max where discoverable, else 10".
#: No capture and no caps document names a WRITE batch max (module docstring,
#: decision 2), so 10 is the shipped default and stays a ceiling.
DEFAULT_BATCH_SIZE = 10

#: §5.1a: validity strings are wall digits under ``timeType:"local"`` (bench A's only
#: option, §1), so a lying device clock lands payroll windows on the wrong wall.
#: Refuse above 60 s of skew; we never touch device clocks (standing rule).
MAX_CLOCK_SKEW_S = 60.0

#: The key set of the ONE proven UserInfo/SetUp body (``users_setup_add_request.json``
#: verbatim). Membership here is what makes a write legal; values are additionally
#: validated against the probe's caps vocabulary (R2 + §3).
CAPTURED_USER_WRITE_KEYS: frozenset[str] = frozenset(
    {
        "employeeNo",
        "name",
        "userType",
        "Valid",
        "doorRight",
        "RightPlan",
        "localUIRight",
        "gender",
    }
)

#: The keys the capture shows as REQUIRED in the body (all of them — the device 400s
#: ``lack employeeNo`` for a body whose employeeNo is not where it looks, and every
#: other key is present in the one shape we proved). A source record missing any of
#: them is refused per-person, not silently written with a smaller body.
REQUIRED_USER_WRITE_KEYS: frozenset[str] = CAPTURED_USER_WRITE_KEYS

#: The key set of the proven read-back (``users_setup_readback_t90.json``
#: ``UserInfoSearch.UserInfo[0]``): device vocabulary on this firmware, used by the §6
#: unknown-field rule to tell "the device added defaults" apart from "the device
#: invented a field nobody has seen".
CAPTURED_USER_READ_KEYS: frozenset[str] = frozenset(
    {
        "employeeNo",
        "name",
        "userType",
        "closeDelayEnabled",
        "Valid",
        "belongGroup",
        "doorRight",
        "RightPlan",
        "maxOpenDoorTime",
        "openDoorTime",
        "roomNumber",
        "floorNumber",
        "localUIRight",
        "gender",
        "numOfCard",
        "numOfFP",
        "numOfFace",
        "PersonInfoExtends",
    }
)

#: The ack every capture shows for an accepted write. Anything else is not "accepted
#: with a note" — it is a rejection (§6: never trust the status code).
USER_SETUP_RESPONSE_OK = 1

#: Keys that must never reach the journal file. ``password`` is already in
#: VOLATILE_FIELDS (so ``normalize_record`` drops it); naming it again makes the
#: intent greppable and keeps this guard independent of the strip list's contents.
_SECRET_KEYS: frozenset[str] = frozenset({"password"})


def _noop_sleep(_seconds: float) -> None:
    return None


def _monotonic() -> float:
    return time.monotonic()


# --- errors -------------------------------------------------------------------------------


class JournalError(GateclerkError):
    """The journal could not be opened, appended, or replayed.

    A journal we cannot trust is a run we must not start: an entry that may be lost to
    a crash is not a journal (§5a), so every failure here is fatal rather than logged.
    """


class WriteShapeError(GateclerkError):
    """We were asked to build a write body the capture does not authorise.

    Raised BEFORE any request: a shape absent from the fixtures has no device truth, so
    we refuse it rather than let the device discover it (§9).
    """


class WriteRejectedError(GateclerkError):
    """The device answered a write with a non-OK envelope.

    Carries the envelope's own words so the journal and the report name the reason
    verbatim (§6: verify, never infer). Raised by transports and by the ack check; a
    refused write is never re-sent (§0.6).
    """

    def __init__(
        self,
        message: str,
        *,
        sub_status: str | None = None,
        http_status: int | None = None,
        envelope: Mapping[str, Any] | None = None,
    ) -> None:
        self.sub_status = sub_status
        self.http_status = http_status
        self.envelope: dict[str, Any] = dict(envelope or {})
        super().__init__(message)


class RejectKind(StrEnum):
    """What a rejected write's ``subStatusCode`` means — only captured vocabulary.

    Every member names a subStatusCode that appears in a committed bench-A capture.
    Anything the captures never show is :attr:`OTHER` and keeps the device's own word
    verbatim in the report: an unknown answer is data, never an inferred category.
    """

    #: Our body shape is wrong (`badJsonContent`, `MessageParametersLack`) — OUR bug:
    #: the fixtures show both rejections for a mis-shapen body.
    SHAPE = "shape_rejected"
    #: The verb itself is wrong (`methodNotAllowed`) — a regression against the capture,
    #: which proved PUT is the verb and POST the 405.
    VERB = "method_not_allowed"
    #: The endpoint does not exist on this firmware (`notSupport`).
    ABSENT = "not_supported"
    #: The device said no for a reason it named itself (capacity, busy-exhausted, a
    #: per-record refusal). §5 step 4: the first of these aborts the phase.
    OTHER = "other_rejected"


class WriteAbortedError(GateclerkError):
    """A write phase aborted: nothing further may be written until a human reads why.

    Carries the :class:`UsersPhaseResult` so the caller can still print which records
    landed (§5 step 4: never a silent partial write).
    """

    def __init__(self, message: str, result: UsersPhaseResult) -> None:
        self.result = result
        super().__init__(message)


class ApplyAbortedError(GateclerkError):
    """The apply refused to start or continue (stale probe, clock skew, drifted plan).

    §5 step 1 and §4's freshness contract: an unverified target, a stale probe, or a
    plan the target has outgrown is never written against.
    """


class VerifyAbortedError(GateclerkError):
    """The verify read itself failed. §0.7: a failed read is never read as "missing".

    Verdicts come from records the device actually returned. When the read errored —
    on the filtered attempt AND the full-paging fallback — every "missing" would be an
    inference from silence, so the walker refuses instead.
    """


class TransportClosedError(GateclerkError):
    """A closed (re-bootstrapped) transport was used again — a budget bookkeeping bug.

    Silence here would let a phase keep writing on a client whose budget was already
    spent, which is the ~190-request lockout class OBSERVED.md records.
    """


# --- §5a: the journal --------------------------------------------------------------------


class JournalState(StrEnum):
    """Lifecycle of one journal entry (§5a)."""

    PLANNED = "planned"
    APPLIED = "applied"
    CONFIRMED = "confirmed"
    #: We sent it and the device refused: unknown state, never undone (§5a —
    #: "planned/applied without confirmed are never deleted (unknown state = human)").
    REJECTED = "rejected"


@dataclass(frozen=True, slots=True)
class JournalEntry:
    """One person's write, as the journal remembers it.

    Person identity is the ``employeeNo`` — the same opaque byte string the bundle's
    ``people.jsonl`` keys on (§1), so the journal holds no MORE identity than the
    bundle already holds (§9). Never in here: a PIN (normalized on the way in, §2/R3),
    a device credential, or a log line.
    """

    seq: int
    state: JournalState
    phase: str
    op: str
    employee_no: str
    #: sha256 prefix — the identity safe to print (§4). The raw no. above is for
    #: matching, exactly like the bundle's own key.
    employee_hash: str
    classification: str
    #: content hash of the pre-write record (from the pre-write snapshot), if any.
    pre_write_hash: str | None = None
    #: content hash of the record we intend the person to LOOK LIKE on the target
    #: (the normalized bundle record — §2's normalization both sides, so this hash is
    #: directly comparable to the §6 read-back hash).
    intended_hash: str | None = None
    #: content hash of the read-back, once the §6 walker confirms it.
    post_write_hash: str | None = None
    #: the device's own subStatusCode when a write was rejected (verbatim, §6).
    device_sub_status: str | None = None
    #: the normalized record we intend (bundle-equivalent bytes, §9).
    intended_record: Mapping[str, Any] | None = None
    #: the full pre-write record from the snapshot (§5a: undo needs the prior object,
    #: not a hash — E1-05's restore-before-delete reads exactly this).
    pre_write_record: Mapping[str, Any] | None = None


@dataclass(slots=True)
class WriteJournal:
    """Append-only JSONL journal with fsync-before-request (§5a).

    Every state transition is its OWN line (append-only: no rewrite, no truncate), so
    ``_replay`` folds a person's lines into their latest state. A torn last line — the
    crash-between-write-and-fsync shape — is reported as a truncation rather than
    guessed at, because that difference decides whether undo may touch anything.

    The file is 0600; writing one INSIDE the repo is refused (same hygiene rule as
    bundles, §2 — a journal is a PII file).
    """

    path: Path
    phase: str
    entries: tuple[JournalEntry, ...] = ()
    #: lines that could not be read (a crash mid-append): reported, never silently
    #: dropped, because "unknown" must not quietly become "never planned".
    truncated: tuple[str, ...] = ()

    # -- opening ------------------------------------------------------------------

    @classmethod
    def open(cls, path: str | os.PathLike[str], *, phase: str) -> WriteJournal:
        """Create or resume the journal at ``path`` (append mode; never truncates)."""
        target = Path(path)
        _refuse_repo_path(target)
        target.parent.mkdir(parents=True, exist_ok=True)
        if target.exists():
            replayed = _replay(target, phase=phase)
            return cls(
                path=target,
                phase=phase,
                entries=replayed.entries,
                truncated=replayed.truncated,
            )
        # Create empty with the final mode BEFORE writing a byte: the first person's
        # name must never be readable by another user in a create-then-chmod window.
        handle = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        os.close(handle)
        return cls(path=target, phase=phase)

    # -- appending -----------------------------------------------------------------

    def planned(
        self,
        *,
        employee_no: str,
        classification: str,
        pre_write_record: Mapping[str, Any] | None,
        intended_record: Mapping[str, Any],
        op: str = "user_setup",
    ) -> JournalEntry:
        """Append ``planned`` and fsync it — the caller may send the request only after.

        §5a is explicit that the append happens BEFORE the request: a write we cannot
        account for after a crash is a write nobody can undo.
        """
        intended = _guard_record(intended_record, what="intended record")
        pre = (
            None
            if pre_write_record is None
            else _guard_record(pre_write_record, what="pre-write record")
        )
        return self._append(
            JournalEntry(
                seq=self._next_seq(),
                state=JournalState.PLANNED,
                phase=self.phase,
                op=op,
                employee_no=employee_no,
                employee_hash=person_hash(employee_no),
                classification=classification,
                pre_write_hash=None if pre is None else content_hash(pre),
                intended_hash=content_hash(intended),
                intended_record=intended,
                pre_write_record=pre,
            )
        )

    def applied(self, entry: JournalEntry) -> JournalEntry:
        """Append ``applied`` — the device accepted the request (statusCode 1)."""
        return self._append(_transition(entry, JournalState.APPLIED))

    def rejected(self, entry: JournalEntry, *, sub_status: str | None) -> JournalEntry:
        """Append ``rejected`` with the device's own word (unknown state = human, §5a)."""
        return self._append(_transition(entry, JournalState.REJECTED, device_sub_status=sub_status))

    def confirmed(self, entry: JournalEntry, *, post_write_hash: str) -> JournalEntry:
        """Append ``confirmed`` — the §6 read-back hash matches the intended hash."""
        return self._append(
            _transition(entry, JournalState.CONFIRMED, post_write_hash=post_write_hash)
        )

    # -- reading -------------------------------------------------------------------

    def by_employee(self, employee_no: str) -> JournalEntry | None:
        for entry in reversed(self.entries):
            if entry.employee_no == employee_no:
                return entry
        return None

    def latest(self, *, state: JournalState | None = None) -> tuple[JournalEntry, ...]:
        """One entry per person (their newest), optionally filtered by state."""
        out: dict[str, JournalEntry] = {}
        for entry in self.entries:
            out[entry.employee_no] = entry
        if state is not None:
            return tuple(e for e in out.values() if e.state is state)
        return tuple(out.values())

    # -- internals ------------------------------------------------------------------

    def _next_seq(self) -> int:
        return max((e.seq for e in self.entries), default=0) + 1

    def _append(self, entry: JournalEntry) -> JournalEntry:
        # Every line that reaches the file passes the secret check — not just the ones
        # that came in through planned(). Transitions carry planned()'s normalized
        # records, so this costs nothing there; it closes the direct-append path.
        for what, record in (
            ("intended record", entry.intended_record),
            ("pre-write record", entry.pre_write_record),
        ):
            if record is None:
                continue
            leaked = set(record) & _SECRET_KEYS
            if leaked:
                raise JournalError(
                    f"refusing to journal {what}: it still carries {sorted(leaked)} "
                    "after normalization — a PIN never enters a journal file (§2, R3)"
                )
        line = json.dumps(_entry_payload(entry), sort_keys=True, separators=(",", ":"))
        try:
            fd = os.open(self.path, os.O_WRONLY | os.O_APPEND, 0o600)
            try:
                os.write(fd, (line + "\n").encode("utf-8"))
                os.fsync(fd)  # §5a: durability BEFORE the request, not after
            finally:
                os.close(fd)
        except OSError as exc:
            raise JournalError(
                f"journal append to {self.path} failed ({exc}); the phase must not "
                "write against an unlogged intent (§5a)"
            ) from exc
        self.entries = (*self.entries, entry)
        return entry


def _transition(entry: JournalEntry, state: JournalState, **changes: Any) -> JournalEntry:
    return replace(entry, state=state, **changes)


def _entry_payload(entry: JournalEntry) -> dict[str, Any]:
    return {
        "schema": JOURNAL_SCHEMA,
        "seq": entry.seq,
        "state": str(entry.state),
        "phase": entry.phase,
        "op": entry.op,
        "employeeNo": entry.employee_no,
        "employeeHash": entry.employee_hash,
        "classification": entry.classification,
        "preWriteHash": entry.pre_write_hash,
        "intendedHash": entry.intended_hash,
        "postWriteHash": entry.post_write_hash,
        "deviceSubStatus": entry.device_sub_status,
        "intendedRecord": dict(entry.intended_record) if entry.intended_record else None,
        "preWriteRecord": dict(entry.pre_write_record) if entry.pre_write_record else None,
    }


def _replay(path: Path, *, phase: str) -> WriteJournal:
    """Fold the JSONL back into one entry per person, newest line winning."""
    latest: dict[str, JournalEntry] = {}
    truncated: list[str] = []
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise JournalError(f"journal {path} exists but cannot be read: {exc}") from exc
    for line_no, line in enumerate(text.splitlines(), start=1):
        if not line.strip():
            continue
        try:
            raw = json.loads(line)
        except json.JSONDecodeError:
            # A torn trailing line is the crash-in-the-middle shape. Reported, never
            # guessed: the caller must decide whether the write happened.
            truncated.append(f"line {line_no} (unparseable)")
            continue
        if not isinstance(raw, dict):
            truncated.append(f"line {line_no} (not an object)")
            continue
        schema = raw.get("schema")
        if schema != JOURNAL_SCHEMA:
            raise JournalError(
                f"journal {path} line {line_no} has schema {schema!r}, expected "
                f"{JOURNAL_SCHEMA!r}; a journal this module does not recognise is "
                "refused, not half-read (§0.7 fail closed)"
            )
        entry = _entry_from_payload(raw, line_no=line_no, path=path)
        latest[entry.employee_no] = entry
    return WriteJournal(
        path=path, phase=phase, entries=tuple(latest.values()), truncated=tuple(truncated)
    )


def _entry_from_payload(raw: Mapping[str, Any], *, line_no: int, path: Path) -> JournalEntry:
    try:
        state = JournalState(str(raw.get("state")))
    except ValueError as exc:
        raise JournalError(
            f"journal {path} line {line_no} carries unknown state {raw.get('state')!r}"
        ) from exc
    return JournalEntry(
        seq=int(raw.get("seq") or 0),
        state=state,
        phase=str(raw.get("phase") or ""),
        op=str(raw.get("op") or ""),
        employee_no=str(raw.get("employeeNo") or ""),
        employee_hash=str(raw.get("employeeHash") or ""),
        classification=str(raw.get("classification") or ""),
        pre_write_hash=_opt_str(raw.get("preWriteHash")),
        intended_hash=_opt_str(raw.get("intendedHash")),
        post_write_hash=_opt_str(raw.get("postWriteHash")),
        device_sub_status=_opt_str(raw.get("deviceSubStatus")),
        intended_record=_opt_map(raw.get("intendedRecord")),
        pre_write_record=_opt_map(raw.get("preWriteRecord")),
    )


def _opt_str(value: Any) -> str | None:
    return value if isinstance(value, str) and value else None


def _opt_map(value: Any) -> dict[str, Any] | None:
    return dict(value) if isinstance(value, Mapping) else None


def _guard_record(record: Mapping[str, Any], *, what: str) -> dict[str, Any]:
    """Normalize on the way in, then REFUSE if any secret key survived (§2/R3, §9).

    ``normalize_record`` strips ``password`` unconditionally; this guard is the second
    lock — a future edit that dropped ``password`` from the volatile list would break
    the bundle's own contract too, but a journal must never be where we learn that.
    """
    normalized = normalize_record(record)
    leaked = set(normalized) & _SECRET_KEYS
    if leaked:
        raise JournalError(
            f"refusing to journal {what}: it still carries {sorted(leaked)} after "
            "normalization — a PIN never enters a journal file (§2, R3)"
        )
    return normalized


def _refuse_repo_path(path: Path) -> None:
    """A journal is a PII file: writing one into a public repo is refused (§2)."""
    resolved = Path(path).resolve()
    root = repo_root(start=resolved.parent if resolved.parent.exists() else None)
    if root is None:
        return
    try:
        resolved.relative_to(root)
    except ValueError:
        return
    raise JournalError(
        f"refusing to write a journal inside the repository ({resolved} under {root}): "
        "journals hold normalized person records, so they live outside the repo at "
        "0600 like bundles do (design §2)"
    )


def person_hash(employee_no: str, *, prefix_len: int = 12) -> str:
    """The printable person identity: sha256 prefix of the opaque employeeNo (§4)."""
    return hashlib.sha256(employee_no.encode("utf-8")).hexdigest()[:prefix_len]


# --- §5 step 3: the write-body projection (the frozen allow-list) -------------------------


def frozen_write_allow_list() -> frozenset[str]:
    """The writable UserInfo keys, frozen from the capture (R2's answer, §5 step 3)."""
    return CAPTURED_USER_WRITE_KEYS


def build_user_setup_body(
    record: Mapping[str, Any],
    *,
    probe: CapabilityMatrix | None = None,
    allow_custom_templates: bool = False,
) -> dict[str, Any]:
    """The ``{"UserInfo": {…}}`` body for one add — EXACTLY the captured shape.

    Fail-closed in four places, each before any request could leave the process:

    1. **Key set.** The body carries exactly the capture's keys. A *missing* key is as
       unproven as an extra one (the fixtures show a wrapped list 400'ing ``lack
       employeeNo`` and a scalar ``enableCardReader`` 400'ing ``badJsonContent`` — this
       family is strict about shape), so an incomplete source record is refused here.
       Keys the record carries that are OUTSIDE the allow-list are not errors — they
       are simply never echoed (R2: device-generated/read-only keys, the ``numOf*``
       counters, ``belongGroup``, ``PersonInfoExtends`` and the PIN must not ride
       along). §6's verify is what catches a bundle record that expected one of them.
    2. **``mode``** — only the captured ``"add"``; a delete/modify mode is refused
       outright (§5 step 8, §5b).
    3. **Vocabulary** (when a probe is given): ``userType`` and ``Valid.timeType`` must
       sit inside the caps document's ``@opt``. Caps are device CLAIMS (§3) and this
       firmware's caps under-claim *availability*, but the ``@opt`` vocabularies are
       exactly what the captures' 400s police, so a value outside them is refused here
       rather than rejected mid-batch.
    4. **Door/security fields** (§1a): a ``planTemplateNo`` other than the carried
       default is refused unless ``allow_custom_templates`` AND the number appears in
       the probe's own RightPlan evidence set. E1-02's diff already routes these to
       conflict/report-only; re-checking at the last frame is deliberate — the writer
       never trusts an upstream filter.
    """
    missing = sorted(k for k in REQUIRED_USER_WRITE_KEYS if k not in record or record[k] is None)
    if missing:
        raise WriteShapeError(
            f"cannot build a captured UserInfo/SetUp body: the record lacks {missing}; "
            "the captured key set is "
            + str(sorted(CAPTURED_USER_WRITE_KEYS))
            + " (users_setup_add_request.json) — a smaller body is an unrecorded shape "
            "and would be the R2 partial-merge risk (§9 capture-before-fake)"
        )
    if record.get("mode") not in (None, "add"):
        raise WriteShapeError(
            f"mode {record.get('mode')!r} is not captured; the only mode bench A proved "
            'for UserInfo/SetUp is "add" (OBSERVED.md §5.0 capture); v1 never deletes '
            "(§5 step 8) and no modify mode is recorded"
        )

    body = {key: record[key] for key in CAPTURED_USER_WRITE_KEYS}
    _check_vocabulary(body, probe=probe)
    _check_template_refs(body, probe=probe, allow_custom=allow_custom_templates)
    return {"UserInfo": {**body, "mode": "add"}}


def _check_vocabulary(body: dict[str, Any], *, probe: CapabilityMatrix | None) -> None:
    """userType / Valid.timeType against the probe's caps ``@opt`` vocabulary."""
    if probe is None:
        return
    caps = probe.caps_raw.get("user_info_capabilities")
    section = caps.get("UserInfoCap") if isinstance(caps, Mapping) else None
    if not isinstance(section, Mapping):
        return
    _check_opt(body.get("userType"), section.get("userType"), "userType", probe)
    valid = body.get("Valid")
    if isinstance(valid, Mapping) and "timeType" in valid:
        valid_cap = section.get("Valid")
        time_cap = valid_cap.get("timeType") if isinstance(valid_cap, Mapping) else None
        _check_opt(valid["timeType"], time_cap, "Valid.timeType", probe)


def _check_opt(value: Any, cap: Any, label: str, probe: CapabilityMatrix) -> None:
    if not isinstance(cap, Mapping):
        return
    opts = cap.get("@opt")
    if not isinstance(opts, str) or not opts.strip():
        return
    allowed = {o.strip() for o in opts.split(",") if o.strip()}
    if allowed and value not in allowed:
        raise WriteShapeError(
            f"{label}={value!r} is outside the vocabulary THIS device claimed for it "
            f"({sorted(allowed)}); caps are the vocabulary source (OBSERVED.md) and the "
            f"probe is for site {probe.site or '?'}/{probe.host or '?'} — refusing to "
            "write a value the target says it does not accept (§3)"
        )


def _check_template_refs(
    body: dict[str, Any], *, probe: CapabilityMatrix | None, allow_custom: bool
) -> None:
    plans = body.get("RightPlan")
    if not isinstance(plans, list):
        return
    evidence = set(probe.template_nos) if probe is not None else set()
    for plan in plans:
        if not isinstance(plan, Mapping):
            raise WriteShapeError(
                f"RightPlan entry {plan!r} is not an object; the capture carries "
                '{"doorNo":1,"planTemplateNo":"1"} — refusing an unrecorded shape'
            )
        number = str(plan.get("planTemplateNo"))
        if number == DEFAULT_CARRIED_TEMPLATE_NO:
            continue
        if not allow_custom:
            raise WriteShapeError(
                f"planTemplateNo {number!r} is a custom device-local preset: carried "
                "only with --carry-templates (design §1a) — refusing to guess content"
            )
        if number not in evidence:
            raise WriteShapeError(
                f"planTemplateNo {number!r} is not in the target's own RightPlan "
                f"evidence set {sorted(evidence)} (design §3: the union of observed "
                "templateNos is the ONLY existence proof on this family)"
            )


# --- §5 steps 3-4: what the users phase writes ---------------------------------------------


@dataclass(frozen=True, slots=True)
class UserWrite:
    """One add this phase may send, with the bundle record it came from."""

    employee_no: str
    employee_hash: str
    record: Mapping[str, Any]
    classification: DiffClass = DiffClass.ADD


@dataclass(frozen=True, slots=True)
class UsersPhaseResult:
    """What a users phase did — the artifact §5 step 4 demands on an abort."""

    planned: tuple[str, ...] = ()  # employee hashes, in send order
    applied: tuple[str, ...] = ()  # device answered statusCode 1
    confirmed: tuple[str, ...] = ()  # §6 read-back hash matched
    rejected: tuple[tuple[str, RejectKind, str | None], ...] = ()  # hash, kind, subStatus
    skipped: tuple[tuple[str, str], ...] = ()  # hash, reason (report-only classes)
    batches: int = 0
    batch_size: int = DEFAULT_BATCH_SIZE
    writes_sent: int = 0
    rebootstraps: int = 0
    aborted: bool = False

    @property
    def landed(self) -> tuple[str, ...]:
        """Persons whose write the device ACCEPTED (verify decides whether it stuck)."""
        return self.applied

    @property
    def clean(self) -> bool:
        return not self.aborted and not self.rejected

    def summary(self) -> dict[str, Any]:
        """PII-free run summary (§4: hashes and counts only) — the report's payload."""
        return {
            "planned": len(self.planned),
            "applied": len(self.applied),
            "confirmed": len(self.confirmed),
            "rejected": [
                {"employee": h, "kind": str(kind), "subStatusCode": sub}
                for h, kind, sub in self.rejected
            ],
            "skipped": [{"employee": h, "reason": r} for h, r in self.skipped],
            "batches": self.batches,
            "batchSize": self.batch_size,
            "writesSent": self.writes_sent,
            "rebootstraps": self.rebootstraps,
            "aborted": self.aborted,
        }


def plan_user_writes(
    plan: Plan,
    bundle: BundleData,
    *,
    probe: CapabilityMatrix | None = None,
    allow_custom_templates: bool = False,
) -> tuple[tuple[UserWrite, ...], tuple[tuple[str, str], ...]]:
    """Split a diff plan into (writable adds, report-only skips) for the users phase.

    ``update``-class persons are SKIPPED with reason ``update_shape_uncaptured`` — the
    capture proved one ``mode:"add"`` on a person that did not exist, and what SetUp
    does to an existing employeeNo is exactly the unrecorded per-field semantics R2
    warns about (§0.3, §9). ``same`` writes nothing; ``conflict`` stays E1-02's
    decision and is refused here too rather than trusted. A record whose shape we cannot
    build is skipped per-person (reason names the refusal) instead of aborting the
    phase, so one malformed person never blocks the report the operator needs to fix it.
    """
    by_no = {str(r["employeeNo"]): r for r in bundle.people if isinstance(r.get("employeeNo"), str)}
    writes: list[UserWrite] = []
    skipped: list[tuple[str, str]] = []
    for item in plan.items:
        if item.classification is DiffClass.SAME:
            continue
        if item.classification is DiffClass.CONFLICT:
            skipped.append((item.employee_hash, "conflict_report_only"))
            continue
        if item.classification is not DiffClass.ADD:
            skipped.append((item.employee_hash, "update_shape_uncaptured"))
            continue
        record = by_no.get(item.employee_no)
        if record is None:
            skipped.append((item.employee_hash, "missing_from_bundle"))
            continue
        try:
            build_user_setup_body(
                record, probe=probe, allow_custom_templates=allow_custom_templates
            )
        except WriteShapeError as exc:
            skipped.append((item.employee_hash, f"shape_refused:{exc}"))
            continue
        writes.append(
            UserWrite(
                employee_no=item.employee_no,
                employee_hash=item.employee_hash,
                record=record,
            )
        )
    return tuple(writes), tuple(skipped)


def derive_user_batch_size(probe: CapabilityMatrix | None) -> int:
    """Batch size = the device's own write ``@max`` where discoverable, else 10 (§5.3).

    Nothing this card may read names a write-batch maximum: ``UserInfoCap.maxRecordNum``
    is the search page/batch cap (§1 says so explicitly — it is not capacity) and
    ``EmployeeNoList.@maxSize`` bounds the SEARCH filter list, not a write body. Reading
    either as a batch cap would be the §1 "capacity is not exposed" trap in a new
    costume, so the fallback ships and the absence stays a recorded fact.
    """
    return DEFAULT_BATCH_SIZE


# --- §5.3 budget: one transport per phase, re-bootstrap before exhaustion -----------------


class WriteTransport(Protocol):
    """The injected device seam (module docstring: this module cannot reach a socket).

    Implementations raise :class:`WriteRejectedError` for a non-OK envelope; a transport-level
    failure raises its own client vocabulary and aborts the phase.

    The users phase needs one verb; the phases that follow (§5 step 2's ordering: cards,
    fingerprints, faces) need their own captured verbs on their own captured paths.
    Rather than fork the budget machinery once per phase — the fork is exactly where a
    second, drifting 80-call counter gets invented — :class:`BudgetedWriteTransport`
    carries ANY named seam method through :meth:`BudgetedWriteTransport.call`, and a
    transport implements the verbs its phase owns (``put_setup`` here;
    ``post_download``/``get_progress`` in E1-06b). One client, one counter, one
    re-bootstrap rule for the whole apply (§5.3).
    """

    def put_setup(self, path: str, body: Mapping[str, Any]) -> dict[str, Any]:
        """PUT one SetUp body and return the parsed ack (raise on a rejection)."""
        ...  # pragma: no cover - protocol

    def close(self) -> None:
        """Release the underlying client (the re-bootstrapped budget starts fresh)."""
        ...  # pragma: no cover - protocol


class BudgetedWriteTransport:
    """Counts authed calls on one client and re-bootstraps it at 80 (§5.3, §0.5).

    The counter is this module's own ledger of the calls IT issued; a test pins it
    against the fake's OWN nonce ledger so the two cannot disagree about what a request
    cost. Re-bootstrap is the P1 recovery arm (fresh digest state = a fresh nonce
    budget) and is the ONLY reason a client is replaced mid-phase: no refused write is
    ever re-sent (§0.6), so a re-send through a new client is structurally impossible.
    """

    def __init__(
        self,
        factory: Callable[[], WriteTransport],
        *,
        limit: int = REBOOTSTRAP_AT_AUTHED_CALLS,
    ) -> None:
        if limit < 1:
            raise ValueError(f"budget limit must be >= 1, got {limit}")
        self._factory = factory
        self._limit = limit
        self._current: WriteTransport | None = None
        self._closed = False
        self._calls = 0
        self.total_calls = 0
        self.rebootstraps = 0

    # -- the seam the phase uses ----------------------------------------------------

    def put_setup(self, path: str, body: Mapping[str, Any]) -> dict[str, Any]:
        return self.call("put_setup", path, body)

    def call(self, verb: str, *args: Any) -> dict[str, Any]:
        """Invoke ONE seam method on the phase's client, counted against the budget.

        Every request a phase issues — write verb or verify read — goes through here, so
        "one long-lived client per phase, re-bootstrap before exhaustion" (§0.5/§5.3) is
        a single implementation with a single counter. ``verb`` is a method NAME on the
        injected transport, never a path or a string the device sees; a name the
        transport does not implement is a programming error and raises
        :class:`TypeError` rather than silently doing nothing.
        """
        if self._closed:
            raise TransportClosedError("this phase's transport was closed; nothing was sent")
        if self._current is None or self._calls >= self._limit:
            self._rotate()
        if self._current is None:  # _rotate always sets one; belt against refactors
            raise TransportClosedError("transport rotation produced no client")
        method = getattr(self._current, verb, None)
        if not callable(method):
            raise TypeError(
                f"the injected transport implements no {verb!r} seam method; the "
                f"phase's budget cannot be spent on a verb that does not exist (§5.3)"
            )
        self._calls += 1
        self.total_calls += 1
        result = method(*args)
        return dict(result)

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        if self._current is not None:
            self._current.close()
            self._current = None

    # -- internals -------------------------------------------------------------------

    def _rotate(self) -> None:
        if self._current is not None:
            self._current.close()
            self.rebootstraps += 1
        self._current = self._factory()
        self._calls = 0


# --- §5 steps 3-4: the users phase --------------------------------------------------------


@dataclass(slots=True)
class _PhaseTally:
    """Mutable accumulator for one phase (the public result stays frozen)."""

    applied: list[str] = field(default_factory=list)
    rejected: list[tuple[str, RejectKind, str | None]] = field(default_factory=list)
    batches: int = 0
    writes_sent: int = 0

    def result(
        self,
        *,
        planned: Sequence[str],
        skipped: Sequence[tuple[str, str]],
        batch_size: int,
        rebootstraps: int,
        aborted: bool,
    ) -> UsersPhaseResult:
        return UsersPhaseResult(
            planned=tuple(planned),
            applied=tuple(self.applied),
            rejected=tuple(self.rejected),
            skipped=tuple(skipped),
            batches=self.batches,
            batch_size=batch_size,
            writes_sent=self.writes_sent,
            rebootstraps=rebootstraps,
            aborted=aborted,
        )


def run_users_phase(
    transport: BudgetedWriteTransport,
    journal: WriteJournal,
    writes: Sequence[UserWrite],
    *,
    probe: CapabilityMatrix | None = None,
    batch_size: int | None = None,
    sleep: Callable[[float], None] = time.sleep,
    batch_delay: float = 1.0,
    allow_custom_templates: bool = False,
    skipped: Sequence[tuple[str, str]] = (),
) -> UsersPhaseResult:
    """Send the allowed adds, journal-first, batching with sleeps (§5 steps 3-4).

    Order per person is fixed and is what the tests pin: journal ``planned`` + fsync →
    request → journal ``applied``. Confirmation is NOT this function's job — §6's walker
    does that from a fresh read, because the status code proves nothing.

    The first rejection ends the phase: the result names which persons landed and which
    one was refused, and the caller decides (never a retry, never a silent partial
    batch, never a "fix" by re-writing).
    """
    size = _effective_batch_size(batch_size)
    planned = tuple(person_hash(w.employee_no) for w in writes)
    tally = _PhaseTally()
    if not writes:
        return tally.result(
            planned=planned,
            skipped=skipped,
            batch_size=size,
            rebootstraps=transport.rebootstraps,
            aborted=False,
        )

    for index, write in enumerate(writes):
        if index % size == 0:
            if index:
                sleep(batch_delay)  # between batches only — never before the first
            tally.batches += 1
        entry = journal.planned(
            employee_no=write.employee_no,
            classification=str(write.classification),
            pre_write_record=None,  # a fresh person: the snapshot has no prior record
            intended_record=write.record,
        )
        body = build_user_setup_body(
            write.record, probe=probe, allow_custom_templates=allow_custom_templates
        )
        tally.writes_sent += 1
        try:
            ack = transport.put_setup(USER_SETUP_PATH, body)
            # INSIDE the try: a non-OK ack is the same event as a raising transport —
            # it journals `rejected`, records the rejection, and aborts via
            # WriteAbortedError (never a raw WriteRejectedError past the journal).
            _require_ok_ack(ack, entry.employee_hash)
        except WriteRejectedError as exc:
            journal.rejected(entry, sub_status=exc.sub_status)
            kind = classify_rejection(exc.sub_status)
            tally.rejected.append((entry.employee_hash, kind, exc.sub_status))
            result = tally.result(
                planned=planned,
                skipped=skipped,
                batch_size=size,
                rebootstraps=transport.rebootstraps,
                aborted=True,
            )
            raise WriteAbortedError(
                f"users phase aborted at {entry.employee_hash} after "
                f"{len(tally.applied)} of {len(writes)} accepted: device answered "
                f"{exc.sub_status or exc} — §5 step 4: the phase stops here and "
                "applied[] above lists the records that landed; nothing was retried "
                "(§0.6)",
                result,
            ) from exc
        journal.applied(entry)
        tally.applied.append(entry.employee_hash)

    return tally.result(
        planned=planned,
        skipped=skipped,
        batch_size=size,
        rebootstraps=transport.rebootstraps,
        aborted=False,
    )


def _effective_batch_size(batch_size: int | None) -> int:
    if batch_size is None:
        return DEFAULT_BATCH_SIZE
    if batch_size < 1:
        raise ValueError(f"batch_size must be >= 1, got {batch_size}")
    return min(batch_size, DEFAULT_BATCH_SIZE)


def _require_ok_ack(ack: Mapping[str, Any], employee_hash_value: str) -> None:
    code = ack.get("statusCode")
    if code == USER_SETUP_RESPONSE_OK:
        return
    raise WriteRejectedError(
        f"UserInfo/SetUp for {employee_hash_value} answered statusCode={code!r} "
        f"(subStatusCode={ack.get('subStatusCode')!r}); only statusCode 1 is an ack "
        "this module treats as accepted (§6: the status code alone proves nothing)",
        sub_status=_opt_str(ack.get("subStatusCode")),
        envelope=ack,
    )


def classify_rejection(sub_status: str | None) -> RejectKind:
    """Map a device subStatusCode onto the captured kinds — no invented vocabulary.

    Only the captured words are mapped; the device's own string rides on separately
    (`WriteRejectedError.sub_status`) so an unmapped reason is reported verbatim, never
    coerced into a category we invented.
    """
    word = (sub_status or "").strip()
    if word in {"badJsonContent", "MessageParametersLack", "badParameters"}:
        return RejectKind.SHAPE
    if word == "methodNotAllowed":
        return RejectKind.VERB
    if word == "notSupport":
        return RejectKind.ABSENT
    return RejectKind.OTHER


# --- §6: the read-back verify walker -------------------------------------------------------


class PersonVerdict(StrEnum):
    """Per-person verify verdict (§6). ``MISMATCH`` is terminal for the run."""

    OK = "ok"
    MISMATCH = "mismatch"
    MISSING = "missing"


@dataclass(frozen=True, slots=True)
class VerifyItem:
    """One person's verify result. Names and codes only — no field values (§4)."""

    employee_no: str
    employee_hash: str
    verdict: PersonVerdict
    #: content hash of the live target record, when the read found one.
    target_hash: str | None = None
    #: content hash we expected (the journal's intended hash).
    expected_hash: str | None = None
    #: field NAMES the target record has that the intended record lacks — the
    #: fail-closed unknown-field rule (§6): a device that silently mangled data is
    #: exactly what verify is for.
    unknown_fields: tuple[str, ...] = ()
    #: field NAMES the intended record has that the target record lacks.
    missing_fields: tuple[str, ...] = ()
    note: str | None = None


@dataclass(frozen=True, slots=True)
class UsersVerifyReport:
    """The §6 walker's output: verdicts plus the coverage evidence."""

    items: tuple[VerifyItem, ...]
    #: True only when the filtered UserInfo/Search answered EXACTLY the requested set.
    coverage_proven: bool
    #: how the walker got its answer ("filtered" / "full-paging (…)") — the report says
    #: which, because a fallback that is invisible is the silently-ignored lesson again.
    method: str
    #: requested persons the filtered read failed to return (the filter was honored but
    #: incomplete, or the person is genuinely gone).
    uncovered: tuple[str, ...] = ()
    #: persons the filtered read returned that were NOT requested — the signature of an
    #: ignored filter (OBSERVED's ``AcsEventCond.employeeNo`` class).
    unexpected: tuple[str, ...] = ()

    def verdict_of(self, employee_no: str) -> PersonVerdict | None:
        for item in self.items:
            if item.employee_no == employee_no:
                return item.verdict
        return None

    @property
    def ok(self) -> bool:
        return all(i.verdict is PersonVerdict.OK for i in self.items)

    @property
    def mismatched(self) -> tuple[VerifyItem, ...]:
        return tuple(i for i in self.items if i.verdict is PersonVerdict.MISMATCH)

    @property
    def missing(self) -> tuple[VerifyItem, ...]:
        return tuple(i for i in self.items if i.verdict is PersonVerdict.MISSING)

    def summary(self) -> dict[str, Any]:
        return {
            "method": self.method,
            "coverageProven": self.coverage_proven,
            "uncovered": list(self.uncovered),
            "unexpected": list(self.unexpected),
            "counts": {
                "ok": sum(1 for i in self.items if i.verdict is PersonVerdict.OK),
                "mismatch": len(self.mismatched),
                "missing": len(self.missing),
            },
        }


#: The search seam: the same shape ``migrate_export`` hands the paging engine — a body
#: in, a parsed envelope out. Production passes a reader over the READ-ONLY
#: ``user_info_search`` endpoint (verify is a read; §6 never re-writes).
SearchReader = Callable[[Mapping[str, Any]], dict[str, Any]]


@dataclass(frozen=True, slots=True)
class _Coverage:
    """What one coverage attempt produced (internal to the walker)."""

    rows: tuple[Mapping[str, Any], ...]
    status: str  # "ok" | "error"
    uncovered: tuple[str, ...] = ()
    unexpected: tuple[str, ...] = ()


def verify_users(
    reader: SearchReader,
    expected: Sequence[UserWrite],
    *,
    page_size: int = 30,
    max_pages: int = 500,
    sleep: Callable[[float], None] = _noop_sleep,
    inter_page_delay: float = 0.0,
    clock: Callable[[], float] = _monotonic,
    filter_max: int | None = None,
) -> UsersVerifyReport:
    """Re-read the touched persons and compare content hashes (§6).

    COVERAGE PROOF first, then the hash compare. The filtered ``EmployeeNoList`` read is
    PROVEN honored on bench A (§1: ``[{"employeeNo":"1"}]`` -> 1/4, ``"99"`` -> 0), and
    it still gets audited here, because OBSERVED.md's other lesson is that some Hikvision
    filters — ``AcsEventCond.employeeNo`` — are silently IGNORED while the answer looks
    perfectly fine. Coverage therefore fails in BOTH directions:

      * a requested person absent from the answer, or
      * an unrequested person present in the answer (the filter was ignored and the
        device answered the whole roster),

    and either way the walker falls back to full paging plus CLIENT-SIDE exact match.
    The fallback is not an optimisation: it is the only way to tell "this person is
    missing" apart from "the device did not filter and we were reading the wrong rows".
    """
    wanted = [w.employee_no for w in expected]
    wanted_set = set(wanted)
    expected_by_no = {w.employee_no: w for w in expected}

    attempt = _filtered_read(
        reader,
        wanted,
        page_size=page_size,
        max_pages=max_pages,
        sleep=sleep,
        inter_page_delay=inter_page_delay,
        clock=clock,
        filter_max=filter_max,
    )
    method = "filtered"
    coverage_proven = attempt.status == "ok" and not attempt.uncovered and not attempt.unexpected
    rows = attempt.rows
    if attempt.status == "error":
        # §0.7: a failed filtered read is not "nobody matched" — try the honest route.
        rows, status = _full_read(
            reader,
            page_size=page_size,
            max_pages=max_pages,
            sleep=sleep,
            inter_page_delay=inter_page_delay,
            clock=clock,
        )
        if status == "error":
            raise VerifyAbortedError(
                "verify read failed on BOTH the filtered and the full-paging route; a "
                "failed read is never verdicted as 'missing' (§0.7) — nothing in this "
                "report is trustworthy, fix the read and re-verify"
            )
        method = "full-paging (filtered read failed)"
        coverage_proven = False
    elif not coverage_proven:
        rows, status = _full_read(
            reader,
            page_size=page_size,
            max_pages=max_pages,
            sleep=sleep,
            inter_page_delay=inter_page_delay,
            clock=clock,
        )
        if status == "error":
            raise VerifyAbortedError(
                "verify fallback (full paging) failed after the filtered read could not "
                f"prove coverage ({len(attempt.uncovered)} uncovered, "
                f"{len(attempt.unexpected)} unexpected); refusing to verdict from a "
                "partial read (§0.7)"
            )
        method = "full-paging (filter coverage failed)"
        coverage_proven = False

    found: dict[str, Mapping[str, Any]] = {}
    for row in rows:
        no = row.get("employeeNo")
        if isinstance(no, str):
            found[no] = row

    items: list[VerifyItem] = []
    for employee_no in wanted:
        write = expected_by_no[employee_no]
        expected_hash = content_hash(write.record)
        record = found.get(employee_no)
        if record is None:
            items.append(
                VerifyItem(
                    employee_no=employee_no,
                    employee_hash=person_hash(employee_no),
                    verdict=PersonVerdict.MISSING,
                    expected_hash=expected_hash,
                    note=f"not present in the {method} read (which said OK)",
                )
            )
            continue
        items.append(
            _compare(
                employee_no=employee_no,
                live=normalize_record(record),
                intended=normalize_record(write.record),
                expected_hash=expected_hash,
            )
        )
    _ = wanted_set  # coverage bookkeeping lives in the attempt; kept for readability
    return UsersVerifyReport(
        items=tuple(items),
        coverage_proven=coverage_proven,
        method=method,
        uncovered=attempt.uncovered,
        unexpected=attempt.unexpected,
    )


def _compare(
    *,
    employee_no: str,
    live: Mapping[str, Any],
    intended: Mapping[str, Any],
    expected_hash: str,
) -> VerifyItem:
    """The §6 hash compare plus the fail-closed unknown-field rule (field NAMES only)."""
    live_hash = content_hash(live)
    # Volatile counters are already gone (normalize_record), and they are excluded
    # again so a future strip-list change cannot turn a counter into a mismatch.
    unknown = sorted(set(live) - set(intended) - VOLATILE_FIELDS)
    lacking = sorted(set(intended) - set(live) - VOLATILE_FIELDS)
    base: dict[str, Any] = {
        "employee_no": employee_no,
        "employee_hash": person_hash(employee_no),
        "target_hash": live_hash,
        "expected_hash": expected_hash,
    }
    if unknown or lacking:
        return VerifyItem(
            **base,
            verdict=PersonVerdict.MISMATCH,
            unknown_fields=tuple(unknown),
            missing_fields=tuple(lacking),
            note="field SETS differ (names only, per §4) — fail closed: a device that "
            "silently rejected or mangled data is exactly what verify is for (§6)",
        )
    if live_hash != expected_hash:
        return VerifyItem(
            **base,
            verdict=PersonVerdict.MISMATCH,
            note="content hash differs on identical field sets (§6)",
        )
    return VerifyItem(**base, verdict=PersonVerdict.OK)


def _filtered_read(
    reader: SearchReader,
    wanted: Sequence[str],
    *,
    page_size: int,
    max_pages: int,
    sleep: Callable[[float], None],
    inter_page_delay: float,
    clock: Callable[[], float],
    filter_max: int | None,
) -> _Coverage:
    """The filtered attempt + the coverage audit (fails in both directions)."""
    limit = filter_max or DEFAULT_BATCH_SIZE
    if len(wanted) > limit:
        # A filter list longer than the device's documented @maxSize is an unrecorded
        # request shape — don't send it; go straight to the honest full walk.
        return _Coverage(rows=(), status="error", uncovered=tuple(wanted))
    rows, status = _paged(
        reader,
        {"EmployeeNoList": [{"employeeNo": no} for no in wanted]},
        page_size=page_size,
        max_pages=max_pages,
        sleep=sleep,
        inter_page_delay=inter_page_delay,
        clock=clock,
        search_prefix="e104f",
    )
    if status != "ok":
        return _Coverage(rows=rows, status="error", uncovered=tuple(wanted))
    seen = {r["employeeNo"] for r in rows if isinstance(r.get("employeeNo"), str)}
    return _Coverage(
        rows=rows,
        status="ok",
        uncovered=tuple(no for no in wanted if no not in seen),
        unexpected=tuple(sorted(seen - set(wanted))),
    )


def _full_read(
    reader: SearchReader,
    *,
    page_size: int,
    max_pages: int,
    sleep: Callable[[float], None],
    inter_page_delay: float,
    clock: Callable[[], float],
) -> tuple[tuple[Mapping[str, Any], ...], str]:
    rows, status = _paged(
        reader,
        {},
        page_size=page_size,
        max_pages=max_pages,
        sleep=sleep,
        inter_page_delay=inter_page_delay,
        clock=clock,
        search_prefix="e104x",
    )
    return rows, status


def _paged(
    reader: SearchReader,
    cond: Mapping[str, Any],
    *,
    page_size: int,
    max_pages: int,
    sleep: Callable[[float], None],
    inter_page_delay: float,
    clock: Callable[[], float],
    search_prefix: str,
) -> tuple[tuple[Mapping[str, Any], ...], str]:
    """Walk the WRAPPED UserInfo/Search dialect to the end of the answer set.

    The same cursor rules as ``paging.PagedSearch`` (one searchID per logical search,
    advance by ``numOfMatches``, terminate on non-MORE / zero rows), because verify must
    not disagree with export about what a complete read means. Inlined rather than
    reusing the engine so the walker can be driven by a bare reader callable and can
    report ``error`` without an exception escaping a generator (§0.7).
    """
    from gateclerk.paging import DEFAULT_SEARCH_ID_LEN, new_search_id

    # Prefix marks WHICH verify attempt this is (f = filtered, x = full-paging fallback)
    # — the fake keys its cursor cache on the id, so the two attempts must not share one.
    # The whole id stays inside the advertised cap, and `new_search_id` keeps its own
    # >=12-char collision floor (paging.MIN_SEARCH_ID_LEN).
    search_id = f"{search_prefix}{new_search_id()}"[:DEFAULT_SEARCH_ID_LEN]
    rows: list[Mapping[str, Any]] = []
    position = 0
    pages = 0
    last_request = clock()
    while True:
        if pages >= max_pages:
            return tuple(rows), "error"
        if pages:
            wait = inter_page_delay - (clock() - last_request)
            if wait > 0:
                sleep(wait)
        body = {
            "UserInfoSearchCond": {
                "searchID": search_id,
                "searchResultPosition": position,
                "maxResults": page_size,
                **cond,
            }
        }
        last_request = clock()
        try:
            answer = reader(body)
        except Exception:  # any read failure is an ERROR, never "empty" (§0.7)
            return tuple(rows), "error"
        pages += 1
        envelope = answer.get("UserInfoSearch")
        if not isinstance(envelope, Mapping):
            return tuple(rows), "error"
        batch = envelope.get("UserInfo")
        if not isinstance(batch, list):
            batch = []
        rows.extend(r for r in batch if isinstance(r, Mapping))
        returned = len(batch)
        status = str(envelope.get("responseStatusStrg") or "").strip().upper()
        num = envelope.get("numOfMatches")
        usable = isinstance(num, int) and not isinstance(num, bool) and 0 <= num <= returned
        step = num if usable else returned
        position += step
        if returned == 0 or status != "MORE":
            return tuple(rows), "ok"


# --- §5 steps 1-2 + 7: the composed users phase -------------------------------------------


@dataclass(frozen=True, slots=True)
class ApplyReport:
    """Everything a run decided and did, in PII-free form (§4/§7's ``-o json``)."""

    phase: str
    writes: UsersPhaseResult
    verify: UsersVerifyReport | None
    journal_path: str
    notes: tuple[str, ...] = ()

    def as_dict(self) -> dict[str, Any]:
        return {
            "phase": self.phase,
            "journal": self.journal_path,
            "writes": self.writes.summary(),
            "verify": None if self.verify is None else self.verify.summary(),
            "notes": list(self.notes),
        }


def check_clock_skew(
    probe: CapabilityMatrix, *, max_skew_s: float = MAX_CLOCK_SKEW_S
) -> CapabilityMatrix:
    """§5.1a: refuse to write ``timeType=local`` validity into a lying clock.

    Bench A's only timeType is ``local`` (§1), so its Valid strings are WALL digits — a
    device clock off by more than ``max_skew_s`` lands a payroll window on the wrong
    wall. We never touch device clocks (standing rule), so the only honest move is to
    refuse. A probe with NO skew evidence is refused too: "unknown" is not "within
    tolerance" (§0.7).
    """
    skew = probe.clock_skew_s
    if skew is None:
        raise ApplyAbortedError(
            "clock-skew gate refused: the probe recorded no System/time skew "
            f"({probe.clock_note or 'no note'}); validity strings on this family are "
            "wall digits, so an unverified clock is never written against (§5.1a)"
        )
    if abs(skew) > max_skew_s:
        raise ApplyAbortedError(
            f"clock-skew gate refused: target clock is {skew:+.1f}s from ours "
            f"(limit {max_skew_s:.0f}s); timeType=local validity would land on the "
            "wrong wall — the device clock is the owner's action, never ours, so this "
            "apply stops here (§5.1a)"
        )
    return probe


def apply_users_phase(
    *,
    plan: Plan,
    bundle: BundleData,
    transport_factory: Callable[[], WriteTransport],
    reader: SearchReader,
    journal_path: str | os.PathLike[str],
    probe: CapabilityMatrix,
    now: Any,
    recheck: Callable[[], Sequence[Classification]] | None = None,
    batch_size: int | None = None,
    sleep: Callable[[float], None] = _noop_sleep,
    batch_delay: float = 1.0,
    allow_custom_templates: bool = False,
    confirm: bool = True,
) -> ApplyReport:
    """Gate → journal → writes → verify → confirm, stopping at the first refusal.

    The order is §5's, not a suggestion: fresh probe (§3/§4) → clock-skew gate (§5.1a)
    → freshness re-diff (§4) → writes (§5.3) → verify (§6) → journal ``confirmed``.
    ``recheck`` is E1-02's ``plan_still_valid`` seam: a classification that moved since
    plan time aborts before a single byte is written. A verify mismatch is TERMINAL
    (§0.6) — the report is the artifact and a human decides; nothing here re-writes a
    mismatch away, and v1 never deletes (§5 step 8).
    """
    require_fresh(probe, now)  # ProbeStaleError is E1-03's contract, unchanged
    check_clock_skew(probe)

    journal = WriteJournal.open(journal_path, phase="users")
    writes, skipped = plan_user_writes(
        plan, bundle, probe=probe, allow_custom_templates=allow_custom_templates
    )

    if recheck is not None and writes:
        changed = plan_still_valid(plan, recheck())
        if changed:
            raise ApplyAbortedError(
                f"freshness contract failed before any write: {len(changed)} person(s) "
                f"changed classification since plan time ({', '.join(changed[:8])}"
                f"{'…' if len(changed) > 8 else ''}) — re-diff and re-run (§4)"
            )

    budgeted = BudgetedWriteTransport(transport_factory)
    notes: list[str] = []
    if skipped:
        notes.append(
            f"{len(skipped)} person(s) report-only in this phase: "
            + ", ".join(f"{h}={r}" for h, r in skipped[:8])
        )
    try:
        result = run_users_phase(
            budgeted,
            journal,
            writes,
            probe=probe,
            batch_size=batch_size,
            sleep=sleep,
            batch_delay=batch_delay,
            allow_custom_templates=allow_custom_templates,
            skipped=skipped,
        )
    finally:
        # The write session ends with the write phase (§5.3): verify below is a READ,
        # and holding a nearly-spent digest session open across it would spend a nonce
        # budget this phase no longer owns.
        budgeted.close()

    verify: UsersVerifyReport | None = None
    if confirm and writes:
        verify = verify_users(reader, writes, sleep=sleep)
        confirmed: list[str] = []
        for item in verify.items:
            entry = journal.by_employee(item.employee_no)
            if entry is None:
                continue
            if item.verdict is PersonVerdict.OK and item.target_hash == entry.intended_hash:
                journal.confirmed(entry, post_write_hash=str(item.target_hash))
                confirmed.append(item.employee_hash)
            elif item.verdict is PersonVerdict.MISMATCH:
                notes.append(
                    f"TERMINAL mismatch for {item.employee_hash}: "
                    + (
                        f"field names differ (unknown={list(item.unknown_fields)}, "
                        f"lacking={list(item.missing_fields)})"
                        if item.unknown_fields or item.missing_fields
                        else f"hash {item.target_hash} != intended {item.expected_hash}"
                    )
                    + " — verify is terminal (§0.6): no re-write, no delete (v1)"
                )
            else:
                notes.append(
                    f"{item.employee_hash}: accepted by the device but ABSENT on "
                    "read-back — unknown state, human decides (§5a)"
                )
        result = replace(result, confirmed=tuple(confirmed))
    budgeted.close()
    return ApplyReport(
        phase="users",
        writes=result,
        verify=verify,
        journal_path=str(journal.path),
        notes=tuple(notes),
    )
