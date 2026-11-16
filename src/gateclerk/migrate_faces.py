"""E1-06 faces phase: ``modelData`` template port + FDSearch-hash verify + face undo.

Design contract: docs/internal/ENROLLMENT-MIGRATION.md — §5 step 6 (faces ARE the product, v4),
§5a (journal lifecycle + undo proof-of-add), §5b/§5b.1 (rule D-WIPE, user-delete ban),
§6 (read-back verify), §9 (capture-before-fake). Everything here rests on committed
bench-A captures under
``tests/fixtures/recorded/site-a-ds-k1t341amf-s/enrollment/`` (PR #43, d34b3a5):

    facesetup_add_request.json         PUT FDSetUp, FLAT {faceLibType,FDID,FPID,modelData}
    facesetup_add_response.json        statusCode 1
    facesetup_readback_fpid90.json     FDSearch row for the FPID, modelData byte-identical
    fdsearch_delete_request.json       PUT FDSearch/Delete, body {"FPID":[{"value":"90"}]}
    fdsearch_delete_response.json      statusCode 1
    fdsearch_delete_verified_nomatch.json  the same FPID read back as NO MATCH

The FDSearch READ dialect (flat body, ROOT envelope, honest zero omitting ``MatchList``,
the 3-of-4-on-one-OK-page quirk) is E1-01b's, already shipped in ``gateclerk.paging`` —
this module reuses that engine and never re-derives the dialect.

**The template is OPAQUE.** ``modelData`` is decoded from base64 to bytes and re-encoded
for the wire; the sha256 of those bytes is the person's face identity. Nothing here
parses, interprets, resizes, re-compresses or re-models a template: there is no code
path in this module that looks at a template byte's value (§2, §8 R1). A face photo is
not in scope — ``faceURL`` photo bytes are dead on this firmware (OBSERVED.md) and
``faceURL`` is in ``VOLATILE_URL_FIELDS``, so it never enters a comparison.

Reuse, not a fork (parent E1-04's instruction): the journal, the 80-call budget, the
rejection vocabulary and ``person_hash`` all come from :mod:`gateclerk.migrate_write`,
and every request — write verb AND verify read — goes through
:class:`gateclerk.migrate_write.BudgetedWriteTransport.call`, the same seam E1-06b used
for the fingerprints phase. Faces own three verbs (FDSearch POST, FDSetUp PUT,
FDSearch/Delete PUT); the counter stays single because §5.3 counts AUTHED CALLS, not
write verbs.

Safety rules honoured here, each with the test that proves it
(tests/test_e1_06_faces_phase.py):

* **No read-back, no confirmed** (§6): the ``statusCode: 1`` ack proves NOTHING. A
  person reaches ``confirmed`` only when a per-person FDSearch returns a row whose
  ``modelData`` sha256 AND length equal the intent (§6 faces arm).
* **Idempotent re-run, never a silent overwrite** (card scope 2): a target row that
  already carries the intended template is ``already_present``; a row carrying a
  DIFFERENT template is a CONFLICT — reported, never overwritten (re-enrolling over
  someone else's face is a human decision).
* **Capacity fail-fast** (§5 step 4): the first rejection of any kind ends the phase and
  the result names which persons landed. Nothing is retried (§0.6).
* **No inferred semantics from caps** (§9): ``modelMaxNum=1`` / ``FDMaxNum=2`` /
  ``isSuportFDSearch=false`` are recorded probe facts, not behaviour (design §1). Our
  bodies always carry exactly ONE template per FPID because that is the captured shape;
  availability comes only from the call itself, never from a caps switch.
* **Undo is proof-of-add, then the captured targeted delete** (§5a/§5b.1): only
  ``confirmed`` entries whose LIVE FDSearch hash still matches are removable; every
  removal is wrapped in the §5b count-delta guard (whole-library count before and after,
  plus the named-FPID read-back) and an over-delete is an INCIDENT that stops the run.
* **§5b.1**: this module never touches ``UserInfoDetail/Delete``. Face deletes are the
  capture-proven targeted shape; the user-delete verb does not exist on this firmware
  and a test pins that no request leaves for it.
* **Budget** (§5.3): 1 FDSearch pre-read + 1 FDSetUp upload + 1 FDSearch read-back per
  person — three authed calls, all on one ledger, re-bootstrapping at 80.

Two decisions a reviewer will want stated, because each is an asymmetry with a sibling
phase and each is forced by a rule:

1. **``already_present`` creates no journal entry.** E1-06b journals an already-present
   fingerprint as ``confirmed``; that is inert there because FP undo is report-only
   (§5b.1). Face undo is REAL, and a journalled ``confirmed`` for a face this run never
   wrote would become undo-able evidence of a write that never happened — undo would
   delete a face that was on the target before we arrived. That is exactly what §5a's
   proof-of-add forbids, so the skip is reported and not journalled (pinned by
   ``test_already_present_writes_nothing_and_journals_nothing``).
2. **The undo terminal lives in the UNDO journal.** §5a names a ``reverted`` transition
   for the source entry; that journal member is E1-05's addition to the shared
   ``WriteJournal`` (its cards phase owns the same need) and this module must not
   pre-empt it. The removal is therefore journalled in its own file
   (``planned`` → ``applied`` → ``confirmed``, ``post_write_hash`` = ``ABSENT_SHA``), the
   source entry stays ``confirmed`` — and a re-run of undo is provably idempotent,
   because the live row now reads ABSENT and lands in ``already_absent`` with no delete
   sent (pinned by ``test_undo_is_idempotent_on_a_second_run``).
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path
from typing import Any, Protocol

from gateclerk.exceptions import GateClerkError
from gateclerk.migrate_bundle import (
    FacesIndex,
    FaceTemplate,
    safe_template_stem,
)
from gateclerk.migrate_diff import (
    # E1-11's shared face-template vocabulary. Defined in migrate_diff because the
    # import spine is faces -> migrate_write -> migrate_diff (both committed edges):
    # diff is the lowest module BOTH consumers already load, so keeping it here is
    # what keeps the DAG acyclic. The faces phase consumes `template_magic` (the
    # report-only family marker) and `face_portability_notes` (the shared formatter);
    # the diff/plan pass uses the same two. One helper, both paths (card §2).
    FACE_PORTABILITY_NOTE_PREFIX,
    face_portability_notes,
    template_magic,
)
from gateclerk.migrate_export import FD_PORTABLE_FACE_LIB_TYPE, FD_PORTABLE_FDID
from gateclerk.migrate_probe import CapabilityMatrix, require_fresh
from gateclerk.migrate_write import (
    DEFAULT_BATCH_SIZE,
    BudgetedWriteTransport,
    JournalEntry,
    JournalState,
    RejectKind,
    WriteJournal,
    WriteRejectedError,
    classify_rejection,
    person_hash,
)
from gateclerk.paging import DEFAULT_INTER_PAGE_DELAY, DEFAULT_MAX_PAGES, fd_search

__all__ = [
    "ABSENT_SHA",
    "BUNDLE_FACES_DIR",
    "CAPTURED_FACE_DELETE_KEYS",
    "CAPTURED_FACE_SETUP_KEYS",
    "FACE_DELETE_PARAMS",
    "FACE_DELETE_PATH",
    "FACE_LIB_TYPE",
    "FACE_PORTABILITY_NOTE_PREFIX",
    "FACE_SEARCH_PATH",
    "FACE_SETUP_PATH",
    "FDID_PORTABLE",
    "MAX_TEMPLATE_BYTES",
    "OP_FACE_DELETE",
    "OP_FACE_SETUP",
    "REBOOTSTRAP_AT_AUTHED_CALLS",
    "TEMPLATE_PORTABILITY_HINT",
    "BudgetedFaceReader",
    "FaceIntent",
    "FacePhaseAbortedError",
    "FaceReadError",
    "FaceRow",
    "FaceShapeError",
    "FaceTransport",
    "FaceUndoIncidentError",
    "FaceVerdict",
    "FaceWrite",
    "FacesPhaseResult",
    "FacesUndoReport",
    "FacesVerifyItem",
    "FacesVerifyReport",
    "ReaderCaller",
    "RowState",
    "SearchCaller",
    "apply_faces_phase",
    "build_face_delete_body",
    "build_face_setup_body",
    "bundle_face_magics",
    "count_face_rows",
    "decode_template",
    "face_portability_notes",
    "face_template_path",
    "faces_report",
    "is_template_portability_rejection",
    "journal_fingerprint",
    "live_metadata",
    "load_face_writes",
    "plan_face_writes",
    "read_face_row",
    "run_faces_phase",
    "template_magic",
    "undo_faces",
    "verify_faces",
    "verify_journal_faces",
]

# --- the captured face vocabulary ---------------------------------------------------------

#: ``PUT /ISAPI/Intelligent/FDLib/FDSetUp?format=json`` — the upload verb the bench
#: capture PROVED (OBSERVED.md "Faces WRITE — PROVEN (R1, the product)"). POST on this
#: path answers ``methodNotAllowed`` (design §1), so PUT is not a preference.
FACE_SETUP_PATH = "/ISAPI/Intelligent/FDLib/FDSetUp"

#: ``POST /ISAPI/Intelligent/FDLib/FDSearch?format=json`` — the proven FLAT, root-envelope
#: read (E1-01b). The verify arm and both undo guards are built on this one call.
FACE_SEARCH_PATH = "/ISAPI/Intelligent/FDLib/FDSearch"

#: ``PUT /ISAPI/Intelligent/FDLib/FDSearch/Delete?format=json&FDID=1&faceLibType=blackFD``
#: — the capture-PROVEN targeted face delete (fdsearch_delete_request.json: "verified NO
#: MATCH after, other people's faces untouched").
FACE_DELETE_PATH = "/ISAPI/Intelligent/FDLib/FDSearch/Delete"

#: The captured query parameters of the delete (the URL, not the body, carries the
#: library identity — fdsearch_delete_request.json is only ``{"FPID":[{"value":…}]}``).
FACE_DELETE_PARAMS: Mapping[str, str] = {
    "format": "json",
    "FDID": FD_PORTABLE_FDID,
    "faceLibType": FD_PORTABLE_FACE_LIB_TYPE,
}

#: The portable face library (design §1: FDID 1 = blackFD is the ACS-bound library;
#: FDID 2 infraredFD exists but is not what unlocks a door).
FDID_PORTABLE = FD_PORTABLE_FDID
FACE_LIB_TYPE = FD_PORTABLE_FACE_LIB_TYPE

#: The bundle subdirectory that holds ``<employeeNo>.b64`` template files (design §2).
#: ``migrate_bundle`` keeps its own constant private; E1-06b set the precedent of naming
#: the layout directory at the call site rather than widening the bundle module's API.
BUNDLE_FACES_DIR = "faces"

#: The key set of the ONE proven FDSetUp body (facesetup_add_request.json verbatim).
#: Note what is NOT here: ``mode``. The capture has no mode key, so none is sent —
#: inventing one is the v3 "8 rejected shapes" mistake class (§11 v4 delta 1).
CAPTURED_FACE_SETUP_KEYS: frozenset[str] = frozenset({"faceLibType", "FDID", "FPID", "modelData"})

#: The key set of the ONE proven FDSearch/Delete body (fdsearch_delete_request.json).
#: The value is a LIST of ``{"value": "<employeeNo>"}`` objects — one entry, because that
#: is the only list length the bench recorded. Multi-value deletes are an extrapolation
#: and are refused (same reasoning E1-04 applied to a batched UserInfo body).
CAPTURED_FACE_DELETE_KEYS: frozenset[str] = frozenset({"FPID"})

#: §5.3: the faces phase shares the users phase's transport ledger and its re-bootstrap
#: point, so one number governs the whole apply (imported, never re-declared).
REBOOTSTRAP_AT_AUTHED_CALLS = 80

#: A sanity ceiling on ONE template's decoded size, NOT a capacity claim. FDLib caps
#: record ``modelMaxNum=1`` and ``FDRecordDataMaxNum=3000`` (probe facts, §1) but no byte
#: maximum; the recorded bench template is 272 B. This ceiling exists only to refuse a
#: 10 MB blob that would be a corrupted bundle, and it is deliberately far above anything
#: the device produces — reading it as a capacity limit would be the §1 trap again.
MAX_TEMPLATE_BYTES = 64 * 1024

#: The identity of "no template at all". sha256 over ZERO bytes: an absent row carries no
#: template bytes, so its hash is the hash of nothing. Used by the undo path to say
#: "confirmed gone" in the same hash-typed field the upload path uses for "confirmed
#: present" — no magic strings in a hash field, and no invented device vocabulary.
ABSENT_SHA = hashlib.sha256(b"").hexdigest()

#: The journal ``op`` values this module writes (an undo of a face add is a delete).
OP_FACE_SETUP = "face_setup"
OP_FACE_DELETE = "face_delete"

#: E1-11 (site-B capture, 2026-10-23, docs/internal/OBSERVED-site-B.md "Face WRITE capture"):
#: the EXACT rejection pair V4.13.0 answers when the request shape is right and the
#: TEMPLATE BYTES are from another firmware generation. Captured verbatim as
#: tests/fixtures/recorded/site-b-ds-k1t344mbfwx-e1/enrollment/facesetup_crossgen_reject_400.json
#: (the site-B capture directory is named for the device serial, which is why the
#: firmware version sits in the sentence above rather than in the path)
#: (HTTP 400 ``{"statusCode":6,"statusString":"Invalid Content","subStatusCode":
#: "badJsonContent","errorCode":1610612759,"errorMsg":"faceURL"}``). The pair is the
#: trigger — capture E1 proved our flat body with the target's OWN template answers
#: ``ok`` on the same box, and the SAME box answers bare ``badJsonContent`` (naming the
#: offending key, e.g. ``EmployeeNoList``/``enableCardReader`` in the bench-A captures)
#: for real shape problems. Matching on bare ``badJsonContent`` would mislabel every
#: shape bug as a firmware wall, so BOTH fields must match.
_TEMPLATE_REJECT_SUB_STATUS = "badJsonContent"
_TEMPLATE_REJECT_ERROR_MSG = "faceURL"

#: The human-facing sentence the abort carries, and the ONLY honest exit from this
#: class: the picture route is dead on both boxes (A's faceURL JPEG export 404s,
#: capture-proven; B says ``isSupportFDSearchDataPackage:false``), so there is no
#: automatic path — faces require re-enrollment on the target.
TEMPLATE_PORTABILITY_HINT = (
    "target firmware rejected the source face templates (generation mismatch: the "
    "captured pair subStatusCode=badJsonContent + errorMsg=faceURL — the device could "
    "not parse modelData and asked for a picture instead, and the picture route is "
    "dead on both firmwares). Faces require re-enrollment on the target; the device "
    "probe record's 'Face WRITE capture' section carries the captured rejection."
)


def is_template_portability_rejection(exc: WriteRejectedError) -> bool:
    """True for the EXACT captured portability envelope — the pair, never one half.

    ``subStatusCode == "badJsonContent"`` alone is NOT this class: the committed
    captures show bare ``badJsonContent`` answering a wrong key (``EmployeeNoList``,
    ``enableCardReader``, a wrapped body) and that stays ``SHAPE`` (our bug). Only the
    full captured pair — that sub-status WITH ``errorMsg == "faceURL"`` — names the
    template-portability wall (capture E2; the shape control E1 rules our body out as
    the cause). Reads the envelope the transport carried; a rejection that arrived
    without one is not this class (we refuse to infer the pair from the message text).
    """
    envelope = exc.envelope
    return (
        envelope.get("subStatusCode") == _TEMPLATE_REJECT_SUB_STATUS
        and envelope.get("errorMsg") == _TEMPLATE_REJECT_ERROR_MSG
    )


def reject_kind_for(exc: WriteRejectedError) -> RejectKind:
    """Classify one rejection: the captured portability pair first, then the generic map.

    One entry point so a phase can never classify the SAME envelope two ways: the pair
    check consumes the E2 envelope, and everything else keeps
    :func:`gateclerk.migrate_write.classify_rejection`'s mapping verbatim (an unmapped
    word stays OTHER with the device's word riding on, §6).
    """
    if is_template_portability_rejection(exc):
        return RejectKind.TEMPLATE_REJECTED
    return classify_rejection(exc.sub_status)


# ``template_magic``, ``face_portability_notes`` and ``FACE_PORTABILITY_NOTE_PREFIX``
# are imported above from migrate_diff (the one shared home — see the import comment)
# and re-exported here because the faces phase is where a reader expects the face
# vocabulary to live; the diff/plan pass imports the same objects from their home.
# There is exactly ONE definition of each, so the plan-time warning and the phase's
# understanding of the wall can never drift apart in text or in rule.


# --- errors ---------------------------------------------------------------------------------


class FaceShapeError(GateClerkError):
    """Asked to build a face request the capture does not authorise.

    Raised before any request leaves the process: a shape absent from the fixtures has no
    device truth, so it is refused here rather than discovered by the device (§9).
    """


class FaceReadError(GateClerkError):
    """A required face read failed or answered a shape this module cannot trust.

    §0.7's fail-closed rule pointed at the face axis: a rejected/malformed FDSearch is
    never read as "this person has no face". Silence is not zero.
    """


class FacePhaseAbortedError(GateClerkError):
    """The faces phase aborted: nothing further may be written until a human reads why.

    Carries the :class:`FacesPhaseResult` so the caller still reports which persons
    landed (§5 step 4: never a silent partial write). Same contract as E1-04's
    ``WriteAbortedError`` and E1-06b's ``FpAbortedError``, with this phase's result type.
    """

    def __init__(self, message: str, result: FacesPhaseResult) -> None:
        self.result = result
        super().__init__(message)


class FaceUndoIncidentError(GateClerkError):
    """The §5b count-delta guard fired: the delete removed MORE than it was told to.

    For faces this is not expected — the captured shape is targeted and bench A verified
    other people's faces untouched — which is exactly why the guard is mandatory anyway:
    the D-WIPE lesson is that this family answers ``ok`` while deleting what the request
    did not name. Stop everything, report, escalate; never "clean up".

    Carries the partial :class:`FacesUndoReport` (what was already removed, the delta
    arithmetic, the incident text) so the operator sees the evidence, not just the
    sentence.
    """

    def __init__(self, message: str, report: FacesUndoReport) -> None:
        self.report = report
        super().__init__(message)


# --- the opaque template --------------------------------------------------------------------


def decode_template(employee_no: str, model_data: Any, *, field_name: str = "modelData") -> bytes:
    """Decode one device ``modelData`` string strictly to bytes — transport, never parsing.

    Whitespace between the base64 characters is tolerated (bundle files end with a newline
    and some firmwares wrap), but anything else failing ``validate=True`` raises: a
    half-decodable template must never be uploaded or compared as "probably fine" (§0.7).
    The bytes are returned EXACTLY as the device's base64 carried them — no interpretation
    of magic, size or structure happens here or anywhere in this module.
    """
    if not isinstance(model_data, str) or not model_data.strip():
        raise FaceShapeError(
            f"face template for {person_hash(employee_no)} carries no usable {field_name}"
        )
    compact = "".join(model_data.split())
    try:
        raw = base64.b64decode(compact, validate=True)
    except Exception as exc:  # binascii.Error subclasses ValueError
        raise FaceShapeError(
            f"face template for {person_hash(employee_no)} is not clean base64 "
            f"({exc.__class__.__name__}) — an un-decodable template cannot be hashed, "
            "so it cannot be verified either; refusing (§0.7)"
        ) from exc
    if not raw:
        raise FaceShapeError(
            f"face template for {person_hash(employee_no)} decodes to zero bytes — an "
            "empty template is never an enrollment to port (§0.7)"
        )
    if len(raw) > MAX_TEMPLATE_BYTES:
        raise FaceShapeError(
            f"face template for {person_hash(employee_no)} decodes to {len(raw)} bytes, "
            f"above the {MAX_TEMPLATE_BYTES} B sanity ceiling — that is a corrupted "
            "bundle file, not a face template (the recorded bench template is 272 B)"
        )
    return raw


@dataclass(frozen=True, slots=True)
class FaceIntent:
    """One person's template identity — the thing the journal and verify agree on.

    sha256 + length of the DECODED bytes (the identity, §2) plus which library it belongs
    to. Never the bytes themselves: reports and journals carry hashes (§4), and the
    bundle file is the only place template bytes live.
    """

    employee_no: str
    employee_hash: str
    fdid: str
    face_lib_type: str
    sha256: str
    length: int

    def metadata(self) -> dict[str, Any]:
        """The journal-safe projection (what ``intended_record`` holds — no template bytes)."""
        return {
            "employeeNo": self.employee_no,
            "FDID": self.fdid,
            "faceLibType": self.face_lib_type,
            "sha256": self.sha256,
            "length": self.length,
        }

    @classmethod
    def from_journal_entry(cls, entry: JournalEntry) -> FaceIntent | None:
        """Rebuild the intent a journal entry recorded (resume/audit/undo runs).

        None when the entry is not a face add this module would verify (a delete entry,
        say, or a face row whose intent record lost its identity) — callers skip those
        rather than comparing them as templates. The identity rides in
        ``intended_record`` because that is the one field ``WriteJournal.planned`` lets a
        caller populate structurally (``intended_hash`` is computed by the journal as a
        CONTENT hash of the record, which for a face is a hash OF the identity — fine to
        carry, never comparable to a template sha).
        """
        if entry.op != OP_FACE_SETUP:
            return None
        record = entry.intended_record or {}
        digest = record.get("sha256")
        length = record.get("length")
        if not isinstance(digest, str) or not digest:
            return None
        if not isinstance(length, int) or isinstance(length, bool) or length < 0:
            return None
        return cls(
            employee_no=entry.employee_no,
            employee_hash=entry.employee_hash,
            fdid=str(record.get("FDID") or FDID_PORTABLE),
            face_lib_type=str(record.get("faceLibType") or FACE_LIB_TYPE),
            sha256=digest,
            length=length,
        )


@dataclass(frozen=True, slots=True)
class FaceWrite:
    """One person's upload: the intent plus the device's own base64 characters to send."""

    intent: FaceIntent
    model_data: str  # the bundle's verbatim base64 string

    @classmethod
    def build(
        cls,
        employee_no: str,
        model_data: Any,
        *,
        fdid: str = FDID_PORTABLE,
        face_lib_type: str = FACE_LIB_TYPE,
        expect_sha256: str | None = None,
        expect_length: int | None = None,
    ) -> FaceWrite:
        """Hash the bytes and cross-check them against what the bundle INDEX claims.

        ``expect_*`` come from ``faces/INDEX.json`` (E1-01b). A mismatch means the bundle
        lies about its own bytes — the reader already refuses that (``read_bundle``), and
        this is the last frame before a write, so a tampered ``.b64`` cannot become a
        device enrollment even if someone handed us a hand-edited index.
        """
        raw = decode_template(employee_no, model_data)
        digest = hashlib.sha256(raw).hexdigest()
        if expect_sha256 is not None and digest != expect_sha256:
            raise FaceShapeError(
                f"face template for {person_hash(employee_no)} hashes to {digest[:12]}… "
                f"but the bundle index records {expect_sha256[:12]}… — a rollback source "
                "that cannot vouch for its own bytes is refused, not uploaded (§0.7)"
            )
        if expect_length is not None and len(raw) != expect_length:
            raise FaceShapeError(
                f"face template for {person_hash(employee_no)} is {len(raw)} B but the "
                f"bundle index records {expect_length} B — refusing (fail closed, §0.7)"
            )
        return cls(
            intent=FaceIntent(
                employee_no=employee_no,
                employee_hash=person_hash(employee_no),
                fdid=fdid,
                face_lib_type=face_lib_type,
                sha256=digest,
                length=len(raw),
            ),
            model_data=str(model_data),
        )


def face_template_path(bundle_dir: str | os.PathLike[str], employee_no: str) -> Path:
    """``faces/<employeeNo>.b64`` for one indexed person (the layout, design §2)."""
    return Path(bundle_dir) / BUNDLE_FACES_DIR / f"{safe_template_stem(employee_no)}.b64"


def load_face_writes(
    bundle_dir: str | os.PathLike[str],
    entries: Sequence[FaceTemplate],
) -> tuple[tuple[FaceWrite, ...], tuple[tuple[str, str], ...]]:
    """Read each indexed template out of ``faces/`` and turn it into an upload.

    The bundle index is the authority on WHICH people have a template and what their
    sha256/length are; the ``.b64`` file is the authority on the bytes. Both must agree
    (``FaceWrite.build``), which is what makes a hand-edited file refuse instead of ride.
    Persons whose file is missing or unreadable are skipped with a reason — a missing
    template is a fact about the bundle, never a zero-length upload (§0.7).
    """
    writes: list[FaceWrite] = []
    skipped: list[tuple[str, str]] = []
    for entry in entries:
        who = person_hash(entry.employee_no)
        try:
            path = face_template_path(bundle_dir, entry.employee_no)
        except ValueError as exc:
            skipped.append((who, f"unnameable:{exc}"))
            continue
        if not path.is_file():
            skipped.append((who, "missing_template_file"))
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except OSError as exc:
            skipped.append((who, f"bundle_unreadable:{exc}"))
            continue
        try:
            writes.append(
                FaceWrite.build(
                    entry.employee_no,
                    text.strip(),
                    fdid=entry.fdid,
                    face_lib_type=entry.face_lib_type,
                    expect_sha256=entry.sha256,
                    expect_length=entry.length,
                )
            )
        except FaceShapeError as exc:
            skipped.append((who, f"template_refused:{exc}"))
            continue
    order = sorted(writes, key=lambda w: w.intent.employee_no)
    return tuple(order), tuple(skipped)


def bundle_face_magics(
    bundle_dir: str | os.PathLike[str],
    entries: Sequence[FaceTemplate],
) -> dict[str, tuple[str, ...]]:
    """Each indexed person's readable template families, read off the bundle's ``.b64``.

    E1-11's SOURCE side for the report-only ``facePortability`` warning. Reads the
    SAME ``faces/<employeeNo>.b64`` files ``load_face_writes`` uploads (the same
    layout, the same tolerant decode) and asks :func:`template_magic` about at most
    8 bytes per template — transport + a head marker, never a parse (§2). A person
    whose file is missing, unreadable, or not clean base64 is simply ABSENT from the
    mapping: the plan pass has nothing to name for them, and the helper must not
    invent a family from silence (§0.7 — the warning's own helper answers absence
    with silence; the phase's skipped list remains where a broken bundle is REPORTED).

    A person may hold several readable families (the target walk is per row); the
    tuple is deduped and sorted so the warning text is deterministic.
    """
    magics: dict[str, tuple[str, ...]] = {}
    for entry in entries:
        try:
            path = face_template_path(bundle_dir, entry.employee_no)
        except ValueError:
            continue
        if not path.is_file():
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except OSError:
            continue
        try:
            raw = decode_template(entry.employee_no, text.strip())
        except FaceShapeError:
            continue
        magic = template_magic(raw)
        if magic is not None:
            magics[entry.employee_no] = (magic,)
    return magics


def plan_face_writes(
    *,
    bundle_dir: str | os.PathLike[str],
    faces: FacesIndex,
    employee_nos: Sequence[str] | None = None,
) -> tuple[tuple[FaceWrite, ...], tuple[tuple[str, str], ...]]:
    """(portable templates, report-only skips) — a BUNDLE-ONLY pass, zero device calls.

    Deliberately device-free, exactly like E1-06b's plan pass: the target is read FRESH
    at execution time (§4's freshness contract — a plan-time target view is the TOCTOU
    hole the design closes), so this answers only what a bundle can answer.

    1. the index must be AVAILABLE: an UNAVAILABLE index never read anyone, and "never
       read" is not "has no face" (§0.7) — everything is skipped with that reason.
    2. ``employee_nos`` (the diff plan's add/update roster) narrows the walk; ``None``
       means "every template the index records".
    3. the ``.b64`` file must exist and still match the INDEX sha256/length.

    The FDSearch pre-read (already_present skip / different-hash conflict) happens in
    :func:`run_faces_phase`, at write time, where §4's freshness contract puts it.
    """
    if faces.state != "AVAILABLE":
        return (), (
            (
                "*",
                f"faces_index_{faces.state.lower()}: {faces.reason} — an index that "
                "never ran is not a zero (§0.7); nothing is portable",
            ),
        )
    entries = list(faces.entries)
    if employee_nos is not None:
        wanted = {str(no) for no in employee_nos}
        entries = [entry for entry in entries if entry.employee_no in wanted]
    return load_face_writes(bundle_dir, entries)


# --- the captured request bodies -------------------------------------------------------------


def build_face_setup_body(write: FaceWrite) -> dict[str, Any]:
    """The FLAT ``FDSetUp`` body — EXACTLY facesetup_add_request.json's four keys.

    The template is re-encoded from the decoded bytes, so what goes on the wire is the
    canonical base64 of the bytes we hashed: the identity that verify checks is the
    identity that was sent. (``test_the_upload_body_is_byte_equal_to_the_capture`` pins
    that for the captured fixture this re-encoding reproduces the capture string exactly,
    so re-encoding is provably not a transformation on the recorded data.)
    """
    raw = decode_template(write.intent.employee_no, write.model_data)
    if hashlib.sha256(raw).hexdigest() != write.intent.sha256:
        raise FaceShapeError(
            f"template bytes for {write.intent.employee_hash} no longer hash to the "
            "journal intent — refusing to upload bytes we cannot vouch for (§0.7)"
        )
    return {
        "faceLibType": write.intent.face_lib_type,
        "FDID": write.intent.fdid,
        "FPID": write.intent.employee_no,
        "modelData": base64.b64encode(raw).decode("ascii"),
    }


def build_face_delete_body(employee_no: str) -> dict[str, Any]:
    """The ``{"FPID":[{"value":"<emp>"}]}`` body — one entry, the captured shape.

    ``FPID`` is a LIST in the capture, and it held exactly one value. A multi-value list
    is the same class of extrapolation E1-04 refused for ``UserInfo/SetUp`` (the only
    batch-shaped body we hold is the one that 400'd), so one delete request per person is
    the shipped shape and ``employee_no`` is a single opaque string.
    """
    if not isinstance(employee_no, str) or not employee_no:
        raise FaceShapeError(
            "the captured FDSearch/Delete body names exactly one FPID; an empty or "
            "non-string FPID is not that shape and is refused before it is sent"
        )
    return {"FPID": [{"value": employee_no}]}


# --- the FDSearch read (one call, strictly verdicted) ---------------------------------------


class RowState(StrEnum):
    """What one targeted FDSearch read honestly says about a person's face."""

    PRESENT = "present"  # one row, modelData present and hashable
    ABSENT = "absent"  # the device's HONEST zero: NO MATCH, MatchList omitted
    UNKNOWN = "unknown"  # a row WITHOUT modelData — the §6 "UNKNOWN field", never OK
    ERROR = "error"  # the read failed / answered a shape we cannot trust (§0.7)


@dataclass(frozen=True, slots=True)
class FaceRow:
    """One targeted FDSearch answer: state + identity, never the template bytes.

    ``magic`` (E1-11) is the template family marker :func:`template_magic` reads off
    the PRESENT row's decoded head — the first 8 bytes only, and only where the row
    actually carries a hashable template (every other state leaves it None). It rides
    on the same decode the sha256 already required (no second look at the bytes, no
    parsing — §2's opaque rule) and feeds ONLY the report-only ``facePortability``
    warning; it never changes a verdict, a write decision, or an exit code.
    """

    state: RowState
    sha256: str | None = None
    length: int | None = None
    #: why a non-PRESENT row is what it is (the device's own words where it had any).
    note: str = ""
    #: E1-11: ``FR\\d{6}`` family marker of the row's template, or None (unknown).
    magic: str | None = None


class SearchCaller(Protocol):
    """The injected READ seam: one FDSearch POST, the parsed root envelope back.

    Satisfied by :class:`BudgetedFaceReader` (reads charged to the same nonce ledger as
    the writes — §5.3 counts AUTHED CALLS, not write verbs) and by :class:`ReaderCaller`
    around a bare callable.
    """

    def post_search(
        self, path: str, body: Mapping[str, Any]
    ) -> dict[str, Any]: ...  # pragma: no cover - protocol


class FaceTransport(Protocol):
    """The verbs this phase may ask of its injected client (§5.0 capture set).

    ``put_face_setup`` is the captured upload, ``put_face_delete`` the capture-proven
    targeted removal, ``post_face_search`` the proven read. E1-06b's ``FpTransport`` set
    the precedent: the budget class carries ANY named seam method
    (``BudgetedWriteTransport.call``), so a phase adds verbs, never counters.
    """

    def post_face_search(
        self, path: str, body: Mapping[str, Any]
    ) -> dict[str, Any]: ...  # pragma: no cover - protocol

    def put_face_setup(
        self, path: str, body: Mapping[str, Any]
    ) -> dict[str, Any]: ...  # pragma: no cover - protocol

    def put_face_delete(
        self, path: str, params: Mapping[str, str], body: Mapping[str, Any]
    ) -> dict[str, Any]: ...  # pragma: no cover - protocol

    def close(self) -> None: ...  # pragma: no cover - protocol


class ReaderCaller:
    """Adapt a bare ``body -> dict`` reader to :class:`SearchCaller`.

    The production verify seam (and most unit tests) hand us the same callable
    ``migrate_export`` hands the paging engine; the budget seam hands us a transport. This
    keeps both on one call signature.
    """

    def __init__(self, reader: Callable[[Mapping[str, Any]], dict[str, Any]]) -> None:
        self._reader = reader

    def post_search(self, path: str, body: Mapping[str, Any]) -> dict[str, Any]:
        del path  # the reader is already bound to the FDSearch endpoint
        return self._reader(body)


class BudgetedFaceReader:
    """Route face READs through the phase's budgeted transport so they cost what they cost.

    A read that bypassed :class:`BudgetedWriteTransport` would be the auth-budget leak
    §0.5 names — the nonce ledger would disagree with our own count and the ~190-request
    lockout class would return. ``verb`` is a method NAME on the injected client, so this
    adapter spends the same single counter the uploads spend.
    """

    def __init__(
        self,
        transport: BudgetedWriteTransport,
        *,
        verb: str = "post_face_search",
    ) -> None:
        self._transport = transport
        self._verb = verb

    def post_search(self, path: str, body: Mapping[str, Any]) -> dict[str, Any]:
        return self._transport.call(self._verb, path, body)


def _flat_search_body(employee_no: str | None, page_size: int) -> dict[str, Any]:
    """The proven FLAT FDSearch cond — the shape the operator confirmed and E1-01b shipped.

    No wrapper (``FDSearchCond`` is what 400'd ``MessageParametersLack faceLibType``,
    §1), no ``searchID`` (the proven body carries none), ``FPID`` only when filtering.
    """
    body: dict[str, Any] = {
        "searchResultPosition": 0,
        "maxResults": page_size,
        "faceLibType": FACE_LIB_TYPE,
        "FDID": FDID_PORTABLE,
    }
    if employee_no is not None:
        body["FPID"] = employee_no
    return body


def read_face_row(
    caller: SearchCaller,
    employee_no: str,
    *,
    page_size: int = 30,
) -> FaceRow:
    """Read ONE person's face row with the captured single-request filter.

    Deliberately ONE request (the card's budget is 3 calls/person): the completeness
    discipline is therefore in the verdict, not in extra paging — a filtered FDSearch that
    answers MORE, or answers more than one row, or answers a row for a DIFFERENT FPID, is
    reported as ERROR. Each of those means the device did not answer the question we asked,
    and §0.7 forbids turning that into "no face".

    The row's ``modelData`` is decoded only to be hashed (opaque rule). A row that carries
    no ``modelData`` is UNKNOWN, and §6 is explicit that UNKNOWN is a mismatch, never an OK.
    """
    try:
        answer = caller.post_search(FACE_SEARCH_PATH, _flat_search_body(employee_no, page_size))
    except Exception as exc:  # any read failure is an ERROR, never "empty" (§0.7)
        return FaceRow(RowState.ERROR, note=f"FDSearch raised {exc.__class__.__name__}: {exc}")
    if not isinstance(answer, Mapping):
        return FaceRow(RowState.ERROR, note=f"FDSearch answered {type(answer).__name__}")
    # The captured root dialect: counts live at the body root (§5.0 capture). A root with
    # no count fields is a protocol break — `paging.response_envelope` says so, and the
    # same rule is re-asserted here because this read is single-page by design.
    if "numOfMatches" not in answer and "totalMatches" not in answer:
        return FaceRow(
            RowState.ERROR,
            note=f"FDSearch root carries no count fields (keys={sorted(answer)!r}) — "
            "a protocol break is never read as zero records (§0.7)",
        )
    status = str(answer.get("responseStatusStrg") or "").strip().upper()
    if status in {"MORE", "PARTIAL"}:
        return FaceRow(
            RowState.ERROR,
            note=f"single-FPID FDSearch said {status!r} — the filter did not answer one "
            "complete page, so 'this person has no face' would be an inference (§0.7)",
        )
    raw_rows = answer.get("MatchList")
    if raw_rows is None:  # the captured honest zero: NO MATCH + MatchList ABSENT
        return FaceRow(
            RowState.ABSENT,
            note=f"device said {status or 'NO MATCH'} with MatchList omitted",
        )
    if not isinstance(raw_rows, list):
        return FaceRow(RowState.ERROR, note=f"MatchList is {type(raw_rows).__name__}")
    if len(raw_rows) != 1:
        return FaceRow(
            RowState.ERROR,
            note=f"single-FPID FDSearch returned {len(raw_rows)} rows — modelMaxNum=1 is "
            "a probe fact, not a licence to pick a winner from a contradiction (§0.7)",
        )
    row = raw_rows[0]
    if not isinstance(row, Mapping):
        return FaceRow(RowState.ERROR, note=f"MatchList row is {type(row).__name__}")
    fpid = row.get("FPID")
    if fpid is None or str(fpid) != employee_no:
        return FaceRow(
            RowState.ERROR,
            note=f"asked for FPID {employee_no!r}, the device answered FPID {fpid!r} — an "
            "ignored filter would make every verdict a lie, so this is an error",
        )
    if "modelData" not in row:
        return FaceRow(
            RowState.UNKNOWN,
            note="row carries no modelData — §6: an UNKNOWN field is a mismatch, not an OK",
        )
    try:
        raw = decode_template(employee_no, row.get("modelData"))
    except FaceShapeError as exc:
        return FaceRow(RowState.ERROR, note=str(exc))
    # The decode the hash REQUIRES is also the only look at the bytes the portability
    # marker needs — first 8 bytes, no parse (§2 opaque rule holds, E1-11).
    return FaceRow(
        RowState.PRESENT,
        sha256=hashlib.sha256(raw).hexdigest(),
        length=len(raw),
        magic=template_magic(raw),
    )


def count_face_rows(
    caller: SearchCaller,
    *,
    page_size: int = 30,
    max_pages: int = DEFAULT_MAX_PAGES,
    inter_page_delay: float = DEFAULT_INTER_PAGE_DELAY,
    sleep: Callable[[float], None] = time.sleep,
    clock: Callable[[], float] = time.monotonic,
) -> int:
    """Whole-library face row count — the §5b guard's before/after measurement.

    Uses E1-01b's OWN engine (``paging.fd_search``), because this endpoint's paging quirk
    (bench A: 3 of 4 rows on one OK page, §1) is exactly the failure a guard must not
    inherit: a naive single-page ``totalMatches`` could under-count the library and then
    read a 4-person wipe as a 3-person wipe. Counting the ROWS the engine actually walked
    is the only reading that cannot be quietly clamped by a page size.

    A library whose rows repeat an FPID is a shape this design has no capture for, so it
    raises rather than letting the guard do arithmetic on noise.
    """
    engine = fd_search(
        lambda body: caller.post_search(FACE_SEARCH_PATH, body),
        page_size=page_size,
        max_pages=max_pages,
        inter_page_delay=inter_page_delay,
        sleep=sleep,
        clock=clock,
    )
    # The engine OWNS the cursor fields (paging.py refuses a caller that passes them —
    # E1-01b's export walks with the two required flat parameters only, §1).
    rows = engine.collect({"faceLibType": FACE_LIB_TYPE, "FDID": FDID_PORTABLE})
    people = {str(r.get("FPID")) for r in rows if r.get("FPID") is not None}
    if len(people) != len(rows):
        raise FaceReadError(
            "the whole-library FDSearch walk returned duplicate FPID rows — the face "
            "library's shape is not what the capture recorded, so a count-delta guard "
            "built on it would be arithmetic on noise (§0.7)"
        )
    return len(rows)


# --- the faces phase -------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class FacesPhaseResult:
    """What the faces phase did — the artifact §5 step 4 demands on an abort."""

    planned: tuple[str, ...] = ()  # employee hash prefixes, in send order
    applied: tuple[str, ...] = ()  # device answered statusCode 1
    confirmed: tuple[str, ...] = ()  # read-back sha256 AND length matched
    already_present: tuple[str, ...] = ()  # pre-read hash == intent (no write sent)
    conflicts: tuple[tuple[str, str], ...] = ()  # hash, reason (a different template)
    rejected: tuple[tuple[str, RejectKind, str | None], ...] = ()  # hash, kind, subStatus
    unconfirmed: tuple[tuple[str, str], ...] = ()  # hash, why the read-back did not match
    skipped: tuple[tuple[str, str], ...] = ()  # hash, reason (bundle-side refusals)
    batches: int = 0
    batch_size: int = DEFAULT_BATCH_SIZE
    calls_sent: int = 0  # authed device calls this phase issued
    rebootstraps: int = 0
    aborted: bool = False
    abort_reason: str | None = None

    @property
    def landed(self) -> tuple[str, ...]:
        """Persons whose upload the device ACCEPTED (only ``confirmed`` says it stuck)."""
        return self.applied

    @property
    def clean(self) -> bool:
        return (
            not self.aborted and not self.rejected and not self.unconfirmed and not self.conflicts
        )

    def summary(self) -> dict[str, Any]:
        """PII-free run summary (§4): hashes and counts only, never names or bytes."""
        return {
            "planned": len(self.planned),
            "applied": len(self.applied),
            "confirmed": len(self.confirmed),
            "alreadyPresent": len(self.already_present),
            "conflicts": [{"employee": h, "reason": r} for h, r in self.conflicts],
            "rejected": [
                {"employee": h, "kind": str(kind), "subStatusCode": sub}
                for h, kind, sub in self.rejected
            ],
            "unconfirmed": [{"employee": h, "reason": r} for h, r in self.unconfirmed],
            "skipped": [{"employee": h, "reason": r} for h, r in self.skipped],
            "batches": self.batches,
            "batchSize": self.batch_size,
            "callsSent": self.calls_sent,
            "rebootstraps": self.rebootstraps,
            "aborted": self.aborted,
            "abortReason": self.abort_reason,
        }


@dataclass(slots=True)
class _Tally:
    """Mutable accumulator for one faces phase (the public result stays frozen)."""

    applied: list[str] = field(default_factory=list)
    confirmed: list[str] = field(default_factory=list)
    already_present: list[str] = field(default_factory=list)
    conflicts: list[tuple[str, str]] = field(default_factory=list)
    rejected: list[tuple[str, RejectKind, str | None]] = field(default_factory=list)
    unconfirmed: list[tuple[str, str]] = field(default_factory=list)
    batches: int = 0
    calls: int = 0

    def result(
        self,
        *,
        planned: Sequence[str],
        skipped: Sequence[tuple[str, str]],
        batch_size: int,
        rebootstraps: int,
        aborted: bool,
        abort_reason: str | None = None,
    ) -> FacesPhaseResult:
        return FacesPhaseResult(
            planned=tuple(planned),
            applied=tuple(self.applied),
            confirmed=tuple(self.confirmed),
            already_present=tuple(self.already_present),
            conflicts=tuple(self.conflicts),
            rejected=tuple(self.rejected),
            unconfirmed=tuple(self.unconfirmed),
            skipped=tuple(skipped),
            batches=self.batches,
            batch_size=batch_size,
            calls_sent=self.calls,
            rebootstraps=rebootstraps,
            aborted=aborted,
            abort_reason=abort_reason,
        )


def _effective_batch_size(batch_size: int | None) -> int:
    """Pacing unit only — faces send one template per request, in batches of this size.

    There is no batched FDSetUp body (the capture holds one flat, singular body), so
    ``batch_size`` groups WHEN we pause, never what we send. Deriving a face batch from
    ``FDRecordDataMaxNum`` would be the §1 capacity trap; the default is E1-04's derived 10.
    """
    if batch_size is None:
        return DEFAULT_BATCH_SIZE
    if batch_size < 1:
        raise ValueError(f"batch_size must be >= 1, got {batch_size}")
    return batch_size


def _abort(
    tally: _Tally,
    transport: BudgetedWriteTransport,
    *,
    planned: Sequence[str],
    skipped: Sequence[tuple[str, str]],
    size: int,
    message: str,
) -> FacePhaseAbortedError:
    """Build the one abort event this phase may raise, with the landed list attached."""
    result = tally.result(
        planned=planned,
        skipped=skipped,
        batch_size=size,
        rebootstraps=transport.rebootstraps,
        aborted=True,
        abort_reason=message,
    )
    return FacePhaseAbortedError(message, result)


def run_faces_phase(
    transport: BudgetedWriteTransport,
    journal: WriteJournal,
    writes: Sequence[FaceWrite],
    *,
    batch_size: int | None = None,
    sleep: Callable[[float], None] = time.sleep,
    batch_delay: float = 1.0,
    page_size: int = 30,
    skipped: Sequence[tuple[str, str]] = (),
) -> FacesPhaseResult:
    """Port one template per person: pre-read, upload, read-back — journal first, always.

    Order per person (§5a), and the tests pin it: FDSearch pre-read → journal
    ``planned``+fsync → ``PUT FDSetUp`` → journal ``applied`` → FDSearch read-back →
    journal ``confirmed``. Three authed calls, all charged to ``transport``'s ledger.

    Decisions taken here, each forced by a rule rather than taste:

    * A target row already carrying the intended hash is ``already_present``: no write is
      sent and NO journal entry is created — an entry we never wrote would become
      undo-able evidence of a write that never happened (module docstring decision 1).
    * A target row carrying a DIFFERENT hash is a CONFLICT: reported and skipped, never
      overwritten. Re-enrolling over a different template destroys a face we did not
      export (§5 step 6; the same report-and-skip spine as §4's conflicts).
    * A row we cannot identify (UNKNOWN, no ``modelData``) skips that person as a
      conflict — we do not upload over a state we cannot describe. A row we cannot READ
      (ERROR) ends the PHASE: an unreadable library is not a per-person fact (§0.7).
    * The ack is not confirmation. ``confirmed`` requires the read-back hash AND length to
      equal the intent; a read-back that disagrees is terminal for the phase (§0.6) and
      the journal deliberately stays at ``applied`` — unknown state, human decides (§5a).
    * The first rejection ends the phase (§5 step 4) and the raised error carries the
      result naming who landed. Nothing is retried (§0.6).
    """
    size = _effective_batch_size(batch_size)
    planned = tuple(w.intent.employee_hash for w in writes)
    tally = _Tally()
    reader = BudgetedFaceReader(transport)
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
                sleep(batch_delay)  # between batches only, never before the first
            tally.batches += 1
        intent = write.intent

        # 1/3 — pre-read (skip rule + conflict rule).
        pre = read_face_row(reader, intent.employee_no, page_size=page_size)
        tally.calls += 1
        if pre.state is RowState.ERROR:
            raise _abort(
                tally,
                transport,
                planned=planned,
                skipped=skipped,
                size=size,
                message=(
                    f"faces phase aborted BEFORE writing {intent.employee_hash}: the "
                    f"required FDSearch pre-read failed ({pre.note}) — an unreadable "
                    "target face state is never treated as absent (§0.7), and nothing in "
                    "this phase was retried (§0.6)."
                ),
            )
        if pre.state is RowState.UNKNOWN:
            tally.conflicts.append((intent.employee_hash, f"row_without_model_data:{pre.note}"))
            continue
        if pre.state is RowState.PRESENT:
            if pre.sha256 == intent.sha256 and pre.length == intent.length:
                tally.already_present.append(intent.employee_hash)
                continue
            tally.conflicts.append(
                (
                    intent.employee_hash,
                    f"existing_template_differs: live={pre.sha256} len={pre.length} "
                    f"intended={intent.sha256} len={intent.length} — re-enrolling over a "
                    "different face template is a human decision, never ours (§5 step 6)",
                )
            )
            continue

        # 2/3 — journal planned (fsync BEFORE the request, §5a) then the upload.
        entry = journal.planned(
            employee_no=intent.employee_no,
            classification="add",
            pre_write_record=None,  # honest zero: the device said this person has no face
            intended_record=intent.metadata(),
            op=OP_FACE_SETUP,
        )
        body = build_face_setup_body(write)
        tally.calls += 1
        try:
            ack = transport.call("put_face_setup", FACE_SETUP_PATH, body)
            # INSIDE the try: a non-OK ack is the same event as a raising transport — it
            # journals `rejected`, records the rejection, and aborts (E1-04's rule).
            _require_ok_ack(ack, intent.employee_hash)
        except WriteRejectedError as exc:
            # E1-11: ONE classifier for this phase's rejections. The captured E2 pair
            # (badJsonContent + errorMsg:faceURL) is the template-portability wall;
            # everything else keeps classify_rejection's mapping verbatim (§6).
            kind = reject_kind_for(exc)
            journal.rejected(entry, sub_status=exc.sub_status, reject_class=kind)
            tally.rejected.append((intent.employee_hash, kind, exc.sub_status))
            if kind is RejectKind.TEMPLATE_REJECTED:
                # The wall, named — still fail-fast (§5 step 4) and still never retried
                # (§0.6): retry-spam against a rejecting firmware spends the lockout
                # budget for an answer the capture already gave. Only the message
                # differs from the generic abort: it must name the wall and the human
                # next step (re-enrollment), not leave the operator at "badJsonContent".
                raise _abort(
                    tally,
                    transport,
                    planned=planned,
                    skipped=skipped,
                    size=size,
                    message=(
                        f"faces phase aborted at {intent.employee_hash} after "
                        f"{len(tally.applied)} of {len(writes)} accepted: "
                        f"{TEMPLATE_PORTABILITY_HINT} "
                        f"The journal entry is 'rejected' with class "
                        f"{RejectKind.TEMPLATE_REJECTED} (device words: "
                        f"{exc.sub_status}/{_TEMPLATE_REJECT_ERROR_MSG}); applied[] in "
                        "the carried result lists who landed; nothing was retried (§0.6) "
                        "and no further face upload may be attempted against this "
                        "target in this run."
                    ),
                ) from exc
            raise _abort(
                tally,
                transport,
                planned=planned,
                skipped=skipped,
                size=size,
                message=(
                    f"faces phase aborted at {intent.employee_hash} after "
                    f"{len(tally.applied)} of {len(writes)} accepted: the device answered "
                    f"{exc.sub_status or exc} (§5 step 4: the phase stops here; applied[] "
                    "in the carried result lists who landed; nothing was retried, §0.6). "
                    "modelMaxNum=1 and FDMaxNum=2 are probe facts, so no capacity "
                    "semantics are assumed here — the device said no in its own words."
                ),
            ) from exc
        journal.applied(entry)
        tally.applied.append(intent.employee_hash)

        # 3/3 — read-back. The ack proved nothing; this does, or it does not.
        post = read_face_row(reader, intent.employee_no, page_size=page_size)
        tally.calls += 1
        if (
            post.state is RowState.PRESENT
            and post.sha256 == intent.sha256
            and post.length == intent.length
        ):
            journal.confirmed(entry, post_write_hash=intent.sha256)
            tally.confirmed.append(intent.employee_hash)
            continue
        why = (
            f"read-back said {post.state}: {post.note}"
            if post.state is not RowState.PRESENT
            else f"read-back hash/length {post.sha256}/{post.length} != intended "
            f"{intent.sha256}/{intent.length}"
        )
        tally.unconfirmed.append((intent.employee_hash, why))
        raise _abort(
            tally,
            transport,
            planned=planned,
            skipped=skipped,
            size=size,
            message=(
                f"TERMINAL: FDSetUp for {intent.employee_hash} was accepted but the "
                f"FDSearch read-back does not match the intent — {why}. The journal stays "
                "at 'applied' (unknown state, human decides, §5a) and the phase stops "
                "here: a mismatch is terminal for the run and is never 'fixed' by a "
                "re-write (§0.6)."
            ),
        )

    return tally.result(
        planned=planned,
        skipped=skipped,
        batch_size=size,
        rebootstraps=transport.rebootstraps,
        aborted=False,
    )


def _require_ok_ack(ack: Any, employee_hash_value: str) -> None:
    """``statusCode: 1`` or a rejection — an ack that is not the captured OK is a refusal."""
    if not isinstance(ack, Mapping):
        raise WriteRejectedError(
            f"FDSetUp for {employee_hash_value} answered {type(ack).__name__}, not an "
            "envelope — an answer we cannot read is not an accepted write (§0.7)"
        )
    code = ack.get("statusCode")
    if code == 1:
        return
    sub_status = ack.get("subStatusCode")
    raise WriteRejectedError(
        f"FDSetUp for {employee_hash_value} answered statusCode={code!r} "
        f"(subStatusCode={sub_status!r}); only statusCode 1 is an accepted ack in any "
        "committed capture (§6: even that proves nothing on its own — the read-back is "
        "the proof)",
        sub_status=None if sub_status is None else str(sub_status),
        envelope=dict(ack),
    )


# --- §6 faces verify (the arm the users verify cannot cover) ---------------------------------


class FaceVerdict(StrEnum):
    """Per-person verify verdict for the face axis (§6). MISMATCH is terminal."""

    OK = "ok"
    MISMATCH = "mismatch"
    MISSING = "missing"
    UNKNOWN = "unknown"  # a row without modelData — §6: this is a mismatch, not an OK


@dataclass(frozen=True, slots=True)
class FacesVerifyItem:
    """One person's face verify result. Hashes and lengths only — no bytes, no names (§4)."""

    employee_no: str
    employee_hash: str
    verdict: FaceVerdict
    live_sha256: str | None = None
    expected_sha256: str | None = None
    live_length: int | None = None
    expected_length: int | None = None
    note: str = ""


@dataclass(frozen=True, slots=True)
class FacesVerifyReport:
    """The §6 face walker's output."""

    items: tuple[FacesVerifyItem, ...]
    #: How many authed FDSearch calls the walk cost (the ledger pin's other half).
    calls_sent: int = 0

    @property
    def ok(self) -> bool:
        return all(i.verdict is FaceVerdict.OK for i in self.items)

    @property
    def terminal(self) -> tuple[FacesVerifyItem, ...]:
        """Everything that must stop the run (§0.6): mismatch, unknown, or accepted-but-absent."""
        return tuple(i for i in self.items if i.verdict is not FaceVerdict.OK)

    def verdict_of(self, employee_no: str) -> FaceVerdict | None:
        for item in self.items:
            if item.employee_no == employee_no:
                return item.verdict
        return None

    def summary(self) -> dict[str, Any]:
        return {
            "counts": {
                "ok": sum(1 for i in self.items if i.verdict is FaceVerdict.OK),
                "mismatch": sum(1 for i in self.items if i.verdict is FaceVerdict.MISMATCH),
                "missing": sum(1 for i in self.items if i.verdict is FaceVerdict.MISSING),
                "unknown": sum(1 for i in self.items if i.verdict is FaceVerdict.UNKNOWN),
            },
            "terminal": [
                {
                    "employee": i.employee_hash,
                    "verdict": str(i.verdict),
                    "live": i.live_sha256,
                    "expected": i.expected_sha256,
                    "liveLength": i.live_length,
                    "expectedLength": i.expected_length,
                }
                for i in self.terminal
            ],
            "callsSent": self.calls_sent,
        }


def verify_faces(
    caller: SearchCaller,
    expected: Sequence[FaceIntent],
    *,
    page_size: int = 30,
) -> FacesVerifyReport:
    """Re-FDSearch every touched FPID and compare hash + length against the intent (§6).

    This is the verify arm §5 step 6 demands because a face upload does NOT move the
    UserInfo content hash — §6's user verify is silent about faces, and the volatile
    counter ``numOfFace`` is deliberately NOT consulted (``normalize_record`` drops it; a
    counter is not a set, §9). Two facts must agree for OK: the sha256 of the returned
    ``modelData`` AND its byte length. A row with no ``modelData`` is UNKNOWN — a
    mismatch, never an OK — and a read that fails is a MISMATCH verdict with the read's
    own words, never "missing" (§0.7).
    """
    items: list[FacesVerifyItem] = []
    calls = 0
    for intent in expected:
        row = read_face_row(caller, intent.employee_no, page_size=page_size)
        calls += 1
        base = {
            "employee_no": intent.employee_no,
            "employee_hash": intent.employee_hash,
            "expected_sha256": intent.sha256,
            "expected_length": intent.length,
            "live_sha256": row.sha256,
            "live_length": row.length,
        }
        if row.state is RowState.PRESENT:
            same = row.sha256 == intent.sha256 and row.length == intent.length
            items.append(
                FacesVerifyItem(
                    **base,
                    verdict=FaceVerdict.OK if same else FaceVerdict.MISMATCH,
                    note="" if same else "live template differs from the journal intent (§6)",
                )
            )
        elif row.state is RowState.ABSENT:
            items.append(
                FacesVerifyItem(
                    **base,
                    verdict=FaceVerdict.MISSING,
                    note=f"the device answered {row.note} — an accepted upload that is "
                    "absent on read-back is terminal (§0.6), not a no-op",
                )
            )
        elif row.state is RowState.UNKNOWN:
            items.append(
                FacesVerifyItem(
                    **base,
                    verdict=FaceVerdict.UNKNOWN,
                    note=row.note or "row carries no modelData",
                )
            )
        else:
            items.append(
                FacesVerifyItem(
                    **base,
                    verdict=FaceVerdict.MISMATCH,
                    note=f"verify read failed: {row.note} — a failed read is never an OK "
                    "and never a 'missing' either (§0.7)",
                )
            )
    return FacesVerifyReport(items=tuple(items), calls_sent=calls)


def verify_journal_faces(
    caller: SearchCaller,
    journal: WriteJournal,
    *,
    page_size: int = 30,
) -> FacesVerifyReport:
    """§6 over the journal: verify every touched person against what the journal intended.

    The journal is the intent record, so this works on a resumed or audited run where no
    upload happened in this process. Persons whose journal entry carries no face identity
    (a delete entry, say) are left to their own path rather than compared as templates.
    """
    expected: list[FaceIntent] = []
    for entry in journal.latest():
        intent = FaceIntent.from_journal_entry(entry)
        if intent is not None:
            expected.append(intent)
    return verify_faces(caller, expected, page_size=page_size)


# --- §5a undo (proof-of-add + the §5b count-delta guard) -------------------------------------


@dataclass(frozen=True, slots=True)
class FacesUndoReport:
    """What an undo removed, what it refused, and the guard's arithmetic evidence."""

    removed: tuple[str, ...] = ()  # confirmed gone by read-back (absent + count delta ok)
    refused: tuple[tuple[str, str], ...] = ()  # hash, reason (non-confirmed / drifted)
    already_absent: tuple[str, ...] = ()  # nothing to remove; not an incident
    deltas: tuple[tuple[str, int, int], ...] = ()  # hash, total_before, total_after
    incidents: tuple[tuple[str, str], ...] = ()  # hash, guard text (stop + escalate)
    journal_path: str = ""
    calls_sent: int = 0

    @property
    def clean(self) -> bool:
        return not self.incidents and not self.refused

    def summary(self) -> dict[str, Any]:
        return {
            "removed": list(self.removed),
            "refused": [{"employee": h, "reason": r} for h, r in self.refused],
            "alreadyAbsent": list(self.already_absent),
            "deltas": [
                {"employee": h, "before": before, "after": after}
                for h, before, after in self.deltas
            ],
            "incidents": [{"employee": h, "guard": g} for h, g in self.incidents],
            "journal": self.journal_path,
            "callsSent": self.calls_sent,
        }


def live_metadata(row: FaceRow) -> dict[str, Any]:
    """The journal's record of the row that existed before the delete (never the bytes)."""
    return {"sha256": row.sha256, "length": row.length, "state": str(row.state)}


def undo_faces(
    transport: BudgetedWriteTransport,
    journal: WriteJournal,
    undo_journal: WriteJournal,
    *,
    employee_nos: Sequence[str] | None = None,
    page_size: int = 30,
    sleep: Callable[[float], None] = time.sleep,
    inter_page_delay: float = DEFAULT_INTER_PAGE_DELAY,
) -> FacesUndoReport:
    """Remove ONLY what this run proved it added, one captured delete at a time.

    Sequence (§5a then §5b), in this order and no other:

    1. **proof-of-add** — the person's journal entry must be a ``confirmed`` face add AND
       a live FDSearch must still answer that entry's post-write hash. A non-confirmed
       entry (``planned``/``applied``/``rejected``) is an unknown state = human, never a
       delete. A drifted row means somebody else touched this face since the run: refuse
       and escalate — someone else's edit wins (§5a).
    2. **count before** — the whole library counted with the proven paging walker.
    3. **the captured delete** — ``PUT FDSearch/Delete?format=json&FDID=1&faceLibType=
       blackFD`` with ``{"FPID":[{"value":"<emp>"}]}``. One person per request (the
       capture's list held one value), one entry per ``confirmed`` add, never any other
       delete verb (§5b.1: ``UserInfoDetail/Delete`` is banned outright).
    4. **count after** — and the guard: if the library shrank by MORE than the one person
       we named, that is a D-WIPE incident. Stop, journal the fact, raise: restore comes
       from the pre-run bundle by a human, never from an automatic re-write.
    5. **read back the named FPID** — must be the device's honest zero before the undo
       entry is ``confirmed``.

    The undo gets its own journal (§5a) — the source entry is left ``confirmed`` because
    the ``reverted`` transition is E1-05's addition to the shared journal (module
    docstring decision 2) — and idempotency comes from step 1's live read: a second run
    finds the row ABSENT and sends no delete.
    """
    targets = (
        list(employee_nos)
        if employee_nos is not None
        else [
            e.employee_no
            for e in journal.latest(state=JournalState.CONFIRMED)
            if e.op == OP_FACE_SETUP
        ]
    )
    reader = BudgetedFaceReader(transport)
    calls = 0
    removed: list[str] = []
    refused: list[tuple[str, str]] = []
    absent: list[str] = []
    deltas: list[tuple[str, int, int]] = []

    def report(incidents: Sequence[tuple[str, str]] = ()) -> FacesUndoReport:
        return FacesUndoReport(
            removed=tuple(removed),
            refused=tuple(refused),
            already_absent=tuple(absent),
            deltas=tuple(deltas),
            incidents=tuple(incidents),
            journal_path=str(undo_journal.path),
            calls_sent=calls,
        )

    for employee_no in targets:
        who = person_hash(employee_no)
        entry = journal.by_employee(employee_no)
        if entry is None or entry.op != OP_FACE_SETUP:
            refused.append(
                (
                    who,
                    "no_face_write_entry — undo removes only what this journal records "
                    "this run added (§5a)",
                )
            )
            continue
        if entry.state is not JournalState.CONFIRMED:
            refused.append(
                (
                    who,
                    f"entry state is {entry.state}, not confirmed — planned/applied/"
                    "rejected are unknown states and unknown states are a human decision, "
                    "never a delete (§5a)",
                )
            )
            continue
        intent = FaceIntent.from_journal_entry(entry)
        if intent is None:
            refused.append((who, "journal entry carries no face identity to prove against"))
            continue
        proof_hash = entry.post_write_hash or intent.sha256

        live = read_face_row(reader, employee_no, page_size=page_size)
        calls += 1
        if live.state is RowState.ERROR:
            refused.append((who, f"proof-of-add read failed: {live.note} (§0.7)"))
            continue
        if live.state is RowState.ABSENT:
            absent.append(who)
            continue
        if live.state is not RowState.PRESENT or live.sha256 != proof_hash:
            refused.append(
                (
                    who,
                    f"proof-of-add FAILED: live hash {live.sha256} != journal "
                    f"{proof_hash} — the record changed after this run wrote it, so "
                    "someone else's edit wins and undo refuses (§5a)",
                )
            )
            continue

        before = count_face_rows(
            reader, page_size=page_size, inter_page_delay=inter_page_delay, sleep=sleep
        )
        calls += 1
        delete_entry = undo_journal.planned(
            employee_no=employee_no,
            classification="undo_delete",
            pre_write_record=live_metadata(live),
            intended_record={"employeeNo": employee_no, "removedSha256": proof_hash},
            op=OP_FACE_DELETE,
        )
        body = build_face_delete_body(employee_no)
        calls += 1
        try:
            ack = transport.call(
                "put_face_delete", FACE_DELETE_PATH, dict(FACE_DELETE_PARAMS), body
            )
            _require_ok_ack(ack, who)
        except WriteRejectedError as exc:
            undo_journal.rejected(delete_entry, sub_status=exc.sub_status)
            refused.append((who, f"delete rejected: {exc.sub_status or exc} (§0.6: not retried)"))
            continue
        undo_journal.applied(delete_entry)

        after = count_face_rows(
            reader, page_size=page_size, inter_page_delay=inter_page_delay, sleep=sleep
        )
        calls += 1
        deltas.append((who, before, after))
        dropped = before - after
        if dropped > 1:
            incident = (
                f"§5b COUNT-DELTA GUARD: the named list was ONE person ({who}) but the "
                f"face library dropped by {dropped} ({before} -> {after}). Treat as an "
                "incident: stop everything, restore from the pre-run bundle, escalate. "
                "Face deletes are capture-proven targeted, which is why this guard is "
                "mandatory anyway — the D-WIPE lesson is that this family answers ok "
                "while deleting what was not named."
            )
            undo_journal.rejected(delete_entry, sub_status="countDeltaGuard")
            raise FaceUndoIncidentError(incident, report(((who, incident),)))

        gone = read_face_row(reader, employee_no, page_size=page_size)
        calls += 1
        if gone.state is not RowState.ABSENT:
            undo_journal.rejected(delete_entry, sub_status="deleteNotApplied")
            refused.append(
                (who, f"named FPID still present after delete ({gone.state}: {gone.note})")
            )
            continue
        undo_journal.confirmed(delete_entry, post_write_hash=ABSENT_SHA)
        removed.append(who)

    return report()


# --- the composed faces phase (§5 step 2's "faces phase → verify faces") ---------------------


def apply_faces_phase(
    *,
    transport_factory: Callable[[], Any],
    journal_path: str | os.PathLike[str],
    writes: Sequence[FaceWrite],
    probe: CapabilityMatrix | None,
    now: Any,
    batch_size: int | None = None,
    sleep: Callable[[float], None] = time.sleep,
    batch_delay: float = 1.0,
    skipped: Sequence[tuple[str, str]] = (),
    confirm: bool = False,
) -> tuple[FacesPhaseResult, WriteJournal, FacesVerifyReport | None]:
    """Probe gate → journal → phase (pre-read, upload, read-back) → ledger closed.

    ``require_fresh`` runs first: §3/§0.3 forbid writing against a device we have not
    probed recently. The clock-skew gate (§5.1a) is the USERS phase's job and is not
    repeated here: a face template carries no wall-clock string, so a skewed clock cannot
    corrupt this phase's data — and per §5 step 2 the faces phase only ever runs inside
    an apply whose users phase already refused a lying clock.

    Confirmation is the phase's own read-back — the SAME comparison §6 asks for, recorded
    in the journal as ``confirmed`` with the post-write hash — which is why ``confirm``
    defaults to False: the card's budget is exactly 3 authed calls per person and a second
    walk would re-read, per person, what the journal already proved (§5.3). With
    ``confirm=True`` the caller asks for the independent §6 walker anyway (an audit run,
    or a long apply where post-phase drift matters), and that walk costs one FDSearch per
    touched person.
    """
    require_fresh(probe, now)  # ProbeStaleError is E1-03's contract, unchanged
    journal = WriteJournal.open(journal_path, phase="faces")
    budgeted = BudgetedWriteTransport(transport_factory)
    try:
        result = run_faces_phase(
            budgeted,
            journal,
            writes,
            batch_size=batch_size,
            sleep=sleep,
            batch_delay=batch_delay,
            skipped=skipped,
        )
        verify: FacesVerifyReport | None = None
        if confirm and writes:
            verify = verify_journal_faces(BudgetedFaceReader(budgeted), journal)
    finally:
        budgeted.close()  # §5.3: the phase owns its client; nothing writes on a closed one
    return result, journal, verify


def faces_report(
    result: FacesPhaseResult,
    journal: WriteJournal,
    *,
    undo: FacesUndoReport | None = None,
    verify: FacesVerifyReport | None = None,
) -> dict[str, Any]:
    """The PII-free run report (§4/§7's ``-o json``): hashes, counts and device words."""
    payload: dict[str, Any] = {
        "phase": "faces",
        "journal": str(journal.path),
        "writes": result.summary(),
        "journalStates": {
            state.value: sum(1 for e in journal.latest() if e.state is state)
            for state in JournalState
        },
    }
    if verify is not None:
        payload["verify"] = verify.summary()
    if undo is not None:
        payload["undo"] = undo.summary()
    return payload


def journal_fingerprint(journal: WriteJournal) -> str:
    """sha256 over the journal's folded state — lets a report reference a run by hash."""
    payload = json.dumps(
        [
            {
                "employee": e.employee_hash,
                "state": str(e.state),
                "op": e.op,
                "intendedHash": e.intended_hash,
                "postWriteHash": e.post_write_hash,
            }
            for e in journal.latest()
        ],
        sort_keys=True,
        separators=(",", ":"),
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()
