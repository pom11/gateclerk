"""E1-06b fingerprints phase: one-shot template port, ack-is-not-confirm, re-read verify.

Design contract: docs/internal/ENROLLMENT-MIGRATION.md — §5 step 2 (FP sits between cards and
faces), §5a (journal), §5b.1 (undo with no verb = REPORT-ONLY), §6 (read-back verify),
§1 "fingerprints" row (READ proven; portability claimable ONLY inside one sensor
family). Parent E1-04 owns the machinery this phase reuses — ``WriteJournal``,
``BudgetedWriteTransport``, ``classify_rejection``, ``person_hash``, the budget maths.
Nothing here forks them.

What bench A proved (docs/internal/OBSERVED.md "E1 §5.0 WRITE-PATH CAPTURE"; the fixtures under
``tests/fixtures/recorded/site-a-ds-k1t341amf-s/enrollment/`` are the truth, this
paragraph is a caption):

    fpdownload_accept_request.json      POST FingerPrintDownload {"FingerPrintCfg":{…}}
    fpdownload_accept_response.json     statusCode 1 / "ok" — the ACCEPT
    fpdownload_readback_still_nofp.json the SAME person's one-shot read after the accept
    fpdownload_progress_reader_reject.json  cardReaderRecvStatus 5, errorMsg "1"
    fpdownload_badjson_scalar_enable_400.json  scalar enableCardReader -> badJsonContent
    fpcfg_capabilities.json             the vocabulary source (fingerPrintID 1..10,
                                        fingerType @opt, cardReaderRecvStatus @opt 0..8)

**The headline the whole module is built around: an FP write ACK IS NOT A CONFIRM.**
Bench A answered `statusCode 1 ok` to the captured body and then never applied it —
read-back stayed `NoFP`, `numOfFP` stayed 0, and `FingerPrintProgress` said
`cardReaderRecvStatus:5` ("the attached reader rejected the template", the third-party
"301"-header family of §1). A `statusCode 1` for this verb is therefore worth *nothing*
(§6's rule on steroids). Consequences, in order of how much they hurt:

1. An entry reaches ``confirmed`` ONLY when the post-write one-shot read returns a
   template whose sha256 equals the journal's intended sha256. Never on the ack.
2. An accepted-but-not-applied write is journalled ``rejected`` with the device's own
   progress words in ``device_sub_status`` and classifies ``OTHER`` — the honest
   terminal state is "attempted, device-side application unverifiable/failed", not
   "applied".
3. The FIRST such non-applied answer ABORTS the phase (§5 step 4 fail-fast): a reader
   that rejects one third-party template rejects them all, and every further write is
   just spend of the auth budget (§0.5) buying a repeat of the same answer.
4. Verify (§6) re-reads every touched person by sha256; a mismatch after an ack is
   TERMINAL. That is the bench-A reality made structural, not a hypothesis.

Reads are one-shot per person: the capture proved ``FingerPrintUpload`` IGNORES
``fpIndex`` (0/1/2 all answered the identical row, ``fingerPrintID: 1``), so this phase
sends ONE definitive read per person — never a walk (PR #42's semantics, pinned so this
card cannot regress it). The honest zero is the device's own word: ``status:"NoFP"``
with ``FingerPrintList`` ABSENT. Any other listless answer is a protocol break (§0.7).

Same-sensor-family rule (§1, and the reason this port is not a general claim): the
bundle carries a ``sensor_family`` NOTE derived from the template's header bytes
(E1-01b). A template whose note is ABSENT is REFUSED — we refuse to port a template we
cannot even say was read from a family-matched sensor. The note travels on every report
line. Cross-family portability stays unclaimable until B/C evidence arrives; nothing
here softens that.

Undo: no FP delete verb was ever captured (OBSERVED.md: `FingerPrintCfg` GET/POST and
the delete caps are notSupport), so FP undo is REPORT-ONLY — "manual removal at the
device", exactly the users-phase position §5b.1 reached from the opposite direction.
This module contains no delete verb, no delete path, and no way to reach one; the card
pins that with a grep-style test.
"""

from __future__ import annotations

import base64
import hashlib
import os
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field, replace
from enum import StrEnum
from pathlib import Path
from typing import Any, Protocol

from gateclerk.exceptions import GateClerkError
from gateclerk.migrate_bundle import (
    FingerprintIndex,
    FingerprintTemplate,
    safe_template_stem,
)
from gateclerk.migrate_export import (
    FP_COND_KEY,
    FP_DATA_TYPE,
    FP_DEVICE_NO_FP,
    FP_ENVELOPE_KEY,
    FP_RECORD_KEY,
)
from gateclerk.migrate_probe import CapabilityMatrix
from gateclerk.migrate_write import (
    REBOOTSTRAP_AT_AUTHED_CALLS,
    BudgetedWriteTransport,
    JournalEntry,
    RejectKind,
    WriteJournal,
    WriteRejectedError,
    classify_rejection,
    person_hash,
)

__all__ = [
    "CAPTURED_FINGER_PRINT_ID",
    "CAPTURED_FP_COND_KEYS",
    "CARD_READER_RECV_REJECTED",
    "FP_CAPACITY_WORDS",
    "FP_DOWNLOAD_PATH",
    "FP_DOWNLOAD_RESPONSE_OK",
    "FP_PROGRESS_PATH",
    "FP_READ_PATH",
    "FP_TEMPLATE_KEYS",
    "FP_UNDO_REPORT_ONLY",
    "MAX_FINGER_PRINT_ID",
    "REBOOTSTRAP_AT_AUTHED_CALLS",
    "BudgetedWriteTransport",
    "FpAbortedError",
    "FpFleetReport",
    "FpPhaseResult",
    "FpProgress",
    "FpRead",
    "FpReadError",
    "FpReadOutcome",
    "FpShapeError",
    "FpTransport",
    "FpVerdictKind",
    "FpVerifyItem",
    "FpVerifyReport",
    "FpWrite",
    "SensorFamily",
    "apply_fingerprints_phase",
    "build_fingerprint_download_body",
    "classify_progress_rejection",
    "decode_template",
    "family_decision",
    "parse_fingerprint_progress",
    "parse_fingerprint_read",
    "plan_fingerprint_writes",
    "read_fingerprint_template",
    "report_only_fingerprint_undo",
    "run_fingerprints_phase",
    "template_bytes",
    "verify_fingerprints",
]

#: The captured WRITE endpoint (client→device; OBSERVED.md names the naming irony).
#: A constant like E1-04's ``USER_SETUP_PATH`` — the read-only registry in
#: ``gateclerk.endpoints`` stays exactly as ``tests/test_endpoints_registry.py`` pins it,
#: and this module issues zero requests by itself: the transport is injected.
FP_DOWNLOAD_PATH = "/ISAPI/AccessControl/FingerPrintDownload"

#: The captured READ endpoint (device→client despite the name, §1). Registered, and
#: reached through an injected read seam — the same POST the export uses.
FP_READ_PATH = "/ISAPI/AccessControl/FingerPrintUpload"

#: The captured PROGRESS endpoint (GET, `?format=json`) — the only device surface that
#: admits an accepted template was never applied (OBSERVED.md "Fingerprints WRITE").
FP_PROGRESS_PATH = "/ISAPI/AccessControl/FingerPrintProgress"

#: The captured request key set (`fpdownload_accept_request.json`). Membership is what
#: makes a write legal; ``enableCardReader`` must be an ARRAY of reader numbers (the
#: scalar spelling 400s `badJsonContent`, errorMsg `enableCardReader` — the fixture
#: that pins it) and ``fingerPrintID`` — not ``fpIndex`` — is the slot key.
FP_TEMPLATE_KEYS: frozenset[str] = frozenset(
    {"enableCardReader", "employeeNo", "fingerPrintID", "fingerType", "fingerData"}
)

#: `fpcfg_capabilities.json`: fingerPrintID @min 1 @max 10. A captured bound, so
#: enforcing it is vocabulary enforcement (§5 step 3's caps-as-vocabulary rule), not a
#: capacity claim (§1: `maxRecordNum`-style maxima are never read as capacity).
MAX_FINGER_PRINT_ID = 10

#: The capture's constant: bench A answers `fingerPrintID: 1` for the one template a
#: person has (OBSERVED.md "FingerPrintUpload READ ignores fpIndex"). Writing anything
#: else would be writing to a slot no capture ever read — an unrecorded shape (§9).
CAPTURED_FINGER_PRINT_ID = 1

#: The ack this verb answers when it accepts (`fpdownload_accept_response.json`).
#: Named exactly like E1-04's constant and used for exactly one thing: deciding
#: whether to journal `applied`. It NEVER implies the template landed — see the
#: module docstring, and note that the constant's name is the bug this card exists to
#: kill ("ack is not confirm").
FP_DOWNLOAD_RESPONSE_OK = 1

#: `fpcfg_capabilities.json` StatusList.cardReaderRecvStatus @opt is "0,…,8", but only
#: ONE value has ever been OBSERVED: 5, the reader's rejection of a template it would
#: not enrol. §9's no-inference rule (and this firmware's caps UNDER-claiming, §1)
#: forbid mapping the other seven from a range declaration, so every observed value
#: stays verbatim and only 5 carries a note. `classify_progress_rejection` is where a
#: second capture could add a mapping — a constant would be a guess.
CARD_READER_RECV_REJECTED = 5

_READER_REJECTION_NOTE = (
    "the attached card reader refused the template (bench A: third-party 301-header "
    "family, §1) — the API acked, the device never enrolled it"
)

#: Capacity-class device words. §1's captured vocabulary: `NoFP` is the device's own
#: honest zero on the FP read; `notSupport` is the only captured "this firmware does
#: not do that" word. Neither is a rejection of OUR body, and both stay OTHER-class
#: unless a capture names them otherwise (card rule 2).
FP_CAPACITY_WORDS: frozenset[str] = frozenset({"noFP", "notSupport"})


# --- errors -------------------------------------------------------------------------------


class FpShapeError(GateClerkError):
    """We were asked to build a FingerPrintDownload body the capture does not authorise.

    Raised before any request leaves the process (§9: a shape absent from the fixtures
    has no device truth, so we refuse it rather than let the device discover it).
    """


class FpReadError(GateClerkError):
    """A one-shot FP read answered something this card has no device truth for.

    §0.7: a failed or unrecognised read is an ERROR, never "the person has no finger".
    The captured protocol break is `statusCode 6 / subStatusCode
    "MessageParametersLack" / errorMsg "FingerPrintCond"` — the wrapper form — and the
    honest zero is `status:"NoFP"` with the record list ABSENT; the two must never be
    collapsed into the same outcome.
    """


class FpAbortedError(GateClerkError):
    """The FP phase aborted. Carries the result so the caller can print what landed.

    §5 step 4: never a silent partial write. The abort reason is always either a device
    answer (accepted-not-applied, a rejection) or a rule this module owns (the
    sensor-family refusal). ``result`` is the phase's :class:`FpPhaseResult` from
    :func:`run_fingerprints_phase`, or the composed :class:`FpFleetReport` when the
    abort surfaced out of :func:`apply_fingerprints_phase` — either way it lists which
    persons landed and which are in unknown state.
    """

    def __init__(self, message: str, result: Any = None) -> None:
        self.result = result
        super().__init__(message)


# --- the read: one shot per person, three honest answers ---------------------------------


class FpReadOutcome(StrEnum):
    """What ONE definitive FP read said about one person."""

    #: A template row (sha256 over the decoded bytes) — the device has it.
    PRESENT = "present"
    #: `status:"NoFP"` with `FingerPrintList` ABSENT — the device's OWN zero word.
    NO_FP = "no_fp"


@dataclass(frozen=True, slots=True)
class FpRead:
    """One person's one-shot read result (opaque bytes; never parsed, §2)."""

    employee_no: str
    outcome: FpReadOutcome
    #: sha256 over the DECODED template bytes (transport bookkeeping, not parsing).
    sha256: str = ""
    length: int = 0
    #: the device's base64 VERBATIM — what gets re-sent on a port, byte-identical.
    finger_data: str = ""
    #: `fingerPrintID` the row carried (captured constant 1; anything else is refused
    #: by `parse_fingerprint_read`, exactly like the export's own guard).
    finger_print_id: str = ""
    #: `status` verbatim, so a report can quote the device rather than paraphrase it.
    device_status: str = ""


def decode_template(finger_data: str, *, employee_no: str) -> tuple[bytes, str]:
    """Strict base64 → (bytes, sha256). Decoding to hash is transport, not parsing.

    The same rule E1-01b's export applies to the bytes it writes into the bundle: the
    payload is never interpreted; whitespace is tolerated (some firmwares wrap), and
    anything that fails ``validate=True`` raises rather than travelling as "probably
    fine" (§0.7).
    """
    if not isinstance(finger_data, str) or not finger_data.strip():
        raise FpReadError(
            f"employeeNo {employee_no!r}: fingerData is empty — a row that claims a "
            "template with no bytes is a protocol break, not a zero (§0.7)"
        )
    compact = "".join(finger_data.split())
    try:
        raw = base64.b64decode(compact, validate=True)
    except Exception as exc:  # binascii.Error is a ValueError subclass
        raise FpReadError(
            f"employeeNo {employee_no!r}: fingerData is not clean base64 ({exc.__class__.__name__})"
        ) from exc
    if not raw:
        raise FpReadError(
            f"employeeNo {employee_no!r}: fingerData decodes to zero bytes — refusing "
            "to journal an empty template as 'enrolled' (§0.7)"
        )
    return raw, hashlib.sha256(raw).hexdigest()


def parse_fingerprint_read(employee_no: str, response: Mapping[str, Any]) -> FpRead:
    """One definitive answer for one person, or a raising `FpReadError`.

    Three-way fail-closed (mirrors `migrate_export.export_fingerprints`, which had the
    same conversation with the same device):

    * envelope + one row + ``fingerPrintID == 1``  ->  :attr:`FpReadOutcome.PRESENT`;
    * ``status:"NoFP"`` with the list ABSENT (or empty)  ->  :attr:`FpReadOutcome.NO_FP`
      — the only listless answer the capture authorises as "zero";
    * everything else (missing envelope, multi-row answer, a ``fingerPrintID`` the
      capture never answered, a listless answer with any other status word) raises.
      A different ``fingerPrintID`` would mean ``fpIndex`` means something on THAT box
      that it does not mean on bench A — a fact we do not have, so we stop instead of
      porting a guess or claiming one read covers a multi-finger person.
    """
    info = response.get(FP_ENVELOPE_KEY)
    if not isinstance(info, Mapping):
        raise FpReadError(
            f"employeeNo {employee_no!r}: response carries no {FP_ENVELOPE_KEY!r} "
            "envelope — reading a protocol break as 'no fingerprint' is the silence "
            "§0.7 refuses"
        )
    status = str(info.get("status") or "")
    rows = info.get(FP_RECORD_KEY)
    if rows is None or rows == []:
        if status == FP_DEVICE_NO_FP:
            return FpRead(
                employee_no=employee_no,
                outcome=FpReadOutcome.NO_FP,
                device_status=status,
            )
        raise FpReadError(
            f"employeeNo {employee_no!r}: no {FP_RECORD_KEY} and status {status!r} "
            f"is not the captured zero word {FP_DEVICE_NO_FP!r} — refusing to read an "
            "unknown answer as 'no fingerprints' (§0.7)"
        )
    if not isinstance(rows, list) or len(rows) != 1:
        raise FpReadError(
            f"employeeNo {employee_no!r}: {FP_RECORD_KEY} is "
            f"{type(rows).__name__} with "
            f"{len(rows) if isinstance(rows, list) else '?'} row(s); the probed shape "
            "is exactly one (OBSERVED.md) — refusing to guess which row is the "
            "person's"
        )
    row = rows[0]
    if not isinstance(row, Mapping):
        raise FpReadError(f"employeeNo {employee_no!r}: row is {type(row).__name__}, not an object")
    finger_print_id = str(row.get("fingerPrintID"))
    if finger_print_id != str(CAPTURED_FINGER_PRINT_ID):
        raise FpReadError(
            f"employeeNo {employee_no!r}: answered fingerPrintID "
            f"{row.get('fingerPrintID')!r}; bench A always answers "
            f"{CAPTURED_FINGER_PRINT_ID} (capture 2026-10-22) — multi-finger reads on "
            "this shape are UNPROVEN, not silently one-finger"
        )
    raw, digest = decode_template(str(row.get("fingerData") or ""), employee_no=employee_no)
    return FpRead(
        employee_no=employee_no,
        outcome=FpReadOutcome.PRESENT,
        sha256=digest,
        length=len(raw),
        finger_data=str(row["fingerData"]),
        finger_print_id=finger_print_id,
        device_status=status,
    )


FpReader = Callable[[Mapping[str, Any]], Mapping[str, Any]]


def read_fingerprint_template(employee_no: str, reader: FpReader) -> FpRead:
    """The one-shot read (`POST FingerPrintUpload?format=json`, captured body).

    The body carries ``fpIndex`` because the capture's captured body carries it — the
    device IGNORES its value (OBSERVED.md: 0/1/2 answered identically), and the fake
    pins that non-regression rather than letting this card "optimise" the field away.
    The wrapper is required (a plain body 400s ``MessageParametersLack``
    ``FingerPrintCond``, §1); a raising reader is a failure, never a zero (§0.7).
    """
    from gateclerk.paging import new_search_id

    body = {
        FP_COND_KEY: {
            "searchID": new_search_id(),
            "employeeNo": employee_no,
            "fpIndex": 0,
            "dataType": FP_DATA_TYPE,
        }
    }
    try:
        response = reader(body)
    except FpReadError:
        raise
    except Exception as exc:
        raise FpReadError(
            f"employeeNo {employee_no!r}: one-shot FingerPrintUpload read failed "
            f"({type(exc).__name__}: {exc}); a failed read is never 'no fingerprint' "
            "(§0.7)"
        ) from exc
    if not isinstance(response, Mapping):
        raise FpReadError(
            f"employeeNo {employee_no!r}: the read answered {type(response).__name__}, "
            "not a JSON object — refusing to verdict from an unreadable answer (§0.7)"
        )
    return parse_fingerprint_read(employee_no, response)


# --- the progress surface: the only honest word about an ack ------------------------------


@dataclass(frozen=True, slots=True)
class FpProgress:
    """What `GET FingerPrintProgress?format=json` answered, in the device's own words."""

    #: every `cardReaderRecvStatus` value the answer carried (ints, verbatim).
    recv_status: tuple[int, ...] = ()
    #: every `errorMsg` verbatim (bench A answered the string "1" — not a code we map).
    error_msg: tuple[str, ...] = ()
    #: `totalStatus` verbatim, when present.
    total_status: str = ""
    #: the device words flattened for the journal/report (`cardReaderRecvStatus=5 errorMsg=1`).
    words: str = ""

    @property
    def rejected(self) -> bool:
        """True when any row carries the ONE observed rejection value (§9 note above)."""
        return CARD_READER_RECV_REJECTED in self.recv_status


def parse_fingerprint_progress(response: Mapping[str, Any]) -> FpProgress:
    """Flatten the captured `FingerPrintStatus.StatusList` shape, values verbatim.

    Nothing here interprets a status number: `errorMsg` on bench A was the string
    "1", which is not a code this repo has any meaning for. Reporting it verbatim is
    the §6 rule ("verify, never infer") applied to the one surface that tells the
    truth about an FP write.
    """
    status = response.get("FingerPrintStatus")
    if not isinstance(status, Mapping):
        return FpProgress(words=f"(no {FP_PROGRESS_PATH} answer in the response body)")
    rows = status.get("StatusList")
    rows = rows if isinstance(rows, list) else []
    recv: list[int] = []
    errors: list[str] = []
    for row in rows:
        if not isinstance(row, Mapping):
            continue
        value = row.get("cardReaderRecvStatus")
        if isinstance(value, bool):
            value = None
        if isinstance(value, int):
            recv.append(value)
        message = row.get("errorMsg")
        if message is not None:
            errors.append(str(message))
    words = " ".join(
        [f"cardReaderRecvStatus={v}" for v in recv] + [f"errorMsg={m}" for m in errors]
    )
    return FpProgress(
        recv_status=tuple(recv),
        error_msg=tuple(errors),
        total_status=str(status["totalStatus"]) if "totalStatus" in status else "",
        words=words or "no StatusList rows",
    )


def classify_progress_rejection(progress: FpProgress) -> tuple[RejectKind, str]:
    """Classify what the progress surface said: class + the device's words to journal.

    Card rule 2: `noFP`/`notSupport`-class answers and reader rejections classify
    OTHER unless a capture maps them otherwise — the progress vocabulary has never been
    mapped by any capture, so every answer is OTHER and the words ride along verbatim.
    A known rejection value additionally carries the note OBSERVED.md recorded for it.
    """
    words = progress.words
    if progress.rejected:
        words = (
            f"{words} (cardReaderRecvStatus={CARD_READER_RECV_REJECTED}: {_READER_REJECTION_NOTE})"
        )
    return RejectKind.OTHER, words


# --- the write body: exactly the captured shape --------------------------------------------


def build_fingerprint_download_body(write: FpWrite) -> dict[str, Any]:
    """The ``{"FingerPrintCfg": {…}}`` body — EXACTLY `fpdownload_accept_request.json`.

    Fail-closed in five places, all before a byte could leave the process:

    1. **Key set.** The five captured keys, no more and no fewer. ``fpIndex`` is
       specifically refused: the capture made ``fingerPrintID`` the slot key, and the
       fake answers the substitution with the captured 400 the way it answers the
       scalar below. ``mode`` is refused too — the captured body has none, and this
       verb's caps (`fpcfg_capabilities.json`) never showed one.
    2. **``enableCardReader`` is an ARRAY of ints** (list of reader numbers,
       OBSERVED.md). A scalar — int or string — is the exact mistake that 400'd
       `badJsonContent` with `errorMsg:"enableCardReader"`
       (`fpdownload_badjson_scalar_enable_400.json`); catching it here is cheaper than
       letting the device spend a budget call saying it.
    3. **``fingerType`` required**, and validated against `fpcfg_capabilities.json`'s
       ``fingerType @opt`` when the probe carries that caps document (§5 step 3's
       caps-are-the-vocabulary-source rule, same shape as E1-04's `_check_vocabulary`).
    4. **``fingerPrintID`` = the captured constant 1**, inside the caps' 1..10 range.
       Writing another slot would be writing where no capture ever read.
    5. **``fingerData`` is the bundle's base64 VERBATIM** — never re-encoded, never
       re-wrapped (opaque payload, §2; the same discipline faces use for `modelData`).
    """
    record = write.template
    unknown = sorted(set(record) - FP_TEMPLATE_KEYS)
    if unknown:
        raise FpShapeError(
            f"cannot build a captured FingerPrintDownload body: {unknown} is not in the "
            f"captured key set {sorted(FP_TEMPLATE_KEYS)} "
            "(fpdownload_accept_request.json). `fpIndex` in particular is NOT the slot "
            "key — `fingerPrintID` is (capture 2026-10-22) — and an unrecorded key is "
            "the R2 partial-merge risk (§9 capture-before-fake)"
        )
    missing = sorted(FP_TEMPLATE_KEYS - set(record))
    if missing:
        raise FpShapeError(
            f"cannot build a captured FingerPrintDownload body: missing {missing}; the "
            "capture carries all five keys and a thinner body is an unrecorded shape"
        )

    readers = record["enableCardReader"]
    if (
        not isinstance(readers, list)
        or not readers
        or any(isinstance(v, bool) or not isinstance(v, int) for v in readers)
    ):
        raise FpShapeError(
            f"enableCardReader must be an ARRAY of reader numbers (the capture's body "
            f"is [1]); {readers!r} is the scalar spelling the device 400'd as "
            "badJsonContent/errorMsg=enableCardReader "
            "(fpdownload_badjson_scalar_enable_400.json)"
        )

    finger_type = record["fingerType"]
    if not isinstance(finger_type, str) or not finger_type:
        raise FpShapeError(
            f"fingerType {finger_type!r} is missing or empty; the capture carries "
            '"normalFP" and the field is required'
        )

    slot = record["fingerPrintID"]
    if isinstance(slot, bool) or not isinstance(slot, int):
        raise FpShapeError(
            f"fingerPrintID {slot!r} must be an int; the capture carries {CAPTURED_FINGER_PRINT_ID}"
        )
    if slot != CAPTURED_FINGER_PRINT_ID:
        raise FpShapeError(
            f"fingerPrintID {slot} names a slot no capture ever read; bench A answered "
            f"only {CAPTURED_FINGER_PRINT_ID} (OBSERVED.md 2026-10-22) — writing an "
            "unproven slot is an unrecorded shape, not a small optimisation"
        )
    if slot < 1 or slot > MAX_FINGER_PRINT_ID:
        raise FpShapeError(
            f"fingerPrintID {slot} is outside the captured caps range 1..{MAX_FINGER_PRINT_ID} "
            "(fpcfg_capabilities.json)"
        )

    finger_data = record["fingerData"]
    if not isinstance(finger_data, str) or not finger_data.strip():
        raise FpShapeError(
            "fingerData is empty — there is nothing to port; refusing to send an "
            "empty template (opaque payload, §2)"
        )

    employee_no = record["employeeNo"]
    if not isinstance(employee_no, str) or not employee_no:
        raise FpShapeError(f"employeeNo {employee_no!r} must be the device's opaque string (§1)")

    _check_finger_type_vocabulary(finger_type, write.probe)
    body = {
        "FingerPrintCfg": {
            "enableCardReader": list(readers),
            "employeeNo": employee_no,
            "fingerPrintID": slot,
            "fingerType": finger_type,
            "fingerData": finger_data,
        }
    }
    _assert_capture_shape(body, write)
    return body


def _check_finger_type_vocabulary(finger_type: str, probe: CapabilityMatrix | None) -> None:
    """fingerType against the caps `@opt` when the probe carries the FP caps document."""
    if probe is None:
        return
    caps = probe.caps_raw.get("caps_fingerprint_cfg")
    section = caps.get("FingerPrintCfg") if isinstance(caps, Mapping) else None
    if not isinstance(section, Mapping):
        return
    opt = section.get("fingerType")
    opts = opt.get("@opt") if isinstance(opt, Mapping) else None
    if not isinstance(opts, str) or not opts.strip():
        return
    allowed = {part.strip() for part in opts.split(",") if part.strip()}
    if allowed and finger_type not in allowed:
        raise FpShapeError(
            f"fingerType={finger_type!r} is outside the vocabulary THIS device claimed "
            f"for it ({sorted(allowed)}); caps are the vocabulary source "
            "(fpcfg_capabilities.json) — refusing to write a value the target says it "
            "does not accept (§3)"
        )


def _assert_capture_shape(body: dict[str, Any], write: FpWrite) -> None:
    """Byte-shape lock: our body must be the capture body modulo data substitution.

    `fpdownload_accept_request.json` is the contract; this proves the *shape* (key set,
    nesting, types) rather than the literal test-person bytes, so a drift in either
    direction fails at build time. The expected shape is the embedded
    ``CAPTURED_FP_COND_KEYS`` tuple, never a file read: this guard runs on the *installed*
    product, and wheels, containers and zipapps do not ship ``tests/`` (GC-P02). The
    fixture is still the authority — ``tests/test_gc_p02_fp_schema.py`` pins this tuple to
    it, so a renamed or drifted capture breaks a test instead of quietly becoming
    folklore (the fake's `_capture()` rule, applied on the product side).
    """
    expected = CAPTURED_FP_COND_KEYS
    cfg = body["FingerPrintCfg"]
    if set(cfg) != set(expected):
        raise FpShapeError(
            f"body key set {sorted(cfg)} drifted from the capture {sorted(expected)} "
            "— the capture is the contract, not a suggestion"
        )
    if not isinstance(cfg["enableCardReader"], list):  # belt; checked above too
        raise FpShapeError("enableCardReader left the builder as a non-array")
    if write.finger_data_b64 != cfg["fingerData"]:
        raise FpShapeError(
            "the fingerData leaving this module is not the bundle's verbatim base64 — "
            "templates are opaque payloads (§2) and are never re-encoded on the way to "
            "a device"
        )


#: The captured FingerPrintCfg key set (fixture:
#: tests/fixtures/recorded/site-a-ds-k1t341amf-s/enrollment/fpdownload_accept_request.json).
#: Embedded, not read at runtime: wheels, containers and zipapps do not ship tests/.
CAPTURED_FP_COND_KEYS: tuple[str, ...] = (
    "employeeNo",
    "enableCardReader",
    "fingerPrintID",
    "fingerType",
    "fingerData",
)


# --- planning: sensor family first, then the one-shot read --------------------------------


class SensorFamily(StrEnum):
    """How the bundle's header-bytes note classifies for the port decision (§1).

    The NOTE is E1-01b's label about the template's leading bytes ("301-header
    (third-party sensor family, not self-identified…)" or "unknown (header is not the
    recorded 301 family)"). This enum is a decision about *portability*, never a claim
    about what the bytes are:

    * ABSENT — the bundle carries no note: the export never recorded what family
      produced these bytes, so the same-family rule (§1) cannot be satisfied even in
      principle. **Refused**, per the card rule.
    * CLAIMED — a note exists, so the port may be *attempted*; the claim itself rests
      on header bytes (and, on a target whose probe carries FP caps, that document —
      reported, never silently assumed). Cross-family portability stays UNCLAIMABLE
      until B/C evidence; the bench-A reader's rejection is the standing proof of why
      the report line says "claimed", not "matches".
    """

    #: No note at all: the bundle never read this person's template. Refused.
    ABSENT = "absent"
    #: The note exists: attempt allowed, family reported on every line as a CLAIM.
    CLAIMED = "claimed"


@dataclass(frozen=True, slots=True)
class FpWrite:
    """One person this phase may port, plus the evidence the rules above require."""

    employee_no: str
    employee_hash: str
    #: the five captured keys, the template values verbatim from the bundle file.
    template: Mapping[str, Any]
    #: the bundle's base64 exactly as the device sent it (compare target of §6).
    finger_data_b64: str
    #: sha256 over the decoded template — the intended hash the journal carries.
    intended_sha256: str
    #: the bundle's sensor-family NOTE (never empty for a planned write).
    sensor_family: str
    family: SensorFamily = SensorFamily.CLAIMED
    probe: CapabilityMatrix | None = None
    #: `fingerPrintID` this write targets (always the captured constant 1).
    finger_print_id: int = CAPTURED_FINGER_PRINT_ID


@dataclass(frozen=True, slots=True)
class _FamilyDecision:
    kind: SensorFamily
    reason: str


def family_decision(entry: FingerprintTemplate, probe: CapabilityMatrix | None) -> _FamilyDecision:
    """Decide whether one bundle template may be ported at all (§1, card rule 5).

    The refusal condition is exactly the card's: NO family note => refuse. With a
    note, the port may be attempted and the family is reported on every line — the
    target-side evidence situation (this probe carries the `FingerPrintCfg` caps
    document or not) is appended to the reason as context, never as a silent gate:
    §1's cross-family claim stays unclaimable either way, and a gate that no real
    probe can satisfy would only hide the phase's honest failure behind a plan-time
    skip (the bench-A reader rejection is the finding; it must SURFACE).
    """
    note = (entry.sensor_family or "").strip()
    if not note:
        return _FamilyDecision(
            SensorFamily.ABSENT,
            "no sensor-family NOTE in the bundle for this template — the export never "
            "recorded what sensor family produced these bytes, so the same-family rule "
            "(§1) cannot be satisfied even in principle; port refused",
        )
    caps = probe.caps_raw.get("caps_fingerprint_cfg") if probe is not None else None
    extra = (
        "target probe carries the FingerPrintCfg caps document (vocabulary evidence)"
        if isinstance(caps, Mapping) and isinstance(caps.get("FingerPrintCfg"), Mapping)
        else "no target FingerPrintCfg caps in the probe: the family claim rests on "
        "source header bytes alone and is reported as CLAIMED, never as MATCHED (§1)"
    )
    return _FamilyDecision(
        SensorFamily.CLAIMED,
        f"family note {note!r}; {extra} — cross-family portability is NOT claimed "
        "until B/C evidence exists (§1)",
    )


def template_bytes(bundle_dir: str | os.PathLike[str], entry: FingerprintTemplate) -> str:
    """The bundle's base64 for one INDEX entry — verbatim, exactly as E1-01b wrote it.

    The bundle reader (`read_bundle`) already proved these bytes match the INDEX
    sha256/length; re-decoding here is the same transport bookkeeping, never a parse.
    """
    path = (
        Path(bundle_dir)
        / "fingerprints"
        / f"{safe_template_stem(entry.employee_no)}-{entry.fp_index}.b64"
    )
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise FpShapeError(
            f"fingerprints/{path.name} is not readable ({exc}) — an AVAILABLE index "
            "entry without its file is a half-present bundle, refused not patched"
        ) from exc
    return text.strip()


def plan_fingerprint_writes(
    *,
    bundle_dir: str | os.PathLike[str],
    fingerprints: FingerprintIndex,
    employee_nos: Sequence[str],
    probe: CapabilityMatrix | None = None,
    finger_print_id: int = CAPTURED_FINGER_PRINT_ID,
    enable_card_reader: Sequence[int] = (1,),
) -> tuple[tuple[FpWrite, ...], tuple[tuple[str, str], ...]]:
    """(portable templates, report-only skips) — a BUNDLE-ONLY pass, zero device calls.

    Deliberately device-free: the target is read FRESH at execution time (§4's
    freshness contract — a plan-time target view is exactly the TOCTOU hole the design
    closes), so this pass answers only the questions a bundle can answer:

    1. INDEX state must be AVAILABLE: an UNAVAILABLE index never read anyone, and
       "never read" is not "has no finger" (§0.7).
    2. the sensor-family NOTE must exist (card rule 5: absent note => REFUSE); the
       claim's evidential basis goes into the report line, not into a silent filter.
    3. the .b64 file must exist and still match the INDEX sha256/length — a rollback
       source that cannot vouch for its own bytes is refused, not ported (§0.7).
    4. the captured body shape must build from these values (fail-fast per-person:
       one malformed template skips ITSELF, it never blocks the operator's table).

    The one-shot read-BEFORE (already_present skip / different-hash conflict) happens
    in :func:`run_fingerprints_phase`, at write time, exactly where §4's freshness
    contract puts it.
    """
    if fingerprints.state != "AVAILABLE":
        return (), (
            (
                "*",
                f"fingerprints_index_{fingerprints.state.lower()}: {fingerprints.reason} "
                "— an index that never ran is not a zero (§0.7); nothing is portable",
            ),
        )
    if finger_print_id != CAPTURED_FINGER_PRINT_ID:
        raise FpShapeError(
            f"finger_print_id={finger_print_id} is not the captured constant "
            f"{CAPTURED_FINGER_PRINT_ID} (OBSERVED.md 2026-10-22) — the phase refuses "
            "to write an unrecorded slot"
        )

    wanted = [str(no) for no in employee_nos]
    by_no: dict[str, FingerprintTemplate] = {}
    for entry in fingerprints.entries:
        by_no.setdefault(entry.employee_no, entry)

    writes: list[FpWrite] = []
    skipped: list[tuple[str, str]] = []
    for employee_no in wanted:
        entry = by_no.get(employee_no)
        if entry is None:
            continue  # honest zero: the AVAILABLE walk said NoFP for this person
        decision = family_decision(entry, probe)
        if decision.kind is not SensorFamily.CLAIMED:
            skipped.append((person_hash(employee_no), f"family_refused:{decision.reason}"))
            continue
        try:
            b64 = template_bytes(bundle_dir, entry)
            raw, digest = decode_template(b64, employee_no=employee_no)
        except (FpShapeError, FpReadError) as exc:
            skipped.append((person_hash(employee_no), f"bundle_unreadable:{exc}"))
            continue
        if digest != entry.sha256 or len(raw) != entry.length:
            skipped.append(
                (
                    person_hash(employee_no),
                    "bundle_digest_drift: the .b64 file no longer matches the INDEX "
                    f"({len(raw)} B / sha {digest[:12]} vs {entry.length} B / sha "
                    f"{entry.sha256[:12]}) — a rollback source that cannot vouch for "
                    "its own bytes is refused, not ported (§0.7)",
                )
            )
            continue
        template = {
            "enableCardReader": [int(v) for v in enable_card_reader],
            "employeeNo": employee_no,
            "fingerPrintID": finger_print_id,
            "fingerType": "normalFP",  # the captured value; validated against caps below
            "fingerData": b64,
        }
        write = FpWrite(
            employee_no=employee_no,
            employee_hash=person_hash(employee_no),
            template=template,
            finger_data_b64=b64,
            intended_sha256=digest,
            sensor_family=entry.sensor_family,
            family=decision.kind,
            probe=probe,
            finger_print_id=finger_print_id,
        )
        try:
            build_fingerprint_download_body(write)
        except FpShapeError as exc:
            skipped.append((person_hash(employee_no), f"shape_refused:{exc}"))
            continue
        writes.append(write)
    return tuple(writes), tuple(skipped)


# --- §5a journal shape for this phase -------------------------------------------------------


def _fp_intended_record(write: FpWrite) -> dict[str, Any]:
    """What the journal carries as this person's "intended record" (§5a/§9).

    Not a device body: the body is a projection of this (exactly the E1-04 lesson —
    verify compares the source READ-shape, never the write shape). ``fingerData`` is
    the bundle's base64, which is already in the bundle the operator holds, so the
    journal leaks nothing the bundle does not already hold (§9); ``password`` can never
    appear here because the key set is fixed by the capture.
    """
    return {
        "employeeNo": write.employee_no,
        "fingerPrintID": write.finger_print_id,
        "fingerType": str(write.template["fingerType"]),
        "fingerData": write.finger_data_b64,
        "sensorFamily": write.sensor_family,
        "templateSha256": write.intended_sha256,
    }


# --- the phase --------------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class FpPhaseResult:
    """What the FP phase did — the artifact §5 step 4 demands on an abort."""

    planned: tuple[str, ...] = ()  # employee hashes, in send order
    applied: tuple[str, ...] = ()  # device answered statusCode 1 (worthless, see above)
    confirmed: tuple[str, ...] = ()  # the ONLY honest success: post-read sha match
    rejected: tuple[tuple[str, RejectKind, str | None], ...] = ()  # hash, kind, words
    skipped: tuple[tuple[str, str], ...] = ()  # hash, reason (report-only classes)
    aborted: bool = False
    abort_reason: str | None = None
    writes_sent: int = 0
    reads_sent: int = 0
    progress_reads: int = 0
    rebootstraps: int = 0

    @property
    def landed(self) -> tuple[str, ...]:
        """Persons the post-write read CONFIRMED by sha.

        Deliberately NOT ``applied``: on bench-A evidence an ack is not a landing, and
        the name that says "the device took it" is how this bug class ships.
        """
        return self.confirmed

    @property
    def clean(self) -> bool:
        return not self.aborted and not self.rejected

    def summary(self) -> dict[str, Any]:
        """PII-free report payload (§4: hashes, counts, device words — never names)."""
        return {
            "planned": len(self.planned),
            "acknowledged": len(self.applied),
            "confirmed": len(self.confirmed),
            "rejected": [
                {"employee": h, "kind": str(kind), "deviceWords": words}
                for h, kind, words in self.rejected
            ],
            "skipped": [{"employee": h, "reason": r} for h, r in self.skipped],
            "writesSent": self.writes_sent,
            "readsSent": self.reads_sent,
            "progressReads": self.progress_reads,
            "rebootstraps": self.rebootstraps,
            "aborted": self.aborted,
            "abortReason": self.abort_reason,
            "ackIsNotConfirm": (
                "statusCode 1 on this verb means the API parsed the body, not that the "
                "reader enrolled it — bench A acked and enrolled nothing (OBSERVED.md "
                "§5.0); only a post-write read by sha256 counts"
            ),
        }


@dataclass(slots=True)
class _FpTally:
    applied: list[str] = field(default_factory=list)
    confirmed: list[str] = field(default_factory=list)
    rejected: list[tuple[str, RejectKind, str | None]] = field(default_factory=list)
    writes_sent: int = 0
    reads_sent: int = 0
    progress_reads: int = 0

    def result(
        self,
        *,
        planned: Sequence[str],
        skipped: Sequence[tuple[str, str]],
        rebootstraps: int,
        aborted: bool,
        abort_reason: str | None,
    ) -> FpPhaseResult:
        return FpPhaseResult(
            planned=tuple(planned),
            applied=tuple(self.applied),
            confirmed=tuple(self.confirmed),
            rejected=tuple(self.rejected),
            skipped=tuple(skipped),
            aborted=aborted,
            abort_reason=abort_reason,
            writes_sent=self.writes_sent,
            reads_sent=self.reads_sent,
            progress_reads=self.progress_reads,
            rebootstraps=rebootstraps,
        )


class FpTransport(Protocol):
    """The injected FP seam (module docstring: no socket reachable from here).

    Implements the two verbs THIS phase owns on their captured paths: POST the download
    and GET the progress surface. The READ seam is separate (:data:`FpReader`, a
    registry-guarded search POST) because the read is a read — it stays on the
    read-only client, exactly as E1-04's verify walker keeps its reader apart from its
    writer. Implementations raise :class:`WriteRejectedError` for a non-OK envelope; a
    transport-level failure raises its own client vocabulary and aborts the phase.
    """

    def post_download(self, path: str, body: Mapping[str, Any]) -> dict[str, Any]:
        """POST one FingerPrintDownload body, return the parsed ack (raise on rejection)."""
        ...  # pragma: no cover - protocol

    def get_progress(self, path: str) -> dict[str, Any]:
        """GET the progress surface and return its parsed body (raise on transport error)."""
        ...  # pragma: no cover - protocol

    def put_setup(self, path: str, body: Mapping[str, Any]) -> dict[str, Any]:
        """Satisfies :class:`gateclerk.migrate_write.WriteTransport` structurally.

        This phase never calls it. The budget class is shared with the users phase
        (parent-card instruction: reuse, do not fork) and its Protocol names
        ``put_setup``; an FP transport states that it could answer the verb and simply
        never gets asked — see :meth:`gateclerk.migrate_write.BudgetedWriteTransport.call`.
        """
        ...  # pragma: no cover - protocol

    def close(self) -> None:
        """Release the underlying client (the re-bootstrapped budget starts fresh)."""
        ...  # pragma: no cover - protocol


def _progress_snapshot(transport: BudgetedWriteTransport, tally: _FpTally) -> FpProgress:
    """The device's own progress answer, pulled on a write-failure path only (budget 1).

    §5.3's worst-case-per-person maths counts the progress probe as part of the FP
    phase, so it is fetched ONLY where the write did not land — a phase that spent it
    on every person would be the auth-budget leak §0.5 names, for a field the ack
    already told us was worthless. A failing progress read does not mask the real
    failure: the answer becomes an :class:`FpProgress` that says so, and the phase
    reports what it can (§0.7: silence is never an answer).
    """
    tally.progress_reads += 1
    try:
        body = transport.call("get_progress", FP_PROGRESS_PATH)
    except Exception as exc:
        return FpProgress(words=f"(progress read failed: {type(exc).__name__}: {exc})")
    return parse_fingerprint_progress(body)


def run_fingerprints_phase(
    transport: BudgetedWriteTransport,
    journal: WriteJournal,
    writes: Sequence[FpWrite],
    reader: FpReader,
    *,
    skipped: Sequence[tuple[str, str]] = (),
    sleep: Callable[[float], None] = lambda _s: None,
    batch_delay: float = 0.0,
) -> FpPhaseResult:
    """Port templates one person at a time: read-before, write, read-after. Fail fast.

    Per person, in this order (the order is the finding — card rule 1 verbatim):

        ONE-SHOT read BEFORE → sha match: journal ``planned`` + immediately
        ``confirmed`` and skip the write (already_present — an idempotent re-run
        writes nothing); different sha: CONFLICT skip, the target's template is NEVER
        overwritten (§0.6); NoFP → journal ``planned`` (fsync, §5a) → POST
        FingerPrintDownload → journal ``applied`` on statusCode 1 → ONE post-write
        one-shot read → sha match → journal ``confirmed``; anything else → journal
        ``rejected`` with the progress words and ABORT the phase.

    The read-before runs HERE, at write time, not in the plan pass: §4's freshness
    contract says the target is read fresh, immediately, and a plan-time target view
    is the TOCTOU hole the design closes. It costs one budget call per person, which
    is exactly what §5.3's worst-case maths already budgets (one read per person).

    Why abort (card rule 1 / §5 step 4): the honest terminal state for an
    accepted-but-not-applied FP write on THIS evidence class is "attempted,
    device-side application unverifiable/failed" — and a reader that rejected one
    third-party-family template will reject every one of them, so continuing spends
    the auth budget (§0.5) buying copies of the same answer. The result that comes back
    on the abort names exactly which persons LANDED (sha-confirmed) and which are in
    unknown state; nothing is retried (§0.6) and nothing is deleted (§5b.1).

    ``sleep``/``batch_delay`` are the same injected pacing seam the users phase uses;
    the FP phase has no captured batch size (no capture names one), so it paces
    per-person rather than inventing a batch shape.
    """
    planned = tuple(w.employee_hash for w in writes)
    tally = _FpTally()
    live_skipped: list[tuple[str, str]] = list(skipped)
    if not writes:
        return tally.result(
            planned=planned,
            skipped=live_skipped,
            rebootstraps=transport.rebootstraps,
            aborted=False,
            abort_reason=None,
        )

    for index, write in enumerate(writes):
        if index:
            sleep(batch_delay)  # pacing between persons, never before the first
        # The one-shot read BEFORE: the device's current answer, fresh, immediately
        # before the decision (never the plan pass's view — §4).
        tally.reads_sent += 1
        try:
            before = read_fingerprint_template(write.employee_no, reader)
        except FpReadError as exc:
            raise _abort(
                tally,
                journal,
                planned,
                live_skipped,
                transport,
                reason=(
                    f"pre-write one-shot read for {write.employee_hash} failed ({exc}) "
                    "— the phase may not write blind against an unreadable target: a "
                    "failed read is never read as 'no fingerprint' (§0.7)"
                ),
            ) from exc
        if before.outcome is FpReadOutcome.PRESENT:
            if before.sha256 == write.intended_sha256:
                # already_present: journal the intent AND its honest terminal state —
                # `confirmed` here means "the sha on the device equals the sha we
                # intended", proven by the read, exactly the §5a contract.
                entry = journal.planned(
                    employee_no=write.employee_no,
                    classification="same",
                    pre_write_record=None,
                    intended_record=_fp_intended_record(write),
                    op="fp_already_present",
                )
                journal.confirmed(entry, post_write_hash=before.sha256)
                tally.confirmed.append(write.employee_hash)
                live_skipped.append(
                    (
                        write.employee_hash,
                        f"already_present: target sha {before.sha256[:12]} == intended "
                        f"{write.intended_sha256[:12]} (one-shot read; nothing "
                        "written) — idempotent re-run",
                    )
                )
                continue
            live_skipped.append(
                (
                    write.employee_hash,
                    f"conflict_target_has_different_template: target sha "
                    f"{before.sha256[:12]} != intended {write.intended_sha256[:12]} — "
                    "NEVER overwritten (§0.6: a mismatch is terminal data, a human "
                    "decides); no journal entry was written because nothing was sent",
                )
            )
            continue
        entry = journal.planned(
            employee_no=write.employee_no,
            classification="fp_add",
            pre_write_record=None,  # the read-before said NoFP: there is no prior record
            intended_record=_fp_intended_record(write),
            op="fp_download",
        )
        body = build_fingerprint_download_body(write)
        tally.writes_sent += 1
        try:
            ack = transport.call("post_download", FP_DOWNLOAD_PATH, body)
        except WriteRejectedError as exc:
            journal.rejected(entry, sub_status=exc.sub_status)
            kind = classify_rejection(exc.sub_status)
            tally.rejected.append((entry.employee_hash, kind, exc.sub_status))
            raise _abort(
                tally,
                journal,
                planned,
                live_skipped,
                transport,
                reason=(
                    f"FingerPrintDownload for {entry.employee_hash} was REFUSED by the "
                    f"device (subStatusCode={exc.sub_status!r}, class {kind}): the "
                    "phase stops here (§5 step 4) and nothing was retried (§0.6)"
                ),
            ) from exc
        code = ack.get("statusCode")
        if code != FP_DOWNLOAD_RESPONSE_OK:
            # §6: only statusCode 1 is even an ack this module treats as accepted;
            # anything else is a rejection carrying the device's own word.
            sub_status = ack.get("subStatusCode")
            sub = sub_status if isinstance(sub_status, str) and sub_status else None
            journal.rejected(entry, sub_status=sub)
            tally.rejected.append((entry.employee_hash, RejectKind.OTHER, sub))
            raise _abort(
                tally,
                journal,
                planned,
                live_skipped,
                transport,
                reason=(
                    f"FingerPrintDownload for {entry.employee_hash} answered "
                    f"statusCode={code!r} (subStatusCode={sub!r}) — not the captured "
                    "ack; the phase stops here (§5 step 4)"
                ),
            )
        journal.applied(entry)
        tally.applied.append(entry.employee_hash)

        # The only moment that means anything: read it back and compare sha256.
        tally.reads_sent += 1
        try:
            read = read_fingerprint_template(write.employee_no, reader)
        except FpReadError as exc:
            journal.rejected(entry, sub_status=str(exc))
            tally.rejected.append((entry.employee_hash, RejectKind.OTHER, str(exc)))
            raise _abort(
                tally,
                journal,
                planned,
                live_skipped,
                transport,
                reason=(
                    f"post-write read-back for {entry.employee_hash} could not be "
                    f"read ({exc}) — application is UNVERIFIABLE, which is a rejection "
                    "on this verb, not a pass (§6: never trust the status code)"
                ),
            ) from exc
        if read.outcome is FpReadOutcome.PRESENT and read.sha256 == write.intended_sha256:
            journal.confirmed(entry, post_write_hash=read.sha256)
            tally.confirmed.append(entry.employee_hash)
            continue

        # Accepted, not applied — the bench-A reality. Journal the device's words and
        # stop the phase; the progress surface is pulled here and only here (budget 1).
        progress = _progress_snapshot(transport, tally)
        kind, progress_words = classify_progress_rejection(progress)
        device_status = read.device_status or "unreadable"
        words = (
            f"ack statusCode=1 accepted but not applied: post-write one-shot read "
            f"answered status={device_status!r} "
            f"(intended template sha256={write.intended_sha256[:12]}); "
            f"FingerPrintProgress: {progress_words}"
        )
        journal.rejected(entry, sub_status=words)
        tally.rejected.append((entry.employee_hash, kind, words))
        raise _abort(
            tally,
            journal,
            planned,
            live_skipped,
            transport,
            reason=(
                f"{entry.employee_hash}: {words} — the FIRST accepted-but-not-applied "
                "answer aborts the FP phase (§5 step 4 fail-fast: a reader that rejects "
                f"one {write.sensor_family or 'third-party'} template rejects them all, "
                "and each further write only spends the auth budget). "
                f"landed(sha-confirmed)={list(tally.confirmed)}; nothing was retried "
                "and nothing was deleted (§5b.1: FP removal is manual at the device)"
            ),
        )

    return tally.result(
        planned=planned,
        skipped=live_skipped,
        rebootstraps=transport.rebootstraps,
        aborted=False,
        abort_reason=None,
    )


def _abort(
    tally: _FpTally,
    journal: WriteJournal,
    planned: Sequence[str],
    skipped: Sequence[tuple[str, str]],
    transport: BudgetedWriteTransport,
    *,
    reason: str,
) -> FpAbortedError:
    result = tally.result(
        planned=planned,
        skipped=skipped,
        rebootstraps=transport.rebootstraps,
        aborted=True,
        abort_reason=reason,
    )
    return FpAbortedError(
        f"fingerprints phase aborted: {reason} — journal {journal.path} holds the "
        "planned/applied/rejected lines for every person named above (§5a: an unknown "
        "state is a human decision, never an auto-undo)",
        result,
    )


# --- §6 verify: re-read by sha, mismatch is terminal -----------------------------------------


class FpVerdictKind(StrEnum):
    """Per-person FP verify verdict (§6). ``MISMATCH`` is terminal for the run."""

    #: The read returned a template whose sha256 equals the journal's intended sha.
    CONFIRMED = "confirmed"
    #: The read answered a template with a DIFFERENT sha — the ack lied. Terminal.
    MISMATCH = "mismatch"
    #: The read answered the device's own zero (`NoFP`) after an ack. Terminal on this
    #: verb: it is the bench-A result, not a transient.
    MISSING = "missing"
    #: The read itself failed. Never verdicted as missing (§0.7).
    UNREADABLE = "unreadable"


@dataclass(frozen=True, slots=True)
class FpVerifyItem:
    """One person's verify line: hashes, counts and device words — no PII (§4)."""

    employee_no: str
    employee_hash: str
    verdict: FpVerdictKind
    intended_sha256: str
    target_sha256: str | None = None
    device_status: str | None = None
    #: the bundle's family note — reported on EVERY line (card rule 5).
    sensor_family: str = ""
    #: how far along the journal was when we were asked to verify.
    journal_state: str | None = None
    note: str = ""


@dataclass(frozen=True, slots=True)
class FpVerifyReport:
    """The verify arm's output. ``terminal`` is the run-stopping signal (§0.6)."""

    items: tuple[FpVerifyItem, ...]

    @property
    def terminal(self) -> bool:
        """A mismatch or a not-applied answer after an ack stops the run (§0.6)."""
        return any(
            i.verdict is FpVerdictKind.MISMATCH or i.verdict is FpVerdictKind.MISSING
            for i in self.items
        )

    @property
    def confirmed(self) -> tuple[FpVerifyItem, ...]:
        return tuple(i for i in self.items if i.verdict is FpVerdictKind.CONFIRMED)

    @property
    def unreadable(self) -> tuple[FpVerifyItem, ...]:
        return tuple(i for i in self.items if i.verdict is FpVerdictKind.UNREADABLE)

    def summary(self) -> dict[str, Any]:
        return {
            "counts": {
                "confirmed": sum(1 for i in self.items if i.verdict is FpVerdictKind.CONFIRMED),
                "mismatch": sum(1 for i in self.items if i.verdict is FpVerdictKind.MISMATCH),
                "missing": sum(1 for i in self.items if i.verdict is FpVerdictKind.MISSING),
                "unreadable": len(self.unreadable),
            },
            "terminal": self.terminal,
            "items": [
                {
                    "employee": i.employee_hash,
                    "verdict": str(i.verdict),
                    "intendedSha256": i.intended_sha256[:12],
                    "targetSha256": (i.target_sha256 or "")[:12] or None,
                    "deviceStatus": i.device_status,
                    "sensorFamily": i.sensor_family,
                    "journalState": i.journal_state,
                    "note": i.note,
                }
                for i in self.items
            ],
            "ackIsNotConfirm": (
                "every verdict above came from a post-write READ by sha256, never "
                "from a statusCode 1 (§6)"
            ),
        }


def verify_fingerprints(
    *,
    journal: WriteJournal,
    writes: Sequence[FpWrite],
    reader: FpReader,
) -> FpVerifyReport:
    """Re-read every touched person ONE shot each and compare by template sha (§6).

    The journal is the source of truth for WHO was touched and WHAT we intended; the
    device is the only source for WHAT IS THERE. An ``ack`` (applied) entry whose read
    comes back `NoFP` is MISSING — terminal — which is exactly the bench-A outcome made
    structural; a different sha is MISMATCH — terminal; a read that fails is UNREADABLE
    and never collapses into "missing" (§0.7). A ``rejected`` entry is still verified:
    the journal said the device refused or never applied it, and verify is what proves
    that claim rather than trusting it.
    """
    by_no = {w.employee_no: w for w in writes}
    items: list[FpVerifyItem] = []
    for employee_no, write in by_no.items():
        entry: JournalEntry | None = journal.by_employee(employee_no)
        state = None if entry is None else str(entry.state)
        intended = write.intended_sha256
        try:
            read = read_fingerprint_template(employee_no, reader)
        except FpReadError as exc:
            items.append(
                FpVerifyItem(
                    employee_no=employee_no,
                    employee_hash=write.employee_hash,
                    verdict=FpVerdictKind.UNREADABLE,
                    intended_sha256=intended,
                    sensor_family=write.sensor_family,
                    journal_state=state,
                    note=f"read failed, never verdicted as missing (§0.7): {exc}",
                )
            )
            continue
        if read.outcome is FpReadOutcome.PRESENT and read.sha256 == intended:
            items.append(
                FpVerifyItem(
                    employee_no=employee_no,
                    employee_hash=write.employee_hash,
                    verdict=FpVerdictKind.CONFIRMED,
                    intended_sha256=intended,
                    target_sha256=read.sha256,
                    device_status=read.device_status,
                    sensor_family=write.sensor_family,
                    journal_state=state,
                )
            )
            continue
        if read.outcome is FpReadOutcome.NO_FP:
            items.append(
                FpVerifyItem(
                    employee_no=employee_no,
                    employee_hash=write.employee_hash,
                    verdict=FpVerdictKind.MISSING,
                    intended_sha256=intended,
                    device_status=read.device_status,
                    sensor_family=write.sensor_family,
                    journal_state=state,
                    note=(
                        "device answered its own zero word after the write was acked — "
                        "the accepted-not-applied class (OBSERVED.md §5.0); TERMINAL "
                        "(§0.6), never re-written"
                    ),
                )
            )
            continue
        items.append(
            FpVerifyItem(
                employee_no=employee_no,
                employee_hash=write.employee_hash,
                verdict=FpVerdictKind.MISMATCH,
                intended_sha256=intended,
                target_sha256=read.sha256,
                device_status=read.device_status,
                sensor_family=write.sensor_family,
                journal_state=state,
                note=(
                    "target holds a template whose sha differs from the intended one — "
                    "terminal (§6); a human decides, this module never overwrites"
                ),
            )
        )
    return FpVerifyReport(items=tuple(items))


# --- composed phase + §5b.1 report-only undo -------------------------------------------------


@dataclass(frozen=True, slots=True)
class FpFleetReport:
    """The whole FP phase: writes, journal position, verify verdicts, undo wording."""

    phase: str
    writes: FpPhaseResult
    verify: FpVerifyReport
    journal_path: str
    notes: tuple[str, ...] = ()

    def as_dict(self) -> dict[str, Any]:
        return {
            "phase": self.phase,
            "journal": self.journal_path,
            "writes": self.writes.summary(),
            "verify": self.verify.summary(),
            "undo": report_only_fingerprint_undo(),
            "notes": list(self.notes),
        }


#: §5b.1 for fingerprints, in the report's words. No delete verb was ever captured
#: (OBSERVED.md: `FingerPrintCfg` GET/POST and the delete caps are notSupport), so this
#: phase's undo is a sentence, not a request. Users reached the same conclusion by the
#: opposite route (every accepted user-delete shape wipes the whole roster).
FP_UNDO_REPORT_ONLY = (
    "FP removal is MANUAL AT THE DEVICE: no fingerprint delete verb exists in any "
    "bench-A capture (OBSERVED.md §5.0: FingerPrintCfg GET/POST and the delete caps "
    "are notSupport), so this phase journals intent and reports it — undo for "
    "fingerprints is 'remove at the device by hand', never an API call (§5b.1, same "
    "shape as the users phase)"
)


def report_only_fingerprint_undo() -> dict[str, Any]:
    """The undo section of the report — a sentence, structurally unable to write."""
    return {
        "mode": "report_only",
        "action": "manual removal at the device",
        "why": FP_UNDO_REPORT_ONLY,
    }


def apply_fingerprints_phase(
    *,
    writes: Sequence[FpWrite],
    skipped: Sequence[tuple[str, str]],
    transport_factory: Callable[[], FpTransport],
    reader: FpReader,
    journal_path: str | os.PathLike[str],
    sleep: Callable[[float], None] = lambda _s: None,
    batch_delay: float = 0.0,
) -> FpFleetReport:
    """Journal → write → re-read → verify, stopping at the first non-applied answer.

    The order stays §5's: journal-before-request (§5a), one transport per phase
    re-bootstrapped at 80 (§5.3), verify after the phase (§6), mismatch terminal
    (§0.6), never a delete (§5 step 8 / §5b.1). Confirmation on this verb can come
    from the READ only — that is the finding this whole module exists to enforce.
    """
    journal = WriteJournal.open(journal_path, phase="fingerprints")
    budgeted = BudgetedWriteTransport(transport_factory)
    notes: list[str] = (
        [
            f"{len(skipped)} person(s) report-only in this phase: "
            + ", ".join(f"{h}={r}" for h, r in skipped[:8])
        ]
        if skipped
        else []
    )
    notes.extend(
        f"{write.employee_hash}: sensor family {write.sensor_family} — "
        f"{SensorFamily.CLAIMED.value} on header-bytes + caps-presence evidence only (§1)"
        for write in writes[:8]
    )
    try:
        try:
            result = run_fingerprints_phase(
                budgeted,
                journal,
                writes,
                reader,
                skipped=skipped,
                sleep=sleep,
                batch_delay=batch_delay,
            )
        except FpAbortedError as exc:
            # §5 step 4's artifact: the abort carries the partial result AND the
            # verify pass still runs, because the operator's next question is exactly
            # "what is actually on the device" (§6) — never answered by a guess.
            verify = verify_fingerprints(journal=journal, writes=writes, reader=reader)
            abort_notes = [str(exc), *notes]
            if verify.terminal:
                abort_notes.append(
                    "TERMINAL verify verdict on the fingerprints phase (§0.6): the run "
                    "stops here; a human decides — no re-write, no delete (§5 step 8, "
                    "§5b.1)"
                )
            report = FpFleetReport(
                phase="fingerprints",
                writes=exc.result,
                verify=verify,
                journal_path=str(journal.path),
                notes=tuple(abort_notes),
            )
            raise FpAbortedError(str(exc), report) from exc
    finally:
        budgeted.close()  # the write session ends with the write phase (§5.3)

    verify = verify_fingerprints(journal=journal, writes=writes, reader=reader)
    # The phase already confirmed each person it could; verify re-reads them, and a
    # verify that no longer agrees with the journal is terminal (§0.6). Entries the
    # phase confirmed but verify cannot are journalled as a mismatch note rather than
    # a silent downgrade — the journal is append-only and the report carries the word.
    result = replace(result, confirmed=tuple(i.employee_hash for i in verify.confirmed))
    if verify.terminal:
        notes.append(
            "TERMINAL verify verdict on the fingerprints phase (§0.6): the run stops "
            "here; a human decides — no re-write, no delete (§5 step 8, §5b.1)"
        )
    return FpFleetReport(
        phase="fingerprints",
        writes=result,
        verify=verify,
        journal_path=str(journal.path),
        notes=tuple(notes),
    )
