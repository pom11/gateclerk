"""The read-only enrollment export (cards E1-01 + E1-01b): device -> bundle, fail closed.

Design docs/ENROLLMENT-MIGRATION.md §0.7/§1/§2/§9. This is the snapshot every E1 write
run is gated behind (§0.1: the export IS the rollback source), so its one absolute
rule is **a failure is never "empty"**: any error on a required read aborts the
export loudly (`EnrollmentReadAborted`). "The device answered zero people" is a fact
only when the device itself said `OK` or `NO MATCH` — silence, a FAIL status, a
missing status key, a 400/404 envelope or a dropped socket all abort. A snapshot that
quietly read as empty would silently become the rollback source for a wiped device.

What the walk reuses (import, never re-express — card rule):
* `gateclerk.paging` owns every cursor rule — one byte-stable `searchID` per logical
  search, advance by returned `numOfMatches`, termination on normalized
  `responseStatusStrg` != MORE, the page-count runaway cap. `user_info_search` and
  `card_info_search` are the two wrapped-dialect engines; `fd_search` uses the
  FLAT-dialect knobs (§9 dialect split, §1 paging quirk). This module adds only the
  per-page fail-closed verdict the enrollment use case demands (the events walk
  warns, E1 aborts) and the identity read.
* `gateclerk.migrate_bundle` owns normalization + hashing + the file layout.

E1-01b adds the two biometric READS that are the product (operator, v4):
* `export_faces()` walks FDSearch FDID 1 (`blackFD`) — the FLAT dialect the device
  accepts (the wrapped style is what 400'd, §1) — and keeps `modelData` as OPAQUE
  bytes: base64 as the device sent it, sha256/length over the decoded form, never
  parsed. `FPID` joins to `employeeNo` by opaque string equality (§1).
* `export_fingerprints()` reads `FingerPrintUpload` (misleading device name:
  device->client) per employee, ONE read each — bench A's capture (2026-10-22) shows
  the endpoint IGNORES fpIndex (0/1/2 answered the same template), and a person's
  zero is the device's own `status: "NoFP"` with the list absent.
  Templates are opaque exactly like faces; the sensor-family NOTE is a label about
  the header bytes, not a parse of them (§1 same-family rule).

The client seam is `IsapiClient`-shaped (`get(name)` / `search(name, body)`), asserted
against `SEARCH_ENDPOINTS` before any call — the same registry guard the pipeline
walker uses. Nothing here can reach a write path: the only POSTs possible are the
stateless searches the registry allows (FDSearch and FingerPrintUpload are both
READS — the write verbs FDSetUp/FaceDataRecord/FingerPrintDownload are registered
nowhere), and these cards are read-only by design.
"""

from __future__ import annotations

import base64
import hashlib
import time
from collections.abc import Callable, Collection, Mapping
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Protocol

from gateclerk.capabilities import device_identity
from gateclerk.endpoints import SEARCH_ENDPOINTS
from gateclerk.exceptions import (
    EnrollmentReadAborted,
    GateClerkError,
    IsapiError,
)
from gateclerk.migrate_bundle import (
    PHOTO_BYTES_ABSENT_REASON,
    FacesIndex,
    FaceTemplate,
    FingerprintIndex,
    FingerprintTemplate,
    content_hash,
    write_bundle,
)
from gateclerk.paging import (
    DEFAULT_INTER_PAGE_DELAY,
    DEFAULT_MAX_PAGES,
    PagedSearch,
    PagingLimits,
    SearchSummary,
    card_info_search,
    fd_search,
    new_search_id,
    user_info_search,
)

__all__ = [
    "ACCEPTED_STATUSES",
    "ClientLike",
    "EnrollmentState",
    "ExportResult",
    "FaceWalk",
    "FingerprintWalk",
    "collect_enrollment_state",
    "export_bundle",
    "export_faces",
    "export_fingerprints",
    "export_full_bundle",
]

# --- FDSearch dialect facts (bench A, 2026-10-21 request side; §5.0 capture 2026-10-22
#     response side; ENROLLMENT-MIGRATION.md §1) ------------------------------------------
#
# The REQUEST body and the ROW keys were probed 2026-10-21. The response envelope was
# CAPTURED live on 2026-10-22: FDSearch answers with NO wrapper — counts/status sit at
# the body root (`""` = the root-envelope dialect `paging.response_envelope` documents)
# and rows sit under `MatchList`; the honest zero omits `MatchList` entirely. The
# earlier `{"FDSearch": {...}}/Records` guess (a documented extrapolation that mirrored
# the fake) failed CLOSED on the real device exactly as §0.7 promises, and the capture
# replaced it with the recorded value.
FD_SEARCH_ENVELOPE_KEY = ""
FD_SEARCH_RECORD_KEY = "MatchList"

#: The one portable FD library of the family (§1: FDID 1 = blackFD; FDID 2 is
#: infraredFD, recorded but out of the port scope). Values are the strings bench A
#: answered — callers may override per device after the probe says otherwise.
FD_PORTABLE_FDID = "1"
FD_PORTABLE_FACE_LIB_TYPE = "blackFD"

#: FingerPrintUpload read shape (§1): the `FingerPrintCond` wrapper is REQUIRED (the
#: plain form 400s `MessageParametersLack:FingerPrintCond`, probed), and rows arrive
#: under `FingerPrintInfo.FingerPrintList`.
FP_COND_KEY = "FingerPrintCond"
FP_ENVELOPE_KEY = "FingerPrintInfo"
FP_RECORD_KEY = "FingerPrintList"
FP_DATA_TYPE = "template"

#: Walk-completion label: every roster employee got a definitive per-person answer
#: (a template row or the device's `NoFP`). ONE-SHOT is the captured truth — there
#: is no fpIndex walk anymore (§5.0 capture 2026-10-22, OBSERVED.md: bench A
#: IGNORES `fpIndex` on the read — fpIndex 0/1/2 all answered the SAME template with
#: `fingerPrintID=1` — so a "walk until empty list" reads one person forever and
#: correctly self-aborts on the old runaway guard; the guard was the premise dying).
FP_STOP_LABEL = "ONE-SHOT-COMPLETE"

#: The device's OWN zero word, captured 2026-10-22 on a person without a
#: fingerprint: `FingerPrintInfo.status == "NoFP"` with `FingerPrintList` ABSENT.
#: Anything else that lacks a list is a protocol break, not a zero (§0.7).
FP_DEVICE_NO_FP = "NoFP"

#: The sensor-family NOTE recorded when a template's first three bytes are the ASCII
#: `301` bench A's fingerprints carried (OBSERVED.md: "third-party sensor family,
#: NOT self-identified"). A label about the bytes, never a parse of them.
_FP_SENSOR_301_NOTE = "301-header (third-party sensor family, not self-identified; §1)"

#: The only `responseStatusStrg` values a page may carry (design §0.7). OK and MORE
#: are the walk's normal vocabulary (paging module); NO MATCH is the device *saying*
#: "zero matches" — the empty-window shape with a missing record key (OBSERVED.md).
#: Anything else — "", an absent key, "FAIL", a token we have never seen — aborts:
#: `normalize_status` makes spelling drift visible but never turns an unknown verdict
#: into success.
ACCEPTED_STATUSES = frozenset({"OK", "MORE", "NOMATCH"})

#: Identity read failure carries the registry name in the abort; deviceInfo answers
#: XML-despite-json on this family, which `IsapiClient.get` already normalizes.
_IDENTITY_ENDPOINT = "device_info"
_SERIAL_PREFIX_LEN = 6


class ClientLike(Protocol):
    """The `IsapiClient` shape this module requires (structural protocol).

    `get(name) -> dict` and `search(name, body) -> dict`, names from
    `gateclerk.endpoints`. Production passes the real client; tests pass the real
    client over `FakeDevice`'s MockTransport — never a permissive stand-in, per the
    §9 fake-strictness rule.
    """

    def get(self, name: str) -> dict[str, Any]: ...  # pragma: no cover - protocol

    def search(
        self, name: str, payload: Mapping[str, Any]
    ) -> dict[str, Any]: ...  # pragma: no cover


@dataclass(frozen=True, slots=True)
class EnrollmentState:
    """The two required reads plus the identity, exactly as the device reported."""

    users: tuple[dict[str, Any], ...]
    cards: tuple[dict[str, Any], ...]
    identity: dict[str, Any]  # model / firmware / serial_prefix — never the host
    termination: dict[str, str]  # registry endpoint -> normalized terminal status


@dataclass(frozen=True, slots=True)
class ExportResult:
    """What an export produced — counts and hashes for reports, never names (design §4).

    E1-01b additions carry defaults so E1-01's call sites (and their pinned tests)
    construct the same result they always did: `fingerprints` defaults to the
    recorded-absence index, `enrollment_counters` to the empty report-only section.
    """

    bundle_dir: Path
    counts: dict[str, int]
    people_hashes: dict[str, str]
    faces: FacesIndex
    termination: dict[str, str]
    fingerprints: FingerprintIndex = field(default_factory=FingerprintIndex)
    enrollment_counters: dict[str, Any] = field(default_factory=dict)


def _search_reader(client: ClientLike, endpoint: str) -> Callable[[Mapping[str, Any]], dict]:
    """POST a whole search body through the registry-guarded client seam.

    Same guard as `pipeline._search_reader`: the endpoint must be one of the
    stateless search POSTs before any request leaves. A name outside
    `SEARCH_ENDPOINTS` is refused here AND by `IsapiClient._check` — the write path
    has to beat two gates, not slip past one.
    """
    if endpoint not in SEARCH_ENDPOINTS:
        raise ValueError(
            f"{endpoint!r} is not a stateless search endpoint; enrollment export may "
            f"only POST to {sorted(SEARCH_ENDPOINTS)}"
        )

    def read(body: Mapping[str, Any]) -> dict[str, Any]:
        return client.search(endpoint, body)

    return read


def _abort(endpoint: str, reason: str, cause: Exception | None = None) -> EnrollmentReadAborted:
    message = (
        f"enrollment export aborted: required read on {endpoint} failed ({reason}) — "
        "a failed read is never treated as 'empty' (design §0.7); no bundle was written"
    )
    return EnrollmentReadAborted(message, endpoint=endpoint, reason=reason, cause=cause)


def _walk(
    engine: PagedSearch,
    endpoint: str,
    label: str,
    cond: Mapping[str, Any] | None = None,
) -> tuple[list[dict[str, Any]], str]:
    """Drain one paged search, checking EVERY page's device verdict.

    The paging engine terminates on non-MORE; it does not judge statuses, because an
    events walk treats an odd terminal status as a summary detail. An enrollment
    snapshot cannot: an unknown verdict mid-walk is exactly the moment a truncated
    pull would masquerade as a complete one, so each page must answer OK / MORE /
    NO MATCH or the export dies naming the page.
    """
    records: list[dict[str, Any]] = []
    try:
        for page in engine.pages(cond or {}):
            if page.status not in ACCEPTED_STATUSES:
                raise _abort(
                    endpoint,
                    f"page {page.index} answered responseStatusStrg="
                    f"{page.status!r} (accepted: {sorted(ACCEPTED_STATUSES)})",
                )
            records.extend(dict(record) for record in page.records)
    except EnrollmentReadAborted:
        raise
    except GateClerkError as exc:
        # Every typed device/paging failure (IsapiError, SearchProtocolError,
        # SearchRunawayError, IsapiPayloadError…) funnels into one export-abort type
        # with the original as `cause`: callers (E1-07 CLI) map one exception to
        # "exit 4, no bundle", and the specific reason stays inspectable. Catching
        # the whole GateClerkError family is deliberate — the fail-closed rule is "ANY
        # device/paging failure aborts", and an allowlist of error classes would fail
        # OPEN the day a new typed error appears.
        raise _abort(endpoint, str(exc), cause=exc) from exc
    summary: SearchSummary | None = engine.summary
    termination = summary.termination if summary else ""
    if not termination:
        raise _abort(endpoint, "walk completed without a reported terminal status")
    return records, termination


def collect_enrollment_state(
    client: ClientLike,
    *,
    limits: PagingLimits | None = None,
    page_size: int | None = None,
    max_pages: int = DEFAULT_MAX_PAGES,
    inter_page_delay: float = DEFAULT_INTER_PAGE_DELAY,
    sleep: Callable[[float], None] = time.sleep,
    clock: Callable[[], float] = time.monotonic,
) -> EnrollmentState:
    """Read users + cards + identity off the device, fail-closed (§0.7).

    Order is identity first: a device we cannot even name is not a device we snapshot
    (the manifest records model/fw/serial-prefix, and a snapshot without an identity
    cannot be matched to its rollback pair later). `sleep`/`clock`/`inter_page_delay`
    keep the paging pacing injectable — tests never wait, production never hammers
    (OBSERVED.md budget discipline).
    """
    try:
        identity_body = client.get(_IDENTITY_ENDPOINT)
    except IsapiError as exc:
        raise _abort(_IDENTITY_ENDPOINT, str(exc), cause=exc) from exc
    # deviceInfo is XML-despite-?format=json on this family (OBSERVED.md), already
    # flattened by the client's parse_body; device_identity() walks wrapped+flat.
    serial, firmware, model = device_identity(identity_body)
    identity = {
        "model": model,
        "firmware": firmware,
        # Prefix only (design §2 "serial prefix"): the full serial never enters a
        # bundle file; six chars is enough to eyeball "same box, two snapshots".
        "serial_prefix": (serial or "")[:_SERIAL_PREFIX_LEN] or None,
    }

    users, users_term = _walk(
        user_info_search(
            _search_reader(client, "user_info_search"),
            limits=limits,
            page_size=page_size,
            max_pages=max_pages,
            inter_page_delay=inter_page_delay,
            sleep=sleep,
            clock=clock,
        ),
        "user_info_search",
        "users",
    )
    cards, cards_term = _walk(
        card_info_search(
            _search_reader(client, "card_info_search"),
            limits=limits,
            page_size=page_size,
            max_pages=max_pages,
            inter_page_delay=inter_page_delay,
            sleep=sleep,
            clock=clock,
        ),
        "card_info_search",
        "cards",
    )
    return EnrollmentState(
        users=tuple(users),
        cards=tuple(cards),
        identity=identity,
        termination={"UserInfo/Search": users_term, "CardInfo/Search": cards_term},
    )


def export_bundle(
    out_dir: Path,
    *,
    client: ClientLike,
    clock: Callable[[], datetime],
    limits: PagingLimits | None = None,
    page_size: int | None = None,
    max_pages: int = DEFAULT_MAX_PAGES,
    inter_page_delay: float = DEFAULT_INTER_PAGE_DELAY,
    sleep: Callable[[float], None] = time.sleep,
    pacing_clock: Callable[[], float] = time.monotonic,
) -> ExportResult:
    """One read-only device pass -> one bundle directory. Read-only by construction.

    * `clock` is INJECTED (card rule): every export byte that could depend on a wall
      clock depends on this callable instead — two runs with the same clock over the
      same device state are byte-identical (the §9 byte-stability test).
    * Faces are the recorded absence (v4 scope note): face template export moved to
      E1-01b, so the bundle carries `faces/INDEX.json` state UNAVAILABLE with the
      operator's reason, never a silent empty directory.
    * Nothing is written unless BOTH required reads completed with accepted
      verdicts: an abort leaves no bundle at the final path (write_bundle stages and
      renames).
    """
    if clock is None:  # defensive: "injected" is a contract, not a default
        raise ValueError("export_bundle requires an injected clock (no wall-clock default)")
    state = collect_enrollment_state(
        client,
        limits=limits,
        page_size=page_size,
        max_pages=max_pages,
        inter_page_delay=inter_page_delay,
        sleep=sleep,
        clock=pacing_clock,
    )
    faces = FacesIndex()  # UNAVAILABLE + reason (E1-01b owns template bytes)
    bundle_dir = write_bundle(
        Path(out_dir),
        identity=state.identity,
        exported_at=clock(),
        people=state.users,
        cards=state.cards,
        faces=faces,
        termination=state.termination,
    )
    people_hashes = {
        str(record["employeeNo"]): content_hash(record)
        for record in state.users
        if "employeeNo" in record
    }
    return ExportResult(
        bundle_dir=bundle_dir,
        counts={"users": len(state.users), "cards": len(state.cards), "faces": 0},
        people_hashes=people_hashes,
        faces=faces,
        termination=state.termination,
    )


# --- E1-01b: the two biometric READS ----------------------------------------------------


@dataclass(frozen=True, slots=True)
class FaceWalk:
    """What the FDSearch walk saw — the bundle inputs plus audit labels.

    `templates` maps employeeNo -> the device's `modelData` base64 VERBATIM (the
    bundle writes exactly those characters; sha256/length in `entries` are over the
    decoded bytes, which is transport bookkeeping, not parsing — design §2 "opaque").
    """

    templates: Mapping[str, str]
    entries: tuple[FaceTemplate, ...]
    termination: str


@dataclass(frozen=True, slots=True)
class FingerprintWalk:
    """What the per-person fpIndex reads saw; `files` is write_bundle's input shape."""

    files: tuple[tuple[str, int, str], ...]
    entries: tuple[FingerprintTemplate, ...]
    termination: str


def _decoded_length(endpoint: str, employee_no: str, value: Any, field: str) -> tuple[bytes, str]:
    """Decode one device base64 template strictly and return (bytes, sha256).

    Decoding to HASH is transport, not parsing: the bytes are never interpreted.
    Whitespace between the b64 characters is tolerated (some firmwares wrap lines)
    but anything else that fails `validate=True` aborts — a half-decodable template
    must never ride into a bundle as "probably fine" (§0.7).
    """
    if not isinstance(value, str) or not value.strip():
        raise _abort(endpoint, f"employeeNo {employee_no!r} row carries no usable {field}")
    compact = "".join(value.split())
    try:
        raw = base64.b64decode(compact, validate=True)
    except Exception as exc:  # binascii.Error is a ValueError subclass
        raise _abort(
            endpoint,
            f"employeeNo {employee_no!r} {field} is not clean base64 ({exc.__class__.__name__})",
            cause=exc,
        ) from exc
    if not raw:
        raise _abort(endpoint, f"employeeNo {employee_no!r} {field} decodes to zero bytes")
    return raw, hashlib.sha256(raw).hexdigest()


def _sensor_family_note(raw: bytes) -> str:
    """A LABEL about a fingerprint template's leading bytes — not a parse of them (§1).

    Bench A's templates start with ASCII `301` (OBSERVED.md: "third-party sensor
    family, NOT self-identified"); anything else is recorded as `unknown` rather
    than guessed. The same-sensor-family portability claim rests on a reader seeing
    this note, which is why it travels in the INDEX entry.
    """
    return (
        _FP_SENSOR_301_NOTE
        if raw[:3] == b"301"
        else "unknown (header is not the recorded 301 family)"
    )


def export_faces(
    client: ClientLike,
    *,
    employee_nos: Collection[str],
    fdid: str = FD_PORTABLE_FDID,
    face_lib_type: str = FD_PORTABLE_FACE_LIB_TYPE,
    limits: PagingLimits | None = None,
    page_size: int | None = None,
    max_pages: int = DEFAULT_MAX_PAGES,
    inter_page_delay: float = DEFAULT_INTER_PAGE_DELAY,
    sleep: Callable[[float], None] = time.sleep,
    clock: Callable[[], float] = time.monotonic,
) -> FaceWalk:
    """Walk FDSearch FDID `fdid` once and join rows to the roster by OPAQUE equality.

    The engine (`paging.fd_search`) owns the flat dialect and the §1 paging quirk
    (bench A answered 3 of 4 rows on one OK page, so only a zero-row page ends the
    walk); this function adds the enrollment verdicts:

    * every page must answer OK / MORE / NO MATCH (`_walk`, §0.7);
    * `modelData` is kept VERBATIM as the device sent it; sha256/length are over the
      decoded bytes (transport bookkeeping, never a parse);
    * `FPID` joins to `employeeNo` by plain string equality — "007" joins "007",
      never "7" (§1: leading zeros are data);
    * a row whose FPID is not on the roster ABORTS (an orphan face is a join bug or
      a tampered row — the bundle writer would refuse it anyway; failing at the read
      names the device as the source);
    * two rows for one person disagreeing on bytes ABORTS (a contradiction, not a
      duplicate — §0.7 says a human decides); identical duplicates collapse.
    """
    roster = {str(no) for no in employee_nos}
    rows, termination = _walk(
        fd_search(
            _search_reader(client, "fd_search"),
            limits=limits,
            page_size=page_size,
            max_pages=max_pages,
            inter_page_delay=inter_page_delay,
            sleep=sleep,
            clock=clock,
        ),
        "fd_search",
        "faces",
        # The two REQUIRED flat parameters (§1: missing either is MessageParametersLack).
        {"faceLibType": face_lib_type, "FDID": fdid},
    )
    templates: dict[str, str] = {}
    entries: dict[str, FaceTemplate] = {}
    for row in rows:
        employee_no = str(row.get("FPID") if row.get("FPID") is not None else "")
        if employee_no not in roster:
            raise _abort(
                "fd_search",
                f"FDSearch row FPID {employee_no!r} is not on the exported roster — an "
                "orphan template is a join bug or a tampered search row (fail closed)",
            )
        raw, digest = _decoded_length("fd_search", employee_no, row.get("modelData"), "modelData")
        entry = FaceTemplate(
            employee_no=employee_no,
            fdid=fdid,
            face_lib_type=face_lib_type,
            sha256=digest,
            length=len(raw),
        )
        previous = entries.get(employee_no)
        if previous is not None:
            if previous.sha256 != entry.sha256:
                raise _abort(
                    "fd_search",
                    f"two FDSearch rows for employeeNo {employee_no!r} carry DIFFERENT "
                    "templates — a contradiction the export must not pick a winner for",
                )
            continue  # byte-identical duplicate: collapse, keep the verbatim string
        templates[employee_no] = str(row["modelData"])  # device's own characters
        entries[employee_no] = entry
    order = sorted(entries)
    return FaceWalk(
        templates={no: templates[no] for no in order},
        entries=tuple(entries[no] for no in order),
        termination=termination,
    )


def export_fingerprints(
    client: ClientLike,
    *,
    employee_nos: Collection[str],
    inter_request_delay: float = DEFAULT_INTER_PAGE_DELAY,
    sleep: Callable[[float], None] = time.sleep,
    pacing_clock: Callable[[], float] = time.monotonic,
) -> FingerprintWalk:
    """Read FingerPrintUpload ONE time per employeeNo — the captured device truth.

    The §5.0 capture (bench A, 2026-10-22) killed the fpIndex-walk premise the v4
    design carried: the endpoint IGNORES `fpIndex` on reads (0, 1 and 2 all answered
    the SAME 512 B template with `fingerPrintID: 1`), so "read until the empty list"
    on a real person is a loop that never terminates — which is exactly how the
    first live export found this, self-aborting on its own runaway guard with no
    bundle written and no data guessed. One read per person, one definitive answer:

    * `FingerPrintCond` wrapper REQUIRED (the plain form 400s
      `MessageParametersLack FingerPrintCond`, §1 — still true post-capture);
    * a template row => the person's fingerprint (fingerPrintID must be 1, the
      captured constant; anything else means fpIndex means something on THAT box
      that we have no evidence for — fail closed rather than port a guess);
    * the device's OWN zero => `status: "NoFP"` with `FingerPrintList` absent — the
      ONLY listless answer accepted as "no fingerprint"; any other missing/empty
      list, missing envelope, multi-row answer, or transport/`statusCode` error
      aborts the export naming the person. Absence is only ever the device's own
      word, never our error path (§0.7).
    """
    read = _search_reader(client, "finger_print_upload")
    files: list[tuple[str, int, str]] = []
    entries: list[FingerprintTemplate] = []
    issued = False
    last_seen = pacing_clock()
    for employee_no in sorted({str(no) for no in employee_nos}):
        if issued:
            # Space request STARTS like the paging engine does (small box,
            # serial sessions) — including the first read of a new person.
            wait = inter_request_delay - (pacing_clock() - last_seen)
            if wait > 0:
                sleep(wait)
        issued = True
        body = {
            FP_COND_KEY: {
                "searchID": new_search_id(),
                "employeeNo": employee_no,
                "fpIndex": 0,
                "dataType": FP_DATA_TYPE,
            }
        }
        last_seen = pacing_clock()
        try:
            response = read(body)
        except GateClerkError as exc:
            # Includes the 400 MessageParametersLack family: if the wrapper we
            # send stops being accepted, that is a protocol break, not "no FP".
            raise _abort(
                "finger_print_upload",
                f"employeeNo {employee_no!r}: {exc}",
                cause=exc,
            ) from exc
        info = response.get(FP_ENVELOPE_KEY)
        if not isinstance(info, Mapping):
            raise _abort(
                "finger_print_upload",
                f"employeeNo {employee_no!r}: response has no {FP_ENVELOPE_KEY!r} "
                "envelope — reading a protocol break as 'no fingerprints' is the "
                "silence §0.7 refuses",
            )
        rows = info.get(FP_RECORD_KEY)
        status = str(info.get("status") or "")
        if rows is None or rows == []:
            # The CAPTURED zero (bench A 2026-10-22): `status: "NoFP"`, list ABSENT.
            # Any other listless answer is an unknown vocabulary, not a zero.
            if status == FP_DEVICE_NO_FP:
                continue
            raise _abort(
                "finger_print_upload",
                f"employeeNo {employee_no!r}: no {FP_RECORD_KEY} and status {status!r} "
                f"is not the captured zero word {FP_DEVICE_NO_FP!r} — refusing to read "
                "an unknown answer as 'no fingerprints' (§0.7)",
            )
        if not isinstance(rows, list) or len(rows) != 1:
            raise _abort(
                "finger_print_upload",
                f"employeeNo {employee_no!r}: {FP_RECORD_KEY} is {type(rows).__name__} "
                f"with {len(rows) if isinstance(rows, list) else '?'} row(s); the "
                "probed shape is exactly one (OBSERVED.md) — refusing to guess which "
                "row is the person's",
            )
        row = rows[0]
        if not isinstance(row, Mapping):
            raise _abort(
                "finger_print_upload",
                f"employeeNo {employee_no!r}: row is {type(row).__name__}, not an object",
            )
        # The capture proved the box IGNORES fpIndex (0/1/2 all answered THIS row,
        # fingerPrintID 1). A different slot number means fpIndex means something on
        # that device that it does not mean on bench A — a fact we do not have, so
        # we stop instead of porting a guess (and instead of claiming one read
        # covers a multi-finger person).
        if str(row.get("fingerPrintID")) != "1":
            raise _abort(
                "finger_print_upload",
                f"employeeNo {employee_no!r}: answered fingerPrintID "
                f"{row.get('fingerPrintID')!r} for an fpIndex=0 read; bench A always "
                "answers 1 (capture 2026-10-22) — multi-finger reads on this shape "
                "are UNPROVEN, not silently one-finger",
            )
        raw, digest = _decoded_length(
            "finger_print_upload", employee_no, row.get("fingerData"), "fingerData"
        )
        files.append((employee_no, 0, str(row["fingerData"])))
        entries.append(
            FingerprintTemplate(
                employee_no=employee_no,
                fp_index=0,
                sha256=digest,
                length=len(raw),
                sensor_family=_sensor_family_note(raw),
            )
        )
    return FingerprintWalk(files=tuple(files), entries=tuple(entries), termination=FP_STOP_LABEL)


def export_full_bundle(
    out_dir: Path,
    *,
    client: ClientLike,
    clock: Callable[[], datetime],
    limits: PagingLimits | None = None,
    page_size: int | None = None,
    max_pages: int = DEFAULT_MAX_PAGES,
    inter_page_delay: float = DEFAULT_INTER_PAGE_DELAY,
    sleep: Callable[[float], None] = time.sleep,
    pacing_clock: Callable[[], float] = time.monotonic,
) -> ExportResult:
    """One read-only pass over ALL FOUR reads -> one bundle (the E1-01b composite).

    E1-01's `export_bundle` stays exactly as shipped (users+cards, faces/FP recorded
    as absences) so its pinned regression tests keep testing what they tested; this
    is the function the E1-07 CLI calls once the biometric reads are wanted. Same
    fail-closed contract: any read failing leaves no bundle at the final path.

    `enrollment_counters` is REPORT-ONLY (v4 §9 "counter vs set"): the per-person
    `numOfFace`/`numOfFP` the roster carries next to what the walks actually
    exported — the disagreement is data for E1-02's conflict classification, never
    something this export resolves (card: cross-check is report-only).
    """
    if clock is None:  # defensive: "injected" is a contract, not a default
        raise ValueError("export_full_bundle requires an injected clock (no wall-clock default)")
    state = collect_enrollment_state(
        client,
        limits=limits,
        page_size=page_size,
        max_pages=max_pages,
        inter_page_delay=inter_page_delay,
        sleep=sleep,
        clock=pacing_clock,
    )
    roster = sorted(
        {
            str(record["employeeNo"])
            for record in state.users
            if record.get("employeeNo") not in (None, "")
        }
    )
    faces_walk = export_faces(
        client,
        employee_nos=roster,
        limits=limits,
        page_size=page_size,
        max_pages=max_pages,
        inter_page_delay=inter_page_delay,
        sleep=sleep,
        clock=pacing_clock,
    )
    fp_walk = export_fingerprints(
        client,
        employee_nos=roster,
        inter_request_delay=inter_page_delay,
        sleep=sleep,
        pacing_clock=pacing_clock,
    )
    faces_index = FacesIndex(
        state="AVAILABLE",
        reason="FDSearch FDID 1 (blackFD) walked to a zero-row page (modelData templates)",
        entries=faces_walk.entries,
        photo_bytes={"reason": PHOTO_BYTES_ABSENT_REASON},
    )
    fp_index = FingerprintIndex(
        state="AVAILABLE",
        reason=(
            "every roster employee got one definitive FingerPrintUpload read "
            f"(template row or the device's {FP_DEVICE_NO_FP!r}; {FP_STOP_LABEL})"
        ),
        entries=fp_walk.entries,
    )
    counters: dict[str, Any] = {}
    for record in state.users:
        employee_no = str(record.get("employeeNo") or "")
        if not employee_no:
            continue
        counters[employee_no] = {
            "numOfFace": record.get("numOfFace"),
            "numOfFP": record.get("numOfFP"),
            "exported_faces": sum(1 for e in faces_walk.entries if e.employee_no == employee_no),
            "exported_fingerprints": sum(
                1 for e in fp_walk.entries if e.employee_no == employee_no
            ),
        }
    bundle_dir = write_bundle(
        Path(out_dir),
        identity=state.identity,
        exported_at=clock(),
        people=state.users,
        cards=state.cards,
        faces=faces_index,
        fingerprints=fp_index,
        face_templates=faces_walk.templates,
        fingerprint_templates=fp_walk.files,
        enrollment_counters=counters,
        termination={
            **state.termination,
            "FDSearch": faces_walk.termination,
            "FingerPrintUpload": fp_walk.termination,
        },
    )
    people_hashes = {
        str(record["employeeNo"]): content_hash(record)
        for record in state.users
        if "employeeNo" in record
    }
    return ExportResult(
        bundle_dir=bundle_dir,
        counts={
            "users": len(state.users),
            "cards": len(state.cards),
            "faces": len(faces_walk.entries),
            "fingerprints": len(fp_walk.entries),
        },
        people_hashes=people_hashes,
        faces=faces_index,
        fingerprints=fp_index,
        enrollment_counters=counters,
        termination={
            **state.termination,
            "FDSearch": faces_walk.termination,
            "FingerPrintUpload": fp_walk.termination,
        },
    )
