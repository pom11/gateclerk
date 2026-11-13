"""The E1 enrollment bundle: normalization, content hashes, writer, reader (card E1-01).

This module is the SINGLE home of the record-normalization and content-hash rules
(design docs/internal/ENROLLMENT-MIGRATION.md §2). Diff (E1-02) and read-back verify (E1-04/05)
import `normalize_record` / `content_hash` from here — they must never re-express them,
because the whole diff/verify contract rests on the source side and the target side
computing byte-identical hashes with the *same* function. Two implementations that can
drift is the bug class this module exists to prevent.

What the bundle is (design §2, v4 + E1-01b addendum):

    <out>/
      manifest.json     schema version, frozen volatile-field list, source identity
                        (model, fw, serial prefix — NEVER the host), exported_at from
                        an INJECTED clock, counts, per-person content hashes,
                        faces state + reason + template hashes, fingerprints state +
                        template hashes + sensor-family note, enrollment counters
                        (REPORT-ONLY: counter vs set, v4 §9 — a count is not a set)
      people.jsonl      normalized UserInfo records, one JSON object per line.
                        `password` NEVER appears — it is stripped at read time (R3).
      cards.jsonl       normalized CardInfo records (employeeNo, cardNo, ...).
      faces/INDEX.json  {"state": "UNAVAILABLE", "reason": ...} when the face walk
                        was not performed (E1-01's recorded absence — never a silent
                        empty directory), or {"state": "AVAILABLE", "entries": [...],
                        "photo_bytes": {...}} per E1-01b: per-person FDID/FPID/
                        sha256/length + the recorded fact that faceURL PHOTO bytes
                        are NOT exportable on this fw (404 every way, §1).
      faces/<employeeNo>.b64          FDSearch `modelData` — the face TEMPLATE, base64
                        exactly as the device sent it (opaque bytes; this module NEVER
                        parses it, §2).
      fingerprints/<employeeNo>-<fpIndex>.b64   FingerPrintUpload-read templates
                        (opaque device base64 + sensor-family note from header bytes,
                        never parsed; same-sensor-family portability rule §1).

Normalization (design §2, "the volatile strip list is FROZEN in the manifest"):
strip EXACTLY `openDoorTime`, the `numOfCard`/`numOfFace`/`numOfFP` counters,
`password` (unconditionally — R3 says pins never enter a bundle in any mode), and the
per-device URL host parts (`photoURL`/`faceURL`). Everything else — name, Valid,
RightPlan, doorRight — is kept verbatim and hashed. The strip list is a module
constant so the bundle writer, the diff and the verifier share one frozen truth.

`employeeNo` is an OPAQUE BYTE STRING (design §1): exact match, never int-cast, never
case-normalized. `record_key` keys people by the exact string the device sent; two
devices that disagree about `"007"` vs `"7"` must not be silently reconciled here.

PII + hygiene rules this module enforces mechanically, not by comment:
* bundle dir 0700, every file 0600 (personal data on a developer laptop);
* an `--out` inside the repo (or any ancestor that is a git repo) is REFUSED —
  public-repo hygiene (design §2);
* `content_hash` is sha256 over canonical JSON (sorted keys, UTF-8, numbers
  normalized) of the NORMALIZED record, so `{"a": 1}` and `{"a": 1.0}` hash equal —
  int-vs-float firmware drift (OBSERVED.md "int-vs-string/nested shape drift") never
  fakes a payroll-relevant "change".
"""

from __future__ import annotations

import base64
import contextlib
import hashlib
import json
import os
import stat
import string
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from gateclerk.exceptions import BundleRepoOutError

__all__ = [
    "BUNDLE_DIRS",
    "BUNDLE_FILES",
    "COMPARE_EXEMPT_FIELDS",
    "DEVICE_ASSIGNED_FIELDS",
    "FACES_ABSENT_REASON",
    "FINGERPRINTS_ABSENT_REASON",
    "MANIFEST_NAME",
    "SCHEMA_VERSION",
    "VOLATILE_FIELDS",
    "VOLATILE_URL_FIELDS",
    "BundleData",
    "BundleManifest",
    "FaceTemplate",
    "FacesIndex",
    "FingerprintIndex",
    "FingerprintTemplate",
    "canonical_bytes",
    "canonical_json",
    "comparable_record",
    "content_hash",
    "frozen_volatile_digest",
    "normalize_record",
    "read_bundle",
    "repo_root",
    "write_bundle",
]

#: The bundle layout version. A reader that does not understand this exact value
#: refuses the bundle instead of half-reading it (fail closed, design §0.7).
#: v2 is the E1-01b addendum layout: `fingerprints/` becomes a required directory,
#: the manifest gains the fingerprints section, the two INDEX digests and the
#: report-only enrollment counters, and faces/INDEX.json learns the AVAILABLE state
#: (entries + the photo_bytes recorded absence). A v1-era bundle carries none of
#: that accounting, so it is REFUSED rather than half-read — no v1 bundle exists in
#: the wild (E1-01 has never exported a real device), so there is nothing to migrate.
SCHEMA_VERSION = "gateclerk-enrollment-bundle/2"

#: The volatile strip list, FROZEN (design §2). `password` is unconditional (§0/R3):
#: a PIN never enters a bundle file in any mode. The counters change under the device's
#: own feet (a punch updates `openDoorTime`, an enrollment moves `numOf*`) and are
#: deliberately NOT part of a person's identity hash; their VALUES still ride in the
#: bundle for the E1-02 diff's unknown_enrollments classification (UNKNOWN not zero).
VOLATILE_FIELDS: frozenset[str] = frozenset(
    {"openDoorTime", "numOfCard", "numOfFace", "numOfFP", "password"}
)

#: Per-device URL fields: the host part of these is device-local plumbing, never
#: person data, and it differs per box by construction — so the value is dropped
#: entirely (a bare `/staging/...` path with a foreign host is still per-device).
VOLATILE_URL_FIELDS: frozenset[str] = frozenset({"photoURL", "faceURL"})

#: Row handles the DEVICE assigns for its own bookkeeping (live A->B, 2026-10-23:
#: site-B answers every `UserInfo/Search` row with a `picID`, site-A rows carry none).
#: Like the stripped URLs these are device-local plumbing, never person identity and
#: never migratable — the captured SetUp write body has no `picID` key, and the face
#: link is FPID/employeeNo, not picID. So they are excluded from the content hash and
#: from every field-SET comparison, but kept in the bundle bytes.
#:
#: NOT in ``VOLATILE_FIELDS`` — deliberately. That list is FROZEN into every bundle
#: manifest as ``frozen_volatile_digest()`` and ``read_bundle`` refuses a mismatch, so
#: widening it would make bundles already exported (the operator's site-a-20261023-1250)
#: unreadable. picID is excluded at COMPARE/HASH time only; no bundle byte moves.
#: If a future capture ever ties faces or cards to picID, this exclusion is wrong and
#: the card that finds it must say so — do not quietly widen the list.
DEVICE_ASSIGNED_FIELDS: frozenset[str] = frozenset({"picID"})

#: The faces state this card ships (v4 scope note, operator 2026-10-21): face
#: template export (FDSearch `modelData`) and FP template export moved to E1-01b;
#: this card records the absence with its reason so downstream cards read a fact,
#: not a silence.
FACES_ABSENT_REASON = "photos not exportable on this fw (faceURL 404); templates handled by E1-01b"

#: The fingerprints state until the FP walk runs (E1-01b): a bundle that never read
#: the FP surface says so, in the same voice faces use. An absent directory is
#: never "the device has no fingerprints" — that claim belongs to an AVAILABLE walk
#: that ended on NO MATCH (design §0.7: a failed/omitted read is never 'empty').
FINGERPRINTS_ABSENT_REASON = (
    "fingerprint templates not read this run (no FingerPrintUpload walk performed)"
)

#: The RECORDED FACT every AVAILABLE faces index carries (v4 §2: "the faceURL-404
#: note ... recorded fact, not an omission"). Photo bytes were probed four ways on
#: bench A and every way 404'd (OBSERVED.md "E1 enrollment-read probes", rounds
#: 11-18, 5 bounded GETs); the modelData TEMPLATE is the portable artifact, not the
#: JPEG. Recording the absence here is what stops a later card from mistaking an
#: empty photo set for a successful export.
PHOTO_BYTES_ABSENT_REASON = (
    "faceURL photo bytes NOT exportable on this fw: every GET form 404s (plain, "
    "%-encoded @WEB token, fresh-cookie same-session; bench A 2026-10-21, bounded "
    "probe rounds) — the modelData template is what makes face unlock work, the "
    "JPEG is a nice-to-have, not the product (ENROLLMENT-MIGRATION.md §1/§8 R1)"
)

#: Bundle layout names (design §2).
MANIFEST_NAME = "manifest.json"
_PEOPLE_NAME = "people.jsonl"
_CARDS_NAME = "cards.jsonl"
_FACES_DIR = "faces"
_FACES_INDEX_NAME = "INDEX.json"
_FINGERPRINTS_DIR = "fingerprints"
BUNDLE_FILES: frozenset[str] = frozenset({MANIFEST_NAME, _PEOPLE_NAME, _CARDS_NAME})
BUNDLE_DIRS: frozenset[str] = frozenset({_FACES_DIR, _FINGERPRINTS_DIR})

#: The full strip set both sides of every hash must agree on.
_STRIPPED_KEYS: frozenset[str] = VOLATILE_FIELDS | VOLATILE_URL_FIELDS

#: What every field-SET comparison (verify's unknown/lacking rule) must ignore: the
#: volatile strip set PLUS the device-assigned row handles. One name, one definition —
#: verify and the diff both read this, so the two sides can never drift apart.
COMPARE_EXEMPT_FIELDS: frozenset[str] = _STRIPPED_KEYS | DEVICE_ASSIGNED_FIELDS


def comparable_record(raw: Mapping[str, Any]) -> dict[str, Any]:
    """The shape every migration hash and field-set comparison uses.

    ``normalize_record`` (bundle bytes keep the device-assigned handle — see
    :data:`DEVICE_ASSIGNED_FIELDS` for why the strip list itself must not move) plus
    dropping the device-assigned keys. Use this whenever a record from one box is
    compared against a record from another box.
    """
    normalized = normalize_record(raw)
    if normalized.keys() & DEVICE_ASSIGNED_FIELDS:
        normalized = {k: v for k, v in normalized.items() if k not in DEVICE_ASSIGNED_FIELDS}
    return normalized


def frozen_volatile_digest() -> str:
    """sha256 over the canonical sorted volatile list — the manifest's freeze token.

    The manifest does NOT spell the volatile names (it stores only this digest):
    the card's hygiene contract is that the literal token `password` appears
    NOWHERE in bundle bytes — grep-style, across every file — and a manifest that
    listed the names would break that grep while trying to document it. The digest
    freezes the list at least as strongly as spelling it out: the reader recomputes
    it from the module constants and refuses a bundle whose export used any other
    strip set. (The names themselves live in code, in one place, on both sides.)
    """
    canonical = json.dumps(sorted(_STRIPPED_KEYS), sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


#: Directory/file modes (design §2: "Bundle dir 0700, files 0600"). Computed as
#: literals here — `stat.S_IXOTH`-style spelling is clearer about the intent: nobody
#: but the owning user may read a person's name out of this tree.
_DIR_MODE = 0o700
_FILE_MODE = 0o600


# --- normalization --------------------------------------------------------------------


def normalize_record(raw: Mapping[str, Any]) -> dict[str, Any]:
    """A copy of `raw` with EXACTLY the volatile set stripped; everything else verbatim.

    The single shared function (module docstring): bundle export, diff and verify all
    run their records through this, so the hashes are comparable across sides.

    - `openDoorTime`, `numOfCard`, `numOfFace`, `numOfFP`, `password` are removed
      (design §2; `password` UNCONDITIONALLY — R3).
    - `photoURL` / `faceURL` are removed whole: their host part is per-device and
      keeping any remnant of a device-local URL inside a *portable* hash would make
      every person differ across devices for a non-person reason.
    - Nothing else is touched — not key order (irrelevant after canonicalization),
      not `name`, not `Valid`, not `RightPlan`, not `doorRight`.
    """
    normalized: dict[str, Any] = {}
    for key, value in raw.items():
        if key in VOLATILE_FIELDS or key in VOLATILE_URL_FIELDS:
            continue
        normalized[key] = value
    return normalized


# --- canonical JSON + content hash -----------------------------------------------------


def _canonical_number(value: float) -> Any:
    """Normalize a JSON number: integral floats become ints (design §2).

    The device family is known to send counts as strings or numbers and (on siblings)
    floats where we expect ints (OBSERVED.md "int-vs-string/nested shape drift"). A
    float that carries no fractional part is the *same value* as the int spelling, and
    a content hash must not read firmware serialization as a payroll change. Non-finite
    floats cannot appear in valid JSON; if one arrives anyway it is data corruption and
    canonicalization refuses to launder it.
    """
    if value != value or value in (float("inf"), float("-inf")):  # NaN / ±inf
        raise ValueError(f"non-finite number {value!r} cannot be canonicalized")
    if value.is_integer():
        return int(value)
    return value


def _canonical_value(value: Any) -> Any:
    """Recursively rebuild `value` in canonical form (keys sorted at dump time)."""
    if isinstance(value, Mapping):
        out: dict[str, Any] = {}
        for key in value:
            if not isinstance(key, str):
                raise ValueError(f"canonical JSON needs string keys, got {key!r}")
            out[key] = _canonical_value(value[key])
        return out
    if isinstance(value, (list, tuple)):
        return [_canonical_value(item) for item in value]
    if isinstance(value, bool):
        # bool BEFORE int on purpose: True must stay true, never become 1 — the
        # device's `Valid.enable` is JSON true/false and "normalizing" it to a
        # number would collide enable=true with enable=1 records.
        return value
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        return _canonical_number(value)
    if value is None or isinstance(value, str):
        return value
    raise ValueError(f"cannot canonicalize {type(value).__name__} into JSON")


def canonical_json(record: Mapping[str, Any]) -> str:
    """The canonical text form: sorted keys, compact separators, UTF-8-safe escapes.

    `ensure_ascii=True` is deliberate: the bytes hashed must not depend on whether a
    given machine would write raw UTF-8 or escapes. `separators=(",", ":")` freezes
    whitespace. Same function on both sides = comparable hashes.
    """
    return json.dumps(
        _canonical_value(record), sort_keys=True, ensure_ascii=True, separators=(",", ":")
    )


def canonical_bytes(record: Mapping[str, Any]) -> bytes:
    """Canonical JSON encoded as UTF-8 bytes — what `content_hash` digests."""
    return canonical_json(record).encode("utf-8")


def content_hash(record: Mapping[str, Any]) -> str:
    """sha256 hex over canonical JSON of `record`, EXACTLY as given.

    Design §2: the hash is over "the record with ONLY the manifest's volatile set
    stripped". Stripping is owned by `normalize_record`; this function must not
    re-strip, because callers hash THREE different shapes and mixing them up is how a
    verify silently compares the wrong things:
      * the NORMALIZED record (people.jsonl lines) — `content_hash(normalize_record(r))`;
      * the RAW record (live target reads) — `content_hash(r)` normalizes internally
        so both spellings of a bundle-vs-live comparison land on identical bytes
        (normalize is idempotent on an already-stripped record);
      * a whole BUNDLE FILE (diff/verify integrity checks) — pass the parsed object
        itself; a re-strip there would strip data the diff depends on.
    """
    normalized = record if _is_comparable(record) else comparable_record(record)
    return hashlib.sha256(canonical_bytes(normalized)).hexdigest()


def _is_comparable(record: Mapping[str, Any]) -> bool:
    """True when `record` already carries none of the volatile nor device-assigned keys."""
    return not (set(record) & COMPARE_EXEMPT_FIELDS)


# --- manifest + faces index shapes ------------------------------------------------------


@dataclass(frozen=True, slots=True)
class FaceTemplate:
    """One FDSearch `modelData` row as the bundle records it (E1-01b).

    The template bytes themselves live ONLY in `faces/<employeeNo>.b64`; this entry
    is the accountable metadata around them: which FD library the row came from
    (`fdid`/`face_lib_type`), which person the device bound it to (`employee_no` —
    the FPID joined to employeeNo by OPAQUE STRING EQUALITY, §1: "007" joins "007",
    never "7"), and sha256+length of the DECODED template. `sha256`/`length` are
    over the decoded bytes the device's base64 carried — hashing the decoded form is
    transport, not parsing: nothing here decodes or interprets template STRUCTURE.
    """

    employee_no: str
    fdid: str
    face_lib_type: str
    sha256: str
    length: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "employeeNo": self.employee_no,
            "fdid": self.fdid,
            "faceLibType": self.face_lib_type,
            "sha256": self.sha256,
            "length": self.length,
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> FaceTemplate:
        return cls(
            employee_no=str(payload.get("employeeNo") or ""),
            fdid=str(payload.get("fdid") or ""),
            face_lib_type=str(payload.get("faceLibType") or ""),
            sha256=str(payload.get("sha256") or ""),
            length=int(payload.get("length") or 0),
        )


@dataclass(frozen=True, slots=True)
class FacesIndex:
    """faces/INDEX.json — faces are either a RECORDED ABSENCE or a WALKED SET.

    * `UNAVAILABLE` (E1-01's default): `reason` says why in the operator's recorded
      words, entries stay empty — never a silent empty directory.
    * `AVAILABLE` (E1-01b ran the FDSearch walk): `entries` carry per-person
      FDID/FPID/sha256/length, and `photo_bytes` records the fact that faceURL
      PHOTO bytes are not exportable on this fw (§2: "recorded fact, not an
      omission"). An AVAILABLE index with zero entries is an honest zero — the walk
      completed and the device said NO MATCH — and it is distinguishable from
      UNAVAILABLE precisely because the state says which. `photo_bytes` is REQUIRED
      in this state: a face export that forgot why the JPEGs are missing is the
      silence §0.7 refuses.
    """

    state: str = "UNAVAILABLE"
    reason: str = FACES_ABSENT_REASON
    entries: tuple[FaceTemplate, ...] = ()
    photo_bytes: Mapping[str, str] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {"state": self.state, "reason": self.reason}
        if self.state == "AVAILABLE":
            payload["entries"] = [entry.to_dict() for entry in self.entries]
            payload["photo_bytes"] = dict(self.photo_bytes)
        return payload

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> FacesIndex:
        state = payload.get("state")
        if state == "UNAVAILABLE":
            return cls(state=state, reason=str(payload.get("reason") or ""))
        if state == "AVAILABLE":
            raw_entries = payload.get("entries")
            if not isinstance(raw_entries, list):
                raise ValueError(
                    "faces/INDEX.json state is AVAILABLE but carries no `entries` list — "
                    "an index whose claim cannot be checked is refused, not half-read "
                    "(design §0.7)"
                )
            photo = payload.get("photo_bytes")
            if not isinstance(photo, Mapping) or not str(photo.get("reason") or ""):
                raise ValueError(
                    "faces/INDEX.json AVAILABLE without a photo_bytes.reason — the "
                    "faceURL-404 recorded absence (design §2) must travel with every "
                    "template walk; an index that forgot why photos are missing is "
                    "exactly the silence §0.7 refuses"
                )
            return cls(
                state=state,
                reason=str(payload.get("reason") or ""),
                entries=tuple(
                    FaceTemplate.from_dict(entry)
                    for entry in raw_entries
                    if isinstance(entry, Mapping)
                ),
                photo_bytes=dict(photo),
            )
        raise ValueError(
            f"faces/INDEX.json state {state!r} is not readable by this schema "
            "(UNAVAILABLE / AVAILABLE) — any other state means a file this reader "
            "must not half-understand (fail closed)"
        )


@dataclass(frozen=True, slots=True)
class FingerprintTemplate:
    """One FingerPrintUpload row as the bundle records it (E1-01b).

    Bytes live only in `fingerprints/<employeeNo>-<fpIndex>.b64`. `sensor_family` is
    a NOTE derived from the template's leading bytes by the export (bench A: ASCII
    "301"-style header = third-party sensor family, NOT self-identified,
    OBSERVED.md) — a label about the bytes, never a parse of them, and the
    same-sensor-family portability claim (§1) rests on the reader seeing it.
    """

    employee_no: str
    fp_index: int
    sha256: str
    length: int
    sensor_family: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "employeeNo": self.employee_no,
            "fpIndex": self.fp_index,
            "sha256": self.sha256,
            "length": self.length,
            "sensor_family": self.sensor_family,
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> FingerprintTemplate:
        return cls(
            employee_no=str(payload.get("employeeNo") or ""),
            fp_index=int(payload.get("fpIndex") or 0),
            sha256=str(payload.get("sha256") or ""),
            length=int(payload.get("length") or 0),
            sensor_family=str(payload.get("sensor_family") or ""),
        )


@dataclass(frozen=True, slots=True)
class FingerprintIndex:
    """fingerprints/INDEX.json — the same two-state discipline faces use.

    UNAVAILABLE says the walk never ran (the E1-01 default); AVAILABLE says every
    employee got one definitive read (a template row, or the device's captured
    `status: "NoFP"` zero — §5.0 capture 2026-10-22 shows FingerPrintUpload ignores
    fpIndex, so it is one read per person, not a walk), with per-file
    sha256/length + the sensor-family note. Zero entries + AVAILABLE = the device
    answered `NoFP` for every person — an honest zero, not a silence.
    """

    state: str = "UNAVAILABLE"
    reason: str = FINGERPRINTS_ABSENT_REASON
    entries: tuple[FingerprintTemplate, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {"state": self.state, "reason": self.reason}
        if self.state == "AVAILABLE":
            payload["entries"] = [entry.to_dict() for entry in self.entries]
        return payload

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> FingerprintIndex:
        state = payload.get("state")
        if state == "UNAVAILABLE":
            return cls(state=state, reason=str(payload.get("reason") or ""))
        if state == "AVAILABLE":
            raw_entries = payload.get("entries")
            if not isinstance(raw_entries, list):
                raise ValueError(
                    "fingerprints/INDEX.json state is AVAILABLE but carries no "
                    "`entries` list — an index whose claim cannot be checked is "
                    "refused, not half-read (design §0.7)"
                )
            return cls(
                state=state,
                reason=str(payload.get("reason") or ""),
                entries=tuple(
                    FingerprintTemplate.from_dict(entry)
                    for entry in raw_entries
                    if isinstance(entry, Mapping)
                ),
            )
        raise ValueError(
            f"fingerprints/INDEX.json state {state!r} is not readable by this schema "
            "(UNAVAILABLE / AVAILABLE) — fail closed, same rule as faces"
        )


@dataclass(frozen=True, slots=True)
class BundleManifest:
    """manifest.json — the self-describing head of a bundle (design §2).

    Deliberate absences: the device HOST (the directory name carries the site label;
    the manifest carries a masked serial PREFIX only — no bundle file may leak a live
    address) and any pin bytes (R3). The face/FP sections carry COUNTS + a DIGEST of
    the index entries — never raw template bytes and never the full entry lists
    (those live in the INDEX.json files; the digest pins them against edits without
    duplicating them, same pattern as volatile_fields_digest).

    The `enrollment_counters` section is REPORT-ONLY (v4 §9 "counter vs set"): the
    device's per-person `numOfFace`/`numOfFP` values next to what the walks actually
    exported. A counter is not a set — E1-02's conflict classification consumes the
    disagreement, the export never resolves it silently.
    """

    schema_version: str
    exported_at: str  # UTC ISO-8601 from an INJECTED clock — never datetime.now here
    identity: Mapping[str, Any]  # model, firmware, serial_prefix — never the host
    counts: Mapping[str, int]  # users / cards / faces / fingerprints
    people_hashes: Mapping[str, str]  # employeeNo (opaque) -> content hash
    volatile_fields_digest: str  # frozen list commitment (see frozen_volatile_digest)
    faces: Mapping[str, str]  # {"state": ..., "reason": ...}
    termination: Mapping[str, str]  # endpoint -> normalized terminal status (audit)
    fingerprints: Mapping[str, str] = field(default_factory=dict)
    faces_index_digest: str = ""  # sha256 over the canonical faces INDEX entries
    fingerprints_index_digest: str = ""  # same for the FP index
    enrollment_counters: Mapping[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "exported_at": self.exported_at,
            "identity": dict(self.identity),
            "counts": dict(self.counts),
            "people_hashes": dict(self.people_hashes),
            "volatile_fields_digest": self.volatile_fields_digest,
            "faces": dict(self.faces),
            "fingerprints": dict(self.fingerprints),
            "faces_index_digest": self.faces_index_digest,
            "fingerprints_index_digest": self.fingerprints_index_digest,
            "enrollment_counters": dict(self.enrollment_counters),
            "termination": dict(self.termination),
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> BundleManifest:
        version = payload.get("schema_version")
        if version != SCHEMA_VERSION:
            raise ValueError(
                f"bundle schema {version!r} is not {SCHEMA_VERSION!r} — refusing to "
                "read a bundle whose layout this code has not reviewed"
            )
        manifest = cls(
            schema_version=version,
            exported_at=str(payload.get("exported_at") or ""),
            identity=dict(payload.get("identity") or {}),
            counts=dict(payload.get("counts") or {}),
            people_hashes=dict(payload.get("people_hashes") or {}),
            volatile_fields_digest=str(payload.get("volatile_fields_digest") or ""),
            faces=dict(payload.get("faces") or {}),
            termination=dict(payload.get("termination") or {}),
            fingerprints=dict(payload.get("fingerprints") or {}),
            faces_index_digest=str(payload.get("faces_index_digest") or ""),
            fingerprints_index_digest=str(payload.get("fingerprints_index_digest") or ""),
            enrollment_counters=dict(payload.get("enrollment_counters") or {}),
        )
        # The frozen digest is a CONTRACT, not decoration: a bundle exported under a
        # different volatile strip set would hash records over different keys, and
        # diff/verify hashes would silently compare different things. Refuse it
        # (fail closed, §0.7). See `frozen_volatile_digest` for why the manifest
        # carries a digest of the list instead of the names themselves.
        if manifest.volatile_fields_digest != frozen_volatile_digest():
            raise ValueError(
                "bundle manifest volatile-list digest does not match this code's "
                f"frozen set {sorted(_STRIPPED_KEYS)!r} — hashes from this bundle "
                "are not comparable; refusing to read it"
            )
        return manifest


@dataclass(frozen=True, slots=True)
class BundleData:
    """A bundle as data: what E1-02's diff consumes (never reach for the files)."""

    manifest: BundleManifest
    people: tuple[Mapping[str, Any], ...]
    cards: tuple[Mapping[str, Any], ...]
    faces: FacesIndex
    fingerprints: FingerprintIndex = field(default_factory=FingerprintIndex)

    def person_hashes(self) -> dict[str, str]:
        """Recomputed per-person hashes, keyed by opaque employeeNo."""
        return {
            str(record["employeeNo"]): content_hash(record)
            for record in self.people
            if "employeeNo" in record
        }


# --- repo-out refusal -------------------------------------------------------------------


def repo_root(start: Path | None = None) -> Path | None:
    """The nearest ancestor directory containing `.git`, or None.

    `.git` may be a directory (a checkout) OR a FILE (a linked worktree — every kanban
    worker runs in one), so both spellings count. A bundle of personal data inside a
    public repo tree is the failure design §2 refuses; the refusal has to see through
    worktrees exactly like `git rev-parse --show-toplevel` does.
    """
    current = (start or Path.cwd()).resolve()
    for candidate in (current, *current.parents):
        if (candidate / ".git").exists():
            return candidate
    return None


def _refuse_repo_out(out: Path) -> None:
    root = repo_root(out)
    if root is not None:
        raise BundleRepoOutError(
            f"refusing to write an enrollment bundle inside a git repo: out={out} is "
            f"under {root}. Bundles carry personal data (names, cards, hashes); a "
            "public repo must never contain one (design §2 'REFUSE an --out inside "
            "the repo'). Write under a private root such as ~/gateclerk/bundles/."
        )
    # Defence in depth: `out` may not exist yet, so repo_root(start) above only sees
    # ancestors that exist. Check the literal path text for the worktree/checkout
    # markers too — a typo'd --out that would land "next to" the repo is cheap to catch.
    lowered = str(out).lower()
    for marker in ("/.worktrees/", "/worktrees/"):
        if marker in lowered:
            raise BundleRepoOutError(
                f"refusing to write an enrollment bundle under a worktree path: {out}"
            )


# --- file hygiene -----------------------------------------------------------------------


def _write_private_text(path: Path, text: str) -> None:
    """Write `text` to `path` at mode 0600, atomically-ish, on an existing 0700 dir.

    `os.open(..., 0o600)` sets the mode at creation — an ordinary `write_text` would
    first create the file with the umask default (often 0644) and a person's name
    would be group-readable for the length of the write.
    """
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, _FILE_MODE)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(text)
    except Exception:
        # fdopen took ownership of the fd on success and closes it on its own exit;
        # if it raised, the fd is still ours and must not leak.
        with contextlib.suppress(OSError):
            os.close(fd)
        raise
    # Belt: honor the intent even if the caller's umask was weird at creation time.
    path.chmod(_FILE_MODE)


def _ensure_private_dir(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)
    path.chmod(_DIR_MODE)
    if stat.S_IMODE(path.stat().st_mode) != _DIR_MODE:  # pragma: no cover - paranoia
        raise RuntimeError(f"bundle dir {path} is not 0700 — refusing to populate it")


#: Charset for template file stems built from device-supplied employeeNo: word
#: characters, dot, hyphen. Path separators are NOT in the charset, and the guard
#: below additionally rejects leading dots and `..` — defense in depth so a device
#: (or a tampered search row) can never name a file outside the faces/ or
#: fingerprints/ directory. Anything the device sent that is NOT in this charset is
#: refused loudly, not sanitized: silently rewriting a person's key is the §1
#: normalization bug in a costume.
_TEMPLATE_STEM_CHARS = set(string.ascii_letters + string.digits + "._-")


def _dump_line(record: Mapping[str, Any]) -> str:
    """One bundle jsonl line: canonical form, so the FILE bytes are byte-stable too."""
    return canonical_json(record)


def index_digest(entries: Sequence[Mapping[str, Any]]) -> str:
    """sha256 over the canonical JSON of an index's entry list (order-sensitive).

    The manifest commits to the INDEX.json entries with this, exactly the way
    `volatile_fields_digest` commits to the strip list: the entries live in their
    own file (single source of truth), the manifest pins their content, and the
    reader recomputes to detect a bundle edited after export. Entries canonicalize
    through the SAME `canonical_json` every other hash in this module uses — no
    second hashing dialect for the biometric axis.
    """
    return hashlib.sha256(canonical_bytes({"entries": list(entries)})).hexdigest()


def safe_template_stem(employee_no: str) -> str:
    """The filesystem stem for one person's template files (opaque employeeNo, §1).

    `employeeNo` arrives from the DEVICE and the bundle path is built from it, so
    the value must not be able to spell a path: separators are outside the charset,
    leading dots and `..` are rejected, and empty/padded values are rejected (a
    person we cannot name a file for is a person we cannot key — fail closed). This
    is a filename guard, not a normalization: a passing value is used EXACTLY as the
    device sent it — "007" stays "007" (§1: leading zeros are data).
    """
    if not employee_no or employee_no != employee_no.strip():
        raise ValueError(
            f"employeeNo {employee_no!r} is empty or carries padding — template files "
            "would name a person the bundle cannot key; refusing (fail closed, §0.7)"
        )
    if employee_no.startswith(".") or ".." in employee_no:
        raise ValueError(
            f"employeeNo {employee_no!r} starts with a dot or contains '..' — a "
            "bundle file name may never traverse; refusing"
        )
    bad = sorted({c for c in employee_no if c not in _TEMPLATE_STEM_CHARS})
    if bad:
        raise ValueError(
            f"employeeNo {employee_no!r} contains {bad} — characters this bundle "
            "format will not put into a file name; the opaque value is used verbatim "
            "otherwise (§1), it is never sanitized to pass"
        )
    return employee_no


# --- writer ------------------------------------------------------------------------------


def write_bundle(
    out_dir: Path,
    *,
    identity: Mapping[str, Any],
    exported_at: datetime,
    people: Iterable[Mapping[str, Any]] = (),
    cards: Iterable[Mapping[str, Any]] = (),
    faces: FacesIndex | None = None,
    fingerprints: FingerprintIndex | None = None,
    face_templates: Mapping[str, str] | None = None,
    fingerprint_templates: Sequence[tuple[str, int, str]] | None = None,
    enrollment_counters: Mapping[str, Any] | None = None,
    termination: Mapping[str, str] | None = None,
) -> Path:
    """Write the bundle atomically and return its path.

    * `exported_at` comes from an INJECTED clock (card: tests assert frozen bytes);
      naive datetimes are treated as UTC, never as local wall time.
    * People/cards are normalized HERE and only here on the write side — the export
      reader hands raw device records to keep the seam honest, and the bundle is the
      place they become normalized lines. A record without an opaque `employeeNo` is
      refused (a person we cannot key is a person we cannot diff or verify).
    * `face_templates` maps employeeNo -> the device's base64 `modelData` string
      VERBATIM (opaque: this module never decodes, parses or re-encodes template
      bytes, design §2) and writes `faces/<employeeNo>.b64`; `fingerprint_templates`
      is the same for `(employeeNo, fpIndex, device base64)` ->
      `fingerprints/<employeeNo>-<fpIndex>.b64`. A template whose employeeNo is not
      one of the bundled people is REFUSED (an orphan template is either a join bug
      or a tampered search row — §0.7 refuses to bundle either), and the matching
      INDEX state must be AVAILABLE (bytes without a walked index is the silence
      §0.7 names).
    * Refuses an out dir inside a git repo (public-repo hygiene).
    * Writes to a sibling `*.partial` dir and renames at the end: a crash mid-export
      leaves a `*.partial` on disk, NEVER a plausible-but-truncated bundle at the
      final path (a truncated bundle that reads as complete is the rollback source
      that isn't one).
    """
    out = Path(out_dir)
    _refuse_repo_out(out)
    if exported_at.tzinfo is None:
        exported_at = exported_at.replace(tzinfo=UTC)
    exported_at = exported_at.astimezone(UTC)

    normalized_people: list[dict[str, Any]] = []
    for raw in people:
        record = normalize_record(raw)
        if "employeeNo" not in record or record["employeeNo"] == "":
            raise ValueError(
                "refusing to bundle a person record without an employeeNo — a person "
                "we cannot key by the opaque number cannot be diffed or verified"
            )
        normalized_people.append(record)
    normalized_cards = [normalize_record(raw) for raw in cards]
    people_keys = {str(record["employeeNo"]) for record in normalized_people}

    face_files = face_templates or {}
    fp_files = fingerprint_templates or ()
    faces_index = faces or FacesIndex()
    fp_index = fingerprints or FingerprintIndex()
    if face_files and faces_index.state != "AVAILABLE":
        raise ValueError(
            f"refusing to write {len(face_files)} face template(s) into a bundle whose "
            f"faces/INDEX.json state is {faces_index.state!r} — template bytes without "
            "a walked, accountable index is exactly the silence design §0.7 refuses"
        )
    if fp_files and fp_index.state != "AVAILABLE":
        raise ValueError(
            f"refusing to write {len(fp_files)} fingerprint template(s) into a bundle "
            f"whose fingerprints/INDEX.json state is {fp_index.state!r} — same rule "
            "as faces: bytes must travel with the index that accounts for them"
        )
    for employee_no in face_files:
        safe_template_stem(employee_no)  # filename guard before any join
        if employee_no not in people_keys:
            raise ValueError(
                f"face template for employeeNo {employee_no!r} has no matching person "
                "in people.jsonl — an orphan template is a join bug or a tampered "
                "FDSearch row (FPID joined to a person who is not on the roster); "
                "refusing (fail closed, §0.7)"
            )
    for employee_no, fp_index_no, _b64 in fp_files:
        safe_template_stem(f"{employee_no}")
        if employee_no not in people_keys:
            raise ValueError(
                f"fingerprint template for employeeNo {employee_no!r} (fpIndex "
                f"{fp_index_no}) has no matching person in people.jsonl — refusing "
                "an orphan template (fail closed, §0.7)"
            )
    # The index digests are computed from the index objects handed in; the writer
    # never re-derives entries from files (single source of truth stays with the
    # caller that actually walked the device, and the reader re-verifies).

    people_text = (
        "".join(_dump_line(record) + "\n" for record in normalized_people) if people else ""
    )
    cards_text = "".join(_dump_line(record) + "\n" for record in normalized_cards) if cards else ""

    manifest = BundleManifest(
        schema_version=SCHEMA_VERSION,
        exported_at=exported_at.isoformat(),
        identity=dict(identity),
        counts={
            "users": len(normalized_people),
            "cards": len(normalized_cards),
            # Truthful ONLY because each section's state says what it means: an
            # UNAVAILABLE count of 0 reads as "not walked", an AVAILABLE 0 as
            # "walked and empty" (design §0.7 — silence is never zero).
            "faces": len(faces_index.entries),
            "fingerprints": len(fp_index.entries),
        },
        people_hashes={
            str(record["employeeNo"]): content_hash(record) for record in normalized_people
        },
        volatile_fields_digest=frozen_volatile_digest(),
        faces=faces_index.to_dict(),
        fingerprints=fp_index.to_dict(),
        faces_index_digest=index_digest([e.to_dict() for e in faces_index.entries]),
        fingerprints_index_digest=index_digest([e.to_dict() for e in fp_index.entries]),
        enrollment_counters=dict(enrollment_counters or {}),
        termination=dict(termination or {}),
    )
    manifest_text = canonical_json(manifest.to_dict()) + "\n"

    staging = out.with_name(out.name + ".partial")
    if staging.exists():
        raise ValueError(
            f"staging path {staging} already exists — a crashed export left debris; "
            "remove it deliberately (it may hold half-written personal data)"
        )
    _ensure_private_dir(staging)
    _ensure_private_dir(staging / _FACES_DIR)
    _ensure_private_dir(staging / _FINGERPRINTS_DIR)
    try:
        _write_private_text(staging / _PEOPLE_NAME, people_text)
        _write_private_text(staging / _CARDS_NAME, cards_text)
        _write_private_text(
            staging / _FACES_DIR / _FACES_INDEX_NAME,
            canonical_json(faces_index.to_dict()) + "\n",
        )
        _write_private_text(
            staging / _FINGERPRINTS_DIR / _FACES_INDEX_NAME,
            canonical_json(fp_index.to_dict()) + "\n",
        )
        # Template bytes: the device's base64 VERBATIM (§2 "base64 as the device
        # gave it") — the ONLY transformation here is the trailing newline, so the
        # bytes hashed by the index and the bytes on disk stay reconcilable.
        for employee_no, b64 in sorted(face_files.items()):
            _write_private_text(
                staging / _FACES_DIR / f"{safe_template_stem(employee_no)}.b64", b64 + "\n"
            )
        for employee_no, fp_index_no, b64 in fp_files:
            _write_private_text(
                staging
                / _FINGERPRINTS_DIR
                / f"{safe_template_stem(employee_no)}-{fp_index_no}.b64",
                b64 + "\n",
            )
        _write_private_text(staging / MANIFEST_NAME, manifest_text)
        if out.exists():
            raise ValueError(
                f"bundle already exists at {out} — refusing to overwrite a rollback "
                "source in place (design §0.1); pass a fresh --out directory"
            )
        os.replace(staging, out)  # noqa: PTH105 — atomic rename IS the point
    except BaseException:
        # Leave the partial visible for a human; do NOT quietly delete possible data.
        raise
    return out


# --- reader -----------------------------------------------------------------------------


def _read_private_text(path: Path, *, bundle: Path) -> str:
    if not path.is_file():
        raise ValueError(f"bundle {bundle} is missing {path.name} — refusing a partial bundle")
    return path.read_text(encoding="utf-8")


def _read_jsonl(text: str, *, bundle: Path, name: str) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for lineno, line in enumerate(text.splitlines(), start=1):
        if not line.strip():
            continue
        try:
            loaded = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ValueError(f"{name}:{lineno} is not valid JSON ({exc}) — refusing") from exc
        if not isinstance(loaded, dict):
            raise ValueError(f"{name}:{lineno} is a {type(loaded).__name__}, not an object")
        records.append(loaded)
    return records


def read_bundle(bundle_dir: Path) -> BundleData:
    """Load and VALIDATE a bundle. Fail closed on anything this schema did not review.

    * schema version + frozen volatile list are checked (BundleManifest.from_dict);
    * a people.jsonl line that still carries a volatile key (notably `password`) is
      REFUSED — a bundle written by an older/other tool must never be diffed as if it
      were ours, and "no pin in the bundle" stays enforceable on the read side too;
    * faces/INDEX.json and fingerprints/INDEX.json must exist and parse (either
      state, design §2); an AVAILABLE section must agree with what is on disk:
      every entry has its .b64 file, the manifest digest matches the entries, and
      each file's decoded bytes match the entry's recorded sha256/length — a
      rollback source that cannot vouch for its own template bytes is refused, not
      half-trusted (a face restore from a tampered .b64 is payroll-adjacent data
      corruption wearing a biometric costume).
    """
    bundle = Path(bundle_dir)
    manifest = BundleManifest.from_dict(
        json.loads(_read_private_text(bundle / MANIFEST_NAME, bundle=bundle))
    )
    people = _read_jsonl(
        _read_private_text(bundle / _PEOPLE_NAME, bundle=bundle), bundle=bundle, name=_PEOPLE_NAME
    )
    cards = _read_jsonl(
        _read_private_text(bundle / _CARDS_NAME, bundle=bundle), bundle=bundle, name=_CARDS_NAME
    )
    faces = FacesIndex.from_dict(
        json.loads(_read_private_text(bundle / _FACES_DIR / _FACES_INDEX_NAME, bundle=bundle))
    )
    fingerprints = FingerprintIndex.from_dict(
        json.loads(
            _read_private_text(bundle / _FINGERPRINTS_DIR / _FACES_INDEX_NAME, bundle=bundle)
        )
    )
    for name, records in ((_PEOPLE_NAME, people), (_CARDS_NAME, cards)):
        for record in records:
            leftovers = sorted(set(record) & (VOLATILE_FIELDS | VOLATILE_URL_FIELDS))
            if leftovers:
                raise ValueError(
                    f"{name} carries volatile field(s) {leftovers} — this bundle was not "
                    "written by this schema (a surviving `password` here would be a pin "
                    "in a PII file, design §2/R3); refusing to read it"
                )
    expected = {
        str(record["employeeNo"]): content_hash(record)
        for record in people
        if "employeeNo" in record
    }
    if expected != dict(manifest.people_hashes):
        raise ValueError(
            f"bundle {bundle}: manifest per-person hashes do not match people.jsonl — "
            "the bundle was edited or truncated after export; refusing to diff or "
            "restore from it"
        )
    counts = dict(manifest.counts)
    if (
        counts.get("users") != len(people)
        or counts.get("cards") != len(cards)
        or counts.get("faces") != len(faces.entries)
        or counts.get("fingerprints") != len(fingerprints.entries)
    ):
        raise ValueError(
            f"bundle {bundle}: manifest counts {counts} disagree with the record files "
            f"(people={len(people)} cards={len(cards)} faces={len(faces.entries)} "
            f"fingerprints={len(fingerprints.entries)}) — refusing a bundle that "
            "cannot say what it holds"
        )
    if manifest.faces_index_digest != index_digest([e.to_dict() for e in faces.entries]):
        raise ValueError(
            f"bundle {bundle}: manifest faces_index_digest does not match "
            "faces/INDEX.json entries — the index was edited after export; refusing"
        )
    if manifest.fingerprints_index_digest != index_digest(
        [e.to_dict() for e in fingerprints.entries]
    ):
        raise ValueError(
            f"bundle {bundle}: manifest fingerprints_index_digest does not match "
            "fingerprints/INDEX.json entries — the index was edited after export; refusing"
        )
    _verify_template_bytes(bundle, faces, fingerprints)
    return BundleData(
        manifest=manifest,
        people=tuple(people),
        cards=tuple(cards),
        faces=faces,
        fingerprints=fingerprints,
    )


def _verify_template_bytes(bundle: Path, faces: FacesIndex, fingerprints: FingerprintIndex) -> None:
    """Re-verify every AVAILABLE-state template file against its index entry.

    The recorded sha256/length are over the DECODED device bytes (what the device's
    base64 carried). Decoding a .b64 file to verify it is transport reconciliation,
    not parsing: the bytes are still never interpreted (opaque rule, §2) — this only
    proves "the file on disk still is what the walk recorded", which is exactly the
    claim a rollback source must be able to make.
    """
    for entry in faces.entries:
        path = bundle / _FACES_DIR / f"{safe_template_stem(entry.employee_no)}.b64"
        _verify_one_b64(
            path,
            expect_sha256=entry.sha256,
            expect_length=entry.length,
            label=f"face template {entry.employee_no!r}",
            bundle=bundle,
        )
    for entry in fingerprints.entries:
        path = (
            bundle
            / _FINGERPRINTS_DIR
            / f"{safe_template_stem(entry.employee_no)}-{entry.fp_index}.b64"
        )
        _verify_one_b64(
            path,
            expect_sha256=entry.sha256,
            expect_length=entry.length,
            label=f"fingerprint template {entry.employee_no!r} fpIndex {entry.fp_index}",
            bundle=bundle,
        )


def _verify_one_b64(
    path: Path, *, expect_sha256: str, expect_length: int, label: str, bundle: Path
) -> None:
    text = _read_private_text(path, bundle=bundle)
    try:
        decoded = base64.b64decode(text.strip(), validate=True)
    except ValueError as exc:  # binascii.Error is a ValueError subclass
        raise ValueError(
            f"bundle {bundle}: {label} file {path.name} is not strict base64 "
            f"({exc}) — a template file the bundle cannot decode is refused, not "
            "half-read (fail closed, §0.7)"
        ) from exc
    if len(decoded) != expect_length or hashlib.sha256(decoded).hexdigest() != expect_sha256:
        raise ValueError(
            f"bundle {bundle}: {label} bytes do not match the index "
            f"(len {len(decoded)} vs {expect_length}, or sha256 mismatch) — the "
            "bundle was edited or truncated after export; refusing to diff, verify "
            "or restore from it"
        )
