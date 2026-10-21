"""The E1 enrollment bundle: normalization, content hashes, writer, reader (card E1-01).

This module is the SINGLE home of the record-normalization and content-hash rules
(design docs/ENROLLMENT-MIGRATION.md §2). Diff (E1-02) and read-back verify (E1-04/05)
import `normalize_record` / `content_hash` from here — they must never re-express them,
because the whole diff/verify contract rests on the source side and the target side
computing byte-identical hashes with the *same* function. Two implementations that can
drift is the bug class this module exists to prevent.

What the bundle is (design §2, v4):

    <out>/
      manifest.json     schema version, frozen volatile-field list, source identity
                        (model, fw, serial prefix — NEVER the host), exported_at from
                        an INJECTED clock, counts, per-person content hashes,
                        faces state + reason (v4 scope note: face *template* export
                        belongs to E1-01b; this card records the state, never bytes)
      people.jsonl      normalized UserInfo records, one JSON object per line.
                        `password` NEVER appears — it is stripped at read time (R3).
      cards.jsonl       normalized CardInfo records (employeeNo, cardNo, ...).
      faces/INDEX.json  {"state": "UNAVAILABLE", "reason": ...} — this card ships
                        faces as a recorded absence, not as data.

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

import contextlib
import hashlib
import json
import os
import stat
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

__all__ = [
    "BUNDLE_DIRS",
    "BUNDLE_FILES",
    "FACES_ABSENT_REASON",
    "MANIFEST_NAME",
    "SCHEMA_VERSION",
    "VOLATILE_FIELDS",
    "VOLATILE_URL_FIELDS",
    "BundleData",
    "BundleManifest",
    "FacesIndex",
    "canonical_bytes",
    "canonical_json",
    "content_hash",
    "frozen_volatile_digest",
    "normalize_record",
    "read_bundle",
    "repo_root",
    "write_bundle",
]

#: The bundle layout version. A reader that does not understand this exact value
#: refuses the bundle instead of half-reading it (fail closed, design §0.7).
SCHEMA_VERSION = "gateclerk-enrollment-bundle/1"

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

#: The faces state this card ships (v4 scope note, operator 2026-10-21): face
#: template export (FDSearch `modelData`) and FP template export moved to E1-01b;
#: this card records the absence with its reason so downstream cards read a fact,
#: not a silence.
FACES_ABSENT_REASON = "photos not exportable on this fw (faceURL 404); templates handled by E1-01b"

#: Bundle layout names (design §2).
MANIFEST_NAME = "manifest.json"
_PEOPLE_NAME = "people.jsonl"
_CARDS_NAME = "cards.jsonl"
_FACES_DIR = "faces"
_FACES_INDEX_NAME = "INDEX.json"
BUNDLE_FILES: frozenset[str] = frozenset({MANIFEST_NAME, _PEOPLE_NAME, _CARDS_NAME})
BUNDLE_DIRS: frozenset[str] = frozenset({_FACES_DIR})

#: The full strip set both sides of every hash must agree on.
_STRIPPED_KEYS: frozenset[str] = VOLATILE_FIELDS | VOLATILE_URL_FIELDS


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
    normalized = record if _is_normalized(record) else normalize_record(record)
    return hashlib.sha256(canonical_bytes(normalized)).hexdigest()


def _is_normalized(record: Mapping[str, Any]) -> bool:
    """True when `record` already carries none of the volatile keys."""
    return not (set(record) & (VOLATILE_FIELDS | VOLATILE_URL_FIELDS))


# --- manifest + faces index shapes ------------------------------------------------------


@dataclass(frozen=True, slots=True)
class FacesIndex:
    """faces/INDEX.json: faces are a RECORDED ABSENCE in this bundle (v4 scope note).

    `state` is UNAVAILABLE (never a silent empty directory), `reason` says why in the
    operator's recorded words, and `counts.faces = 0` is truthful only *because* the
    state says what it means.
    """

    state: str = "UNAVAILABLE"
    reason: str = FACES_ABSENT_REASON

    def to_dict(self) -> dict[str, Any]:
        return {"state": self.state, "reason": self.reason}

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> FacesIndex:
        state = payload.get("state")
        if state != "UNAVAILABLE":
            raise ValueError(
                f"faces/INDEX.json state {state!r} is not readable by this schema: this "
                "bundle version carries NO face bytes, so any other state means a file "
                "this reader must not half-understand (fail closed)"
            )
        return cls(state=state, reason=str(payload.get("reason") or ""))


@dataclass(frozen=True, slots=True)
class BundleManifest:
    """manifest.json — the self-describing head of a bundle (design §2).

    Deliberate absences: the device HOST (the directory name carries the site label;
    the manifest carries a masked serial PREFIX only — no bundle file may leak a live
    address) and any pin bytes (R3).
    """

    schema_version: str
    exported_at: str  # UTC ISO-8601 from an INJECTED clock — never datetime.now here
    identity: Mapping[str, Any]  # model, firmware, serial_prefix — never the host
    counts: Mapping[str, int]  # users / cards / faces
    people_hashes: Mapping[str, str]  # employeeNo (opaque) -> content hash
    volatile_fields_digest: str  # frozen list commitment (see frozen_volatile_digest)
    faces: Mapping[str, str]  # {"state": ..., "reason": ...}
    termination: Mapping[str, str]  # endpoint -> normalized terminal status (audit)

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "exported_at": self.exported_at,
            "identity": dict(self.identity),
            "counts": dict(self.counts),
            "people_hashes": dict(self.people_hashes),
            "volatile_fields_digest": self.volatile_fields_digest,
            "faces": dict(self.faces),
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
        raise ValueError(
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
            raise ValueError(f"refusing to write an enrollment bundle under a worktree path: {out}")


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


def _dump_line(record: Mapping[str, Any]) -> str:
    """One bundle jsonl line: canonical form, so the FILE bytes are byte-stable too."""
    return canonical_json(record)


# --- writer ------------------------------------------------------------------------------


def write_bundle(
    out_dir: Path,
    *,
    identity: Mapping[str, Any],
    exported_at: datetime,
    people: Iterable[Mapping[str, Any]] = (),
    cards: Iterable[Mapping[str, Any]] = (),
    faces: FacesIndex | None = None,
    termination: Mapping[str, str] | None = None,
) -> Path:
    """Write the bundle atomically and return its path.

    * `exported_at` comes from an INJECTED clock (card: tests assert frozen bytes);
      naive datetimes are treated as UTC, never as local wall time.
    * People/cards are normalized HERE and only here on the write side — the export
      reader hands raw device records to keep the seam honest, and the bundle is the
      place they become normalized lines. A record without an opaque `employeeNo` is
      refused (a person we cannot key is a person we cannot diff or verify).
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

    people_text = (
        "".join(_dump_line(record) + "\n" for record in normalized_people) if people else ""
    )
    cards_text = "".join(_dump_line(record) + "\n" for record in normalized_cards) if cards else ""
    faces_index = faces or FacesIndex()

    manifest = BundleManifest(
        schema_version=SCHEMA_VERSION,
        exported_at=exported_at.isoformat(),
        identity=dict(identity),
        counts={
            "users": len(normalized_people),
            "cards": len(normalized_cards),
            "faces": 0,  # truthful only because faces.state says what it means
        },
        people_hashes={
            str(record["employeeNo"]): content_hash(record) for record in normalized_people
        },
        volatile_fields_digest=frozen_volatile_digest(),
        faces=faces_index.to_dict(),
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
    try:
        _write_private_text(staging / _PEOPLE_NAME, people_text)
        _write_private_text(staging / _CARDS_NAME, cards_text)
        _write_private_text(
            staging / _FACES_DIR / _FACES_INDEX_NAME,
            canonical_json(faces_index.to_dict()) + "\n",
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
    * faces/INDEX.json must exist with the recorded-UNAVAILABLE state (design §2).
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
    if counts.get("users") != len(people) or counts.get("cards") != len(cards):
        raise ValueError(
            f"bundle {bundle}: manifest counts {counts} disagree with the record files "
            f"(people={len(people)} cards={len(cards)}) — refusing a bundle that "
            "cannot say how many people it holds"
        )
    return BundleData(manifest=manifest, people=tuple(people), cards=tuple(cards), faces=faces)
