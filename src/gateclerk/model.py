"""The normalized record — the output contract for P2 (store) and P3 (consumer).

Card p1-07. Everything upstream (transport, paging, capabilities, classifier, tz
resolver) produces facts; everything downstream (the P2 sqlite store, the P3/BC
mapping, the JSONL push payload) consumes *this* shape. Field names here are therefore
a contract, not an implementation detail: renaming one is a spec discussion, never a
silent edit. `tests/test_model.py` pins the exact key set and `docs/internal/DESIGN.md` "Event
model" is its prose twin; p1-08 renders its table columns from `RECORD_JSON_KEYS`.

Three rules this module exists to enforce:

* **`raw` survives everything.** The untouched device dict rides along, is serialized,
  and comes back byte-equal from `from_json(to_json(x))`. DESIGN.md: "We never discard
  the raw" — a normalized field that turns out to be wrong is recoverable only if the
  raw is intact. (One documented exception: `UserRecord` strips the device's
  `password` hash from `raw` — OBSERVED.md "strip it, never store".)
* **Nothing is invented.** `direction` may be `in`/`out` only when the device's own
  `attendanceStatus` said so — OBSERVED.md: that field is null on every site-a event
  today, so today's honest value is `unknown` + `direction_source=none`. `verify_mode`,
  `attendance_status` and `name` are stored verbatim, and an encrypted-looking name is
  *flagged* (`encrypted_person_data`) rather than dropped or decoded. `None` means "no
  evidence", never "fine" — the same convention as `tz_offset_mismatch`.
* **`employee_no` stays a string.** Leading zeros and alphanumeric ids are the whole
  point of `employeeNoString`; coercing it to int merges two people into one.

What this module deliberately does **not** do: it never touches the network, never
reads config, and never derives `outcome`/`unknown_code` itself. Those are p1-04's
classifier verdicts (`gateclerk.event_codes.Outcome`, `EventClassification.unknown_code`)
copied through verbatim — re-deriving them here would put a second, drifting copy of
the event-code table on the payroll path. Assembling a record from a device event + a
`ResolvedTime` + an `EventClassification` is the pipeline's job (wired by p1-08); this
module says what a record must look like and guarantees it round-trips.

The `event_time_*` / `tz_*` key names and their semantics come from
`gateclerk.tz.ResolvedTime.as_record()` (p1-06) and are consumed **as-is** —
`tz_fields_from_record()` refuses a block that renames one of them.
"""

from __future__ import annotations

import hashlib
import json
import math
import unicodedata
from collections.abc import Iterable, Iterator, Mapping
from dataclasses import MISSING, dataclass, field, fields
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any, Literal

__all__ = [
    "DIRECTION_SOURCE_BY_STATUS",
    "EVENT_TZ_KEYS",
    "KEY_ALGORITHM",
    "RECORD_JSON_KEYS",
    "Direction",
    "DirectionSource",
    "EventRecord",
    "ModelFieldError",
    "Outcome",
    "TzSource",
    "UserRecord",
    "canonical_json",
    "canonical_status",
    "direction_for_status",
    "event_keys",
    "fingerprint_key_hash",
    "fingerprint_key_json",
    "from_jsonl",
    "idempotency_key_hash",
    "idempotency_key_json",
    "is_encrypted_person_data",
    "iter_jsonl",
    "to_jsonl",
    "tz_fields_from_record",
]


class ModelFieldError(ValueError):
    """A payload does not match the contract.

    Deliberately loud: the alternative is a record that quietly lost a field, and a
    silently-missing field on a payroll record is the bug class this repo exists to
    avoid (OBSERVED.md: a silently-ignored filter "looks like data, isn't filtered, and
    nobody notices until payroll is wrong").
    """


class Direction(StrEnum):
    """Which way the person went. `unknown` is today's honest answer for site-a."""

    IN = "in"
    OUT = "out"
    UNKNOWN = "unknown"


class DirectionSource(StrEnum):
    """Who decided the direction (DESIGN.md "in/out: the two real options").

    `none` is what every site-a record carries: the terminal is in pure access-control
    mode and `attendanceStatus` is null on all 30 events (OBSERVED.md). `inferred` is
    in the enum so a mixed history stays auditable *if* P3 ever writes a derived
    direction back onto a record — **P1 never writes it** (card p1-07: no first/last
    inference anywhere), which `tests/test_model.py` pins by checking that every
    direction-producing helper in this module yields only `device`/`none`.
    """

    DEVICE = "device"
    INFERRED = "inferred"
    NONE = "none"


class TzSource(StrEnum):
    """How the record's UTC instant was obtained.

    Same spellings as `gateclerk.tz.TzSource` (p1-06); re-declared here so a record read
    back from the P2 store or a JSONL file can be validated without importing the
    resolver. The two enums are pinned equal by `tests/test_model.py`.
    """

    SITE_TZ = "site-tz"
    STRING_OFFSET = "string-offset"
    UNRESOLVED = "unresolved"


class Outcome(StrEnum):
    """The device code's verdict. Same spellings as `gateclerk.event_codes.Outcome`."""

    GRANTED = "granted"
    DENIED = "denied"
    INFO = "info"


#: The ten keys `ResolvedTime.as_record()` publishes, verbatim. p1-07 consumes them;
#: renaming one changes the p1-06 contract and belongs in DESIGN.md first.
EVENT_TZ_KEYS: tuple[str, ...] = (
    "event_time_utc",
    "event_time_local",
    "tz_offset_min",
    "tz_offset_min_device",
    "tz_source",
    "iana_tz",
    "tz_unresolved",
    "tz_ambiguous",
    "tz_nonexistent",
    "tz_reason",
)

#: The only `attendanceStatus` values that settle direction. Everything else the device
#: may report — `breakIn`, `breakOut`, `overtimeIn`, `overtimeOut`, `undefined`, or a
#: site-customized label — is kept verbatim in `attendance_status` and leaves
#: `direction=unknown` until P3 decides a policy (card p1-07).
DIRECTION_SOURCE_BY_STATUS: Mapping[str, Direction] = {
    "checkin": Direction.IN,
    "checkout": Direction.OUT,
}

#: Vendor spellings, so a `"Check In"` (references §4 shows `label` carrying that form)
#: stores as the enum text without inventing a value.
_STATUS_ALIASES: Mapping[str, str] = {
    "checkin": "checkIn",
    "checkout": "checkOut",
    "breakin": "breakIn",
    "breakout": "breakOut",
    "overtimein": "overtimeIn",
    "overtimeout": "overtimeOut",
    "undefined": "undefined",
}


def _status_key(attendance_status: str) -> str:
    return attendance_status.strip().lower().replace("_", "").replace(" ", "")


def direction_for_status(attendance_status: str | None) -> tuple[Direction, DirectionSource]:
    """(direction, direction_source) implied by one verbatim `attendanceStatus`.

    The only legal route to `direction=in|out`. An absent, `undefined`, empty or
    unrecognized value returns `(UNKNOWN, NONE)` — the pair OBSERVED.md says every
    site-a event gets today. Never first/last, never read off `minor`, never inferred.
    """
    if attendance_status is None:
        return Direction.UNKNOWN, DirectionSource.NONE
    direction = DIRECTION_SOURCE_BY_STATUS.get(_status_key(attendance_status))
    if direction is None:
        return Direction.UNKNOWN, DirectionSource.NONE
    return direction, DirectionSource.DEVICE


def canonical_status(attendance_status: object) -> str | None:
    """The vendor spelling of a status if we know it, else the trimmed device text.

    Normalizes only the *spelling* of a value we already recognize: a site-customized
    label survives verbatim, because rewriting it would put our guess in the field the
    audit trail depends on. Empty/absent/None collapses to `None` (absent == unknown).
    """
    if not isinstance(attendance_status, str):
        return None
    text = attendance_status.strip()
    if not text:
        return None
    return _STATUS_ALIASES.get(_status_key(text), text)


# --- encrypted person data --------------------------------------------------------------

#: The Hikvision person-data encryption scheme returns names as a base64 blob (DESIGN.md
#: "Encrypted person data"). RESOLVED for site-a: the 2026-10-15 probe returned plain
#: names and `GET /ISAPI/Security/encryption/capabilities` → 404 notSupport, so this is
#: a tripwire for sites B/C or a firmware change, not a live condition.
_B64_ALPHABET = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=")

#: Shortest blob we will call encrypted. Below this a real name can still look like
#: base64, and a false positive costs a usable name behind a flag.
_MIN_BLOB_LEN = 16

#: DESIGN.md's own wording for the detector is "high-entropy no-space strings". 3.5 bits
#: per character sits above any Latin name we can construct of the same length (a
#: 14-char Romanian name measures ~3.2) and well below base64 of ciphertext (~4+).
_MIN_BLOB_ENTROPY = 3.5


def _entropy(text: str) -> float:
    """Shannon entropy in bits/character. Written out to avoid a numpy dependency."""
    counts: dict[str, int] = {}
    for ch in text:
        counts[ch] = counts.get(ch, 0) + 1
    total = len(text)
    return -sum((n / total) * math.log2(n / total) for n in counts.values())


def is_encrypted_person_data(name: str | None) -> bool:
    """True when `name` reads as a base64 blob rather than as a person's name.

    Conjunction, all conditions required: long enough, a whole number of padded base64
    groups, nothing outside the base64 alphabet, no whitespace, at least one digit (a
    Latin-script name has none; base64 of ciphertext at this length almost always does),
    and high entropy.

    The cost of a false positive is *a flag*, never data: `name` and `raw` keep whatever
    the device sent, and the flag is what tells a consumer not to print it as a name.
    That asymmetry is deliberate (DESIGN.md: "detect ... and flag rather than store
    garbage as a name").
    """
    if not name:
        return False
    text = name.strip()
    if len(text) < _MIN_BLOB_LEN or len(text) % 4 != 0:
        return False
    if any(ch.isspace() for ch in text):
        return False
    if not set(text) <= _B64_ALPHABET:
        return False
    if not any(ch.isdigit() for ch in text):
        return False
    return _entropy(text) >= _MIN_BLOB_ENTROPY


# --- scalar coercion --------------------------------------------------------------------


def _as_str(value: object, *, field: str) -> str | None:
    if value is None:
        return None
    if isinstance(value, str):
        return value.strip() or None
    raise ModelFieldError(f"{field} must be a string or null, got {value!r}")


def _as_int(value: object, *, field: str) -> int | None:
    """Numeric field → int, tolerant of the stringified numbers some fw emits.

    `"75"` for `minor` is real (docs/internal/references/acs-event-codes.md §5 notes fw-dependent
    field types); reading it as 0 would silently rename a pass into an unknown code.
    """
    if value is None:
        return None
    if isinstance(value, bool):
        raise ModelFieldError(f"{field} must be an int, got bool {value!r}")
    if isinstance(value, int):
        return value
    if isinstance(value, str) and value.strip().lstrip("-").isdigit():
        return int(value.strip())
    raise ModelFieldError(f"{field} must be an int, got {value!r}")


def _as_bool(value: object, *, field: str) -> bool | None:
    """`None` (no evidence) survives as `None`; a bool stays a bool. Anything else raises.

    `tz_offset_mismatch` is the three-valued one (p1-06c: None means "there was no claim
    to compare", which is NOT the same as "agrees"), so None must not collapse to False.
    """
    if value is None:
        return None
    if isinstance(value, bool):
        return value
    raise ModelFieldError(f"{field} must be a bool or null, got {value!r}")


def _as_enum(enum_type: type[StrEnum], value: object, *, field: str) -> Any:
    if value is None:
        return None
    try:
        return enum_type(value)
    except ValueError as exc:
        allowed = ", ".join(repr(member.value) for member in enum_type)
        raise ModelFieldError(
            f"{field} {value!r} is not one of {allowed} — this module never invents a "
            "value, so a new spelling is a contract change, not a coercion"
        ) from exc


def _dump_datetime(value: datetime | None) -> str | None:
    """Aware datetime → UTC ISO-8601. A naive value is refused, not assumed."""
    if value is None:
        return None
    if not isinstance(value, datetime):
        raise ModelFieldError(f"expected a datetime, got {type(value).__name__}")
    if value.tzinfo is None or value.utcoffset() is None:
        raise ModelFieldError(
            "event_time_utc/captured_at must be tz-aware: the instant is payroll data "
            "and a naive value is a guess about which zone it means. An unresolvable "
            "time belongs in tz_unresolved=true with event_time_utc=None (DESIGN.md "
            "'Time handling' item 4: never silently assume UTC)."
        )
    return value.astimezone(UTC).isoformat()


def _load_datetime(value: object, *, field: str) -> datetime | None:
    """Inverse of `_dump_datetime`. `None` passes through — that is the unresolved case."""
    if value is None:
        return None
    if isinstance(value, datetime):
        moment = value
    else:
        if not isinstance(value, str) or not value.strip():
            raise ModelFieldError(f"{field} must be an ISO-8601 string, got {value!r}")
        text = value.strip()
        # `fromisoformat` only accepted 'Z' from 3.11; the payload crosses to consumers
        # who write it, and a 'Z' stamp is the same instant as '+00:00'.
        if text.endswith(("Z", "z")):
            text = f"{text[:-1]}+00:00"
        try:
            moment = datetime.fromisoformat(text)
        except ValueError as exc:
            raise ModelFieldError(f"{field} {value!r} is not ISO-8601 ({exc})") from exc
    if moment.tzinfo is None or moment.utcoffset() is None:
        raise ModelFieldError(f"{field} {value!r} carries no offset — event_time_utc is an instant")
    return moment.astimezone(UTC)


# --- the event record --------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class EventRecord:
    """One normalized event. The field set and key spellings are the P2/P3 contract.

    Frozen + slotted on purpose: the idempotency key means the same event is written
    again by every overlapping poll window, so a record must be safely shareable. It is
    *not* hashable (`raw` is a dict) — key digests come from `canonical_json` over
    explicit field values instead, which is stable across Python versions in a way
    `hash()` of a dataclass is not.
    """

    # --- identity / idempotency -----------------------------------------------
    #: Config-level site label (DESIGN.md open question 3: today the agent's own name).
    site: str
    #: From `System/deviceInfo`. Half the idempotency key.
    device_serial: str
    #: The device's own monotonic counter — counts ALL events incl. the major=3 noise,
    #: which is what makes it sound as a device-wide checkpoint (OBSERVED.md).
    serial_no: int | None = None
    #: `employeeNoString` preferred, `employeeNo` only as a str fallback. **Never int.**
    employee_no: str | None = None
    #: Verbatim — including an encrypted-looking blob (flagged, never rewritten).
    name: str | None = None

    # --- time: the p1-06 `ResolvedTime.as_record()` keys, consumed verbatim ----
    #: Resolved instant (tz-aware UTC); None when it could not be resolved.
    event_time_utc: datetime | None = None
    #: The device's own local string, untouched (e.g. `2026-10-12T14:11:16+02:00`).
    event_time_local: str | None = None
    #: Offset actually used for the UTC math (the site zone's, at that wall time).
    tz_offset_min: int | None = None
    #: What the device claimed. Wrong on site-a all summer — audit only, never used.
    tz_offset_min_device: int | None = None
    tz_source: TzSource | None = None
    iana_tz: str | None = None
    tz_unresolved: bool = False
    tz_ambiguous: bool = False
    tz_nonexistent: bool = False
    tz_reason: str | None = None
    #: p1-06c: None = there was no claim to compare (never report "agrees" for nothing).
    tz_offset_mismatch: bool | None = None

    # --- direction -------------------------------------------------------------
    direction: Direction = Direction.UNKNOWN
    #: Verbatim device value, or None. Kept even when it did not settle direction.
    attendance_status: str | None = None
    direction_source: DirectionSource = DirectionSource.NONE

    # --- device classification: copied through, never re-derived ---------------
    #: `currentVerifyMode` verbatim (`cardOrFaceOrFp` on every real site-a pass — the fw
    #: cannot tell face from card; `invalid` on door/noise events).
    verify_mode: str | None = None
    major: int | None = None
    minor: int | None = None
    #: p1-04's verdict for (major, minor); `info` for anything unnamed.
    outcome: Outcome = Outcome.INFO
    #: (major, minor) not in the curated code table. Kept, never dropped.
    unknown_code: bool = False
    #: `name` reads as an encrypted blob (DESIGN.md "Encrypted person data").
    encrypted_person_data: bool = False

    # --- audit -----------------------------------------------------------------
    #: The untouched device record. Nothing else in the shape is authoritative.
    raw: Mapping[str, Any] = field(default_factory=dict)
    #: When *we* read it — not a device fact, so it never participates in a key.
    captured_at: datetime | None = None

    def __post_init__(self) -> None:
        _apply_event_fields(
            self, _coerce_event_fields({f.name: getattr(self, f.name) for f in fields(self)})
        )

    # --- serialization ---------------------------------------------------------

    def to_dict(self) -> dict[str, Any]:
        """Flat JSON-safe dict; key order = declaration order (a stable JSONL line)."""
        out: dict[str, Any] = {f.name: getattr(self, f.name) for f in fields(self)}
        out["event_time_utc"] = _dump_datetime(self.event_time_utc)
        out["captured_at"] = _dump_datetime(self.captured_at)
        out["tz_source"] = None if self.tz_source is None else self.tz_source.value
        out["direction"] = self.direction.value
        out["direction_source"] = self.direction_source.value
        out["outcome"] = self.outcome.value
        # Shallow copy, deliberately: `raw` is *the device's* record and the only thing
        # we must hand back untouched. A deep copy on every serialization would be the
        # hot path's real cost and would buy no safety we do not already have.
        out["raw"] = dict(self.raw)
        return out

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> EventRecord:
        """Build a record from a dict — a `to_dict()` payload or a resolver-shaped block.

        Unknown keys are rejected rather than ignored: a typo'd key would vanish and the
        record would then look legitimately empty, which is the failure this whole card
        is written to make impossible.
        """
        return _event_from_fields(_coerce_event_fields(_event_payload(dict(payload))))

    def to_json(self, *, indent: int | None = None) -> str:
        """Canonical JSON text. Unicode stays readable — diacritics are names, not noise."""
        return _dumps(self.to_dict(), indent=indent)

    @classmethod
    def from_json(cls, text: str) -> EventRecord:
        return cls.from_dict(_loads(text, what="record"))

    # --- keys ------------------------------------------------------------------

    @property
    def idempotency_hash(self) -> str:
        """sha256 of the `(device_serial, serial_no)` primary key."""
        return idempotency_key_hash(self.device_serial, self.serial_no)

    @property
    def fingerprint_hash(self) -> str:
        """sha256 of the `(employee_no, event_time_local, minor)` secondary guard."""
        return fingerprint_key_hash(self.employee_no, self.event_time_local, self.minor)

    @property
    def is_punch_candidate(self) -> bool:
        """major=5 + granted + attributed + a code we can name (DESIGN.md punch rule).

        A *property of the record*, never a filter applied here — everything is stored
        and filtering is a query-time property. Deliberately does not second-guess
        `verify_mode` (p1-04 owns the complete rule, incl. `AUTH_PASS_MINORS`).
        """
        return (
            self.major == 5
            and self.outcome is Outcome.GRANTED
            and bool(self.employee_no)
            and not self.unknown_code
        )

    def key_columns(self) -> dict[str, Any]:
        """Both key forms, ready for the P2 store's UNIQUE/UPSERT columns."""
        return event_keys(self)


def _coerce_event_fields(data: dict[str, Any]) -> dict[str, Any]:
    """Normalize one record's field dict and return it.

    The single place the record's rules live, shared by construction and
    deserialization: a constructor stricter than the loader is how a store written
    today stops being readable tomorrow, and a loader looser than the constructor is
    how a bad row gets accepted on the way back in.
    """
    # --- identity: required, and required to actually say something
    site = _as_str(data["site"], field="site")
    device_serial = _as_str(data["device_serial"], field="device_serial")
    if not site:
        raise ModelFieldError("site is required (an unattributed punch cannot be reconciled)")
    if not device_serial:
        raise ModelFieldError("device_serial is required (it is half the idempotency key)")
    data["site"] = site
    data["device_serial"] = device_serial

    data["serial_no"] = _as_int(data["serial_no"], field="serial_no")
    employee_no = _as_str(data["employee_no"], field="employee_no")
    if employee_no is not None:
        # NFC so two spellings of one name (precomposed vs combining marks) are one
        # person in the store, and "007" is never equal to "7".
        employee_no = unicodedata.normalize("NFC", employee_no)
    data["employee_no"] = employee_no
    name = _as_str(data["name"], field="name")
    if name is not None:
        name = unicodedata.normalize("NFC", name)
    data["name"] = name

    # --- time block (the p1-06 keys, same names, same meanings)
    data["event_time_utc"] = _load_datetime(data["event_time_utc"], field="event_time_utc")
    data["event_time_local"] = _as_str(data["event_time_local"], field="event_time_local")
    data["tz_offset_min"] = _as_int(data["tz_offset_min"], field="tz_offset_min")
    data["tz_offset_min_device"] = _as_int(
        data["tz_offset_min_device"], field="tz_offset_min_device"
    )
    data["tz_source"] = _as_enum(TzSource, data["tz_source"], field="tz_source")
    data["iana_tz"] = _as_str(data["iana_tz"], field="iana_tz")
    for flag in ("tz_unresolved", "tz_ambiguous", "tz_nonexistent"):
        data[flag] = bool(_as_bool(data[flag], field=flag))
    data["tz_reason"] = _as_str(data["tz_reason"], field="tz_reason")
    data["tz_offset_mismatch"] = _as_bool(data["tz_offset_mismatch"], field="tz_offset_mismatch")

    # --- direction: the no-inference invariant lives here
    data["attendance_status"] = canonical_status(data["attendance_status"])
    direction = _as_enum(Direction, data["direction"], field="direction") or Direction.UNKNOWN
    source = (
        _as_enum(DirectionSource, data["direction_source"], field="direction_source")
        or DirectionSource.NONE
    )
    # The rule "direction comes ONLY from attendanceStatus" is implemented as a
    # *derivation*, not as a validation of whatever the caller passed: the device's own
    # value is the only thing that can produce in/out, so the field cannot drift from it
    # and there is no code path that writes an inferred direction by accident.
    implied, implied_source = direction_for_status(data["attendance_status"])
    if implied is not Direction.UNKNOWN:
        if direction not in (Direction.UNKNOWN, implied):
            raise ModelFieldError(
                f"direction={direction.value!r} contradicts "
                f"attendance_status={data['attendance_status']!r} (which says "
                f"{implied.value!r}): direction comes ONLY from attendanceStatus"
            )
        if source is DirectionSource.INFERRED:
            raise ModelFieldError(
                "direction_source=inferred while attendanceStatus states the direction: "
                "the device decided it, so claiming otherwise breaks the audit trail "
                "DESIGN.md keeps direction_source for"
            )
        direction, source = implied, implied_source
    elif source is DirectionSource.DEVICE:
        raise ModelFieldError(
            f"direction_source=device but attendance_status="
            f"{data['attendance_status']!r} states no direction (only checkIn/checkOut "
            "do) — nothing to attribute the value to"
        )
    elif source is DirectionSource.INFERRED:
        # The only legal non-device direction: a record a *consumer* (P3) wrote back,
        # with the inference attributed. P1's own pipeline never reaches this branch —
        # nothing upstream calls `direction_for_status` to invent one.
        if direction is Direction.UNKNOWN:
            raise ModelFieldError(
                "direction_source=inferred claims a decision while direction=unknown"
            )
    elif direction is not Direction.UNKNOWN:
        raise ModelFieldError(
            f"direction={direction.value!r} with direction_source=none is an "
            "unattributed direction: P1 never infers in/out (card p1-07). Either carry "
            "the device's own attendanceStatus, or write the inference as "
            "direction_source=inferred (a P3 decision, never a connector one)."
        )
    data["direction"] = direction
    data["direction_source"] = source

    # --- classification, copied through
    data["verify_mode"] = _as_str(data["verify_mode"], field="verify_mode")
    data["major"] = _as_int(data["major"], field="major")
    data["minor"] = _as_int(data["minor"], field="minor")
    data["outcome"] = _as_enum(Outcome, data["outcome"], field="outcome") or Outcome.INFO
    data["unknown_code"] = bool(data["unknown_code"])

    raw = data["raw"]
    if raw is None:
        raw = {}
    if not isinstance(raw, Mapping):
        raise ModelFieldError(f"raw must be the device's JSON object, got {type(raw).__name__}")
    data["raw"] = dict(raw)

    # Recomputed on every path, so a record read back from a store written before the
    # rule tightened still tells the truth about its own name.
    data["encrypted_person_data"] = bool(data["encrypted_person_data"]) or is_encrypted_person_data(
        data["name"]
    )
    data["captured_at"] = _load_datetime(data["captured_at"], field="captured_at")
    return data


def _event_from_fields(data: dict[str, Any]) -> EventRecord:
    """Build a record from field values *already* run through `_coerce_event_fields`.

    Bypasses `__post_init__` via `__new__` so the rules are not applied twice: once is
    plenty, and re-normalizing an already-normalized record would make the constructor a
    second place for the rules to drift.
    """
    record = object.__new__(EventRecord)
    for name, value in data.items():
        object.__setattr__(record, name, value)
    return record


def _apply_event_fields(record: EventRecord, data: dict[str, Any]) -> None:
    """Write coerced values back onto a frozen dataclass.

    `object.__setattr__` is the sanctioned way — the same one `tz.ResolvedTime` uses for
    its derived field. The alternative is to make the record mutable, and a record a poll
    loop can edit after handing it to the store is not a record.
    """
    for name, value in data.items():
        object.__setattr__(record, name, value)


def _event_payload(payload: dict[str, Any]) -> dict[str, Any]:
    """Fill every declared field from a payload dict, rejecting unknown keys."""
    known = {f.name for f in fields(EventRecord)}
    unknown = sorted(set(payload) - known)
    if unknown:
        raise ModelFieldError(
            f"unknown key(s) {unknown} — the field set is the P2/P3 contract (see "
            f"{__name__}.RECORD_JSON_KEYS); accepting a typo would silently blank a field"
        )
    data: dict[str, Any] = {}
    for f in fields(EventRecord):
        if f.name in payload:
            data[f.name] = payload[f.name]
        elif f.default is MISSING and f.default_factory is MISSING:
            raise ModelFieldError(f"payload is missing required key {f.name!r}")
        elif f.default is not MISSING:
            data[f.name] = f.default
        else:
            data[f.name] = f.default_factory()  # type: ignore[misc]
    return data


#: The JSON key set of an event record, in declaration order. Pinned by a test; p1-08
#: renders its table columns and the P2 store builds its columns from this tuple.
RECORD_JSON_KEYS: tuple[str, ...] = tuple(f.name for f in fields(EventRecord))


def tz_fields_from_record(record: Mapping[str, Any]) -> dict[str, Any]:
    """The ten tz keys out of `ResolvedTime.as_record()`, with `tz_offset_mismatch` added.

    The seam p1-06's ownership note asked for: `EventRecord` consumes those keys
    **as-is**. A block that lacks one of them did not come from `as_record()` (a renamed
    or hand-built dict) and defaulting it silently would put a blank column on the
    payroll path, so this raises and names the key. `tz_offset_mismatch` is *not*
    required — p1-06c computes it by comparing `tz_offset_min` with
    `tz_offset_min_device`, both already here — and is returned as None when absent.
    """
    missing = [key for key in EVENT_TZ_KEYS if key not in record]
    if missing:
        raise ModelFieldError(
            f"time block is missing {missing} — expected exactly the keys "
            "gateclerk.tz.ResolvedTime.as_record() publishes (renaming one is a change to "
            "the p1-06 contract and belongs in DESIGN.md, not in a local edit)"
        )
    out: dict[str, Any] = {key: record[key] for key in EVENT_TZ_KEYS}
    out["tz_offset_mismatch"] = record.get("tz_offset_mismatch")
    return out


# --- the user record ----------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class UserRecord:
    """One `UserInfo/Search` record, with the device's `password` hash stripped.

    The real device sends a `password` key per user (OBSERVED.md endpoint table:
    "**strip it, never store**"), so stripping happens here — before any
    serialization — rather than in each consumer. That makes this the one place in the
    model where `raw` is *not* byte-equal to what the device sent, and the deliberate
    exception to `EventRecord`'s rule: an event record has no credential field, a user
    record does.
    """

    employee_no: str
    #: Verbatim, or None when it read as an encrypted blob.
    name: str | None = None
    #: `userType` verbatim (`normal`, `visitor`, `blacklist`, `pattern`).
    user_type: str | None = None
    #: `Valid.beginTime` verbatim (device-local, usually naive — no tz claim).
    valid_from: str | None = None
    #: `Valid.endTime` verbatim.
    valid_to: str | None = None
    #: `Valid.enable` verbatim (None = the device did not say).
    valid_enabled: bool | None = None
    encrypted_person_data: bool = False
    raw: Mapping[str, Any] = field(default_factory=dict)

    @classmethod
    def from_device_user(cls, payload: Mapping[str, Any]) -> UserRecord:
        """Normalize one `UserInfo` entry (with or without a response wrapper).

        `employeeNoString` is preferred over `employeeNo` for the same reason as in the
        event model, and both are read as strings — site-a's ids are "1".."4" today,
        which is precisely the case where an int would look harmless and then break the
        first site that uses "0007A".
        """
        body = _unwrap_user_body(dict(payload))

        # The redaction, before anything else can see the dict.
        body = {k: v for k, v in body.items() if k.lower() != "password"}

        employee_no = _employee_no_from(body)
        if employee_no is None:
            raise ModelFieldError(
                "UserInfo record carries no employeeNoString/employeeNo — an "
                "unattributed person cannot enter a roster"
            )
        valid = body.get("Valid")
        valid = valid if isinstance(valid, Mapping) else {}
        name = _as_str(body.get("name"), field="name")
        if name is not None:
            name = unicodedata.normalize("NFC", name)
        return cls(
            employee_no=unicodedata.normalize("NFC", employee_no),
            name=name,
            user_type=_as_str(body.get("userType"), field="userType"),
            valid_from=_as_str(valid.get("beginTime"), field="Valid.beginTime"),
            valid_to=_as_str(valid.get("endTime"), field="Valid.endTime"),
            valid_enabled=_as_bool(valid.get("enable"), field="Valid.enable"),
            encrypted_person_data=is_encrypted_person_data(name),
            raw=body,
        )

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {f.name: getattr(self, f.name) for f in fields(self)}
        out["raw"] = dict(self.raw)
        return out

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> UserRecord:
        known = {f.name for f in fields(cls)}
        unknown = sorted(set(payload) - known)
        if unknown:
            raise ModelFieldError(
                f"unknown key(s) {unknown} in a UserRecord payload — the field set is "
                "the P2/P3 contract"
            )
        employee_no = _as_str(payload.get("employee_no"), field="employee_no")
        if not employee_no:
            raise ModelFieldError("employee_no is required")
        name = _as_str(payload.get("name"), field="name")
        raw = payload.get("raw", {})
        if raw is None:
            raw = {}
        if not isinstance(raw, Mapping):
            raise ModelFieldError("raw must be a JSON object")
        # Belt and braces: a payload whose raw still carries a hash never came from here.
        raw = {k: v for k, v in raw.items() if k.lower() != "password"}
        return cls(
            employee_no=unicodedata.normalize("NFC", employee_no),
            name=None if name is None else unicodedata.normalize("NFC", name),
            user_type=_as_str(payload.get("user_type"), field="user_type"),
            valid_from=_as_str(payload.get("valid_from"), field="valid_from"),
            valid_to=_as_str(payload.get("valid_to"), field="valid_to"),
            valid_enabled=_as_bool(payload.get("valid_enabled"), field="valid_enabled"),
            encrypted_person_data=bool(payload.get("encrypted_person_data"))
            or is_encrypted_person_data(name),
            raw=raw,
        )

    def to_json(self, *, indent: int | None = None) -> str:
        return _dumps(self.to_dict(), indent=indent)

    @classmethod
    def from_json(cls, text: str) -> UserRecord:
        return cls.from_dict(_loads(text, what="user record"))


#: Wrapper keys a UserInfo entry may arrive inside (a single record from the XML path
#: arrives as `{"UserInfo": {...}}`; the p1-05 paging engine hands us the entries).
_USER_WRAPPERS: tuple[str, ...] = ("UserInfo", "UserInfoSearch", "user")


def _unwrap_user_body(body: Mapping[str, Any]) -> dict[str, Any]:
    """One UserInfo entry, unwrapped if it came wrapped.

    Same shape-tolerance as `event_codes._record_fields`, for the same reason: a caller
    may hand us the entry or a one-record wrapper, and mistaking a wrapper for an entry
    is a "no employeeNo" error that reads like a device fault.
    """
    for wrapper in _USER_WRAPPERS:
        inner = body.get(wrapper)
        if isinstance(inner, Mapping) and any(
            k in inner for k in ("employeeNo", "employeeNoString")
        ):
            return dict(inner)
    return dict(body)


def _employee_no_from(record: Mapping[str, Any]) -> str | None:
    """`employeeNoString` first; `employeeNo` only as a str fallback. Never int out."""
    for key in ("employeeNoString", "employeeNo"):
        value = record.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
        if isinstance(value, int) and not isinstance(value, bool):
            return str(value)
    return None


# --- stable keys for the P2 store ----------------------------------------------------------

#: Namespaced so a future scheme (blake3, a different canonicalization) cannot be
#: silently conflated with these digests inside the same store column.
KEY_ALGORITHM = "sha256-canonical-json-v1"


def canonical_json(value: Any) -> str:
    """The canonical text a key digest is taken of.

    Stability *is* the requirement: these digests become UNIQUE columns, so they must be
    byte-identical across Python versions and to whatever the P2 store computes
    independently. Hence no `repr`, no `dataclasses.asdict`, no reliance on dict
    ordering — `sort_keys` plus a small explicit type mapping (datetime → UTC ISO,
    StrEnum → value, str → NFC) and a refusal for anything else.
    """
    return json.dumps(
        _canonical_value(value),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )


def _canonical_value(value: Any) -> Any:
    if value is None or isinstance(value, (bool, int)):
        return value
    if isinstance(value, float):
        if value != value or value in (math.inf, -math.inf):
            raise ModelFieldError("cannot canonicalize a non-finite float into a key")
        return value
    if isinstance(value, datetime):
        return _dump_datetime(value)
    if isinstance(value, StrEnum):
        return value.value
    if isinstance(value, str):
        return unicodedata.normalize("NFC", value)
    if isinstance(value, Mapping):
        return {str(k): _canonical_value(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_canonical_value(v) for v in value]
    raise ModelFieldError(
        f"cannot canonicalize {type(value).__name__} into a key — a key is built from "
        "JSON scalars, so a new field type in a key is a contract decision"
    )


def _digest(payload: Mapping[str, Any]) -> str:
    return hashlib.sha256(canonical_json(payload).encode("utf-8")).hexdigest()


def idempotency_key_json(device_serial: str, serial_no: int | None) -> str:
    """Canonical JSON of the primary key — the textual twin of the sqlite UNIQUE tuple."""
    return canonical_json({"device_serial": device_serial, "serial_no": serial_no})


def idempotency_key_hash(device_serial: str, serial_no: int | None) -> str:
    """sha256 hex of `idempotency_key_json`. The UPSERT target that makes overlap free."""
    return _digest({"device_serial": device_serial, "serial_no": serial_no})


def fingerprint_key_json(
    employee_no: str | None, event_time_local: str | None, minor: int | None
) -> str:
    """Canonical JSON of the secondary guard.

    `(employee_no, event_time_local, minor)` — device-*local*, verbatim — because the
    guard exists for the case DESIGN.md names: a device whose `serialNo` resets after a
    firmware upgrade or a log clear. Two records agreeing on all three are the same
    punch read twice; a genuine double-badge at the same second and minor is
    indistinguishable by construction, which is exactly why this is a guard and not the
    primary key.
    """
    return canonical_json(
        {"employee_no": employee_no, "event_time_local": event_time_local, "minor": minor}
    )


def fingerprint_key_hash(
    employee_no: str | None, event_time_local: str | None, minor: int | None
) -> str:
    return _digest(
        {"employee_no": employee_no, "event_time_local": event_time_local, "minor": minor}
    )


def event_keys(record: EventRecord) -> dict[str, Any]:
    """Both key forms for one record, algorithm-tagged, for the P2 store's columns.

    The JSON form goes in a column too: a hash collision in a UNIQUE index would be
    invisible, while `(hash, json)` pairs let a human see which two records collided.
    """
    return {
        "algorithm": KEY_ALGORITHM,
        "idempotency_json": idempotency_key_json(record.device_serial, record.serial_no),
        "idempotency_hash": idempotency_key_hash(record.device_serial, record.serial_no),
        "fingerprint_json": fingerprint_key_json(
            record.employee_no, record.event_time_local, record.minor
        ),
        "fingerprint_hash": fingerprint_key_hash(
            record.employee_no, record.event_time_local, record.minor
        ),
    }


# --- JSONL: the future push payload ---------------------------------------------------------


def _dumps(payload: Mapping[str, Any], *, indent: int | None) -> str:
    """One JSON writer for the whole module — `ensure_ascii=False` everywhere.

    Names with diacritics must stay readable in a stored line and on the wire; the
    escape-everything default turns `Popescu-Ionescu` into noise and makes a recorded
    payload impossible to eyeball during a payroll triage.
    """
    return json.dumps(
        payload,
        ensure_ascii=False,
        indent=indent,
        separators=None if indent else (",", ":"),
        allow_nan=False,
    )


def _loads(text: str, *, what: str) -> dict[str, Any]:
    try:
        payload = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ModelFieldError(f"{what} is not valid JSON ({exc})") from exc
    if not isinstance(payload, dict):
        raise ModelFieldError(f"{what} must be a JSON object, got {type(payload).__name__}")
    return payload


def to_jsonl(records: Iterable[EventRecord | UserRecord]) -> str:
    """One record per line — the P2→ingest push payload format (DESIGN.md architecture).

    Always newline-terminated so batches can be concatenated without gluing two records
    onto one line.
    """
    lines = [_jsonl_line(record) for record in records]
    return "".join(f"{line}\n" for line in lines)


def _jsonl_line(record: EventRecord | UserRecord) -> str:
    if not isinstance(record, (EventRecord, UserRecord)):
        raise ModelFieldError(f"to_jsonl takes EventRecord/UserRecord, got {type(record).__name__}")
    return json.dumps(record.to_dict(), ensure_ascii=False, separators=(",", ":"), allow_nan=False)


def iter_jsonl(
    text_or_lines: str | Iterable[str], *, kind: Literal["event", "user"] = "event"
) -> Iterator[Any]:
    """Parse JSONL text (or an iterable of lines) into records, skipping blank lines.

    Blank lines are skipped; everything else is strict, and a bad line names its line
    number. A silently-dropped line in a payroll push is the same invisible data loss
    class as a silently-ignored device filter, and just as expensive to notice later.
    """
    lines = text_or_lines.splitlines() if isinstance(text_or_lines, str) else text_or_lines
    parse = EventRecord.from_json if kind == "event" else UserRecord.from_json
    for number, line in enumerate(lines, start=1):
        stripped = line.strip()
        if not stripped:
            continue
        try:
            yield parse(stripped)
        except ModelFieldError as exc:
            raise ModelFieldError(f"line {number}: {exc}") from exc


def from_jsonl(text: str, *, kind: Literal["event", "user"] = "event") -> list[Any]:
    return list(iter_jsonl(text, kind=kind))
