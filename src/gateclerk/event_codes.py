"""Major/minor classification: name codes, never invent them (card p1-04).

Every event gets an `outcome` in {granted, denied, info}. An unrecognised code becomes
`info` with `unknown_code=True` and is **kept** — dropping unknowns is how punches go
missing silently on a payroll pipeline (DESIGN.md "Noise filter is part of the
contract": filtering is a query-time property, so a misclassification never loses data).

Two authorities, deliberately separate (this is the whole design of the module):

* **`gateclerk.capabilities` decides what is *queryable*.** The device's advertised
  `minorEvent/minorAlarm/minorOperation/...` sets mark a code `not_advertised`.
* **The table here decides what a code *means*.** Names come from the vendor hex-named
  tables cross-checked in docs/references/acs-event-codes.md §3, which the same brief
  shows disagreeing with a circulating "best-practices" table — that one labels minor 38
  "card authentication success" and it is wrong (38 = 0x26 fingerprint pass; the valid
  **card** pass is minor 1). So the table is curated, cited, and never extended by
  guessing: a code we cannot name stays `info + unknown_code`.

The punch-candidate rule (card + DESIGN.md + OBSERVED.md):

    major == 5 AND outcome == granted AND minor is a known *authentication* pass
    AND employee_no present AND currentVerifyMode is a real auth mode

Consequences that are device-verified, not stylistic:

* `minor 21/22` (lock open/close) ride along with every pass as a same-second triple
  `(5,75)+(5,21)+(5,22)` (OBSERVED.md, references §3) — they are `info`, never punch
  candidates, and a consumer that counts them would triple-count the day.
* `major == 3` is fully non-punch: it carries the 1-per-minute remote-op heartbeat
  `(3,1029)` — 10,169 of site-a's 10,199 events — and the legitimate remote/app opens
  `(3,1024)`. Both are `info`; both are stored.
* `currentVerifyMode` is kept **verbatim**. On this firmware every real pass reads
  `cardOrFaceOrFp` (it cannot tell face from card) and door/noise events read `invalid`
  (OBSERVED.md). Only `invalid`/`unknown`/absent disqualifies a punch; we never invent a
  finer mode than the device reported, and we never invent one from the minor either.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

from gateclerk.capabilities import DeviceCapabilities

__all__ = [
    "AUTH_PASS_MINORS",
    "DENIED_MINORS",
    "DOOR_STATE_MINORS",
    "EVENT_CODE_TABLE",
    "MAJOR_CLASS",
    "NON_AUTH_VERIFY_MODES",
    "PUNCH_MAJOR",
    "CodeInfo",
    "EventClassification",
    "Outcome",
    "classify_batch",
    "classify_event",
    "name_for",
    "outcome_for",
]


class Outcome(StrEnum):
    """What happened, as far as the device's code says. `info` = not an auth result."""

    GRANTED = "granted"
    DENIED = "denied"
    INFO = "info"


#: The only major that carries authentication events on this firmware family
#: (docs/references/acs-event-codes.md §3: major 5 = MAJOR_EVENT, "the T&A payload").
PUNCH_MAJOR = 5

#: major -> vendor class name (references §3), kept for the human table + audit.
MAJOR_CLASS: dict[int, str] = {
    0: "ALL",
    1: "ALARM",
    2: "EXCEPTION",
    3: "OPERATION",
    5: "EVENT",
}


@dataclass(frozen=True, slots=True)
class CodeInfo:
    """One curated (major, minor) entry: a name and an outcome. Nothing else.

    Deliberately no `is_punch` flag — punch-ness is *derived* (major 5 + granted + an
    authentication minor + employee + verify mode), and a flag here would be a second,
    drift-prone answer to the same question.
    """

    name: str
    outcome: Outcome
    #: Human note where the label needs defending (e.g. the minor-38 mislabel warning).
    note: str | None = None


def _c(name: str, outcome: Outcome, note: str | None = None) -> CodeInfo:
    return CodeInfo(name=name, outcome=outcome, note=note)


_G = Outcome.GRANTED
_D = Outcome.DENIED
_I = Outcome.INFO

#: Curated name table. Source: docs/references/acs-event-codes.md §3, where the vendor
#: hex-named table (node-red `MAJOR_EVENT-0x5.json`) was cross-checked against the
#: decimal catalog (`mmisobuj/HikvisionIsupServer`) and both agreed. Codes the device
#: advertises but this table does not name are classified `info + unknown_code` — they
#: are *not* back-filled with a plausible name.
EVENT_CODE_TABLE: dict[tuple[int, int], CodeInfo] = {
    # --- major 1: alarms -----------------------------------------------------------------
    (1, 1034): _c("STRESS_ALARM", _I, "duress alarm"),
    (1, 1036): _c("CARD_MAX_AUTH_FAIL", _I),
    (1, 1090): _c("LEGAL_EVENT_STORAGE_NEAR_FULL", _I),
    # --- major 2: device exceptions -------------------------------------------------------
    (2, 1024): _c("DEVICE_POWER_ON", _I),
    (2, 1025): _c("DEVICE_POWER_OFF", _I),
    (2, 1033): _c("CARD_READER_OFFLINE", _I),
    (2, 1034): _c("CARD_READER_RESUME", _I),
    (2, 1064): _c("LOCAL_LOGIN_LOCK", _I),
    (2, 1065): _c("LOCAL_LOGIN_UNLOCK", _I),
    # --- major 3: operations (NEVER punch candidates) -------------------------------------
    (3, 80): _c("LOCAL_LOGIN", _I),
    (3, 90): _c("LOCAL_LOGOUT", _I),
    (3, 112): _c("REMOTE_LOGIN", _I),
    (3, 113): _c("REMOTE_LOGOUT", _I),
    (3, 1024): _c("REMOTE_OPEN_DOOR", _I, "opened by app/platform, not by a credential"),
    (3, 1025): _c("REMOTE_CLOSE_DOOR", _I),
    (3, 1026): _c("REMOTE_ALWAYS_OPEN", _I),
    (3, 1027): _c("REMOTE_ALWAYS_CLOSE", _I),
    (3, 1035): _c("REMOTE_CAPTURE_PIC", _I),
    (3, 1039): _c("UNLOCK_PASSWORD_OPEN_DOOR", _I),
    # --- major 5: authentication + door events --------------------------------------------
    # Passes. `1` is the valid CARD pass and `38` the FINGERPRINT pass: a circulating
    # "best-practices" table labels 38 as card success and 113 as fingerprint, which is
    # wrong against the vendor hex table (38 = 0x26, 113 = 0x71 blacklist) — see
    # docs/references/acs-event-codes.md §3 "Note on a circulating error".
    (5, 1): _c("CARD_PASS", _G, "valid card, right OK — the CARD pass"),
    (5, 2): _c("CARD_AND_PSW_PASS", _G),
    (5, 16): _c("MULTI_VERIFY_SUCCESS", _G),
    (5, 38): _c("FINGERPRINT_PASS", _G, "fingerprint matched — NOT card (common mislabel)"),
    (5, 40): _c("CARD_AND_FINGERPRINT_PASS", _G),
    (5, 54): _c("FACE_AND_FINGERPRINT_PASS", _G),
    (5, 57): _c("FACE_AND_PASSWORD_PASS", _G),
    (5, 60): _c("FACE_AND_CARD_PASS", _G, "card+face combined pass"),
    (5, 66): _c("FACE_CARD_AND_FINGERPRINT_PASS", _G),
    (5, 75): _c("FACE_VERIFY_PASS", _G, "face recognized/verified"),
    (5, 77): _c("EMPLOYEENO_AND_FACE_PASS", _G),
    (5, 153): _c("COMBINED_VERIFY_PASS", _G, "generic combined authentication pass"),
    (5, 156): _c("ORCODE_VERIFY_PASS", _G, "QR / one-code pass"),
    (5, 159): _c("BLUETOOTH_VERIFY_PASS", _G),
    (5, 179): _c("DYNAMICCODE_VERIFY_PASS", _G),
    (5, 181): _c("PASSWORD_VERIFY_PASS", _G),
    (5, 190): _c("IRIS_VERIFY_PASS", _G),
    # Failures against a credential/identity: denied, still stored.
    (5, 3): _c("CARD_AND_PSW_FAIL", _D),
    (5, 6): _c("CARD_NO_RIGHT", _D, "valid card, no permission at this door"),
    (5, 7): _c("CARD_INVALID_PERIOD", _D),
    (5, 8): _c("CARD_OUT_OF_DATE", _D),
    (5, 9): _c("INVALID_CARD", _D, "card number not registered"),
    (5, 12): _c("NOT_BELONG_MULTI_GROUP", _D),
    (5, 39): _c("FINGERPRINT_FAIL", _D),
    (5, 61): _c("FACE_AND_CARD_FAIL", _D),
    (5, 76): _c("FACE_VERIFY_FAIL", _D, "mismatch against the matched person"),
    (5, 80): _c("FACE_NO_MATCH", _D, "1:N miss — no identity matched"),
    (5, 113): _c("CERTIFICATE_BLACKLIST", _D, "blacklisted person detected"),
    (5, 151): _c("PASSWORD_MISMATCH", _D),
    (5, 152): _c("EMPLOYEE_NO_NOT_EXIST", _D),
    (5, 155): _c("VERIFY_MODE_MISMATCH", _D, "wrong auth type used"),
    (5, 162): _c("INFORMAL_MIFARE_CARD_FAIL", _D),
    # Door state / button: info. 21/22 follow EVERY pass (same-second triple) — counting
    # them as punches would triple-count attendance (OBSERVED.md census).
    (5, 21): _c("LOCK_OPEN", _I, "relay fired / door unlocked — follows a pass, not a punch"),
    (5, 22): _c("LOCK_CLOSE", _I),
    (5, 23): _c("DOOR_BUTTON_PRESS", _I, "exit button"),
    (5, 24): _c("DOOR_BUTTON_RESUME", _I),
    (5, 25): _c("DOOR_OPEN_NORMAL", _I),
    (5, 26): _c("DOOR_CLOSE_NORMAL", _I),
    (5, 27): _c("DOOR_OPEN_ABNORMAL", _I, "opened without unlock (tailgate/forced)"),
    (5, 28): _c("DOOR_OPEN_TIMEOUT", _I),
    (5, 29): _c("DOOR_ALWAYS_OPEN", _I),
    (5, 30): _c("DOOR_ALWAYS_CLOSE", _I),
    (5, 31): _c("DOOR_RESUME_FROM_ALWAYS_OPEN", _I),
    (5, 32): _c("DOOR_RESUME_FROM_ALWAYS_CLOSE", _I),
    (5, 33): _c("FIRST_OPEN_DOOR", _I),
    (5, 34): _c("DOOR_OPEN_BY_REMOTE", _I),
    (5, 35): _c("DOOR_CLOSE_BY_REMOTE", _I),
    (5, 36): _c("DOOR_OPEN_BY_MEMORY_CARD", _I),
    (5, 37): _c("DOOR_CLOSE_BY_MEMORY_CARD", _I),
    (5, 49): _c("CASE_SENSOR_OPEN", _I),
    (5, 51): _c("DOOR_BROKEN_IN", _I, "door held open / forced"),
    (5, 104): _c("DEVICE_FORCE_OPEN", _I),
    (5, 105): _c("DEVICE_RECOVER_FORCE", _I),
    (5, 112): _c("DEVICE_TAMPER", _I),
    (5, 114): _c("DEVICE_TAMPER_RECOVER", _I),
    (5, 115): _c("DEVICE_RESET", _I),
    (5, 116): _c("DEVICE_SHUTDOWN", _I),
    (5, 142): _c("REMOTE_CONTROL_OPEN", _I, "platform-initiated open, not a credential"),
    (5, 154): _c("COMBINED_VERIFY_FAIL", _D),
    (5, 193): _c("FIRST_CARD_SWIPE", _I),
}

#: The authentication passes under major 5 — everything the vendor table calls a
#: *_PASS / *_SUCCESS. Door-state codes are excluded by construction, so a consumer can
#: read this set as "a credential was presented and accepted".
AUTH_PASS_MINORS: frozenset[int] = frozenset(
    minor
    for (major, minor), info in EVENT_CODE_TABLE.items()
    if major == PUNCH_MAJOR and info.outcome is Outcome.GRANTED
)

DENIED_MINORS: frozenset[int] = frozenset(
    minor
    for (major, minor), info in EVENT_CODE_TABLE.items()
    if major == PUNCH_MAJOR and info.outcome is Outcome.DENIED
)

DOOR_STATE_MINORS: frozenset[int] = frozenset(
    minor
    for (major, minor), info in EVENT_CODE_TABLE.items()
    if major == PUNCH_MAJOR and info.outcome is Outcome.INFO
)

#: `currentVerifyMode` values that mean "no credential authenticated here". OBSERVED.md:
#: door/noise records carry `invalid`; real passes carry `cardOrFaceOrFp`. Anything else
#: is kept verbatim and treated as a real mode — including modes this table has never
#: seen, because refusing an unknown-but-plausible mode would *drop* a punch, which is the
#: failure mode this card rules out above everything else.
NON_AUTH_VERIFY_MODES = frozenset({"", "invalid", "unknown", "undefined", "none", "null"})


def name_for(major: int, minor: int) -> str | None:
    """Curated name for a code, or None (which the caller must surface as unknown)."""
    info = EVENT_CODE_TABLE.get((major, minor))
    return None if info is None else info.name


def outcome_for(major: int, minor: int) -> Outcome:
    """Outcome for a code. Unnamed code -> INFO (kept, flagged, never dropped)."""
    info = EVENT_CODE_TABLE.get((major, minor))
    return Outcome.INFO if info is None else info.outcome


# --- record accessors -----------------------------------------------------------------


def _record_fields(record: Mapping[str, Any]) -> Mapping[str, Any]:
    """Unwrap an event wrapper (`AccessControllerEvent`/`AcsEvent`/`event`) if present.

    A caller may hand us one record or a response page. A page has no `major` at its
    root, so it classifies as `info + unknown_code` (kept, flagged) rather than being
    silently mistaken for one event with a missing code — batches belong in
    `classify_batch`, which takes the `InfoList` itself.
    """
    for wrapper in ("AccessControllerEvent", "AcsEvent", "event"):
        inner = record.get(wrapper)
        if isinstance(inner, Mapping) and ("major" in inner or "minor" in inner):
            return inner
    return record


def _as_int_or_none(value: Any) -> int | None:
    """int / numeric string -> int; anything else None. Never a silent 0.

    `minor: "75"` is real (some firmwares stringify numeric fields — references §5) and a
    classification that read it as 0 would rename a pass into an unknown code.
    """
    if value is None or isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str) and value.strip().lstrip("-").isdigit():
        return int(value.strip())
    return None


def _employee_no(record: Mapping[str, Any]) -> str | None:
    """`employeeNoString` preferred, `employeeNo` only as fallback (references §5).

    The int form truncates leading zeros and alphanumeric employee ids, which are exactly
    the ids a real site uses once the device stops auto-assigning "1".."4" (DESIGN.md
    event model), so preferring it would merge two people into one employee.
    """
    text = record.get("employeeNoString")
    if isinstance(text, str) and text.strip():
        return text.strip()
    fallback = record.get("employeeNo")
    if isinstance(fallback, str) and fallback.strip():
        return fallback.strip()
    if isinstance(fallback, int) and not isinstance(fallback, bool):
        return str(fallback)
    return None


# --- classification ---------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class EventClassification:
    """The classification of one device record. `raw` is the untouched record.

    `punch_candidate` is a *property of the record*, not a filter applied by us: the
    caller decides what to store, and per DESIGN.md everything is stored and filtering
    happens at query time. A record that is not a punch candidate is still returned, with
    `reason` explaining why.
    """

    major: int | None
    minor: int | None
    outcome: Outcome
    code_name: str | None
    #: True when (major, minor) is not in the curated table. Kept + info, never dropped.
    unknown_code: bool
    #: True when the device did NOT list this code in its capability set (None = the
    #: device gave us no list to check, which is not evidence of anything).
    not_advertised: bool | None
    #: `currentVerifyMode` verbatim — no normalisation, no invented finer mode.
    verify_mode: str | None
    employee_no: str | None
    serial_no: int | None
    event_time: str | None
    #: major == 5 && granted && auth minor && employee present && real verify mode.
    punch_candidate: bool
    #: True for the major-3 operation stream (the site-a 1/min heartbeat lives here).
    operation_stream: bool
    major_class: str | None
    reason: str | None = None
    raw: Mapping[str, Any] = field(default_factory=dict, repr=False)

    def as_dict(self) -> dict[str, Any]:
        return {
            "major": self.major,
            "minor": self.minor,
            "major_class": self.major_class,
            "code_name": self.code_name,
            "outcome": self.outcome.value,
            "unknown_code": self.unknown_code,
            "not_advertised": self.not_advertised,
            "verify_mode": self.verify_mode,
            "employee_no": self.employee_no,
            "serial_no": self.serial_no,
            "event_time": self.event_time,
            "punch_candidate": self.punch_candidate,
            "operation_stream": self.operation_stream,
            "reason": self.reason,
        }


def _verify_is_auth_mode(verify_mode: str | None) -> bool:
    return (verify_mode or "").strip().lower() not in NON_AUTH_VERIFY_MODES


def classify_event(
    record: Mapping[str, Any],
    *,
    capabilities: DeviceCapabilities | None = None,
) -> EventClassification:
    """Classify one AcsEvent record (or a whole search-response page's first record —
    see `_record_fields`). Never raises for an odd record: an unreadable code is
    `info + unknown_code`, because the alternative is losing a punch silently."""
    fields = _record_fields(record)
    major = _as_int_or_none(fields.get("major"))
    minor = _as_int_or_none(fields.get("minor"))

    if major is None or minor is None:
        return EventClassification(
            major=major,
            minor=minor,
            outcome=Outcome.INFO,
            code_name=None,
            unknown_code=True,
            not_advertised=None,
            verify_mode=_text_or_none(fields.get("currentVerifyMode")),
            employee_no=_employee_no(fields),
            serial_no=_as_int_or_none(fields.get("serialNo")),
            event_time=_text_or_none(fields.get("time")),
            punch_candidate=False,
            operation_stream=major == 3,
            major_class=None if major is None else MAJOR_CLASS.get(major),
            reason="record carries no readable major/minor pair",
            raw=dict(record),
        )

    info = EVENT_CODE_TABLE.get((major, minor))
    outcome = Outcome.INFO if info is None else info.outcome
    unknown = info is None
    verify_mode = _text_or_none(fields.get("currentVerifyMode"))
    employee_no = _employee_no(fields)
    advertised = None if capabilities is None else capabilities.is_advertised(major, minor)
    # The field is named `not_advertised`, so invert the predicate. `None` ("the device
    # gave no list to check") stays None — silence is not evidence (is_advertised).
    not_advertised = None if advertised is None else (not advertised)

    punch, reason = _punch_decision(
        major=major,
        minor=minor,
        outcome=outcome,
        unknown=unknown,
        verify_mode=verify_mode,
        employee_no=employee_no,
        not_advertised=not_advertised,
    )

    return EventClassification(
        major=major,
        minor=minor,
        outcome=outcome,
        code_name=None if info is None else info.name,
        unknown_code=unknown,
        not_advertised=not_advertised,
        verify_mode=verify_mode,
        employee_no=employee_no,
        serial_no=_as_int_or_none(fields.get("serialNo")),
        event_time=_text_or_none(fields.get("time")),
        punch_candidate=punch,
        operation_stream=major == 3,
        major_class=MAJOR_CLASS.get(major),
        reason=reason,
        raw=dict(record),
    )


def _text_or_none(value: Any) -> str | None:
    if isinstance(value, str) and value.strip():
        return value.strip()
    return None


def _punch_decision(
    *,
    major: int,
    minor: int,
    outcome: Outcome,
    unknown: bool,
    verify_mode: str | None,
    employee_no: str | None,
    not_advertised: bool | None,
) -> tuple[bool, str | None]:
    """The rule, stated once, with the reason it failed on top.

    Order is diagnostic-first: the returned `reason` is what a human reads when a day of
    punches looks thin, so the *first* failing condition is the useful one.
    """
    if major != PUNCH_MAJOR:
        return False, f"major {major} is not an authentication major (only major 5)"
    if unknown:
        return False, "code is not in the curated table (unknown_code) — not guessed as a pass"
    if outcome is not Outcome.GRANTED:
        return False, f"outcome {outcome.value} is not granted"
    if minor not in AUTH_PASS_MINORS:
        return False, f"minor {minor} is a door-state/operation code, not an authentication pass"
    if not employee_no:
        return False, "no employeeNoString — an unattributed pass cannot enter a timesheet"
    if not _verify_is_auth_mode(verify_mode):
        return False, f"currentVerifyMode {verify_mode!r} is not an authentication mode"
    if not_advertised:
        # Not disqualifying — the device can under-advertise (site-a omits `cardOrFaceOrFp`
        # from its own verifyMode list). Flagged, still a candidate.
        return True, f"minor {minor} is not in the device's advertised set (kept anyway)"
    return True, None


def classify_batch(
    records: Iterable[Mapping[str, Any]],
    *,
    capabilities: DeviceCapabilities | None = None,
) -> list[EventClassification]:
    """Classify an iterable of records (e.g. `page["AcsEvent"]["InfoList"]`)."""
    return [classify_event(record, capabilities=capabilities) for record in records]
