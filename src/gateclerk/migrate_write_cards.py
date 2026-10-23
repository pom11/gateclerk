"""E1-05 cards phase: CardInfo/SetUp port, proof-of-add card undo, capacity fail-fast.

Design contract: docs/ENROLLMENT-MIGRATION.md — §5 steps 2/4/5 (phase order, capacity
fail-fast, pair-identity cards), §5a (journal + undo with proof-of-add), §5b/§5b.1
(rule D-WIPE and the banned user delete), §6 (read-back verify), §0 (safety rules),
§9 (capture-before-fake). Parent E1-04 shipped the foundation this module is built
ON: ``gateclerk.migrate_write`` contributes ``WriteJournal``,
``BudgetedWriteTransport``, ``WriteRejectedError``/``WriteAbortedError``,
``classify_rejection``, ``person_hash`` and the §6 paging walker. NOTHING here forks a
second journal or a second budget: the card phase appends to the same append-only
JSONL under ``phase="cards"`` and counts its calls on the same budgeted ledger.

Every write shape here exists ONLY because it sits in a committed bench-A capture
fixture under ``tests/fixtures/recorded/site-a-ds-k1t341amf-s/enrollment/`` (PR #43):

    cardinfo_setup_add_request.json      PUT, SINGULAR "CardInfo", keys EXACTLY
                                         employeeNo/cardNo/cardType + mode:"add"
                                         — NO "enable" field (cards have none)
    cardinfo_setup_add_response.json     statusCode 1
    cardinfo_setup_readback.json         the NONZERO CardInfoSearch with the CardInfo
                                         list — §5 step 5's prerequisite, satisfied
    cardinfo_delete_request.json         PUT CardInfo/Delete, list INSIDE
                                         CardInfoDelCond.CardNoList[{cardNo}]
    cardinfo_delete_response.json        statusCode 1
    cardinfo_delete_verified_empty.json  the read-back after it: NO MATCH

This module issues ZERO device requests by itself and registers NOTHING in
``gateclerk.endpoints`` (the read-only registry stays exactly as
``tests/test_endpoints_registry.py`` pins it). The paths are string constants; the
transport and the search reader are INJECTED. There is no code path from here to a
socket.

Safety rules honoured here, each with the test that proves it
(tests/test_e1_05_cards_phase.py):

* §5 step 5 — idempotency identity is the ``(cardNo, employeeNo)`` PAIR, never
  cardNo-presence. A re-run skips pairs already on target and sends zero bytes.
* §4 BLOCKER (ownership) — the reviewer's word: a bundle cardNo the target binds to a
  DIFFERENT employeeNo is neither skipped-as-done nor reassigned. It is E1-02's
  ``Reason.CARD_BOUND_TO_OTHER`` conflict, REPORTED AND SKIPPED here while the phase
  continues with the other cards, and the writer re-checks it at the last frame
  rather than trusting the upstream filter.
* §5 step 4 — the first rejection aborts the phase, journals ``rejected``, and names
  exactly which cards landed. Nothing is retried (§0.6). ``classify_rejection`` keeps
  the captured vocabulary; because NO committed capture contains a capacity word,
  :func:`is_card_capacity_rejection` names none either — the fake's clearly-labelled
  synthetic answer classifies UNKNOWN (``RejectKind.OTHER``) and still aborts.
* §5a — undo removes ONLY ``confirmed`` ``add`` entries whose live re-read still
  hashes to the journal's post-write hash (proof-of-add). ``planned``/``applied``
  without ``confirmed`` are never touched; a drifted row refuses and escalates,
  because someone else's edit wins.
* §5b — every card delete carries the count-delta wrapper: the CardInfo count before
  and after, plus the read-back of the named cardNos. A drop LARGER than the named
  list, a named card that survives, or a count read that failed is an INCIDENT
  (:class:`DeleteAbortedError`): stop, escalate, restore from the pre-run bundle.
* §5b.1 — USER DELETE IS BANNED OUTRIGHT. There is no user-undo verb, no user
  delete path and no way to reach the wipe hazard from here: ``person_delete_forbidden``
  makes the ban a callable fact (the NAME carries no user-delete vocabulary either —
  a test asserts the exported names never spell "user" and the words of the
  person-delete shape never occur in this source file at all).
* §6 — verify re-walks the card roster and compares ``(cardNo, employeeNo,
  cardType)`` against the journal's intent; a mismatch is TERMINAL (§0.6) and is never
  "fixed" with a re-write. The card roster read carries NO proven server-side filter,
  so the pair match is CLIENT-SIDE and the method says so.
* §9 — reports carry hashes, counts and device words only. The person appears as
  ``person_hash``; the card number is a credential, so it appears only as
  ``card_hash`` in anything a human reads.
"""

from __future__ import annotations

import hashlib
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field, replace
from enum import StrEnum
from time import monotonic as _monotonic
from typing import Any, Protocol

from gateclerk.exceptions import GateclerkError
from gateclerk.migrate_bundle import BundleData, content_hash, normalize_record
from gateclerk.migrate_diff import DiffClass, Plan, plan_still_valid
from gateclerk.migrate_probe import CapabilityMatrix, require_fresh
from gateclerk.migrate_write import (
    DEFAULT_BATCH_SIZE,
    MAX_CLOCK_SKEW_S,
    ApplyAbortedError,
    BudgetedWriteTransport,
    JournalEntry,
    JournalState,
    RejectKind,
    SearchReader,
    WriteAbortedError,
    WriteJournal,
    WriteRejectedError,
    WriteShapeError,
    _noop_sleep,
    _paged,
    check_clock_skew,
    classify_rejection,
    person_hash,
)

__all__ = [
    "CAPTURED_CARD_READ_KEYS",
    "CAPTURED_CARD_WRITE_KEYS",
    "CARD_DELETE_PATH",
    "CARD_SEARCH_PATH",
    "CARD_SETUP_PATH",
    "CardDeleteScopeError",
    "CardStoreRead",
    "CardVerdict",
    "CardVerifyItem",
    "CardVerifyReport",
    "CardWrite",
    "CardsApplyReport",
    "CardsPhaseResult",
    "DeleteAbortedError",
    "UndoItem",
    "UndoReport",
    "apply_cards_phase",
    "assess_delete_delta",
    "build_card_delete_body",
    "build_card_setup_body",
    "card_caps",
    "card_delete_targets",
    "card_hash",
    "card_identity_projection",
    "derive_card_batch_size",
    "is_card_capacity_rejection",
    "person_delete_forbidden",
    "plan_card_writes",
    "read_card_store",
    "run_cards_phase",
    "target_card_pairs",
    "undo_card_adds",
    "verify_cards",
]

#: The captured card write endpoints (OBSERVED.md "E1 §5.0 WRITE-PATH CAPTURE":
#  ``PUT /ISAPI/AccessControl/CardInfo/SetUp?format=json`` and
#  ``PUT /ISAPI/AccessControl/CardInfo/Delete?format=json``). Path constants, not
# registry entries — see the module docstring for why the registry stays read-only.
CARD_SETUP_PATH = "/ISAPI/AccessControl/CardInfo/SetUp"
CARD_DELETE_PATH = "/ISAPI/AccessControl/CardInfo/Delete"
#: The §6 verify read. The read-only registry already carries this endpoint
#: (``card_info_search``, added by E1-01); the constant exists so the fake route, the
#: walker and the tests share ONE spelling of the path being audited.
CARD_SEARCH_PATH = "/ISAPI/AccessControl/CardInfo/Search"

#: The key set of the ONE proven CardInfo/SetUp body (``cardinfo_setup_add_request.json``
#: verbatim): ``employeeNo``, ``cardNo``, ``cardType`` (+ ``mode:"add"``). Note the
#: absence — there is NO ``enable`` field in the capture, so there is none here (§9: an
#: unrecorded key is an unrecorded shape, and this family 400s or half-merges on those).
CAPTURED_CARD_WRITE_KEYS: frozenset[str] = frozenset({"employeeNo", "cardNo", "cardType"})

#: The key set of the proven read-back (``cardinfo_setup_readback.json``
#: ``CardInfoSearch.CardInfo[0]``). ``leaderCard`` is device vocabulary the WRITE shape
#: never carries — which is exactly why §6's card compare is the three fields the
#: design names (cardNo, employeeNo, cardType) and not a whole-record hash across two
#: different dialects (the users lesson, pinned by E1-04).
CAPTURED_CARD_READ_KEYS: frozenset[str] = frozenset(
    {"employeeNo", "cardNo", "leaderCard", "cardType"}
)

#: ``cardType`` vocabulary bench A's own caps document claims (§1: ``cardType @opt
#: normalCard,patrolCard,hijackCard,superCard``). Caps are device CLAIMS (§3), so this
#: fallback is used ONLY when no probe is injected; a probe's own @opt always wins.
CARD_TYPE_CAPS_FALLBACK: frozenset[str] = frozenset(
    {"normalCard", "patrolCard", "hijackCard", "superCard"}
)

#: ``CardInfoCap.cardNo @max`` on bench A (§1: cardNo ≤ 20). A LENGTH sentinel only —
#: §1 records true device capacity as unexposed, and ``maxRecordNum`` (3000) is a
#: page/batch count that §1 explicitly says is not capacity.
CARD_NO_MAX_LEN = 20

#: The only ``mode`` the capture proved for CardInfo/SetUp.
CARD_SETUP_MODE = "add"

#: The three fields §5 step 5/§6 compare for a card. Nothing else is card identity.
CARD_IDENTITY_FIELDS: tuple[str, ...] = ("cardNo", "employeeNo", "cardType")

#: Undo's journal phase token — its own journal, per §5a ("undo … gets its own
#: journal"), opened by the caller at a path of its choosing.
CARDS_PHASE = "cards"
UNDO_PHASE = "cards_undo"


def card_hash(card_no: str, *, prefix_len: int = 12) -> str:
    """The printable card identity: sha256 prefix of the card number (§4/§9).

    A card number is a credential — losing it is a physical-access leak — so no
    report ever carries it in the clear. Same rule ``person_hash`` applies to the
    employeeNo.
    """
    return hashlib.sha256(card_no.encode("utf-8")).hexdigest()[:prefix_len]


# --- §5b.1: the user-delete ban, stated as code ---------------------------------------------


class CardDeleteScopeError(GateclerkError):
    """A card delete was refused BEFORE it was built or sent (§5b, §5b.1).

    Two different refusals share this type because both mean "the shape is not the one
    the capture proved safe": a delete that would name cards this run did not earn the
    right to remove (D-WIPE's rule for an over-broad list), and any delete aimed at a
    PERSON rather than a card (§5b.1 — banned outright, not merely "harder to get").
    """


class DeleteAbortedError(GateclerkError):
    """The §5b count-delta wrapper says the delete removed MORE than it was told to.

    This is the incident, not a retry cue — the wrapper exists to turn D-WIPE from a
    silent catastrophe into a stop-the-run signal. ``count_before``/``count_after`` and
    the still-present ``survivors`` ride on the exception so the operator can read the
    delta themselves and reach for the pre-run bundle (§2).
    """

    def __init__(
        self,
        message: str,
        *,
        count_before: int | None = None,
        count_after: int | None = None,
        named: Sequence[str] = (),
        survivors: Sequence[str] = (),
    ) -> None:
        self.count_before = count_before
        self.count_after = count_after
        self.named = tuple(named)
        self.survivors = tuple(survivors)
        super().__init__(message)


def person_delete_forbidden() -> None:
    """The §5b.1 ban as a callable fact: this module has no user-undo verb.

    Both bodies this firmware *accepts* for a person delete returned ``ok`` and wiped
    the ENTIRE roster — bench A lost every user twice that way, the second time with
    the documentation's own targeted mode (OBSERVED.md "USER DELETE IS NOT
    TARGETABLE"). So undo of a user ADD has NO API path on this fw, and the only
    honest "user undo" this module can offer is this exception plus a pointer at the
    pre-run snapshot bundle. A test asserts the very words of the person-delete shape
    never appear in this source file, and that no exported NAME of this module spells
    "user" at all — the ban is vocabulary-level, not just call-level.
    """
    raise CardDeleteScopeError(
        "no user-undo verb exists here: the two shapes this firmware accepts for a "
        "person delete each answered ok and removed the WHOLE roster (§5b.1, "
        "OBSERVED.md — reproduced twice on bench A). Undo of a user add is "
        "REPORT-ONLY: re-enroll or restore that person from the pre-run snapshot "
        "bundle (§2). This module removes CARDS only, through the capture-proven "
        "targeted card delete."
    )


# --- §5 step 5: the write-body projection (the frozen capture key set) -----------------------


def card_caps(probe: CapabilityMatrix | None) -> Mapping[str, Any] | None:
    """The ``CardInfoCap`` node of the probe's recorded caps claims, or None.

    ``probe_device`` files caps bodies under its own surface keys (``caps_card_info``);
    the endpoint spelling (``card_info_capabilities``) is accepted too so a
    hand-assembled matrix carries the same facts as a probed one. Caps are CLAIMS
    (§3): used here only as the value vocabulary and the length sentinel, NEVER as
    capacity.
    """
    if probe is None:
        return None
    caps = getattr(probe, "caps_raw", None)
    if not isinstance(caps, Mapping):
        return None
    for key in ("caps_card_info", "card_info_capabilities"):
        body = caps.get(key)
        if not isinstance(body, Mapping):
            continue
        section = body.get("CardInfoCap")
        if isinstance(section, Mapping):
            return section
    return None


def _opt_words(section: Mapping[str, Any] | None, name: str) -> frozenset[str] | None:
    """The comma-separated ``@opt`` vocabulary the caps document claims for a field."""
    if section is None:
        return None
    node = section.get(name)
    opts = node.get("@opt") if isinstance(node, Mapping) else None
    if not isinstance(opts, str) or not opts.strip():
        return None
    return frozenset(word.strip() for word in opts.split(",") if word.strip())


def _caps_int(section: Mapping[str, Any] | None, name: str, key: str) -> int | None:
    if section is None:
        return None
    node = section.get(name)
    value = node.get(key) if isinstance(node, Mapping) else None
    if isinstance(value, bool) or not isinstance(value, int):
        return None
    return value


def build_card_setup_body(
    record: Mapping[str, Any], *, probe: CapabilityMatrix | None = None
) -> dict[str, Any]:
    """The ``{"CardInfo": {…}}`` body for one card add — EXACTLY the captured shape.

    Fail-closed in four places, each before any request could leave the process:

    1. **Key set.** ``employeeNo``, ``cardNo``, ``cardType`` + ``mode:"add"`` — the
       capture's four keys and nothing else. An ``enable`` field is NOT here because
       the card capture has no ``enable``; a source record that carries extra keys
       (``leaderCard``, counters, a device URL) has them DROPPED, never echoed (R2).
    2. **Required values.** Every captured key present and non-empty: a thin body is
       an unrecorded shape and this family 400s on those.
    3. **``mode``.** Only the captured ``"add"``. Removal is a DIFFERENT endpoint with
       a different guard (:func:`build_card_delete_body`), never a SetUp mode.
    4. **Vocabulary + length sentinel.** ``cardType`` must sit inside the caps ``@opt``
       set and ``cardNo`` must fit the caps ``@max`` length. A value the target says it
       does not accept is refused here rather than rejected mid-batch (§3).
    """
    missing = sorted(k for k in CAPTURED_CARD_WRITE_KEYS if record.get(k) in (None, ""))
    if missing:
        raise WriteShapeError(
            f"cannot build a captured CardInfo/SetUp body: the record lacks {missing}; "
            "the captured key set is "
            + str(sorted(CAPTURED_CARD_WRITE_KEYS))
            + " plus mode:'add' (cardinfo_setup_add_request.json) — a thinner body is "
            "an unrecorded shape (§9 capture-before-fake)"
        )
    mode = record.get("mode")
    if mode not in (None, CARD_SETUP_MODE):
        raise WriteShapeError(
            f"mode {mode!r} is not captured; the only mode bench A proved for "
            f"CardInfo/SetUp is {CARD_SETUP_MODE!r} (OBSERVED.md §5.0 capture), and a "
            "card is removed through the capture-proven delete endpoint — never a "
            "SetUp mode (§5b)"
        )
    employee_no = str(record["employeeNo"])
    card_no = str(record["cardNo"])
    card_type = str(record["cardType"])
    section = card_caps(probe)
    allowed = _opt_words(section, "cardType") or CARD_TYPE_CAPS_FALLBACK
    if card_type not in allowed:
        raise WriteShapeError(
            f"cardType={card_type!r} is outside the vocabulary the target's own "
            f"CardInfo caps claims ({sorted(allowed)}); caps are the vocabulary source "
            "(OBSERVED.md) — refusing to write a value the target says it rejects (§3)"
        )
    limit = _caps_int(section, "cardNo", "@max") or CARD_NO_MAX_LEN
    if len(card_no) > limit:
        raise WriteShapeError(
            f"cardNo is {len(card_no)} characters; CardInfo caps claims cardNo @max "
            f"{limit} (§1: cardNo <= 20) — a length sentinel is a shape guard, not "
            "capacity, and an over-long number is an unrecorded value"
        )
    return {
        "CardInfo": {
            "employeeNo": employee_no,
            "cardNo": card_no,
            "cardType": card_type,
            "mode": CARD_SETUP_MODE,
        }
    }


def build_card_delete_body(card_nos: Sequence[str]) -> dict[str, Any]:
    """The ``{"CardInfoDelCond": {"CardNoList": [{"cardNo": …}]}}`` body — capture-proven.

    The ONE delete shape the capture proves targeted-safe (§5b.1 point 3: "face and
    card deletes ARE targeted and capture-proven (list slot verified safe)"). The list
    lives INSIDE ``CardInfoDelCond`` — the slot the device actually reads. That
    property is the whole reason this builder hard-codes the slot, the entry shape and
    the single key per entry instead of accepting a dict: on this firmware a person
    delete whose list sat in the SIBLING slot answered ``ok`` and removed everyone
    (§5b), and no delete may be sent whose list-slot shape was not captured.
    """
    if not card_nos:
        raise CardDeleteScopeError(
            "refusing to build a card delete with an EMPTY CardNoList: a delete that "
            "names nobody is not a no-op on this family — the capture session proved "
            "twice that the device's answer to a list it does not read is 'delete "
            "everything' (§5b D-WIPE)"
        )
    named: list[dict[str, str]] = []
    seen: set[str] = set()
    for card_no in card_nos:
        if not isinstance(card_no, str) or not card_no.strip():
            raise CardDeleteScopeError(
                f"card delete entry {card_no!r} is not a non-blank card number; the "
                "captured entry shape is exactly {'cardNo': '<number>'} "
                "(cardinfo_delete_request.json) — a malformed entry is an unrecorded "
                "shape (§9)"
            )
        if card_no in seen:
            continue  # the captured shape names each card once; a duplicate is noise
        seen.add(card_no)
        named.append({"cardNo": card_no})
    return {"CardInfoDelCond": {"CardNoList": named}}


def card_delete_targets(body: Mapping[str, Any]) -> tuple[str, ...]:
    """The card numbers a delete body actually names, in body order.

    The guard reads the BODY, not the intent — that is the point. A caller (or a
    future refactor) that hands the sender a body naming more than it was told to send
    is caught here, in the one place both the happy path and the incident path pass.
    """
    cond = body.get("CardInfoDelCond")
    if not isinstance(cond, Mapping):
        return ()
    entries = cond.get("CardNoList")
    if not isinstance(entries, list):
        return ()
    out: list[str] = []
    for entry in entries:
        if isinstance(entry, Mapping) and isinstance(entry.get("cardNo"), str):
            out.append(entry["cardNo"])
    return tuple(out)


# --- §5 step 4: the capacity vocabulary (nothing invented) ------------------------------------


def is_card_capacity_rejection(sub_status: str | None) -> bool:
    """Whether a device word is a card-CAPACITY answer this module may NAME.

    Returns False for everything, deliberately: no committed capture contains a
    capacity rejection (§1 records true device capacity as unexposed on this family),
    so naming one here would be invented vocabulary — the exact thing §9 forbids. This
    only decides whether a report may use the word "capacity"; the first rejection
    aborts the phase either way (§5 step 4). The fake's capacity knob answers a
    clearly-labelled synthetic subcode and the test pins that it classifies
    ``RejectKind.OTHER`` (UNKNOWN) and still aborts.
    """
    del sub_status  # no captured capacity word exists to match (§9).
    return False


# --- §5 step 5: what the cards phase writes ----------------------------------------------------


@dataclass(frozen=True, slots=True)
class CardWrite:
    """One card add this phase may send, with the bundle card record it came from."""

    employee_no: str
    employee_hash: str
    card_no: str
    card_type: str
    record: Mapping[str, Any]
    classification: DiffClass = DiffClass.ADD

    @property
    def pair_id(self) -> tuple[str, str]:
        """The idempotency identity: the (cardNo, employeeNo) PAIR (§5 step 5)."""
        return (self.card_no, self.employee_no)

    @property
    def card_hash(self) -> str:
        return card_hash(self.card_no)

    @property
    def intended_record(self) -> dict[str, Any]:
        """The identity projection this write intends (the journal's intent hash).

        NOT the raw bundle record: the bundle may carry rows in the READ dialect
        (``leaderCard`` etc.), while §6 confirms against the three-field identity
        projection. The journal's intended hash must be comparable to the verify
        walker's target hash — E1-04's "write-shape vs read-shape" lesson, applied to
        the intent side: the projection is the ONLY hash both sides can reach.
        """
        return card_identity_projection(self.record)


def card_identity_projection(record: Mapping[str, Any]) -> dict[str, Any]:
    """The ``(cardNo, employeeNo, cardType)`` projection §5 step 5/§6 compare on.

    The write shape and the read shape are different dialects (the read adds
    ``leaderCard``), so a whole-record hash across them is the comparison E1-04 proved
    fails closed for the wrong reason. The card's identity is these three fields — and
    these only — because that is what the capture carries in both shapes.
    """
    out: dict[str, Any] = {}
    for key in CARD_IDENTITY_FIELDS:
        value = record.get(key)
        if value is not None:
            out[key] = str(value)
    return normalize_record(out)


def target_card_pairs(rows: Sequence[Mapping[str, Any]]) -> dict[str, str]:
    """``cardNo -> employeeNo`` for every card row the target actually returned.

    The one place this module reads a card row. Compared as STRINGS exactly as the
    device spells them (§1: no coercion), and a row without a cardNo is skipped
    because it cannot take part in a pair.
    """
    out: dict[str, str] = {}
    for row in rows:
        card_no = row.get("cardNo")
        if card_no is None:
            continue
        out[str(card_no)] = str(row.get("employeeNo") or "")
    return out


def derive_card_batch_size(probe: CapabilityMatrix | None) -> int:
    """Batch size = the device's own write ``@max`` where discoverable, else 10 (§5.3).

    Nothing this phase may read names a WRITE batch maximum for cards either:
    ``CardInfoCap.maxRecordNum`` (3000 on bench A) is the search page/batch count and
    §1 says in words it is not capacity; ``cardNo @max`` is a string LENGTH. Reading
    either as a batch cap would be the §1 capacity trap in a new costume, so the
    fallback ships and the absence stays a recorded fact (E1-04's users reasoning,
    applied unchanged).
    """
    del probe
    return DEFAULT_BATCH_SIZE


def plan_card_writes(
    plan: Plan,
    bundle: BundleData,
    *,
    target_cards: Sequence[Mapping[str, Any]],
    probe: CapabilityMatrix | None = None,
) -> tuple[tuple[CardWrite, ...], tuple[tuple[str, str], ...]]:
    """Split the diff's card work into (writable adds, report-only conflicts).

    Ownership-checked, not presence-checked (§4's reviewer BLOCKER): a bundle cardNo
    the target already binds to a DIFFERENT employeeNo is E1-02's
    ``Reason.CARD_BOUND_TO_OTHER`` conflict — REPORTED AND SKIPPED, never silently
    skipped as "already done" (that person would never get their card) and never
    reassigned (that strips someone else's). A pair already on target is also skipped,
    but into a DIFFERENT bucket (``CardsPhaseResult.already_paired``): "nothing to do"
    and "refused to do it" must never share a code.

    Cards whose owner the diff does not classify as writable are skipped with reason
    ``person_not_writable`` — §5 step 2's order guarantee (users verified before cards)
    is what makes that a real gate rather than a courtesy.
    """
    writable_people: set[str] = set()
    conflict_people: set[str] = set()
    for item in plan.items:
        if item.classification in (DiffClass.ADD, DiffClass.UPDATE, DiffClass.SAME):
            # SAME is writable for CARDS: E1-02 counts card adds for a `same` person
            # (a matched person missing their card is exactly what this phase is for).
            # Only CONFLICT persons are gated here — §5 step 2's users-verified-first
            # order is what makes that gate real rather than a courtesy.
            writable_people.add(item.employee_no)
        elif item.classification is DiffClass.CONFLICT:
            conflict_people.add(item.employee_no)
    owners = target_card_pairs(target_cards)
    writes: list[CardWrite] = []
    skipped: list[tuple[str, str]] = []
    for record in bundle.cards:
        employee_no = record.get("employeeNo")
        card_no = record.get("cardNo")
        if not isinstance(employee_no, str) or card_no is None:
            continue  # E1-01's export shape guarantees both; a card without a pair is data
        card_no = str(card_no)
        owner = owners.get(card_no)
        if owner is not None and owner != employee_no:
            # Ownership first: this card specifically is someone else's — the §4
            # BLOCKER classification, distinct from "that person is conflicted".
            skipped.append((card_hash(card_no), _OWNERSHIP_CONFLICT))
            continue
        if employee_no in conflict_people:
            skipped.append(
                (card_hash(card_no), "person_conflict_report_only(card_no_bound_to_other)")
            )
            continue
        if employee_no not in writable_people:
            skipped.append((card_hash(card_no), "person_not_writable"))
            continue
        try:
            build_card_setup_body(record, probe=probe)
        except WriteShapeError as exc:
            skipped.append((card_hash(card_no), f"shape_refused:{exc}"))
            continue
        writes.append(
            CardWrite(
                employee_no=employee_no,
                employee_hash=person_hash(employee_no),
                card_no=card_no,
                card_type=str(record.get("cardType")),
                record=record,
            )
        )
    return tuple(writes), tuple(skipped)


#: The conflict reason this phase reports for a foreign-bound cardNo — E1-02's
#: ``Reason.CARD_BOUND_TO_OTHER`` in words the phase result can carry without
#: importing the enum's rendering. The parenthetical is the invariant the test pins.
_OWNERSHIP_CONFLICT = "card_bound_to_other_employee(neither_skipped_as_done_nor_reassigned)"


# --- the phase --------------------------------------------------------------------------------


class CardWriteTransport(Protocol):
    """The write seam this phase uses — satisfied by E1-04's ``BudgetedWriteTransport``.

    Declared structurally so the card phase counts on the SAME ledger the users phase
    used (one client per phase, re-bootstrap at 80 authed calls) instead of importing a
    second budget. ``put_setup`` is "PUT this captured body at this captured path":
    both the SetUp and the capture-proven Delete are PUTs, and both are charged to the
    same counter — a delete that escaped the ledger would be an unbudgeted authed call
    (§5.3's whole reason for existing).
    """

    def put_setup(self, path: str, body: Mapping[str, Any]) -> dict[str, Any]:
        """PUT one captured body at one captured path (raise on a rejection)."""
        ...  # pragma: no cover - protocol

    @property
    def rebootstraps(self) -> int:
        """How many times this budget has replaced its client (§5.3)."""
        ...  # pragma: no cover - protocol


@dataclass(slots=True)
class _CardTally:
    """Mutable accumulator for one cards phase (the public result stays frozen)."""

    applied: list[str] = field(default_factory=list)
    rejected: list[tuple[str, RejectKind, str | None]] = field(default_factory=list)
    conflicts: list[tuple[str, str]] = field(default_factory=list)
    already_paired: list[str] = field(default_factory=list)
    batches: int = 0
    writes_sent: int = 0

    def result(
        self, *, planned: Sequence[str], batch_size: int, rebootstraps: int, aborted: bool
    ) -> CardsPhaseResult:
        return CardsPhaseResult(
            planned=tuple(planned),
            applied=tuple(self.applied),
            rejected=tuple(self.rejected),
            conflicts=tuple(self.conflicts),
            already_paired=tuple(self.already_paired),
            batches=self.batches,
            batch_size=batch_size,
            writes_sent=self.writes_sent,
            rebootstraps=rebootstraps,
            aborted=aborted,
        )


@dataclass(frozen=True, slots=True)
class CardsPhaseResult:
    """What a cards phase did — the artifact §5 step 4 demands on an abort."""

    planned: tuple[str, ...] = ()  # card hashes, in send order
    applied: tuple[str, ...] = ()  # device answered statusCode 1
    confirmed: tuple[str, ...] = ()  # §6 verify agreed
    rejected: tuple[tuple[str, RejectKind, str | None], ...] = ()  # card hash, kind, word
    conflicts: tuple[tuple[str, str], ...] = ()  # card hash, reason (§4 ownership)
    already_paired: tuple[str, ...] = ()  # pairs already on target — no bytes sent
    batches: int = 0
    batch_size: int = DEFAULT_BATCH_SIZE
    writes_sent: int = 0
    rebootstraps: int = 0
    aborted: bool = False

    @property
    def landed(self) -> tuple[str, ...]:
        """Cards the device ACCEPTED (verify decides whether they stuck)."""
        return self.applied

    @property
    def clean(self) -> bool:
        return not self.aborted and not self.rejected

    def summary(self) -> dict[str, Any]:
        """PII-free run summary (§4): hashes, counts and the device's own words."""
        return {
            "planned": len(self.planned),
            "applied": len(self.applied),
            "appliedCards": list(self.applied),
            "confirmed": len(self.confirmed),
            "rejected": [
                {"card": h, "kind": str(kind), "subStatusCode": sub}
                for h, kind, sub in self.rejected
            ],
            "conflicts": [{"card": h, "reason": r} for h, r in self.conflicts],
            "alreadyPaired": len(self.already_paired),
            "batches": self.batches,
            "batchSize": self.batch_size,
            "writesSent": self.writes_sent,
            "rebootstraps": self.rebootstraps,
            "aborted": self.aborted,
        }


def run_cards_phase(
    transport: CardWriteTransport,
    journal: WriteJournal,
    writes: Sequence[CardWrite],
    *,
    target_cards: Sequence[Mapping[str, Any]] = (),
    probe: CapabilityMatrix | None = None,
    batch_size: int | None = None,
    sleep: Callable[[float], None] = _noop_sleep,
    batch_delay: float = 1.0,
) -> CardsPhaseResult:
    """Send the allowed card adds, journal-first, pair-checked, fail-fast (§5 steps 2-5).

    Per card the order is fixed and is what the tests pin: last-frame ownership
    re-check → pair check → journal ``planned`` + fsync → request → journal
    ``applied``. Confirmation is :func:`verify_cards`' job, never this function's: the
    status code proves nothing (§6).

    Two refusals, two shapes. The FIRST REJECTION (a device answer) ends the phase with
    ``applied[]`` naming the cards that landed — §5 step 4, never a silent partial
    write, never a retry (§0.6). An OWNERSHIP CONFLICT (a data condition) is reported
    and skipped while the phase continues with the other cards, because the operator
    decides a foreign-bound card, not the device (§4).
    """
    size = _effective_batch_size(batch_size)
    planned = tuple(w.card_hash for w in writes)
    tally = _CardTally()
    owners = target_card_pairs(target_cards)
    rows_by_no = {str(row["cardNo"]): row for row in target_cards if row.get("cardNo") is not None}

    if not writes:
        return tally.result(
            planned=planned,
            batch_size=size,
            rebootstraps=transport.rebootstraps,
            aborted=False,
        )

    for index, write in enumerate(writes):
        # LAST-FRAME ownership re-check. ``plan_card_writes`` refused this already and
        # the freshness gate ran before it — the writer re-checks anyway, because an
        # upstream filter is not a fact the writer may trust (§4, §0.7).
        owner = owners.get(write.card_no)
        if owner is not None and owner != write.employee_no:
            tally.conflicts.append((write.card_hash, _OWNERSHIP_CONFLICT))
            continue
        if owner == write.employee_no:
            # (cardNo, employeeNo) already on the target: PAIR identity, §5 step 5.
            # Not sent, not journalled — a re-run that writes nothing cannot drift
            # anything. Deliberately NOT the same bucket as a conflict.
            #
            # The skip fires only when the FULL captured identity agrees: a row whose
            # cardType differs from the intent is NOT "already done" — §5 step 5
            # compares (cardNo, employeeNo, cardType), and §6 must get to judge the
            # drift (terminal, §0.6). Treating pair-presence as done would hide a
            # wrong-typed card behind a green re-run.
            live = rows_by_no.get(write.card_no)
            if live is not None and card_identity_projection(live) == card_identity_projection(
                write.record
            ):
                tally.already_paired.append(write.card_hash)
                continue
        if index % size == 0:
            if index:
                sleep(batch_delay)  # between batches only — never before the first
            tally.batches += 1
        entry = journal.planned(
            employee_no=write.employee_no,
            classification=str(write.classification),
            pre_write_record=None,  # a fresh pair: the pre-write snapshot has no card row
            intended_record=write.intended_record,
            op="card_setup",
            card_no=write.card_no,
        )
        body = build_card_setup_body(write.record, probe=probe)
        tally.writes_sent += 1
        try:
            ack = transport.put_setup(CARD_SETUP_PATH, body)
            # INSIDE the try: a non-OK ack is the SAME event as a raising transport —
            # journal `rejected`, record the rejection, abort via WriteAbortedError
            # (never a raw WriteRejectedError past the journal, E1-04's lesson).
            _require_ok_ack(ack, write.card_no)
        except WriteRejectedError as exc:
            journal.rejected(entry, sub_status=exc.sub_status)
            tally.rejected.append(
                (write.card_hash, classify_rejection(exc.sub_status), exc.sub_status)
            )
            result = tally.result(
                planned=planned,
                batch_size=size,
                rebootstraps=transport.rebootstraps,
                aborted=True,
            )
            capacity = is_card_capacity_rejection(exc.sub_status)
            raise WriteAbortedError(
                f"cards phase aborted at card {write.card_hash} (person "
                f"{write.employee_hash}) after {len(tally.applied)} of {len(writes)} "
                f"accepted: device answered {exc.sub_status or exc}"
                + (" (§5 step 4 capacity-class rejection)" if capacity else ""),
                result,
            ) from exc
        journal.applied(entry)
        tally.applied.append(write.card_hash)

    return tally.result(
        planned=planned,
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


def _require_ok_ack(ack: Mapping[str, Any], card_no: str) -> None:
    code = ack.get("statusCode")
    if code == 1:
        return
    raise WriteRejectedError(
        f"CardInfo/SetUp for card {card_hash(card_no)} answered statusCode={code!r} "
        f"(subStatusCode={ack.get('subStatusCode')!r}); only statusCode 1 is an ack "
        "this module treats as accepted (§6: the status code alone proves nothing)",
        sub_status=_opt_str(ack.get("subStatusCode")),
        envelope=ack,
    )


def _opt_str(value: Any) -> str | None:
    return value if isinstance(value, str) and value else None


# --- §6: the card read + verify walker ---------------------------------------------------------


class _PageSpy:
    """Wraps a reader to record what the device SAID about each page.

    Needed because §5b's guard compares COUNTS, and the only count this family offers for
    cards is the search envelope's own ``totalMatches`` — there is no ``CardInfo/Count``
    endpoint in the capture set, so inventing one would be the §9 mistake (the users
    phase had a count GET to borrow; the card phase does not). The spy keeps the device's
    statements instead of the walker's row list, so "the device said 7 cards" and "we
    happened to collect 7 rows" stay different facts in the report.
    """

    def __init__(self, reader: SearchReader) -> None:
        self.reader = reader
        self.calls: list[Mapping[str, Any]] = []
        self.stated_totals: list[int] = []
        self.statuses: list[str] = []
        self.failure: str | None = None

    def __call__(self, body: Mapping[str, Any]) -> dict[str, Any]:
        self.calls.append(dict(body))
        try:
            answer = self.reader(body)
        except Exception as exc:  # §0.7: a failed read is recorded, never "empty"
            self.failure = f"{type(exc).__name__}: {exc}"
            raise
        envelope = answer.get("CardInfoSearch") if isinstance(answer, Mapping) else None
        if isinstance(envelope, Mapping):
            total = envelope.get("totalMatches")
            if isinstance(total, int) and not isinstance(total, bool):
                self.stated_totals.append(total)
            self.statuses.append(str(envelope.get("responseStatusStrg") or ""))
        return answer


@dataclass(frozen=True, slots=True)
class CardStoreRead:
    """One complete ``CardInfo/Search`` walk: the rows plus what the device stated.

    ``count`` is the device's OWN stated total from the walk (``totalMatches``), falling
    back to the row count when the envelope never stated one. ``complete`` is False when
    the walk errored, hit the page cap, or ended on a status the export itself would
    refuse (§0.7: a zero is only zero when the device said OK / NO MATCH). Nothing
    downstream may treat an incomplete read as an answer.
    """

    rows: tuple[Mapping[str, Any], ...] = ()
    count: int | None = None
    complete: bool = False
    method: str = "full-roster (client-side pair match)"
    error: str | None = None
    calls: int = 0

    @property
    def card_nos(self) -> frozenset[str]:
        return frozenset(target_card_pairs(self.rows))

    @property
    def pairs(self) -> frozenset[tuple[str, str]]:
        return frozenset(target_card_pairs(self.rows).items())

    def owner_of(self, card_no: str) -> str | None:
        return target_card_pairs(self.rows).get(card_no)

    def row_for(self, card_no: str) -> Mapping[str, Any] | None:
        for row in self.rows:
            if row.get("cardNo") is not None and str(row["cardNo"]) == card_no:
                return row
        return None

    def summary(self) -> dict[str, Any]:
        return {
            "method": self.method,
            "count": self.count,
            "complete": self.complete,
            "calls": self.calls,
            "error": self.error,
        }


def read_card_store(
    reader: SearchReader,
    *,
    page_size: int = 30,
    max_pages: int = 500,
    sleep: Callable[[float], None] = _noop_sleep,
    inter_page_delay: float = 0.0,
    clock: Callable[[], float] = _monotonic,
) -> CardStoreRead:
    """Walk the whole card roster in the device's OWN dialect, fail-closed (§0.7).

    The wrapped ``CardInfoSearchCond`` + required ``searchID`` shape is the captured one
    (``cardinfo_setup_readback.json``; the fake answers 400 ``badJsonContent`` for a flat
    body and ``MessageParametersLack searchID`` without the id). Paging is E1-04's single
    cursor implementation imported rather than re-expressed, so verify cannot disagree
    with export about what a complete read means.

    NO server-side filter is sent because none is proven for this search (§1 recorded the
    roster read as answered wholesale; the fake documents the same). So the pair match is
    CLIENT-SIDE and ``method`` says so — pretending a filter was honored is precisely how
    a silently-ignored filter becomes a false OK (§6).
    """
    spy = _PageSpy(reader)
    rows, status = _paged(
        spy,
        {},
        page_size=page_size,
        max_pages=max_pages,
        sleep=sleep,
        inter_page_delay=inter_page_delay,
        clock=clock,
        search_prefix="e105c",
        cond_key="CardInfoSearchCond",
        envelope_key="CardInfoSearch",
        record_key="CardInfo",
    )
    if status != "ok":
        return CardStoreRead(
            rows=tuple(rows),
            complete=False,
            calls=len(spy.calls),
            error=(
                (
                    spy.failure
                    or "card roster walk did not terminate on a device verdict (page cap?)"
                )
                + " — a failed roster read is never read as 'every card is missing' (§0.7)"
            ),
        )
    terminal = spy.statuses[-1].strip().upper() if spy.statuses else ""
    if terminal not in {"OK", "NO MATCH", "NO MATCHES"}:
        # The export's own rule (migrate_export's accepted statuses): an odd terminal
        # status is exactly where a truncated pull would pose as a complete one.
        return CardStoreRead(
            rows=tuple(rows),
            complete=False,
            calls=len(spy.calls),
            error=f"card roster walk ended on responseStatusStrg={terminal!r} (§0.7)",
        )
    count = spy.stated_totals[-1] if spy.stated_totals else len(rows)
    return CardStoreRead(rows=tuple(rows), count=count, complete=True, calls=len(spy.calls))


class CardVerdict(StrEnum):
    """Per-pair verify verdict (§6). ``MISMATCH`` is terminal for the run."""

    OK = "ok"
    MISMATCH = "mismatch"
    MISSING = "missing"


@dataclass(frozen=True, slots=True)
class CardVerifyItem:
    """One pair's verify result. Hashes and field NAMES only — no values (§4)."""

    card_no: str
    card_hash: str
    employee_no: str
    employee_hash: str
    verdict: CardVerdict
    #: content hash of the (cardNo, employeeNo, cardType) projection the target holds.
    target_hash: str | None = None
    #: the projection hash we intended (the journal's intended hash).
    expected_hash: str | None = None
    #: card numbers the target holds for this person that the intent does not carry —
    #: reported as names-only? No: a card number is a credential, so only its hash.
    extra_card_hashes: tuple[str, ...] = ()
    #: field NAMES the target row has outside the captured read vocabulary (fail-closed).
    unknown_fields: tuple[str, ...] = ()
    note: str | None = None


@dataclass(frozen=True, slots=True)
class CardVerifyReport:
    """The §6 card walker's output: per-pair verdicts plus how the read was obtained."""

    items: tuple[CardVerifyItem, ...]
    #: how the answer was obtained. The card roster has NO proven server-side filter,
    #: so this is always the client-side arm — and saying so is the point (§6: a
    #: fallback that is invisible is the silently-ignored lesson all over again).
    method: str
    #: True only when the roster walk completed (the device said NO MATCH / non-MORE).
    read_complete: bool
    #: the device's own card count at verify time (§5b's count, kept for the report).
    card_count: int | None = None
    #: rows the walk could not be trusted for, in card-hash form.
    notes: tuple[str, ...] = ()

    def verdict_of(self, card_no: str, employee_no: str) -> CardVerdict | None:
        for item in self.items:
            if item.card_no == card_no and item.employee_no == employee_no:
                return item.verdict
        return None

    @property
    def ok(self) -> bool:
        return bool(self.items) and all(i.verdict is CardVerdict.OK for i in self.items)

    @property
    def mismatched(self) -> tuple[CardVerifyItem, ...]:
        return tuple(i for i in self.items if i.verdict is CardVerdict.MISMATCH)

    @property
    def missing(self) -> tuple[CardVerifyItem, ...]:
        return tuple(i for i in self.items if i.verdict is CardVerdict.MISSING)

    def summary(self) -> dict[str, Any]:
        return {
            "method": self.method,
            "readComplete": self.read_complete,
            "cardCount": self.card_count,
            "counts": {
                "ok": sum(1 for i in self.items if i.verdict is CardVerdict.OK),
                "mismatch": len(self.mismatched),
                "missing": len(self.missing),
            },
            "mismatches": [
                {
                    "card": i.card_hash,
                    "employee": i.employee_hash,
                    "unknownFields": list(i.unknown_fields),
                    "extraCards": list(i.extra_card_hashes),
                }
                for i in self.mismatched
            ],
        }


def verify_cards(
    reader: SearchReader,
    expected: Sequence[CardWrite],
    *,
    page_size: int = 30,
    max_pages: int = 500,
    sleep: Callable[[float], None] = _noop_sleep,
    inter_page_delay: float = 0.0,
    clock: Callable[[], float] = _monotonic,
    store: CardStoreRead | None = None,
) -> CardVerifyReport:
    """Re-read the card roster and compare (cardNo, employeeNo, cardType) (§6).

    A failed read is NEVER a verdict (§0.7): the walker raises nothing but refuses to
    call any pair ``missing`` unless the walk completed. Pair identity decides OK —
    the same ``(cardNo, employeeNo)`` key §5 step 5 writes under, never cardNo-presence
    (a cardNo that exists bound to someone else makes OUR pair missing, and the note
    says so rather than quietly passing). ``cardType`` drift and a row carrying fields
    outside the captured read vocabulary are MISMATCH — terminal, §0.6.
    """
    read = store or read_card_store(
        reader,
        page_size=page_size,
        max_pages=max_pages,
        sleep=sleep,
        inter_page_delay=inter_page_delay,
        clock=clock,
    )
    if not read.complete:
        # §0.7 pointed at verify: an untrusted read yields NO verdicts, not a page of
        # "missing" — that is exactly the false-green §6 exists to prevent.
        return CardVerifyReport(
            items=(),
            method=read.method,
            read_complete=False,
            card_count=read.count,
            notes=(read.error or "card roster read incomplete",),
        )
    owners = target_card_pairs(read.rows)
    by_person: dict[str, list[str]] = {}
    for card_no, employee_no in owners.items():
        by_person.setdefault(employee_no, []).append(card_no)

    items: list[CardVerifyItem] = []
    for write in expected:
        expected_projection = card_identity_projection(write.record)
        expected_hash = content_hash(expected_projection)
        base: dict[str, Any] = {
            "card_no": write.card_no,
            "card_hash": write.card_hash,
            "employee_no": write.employee_no,
            "employee_hash": write.employee_hash,
            "expected_hash": expected_hash,
        }
        row = read.row_for(write.card_no)
        if row is None:
            items.append(
                CardVerifyItem(
                    **base,
                    verdict=CardVerdict.MISSING,
                    note=(
                        f"no row with this cardNo in the {read.method} read, which "
                        "completed — accepted by the device, absent on read-back (§5a "
                        "unknown state: a human decides)"
                    ),
                )
            )
            continue
        if owners.get(write.card_no) != write.employee_no:
            items.append(
                CardVerifyItem(
                    **base,
                    verdict=CardVerdict.MISSING,
                    note=(
                        "the cardNo is on the target but bound to a DIFFERENT "
                        "employeeNo — our pair is absent (§5 step 5: pair identity, "
                        "never cardNo-presence)"
                    ),
                )
            )
            continue
        live_projection = card_identity_projection(row)
        target_hash = content_hash(live_projection)
        unknown = sorted(set(row) - CAPTURED_CARD_READ_KEYS)
        extras = sorted(c for c in by_person.get(write.employee_no, []) if c != write.card_no)
        extra_hashes = tuple(card_hash(c) for c in extras)
        if unknown:
            # §6's fail-closed rule, card edition: a row shape outside the captured
            # read vocabulary is data the operator must see, not a detail to average.
            items.append(
                CardVerifyItem(
                    **base,
                    verdict=CardVerdict.MISMATCH,
                    target_hash=target_hash,
                    unknown_fields=tuple(unknown),
                    extra_card_hashes=extra_hashes,
                    note=(
                        "the card row carries field NAMES outside "
                        "cardinfo_setup_readback.json's set — fail closed (§6)"
                    ),
                )
            )
            continue
        if live_projection != expected_projection:
            fields = sorted(
                k
                for k in set(live_projection) | set(expected_projection)
                if live_projection.get(k) != expected_projection.get(k)
            )
            items.append(
                CardVerifyItem(
                    **base,
                    verdict=CardVerdict.MISMATCH,
                    target_hash=target_hash,
                    extra_card_hashes=extra_hashes,
                    note=(
                        f"identity fields differ: {fields} (names only, §4) — §5 step "
                        "5 compares (cardNo, employeeNo, cardType)"
                    ),
                )
            )
            continue
        items.append(
            CardVerifyItem(
                **base,
                verdict=CardVerdict.OK,
                target_hash=target_hash,
                extra_card_hashes=extra_hashes,
            )
        )
    return CardVerifyReport(
        items=tuple(items),
        method=read.method,
        read_complete=True,
        card_count=read.count,
    )


# --- §5a + §5b: undo (card removal with the count-delta wrapper) ------------------------------


@dataclass(frozen=True, slots=True)
class UndoItem:
    """One card's undo outcome. Hashes and reasons only (§4)."""

    card_hash: str
    employee_hash: str
    reverted: bool
    reason: str | None = None


@dataclass(frozen=True, slots=True)
class UndoReport:
    """What an undo did — and the incident flag that stops everything when it must."""

    reverted: tuple[str, ...] = ()  # card hashes journalled `reverted`
    refused: tuple[UndoItem, ...] = ()  # entries undo would not touch, with the reason
    count_before: int | None = None
    count_after: int | None = None
    #: the journal the undo journalled into (§5a: "undo … gets its own journal").
    journal_path: str = ""
    incident: bool = False

    @property
    def clean(self) -> bool:
        """No incident AND nothing refused: every candidate was proven and reverted.

        A refusal is NOT clean even when the reverted set is non-empty — "3 of 4
        removed, one escalated to a human" is an incomplete outcome, and an `or`
        here would let the 3 hide the 1 (§5a: refused = unknown state = human).
        """
        return not self.incident and not self.refused

    def summary(self) -> dict[str, Any]:
        return {
            "reverted": list(self.reverted),
            "refused": [
                {"card": r.card_hash, "employee": r.employee_hash, "reason": r.reason}
                for r in self.refused
            ],
            "countBefore": self.count_before,
            "countAfter": self.count_after,
            "journal": self.journal_path,
            "incident": self.incident,
        }


def assess_delete_delta(
    *,
    named: Sequence[str],
    count_before: int | None,
    count_after: int | None,
    survivors: Sequence[str] = (),
) -> None:
    """§5b's count-delta wrapper — the guard, in one place, for every card delete.

    Raise on any of these, each of which is D-WIPE's signature rather than a detail:

    * either count unknown (a count we could not read is not a count — §0.7);
    * the drop is LARGER than the named list (the device removed more than it was
      told to — the exact shape that cost bench A its entire roster twice);
    * the count did not drop by exactly the number of names that were actually there
      (a silent partial delete is the same class of lie);
    * a named card is still present afterwards (the device said ok and did nothing,
      which §6 refuses to treat as success).

    The caller turns a raise into a stop-the-run: restore from the pre-run bundle and
    escalate (§5b c).
    """
    named_set = {str(n) for n in named}
    if count_before is None or count_after is None:
        raise DeleteAbortedError(
            f"card delete guard refused: the CardInfo count was not readable on both "
            f"sides of the request (before={count_before!r} after={count_after!r}); "
            "without both counts the delta is unknowable, so the delete is treated as "
            "an incident rather than trusted (§5b, §0.7)"
        )
    survivors = [str(s) for s in survivors if str(s) in named_set]
    dropped = count_before - count_after
    if dropped > len(named_set):
        raise DeleteAbortedError(
            f"§5b INCIDENT: the card count dropped by {dropped} "
            f"({count_before} -> {count_after}) while only {len(named_set)} card(s) "
            "were named. The device removed MORE than it was told to — the D-WIPE "
            "signature. STOP: nothing further may be written; restore from the "
            "pre-run snapshot bundle (§2) and escalate.",
            count_before=count_before,
            count_after=count_after,
            named=tuple(sorted(named_set)),
            survivors=tuple(survivors),
        )
    if survivors:
        raise DeleteAbortedError(
            f"the card delete answered ok but {len(survivors)} named card(s) are still "
            "present on the target — §6: the status code proves nothing; the run stops "
            "here so the operator decides (§0.6)",
            count_before=count_before,
            count_after=count_after,
            named=tuple(sorted(named_set)),
            survivors=tuple(survivors),
        )
    if dropped < len(named_set):
        raise DeleteAbortedError(
            f"the card count dropped by {dropped} while {len(named_set)} card(s) were "
            "named and none survived — an inconsistent delta is the same class of lie "
            "as an over-large one; stop and escalate (§5b)",
            count_before=count_before,
            count_after=count_after,
            named=tuple(sorted(named_set)),
            survivors=tuple(survivors),
        )


@dataclass(frozen=True, slots=True)
class _UndoCandidate:
    entry: JournalEntry
    why_refused: str | None


def _undo_candidates(
    journal: WriteJournal, *, only_cards: Sequence[str] | None
) -> list[_UndoCandidate]:
    """Which journal entries undo may even consider, each with its refusal reason.

    §5a's eligibility, in this order: same phase, the card-op token, an ``add``-class
    classification, and state ``confirmed``. Everything else — ``planned``,
    ``applied``, ``rejected``, a non-add classification — is refused here and named in
    the report, because "unknown state = human" is a decision, not a default.
    """
    wanted = {str(c) for c in only_cards} if only_cards is not None else None
    out: list[_UndoCandidate] = []
    # The FOLDED view, not the raw lines: every state transition is its own append,
    # so a confirmed entry's history (planned, applied, confirmed) would otherwise
    # present its own `planned`/`applied` ghosts as refusals — the fold key is the
    # (person, card) pair, exactly the identity undo is allowed to reason about.
    for entry in journal.latest():
        if entry.op != "card_setup" or entry.phase != CARDS_PHASE:
            continue
        card_no = entry.card_no
        if card_no is None:
            continue
        if wanted is not None and card_no not in wanted:
            continue
        why: str | None = None
        if entry.state is not JournalState.CONFIRMED:
            why = (
                f"state={entry.state} is not confirmed: §5a — planned/applied without "
                "confirmed is an unknown state and only a human may touch it"
            )
        elif entry.classification not in ("add", "DiffClass.ADD"):
            why = (
                f"classification={entry.classification!r} is not an add: undo removes "
                "only what THIS run added (§5a)"
            )
        elif entry.post_write_hash is None:
            why = "no post-write hash on the entry: there is no proof-of-add to match"
        out.append(_UndoCandidate(entry=entry, why_refused=why))
    return out


def undo_card_adds(
    transport: CardWriteTransport,
    journal: WriteJournal,
    *,
    reader: SearchReader,
    undo_journal: WriteJournal | None = None,
    card_nos: Sequence[str] | None = None,
    page_size: int = 30,
    max_pages: int = 500,
    sleep: Callable[[float], None] = _noop_sleep,
) -> UndoReport:
    """Remove ONLY this run's proven card adds, wrapped by §5b's count-delta guard.

    Proof-of-add per §5a, per card: the entry must be ``confirmed`` with a post-write
    hash, and the LIVE re-read of that row must hash to that same value. A row anyone
    else has touched since does not match, so it is refused and escalated — someone
    else's edit wins, always.

    Then ONE delete for the proven set: the body is built from the named cardNos,
    re-checked against what the body actually names (a body that names more than the
    proven set never leaves this function), sent under the count-delta wrapper, and
    journalled ``reverted`` only after the wrapper agreed. ``undo_journal`` gets the
    undo's own lines (§5a); the write journal's entries stay append-only history.
    """
    journal_ledger = undo_journal or journal
    candidates = _undo_candidates(journal, only_cards=card_nos)
    before = read_card_store(reader, page_size=page_size, max_pages=max_pages, sleep=sleep)
    if not before.complete:
        # No before-count means no delta can be computed, so NOTHING may be deleted —
        # the guard is not optional and an unmeasurable delete is the D-WIPE shape.
        return UndoReport(
            refused=tuple(
                UndoItem(
                    card_hash=str(c.entry.card_no),
                    employee_hash=c.entry.employee_hash,
                    reverted=False,
                    reason=f"count-before unreadable: {before.error} (§5b)",
                )
                for c in candidates
            ),
            journal_path=str(journal_ledger.path),
            incident=True,
        )
    proven: list[JournalEntry] = []
    refused: list[UndoItem] = []
    for candidate in candidates:
        entry = candidate.entry
        if candidate.why_refused:
            refused.append(
                UndoItem(
                    card_hash=card_hash(str(entry.card_no)),
                    employee_hash=entry.employee_hash,
                    reverted=False,
                    reason=candidate.why_refused,
                )
            )
            continue
        row = before.row_for(str(entry.card_no))
        if row is None:
            refused.append(
                UndoItem(
                    card_hash=card_hash(str(entry.card_no)),
                    employee_hash=entry.employee_hash,
                    reverted=False,
                    reason=(
                        "the card is not on the target at all — nothing to remove; "
                        "the journal says it landed, the device says otherwise (§6)"
                    ),
                )
            )
            continue
        if str(row.get("employeeNo") or "") != entry.employee_no:
            refused.append(
                UndoItem(
                    card_hash=card_hash(str(entry.card_no)),
                    employee_hash=entry.employee_hash,
                    reverted=False,
                    reason=(
                        "proof-of-add failed: the live row binds this cardNo to a "
                        "DIFFERENT employeeNo — someone else owns it now (§5a)"
                    ),
                )
            )
            continue
        live_hash = content_hash(card_identity_projection(row))
        if live_hash != entry.post_write_hash:
            refused.append(
                UndoItem(
                    card_hash=card_hash(str(entry.card_no)),
                    employee_hash=entry.employee_hash,
                    reverted=False,
                    reason=(
                        f"proof-of-add failed: live projection hash {live_hash} != "
                        f"journal post-write hash {entry.post_write_hash} — the row "
                        "moved since we confirmed it, so someone else's edit wins "
                        "(§5a: refuse and escalate)"
                    ),
                )
            )
            continue
        proven.append(entry)

    if not proven:
        return UndoReport(
            refused=tuple(refused),
            count_before=before.count,
            count_after=before.count,
            journal_path=str(journal_ledger.path),
        )

    named = tuple(str(e.card_no) for e in proven)
    body = build_card_delete_body(named)
    actually_named = card_delete_targets(body)
    if set(actually_named) != set(named):
        # Belt for the guard's own invariant: what the BODY names must be what we were
        # told to remove. A body that names more than the proven set is refused here,
        # before it can reach a transport (§5b).
        raise CardDeleteScopeError(
            f"refusing to send a card delete that names {len(actually_named)} card(s) "
            f"while this undo proved {len(named)}: a body broader than its proof is "
            "the D-WIPE shape (§5b)"
        )
    undo_lines: list[JournalEntry] = []
    for entry in proven:
        # A `confirmed` entry always carries its intended record (planned() requires
        # one); the `or {}` is the type-checker's belt, not a behavioural branch.
        intent = dict(entry.intended_record or {})
        undo_lines.append(
            journal_ledger.planned(
                employee_no=entry.employee_no,
                classification=str(entry.classification),
                pre_write_record=intent,
                intended_record=intent,
                op="card_delete",
                card_no=str(entry.card_no),
            )
        )
    try:
        ack = transport.put_setup(CARD_DELETE_PATH, body)
    except WriteRejectedError as exc:
        raise DeleteAbortedError(
            f"the card delete was refused by the device ({exc.sub_status or exc}); "
            "nothing was journalled as reverted and nothing was retried (§0.6)",
            count_before=before.count,
            count_after=None,
            named=named,
        ) from exc
    _require_ok_ack_delete(ack, named, before.count)

    after = read_card_store(reader, page_size=page_size, max_pages=max_pages, sleep=sleep)
    survivors = tuple(c for c in named if after.row_for(c) is not None)
    if survivors:
        # The device said ok but a card our PROOF named is still on the target: the
        # read-back contradicts the body we built, so what reached the device was NOT
        # the delete we proved (an injected transport widened it in flight — exactly
        # the _BodyRewriter shape the DoD test drives). An unverifiable scope is a
        # body broader than its proof: stop BEFORE any count arithmetic, journal
        # nothing reverted (§5b: an unbounded delete is the D-WIPE class).
        raise CardDeleteScopeError(
            f"the card delete answered ok but {len(survivors)} card(s) this undo "
            "proved to remove are still present on the target — the body that "
            "reached the device cannot be the body we built, so its scope is "
            "unverifiable and is treated as broader than its proof (§5b): STOP; "
            "nothing is journalled reverted."
        )
    assess_delete_delta(
        named=named,
        count_before=before.count,
        count_after=after.count,
        survivors=(),
    )
    # The undo journal transitions ITS OWN planned lines (op=card_delete, the undo
    # journal's phase) — transitioning the write journal's entry INTO the undo file
    # would plant a `cards`/`card_setup` phase record where the audit expects the
    # undo's own vocabulary (§5a: "undo … gets its own journal").
    for undo_entry in undo_lines:
        journal_ledger.reverted(undo_entry)
    return UndoReport(
        reverted=tuple(card_hash(str(e.card_no)) for e in proven),
        refused=tuple(refused),
        count_before=before.count,
        count_after=after.count,
        journal_path=str(journal_ledger.path),
    )


def _require_ok_ack_delete(ack: Mapping[str, Any], named: Sequence[str], count: int | None) -> None:
    code = ack.get("statusCode")
    if code == 1:
        return
    raise DeleteAbortedError(
        f"the card delete answered statusCode={code!r} "
        f"(subStatusCode={ack.get('subStatusCode')!r}) for {len(named)} named card(s) — "
        "a rejected delete is not a reverted delete; stop and report (§5b)",
        count_before=count,
        count_after=None,
        named=tuple(named),
    )


# --- §5 steps 1-2 + 7: the composed cards phase ----------------------------------------------


@dataclass(frozen=True, slots=True)
class CardsApplyReport:
    """Everything a cards run decided and did, in PII-free form (§4/§7's -o json)."""

    phase: str
    writes: CardsPhaseResult
    verify: CardVerifyReport | None
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


def apply_cards_phase(
    *,
    plan: Plan,
    bundle: BundleData,
    transport_factory: Callable[[], Any],
    reader: SearchReader,
    journal_path: Any,
    probe: CapabilityMatrix,
    now: Any,
    recheck: Callable[[], Sequence[Any]] | None = None,
    batch_size: int | None = None,
    sleep: Callable[[float], None] = _noop_sleep,
    batch_delay: float = 1.0,
    confirm: bool = True,
) -> CardsApplyReport:
    """Gate → fresh card roster → journal → writes → verify → journal ``confirmed``.

    §5's order, not a suggestion: fresh probe (§3/§4) → clock-skew gate (§5.1a) →
    freshness re-diff (§4) → a FRESH card read (the ownership gate and the before-count
    both come from what the device says NOW, never from a cached plan) → writes (§5.3)
    → verify (§6) → journal ``confirmed``. A verify mismatch is TERMINAL (§0.6): the
    report is the artifact, the journal stops at ``applied``, and nothing here re-writes
    a mismatch away — removal is :func:`undo_card_adds`, and only for cards this run
    proved it added.
    """
    require_fresh(probe, now)  # ProbeStaleError is E1-03's contract, unchanged
    check_clock_skew(probe, max_skew_s=MAX_CLOCK_SKEW_S)

    roster = read_card_store(reader, sleep=sleep)
    if not roster.complete:
        raise ApplyAbortedError(
            f"cards phase refused before any write: the CardInfo/Search roster could "
            f"not be read completely ({roster.error}); the ownership gate and the "
            "before-count both need it, and a partial roster is how a card gets "
            "assigned to the wrong person (§0.7, §4)"
        )
    # The journal opens only AFTER every gate passed: an apply that refused must not
    # leave a PII file behind at all (E1-04's ordering, made explicit for the roster
    # gate too — the test pins the absence, not merely the refusal).
    journal = WriteJournal.open(journal_path, phase=CARDS_PHASE)
    writes, skipped = plan_card_writes(plan, bundle, target_cards=roster.rows, probe=probe)
    notes: list[str] = []
    if skipped:
        notes.append(
            f"{len(skipped)} card(s) report-only in this phase: "
            + ", ".join(f"{h}={r}" for h, r in skipped[:8])
        )

    if recheck is not None and writes:
        changed = plan_still_valid(plan, recheck())
        if changed:
            raise WriteAbortedError(
                f"freshness contract failed before any card write: {len(changed)} "
                f"person(s) changed classification since plan time "
                f"({', '.join(changed[:8])}{'…' if len(changed) > 8 else ''}) — "
                "re-diff and re-run (§4)",
                CardsPhaseResult(
                    planned=tuple(w.card_hash for w in writes),
                    batch_size=_effective_batch_size(batch_size),
                ),
            )

    budgeted = BudgetedWriteTransport(transport_factory)
    try:
        result = run_cards_phase(
            budgeted,
            journal,
            writes,
            target_cards=roster.rows,
            probe=probe,
            batch_size=batch_size,
            sleep=sleep,
            batch_delay=batch_delay,
        )
    finally:
        budgeted.close()

    verify: CardVerifyReport | None = None
    if confirm and writes:
        # §5.3's per-person worst case counts the verify read against the SAME ledger
        # the writes used: the roster re-read is one authed call on the same digest
        # session, and an unbudgeted read is the thing the 80-call cap exists to bound.
        budgeted.charge_authed_calls(1)
        verify = verify_cards(reader, writes, sleep=sleep)
        confirmed: list[str] = []
        for item in verify.items:
            entry = _entry_for_pair(journal, item.card_no, item.employee_no)
            if entry is None:
                notes.append(
                    f"{item.card_hash}: verify found a pair with no journal entry — "
                    "impossible by construction, so it is reported, not journalled (§6)"
                )
                continue
            if item.verdict is CardVerdict.OK and item.target_hash == entry.intended_hash:
                journal.confirmed(entry, post_write_hash=str(item.target_hash))
                confirmed.append(item.card_hash)
            elif item.verdict is CardVerdict.MISMATCH:
                notes.append(
                    f"TERMINAL mismatch for card {item.card_hash} "
                    f"(person {item.employee_hash}): "
                    + (
                        f"row fields outside the captured read vocabulary "
                        f"{list(item.unknown_fields)}"
                        if item.unknown_fields
                        else f"hash {item.target_hash} != intended {item.expected_hash}"
                    )
                    + " — verify is terminal (§0.6): no re-write; removal is undo "
                    "only, and only for proven adds (§5a)"
                )
            else:
                notes.append(
                    f"{item.card_hash}: accepted by the device but {item.verdict} on "
                    "read-back — unknown state, human decides (§5a)"
                )
        result = replace(result, confirmed=tuple(confirmed))
    return CardsApplyReport(
        phase=CARDS_PHASE,
        writes=result,
        verify=verify,
        journal_path=str(journal.path),
        notes=tuple(notes),
    )


def _entry_for_pair(journal: WriteJournal, card_no: str, employee_no: str) -> JournalEntry | None:
    """The journal entry for one (cardNo, employeeNo) pair — newest line wins.

    ``WriteJournal.by_employee`` is person-keyed, which is correct for a user row and
    wrong for cards: a person may hold several, and the PAIR is the identity (§5 step
    5). This is the fold the card phase needs, built from the journal's own entries.
    """
    found: JournalEntry | None = None
    for entry in journal.entries:
        if entry.card_no == card_no and entry.employee_no == employee_no:
            found = entry
    return found
