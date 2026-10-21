"""The read-only enrollment export (card E1-01): device -> bundle, fail closed.

Design docs/ENROLLMENT-MIGRATION.md §0.7/§2/§9. This is the snapshot every E1 write
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
  `card_info_search` are the two engines; this module adds only the per-page
  fail-closed verdict the enrollment use case demands (the events walk warns, E1
  aborts) and the identity read.
* `gateclerk.migrate_bundle` owns normalization + hashing + the file layout.

The client seam is `IsapiClient`-shaped (`get(name)` / `search(name, body)`), asserted
against `SEARCH_ENDPOINTS` before any call — the same registry guard the pipeline
walker uses. Nothing here can reach a write path: the only POSTs possible are the
stateless searches the registry allows, and this card is read-only by design.
"""

from __future__ import annotations

import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Protocol

from gateclerk.capabilities import device_identity
from gateclerk.endpoints import SEARCH_ENDPOINTS
from gateclerk.exceptions import EnrollmentReadAborted, IsapiError, GateclerkError
from gateclerk.migrate_bundle import FacesIndex, content_hash, write_bundle
from gateclerk.paging import (
    DEFAULT_INTER_PAGE_DELAY,
    DEFAULT_MAX_PAGES,
    PagedSearch,
    PagingLimits,
    SearchSummary,
    card_info_search,
    user_info_search,
)

__all__ = [
    "ACCEPTED_STATUSES",
    "ClientLike",
    "EnrollmentState",
    "ExportResult",
    "collect_enrollment_state",
    "export_bundle",
]

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
    """What an export produced — counts and hashes for reports, never names (design §4)."""

    bundle_dir: Path
    counts: dict[str, int]
    people_hashes: dict[str, str]
    faces: FacesIndex
    termination: dict[str, str]


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


def _walk(engine: PagedSearch, endpoint: str, label: str) -> tuple[list[dict[str, Any]], str]:
    """Drain one paged search, checking EVERY page's device verdict.

    The paging engine terminates on non-MORE; it does not judge statuses, because an
    events walk treats an odd terminal status as a summary detail. An enrollment
    snapshot cannot: an unknown verdict mid-walk is exactly the moment a truncated
    pull would masquerade as a complete one, so each page must answer OK / MORE /
    NO MATCH or the export dies naming the page.
    """
    records: list[dict[str, Any]] = []
    try:
        for page in engine.pages({}):
            if page.status not in ACCEPTED_STATUSES:
                raise _abort(
                    endpoint,
                    f"page {page.index} answered responseStatusStrg="
                    f"{page.status!r} (accepted: {sorted(ACCEPTED_STATUSES)})",
                )
            records.extend(dict(record) for record in page.records)
    except EnrollmentReadAborted:
        raise
    except GateclerkError as exc:
        # Every typed device/paging failure (IsapiError, SearchProtocolError,
        # SearchRunawayError, IsapiPayloadError…) funnels into one export-abort type
        # with the original as `cause`: callers (E1-07 CLI) map one exception to
        # "exit 4, no bundle", and the specific reason stays inspectable. Catching
        # the whole GateclerkError family is deliberate — the fail-closed rule is "ANY
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
