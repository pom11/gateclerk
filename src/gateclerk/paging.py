"""The paged-search engine for the two stateless search POSTs (card p1-05).

One walk, one device cursor
--------------------------
A Hikvision search is *stateful on the device*: `searchID` names a cached cursor,
and the walk is driven by three fields per request — `searchID`,
`searchResultPosition`, `maxResults`. Every rule below is a device fact recorded in
docs/OBSERVED.md (site-a DS-K1T341AMF-S, fw V3.2.30) or docs/DESIGN.md "Paging +
checkpoint"; the wording here traces to them, not to Hikvision documentation
generally. Each rule has a test against `FakeDevice` in tests/test_paging.py.

* **`searchID` is generated once per logical search** (uuid4, clamped to the
  advertised length) and then **byte-identical on every page** — the device caches
  the cursor under it. Changing it mid-walk restarts at page 1 **silently**: no
  error, plausible records, an endless loop (references/acs-event-codes.md §1.2,
  re-confirmed on the device probe). A new logical search (a new query window) gets
  a new id.
* **`searchResultPosition` is 0-based** (OBSERVED.md) and the cursor advances by the
  **returned `numOfMatches`** — never by the requested `maxResults`, never by
  `totalMatches`. Oversized `maxResults` is *silently clamped* by the firmware
  (vendor text, confirmed in the research pass), so advancing by the requested page
  size skips records with no error at all: on a payroll pipeline that is missing
  punches, not a cosmetic bug. `totalMatches` is advisory display, never a bound.
* **Termination is `responseStatusStrg` != MORE, or an empty `InfoList`.** The
  observed values are exactly `OK`, `MORE`, `NO MATCH` — the last one **with a
  space**, so raw comparisons against `"NO_MATCHES"` never match; every
  comparison here goes through `normalize_status()` first. The empty-window
  response carries **no `InfoList` key at all** (not `[]`) — that is an empty
  result, not a protocol error, and it is never an exception (OBSERVED.md).
* **A hard page cap raises instead of spinning** (card: 10k pages). The cap is the
  safety net for the silent-restart class above and for any fw that answers MORE
  forever: a walk that reaches it aborts loudly (`SearchRunawayError`, p1-08 exit
  5). A truncated pull that *looks* complete is worse than a failed one.

AcsEvent is never queried unbounded
-----------------------------------
The card requires `startTime`/`endTime` on every event search: some firmware
answers an unbounded query with `Invalid Content`, and an unbounded walk over the
full ~10k history is the slow page-heavy path DESIGN.md rules out. So the event
side of this module *refuses* to build an unbounded body — `build_event_cond()`
takes a `gateclerk.tz.DeviceWindow` and `iter_event_windows()` chunks the range
(default `1d`) and pages inside each chunk. The window strings come from
`gateclerk.tz.window_for_device` — the site-tz wall clock — and on the wire they
**always carry an offset** (the naive pair 400s, OBSERVED.md "Event-window
startTime form: offset REQUIRED", live proof 2026-10-17). The p1-05c A/B
(OBSERVED.md "Window offsets are ARITHMETIC for the device") settled *which*
offset: the **device's claimed one** (`device_offset_min=...` relabels the
site-wall digits), because the device converts each label to an instant and back
onto its own clock — a site-labeled window arrives shifted by the label delta and
silently loses boundary events. The site-labeled pair (`with_offset=True`) remains
the fallback when the device's claim is unreadable; the naive pair
(`with_offset=False`) stays available on the struct, but nothing on the event wire
may use it.

`beginSerialNo`/`endSerialNo` are exposed for checkpointed pulls and `timeReverseOrder`
for newest-first reads; oldest-first (`timeReverseOrder=False`) is the backfill
default. Neither is ever a paging key (references §1.4: serial is not safe as a
cursor — the cursor is position, the checkpoint is `max(serialNo)` computed by the
caller over completed chunks only).

`maxResults` is clamped to the advertised cap (30 on site-a) via `PagingLimits` —
the numbers come from p1-04's capability discovery as a value object; this module
never fetches capabilities itself. Inter-page delay defaults to 100 ms (small box,
serial sessions), injected `sleep`/`clock` so tests never wait.

What is deliberately NOT here
-----------------------------
* Capability discovery / `maxResults` probing — p1-04 (`PagingLimits` is the seam).
* The `AcsEventTotalNum` cross-check — a third POST is a reviewed registry decision, so it
  was added with the CLI flag that consumes it (p1-08's `--count`), not folded into the
  engine that never calls it. The engine exposes
  `SearchSummary` (pages, records, positions) so p1-08 can warn on mismatch
  against `UserInfo/Count` / `AcsEventTotalNum` without the engine owning either.
* Normalization/classification of records (p1-07) and CLI surface (p1-08).
"""

from __future__ import annotations

import re
import time
import uuid
from collections.abc import Callable, Iterator, Mapping
from dataclasses import dataclass
from datetime import datetime, timedelta, tzinfo
from typing import Any

from gateclerk.exceptions import (
    EventBoundsError,
    SearchProtocolError,
    SearchRunawayError,
)
from gateclerk.tz import (
    DEFAULT_SITE_TZ,
    DeviceWindow,
    TimestampInputError,
    UserTimestamp,
    window_for_device,
)

__all__ = [
    "DEFAULT_CHUNK",
    "DEFAULT_INTER_PAGE_DELAY",
    "DEFAULT_MAX_PAGES",
    "DEFAULT_MAX_RESULTS",
    "DEFAULT_SEARCH_ID_LEN",
    "MAX_SEARCH_ID_LEN",
    "MIN_SEARCH_ID_LEN",
    "STATUS_MORE",
    "ChunkResult",
    "CountGetter",
    "PageReader",
    "PageRecord",
    "PagedSearch",
    "PagingLimits",
    "RosterResult",
    "SearchSummary",
    "acs_event_search",
    "build_event_cond",
    "chunk_window",
    "clamp_page_size",
    "collect_users",
    "envelope_records",
    "is_more",
    "iter_event_windows",
    "iter_users",
    "new_search_id",
    "normalize_status",
    "parse_chunk",
    "response_envelope",
    "user_info_search",
]

#: OBSERVED.md: site-a advertises `maxResults @max = 30`; "we request 30 and never
#: more" (DESIGN.md). A box that advertises less (some DS-K1T* say 10) clamps lower
#: via PagingLimits — never hardcode a bigger number.
DEFAULT_MAX_RESULTS = 30

#: Highest `maxResults` we will honour from a capability. The research pass saw
#: 10 (DS-K1T804AMF), 30 (site-a) and 150 (Hikvision-API-Reference author) —
#: 150 is the highest credible value; beyond it the capability is not one we know
#: how to page safely (see PagingLimits).
MAX_KNOWN_MAX_RESULTS = 150

#: Below this a uuid4 prefix stops being collision-safe (48 bits ≈ 16M searches
#: on one device before birthday collisions — nobody polls a door terminal that
#: often); a capability @max that small is a firmware we have never seen. Fail
#: loudly rather than hand out ids that can alias another walk's cursor.
MIN_SEARCH_ID_LEN = 12

#: The hard ceiling: site-a advertises `searchID @max = 64` (OBSERVED.md), so a
#: uuid4-hex (32 chars) always fits; nothing longer is ever generated.
MAX_SEARCH_ID_LEN = 64

#: Cross-model safe default until p1-04 hands us the device's own @max: references
#: §1.2 "Safe rule: ASCII <= 20" — site-a's AcsEvent accepts 64 (OBSERVED.md), but
#: a sibling model rejected a 36-char id with `Invalid Content`, and
#: UserInfo/Search has never been probed. 20 travels everywhere we have evidence.
DEFAULT_SEARCH_ID_LEN = 20

#: DESIGN.md "Throttling": inter-page delay 100 ms default — single connection,
#: serial requests, these boxes dislike being hammered.
DEFAULT_INTER_PAGE_DELAY = 0.100

#: Card: "a hard safety cap (10k pages) that raises instead of looping forever".
#: At the 30-page cap that is 300k records per logical search — beyond any real
#: window; reaching it means the device is misbehaving, not that the data is big.
DEFAULT_MAX_PAGES = 10_000

#: Card/DESIGN.md: chunk windows to --chunk (default 1d). The full 7-month window
#: works on this fw, but chunking bounds what a mid-search failure costs.
DEFAULT_CHUNK = "1d"

#: The only continuation value. Everything else — OK, NO MATCH, and anything we
#: have never seen — terminates the walk. The observed spellings are "OK", "MORE",
#: "NO MATCH" (OBSERVED.md: the space is real); comparisons normalize first.
STATUS_MORE = "MORE"

#: PageReader: POST a complete search body, get the parsed dict back. In
# production this is `IsapiClient.search`; tests hand it a scripted callable
# (and FakeDevice sits behind the real client in the end-to-end tests).
PageReader = Callable[[Mapping[str, Any]], dict[str, Any]]


# --- status normalisation ------------------------------------------------------------


def normalize_status(raw: object) -> str:
    """`"NO MATCH"` -> `"NOMATCH"`, `" ok "` -> `"OK"`; comparison-safe on purpose.

    OBSERVED.md: the empty-window value on this firmware is `NO MATCH` **with a
    space**, so `raw == "NO_MATCHES"` (the value DESIGN.md's original card text
    listed) never matches and the walk would treat an empty window as a
    continuation. Every status read goes through here.
    """
    if raw is None:
        return ""
    return str(raw).strip().upper().replace(" ", "").replace("_", "")


def is_more(status: str) -> bool:
    """True only for the normalized MORE token — the single continuation value."""
    return status == STATUS_MORE


# --- limits --------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class PagingLimits:
    """Device-advertised paging limits (p1-04 reads them from capabilities; tests
    construct them directly).

    Both fields clamp *down* to the highest value we know travels safely (30-page
    and 64-char values are what site-a advertises; the research pass saw 10/30/150
    and 20/32/64 elsewhere). Clamping the page size is safe by construction: the
    cursor advances by the returned `numOfMatches`, never by what we asked for, so
    a device that serves fewer than asked can never make us skip. A searchID cap
    *below* the collision-safe floor is the opposite case — too short an id could
    alias another walk's cached cursor and silently restart page 1 — so that one
    raises instead of quietly proceeding.
    """

    max_results: int = DEFAULT_MAX_RESULTS
    search_id_max_len: int = DEFAULT_SEARCH_ID_LEN

    def __post_init__(self) -> None:
        if self.max_results < 1:
            raise ValueError(f"maxResults must be >= 1, got {self.max_results}")
        object.__setattr__(self, "max_results", min(self.max_results, MAX_KNOWN_MAX_RESULTS))
        if self.search_id_max_len < MIN_SEARCH_ID_LEN:
            raise ValueError(
                f"searchID capability @max {self.search_id_max_len} is below "
                f"{MIN_SEARCH_ID_LEN} — a uuid4 prefix that short is not collision-safe"
            )
        # Clamp *down* to the known ceiling: an over-long searchID is `Invalid
        # Content` on sibling models (references §1.2), so the shorter value always
        # travels, whatever the device advertises.
        object.__setattr__(
            self, "search_id_max_len", min(self.search_id_max_len, MAX_SEARCH_ID_LEN)
        )


def clamp_page_size(limits: PagingLimits, requested: int | None = None) -> int:
    """The page size we may actually ask for.

    The firmware *silently* clamps an oversized request (no error) — so we clamp
    first, and the returned `numOfMatches` stays the only cursor input anyway. A
    requested size below the cap is honoured (a caller debugging with pages of 5).
    """
    wanted = DEFAULT_MAX_RESULTS if requested is None else requested
    if wanted < 1:
        raise ValueError(f"maxResults must be >= 1, got {wanted}")
    return min(wanted, limits.max_results)


def new_search_id(max_len: int = DEFAULT_SEARCH_ID_LEN) -> str:
    """A fresh uuid4 (hex, no dashes) clamped to the advertised length.

    One per *logical search*, then frozen for every page of it (module docstring,
    first bullet). `hex` keeps it ASCII and dash-free; 32 chars fits any known
    capability, and models with @max 20 get their first 20.
    """
    if max_len < MIN_SEARCH_ID_LEN:
        raise ValueError(
            f"searchID length {max_len} below {MIN_SEARCH_ID_LEN}; refusing an id that "
            "could alias another search's cached cursor"
        )
    return uuid.uuid4().hex[: min(max_len, 32)]


# --- response reading -----------------------------------------------------------------


def _coerce_count(value: object, *, field: str, search_id: str) -> int | None:
    """int/numeric-string -> int; absent -> None; anything else -> loud error.

    `totalMatches`/`numOfMatches` have been reported arriving as strings on other
    firmware families (OBSERVED.md "int-vs-string/nested shape drift"). A
    non-numeric count is not something we guess at: silently treating it as 0 makes
    a populated walk look empty.
    """
    if value is None:
        return None
    if isinstance(value, bool):
        raise SearchProtocolError(
            f"search response {field}={value!r} is a bool, not a count (searchID={search_id})"
        )
    if isinstance(value, int):
        return value
    if isinstance(value, str) and value.strip().lstrip("-").isdigit():
        return int(value.strip())
    raise SearchProtocolError(
        f"search response {field}={value!r} is not numeric (searchID={search_id})"
    )


def response_envelope(
    body: Mapping[str, Any], envelope_key: str, *, search_id: str
) -> Mapping[str, Any]:
    """The envelope under the root key (`AcsEvent` / `UserInfoSearch`), or a loud error.

    A body without the root key is NOT treated as "empty result": the observed
    empty-window shape keeps the root key and merely omits `InfoList`
    (OBSERVED.md). A rootless body means the device changed protocol on us —
    reading that as zero records is how "nobody clocked in" gets fabricated.
    """
    envelope = body.get(envelope_key)
    if not isinstance(envelope, Mapping):
        raise SearchProtocolError(
            f"search response has no {envelope_key!r} object (keys={sorted(body)!r}, "
            f"searchID={search_id}) — refusing to read a protocol break as zero records"
        )
    return envelope


def envelope_records(envelope: Mapping[str, Any], record_key: str) -> list[Mapping[str, Any]]:
    """Records under `record_key` (`InfoList` / `UserInfo`).

    Absent key -> `[]`: the empty-window response omits it entirely (OBSERVED.md),
    which is a legitimate "no records", not an error. A present-but-non-list value
    is a protocol break and raises.
    """
    records = envelope.get(record_key)
    if records is None:
        return []
    if not isinstance(records, list):
        raise SearchProtocolError(
            f"search response {record_key} is {type(records).__name__}, not a list"
        )
    return [r for r in records if isinstance(r, Mapping)]


# --- the walk -------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class PageRecord:
    """One page as the device actually answered it — the audit trail of a walk."""

    index: int
    search_id: str
    position: int
    requested_max: int
    num_of_matches: int
    records: tuple[Mapping[str, Any], ...]
    status: str  # normalized
    total_matches: int | None  # advisory display only, never a loop bound


@dataclass(frozen=True, slots=True)
class SearchSummary:
    """What a completed walk consumed. Advisory cross-check input for p1-08."""

    endpoint: str
    search_id: str
    pages: int
    records: int
    final_position: int
    termination: str  # normalized terminal status (OK / NOMATCH / ...)


class PagedSearch:
    """Drives one cursor against one search endpoint.

    `reader` POSTs a complete body and returns the parsed dict (`IsapiClient.search`
    in production, a scripted callable in unit tests — the end-to-end tests wire the
    real client over `FakeDevice`). The engine owns `searchID`/`searchResultPosition`
    /`maxResults`; callers supply only the query conditions.
    """

    def __init__(
        self,
        reader: PageReader,
        *,
        endpoint: str,
        cond_key: str,
        envelope_key: str,
        record_key: str,
        limits: PagingLimits | None = None,
        page_size: int | None = None,
        max_pages: int = DEFAULT_MAX_PAGES,
        inter_page_delay: float = DEFAULT_INTER_PAGE_DELAY,
        sleep: Callable[[float], None] = time.sleep,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        if max_pages < 1:
            raise ValueError(f"max_pages must be >= 1, got {max_pages}")
        if inter_page_delay < 0:
            raise ValueError(f"inter_page_delay must be >= 0, got {inter_page_delay}")
        self._reader = reader
        self.endpoint = endpoint
        self._cond_key = cond_key
        self._envelope_key = envelope_key
        self._record_key = record_key
        self.limits = limits or PagingLimits()
        self._page_size = clamp_page_size(self.limits, page_size)
        self._max_pages = max_pages
        self._delay = inter_page_delay
        self._sleep = sleep
        self._clock = clock
        #: monotonic timestamp of the last request START; drives inter_page_delay
        self._last_request_at = 0.0
        #: True once ANY request has been issued on this engine — the delay is
        #: between REQUESTS, so it also spaces the first page of a new chunk after
        #: the last page of the previous one (iter_event_windows reuses the engine).
        self._ever_issued = False
        #: stats of the most recent pages()/collect() — p1-08 reads the summary
        self.summary: SearchSummary | None = None

    # -- public ----------------------------------------------------------------------

    def pages(
        self, cond: Mapping[str, Any], *, search_id: str | None = None
    ) -> Iterator[PageRecord]:
        """Walk every page of one logical search; yields pages in device order.

        `cond` is the caller's query conditions (`major`, `startTime`, ...). The
        engine adds the three cursor fields and refuses — before any request — to
        overwrite one a caller tried to pass by hand: the cursor is ours.
        """
        overlap = {"searchID", "searchResultPosition", "maxResults"} & set(cond)
        if overlap:
            raise SearchProtocolError(
                f"caller passed cursor field(s) {sorted(overlap)} in cond — the engine "
                "owns searchID/searchResultPosition/maxResults (mid-walk changes make "
                "the device silently restart or skip: references §1.2/§1.3)"
            )
        sid = search_id if search_id is not None else new_search_id(self.limits.search_id_max_len)
        position = 0
        pages_read = 0
        records_total = 0
        status = ""
        while True:
            if pages_read >= self._max_pages:
                raise SearchRunawayError(
                    f"paged search on {self.endpoint} hit the safety cap of "
                    f"{self._max_pages} pages while the device still said MORE "
                    f"(position={position}, searchID={sid}); aborting instead of "
                    "looping forever — the device is misbehaving (a searchID change "
                    "mid-walk restarts page 1 SILENTLY, references §1.2)",
                    endpoint=self.endpoint,
                    search_id=sid,
                    pages=pages_read,
                    position=position,
                )
            if self._ever_issued:
                # Between REQUESTS, not between walks: this also spaces the first
                # page of a new chunk after the last page of the previous chunk.
                self._pace()
            body: dict[str, Any] = {
                self._cond_key: {
                    "searchID": sid,
                    "searchResultPosition": position,
                    "maxResults": self._page_size,
                    **cond,
                }
            }
            self._last_request_at = self._clock()
            self._ever_issued = True
            response = self._reader(body)
            envelope = response_envelope(response, self._envelope_key, search_id=sid)
            records = envelope_records(envelope, self._record_key)
            status = normalize_status(envelope.get("responseStatusStrg"))
            num = _coerce_count(envelope.get("numOfMatches"), field="numOfMatches", search_id=sid)
            total = _coerce_count(envelope.get("totalMatches"), field="totalMatches", search_id=sid)
            returned = len(records)
            reported = num if num is not None else returned
            yield PageRecord(
                index=pages_read,
                search_id=sid,
                position=position,
                requested_max=self._page_size,
                num_of_matches=reported,
                records=tuple(records),
                status=status,
                total_matches=total,
            )
            pages_read += 1
            records_total += returned
            # Termination (module docstring, third bullet): MORE is the only
            # continuation value, and an empty record list ends the walk too —
            # the empty-window response has NO InfoList key at all (OBSERVED.md).
            if not is_more(status) or returned == 0:
                break
            # Advance by what the device SAYS it matched — but never past what it
            # actually handed back. When the two disagree (a firmware contradiction
            # we refuse to bet payroll on), the smaller step can only re-read
            # records — UPSERT on (device_serial, serial_no) makes duplicates free
            # (DESIGN.md idempotency), while advancing by a too-large numOfMatches
            # would skip punches SILENTLY. When they agree (every observed page),
            # this is exactly "advance by numOfMatches".
            position += min(reported, returned)
        self.summary = SearchSummary(
            endpoint=self.endpoint,
            search_id=sid,
            pages=pages_read,
            records=records_total,
            final_position=position,
            termination=status,
        )

    def collect(
        self, cond: Mapping[str, Any], *, search_id: str | None = None
    ) -> list[dict[str, Any]]:
        """Every record of one logical search, in page order (NO_MATCH -> [])."""
        out: list[dict[str, Any]] = []
        for page in self.pages(cond, search_id=search_id):
            out.extend(dict(r) for r in page.records)
        return out

    # -- internals ---------------------------------------------------------------------

    def _pace(self) -> None:
        """Space request STARTS by `inter_page_delay`, net of request time.

        The delay is a floor on how often the box gets hit: a page that took 90 ms
        costs 10 ms of wait, not 110. `sleep`/`clock` are injectable so tests
        assert the pacing without waiting (card: small box, serial sessions)."""
        since = self._clock() - self._last_request_at
        wait = self._delay - since
        if wait > 0:
            self._sleep(wait)


# --- AcsEvent side ---------------------------------------------------------------------


def build_event_cond(
    window: DeviceWindow,
    *,
    with_offset: bool = True,
    device_offset_min: int | None = None,
    major: int = 0,
    minor: int = 0,
    employee_no: str | None = None,
    begin_serial_no: int | None = None,
    end_serial_no: int | None = None,
    time_reverse_order: bool | None = None,
    extra: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """The `AcsEventCond` conditions for one bounded time window.

    `startTime`/`endTime` are ALWAYS present (card: some fw answers an unbounded
    query with `Invalid Content`; DESIGN.md rules out full-history walks) — the
    values come from `gateclerk.tz.window_for_device`, i.e. the site-tz wall clock.
    **The pair must carry an offset**: the live run of 2026-10-17 (OBSERVED.md
    "Event-window startTime form: offset REQUIRED") shows this firmware 400s a
    naive `startTime` — `statusCode=6`, `subStatusCode=badJsonContent`,
    `errorMsg=startTime`.

    *Which* offset is the p1-05c rule (OBSERVED.md "Window offsets are ARITHMETIC
    for the device", A/B same day): pass the device's claimed offset as
    `device_offset_min` (e.g. `120` for site-a's year-round `+02:00`) and the wire
    pair becomes the site-wall digits relabeled with it — the shape the device's
    label arithmetic turns into the window we actually asked for. With `None` we
    keep the p1-05b site-labeled pair (`with_offset=True`): the honest fallback for
    a device whose claim we could not read, which the caller must WARN about rather
    than silently accept (pipeline.py surfaces the line). The naive pair
    (`with_offset=False`, only consulted when no claim is given) stays on the struct
    for callers that need the raw wall strings; using it in an event search body is
    the bug this default exists to prevent.

    `employee_no` maps to `employeeNoString`, never `employeeNo` (OBSERVED.md
    "Server-side filter truth": the suffixless form is SILENTLY IGNORED on this fw
    — the worst bug class: looks like data, isn't filtered). Callers still
    re-filter client-side; a filter we probed is a performance hint, not a promise.
    """
    if window.since_device_local in (None, "") or window.until_device_local in (None, ""):
        # Defensive: DeviceWindow always carries both today; a future caller
        # handing us a half-window must not produce an unbounded query.
        raise EventBoundsError("event search needs a complete startTime/endTime window")
    start, end = window.search_pair(with_offset=with_offset, device_offset_min=device_offset_min)
    cond: dict[str, Any] = {
        "startTime": start,
        "endTime": end,
        "major": major,
        "minor": minor,
    }
    if employee_no is not None:
        cond["employeeNoString"] = employee_no
    if begin_serial_no is not None:
        cond["beginSerialNo"] = begin_serial_no
    if end_serial_no is not None:
        cond["endSerialNo"] = end_serial_no
    if time_reverse_order is not None:
        cond["timeReverseOrder"] = bool(time_reverse_order)
    if extra:
        cond.update(extra)
    # DESIGN.md: never send picEnable — snapshots bloat pages and nobody asked.
    if "picEnable" in cond:
        raise SearchProtocolError("picEnable must never be sent (DESIGN.md paging rules)")
    forbidden = {"searchID", "searchResultPosition", "maxResults"} & set(cond)
    if forbidden:
        raise SearchProtocolError(
            f"event conditions must not carry cursor fields {sorted(forbidden)}; "
            "the engine owns them (PagedSearch)"
        )
    return cond


@dataclass(frozen=True, slots=True)
class ChunkResult:
    """One completed time chunk: its records and the walk facts for that chunk."""

    start: datetime
    end: datetime
    window: DeviceWindow
    search_id: str
    pages: int
    records: tuple[Mapping[str, Any], ...]
    termination: str
    #: max serialNo seen in THIS completed chunk — the checkpoint material.
    #: Callers persist max() over COMPLETED chunks only: a chunk that raised
    #: SearchRunawayError never yields, so a failed chunk can never advance the
    #: checkpoint and silently skip its events on the next run.
    max_serial_no: int | None


def parse_chunk(spec: str | timedelta) -> timedelta:
    """`"1d"`/`"12h"`/`"30m"`/`"45s"` (or a timedelta) -> chunk width. Must be > 0."""
    if isinstance(spec, timedelta):
        if spec <= timedelta(0):
            raise TimestampInputError(f"chunk must be positive, got {spec}")
        return spec
    match = re.fullmatch(r"(\d+)([smhd])", spec.strip().lower())
    if not match:
        raise TimestampInputError(
            f"cannot read chunk {spec!r}; use Ns/Nm/Nh/Nd (e.g. '1d', '12h') or a timedelta"
        )
    amount = int(match.group(1))
    unit = {"s": 1, "m": 60, "h": 3600, "d": 86400}[match.group(2)]
    step = timedelta(seconds=amount * unit)
    if step <= timedelta(0):
        raise TimestampInputError(f"chunk must be positive, got {spec!r}")
    return step


def chunk_window(
    start: UserTimestamp | datetime,
    end: UserTimestamp | datetime,
    *,
    chunk: str | timedelta = DEFAULT_CHUNK,
    site_tz: str | tzinfo | None = DEFAULT_SITE_TZ,
) -> Iterator[tuple[datetime, datetime]]:
    """Split [start, end) into <=chunk-wide tz-aware slices, chronologically.

    Adjacent chunks touch at the edge, and the device's startTime/endTime bounds
    are inclusive on both ends, so an event landing exactly on an edge can arrive
    twice. That is deliberate: `UPSERT` on (device_serial, serial_no) makes the
    re-read free (DESIGN.md), while a half-open guess at the boundary would cost a
    punch. An empty range (start == end) yields no chunks; start > end raises.
    """
    step = parse_chunk(chunk)
    start_dt = _instant(start)
    end_dt = _instant(end)
    if end_dt < start_dt:
        raise TimestampInputError(
            f"--until ({end_dt.isoformat()}) is before --since ({start_dt.isoformat()})"
        )
    cursor = start_dt
    while cursor < end_dt:
        nxt = min(cursor + step, end_dt)
        yield cursor, nxt
        cursor = nxt


def _instant(value: UserTimestamp | datetime) -> datetime:
    if isinstance(value, UserTimestamp):
        return value.value
    if value.tzinfo is None:
        raise TimestampInputError(
            "chunking needs tz-aware bounds (pass parsed --since/--until or "
            "UserTimestamp values; naive instants could be device wall or site wall)"
        )
    return value


def acs_event_search(
    reader: PageReader,
    *,
    limits: PagingLimits | None = None,
    page_size: int | None = None,
    max_pages: int = DEFAULT_MAX_PAGES,
    inter_page_delay: float = DEFAULT_INTER_PAGE_DELAY,
    sleep: Callable[[float], None] = time.sleep,
    clock: Callable[[], float] = time.monotonic,
) -> PagedSearch:
    """A cursor bound to `POST /ISAPI/AccessControl/AcsEvent?format=json`."""
    return PagedSearch(
        reader,
        endpoint="acs_event_search",
        cond_key="AcsEventCond",
        envelope_key="AcsEvent",
        record_key="InfoList",
        limits=limits,
        page_size=page_size,
        max_pages=max_pages,
        inter_page_delay=inter_page_delay,
        sleep=sleep,
        clock=clock,
    )


def user_info_search(
    reader: PageReader,
    *,
    limits: PagingLimits | None = None,
    page_size: int | None = None,
    max_pages: int = DEFAULT_MAX_PAGES,
    inter_page_delay: float = DEFAULT_INTER_PAGE_DELAY,
    sleep: Callable[[float], None] = time.sleep,
    clock: Callable[[], float] = time.monotonic,
) -> PagedSearch:
    """A cursor bound to `POST /ISAPI/AccessControl/UserInfo/Search?format=json`."""
    return PagedSearch(
        reader,
        endpoint="user_info_search",
        cond_key="UserInfoSearchCond",
        envelope_key="UserInfoSearch",
        record_key="UserInfo",
        limits=limits,
        page_size=page_size,
        max_pages=max_pages,
        inter_page_delay=inter_page_delay,
        sleep=sleep,
        clock=clock,
    )


def iter_event_windows(
    reader: PageReader,
    *,
    since: UserTimestamp | datetime,
    until: UserTimestamp | datetime,
    chunk: str | timedelta = DEFAULT_CHUNK,
    site_tz: str | tzinfo | None = DEFAULT_SITE_TZ,
    with_offset: bool = True,
    device_offset_min: int | None = None,
    limits: PagingLimits | None = None,
    page_size: int | None = None,
    max_pages: int = DEFAULT_MAX_PAGES,
    inter_page_delay: float = DEFAULT_INTER_PAGE_DELAY,
    sleep: Callable[[float], None] = time.sleep,
    clock: Callable[[], float] = time.monotonic,
    major: int = 0,
    minor: int = 0,
    employee_no: str | None = None,
    begin_serial_no: int | None = None,
    end_serial_no: int | None = None,
    time_reverse_order: bool | None = None,
) -> Iterator[ChunkResult]:
    """Chunk [since, until] to `chunk` (default 1d) and page **inside each chunk**.

    Bodies carry `startTime`/`endTime` with an offset label on every chunk (the
    device 400s a naive bound — OBSERVED.md "Event-window startTime form: offset
    REQUIRED", live proof 2026-10-17). The p1-05c rule decides *which* label
    (OBSERVED.md "Window offsets are ARITHMETIC for the device"): pass the
    device's claimed offset as `device_offset_min` and every chunk's window is the
    site-wall digits relabeled with it — the only shape the device's label
    arithmetic resolves to the window we asked for. With `None` the chunks keep the
    site-labeled pair (p1-05b behavior), which the caller must surface as a warning
    (pipeline.py's fallback line) — the shift is silent, boundary events are not.

    Every chunk is a new logical search: fresh `searchID`, its own cursor walk, its
    own `SearchSummary`. Chunks run chronologically (oldest-first backfill;
    `time_reverse_order=True` reverses the order *within* a chunk, which is what the
    device honours — OBSERVED.md). A chunk that fails raises out of this generator
    before yielding, so the caller's checkpoint (`max_serial_no` over yielded
    chunks) can never jump past a failed window.
    """
    search = acs_event_search(
        reader,
        limits=limits,
        page_size=page_size,
        max_pages=max_pages,
        inter_page_delay=inter_page_delay,
        sleep=sleep,
        clock=clock,
    )
    for chunk_start, chunk_end in chunk_window(since, until, chunk=chunk, site_tz=site_tz):
        window = window_for_device(chunk_start, chunk_end, site_tz=site_tz)
        cond = build_event_cond(
            window,
            with_offset=with_offset,
            device_offset_min=device_offset_min,
            major=major,
            minor=minor,
            employee_no=employee_no,
            begin_serial_no=begin_serial_no,
            end_serial_no=end_serial_no,
            time_reverse_order=time_reverse_order,
        )
        records: list[Mapping[str, Any]] = []
        for page in search.pages(cond):
            records.extend(page.records)
        if search.summary is None:  # defensive; pages() sets it before completing
            raise SearchProtocolError("event chunk walk completed without a summary")
        max_serial = _max_serial(records)
        yield ChunkResult(
            start=chunk_start,
            end=chunk_end,
            window=window,
            search_id=search.summary.search_id,
            pages=search.summary.pages,
            records=tuple(records),
            termination=search.summary.termination,
            max_serial_no=max_serial,
        )


def _max_serial(records: tuple[Mapping[str, Any], ...] | list[Mapping[str, Any]]) -> int | None:
    """max(serialNo) over records; non-numeric serials ignored (checkpoint material).

    OBSERVED.md: serialNo counts ALL events including the major=3 noise, so a
    device-wide checkpoint on it is sound — but it is computed by the *caller* over
    completed chunks, never used as a paging cursor here.
    """
    values = []
    for record in records:
        serial = record.get("serialNo")
        if isinstance(serial, int) and not isinstance(serial, bool):
            values.append(serial)
        elif isinstance(serial, str) and serial.strip().isdigit():
            values.append(int(serial.strip()))
    return max(values) if values else None


# --- UserInfo side -----------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class RosterResult:
    """A finished `UserInfo/Search` pull + the advisory `UserInfo/Count` cross-check.

    `count_matches` is None when no count callable was supplied. A mismatch is a
    WARNING for the operator (card: "warn, don't fail") — the roster grows between
    the last page and the count GET, and `UserInfo/Count` is a GET with its own
    timing, so disagreement is normal-on-a-busy-box, not corruption. p1-08 prints
    it; nothing here raises on it.
    """

    users: tuple[Mapping[str, Any], ...]
    pages: int
    search_id: str
    termination: str
    device_count: int | None
    count_matches: bool | None


def iter_users(
    reader: PageReader,
    *,
    limits: PagingLimits | None = None,
    page_size: int | None = None,
    max_pages: int = DEFAULT_MAX_PAGES,
    inter_page_delay: float = DEFAULT_INTER_PAGE_DELAY,
    sleep: Callable[[float], None] = time.sleep,
    clock: Callable[[], float] = time.monotonic,
    search_id: str | None = None,
) -> Iterator[Mapping[str, Any]]:
    """Every user record from `UserInfo/Search`, same engine and rules as events."""
    search = user_info_search(
        reader,
        limits=limits,
        page_size=page_size,
        max_pages=max_pages,
        inter_page_delay=inter_page_delay,
        sleep=sleep,
        clock=clock,
    )
    yield from search.collect({}, search_id=search_id)


#: `GET /ISAPI/AccessControl/UserInfo/Count` reader: returns the parsed body.
CountGetter = Callable[[], dict[str, Any]]


def collect_users(
    reader: PageReader,
    *,
    count_get: CountGetter | None = None,
    limits: PagingLimits | None = None,
    page_size: int | None = None,
    max_pages: int = DEFAULT_MAX_PAGES,
    inter_page_delay: float = DEFAULT_INTER_PAGE_DELAY,
    sleep: Callable[[float], None] = time.sleep,
    clock: Callable[[], float] = time.monotonic,
) -> RosterResult:
    """Full roster + (optional) `UserInfo/Count` post-pull sanity check.

    The count GET happens AFTER the walk (card: post-pull sanity check), and its
    failure is swallowed into `device_count=None` only in the sense that a missing
    number cannot fail a payroll pull — the warning path is `count_matches=False`,
    surfaced, never raised.
    """
    search = user_info_search(
        reader,
        limits=limits,
        page_size=page_size,
        max_pages=max_pages,
        inter_page_delay=inter_page_delay,
        sleep=sleep,
        clock=clock,
    )
    users = search.collect({})
    if search.summary is None:  # defensive; collect() sets it before returning
        raise SearchProtocolError("roster walk completed without a summary")
    device_count: int | None = None
    matches: bool | None = None
    if count_get is not None:
        body = count_get()
        inner = body.get("UserInfoCount")
        raw = inner.get("userNumber") if isinstance(inner, Mapping) else None
        device_count = _coerce_count(
            raw, field="UserInfoCount.userNumber", search_id=search.summary.search_id
        )
        matches = device_count == len(users)
    return RosterResult(
        users=tuple(users),
        pages=search.summary.pages,
        search_id=search.summary.search_id,
        termination=search.summary.termination,
        device_count=device_count,
        count_matches=matches,
    )
