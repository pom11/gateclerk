"""The p1-08 command pipeline: record assembly, device walks, request logging.

`cli.py` owns argument parsing, the exit-code contract and rendering. Everything that
assembles a record or drives a search lives here, so both files stay readable and the
assembly rules are testable without a console. Three responsibilities:

1. **Record assembly** (`event_record_from_device` / `user_record_from_device`) — the
   field-by-field recipe from p1-06's resolver output and p1-04's classifier into a
   p1-07 record. It is the recipe p1-07's own tests carry a private copy of
   (`tests/test_model.py::record_from_event`), promoted to product code.

   It lives here rather than in `model.py` on purpose: `model.py` is the record
   *contract* (field set, round-trip, key digests) and imports neither p1-04 nor p1-06.
   A factory that pulled in the classifier and the resolver would drag both into the
   contract module's import graph for one caller's convenience, and would make the
   module that only *describes* the record depend on the things that produce it.

2. **Search walks** (`fetch_events` / `fetch_users`) — explicit wrappers over
   `gateclerk.paging` that pin the two rules OBSERVED.md says are load-bearing on this
   firmware and that a caller must not be able to get wrong: the employee filter is
   applied again CLIENT-side, and the page size is clamped to the device's own
   capability.

3. **Verbose request logging** (`RequestLogger`) — card p1-08: "when a live call
   misbehaves I want the request body on screen, not guessed", with the Authorization
   header redacted because that header carries credential-derived material.

Read-only (DESIGN.md invariant): this module only calls `client.get_response` /
`client.search_response`, and every endpoint name it passes goes through the closed
registry (`gateclerk.endpoints`). It never opens a socket by itself; tests drive it with
`tests/fakedevice.py`.
"""

from __future__ import annotations

import json
from collections.abc import Callable, Iterator, Mapping
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from typing import Any

from gateclerk.capabilities import DeviceCapabilities, device_identity, discover
from gateclerk.endpoints import SEARCH_ENDPOINTS, endpoint_for
from gateclerk.event_codes import PUNCH_MAJOR, classify_event
from gateclerk.exceptions import IsapiAuthError, IsapiError
from gateclerk.isapi_response import parse_body
from gateclerk.model import EventRecord, UserRecord, tz_fields_from_record
from gateclerk.paging import (
    DEFAULT_INTER_PAGE_DELAY,
    ChunkResult,
    PageReader,
    PagingLimits,
    RosterResult,
    collect_users,
    iter_event_windows,
)
from gateclerk.secrets import Secret, redact
from gateclerk.tz import (
    DEFAULT_SITE_TZ,
    DeviceTime,
    TimeResolver,
    UserTimestamp,
    offset_hhmm,
    read_system_time,
    resolve_event_time,
    window_for_device,
)

__all__ = [
    "DEFAULT_SITE_LABEL",
    "NOISE_MAJOR",
    "LoggedClient",
    "RequestLogger",
    "RunContext",
    "WindowLabels",
    "compile_run_context",
    "device_time_reading",
    "device_window_labels",
    "event_record_from_device",
    "event_total_count",
    "fetch_events",
    "fetch_users",
    "paging_limits_from_caps",
    "read_capabilities",
    "read_device_identity",
    "user_record_from_device",
]

#: The `--site-label` value when the operator did not name one (card p1-08: "free-text
#: label stamped onto records, default 'site-a'"). A record with no site cannot be
#: reconciled across three sites (DESIGN.md open question 3), so the default is a real
#: label rather than None.
DEFAULT_SITE_LABEL = "site-a"

#: The heartbeat stream, excluded from punch output unless `--include-noise` (orchestrator
#: note, 2026-10-15). OBSERVED.md census: 10,169 of 10,199 site-a events are
#: major=3/minor=1029 — a remote-op/cloud poll every minute on the minute. So the default
#: is *exclude*: a default that included it would show payroll 99.7% heartbeat.
NOISE_MAJOR = 3

#: Never send this key (DESIGN.md paging rules). Checked here *and* in
#: `paging.build_event_cond`, because the last point before the socket is the one that
#: can still stop the request.
_FORBIDDEN_COND_KEYS = frozenset({"picEnable"})

#: Tokens `--verify` accepts inside a compound `currentVerifyMode` value. OBSERVED.md:
#: site-a reports `cardOrFaceOrFp` on every real pass and does NOT say which of the three
#: it was, so `--verify face` can only honestly ask "could this have been a face pass".
_VERIFY_TOKENS = frozenset({"card", "face", "fp", "password"})


# --- the resolved run context ----------------------------------------------------------


@dataclass(frozen=True, slots=True)
class WindowLabels:
    """What the event windows get stamped with this run (p1-05c).

    `claimed_offset_min` is the offset the device *labels its own clock* with — read
    from `GET /ISAPI/System/time` (`read_system_time`'s `claimed_offset_minutes`),
    which on site-a is `+02:00` year-round while the site zone is `+03:00` in summer
    (OBSERVED.md "time/offset bug"). The A/B of 2026-10-17 (OBSERVED.md "Window
    offsets are ARITHMETIC") proved the device re-anchors window bounds on THAT
    clock, so the correct wire shape is site-wall digits carrying this label.

    None means "the claim was unreadable" — and then `note` says why, and the walk
    proceeds site-labeled with a visible warning (the p1-05b shape). A claim is
    never invented: guessing an offset would shift payroll windows silently, which
    is the exact bug class this card exists to close.
    """

    claimed_offset_min: int | None
    #: Why the claim could not be read (surfaced on the warning line), when it could not.
    note: str | None = None


@dataclass(frozen=True, slots=True)
class RunContext:
    """Per-run facts every command needs, resolved once, before the first request.

    Frozen and validated *before any socket opens*, because the alternative is
    discovering a typo'd `--tz` after three pages of a 200-page backfill. A
    half-finished read against door hardware is what p1-05 chunks windows to bound; a
    wrong zone is a payroll bug, not a retry.
    """

    #: Free-text label stamped on every record (`--site-label`, default 'site-a').
    site: str = DEFAULT_SITE_LABEL
    #: Zone used to interpret naive `--since`/`--until` and to resolve event times
    #: (DESIGN.md "Time handling" policy 1: site-tz is primary, never the device's claim).
    site_tz: str = DEFAULT_SITE_TZ
    #: Paging limits from the device's capability, or None for p1-05's conservative ones.
    limits: PagingLimits | None = None
    #: Inter-page pacing. p1-02's `page_delay_ms` is the config source (DESIGN.md: 100 ms).
    inter_page_delay: float = DEFAULT_INTER_PAGE_DELAY
    #: Page size we ask for; still clamped to the capability inside p1-05's engine.
    page_size: int | None = None
    #: `--max-results N`: stop after N OUTPUT records, mid-walk. A cap, never a cursor.
    max_records: int | None = None
    #: The verbose logger, when `--verbose` was given.
    logger: RequestLogger | None = None
    #: The device's claimed UTC offset in minutes (p1-05c), from `device_window_labels`
    #: read ONCE per run. None = unreadable -> event windows fall back to the site
    #: label and `fetch_events` warns; never a silently invented offset.
    claimed_offset_min: int | None = None
    #: Why the claim was unreadable, when it was (folded into the warning line).
    claimed_offset_note: str | None = None
    #: Injectable clock for `captured_at`, so a golden test is not a timestamp race.
    now: Callable[[], datetime] = lambda: datetime.now(UTC)

    def __post_init__(self) -> None:
        if not self.site.strip():
            raise ValueError(
                "site label must not be empty (an unattributed punch cannot be reconciled)"
            )
        if self.max_records is not None and self.max_records < 1:
            raise ValueError(f"--max-results must be >= 1, got {self.max_records}")
        if self.inter_page_delay < 0:
            raise ValueError(f"inter-page delay must be >= 0, got {self.inter_page_delay}")
        # Fail here rather than on page 40: an unresolvable zone resolves EVERY event in
        # the run to `unresolved`, which reads like data instead of like a typo. A bad zone
        # *name* already raises out of the resolver; this refuses the other route to the
        # same silent outcome — a zone that was given but resolves to nothing.
        if self.site_tz is not None and TimeResolver(site_tz=self.site_tz).zone is None:
            raise ValueError(f"site timezone {self.site_tz!r} resolves to no zone")

    def with_logger(self, logger: RequestLogger | None) -> RunContext:
        """Same context, logging (frozen dataclass, so: a copy)."""
        return replace(self, logger=logger)

    def with_device_claim(
        self, claimed_offset_min: int | None, note: str | None = None
    ) -> RunContext:
        """Same context with the run's window-label decision (p1-05c; frozen, so: a copy)."""
        return replace(self, claimed_offset_min=claimed_offset_min, claimed_offset_note=note)


def compile_run_context(
    *,
    site: str | None = None,
    site_tz: str | None = None,
    caps: DeviceCapabilities | None = None,
    page_delay_ms: int | None = None,
    page_size: int | None = None,
    max_records: int | None = None,
    logger: RequestLogger | None = None,
    claimed_offset_min: int | None = None,
    claimed_offset_note: str | None = None,
    now: Callable[[], datetime] = lambda: datetime.now(UTC),
) -> RunContext:
    """Assemble a `RunContext` from already-resolved values.

    `site_tz` is the *already merged* value (flag > sites.toml > default). This function
    does no config precedence of its own on purpose: p1-02's `site_from_args` owns
    precedence, and a second precedence ladder in a second module is how the two drift.
    `caps` supplies the paging limits once the CLI has read them (p1-04's discovery).
    `claimed_offset_min`/`claimed_offset_note` carry the p1-05c window-label decision
    from `device_window_labels` (read once, before the walk); `None` means "unreadable"
    and selects the warned site-labeled fallback, never an invented offset.
    """
    delay = DEFAULT_INTER_PAGE_DELAY if page_delay_ms is None else page_delay_ms / 1000.0
    return RunContext(
        site=site if site is not None else DEFAULT_SITE_LABEL,
        site_tz=site_tz if site_tz is not None else DEFAULT_SITE_TZ,
        limits=None if caps is None else paging_limits_from_caps(caps),
        inter_page_delay=delay,
        page_size=page_size,
        max_records=max_records,
        logger=logger,
        claimed_offset_min=claimed_offset_min,
        claimed_offset_note=claimed_offset_note,
        now=now,
    )


def paging_limits_from_caps(caps: DeviceCapabilities) -> PagingLimits:
    """p1-04's advertised limits, expressed as p1-05's `PagingLimits`.

    A `None` from the device means "it did not say", and selects p1-05's conservative
    default rather than a guess — `PagingLimits()`'s own values, not a copy of them, so
    the two modules cannot drift apart on what "conservative" means.
    """
    defaults = PagingLimits()
    return PagingLimits(
        max_results=defaults.max_results if caps.max_results is None else caps.max_results,
        search_id_max_len=(
            defaults.search_id_max_len if caps.search_id_max is None else caps.search_id_max
        ),
    )


# --- verbose request logging -----------------------------------------------------------


class RequestLogger:
    """Logs the exact ISAPI request about to be sent, with the credential redacted.

    Card p1-08: `--verbose` must put the request **body** on screen. All three things you
    need for a misbehaving call are here — the path including the query (a digest `uri=`
    that dropped `?format=json` is the infinite-401 bug of gotchas §1.4), the headers, and
    the body. For a POST the body is serialised with the same `separators` and
    `ensure_ascii` `IsapiClient._call` uses, so what you read is what the box read.

    Redaction is not optional (DESIGN.md "Credentials": a device password never reaches a
    log). `Authorization` is dropped from the header map entirely rather than printed with
    an inline mask — a header that must not be logged should not appear at all — and every
    line additionally passes through `secrets.redact`, because an operator who used
    `--password` can have that value echoed back inside a device error or a search body.

    Lines go to **stderr**: `gateclerk events --format jsonl > punches.jsonl` has to stay
    parseable with `--verbose` on, which is precisely when a human turns it on.
    """

    #: Headers that carry credentials in some form. `Authorization` is the live one (the
    #: digest response is an MD5 over the password); the rest fail closed for free.
    SECRET_HEADERS = frozenset(
        {"authorization", "proxy-authorization", "cookie", "set-cookie", "www-authenticate"}
    )

    def __init__(self, secrets: tuple[Secret | str, ...] = ()) -> None:
        self._secrets = tuple(secrets)
        #: Every line emitted — so tests assert on the log rather than scraping a
        #: terminal, and so a caller can capture the log instead of printing it.
        self.lines: list[str] = []

    def log_request(
        self,
        method: str,
        path: str,
        *,
        headers: Mapping[str, str] | None = None,
        body: str | None = None,
    ) -> None:
        """One request block: `> METHOD path`, the non-secret headers, then the body."""
        headers = headers or {}
        safe = {
            name: value
            for name, value in sorted(headers.items())
            if name.lower() not in self.SECRET_HEADERS
        }
        self._emit(f"> {method.upper()} {path}")
        for name, value in safe.items():
            self._emit(f">   {name}: {value}")
        if body:
            self._emit(f">   body: {body}")
        if headers and not safe:
            # Say so: someone staring at a header-less block should learn the headers
            # exist and are withheld, not conclude the client sent none.
            self._emit(">   (other headers withheld: credential-bearing)")

    def log_response(self, status: int, *, endpoint: str, bytes_read: int | None = None) -> None:
        """One line per response — enough to see a 401 storm without a packet capture."""
        size = "" if bytes_read is None else f" {bytes_read}B"
        self._emit(f"< {endpoint} -> HTTP {status}{size}")

    def note(self, text: str) -> None:
        """A non-request observation: page counts, filters applied, why we stopped."""
        self._emit(f"# {text}")

    def _emit(self, line: str) -> None:
        from gateclerk.output import make_console  # local: keeps the module import cheap

        safe = redact(line, *self._secrets)
        self.lines.append(safe)
        make_console(stderr=True).print(safe, markup=False)


# --- device reads ----------------------------------------------------------------------


def read_device_identity(client: Any) -> tuple[str | None, str | None, str | None]:
    """(serial, firmware, model) from `GET /ISAPI/System/deviceInfo`.

    The serial is half the idempotency key (DESIGN.md), so the CLI refuses to assemble
    event records without one rather than stamping records with an empty serial — a blank
    `device_serial` is refused by the model anyway, but refusing here names the endpoint
    that failed instead of the field.
    """
    return device_identity(client.get("device_info"))


def read_capabilities(
    client: Any, *, force_refresh: bool = False, cache: Any = None
) -> DeviceCapabilities:
    """p1-04's discovery, re-exported so a command body imports device reads from ONE place.

    Kept as a function rather than a bare re-export because the CLI's `--refresh` flag
    maps onto `force_refresh` here, and that mapping deserves a name.
    """
    return discover(client, cache=cache, force_refresh=force_refresh)


def device_time_reading(client: Any) -> tuple[DeviceTime, str]:
    """`GET /ISAPI/System/time` parsed, plus the raw body for the `--json` passthrough.

    Reads raw bytes and hands them to `tz.read_system_time` rather than calling
    `client.get()`, because this firmware answers System/time as **XML despite
    `?format=json`** (OBSERVED.md) — the card's own ownership note, and the reason this
    helper exists at all instead of being a one-liner in the command body.
    """
    raw = client.get_response("system_time").content
    return read_system_time(raw), raw.decode("utf-8", "replace")


def device_window_labels(client: Any) -> WindowLabels:
    """The window-label decision for one run: the device's claimed offset, read ONCE.

    p1-05c (OBSERVED.md "Window offsets are ARITHMETIC"): the device interprets each
    window bound by converting the label to an instant and re-anchoring it on ITS
    clock, so event windows must be site-wall digits labeled with the offset the
    device itself reports. That offset lives in the `localTime` stamp of
    `GET /ISAPI/System/time` — a cheap, read-only GET already in the p1-08 read
    patterns, and read here exactly once per run: per-chunk reads would multiply
    requests against a box that already caps digest nonces near 190 uses
    (OBSERVED.md "Digest nonce use-cap") for an answer that does not change
    mid-walk.

    A transport failure is a *fallback*, not a failure: the walk can still run
    site-labeled (p1-05b behavior), and `fetch_events` says so loudly. The one
    exception is an auth error, which is re-raised: an unauthenticated run must
    never spend its one cheap read deciding to degrade payroll windows quietly —
    exit 3 exists for a human to check the credential.
    """
    try:
        reading, _raw = device_time_reading(client)
    except IsapiAuthError:
        raise
    except IsapiError as exc:
        return WindowLabels(None, note=f"System/time unreadable: {exc}")
    if reading.claimed_offset_minutes is None:
        return WindowLabels(
            None,
            note=reading.note or "System/time localTime carried no UTC offset",
        )
    return WindowLabels(reading.claimed_offset_minutes)


# --- record assembly -------------------------------------------------------------------


def event_record_from_device(
    event: Mapping[str, Any],
    *,
    site: str,
    device_serial: str,
    site_tz: str | None = DEFAULT_SITE_TZ,
    capabilities: DeviceCapabilities | None = None,
    captured_at: datetime | None = None,
) -> EventRecord:
    """One raw AcsEvent record -> a p1-07 `EventRecord`. The assembly contract.

    Most fields are copied through; the derived ones are the ones to review, and each is
    decided by the card that owns it, never re-derived here:

    * `major` / `minor` / `outcome` / `unknown_code` / `verify_mode` / `employee_no` —
      p1-04's `classify_event` verdict (curated table plus the device's own advertised code
      set; DESIGN.md "Why we read /capabilities").
    * the ten `tz_*` keys — p1-06's `as_record()`, consumed **verbatim** through
      `model.tz_fields_from_record`, which refuses a block that renamed one. The device's
      claimed offset travels as `tz_offset_min_device` and is never used for the math.
    * `tz_offset_mismatch` — p1-06c, computed by `tz.resolve_event_time` from the two
      offsets *after* resolution, and structurally unable to move the instant.
    * `direction` / `direction_source` — p1-07's no-inference rule inside the model:
      derived only from `attendanceStatus`, which is null on site-a (`unknown` / `none`).

    `raw` stays the untouched device record. Unlike a UserInfo entry, an event carries no
    `password` key: there is nothing to strip here, and nothing here removes a field.
    """
    verdict = classify_event(event, capabilities=capabilities)
    raw_time = event.get("time")
    raw_time = raw_time if isinstance(raw_time, str) else None
    resolved = TimeResolver(site_tz=site_tz).resolve(raw_time)
    # p1-06d's façade: resolution runs first and alone, the flag is computed afterwards
    # from the result. Passing no explicit claim means the string's own stamp is the
    # claim — which is what surfaces site-a's +02:00-in-+03:00 bug instead of reporting
    # "nothing to compare".
    facade = resolve_event_time(raw_time, site_tz)

    return EventRecord.from_dict(
        {
            "site": site,
            "device_serial": device_serial,
            "serial_no": event.get("serialNo"),
            # verdict.employee_no is `employeeNoString` first and always a str
            # (event_codes._employee_no): routing through the classifier keeps exactly one
            # decision site for "who is this" between classifier and record.
            "employee_no": verdict.employee_no,
            "name": _name_field(event),
            "attendance_status": event.get("attendanceStatus"),
            "verify_mode": verdict.verify_mode,
            "major": verdict.major,
            "minor": verdict.minor,
            "outcome": verdict.outcome,
            "unknown_code": verdict.unknown_code,
            "raw": dict(event),
            "captured_at": captured_at,
            **tz_fields_from_record(
                {
                    **resolved.as_record(),
                    # None means "there was no claim to compare" and must stay None, not
                    # become False: claiming "agrees" about missing data is a false
                    # reassurance on the payroll path (tz_mismatch.py's rule).
                    "tz_offset_mismatch": facade.mismatch,
                }
            ),
        }
    )


def _name_field(event: Mapping[str, Any]) -> str | None:
    """`name` as the device reported it: a non-empty string, else None.

    The model NFC-normalizes it and flags an encrypted-looking blob; this only refuses a
    non-string value (an XML flattening can hand back a dict), which would otherwise be
    reported as a contract error about the field rather than about the device's odd shape.
    """
    name = event.get("name")
    if isinstance(name, str) and name.strip():
        return name
    return None


def user_record_from_device(user: Mapping[str, Any]) -> UserRecord:
    """One `UserInfo/Search` entry -> `UserRecord`, which strips the `password` hash.

    `UserRecord.from_device_user` does the work, including the redaction before anything
    can store it. This named seam exists so the CLI has one import site for
    "device record -> model record", and so p1-09's CLI tests drive the same path p1-08
    uses instead of assembling records a second way.
    """
    return UserRecord.from_device_user(user)


# --- the walks -------------------------------------------------------------------------


def fetch_events(
    client: Any,
    *,
    since: UserTimestamp,
    until: UserTimestamp,
    context: RunContext,
    device_serial: str,
    chunk: str = "1d",
    employee_no: str | None = None,
    verify: str | None = None,
    outcome: str | None = None,
    include_noise: bool = False,
    time_reverse_order: bool | None = None,
    caps: DeviceCapabilities | None = None,
) -> Iterator[EventRecord]:
    """Page every chunk of [since, until]; yield normalized records, oldest chunk first.

    Filters, and which side of the wire each belongs on — OBSERVED.md's "filter
    CLIENT-side" policy is the reason this wrapper exists rather than the CLI calling
    `iter_event_windows` directly:

    * `startTime`/`endTime`/`major`/`employeeNoString` go to the device (the only server
      filters probed to work on this firmware) **and** `employee_no` is re-applied
      client-side. A silently-ignored filter "looks like data, isn't filtered, and nobody
      notices until payroll is wrong" (OBSERVED.md), so a server filter is a performance
      hint, never a guarantee.
    * `verify` and `outcome` are client-side only. `verify_mode` is the verbatim
      `currentVerifyMode`, which on this firmware cannot distinguish face from card.
    * `major=3` is dropped unless `include_noise` — both by asking for `major=5` and again
      client-side, so a firmware that ignored the major filter cannot refill the table
      with heartbeats.

    `--max-results` caps OUTPUT, applied after the client-side filters: `--max-results 10
    --verify face` means ten matching records (what a human means by it), not ten records
    that then filtered down to four.

    Window labels (p1-05c, OBSERVED.md "Window offsets are ARITHMETIC"): every chunk
    goes out as site-wall digits labeled with `context.claimed_offset_min` — the
    device's own claimed offset, read once per run by `device_window_labels`. When no
    claim was readable the chunks keep the site label (the p1-05b shape) and a warning
    line goes to stderr: during DST that shape arrives one hour early in device terms
    and silently loses boundary punches, so the run must SAY it is at risk rather
    than print a plausible short table. The offset is never invented, and never naive
    (the firmware 400s that).
    """
    limits = context.limits or PagingLimits()
    major = 0 if include_noise else 5
    label = (
        f"device-claimed {offset_hhmm(context.claimed_offset_min)}"
        if context.claimed_offset_min is not None
        else "site (fallback)"
    )
    if context.logger is not None:
        context.logger.note(
            f"events window {since.value.isoformat()} .. {until.value.isoformat()} "
            f"chunk={chunk} major={major} site={context.site} tz={context.site_tz} "
            f"window_label={label}"
        )
    _warn_site_labeled(context, since)
    yielded = 0
    for chunk_result in iter_event_windows(
        _search_reader(client),
        since=since,
        until=until,
        chunk=chunk,
        site_tz=context.site_tz,
        device_offset_min=context.claimed_offset_min,
        limits=limits,
        page_size=context.page_size,
        inter_page_delay=context.inter_page_delay,
        major=major,
        employee_no=employee_no,
        time_reverse_order=time_reverse_order,
    ):
        _log_chunk(context.logger, chunk_result)
        for raw in chunk_result.records:
            record = event_record_from_device(
                raw,
                site=context.site,
                device_serial=device_serial,
                site_tz=context.site_tz,
                capabilities=caps,
                captured_at=context.now(),
            )
            if record.major == NOISE_MAJOR and not include_noise:
                continue
            if not _matches(record, employee_no=employee_no, verify=verify, outcome=outcome):
                continue
            yield record
            yielded += 1
            if context.max_records is not None and yielded >= context.max_records:
                if context.logger is not None:
                    context.logger.note(
                        f"stopped at --max-results {context.max_records} (chunk "
                        f"{chunk_result.start.isoformat()}..{chunk_result.end.isoformat()})"
                    )
                return


def fetch_users(
    client: Any,
    *,
    context: RunContext,
    with_count: bool = False,
    caps: DeviceCapabilities | None = None,
) -> RosterResult:
    """The full roster, plus the advisory `UserInfo/Count` cross-check when asked.

    `with_count` wires GET `UserInfo/Count` as p1-05's post-pull sanity check. A
    disagreement is `count_matches=False` for the operator to read, never an exception
    (paging.py's rule: the roster grows between the last page and the count GET, so
    disagreement is normal-on-a-busy-box, not corruption). Display-only by design — no
    count here is ever a loop bound (DESIGN.md: `totalMatches` is advisory, and
    `AcsEvent/Total` is not even supported on this firmware).
    """
    limits = context.limits
    if limits is None and caps is not None:
        limits = paging_limits_from_caps(caps)
    result = collect_users(
        _search_reader(client, "user_info_search"),
        count_get=_count_getter(client) if with_count else None,
        limits=limits or PagingLimits(),
        page_size=context.page_size,
        inter_page_delay=context.inter_page_delay,
    )
    if context.logger is not None:
        context.logger.note(
            f"users: {len(result.users)} record(s) over {result.pages} page(s) "
            f"termination={result.termination} device_count={result.device_count}"
        )
    return result


# --- internals -------------------------------------------------------------------------


def _matches(
    record: EventRecord, *, employee_no: str | None, verify: str | None, outcome: str | None
) -> bool:
    """Client-side filter over an assembled record. Every given condition must hold."""
    if employee_no is not None and record.employee_no != employee_no:
        return False
    if verify is not None and not _verify_matches(record.verify_mode, verify):
        return False
    return outcome is None or record.outcome.value == outcome.strip().lower()


def _verify_matches(verify_mode: str | None, wanted: str) -> bool:
    """`--verify face|card|fp` against the device's verbatim `currentVerifyMode`.

    Substring match rather than equality, deliberately: OBSERVED.md records
    `currentVerifyMode: "cardOrFaceOrFp"` for every real pass on site-a, so comparing
    against `"face"` exactly would print an empty table on the only device we have ever
    measured — and an empty table is the output that reads as "nobody clocked in", the
    worst possible failure on this path. A firmware that reports `face` plainly matches
    too. `invalid` (a door event, not a verification) matches nothing, which is honest.
    """
    if verify_mode is None:
        return False
    needle = wanted.strip().lower()
    if needle not in _VERIFY_TOKENS:
        # An operator asking about a mode we do not know: compare verbatim, and let the
        # empty result be the answer rather than guessing what it meant.
        return needle == verify_mode.strip().lower()
    return needle in verify_mode.strip().lower()


class LoggedClient:
    """A pass-through client wrapper that logs every request it carries.

    Wrapping (rather than logging inside each command body) is what makes `--verbose`
    complete: `capabilities.discover()` opens its own three GETs, and p1-04 owns that
    sequence — this way the requests get logged without a hook request into another
    card's module, and without a second description of what p1-04 does that can go stale.

    It is *pass-through* in the strong sense: same methods, same arguments, same return
    values, `close()` forwarded. When `logger` is None the CLI uses the bare `IsapiClient`
    and this class is not constructed at all, so the default path adds nothing.
    """

    def __init__(self, client: Any, logger: RequestLogger) -> None:
        self._client = client
        self._logger = logger

    # -- lifecycle forwarded so `with _client_for(...)` still owns the socket ------------
    def __enter__(self) -> LoggedClient:
        self._client.__enter__()
        return self

    def __exit__(self, *exc: object) -> None:
        self._client.__exit__(*exc)

    def close(self) -> None:
        self._client.close()

    def __getattr__(self, name: str) -> Any:
        # Anything else (`.timeout`, `.circuit_open()`, `.reset_circuit()`) is the wrapped
        # client's. Keeps the wrapper transparent if a later card reaches for another
        # IsapiClient method — a wrapper that hides methods is a wrapper that surprises.
        return getattr(self._client, name)

    def get(self, name: str) -> dict[str, Any]:
        return parse_body(self.get_response(name).content)

    def get_response(self, name: str) -> Any:
        self._logger.log_request("GET", endpoint_for(name).url_path)
        response = self._client.get_response(name)
        self._logger.log_response(
            response.status_code, endpoint=name, bytes_read=len(response.content)
        )
        return response

    def search(self, name: str, payload: Mapping[str, Any]) -> dict[str, Any]:
        return parse_body(self.search_response(name, payload).content)

    def search_response(self, name: str, payload: Mapping[str, Any]) -> Any:
        _refuse_snapshot_requests(payload)
        self._logger.log_request(
            "POST",
            endpoint_for(name).url_path,
            # Same serialisation IsapiClient._call uses (same separators, same
            # ensure_ascii), so the logged body is the request and not a description of it.
            body=json.dumps(payload, ensure_ascii=False, separators=(",", ":")),
        )
        response = self._client.search_response(name, payload)
        self._logger.log_response(
            response.status_code, endpoint=name, bytes_read=len(response.content)
        )
        return response


def _refuse_snapshot_requests(payload: Mapping[str, Any]) -> None:
    """The last-line read-only guard: a search body must never ask for snapshots.

    DESIGN.md's paging rules forbid `picEnable:true` outright (snapshots bloat pages and
    nobody asked for them). `paging.build_event_cond` already refuses it; checking again
    here is deliberate, because this is the last point before the bytes leave.
    """
    for value in payload.values():
        if isinstance(value, Mapping) and _FORBIDDEN_COND_KEYS & set(value):
            raise ValueError(
                "search body carries picEnable — never sent (DESIGN.md paging rules). "
                "The paging engine does not add it, so a caller smuggled it in."
            )


def _warn_site_labeled(context: RunContext, since: UserTimestamp) -> None:
    """The p1-05c fallback warning: a site-labeled window is a KNOWN-RISKY shape.

    Emitted per run (not per chunk) on stderr, outside `--verbose`: an operator
    watching `gateclerk events` in summer must see "boundaries may shift" without
    digging for it, because the failure mode is a plausible short table — NO MATCH
    looks exactly like a quiet day (OBSERVED.md's A/B). The site label shown is the
    one the wire actually carries: `since.value` is tz-aware in the site zone, so
    its trailing offset IS the pair's label, no re-derivation to drift.
    """
    if context.claimed_offset_min is not None:
        return
    site_label = since.value.isoformat()[-6:]
    reason = f" ({context.claimed_offset_note})" if context.claimed_offset_note else ""
    message = (
        f"warning: window labeled {site_label}; device arithmetic may shift boundaries "
        f"— device time unreadable{reason}. Events near a window edge may be silently "
        "missing (OBSERVED.md: the device re-anchors labels on its own clock)."
    )
    if context.logger is not None:
        context.logger.note(message)
    else:
        from gateclerk.output import make_console  # local: keeps the module import cheap

        make_console(stderr=True).print(message, markup=False)


def event_total_count(
    client: Any,
    *,
    since: UserTimestamp,
    until: UserTimestamp,
    site_tz: str,
    major: int = PUNCH_MAJOR,
    minor: int = 0,
    device_offset_min: int | None = None,
) -> int | None:
    """`POST /ISAPI/AccessControl/AcsEventTotalNum` for the same window: the device's own
    count, for the `--count` display line. None when it will not give us a readable one.

    This is the third POST the registry had been holding back. p1-05's handoff is explicit
    that it is not the engine's to add ("3rd POST is a reviewed registry decision … belongs
    with p1-08 --count"), and the orchestrator's 2026-10-15 brief names the endpoint: the
    obvious `AcsEvent/Total` is `400 notSupport` on this firmware (OBSERVED.md) while
    `AcsEventTotalNum` works and returned exactly the 30 major=5 events the paged walk
    found.

    Display only, and it never raises: the window it counts was chosen by *our* chunking and
    the device counts its own log ring, so disagreement is normal on a busy box. Failing a
    payroll pull because an advisory number disagreed with itself would be the worst kind
    of overreach this tool can commit. `paging._coerce_count` is loud about a non-numeric
    count because there it is a loop bound; here the same value is a printed sentence, so an
    unreadable count prints as "the device gave no readable count" instead.

    `minor=0` is the whole-major count — the probe that produced OBSERVED.md's `totalNum:30`
    used `(major 5, minor 0)` and got exactly the paged total, which is the only evidence we
    have that 0 means "all minors" rather than "minor zero".
    """
    window = window_for_device(since, until, site_tz=site_tz)
    # Offset-bearing pair, labeled EXACTLY like the walk (p1-05c): the count probe
    # takes the same body shape as AcsEvent, so it must carry the same label too —
    # a walk relabeled +02:00 and a count probe still +03:00 would compare two
    # different windows and print a nonsense cross-check (one shape, no split-brain).
    # The naive form stays impossible (OBSERVED.md "Event-window startTime form:
    # offset REQUIRED", live proof 2026-10-17).
    start, end = window.search_pair(with_offset=True, device_offset_min=device_offset_min)
    try:
        body = client.search(
            "acs_event_total_num",
            {
                "AcsEventTotalNumCond": {
                    "major": major,
                    "minor": minor,
                    "startTime": start,
                    "endTime": end,
                }
            },
        )
    except IsapiError as exc:
        if isinstance(exc, IsapiAuthError):
            # Never swallow the "authenticated and refused, circuit opened" class behind an
            # advisory number: exit 3 exists because a human has to check the credential
            # before the account is locked. The walk would normally have raised first, but
            # the count call is not the place to decide an auth failure is unimportant.
            raise
        # Includes the 404/400 `notSupport` a firmware that lacks this endpoint answers with
        # (OBSERVED.md: the similarly-named `AcsEvent/Total` is `400 notSupport` on site-a, so
        # a future box may not have this one either). A missing advisory number is not a
        # failed pull: the walk already produced the records.
        return None
    node: Mapping[str, Any] = body if isinstance(body, Mapping) else {}
    inner = node.get("AcsEventTotalNum")
    if isinstance(inner, Mapping):
        node = inner
    value = node.get("totalNum", node.get("numOfMatches"))
    if isinstance(value, bool) or value is None:
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str) and value.strip().lstrip("-").isdigit():
        return int(value.strip())
    return None


def _search_reader(client: Any, endpoint: str = "acs_event_search") -> PageReader:
    """The paging engine's `PageReader`: POST a whole search body, get the parsed dict.

    The engine owns `searchID`/`searchResultPosition`/`maxResults`; this only moves the
    bytes. `endpoint` is a registry name, so the two walks (events, roster) share one
    implementation and neither can invent a path.

    `SEARCH_ENDPOINTS` is asserted, not trusted: it is the registry's own list of POSTs that
    are stateless reads, and the only way this helper can be used on a write path is if that
    list and the registry both change — which is the reviewed change the registry docstring
    asks for, checked here rather than assumed.
    """
    if endpoint not in SEARCH_ENDPOINTS:
        raise ValueError(
            f"{endpoint!r} is not a stateless search endpoint; this walker may only POST "
            f"to {sorted(SEARCH_ENDPOINTS)}"
        )

    def read(body: Mapping[str, Any]) -> dict[str, Any]:
        return client.search(endpoint, body)

    return read


def _count_getter(client: Any) -> Callable[[], dict[str, Any]]:
    """The advisory `UserInfo/Count` reader p1-05's post-pull sanity check wants.

    Made non-raising here, at the CLI's seam: `collect_users` calls `count_get()` plainly,
    so an `IsapiNotFound` from a firmware with no count endpoint (OBSERVED.md records that
    shape for this endpoint's neighbours) would escape as exit 4 and fail a roster pull over
    a number that only decorates it. `paging`'s own rule is warn-not-fail; returning `{}` is
    how that rule reaches the engine without editing the engine.
    """

    def get() -> dict[str, Any]:
        try:
            return client.get("user_info_count")
        except IsapiError as exc:
            if isinstance(exc, IsapiAuthError):
                raise
            return {}

    return get


def _log_chunk(logger: RequestLogger | None, chunk: ChunkResult) -> None:
    if logger is None:
        return
    logger.note(
        f"chunk {chunk.start.isoformat()}..{chunk.end.isoformat()} "
        f"searchID={chunk.search_id} pages={chunk.pages} records={len(chunk.records)} "
        f"termination={chunk.termination} max_serial={chunk.max_serial_no}"
    )
