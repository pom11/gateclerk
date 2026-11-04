"""The top-level `gateclerk events` command (CLI-SEAM-MOVE).

One-way import law (`tests/test_cli_structure.py`): `gateclerk.cli` imports this module and
calls `events_cmds.register(app)`; this module imports `gateclerk.cli_shared`, never
`gateclerk.cli`.
"""

from __future__ import annotations

from typing import Annotated, Any

import typer

from gateclerk import cli_shared, pipeline
from gateclerk.cli_shared import (
    DEFAULT_PORT,
    DEFAULT_TIMEOUT,
    DEFAULT_TZ,
    OUTCOME_CHOICES,
    VERIFY_CHOICES,
    ConfigOpt,
    CountOpt,
    HostArg,
    PasswordOpt,
    PortOpt,
    SiteLabelOpt,
    SiteOpt,
    TimeoutOpt,
    TzOpt,
    UserOpt,
    VerboseOpt,
    _client_for,
    _config_exit,
    _context,
    _device_exit,
    _Guard,
    _logger_for,
    _print_count_crosscheck,
    _resolve_creds,
    _resolve_site,
    _resolve_window,
    _resolved_site_tz,
    _validate_choice,
)
from gateclerk.output import CHOICES as OUTPUT_CHOICES
from gateclerk.output import OutputFormat, render
from gateclerk.paging import DEFAULT_CHUNK, parse_chunk
from gateclerk.tz import TimestampInputError

__all__ = ["EVENT_COLUMNS", "_event_row", "events", "register"]

EVENT_COLUMNS: tuple[str, ...] = (
    "serial_no",
    "utc",
    "local",
    "employee_no",
    "name",
    "verify",
    "outcome",
    "status",
    "direction",
)


def _event_row(record: Any) -> dict[str, Any]:
    """One `EventRecord` as the human table wants it."""
    return {
        "serial_no": record.serial_no,
        "utc": None if record.event_time_utc is None else record.event_time_utc.isoformat(),
        "local": record.event_time_local,
        "employee_no": record.employee_no,
        "name": record.name,
        "verify": record.verify_mode,
        "outcome": record.outcome.value,
        "status": record.attendance_status,
        "direction": record.direction.value,
    }


def events(
    ctx: typer.Context,
    since: Annotated[
        str | None,
        typer.Option(
            "--since",
            help="Window start, ISO-8601. Required (DESIGN.md forbids an unbounded "
            "history walk). Naive values are read in --tz / the site's iana_tz; a bare "
            "date means midnight there.",
        ),
    ] = None,
    until: Annotated[
        str | None,
        typer.Option(
            "--until",
            help="Window end, ISO-8601. Required. Both ends are inclusive on the device, "
            "and chunk edges deliberately overlap: UPSERT on (device_serial, serial_no) "
            "makes the re-read free, while a half-open guess at an edge could cost a punch.",
        ),
    ] = None,
    host: HostArg = None,
    site: SiteOpt = None,
    config: ConfigOpt = None,
    port: PortOpt = DEFAULT_PORT,
    user: UserOpt = None,
    password: PasswordOpt = None,
    timeout: TimeoutOpt = DEFAULT_TIMEOUT,
    tz: TzOpt = DEFAULT_TZ,
    format: Annotated[
        OutputFormat,
        typer.Option(
            "--format",
            "--output",
            "-o",
            case_sensitive=False,
            help=f"Output format ({', '.join(OUTPUT_CHOICES)}). `jsonl` is the stream that "
            "feeds gateclerk.model.from_jsonl() losslessly.",
        ),
    ] = OutputFormat.TABLE,
    site_label: SiteLabelOpt = None,
    employee_no: Annotated[
        str | None,
        typer.Option(
            "--employee-no",
            help="Only this employee. Sent as employeeNoString (the suffixless employeeNo "
            "is SILENTLY IGNORED on this firmware — OBSERVED.md) AND re-applied "
            "client-side as defence: a filter we have not probed is a hint, not a promise.",
        ),
    ] = None,
    verify: Annotated[
        str | None,
        typer.Option(
            "--verify",
            help="Filter on currentVerifyMode, client-side: "
            f"{', '.join(VERIFY_CHOICES)}. Substring-matched, because site-a reports "
            "'cardOrFaceOrFp' for every real pass and cannot say which of the three it "
            "was — the honest question is 'could this have been a face pass'.",
        ),
    ] = None,
    outcome: Annotated[
        str | None,
        typer.Option(
            "--outcome",
            help=f"Filter on the p1-04 verdict: {', '.join(OUTCOME_CHOICES)}. "
            "'granted' is the punch set; 'info' is door/button/unknown/heartbeat.",
        ),
    ] = None,
    chunk: Annotated[
        str,
        typer.Option(
            "--chunk",
            help=f"Split [since, until] into windows this wide (Ns/Nm/Nh/Nd, default "
            f"{DEFAULT_CHUNK}). Each chunk is its own logical search, so a mid-search "
            "failure costs one chunk instead of the whole backfill.",
        ),
    ] = DEFAULT_CHUNK,
    max_results: Annotated[
        int | None,
        typer.Option(
            "--max-results",
            min=1,
            help="Stop after this many OUTPUT records (after the client-side filters, so "
            "`--max-results 10 --verify face` means ten matching records). A cap, never a "
            "cursor: the cursor advances only by the device's numOfMatches.",
        ),
    ] = None,
    include_noise: Annotated[
        bool,
        typer.Option(
            "--include-noise",
            help="Keep the major=3 operation stream (site-a: a remote-op/cloud heartbeat "
            "every minute on the minute — 10,169 of 10,199 events). Off by default, so "
            "the table shows punches. Nothing is deleted either way: filtering is a "
            "query-time property (DESIGN.md).",
        ),
    ] = False,
    reverse: Annotated[
        bool,
        typer.Option(
            "--reverse",
            help="Ask the device for newest-first within each chunk (timeReverseOrder, "
            "honoured on this fw). Chunks are still walked oldest-first.",
        ),
    ] = False,
    count: CountOpt = False,
    verbose: VerboseOpt = False,
) -> None:
    """Paged punches via POST /ISAPI/AccessControl/AcsEvent, normalized (card p1-08).

    stdout only — there is no local store in P1 (that is P2), and no checkpoint is
    persisted yet, so `--since`/`--until` are the whole user-facing contract: re-running
    the same window re-reads the same events and that is free by design, because the
    idempotency key is `(device_serial, serial_no)`.

    The table shows UTC and the device's own local string **side by side**, which is the
    payroll triage question ("which one is this?"): site-a stamps +02:00 in +03:00 summer,
    so the local string is evidence, not a redundant column. `tz_offset_min` (the offset
    we used) and `tz_offset_min_device` (what it claimed) are both in `--format json`.

    An empty window prints an empty table and exits 0 — "nobody clocked in" is a valid
    answer, and only a filter typo should be able to look like a failure.

    A run where any printed record has `tz_offset_mismatch=true` ends with ONE summary
    line on stderr (p1-06c: site-a's summer +02:00-on-a-+03:00 wall clock; the records
    are correct, the site-tz resolution is authoritative). Never per record, never on
    stdout, never an exit-code change — `--format jsonl > out.jsonl` stays parseable.
    """
    fmt = format
    site_config = _resolve_site(host=host, site=site, port=port, sites_file=config, output=fmt)
    target = site_config.target()
    _validate_choice(fmt, verify, flag="--verify", allowed=VERIFY_CHOICES)
    _validate_choice(fmt, outcome, flag="--outcome", allowed=OUTCOME_CHOICES)
    site_tz, tz_mapped = _resolved_site_tz(tz=tz, site=site_config, fmt=fmt, ctx=ctx)
    try:
        parse_chunk(chunk)
    except TimestampInputError as exc:
        raise _config_exit(fmt, str(exc)) from exc
    start, end = _resolve_window(since=since, until=until, site_tz=site_tz, fmt=fmt)

    creds = _resolve_creds(target, user=user, password=password, output=fmt)
    logger = _logger_for(verbose, creds)
    with _Guard(fmt):
        with _client_for(target, creds, timeout=timeout, output=fmt, logger=logger) as client:
            serial, _firmware, _model = pipeline.read_device_identity(client)
            if not serial:
                raise _device_exit(
                    fmt,
                    "GET /ISAPI/System/deviceInfo returned no serialNumber — the serial is "
                    "half the idempotency key, so records cannot be assembled without it",
                )
            caps = pipeline.read_capabilities(client)
            device_claim = pipeline.device_window_labels(client)
            context = _context(
                site_config=site_config,
                site_label=site_label,
                site_tz=site_tz,
                caps=caps,
                max_records=max_results,
                logger=logger,
                device_claim=device_claim,
            )
            records = list(
                pipeline.fetch_events(
                    client,
                    since=start,
                    until=end,
                    context=context,
                    device_serial=serial,
                    chunk=chunk,
                    employee_no=employee_no,
                    verify=verify,
                    outcome=outcome,
                    include_noise=include_noise,
                    time_reverse_order=True if reverse else None,
                    caps=caps,
                )
            )
            device_count = (
                pipeline.event_total_count(
                    client,
                    since=start,
                    until=end,
                    site_tz=site_tz,
                    device_offset_min=device_claim.claimed_offset_min,
                )
                if count
                else None
            )
        if fmt is OutputFormat.TABLE:
            render([_event_row(r) for r in records], fmt="table", columns=EVENT_COLUMNS)
        else:
            render([r.to_dict() for r in records], fmt=fmt.value)
        if count:
            capped = max_results is not None and len(records) >= max_results
            _print_count_crosscheck(
                device_count,
                len(records),
                filtered=bool(employee_no or verify or outcome) or capped,
                capped=capped,
            )
        cli_shared._warn_tz_mismatch(records, mapping_declared=tz_mapped)


def register(app: typer.Typer) -> None:
    """Attach the top-level `events` command to the root CLI app."""
    app.command("events")(events)
