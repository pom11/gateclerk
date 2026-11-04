"""The `gateclerk device` group: `info`, `time`, and `capabilities` (CLI-SEAM-MOVE).

One-way import law (`tests/test_cli_structure.py`): `gateclerk.cli` imports this module and
calls `device_cmds.register(app)`; this module imports `gateclerk.cli_shared`, never
`gateclerk.cli`.
"""

from __future__ import annotations

from typing import Annotated, Any

import typer

from gateclerk import pipeline
from gateclerk.capabilities import device_identity
from gateclerk.cli_shared import (
    DEFAULT_PORT,
    DEFAULT_TIMEOUT,
    DEFAULT_TZ,
    ConfigOpt,
    HostArg,
    OutputOpt,
    PasswordOpt,
    PortOpt,
    SiteOpt,
    TimeoutOpt,
    TzOpt,
    UserOpt,
    VerboseOpt,
    _client_for,
    _Guard,
    _iso,
    _logger_for,
    _nested,
    _resolve_creds,
    _resolve_site,
    _resolved_site_tz,
)
from gateclerk.output import OutputFormat, make_console, render
from gateclerk.tz import SKEW_WARN_SECONDS, DeviceTime, compute_skew, offset_hhmm
from gateclerk.tz_mismatch import is_offset_mismatch, site_offset_minutes

__all__ = ["NO_OFFSET_EVIDENCE", "_tz_offset_verdict", "device_app", "register"]

device_app = typer.Typer(
    name="device",
    help="Single-device reads (identity, clock, capabilities).",
    no_args_is_help=True,
    context_settings={"help_option_names": ["-h", "--help"]},
)

NO_OFFSET_EVIDENCE = "no evidence (device claims nothing)"


def _tz_offset_verdict(
    reading: DeviceTime, site_tz: str, *, mapped_via: str | None = None
) -> tuple[bool | None, int | None, str]:
    """(mismatch, site offset at the device's wall instant, human sentence) — p1-11."""
    mapping_note = f" (mapped via sites.toml: {mapped_via})" if mapped_via is not None else ""
    if reading.naive_local is None:
        return None, None, "no evidence (no readable device wall clock)"
    site_min = site_offset_minutes(reading.naive_local, site_tz)
    claim_min = reading.claimed_offset_minutes
    verdict = is_offset_mismatch(claim_min, reading.naive_local, site_tz)

    def label(minutes: int) -> str:
        try:
            return f"{offset_hhmm(minutes)} ({minutes} min)"
        except ValueError:  # pragma: no cover
            return f"{minutes} min"

    site = f"site resolves {label(site_min)}"
    if verdict is None or claim_min is None:
        return verdict, site_min, f"{NO_OFFSET_EVIDENCE}, {site}{mapping_note}"
    claim = f"device claims {label(claim_min)}"
    if verdict:
        return verdict, site_min, f"MISMATCH — {claim}, {site}{mapping_note}; records unaffected"
    return verdict, site_min, f"agrees — {claim}, {site}{mapping_note}"


@device_app.command("info")
def device_info(
    host: HostArg = None,
    site: SiteOpt = None,
    config: ConfigOpt = None,
    port: PortOpt = DEFAULT_PORT,
    user: UserOpt = None,
    password: PasswordOpt = None,
    timeout: TimeoutOpt = DEFAULT_TIMEOUT,
    output: OutputOpt = OutputFormat.TABLE,
    verbose: VerboseOpt = False,
    json_flag: Annotated[
        bool,
        typer.Option(
            "--json",
            help="Raw deviceInfo passthrough (the body as the device answered it). "
            "Shorthand for --output json.",
        ),
    ] = False,
) -> None:
    """Read GET /ISAPI/System/deviceInfo (model, serial, firmware version).

    The serial is half the idempotency key (DESIGN.md), which is why `events` reads this
    endpoint itself before assembling a single record. This firmware answers System/*
    as **XML despite `?format=json`** (OBSERVED.md); `parse_body` sniffs the first byte
    rather than trusting Content-Type, so `--json` below means "give me the parsed body",
    not "the device sent JSON".
    """
    fmt = OutputFormat.JSON if json_flag else output
    site_config = _resolve_site(host=host, site=site, port=port, sites_file=config, output=fmt)
    target = site_config.target()
    creds = _resolve_creds(target, user=user, password=password, output=fmt)
    logger = _logger_for(verbose, creds)
    machine = fmt is OutputFormat.JSON or fmt is OutputFormat.JSONL
    rows: list[dict[str, Any]] = []
    columns: tuple[str, ...] | None = None if machine else ("field", "value")
    with _Guard(fmt):
        with _client_for(target, creds, timeout=timeout, output=fmt, logger=logger) as client:
            body = client.get("device_info")
        if machine:
            rows = [dict(body)]
        else:
            serial, firmware, model = device_identity(body)
            rows = [
                {"field": "model", "value": model},
                {"field": "serial", "value": serial},
                {"field": "firmware", "value": firmware},
                {"field": "deviceName", "value": _nested(body, "deviceName")},
                {"field": "deviceType", "value": _nested(body, "deviceType")},
                {
                    "field": "firmwareReleasedDate",
                    "value": _nested(body, "firmwareReleasedDate"),
                },
            ]
    render(rows, fmt=fmt.value, columns=columns)


@device_app.command("time")
def device_time(
    ctx: typer.Context,
    host: HostArg = None,
    site: SiteOpt = None,
    config: ConfigOpt = None,
    port: PortOpt = DEFAULT_PORT,
    user: UserOpt = None,
    password: PasswordOpt = None,
    timeout: TimeoutOpt = DEFAULT_TIMEOUT,
    tz: TzOpt = DEFAULT_TZ,
    output: OutputOpt = OutputFormat.TABLE,
    verbose: VerboseOpt = False,
    json_flag: Annotated[
        bool,
        typer.Option(
            "--json",
            help="Raw System/time passthrough (verbatim body — this fw answers XML) plus "
            "the parsed reading, the tz offset verdict and the skew. "
            "Shorthand for --output json.",
        ),
    ] = False,
) -> None:
    """Read GET /ISAPI/System/time and compare its wall clock with ours.

    Three rules from OBSERVED.md decide what this prints:

    * the reading is parsed from the **raw body** (`pipeline.device_time_reading`),
      because this firmware answers System/time as XML even with `?format=json`;
    * the skew is a **wall-clock comparison in the site zone**
      (`tz.compute_skew`), not an instant comparison. The device labels +02:00 in
      Bucharest summer; comparing instants would report that ~1 h tz bug as a 3600 s
      "NTP skew" forever — a permanent false alarm blaming the clock for a timezone
      mistake. The wall clock is the thing OBSERVED.md verified healthy (~4 s) and the
      thing whose drift actually corrupts punch order.
    * the skew is NOT the whole answer, so the offset comparison prints beside it
      (`tz_mismatch.py`'s three-valued rule; DESIGN.md "Open questions" item 7).
      Site-a in summer has a healthy skew and a wrong claimed offset on every
      record: an operator who reads only the skew would send that box home as
      fixed. `None` means the device claimed nothing, and it renders as absence —
      never as agreement (the model.py convention).
    """
    fmt = OutputFormat.JSON if json_flag else output
    site_config = _resolve_site(host=host, site=site, port=port, sites_file=config, output=fmt)
    target = site_config.target()
    creds = _resolve_creds(target, user=user, password=password, output=fmt)
    site_tz, tz_mapped = _resolved_site_tz(tz=tz, site=site_config, fmt=fmt, ctx=ctx)
    logger = _logger_for(verbose, creds)
    machine = fmt is OutputFormat.JSON or fmt is OutputFormat.JSONL
    rows: list[dict[str, Any]] = []
    with _Guard(fmt):
        with _client_for(target, creds, timeout=timeout, output=fmt, logger=logger) as client:
            reading, raw_text = pipeline.device_time_reading(client)
        skew = compute_skew(reading, site_tz=site_tz, warn_seconds=SKEW_WARN_SECONDS)
        offset_verdict, site_offset_min, offset_detail = _tz_offset_verdict(
            reading, site_tz, mapped_via=site_config.device_tz if tz_mapped else None
        )
        if machine:
            rows = [
                {
                    "endpoint": "system_time",
                    "raw_body": raw_text,
                    "local_time_raw": reading.local_time_raw,
                    "device_wall": _iso(reading.naive_local),
                    "device_claimed_offset_min": reading.claimed_offset_minutes,
                    "tz_rule": reading.tz_raw,
                    "parse_note": reading.note,
                    "site_tz": site_tz,
                    "tz_mapped_via": site_config.device_tz if tz_mapped else None,
                    "tz_offset_mismatch": offset_verdict,
                    "site_offset_min_at_instant": site_offset_min,
                    "our_wall": _iso(skew.our_wall),
                    "skew_seconds": skew.skew_seconds,
                    "skew_warn": skew.warn,
                    "skew_warn_seconds": skew.warn_seconds,
                    "skew_reason": skew.reason,
                }
            ]
        else:
            rows = [
                {"field": "device localTime (verbatim)", "value": reading.local_time_raw},
                {"field": "device wall clock", "value": _iso(reading.naive_local)},
                {
                    "field": "device claimed UTC offset (minutes)",
                    "value": reading.claimed_offset_minutes,
                },
                {
                    "field": "device tz rule (Hikvision dialect, diagnostics only)",
                    "value": reading.tz_raw,
                },
                {"field": "site tz", "value": site_tz},
                {"field": "tz offset vs site (verdict)", "value": offset_detail},
                {"field": "our wall clock in the site tz", "value": _iso(skew.our_wall)},
                {
                    "field": f"wall-clock skew (seconds, warn > {SKEW_WARN_SECONDS:.0f}s)",
                    "value": None if skew.skew_seconds is None else f"{skew.skew_seconds:+.1f}",
                },
                {"field": "parse note", "value": reading.note},
                {"field": "skew reason", "value": skew.reason},
            ]
        render(rows, fmt=fmt.value, columns=None if machine else ("field", "value"))
        if skew.message:
            make_console(stderr=True).print(
                f"[yellow]warning:[/yellow] {skew.message}", markup=True
            )


@device_app.command("capabilities")
def device_capabilities(
    host: HostArg = None,
    site: SiteOpt = None,
    config: ConfigOpt = None,
    port: PortOpt = DEFAULT_PORT,
    user: UserOpt = None,
    password: PasswordOpt = None,
    timeout: TimeoutOpt = DEFAULT_TIMEOUT,
    output: OutputOpt = OutputFormat.TABLE,
    verbose: VerboseOpt = False,
    json_flag: Annotated[
        bool,
        typer.Option(
            "--json",
            help="Raw capability dump (the evidence trail for docs/OBSERVED.md). "
            "Shorthand for --output json.",
        ),
    ] = False,
    refresh: Annotated[
        bool,
        typer.Option(
            "--refresh",
            help="Ignore the in-process (serial, firmware) cache and re-read the device.",
        ),
    ] = False,
) -> None:
    """Read the device's own capability advertisement (card p1-04).

    Card size we may ask for, searchID length, the queryable major set and the minor
    code sets all come from here — never from a guessed table. `--json` prints the raw
    bodies too, which is what gets pasted into docs/OBSERVED.md after a live run.

    `fmt` is resolved BEFORE any failure can happen and is what every error path is
    given: `--json` means "machine-readable, including the errors", and a config failure
    during host/credential resolution used to print prose while exiting 2, which broke
    the caller that asked for JSON.
    """
    fmt = OutputFormat.JSON if json_flag else output
    site_config = _resolve_site(host=host, site=site, port=port, sites_file=config, output=fmt)
    target = site_config.target()
    creds = _resolve_creds(target, user=user, password=password, output=fmt)
    logger = _logger_for(verbose, creds)
    with (
        _Guard(fmt),
        _client_for(target, creds, timeout=timeout, output=fmt, logger=logger) as client,
    ):
        caps = pipeline.read_capabilities(client, force_refresh=refresh)
    if fmt is OutputFormat.JSON or fmt is OutputFormat.JSONL:
        render([caps.as_dict()], fmt=fmt.value)
        return
    render(
        [
            {
                "capability": "device",
                "value": " ".join(str(p) for p in (caps.model, caps.serial, caps.firmware) if p),
            },
            *caps.summary_rows(),
        ],
        fmt=fmt.value,
        columns=("capability", "value"),
    )


def register(app: typer.Typer) -> None:
    """Attach the `device` group to the root CLI app."""
    app.add_typer(device_app)
