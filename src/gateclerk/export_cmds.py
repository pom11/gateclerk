"""The `gateclerk export` group: inventory and scan exports (EXPORT-CONFIG / EXPORT-SCANS).

One-way import law (`tests/test_cli_structure.py`): `gateclerk.cli` imports this module and
calls `export_cmds.register(app)`; this module imports `gateclerk.cli_shared` and
`gateclerk.export_cli`, never `gateclerk.cli`.
"""

from __future__ import annotations

import sys
from typing import Annotated

import typer

from gateclerk import config as cfg
from gateclerk import export_cli
from gateclerk.cli_shared import _config_exit, _fail
from gateclerk.exceptions import ConfigError, EventBoundsError
from gateclerk.output import OutputFormat
from gateclerk.tz import TimestampInputError

export_app = typer.Typer(
    name="export",
    help=(
        "Export site/device configuration inventory and local store scan records to CSV "
        "or JSONL. Credential references are exported by name; secret values never are."
    ),
    no_args_is_help=True,
    context_settings={"help_option_names": ["-h", "--help"]},
)

ExportConfigFileOpt = Annotated[
    str,
    typer.Option(
        "--config",
        help=(
            "Path to sites.toml to read (default ./sites.toml). Refs only; "
            "unknown keys are dropped on config export."
        ),
    ),
]
ExportSiteOpt = Annotated[
    str | None,
    typer.Option(
        "--site",
        help="Site name in sites.toml (required for `export scans` when >1 site is configured).",
    ),
]
ExportStateRootOpt = Annotated[
    str | None,
    typer.Option(
        "--state-root",
        help="State directory containing the site SQLite store (or overriding state_dir).",
    ),
]
ExportFormatOpt = Annotated[
    str,
    typer.Option(
        "--format",
        help="Export format: `csv` (default) or `jsonl`.",
    ),
]
ExportOutputOpt = Annotated[
    str | None,
    typer.Option(
        "--output",
        "-o",
        help=(
            "Destination file path (required when stdout is an interactive TTY; "
            "omit when piping stdout)."
        ),
    ),
]
ExportBomOpt = Annotated[
    bool,
    typer.Option(
        "--bom",
        help="Prepend a UTF-8 BOM to CSV output for Excel-on-Windows compatibility.",
    ),
]
ExportDeviceOpt = Annotated[
    str | None,
    typer.Option(
        "--device",
        help="Filter exported scans to this device_serial.",
    ),
]
ExportEmployeeOpt = Annotated[
    str | None,
    typer.Option(
        "--employee",
        help="Filter exported scans to this employee_no string.",
    ),
]
ExportSinceOpt = Annotated[
    str | None,
    typer.Option(
        "--since",
        help="Lower bound on event time (inclusive; ISO-8601 or YYYY-MM-DD in site timezone).",
    ),
]
ExportUntilOpt = Annotated[
    str | None,
    typer.Option(
        "--until",
        help="Upper bound on event time (inclusive; ISO-8601 or YYYY-MM-DD in site timezone).",
    ),
]
ExportDirectionOpt = Annotated[
    str,
    typer.Option(
        "--direction",
        help="Filter by stored direction: `in`, `out`, or `any` (default `any`).",
    ),
]
ExportRedactOpt = Annotated[
    bool,
    typer.Option(
        "--redact",
        help=(
            "Drop personal-data identifier columns (`employee_no`, `cardNo`, `name`) and "
            "strip them from `raw` JSON so the export can be shared safely."
        ),
    ),
]


def _resolve_fmt_and_output(fmt: str, output: str | None) -> tuple[str, str | None, OutputFormat]:
    effective_fmt = fmt
    effective_output = output
    if output in ("json", "jsonl") and fmt == "csv":
        effective_fmt = "jsonl"
        effective_output = None
    elif output == "table" and fmt == "csv":
        effective_fmt = "csv"
        effective_output = None
    err_fmt = (
        OutputFormat.JSON
        if effective_fmt.strip().lower() in ("json", "jsonl")
        else OutputFormat.TABLE
    )
    return effective_fmt, effective_output, err_fmt


@export_app.command("config")
def export_config(
    config: ExportConfigFileOpt = cfg.DEFAULT_SITES_FILE,
    site: ExportSiteOpt = None,
    state_root: ExportStateRootOpt = None,
    fmt: ExportFormatOpt = "csv",
    output: ExportOutputOpt = None,
    bom: ExportBomOpt = False,
) -> None:
    """Export sites + devices inventory from sites.toml (allowlist columns, ref names only)."""
    effective_fmt, effective_output, err_fmt = _resolve_fmt_and_output(fmt, output)
    try:
        stdout_payload, stderr_summary = export_cli.export_config_file(
            config_path=config,
            site=site,
            state_root=state_root,
            fmt=effective_fmt,
            output_path=effective_output,
            bom=bom,
        )
    except ConfigError as exc:
        raise _config_exit(err_fmt, str(exc)) from exc

    if stdout_payload:
        sys.stdout.write(stdout_payload)
    if stderr_summary:
        sys.stderr.write(stderr_summary + "\n")


@export_app.command("scans")
def export_scans(
    config: ExportConfigFileOpt = cfg.DEFAULT_SITES_FILE,
    site: ExportSiteOpt = None,
    state_root: ExportStateRootOpt = None,
    device: ExportDeviceOpt = None,
    employee: ExportEmployeeOpt = None,
    since: ExportSinceOpt = None,
    until: ExportUntilOpt = None,
    direction: ExportDirectionOpt = "any",
    fmt: ExportFormatOpt = "csv",
    output: ExportOutputOpt = None,
    bom: ExportBomOpt = False,
    redact: ExportRedactOpt = False,
) -> None:
    """Stream stored scans from the local SQLite database to CSV or JSONL (personal data).

    Attendance scans are personal data (GDPR-adjacent workforce records). Output goes to
    stdout only when piped; on an interactive TTY, `--output <path>` (`-o <path>`) is
    required so no surprise file is created. Pass `--redact` to omit `employee_no`,
    `cardNo`, and `name` when sharing diagnostics.
    """
    effective_fmt, effective_output, err_fmt = _resolve_fmt_and_output(fmt, output)
    try:
        _count, stderr_msg = export_cli.export_scans_stream(
            config_path=config,
            site=site,
            state_root=state_root,
            device=device,
            employee=employee,
            since=since,
            until=until,
            direction=direction,
            fmt=effective_fmt,
            output_path=effective_output,
            bom=bom,
            redact=redact,
        )
    except (ConfigError, TimestampInputError, EventBoundsError) as exc:
        raise _fail(err_fmt, exc) from exc

    if stderr_msg:
        sys.stderr.write(stderr_msg + "\n")


def register(app: typer.Typer) -> None:
    """Attach the `export` group to the root CLI app."""
    app.add_typer(export_app)
