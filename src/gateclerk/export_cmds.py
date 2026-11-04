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
from gateclerk.cli_shared import _config_exit
from gateclerk.exceptions import ConfigError
from gateclerk.output import OutputFormat

export_app = typer.Typer(
    name="export",
    help=(
        "Export site/device configuration inventory (and local store records) to CSV or "
        "JSONL. Credential references are exported by name; secret values never are."
    ),
    no_args_is_help=True,
    context_settings={"help_option_names": ["-h", "--help"]},
)

ExportConfigFileOpt = Annotated[
    str,
    typer.Option(
        "--config",
        help=(
            "Path to sites.toml to project (default ./sites.toml). Refs only; "
            "unknown keys are dropped."
        ),
    ),
]
ExportSiteOpt = Annotated[
    str | None,
    typer.Option(
        "--site",
        help="Export only this named [[site]] block (default: export all configured sites).",
    ),
]
ExportStateRootOpt = Annotated[
    str | None,
    typer.Option(
        "--state-root",
        help="Override the state_dir column reported for each exported site.",
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
    # When someone invokes `-o json` or `-o jsonl` (the CLI-wide machine-output muscle
    # memory), treat it as format=jsonl to stdout if stdout is not a TTY, unless `output`
    # looks like a file path.
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


def register(app: typer.Typer) -> None:
    """Attach the `export` group to the root CLI app."""
    app.add_typer(export_app)
