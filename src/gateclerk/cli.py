"""`gateclerk` command line — root app, `--version` callback, and group registrations.

CLI-SPLIT-STRUCTURE and CLI-SEAM-MOVE moved every command group (`device`, `users`,
`events`, `creds`, `agent`, `migrate`, `sink`, `demo`, `export`, `status`, `service`,
`doctor`, `init`) into its own domain `*_cmds.py` / `*_cli.py` module, and relocated the
shared option definitions, failure-to-exit conversion, and test seams (`IsapiClient`,
`_now`, `_warn_tz_mismatch`, `_migrate_client`, `_migrate_seams`) into
`gateclerk.cli_shared`. This file is now only the root Typer app, the registrations in
their historical `--help` order, and `main()`.
"""

from __future__ import annotations

from typing import Annotated

import typer

from gateclerk import (
    __version__,
    agent_cmds,
    creds_cmds,
    demo_cmds,
    device_cmds,
    doctor_cmds,
    events_cmds,
    export_cmds,
    migrate_cmds,
    service_cmds,
    sink_cmds,
    status_cmds,
    users_cmds,
)
from gateclerk.cli_conventions import (
    AUTH_TERMINAL_EXIT,
    CONFIG_ERROR_EXIT,
    DEVICE_ERROR_EXIT,
    RUNAWAY_EXIT,
)
from gateclerk.cli_shared import (
    DEFAULT_PORT,
    DEFAULT_TIMEOUT,
    DEFAULT_TZ,
    OUTCOME_CHOICES,
    VERIFY_CHOICES,
    IsapiClient,
    _fail,
    _migrate_client,
    _migrate_seams,
    _now,
    _warn_tz_mismatch,
)
from gateclerk.init_cli import init_app

__all__ = [
    "AUTH_TERMINAL_EXIT",
    "CONFIG_ERROR_EXIT",
    "DEFAULT_PORT",
    "DEFAULT_TIMEOUT",
    "DEFAULT_TZ",
    "DEVICE_ERROR_EXIT",
    "OUTCOME_CHOICES",
    "RUNAWAY_EXIT",
    "VERIFY_CHOICES",
    "IsapiClient",
    "_fail",
    "_migrate_client",
    "_migrate_seams",
    "_now",
    "_warn_tz_mismatch",
    "app",
    "main",
]

app = typer.Typer(
    name="gateclerk",
    help=(
        "Hikvision attendance connector: read-only P1 surface (never writes), plus the "
        "E1 enrollment-migration group `gateclerk migrate`, whose writes happen ONLY "
        "under its explicitly gated `apply --apply` (docs/ENROLLMENT-MIGRATION.md §7)."
    ),
    no_args_is_help=True,
    add_completion=False,
    context_settings={"help_option_names": ["-h", "--help"]},
)


def _version_callback(value: bool) -> None:
    """Eager: prints the version and exits before click demands a subcommand."""
    if value:
        typer.echo(f"gateclerk {__version__}")
        raise typer.Exit(code=0)


@app.callback(invoke_without_command=True)
def root(
    version: Annotated[
        bool,
        typer.Option(
            "--version",
            "-V",
            help="Print the version and exit.",
            callback=_version_callback,
            is_eager=True,
        ),
    ] = False,
) -> None:
    """Read-only Hikvision attendance reader. Device writes are never issued."""


def _usage_error_classes() -> tuple[type[BaseException], ...]:
    classes: list[type[BaseException]] = [typer.exceptions.TyperException]
    try:
        import click
    except ImportError:
        pass
    else:  # pragma: no cover
        classes.append(click.UsageError)
    return tuple(classes)


_USAGE_ERRORS = _usage_error_classes()

# Registrations in exact historical order so root `--help` is byte-identical.
device_cmds.register(app)
users_cmds.register(app)
creds_cmds.register(app)
events_cmds.register(app)
agent_cmds.register(app)
migrate_cmds.register(app)
sink_cmds.register(app)
demo_cmds.register(app)
export_cmds.register(app)
status_cmds.register(app)
service_cmds.register(app)
doctor_cmds.register(app)
app.add_typer(init_app)


def main(argv: list[str] | None = None) -> int:
    try:
        result = app(args=argv, prog_name="gateclerk", standalone_mode=False)
    except typer.Exit as exc:
        return int(exc.exit_code)
    except _USAGE_ERRORS as exc:
        exc.show()
        return int(exc.exit_code)
    return 0 if result is None else int(result)


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
