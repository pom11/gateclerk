"""`gateclerk` command line.

P1 surface (docs/DESIGN.md, phase plan): `device info`, `device time`, `users list`,
`events --since/--until`. This scaffold wires the command tree, the shared flags and
the output formats; each command body is filled in by its own card. The stubs exit
NOT_IMPLEMENTED_EXIT (3) and name the card that owns the implementation, so a
half-built command can never be mistaken for a working one.

Connection flags are declared ONCE here — they are the interface between p1-02
(credential resolution), p1-03 (transport) and the command bodies. Later cards fill in
behaviour behind these names; they do not invent new spellings of `--host`.
"""

from __future__ import annotations

from typing import Annotated

import typer

from gateclerk import __version__
from gateclerk.output import CHOICES as OUTPUT_CHOICES
from gateclerk.output import OutputFormat, make_console

__all__ = ["NOT_IMPLEMENTED_EXIT", "app", "main"]

app = typer.Typer(
    name="gateclerk",
    help="Read-only Hikvision attendance reader (P1). Never writes to the device.",
    no_args_is_help=True,
    add_completion=False,
    context_settings={"help_option_names": ["-h", "--help"]},
)

device_app = typer.Typer(
    name="device",
    help="Single-device reads (info, clock).",
    no_args_is_help=True,
    context_settings={"help_option_names": ["-h", "--help"]},
)
users_app = typer.Typer(
    name="users",
    help="Employee roster reads.",
    no_args_is_help=True,
    context_settings={"help_option_names": ["-h", "--help"]},
)
events_app = typer.Typer(
    name="events",
    help="Punch event reads.",
    no_args_is_help=True,
    context_settings={"help_option_names": ["-h", "--help"]},
)

app.add_typer(device_app)
app.add_typer(users_app)
app.add_typer(events_app)

#: Distinct from a real failure (1) so a script can tell "not built yet" from "broke".
NOT_IMPLEMENTED_EXIT = 3

DEFAULT_PORT = 80
DEFAULT_TIMEOUT = 30.0
DEFAULT_TZ = "Europe/Bucharest"

# --- shared options -----------------------------------------------------------------
# Declared once so every device-reading command spells them identically. p1-02 layers
# Keychain + env resolution underneath --user/--password; p1-03 consumes --timeout.

HostArg = Annotated[str, typer.Option("--host", help="Device hostname or IP on the site LAN.")]
PortOpt = Annotated[
    int, typer.Option("--port", help="ISAPI port. P1 targets HTTP:80; TLS is out of scope.")
]
UserOpt = Annotated[
    str | None,
    typer.Option("--user", help="Override the ISAPI user. Prefer Keychain/env — see README."),
]
PasswordOpt = Annotated[
    str | None,
    typer.Option(
        "--password",
        help="Override the ISAPI password. Discouraged (it lands in shell history). "
        "Resolution order: flag > GATECLERK_* env > macOS Keychain (service gateclerk-hikvision).",
        hide_input=True,
    ),
]
TimeoutOpt = Annotated[
    float,
    typer.Option("--timeout", min=1.0, help="Read timeout in seconds (connect timeout is 10s)."),
]
OutputOpt = Annotated[
    OutputFormat,
    typer.Option(
        "--output",
        "-o",
        case_sensitive=False,
        help=f"Output format ({', '.join(OUTPUT_CHOICES)}). json is the stable machine form.",
    ),
]
TzOpt = Annotated[
    str,
    typer.Option("--tz", help="IANA zone used to interpret naive --since/--until (p1-06)."),
]


def _stub(what: str, owners: str, **resolved: object) -> None:
    """The one stub failure every unbuilt command shares.

    Prints the owning card(s) and the resolved request shape — never a credential — so
    the next card can see the flag plumbing already works end to end, then exits with a
    code that is not a crash.
    """
    detail = " ".join(f"{k}={v}" for k, v in resolved.items() if v is not None)
    make_console().print(
        f"[red]error:[/red] `gateclerk {what}` is a scaffold stub, not implemented — "
        f"owned by {owners}. Resolved request: {detail}",
        markup=True,
    )
    raise typer.Exit(code=NOT_IMPLEMENTED_EXIT)


# --- root ---------------------------------------------------------------------------


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


# --- device -------------------------------------------------------------------------


@device_app.command("info")
def device_info(
    host: HostArg,
    port: PortOpt = DEFAULT_PORT,
    user: UserOpt = None,
    password: PasswordOpt = None,
    timeout: TimeoutOpt = DEFAULT_TIMEOUT,
    output: OutputOpt = OutputFormat.TABLE,
) -> None:
    """Read GET /ISAPI/System/deviceInfo (model, serial, firmware version)."""
    _stub("device info", "cards p1-03 (transport) + p1-02 (credentials)", host=host, port=port)


@device_app.command("time")
def device_time(
    host: HostArg,
    port: PortOpt = DEFAULT_PORT,
    user: UserOpt = None,
    password: PasswordOpt = None,
    timeout: TimeoutOpt = DEFAULT_TIMEOUT,
    output: OutputOpt = OutputFormat.TABLE,
) -> None:
    """Read GET /ISAPI/System/time (device clock, tz, skew vs our clock)."""
    _stub("device time", "cards p1-03 (transport) + p1-06 (tz/skew)", host=host, port=port)


# --- users --------------------------------------------------------------------------


@users_app.command("list")
def users_list(
    host: HostArg,
    port: PortOpt = DEFAULT_PORT,
    user: UserOpt = None,
    password: PasswordOpt = None,
    timeout: TimeoutOpt = DEFAULT_TIMEOUT,
    output: OutputOpt = OutputFormat.TABLE,
) -> None:
    """Paged roster via POST /ISAPI/AccessControl/UserInfo/Search."""
    _stub("users list", "cards p1-03 (paging) + p1-07 (UserRecord)", host=host, port=port)


# --- events -------------------------------------------------------------------------


@events_app.command("search")
def events_search(
    host: HostArg,
    since: Annotated[
        str | None,
        typer.Option("--since", help="Window start, ISO-8601 (naive values read in --tz)."),
    ] = None,
    until: Annotated[str | None, typer.Option("--until", help="Window end, ISO-8601.")] = None,
    port: PortOpt = DEFAULT_PORT,
    user: UserOpt = None,
    password: PasswordOpt = None,
    timeout: TimeoutOpt = DEFAULT_TIMEOUT,
    tz: TzOpt = DEFAULT_TZ,
    output: OutputOpt = OutputFormat.TABLE,
) -> None:
    """Paged punches via POST /ISAPI/AccessControl/AcsEvent, normalized.

    DESIGN.md names this command `gateclerk events --since/--until`; it is a subcommand
    here because the events group will also grow export/stats verbs.
    """
    _stub(
        "events search",
        "cards p1-03 (paging) + p1-06 (time) + p1-07 (EventRecord)",
        host=host,
        port=port,
        since=since,
        until=until,
        tz=tz,
    )


def main(argv: list[str] | None = None) -> int:
    """Console entry point. Returns an exit code instead of calling sys.exit()."""
    try:
        result = app(args=argv, prog_name="gateclerk", standalone_mode=False)
    except typer.Exit as exc:  # raised by --version and by every stub
        return int(exc.exit_code)
    except typer.exceptions.UsageError as exc:
        exc.show()
        return int(exc.exit_code)
    return 0 if result is None else int(result)


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
