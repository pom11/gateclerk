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

import httpx
import typer

from gateclerk import __version__
from gateclerk import config as cfg
from gateclerk.capabilities import discover
from gateclerk.config import KeychainReader, resolve_credentials, site_from_args
from gateclerk.exceptions import (
    ConfigError,
    CredentialUnavailable,
    IsapiAuthError,
    GateclerkError,
)
from gateclerk.isapi_transport import IsapiClient
from gateclerk.output import CHOICES as OUTPUT_CHOICES
from gateclerk.output import OutputFormat, make_console, render

__all__ = ["CONFIG_ERROR_EXIT", "DEVICE_ERROR_EXIT", "NOT_IMPLEMENTED_EXIT", "app", "main"]

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
creds_app = typer.Typer(
    name="creds",
    help="Credential/config diagnostics. Never contacts the device.",
    no_args_is_help=True,
    context_settings={"help_option_names": ["-h", "--help"]},
)

app.add_typer(device_app)
app.add_typer(users_app)
app.add_typer(events_app)
app.add_typer(creds_app)

#: Distinct from a real failure (1) so a script can tell "not built yet" from "broke".
NOT_IMPLEMENTED_EXIT = 3

#: p1-08's exit-code contract, declared here because p1-02 already needs it: a config or
#: credential failure is a different class of "you have not told me how to reach it" from
#: a device error.
CONFIG_ERROR_EXIT = 2

#: Also from p1-08's contract, declared here because p1-04's `device capabilities` needs
#: it now: the read failed at the protocol/transport boundary rather than in the request —
#: the box answered and said no (or said something we refused to parse), or the host name
#: never made it to the resolver at all (unresolvable, or unencodable: `[Errno 8]`,
#: `UnicodeError`/`idna.IDNAError` from the idna step). Distinct from 2 so a script can
#: tell "fix your config" from "the box, its firmware, or the name you gave me".
DEVICE_ERROR_EXIT = 4

#: p1-08's contract, same reasoning: a terminal 401 (circuit open / lockout risk) is its
#: own class — the transport already refused to retry, and a human has to intervene.
AUTH_TERMINAL_EXIT = 3

# Port / timeout / tz come from gateclerk.config so the CLI default and the config default
# cannot drift apart (p1-01 left these literal here; p1-02 owns the values now).
DEFAULT_PORT = cfg.DEFAULT_PORT
DEFAULT_TIMEOUT = cfg.DEFAULT_TIMEOUT_S
DEFAULT_TZ = cfg.DEFAULT_IANA_TZ

# --- shared options -----------------------------------------------------------------
# Declared once so every device-reading command spells them identically. p1-02 layers
# Keychain + env resolution underneath --user/--password; p1-03 consumes --timeout.
#
# `--host` is optional at the OPTION level (not at the command level): a device is still
# never guessed at, it can now also arrive via `--site` from sites.toml. `_site()` below
# turns "neither given" into a config error (exit 2), which is a different and more useful
# signal than a click usage error.

HostArg = Annotated[
    str | None,
    typer.Option(
        "--host",
        help="Device hostname or IP on the site LAN. Mutually exclusive with --site.",
    ),
]
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
ConfigOpt = Annotated[
    str | None,
    typer.Option(
        "--config",
        help="Path to sites.toml (default ./sites.toml), read only with --site. "
        "This tool never guesses a device: --host or --site is required.",
    ),
]
SiteOpt = Annotated[
    str | None,
    typer.Option(
        "--site",
        help="Name of a site block in sites.toml; supplies --host. Mutually exclusive with --host.",
    ),
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


def _config_exit(console_output: OutputFormat, message: str) -> typer.Exit:
    """Report a config/credential failure the way the format asks and exit 2."""
    if console_output is OutputFormat.JSON:
        render([{"error": message, "exit_code": CONFIG_ERROR_EXIT}], fmt="json")
    else:
        make_console().print(f"[red]error:[/red] {message}", markup=True)
    return typer.Exit(code=CONFIG_ERROR_EXIT)


def _resolve_site(
    *,
    host: str | None,
    site: str | None,
    port: int,
    sites_file: str | None,
    output: OutputFormat,
) -> cfg.SiteConfig:
    """--site NAME reads sites.toml; --host is a one-off. Never a guess."""
    try:
        return site_from_args(site=site, host=host, port=port, config_path=sites_file)
    except ConfigError as exc:
        raise _config_exit(output, str(exc)) from exc


def _resolve_creds(
    target: cfg.DeviceTarget,
    *,
    user: str | None,
    password: str | None,
    output: OutputFormat,
    keychain: KeychainReader | None = None,
) -> cfg.Credentials:
    """Resolve credentials, converting a failure into the documented exit 2.

    ConfigError is caught alongside CredentialUnavailable on purpose: the env rung derives
    per-host variable names from the host (`host_env_prefix`), and a host that sanitizes to
    an empty name (`--host ".."`, `-`, `//`) raises ConfigError from inside that derivation.
    That is the same config class the p1-08 contract already maps to exit 2; letting it
    escape printed an uncaught traceback with exit 1 instead.
    """
    try:
        return resolve_credentials(target, user=user, password=password, keychain=keychain)
    except (CredentialUnavailable, ConfigError) as exc:
        raise _config_exit(output, str(exc)) from exc


def _device_exit(console_output: OutputFormat, message: str) -> typer.Exit:
    """Report a device/protocol failure (exit 4): the box answered, and it was not usable."""
    if console_output is OutputFormat.JSON:
        render([{"error": message, "exit_code": DEVICE_ERROR_EXIT}], fmt="json")
    else:
        make_console().print(f"[red]error:[/red] {message}", markup=True)
    return typer.Exit(code=DEVICE_ERROR_EXIT)


def _auth_exit(console_output: OutputFormat, message: str) -> typer.Exit:
    """Report a terminal 401 (exit 3, p1-08's contract) with the lockout warning attached.

    The number 3 is also NOT_IMPLEMENTED_EXIT for the *stub* commands — deliberately not
    resolved here: within an implemented command 3 can only mean terminal-auth (a stub
    never authenticates), and p1-08 owns the final table. Flagged on the board so the
    orchestrator renumbers deliberately, not by accident, when the stubs die.
    """
    hint = (
        " (the transport circuit-opened to protect against a terminal account lockout — "
        "verify the credential before retrying; see gateclerk creds check)"
    )
    if console_output is OutputFormat.JSON:
        render(
            [{"error": message + hint, "exit_code": AUTH_TERMINAL_EXIT}],
            fmt="json",
        )
    else:
        make_console().print(f"[red]error:[/red] {message}{hint}", markup=True)
    return typer.Exit(code=AUTH_TERMINAL_EXIT)


def _client_for(
    target: cfg.DeviceTarget,
    creds: cfg.Credentials,
    *,
    timeout: float,
    output: OutputFormat,
) -> IsapiClient:
    """Build the read-only client for one device.

    `reveal()` is called here and nowhere else: the plaintext exists from this line to the
    transport's digest object (p1-02's seam). A construction failure is a config problem
    (a bad base_url), so it exits 2 like any other "you have not told me how to reach it".

    The caught pair is deliberate: httpx raises InvalidURL for a malformed URL and it is
    NOT a ValueError subclass (verified against httpx 0.28 — InvalidURL.__mro__ is
    (InvalidURL, Exception, ...)), so `--host "[fe80::1"` would otherwise escape as a raw
    traceback with exit 1 instead of the exit-2 config contract (p1-08).
    """
    try:
        return IsapiClient(
            f"http://{target.host}:{target.port}",
            creds.user,
            creds.password.reveal(),
            read_timeout=timeout,
        )
    except (ValueError, httpx.InvalidURL) as exc:
        raise _config_exit(output, str(exc)) from exc


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
    host: HostArg = None,
    site: SiteOpt = None,
    config: ConfigOpt = None,
    port: PortOpt = DEFAULT_PORT,
    user: UserOpt = None,
    password: PasswordOpt = None,
    timeout: TimeoutOpt = DEFAULT_TIMEOUT,
    output: OutputOpt = OutputFormat.TABLE,
) -> None:
    """Read GET /ISAPI/System/deviceInfo (model, serial, firmware version)."""
    target = _resolve_site(
        host=host, site=site, port=port, sites_file=config, output=output
    ).target()
    _stub(
        "device info",
        "card p1-03 (transport)",
        host=target.host,
        port=target.port,
    )


@device_app.command("time")
def device_time(
    host: HostArg = None,
    site: SiteOpt = None,
    config: ConfigOpt = None,
    port: PortOpt = DEFAULT_PORT,
    user: UserOpt = None,
    password: PasswordOpt = None,
    timeout: TimeoutOpt = DEFAULT_TIMEOUT,
    output: OutputOpt = OutputFormat.TABLE,
) -> None:
    """Read GET /ISAPI/System/time (device clock, tz, skew vs our clock)."""
    target = _resolve_site(
        host=host, site=site, port=port, sites_file=config, output=output
    ).target()
    _stub(
        "device time",
        "cards p1-03 (transport) + p1-06 (tz/skew)",
        host=target.host,
        port=target.port,
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
    target = _resolve_site(host=host, site=site, port=port, sites_file=config, output=fmt).target()
    creds = _resolve_creds(target, user=user, password=password, output=fmt)
    with _client_for(target, creds, timeout=timeout, output=fmt) as client:
        try:
            caps = discover(client, force_refresh=refresh)
        except IsapiAuthError as exc:
            raise _auth_exit(fmt, str(exc)) from exc
        except GateclerkError as exc:
            raise _device_exit(fmt, str(exc)) from exc
    if fmt is OutputFormat.JSON:
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


# --- users --------------------------------------------------------------------------


@users_app.command("list")
def users_list(
    host: HostArg = None,
    site: SiteOpt = None,
    config: ConfigOpt = None,
    port: PortOpt = DEFAULT_PORT,
    user: UserOpt = None,
    password: PasswordOpt = None,
    timeout: TimeoutOpt = DEFAULT_TIMEOUT,
    output: OutputOpt = OutputFormat.TABLE,
) -> None:
    """Paged roster via POST /ISAPI/AccessControl/UserInfo/Search."""
    target = _resolve_site(
        host=host, site=site, port=port, sites_file=config, output=output
    ).target()
    _stub(
        "users list",
        "cards p1-03 (paging) + p1-07 (UserRecord)",
        host=target.host,
        port=target.port,
    )


# --- events -------------------------------------------------------------------------


@events_app.command("search")
def events_search(
    host: HostArg = None,
    since: Annotated[
        str | None,
        typer.Option("--since", help="Window start, ISO-8601 (naive values read in --tz)."),
    ] = None,
    until: Annotated[str | None, typer.Option("--until", help="Window end, ISO-8601.")] = None,
    site: SiteOpt = None,
    config: ConfigOpt = None,
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
    target = _resolve_site(
        host=host, site=site, port=port, sites_file=config, output=output
    ).target()
    _stub(
        "events search",
        "cards p1-03 (paging) + p1-06 (time) + p1-07 (EventRecord)",
        host=target.host,
        port=target.port,
        since=since,
        until=until,
        tz=tz,
    )


# --- creds (p1-02): diagnostics that never open a socket ------------------------------


@creds_app.command("check")
def creds_check(
    host: HostArg = None,
    site: SiteOpt = None,
    config: ConfigOpt = None,
    port: PortOpt = DEFAULT_PORT,
    user: UserOpt = None,
    password: PasswordOpt = None,
    output: OutputOpt = OutputFormat.TABLE,
) -> None:
    """Resolve the credential for a device and report the SOURCE. No network, no device.

    This is the command the orchestrator uses to verify the live Keychain path once
    (card p1-02 DoD) without p1-03's transport existing yet: it exercises flags, env and
    `security find-generic-password`, prints `admin@host via keychain`, and never prints
    the password. Exit 2 with the exact `security` command to run when resolution fails.
    """
    target = _resolve_site(
        host=host, site=site, port=port, sites_file=config, output=output
    ).target()
    creds = _resolve_creds(target, user=user, password=password, output=output)
    render(
        [
            {
                "site": target.site,
                "host": target.host,
                "port": target.port,
                "user": creds.user,
                "source": creds.source.value,
                "password": "***",
            }
        ],
        fmt=output.value,
        columns=("site", "host", "port", "user", "source", "password"),
    )


@creds_app.command("explain")
def creds_explain(
    host: str,
    port: PortOpt = DEFAULT_PORT,
    output: OutputOpt = OutputFormat.TABLE,
) -> None:
    """Print where this host's credential WOULD be looked for. Reads nothing, resolves nothing."""
    rows = [
        {
            "rung": 1,
            "source": "flag",
            "where": "--user / --password",
            "detail": "highest precedence; one-off debugging (lands in shell history)",
        },
        {
            "rung": 2,
            "source": "env",
            "where": ", ".join(cfg.env_var_names(host)[:2]),
            "detail": "per-host beats global",
        },
        {
            "rung": 3,
            "source": "env",
            "where": ", ".join(cfg.env_var_names(host)[2:]),
            "detail": "global fallback (a gitignored .env feeds this rung)",
        },
        {
            "rung": 4,
            "source": "keychain",
            "where": cfg.DeviceTarget(host=host, port=port).find_command(),
            "detail": "comment field carries user=<isapi_user>",
        },
        {
            "rung": 5,
            "source": "keychain",
            "where": cfg.DeviceTarget(host=host, port=port).add_command(),
            "detail": "creates the item; -w last so the password is prompted, not argv",
        },
    ]
    render(rows, fmt=output.value, columns=("rung", "source", "where", "detail"))


#: Exception classes that mean "click/typer refused your command line" (exit 2), for
#: whichever typer layout is installed. typer >= 0.25 vendors click as `typer._click`, so
#: its UsageError derives from the public `typer.exceptions.TyperException` and the plain
#: `import click` below fails; older typer re-exported click's UsageError, which derives
#: from RuntimeError and is NOT a TyperException — hence the optional click rung rather
#: than one class name. `typer.exceptions.UsageError` (what this file used to name) has
#: never existed in any typer release: on typer 0.27 the `except` clause itself raised
#: AttributeError, so `main()` exited 1 with a traceback on every usage error.
def _usage_error_classes() -> tuple[type[BaseException], ...]:
    classes: list[type[BaseException]] = [typer.exceptions.TyperException]
    try:
        import click  # optional rung: only present on typer < 0.25
    except ImportError:
        pass
    else:  # pragma: no cover — depends on the installed typer layout
        classes.append(click.UsageError)
    return tuple(classes)


_USAGE_ERRORS = _usage_error_classes()


def main(argv: list[str] | None = None) -> int:
    """Console entry point. Returns an exit code instead of calling sys.exit()."""
    try:
        result = app(args=argv, prog_name="gateclerk", standalone_mode=False)
    except typer.Exit as exc:  # raised by --version and by every stub
        return int(exc.exit_code)
    except _USAGE_ERRORS as exc:  # click/typer refused the command line: exit 2
        exc.show()
        return int(exc.exit_code)
    return 0 if result is None else int(result)


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
