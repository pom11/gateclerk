"""The shared CLI furniture: option spellings, hidden-alias groups, failure-to-exit.

CLI-SPLIT-STRUCTURE moved this out of `gateclerk.cli` (the merge-collision generator)
together with the `agent` / `sink` / `demo` command groups. It is the module every command
module may import — `cli.py` imports it too, so a shared flag spelling, a shared option
default and the failure-to-exit renderer exist EXACTLY ONCE for the whole surface. The
dependency direction is a law, not a style note:

    gateclerk.cli  ->  gateclerk.cli_shared, gateclerk.agent_cmds, gateclerk.sink_cmds,
                     gateclerk.demo_cmds, <domain modules>
    <cmd module>   ->  gateclerk.cli_shared                  (NEVER -> gateclerk.cli)

What belongs here, and why nothing else does:

* `_alias_group` — CLI-VERBS-HELP's hidden-alias click class. Every group carrying a
  superseded spelling needs it, including the groups that now live in their own module.
* The shared `Annotated[...]` option aliases (HostArg … CountOpt) and the agent group's
  site/config/state-root trio, which the `sink` group reuses. `tests/_cli_surface.py`
  reads declared flags from the Click definition, so these help strings and defaults ARE
  the pinned surface; a second copy of a help string is a surface that can drift.
* The failure-to-exit conversion (`_config_exit` … `_Guard`). The exit-code CONTRACT and
  its numbers live in `gateclerk.cli_conventions`; what lives here is the per-class payload
  and renderer that turns a failure into the documented number.

Nothing in this module builds a `typer.Typer` or registers a command — that is exactly
what keeps it importable from any command module without an import cycle.
"""

from __future__ import annotations

from typing import Annotated, Any

import typer
from typer.core import TyperGroup

from gateclerk.cli_conventions import (
    AUTH_TERMINAL_EXIT,
    CONFIG_ERROR_EXIT,
    DEVICE_ERROR_EXIT,
    RUNAWAY_EXIT,
    resolve_alias,
)
from gateclerk.cli_conventions import exit_code_for as _exit_code_for
from gateclerk.output import CHOICES as OUTPUT_CHOICES
from gateclerk.output import OutputFormat, make_console, render
from gateclerk.pipeline import DEFAULT_SITE_LABEL


#: The click class for a group whose verb vocabulary was normalized by CLI-VERBS-HELP: it
#: accepts the superseded spellings declared in ``cli_conventions.ALIASES`` on the command
#: line WITHOUT declaring them.
#:
#: Why a subclass rather than a second ``@creds_app.command("check")`` on the same
#: function: a registered alias lands in ``Group.commands``, so it shows up in ``--help``
#: and in every "the surface is exactly these commands" test. Two spellings printed side by
#: side teach the operator nothing about which one to type, and a surface test that has to
#: allow both stops catching real additions. Resolving in ``get_command`` keeps the DECLARED
#: surface at one spelling per operation while every existing script, cron wrapper and
#: muscle memory keeps working.
#:
#: A subclass per group, not one class with a mutable attribute: two groups sharing a class
#: would share whichever path was assigned last, so `creds`'s aliases would silently apply
#: inside `agent deadletter`. A closure over `path` cannot drift.
def _alias_group(path: tuple[str, ...]) -> type[TyperGroup]:
    class _Group(TyperGroup):
        def get_command(self, ctx: Any, cmd_name: str) -> Any:
            command = super().get_command(ctx, cmd_name)
            if command is not None:
                return command
            # Consulted only after the real lookup missed, so an alias can never shadow a
            # real command and an unknown name still reaches click and exits 2 (usage).
            canonical = resolve_alias(path, cmd_name)
            return super().get_command(ctx, canonical) if canonical is not None else None

    _Group.__name__ = f"AliasGroup_{'_'.join(path)}"
    return _Group


# --- shared options -----------------------------------------------------------------
# Declared once so every device-reading command spells them identically. p1-02 layers
# Keychain + env resolution underneath --user/--password; p1-03 consumes --timeout.
#
# `--host` is optional at the OPTION level (not at the command level): a device is still
# never guessed at, it can now also arrive via `--site` from sites.toml.
# `gateclerk.cli._resolve_site()` below turns "neither given" into a config error (exit 2),
# which is a different and more
# useful signal than a click usage error.

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
VerboseOpt = Annotated[
    bool,
    typer.Option(
        "--verbose",
        "-v",
        help="Log every ISAPI request (method, path, headers, body) to stderr before it is "
        "sent. The Authorization header is withheld — it is credential-derived. Goes to "
        "stderr so `--format jsonl > out.jsonl` stays parseable with this on.",
    ),
]
SiteLabelOpt = Annotated[
    str | None,
    typer.Option(
        "--site-label",
        help=f"Free-text label stamped onto every record (default: the --site name, else "
        f"{DEFAULT_SITE_LABEL!r}). DESIGN.md open question 3: until a punch joins to a BC "
        "location code this is the agent's own name for itself. Separate from --site "
        "because --site is p1-02's sites.toml selector and cannot mean two things.",
    ),
]
TzOpt = Annotated[
    str,
    typer.Option(
        "--tz",
        help="IANA zone used to interpret naive --since/--until and to resolve event times "
        "(DESIGN.md: site-tz is primary, the device's own offset is never trusted).",
    ),
]
CountOpt = Annotated[
    bool,
    typer.Option(
        "--count",
        help="Cross-check the row count against the device's own count endpoint and print "
        "the comparison. DISPLAY ONLY — never a loop bound (DESIGN.md: totalMatches is "
        "advisory, and AcsEvent/Total is not supported on this firmware).",
    ),
]


#: `--site` is REQUIRED here, unlike the CLI's `--site`/`--host` pair: one unit is one site and
#: the systemd instance name (`%i`) is the only thing that selects it. There is no `--host`
#: because a site's device hosts belong to sites.toml, not to whoever typed the command line.
AgentSiteOpt = Annotated[
    str,
    typer.Option("--site", help="Site block to serve (the systemd instance name, %i)."),
]
AgentConfigOpt = Annotated[
    str | None,
    typer.Option("--config", help="sites.toml to read (default ./sites.toml). Refs only."),
]
AgentStateRootOpt = Annotated[
    str | None,
    typer.Option(
        "--state-root",
        help="Where this site's store, park dir and health snapshot live. A relative db_path "
        "(and the derived ./gateclerk-<site>.sqlite3) resolves under it.",
    ),
]
AgentCredentialsDirOpt = Annotated[
    str | None,
    typer.Option(
        "--credentials-dir",
        help="Where the systemd credential files are (default: $CREDENTIALS_DIRECTORY, which "
        "the unit sets). A LoadCredential= reference arrives as a FILE, not an env var.",
    ),
]
AgentPasswordOpt = Annotated[
    str | None,
    typer.Option(
        "--password",
        help="Override the ISAPI password for every device of this site. Discouraged "
        "(shell history); resolution stays flag > env > keychain.",
        hide_input=True,
    ),
]


# --- failure-to-exit-code conversion ------------------------------------------------


def _error_payload(fmt: OutputFormat, message: str, code: int) -> None:
    """Print a failure the way the requested format asks (jsonl included: it is json)."""
    if fmt is OutputFormat.JSON or fmt is OutputFormat.JSONL:
        render([{"error": message, "exit_code": code}], fmt=fmt.value)
    else:
        make_console().print(f"[red]error:[/red] {message}", markup=True)


def _config_exit(fmt: OutputFormat, message: str) -> typer.Exit:
    """Report a config/credential/bad-flag failure (exit 2)."""
    _error_payload(fmt, message, CONFIG_ERROR_EXIT)
    return typer.Exit(code=CONFIG_ERROR_EXIT)


def _device_exit(fmt: OutputFormat, message: str) -> typer.Exit:
    """Report a device/protocol failure (exit 4): the box answered, and it was not usable."""
    _error_payload(fmt, message, DEVICE_ERROR_EXIT)
    return typer.Exit(code=DEVICE_ERROR_EXIT)


def _auth_exit(fmt: OutputFormat, message: str) -> typer.Exit:
    """Report a terminal 401 (exit 3) with the lockout warning attached.

    The warning is not decoration: at three sites a wrong password in a deployed poller
    locks the admin account, and the same account is what opens the door. The transport
    already stopped retrying; the human has to verify the credential by hand.
    """
    hint = (
        " (the transport circuit-opened to protect against a terminal account lockout — "
        "verify the credential before retrying; see gateclerk creds test)"
    )
    _error_payload(fmt, message + hint, AUTH_TERMINAL_EXIT)
    return typer.Exit(code=AUTH_TERMINAL_EXIT)


def _runaway_exit(fmt: OutputFormat, message: str) -> typer.Exit:
    """Report the paging cap (exit 5): the device kept saying MORE past 10k pages."""
    _error_payload(
        fmt,
        message + " (the paging engine refused to loop forever on a device that misbehaves; "
        "narrow --since/--until or check the device's log ring)",
        RUNAWAY_EXIT,
    )
    return typer.Exit(code=RUNAWAY_EXIT)


def _classify(exc: BaseException) -> int:
    """`cli_conventions.exit_code_for`, with unclassified exceptions re-raising THEMSELVES.

    `exit_code_for` reports an unknown class as a `KeyError` naming it — right for a
    lookup, wrong here: p1-08's `_fail` ended in `raise exc` so the traceback shows the
    module that actually has the bug, and a `KeyError` substituting for it would hide it.
    `from None` drops the KeyError from the chain so the traceback reads as it did before.

    Exit 1 is deliberately NOT a catch-all: an unclassified crash must not read as an
    expected, branchable failure (see the conventions module's table, code 1).
    """
    try:
        return _exit_code_for(exc)
    except KeyError:
        raise exc from None


def _fail(fmt: OutputFormat, exc: BaseException) -> typer.Exit:
    """Map any exception escaping a command body onto the documented exit code.

    The CLASSIFICATION lives in `gateclerk.cli_conventions.exit_code_for` — the one place a
    new exception class can be added — and this function owns only the per-class message
    and payload. That split is what keeps the numbers from drifting: the mapping is not
    restated here, so a command body cannot pick a different code for the same failure and
    the conventions module's table stays the truth a reviewer can read.

    `TimestampInputError` and `EventBoundsError` land on 2 on purpose: both mean a value
    the operator typed was unusable, which is the "fix your input" class, not "the box is
    broken". `SearchProtocolError` lands on 4: the device changed shape on us.
    """
    code = _classify(exc)
    if code == AUTH_TERMINAL_EXIT:
        return _auth_exit(fmt, str(exc))
    if code == RUNAWAY_EXIT:
        return _runaway_exit(fmt, str(exc))
    if code == CONFIG_ERROR_EXIT:
        return _config_exit(fmt, str(exc))
    return _device_exit(fmt, str(exc))


#: `IsapiError` and the other classes in the import block above were used by the inline
#: isinstance chain that `_fail` carried; the chain now lives in
#: `gateclerk.cli_conventions.exit_code_for`, so the classes are no longer named here.


class _Guard:
    """Context manager: `with _Guard(fmt): ...` turns any GateClerkError into its exit code.

    Commands are written straight-line — resolve site, resolve creds, open client, read —
    and every one of those steps can fail. Repeating a six-branch try/except in each body
    is how one body ends up mapping a failure differently from its neighbour, so the
    conversion lives here and the bodies stay readable.

    Note what this does NOT cover: a read that happens *inside* the `with` and whose result
    is consumed *after* it. A `pipeline` call that raises in there exits from `__exit__`, so
    the lines below the block never run and no half-built record is ever rendered. Anything
    that must inspect a result on an error path (the `--json` passthroughs) assigns its own
    name inside the block and re-raises, rather than letting the failure slip past the guard.
    """

    def __init__(self, fmt: OutputFormat) -> None:
        self._fmt = fmt

    def __enter__(self) -> _Guard:
        return self

    def __exit__(self, exc_type: object, exc: BaseException | None, tb: object) -> bool:
        if exc is None:
            return False
        raise _fail(self._fmt, exc) from exc
