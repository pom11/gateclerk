"""`gateclerk` command line — the P1 read-only surface (card p1-08).

Four device-reading commands, all wired end to end against `gateclerk.paging`,
`gateclerk.model` and `gateclerk.pipeline`, plus the two credential diagnostics from p1-02:

    gateclerk device info | time | capabilities
    gateclerk users list
    gateclerk events --since --until
    gateclerk creds check | explain

Exit codes are the card's contract and are stable per class of failure:

    0  ok
    2  config / credential error (also: a malformed flag value — "you have not told me
       how to reach it", or what you told me is not usable)
    3  terminal auth failure (the transport circuit-opened to avoid a lockout)
    4  device / protocol error (the box answered and it was not usable)
    5  runaway paging cap (the device kept saying MORE past 10k pages)

Nothing here contacts a device by itself; `IsapiClient` is constructed in `_client_for`
and every endpoint name reaching it is a registry entry (see `gateclerk.endpoints`).

Command-name note: the card and DESIGN.md's phase plan both name `gateclerk events
--since/--until` (flat). The p1-01 scaffold had it as `events search` on the theory that
the group would later grow export/stats verbs; those verbs are P2/P3 and uncarded, so the
flat spelling wins and the `events` group is gone. `users` and `device` stay groups
because the card names them as groups (`users list`, `device info`).
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated, Any

import httpx
import typer

from gateclerk import __version__, pipeline
from gateclerk import config as cfg
from gateclerk.capabilities import device_identity
from gateclerk.config import KeychainReader, resolve_credentials, site_from_args
from gateclerk.exceptions import (
    ConfigError,
    CredentialUnavailable,
    EventBoundsError,
    IsapiAuthError,
    GateclerkError,
    SearchProtocolError,
    SearchRunawayError,
)
from gateclerk.isapi_transport import IsapiClient
from gateclerk.output import CHOICES as OUTPUT_CHOICES
from gateclerk.output import OutputFormat, make_console, render
from gateclerk.paging import DEFAULT_CHUNK, parse_chunk
from gateclerk.pipeline import DEFAULT_SITE_LABEL, RequestLogger, RunContext
from gateclerk.tz import (
    SKEW_WARN_SECONDS,
    DeviceTime,
    TimestampInputError,
    UserTimestamp,
    compute_skew,
    offset_hhmm,
    parse_user_timestamp,
)
from gateclerk.tz_mismatch import is_offset_mismatch, site_offset_minutes

__all__ = [
    "AUTH_TERMINAL_EXIT",
    "CONFIG_ERROR_EXIT",
    "DEVICE_ERROR_EXIT",
    "RUNAWAY_EXIT",
    "app",
    "main",
]

app = typer.Typer(
    name="gateclerk",
    help="Read-only Hikvision attendance reader (P1). Never writes to the device.",
    no_args_is_help=True,
    add_completion=False,
    context_settings={"help_option_names": ["-h", "--help"]},
)

device_app = typer.Typer(
    name="device",
    help="Single-device reads (identity, clock, capabilities).",
    no_args_is_help=True,
    context_settings={"help_option_names": ["-h", "--help"]},
)
users_app = typer.Typer(
    name="users",
    help="Employee roster reads.",
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
app.add_typer(creds_app)

#: p1-08's exit-code contract, declared here because other cards' tests import them:
#: a config or credential failure is a different class of "you have not told me how to
#: reach it" from a device error.
CONFIG_ERROR_EXIT = 2

#: Also from p1-08's contract, declared here because p1-04's `device capabilities` needs
#: it now: the read failed at the protocol/transport boundary rather than in the request —
#: the box answered and said no (or said something we refused to parse), or the host name
#: never made it to the resolver at all (unresolvable, or unencodable: `[Errno 8]`,
#: `UnicodeError`/`idna.IDNAError` from the idna step). Distinct from 2 so a script can
#: tell "fix your config" from "the box, its firmware, or the name you gave me".
DEVICE_ERROR_EXIT = 4

#: A terminal 401 (circuit open / lockout risk) is its own class — the transport already
#: refused to retry, and a human has to intervene.
#:
#: RESOLVED at this card (p1-08's own contract asked for the renumber): p1-01's
#: NOT_IMPLEMENTED_EXIT was also 3, which made "not built yet" and "authenticated and
#: refused" the same number. Every scaffold stub is now implemented, so the stub code is
#: gone and 3 means terminal-auth and nothing else.
AUTH_TERMINAL_EXIT = 3

#: The runaway paging cap (p1-08: "5 runaway-cap"). p1-05 raises
#: `SearchRunawayError` rather than loop forever; this is the number a cron wrapper reads
#: to distinguish "the device is misbehaving" from "my network is down".
RUNAWAY_EXIT = 5

# Port / timeout / tz come from gateclerk.config so the CLI default and the config default
# cannot drift apart.
DEFAULT_PORT = cfg.DEFAULT_PORT
DEFAULT_TIMEOUT = cfg.DEFAULT_TIMEOUT_S
DEFAULT_TZ = cfg.DEFAULT_IANA_TZ

#: The `--verify` values we accept. OBSERVED.md is why this is a *question about the
#: field*, not a claim about the device: site-a reports `cardOrFaceOrFp` on every real
#: pass and cannot say which of the three it was, so `--verify face` asks "could this
#: have been a face pass". Restricting the flag to these four keeps a typo (`--verify
#: finger`) from silently filtering everything out — an empty table is the output that
#: reads as "nobody clocked in".
VERIFY_CHOICES = ("face", "card", "fp", "password")

#: `--outcome` values, from the model's own enum so the CLI cannot advertise a verdict
#: the record cannot carry.
OUTCOME_CHOICES = ("granted", "denied", "info")


# --- shared options -----------------------------------------------------------------
# Declared once so every device-reading command spells them identically. p1-02 layers
# Keychain + env resolution underneath --user/--password; p1-03 consumes --timeout.
#
# `--host` is optional at the OPTION level (not at the command level): a device is still
# never guessed at, it can now also arrive via `--site` from sites.toml. `_resolve_site()`
# below turns "neither given" into a config error (exit 2), which is a different and more
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
        "verify the credential before retrying; see gateclerk creds check)"
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


def _fail(fmt: OutputFormat, exc: BaseException) -> typer.Exit:
    """Map any exception escaping a command body onto the documented exit code.

    One function, so a command body cannot pick a different mapping for the same failure
    and so a new exception class has exactly one place to be added. The order matters:
    `IsapiAuthError` is an `IsapiError`, and `SearchRunawayError`/`SearchProtocolError`
    are `GateclerkError`s, so the specific classes must be tested before the general ones.

    `TimestampInputError` and `EventBoundsError` land on 2 on purpose: both mean a value
    the operator typed was unusable, which is the "fix your input" class, not "the box is
    broken". `SearchProtocolError` lands on 4: the device changed shape on us.
    """
    if isinstance(exc, IsapiAuthError):
        return _auth_exit(fmt, str(exc))
    if isinstance(exc, SearchRunawayError):
        return _runaway_exit(fmt, str(exc))
    if isinstance(exc, (ConfigError, CredentialUnavailable, TimestampInputError, EventBoundsError)):
        return _config_exit(fmt, str(exc))
    if isinstance(exc, (SearchProtocolError, IsapiError)):
        return _device_exit(fmt, str(exc))
    if isinstance(exc, GateclerkError):
        return _device_exit(fmt, str(exc))
    raise exc


#: `IsapiError` is imported for the isinstance check above; the name is bound here so the
#: import block at the top stays the single list of what this module depends on.
from gateclerk.exceptions import IsapiError  # noqa: E402  (after _fail's definition reads better)


class _Guard:
    """Context manager: `with _Guard(fmt): ...` turns any GateclerkError into its exit code.

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


# --- resolution helpers ---------------------------------------------------------------


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


def _client_for(
    target: cfg.DeviceTarget,
    creds: cfg.Credentials,
    *,
    timeout: float,
    output: OutputFormat,
    logger: RequestLogger | None = None,
) -> Any:
    """Build the read-only client for one device, wrapped for logging when asked.

    `reveal()` is called here and nowhere else: the plaintext exists from this line to the
    transport's digest object (p1-02's seam). A construction failure is a config problem
    (a bad base_url), so it exits 2 like any other "you have not told me how to reach it".

    The caught pair is deliberate: httpx raises InvalidURL for a malformed URL and it is
    NOT a ValueError subclass (verified against httpx 0.28 — InvalidURL.__mro__ is
    (InvalidURL, Exception, ...)), so `--host "[fe80::1"` would otherwise escape as a raw
    traceback with exit 1 instead of the exit-2 config contract (p1-08).

    With `--verbose` the client is wrapped in `pipeline.LoggedClient`, which logs every
    request it carries — including the three GETs `capabilities.discover()` opens on its
    own, without that module having to know logging exists.
    """
    try:
        client = IsapiClient(
            f"http://{target.host}:{target.port}",
            creds.user,
            creds.password.reveal(),
            read_timeout=timeout,
        )
    except (ValueError, httpx.InvalidURL) as exc:
        raise _config_exit(output, str(exc)) from exc
    if logger is None:
        return client
    return pipeline.LoggedClient(client, logger)


def _iso(value: datetime | None) -> str | None:
    """ISO-8601 for a datetime a record may not have. None stays None.

    `to_dict()` in the model does the same thing for the same reason — a missing timestamp
    is `null` in JSON and `-` in the table, never the string "None" — and the CLI's own
    views need that rule in three commands, so it is a function rather than three copies of
    a conditional expression.
    """
    return None if value is None else value.isoformat()


def _nested(body: Mapping[str, Any], key: str) -> Any:
    """Read `key` from a deviceInfo body, at the top level or one wrapper deep.

    This firmware answers deviceInfo as XML despite `?format=json`, and `parse_body`
    flattens that into `{"DeviceInfo": {...}}`. A human table wants the fields either way,
    so the lookup tolerates both the wrapped and the flat spelling — the same tolerance
    `capabilities.device_identity` already applies for the same reason.

    One level only, deliberately: `capabilities._flatten` is the module that knows this
    firmware's XML shapes, and a second deep-walker in the CLI would be a second dialect to
    keep correct.
    """
    if key in body:
        return body[key]
    for value in body.values():
        if isinstance(value, Mapping) and key in value:
            return value[key]
    return None


def _logger_for(verbose: bool, creds: cfg.Credentials | None) -> RequestLogger | None:
    """The verbose logger, or None. Built after creds so the password can be redacted."""
    if not verbose:
        return None
    secrets: list[Any] = []
    if creds is not None:
        secrets.append(creds.password)
    return RequestLogger(secrets=tuple(secrets))


def _validate_choice(
    fmt: OutputFormat, value: str | None, *, flag: str, allowed: tuple[str, ...]
) -> None:
    """Reject an unknown `--verify`/`--outcome` as exit 2 rather than filtering to nothing.

    An empty result set is the most dangerous output this tool produces — it looks like a
    quiet day, not like a typo. Failing loudly on the flag is the cheaper truth.
    """
    if value is None:
        return
    if value.strip().lower() not in allowed:
        raise _config_exit(
            fmt, f"{flag} {value!r} is not one of {', '.join(allowed)} (case-insensitive)"
        )


def _resolve_window(
    *,
    since: str | None,
    until: str | None,
    site_tz: str,
    fmt: OutputFormat,
) -> tuple[UserTimestamp, UserTimestamp]:
    """Parse --since/--until into instants. Both are required; a bad value exits 2.

    Required because DESIGN.md forbids an unbounded history walk ("some fw answers an
    unbounded query with `Invalid Content`", and a full-history pull is not what payroll
    asks for). A missing bound is therefore a usage error on this command, not a default.
    """
    try:
        start = parse_user_timestamp(since, site_tz=site_tz, field_name="--since")
        end = parse_user_timestamp(until, site_tz=site_tz, field_name="--until")
    except TimestampInputError as exc:
        raise _config_exit(fmt, str(exc)) from exc
    return start, end


def _resolved_site_tz(
    *,
    tz: str | None,
    site: cfg.SiteConfig,
    fmt: OutputFormat,
    ctx: Any = None,
) -> tuple[str, bool]:
    """The zone the run resolves punches in, as `(zone, mapping_in_play)`.

    Base precedence: `--tz` beats sites.toml's `iana_tz`, which beats the compiled-in
    default. Validated by constructing the context (which resolves the zone before any
    socket), so a typo'd zone is exit 2 with the zone name in the message, not 400 pages
    of `unresolved` records.

    p1-12 (owner decision 2026-10-18): a site block that declares `device_tz` says "this
    device's wall digits live in this zone, whatever the clock claims" — site-a stamps
    +02:00 year-round while the digits ARE Bucharest (OBSERVED.md "time/offset bug").
    The mapped zone is then authoritative over the claimed offset, and the second return
    value tells the caller the wrongness is declared: the run-level warning is silenced
    while the record provenance (`tz_offset_mismatch` + both offsets) fills unchanged.
    Without the key the zone is what it always was and `False` comes back — the
    unmapped-device path stays byte-for-byte today's.

    An explicit `--tz` still beats a declared `device_tz`: the operator who typed the
    zone wants that zone, and silently ignoring the most specific instrument on the
    command line is the failure mode this repo names elsewhere ("a flag we silently
    ignore is a bug, not a default"). Telling "typed" from "the declared default landed
    in the value" is impossible from the value alone — `tz: TzOpt = DEFAULT_TZ` makes an
    absent flag arrive as `'Europe/Bucharest'`, indistinguishable from an operator who
    insisted on Bucharest — so `ctx` (the Click context the command passes) answers it
    via the parameter source. Without a `ctx` there is no evidence anyone typed
    `--tz`, the mapping stands: callers get the config's intent, never a guess.
    """
    typed_tz = ctx is not None and _tz_flag_given(ctx)
    if site.device_tz is not None and not typed_tz:
        chosen = site.device_tz
        mapped = True
    else:
        chosen = tz if tz is not None else (site.iana_tz or DEFAULT_TZ)
        mapped = False
    try:
        RunContext(site="validate", site_tz=chosen)
    except TimestampInputError as exc:
        raise _config_exit(fmt, str(exc)) from exc
    return chosen, mapped


def _tz_flag_given(ctx: Any) -> bool:
    """True when `--tz` was actually typed, not when its declared default landed.

    Click's own bookkeeping (the parameter source), because no CLI here may re-derive
    that fact from the value: the value cannot distinguish "not given" from "given, and
    given the same string the default happens to hold" — and a mapping silently beating
    an explicitly typed zone, or silently losing to an untouched default, are both
    payroll bugs this seam exists to keep apart. Fails CLOSED (treat as typed) when the
    context cannot answer: an operator-visible alarm is cheaper than a silently mapped
    run nobody approved.
    """
    try:
        source = ctx.get_parameter_source("tz")
    except Exception:  # pragma: no cover - a Click context always answers; belt, not branch
        return True
    return source is not None and source.name != "DEFAULT"


def _now() -> datetime:
    """The clock `captured_at` is stamped from — one module-level name, so a test can
    freeze it instead of tolerating a timestamp race.

    `RunContext.now` was already injectable (p1-08's own design); this is the seam that
    lets the CLI's own test suite use it. The default is the real wall clock, and nothing
    else in this module reads the time, so a frozen clock is provably the only thing a
    test changes.
    """
    return datetime.now(UTC)


def _context(
    *,
    site_config: cfg.SiteConfig,
    site_label: str | None,
    site_tz: str,
    caps: Any = None,
    max_records: int | None,
    logger: RequestLogger | None,
    device_claim: pipeline.WindowLabels | None = None,
) -> RunContext:
    """Assemble the run context, translating a bad flag value into exit 2.

    `device_claim` is the p1-05c window-label decision (the device's claimed offset,
    read ONCE per run by `pipeline.device_window_labels`); None keeps the warned
    site-labeled fallback.
    """
    label = site_label if site_label is not None else (site_config.name or DEFAULT_SITE_LABEL)
    try:
        return pipeline.compile_run_context(
            site=label,
            site_tz=site_tz,
            caps=caps,
            page_delay_ms=site_config.page_delay_ms,
            max_records=max_records,
            logger=logger,
            claimed_offset_min=None if device_claim is None else device_claim.claimed_offset_min,
            claimed_offset_note=None if device_claim is None else device_claim.note,
            now=_now,
        )
    except (ValueError, TimestampInputError) as exc:
        raise _config_exit(logger_format(logger), str(exc)) from exc


def logger_format(logger: RequestLogger | None) -> OutputFormat:  # pragma: no cover - tiny
    """Errors raised while building the context have no format in hand; default to table."""
    return OutputFormat.TABLE


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
        # Both views are built INSIDE the guard: `body` only exists if the read succeeded,
        # and a raw passthrough that skipped a failing read would print `{}` as though the
        # device had answered an empty document.
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


#: The rendered verdict for "the device asserted no offset at all" (p1-11). Worded as
#: ABSENCE on purpose: `None` is "no evidence", never "fine" (model.py's convention) — an
#: operator who read this line as "the offsets agree" would send a naive-clock box home
#: as healthy. Pinned by exact rendered text in tests/test_cli_commands.py.
NO_OFFSET_EVIDENCE = "no evidence (device claims nothing)"


def _tz_offset_verdict(
    reading: DeviceTime, site_tz: str, *, mapped_via: str | None = None
) -> tuple[bool | None, int | None, str]:
    """(mismatch, site offset at the device's wall instant, human sentence) — p1-11.

    DESIGN.md "Phase plan" item 7's other half: an operator standing at the device sees a
    wall clock ~4 s off (the skew rows below) and must NOT conclude the time is fine —
    site-a in summer has skew ≈ 0 with a wrong offset on every record. This is that
    comparison on the `device time` surface; the per-event column and the run-level
    warning already shipped with p1-06.

    The rule is `tz_mismatch.py`'s, imported and not restated: three-valued, where
    **None means there was no claim to compare** and is rendered as absence (see
    `NO_OFFSET_EVIDENCE`), never as agreement. Both sides are computed from the reading
    the command already fetched — no second request, and the device's own wall digits are
    what the site zone is resolved at, so the comparison is immune to the device's label.

    `mapped_via` (p1-12) is the site's declared `device_tz` when the mapping is in play:
    the zone the comparison resolves against is then the *mapped* one, and the sentence
    says so — an operator reading "MISMATCH" beside a silenced run alarm must be able to
    see WHY the run stayed quiet (the wrongness is declared in sites.toml) instead of
    concluding the two surfaces disagree with each other.

    The wall clock being unparseable is its own honest answer: with no wall there is
    nothing for the zone to resolve against (and no claim — both come out of the same
    `localTime` string), so the verdict and the site offset are both None and the sentence
    says which fact is missing. `offset_hhmm` cannot refuse a value from here (a
    `localTime` stamp is ±HH:MM by `_TIME_RE`, a zone offset is within ±23:59), but the
    label keeps a raw-minutes arm rather than trusting that reading of two other modules.
    """
    # p1-12: why the run-level alarm is silent for this device, appended to every
    # verdict sentence when a sites.toml mapping is what made the comparison.
    mapping_note = f" (mapped via sites.toml: {mapped_via})" if mapped_via is not None else ""
    if reading.naive_local is None:
        return None, None, "no evidence (no readable device wall clock)"
    site_min = site_offset_minutes(reading.naive_local, site_tz)
    claim_min = reading.claimed_offset_minutes
    verdict = is_offset_mismatch(claim_min, reading.naive_local, site_tz)

    def label(minutes: int) -> str:
        try:
            return f"{offset_hhmm(minutes)} ({minutes} min)"
        except ValueError:  # pragma: no cover - see docstring; never crash the report
            return f"{minutes} min"

    site = f"site resolves {label(site_min)}"
    # `verdict is None` and `claim_min is None` are the same fact here (the detector
    # answers None exactly when the claim asserts nothing); spelling both out keeps the
    # type checker happy without adding a branch that could drift from the policy.
    if verdict is None or claim_min is None:
        return verdict, site_min, f"{NO_OFFSET_EVIDENCE}, {site}{mapping_note}"
    claim = f"device claims {label(claim_min)}"
    if verdict:
        # "records unaffected": the resolution path already ignores this claim (DESIGN.md
        # item 2), so a flag that read like an accusation of bad data would be the lie.
        return verdict, site_min, f"MISMATCH — {claim}, {site}{mapping_note}; records unaffected"
    return verdict, site_min, f"agrees — {claim}, {site}{mapping_note}"


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
        # Everything downstream of the read runs INSIDE the guard: `reading` only exists if
        # the read succeeded, and a `--json` passthrough that rendered after the block would
        # have nothing honest to print on the failure path.
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
                    # p1-12: the mapping the effective zone came from, when sites.toml's
                    # `device_tz` chose it — `null` means the zone is the plain
                    # --tz/iana_tz/default answer. Machine-surface twin of the
                    # "mapped via sites.toml" wording in the table verdict row.
                    "tz_mapped_via": site_config.device_tz if tz_mapped else None,
                    # p1-11 (DESIGN.md item 7): the three-valued comparison, same semantics
                    # as the event record's `tz_offset_mismatch` — null = no claim, NOT
                    # agreement. `site_offset_min_at_instant` is the other side of it, so a
                    # reader never has to re-derive which side disagreed.
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
        # The warning line is the point of the command (DESIGN.md: "skew over a threshold is
        # a log line, not an auto-fix"), and Skew.message already refuses to promise a write.
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
    # One parenthesised `with` for both: the guard has to outlive the client, and
    # listing them as siblings says that in the shape of the code.
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
    verbose: VerboseOpt = False,
    site_label: SiteLabelOpt = None,
    employee_no: Annotated[
        str | None,
        typer.Option(
            "--employee-no",
            help="Keep only this employee's roster entry. Applied CLIENT-side: "
            "UserInfo/Search has never been probed for a server-side employee filter, "
            "and OBSERVED.md's policy is to never trust one we have not probed.",
        ),
    ] = None,
    count: CountOpt = False,
) -> None:
    """Paged roster via POST /ISAPI/AccessControl/UserInfo/Search.

    Table columns are the card's: `employee_no`, `name`, `valid`. `valid` is the device's
    `Valid.enable` flag — `yes` / `no` / `unknown` when the device did not say, which is
    reported as its own value rather than folded into "no" (an absent claim is not a
    denial). `valid_from`/`valid_to` ride in `--output json`, verbatim and with no tz
    claim: the device sends them naive and we make none (DESIGN.md: keep the raw).

    The device sends a `password` hash per user (OBSERVED.md endpoint table: "strip it,
    never store"). `UserRecord.from_device_user` removes it before anything can serialize
    it, so it cannot reach this table, this json, or a jsonl file.
    """
    fmt = output
    site_config = _resolve_site(host=host, site=site, port=port, sites_file=config, output=fmt)
    target = site_config.target()
    creds = _resolve_creds(target, user=user, password=password, output=fmt)
    logger = _logger_for(verbose, creds)
    with _Guard(fmt):
        with _client_for(target, creds, timeout=timeout, output=fmt, logger=logger) as client:
            context = _context(
                site_config=site_config,
                site_label=site_label,
                site_tz=site_config.iana_tz or DEFAULT_TZ,
                max_records=None,
                logger=logger,
            )
            result = pipeline.fetch_users(client, context=context, with_count=count)
        records = [pipeline.user_record_from_device(u) for u in result.users]
        if employee_no is not None:
            records = [r for r in records if r.employee_no == employee_no]
        if fmt is OutputFormat.TABLE:
            render(
                [
                    {
                        "employee_no": r.employee_no,
                        "name": r.name,
                        "valid": _valid_label(r),
                    }
                    for r in records
                ],
                fmt="table",
                columns=("employee_no", "name", "valid"),
            )
        else:
            render([r.to_dict() for r in records], fmt=fmt.value)
        if count:
            _print_count_crosscheck(
                result.device_count, len(records), filtered=employee_no is not None
            )


# --- events -------------------------------------------------------------------------


@app.command("events")
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
            # p1-05c (OBSERVED.md "Window offsets are ARITHMETIC"): the device does
            # arithmetic on window labels, so the walk's bounds must carry the DEVICE's
            # claimed offset — read once here, before the walk, never per chunk.
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
            # The advisory count is read AFTER the walk on purpose: the device counts its log
            # ring as it is now, and the walk is what we just saw. Reading it first would make
            # an event that landed mid-walk look like a lost record.
            # p1-05c: it carries the SAME label as the walk (device_claim) — a count probe
            # labeled differently counts a different window than the one we just walked.
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
        # Rendered inside the guard, so a failure inside `to_dict()`/`_event_row` cannot
        # leave a half-printed stream followed by an error line on stdout.
        if fmt is OutputFormat.TABLE:
            render([_event_row(r) for r in records], fmt="table", columns=EVENT_COLUMNS)
        else:
            render([r.to_dict() for r in records], fmt=fmt.value)
        if count:
            # What we compared: `AcsEventTotalNum` counts major=5 for the whole window, so
            # noise exclusion is already agreed between the two numbers. What makes them
            # legitimately differ is a client-side filter, or the --max-results cap.
            capped = max_results is not None and len(records) >= max_results
            _print_count_crosscheck(
                device_count,
                len(records),
                filtered=bool(employee_no or verify or outcome) or capped,
                capped=capped,
            )
        # p1-06c's run-level visibility: the walk is done, the stream is rendered, this
        # only summarizes what was just printed — display-only, like the `--count` line
        # above it, and it never changes the exit code.
        _warn_tz_mismatch(records, mapping_declared=tz_mapped)


#: The card's table columns, in this order. `utc` and `local` are adjacent on purpose:
#: reading them side by side is how a payroll person spots the offset bug themselves.
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
    """One `EventRecord` as the human table wants it.

    Column names are the card's short spellings; the values are the record's own fields,
    never re-derived. `utc` is our resolved instant, `local` is the device's verbatim
    string (`event_time_local`) — that pairing is the payroll triage view. `status` is the
    device's `attendanceStatus` (null on site-a -> '-') and `direction` is what the model
    derived from it, kept as two columns so a null status and an inferred direction can
    never be confused for each other.
    """
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


def _valid_label(record: Any) -> str:
    """`Valid.enable` as a word. `unknown` is its own answer, never folded into `no`."""
    if record.valid_enabled is None:
        return "unknown"
    return "yes" if record.valid_enabled else "no"


def _print_count_crosscheck(
    device_count: int | None, shown: int, *, filtered: bool, capped: bool = False
) -> None:
    """The `--count` line: display only, and honest about what it compared.

    Never a loop bound (DESIGN.md), and never an error: the roster/log grows between the
    pages and the count GET. With a client-side filter or a `--max-results` cap applied the
    two numbers are *supposed* to differ, so the line says which is which instead of printing
    a mismatch that means nothing — a bare "device says 100, printed 10" reads like ten
    dropped records when it is one flag working as instructed.
    """
    console = make_console(stderr=True)
    if device_count is None:
        console.print("count: the device gave no readable count", markup=False)
        return
    agrees = not filtered and device_count == shown
    verb = "agrees" if agrees else "reported"
    why = ""
    if not agrees:
        why = " (client-side filter applied)" if filtered and not capped else ""
        if capped:
            why = " (--max-results capped the output)"
    console.print(f"count: device says {device_count}, printed {shown} ({verb}{why})", markup=False)


# --- p1-06c run-level warning --------------------------------------------------------------


def _warn_tz_mismatch(records: Sequence[Any], *, mapping_declared: bool = False) -> None:
    """ONE stderr summary line when any printed record has `tz_offset_mismatch=true`.

    The column shipped with p1-06 (`tz_mismatch.py` owns the policy; DESIGN.md "Time
    handling" item 2: site-tz math is authoritative, the flag is audit-only). What was
    missing is visibility: on site-a in summer the flag is true on ~100% of records
    (the device claims +02:00 while Europe/Bucharest resolves +03:00) until the OWNER
    fixes the device tz — a device write we never make — and an operator watching a
    backfill saw silence unless they grepped the JSONL.

    p1-12 (owner decision 2026-10-18): the clocks are NOT going to be fixed physically;
    a site declares the wrongness once, in sites.toml (`device_tz`), and `events` hands
    in `mapping_declared=True` when that mapping is what resolved the run's zone. Then
    this prints NOTHING: the mismatch is known and accepted, and re-announcing it on
    every backfill is noise that trains operators to ignore warnings — the exact
    failure the line above exists to prevent, arriving from the other direction.
    The suppression is at THIS line only: every record still carries
    `tz_offset_mismatch` and both offset fields exactly as an unmapped run would
    (provenance is a fact about the data, the warning is a policy about attention).
    The mapping flag is keyed on "the mapping made this run's zone" — not on record
    counts or flag values — so an unmapped device warns exactly as before, including
    an explicit `--tz` overriding a declared mapping (the mapping then is NOT what
    resolved the zone, so the alarm the mapping silenced comes back).

    The precedent is `--count` (paging.py: "warn, don't fail"): one line, after the
    run, exit code untouched; `make_console(stderr=True)` keeps `--format jsonl >
    out.jsonl` parseable with the warning on (the same invariant `--verbose` pins).
    Rules this line obeys:

    * NEVER per-record — 1104 mismatched events still produce ONE line, and a
      multi-chunk walk summarizes the WHOLE run (the CLI hands in all output records);
    * a run with no true flags prints nothing — and a flag of None is "there was no
      claim to compare" (tz_mismatch.py's three-valued rule), so it counts neither as
      a mismatch nor as agreement: an all-None run is silence about mismatch;
    * the pair shown is READ OFF the records' own columns (`tz_offset_min_device` =
      what the device claimed, `tz_offset_min` = the site offset the UTC math used),
      never re-derived — a summary that recomputes can disagree with the records it
      summarizes. Distinct pairs are joined so a DST-boundary run whose mismatches go
      both ways (claim +02:00/site +03:00 in June; claim +03:00/site +02:00 in late
      October) names both instead of mislabeling one half;
    * the line says the records are correct: the resolution is already right, and
      anything that reads like "1104 records are wrong" would be a worse lie than the
      silence this replaced.
    """
    if mapping_declared:
        # Known-wrong, declared in sites.toml — the whole point of the mapping is that
        # this run stays quiet. Deliberately BEFORE any record inspection: the
        # suppression must not depend on what the records happen to say.
        return
    flagged = [r for r in records if r.tz_offset_mismatch is True]
    if not flagged:
        return

    def label(minutes: int) -> str:
        # A wild claim (`+99:30` on a malformed stamp) is out of the ±HH:MM ISO form
        # `offset_hhmm` refuses: show it as raw minutes rather than let the WARNING
        # crash the run it is reporting on (warn, don't fail — both directions).
        # EVERY interpolation below goes through this guard: offset_hhmm raising inside
        # the `with _Guard(fmt)` block would exit 1 on a run the card requires to exit 0
        # (pinned e2e by test_a_wild_claim_through_the_cli_still_exits_zero — a nested
        # function ruff cannot flag, so the pin is what keeps this guard alive).
        try:
            return offset_hhmm(minutes)
        except ValueError:
            return f"{minutes:+d} min"

    pairs: list[tuple[int, int]] = []
    for record in flagged:
        claimed, used = record.tz_offset_min_device, record.tz_offset_min
        # True without both offsets means the flag and its own columns disagree — a
        # policy bug upstream. Say so instead of printing a sentence with blanks.
        if claimed is None or used is None:
            make_console(stderr=True).print(
                "warning: some events have tz_offset_mismatch=true but no offsets to "
                "explain it — see tz_offset_min_device / tz_offset_min in the records",
                markup=False,
            )
            return
        pair = (claimed, used)
        if pair not in pairs:
            pairs.append(pair)
    zones = sorted({r.iana_tz for r in flagged if r.iana_tz})
    site = ", ".join(zones) if zones else "the configured site zone"
    if len(pairs) == 1:
        claimed, used = pairs[0]
        detail = (
            f"device claims {label(claimed)}; site {site} resolves {label(used)} at these instants"
        )
    else:
        joined = "; ".join(
            f"device claims {label(claimed)} vs site-resolved {label(used)}"
            for claimed, used in pairs
        )
        detail = f"{joined}; site {site} at these instants"
    make_console(stderr=True).print(
        f"warning: {len(flagged)} of {len(records)} events have tz_offset_mismatch=true "
        f"({detail}) — records are correct, site-tz resolution is authoritative",
        markup=False,
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
    (card p1-02 DoD): it exercises flags, env and `security find-generic-password`,
    prints `admin@host via keychain`, and never prints the password. Exit 2 with the exact
    `security` command to run when resolution fails.
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


# --- entry point -----------------------------------------------------------------------


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


# --- agent (P2-07b): the commands the site unit runs ----------------------------------------
#
# A NEW group only; nothing above this line is touched. `gateclerk agent run` is the process
# `deploy/gateclerk-agent@.service` starts, and `ack` / `deadletter` are the two owner commands
# the unit cannot do for itself. The bodies are thin on purpose: every rule (the cadence, the
# walk, the UPSERT, the park, the backoff, the dead letter) lives in the P2 module that shipped
# it and is imported, never re-expressed here. `gateclerk.agent_cli` is imported inside the
# bodies, not at the top: it imports P2-06's collector, which imports `cli._warn_tz_mismatch`
# back, and the CLI must stay importable without the agent present.
#
# These commands read the site with surface=AGENT (`config.ConfigSurface`): the agent refuses a
# block with no explicit `iana_tz`, because site tz is payroll truth and the compiled-in default
# is a site-a value (§2d). The CLI's own commands keep surface=CLI and are unaffected.

agent_app = typer.Typer(
    name="agent",
    help="The site agent itself (P2): serve one site, ack a parked device, triage dead letters.",
    no_args_is_help=True,
    context_settings={"help_option_names": ["-h", "--help"]},
)
deadletter_app = typer.Typer(
    name="deadletter",
    help="Dead-letter triage (P2-04): the pushes that failed past the 24h bound.",
    no_args_is_help=True,
    context_settings={"help_option_names": ["-h", "--help"]},
)
app.add_typer(agent_app)
agent_app.add_typer(deadletter_app)

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


def _agent_site(site: str, config: str | None, *, output: OutputFormat) -> cfg.SiteConfig:
    """Load one site block on the AGENT surface (strict `iana_tz`); exit 2 on any refusal."""
    try:
        return cfg.site_from_args(site=site, config_path=config, surface=cfg.ConfigSurface.AGENT)
    except ConfigError as exc:
        raise _config_exit(output, str(exc)) from exc


@agent_app.command("run")
def agent_run(
    site: AgentSiteOpt,
    config: AgentConfigOpt = None,
    state_root: AgentStateRootOpt = None,
    credentials_dir: AgentCredentialsDirOpt = None,
    password: AgentPasswordOpt = None,
    once: Annotated[
        bool,
        typer.Option(
            "--once",
            help="One tick, then exit 0 — the smoke test (deploy/README.md step 3). NOT for the "
            "unit: under Restart=always that becomes a five-second poll of the device.",
        ),
    ] = False,
    max_ticks: Annotated[
        int | None,
        typer.Option("--max-ticks", help="Stop after N ticks (tests and dry runs)."),
    ] = None,
    output: OutputOpt = OutputFormat.TABLE,
) -> None:
    """Serve one site: poll its devices, store, checkpoint, queue, push. The unit's ExecStart.

    Wiring only — P2-03's loop per device, P2-05's park gate around every tick (a refused tick
    sends ZERO requests), P2-02's store, P2-04's queue and drain, P2-06's health snapshot.
    Exits 2 on a config or credential problem (p1-08's contract) and 3 when the run ends with
    the site needing a human — a device parked unacked (terminal 401) or a transport
    circuit open — which `--once` is how an operator finds out (deploy/README.md step 3).
    """
    from gateclerk import agent_cli

    target = _agent_site(site, config, output=output)
    try:
        agent = agent_cli.build_site_agent(
            target,
            state_root=state_root,
            credentials_dir=credentials_dir,
            password=password,
        )
        try:
            report = agent.run(once=once, max_ticks=max_ticks)
        finally:
            agent.close()
    except Exception as exc:
        # `_fail` is p1-08's single mapping (config 2, terminal-auth 3, device 4). The agent
        # adds no codes of its own, so a script that knows the CLI's contract knows this one.
        raise _fail(output, exc) from exc
    payload = report.as_dict()
    if payload.pop("needs_human"):
        # The table form prints the report first: the counters are what the operator reads
        # to decide WHY. JSON forms stay one-document (the error object), like every other
        # exit path. The unit form never gets here — the loop never returns — so a park
        # cannot turn into a Restart=always crash loop against a door controller.
        if output not in (OutputFormat.JSON, OutputFormat.JSONL):
            render([payload], fmt=output.value, columns=tuple(payload))
        raise _auth_exit(
            output,
            f"site {target.name!r} needs a human: parked={list(report.parked)} "
            f"circuit_open={list(report.circuit_open)}",
        )
    render([payload], fmt=output.value, columns=tuple(payload))


@agent_app.command("ack")
def agent_ack(
    site: AgentSiteOpt,
    config: AgentConfigOpt = None,
    state_root: AgentStateRootOpt = None,
    device_serial: Annotated[
        str | None,
        typer.Option(
            "--device-serial",
            help="Ack ONE parked device (its serial). Omit to ack every park of this site.",
        ),
    ] = None,
    output: OutputOpt = OutputFormat.TABLE,
) -> None:
    """Operator acknowledgement of a parked device (P2-05): open the re-probe grid.

    A park means the device answered a terminal 401 with a digest challenge — dead or wrong
    credentials, on a device that counts failed logins. Acking says "I fixed the credential, you
    may knock again", and the policy then allows ONE attempt per re-probe period, the first at
    ack + period (never immediately). Zero parks opened exits 2 rather than 0: an ack that found
    nothing must not look like it cleared one.
    """
    from gateclerk import agent_cli

    target = _agent_site(site, config, output=output)
    db_path = agent_cli.resolve_db_path(target, state_root)
    if not Path(db_path).exists():
        # No store yet = no park can exist: the same exit-2 "nothing to ack" as an empty
        # park dir, phrased so the operator sees WHY (a crash from sqlite cannot open on a
        # missing directory is not an answer to a command typed in good faith).
        raise _config_exit(
            output,
            f"no store at {db_path} for site {target.name!r}: nothing to ack "
            "(has `gateclerk agent run` ever run for this site?)",
        )
    try:
        conn = agent_cli.connect(db_path)
    except (ConfigError, OSError) as exc:
        raise _config_exit(output, str(exc)) from exc
    policy = agent_cli.AlertPolicy(
        site=target.name,
        cadence_s=target.cadence_s,
        conn=conn,
        park_dir=agent_cli.resolve_state_root(target, state_root) / agent_cli.PARK_DIR_NAME,
        # The ack stamps the re-probe grid from the AGENT's clock — the same `agent_cli._now`
        # indirection `agent run` threads through every seam. Production behaviour is
        # identical (the seam defaults to wall clock); it just keeps ack and run inside ONE
        # time universe for the suite and for an ops smoke test.
        now=agent_cli._now,
    )
    opened = policy.ack(target.name, device_serial)
    render(
        [{"site": target.name, "parks_opened": opened, "device_serial": device_serial or "all"}],
        fmt=output.value,
        columns=("site", "parks_opened", "device_serial"),
    )
    if opened == 0:
        raise _config_exit(
            output,
            f"no parked device for site {target.name!r}: nothing to ack "
            "(a typo'd --device-serial cannot clear a park)",
        )


@deadletter_app.command("list")
def deadletter_list(
    site: AgentSiteOpt,
    config: AgentConfigOpt = None,
    state_root: AgentStateRootOpt = None,
    limit: Annotated[
        int, typer.Option("--limit", help="Most dead letters to show (oldest outage first).")
    ] = 50,
    output: OutputOpt = OutputFormat.TABLE,
) -> None:
    """List this site's dead-lettered pushes — the triage list the owner reads.

    Rows are shown WITHOUT the payload: it carries punch data (an employee number and a name).
    The payload stays in the db until the owner deletes the row, which is the only way a dead
    letter ever leaves the table (§2b).
    """
    from gateclerk import agent_cli, agent_push

    target = _agent_site(site, config, output=output)
    conn = agent_cli.connect(agent_cli.resolve_db_path(target, state_root))
    rows = [
        {
            "id": row.id,
            "event_id": row.event_id,
            "endpoint": row.endpoint,
            "error_class": row.error_class,
            "attempts": row.attempts,
            "first_attempt_at": row.first_attempt_at,
            "last_attempt_at": row.last_attempt_at,
        }
        for row in agent_push.dead_letter_rows(conn, limit=limit)
    ]
    render(
        rows,
        fmt=output.value,
        columns=(
            "id",
            "event_id",
            "endpoint",
            "error_class",
            "attempts",
            "first_attempt_at",
            "last_attempt_at",
        ),
    )


@deadletter_app.command("delete")
def deadletter_delete(
    id_: Annotated[int, typer.Argument(help="dead_letter row id (from `agent deadletter list`).")],
    site: AgentSiteOpt,
    config: AgentConfigOpt = None,
    state_root: AgentStateRootOpt = None,
    output: OutputOpt = OutputFormat.TABLE,
) -> None:
    """Remove ONE dead-letter row — the only code path that ever deletes one (§2b).

    Deleting is a human call: the payload is the only copy of a punch that never reached the
    ingest, and a dead letter is never retried again once it is removed. An id that does not
    exist exits 2 — a typo must not read as a deletion.

    The removal is recorded in the site's push ledger (`agent_cli.discard_dead_letter`):
    without that line the event row — still in the store, now unexcluded — would be re-queued
    and RE-PUSHED on the next pass, which would undo the owner's decision (§2b).
    """
    from gateclerk import agent_cli

    target = _agent_site(site, config, output=output)
    state_dir = agent_cli.resolve_state_root(target, state_root)
    conn = agent_cli.connect(agent_cli.resolve_db_path(target, state_root))
    ledger = agent_cli.PushLedger(state_dir / agent_cli.PUSH_LEDGER_FILE_NAME)
    removed = agent_cli.discard_dead_letter(conn, id_, ledger=ledger)
    if not removed:
        raise _config_exit(output, f"no dead_letter row with id {id_}: nothing was deleted")
    render([{"id": id_, "removed": True}], fmt=output.value, columns=("id", "removed"))


def main(argv: list[str] | None = None) -> int:
    """Console entry point. Returns an exit code instead of calling sys.exit()."""
    try:
        result = app(args=argv, prog_name="gateclerk", standalone_mode=False)
    except typer.Exit as exc:  # raised by --version and by every exit-code path
        return int(exc.exit_code)
    except _USAGE_ERRORS as exc:  # click/typer refused the command line: exit 2
        exc.show()
        return int(exc.exit_code)
    return 0 if result is None else int(result)


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
