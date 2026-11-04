"""The shared CLI furniture: option spellings, hidden-alias groups, failure-to-exit, and seams.

CLI-SPLIT-STRUCTURE and CLI-SEAM-MOVE moved this out of `gateclerk.cli` together with every
command group. It is the module every command module imports — `cli.py` imports it too, so
a shared flag spelling, a shared option default, the failure-to-exit renderer, and the
client/clock/migration seams (`IsapiClient`, `_now`, `_warn_tz_mismatch`, `_migrate_client`,
`_migrate_seams`) exist EXACTLY ONCE for the whole surface. The dependency direction is a
law, not a style note:

    gateclerk.cli  ->  gateclerk.cli_shared, gateclerk.*_cmds, <domain modules>
    <cmd module>   ->  gateclerk.cli_shared                  (NEVER -> gateclerk.cli)

Nothing in this module builds a `typer.Typer` or registers a command — that is what keeps
it importable from any command module without an import cycle.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from datetime import UTC, datetime
from typing import Annotated, Any

import httpx
import typer
from typer.core import TyperGroup

from gateclerk import config as cfg
from gateclerk import pipeline
from gateclerk.cli_conventions import (
    AUTH_TERMINAL_EXIT,
    CONFIG_ERROR_EXIT,
    DEVICE_ERROR_EXIT,
    RUNAWAY_EXIT,
    resolve_alias,
)
from gateclerk.cli_conventions import exit_code_for as _exit_code_for
from gateclerk.config import KeychainReader, resolve_credentials, site_from_args
from gateclerk.exceptions import ConfigError, CredentialUnavailable
from gateclerk.isapi_transport import IsapiClient
from gateclerk.output import CHOICES as OUTPUT_CHOICES
from gateclerk.output import OutputFormat, make_console, render
from gateclerk.pipeline import DEFAULT_SITE_LABEL, RequestLogger, RunContext
from gateclerk.tz import (
    TimestampInputError,
    UserTimestamp,
    offset_hhmm,
    parse_user_timestamp,
)

DEFAULT_PORT = cfg.DEFAULT_PORT
DEFAULT_TIMEOUT = cfg.DEFAULT_TIMEOUT_S
DEFAULT_TZ = cfg.DEFAULT_IANA_TZ

VERIFY_CHOICES = ("face", "card", "fp", "password")
OUTCOME_CHOICES = ("granted", "denied", "info")


def _alias_group(path: tuple[str, ...]) -> type[TyperGroup]:
    class _Group(TyperGroup):
        def get_command(self, ctx: Any, cmd_name: str) -> Any:
            command = super().get_command(ctx, cmd_name)
            if command is not None:
                return command
            canonical = resolve_alias(path, cmd_name)
            return super().get_command(ctx, canonical) if canonical is not None else None

    _Group.__name__ = f"AliasGroup_{'_'.join(path)}"
    return _Group


# --- shared options -----------------------------------------------------------------

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
    """Report a terminal 401 (exit 3) with the lockout warning attached."""
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
    try:
        return _exit_code_for(exc)
    except KeyError:
        raise exc from None


def _fail(fmt: OutputFormat, exc: BaseException) -> typer.Exit:
    """Map any exception escaping a command body onto the documented exit code."""
    code = _classify(exc)
    if code == AUTH_TERMINAL_EXIT:
        return _auth_exit(fmt, str(exc))
    if code == RUNAWAY_EXIT:
        return _runaway_exit(fmt, str(exc))
    if code == CONFIG_ERROR_EXIT:
        return _config_exit(fmt, str(exc))
    return _device_exit(fmt, str(exc))


class _Guard:
    """Context manager: `with _Guard(fmt): ...` turns any GateClerkError into its exit code."""

    def __init__(self, fmt: OutputFormat) -> None:
        self._fmt = fmt

    def __enter__(self) -> _Guard:
        return self

    def __exit__(self, exc_type: object, exc: BaseException | None, tb: object) -> bool:
        if exc is None:
            return False
        raise _fail(self._fmt, exc) from exc


# --- shared resolution, client, clock, tz-warning, and migration seams ---------------


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
    """Resolve credentials, converting a failure into the documented exit 2."""
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
    trust_env: bool = True,
) -> Any:
    """Build the read-only client for one device, wrapped for logging when asked.

    `trust_env` keeps httpx's default (True) for ordinary read commands — the posture
    demo_walkthrough.py:747 documents as deliberate — while a caller with a LAN-local
    NO_PROXY law (doctor's device probe) opts out explicitly, so a proxy the operator's
    shell exports can never make a healthy device read as "unreachable".
    """
    try:
        client = IsapiClient(
            f"http://{target.host}:{target.port}",
            creds.user,
            creds.password.reveal(),
            read_timeout=timeout,
            trust_env=trust_env,
        )
    except (ValueError, httpx.InvalidURL) as exc:
        raise _config_exit(output, str(exc)) from exc
    if logger is None:
        return client
    return pipeline.LoggedClient(client, logger)


def default_device_prober(
    site: cfg.SiteConfig,
    *,
    env: Mapping[str, str] | None = None,
    now: datetime | None = None,
) -> tuple[str, float | None]:
    """Probe one site through THE SAME client the read commands build (`_client_for`).

    The sanctioned seam `gateclerk doctor --probe` reaches for: `doctor_cli`'s own
    `default_device_prober` builds its client directly, and this one builds it through
    `_client_for`, so the check exercises the factory every read command shares instead
    of a parallel construction that can drift from it (which is exactly how #79's
    TypeError survived a green suite). Two read-only GETs (`device_info`, `system_time`),
    one credential resolve, no writes, no restart, no secret in the summary.
    """
    from gateclerk import pipeline

    target = site.target()
    creds = _resolve_creds_plain(target, env=env)
    client = _client_for(target, creds, timeout=site.timeout_s, output=OutputFormat.TABLE)
    try:
        serial, _firmware, model = pipeline.read_device_identity(client)
        dev_time, _raw = pipeline.device_time_reading(client)
    finally:
        close = getattr(client, "close", None)
        if close is not None:
            close()

    from gateclerk.tz import DEFAULT_SITE_TZ, SKEW_WARN_SECONDS, compute_skew

    tz_name = site.device_tz or site.iana_tz or DEFAULT_SITE_TZ
    skew = compute_skew(
        dev_time,
        our_now=now or datetime.now(UTC),
        site_tz=tz_name,
        warn_seconds=SKEW_WARN_SECONDS,
    )
    return f"model={model or '?'} serial={serial or '?'}", skew.skew_seconds


def _resolve_creds_plain(
    target: cfg.DeviceTarget, *, env: Mapping[str, str] | None = None
) -> cfg.Credentials:
    """Resolve credentials WITHOUT converting to an exit — the prober maps errors itself.

    `_resolve_creds` raises `Exit`; a device prober must hand the doctor's own section
    mapper a `CredentialUnavailable` so the row reads "cannot probe device (credentials
    unavailable)", not a bare exit-2 with no section.
    """
    return resolve_credentials(target, env=env)


def _iso(value: datetime | None) -> str | None:
    """ISO-8601 for a datetime a record may not have. None stays None."""
    return None if value is None else value.isoformat()


def _nested(body: Mapping[str, Any], key: str) -> Any:
    """Read `key` from a deviceInfo body, at the top level or one wrapper deep."""
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
    """Reject an unknown `--verify`/`--outcome` as exit 2 rather than filtering to nothing."""
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
    """Parse --since/--until into instants. Both are required; a bad value exits 2."""
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
    """The zone the run resolves punches in, as `(zone, mapping_in_play)`."""
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
    """True when `--tz` was actually typed, not when its declared default landed."""
    try:
        source = ctx.get_parameter_source("tz")
    except Exception:  # pragma: no cover
        return True
    return source is not None and source.name != "DEFAULT"


def _now() -> datetime:
    """The clock `captured_at` is stamped from — one module-level seam for tests."""
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
    """Assemble the run context, translating a bad flag value into exit 2."""
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
            now=lambda: _now(),
        )
    except (ValueError, TimestampInputError) as exc:
        raise _config_exit(logger_format(logger), str(exc)) from exc


def logger_format(logger: RequestLogger | None) -> OutputFormat:  # pragma: no cover
    return OutputFormat.TABLE


def _valid_label(record: Any) -> str:
    """`Valid.enable` as a word. `unknown` is its own answer, never folded into `no`."""
    if record.valid_enabled is None:
        return "unknown"
    return "yes" if record.valid_enabled else "no"


def _print_count_crosscheck(
    device_count: int | None, shown: int, *, filtered: bool, capped: bool = False
) -> None:
    """The `--count` line: display only, and honest about what it compared."""
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


def _warn_tz_mismatch(records: Sequence[Any], *, mapping_declared: bool = False) -> None:
    """ONE stderr summary line when any printed record has `tz_offset_mismatch=true`."""
    if mapping_declared:
        return
    flagged = [r for r in records if r.tz_offset_mismatch is True]
    if not flagged:
        return

    def label(minutes: int) -> str:
        try:
            return offset_hhmm(minutes)
        except ValueError:
            return f"{minutes:+d} min"

    pairs: list[tuple[int, int]] = []
    for record in flagged:
        claimed, used = record.tz_offset_min_device, record.tz_offset_min
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


def _migrate_client(
    *,
    host: str | None,
    site: str | None,
    port: int,
    config: str | None,
    user: str | None,
    password: str | None,
    timeout: float,
    fmt: OutputFormat,
    verbose: bool = False,
) -> tuple[cfg.SiteConfig, Any, Callable[[], Any]]:
    """The read client + a FACTORY for fresh ones, built by the SAME helpers P1 uses."""
    site_config = _resolve_site(host=host, site=site, port=port, sites_file=config, output=fmt)
    target = site_config.target()
    creds = _resolve_creds(target, user=user, password=password, output=fmt)
    logger = _logger_for(verbose, creds)

    def factory() -> Any:
        return _client_for(target, creds, timeout=timeout, output=fmt, logger=logger)

    return site_config, factory(), factory


def _read_target_state(client: Any) -> Any:
    """A fresh full target read — §4: the target is never a cached or bundled view."""
    from gateclerk.migrate_export import collect_enrollment_state

    return collect_enrollment_state(client, inter_page_delay=0.0, sleep=lambda _s: None)


def _migrate_seams(client: Any, client_factory: Callable[[], Any], *, writable: bool) -> Any:
    """The composer's seams: registry reads on the command's client, write verbs per phase."""
    from gateclerk import migrate_apply as apply_mod

    def _read_only_only() -> Any:
        raise AssertionError(
            "this migrate command is a read pass: no write client may be constructed here (§7)"
        )

    return apply_mod.ApplySeams(
        read_target_state=lambda: _read_target_state(client),
        users_transport_factory=(
            (lambda: apply_mod.UserWriteTransport(client_factory()))
            if writable
            else _read_only_only
        ),
        cards_transport_factory=(
            (lambda: apply_mod.CardWriteTransport(client_factory()))
            if writable
            else _read_only_only
        ),
        fp_transport_factory=(
            (lambda: apply_mod.FpWriteTransport(client_factory())) if writable else _read_only_only
        ),
        faces_transport_factory=(
            (lambda: apply_mod.FaceWriteTransport(client_factory()))
            if writable
            else _read_only_only
        ),
        users_reader=apply_mod.reader_for(client, "user_info_search"),
        cards_reader=apply_mod.reader_for(client, "card_info_search"),
        fp_reader=lambda body: client.search("finger_print_upload", body),
        faces_reader=apply_mod.reader_for(client, "fd_search"),
    )
