"""Config model + credential resolution (card p1-02).

Two jobs, one seam:

  Config    `sites.toml` -> `SiteConfig` (docs/DESIGN.md "Credential plumbing"): the site
            block is the committed, non-secret half of the connection. Hosts are not
            secrets; passwords never appear in this file.
  Creds     `resolve_credentials()` turns (flags, env, macOS Keychain) into a
            `Credentials(user, Secret)` and says which source won. Precedence is fixed:
            **flag > env > keychain** (card p1-02). A gitignored `.env` is only a way of
            getting values into the environment, so it needs no rung of its own.

The seam that matters for the rest of P1: p1-03's ISAPI client receives a **callable**
(`CredentialProvider`), never a password attribute. The client therefore cannot hold a
plaintext password, cannot log one, and P2's site agent can hand it a systemd-credential
provider without touching ISAPI code.

VERIFIED against the real `security` CLI (macOS, throwaway keychain, 2026-10-15):
  * `find-generic-password -s S -a A -w` prints ONLY the secret, newline-terminated.
  * Without `-w` it prints the attribute list and NOT the secret; the comment is the
    `icmt` field, so the `user=...` hint is read from `"icmt"<blob>="user=admin"`.
  * A missing item exits **44**: `security: SecKeychainSearchCopyNext: The specified item
    could not be found in the keychain.`
  * The comment flag is **`-j`**, not `-C` (`-C` is a four-char *type* code) — the
    `security add-generic-password` hint this module prints uses `-j` for that reason.
"""

from __future__ import annotations

import contextlib
import contextvars
import os
import re
import shlex
import shutil
import subprocess
import tomllib
from collections.abc import Callable, Iterable, Iterator, Mapping
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Any

from gateclerk.exceptions import ConfigError, CredentialUnavailable, redact_b64
from gateclerk.secrets import Secret, redact

__all__ = [
    "DEFAULT_CADENCE_S",
    "DEFAULT_DB_PATH_TEMPLATE",
    "DEFAULT_DB_WARN_BYTES",
    "DEFAULT_IANA_TZ",
    "DEFAULT_ISAPI_USER",
    "DEFAULT_KEYCHAIN_SERVICE",
    "DEFAULT_OVERLAP_S",
    "DEFAULT_PAGE_DELAY_MS",
    "DEFAULT_PORT",
    "DEFAULT_PUSH_DEAD_LETTER_AFTER_S",
    "DEFAULT_SITES_FILE",
    "DEFAULT_TIMEOUT_S",
    "ENV_PREFIX",
    "KEYCHAIN_EXIT_NOT_FOUND",
    "PUSH_TARGET_SCHEMES",
    "SECURITY_BIN",
    "ConfigSurface",
    "CredentialProvider",
    "CredentialSource",
    "Credentials",
    "DeviceTarget",
    "KeychainItem",
    "KeychainReader",
    "SiteConfig",
    "credential_provider",
    "credential_ref",
    "describe_target",
    "env_var_names",
    "explicit_iana_tz_required",
    "find_site",
    "host_env_prefix",
    "load_sites",
    "parse_sites",
    "resolve_credentials",
    "safe_line",
    "site_from_args",
]

# Defaults are DESIGN.md decisions, not whims: ISAPI lives on HTTP:80 (8000 is the
# Hikvision SDK protocol port), a 30 s read timeout because the device drops idle
# keep-alives, and a 100 ms inter-page delay because these boxes prefer serial requests.
DEFAULT_PORT = 80
DEFAULT_TIMEOUT_S = 30.0
DEFAULT_PAGE_DELAY_MS = 100
DEFAULT_KEYCHAIN_SERVICE = "gateclerk-hikvision"
DEFAULT_ISAPI_USER = "admin"
DEFAULT_IANA_TZ = "Europe/Bucharest"
DEFAULT_SITES_FILE = "sites.toml"

# P2 agent defaults are docs/P2-SITE-AGENT.md decisions, signed off 2026-10-19 — the
# card text cites the seam for each number. They live HERE (and every P2 key of the
# schema is defined NOW) so later P2 cards only read them:
#   cadence/overlap 5 min/5 min (§2a: minutes, not days — the ~190-request nonce use-cap
#     makes retirement routine at any minutes-scale cadence, and the overlap is the
#     crash/clock-step gap-healer);
#   db_warn_bytes 2 GiB watermark (§2b: keep-everything + watermark alert);
#   push_dead_letter_after_s 24 h of continuous push failure (§2c);
#   db path derives `./gateclerk-<site>.sqlite3` per site (§2b; `*.sqlite3` is already
#     gitignored — deliberately no DEFAULT_PUSH_TARGET: spec §3/§2d forbid ever
#     defaulting an endpoint, absence means "pusher off", the P2-04 decision point).
DEFAULT_CADENCE_S = 300
DEFAULT_OVERLAP_S = 300
DEFAULT_DB_WARN_BYTES = 2 * 1024**3
DEFAULT_PUSH_DEAD_LETTER_AFTER_S = 86400
DEFAULT_DB_PATH_TEMPLATE = "./gateclerk-{site}.sqlite3"

#: The only `push_target` schemes the validator accepts (§3: the push leg is ordinary
#: HTTPS to our own endpoint; `stub://` is the owner-authorized local stub ingest).
#: Everything else — `ftp://`, plaintext `http://`, `file://`, scheme-less — is refused.
PUSH_TARGET_SCHEMES = ("stub://", "https://")

ENV_PREFIX = "GATECLERK"
SECURITY_BIN = "/usr/bin/security"

#: What `security` exits when the item simply is not in the keychain (VERIFIED, above).
KEYCHAIN_EXIT_NOT_FOUND = 44


class ConfigSurface(StrEnum):
    """WHICH process is reading the config — the strictness is a property of the CALLER,
    never of the file (a shared `sites.toml` must not be able to disqualify its own CLI
    use by carrying a key).

    CLI   — the P1 operator surface: today's behaviour, `iana_tz` optional (the CLI
            falls back to `DEFAULT_IANA_TZ` via `--tz` precedence in cli.py).
    AGENT — the P2 site agent (docs/P2-SITE-AGENT.md §2d): a block without an explicit
            `iana_tz` is REFUSED, because site tz is payroll truth and the compiled-in
            default is a *site-a* value that must never decide another site's payroll.
    """

    CLI = "cli"
    AGENT = "agent"


#: Process-wide strictness for an agent entry point that cannot thread `surface=`
#: through every config read (systemd unit-per-site main(): flip it on once at startup).
#: A ContextVar, not a module global: nesting is token-reset and exception-safe.
_STRICT_IANA_TZ: contextvars.ContextVar[bool] = contextvars.ContextVar(
    "gateclerk_strict_iana_tz", default=False
)


@contextlib.contextmanager
def explicit_iana_tz_required() -> Iterator[None]:
    """Within this block, EVERY config read behaves as the agent surface (spec §2d).

    Deliberately additive: the `surface=` argument stays the explicit seam (tests and
    call sites that know what they are); this covers an agent process' inherited paths
    (shared helpers, `site_from_args` reuse) without editing each of them.
    """
    token = _STRICT_IANA_TZ.set(True)
    try:
        yield
    finally:
        _STRICT_IANA_TZ.reset(token)


class CredentialSource(StrEnum):
    """Where a resolved credential came from. Safe to print; never the secret."""

    FLAG = "flag"
    ENV = "env"
    KEYCHAIN = "keychain"


@dataclass(frozen=True, slots=True)
class SiteConfig:
    """One `[[site]]` block of `sites.toml` — the non-secret half of a connection.

    P2-01 defines EVERY key of the P2 schema here (this module owns the file for the
    whole phase), so later P2 cards only read fields: the agent keys below are validated
    at parse time AND construct time exactly like P1's, and `surface` says which process
    is asking — the agent refuses a block whose `iana_tz` is missing, the CLI does not
    (docs/P2-SITE-AGENT.md §2d; see `ConfigSurface`).
    """

    name: str
    host: str
    port: int = DEFAULT_PORT
    timeout_s: float = DEFAULT_TIMEOUT_S
    page_delay_ms: int = DEFAULT_PAGE_DELAY_MS
    iana_tz: str | None = None
    #: p1-12 (owner decision 2026-10-18): the zone the device's wall digits actually
    #: live in, declared per device. On site-a the clock stamps +02:00 year-round while
    #: the digits ARE site-local Europe/Bucharest (OBSERVED.md "time/offset bug"), and
    #: the owner will not touch the device clock — so the mapping is declared here and
    #: the run resolves against it. When set it is authoritative over the claimed
    #: offset AND silences the run-level tz warning (the wrongness is known and
    #: accepted); when absent, today's behaviour byte-for-byte.
    device_tz: str | None = None
    isapi_user: str = DEFAULT_ISAPI_USER
    keychain_service: str = DEFAULT_KEYCHAIN_SERVICE
    # --- P2 agent keys (docs/P2-SITE-AGENT.md §2a-§2d) ---------------------------------
    #: Seconds between polls (§2a: 5 min against the ~190-request nonce use-cap).
    cadence_s: int = DEFAULT_CADENCE_S
    #: Seconds of already-seen window re-read on every poll (§2a: the gap-healer).
    overlap_s: int = DEFAULT_OVERLAP_S
    #: Local sqlite path; `None` means "derive `./gateclerk-<site>.sqlite3`" (§2b) — see
    #: `db_path_resolved`. The `*.sqlite3` gitignore pattern already covers the default.
    db_path: str | None = None
    #: Disk watermark in bytes past which the agent warns (§2b: keep-everything + alert).
    db_warn_bytes: int = DEFAULT_DB_WARN_BYTES
    #: Ingest endpoint REF for the outbound push (§3: abstract, never defaulted). `None`
    #: means the pusher is off. Accepted schemes: `PUSH_TARGET_SCHEMES`.
    push_target: str | None = None
    #: Task 15: the BC device code (page 70602) this device is registered under, when it
    #: differs from the serial. The hourly device-users roster names the device by this
    #: code when set, else by its serial (the ingest resolves serial -> code itself).
    device_code: str | None = None
    #: Continuous-push-failure seconds before a batch is dead-lettered (§2c: 24 h).
    push_dead_letter_after_s: int = DEFAULT_PUSH_DEAD_LETTER_AFTER_S
    #: Which process is reading (see `ConfigSurface`). NOT a TOML key: strictness
    #: belongs to the caller, so a shared sites.toml can never disqualify its own CLI.
    surface: ConfigSurface = ConfigSurface.CLI

    #: Keys a `[[site]]` block may carry. Anything else is refused loudly: a silently
    #: ignored `timeout_s = 5` would mean we poll a door controller for 30 s and believe
    #: we configured 5. Credential VALUES have no key here by design (DESIGN.md
    #: "Credential plumbing", spec §2d): a `password =` line lands in the refusal below.
    _KNOWN_KEYS = frozenset(
        {
            "name",
            "host",
            "port",
            "timeout_s",
            "page_delay_ms",
            "iana_tz",
            "device_tz",
            "isapi_user",
            "keychain_service",
            "cadence_s",
            "overlap_s",
            "db_path",
            "db_warn_bytes",
            "push_target",
            "device_code",
            "push_dead_letter_after_s",
        }
    )

    def __post_init__(self) -> None:
        # `surface` is normalised BEFORE validating: the field is typed
        # `ConfigSurface` for readers, but an agent entry point may legitimately pass
        # the plain string "agent" (StrEnum accepts it). An unknown spelling is a
        # ConfigError, never a silent downgrade to CLI — that hole would be §2d again.
        object.__setattr__(self, "surface", _coerce_surface(self.surface))
        self.validate()

    @property
    def db_path_resolved(self) -> str:
        """The sqlite path to actually open: the operator's, else the site-derived one.

        Derivation lives here (not in each caller) so P2-02's store, P2-04's dead-letter
        and P2-05's watermark alert cannot disagree about where site-a's data is.
        """
        if self.db_path is not None:
            return self.db_path
        return DEFAULT_DB_PATH_TEMPLATE.format(site=self.name)

    def target(self) -> DeviceTarget:
        """The device half of the config, as the credential resolver wants it."""
        return DeviceTarget(
            host=self.host,
            port=self.port,
            site=self.name,
            keychain_service=self.keychain_service,
            config_user=self.isapi_user,
        )

    def validate(self) -> None:
        """Fail loudly and before any network call. p1-08 maps this to exit 2.

        Every problem names the key the operator typed (and the message carries the
        site name), the style set by the unknown-key refusal and p1-12's `device_tz`.
        """
        problems: list[str] = []
        if not self.name.strip():
            problems.append("name must not be empty")
        if not self.host.strip():
            problems.append("host must not be empty")
        if not 1 <= self.port <= 65535:
            problems.append(f"port {self.port} out of range 1..65535")
        if self.timeout_s <= 0:
            problems.append(f"timeout_s {self.timeout_s} must be > 0")
        if self.page_delay_ms < 0:
            problems.append(f"page_delay_ms {self.page_delay_ms} must be >= 0")
        if self.iana_tz is not None:
            problem = _tz_problem(self.iana_tz)
            if problem:
                problems.append(problem)
        if self.device_tz is not None:
            # Same strictness as `iana_tz` (p1-12): a typo'd mapping must not quietly fall
            # back to the device's wrong claim — the whole point of the key is that the
            # mapping is what the run resolves against.
            problem = _tz_problem(self.device_tz, key="device_tz")
            if problem:
                problems.append(problem)
        if not self.keychain_service.strip():
            problems.append("keychain_service must not be empty")
        # --- P2 agent keys ------------------------------------------------------------
        # cadence/overlap > 0: 0 would busy-poll a device whose digest nonce dies at
        # ~190 uses, and a negative overlap moves the window's lower bound FORWARD —
        # a silent gap in the exact crash-heal case the overlap exists for.
        if self.cadence_s <= 0:
            problems.append(f"cadence_s {self.cadence_s} must be > 0")
        if self.overlap_s < 0:
            problems.append(f"overlap_s {self.overlap_s} must be >= 0")
        if self.db_warn_bytes <= 0:
            problems.append(f"db_warn_bytes {self.db_warn_bytes} must be > 0")
        if self.push_dead_letter_after_s <= 0:
            problems.append(f"push_dead_letter_after_s {self.push_dead_letter_after_s} must be > 0")
        if self.db_path is not None and not self.db_path.strip():
            problems.append("db_path must not be empty (omit the key for the site default)")
        if self.push_target is not None:
            problem = _push_target_problem(self.push_target)
            if problem:
                problems.append(problem)
        # Task 15: a blank `device_code` would roster with an empty `deviceCode`, which
        # the ingest answers 400 `invalid_user_line` for — an empty string is "unset",
        # and the roster then names the device by serial like any unset key does.
        if self.device_code is not None and not self.device_code.strip():
            problems.append("device_code must not be empty (omit the key to use the serial)")
        # §2d: on the agent surface the zone is REQUIRED, never defaulted. The
        # compiled-in DEFAULT_IANA_TZ is a site-a value and must never decide another
        # site's payroll, so it is simply absent from this branch — an agent that wants
        # a zone must have one declared in the file.
        if self._strict_iana_tz() and self.iana_tz is None:
            problems.append(
                "iana_tz is required (the site timezone is payroll truth and is never "
                'defaulted — add iana_tz = "Europe/Bucharest" or the site\'s real zone)'
            )
        if problems:
            raise ConfigError(f"site {self.name!r} is misconfigured: {('; '.join(problems))}")

    def _strict_iana_tz(self) -> bool:
        """Whether the REQUIRED-zone rule applies to THIS read: the agent surface, or
        the process-wide `explicit_iana_tz_required()` block an agent process sets."""
        return self.surface is ConfigSurface.AGENT or _STRICT_IANA_TZ.get()

    @classmethod
    def from_table(
        cls, table: Mapping[str, Any], *, surface: str | ConfigSurface = "cli"
    ) -> SiteConfig:
        """Build from one parsed TOML table, rejecting unknown keys and wrong types.

        `surface` is passed in by the reader (never read from the table — see
        `ConfigSurface`); a block that lacks `iana_tz` is refused here on the agent
        surface, which is the parse-time half of the "construct-time + parse-time both"
        requirement.
        """
        unknown = sorted(set(table) - cls._KNOWN_KEYS)
        if unknown:
            raise ConfigError(
                f"unknown key(s) {unknown} in a [[site]] block "
                f"(accepted: {sorted(cls._KNOWN_KEYS)})"
            )
        for key in ("name", "host"):
            if key not in table:
                raise ConfigError(f"[[site]] block is missing required key {key!r}")
        return cls(
            name=_text(table["name"], "name"),
            host=_text(table["host"], "host"),
            port=_int(table.get("port", DEFAULT_PORT), "port"),
            timeout_s=_number(table.get("timeout_s", DEFAULT_TIMEOUT_S), "timeout_s"),
            page_delay_ms=_int(table.get("page_delay_ms", DEFAULT_PAGE_DELAY_MS), "page_delay_ms"),
            iana_tz=_text(table["iana_tz"], "iana_tz") if "iana_tz" in table else None,
            device_tz=_text(table["device_tz"], "device_tz") if "device_tz" in table else None,
            isapi_user=_text(table.get("isapi_user", DEFAULT_ISAPI_USER), "isapi_user"),
            keychain_service=_text(
                table.get("keychain_service", DEFAULT_KEYCHAIN_SERVICE), "keychain_service"
            ),
            cadence_s=_int(table.get("cadence_s", DEFAULT_CADENCE_S), "cadence_s"),
            overlap_s=_int(table.get("overlap_s", DEFAULT_OVERLAP_S), "overlap_s"),
            db_path=_text(table["db_path"], "db_path") if "db_path" in table else None,
            db_warn_bytes=_int(table.get("db_warn_bytes", DEFAULT_DB_WARN_BYTES), "db_warn_bytes"),
            push_target=(
                _text(table["push_target"], "push_target") if "push_target" in table else None
            ),
            device_code=(
                _text(table["device_code"], "device_code") if "device_code" in table else None
            ),
            push_dead_letter_after_s=_int(
                table.get("push_dead_letter_after_s", DEFAULT_PUSH_DEAD_LETTER_AFTER_S),
                "push_dead_letter_after_s",
            ),
            surface=_coerce_surface(surface),
        )


def _text(value: object, key: str) -> str:
    if not isinstance(value, str):
        raise ConfigError(f"{key} must be a string, got {type(value).__name__}")
    return value


def _int(value: object, key: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ConfigError(f"{key} must be an integer, got {type(value).__name__}")
    return value


def _number(value: object, key: str) -> float:
    if isinstance(value, bool) or not isinstance(value, int | float):
        raise ConfigError(f"{key} must be a number, got {type(value).__name__}")
    return float(value)


def _tz_problem(iana_tz: str, *, key: str = "iana_tz") -> str | None:
    """`None` when zoneinfo resolves the name, else a message. We never assume UTC.

    `key` names the config key the value came from, so the error points at the line the
    operator typed: `iana_tz` (unchanged wording) or `device_tz` (p1-12).
    """
    try:
        from zoneinfo import ZoneInfo

        ZoneInfo(iana_tz)
    except Exception as exc:  # ZoneInfoNotFoundError arrives as a KeyError subclass
        return f"{key} {iana_tz!r} is not a resolvable IANA zone ({type(exc).__name__})"
    return None


def _coerce_surface(value: str | ConfigSurface) -> ConfigSurface:
    """Validate a surface argument. An unknown spelling is refused, NOT downgraded: a
    typo'd `surface="agenta"` silently becoming CLI would be the §2d hole through the
    back door.
    """
    try:
        return ConfigSurface(value)
    except ValueError:
        known = ", ".join(s.value for s in ConfigSurface)
        raise ConfigError(f"surface {value!r} is unknown (accepted: {known})") from None


def _push_target_problem(target: str, *, key: str = "push_target") -> str | None:
    """`None` when the ref carries an accepted scheme, else a refusal naming it.

    §3: the target is an ABSTRACT ingest ref — an endpoint may never be invented or
    defaulted, so the only shapes that pass are the owner-authorized local stub and
    real HTTPS. Matched case-sensitively on purpose: `HTTPS://` in a config is a
    mistake worth a loud error, not a silently accepted one.
    """
    if target.startswith(PUSH_TARGET_SCHEMES):
        return None
    allowed = " or ".join(PUSH_TARGET_SCHEMES)
    return (
        f"{key} {target!r} has an unacceptable scheme: a push target must start with "
        f"{allowed} (never a default endpoint — docs/P2-SITE-AGENT.md §3)"
    )


def credential_ref(site: str, host: str) -> str:
    """The credential REFERENCE name for one device: `gateclerk-<site>-<host>` (§2d).

    A helper rather than a prose convention, so P2-04/05 (and the systemd unit naming
    `LoadCredential=` follows) cannot drift from each other by hand-crafting strings.
    Refs only, always: this produces a NAME to look a secret up under — macOS keeps the
    existing keychain scheme (`-s gateclerk-hikvision -a <host>` is unchanged), agent
    hosts resolve the name via systemd credentials or the `GATECLERK_<HOST>_PASSWORD`
    env rung. No password value ever passes through here.
    """
    for label, value in (("site", site), ("host", host)):
        if not value or not value.strip():
            raise ConfigError(f"credential_ref: {label} must not be empty")
    return f"gateclerk-{site.strip()}-{host.strip()}"


@dataclass(frozen=True, slots=True)
class DeviceTarget:
    """What the resolver needs to know about one device. Host is config, not a secret.

    `keychain_account` is the host by policy (DESIGN.md: "the keychain account is the
    host"), so plugging in site B/C is one `security add-generic-password` and no code.
    """

    host: str
    port: int = DEFAULT_PORT
    site: str | None = None
    keychain_service: str = DEFAULT_KEYCHAIN_SERVICE
    config_user: str | None = None

    @property
    def keychain_account(self) -> str:
        return self.host

    def find_command(self) -> str:
        """The exact read command, shell-quoted so the user can paste it."""
        return (
            "security find-generic-password "
            f"-s {shlex.quote(self.keychain_service)} "
            f"-a {shlex.quote(self.keychain_account)} -w"
        )

    def add_command(self) -> str:
        """The exact write command that would satisfy this target (a human runs it).

        `-j 'user=...'` because the comment is what carries the user hint; `-U` so a
        re-run updates instead of failing; `-w` last so the password is *prompted* and
        never typed onto a command line into shell history.
        """
        user = self.config_user or DEFAULT_ISAPI_USER
        return (
            "security add-generic-password -U "
            f"-s {shlex.quote(self.keychain_service)} "
            f"-a {shlex.quote(self.keychain_account)} "
            f"-j {shlex.quote(f'user={user}')} -w"
        )


@dataclass(frozen=True, slots=True)
class KeychainItem:
    """A generic-password item: the secret plus the comment that carries `user=...`."""

    password: Secret
    comment: str | None = None

    def user_hint(self) -> str | None:
        """The `user=` inside the comment, if the item carries one.

        Tolerant of surrounding text (`"gateclerk user=admin (site-a)"`): humans write these
        by hand, and a strict parser would make one typo mean re-entering the password.
        """
        if not self.comment:
            return None
        match = re.search(r"(?i)\buser\s*=\s*([^\s,;]+)", self.comment)
        return match.group(1) if match else None


@dataclass(frozen=True, slots=True)
class Credentials:
    """A resolved (user, password) plus where it came from.

    `repr` is written by hand rather than inherited from the dataclass: this object is
    exactly what a `--verbose` log line or a failed assertion would print.
    """

    user: str
    password: Secret
    source: CredentialSource
    host: str | None = None

    def __repr__(self) -> str:
        return (
            f"Credentials(user={self.user!r}, password={self.password!r}, "
            f"source={self.source.value!r}, host={self.host!r})"
        )

    def describe(self) -> str:
        """Safe one-liner for humans: identity and provenance, no secret."""
        where = f"@{self.host}" if self.host else ""
        return f"{self.user}{where} via {self.source.value}"


#: The seam p1-03 codes against. A *provider* is called per authentication attempt, so a
#: long-lived client can re-read the keychain when a digest nonce goes stale without ever
#: holding the plaintext. Nothing downstream may stash `provider().password.reveal()`.
CredentialProvider = Callable[[], Credentials]


# --- env rung ------------------------------------------------------------------------


def host_env_prefix(host: str) -> str:
    """`192.0.2.10` -> `GATECLERK_192_0_2_10`; `dev.example.com` -> `GATECLERK_DEV_EXAMPLE_COM`.

    Every non-alphanumeric becomes `_` so the result is a legal shell variable — which is
    what makes a per-host override settable from a shell, a dotenv, or systemd's
    EnvironmentFile without quoting games.
    """
    sanitized = re.sub(r"[^A-Za-z0-9]", "_", host).strip("_").upper()
    if not sanitized:
        raise ConfigError(f"host {host!r} sanitizes to an empty env var name")
    return f"{ENV_PREFIX}_{sanitized}"


def env_var_names(host: str) -> tuple[str, str, str, str]:
    """(per-host user, per-host password, global user, global password).

    The tuple order IS the precedence: per-host beats global, because "override this
    device" is more specific than "override whatever device".
    """
    prefix = host_env_prefix(host)
    return (
        f"{prefix}_USER",
        f"{prefix}_PASSWORD",
        f"{ENV_PREFIX}_USER",
        f"{ENV_PREFIX}_PASSWORD",
    )


# --- keychain rung -------------------------------------------------------------------


class KeychainReader:
    """Read `service`/`account` generic-password items through `/usr/bin/security`.

    `runner` is injectable and defaults to `subprocess.run`; every test hands in a fake,
    so CI never spawns `security` (DoD: no real keychain calls in CI).

    The secret needs `-w`; the comment needs the attribute dump, which is a *second*
    invocation. Since each invocation can raise a macOS ACL prompt, the attribute call is
    opt-out (`with_comment=False`) and the resolver skips it whenever the user is already
    known from a flag, env, or sites.toml.
    """

    def __init__(
        self,
        *,
        runner: Callable[..., subprocess.CompletedProcess[bytes]] | None = None,
        binary: str = SECURITY_BIN,
    ) -> None:
        self._runner = runner
        self._binary = binary

    def read(self, target: DeviceTarget, *, with_comment: bool = True) -> KeychainItem:
        # The availability guard protects against a confusing OSError from spawning a
        # nonexistent binary on a non-macOS host. It is therefore a property of the REAL
        # subprocess: when a runner is injected, no OS process is involved and the guard
        # must not preempt it — otherwise every injected-runner keychain test passes on a
        # Mac and fails on Linux CI, which has no /usr/bin/security. (That is exactly the
        # CI-only failure this line used to cause.)
        if self._runner is None and shutil.which(self._binary) is None:
            raise CredentialUnavailable(
                f"no credential found for {target.host!r} in the environment, and the macOS "
                f"Keychain is unavailable here ({self._binary} not found). "
                f"Set {env_var_names(target.host)[1]} or pass --password."
            )
        raw = self._run(target, with_secret=True)
        password = raw.decode("utf-8", "surrogateescape").strip()
        if not password:
            raise self._denied(target, "the item exists but its password is empty")
        comment = None
        if with_comment:
            attributes = self._run(target, with_secret=False).decode("utf-8", "surrogateescape")
            # Verbatim is safe here: VERIFIED the attribute dump carries no `password`
            # field — only the human-written comment.
            comment = _parse_icmt(attributes)
        return KeychainItem(
            password=Secret(password, label=f"keychain:{target.host}"), comment=comment
        )

    def _run(self, target: DeviceTarget, *, with_secret: bool) -> bytes:
        argv = [
            self._binary,
            "find-generic-password",
            "-s",
            target.keychain_service,
            "-a",
            target.keychain_account,
        ]
        if with_secret:
            argv.append("-w")
        runner = self._runner or subprocess.run
        try:
            proc = runner(argv, capture_output=True, check=False)
        except OSError as exc:
            raise self._denied(target, f"could not be executed ({exc.strerror or exc})") from exc
        if proc.returncode != 0:
            stderr = redact_b64((proc.stderr or b"").decode("utf-8", "surrogateescape").strip())
            if proc.returncode == KEYCHAIN_EXIT_NOT_FOUND:
                raise CredentialUnavailable(
                    f"keychain item missing for {target.host!r}: no generic password for "
                    f"service {target.keychain_service!r}, account {target.keychain_account!r}.\n"
                    f"    read that failed:  {target.find_command()}\n"
                    f"    add the item with: {target.add_command()}"
                )
            raise self._denied(
                target, f"exited {proc.returncode}" + (f": {stderr}" if stderr else "")
            )
        return _as_bytes(proc.stdout)

    def _denied(self, target: DeviceTarget, why: str) -> CredentialUnavailable:
        return CredentialUnavailable(
            f"keychain access denied or unusable for {target.host!r} ({why}). "
            f"Check with:\n    {target.find_command()}\n"
            f"or override with --password / {env_var_names(target.host)[1]}."
        )


def _as_bytes(value: object) -> bytes:
    """Accept byte or text streams so a test fake can hand back a plain str."""
    if isinstance(value, bytes):
        return value
    if isinstance(value, str):
        return value.encode()
    return b""


_ICMT = re.compile(r'"icmt"<blob>="([^"]*)"')


def _parse_icmt(attributes_text: str) -> str | None:
    """The `icmt` (comment) field of a `security find-generic-password` dump."""
    match = _ICMT.search(attributes_text)
    if not match or match.group(1) == "<NULL>":
        return None
    return match.group(1)


# --- resolution ----------------------------------------------------------------------


def resolve_credentials(
    target: DeviceTarget,
    *,
    user: str | None = None,
    password: str | None = None,
    env: Mapping[str, str] | None = None,
    keychain: KeychainReader | None = None,
) -> Credentials:
    """Resolve (user, password) for a device. **flag > env > keychain**, nothing else.

    `user`/`password` are the CLI flag values (None when the flag was not given). The
    *user* has extra rungs after env — `sites.toml`'s `isapi_user`, then the keychain
    item's `user=` comment, then `admin` — because DESIGN.md calls the comment a hint
    ("overridable ... unless overridden"), not an authority.

    Raises `CredentialUnavailable` naming the source and the exact command/variable that
    would fix it. No password in any message, including on the failure path.
    """
    environ: Mapping[str, str] = os.environ if env is None else env
    host_user, host_password, global_user, global_password = env_var_names(target.host)

    keychain_user: str | None = None
    if password is not None:
        secret: Secret = Secret(password, label=f"flag:{target.host}")
        source = CredentialSource.FLAG
    elif (env_pw := _first_set(environ, host_password, global_password)) is not None:
        secret = Secret(env_pw, label=f"env:{target.host}")
        source = CredentialSource.ENV
    else:
        # Only pay for the second (`icmt`) security call if nothing else can name the user.
        need_user = not (user or _first_set(environ, host_user, global_user) or target.config_user)
        item = (keychain or KeychainReader()).read(target, with_comment=need_user)
        secret = item.password
        source = CredentialSource.KEYCHAIN
        keychain_user = item.user_hint() if need_user else None

    resolved_user = _resolve_user(
        target,
        flag_user=user,
        environ=environ,
        host_user=host_user,
        global_user=global_user,
        keychain_user=keychain_user,
    )
    creds = Credentials(user=resolved_user, password=secret, source=source, host=target.host)
    if not creds.password.reveal():
        raise CredentialUnavailable(
            f"resolved an EMPTY password for {target.host!r} from {source.value}. "
            "An empty password is never a valid ISAPI credential; unset the variable or "
            "re-enter the keychain item."
        )
    return creds


def _resolve_user(
    target: DeviceTarget,
    *,
    flag_user: str | None,
    environ: Mapping[str, str],
    host_user: str,
    global_user: str,
    keychain_user: str | None,
) -> str:
    """flag > env > sites.toml isapi_user > keychain `user=` comment > `admin`."""
    for candidate in (
        flag_user,
        _first_set(environ, host_user, global_user),
        target.config_user,
        keychain_user,
    ):
        if candidate:
            return candidate
    return DEFAULT_ISAPI_USER


def _first_set(environ: Mapping[str, str], *names: str) -> str | None:
    """First non-empty value among `names`. An empty variable means unset, not ''.

    That distinction matters: `GATECLERK_PASSWORD=` in a half-filled `.env` must fall
    through to the keychain, not resolve to a blank password and burn a 401 (and part of
    the device's lockout budget) before anyone notices.
    """
    for name in names:
        value = environ.get(name)
        if value:
            return value
    return None


def credential_provider(
    target: DeviceTarget,
    *,
    user: str | None = None,
    password: str | None = None,
    env: Mapping[str, str] | None = None,
    keychain: KeychainReader | None = None,
) -> CredentialProvider:
    """A *callable* that resolves on demand — what the ISAPI client receives.

    Re-resolution is the feature: a digest nonce can expire minutes into a paged pull,
    and at that moment the client asks for a credential instead of reaching for one it
    cached. It also means no plaintext password ever lives on the client object.
    """
    return lambda: resolve_credentials(
        target, user=user, password=password, env=env, keychain=keychain
    )


# --- sites.toml ----------------------------------------------------------------------


def _warn_stderr(message: str) -> None:
    """The default warning emitter: stderr via the shared console, the `--verbose`/
    jsonl-pipe invariant (stdout stays parseable) that p1-05c/p1-06c established.
    """
    from gateclerk.output import make_console  # local import: config must stay cheap

    make_console(stderr=True).print(message, markup=False)


def load_sites(
    path: Path | str = DEFAULT_SITES_FILE,
    *,
    surface: str | ConfigSurface = "cli",
) -> dict[str, SiteConfig]:
    """Parse `sites.toml` into `{name: SiteConfig}`. Raises on a bad file or bad block.

    `surface` says which process is reading (see `ConfigSurface`): the agent surface
    refuses a block without an explicit `iana_tz` (docs/P2-SITE-AGENT.md §2d).
    """
    file = Path(path)
    try:
        raw = file.read_bytes()
    except FileNotFoundError:
        raise ConfigError(
            f"sites file {file} not found. Create it with one [[site]] block (see "
            "docs/DESIGN.md 'Credential plumbing') or pass --config / --host."
        ) from None
    except OSError as exc:
        raise ConfigError(f"cannot read sites file {file}: {exc.strerror or exc}") from exc
    return parse_sites(raw, origin=str(file), surface=surface)


def parse_sites(
    raw: bytes,
    *,
    origin: str = "<bytes>",
    surface: str | ConfigSurface = "cli",
) -> dict[str, SiteConfig]:
    """Parse the TOML bytes of a sites file.

    No redaction on the way in: this is *our own* config text and mangling base64-shaped
    runs would corrupt it. A sites file has no business carrying a password, and if one
    appears the value simply becomes a config string — the credential path never reads
    it (and any such key is refused outright as unknown, DoD: refs-only).
    """
    try:
        data = tomllib.loads(raw.decode("utf-8"))
    except (tomllib.TOMLDecodeError, UnicodeDecodeError) as exc:
        raise ConfigError(f"{origin} is not valid TOML: {redact_b64(str(exc))}") from exc
    blocks = data.get("site")
    if blocks is None:
        return {}
    if not isinstance(blocks, list):
        raise ConfigError(f"{origin}: [[site]] must be an array of tables")
    sites: dict[str, SiteConfig] = {}
    for block in blocks:
        if not isinstance(block, Mapping):
            raise ConfigError(f"{origin}: a [[site]] entry is not a table")
        site = SiteConfig.from_table(block, surface=surface)
        if site.name in sites:
            raise ConfigError(f"{origin}: duplicate site name {site.name!r}")
        sites[site.name] = site
    return sites


def find_site(sites: Mapping[str, SiteConfig], name: str) -> SiteConfig:
    """Look a site up by name, with the useful error when it isn't there."""
    try:
        return sites[name]
    except KeyError:
        known = ", ".join(sorted(sites)) or "(none configured)"
        raise ConfigError(f"no site named {name!r}; configured: {known}") from None


def site_from_args(
    *,
    site: str | None = None,
    host: str | None = None,
    port: int = DEFAULT_PORT,
    config_path: Path | str | None = None,
    surface: str | ConfigSurface = "cli",
    warn: Callable[[str], None] | None = None,
) -> SiteConfig:
    """`--site NAME` reads that block from sites.toml; `--host` builds a one-off.

    There is deliberately **no implicit default site**, even when sites.toml holds exactly
    one block. A connector for door hardware must never guess which door to talk to: the
    file can be a leftover from another directory, and P1's config carries a real site
    address. Exactly one of the two flags is required.

    P2-01 scoping decision (card: "validator enabled for the agent surface AND warns on
    CLI `--site` reads"): a CLI-surface read of a block with no `iana_tz` still works —
    P1's `--tz` precedence keeps `DEFAULT_IANA_TZ` as the fallback and no existing
    command starts failing — but it is exactly the defaulted-payroll-truth situation
    §2d refuses, so one `warning:` line naming site+key goes to stderr (`warn` injects a
    collector for tests). The agent surface never warns: it raises (see `ConfigSurface`).
    """
    if site is not None and host is not None:
        raise ConfigError("--site and --host are mutually exclusive — pick one device")
    if site is not None:
        found = find_site(load_sites(config_path or DEFAULT_SITES_FILE, surface=surface), site)
        if found.iana_tz is None:
            message = (
                f"warning: site {found.name!r} has no iana_tz in sites.toml; UTC math "
                "falls back to the compiled-in default (a site-a value). Site timezone "
                "is payroll truth — declare iana_tz explicitly (docs/P2-SITE-AGENT.md §2d)."
            )
            (warn or _warn_stderr)(message)
        return found
    if host is not None:
        # A `--host` one-off has no block, so there is no missing key to warn about —
        # and P1 built these with no zone for months; byte-for-byte behaviour.
        return SiteConfig(name=site or host, host=host, port=port, surface=_coerce_surface(surface))
    raise ConfigError(
        "no device given: pass --host HOST or --site NAME (sites.toml is only read for "
        "--site; this tool never guesses which device to poll)."
    )


def safe_line(parts: Iterable[tuple[str, object]], *secrets: Secret | str | None) -> str:
    """Render `k=v` diagnostics with every secret masked.

    Diagnostics are where credentials leak in real projects, so the sanctioned renderer
    takes the secrets as arguments and redacts the finished line: a caller has to go out
    of its way to leak rather than into it.
    """
    line = " ".join(f"{key}={value}" for key, value in parts if value is not None)
    return redact(line, *secrets)


def describe_target(target: DeviceTarget, creds: Credentials) -> str:
    """The one line a `--verbose` run prints about a connection. Never the secret."""
    return safe_line(
        [
            ("target", f"{creds.user}@{target.host}:{target.port}"),
            ("site", target.site),
            ("creds", creds.source.value),
        ],
        creds.password,
    )
