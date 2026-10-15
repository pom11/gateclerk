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

import os
import re
import shlex
import shutil
import subprocess
import tomllib
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Any

from gateclerk.exceptions import ConfigError, CredentialUnavailable, redact_b64
from gateclerk.secrets import Secret, redact

__all__ = [
    "DEFAULT_IANA_TZ",
    "DEFAULT_ISAPI_USER",
    "DEFAULT_KEYCHAIN_SERVICE",
    "DEFAULT_PAGE_DELAY_MS",
    "DEFAULT_PORT",
    "DEFAULT_SITES_FILE",
    "DEFAULT_TIMEOUT_S",
    "ENV_PREFIX",
    "KEYCHAIN_EXIT_NOT_FOUND",
    "SECURITY_BIN",
    "CredentialProvider",
    "CredentialSource",
    "Credentials",
    "DeviceTarget",
    "KeychainItem",
    "KeychainReader",
    "SiteConfig",
    "credential_provider",
    "describe_target",
    "env_var_names",
    "find_site",
    "host_env_prefix",
    "load_sites",
    "load_sites_if_present",
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

ENV_PREFIX = "GATECLERK"
SECURITY_BIN = "/usr/bin/security"

#: What `security` exits when the item simply is not in the keychain (VERIFIED, above).
KEYCHAIN_EXIT_NOT_FOUND = 44


class CredentialSource(StrEnum):
    """Where a resolved credential came from. Safe to print; never the secret."""

    FLAG = "flag"
    ENV = "env"
    KEYCHAIN = "keychain"


@dataclass(frozen=True, slots=True)
class SiteConfig:
    """One `[[site]]` block of `sites.toml` — the non-secret half of a connection."""

    name: str
    host: str
    port: int = DEFAULT_PORT
    timeout_s: float = DEFAULT_TIMEOUT_S
    page_delay_ms: int = DEFAULT_PAGE_DELAY_MS
    iana_tz: str | None = None
    isapi_user: str = DEFAULT_ISAPI_USER
    keychain_service: str = DEFAULT_KEYCHAIN_SERVICE

    #: Keys a `[[site]]` block may carry. Anything else is refused loudly: a silently
    #: ignored `timeout_s = 5` would mean we poll a door controller for 30 s and believe
    #: we configured 5.
    _KNOWN_KEYS = frozenset(
        {
            "name",
            "host",
            "port",
            "timeout_s",
            "page_delay_ms",
            "iana_tz",
            "isapi_user",
            "keychain_service",
        }
    )

    def __post_init__(self) -> None:
        self.validate()

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
        """Fail loudly and before any network call. p1-08 maps this to exit 2."""
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
        if not self.keychain_service.strip():
            problems.append("keychain_service must not be empty")
        if problems:
            raise ConfigError(f"site {self.name!r} is misconfigured: {('; '.join(problems))}")

    @classmethod
    def from_table(cls, table: Mapping[str, Any]) -> SiteConfig:
        """Build from one parsed TOML table, rejecting unknown keys and wrong types."""
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
            isapi_user=_text(table.get("isapi_user", DEFAULT_ISAPI_USER), "isapi_user"),
            keychain_service=_text(
                table.get("keychain_service", DEFAULT_KEYCHAIN_SERVICE), "keychain_service"
            ),
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


def _tz_problem(iana_tz: str) -> str | None:
    """`None` when zoneinfo resolves the name, else a message. We never assume UTC."""
    try:
        from zoneinfo import ZoneInfo

        ZoneInfo(iana_tz)
    except Exception as exc:  # ZoneInfoNotFoundError arrives as a KeyError subclass
        return f"iana_tz {iana_tz!r} is not a resolvable IANA zone ({type(exc).__name__})"
    return None


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
        if shutil.which(self._binary) is None:
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


def load_sites(path: Path | str = DEFAULT_SITES_FILE) -> dict[str, SiteConfig]:
    """Parse `sites.toml` into `{name: SiteConfig}`. Raises on a bad file or bad block."""
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
    return parse_sites(raw, origin=str(file))


def load_sites_if_present(path: Path | str = DEFAULT_SITES_FILE) -> dict[str, SiteConfig]:
    """As `load_sites`, but an absent file means "no sites configured", not an error."""
    try:
        return load_sites(path)
    except ConfigError as exc:
        if "not found" in str(exc):
            return {}
        raise


def parse_sites(raw: bytes, *, origin: str = "<bytes>") -> dict[str, SiteConfig]:
    """Parse the TOML bytes of a sites file.

    No redaction on the way in: this is *our own* config text and mangling base64-shaped
    runs would corrupt it. A sites file has no business carrying a password, and if one
    appears the value simply becomes a config string — the credential path never reads it.
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
        site = SiteConfig.from_table(block)
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
) -> SiteConfig:
    """`--site NAME` reads that block; `--host` builds a one-off; neither, one site wins.

    A single `[[site]]` block is used implicitly so the one-device case needs no ceremony,
    while `--site` becomes required the moment a second site exists — guessing which door
    controller to poll is not a default anybody should have.
    """
    if site is not None:
        return find_site(load_sites(config_path or DEFAULT_SITES_FILE), site)
    if host is not None:
        return SiteConfig(name=host, host=host, port=port)
    sites = load_sites_if_present(config_path or DEFAULT_SITES_FILE)
    if len(sites) == 1:
        return next(iter(sites.values()))
    configured = ", ".join(sorted(sites)) or "none configured"
    raise ConfigError(
        f"no device given: pass --host HOST (or --site NAME with sites.toml). Sites: {configured}"
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
