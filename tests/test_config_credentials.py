"""Credential + config resolution (p1-02): sources, precedence, redaction.

Fully offline. Every keychain read goes through an injected fake `runner`, so `security`
is never spawned here — and `test_the_default_runner_is_never_used` proves that claim
instead of trusting it. Hosts are TEST-NET addresses per tests/test_repo_hygiene.py.

VERIFIED shapes (the fake returns exactly what the real CLI printed in a 2026-10-15
probe against a throwaway keychain — see config.py's module docstring):
    -w              -> "<the secret>\\n"
    no -w           -> the attribute list, comment as   "icmt"<blob>="user=admin"
    missing item    -> exit 44, `SecKeychainSearchCopyNext: The specified item could
                       not be found in the keychain.`
"""

from __future__ import annotations

import shlex
import subprocess
from pathlib import Path
from typing import Any

import pytest

from gateclerk.config import (
    DEFAULT_ISAPI_USER,
    DEFAULT_KEYCHAIN_SERVICE,
    DEFAULT_PAGE_DELAY_MS,
    DEFAULT_PORT,
    DEFAULT_TIMEOUT_S,
    KEYCHAIN_EXIT_NOT_FOUND,
    Credentials,
    CredentialSource,
    DeviceTarget,
    KeychainItem,
    KeychainReader,
    SiteConfig,
    credential_provider,
    describe_target,
    env_var_names,
    find_site,
    host_env_prefix,
    load_sites,
    parse_sites,
    resolve_credentials,
    safe_line,
    site_from_args,
)
from gateclerk.exceptions import ConfigError, CredentialUnavailable, redact_b64
from gateclerk.secrets import MASK, Secret, redact

HOST = "192.0.2.10"
PW = "fake-pw"
SECRET_STDOUT = f"{PW}\n".encode()
ATTRS_STDOUT = (
    b'keychain: "/Users/x/Library/Keychains/login.keychain-db"\n'
    b'version: 512\nclass: "genp"\nattributes:\n'
    b'    0x00000007 <blob>="gateclerk-hikvision"\n'
    b'    "acct"<blob>="192.0.2.10"\n'
    b'    "icmt"<blob>="user=admin"\n'
    b'    "svce"<blob>="gateclerk-hikvision"\n'
)
NOT_FOUND_STDERR = (
    b"security: SecKeychainSearchCopyNext: The specified item could not be found in the keychain.\n"
)


def target(**over: Any) -> DeviceTarget:
    params: dict[str, Any] = {"host": HOST}
    params.update(over)
    return DeviceTarget(**params)


class FakeSecurity:
    """Stand-in for `/usr/bin/security`. Records every argv so the exact command is testable."""

    def __init__(
        self,
        *,
        secret: bytes | str = SECRET_STDOUT,
        attributes: bytes | str = ATTRS_STDOUT,
        secret_rc: int = 0,
        secret_stderr: bytes = b"",
        attrs_rc: int = 0,
        attrs_stderr: bytes = b"",
        raise_os_error: OSError | None = None,
    ) -> None:
        self.secret = secret
        self.attributes = attributes
        self.secret_rc = secret_rc
        self.secret_stderr = secret_stderr
        self.attrs_rc = attrs_rc
        self.attrs_stderr = attrs_stderr
        self.raise_os_error = raise_os_error
        self.calls: list[list[str]] = []

    def __call__(self, argv: list[str], **kwargs: Any) -> subprocess.CompletedProcess[Any]:
        self.calls.append(list(argv))
        if self.raise_os_error is not None:
            raise self.raise_os_error
        with_secret = argv[-1] == "-w"
        return subprocess.CompletedProcess(
            args=argv,
            returncode=self.secret_rc if with_secret else self.attrs_rc,
            stdout=self.secret if with_secret else self.attributes,
            stderr=self.secret_stderr if with_secret else self.attrs_stderr,
        )

    @property
    def with_secret(self) -> list[str]:
        return next(c for c in self.calls if c[-1] == "-w")

    @property
    def without_secret(self) -> list[str]:
        return next(c for c in self.calls if c[-1] != "-w")


def reader(fake: FakeSecurity) -> KeychainReader:
    return KeychainReader(runner=fake)


@pytest.fixture(autouse=True)
def pretend_no_security_binary(monkeypatch: pytest.MonkeyPatch) -> None:
    """Make this whole file behave the same on a Mac and on Linux CI.

    CI runs on ubuntu-latest, where `/usr/bin/security` does not exist. Every test here
    injects a fake runner, so none of them needs the binary — but if the product code ever
    consults `shutil.which` before the injected runner, the suite passes on macOS and
    fails on CI. Forcing `which` to return None pins that platform independence in, rather
    than leaving it to the developer's laptop.
    """
    import gateclerk.config as cfg

    monkeypatch.setattr(cfg.shutil, "which", lambda _path: None)


def resolve(**over: Any) -> Credentials:
    """Resolve against a fake keychain; env defaults to empty so the keychain rung is live."""
    params: dict[str, Any] = {"env": {}}
    params.update(over)
    fake = params.pop("fake", FakeSecurity())
    return resolve_credentials(target(), keychain=reader(fake), **params)


# --- sites.toml: the DESIGN.md schema --------------------------------------------------

SITE_A_TOML = """
[[site]]
name = "site-a"
host = "192.0.2.10"
port = 80
iana_tz = "Europe/Bucharest"
isapi_user = "admin"
keychain_service = "gateclerk-hikvision"
"""


def test_the_documented_site_block_parses() -> None:
    """DESIGN.md's `[[site]]` block is the contract — every documented key must land."""
    sites = parse_sites(SITE_A_TOML.encode())
    site = find_site(sites, "site-a")
    assert site.host == HOST
    assert site.port == DEFAULT_PORT == 80
    assert site.iana_tz == "Europe/Bucharest"
    assert site.isapi_user == "admin"
    assert site.keychain_service == DEFAULT_KEYCHAIN_SERVICE == "gateclerk-hikvision"


def test_defaults_match_design_decisions() -> None:
    """port 80 / 30 s / 100 ms page delay: DESIGN.md numbers, not local whims."""
    site = parse_sites(b'[[site]]\nname = "s"\nhost = "192.0.2.1"\n')["s"]
    assert (site.port, site.timeout_s, site.page_delay_ms) == (80, 30.0, 100)
    assert (DEFAULT_PORT, DEFAULT_TIMEOUT_S, DEFAULT_PAGE_DELAY_MS) == (80, 30.0, 100)
    assert site.isapi_user == DEFAULT_ISAPI_USER == "admin"
    assert site.iana_tz is None


def test_target_carries_keychain_identity_from_the_site() -> None:
    site = parse_sites(SITE_A_TOML.encode())["site-a"]
    tgt = site.target()
    assert tgt.keychain_account == HOST, "the keychain account IS the host (DESIGN.md)"
    assert tgt.keychain_service == "gateclerk-hikvision"
    assert tgt.config_user == "admin"
    assert tgt.site == "site-a"
    assert tgt.port == 80


def test_unknown_key_is_refused_not_ignored() -> None:
    """A silently dropped `timeout = 5` would poll a door controller for 30 s believing 5."""
    with pytest.raises(ConfigError, match="unknown key"):
        parse_sites(b'[[site]]\nname = "s"\nhost = "h"\ntimeout = 5\n')


@pytest.mark.parametrize(
    ("toml", "needle"),
    [
        (b'[[site]]\nname = "s"\n', "missing required key 'host'"),
        (b'[[site]]\nhost = "h"\n', "missing required key 'name'"),
        (b"[site]\nname = 's'\n", "array of tables"),
        (b"not toml at all =", "not valid TOML"),
        (b'[[site]]\nname = "a"\nhost = "h"\n[[site]]\nname = "a"\nhost = "i"\n', "duplicate"),
        (b'[[site]]\nname = "s"\nhost = 8\n', "host must be a string"),
        (b'[[site]]\nname = "s"\nhost = "h"\nport = "80"\n', "port must be an integer"),
        (b'[[site]]\nname = "s"\nhost = "h"\nport = true\n', "port must be an integer"),
    ],
)
def test_bad_config_says_what_is_wrong(toml: bytes, needle: str) -> None:
    with pytest.raises(ConfigError) as exc:
        parse_sites(toml)
    assert needle in str(exc.value)


@pytest.mark.parametrize(
    ("toml", "needle"),
    [
        (b'[[site]]\nname = "s"\nhost = "h"\nport = 0\n', "port 0 out of range"),
        (b'[[site]]\nname = "s"\nhost = "h"\nport = 70000\n', "port 70000 out of range"),
        (b'[[site]]\nname = "s"\nhost = "h"\ntimeout_s = 0\n', "timeout_s"),
        (b'[[site]]\nname = "s"\nhost = "h"\npage_delay_ms = -1\n', "page_delay_ms"),
        (b'[[site]]\nname = ""\nhost = "h"\n', "name must not be empty"),
        (b'[[site]]\nname = "s"\nhost = "  "\n', "host must not be empty"),
        (b'[[site]]\nname = "s"\nhost = "h"\niana_tz = "Mars/Olympus_Mons"\n', "iana_tz"),
        (b'[[site]]\nname = "s"\nhost = "h"\nkeychain_service = ""\n', "keychain_service"),
    ],
)
def test_validation_rejects_values_that_would_burn_a_request(toml: bytes, needle: str) -> None:
    with pytest.raises(ConfigError, match=needle):
        parse_sites(toml)


def test_constructor_validates_too_so_no_unvalidated_path_exists() -> None:
    """Not only TOML: `SiteConfig(...)` directly must refuse the same nonsense."""
    with pytest.raises(ConfigError, match="port"):
        SiteConfig(name="s", host="h", port=99999)
    with pytest.raises(ConfigError, match="port"):
        target_site = SiteConfig(name="s", host="h")
        object.__setattr__(target_site, "port", -1)
        target_site.validate()


def test_load_sites_reports_a_missing_file_as_actionable(tmp_path: Path) -> None:
    with pytest.raises(ConfigError, match="not found"):
        load_sites(tmp_path / "nope.toml")


def test_load_sites_reads_a_real_file(tmp_path: Path) -> None:
    path = tmp_path / "sites.toml"
    path.write_text(SITE_A_TOML, encoding="utf-8")
    assert find_site(load_sites(path), "site-a").host == HOST
    # A malformed file is a hard error, never silently treated as "no sites".
    bad = tmp_path / "bad.toml"
    bad.write_text("= no", encoding="utf-8")
    with pytest.raises(ConfigError, match="not valid TOML"):
        load_sites(bad)


def test_the_shipped_example_config_actually_parses() -> None:
    """Docs drift silently; this makes `sites.toml.example` executable documentation.

    The file is the one a human copies when wiring a site, so a wrong key name in it is a
    broken first experience — and it must stay TEST-NET like every other committed address.
    """
    from gateclerk.config import DEFAULT_PORT, DEFAULT_TIMEOUT_S

    example = Path(__file__).resolve().parents[1] / "sites.toml.example"
    site = find_site(load_sites(example), "site-a")
    assert site.port == DEFAULT_PORT == 80
    assert site.timeout_s == DEFAULT_TIMEOUT_S
    assert site.iana_tz == "Europe/Bucharest"
    assert site.keychain_service == DEFAULT_KEYCHAIN_SERVICE
    assert site.isapi_user == DEFAULT_ISAPI_USER
    assert site.host in {"192.0.2.10"}, "the example must not name a real device"


def test_find_site_names_what_is_configured() -> None:
    sites = parse_sites(SITE_A_TOML.encode())
    with pytest.raises(ConfigError) as exc:
        find_site(sites, "site-z")
    msg = str(exc.value)
    assert "no site named 'site-z'" in msg
    assert "site-a" in msg, "the error must list what IS configured"
    with pytest.raises(ConfigError, match="none configured"):
        find_site({}, "anything")


def test_site_from_args_requires_an_explicit_device(tmp_path: Path) -> None:
    path = tmp_path / "sites.toml"
    path.write_text(SITE_A_TOML, encoding="utf-8")
    assert site_from_args(site="site-a", config_path=path).host == HOST
    assert site_from_args(host="192.0.2.99", config_path=path).host == "192.0.2.99"
    # --site and --host cannot both name a device.
    with pytest.raises(ConfigError, match="mutually exclusive"):
        site_from_args(site="site-a", host="192.0.2.99", config_path=path)
    # NEITHER flag: refused even though exactly one site is configured. The connector must
    # never resolve to a device the user did not name — a stale sites.toml in the cwd that
    # happens to carry a real site address must not become the default target.
    with pytest.raises(ConfigError, match="no device given"):
        site_from_args(config_path=path)
    with pytest.raises(ConfigError, match="no device given"):
        site_from_args(config_path=tmp_path / "absent.toml")


# --- env rung --------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("host", "want"),
    [
        ("192.0.2.10", "GATECLERK_192_0_2_10"),
        ("dev.example.com", "GATECLERK_DEV_EXAMPLE_COM"),
        ("door-1.lan", "GATECLERK_DOOR_1_LAN"),
        ("admin@192.0.2.10", "GATECLERK_ADMIN_192_0_2_10"),
    ],
)
def test_host_sanitizes_to_a_legal_shell_variable(host: str, want: str) -> None:
    got = host_env_prefix(host)
    assert got == want
    assert got.isidentifier(), f"{got} must be usable as a shell/EnvironmentFile variable"


def test_a_host_that_sanitizes_to_nothing_is_an_error_not_an_empty_varname() -> None:
    with pytest.raises(ConfigError, match="sanitizes to an empty"):
        host_env_prefix("...")


def test_env_var_names_are_per_host_before_global() -> None:
    host_user, host_pw, glob_user, glob_pw = env_var_names(HOST)
    assert (host_user, host_pw) == ("GATECLERK_192_0_2_10_USER", "GATECLERK_192_0_2_10_PASSWORD")
    assert (glob_user, glob_pw) == ("GATECLERK_USER", "GATECLERK_PASSWORD")


def test_per_host_env_beats_the_global_env() -> None:
    creds = resolve(
        env={
            "GATECLERK_192_0_2_10_PASSWORD": "fake-pw",
            "GATECLERK_PASSWORD": "test-pw",
            "GATECLERK_192_0_2_10_USER": "isapi-a",
            "GATECLERK_USER": "isapi-b",
        },
        fake=FakeSecurity(),
    )
    assert creds.source is CredentialSource.ENV
    assert creds.user == "isapi-a"
    assert creds.password.reveal() == "fake-pw"


def test_global_env_is_used_when_no_per_host_value_exists() -> None:
    creds = resolve(env={"GATECLERK_PASSWORD": "fake-pw"}, fake=FakeSecurity())
    assert creds.source is CredentialSource.ENV
    assert creds.password.reveal() == "fake-pw"


def test_an_empty_env_var_means_unset_and_falls_through_to_keychain() -> None:
    """`GATECLERK_PASSWORD=` in a half-filled .env must not burn a 401 + lockout budget."""
    fake = FakeSecurity()
    creds = resolve(env={"GATECLERK_PASSWORD": ""}, fake=fake)
    assert creds.source is CredentialSource.KEYCHAIN
    assert creds.password.reveal() == PW
    assert fake.calls, "and it actually asked the keychain"


# --- keychain rung ---------------------------------------------------------------------


def test_keychain_argv_is_exactly_the_documented_command() -> None:
    fake = FakeSecurity()
    resolve(fake=fake)
    argv = fake.with_secret
    assert argv[0] == "/usr/bin/security"
    assert argv[1] == "find-generic-password"
    assert argv[2:] == ["-s", "gateclerk-hikvision", "-a", HOST, "-w"]
    assert HOST in fake.without_secret, "account = host, never the site name"


def test_service_and_account_come_from_the_site_block() -> None:
    fake = FakeSecurity()
    tgt = target(keychain_service="gateclerk-site-b")
    resolve_credentials(tgt, env={}, keychain=reader(fake))
    argv = fake.with_secret
    assert argv[argv.index("-s") + 1] == "gateclerk-site-b"
    assert argv[argv.index("-a") + 1] == HOST


def test_user_is_parsed_from_the_icmt_comment() -> None:
    item = KeychainReader(runner=FakeSecurity()).read(target())
    assert item.comment == "user=admin"
    assert item.user_hint() == "admin"


@pytest.mark.parametrize(
    ("comment", "want"),
    [
        ("user=admin", "admin"),
        ("user = isapi_svc", "isapi_svc"),
        ("USER=Root", "Root"),
        ("gateclerk user=admin (site-a)", "admin"),
        ("site-b; user=svc-b, added 2026-10-15", "svc-b"),
        ("no hint here", None),
        ("", None),
        (None, None),
    ],
)
def test_user_hint_is_tolerant_of_human_comment_text(comment: str | None, want: str | None) -> None:
    """A human writes these by hand; a typo in the prose must not force re-typing the pw."""
    assert KeychainItem(password=Secret(PW), comment=comment).user_hint() == want


def test_missing_icmt_is_not_an_error() -> None:
    fake = FakeSecurity(attributes=b'    "icmt"<blob>=<NULL>\n')
    assert KeychainReader(runner=fake).read(target()).comment is None


def test_second_call_only_happens_when_the_user_is_still_unknown() -> None:
    """Each `security` call can raise a macOS ACL prompt — do not make two if one will do."""
    fake = FakeSecurity()
    resolve(fake=fake)
    assert len(fake.calls) == 2, "secret + attributes, because nothing else named the user"

    fake2 = FakeSecurity()
    resolve(user="admin", fake=fake2)
    assert len(fake2.calls) == 1, "user already known: no second prompt"

    fake3 = FakeSecurity()
    resolve_credentials(target(config_user="isapi"), env={}, keychain=reader(fake3))
    assert len(fake3.calls) == 1, "sites.toml already names the user"

    # env names the user, so the password comes from the keychain with ONE call (no icmt).
    fake4 = FakeSecurity()
    creds4 = resolve(env={"GATECLERK_USER": "isapi"}, fake=fake4)
    assert len(fake4.calls) == 1, "password from keychain, user from env: no attribute call"
    assert creds4.user == "isapi" and creds4.source is CredentialSource.KEYCHAIN

    # A full env password means the keychain is never touched at all.
    fake5 = FakeSecurity()
    resolve(env={"GATECLERK_PASSWORD": "fake-env-pw"}, fake=fake5)
    assert fake5.calls == [], "env won the password rung; the keychain must not be touched"


def test_missing_item_names_the_exact_security_command_to_run() -> None:
    fake = FakeSecurity(secret_rc=KEYCHAIN_EXIT_NOT_FOUND, secret_stderr=NOT_FOUND_STDERR)
    with pytest.raises(CredentialUnavailable) as exc:
        resolve(fake=fake)
    msg = str(exc.value)
    assert "keychain item missing" in msg
    assert HOST in msg and "gateclerk-hikvision" in msg
    assert "add-generic-password" in msg, "the fix must be a paste away"
    # Both printed commands must parse back into exactly the argv they claim to be.
    lines = [ln.split(":", 1)[1].strip() for ln in msg.splitlines() if "security " in ln]
    assert len(lines) == 2, msg
    assert shlex.split(lines[0]) == [
        "security",
        "find-generic-password",
        "-s",
        DEFAULT_KEYCHAIN_SERVICE,
        "-a",
        HOST,
        "-w",
    ], "the message must name the exact read command (DoD)"
    add_argv = shlex.split(lines[1])
    assert add_argv[:2] == ["security", "add-generic-password"]
    assert "-U" in add_argv, "re-running must update, not fail"
    assert add_argv[add_argv.index("-j") + 1] == "user=admin"
    assert add_argv[-1] == "-w", "-w last so the password is prompted, never typed in argv"


def test_denied_access_names_the_command_and_the_env_fallback() -> None:
    fake = FakeSecurity(secret_rc=128, secret_stderr=b" SecKeychainCopyDomainSearchList: denied")
    with pytest.raises(CredentialUnavailable) as exc:
        resolve(fake=fake)
    msg = str(exc.value)
    assert "keychain access denied" in msg
    assert "find-generic-password" in msg
    assert "GATECLERK_192_0_2_10_PASSWORD" in msg
    assert "128" in msg


def test_a_binary_that_cannot_exec_is_reported_not_raised_as_oserror() -> None:
    fake = FakeSecurity(raise_os_error=OSError(13, "Permission denied"))
    with pytest.raises(CredentialUnavailable, match="could not be executed"):
        resolve(fake=fake)


def test_missing_binary_points_at_the_env_rung(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("gateclerk.config.shutil.which", lambda _p: None)
    with pytest.raises(CredentialUnavailable) as exc:
        resolve_credentials(target(), env={})
    msg = str(exc.value)
    assert "Keychain is unavailable" in msg and "GATECLERK_192_0_2_10_PASSWORD" in msg


def test_an_item_with_an_empty_password_is_refused() -> None:
    fake = FakeSecurity(secret=b"\n")
    with pytest.raises(CredentialUnavailable, match="password is empty"):
        resolve(fake=fake)


def test_stdout_is_decoded_without_losing_odd_bytes() -> None:
    """A password is bytes; a lone surrogate must survive rather than crash the read."""
    fake = FakeSecurity(secret=b"caf\xe9\n")
    creds = resolve(fake=fake)
    assert creds.password.reveal().startswith("caf")


# --- precedence: flag > env > keychain --------------------------------------------------


def test_flag_beats_env_and_keychain() -> None:
    fake = FakeSecurity(secret=b"fake-keychain-pw\n")
    creds = resolve(
        user="flagged", password="fake-flag-pw", env={"GATECLERK_PASSWORD": "fake-env-pw"}, fake=fake
    )
    assert creds.source is CredentialSource.FLAG
    assert creds.password.reveal() == "fake-flag-pw"
    assert creds.user == "flagged"
    assert fake.calls == [], "an explicit flag must not touch the keychain at all"


def test_env_beats_keychain() -> None:
    fake = FakeSecurity(secret=b"fake-keychain-pw\n")
    creds = resolve(env={"GATECLERK_192_0_2_10_PASSWORD": "fake-env-pw"}, fake=fake)
    assert creds.source is CredentialSource.ENV
    assert creds.password.reveal() == "fake-env-pw"
    assert fake.calls == []


def test_keychain_is_the_last_rung() -> None:
    creds = resolve(fake=FakeSecurity(secret=b"fake-keychain-pw\n"))
    assert creds.source is CredentialSource.KEYCHAIN
    assert creds.password.reveal() == "fake-keychain-pw"


def test_explicit_empty_flag_is_an_error_not_a_fallthrough() -> None:
    """`--password ''` means 'I meant to give one' — falling through would hide a typo."""
    with pytest.raises(CredentialUnavailable, match="EMPTY password"):
        resolve(password="", fake=FakeSecurity())


@pytest.mark.parametrize(
    ("env", "config_user", "keychain_comment", "flag", "want"),
    [
        ({}, None, None, None, "admin"),  # nothing anywhere -> documented default
        ({}, "cfg-user", None, None, "cfg-user"),  # sites.toml beats the comment
        ({}, None, "user=from-comment", None, "from-comment"),
        ({}, "cfg-user", "user=from-comment", None, "cfg-user"),
        ({"GATECLERK_USER": "env-user"}, "cfg-user", "user=from-comment", None, "env-user"),
        ({"GATECLERK_USER": "env-user"}, "cfg-user", "user=from-comment", "flag-user", "flag-user"),
    ],
)
def test_user_precedence_flag_env_config_comment_default(
    env: dict[str, str],
    config_user: str | None,
    keychain_comment: str | None,
    flag: str | None,
    want: str,
) -> None:
    attrs = ATTRS_STDOUT
    if keychain_comment is None:
        attrs = b'    "icmt"<blob>=<NULL>\n'
    elif keychain_comment != "user=admin":
        attrs = f'    "icmt"<blob>="{keychain_comment}"\n'.encode()
    fake = FakeSecurity(attributes=attrs)
    creds = resolve_credentials(
        target(config_user=config_user), user=flag, env=env, keychain=reader(fake)
    )
    assert creds.user == want


def test_user_rung_still_works_when_the_password_came_from_a_flag() -> None:
    creds = resolve(password="fake-flag-pw", env={"GATECLERK_USER": "env-user"}, fake=FakeSecurity())
    assert creds.user == "env-user"


# --- the seam p1-03 consumes ------------------------------------------------------------


def test_client_receives_a_callable_not_a_password() -> None:
    """The ISAPI client gets a provider; re-calling it re-resolves (stale-nonce case)."""
    fake = FakeSecurity()
    provider = credential_provider(target(), env={}, keychain=reader(fake))
    assert callable(provider)
    first = provider()
    second = provider()
    assert first.password.reveal() == PW == second.password.reveal()
    assert len(fake.calls) == 4, "each authentication attempt re-reads the source"
    # A provider is a function object; it must not carry the plaintext in its repr.
    assert PW not in repr(provider)
    assert PW not in str(provider)


def test_provider_picks_up_a_source_that_changed_between_calls() -> None:
    """Keychain fixed mid-run (human adds the item) -> the next call succeeds. No caching."""
    env = {"GATECLERK_PASSWORD": "fake-env-pw"}
    state = dict(env)
    provider = credential_provider(target(), env=state, keychain=reader(FakeSecurity()))
    assert provider().password.reveal() == "fake-env-pw"
    state["GATECLERK_192_0_2_10_PASSWORD"] = "fake-per-host-pw"
    assert provider().password.reveal() == "fake-per-host-pw"


def test_the_default_subprocess_run_is_never_used(monkeypatch: pytest.MonkeyPatch) -> None:
    """The DoD says 'no real keychain calls in CI'. This is how that claim is pinned."""
    real_run = subprocess.run

    def explode(*args: Any, **kwargs: Any) -> Any:
        raise AssertionError(f"a test tried to spawn a real process: {args[:1]}")

    monkeypatch.setattr(subprocess, "run", explode)
    try:
        creds = resolve(fake=FakeSecurity())
        assert creds.password.reveal() == PW
        # No injected reader + a host with no `security` binary: documented error, no spawn.
        monkeypatch.setattr("gateclerk.config.shutil.which", lambda _p: None)
        with pytest.raises(CredentialUnavailable, match="Keychain is unavailable"):
            resolve_credentials(target(), env={})
    finally:
        monkeypatch.setattr(subprocess, "run", real_run)


# --- redaction: the DoD's "no password in repr" ----------------------------------------


def test_secret_repr_and_str_carry_only_the_mask() -> None:
    secret = Secret(PW, label="keychain:192.0.2.10")
    assert MASK in repr(secret) and PW not in repr(secret)
    assert str(secret) == MASK
    assert PW not in f"{secret}"
    assert PW not in f"{secret!r}"
    assert PW not in format(secret)


def test_a_configured_clients_repr_contains_no_password() -> None:
    """DoD, literally: the object a client would hold, built from a real resolution."""

    class StubIsapiClient:  # mirrors what p1-03 holds: a provider, not a password
        def __init__(self, provider: Any, host: str, port: int) -> None:
            self._provider = provider
            self.host = host
            self.port = port

        def __repr__(self) -> str:
            creds = self._provider()
            return (
                f"StubIsapiClient(host={self.host!r}, port={self.port}, "
                f"user={creds.user!r}, creds={creds.source.value!r})"
            )

    provider = credential_provider(target(), env={}, keychain=reader(FakeSecurity()))
    client_repr = repr(StubIsapiClient(provider, HOST, 80))
    assert PW not in client_repr, client_repr
    creds_repr = repr(provider())
    assert PW not in creds_repr and MASK in creds_repr, creds_repr


def test_credentials_repr_says_what_it_resolved_without_saying_the_secret() -> None:
    creds = resolve(fake=FakeSecurity())
    text = repr(creds)
    assert PW not in text
    assert "keychain" in text and HOST in text and "admin" in text
    assert creds.describe() == f"admin@{HOST} via keychain"
    assert PW not in creds.describe()


def test_failing_equality_does_not_leak_through_a_pytest_diff() -> None:
    """The reason __eq__ is identity-based: `assert creds == other` prints both reprs."""
    a = Secret(PW)
    b = Secret(PW)
    assert a != b, "identity equality is deliberate"
    assert PW not in repr({a: 1})


def test_secret_is_falsy_only_when_empty() -> None:
    assert bool(Secret(PW)) is True
    assert bool(Secret("")) is False


def test_secret_value_is_immutable_after_construction() -> None:
    """A Secret cannot be quietly re-pointed at another value (or cleared) by downstream code."""
    secret = Secret(PW)
    with pytest.raises(TypeError):
        secret._value = "other-pw"  # type: ignore[misc]
    with pytest.raises(TypeError):
        secret.label = "elsewhere"  # type: ignore[misc]
    with pytest.raises(TypeError):
        del secret._value  # type: ignore[misc]
    assert secret.reveal() == PW


def test_redact_replaces_every_occurrence_longest_first() -> None:
    nested = Secret("sesame-pw")
    whole = Secret("sesame-pw-and-friend")
    text = "echo sesame-pw-and-friend then sesame-pw"
    out = redact(text, nested, whole)
    assert "sesame" not in out
    assert out.count(MASK) == 2
    assert redact("nothing here", None, Secret(""), "") == "nothing here"


def test_safe_line_masks_diagnostics() -> None:
    creds = resolve(fake=FakeSecurity())
    line = safe_line([("host", HOST), ("user", creds.user)], creds.password)
    assert PW not in line and HOST in line and "admin" in line
    assert describe_target(target(), creds) == f"target=admin@{HOST}:80 creds=keychain"
    named = target(site="site-a")
    assert describe_target(named, creds) == f"target=admin@{HOST}:80 site=site-a creds=keychain"


def test_a_keychain_error_message_never_echoes_a_base64_looking_secret() -> None:
    """stderr is foreign text; a blob-shaped run is blanked before it reaches the user."""
    blob = b"c2VjcmV0LXBhc3N3b3JkLXZhbHVlLWxvb2tpbmctaGVyZQ=="
    fake = FakeSecurity(secret_rc=128, secret_stderr=b"acl error " + blob)
    with pytest.raises(CredentialUnavailable) as exc:
        resolve(fake=fake)
    assert b"secret-password" not in str(exc.value).encode()
    assert "<redacted>" in str(exc.value)


@pytest.mark.parametrize(
    "diagnostic",
    [
        # The real strings macOS prints (captured in the 2026-10-15 probe). Redaction that
        # ate these would turn an actionable error into "<redacted>: item could not be…".
        "SecKeychainSearchCopyNext: The specified item could not be found in the keychain.",
        "security: SecKeychainCopyDomainSearchList: UNIXService[0x0] { 128 }",
    ],
)
def test_redaction_leaves_macos_diagnostics_intact(diagnostic: str) -> None:
    assert redact_b64(diagnostic) == diagnostic


def test_resolution_error_message_is_free_of_every_credential_value() -> None:
    fake = FakeSecurity(secret_rc=KEYCHAIN_EXIT_NOT_FOUND, secret_stderr=NOT_FOUND_STDERR)
    # No env PASSWORD, so the keychain rung is reached and fails. A password that happens
    # to sit in the environment for ANOTHER host must still never surface here.
    env = {"GATECLERK_192_0_2_99_PASSWORD": "fake-other-host-pw", "GATECLERK_USER": "svc"}
    with pytest.raises(CredentialUnavailable) as exc:
        resolve_credentials(target(), env=env, keychain=reader(fake))
    msg = str(exc.value)
    assert PW not in msg and "fake-other-host-pw" not in msg


def test_hygiene_note_this_file_uses_only_placeholder_secrets() -> None:
    """tests/test_repo_hygiene.py enforces this repo-wide; assert the intent locally too."""
    assert all(
        p.startswith(("fake", "test", "fake-keychain-pw", "fake-env-pw", "fake-per-host"))
        for p in [PW, "test-pw", "fake-keychain-pw", "fake-env-pw", "fake-per-host-pw"]
    )
