"""Card CREDSTORE-LINUX: the platform-symmetric resolver and the 0600 credential file.

Five arms, in the order the card names them:

1. the **file backend** under a tmp HOME — round-trip, atomicity, and the 0600 refusal on
   both read and write (the message names the path, the mode and the `chmod`, never a value);
2. the **precedence matrix** — explicit flag > env > platform store (Keychain) > file,
   exercised by turning each rung on and off rather than by trusting one ordering;
3. **portability** — the same `sites.toml` resolves on a fake-Linux host (no Keychain) from
   the env rung or the file, and on a fake-macOS host from the Keychain, with the *ref name*
   identical on both;
4. the **macOS arms unchanged** — the Keychain rung still issues exactly p1-02's argv and
   still wins over a file that is present, so the live site-a path cannot regress silently;
5. the **redact sweep** — a value that reaches the resolver may not appear in a repr, a
   message, a rendered row, or a CLI screen, including on every failure path.

Everything here is offline (`tests/conftest.py`'s `netoff`) and keychain-free: `security`
is a fake `runner`, and the file backend is a tmp path. The suite's autouse
`no_ambient_credential_file` fixture points `$GATECLERK_CREDENTIALS_FILE` at `off`, so an
operator's real store can never decide one of these outcomes — each test names its own file.
"""

from __future__ import annotations

import json
import os
import stat
import subprocess
from pathlib import Path
from typing import Any

import pytest
from typer.testing import CliRunner

from gateclerk import credentials
from gateclerk.cli import CONFIG_ERROR_EXIT, app
from gateclerk.config import (
    DEFAULT_KEYCHAIN_SERVICE,
    KEYCHAIN_EXIT_NOT_FOUND,
    CredentialSource,
    DeviceTarget,
    KeychainReader,
    load_sites,
    resolve_credentials,
)
from gateclerk.credentials import (
    CREDENTIALS_FILE_ENV,
    CredentialFileStore,
    default_credential_file,
    device_credential_refs,
    device_ref,
    env_var_for_ref,
    ingest_ref,
    is_macos,
    resolve_file_store,
    resolve_ingest_token,
)
from gateclerk.exceptions import CredentialUnavailable

runner = CliRunner()

HOST = "192.0.2.10"
SITE = "site-a"
DEVICE_REF = f"gateclerk-{SITE}-{HOST}"
INGEST_SITE = "site-a"
PER_HOST_PW_VAR = "GATECLERK_192_0_2_10_PASSWORD"

#: Recognisably fake (tests/test_repo_hygiene.py's PLACEHOLDER) and distinct per rung, so a
#: wrong rung shows up as the WRONG STRING rather than as a passing equality.
FROM_FLAG = "fake-flag-pw"
FROM_ENV = "fake-env-pw"
FROM_KEYCHAIN = "fake-keychain-pw"
FROM_FILE = "fake-file-pw"

SITES_TOML = f"""
[[site]]
name = "{SITE}"
host = "{HOST}"
port = 80
iana_tz = "Europe/Bucharest"
isapi_user = "isapi-svc"
"""


# --- fakes ----------------------------------------------------------------------------


class FakeSecurity:
    """Stand-in for `/usr/bin/security` (same shape as test_config_credentials')."""

    def __init__(
        self,
        *,
        items: dict[str, str] | None = None,
        default: str | None = FROM_KEYCHAIN,
        not_found_rc: bool = False,
        comment: str | None = None,
    ) -> None:
        self.items = items or {}
        self.default = default
        self.not_found_rc = not_found_rc
        self.comment = comment
        self.calls: list[list[str]] = []

    def __call__(self, argv: list[str], **_kw: Any) -> subprocess.CompletedProcess[Any]:
        self.calls.append(list(argv))
        service = argv[argv.index("-s") + 1]
        account = argv[argv.index("-a") + 1]
        with_secret = argv[-1] == "-w"
        value = self.items.get(service, self.items.get(account, self.default))
        if self.not_found_rc or value is None:
            return subprocess.CompletedProcess(
                args=argv,
                returncode=KEYCHAIN_EXIT_NOT_FOUND,
                stdout=b"",
                stderr=b"security: SecKeychainSearchCopyNext: "
                b"The specified item could not be found in the keychain.\n",
            )
        if with_secret:
            return subprocess.CompletedProcess(
                args=argv, returncode=0, stdout=f"{value}\n".encode()
            )
        comment = self.comment if self.comment is not None else "user=admin"
        dump = (
            f'    "svce"<blob>="{service}"\n'
            f'    "acct"<blob>="{account}"\n'
            f'    "icmt"<blob>="{comment}"\n'
        )
        return subprocess.CompletedProcess(args=argv, returncode=0, stdout=dump.encode())


class FakeKeychain:
    """A `KeychainReader` seam that records which SERVICE it was asked for."""

    def __init__(self, *, items: dict[str, str] | None = None, fail: bool = False) -> None:
        self.items = items or {}
        self.fail = fail
        self.reads: list[tuple[str, bool]] = []

    def read(self, target: Any, *, with_comment: bool = True) -> Any:
        from gateclerk.secrets import Secret

        self.reads.append((target.keychain_service, with_comment))
        if self.fail:
            raise CredentialUnavailable(f"no item for service {target.keychain_service!r}")
        value = self.items.get(target.keychain_service)
        if value is None:
            raise CredentialUnavailable(
                f"keychain item missing for service {target.keychain_service!r}"
            )
        return type("Item", (), {"password": Secret(value), "comment": None})()


def target(**over: Any) -> DeviceTarget:
    params: dict[str, Any] = {"host": HOST, "site": SITE}
    params.update(over)
    return DeviceTarget(**params)


def store_at(tmp_path: Path, name: str = "credentials.json") -> CredentialFileStore:
    return CredentialFileStore(tmp_path / name)


def write_store(store: CredentialFileStore, refs: dict[str, str]) -> None:
    """Create a store the documented way: the shape AND the 0600 mode."""
    store.path.parent.mkdir(parents=True, exist_ok=True)
    store.path.write_text(json.dumps({"refs": refs}), encoding="utf-8")
    store.path.chmod(0o600)


# --- 1. the file backend --------------------------------------------------------------


def test_default_path_is_the_documented_xdg_location(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(CREDENTIALS_FILE_ENV, raising=False)
    monkeypatch.setattr(Path, "home", lambda: Path("/home/operator"))
    assert default_credential_file() == Path("/home/operator/.config/gateclerk/credentials.json")


def test_env_var_relocates_the_store(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(CREDENTIALS_FILE_ENV, "/srv/gateclerk/creds.json")
    assert str(default_credential_file()) == "/srv/gateclerk/creds.json"


@pytest.mark.parametrize("spelling", ["", "off", "none", "OFF", " disabled "])
def test_disable_spellings_turn_the_rung_off(spelling: str) -> None:
    assert resolve_file_store(env={CREDENTIALS_FILE_ENV: spelling}) is None


def test_roundtrip_write_then_find_returns_the_same_value(tmp_path: Path) -> None:
    store = store_at(tmp_path)
    store.write(DEVICE_REF, FROM_FILE)
    found = store.find(DEVICE_REF)
    assert found is not None and found[0] == DEVICE_REF
    assert found[1].reveal() == FROM_FILE


def test_written_file_is_mode_0600_even_under_a_loose_umask(tmp_path: Path) -> None:
    """The mode is insisted on AFTER the write, because a umask lowers open()'s request.

    `open(..., 0o600)` is ANDed with ~umask, so a process with umask 022 gets 0600 but one
    with a weird umask (or a filesystem without POSIX modes) may not; the post-write chmod
    is what makes the promise unconditional, and it is the promise the card is about.
    """
    store = store_at(tmp_path)
    previous = os.umask(0o077)
    try:
        store.write(DEVICE_REF, FROM_FILE)
    finally:
        os.umask(previous)
    assert stat.S_IMODE(store.path.stat().st_mode) == 0o600


def test_a_second_write_keeps_the_other_refs(tmp_path: Path) -> None:
    """Refs accumulate: two devices and an ingest token live in one file, one per name."""
    store = store_at(tmp_path)
    store.write(DEVICE_REF, FROM_FILE)
    store.write(ingest_ref(INGEST_SITE), "fake-token-value")
    assert store.names() == (ingest_ref(INGEST_SITE), DEVICE_REF)
    assert store.read(DEVICE_REF).reveal() == FROM_FILE


def test_write_is_atomic_no_temp_file_survives(tmp_path: Path) -> None:
    store = store_at(tmp_path)
    store.write(DEVICE_REF, FROM_FILE)
    leftovers = [p.name for p in store.path.parent.iterdir() if p.name.endswith(".tmp")]
    assert leftovers == [], f"a temp file was left next to the store: {leftovers}"


def test_remove_drops_one_ref_and_reports_whether_it_was_there(tmp_path: Path) -> None:
    store = store_at(tmp_path)
    store.write(DEVICE_REF, FROM_FILE)
    assert store.remove(DEVICE_REF) is True
    assert store.remove(DEVICE_REF) is False
    assert store.names() == ()


def test_write_of_an_empty_value_is_refused(tmp_path: Path) -> None:
    """An empty stored value would shadow every rung above it with a blank."""
    store = store_at(tmp_path)
    with pytest.raises(CredentialUnavailable, match="EMPTY value"):
        store.write(DEVICE_REF, "")


def test_names_and_source_for_never_expose_a_value(tmp_path: Path) -> None:
    store = store_at(tmp_path)
    write_store(store, {DEVICE_REF: FROM_FILE, "gateclerk-ingest-site-a": "fake-other"})
    text = repr(store) + repr(store.names()) + store.source_for(DEVICE_REF)
    assert FROM_FILE not in text and "fake-other" not in text
    assert store.source_for(DEVICE_REF) == "present"
    assert store.source_for("gateclerk-nope") == "absent"


def test_a_ref_stored_empty_reports_empty_not_absent(tmp_path: Path) -> None:
    """`absent` and `empty` are different diagnoses, and only one of them is a typo."""
    store = store_at(tmp_path)
    write_store(store, {DEVICE_REF: ""})
    assert store.source_for(DEVICE_REF) == "empty"
    assert store.read(DEVICE_REF) is None, "an empty value is no credential, as everywhere here"


# --- the 0600 refusal (the card's "refuse + clear message on looser perms") ----------


@pytest.mark.parametrize("mode", [0o644, 0o640, 0o604, 0o666, 0o755])
def test_reading_a_permissive_store_is_refused(tmp_path: Path, mode: int) -> None:
    store = store_at(tmp_path)
    write_store(store, {DEVICE_REF: FROM_FILE})
    store.path.chmod(mode)
    with pytest.raises(CredentialUnavailable) as excinfo:
        store.read(DEVICE_REF)
    message = str(excinfo.value)
    assert "mode" in message and "0600" in message, "the message must name the required mode"
    assert "chmod 600" in message, "and the exact fix"
    assert str(store.path) in message, "and which file it is talking about"
    assert FROM_FILE not in message, "while never echoing the value it refused to read"


def test_a_store_the_owner_can_execute_is_accepted(tmp_path: Path) -> None:
    """The invariant is "no group/other bits", not a byte-exact 0600.

    0700 is owner-only: nothing gained by refusing it, and a refusal here would be a mode
    snobbery that makes an operator chmod a working file for no security reason. The mask
    that decides (`PERMISSIVE_BITS`) is about WHO ELSE can read the file.
    """
    store = store_at(tmp_path)
    write_store(store, {DEVICE_REF: FROM_FILE})
    store.path.chmod(0o700)
    assert store.read(DEVICE_REF).reveal() == FROM_FILE


def test_write_to_a_permissive_store_is_refused_before_the_value_lands(tmp_path: Path) -> None:
    """Refusing on write matters as much as on read: augmenting a leaky store IS the leak."""
    store = store_at(tmp_path)
    write_store(store, {DEVICE_REF: FROM_FILE})
    store.path.chmod(0o644)
    with pytest.raises(CredentialUnavailable, match="refuses to use it"):
        store.write("gateclerk-site-b-192.0.2.11", "fake-new-pw")
    stored = json.loads(store.path.read_text(encoding="utf-8"))
    assert "gateclerk-site-b-192.0.2.11" not in stored["refs"], (
        "the new ref must NOT have been added"
    )


def test_a_store_returned_to_0600_resolves_again(tmp_path: Path) -> None:
    """The refusal is about the MODE, not about having once been permissive."""
    store = store_at(tmp_path)
    write_store(store, {DEVICE_REF: FROM_FILE})
    store.path.chmod(0o644)
    with pytest.raises(CredentialUnavailable):
        store.read(DEVICE_REF)
    store.path.chmod(0o600)
    assert store.read(DEVICE_REF).reveal() == FROM_FILE


@pytest.mark.parametrize(
    ("body", "needle"),
    [
        ("not json at all", "not valid JSON"),
        ('{"refs": "nope"}', '"refs" object'),
        ('{"refz": {}}', '"refs" object'),
        ('{"refs": {"a": 7}}', "not a string"),
    ],
)
def test_a_malformed_store_is_an_error_not_a_miss(tmp_path: Path, body: str, needle: str) -> None:
    """A silently-ignored broken file becomes a mystery 401 at the device's lockout counter."""
    store = store_at(tmp_path)
    store.path.parent.mkdir(parents=True, exist_ok=True)
    store.path.write_text(body, encoding="utf-8")
    store.path.chmod(0o600)
    with pytest.raises(CredentialUnavailable, match=needle):
        store.read(DEVICE_REF)


def test_a_missing_store_is_not_an_error(tmp_path: Path) -> None:
    assert store_at(tmp_path).read(DEVICE_REF) is None
    assert store_at(tmp_path).names() == ()


def test_a_directory_where_the_store_should_be_is_reported(tmp_path: Path) -> None:
    store = store_at(tmp_path)
    store.path.mkdir(parents=True)
    with pytest.raises(CredentialUnavailable, match="directory"):
        store.read(DEVICE_REF)


# --- 2. the precedence matrix ---------------------------------------------------------


@pytest.mark.parametrize(
    ("flag", "env_on", "keychain_on", "file_on", "want_source", "want_value"),
    [
        # All four present: each rung in turn must beat the ones below it.
        (True, True, True, True, CredentialSource.FLAG, FROM_FLAG),
        (False, True, True, True, CredentialSource.ENV, FROM_ENV),
        (False, False, True, True, CredentialSource.KEYCHAIN, FROM_KEYCHAIN),
        (False, False, False, True, CredentialSource.FILE, FROM_FILE),
        # Nothing at all: a refusal, naming both fixes (pinned separately below).
        (False, False, False, False, "raises", None),
        # Each rung ALONE, so no row above passes only because a higher rung happened to be on.
        (True, False, False, False, CredentialSource.FLAG, FROM_FLAG),
        (False, True, False, False, CredentialSource.ENV, FROM_ENV),
        (False, False, True, False, CredentialSource.KEYCHAIN, FROM_KEYCHAIN),
        (False, False, False, True, CredentialSource.FILE, FROM_FILE),
    ],
)
def test_precedence_matrix(
    tmp_path: Path,
    flag: bool,
    env_on: bool,
    keychain_on: bool,
    file_on: bool,
    want_source: CredentialSource | str | None,
    want_value: str | None,
) -> None:
    """Every rung on, then each one removed in turn: the order is flag > env > store > file.

    The Keychain is ALWAYS an injected fake, including when the row says it is "off": a
    `store=None, keychain=None` resolution would let `KeychainReader` fall back to the real
    `/usr/bin/security` subprocess — which passes on CI (no binary) and silently spawns a
    real process on a Mac, i.e. the worst possible direction for a credential test to fail
    in. `not_found_rc=True` is how "there is no keychain item here" is answered offline.
    """
    store = store_at(tmp_path) if file_on else None
    if store is not None:
        write_store(store, {DEVICE_REF: FROM_FILE})
    security = (
        FakeSecurity(items={DEFAULT_KEYCHAIN_SERVICE: FROM_KEYCHAIN})
        if keychain_on
        else FakeSecurity(not_found_rc=True)
    )
    env = {PER_HOST_PW_VAR: FROM_ENV} if env_on else {}

    def call() -> Any:
        return resolve_credentials(
            target(),
            password=FROM_FLAG if flag else None,
            env=env,
            keychain=KeychainReader(runner=security),
            store=store,
            platform_name="Darwin",
        )

    if want_source == "raises":
        with pytest.raises(CredentialUnavailable):
            call()
        return
    creds = call()
    assert creds.source is want_source
    assert creds.password.reveal() == want_value


def test_empty_env_rung_falls_through_to_the_file(tmp_path: Path) -> None:
    """`GATECLERK_..._PASSWORD=` is "unset", not "the password is empty" (p1-02's rule)."""
    store = store_at(tmp_path)
    write_store(store, {DEVICE_REF: FROM_FILE})
    creds = resolve_credentials(
        target(),
        env={PER_HOST_PW_VAR: "", "GATECLERK_PASSWORD": ""},
        keychain=KeychainReader(runner=FakeSecurity(not_found_rc=True)),
        store=store,
        platform_name="Linux",
    )
    assert creds.source is CredentialSource.FILE


def test_per_host_env_beats_the_global_env_and_the_file(tmp_path: Path) -> None:
    store = store_at(tmp_path)
    write_store(store, {DEVICE_REF: FROM_FILE})
    creds = resolve_credentials(
        target(),
        env={"GATECLERK_PASSWORD": "fake-global-pw", PER_HOST_PW_VAR: FROM_ENV},
        store=store,
        platform_name="Linux",
    )
    assert creds.source is CredentialSource.ENV and creds.password.reveal() == FROM_ENV


def test_file_rung_is_consulted_without_spawning_security(tmp_path: Path) -> None:
    """On Linux the file rung answers with no `security` process at all (the point of the card).

    `KeychainReader` raises `CredentialUnavailable` when the binary is missing, so a
    resolution that reaches the file proves the platform-store failure was survived rather
    than fatal — the behaviour that made a Linux deploy need an env file before this card.
    """
    store = store_at(tmp_path)
    write_store(store, {DEVICE_REF: FROM_FILE})
    real_which = __import__("shutil").which
    monkey = pytest.MonkeyPatch()
    monkey.setattr("gateclerk.config.shutil.which", lambda _p: None)
    try:
        creds = resolve_credentials(
            target(config_user="isapi-svc"), env={}, store=store, platform_name="Linux"
        )
    finally:
        monkey.undo()
    assert creds.source is CredentialSource.FILE
    assert real_which is not None


def test_no_rung_at_all_names_the_file_fix(tmp_path: Path) -> None:
    """A Linux host with nothing installed gets the `creds set` line, not a macOS command."""
    store = store_at(tmp_path)
    with pytest.raises(CredentialUnavailable) as excinfo:
        resolve_credentials(
            target(config_user="isapi-svc"),
            env={},
            keychain=KeychainReader(runner=FakeSecurity(not_found_rc=True)),
            store=store,
            platform_name="Linux",
        )
    message = str(excinfo.value)
    assert "gateclerk creds set" in message and str(store.path) in message
    assert PER_HOST_PW_VAR in message, "both fixes are offered, in ladder order"


# --- 3. portability: one sites.toml, two platforms ------------------------------------


def sites_file(tmp_path: Path) -> Path:
    path = tmp_path / "sites.toml"
    path.write_text(SITES_TOML, encoding="utf-8")
    return path


def test_the_same_sites_toml_resolves_on_fake_linux_from_the_env(tmp_path: Path) -> None:
    path = sites_file(tmp_path)
    site = load_sites(path, surface="agent")["site-a"]
    creds = resolve_credentials(
        site.target(), env={PER_HOST_PW_VAR: FROM_ENV}, store=None, platform_name="Linux"
    )
    assert creds.source is CredentialSource.ENV and creds.user == "isapi-svc"


def test_the_same_sites_toml_resolves_on_fake_linux_from_the_file(tmp_path: Path) -> None:
    path = sites_file(tmp_path)
    site = load_sites(path, surface="agent")["site-a"]
    store = store_at(tmp_path)
    # The ref is derived from the SAME site+host the toml names — that is the portability claim.
    write_store(store, {device_ref(site.name, site.host): FROM_FILE})
    creds = resolve_credentials(site.target(), env={}, store=store, platform_name="Linux")
    assert creds.source is CredentialSource.FILE and creds.password.reveal() == FROM_FILE
    assert creds.user == "isapi-svc", "the toml still names the user on either platform"


def test_the_same_sites_toml_resolves_on_fake_macos_from_the_keychain(tmp_path: Path) -> None:
    path = sites_file(tmp_path)
    site = load_sites(path, surface="agent")["site-a"]
    creds = resolve_credentials(
        site.target(),
        env={},
        keychain=KeychainReader(
            runner=FakeSecurity(items={DEFAULT_KEYCHAIN_SERVICE: FROM_KEYCHAIN})
        ),
        store=None,
        platform_name="Darwin",
    )
    assert creds.source is CredentialSource.KEYCHAIN


def test_ref_names_are_platform_free_and_match_the_documented_conventions() -> None:
    """`gateclerk-<site>-<host>` and `gateclerk-ingest-<site>` are the only names in play.

    These are the strings a `LoadCredential=` unit line carries (config.credential_ref) and
    the ones the ingest function's docs name, so the file backend must key on exactly them.
    """
    assert device_ref(SITE, HOST) == DEVICE_REF
    assert ingest_ref(INGEST_SITE) == f"gateclerk-ingest-{INGEST_SITE}"
    assert device_credential_refs(target()) == (DEVICE_REF, HOST)
    # A bare --host (no site block) has no site to name: the ref is the host, which is what
    # today's keychain ACCOUNT already is, so existing macOS items keep answering.
    assert device_credential_refs(DeviceTarget(host=HOST)) == (HOST,)


@pytest.mark.parametrize(
    ("ref", "want"),
    [
        (HOST, PER_HOST_PW_VAR),
        (ingest_ref("site-a"), "GATECLERK_INGEST_TOKEN_SITE-A"),
        ("unrelated-name", "GATECLERK_UNRELATED_NAME_PASSWORD"),
    ],
)
def test_the_inverse_mapping_names_the_env_rung(ref: str, want: str) -> None:
    assert env_var_for_ref(ref) == want


def test_an_ambiguous_device_ref_offers_every_split_rather_than_a_wrong_guess() -> None:
    """`gateclerk-<site>-<host>` is not invertible: site names and hosts both carry hyphens.

    `GATECLERK_A_192_0_2_10_PASSWORD` is a real candidate (site `a`, host `192.0.2.10`) and so
    is `GATECLERK_192_0_2_10_PASSWORD` (site `site-a`). Naming one of them in a report would
    send an operator to set a variable that never gets read, so `env_var_for_ref` abstains
    and `env_var_candidates` lists them all.
    """
    assert env_var_for_ref(DEVICE_REF) is None
    candidates = credentials.env_var_candidates(DEVICE_REF)
    assert PER_HOST_PW_VAR in candidates, "the useful candidate is still offered"
    assert "GATECLERK_A_192_0_2_10_PASSWORD" in candidates
    assert len(candidates) > 1


def test_platform_probe_is_injectable() -> None:
    """The branch Linux CI exercises is the branch a Mac cannot fake by accident."""
    assert is_macos("Darwin") is True
    assert is_macos("Linux") is False


# --- 4. the macOS arms are unchanged --------------------------------------------------


def test_macos_keychain_wins_over_a_present_file(tmp_path: Path) -> None:
    """The file sits BELOW the store: dropping a credentials.json on a Mac must not shadow."""
    store = store_at(tmp_path)
    write_store(store, {DEVICE_REF: FROM_FILE})
    creds = resolve_credentials(
        target(),
        env={},
        keychain=KeychainReader(
            runner=FakeSecurity(items={DEFAULT_KEYCHAIN_SERVICE: FROM_KEYCHAIN})
        ),
        store=store,
        platform_name="Darwin",
    )
    assert creds.source is CredentialSource.KEYCHAIN
    assert creds.password.reveal() == FROM_KEYCHAIN


def test_macos_still_issues_exactly_p1_02_argv(tmp_path: Path) -> None:
    fake = FakeSecurity()
    resolve_credentials(
        DeviceTarget(host=HOST),  # a bare --host: one account, the host
        env={},
        keychain=KeychainReader(runner=fake),
        store=store_at(tmp_path),
        platform_name="Darwin",
    )
    assert fake.calls[0] == [
        "/usr/bin/security",
        "find-generic-password",
        "-s",
        DEFAULT_KEYCHAIN_SERVICE,
        "-a",
        HOST,
        "-w",
    ]


def test_the_second_security_call_is_still_only_for_an_unknown_user(tmp_path: Path) -> None:
    """Each `security` call can raise an ACL prompt; the file rung must not change that count."""
    fake = FakeSecurity()
    resolve_credentials(
        DeviceTarget(host=HOST), env={}, keychain=KeychainReader(runner=fake), store=None
    )
    assert len(fake.calls) == 2, "secret + attributes, because nothing else named the user"

    fake2 = FakeSecurity()
    resolve_credentials(
        DeviceTarget(host=HOST, config_user="isapi"),
        env={},
        keychain=KeychainReader(runner=fake2),
        store=None,
    )
    assert len(fake2.calls) == 1, "sites.toml names the user: no second prompt"


def test_keychain_user_hint_still_wins_when_nothing_else_names_the_user(tmp_path: Path) -> None:
    fake = FakeSecurity(comment="user=from-comment")
    creds = resolve_credentials(
        DeviceTarget(host=HOST),
        env={},
        keychain=KeychainReader(runner=fake),
        store=store_at(tmp_path),
        platform_name="Darwin",
    )
    assert creds.user == "from-comment"


def test_file_rung_does_not_invent_a_keychain_call(tmp_path: Path) -> None:
    """A run that resolves from the file must not have spawned `security` for the password."""
    fake = FakeSecurity(not_found_rc=True)
    store = store_at(tmp_path)
    write_store(store, {DEVICE_REF: FROM_FILE})
    resolve_credentials(
        target(config_user="isapi-svc"),
        env={},
        keychain=KeychainReader(runner=fake),
        store=store,
        platform_name="Darwin",
    )
    assert all(c[-1] == "-w" for c in fake.calls), "one secret read, no attribute dump"


def test_store_none_skips_the_file_rung_entirely(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """`store=None` is not "ambient": a file that exists on disk must not answer."""
    real = store_at(tmp_path)
    write_store(real, {DEVICE_REF: FROM_FILE})
    monkeypatch.setenv(CREDENTIALS_FILE_ENV, str(real.path))
    with pytest.raises(CredentialUnavailable):
        resolve_credentials(
            target(config_user="isapi-svc"),
            env={},
            keychain=KeychainReader(runner=FakeSecurity(not_found_rc=True)),
            store=None,
            platform_name="Linux",
        )


# --- the ingest bearer walks the same ladder -----------------------------------------


def test_ingest_token_prefers_env_then_keychain_then_file(tmp_path: Path) -> None:
    store = store_at(tmp_path)
    write_store(store, {ingest_ref(INGEST_SITE): "fake-file-token"})
    keychain = FakeKeychain(items={f"gateclerk-ingest-{INGEST_SITE}": "fake-keychain-token"})

    from_env = resolve_ingest_token(
        INGEST_SITE,
        env={"GATECLERK_INGEST_TOKEN_SITE-A": "fake-env-token"},
        keychain=keychain,
        store=store,
        env_var="GATECLERK_INGEST_TOKEN_SITE-A",
        keychain_service=f"gateclerk-ingest-{INGEST_SITE}",
    )
    assert from_env.secret.reveal() == "fake-env-token"

    from_keychain = resolve_ingest_token(
        INGEST_SITE,
        env={},
        keychain=keychain,
        store=store,
        env_var="GATECLERK_INGEST_TOKEN_SITE-A",
        keychain_service=f"gateclerk-ingest-{INGEST_SITE}",
    )
    assert from_keychain.secret.reveal() == "fake-keychain-token"

    from_file = resolve_ingest_token(
        INGEST_SITE,
        env={},
        keychain=FakeKeychain(items={}),
        store=store,
        env_var="GATECLERK_INGEST_TOKEN_SITE-A",
        keychain_service=f"gateclerk-ingest-{INGEST_SITE}",
    )
    assert from_file.secret.reveal() == "fake-file-token"


def test_ingest_token_explicit_beats_everything_and_touches_nothing(tmp_path: Path) -> None:
    store = store_at(tmp_path)
    write_store(store, {ingest_ref(INGEST_SITE): "fake-file-token"})
    keychain = FakeKeychain(items={f"gateclerk-ingest-{INGEST_SITE}": "fake-keychain-token"})
    resolved = resolve_ingest_token(
        INGEST_SITE,
        token="fake-explicit-token",
        env={"GATECLERK_INGEST_TOKEN_SITE-A": "fake-env-token"},
        keychain=keychain,
        store=store,
        env_var="GATECLERK_INGEST_TOKEN_SITE-A",
        keychain_service=f"gateclerk-ingest-{INGEST_SITE}",
    )
    assert resolved.secret.reveal() == "fake-explicit-token"
    assert keychain.reads == [], "an explicit token must not read a store at all"


def test_ingest_token_never_falls_back_to_another_sites_token(tmp_path: Path) -> None:
    """The token DETERMINES the site — a cross-site fallback is a mis-attributed punch."""
    store = store_at(tmp_path)
    write_store(store, {ingest_ref("site-b"): "fake-other-site-token"})
    with pytest.raises(CredentialUnavailable) as excinfo:
        resolve_ingest_token(
            INGEST_SITE,
            env={},
            keychain=FakeKeychain(items={}),
            store=store,
            env_var="GATECLERK_INGEST_TOKEN_SITE-A",
            keychain_service=f"gateclerk-ingest-{INGEST_SITE}",
        )
    assert "fake-other-site-token" not in str(excinfo.value)


# --- 5. redact sweep -------------------------------------------------------------------


def test_a_value_reaches_no_repr_and_no_message(tmp_path: Path) -> None:
    store = store_at(tmp_path)
    write_store(store, {DEVICE_REF: FROM_FILE, "gateclerk-ingest-site-a": "fake-file-token"})
    creds = resolve_credentials(
        target(config_user="svc"), env={}, store=store, platform_name="Linux"
    )
    haystacks = {
        "creds": repr(creds),
        "describe": creds.describe(),
        "password": repr(creds.password) + str(creds.password),
        "store": repr(store),
        "names": repr(store.names()),
    }
    for name, text in haystacks.items():
        assert FROM_FILE not in text, f"the password leaked into {name}"
        assert "fake-file-token" not in text, f"the token leaked into {name}"


def test_a_macos_refusal_is_p1_02_text_verbatim(tmp_path: Path) -> None:
    """The macOS failure screen is byte-for-byte what p1-02 printed — file rung or not.

    `creds check` on a Mac is what the operator reads, and muscle memory plus existing docs
    point at "keychain item missing … add the item with: security …". Appending the new
    file backend to that text would be a behaviour change on the platform that already
    works, which is exactly what the card forbids.
    """
    store = store_at(tmp_path)
    write_store(store, {DEVICE_REF: FROM_FILE})
    store.path.chmod(0o644)
    with pytest.raises(CredentialUnavailable) as excinfo:
        resolve_credentials(
            DeviceTarget(host=HOST, site=SITE),
            env={},
            keychain=KeychainReader(runner=FakeSecurity(not_found_rc=True)),
            store=store,
            platform_name="Darwin",
        )
    message = str(excinfo.value)
    assert message.startswith("keychain item missing for")
    assert "add-generic-password" in message
    assert FROM_FILE not in message, "and it still never echoes the refused file's value"


def test_a_linux_refusal_names_the_file_fix_as_well_as_the_env_rung(tmp_path: Path) -> None:
    """Failure is the leak-prone path: a permissive file names its mode, never its secret."""
    store = store_at(tmp_path)
    write_store(store, {DEVICE_REF: FROM_FILE})
    store.path.chmod(0o644)
    env = {PER_HOST_PW_VAR: "", "GATECLERK_PASSWORD": ""}
    keychain = KeychainReader(runner=FakeSecurity(not_found_rc=True))
    with pytest.raises(CredentialUnavailable) as excinfo:
        resolve_credentials(
            DeviceTarget(host=HOST, site=SITE),
            env=env,
            keychain=keychain,
            store=store,
            platform_name="Linux",
        )
    message = str(excinfo.value)
    assert FROM_FILE not in message, "the refused file's value must not be echoed"
    assert str(store.path) in message and "chmod 600" in message
    assert PER_HOST_PW_VAR in message, "the env fix is named too"


def test_a_keychain_error_text_never_carries_a_file_rung_value(tmp_path: Path) -> None:
    """On a non-macOS host the resolver prints the Keychain error VERBATIM plus the fixes.

    That verbatim passthrough is what makes this worth pinning: the text comes from
    `security`'s stderr (foreign text), so the redaction rule has to hold on it too. The
    file rung is deliberately present-but-refused (0644) so the message is assembled from
    BOTH rungs' failure texts while neither may leak its own contents.
    """
    store = store_at(tmp_path)
    write_store(store, {DEVICE_REF: FROM_FILE})
    store.path.chmod(0o644)
    with pytest.raises(CredentialUnavailable) as excinfo:
        resolve_credentials(
            DeviceTarget(host=HOST, site=SITE),
            env={},
            keychain=KeychainReader(runner=FakeSecurity(not_found_rc=True)),
            store=store,
            platform_name="Linux",
        )
    message = str(excinfo.value)
    assert FROM_FILE not in message
    assert DEFAULT_KEYCHAIN_SERVICE in message, "the missing item is still named"
    assert "chmod 600" in message, "and the file rung's own fix is too"


# --- the CLI surface: set / get / remove ----------------------------------------------


def cli(
    args: list[str], env: dict[str, str] | None = None, input_text: str | None = None
) -> tuple[int, str]:
    result = runner.invoke(app, args, env=env or {}, catch_exceptions=False, input=input_text)
    return result.exit_code, result.output


def test_creds_set_creates_a_0600_file_and_prints_no_value(tmp_path: Path) -> None:
    path = tmp_path / "credentials.json"
    value_file = tmp_path / "value.txt"
    value_file.write_text(f"{FROM_FILE}\n", encoding="utf-8")
    code, out = cli(
        [
            "creds",
            "set",
            DEVICE_REF,
            "--file",
            str(value_file),
            "--credentials-file",
            str(path),
            "-o",
            "json",
        ],
        env={CREDENTIALS_FILE_ENV: "off"},
    )
    assert code == 0, out
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert json.loads(path.read_text())["refs"][DEVICE_REF] == FROM_FILE
    assert FROM_FILE not in out, "the value must never be printed"


def test_creds_set_reads_the_value_from_stdin(tmp_path: Path) -> None:
    path = tmp_path / "credentials.json"
    code, out = cli(
        ["creds", "set", DEVICE_REF, "--file", "-", "--credentials-file", str(path), "-o", "json"],
        env={CREDENTIALS_FILE_ENV: "off"},
        input_text=f"{FROM_ENV}\n",
    )
    assert code == 0, out
    assert json.loads(path.read_text())["refs"][DEVICE_REF] == FROM_ENV
    assert FROM_ENV not in out


def test_creds_set_without_a_file_is_a_usage_refusal_not_a_prompt(tmp_path: Path) -> None:
    code, out = cli(
        ["creds", "set", DEVICE_REF, "--credentials-file", str(tmp_path / "c.json")],
        env={CREDENTIALS_FILE_ENV: "off"},
    )
    assert code == CONFIG_ERROR_EXIT
    assert "--file" in out and "non-interactive" in out.lower()


def test_creds_set_refuses_a_permissive_target(tmp_path: Path) -> None:
    path = tmp_path / "credentials.json"
    write_store(CredentialFileStore(path), {DEVICE_REF: FROM_FILE})
    path.chmod(0o644)
    value_file = tmp_path / "value.txt"
    value_file.write_text("fake-new-pw\n", encoding="utf-8")
    code, out = cli(
        [
            "creds",
            "set",
            "gateclerk-site-b-192.0.2.11",
            "--file",
            str(value_file),
            "--credentials-file",
            str(path),
        ],
        env={CREDENTIALS_FILE_ENV: "off"},
    )
    assert code == CONFIG_ERROR_EXIT
    assert "chmod 600" in out
    assert "gateclerk-site-b-192.0.2.11" not in path.read_text(encoding="utf-8")


def test_creds_get_lists_names_never_values_and_flags_an_empty_ref(tmp_path: Path) -> None:
    path = tmp_path / "credentials.json"
    write_store(
        CredentialFileStore(path), {DEVICE_REF: FROM_FILE, "gateclerk-site-b-192.0.2.11": ""}
    )
    code, out = cli(
        ["creds", "get", "--credentials-file", str(path), "-o", "json"],
        env={CREDENTIALS_FILE_ENV: "off"},
    )
    assert code == 0, out
    rows = [json.loads(line) for line in out.splitlines() if line.startswith("{")]
    by_ref = {r["ref"]: r for r in rows}
    assert by_ref[DEVICE_REF]["status"] == "present"
    assert by_ref["gateclerk-site-b-192.0.2.11"]["status"] == "empty"
    assert FROM_FILE not in out
    # The env column lists every candidate the name admits (a `gateclerk-<site>-<host>` ref is
    # not invertible), and the useful one must be among them.
    assert PER_HOST_PW_VAR in by_ref[DEVICE_REF]["env_var"]


def test_creds_get_on_a_named_ref_reports_existence_only(tmp_path: Path) -> None:
    path = tmp_path / "credentials.json"
    write_store(CredentialFileStore(path), {DEVICE_REF: FROM_FILE})
    code, out = cli(
        ["creds", "get", DEVICE_REF, "--credentials-file", str(path), "-o", "json"],
        env={CREDENTIALS_FILE_ENV: "off"},
    )
    assert code == 0, out
    assert FROM_FILE not in out and DEVICE_REF in out


def test_creds_get_on_a_missing_file_is_not_an_error(tmp_path: Path) -> None:
    code, out = cli(
        ["creds", "get", "--credentials-file", str(tmp_path / "absent.json"), "-o", "json"],
        env={CREDENTIALS_FILE_ENV: "off"},
    )
    assert code == 0, out


def test_creds_remove_is_idempotent(tmp_path: Path) -> None:
    path = tmp_path / "credentials.json"
    write_store(CredentialFileStore(path), {DEVICE_REF: FROM_FILE})
    args = ["creds", "remove", DEVICE_REF, "--credentials-file", str(path), "-o", "json"]
    assert cli(args, env={CREDENTIALS_FILE_ENV: "off"})[0] == 0
    assert json.loads(path.read_text())["refs"] == {}
    code, out = cli(args, env={CREDENTIALS_FILE_ENV: "off"})
    assert code == 0, f"removing an absent ref must not be a failure: {out}"


def test_creds_commands_take_no_device_flags() -> None:
    """`creds set|get|remove` cannot name a device, so they cannot write to one."""
    import typer

    root = typer.main.get_command(app)
    for verb in ("set", "get", "remove"):
        cmd = root.commands["creds"].commands[verb]
        flags = {opt for p in cmd.params for opt in (getattr(p, "opts", ()) or ())}
        for forbidden in ("--host", "--port", "--site", "--password"):
            assert forbidden not in flags, f"creds {verb} grew {forbidden}"


def test_creds_set_writes_no_device_and_prints_no_value(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The scoped write ban, pinned by behaviour: a `creds set` opens no socket and no device.

    The help-text tripwire had to stop banning the word "set" (the card names the command
    `creds set`); this is what replaces it on the command itself — a socket attempt raises
    (conftest's netoff) and no ISAPI path is ever constructed.
    """
    import socket

    def explode(*_a: object, **_k: object) -> None:
        raise AssertionError("creds set must not open a socket")

    monkeypatch.setattr(socket, "socket", explode)
    monkeypatch.setattr(socket, "create_connection", explode)
    path = tmp_path / "credentials.json"
    value_file = tmp_path / "value.txt"
    value_file.write_text(f"{FROM_FILE}\n", encoding="utf-8")
    code, out = cli(
        ["creds", "set", DEVICE_REF, "--file", str(value_file), "--credentials-file", str(path)],
        env={CREDENTIALS_FILE_ENV: "off"},
    )
    assert code == 0, out
    assert FROM_FILE not in out
