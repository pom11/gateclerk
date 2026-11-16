"""The one credential resolver: platform-symmetric, so the same `sites.toml` works on mac and Linux.

Why this module exists (card CREDSTORE-LINUX)
---------------------------------------------
Until now the ladder was **flag > env > keychain**, which is fine on macOS and a dead end
on a Linux release host: there is no keychain there, so the last rung answered "install a
macOS binary" and every deploy needed an env file. This module makes the ladder the same
*shape* on every platform:

    explicit flag ref  >  env var  >  platform store (macOS Keychain)  >  credential FILE

Two rules hold the shape together:

* **One entry point.** `resolve_secret()` is what every call site goes through — the
  device password (`config.resolve_credentials`) and the per-site ingest bearer
  (`agent_push.HttpsIngestTransport`). A second ladder somewhere else is how a Linux host
  ends up resolving a credential the operator never installed, or failing to find one that
  is installed.
* **Names are portable; backends are not.** A credential is addressed by a REF NAME
  (`gateclerk-site-a-192.0.2.10`, `gateclerk-ingest-site-a`) that means the same thing on every
  platform. Only the backend behind the name differs — keychain item on macOS, `refs` entry
  in the JSON file on Linux — so `sites.toml` travels mac<->Linux unchanged and still never
  carries a value.

The file backend
----------------
`~/.config/gateclerk/credentials.json`, mode **0600 required**:

    {"refs": {"gateclerk-site-a-192.0.2.10": "…", "gateclerk-ingest-site-a": "…"}}

`0600` is a hard refusal in both directions (read *and* write), not a warning: a plaintext
secret store another user on the box can open is the one accident this design exists to
prevent, and a warning scrolls past. The message names the path, the mode and the exact
`chmod` — never a value. The file is created only by `gateclerk creds set <ref> --file …`
(non-interactive; `--file -` pipes the value from stdin), so nothing ever prompts a secret
into a terminal or takes one as an argv value where it lands in shell history.

macOS behaviour is unchanged on purpose: when the Keychain answers, it answers exactly as
card p1-02 shipped it (same service, same account, same `icmt` user hint, same one-vs-two
`security` invocations), pinned by tests/test_config_credentials.py. The file rung sits
BELOW the Keychain, so dropping a `credentials.json` onto a Mac cannot shadow a keychain
item — the platform store still wins there, and on Linux the file is simply the backend
that exists.
"""

from __future__ import annotations

import contextlib
import json
import os
import platform
import stat
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from gateclerk.config import (
    AMBIENT,
    CredentialSource,
    DeviceTarget,
    KeychainItem,
    KeychainReader,
    credential_ref,
    env_var_names,
)
from gateclerk.exceptions import CredentialUnavailable
from gateclerk.secrets import Secret

__all__ = [
    "AMBIENT",  # re-exported from config so both sides name the same sentinel
    "CREDENTIALS_FILE_ENV",
    "CREDENTIALS_FILE_RELPATH",
    "PERMISSIVE_BITS",
    "REQUIRED_FILE_MODE",
    "CredentialFileStore",
    "ResolvedRef",
    "default_credential_file",
    "device_credential_refs",
    "device_ref",
    "env_var_for_ref",
    "ingest_ref",
    "is_macos",
    "resolve_device_password",
    "resolve_file_store",
    "resolve_ingest_token",
    "resolve_secret",
]

#: Env var naming the credential file, overriding the default location. One knob on
#: purpose: a second `GATECLERK_CREDENTIALS_DIR` would make "which file won?" a question.
CREDENTIALS_FILE_ENV = "GATECLERK_CREDENTIALS_FILE"

#: The default location: `~/.config/gateclerk/credentials.json` (the XDG config dir on
#: Linux, and the same path on macOS so a copied file works there too with no search).
CREDENTIALS_FILE_RELPATH = Path(".config") / "gateclerk" / "credentials.json"

#: The only acceptable mode, and the mask meaning "someone other than the owner can read
#: it". Any group/other bit at all — read OR write — is a refusal: 0640 leaks too.
REQUIRED_FILE_MODE = 0o600
PERMISSIVE_BITS = 0o777 ^ 0o700

#: Spellings of `$GATECLERK_CREDENTIALS_FILE` that turn the file rung OFF. The escape hatch
#: for a host where a stray `credentials.json` must not be able to answer, and the switch
#: the test suite uses so an operator's real store can never decide a test's outcome.
DISABLED_SPELLINGS = frozenset({"", "off", "none", "no", "false", "disable", "disabled"})

#: `AMBIENT` (the "no explicit store was passed" sentinel) is imported from `gateclerk.config`
#: above, where it is defined — `credentials` imports `config`, so that is the one place
#: either module can name it at def time without an import cycle.


def is_macos(name: str | None = None) -> bool:
    """Whether the platform store is the macOS Keychain.

    `name` is injectable (read from `platform.system()` when omitted) for the reason every
    other seam here is injectable: a test that branches on the real host passes on a Mac
    and lies on Linux CI.
    """
    return (platform.system() if name is None else name) == "Darwin"


def _effective_env(env: Mapping[str, str] | None) -> Mapping[str, str]:
    """The mapping that decides WHERE the store lives: the caller's over the ambient one.

    Location is process configuration, not a credential rung, so an injected resolution
    `env` that does not name `$GATECLERK_CREDENTIALS_FILE` does not hide the operator's (or
    the test suite's) setting — see `tests/conftest.py`, which turns the file rung off for
    the whole offline suite exactly this way.
    """
    if env is None:
        return os.environ
    if CREDENTIALS_FILE_ENV in env:
        return env
    if CREDENTIALS_FILE_ENV in os.environ:
        return {**os.environ, **env}
    return env


def default_credential_file(env: Mapping[str, str] | None = None) -> Path:
    """The credential file this process would use: `$GATECLERK_CREDENTIALS_FILE` or the default.

    Read at call time, not import time, so a systemd `EnvironmentFile=` (and a test's tmp
    HOME) can point it elsewhere without a code path of its own.
    """
    environ = _effective_env(env)
    override = environ.get(CREDENTIALS_FILE_ENV)
    if override and override.strip() and override.strip().lower() not in DISABLED_SPELLINGS:
        return Path(override.strip()).expanduser()
    return Path.home() / CREDENTIALS_FILE_RELPATH


def resolve_file_store(
    env: Mapping[str, str] | None = None, *, path: Path | str | None = None
) -> CredentialFileStore | None:
    """The file backend to consult, or `None` when the operator turned it off."""
    if path is not None:
        return CredentialFileStore(path)
    environ = _effective_env(env)
    override = environ.get(CREDENTIALS_FILE_ENV)
    if override is not None and override.strip().lower() in DISABLED_SPELLINGS:
        return None
    return CredentialFileStore(default_credential_file(environ))


# --- portable ref names ---------------------------------------------------------------


def device_ref(site: str | None, host: str) -> str:
    """The portable credential REF for one device: `gateclerk-<site>-<host>`, or `<host>`.

    With a site block the name is `config.credential_ref`'s — the same string systemd's
    `LoadCredential=` carries and the unit template already writes. Without one (a bare
    `--host 192.0.2.10`, which is most of P1's CLI use) there is no site to name, so the
    ref is the host: exactly what today's keychain ACCOUNT already is, which is why
    existing macOS items keep answering without being re-entered.
    """
    if site is not None and str(site).strip():
        return credential_ref(str(site), host)
    return host


def device_credential_refs(target: DeviceTarget) -> tuple[str, ...]:
    """The portable names a device password may be stored under, most portable first.

    Two names for a site block, one for a bare `--host`:

      1. `gateclerk-<site>-<host>` — the §2d name, and the only one that means anything on
         a Linux host (there is no legacy there, and the same file must resolve after a
         copy from a Mac);
      2. the legacy keychain address (the host itself) — kept so the item p1-02 told
         operators to create still answers on macOS with no re-typing.

    A bare `--host` collapses both to the host, so a plain CLI run reads exactly one
    keychain item, as it does today.
    """
    return tuple(dict.fromkeys([device_ref(target.site, target.host), target.keychain_account]))


#: The ref-name prefixes this repo's naming rules produce, spelled once here (the resolver
#: owns the names) so the inverse mapping below and the forward helpers cannot drift.
#: `agent_push` imports `INGEST_TOKEN_ENV_PREFIX` from here rather than repeating it. That
#: name is the AGENT's own contract; the Cloud Run receiver reads its own legacy-prefixed
#: constant and site-list env var from its own secret store (deliberately not spelled here;
#: see the private plan). The two ends are configured independently and neither name has
#: to match.
DEVICE_REF_PREFIX = "gateclerk-"
INGEST_REF_PREFIX = f"{DEVICE_REF_PREFIX}ingest-"
INGEST_TOKEN_ENV_PREFIX = "GATECLERK_INGEST_TOKEN_"  # noqa: S105 — a variable-NAME prefix


def env_var_candidates(ref: str) -> tuple[str, ...]:
    """Every env variable that COULD satisfy one ref name, in plausible order.

    The forward rules live in `config.env_var_names` and `ingest_token_env_var`; this is
    their inverse, and it is a *set* rather than one answer because
    `gateclerk-<site>-<host>` cannot be split back apart with certainty: site names carry
    hyphens (`site-a`) and so do hostnames (`dev-box.example`), and no separator rule can
    tell where one ends and the other begins. Enumerating the splits is honest — it can say
    "one of these variables would answer" — where guessing one would name a variable that
    does not exist.

      `gateclerk-ingest-<site>`  -> `GATECLERK_INGEST_TOKEN_<SITE>` (unambiguous: the whole
                                  remainder is the site)
      `<host>`                 -> `GATECLERK_<SANITIZED_HOST>_PASSWORD` (a bare-`--host` ref)
      `gateclerk-<site>-<host>`  -> one candidate per hyphen split of the remainder
    """
    from gateclerk.exceptions import ConfigError

    name = ref.strip()
    if not name:
        return ()
    if name.startswith(INGEST_REF_PREFIX):
        return (f"{INGEST_TOKEN_ENV_PREFIX}{name[len(INGEST_REF_PREFIX) :].upper()}",)
    if not name.startswith(DEVICE_REF_PREFIX):
        try:
            return (env_var_names(name)[1],)
        except ConfigError:
            return ()
    parts = name[len(DEVICE_REF_PREFIX) :].split("-")
    out: list[str] = []
    for cut in range(1, len(parts)):
        host = "-".join(parts[cut:])
        try:
            out.append(env_var_names(host)[1])
        except ConfigError:
            continue
    return tuple(dict.fromkeys(out))


def env_var_summary(ref: str) -> str:
    """What to PRINT as one ref's env rung: the candidate(s), or an honest empty string.

    Joined with ` | ` when the name is ambiguous (a `gateclerk-<site>-<host>` ref whose
    site/host split is not recoverable), because telling an operator "set one of these" is
    actionable and telling them a guessed variable is not.
    """
    return " | ".join(env_var_candidates(ref))


def env_var_for_ref(ref: str) -> str | None:
    """The env variable for one ref, when the NAME determines exactly one; else None.

    `creds get` prints this column, and printing a variable the operator would set in
    vain is worse than printing nothing — so an ambiguous device ref (where the site/host
    split is not recoverable) gets None and the detail line says why. `env_var_candidates`
    is what the "would the env rung satisfy this?" check uses, since any match is enough
    there and a wrong guess is harmless.
    """
    candidates = env_var_candidates(ref)
    return candidates[0] if len(candidates) == 1 else None


def ingest_ref(site: str) -> str:
    """The portable credential REF for one site's ingest bearer: `gateclerk-ingest-<site>`.

    Deliberately the same string as `agent_push.ingest_keychain_service(site)` — that is
    not a coincidence to tidy away, it *is* the portability rule: the bearer lives under
    one name and the backend (keychain item on macOS, `refs` entry on Linux) is the
    resolver's choice, not the call site's.
    """
    return credential_ref("ingest", site)


# --- the file backend -----------------------------------------------------------------


class CredentialFileStore:
    """The JSON credential file: `{"refs": {name: value}}`, mode 0600 or refused.

    A small explicit object rather than module functions because the path *is* state a
    caller may want to name (`$GATECLERK_CREDENTIALS_FILE`, a test's tmp HOME). Every read
    and every write goes through the same permission check — there is no "just this once"
    path, which is what makes the 0600 promise mean something.

    Values never appear in a repr, a message, or a log line: `find()` hands back a
    `Secret`, and the failure texts name only path, ref name, mode and shape.
    """

    __slots__ = ("path",)

    def __init__(self, path: Path | str) -> None:
        self.path = Path(path).expanduser()

    def __repr__(self) -> str:
        # No values, ever: this object is held by a resolver that outlives the lookup.
        return f"CredentialFileStore(path={str(self.path)!r})"

    # --- reading ---------------------------------------------------------------------

    def exists(self) -> bool:
        return self.path.is_file()

    def mode(self) -> int | None:
        """The file's permission bits, or None when there is no file to stat."""
        try:
            return stat.S_IMODE(self.path.stat().st_mode)
        except OSError:
            return None

    def find(self, *refs: str) -> tuple[str, Secret] | None:
        """`(name, Secret)` for the first of `refs` the file carries; None when none do.

        The name comes back because a ladder with more than one candidate ref (the device
        one has two) has to report WHICH name answered, and `Secret.label` is already
        carrying the `file:<name>` provenance.
        """
        refs_map = self._read_refs()
        for name in refs:
            value = refs_map.get(name)
            if value:
                return name, Secret(str(value), label=f"file:{name}")
        return None

    def read(self, *refs: str) -> Secret | None:
        """The value for the first of `refs`, or None (the name-dropping form of `find`)."""
        found = self.find(*refs)
        return None if found is None else found[1]

    def names(self) -> tuple[str, ...]:
        """Every ref name the file carries — sorted, and never a value.

        This is what `creds get` (and, once CLI-DOCTOR merges, `doctor`) surface, so "what
        is installed?" is answerable with a command that could not print a secret if it
        tried.
        """
        return tuple(sorted(self._read_refs()))

    def has(self, name: str) -> bool:
        """Whether `name` is present with a non-empty value."""
        return bool(self._read_refs().get(name))

    def source_for(self, name: str) -> str:
        """What this file says about one ref: `present`, `absent`, or `empty`.

        Three answers, not two, because the third one is the bug people hit: a ref stored
        with an empty value reads as absent to the resolver (an empty variable counts as
        unset everywhere in this repo), and an operator staring at a `creds get` that says
        "no" has no way to find out they typed it wrong.
        """
        value = self._read_refs().get(name)
        if value is None:
            return "absent"
        return "present" if value else "empty"

    # --- writing (only `gateclerk creds set` does this) --------------------------------

    def write(self, name: str, value: str) -> None:
        """Add or replace one ref, atomically, creating the file 0600.

        The mode check runs BEFORE the value is written: an existing 0644 store is refused
        rather than quietly augmented (writing a secret into a file other users can read is
        the accident itself, not its aftermath). The write is a temp file plus `os.replace`
        so a crash cannot leave a half-written store — or a store missing a ref.
        """
        if not name or not name.strip():
            raise CredentialUnavailable("a credential ref name must not be empty")
        if not value:
            raise CredentialUnavailable(
                f"refusing to store an EMPTY value under {name.strip()!r}: an empty "
                "credential is never valid, and it would shadow the env and platform "
                "rungs with a blank."
            )
        refs_map = self._read_refs()  # also enforces the mode on an existing file
        refs_map[name.strip()] = value
        self._atomic_write(refs_map)

    def remove(self, name: str) -> bool:
        """Drop one ref. True when something was removed, False when the name was absent."""
        refs_map = self._read_refs()
        if name.strip() not in refs_map:
            return False
        del refs_map[name.strip()]
        self._atomic_write(refs_map)
        return True

    def _atomic_write(self, refs_map: dict[str, Any]) -> None:
        directory = self.path.parent
        try:
            directory.mkdir(parents=True, exist_ok=True)
            directory.chmod(0o700)
        except OSError as exc:
            raise CredentialUnavailable(
                f"cannot prepare the credential directory {directory}: {exc.strerror or exc}"
            ) from exc
        payload = json.dumps({"refs": refs_map}, indent=2, sort_keys=True) + "\n"
        # `0o600` at open() time rather than a chmod after the fact: between create and
        # chmod the file would briefly exist with the umask's mode, which is exactly the
        # window this card exists to close. The chmods below are still needed because a
        # umask can LOWER the mode open() asked for.
        tmp = self.path.with_name(f"{self.path.name}.tmp")
        try:
            fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, REQUIRED_FILE_MODE)
            try:
                with os.fdopen(fd, "w", encoding="utf-8") as handle:
                    handle.write(payload)
                tmp.chmod(REQUIRED_FILE_MODE)
                tmp.replace(self.path)
                self.path.chmod(REQUIRED_FILE_MODE)
            except BaseException:
                with contextlib.suppress(OSError):
                    tmp.unlink()
                raise
        except OSError as exc:
            raise CredentialUnavailable(
                f"cannot write the credential file {self.path}: {exc.strerror or exc}"
            ) from exc

    # --- the one place the file's shape and mode are decided -------------------------

    def _read_refs(self) -> dict[str, Any]:
        try:
            raw = self.path.read_bytes()
        except FileNotFoundError:
            return {}
        except NotADirectoryError:
            raise self._bad(f"its parent {self.path.parent} is not a directory") from None
        except IsADirectoryError:
            raise self._bad("it is a directory, not a JSON file") from None
        except OSError as exc:
            raise self._bad(exc.strerror or str(exc)) from exc

        # Checked on the bytes we are about to trust: an unreadable-by-us file already
        # raised, so what is left to ask is "can ANYONE ELSE read it?".
        mode = self.mode()
        if mode is not None and mode & PERMISSIVE_BITS:
            raise CredentialUnavailable(
                f"the credential file {self.path} is mode {mode:04o} — group or other can "
                f"read a plaintext secret store, so gateclerk refuses to use it. Fix it and "
                f"re-run:\n    chmod 600 {self.path}\n"
                f"(0600 owner-read/write is the required mode; README 'Credentials'.)"
            )
        if not raw.strip():
            return {}
        try:
            document = json.loads(raw.decode("utf-8"))
        except (ValueError, UnicodeDecodeError) as exc:
            raise self._bad(
                f"it is not valid JSON ({type(exc).__name__}); rewrite it with "
                "`gateclerk creds set <ref> --file -`"
            ) from None
        if not isinstance(document, dict) or not isinstance(document.get("refs"), dict):
            raise self._bad(
                'it has no "refs" object — the documented shape is '
                '{"refs": {"<ref-name>": "<value>"}}: ref names and values, nothing else'
            )
        refs_map: dict[str, Any] = document["refs"]
        for name, value in refs_map.items():
            if not isinstance(value, str):
                # Names the ref and the file, never the offending value.
                raise self._bad(f"ref {name!r} holds a {type(value).__name__}, not a string")
        return refs_map

    def _bad(self, why: str) -> CredentialUnavailable:
        return CredentialUnavailable(
            f"cannot use the credential file {self.path}: {why}. The file must be mode "
            f'{REQUIRED_FILE_MODE:04o} and shaped as {{"refs": {{"<ref>": "<value>"}}}}. '
            "A missing file is fine (the other rungs answer); a broken one is not."
        )


# --- the resolver ---------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class ResolvedRef:
    """A resolved credential plus the safe half of its provenance (name + backend)."""

    ref: str
    secret: Secret
    source: CredentialSource
    comment: str | None = None

    def __repr__(self) -> str:
        return (
            f"ResolvedRef(ref={self.ref!r}, secret={self.secret!r}, "
            f"source={self.source.value!r}, comment={self.comment!r})"
        )

    def user_hint(self) -> str | None:
        """The `user=` inside the platform item's comment, if it carried one.

        Delegates to `KeychainItem.user_hint()` rather than repeating its regex: that
        parser is tolerant of surrounding text on purpose (humans write these comments by
        hand) and p1-02's tests pin exactly how tolerant. A resolver that re-implemented it
        would be a second definition of "what counts as a user hint", and the second one
        always loses the edge cases.
        """
        if self.comment is None:
            return None
        return KeychainItem(password=self.secret, comment=self.comment).user_hint()


def resolve_secret(
    *,
    refs: Sequence[str],
    env_names: Sequence[str],
    what: str,
    explicit: Secret | None = None,
    store_refs: Sequence[str] | None = None,
    store_target: Callable[[str], DeviceTarget] | None = None,
    add_command: Callable[[str], str] | None = None,
    env: Mapping[str, str] | None = None,
    keychain: Any = None,
    store: Any = AMBIENT,
    with_comment: bool = True,
    platform_name: str | None = None,
) -> ResolvedRef:
    """Resolve one credential by ref name: **flag > env > platform store > file**.

    `refs` — the portable names, first = the one to advertise in a fix line.
    `store_refs` — the names to look up in the platform store (defaults to `refs`). The
    device ladder passes only the legacy keychain address here: on macOS the Keychain rung
    must make exactly the p1-02 call with the p1-02 argv, and trying a second service name
    first would add a `security` invocation — each of which can raise a macOS ACL prompt —
    to every run that has a keychain item today.
    `store_target` — builds the platform-store address for a name (None = no store rung).
    `env_names` — the env variables, in precedence order; `explicit` — the flag value.
    `what` — the noun the messages describe ("credential for device 192.0.2.10").
    `add_command` — the copy-paste fix line for a name.

    Raises `CredentialUnavailable` naming every rung it tried plus the exact fix for each.
    No value appears in any message, including the failure path.
    """
    if not refs:
        raise CredentialUnavailable(f"{what}: no credential reference name was given")
    environ = _effective_env(env)

    if explicit is not None:
        # An EMPTY explicit value still wins the rung and returns: `resolve_credentials`
        # then refuses it as "an EMPTY password is never valid" rather than silently
        # falling through to env/keychain, which is p1-02's pinned behaviour for
        # `--password ''` ("I meant to give one" — a fallthrough hides the typo).
        return ResolvedRef(ref=refs[0], secret=explicit, source=CredentialSource.FLAG)

    for name in env_names:
        value = environ.get(name)
        if value:
            return ResolvedRef(
                ref=refs[0],
                secret=Secret(value, label=f"env:{name}"),
                source=CredentialSource.ENV,
            )

    miss: list[str] = []
    keychain_error: CredentialUnavailable | None = None

    # --- platform store (the macOS Keychain; elsewhere it reports itself unavailable)
    if store_target is not None:
        reader: Any = keychain if keychain is not None else KeychainReader()
        for ref in refs if store_refs is None else store_refs:
            try:
                item = reader.read(store_target(ref), with_comment=with_comment)
            except CredentialUnavailable as exc:
                keychain_error = keychain_error or exc
                miss.append(f"platform store: {exc}")
                continue
            if item.password.reveal():
                return ResolvedRef(
                    ref=ref,
                    secret=item.password,
                    source=CredentialSource.KEYCHAIN,
                    # `getattr`, not a direct read: `KeychainReader` always answers with a
                    # `KeychainItem`, but the injected fakes across three test files are
                    # duck-typed objects carrying only `password` — and a resolver that
                    # crashed on a reader without a comment would turn a passing test into
                    # a false failure on the seam the tests exist to exercise.
                    comment=getattr(item, "comment", None),
                )
            miss.append(f"platform store: item {ref!r} exists but is empty")
    else:
        miss.append("platform store: not applicable")

    # --- file backend (the Linux answer, and the lowest rung everywhere)
    file_store: CredentialFileStore | None = (
        resolve_file_store(environ) if store is AMBIENT else store
    )
    if file_store is not None:
        try:
            found = file_store.find(*refs)
        except CredentialUnavailable as exc:
            miss.append(f"credential file: {exc}")
        else:
            if found is not None:
                ref, secret = found
                return ResolvedRef(ref=ref, secret=secret, source=CredentialSource.FILE)
            miss.append(f"credential file: no ref among {list(refs)} in {file_store.path}")
    else:
        miss.append(f"credential file: disabled (${CREDENTIALS_FILE_ENV})")

    raise _no_credential(
        what,
        refs,
        env_names,
        miss,
        keychain_error=keychain_error,
        add_command=add_command,
        platform_name=platform_name,
        store=file_store,
    )


def _no_credential(
    what: str,
    refs: Sequence[str],
    env_names: Sequence[str],
    miss: Sequence[str],
    *,
    keychain_error: CredentialUnavailable | None,
    add_command: Callable[[str], str] | None,
    platform_name: str | None,
    store: CredentialFileStore | None,
) -> CredentialUnavailable:
    """Build the refusal, keeping the macOS Keychain text byte-identical to p1-02.

    Three shapes, chosen by which rung came back empty:

    * macOS and the Keychain answered with an error -> that error verbatim. It is pinned
      by tests and by muscle memory ("the fix is a paste away"), and the card's rule is
      that the macOS path does not change.
    * Another platform, but the Keychain produced an error -> that text, then the fixes
      that exist HERE (env, file). No `security` line is added when the text already
      carries one: two paste-away commands for the same missing item read as a puzzle.
    * Nothing errored (every rung simply missed) -> the ladder, each rung's own reason,
      plus one fix line per rung that an operator can fill in.
    """
    if keychain_error is not None:
        if is_macos(platform_name):
            return CredentialUnavailable(str(keychain_error))
        already_names_fix = "add-generic-password" in str(keychain_error)
        lines = [f"no {what}: {keychain_error}", "", "Also tried:"]
        # The other rungs' own reasons are printed too (never a value): on Linux the
        # Keychain error is the *least* actionable line in the message, and "the file you
        # installed is mode 0644" is the line that fixes the deploy.
        lines += [f"    - {reason}" for reason in miss if "platform store" not in reason]
        lines.append("Fix one of:")
        lines += _fix_lines(refs, env_names, add_command, store, skip_platform=already_names_fix)
        return CredentialUnavailable("\n".join(lines))

    lines = [f"no {what}. Tried:"]
    lines += [f"    - {reason}" for reason in miss]
    lines.append("Fix one of:")
    lines += _fix_lines(refs, env_names, add_command, store, skip_platform=False)
    return CredentialUnavailable("\n".join(lines))


def _fix_lines(
    refs: Sequence[str],
    env_names: Sequence[str],
    add_command: Callable[[str], str] | None,
    store: CredentialFileStore | None,
    *,
    skip_platform: bool,
) -> list[str]:
    """The paste-away fixes, in ladder order. Never a value; each is one command."""
    lines: list[str] = []
    if add_command is not None and not skip_platform:
        lines.append(f"    {add_command(refs[0])}")
    if env_names:
        lines.append(
            f"    set {env_names[0]} in the environment (a gitignored .env, a systemd "
            "EnvironmentFile=, or the shell — never a committed file)"
        )
    if store is not None:
        lines.append(
            f"    store it in {store.path} with:\n"
            f"        gateclerk creds set {refs[0]} --file -   "
            "# the value arrives on stdin, so it never lands in shell history"
        )
    return lines


def resolve_device_password(
    target: DeviceTarget,
    *,
    password: str | None = None,
    env: Mapping[str, str] | None = None,
    keychain: Any = None,
    store: Any = AMBIENT,
    with_comment: bool = True,
    platform_name: str | None = None,
) -> ResolvedRef:
    """The device half of the ladder as one `ResolvedRef` (no user resolution here).

    `config.resolve_credentials` remains the public entry point and calls this; it is a
    separate function so the ingest path and any later call site can share `resolve_secret`
    without pretending to be a device login.
    """
    explicit = Secret(password, label=f"flag:{target.host}") if password is not None else None
    # The PASSWORD rungs only, in precedence order: `env_var_names` returns (per-host user,
    # per-host password, global user, global password) because the CLI's `_resolve_user`
    # walks the same tuple for the *user*. Handing the whole tuple to the password ladder
    # would read `GATECLERK_<HOST>_USER` as a password — which is exactly the mistake a
    # "just pass the tuple" refactor makes, so the two slots are picked by name.
    _, host_password, _, global_password = env_var_names(target.host)

    def store_target(ref: str) -> DeviceTarget:
        # The legacy name IS today's item (service `keychain_service`, account = the host),
        # so it resolves with p1-02's argv. A portable name would live under the ref
        # itself — `creds set` writes it to the file backend, so this branch is the seam a
        # future keychain-backed portable store would use, not a second lookup on today's
        # path (`store_refs` never asks for it).
        if ref == target.keychain_account:
            return target
        return DeviceTarget(
            host=target.host,
            port=target.port,
            site=target.site,
            keychain_service=ref,
            config_user=target.config_user,
        )

    return resolve_secret(
        refs=device_credential_refs(target),
        store_refs=(target.keychain_account,),
        env_names=(host_password, global_password),
        what=f"credential for device {target.host!r}",
        explicit=explicit,
        store_target=store_target,
        add_command=lambda ref: _device_add_command(target, ref),
        env=env,
        keychain=keychain,
        store=store,
        with_comment=with_comment,
        platform_name=platform_name,
    )


def _device_add_command(target: DeviceTarget, ref: str) -> str:
    """The `security` command that would satisfy one ref name (macOS's own fix line)."""
    if ref == target.keychain_account:
        return target.add_command()  # carries the `user=` comment hint, as p1-02 shipped
    return DeviceTarget(
        host=target.host,
        port=target.port,
        site=target.site,
        keychain_service=ref,
        config_user=target.config_user,
    ).add_command()


def resolve_ingest_token(
    site: str,
    *,
    token: str | Secret | None = None,
    env: Mapping[str, str] | None = None,
    keychain: Any = None,
    store: Any = AMBIENT,
    env_var: str,
    keychain_service: str,
    platform_name: str | None = None,
) -> ResolvedRef:
    """One site's ingest bearer token, through the same ladder as a device password.

    `env_var` / `keychain_service` are passed in rather than imported from `agent_push`
    because that module imports this one: the names stay where they were defined
    (`GATECLERK_INGEST_TOKEN_<SITE>`, `gateclerk-ingest-<site>`, both mirrored from the ingest
    function) and this function only resolves them.

    There is still NO global fallback rung — see `HttpsIngestTransport._resolve_token`: the
    token DETERMINES the site, so falling back to another site's token would either 403 or,
    worse, attribute one site's punches to another.
    """
    explicit: Secret | None
    if isinstance(token, str):
        explicit = Secret(token, label=f"flag:{site}") if token else None
    else:
        explicit = token

    def store_target(ref: str) -> DeviceTarget:
        # The keychain ACCOUNT is the site (a device credential's account is the host —
        # different item, different purpose, both macOS-managed).
        return DeviceTarget(host=site, site=site, keychain_service=ref)

    def add_command(ref: str) -> str:
        import shlex

        # No `user=` comment: an ingest bearer has no user half, and a misleading command
        # is worse than none. `-w` last so the value is prompted, never typed into history.
        return (
            "security add-generic-password -U "
            f"-s {shlex.quote(ref)} -a {shlex.quote(site.strip())} -w"
        )

    return resolve_secret(
        refs=(ingest_ref(site),),
        store_refs=(keychain_service,),
        env_names=(env_var,),
        what=f"ingest bearer token for site {site!r}",
        explicit=explicit,
        store_target=store_target,
        add_command=add_command,
        env=env,
        keychain=keychain,
        store=store,
        with_comment=False,  # no `user=` hint; a 2nd `security` call is a 2nd ACL prompt
        platform_name=platform_name,
    )
