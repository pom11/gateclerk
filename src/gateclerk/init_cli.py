"""`gateclerk init` — guided first-site setup, safe for a nervous new user (card CLI-INIT).

What this module owns
---------------------
One command, five steps, in the order the card specifies:

  1. **where** the config goes (default ``~/gateclerk/sites.toml``), created if absent;
  2. **the device**: host + admin credential *references*, then one read-only probe
     (deviceInfo: model/serial/firmware, plus the enrolled-user count);
  3. **where the data goes**: an https ingest URL + a bearer REFERENCE name, or a
     csv/jsonl file sink — validated by ``gateclerk.sinks``/``sink_cli``, not re-derived;
  4. **``device_code``**: explained, and written only when the operator says BC's device
     code differs from the serial the probe just read;
  5. **write** the file atomically, print what went into it (names only), then next steps.

Why a group with ``invoke_without_command`` instead of a plain command
---------------------------------------------------------------------
``gateclerk init`` is one operation, not a family — but declaring it as a leaf *command*
inside ``cli.py`` is what the fleet's structure card (CLI-SPLIT-STRUCTURE) is removing. A
Typer group whose only behavior is its callback reads as one leaf to the surface guards
(``test_cli_conventions._leaves`` descends ``Group.commands``, and this group has none)
while keeping every handler in this module. The steer from the orchestrator was explicit:
declare the group and its handler here, and let ``cli.py`` do nothing but ``add_typer``.

The four safety laws, and where each is enforced
------------------------------------------------
* **never clobber** — an existing target is refused (exit 2) naming ``sink add`` /
  ``sink remove`` / editing the file, unless ``--force``, and ``--force`` first copies the
  bytes it is replacing next to the file. A file that does not even parse is still an
  existing file: replacing it is exactly the clobber the rule exists to stop.
* **references only** — the written text is produced by ``SiteConfig`` + the sink
  registry, which have no key that could hold a password (an unknown key is refused at
  parse time), and every token flag goes through ``sink_cli.token_ref_problem`` first, so
  a bearer typed into a reference prompt is refused *and not echoed back*.
* **never a keychain value** — setup only ever asks whether an item EXISTS
  (``sink_cli.keychain_item_exists``: an attribute lookup, no ``-w``, nothing printable
  comes back) and prints the ``security add-generic-password`` line for the human to run.
  ``plan_site`` therefore never constructs a reader at all; only the probe authenticates,
  through ``config.resolve_credentials`` — the same ladder every other command uses.
* **atomic write** — temp file in the target's own directory, fsync, re-parse with the
  real validator, then ``os.replace`` (see :func:`write_config_atomic`), the same law
  ``sink_cli._install`` enforces for an already-deployed site.

Exit codes are ``gateclerk.cli_conventions``' shipped contract, imported not re-declared:
2 usage/config/credential, 3 terminal auth (a 401 during the probe), 4 device/protocol
(the box did not answer). ``init`` never restarts a service and never shells out: there
is no ``subprocess`` in this module, by test.
"""

from __future__ import annotations

import os
import re
import sys
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Annotated, Any

import httpx
import typer

from gateclerk import config as cfg
from gateclerk.cli_conventions import ExitCode, exit_code_for
from gateclerk.exceptions import ConfigError, CredentialUnavailable, GateClerkError
from gateclerk.output import OutputFormat, make_console, render
from gateclerk.secrets import Secret
from gateclerk.sink_cli import keychain_item_exists, token_ref_problem

__all__ = [
    "ANSWER_ORDER",
    "DEFAULT_STATE_DIR",
    "InitError",
    "ProbeReport",
    "SitePlan",
    "build_site_block",
    "credential_hint",
    "device_code_explanation",
    "keychain_item_exists",
    "plan_site",
    "probe_device",
    "push_target_problem",
    "render_next_steps",
    "write_config_atomic",
]

#: The card's step (1): state + config location. ``~/gateclerk/`` is the default because it
#: is outside every git checkout (a committed sites.toml is how a host name escapes a repo)
#: and outside ``/etc`` (no sudo, so no root-owned config a user cannot edit).
DEFAULT_STATE_DIR = Path("~/gateclerk").expanduser()

#: The questions, in the order they are asked. ``tests/test_cli_init.py`` pins this tuple
#: against its own transcript builder, so a reworded prompt cannot silently make a test
#: answer the wrong question.
ANSWER_ORDER: tuple[str, ...] = (
    "site",
    "host",
    "port",
    "user",
    "iana_tz",
    "push",
    "push_url",
    "token_ref",
    "codes_differ",
    "device_code",
    "confirm",
)

#: What the push step accepts. ``none`` is first because a site with no sink is a valid
#: state (spec §3: absence means the pusher is off, and an endpoint may never be defaulted).
PUSH_CHOICES = ("none", "https", "csv", "jsonl")

#: The one text this module prints about a missing credential, other than the command.
_CRED_INTRO = "no admin credential found for this device — add it, then re-run:"


class InitError(Exception):
    """A refusal the operator can act on: exit 2 (the config/usage class), message only.

    Deliberately not a ``ConfigError``: the config layer's own errors mean "the file you
    pointed me at is unusable", which is a different sentence to print than "the answer you
    gave me is unusable". Both map to 2, and both are printed by the same printer.
    """


@dataclass(frozen=True, slots=True)
class ProbeReport:
    """What the read-only probe learned. Names and numbers, never a credential.

    `user_count_known` separates "the device has zero enrolled users" from "this firmware
    would not tell me" — the first is a fact about the box, the second is a fact about the
    probe, and an operator who reads the second as the first will go and enroll someone.
    """

    serial: str | None
    model: str | None
    firmware: str | None
    device_name: str | None = None
    device_type: str | None = None
    user_count: int | None = None
    user_count_known: bool = False

    def as_row(self) -> dict[str, Any]:
        return {
            "serial": self.serial,
            "model": self.model,
            "firmware": self.firmware,
            "device_name": self.device_name,
            "device_type": self.device_type,
            "user_count": self.user_count,
            "user_count_known": self.user_count_known,
        }


@dataclass(slots=True)
class SitePlan:
    """The site block `init` would write, plus the evidence behind it.

    `render()` is the only thing that reaches the file, and it is a pure function of these
    fields: the write path re-parses exactly this text, so what the operator confirmed on
    screen is byte-identical to what lands on disk.
    """

    site: cfg.SiteConfig
    answers: dict[str, str] = field(default_factory=dict)
    probe: ProbeReport | None = None
    sink_url: str | None = None
    sink_type: str | None = None
    sink_path: str | None = None
    token_env: str | None = None
    token_keychain: str | None = None
    credential_add_command: str | None = None
    code_explanation: str | None = None

    def render(self) -> str:
        """The sites.toml text for this plan: header comment + one `[[site]]` block.

        Built by `build_site_block`, which emits `key = value` lines from the validated
        `SiteConfig` — no f-string interpolation of an answer anywhere, which is what makes
        "refs only" a structural property rather than a review habit.
        """
        return build_site_block(self.site, sink=self._sink_block())

    def _sink_block(self) -> dict[str, Any] | None:
        if self.sink_type is None:
            return None
        block: dict[str, Any] = {"name": "ingest", "type": self.sink_type}
        if self.sink_type == "https":
            block["url"] = self.sink_url or ""
            if self.token_env:
                block["token_env"] = self.token_env
            if self.token_keychain:
                block["token_keychain"] = self.token_keychain
        else:
            block["path"] = self.sink_path or ""
        return block


# --- step 3 validation (delegated, deliberately) ------------------------------------------------


def push_target_problem(url: str) -> str | None:
    """`None` when an ingest URL carries an accepted scheme, else a refusal naming it.

    Reads `cfg.PUSH_TARGET_SCHEMES` — §3's own tuple — rather than re-spelling `https://`:
    a sink is a new NAME for a target, not a new kind of target, so `http://` stays refused
    for exactly the reason §3 refuses it (a bearer token never crosses clear text) and
    `stub://` stays the owner-authorized local exception. If §3 ever widens, `init` widens
    with it instead of drifting behind it.
    """
    allowed = " or ".join(cfg.PUSH_TARGET_SCHEMES)
    if not url.startswith(cfg.PUSH_TARGET_SCHEMES):
        return (
            f"push url {url!r} has an unacceptable scheme: it must start with {allowed} "
            "(never a default endpoint — docs/P2-SITE-AGENT.md §3)"
        )
    return None


# --- step 1 + 2: the credential, by reference ----------------------------------------------------


def credential_hint(site: str, host: str, *, user: str, keychain_service: str) -> dict[str, str]:
    """Where a credential would be found for this device — NAMES only, nothing resolved.

    Returns the two names an operator needs (`env_var`, `keychain`) plus the exact
    `security add-generic-password` line that would create the item. No value is read here
    and none can be: `DeviceTarget.add_command()` ends in `-w`, which makes `security`
    PROMPT for the value, so the password never enters a shell history or this process.
    """
    target = cfg.DeviceTarget(
        host=host,
        site=site,
        keychain_service=keychain_service,
        config_user=user,
    )
    env_names = cfg.env_var_names(host)
    return {
        "env_user": env_names[0],
        "env_password": env_names[1],
        "keychain_service": keychain_service,
        "keychain_account": target.keychain_account,
        "add_command": target.add_command(),
        "find_command": target.find_command(),
        "ref": cfg.credential_ref(site, host),
    }


def credential_available(
    host: str,
    *,
    keychain_service: str,
    env: Mapping[str, str] | None = None,
    exists: Callable[[str, str], bool | None] | None = None,
) -> tuple[bool, str | None]:
    """Is there a credential for this device? Answers WITHOUT reading any value.

    `(yes, None)` when one of the non-interactive rungs can supply it, `(no, why)`
    otherwise. Two belts on the "never a value" law:

    * the env rung is tested by NAME presence — the value is never even read here;
    * the keychain rung is `keychain_item_exists`, which is an attribute lookup without
      `-w`. It returns None ("cannot tell", i.e. not macOS), which is reported as a
      refusal-with-a-suggestion rather than a false "it is not there".

    `exists` is injectable so the suite never spawns `security`; the default is the same
    helper `sink test` uses, so the two commands cannot disagree about what "configured"
    means.
    """
    environ: Mapping[str, str] = os.environ if env is None else env
    host_user, host_password, global_user, global_password = cfg.env_var_names(host)
    for name in (host_password, global_password):
        if environ.get(name):
            return True, None
    probe = exists or (lambda service, account: keychain_item_exists(service, account=account))
    verdict = probe(keychain_service, host)
    if verdict is True:
        return True, None
    if verdict is None:
        return (
            False,
            f"no {host_password} in the environment, and no keychain is available here to "
            f"check — set {host_password} (user via {host_user}, or the global "
            f"{global_user}/{global_password}).",
        )
    return False, None


# --- step 2: the probe ---------------------------------------------------------------------------


def probe_device(
    *,
    host: str,
    port: int,
    user: str,
    password: Secret,
    timeout_s: float = cfg.DEFAULT_TIMEOUT_S,
    site: str | None = None,
    site_tz: str = "UTC",
) -> ProbeReport:
    """Read-only device probe: `System/deviceInfo` + the enrolled-user count.

    Exactly two things on the wire, both in the read-only endpoint registry: a GET
    `System/deviceInfo` and the roster walk (whose count GET is the `--count` cross-check
    p1-05 already ships). No POST to a write path, no verb the read-only client cannot use —
    the same guarantee `test_cli_e2e_battery.py` enforces for the event commands, held here
    by construction: this function only ever calls `client.get` and `pipeline.fetch_users`.

    `site_tz` is threaded from the answer the operator just gave: the probe reads no
    timestamps, so the zone decides nothing here — but `compile_run_context` validates it
    before any socket opens, which is what makes a typo'd zone exit 2 with the zone named
    instead of arriving later as 400 pages of `unresolved` records.

    Raises the transport's own typed errors (`IsapiAuthError` on 401, `IsapiError` on an
    unreachable/unusable box) so the caller can map them to 3 and 4 through
    `cli_conventions.exit_code_for` — the one source for the numbers. A probe that failed
    is never turned into a "looks fine" report: the caller writes nothing on this path.
    """
    from gateclerk import pipeline
    from gateclerk.capabilities import device_identity
    from gateclerk.cli import IsapiClient  # the seam the suite redirects

    with IsapiClient(
        f"http://{host}:{port}", user, password.reveal(), read_timeout=timeout_s
    ) as client:
        body = client.get("device_info")
        serial, firmware, model = device_identity(body)
        context = pipeline.compile_run_context(
            site=site or host,
            site_tz=site_tz,
            max_records=1000,
        )
        roster = pipeline.fetch_users(client, context=context, with_count=True)
        node = _device_info_node(body)
        return ProbeReport(
            serial=serial,
            model=model,
            firmware=firmware,
            device_name=_text_of(node, "deviceName"),
            device_type=_text_of(node, "deviceType"),
            user_count=len(roster.users),
            user_count_known=True,
        )


def _device_info_node(body: Mapping[str, Any]) -> Mapping[str, Any]:
    """The `DeviceInfo` mapping inside a deviceInfo body (XML-flattened, per OBSERVED.md)."""
    for value in body.values():
        if isinstance(value, Mapping) and any(k in value for k in ("serialNumber", "model")):
            return value
    return body


def _text_of(node: Mapping[str, Any], key: str) -> str | None:
    value = node.get(key)
    return str(value) if value not in (None, "") else None


# --- steps 1-4: the plan ------------------------------------------------------------------------


def plan_site(
    answers: Mapping[str, str],
    *,
    env: Mapping[str, str] | None = None,
    keychain: Any = None,
) -> SitePlan:
    """Turn the operator's answers into a validated `SitePlan`. Refuses loudly, exits 2.

    This is the pure half of `init` — no console, no filesystem, no socket, no keychain
    reader (the `keychain` argument exists so a test can PROVE the resolver never calls it;
    production passes None and nothing ever constructs one here). Everything the file will
    contain is decided here, so "what I confirmed on screen" and "what is on disk" are the
    same object.

    Order of refusals is the order that is most useful to whoever typed it:
    a missing required answer (a scripted run must not guess a payroll timezone), then the
    timezone (payroll truth, and the cheapest thing to get wrong), then the sink shape and
    its token reference (the one mistake that puts a bearer in a committed file), then
    `device_code` (only meaningful when the operator said the codes differ).
    """
    environ: Mapping[str, str] = os.environ if env is None else env
    del environ  # the plan holds NAMES; whether a rung is populated is `credential_available`'s job

    def answer(key: str, *, required: bool = True) -> str:
        value = (answers.get(key) or "").strip()
        if not value and required:
            raise InitError(
                f"no answer for {key!r}. Nothing here is guessed: the site name and the "
                "site timezone in particular are payroll truth, and a default for either "
                "would be someone else's site."
            )
        return value

    site_name = answer("site")
    host = answer("host")
    raw_port = (answers.get("port") or "").strip()
    port = _port(raw_port) if raw_port else cfg.DEFAULT_PORT
    user = (answers.get("user") or "").strip() or cfg.DEFAULT_ISAPI_USER
    iana_tz = answer("iana_tz")

    push = (answer("push", required=False) or "none").lower()
    if push not in PUSH_CHOICES:
        raise InitError(
            f"push target {push!r} is unknown (choose: {', '.join(PUSH_CHOICES)}). "
            "`none` is a valid answer — no sink means the pusher stays off, never a "
            "defaulted endpoint."
        )

    sink_url = (answers.get("push_url") or "").strip() or None
    token_ref = (answers.get("token_ref") or "").strip() or None
    sink_path: str | None = None
    token_env: str | None = None
    token_keychain: str | None = None

    if push == "none":
        if sink_url:
            raise InitError(
                "you chose `none` for the push target but named a URL — pick one. A site "
                "with a URL and no sink silently delivers nothing."
            )
    elif push == "https":
        if not sink_url:
            raise InitError(
                "an https sink needs the ingest URL. There is no default endpoint to fall "
                "back on (docs/P2-SITE-AGENT.md §3), so this is a refusal, not a guess."
            )
        problem = push_target_problem(sink_url)
        if problem is not None:
            raise InitError(problem)
        # The token flag is a NAME. `token_ref_problem` refuses a value-shaped string
        # WITHOUT echoing it, which is why this line can safely print the flag name.
        token_env, token_keychain = (
            _token_rungs(token_ref, site=site_name) if token_ref else (None, None)
        )
    else:
        if not sink_url:
            raise InitError(f"a {push} sink needs an absolute file path (the sink writes there).")
        sink_path = sink_url
        sink_url = None
        if token_ref:
            raise InitError(
                f"a {push} sink has no bearer token to reference — drop the token "
                "reference or choose `https`."
            )

    codes_differ = _yes_no(answers.get("codes_differ") or "", "codes_differ")
    # The code is honoured ONLY when the operator said the codes differ. An answer in that
    # slot while saying "they match" is an answer the operator did not mean to give (the
    # scripted-transcript shape), and writing it would rename every roster line for this
    # site on the strength of a line nobody was reading.
    device_code = (answers.get("device_code") or "").strip() or None
    if not codes_differ:
        device_code = None
    explanation: str | None = None
    if codes_differ:
        if not device_code:
            raise InitError(
                "you said Business Central's device Code differs from the device Serial, so "
                f"the code is required (e.g. `D-IF-1`). {device_code_explanation()}"
            )
        explanation = device_code_explanation(device_code)

    # One construction, one validator: `SiteConfig` refuses an unresolvable zone, a bad
    # port, an empty name/host, and — the law that matters most here — any key it does not
    # know, which is how "a password cannot be written by this command" stays true even if
    # someone later adds a prompt they should not have added.
    site = cfg.SiteConfig(
        name=site_name,
        host=host,
        port=port,
        iana_tz=iana_tz,
        isapi_user=user,
        device_code=device_code,
        surface=cfg.ConfigSurface.CLI,
    )
    return SitePlan(
        site=site,
        answers=dict(answers),
        sink_type=None if push == "none" else push,
        sink_url=sink_url,
        sink_path=sink_path,
        token_env=token_env,
        token_keychain=token_keychain,
        code_explanation=explanation,
    )


def _port(raw: str) -> int:
    try:
        port = int(raw)
    except ValueError:
        raise InitError(f"port {raw!r} is not a number") from None
    if not 1 <= port <= 65535:
        raise InitError(f"port {port} is outside 1..65535")
    return port


def _yes_no(raw: str, key: str) -> bool:
    value = raw.strip().lower()
    if value in ("y", "yes"):
        return True
    if value in ("n", "no", ""):
        return False
    raise InitError(f"{key} must be answered yes or no (got {raw!r})")


def _token_rungs(ref: str, *, site: str) -> tuple[str | None, str | None]:
    """Split a bearer reference into (env_var_name, keychain_service). Names only.

    The two conventions this repo already uses decide the answer — `GATECLERK_INGEST_TOKEN_SITE-A`
    is an env var (upper case, and site names carry dashes, so the pattern admits them) and
    `gateclerk-ingest-site-a` is a keychain service (lower case) — which means `init` invents
    no third spelling of "where the token lives". The value-shape guard runs FIRST, so the
    refusal for a pasted bearer is `sink add`'s own words and never echoes the pasted string.

    `site` is kept in the signature because the DEFAULT reference for a site is
    site-derived (`agent_push.ingest_keychain_service(site)`), and a reader who lands here
    from the https branch should find the site name in scope rather than wondering where the
    default came from.
    """
    problem = token_ref_problem(ref)
    if problem is not None:
        raise InitError(f"bearer reference: {problem}")
    del site  # the reference the operator typed wins; the site default applies only when absent
    if re.fullmatch(r"[A-Z][A-Z0-9_-]*", ref):
        return ref, None
    return None, ref


def device_code_explanation(device_code: str | None = None) -> str:
    """Why `device_code` exists, and why it is REQUIRED until the roster fix ships.

    The honest sentence, not a sales pitch: the hourly device-users roster names a device
    by `device_code` when the site declares one and by `serial` otherwise, and the
    serial -> code resolution on the ingest side is not finished — so when BC's Code is not
    the serial, declaring the code here is the difference between a roster that joins and a
    roster nobody can attribute.
    """
    named = f" Declaring `device_code = {device_code!r}` makes the roster name this device "
    return (
        "Business Central's device Code and the device's own SerialNumber are two different "
        "strings, and the hourly device-users roster uses whichever the site declares."
        + (named + "by BC's code instead of its serial." if device_code else "")
        + " Leave the key out only when BC really does use the serial "
        "(`gateclerk device info` prints the serial the box reported)."
    )


# --- step 5: the write ---------------------------------------------------------------------------


def build_site_block(site: cfg.SiteConfig, *, sink: Mapping[str, Any] | None = None) -> str:
    """The TOML text for one site: a header comment, then the `[[site]]` block.

    Every value is emitted through `_toml_value` — TOML's own quoting rules applied to a
    validated `SiteConfig` field — so there is no string interpolation of a raw answer
    anywhere in the write path. The keys emitted are exactly the non-default keys of the
    model: a line for something the operator did not choose would be a line nobody can
    audit.
    """
    lines: list[str] = [
        "# Written by `gateclerk init` — the non-secret half of one site's connection.",
        "# Hosts are config, not secrets; passwords never appear here (the resolver reads",
        "# them from the environment or the macOS Keychain; `gateclerk creds explain` shows",
        "# which rung would answer). Edit with `gateclerk sink add|remove` or by hand.",
        "",
        "[[site]]",
    ]
    # The five keys `sites.toml.example` shows uncommented are always emitted — including
    # the ones that happen to equal the default — because a written file an operator can
    # read without consulting the repo is the point of writing one: `keychain_service` and
    # `isapi_user` named on the page are what make `creds test`'s answer make sense. The
    # rest appear only when they differ from the default, so a line in this file is always
    # either a decision the operator made or a pointer at where a credential lives.
    emitted: list[tuple[str, object]] = [
        ("name", site.name),
        ("host", site.host),
        ("isapi_user", site.isapi_user),
        ("keychain_service", site.keychain_service),
    ]
    if site.iana_tz is not None:
        emitted.append(("iana_tz", site.iana_tz))
    if site.port != cfg.DEFAULT_PORT:
        emitted.append(("port", site.port))
    if site.device_tz is not None:
        emitted.append(("device_tz", site.device_tz))
    if site.timeout_s != cfg.DEFAULT_TIMEOUT_S:
        emitted.append(("timeout_s", site.timeout_s))
    if site.device_code is not None:
        emitted.append(("device_code", site.device_code))
    lines.extend(f"{key} = {_toml_value(value)}" for key, value in emitted)
    if sink is not None:
        lines.append("")
        lines.append("[[site.sink]]")
        lines.extend(f"{key} = {_toml_value(value)}" for key, value in sink.items())
    return "\n".join(lines) + "\n"


def _toml_value(value: object) -> str:
    """A validated model field as a TOML literal. Ints stay ints, everything else is quoted."""
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int):
        return str(value)
    if isinstance(value, float):
        return repr(value)
    text = str(value)
    return '"' + text.replace("\\", "\\\\").replace('"', '\\"') + '"'


def write_config_atomic(target: Path | str, text: str) -> Path:
    """Write `text` to `target` through temp + fsync + re-validate + rename. Returns `target`.

    Why every step is load-bearing (the same argument `sink_cli._install` makes for an
    already-deployed site, and this module is the one an operator meets FIRST):

    * temp file **in the target's directory** — `os.replace` is atomic only within one
      filesystem, and the target's parent is created first so `~/gateclerk/` on a fresh host
      works without a separate step;
    * **0600 on the temp file** — `os.replace` carries the temp file's mode onto the
      target, so a permissive umask would otherwise ship a group-readable config and the
      rename would silently keep it that way;
    * **fsync before the rename** — without it, a power cut can leave a renamed file whose
      bytes never landed;
    * **re-parse before the rename** — the file an agent unit starts with must already be
      one the config layer accepted, so an invalid body raises HERE and the target never
      appears;
    * **temp file cleaned up on every failure path** — a directory full of `.sites.toml.*`
      files is how an operator starts doubting which one is live.
    """
    path = Path(target)
    parent = path.parent
    parent.mkdir(parents=True, exist_ok=True)
    tmp = parent / f".{path.name}.gateclerk-tmp"
    try:
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        try:
            cfg.parse_sites(tmp.read_bytes(), origin=str(tmp))
        except ConfigError:
            raise
        os.replace(tmp, path)  # noqa: PTH105 — atomic rename IS the point
    except BaseException:
        tmp.unlink(missing_ok=True)
        raise
    return path


# --- reporting -----------------------------------------------------------------------------------


def render_next_steps(config_path: Path, site: str, *, sink: str | None = None) -> list[str]:
    """The lines printed after a successful write — what to run next, in order.

    Kept as data (a list of strings) rather than as console output so the machine form can
    print the same list it shows a human, and so `tests/test_cli_init.py` can assert the
    commands the card names without parsing prose.

    `doctor` is deliberately NOT one of them: `gateclerk doctor` is CLI-DOCTOR's surface
    (t_0c1cf9fd) and is not wired yet, and a next-steps block that tells a new user to run
    a command that exits 2 teaches them the tool is broken on their first day. `creds test`
    is the health check that exists today.
    """
    steps = [
        f"gateclerk creds test --config {config_path} --site {site}"
        "        # does the credential resolve, and from which rung",
        f"gateclerk device info --config {config_path} --site {site}"
        "         # read the box again and see model/serial/firmware",
    ]
    if sink is not None:
        steps.append(
            f"gateclerk sink test --config {config_path} --site {site} --name ingest --probe"
            "   # reach the sink once, with a benign empty batch"
        )
    steps.append(
        "gateclerk demo device serve"
        "                                   # no device handy? practise against a fake"
    )
    steps.append(
        f"gateclerk agent run --config {config_path} --site {site} --once"
        "          # one tick end-to-end (the deploy smoke test)"
    )
    return steps


# --- the CLI handler ------------------------------------------------------------------------------


init_app = typer.Typer(
    name="init",
    help=(
        "Guided first-site setup: pick the config location, probe the device through "
        "credential REFERENCES, choose where the data goes, then write sites.toml "
        "atomically. Prints names only — never a secret — and never overwrites an "
        "existing config without --force plus a backup copy."
    ),
    invoke_without_command=True,
    no_args_is_help=False,
    context_settings={"help_option_names": ["-h", "--help"]},
)

ConfigPathOpt = Annotated[
    str | None,
    typer.Option(
        "--config",
        help="Where sites.toml goes (default ~/gateclerk/sites.toml). An existing file is "
        "refused unless --force, which first copies it beside itself.",
    ),
]
StateRootOpt = Annotated[
    str | None,
    typer.Option(
        "--state-root",
        help="Put the config here instead (the directory is created). One writable "
        "directory per site is what `agent run --state-root` expects.",
    ),
]
YesOpt = Annotated[
    bool,
    typer.Option(
        "--yes",
        "-y",
        help="Do not ask for the final confirmation. The answers themselves are still "
        "asked for (nothing about payroll truth is defaulted), so this is the flag for a "
        "piped transcript, not for skipping the interview.",
    ),
]
ForceOpt = Annotated[
    bool,
    typer.Option(
        "--force",
        help="Replace an existing config. The bytes being replaced are copied beside the "
        "file first, and the copy is named in the output.",
    ),
]
CheckOnlyOpt = Annotated[
    bool,
    typer.Option(
        "--check-only",
        help="Walk every step, probe the device, print the plan — write nothing. The dry "
        "run to reach for when the existing config is precious.",
    ),
]


def _fail(fmt: OutputFormat, message: str, code: ExitCode) -> typer.Exit:
    """Print a refusal in the requested format and carry `code` out of the process.

    Same payload shape as `cli._error_payload` (`{"error", "exit_code"}` on one line for
    the machine forms, plain text otherwise) and the same numbers, imported from
    `cli_conventions` rather than re-declared. Markup is OFF because these messages name
    config keys like `[[site.sink]]`, which Rich would otherwise eat as a tag — the same
    reason `sink_cli` has its own printer.
    """
    if fmt is OutputFormat.JSON or fmt is OutputFormat.JSONL:
        render([{"error": message, "exit_code": int(code)}], fmt=fmt.value)
    else:
        make_console().print(f"error: {message}", markup=False)
    return typer.Exit(code=int(code))


def _classify(fmt: OutputFormat, exc: BaseException) -> typer.Exit:
    """Map any gateclerk error onto its documented exit code via the conventions module."""
    code = ExitCode(exit_code_for(exc))
    message = str(exc) or type(exc).__name__
    if code is ExitCode.AUTH_TERMINAL:
        message += (
            "\n  A 401 during setup is a credential problem, not a wiring problem: verify "
            "the password before the site goes live (the account locks)."
        )
    return _fail(fmt, message, code)


class _StdinAnswers:
    """Read the interview's answers from a stream, one line per question.

    EOF is `None`, not an abort: a scripted run that runs out of answers must exit 2 with a
    sentence naming the question it could not answer, not die in a Click `Abort` with exit 1
    and no explanation. The question itself is printed first so a human reading a log can
    tell which answer was missing.
    """

    def __init__(self, stream: Any = None, *, quiet: bool = False) -> None:
        self._stream = stream if stream is not None else sys.stdin
        self._quiet = quiet

    def ask(self, key: str, question: str, *, default: str | None = None) -> str | None:
        if not self._quiet:
            suffix = f" [{default}]" if default else ""
            make_console().print(f"{question}{suffix}: ", markup=False, end="")
        try:
            line = self._stream.readline()
        except Exception:  # pragma: no cover - a closed stream is a usage problem
            return None
        if not line:
            return None
        return line.strip()


@init_app.callback(invoke_without_command=True)
def init_command(
    config: ConfigPathOpt = None,
    state_root: StateRootOpt = None,
    yes: YesOpt = False,
    force: ForceOpt = False,
    check_only: CheckOnlyOpt = False,
    output: Annotated[
        OutputFormat,
        typer.Option(
            "--output",
            "-o",
            case_sensitive=False,
            help="Output format (table, json, jsonl). json frames the records; the "
            "interview questions still print, so pipe a transcript in rather than reading "
            "the machine form by eye.",
        ),
    ] = OutputFormat.TABLE,
) -> None:
    """Walk through creating the first site config: location, device probe, sink, then write.

    Five steps, each refusing before it writes anything (see this module's docstring for
    the laws). Nothing is guessed: the site name and the site timezone in particular have
    no defaults, because a defaulted payroll zone is a wrong payroll answer with a
    confident exit code.

    The device probe is read-only (`System/deviceInfo` plus the roster count) and its
    credential comes from the environment or the Keychain by REFERENCE — `init` never asks
    you to type a password, never writes one, and prints the exact
    `security add-generic-password` line to run if the item is missing. It never restarts
    anything: the last line it prints is the command you run next.
    """
    machine = output is OutputFormat.JSON or output is OutputFormat.JSONL
    console = make_console()
    target = _target_path(config=config, state_root=state_root)

    # Step 1 — refuse a clobber BEFORE the interview. Nobody should spend ten answers
    # discovering the file was there all along, and a refusal that comes before any I/O is
    # a refusal that provably touched nothing.
    if target.exists() and not force:
        raise _fail(
            output,
            _clobber_message(target, parseable=_config_parses(target)),
            ExitCode.USAGE_OR_CONFIG,
        )

    answers = _collect_answers(_StdinAnswers(quiet=machine))
    try:
        plan = plan_site(answers)
    except InitError as exc:
        raise _fail(output, str(exc), ExitCode.USAGE_OR_CONFIG) from exc
    except ConfigError as exc:
        raise _classify(output, exc) from exc

    # Step 2 — the credential, by reference only, then the probe.
    hint = credential_hint(
        plan.site.name,
        plan.site.host,
        user=plan.site.isapi_user,
        keychain_service=plan.site.keychain_service,
    )
    plan.credential_add_command = hint["add_command"]
    have_credential, why_not = credential_available(
        plan.site.host, keychain_service=plan.site.keychain_service
    )
    if not have_credential:
        raise _fail(
            output,
            _no_credential_message(hint, why_not),
            ExitCode.USAGE_OR_CONFIG,
        )

    if not machine:
        console.print(
            f"probing {plan.site.host}:{plan.site.port} (read-only: deviceInfo + roster count)",
            markup=False,
        )
    try:
        creds = cfg.resolve_credentials(
            cfg.DeviceTarget(
                host=plan.site.host,
                port=plan.site.port,
                site=plan.site.name,
                keychain_service=plan.site.keychain_service,
                config_user=plan.site.isapi_user,
            ),
            user=plan.site.isapi_user or None,
        )
        plan.probe = probe_device(
            host=plan.site.host,
            port=plan.site.port,
            user=creds.user,
            password=creds.password,
            timeout_s=plan.site.timeout_s,
            site=plan.site.name,
        )
    except (InitError, ConfigError, CredentialUnavailable, GateClerkError) as exc:
        raise _classify(output, exc) from exc
    except (ValueError, httpx.InvalidURL) as exc:
        # The pair `_client_for` catches for the same reason: httpx's InvalidURL is NOT a
        # ValueError subclass, so a host that survives our checks and dies in httpx's URL
        # layer would otherwise escape as an unclassified traceback with exit 1. It is a
        # config-class answer ("you told me how to reach it, and it is unusable"), so 2.
        raise _fail(output, str(exc), ExitCode.USAGE_OR_CONFIG) from exc

    # The confirmation the operator actually reads: what will be written, and why. The
    # answer is ALWAYS consumed, including under `--yes` — a piped transcript must be able
    # to decline, and a flag that silently discards an explicit "no" is a flag that writes
    # over someone's file.
    plan_text = plan.render()
    if not machine:
        _print_plan(console, plan, plan_text, target, check_only=check_only)
    confirmed = _confirm(_StdinAnswers(quiet=machine), assume_yes=yes)
    if not confirmed:
        if not machine:
            console.print("not written — nothing changed.", markup=False)
        render(
            [{"result": "not written", "config": str(target), "reason": "declined"}],
            fmt=output.value,
            columns=("result", "config", "reason"),
        )
        return

    if check_only:
        if not machine:
            console.print(
                "check-only: plan above validated; the file was not written.", markup=False
            )
        render(
            [
                {
                    "result": "not written",
                    "config": str(target),
                    "reason": "check-only",
                    "probe": plan.probe.as_row() if plan.probe is not None else None,
                }
            ],
            fmt=output.value,
        )
        return

    # `--force` on a live path is allowed only with the old bytes kept beside the file.
    backup: Path | None = None
    if force and target.exists():
        backup = _backup_copy(target)

    try:
        # Re-validate the rendered text with the REAL validator and re-check the site
        # landed, exactly as `sink add` does: the file that exists afterwards must be one
        # the agent can start from, and a plan that renders to something the parser
        # rejects is a bug this line turns into a refusal instead of a broken deployment.
        written = write_config_atomic(target, plan_text)
        parsed = cfg.load_sites(written, surface=cfg.ConfigSurface.AGENT)
        if plan.site.name not in parsed:
            raise ConfigError(
                f"{written} parses but carries no site {plan.site.name!r} — refusing to "
                "call a config that does not name its site a success."
            )
    except (ConfigError, OSError) as exc:
        raise _fail(output, f"could not write {target}: {exc}", ExitCode.USAGE_OR_CONFIG) from exc

    _report_success(console, output, plan, written=target, backup=backup)


def _target_path(*, config: str | None, state_root: str | None) -> Path:
    """Where the config goes: `--config`, else `--state-root`/sites.toml, else `~/gateclerk/`."""
    if config:
        return Path(config).expanduser()
    if state_root:
        return Path(state_root).expanduser() / cfg.DEFAULT_SITES_FILE
    return DEFAULT_STATE_DIR / cfg.DEFAULT_SITES_FILE


def _config_parses(target: Path) -> bool:
    """Whether an existing file is parseable config — for the refusal's wording only."""
    try:
        cfg.parse_sites(target.read_bytes())
    except (ConfigError, OSError):
        return False
    return True


def _clobber_message(target: Path, *, parseable: bool) -> str:
    """The refusal an operator can act on, naming the command that edits instead of replaces."""
    head = (
        f"{target} already exists, and `init` will not overwrite it."
        if parseable
        else f"{target} already exists and cannot be parsed, and `init` will not overwrite it."
    )
    if not parseable:
        head += (
            " A file that does not parse is still somebody's file — fix it by hand, or move "
            "it aside and re-run."
        )
    return (
        f"{head}\n"
        f"  to add or remove a sink on the existing site: gateclerk sink add / sink remove\n"
        f"  to add another site: edit {target} (see sites.toml.example in the repo)\n"
        f"  to replace it deliberately: re-run with --force (a backup copy is made first)\n"
        "  to see what `init` would write without writing it: --check-only"
    )


def _no_credential_message(hint: Mapping[str, str], why_not: str | None) -> str:
    """The install step nobody ran, spelled out as the line to run."""
    if why_not:
        return f"{_CRED_INTRO}\n    {hint['add_command']}\n  {why_not}"
    return (
        f"{_CRED_INTRO}\n"
        f"    {hint['add_command']}\n"
        f"  check it exists with: {hint['find_command']}\n"
        f"  (headless host? set {hint['env_password']} and, if the user is not "
        f"'{cfg.DEFAULT_ISAPI_USER}', {hint['env_user']} instead)"
    )


def _collect_answers(reader: _StdinAnswers) -> dict[str, str]:
    """Ask the interview. Every answer is a string; validation happens in `plan_site`.

    Defaults are offered only for things where a default is a FACT about this repo rather
    than about the site (the port is 80 because ISAPI lives on 80, 8000 is Hikvision's SDK
    port; the ISAPI user is `admin` because that is the keychain item's comment hint). The
    site name and the timezone get none: those are the two answers a wrong guess would
    make payroll wrong.
    """
    questions: list[tuple[str, str, str | None]] = [
        ("site", "Site name (the name `--site` and the systemd unit use)", None),
        ("host", "Device host or IP on the site LAN", None),
        ("port", "ISAPI port", str(cfg.DEFAULT_PORT)),
        (
            "user",
            "ISAPI user (the keychain item's comment can also carry it)",
            cfg.DEFAULT_ISAPI_USER,
        ),
        ("iana_tz", "Site timezone as an IANA zone (payroll truth — no default)", None),
        (
            "push",
            "Where punches go: none | https | csv | jsonl",
            "none",
        ),
        ("push_url", "Ingest URL (https://…) or, for csv/jsonl, the ABSOLUTE file path", ""),
        (
            "token_ref",
            "Bearer token REFERENCE — an env var NAME (GATECLERK_INGEST_TOKEN_…) or a "
            "keychain service (gateclerk-ingest-…). Not the token itself",
            "",
        ),
    ]
    collected: dict[str, str] = {}
    for key, question, default in questions:
        collected[key] = reader.ask(key, question, default=default) or ""

    serial_note = (
        "Business Central's device Code — is it DIFFERENT from the device Serial the probe "
        "just read?"
    )
    collected["codes_differ"] = (
        reader.ask("codes_differ", f"{serial_note} (yes/no)", default="no") or ""
    )
    collected["device_code"] = (
        reader.ask("device_code", "BC device Code (e.g. D-IF-1)", default="") or ""
    )
    return collected


def _confirm(reader: _StdinAnswers, *, assume_yes: bool = False) -> bool:
    """Read the final yes/no. The answer is always CONSUMED, even under `--yes`.

    Two bugs this shape avoids: a confirm line left unread on a piped transcript is a line
    a later reader mis-attributes to another question, and a `--yes` that short-circuits the
    read turns "the transcript said no" into "the file got written anyway". `assume_yes`
    only supplies the answer when the stream has run out of lines (EOF), which is the case
    `--yes` actually exists for.
    """
    value = (reader.ask("confirm", "write this config? (yes/no)", default="yes") or "").lower()
    if value.strip() in ("y", "yes", ""):
        return True
    return assume_yes and value.strip() == ""


def _print_plan(
    console: Any, plan: SitePlan, plan_text: str, target: Path, *, check_only: bool
) -> None:
    """Show the operator exactly what will land on disk, then why each choice was made."""
    console.print(f"\nconfig: {target}", markup=False)
    console.print(plan_text.rstrip(), markup=False)
    if plan.probe is not None:
        probe = plan.probe
        console.print(
            f"\ndevice: {probe.model or '?'} serial={probe.serial or '?'} "
            f"firmware={probe.firmware or '?'} enrolled_users="
            + (str(probe.user_count) if probe.user_count_known else "(not reported)")
            + (f" name={probe.device_name}" if probe.device_name else ""),
            markup=False,
        )
    if plan.code_explanation:
        console.print(f"\ndevice_code: {plan.code_explanation}", markup=False)
    else:
        console.print(
            "\ndevice_code: not written — you said BC's Code matches the serial. If the "
            "hourly roster ever arrives unattributed, that assumption is the first thing "
            "to re-check (`gateclerk device info` prints the serial).",
            markup=False,
        )
    add_line = (
        f"To add the keychain item: {plan.credential_add_command}"
        if plan.credential_add_command
        else ""
    )
    console.print(f"\ncredentials: never stored here. {add_line}", markup=False)
    if check_only:
        console.print("\n(--check-only: nothing will be written)", markup=False)


def _backup_copy(target: Path) -> Path:
    """Keep the bytes being replaced, beside the file, named after it.

    A timestamp in the name is what makes the operation safe to repeat: a second
    `--force` must not overwrite the copy of what the first `--force` replaced.
    """
    from datetime import UTC, datetime

    stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    backup = target.with_name(f"{target.name}.before-init-{stamp}.bak")
    backup.write_bytes(target.read_bytes())
    backup.chmod(0o600)
    return backup


def _report_success(
    console: Any,
    output: OutputFormat,
    plan: SitePlan,
    *,
    written: Path,
    backup: Path | None,
) -> None:
    """Print what was written (names only), the credential line, and the next steps."""
    row: dict[str, Any] = {
        "result": "written",
        "config": str(written),
        "site": plan.site.name,
        "host": plan.site.host,
        "iana_tz": plan.site.iana_tz,
        "sink": plan.sink_type or "none",
        "device_code": plan.site.device_code,
        "probe": plan.probe.as_row() if plan.probe is not None else None,
        "backup": str(backup) if backup else None,
        "credential_add": plan.credential_add_command,
        "next_steps": render_next_steps(written, plan.site.name, sink=plan.sink_type),
    }
    if output is OutputFormat.TABLE:
        console.print(f"\nwrote {written}", markup=False)
        if backup:
            console.print(f"backup of the replaced file: {backup}", markup=False)
        console.print(
            "\nthe config names these keys: "
            + ", ".join(
                key
                for key in ("name", "host", "port", "iana_tz", "device_code")
                if getattr(plan.site, key, None) not in (None, cfg.DEFAULT_PORT)
            ),
            markup=False,
        )
        console.print(f"credential (not in the file): {plan.credential_add_command}", markup=False)
        console.print("\nnext steps:", markup=False)
        for step in row["next_steps"]:
            console.print(f"  {step}", markup=False)
    render([row], fmt=output.value)
