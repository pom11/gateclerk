"""`gateclerk service install|uninstall|logs` — the unit-file half of deploy/, as a renderer.

What this module owns
---------------------
`deploy/` shipped the SHAPE of a working install (P2-07a): a systemd template unit and a
launchd plist, both rendered by hand with `sed` per `deploy/README.md` step 2. This module
is that substitution expressed once, in the shape every other deploy decision in this repo
already has (`gateclerk.config`): resolve → render → decide → print. It never loads, starts,
stops, boots out, kickstarts, enables or disables anything, and it never runs a service
manager — by test (see "the load is not this tool's").

The three verbs and the law each enforces
-----------------------------------------
``install``     render the unit for one site, write it into the right directory, print the
                exact load command. Writing the file is a file operation and is reversible
                (`uninstall` removes exactly it); loading it is the operator's decision. A
                tool that also loaded it would be a tool that could start a poller against
                a door controller by accident — the cutover law the whole P2 series holds.
``uninstall``   refuse to remove a unit file it cannot PROVE it wrote (the
                ``gateclerk-managed-by:`` marker), then print the unload command. A
                hand-rendered or package-owned unit is removed by its owner, per
                deploy/README.md step 8 — never by a tool that is guessing.
``logs``        compose the follow command for the platform (``tail -f`` on the plist's own
                ``StandardOutPath``/``StandardErrorPath``, ``journalctl --user -u``
                otherwise) and print it; ``--exec`` replaces this process with the composed
                argv so the operator gets a real follow with the tested flags.

The live-label refusal (macOS)
------------------------------
`deploy/gateclerk-agent.plist` and `deploy/README.md` step 6 both document the launchd job as
`com.gateclerk.agent.<site>.plist`. The operator's own dev-box agent already lives under that
exact pattern, so an install that quietly wrote a second plist for the same label would
leave launchd running whichever job it picked up first — a poller nobody reads the logs of.
`install` therefore REFUSES, before it touches anything, when a plist matching the live
label pattern sits in the target directory, unless `--label` names a label outside the
pattern. The refusal is about the FILE, and it fires even when nothing is loaded: a plist
that is merely unloaded today is loaded by the next reboot.

The load is not this tool's
---------------------------
Every successful path prints the exact command and stops:

    launchd   launchctl bootstrap gui/$UID ~/Library/LaunchAgents/com.gateclerk.agent.X.plist
    systemd   systemctl --user daemon-reload && systemctl --user enable --now gateclerk-agent@X

Nothing here calls a service manager. `gateclerk init` holds the same rule ("no subprocess in
this module, by test") and `tests/test_service_cli.py` reads this module's AST to prove it
here too. `logs --exec` is the one deliberate exception: it execs the follow command it just
printed (`tail`/`journalctl`) — never a service manager, and its own test pins that the
composed argv can only begin with those two names.

References, never values (unchanged from deploy/)
-------------------------------------------------
The rendered unit carries `LoadCredential=gateclerk-<site>-<host>:<credential dir>/….txt`; the
rendered plist carries the same reference NAMES plus the env-rung variable NAME. There is no
flag here that could carry a secret and no key in either template that could hold one:
launchd's `EnvironmentVariables` stays limited to `PYTHONUNBUFFERED` and `TZ`, the systemd
unit has no `Environment=`/`SetCredential=` line, and a value in either file would be
world-readable (unit files are) or session-readable (plists are).

Nothing is baked in
-------------------
`--python` / `--entrypoint` / `--config` / `--state-dir` / `--credentials-dir` / `--label`
resolve from arguments, and the credential references resolve from the site's own
`sites.toml` block through `gateclerk.config` (the loader the agent itself runs on, at the
same `surface=AGENT` strictness). Platform defaults are a LAYOUT under the caller's home or
`/var/lib`, never a specific person's home, and every render is checked for a leftover
`<TOKEN>` before it can be written: a half-rendered unit is a dead agent, and a dead agent
is silent punch loss.
"""

from __future__ import annotations

import os
import plistlib
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import Any

__all__ = [
    "DEFAULT_CREDENTIAL_DIR",
    "DROP_IN_SUFFIX",
    "FOLLOW_COMMANDS",
    "LINUX_STATE_ROOT",
    "MARKER_PREFIX",
    "PLATFORMS",
    "PLATFORM_LAUNCHD",
    "PLATFORM_SYSTEMD",
    "PLIST_LABEL_PREFIX",
    "PLIST_LABEL_TEMPLATE",
    "UNIT_TEMPLATE_STEM",
    "ExistingState",
    "Refusal",
    "ServiceCommand",
    "ServiceError",
    "ServicePaths",
    "ServicePlan",
    "ServiceSpec",
    "collect_existing",
    "credential_ref_lines",
    "default_config_path",
    "default_state_dir",
    "detect_platform",
    "follow_command",
    "load_commands",
    "plan_install",
    "plan_logs",
    "plan_uninstall",
    "plist_log_paths",
    "plist_payload",
    "read_marker",
    "render_plist",
    "render_unit",
    "service_paths",
    "status_query",
    "unit_file_name",
    "validate_spec",
]

#: The two platforms, spelled as `--platform` accepts them and as `-o json` reports them.
PLATFORM_LAUNCHD = "launchd"
PLATFORM_SYSTEMD = "systemd"
PLATFORMS: tuple[str, ...] = (PLATFORM_LAUNCHD, PLATFORM_SYSTEMD)

#: The provenance marker. A unit file WITHOUT it is not this tool's to remove, and the
#: refusal says so instead of quietly deleting somebody's install.
MARKER_PREFIX = "gateclerk-managed-by: gateclerk service install"

#: The live launchd label family, documented by `deploy/gateclerk-agent.plist` ("save as
#: com.gateclerk.agent.SITE_LABEL.plist") and `deploy/README.md` step 6. Any plist whose name
#: starts with this is operator territory as far as the refusal is concerned.
PLIST_LABEL_PREFIX = "com.gateclerk.agent."
PLIST_LABEL_TEMPLATE = PLIST_LABEL_PREFIX + "{label}"

#: The systemd template-unit convention of the committed template: the instance IS the site
#: name, so the per-site rendered file is named after the instance and `%i` still works.
UNIT_TEMPLATE_STEM = "gateclerk-agent@"
#: The drop-in directory `deploy/README.md` step 3a recommends for credentials. Its presence
#: is REPORTED (never read, never removed) so an operator removing a unit can see that a
#: credential drop-in is still on the box.
DROP_IN_SUFFIX = ".service.d"

#: Where the 0600 credential SOURCE files live on Linux (`deploy/README.md` step 1). A
#: NAME-shaped path, never a secret, and never created by this tool. `--credentials-dir`
#: overrides it.
DEFAULT_CREDENTIAL_DIR = "/etc/gateclerk/credentials"

#: The Linux state root `deploy/README.md` step 1 creates, used when the process is root.
LINUX_STATE_ROOT = "/var/lib/gateclerk"

#: The two programs `logs` may follow with. Nothing else may appear as argv[0], and the
#: CLI's `--exec` guard asserts exactly this set.
FOLLOW_TAIL = "tail"
FOLLOW_JOURNALCTL = "journalctl"
FOLLOW_COMMANDS: tuple[str, ...] = (FOLLOW_TAIL, FOLLOW_JOURNALCTL)

_REMAINING_TOKEN = re.compile(r"<[A-Z][A-Z0-9_]*>")
# MULTILINE is load-bearing: a unit file's marker is its FIRST line (the `#` form) but a
# plist's marker sits on the fourth (the XML declaration and DOCTYPE own the first two), so a
# `^` anchored at the whole string would read every plist as unmanaged.
_MARKER_LINE = re.compile(rf"^\s*(?:#\s*|<!--\s*)?{re.escape(MARKER_PREFIX)}", re.MULTILINE)
_SITE_IN_NAME = re.compile(r"^[a-z0-9][a-z0-9._-]*$")
_LABEL_IN_PLIST_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")
_METACHARACTER = re.compile(r"""["'`$\\]""")


class Refusal(StrEnum):
    """Every way this command says no. The value is the machine-readable code in `-o json`.

    An enum, not free strings: the CLI, the tests and the docs all have to name the same
    refusal, and a refusal whose kind drifts is a refusal a script cannot branch on.
    """

    LIVE_LABEL = "live_label_conflict"
    ALREADY_INSTALLED = "already_installed"
    NOT_MANAGED = "not_managed_by_gateclerk"
    MISSING = "unit_not_installed"
    BAD_VALUE = "bad_value"
    NO_LOG_DESTINATION = "no_log_destination"


#: One template per :class:`Refusal`, in the words an operator can act on. The CLI fills in
#: the specifics and the tests assert the KIND plus the named fields, not the prose.
REFUSALS: dict[Refusal, str] = {
    Refusal.LIVE_LABEL: (
        "{path} already exists and matches the live label pattern {pattern}. It is "
        "operator-owned, so this command will not overwrite it and will not touch the job. "
        "Load the existing file yourself (`launchctl bootstrap gui/$UID {path}`), render "
        "this site under another name with `--label NAME`, or move the file aside."
    ),
    Refusal.ALREADY_INSTALLED: (
        "{path} already exists{detail}. Nothing was written. `gateclerk service uninstall "
        "--site {site}` removes the unit this command installed; --force replaces it "
        "deliberately."
    ),
    Refusal.NOT_MANAGED: (
        "{path} carries no `{marker}` marker, so this command cannot prove it wrote the "
        "file. It was not removed. Hand-rendered and package-owned units go away the way "
        "deploy/README.md step 8 says, after this tool's unload command has run."
    ),
    Refusal.MISSING: (
        "no unit for site {site} at {path} — nothing to remove. `gateclerk service install "
        "--site {site}` writes one and prints the load command."
    ),
    Refusal.BAD_VALUE: "{problem}",
    Refusal.NO_LOG_DESTINATION: (
        "no log destination could be read from {path}: it is missing or is not a readable "
        "plist, so `logs` has nothing to follow. `launchctl print gui/$UID/{label}` shows "
        "the paths launchd is using."
    ),
}


class ServiceError(Exception):
    """A refusal the operator can act on. Exit 2 — the config/usage class — is its code.

    `kind` is the machine-readable name and `fields` is what the message was built from, so
    `-o json` can report a refusal structurally instead of asking a script to read prose.
    """

    def __init__(self, kind: Refusal, message: str, **fields: object) -> None:
        super().__init__(message)
        self.kind = kind
        self.fields: dict[str, object] = {"refusal": str(kind.value), **fields}


# --- platform -------------------------------------------------------------------------------


def detect_platform(sysname: str | None = None) -> str:
    """`launchd` on Darwin, `systemd` on Linux — the split `deploy/README.md` already draws.

    Accepts either an OS name (`Darwin`, `Linux`) or a platform token (`launchd`, `systemd`),
    because the caller is either this machine's `platform.system()` or the operator's
    `--platform` flag and both have to land on the same two answers. `sysname` is injectable
    (and read from `platform.system()` only when None) because CI is Linux and the developer
    box is Darwin: a test that cannot name the platform cannot pin either renderer. Anything
    else is refused rather than guessed — writing a plist on a Linux box, or a unit into
    `~/Library/LaunchAgents` on a Mac, is a file that never loads.
    """
    name = sysname
    if name is None:
        import platform

        name = platform.system()
    lowered = (name or "").strip().lower()
    if lowered in ("darwin", PLATFORM_LAUNCHD):
        return PLATFORM_LAUNCHD
    if lowered in ("linux", PLATFORM_SYSTEMD):
        return PLATFORM_SYSTEMD
    raise ServiceError(
        Refusal.BAD_VALUE,
        f"platform {name!r} is not supported by `gateclerk service`: macOS gets a launchd "
        "LaunchAgent, Linux gets a systemd user unit. Windows hosts run the same "
        "`agent run` command line from Task Scheduler (deploy/README.md step 6).",
        platform=name,
    )


# --- the spec -------------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class ServiceSpec:
    """Everything a unit file has to say, already resolved from arguments + sites.toml.

    Frozen because the renderers must not be able to edit their input: `plan_install`
    validates one of these and renders it, and the renderers take nothing else, so "what was
    validated" and "what was written" are the same object (the law `init_cli.SitePlan` states
    for sites.toml).

    There is deliberately no credential field: a secret has no place here because it has no
    place in either template.
    """

    site: str
    platform: str
    python: str
    entrypoint: str
    config: str
    state_dir: str
    credentials_dir: str = DEFAULT_CREDENTIAL_DIR
    hosts: tuple[str, ...] = ()
    #: launchd only: the job label. `None` means "the site name", which is exactly what puts
    #: the file name in the live label pattern — the refusal's trigger.
    label: str | None = None
    #: systemd only: write a system unit under /etc instead of a user unit under ~/.config.
    system_unit: bool = False

    @property
    def job_label(self) -> str:
        """The name this install is identified by on either platform."""
        return self.label or self.site


@dataclass(frozen=True, slots=True)
class ServicePaths:
    """Where the unit lives and what its load command names. Derived, never typed by hand."""

    unit_path: Path
    #: launchd: the plist's own stdout/stderr paths — the log destination `logs` follows.
    stdout_path: Path | None = None
    stderr_path: Path | None = None
    #: launchd: the job label launchd will know it by.
    label: str | None = None

    def as_row(self) -> dict[str, Any]:
        return {
            "unit_path": str(self.unit_path),
            "stdout_path": str(self.stdout_path) if self.stdout_path else None,
            "stderr_path": str(self.stderr_path) if self.stderr_path else None,
            "label": self.label,
        }


def validate_spec(spec: ServiceSpec) -> None:
    """Refuse anything that would render a unit that fails at ExecStart (exit 2 class).

    The checks are the ones a template cannot make for itself. A unit file has no quoting
    layer: `systemd` splits `ExecStart` on whitespace and refuses a unit whose path contains
    a shell metacharacter expansion it will not perform, so a path with a space or a quote in
    it must be turned down here instead of becoming a unit that silently starts something
    else. A relative path in a unit resolves against the service's own working directory
    (systemd) or `/` (launchd), which is never what the person who typed it meant.
    """
    problems: list[str] = []
    if spec.platform not in PLATFORMS:
        problems.append(f"platform {spec.platform!r} is unknown (choose {', '.join(PLATFORMS)})")
    if not _SITE_IN_NAME.match(spec.site):
        problems.append(
            f"site {spec.site!r} is not a valid unit instance name: lowercase letters, "
            "digits, dot, underscore and dash, and it must not start or end with a separator"
        )
    if not _LABEL_IN_PLIST_NAME.match(spec.job_label):
        problems.append(
            f"label {spec.job_label!r} is not usable as a launchd job label or file name "
            "component (letters, digits, dot, underscore, dash)"
        )
    for name, value in (
        ("--python", spec.python),
        ("--config", spec.config),
        ("--state-dir", spec.state_dir),
        ("--credentials-dir", spec.credentials_dir),
    ):
        problems.extend(_path_problem(name, value, allow_space=spec.platform == PLATFORM_LAUNCHD))
    problems.extend(_entrypoint_problem(spec.entrypoint))
    if spec.system_unit and spec.platform != PLATFORM_SYSTEMD:
        problems.append(
            "--system-unit is a systemd option; on macOS the job is a LaunchAgent in the "
            "user's own session"
        )
    for host in spec.hosts:
        if not host.strip():
            problems.append("a device host resolved to an empty string")
        elif _METACHARACTER.search(host) or " " in host:
            problems.append(f"device host {host!r} is not usable in a credential name")
    if problems:
        raise ServiceError(
            Refusal.BAD_VALUE,
            "; ".join(problems),
            problems=problems,
            site=spec.site,
        )


def _path_problem(name: str, value: str, *, allow_space: bool = False) -> list[str]:
    """One path flag's problems.

    `allow_space` is set for launchd only, and the reason is a real difference between the two
    file formats rather than a tolerance: a plist entry is one XML string and `plistlib`
    escapes it, so the macOS `Application Support` state dir this module defaults to — whose
    parent contains a space — is safe there. systemd's `ExecStart` splits on whitespace and
    quotes with backslashes, not shell quotes, so a space there would need quoting this
    renderer does not implement; refusing is the honest answer, and it names the platform.
    """
    if not value or not value.strip():
        return [f"{name} is empty"]
    if value.strip() != value:
        return [f"{name} has surrounding whitespace"]
    problems = []
    if not value.startswith("/"):
        problems.append(
            f"{name} must be an absolute path — a relative path in a unit file resolves "
            f"against the service's working directory, not yours: {value!r}"
        )
    if _METACHARACTER.search(value):
        # The offending value is deliberately NOT echoed: a path-shaped flag is still a flag
        # somebody might type a secret into, and a refusal that prints the value prints the
        # secret into the terminal, the log and `-o json`.
        problems.append(
            f"{name} contains a shell metacharacter, which neither a unit file nor a plist "
            "can quote; the rejected value is not shown here on purpose"
        )
    if " " in value and not allow_space:
        problems.append(
            f"{name} contains a space ({value!r}); systemd's ExecStart splits on whitespace "
            "and the quoting rules are systemd's own, so this command refuses rather than "
            "guess them (launchd plists have no such limit)"
        )
    return problems


def _entrypoint_problem(entrypoint: str) -> list[str]:
    """The entry point is one or more argv tokens (`-m gateclerk.cli`), so spaces are allowed —
    but only as single separators between plain tokens. Everything else the path check
    enforces, it enforces here too.
    """
    if not entrypoint or not entrypoint.strip():
        return ["--entrypoint is empty"]
    if entrypoint.strip() != entrypoint or "  " in entrypoint:
        return [
            f"--entrypoint {entrypoint!r} must be argv tokens separated by single spaces "
            "(e.g. `-m gateclerk.cli`)"
        ]
    if _METACHARACTER.search(entrypoint):
        return [
            f"--entrypoint {entrypoint!r} contains a shell metacharacter, which a unit file "
            "cannot quote"
        ]
    return []


def unit_file_name(spec: ServiceSpec) -> str:
    """The file name this spec writes, on its platform.

    launchd: `com.gateclerk.agent.<label>.plist` — the name both `deploy/README.md` step 6 and
    the committed plist's own header document, so a rendered install and a hand-rendered one
    agree on disk. systemd: `gateclerk-agent@<site>.service`, the instantiated form of the
    committed template's name, which is what keeps `%i` expanding to the site.
    """
    if spec.platform == PLATFORM_LAUNCHD:
        return PLIST_LABEL_TEMPLATE.format(label=spec.job_label) + ".plist"
    return f"{UNIT_TEMPLATE_STEM}{spec.site}.service"


def unit_directory(spec: ServiceSpec, *, home: Path | None = None) -> Path:
    """The platform's unit directory: where a LaunchAgent / user unit / system unit lives.

    Every default is a LAYOUT, not a person: `home` defaults to `Path.home()` at call time, so
    a test can hand in a tmp dir and nothing about a specific user is baked in. The systemd
    system path is `/etc/systemd/system` — the directory `deploy/README.md` step 2 renders
    into — and the user path is the documented `~/.config/systemd/system`.
    """
    root = Path.home() if home is None else Path(home)
    if spec.platform == PLATFORM_LAUNCHD:
        return root / "Library" / "LaunchAgents"
    if spec.system_unit:
        return Path("/etc/systemd/system")
    return root / ".config" / "systemd" / "system"


def service_paths(
    spec: ServiceSpec, *, home: Path | None = None, unit_dir: Path | None = None
) -> ServicePaths:
    """The unit path plus the log destinations, from the spec and platform conventions.

    `unit_dir` overrides the platform directory outright (the CLI's `--dir`), which is how a
    dry install into a scratch directory works and how `uninstall`/`logs` find a unit the
    operator keeps somewhere unusual. It pins the DIRECTORY only — the file name is still the
    platform's own, so a rendered install and a hand-rendered one agree on the name.
    """
    directory = unit_dir if unit_dir is not None else unit_directory(spec, home=home)
    path = directory / unit_file_name(spec)
    if spec.platform == PLATFORM_LAUNCHD:
        out, err = plist_log_paths(path)
        return ServicePaths(
            unit_path=path,
            stdout_path=out,
            stderr_path=err,
            label=PLIST_LABEL_TEMPLATE.format(label=spec.job_label),
        )
    return ServicePaths(unit_path=path)


def default_state_dir(platform: str, site: str, *, home: Path | None = None) -> str:
    """The per-site state dir when the operator did not pass `--state-dir`.

    Linux + root: `/var/lib/gateclerk/<site>` — the directory `deploy/README.md` step 1
    creates and the one the unit's `ReadWritePaths` may open. Linux + non-root: the XDG
    state location, because pointing a user unit at a root-owned directory guarantees a
    permission failure at the first write. macOS: `~/Library/Application Support/gateclerk/<site>`.
    No literal home appears in any of them.
    """
    root = Path.home() if home is None else Path(home)
    if platform == PLATFORM_LAUNCHD:
        return str(root / "Library" / "Application Support" / "gateclerk" / site)
    import os

    if getattr(os, "geteuid", lambda: 1)() == 0:
        return f"{LINUX_STATE_ROOT}/{site}"
    xdg = os.getenv("XDG_STATE_HOME")
    base = Path(xdg).expanduser() if xdg else root / ".local" / "state"
    return str(base / "gateclerk" / site)


def default_config_path(*, home: Path | None = None) -> str:
    """`~/gateclerk/sites.toml` — `init`'s write target, so `init` and `service install` agree
    without either importing the other. A layout default, overridable with `--config`.

    Reads the HOME *variable* (not `Path.home()`): this is a config-location guess for a human
    who passed no `--config`, and the test suite — and a wrapper that runs the CLI under
    another user — must be able to point it somewhere reproducible.
    """
    root = Path(os.getenv("HOME") or str(Path.home())) if home is None else Path(home)
    return str(root / "gateclerk" / "sites.toml")


# --- what the caller says is already on disk --------------------------------------------------


@dataclass(frozen=True, slots=True)
class ExistingState:
    """What the plans may assume about the filesystem, as data.

    `install`'s refusals are the whole value of the command, so they have to be testable
    without building a fake `~/Library/LaunchAgents`; and the CLI must not decide anything by
    a rule the tests do not exercise. Both are served by passing the state in: a mapping of
    file path -> bytes (None = absent) and directory -> names. Anything a caller leaves out
    falls back to reading the real path, so the CLI passes nothing and gets the truth.
    """

    files: Mapping[str, bytes | None] = field(default_factory=dict)
    directories: Mapping[str, Sequence[str]] = field(default_factory=dict)

    def file_at(self, path: Path) -> bytes | None:
        key = str(path)
        if key in self.files:
            return self.files[key]
        try:
            return path.read_bytes()
        except OSError:
            return None

    def names_in(self, directory: Path) -> list[str]:
        key = str(directory)
        if key in self.directories:
            return [str(name) for name in self.directories[key]]
        try:
            return sorted(p.name for p in directory.iterdir() if p.is_file())
        except OSError:
            return []


def collect_existing(paths: ServicePaths, *, spec: ServiceSpec) -> ExistingState:
    """Read the two things a plan needs from disk. Missing paths are not errors.

    Only the unit file and the LaunchAgents directory listing — the tool looks at nothing
    else, which is also the guarantee `logs`/`uninstall` print alongside their output.
    """
    files: dict[str, bytes | None] = {str(paths.unit_path): _read_or_none(paths.unit_path)}
    directories: dict[str, list[str]] = {}
    if spec.platform == PLATFORM_LAUNCHD:
        directory = paths.unit_path.parent
        directories[str(directory)] = [
            name for name in _listing(directory) if name.endswith(".plist")
        ]
    return ExistingState(files=files, directories=directories)


def _read_or_none(path: Path) -> bytes | None:
    try:
        return path.read_bytes()
    except OSError:
        return None


def _listing(directory: Path) -> list[str]:
    try:
        return sorted(p.name for p in directory.iterdir() if p.is_file())
    except OSError:
        return []


# --- rendering: systemd ----------------------------------------------------------------------


#: The directives of the committed `deploy/gateclerk-agent@.service`, with the prose that only a
#: committed template needs left behind. The token vocabulary (`<STATE_ROOT>`, `<CONFIG_PATH>`,
#: `<EXEC_START>`) and every policy value are the ones `tests/test_deploy_templates.py` pins
#: for the template: `Restart=always`, `RestartSec=5`, `TimeoutStopSec=30`, `KillSignal=
#: SIGTERM`, the hardening set, `[Install]`, and credential naming through
#: `config.credential_ref`.
#:
#: THREE deliberate differences from the template, all because this unit is a USER unit by
#: default:
#:
#:  1. `User=`/`Group=gateclerk` appear only in the system form. A `--user` manager cannot drop
#:     privileges, so `User=gateclerk` there is a start failure dressed as hardening.
#:  2. `ProtectHome=yes` and the strict `ReadWritePaths=<STATE_ROOT>/<SITE>` appear only in
#:     the system form. A user unit whose state dir IS `~/.local/state/gateclerk/<site>` would
#:     be shielded from the one directory it is allowed to write.
#:  3. `[Install] WantedBy` is `default.target` for a user unit (`multi-user.target` does not
#:     exist in a user manager, and `enable` needs a WantedBy).
#:
#: Also note the working directory: the template keeps `<STATE_ROOT>` as the PARENT and passes
#: `--state-root <STATE_ROOT>/<SITE>`. Here `state_dir` is already the per-site directory, so
#: `WorkingDirectory` and `--state-root` name the same place — which is what `deploy/README.md`
#: "Where the state files actually come from" says the agent needs (a relative `db_path`
#: resolves against the working directory).
UNIT_DIRECTIVES = """[Unit]
Description=gateclerk site agent for %i (read-only Hikvision attendance poller)
Documentation=https://github.com/pom11/gateclerk/blob/main/deploy/README.md
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
{identity}WorkingDirectory=<STATE_ROOT>
{exec_start}Restart=always
RestartSec=5
TimeoutStopSec=30
KillSignal=SIGTERM
{credentials}{hardening}RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
SystemCallArchitectures=native
UMask=0027
StandardOutput=journal
StandardError=journal
SyslogIdentifier=gateclerk-agent-%i

[Install]
WantedBy={wanted}
"""

#: The `ExecStart` line, split for the 100-column rule and joined here so the RENDERED bytes
#: stay one line (systemd's `ExecStart` is one directive; a real backslash continuation inside
#: the template string would survive into the unit file and change what systemd parses).
EXEC_START_LINE = (
    "ExecStart=<EXEC_START> <ENTRYPOINT> agent run --site %i"
    " --config <CONFIG_PATH> --state-root <STATE_ROOT>\n"
)

#: The hardening block the template declares, minus `ProtectSystem=strict` +
#: `ReadWritePaths` + `ProtectHome` (difference 2 above) — everything else is kept verbatim,
#: including `MemoryDenyWriteExecute` and `LockPersonality`, so a rendered user unit is not a
#: softer unit than the one the README documents.
USER_HARDENING = """NoNewPrivileges=yes
ProtectSystem=full
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
ProtectClock=yes
ProtectHostname=yes
RestrictSUIDSGID=yes
RestrictRealtime=yes
RestrictNamespaces=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
"""

#: Byte-for-byte the template's hardening pair plus the rest of its list: the system unit IS
#: the template's shape, so it keeps `ProtectSystem=strict` and the single writable path.
SYSTEM_HARDENING = """NoNewPrivileges=yes
ProtectSystem=strict
ReadWritePaths=<STATE_ROOT>
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
ProtectClock=yes
ProtectHostname=yes
RestrictSUIDSGID=yes
RestrictRealtime=yes
RestrictNamespaces=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
"""


def render_unit(spec: ServiceSpec, version: str, *, now: datetime | None = None) -> str:
    """The systemd unit text for one site: directives plus the provenance marker.

    The committed template's prose stays in the template (a rendered unit is read by
    `systemctl`, and `deploy/README.md` carries the explanation). What must survive is the
    marker — `uninstall` proves its own authorship with it — and the credential reference,
    which is the line that says where the secret is NOT.

    A leftover `<TOKEN>` raises: the template's own rule is that an un-substituted token
    should fail at `ExecStart` loudly rather than run a wrong agent, and a renderer that can
    emit one turns a typo into a dead poller.
    """
    block = credential_block(spec)
    if spec.system_unit:
        identity = "User=gateclerk\nGroup=gateclerk\n"
        hardening = SYSTEM_HARDENING
        wanted = "multi-user.target"
    else:
        identity = ""
        hardening = USER_HARDENING
        wanted = "default.target"
    body = UNIT_DIRECTIVES.format(
        identity=identity,
        hardening=hardening,
        wanted=wanted,
        credentials=block,
        exec_start=EXEC_START_LINE,
    )
    for token, value in {
        "<STATE_ROOT>": spec.state_dir,
        "<CONFIG_PATH>": spec.config,
        "<EXEC_START>": spec.python,
        "<ENTRYPOINT>": spec.entrypoint,
    }.items():
        body = body.replace(token, value)
    left = sorted(set(_REMAINING_TOKEN.findall(body)))
    if left:
        raise ServiceError(
            Refusal.BAD_VALUE,
            f"the unit renderer left {left} un-substituted for site {spec.site!r} — refusing "
            "to write a unit that would fail at ExecStart",
            tokens=left,
            site=spec.site,
        )
    stamp = _stamp(now)
    return (
        f"# {MARKER_PREFIX} {version}\n"
        f"# Site {spec.site}; rendered {stamp} from deploy/gateclerk-agent@.service.\n"
        "# Re-render (`gateclerk service install`) instead of editing this file.\n" + body
    )


def credential_block(spec: ServiceSpec) -> str:
    """The `LoadCredential=` lines, one per device of the site, references only.

    Empty string when no device resolved: a unit with no credential line is honest about
    having nothing to load (and the install note says so) whereas a line naming a host nobody
    configured would point at a file that does not exist and fail the unit at start.
    """
    lines = [
        f"LoadCredential={_credential_ref(spec.site, host)}"
        f":{spec.credentials_dir.rstrip('/')}/{_credential_ref(spec.site, host)}.txt"
        for host in spec.hosts
    ]
    if not lines:
        return ""
    header = (
        "# Credential REFERENCES, never values (deploy/README.md step 3). Each source file "
        "is\n# root-owned 0600; systemd exposes it under $CREDENTIALS_DIRECTORY.\n"
    )
    return header + "\n".join(lines) + "\n"


def _credential_ref(site: str, host: str) -> str:
    """`gateclerk.config.credential_ref` — the one naming helper, imported not restated.

    Imported lazily on purpose: `gateclerk.config` pulls in the credential resolver, and the
    renderers must stay importable (and testable) without it. The naming law is not duplicated
    here — `tests/test_deploy_templates.py` already pins the template's `gateclerk-<SITE>-<HOST>`
    to this same function.
    """
    from gateclerk.config import credential_ref

    return credential_ref(site, host)


# --- rendering: launchd ----------------------------------------------------------------------


def plist_payload(spec: ServiceSpec) -> dict[str, Any]:
    """The LaunchAgent dictionary: the committed example's keys, rendered for one site.

    A function returning a dict rather than a text template, because a plist is XML and
    hand-splicing paths into XML needs escaping rules this module should not own; `plistlib`
    is the stdlib's only correct writer, and the round-trip in :func:`render_plist` is what
    proves the render is loadable.

    Keys and values match `deploy/gateclerk-agent.plist` exactly — `Label`,
    `ProgramArguments`, `WorkingDirectory`, `KeepAlive{SuccessfulExit:false, Crashed:true}`,
    `ThrottleInterval: 5`, `EnvironmentVariables{PYTHONUNBUFFERED, TZ}`, `StandardOutPath`,
    `StandardErrorPath`, `ProcessType: Background`, `Nice: 10` — so the structural pins
    `tests/test_deploy_templates.py` holds for the example hold for a rendered job too. No
    `--once`: `KeepAlive` + `--once` is a five-second poll of a door controller.
    """
    state = spec.state_dir
    log_name = f"gateclerk-agent-{spec.job_label}"
    return {
        "Label": PLIST_LABEL_TEMPLATE.format(label=spec.job_label),
        "ProgramArguments": [
            spec.python,
            *spec.entrypoint.split(),
            "agent",
            "run",
            "--site",
            spec.site,
            "--config",
            spec.config,
            "--state-root",
            state,
        ],
        "WorkingDirectory": state,
        "KeepAlive": {"SuccessfulExit": False, "Crashed": True},
        "ThrottleInterval": 5,
        # Only non-secret environment, exactly as the committed example documents it: the
        # credential comes from the Keychain rung or the env rung the block below NAMES.
        "EnvironmentVariables": {"PYTHONUNBUFFERED": "1", "TZ": "UTC"},
        "StandardOutPath": f"{state}/logs/{log_name}.out.log",
        "StandardErrorPath": f"{state}/logs/{log_name}.err.log",
        "ProcessType": "Background",
        "Nice": 10,
    }


def credential_ref_lines(spec: ServiceSpec) -> list[str]:
    """The credential-reference block: NAMES only, one line per device of the site.

    The same content the committed plist carries between its `gateclerk-credential-refs`
    markers, rendered with the real host where the example says `HOST`: the
    `credential_ref` name and the env-rung variable NAME `gateclerk.config` derives from that
    host. No value, and no key in this output that could hold one.
    """
    from gateclerk.config import env_var_names

    lines: list[str] = []
    for host in spec.hosts:
        _, password_var, _, _ = env_var_names(host)
        lines.append(
            f"credential reference  {_credential_ref(spec.site, host)}   env rung {password_var}"
        )
    if not lines:
        lines.append(
            "credential reference  (no device resolved for this site — add the device to "
            "sites.toml and re-render)"
        )
    return lines


def render_plist(spec: ServiceSpec, version: str, *, now: datetime | None = None) -> str:
    """The LaunchAgent plist for one site: `plistlib`'s bytes plus the marker and refs comment.

    The credential block is spliced immediately above `EnvironmentVariables`, which is where
    the committed example puts it. The splice is asserted, not hoped for: if the anchor is not
    found exactly once, this raises rather than shipping a plist whose only credential
    documentation silently vanished (a comment that disappears without an error is the exact
    failure mode this repo has been bitten by once already).
    """
    payload = plist_payload(spec)
    dumped = plistlib.dumps(payload).decode("utf-8")
    # plistlib's first two lines are the XML declaration and the DOCTYPE, which the header
    # below re-emits (with the marker comments between them and the payload). Indentation is
    # plistlib's own (tabs), so the splice is done LINE-wise on the stripped key rather than
    # against a hard-coded indentation string — a renderer that silently failed to find its
    # anchor would otherwise ship a plist with no credential documentation at all.
    lines = dumped.splitlines()[2:]
    anchor = "<key>EnvironmentVariables</key>"
    indexes = [i for i, line in enumerate(lines) if line.strip() == anchor]
    if len(indexes) != 1:
        raise ServiceError(
            Refusal.BAD_VALUE,
            "the plist renderer could not find its EnvironmentVariables anchor exactly once "
            f"(found {len(indexes)}) — refusing to write a plist without its "
            "credential-reference block",
            site=spec.site,
        )
    at = indexes[0]
    indent = lines[at][: len(lines[at]) - len(lines[at].lstrip())]
    refs = "\n".join(f"       {line}" for line in credential_ref_lines(spec))
    comment = indent + (
        "<!-- gateclerk-credential-refs-begin\n"
        f"       Rendered for site {spec.site} on {_stamp(now)}. launchd has no\n"
        "       LoadCredential=, so this block names the reference and the env-rung variable\n"
        "       NAME and holds NO value: the value comes from the Keychain rung (preferred on\n"
        "       a dev box) or from a 0600 file that exports the env rung.\n"
        f"{refs}\n"
        "       gateclerk-credential-refs-end -->"
    )
    lines.insert(at, comment)
    body = "\n".join(lines) + "\n"
    header = (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" '
        '"http://www.apple.com/DTDs/PropertyList-1.0.dtd">\n'
        f"<!-- {MARKER_PREFIX} {version} -->\n"
        f"<!-- Site {spec.site}; rendered from deploy/gateclerk-agent.plist's keys. "
        "Re-render instead of editing. -->\n"
    )
    text = header + body
    parsed = plistlib.loads(text.encode("utf-8"))
    if not isinstance(parsed, dict) or parsed.get("Label") != payload["Label"]:
        raise ServiceError(
            Refusal.BAD_VALUE,
            "the rendered plist does not parse back to the label it was rendered for — "
            "refusing to write a job launchd would reject",
            site=spec.site,
        )
    if "gateclerk-credential-refs-end" not in text:
        raise ServiceError(  # pragma: no cover - belt for the splice above
            Refusal.BAD_VALUE,
            "the rendered plist lost its credential-reference block",
            site=spec.site,
        )
    return text


def plist_log_paths(plist_path: Path) -> tuple[Path | None, Path | None]:
    """Read (stdout, stderr) back out of a plist. `(None, None)` when missing or unreadable.

    Read from the FILE rather than recomputed, so `logs` follows the destination the job
    actually has — including when an operator edited the paths by hand. Best-effort by
    design: `logs` for a plist that does not exist yet must say so, not traceback.
    """
    try:
        payload = plistlib.loads(plist_path.read_bytes())
    except Exception:
        return (None, None)
    if not isinstance(payload, dict):
        return (None, None)
    out = payload.get("StandardOutPath")
    err = payload.get("StandardErrorPath")
    return (
        Path(out) if isinstance(out, str) and out else None,
        Path(err) if isinstance(err, str) and err else None,
    )


def _stamp(now: datetime | None) -> str:
    value = datetime.now(UTC) if now is None else now
    return value.isoformat(timespec="seconds")


# --- authorship proof ------------------------------------------------------------------------


def read_marker(unit_path: Path) -> str | None:
    """The `gateclerk-managed-by:` line this tool wrote, or None. Text only, no execution.

    One reader covers both platforms: a unit file is plain text and a plist marker is an XML
    comment, and both match the same pattern. Used by `uninstall` as its proof of authorship.
    """
    try:
        return _marker_in_text(unit_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError):
        return None


def _marker_in_text(text: str) -> str | None:
    for match in _MARKER_LINE.finditer(text):
        return match.group(0).strip()
    return None


def existing_plist_conflict(
    directory: Path,
    *,
    label: str,
    explicit_label: bool = False,
    names: Sequence[str] | None = None,
) -> Path | None:
    """The operator-owned plist that makes this install unsafe, or None.

    The rule is the card's literal words: a plist named `com.gateclerk.agent.*.plist` that is
    not provably ours makes this install refuse, and the only thing that lifts the refusal is
    an explicit `--label` (which writes beside the operator's file under its own name, never
    over it). "Provably ours" is the marker test, not the name test: a file that happens to
    carry OUR name but no `gateclerk-managed-by:` line was hand-rendered or package-shipped, and
    its owner is a human — so even a foreign plist named exactly like ours refuses, with the
    `--label` escape hatch still available (a new name avoids the clash entirely).

    It does not ask launchd whether anything is loaded: a file that is merely unloaded today
    is loaded by the next reboot. `names` lets a caller supply the listing (see
    :class:`ExistingState`) instead of a real directory read.
    """
    listing = names if names is not None else _listing(directory)
    ours = PLIST_LABEL_TEMPLATE.format(label=label) + ".plist"
    for name in sorted(listing):
        if not (name.startswith(PLIST_LABEL_PREFIX) and name.endswith(".plist")):
            continue
        if name == ours:
            try:
                text = (directory / name).read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            if _marker_in_text(text) is None:
                return directory / name  # our name, someone else's file
            continue  # our name and our marker: the already-installed check owns this case
        if not explicit_label:
            return directory / name
    return None


# --- the plan --------------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class ServiceCommand:
    """One command line this tool hands to the operator (or execs, for `logs --exec`).

    `argv` is the truth a test asserts on; `text` is what a human copies. Both are kept
    because a printed command that no test can inspect is a command that drifts from the one
    that was checked, and this one is the difference between "installed" and "running".
    """

    argv: tuple[str, ...]
    text: str
    #: Why the operator is being told to run this. Machine-readable; part of `-o json`.
    when: str = ""

    def as_row(self) -> dict[str, Any]:
        return {"command": self.text, "argv": list(self.argv), "when": self.when}


@dataclass(frozen=True, slots=True)
class ServicePlan:
    """The outcome of install / uninstall / logs: what changed, and what to run next."""

    action: str
    site: str
    platform: str
    paths: ServicePaths
    #: The spec this plan was built from, so a caller (the CLI's status block, a test) reads
    #: the resolved values off the plan instead of reverse-engineering them from the paths.
    spec: ServiceSpec | None = None
    wrote: bool = False
    removed: bool = False
    unit_text: str = ""
    commands: tuple[ServiceCommand, ...] = ()
    notes: tuple[str, ...] = ()
    refusal: str | None = None
    refusal_fields: Mapping[str, object] = field(default_factory=dict)
    #: `logs` only: the follow command this plan composed, exposed so `--exec` and the test
    #: read the same object the row was rendered from.
    follow: ServiceCommand | None = None

    def as_row(self) -> dict[str, Any]:
        row: dict[str, Any] = {
            "action": self.action,
            "site": self.site,
            "platform": self.platform,
            "wrote": self.wrote,
            "removed": self.removed,
            **self.paths.as_row(),
            "commands": [command.as_row() for command in self.commands],
            "notes": list(self.notes),
        }
        if self.follow is not None:
            row["follow"] = self.follow.as_row()
        if self.refusal:
            row["refusal"] = self.refusal
            row.update(self.refusal_fields)
        return row


def _command(*argv: str, when: str = "") -> ServiceCommand:
    return ServiceCommand(argv=tuple(argv), text=" ".join(argv), when=when)


def load_commands(spec: ServiceSpec, paths: ServicePaths) -> tuple[ServiceCommand, ...]:
    """THE load step — printed, never run. The cutover law lives in this function.

    launchd: `launchctl bootstrap gui/$UID <plist>`, the modern form. `launchctl load` is
    deprecated and takes no target, so the printed command is the one that still works after
    a macOS upgrade; `$UID` is left unexpanded on purpose so the operator's shell supplies the
    per-user GUI domain (the spelling `launchctl bootstrap` documents).
    systemd: `daemon-reload` then `enable --now`, the two commands `deploy/README.md` step 4
    runs, with `--user` unless the system-unit flag was given.
    """
    if spec.platform == PLATFORM_LAUNCHD:
        return (
            _command(
                "launchctl",
                "bootstrap",
                "gui/$UID",
                str(paths.unit_path),
                when="load the job — this command did NOT load it",
            ),
            _command(
                "launchctl",
                "print",
                "gui/$UID",
                str(paths.label),
                when="confirm the job is loaded and see its last exit status",
            ),
        )
    scope = () if spec.system_unit else ("--user",)
    unit = f"{UNIT_TEMPLATE_STEM}{spec.site}.service"
    return (
        _command("systemctl", *scope, "daemon-reload", when="make systemd read the new file"),
        _command(
            "systemctl",
            *scope,
            "enable",
            "--now",
            unit,
            when="start the unit now and on every boot",
        ),
    )


def uninstall_commands(spec: ServiceSpec) -> tuple[ServiceCommand, ...]:
    """THE unload step for a unit this tool installed. Printed, never run.

    `disable --now` first, so a running unit is stopped and its boot link removed before the
    file disappears; then `daemon-reload`, because systemd keeps a removed unit loaded in
    memory until it is told to forget it.
    """
    if spec.platform == PLATFORM_LAUNCHD:
        return (
            _command(
                "launchctl",
                "bootout",
                "gui/$UID",
                PLIST_LABEL_TEMPLATE.format(label=spec.job_label),
                when="unload the job — this command did NOT unload it",
            ),
        )
    scope = () if spec.system_unit else ("--user",)
    unit = f"{UNIT_TEMPLATE_STEM}{spec.site}.service"
    return (
        _command(
            "systemctl", *scope, "disable", "--now", unit, when="stop the unit and its boot link"
        ),
        _command("systemctl", *scope, "daemon-reload", when="forget the removed file"),
    )


def status_query(spec: ServiceSpec) -> ServiceCommand:
    """The command that answers "is it running, and with what status", per platform.

    Composed here and printed, never executed, so the offline suite never needs a service
    manager. `systemctl show -p` names the fields rather than grepping free text: those are
    the same four the README's step 5 checks, and `-o json` reports the command alongside the
    fields it would return so a script can run it and read `ActiveState` itself.
    """
    if spec.platform == PLATFORM_LAUNCHD:
        return _command(
            "launchctl",
            "print",
            "gui/$UID",
            PLIST_LABEL_TEMPLATE.format(label=spec.job_label),
            when="unit status: last exit code, PID, and the paths launchd is using",
        )
    scope = () if spec.system_unit else ("--user",)
    return _command(
        "systemctl",
        *scope,
        "show",
        f"{UNIT_TEMPLATE_STEM}{spec.site}.service",
        "-p",
        "ActiveState,SubState,MainPID,ExecMainStartTimestamp,ExecMainStatus",
        when="unit status fields (ActiveState, SubState, MainPID, start time, last status)",
    )


def follow_command(
    spec: ServiceSpec,
    paths: ServicePaths,
    *,
    since: str | None = None,
    lines: int = 50,
) -> ServiceCommand:
    """Compose the follow command. The argv composition is what its test pins.

    launchd has no journal, so the destination is the plist's own `StandardOutPath` plus
    `StandardErrorPath` — an alert page is a stderr line (P2-05's default sink), and following
    only stdout is how a parked site stays invisible. `--since` is a journalctl concept and has
    no `tail` equivalent, so the plan reports it as ignored instead of dropping it silently.

    systemd: `journalctl --user -u gateclerk-agent@<site> -n <lines> [-since …] -f`, with `--since`
    passed through verbatim — journalctl parses it, this tool does not, so a wrong value fails
    in journalctl's own words rather than in a local parser with a different grammar.
    """
    if spec.platform == PLATFORM_LAUNCHD:
        targets = [p for p in (paths.stdout_path, paths.stderr_path) if p is not None]
        argv: list[str] = [FOLLOW_TAIL, "-n", str(lines), "-f"]
        argv += [str(p) for p in targets]
        return _command(*argv, when="follow the job's own log files")
    scope = () if spec.system_unit else ("--user",)
    argv = [FOLLOW_JOURNALCTL, *scope, "-u", f"{UNIT_TEMPLATE_STEM}{spec.site}.service"]
    argv += ["-n", str(lines)]
    if since:
        argv += ["--since", since]
    argv.append("-f")
    return _command(*argv, when="follow journald for this unit")


# --- the plans -------------------------------------------------------------------------------


def plan_install(
    spec: ServiceSpec,
    version: str,
    *,
    home: Path | None = None,
    unit_dir: Path | None = None,
    force: bool = False,
    existing: ExistingState | None = None,
    now: datetime | None = None,
) -> ServicePlan:
    """Decide and render an install. Writes NOTHING — it returns what would be written.

    Refusal order is the order most useful to whoever typed it. The live-label conflict comes
    FIRST: it is the one that protects somebody else's file, and it must be checked before the
    same-site check, because an operator changing a label is exactly the case where both
    exist. Then the already-installed check, then the render. A refusal therefore provably
    touched nothing — no directory was created, no file was opened for writing.

    `unit_dir` pins the directory the unit is written to (the CLI's `--dir`); it must be
    absolute because the load command the plan prints names this path, and a relative one
    would only work from the directory it was written in.
    """
    validate_spec(spec)
    if unit_dir is not None and not str(unit_dir).startswith("/"):
        raise ServiceError(
            Refusal.BAD_VALUE,
            f"--dir {str(unit_dir)!r} is not an absolute path: the load command this "
            "command prints names the unit's full path, and a relative one would only work "
            "from the directory it was written in",
            site=spec.site,
        )
    paths = service_paths(spec, home=home, unit_dir=unit_dir)
    state = existing if existing is not None else collect_existing(paths, spec=spec)

    if spec.platform == PLATFORM_LAUNCHD:
        conflict = existing_plist_conflict(
            paths.unit_path.parent,
            label=spec.job_label,
            explicit_label=spec.label is not None,
            names=state.names_in(paths.unit_path.parent),
        )
        if conflict is not None:
            message = REFUSALS[Refusal.LIVE_LABEL].format(
                path=conflict, pattern=f"{PLIST_LABEL_PREFIX}*.plist"
            )
            raise ServiceError(Refusal.LIVE_LABEL, message, path=str(conflict), site=spec.site)

    current = state.file_at(paths.unit_path)
    marker = _marker_in_text(current.decode("utf-8", "replace")) if current is not None else None
    if current is not None and not force:
        detail = (
            f" and carries this tool's marker (`{marker}`)"
            if marker
            else " and carries no marker, so it is not this tool's"
        )
        message = REFUSALS[Refusal.ALREADY_INSTALLED].format(
            path=paths.unit_path, detail=detail, site=spec.site
        )
        raise ServiceError(
            Refusal.ALREADY_INSTALLED, message, path=str(paths.unit_path), site=spec.site
        )

    text = (
        render_plist(spec, version, now=now)
        if spec.platform == PLATFORM_LAUNCHD
        else render_unit(spec, version, now=now)
    )
    notes: list[str] = []
    if current is not None and force:
        notes.append(
            f"--force: replacing the {paths.unit_path} that was already there"
            + ("" if marker else " (it carried no gateclerk marker)").rstrip()
            + "."
        )
    if not spec.hosts:
        notes.append(
            "no device host was resolved from sites.toml, so the rendered unit carries no "
            "credential reference — `gateclerk creds test` shows what would resolve; add the "
            "device to the site block and re-render."
        )
    if spec.platform == PLATFORM_LAUNCHD:
        notes.append(
            "launchd has no LoadCredential=: the credential comes from the Keychain rung "
            "(preferred) or the env rung the rendered block names. Nothing here writes a "
            "secret into a plist."
        )
    else:
        notes.append(
            f"provision the 0600 credential source file(s) under {spec.credentials_dir} "
            "BEFORE loading (deploy/README.md step 3): starting without them parks the site "
            "on a terminal 401 and spends the device's lockout budget."
        )
    return ServicePlan(
        action="install",
        site=spec.site,
        platform=spec.platform,
        paths=paths,
        spec=spec,
        wrote=True,
        unit_text=text,
        commands=load_commands(spec, paths),
        notes=tuple(notes),
    )


def plan_uninstall(
    spec: ServiceSpec,
    *,
    home: Path | None = None,
    unit_dir: Path | None = None,
    existing: ExistingState | None = None,
) -> ServicePlan:
    """Decide an uninstall. Removes nothing the marker cannot prove this tool wrote.

    The marker is the whole law: a unit without it was hand-rendered per `deploy/README.md`
    step 2 or shipped by a package, and in both cases its owner is a human who should be the
    one to delete it. Refusing here costs nothing; deleting a live operator's unit does not
    come back.
    """
    validate_spec(spec)
    paths = service_paths(spec, home=home, unit_dir=unit_dir)
    state = existing if existing is not None else collect_existing(paths, spec=spec)
    current = state.file_at(paths.unit_path)
    if current is None:
        message = REFUSALS[Refusal.MISSING].format(site=spec.site, path=paths.unit_path)
        raise ServiceError(Refusal.MISSING, message, path=str(paths.unit_path), site=spec.site)
    marker = _marker_in_text(current.decode("utf-8", "replace"))
    if marker is None:
        message = REFUSALS[Refusal.NOT_MANAGED].format(path=paths.unit_path, marker=MARKER_PREFIX)
        raise ServiceError(Refusal.NOT_MANAGED, message, path=str(paths.unit_path), site=spec.site)
    notes = [f"marker found: {marker}"]
    # `DROP_IN_SUFFIX` attaches to the unit's STEMS (`gateclerk-agent@site-a` + `.service.d`),
    # the systemd convention deploy/README.md step 3a names — appending it to the full file
    # name would look for `...service.service.d`, a directory that can never exist, and the
    # note below would silently never fire.
    drop_in = paths.unit_path.with_name(paths.unit_path.stem + DROP_IN_SUFFIX)
    if drop_in.exists():
        notes.append(
            f"{drop_in} still exists and was NOT touched — it may carry a LoadCredential= "
            "drop-in (deploy/README.md step 3a). Remove it deliberately; the 0600 credential "
            "source files stay where they are."
        )
    return ServicePlan(
        action="uninstall",
        site=spec.site,
        platform=spec.platform,
        paths=paths,
        spec=spec,
        removed=True,
        commands=uninstall_commands(spec),
        notes=tuple(notes),
    )


def plan_logs(
    spec: ServiceSpec,
    *,
    home: Path | None = None,
    unit_dir: Path | None = None,
    existing: ExistingState | None = None,
    since: str | None = None,
    lines: int = 50,
) -> ServicePlan:
    """Compose the follow command and say what it will read. Runs nothing.

    launchd has no journal and `tail` has no start bound, so `--since` there is reported as
    ignored rather than dropped: a flag that silently does nothing is a flag that teaches an
    operator their tool lies.
    """
    validate_spec(spec)
    paths = service_paths(spec, home=home, unit_dir=unit_dir)
    state = existing if existing is not None else collect_existing(paths, spec=spec)
    notes: list[str] = []
    if spec.platform == PLATFORM_LAUNCHD:
        # The destination comes from the file that is actually there, because that is what
        # launchd is writing to (the operator may have edited the paths); `state` is consulted
        # first so a caller can supply the bytes without a real filesystem.
        stored_out, stored_err = _log_paths_from(state, paths.unit_path)
        if stored_out is None:
            message = REFUSALS[Refusal.NO_LOG_DESTINATION].format(
                path=paths.unit_path, label=paths.label
            )
            raise ServiceError(
                Refusal.NO_LOG_DESTINATION,
                message,
                path=str(paths.unit_path),
                site=spec.site,
            )
        out_path = stored_out
        paths = ServicePaths(
            unit_path=paths.unit_path,
            stdout_path=out_path,
            stderr_path=stored_err,
            label=paths.label,
        )
        if since:
            notes.append(
                f"--since {since!r} has no effect under launchd (`tail -f` has no start "
                "bound); on Linux the same flag reaches journalctl."
            )
        if not out_path.exists():
            notes.append(
                f"{out_path} does not exist yet: the job has not been loaded, or has "
                "not written a line. `gateclerk service install` prints the load command."
            )
    elif since:
        notes.append(f"--since {since!r} is passed to journalctl verbatim.")
    follow = follow_command(spec, paths, since=since, lines=lines)
    return ServicePlan(
        action="logs",
        site=spec.site,
        platform=spec.platform,
        paths=paths,
        spec=spec,
        commands=(follow,),
        notes=tuple(notes),
        follow=follow,
    )


def _log_paths_from(state: ExistingState, unit_path: Path) -> tuple[Path | None, Path | None]:
    """`plist_log_paths`, but reading through :class:`ExistingState` when it has the bytes."""
    data = state.file_at(unit_path)
    if data is None:
        return (None, None)
    try:
        payload = plistlib.loads(data)
    except Exception:
        return (None, None)
    if not isinstance(payload, dict):
        return (None, None)
    out = payload.get("StandardOutPath")
    err = payload.get("StandardErrorPath")
    return (
        Path(out) if isinstance(out, str) and out else None,
        Path(err) if isinstance(err, str) and err else None,
    )
