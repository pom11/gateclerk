"""The `gateclerk service` group: install|uninstall|logs for the site agent as a daemon.

CLI-SPLIT-STRUCTURE's pattern: this module declares the group and its handlers, and
`gateclerk.cli` attaches it with `service_cmds.register(app)` — one import and one call in
`cli.py`, nothing else. One-way import law: `gateclerk.cli` imports this module; this module
imports `gateclerk.cli_shared`, never `gateclerk.cli`.

All the DECISIONS live in `gateclerk.service_cli` (resolve → render → decide → print). This
module is the Click surface: turn flags into a `ServiceSpec`, ask the planner for a plan,
render it. That split is what lets `tests/test_service_cli.py` pin the live-label refusal,
the marker guard and the log-argv composition without a tmp home, a fake service manager, or
a monkeypatched `subprocess` — and it is why the two guards the card asked for
("never actually calling launchctl/systemctl in CI") are structural rather than hopeful.

The three laws the handlers exist to enforce
--------------------------------------------
1. **install never loads.** The plan writes the unit and prints
   `launchctl bootstrap gui/$UID …` / `systemctl --user daemon-reload && systemctl --user
   enable --now …`. It does not run them (docs/P2-SITE-AGENT.md cutover law: the operator
   decides when a poller starts against a live door controller).
2. **uninstall needs proof.** A unit without the `gateclerk-managed-by:` marker is refused;
   the handler prints the unload command and leaves the file alone.
3. **nothing here runs a service manager.** No `subprocess` import anywhere in this module
   or in `service_cli`. `logs --exec` is the one place a process is replaced — `os.execvp`
   with the argv the planner composed, and `_exec_follow` refuses any argv[0] that is not
   `tail` or `journalctl`. That function is the only `exec*` call in the group, by AST test.

Exit codes are `gateclerk.cli_conventions`' shipped contract: 2 for every refusal here
(`ServiceError.kind` names which), because all of them are "the operator has not told the
tool how to do this safely" — the same class as a config error, and the same number the live
launchd unit already branches on.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import Annotated, Any

import typer

from gateclerk import config as cfg
from gateclerk import service_cli as svc
from gateclerk.cli_conventions import CONFIG_ERROR_EXIT
from gateclerk.cli_shared import OutputOpt, _config_exit
from gateclerk.exceptions import ConfigError
from gateclerk.output import OutputFormat, make_console, render

__all__ = ["register", "service_app"]

#: The committed templates' own entry point, so a rendered unit runs exactly what
#: `deploy/gateclerk-agent@.service` and `deploy/gateclerk-agent.plist` document.
DEFAULT_ENTRYPOINT = "-m gateclerk.cli"

service_app = typer.Typer(
    name="service",
    help=(
        "The site agent as a service unit: render and write it (install), remove a unit this "
        "command wrote (uninstall), follow its logs. Renders deploy/'s templates for one "
        "site — and never loads, starts, stops or restarts anything. The load command is "
        "printed for you to run."
    ),
    no_args_is_help=True,
    context_settings={"help_option_names": ["-h", "--help"]},
)

# --- options -------------------------------------------------------------------------------

ServiceSiteOpt = Annotated[
    str,
    typer.Option("--site", help="Site block to serve (the systemd instance name, %i)."),
]
ServiceConfigOpt = Annotated[
    str | None,
    typer.Option(
        "--config",
        help="sites.toml to read (default ~/gateclerk/sites.toml, i.e. where `init` wrote it). "
        "Read with the agent's own strictness: the site must declare iana_tz. Refs only.",
    ),
]
ServicePythonOpt = Annotated[
    str | None,
    typer.Option(
        "--python",
        help="The python of the venv gateclerk was installed into (default: the python running "
        "this command). Absolute — a relative path in a unit file resolves against the "
        "service's working directory.",
    ),
]
ServiceEntrypointOpt = Annotated[
    str | None,
    typer.Option(
        "--entrypoint",
        help=f"argv after the python (default: {DEFAULT_ENTRYPOINT!r}, the form deploy/'s "
        "templates use). Space-separated tokens.",
    ),
]
ServiceStateDirOpt = Annotated[
    str | None,
    typer.Option(
        "--state-dir",
        help="This site's writable directory (store, park, launchd logs). Default is a "
        "per-site layout under the XDG/Application-Support state root, or "
        f"{svc.LINUX_STATE_ROOT}/<site> when running as root on Linux.",
    ),
]
ServiceDirOpt = Annotated[
    Path | None,
    typer.Option(
        "--dir",
        help="Write the unit here instead of the platform's unit directory "
        "(~/Library/LaunchAgents, ~/.config/systemd/system, or /etc/systemd/system with "
        "--system-unit). Also what uninstall and logs look at.",
    ),
]
ServiceLabelOpt = Annotated[
    str | None,
    typer.Option(
        "--label",
        help="launchd job label suffix (default: the site name, which lands the file in the "
        "live com.gateclerk.agent.<site>.plist pattern). Name something else to install "
        "alongside an existing dev-box agent.",
    ),
]
ServiceHostOpt = Annotated[
    list[str] | None,
    typer.Option(
        "--host",
        help="Device host to write credential references for (repeatable). Default: the "
        "site's host in sites.toml. A host is config, never a secret.",
    ),
]
ServiceCredentialsDirOpt = Annotated[
    str | None,
    typer.Option(
        "--credentials-dir",
        help=f"Where the 0600 credential source files live (default "
        f"{svc.DEFAULT_CREDENTIAL_DIR}, deploy/README.md step 1). systemd only.",
    ),
]
ServiceSystemUnitOpt = Annotated[
    bool,
    typer.Option(
        "--system-unit",
        help="Write a system unit under /etc/systemd/system (needs root to write, and keeps "
        "User=gateclerk/Group=gateclerk like the committed template) instead of a user unit.",
    ),
]
ServicePlatformOpt = Annotated[
    str,
    typer.Option(
        "--platform",
        help="Target platform: `auto` (this machine), `launchd` (macOS LaunchAgent) or "
        "`systemd` (Linux user unit). Lets you render the other platform's file from here.",
    ),
]
ServiceForceOpt = Annotated[
    bool,
    typer.Option(
        "--force",
        help="install only: replace an existing unit file. Never bypasses the live-label "
        "refusal, and never bypasses the marker requirement on uninstall.",
    ),
]
ServiceDryRunOpt = Annotated[
    bool,
    typer.Option(
        "--dry-run",
        help="install only: render and print the unit text, write nothing. The pre-flight "
        "that `deploy/README.md` asks for (`systemd-run` proves the render on the box).",
    ),
]
ServiceSinceOpt = Annotated[
    str | None,
    typer.Option(
        "--since",
        help="logs: journalctl `--since` value (e.g. '1 hour ago', '2026-11-04 08:00'), "
        "passed through verbatim. No effect under launchd, which is reported, not hidden.",
    ),
]
ServiceLinesOpt = Annotated[
    int,
    typer.Option("--lines", min=1, help="logs: how many lines to show before following."),
]
ServiceExecOpt = Annotated[
    bool,
    typer.Option(
        "--exec",
        help="logs: replace this process with the composed `tail -f` / `journalctl -f` "
        "command instead of printing it. Only ever those two programs.",
    ),
]


# --- handlers -------------------------------------------------------------------------------


@service_app.command("install")
def service_install(
    site: ServiceSiteOpt,
    config: ServiceConfigOpt = None,
    python: ServicePythonOpt = None,
    entrypoint: ServiceEntrypointOpt = None,
    state_dir: ServiceStateDirOpt = None,
    dir: ServiceDirOpt = None,
    label: ServiceLabelOpt = None,
    host: ServiceHostOpt = None,
    credentials_dir: ServiceCredentialsDirOpt = None,
    system_unit: ServiceSystemUnitOpt = False,
    platform: ServicePlatformOpt = "auto",
    force: ServiceForceOpt = False,
    dry_run: ServiceDryRunOpt = False,
    output: OutputOpt = OutputFormat.TABLE,
) -> None:
    """Render the unit for one site, write it, and PRINT the load command. Never loads it.

    Resolves the python, entry point, config and state dir from the flags (no home is baked
    in), reads the site's device host from `sites.toml` for the credential references, then
    writes the rendered file into the platform's unit directory. The load step stays yours:
    `launchctl bootstrap gui/$UID …` on macOS, `systemctl --user daemon-reload && systemctl
    --user enable --now …` on Linux — printed, in order, and run by nobody here.

    Refuses (exit 2, nothing touched) when a launchd plist matching the live
    `com.gateclerk.agent.*.plist` pattern already sits in the target directory, when the unit
    file already exists without `--force`, or when a flag would render a unit that cannot
    start.
    """
    plan = _install_plan(
        site=site,
        config=config,
        python=python,
        entrypoint=entrypoint,
        state_dir=state_dir,
        directory=dir,
        label=label,
        hosts=host,
        credentials_dir=credentials_dir,
        system_unit=system_unit,
        platform=platform,
        force=force,
        output=output,
    )
    if dry_run:
        _print_unit(plan)
    else:
        _write_unit(plan)
    _report(plan, output, wrote=not dry_run)


@service_app.command("uninstall")
def service_uninstall(
    site: ServiceSiteOpt,
    config: ServiceConfigOpt = None,
    dir: ServiceDirOpt = None,
    label: ServiceLabelOpt = None,
    system_unit: ServiceSystemUnitOpt = False,
    platform: ServicePlatformOpt = "auto",
    output: OutputOpt = OutputFormat.TABLE,
) -> None:
    """Remove a unit file THIS command wrote, and print the unload command. Never unloads it.

    Proof first: the file must carry the `gateclerk-managed-by:` marker this tool writes. A
    unit without it — hand-rendered with `sed`, or shipped by a package — is refused with
    exit 2 and left exactly where it is, because removing somebody else's live unit is not a
    side effect a naming guess should be able to cause. The file's absence is also a refusal
    (exit 2), naming the path it looked at.

    Order matters for the operator: run the printed `launchctl bootout` / `systemctl --user
    disable --now` FIRST, then re-run this to remove the file, then `daemon-reload`.
    """
    spec = _spec(
        site=site,
        config=config,
        python=None,
        entrypoint=None,
        state_dir=None,
        directory=dir,
        label=label,
        hosts=None,
        credentials_dir=None,
        system_unit=system_unit,
        platform=platform,
        output=output,
    )
    plan = _plan(lambda: svc.plan_uninstall(spec, **_home_kw(dir)), output, site=site)
    _remove_unit(plan)
    _report(plan, output, wrote=False)


@service_app.command("logs")
def service_logs(
    site: ServiceSiteOpt,
    config: ServiceConfigOpt = None,
    dir: ServiceDirOpt = None,
    label: ServiceLabelOpt = None,
    system_unit: ServiceSystemUnitOpt = False,
    platform: ServicePlatformOpt = "auto",
    since: ServiceSinceOpt = None,
    lines: ServiceLinesOpt = 50,
    execute: ServiceExecOpt = False,
    output: OutputOpt = OutputFormat.TABLE,
) -> None:
    """Follow the agent's logs: `tail -f` the plist's own files, or `journalctl --user -u`.

    The destination is read from the installed file when there is one, so an operator who
    edited `StandardOutPath` follows what launchd is really writing. A missing plist (launchd)
    is a refusal with the load command attached rather than an exec of a `tail` that would
    fail. `--since` reaches journalctl verbatim and is reported as a no-op under launchd.

    `--exec` replaces this process with the composed argv — `tail` or `journalctl`, nothing
    else; the guard in `_exec_follow` refuses any other program, so no flag here can reach a
    service manager.
    """
    spec = _spec(
        site=site,
        config=config,
        python=None,
        entrypoint=None,
        state_dir=None,
        directory=dir,
        label=label,
        hosts=None,
        credentials_dir=None,
        system_unit=system_unit,
        platform=platform,
        output=output,
    )
    plan = _plan(
        lambda: svc.plan_logs(spec, since=since, lines=lines, **_home_kw(dir)),
        output,
        site=site,
    )
    if execute:
        _exec_follow(plan)  # only returns if exec failed, which it cannot get past
    _report(plan, output, wrote=False)


# --- spec + plan plumbing ---------------------------------------------------------------------


def _spec(
    *,
    site: str,
    config: str | None,
    python: str | None,
    entrypoint: str | None,
    state_dir: str | None,
    directory: Path | None,
    label: str | None,
    hosts: list[str] | None,
    credentials_dir: str | None,
    system_unit: bool,
    platform: str,
    output: OutputFormat,
) -> svc.ServiceSpec:
    """Flags + sites.toml → a validated `ServiceSpec`. Every refusal here is exit 2.

    The site is read at the AGENT surface — the same strictness the process this unit starts
    will use — so a site that cannot run its own agent never gets a unit written for it.
    """
    target_platform = _platform(platform, output)
    resolved_config = config or svc.default_config_path()
    resolved_hosts = tuple(h.strip() for h in (hosts or ()) if h and h.strip())
    if not resolved_hosts:
        resolved_hosts = _site_host(resolved_config, site, output)
    resolved_state = state_dir or svc.default_state_dir(target_platform, site)
    return svc.ServiceSpec(
        site=site,
        platform=target_platform,
        python=python or sys.executable,
        entrypoint=entrypoint or DEFAULT_ENTRYPOINT,
        config=resolved_config,
        state_dir=resolved_state,
        credentials_dir=credentials_dir or svc.DEFAULT_CREDENTIAL_DIR,
        hosts=resolved_hosts,
        label=label,
        system_unit=system_unit,
    )


def _platform(requested: str, output: OutputFormat) -> str:
    try:
        return svc.detect_platform(None if requested in ("", "auto") else requested)
    except svc.ServiceError as exc:
        raise _config_exit(output, str(exc)) from exc


def _site_host(config_path: str, site: str, output: OutputFormat) -> tuple[str, ...]:
    """The site's device host, for credential references. Names only, never a credential.

    surface=AGENT on purpose (see the docstring above). A site the agent would refuse is a
    site this command must not write a unit for, and the refusal is the config layer's own
    sentence, not a paraphrase of it.
    """
    try:
        target = cfg.site_from_args(
            site=site, config_path=config_path, surface=cfg.ConfigSurface.AGENT
        )
    except ConfigError as exc:
        raise _config_exit(
            output,
            f"{exc} (a unit is only written for a site the agent itself would start; "
            "pass --host NAME to name the device without a sites.toml entry)",
        ) from exc
    return (target.host,)


def _install_plan(
    *,
    site: str,
    config: str | None,
    python: str | None,
    entrypoint: str | None,
    state_dir: str | None,
    directory: Path | None,
    label: str | None,
    hosts: list[str] | None,
    credentials_dir: str | None,
    system_unit: bool,
    platform: str,
    force: bool,
    output: OutputFormat,
) -> svc.ServicePlan:
    spec = _spec(
        site=site,
        config=config,
        python=python,
        entrypoint=entrypoint,
        state_dir=state_dir,
        directory=directory,
        label=label,
        hosts=hosts,
        credentials_dir=credentials_dir,
        system_unit=system_unit,
        platform=platform,
        output=output,
    )
    version = _version()
    return _plan(
        lambda: svc.plan_install(spec, version, force=force, **_home_kw(directory)),
        output,
        site=site,
    )


def _home_kw(directory: Path | None) -> dict[str, Any]:
    """The `unit_dir=` pin for `--dir`. Absolute-ness is checked by the planner.

    `home=` stays the seam for the *defaults* (a test hands in a tmp home and the platform
    layout resolves under it); `--dir` is a different thing — it names the unit directory
    outright, which is what an operator typing `--dir /tmp/x` means.
    """
    if directory is not None:
        return {"unit_dir": Path(directory).expanduser()}
    return {}


def _plan(body: Any, output: OutputFormat, *, site: str) -> svc.ServicePlan:
    """Run a planner call, turning `ServiceError` into the documented exit 2.

    `ServiceError` is not a `GateclerkError`, so `_Guard` would re-raise it as an unclassified
    bug — deliberately: a refusal in this group is its own class of thing, and the machine
    form gets the refusal `kind` as a field instead of a paraphrased message.
    """
    try:
        return body()
    except svc.ServiceError as exc:
        if output is OutputFormat.JSON or output is OutputFormat.JSONL:
            render(
                [
                    {
                        "error": str(exc),
                        "exit_code": CONFIG_ERROR_EXIT,
                        **exc.fields,
                        "site": site,
                    }
                ],
                fmt=output.value,
            )
        else:
            make_console().print(f"error: {exc}", markup=False)
        raise typer.Exit(code=CONFIG_ERROR_EXIT) from exc
    except ConfigError as exc:
        raise _config_exit(output, str(exc)) from exc


def _version() -> str:
    from gateclerk import __version__

    return __version__


# --- the four file/process operations the handlers are allowed -------------------------------


def _write_unit(plan: svc.ServicePlan) -> None:
    """temp file + fsync + re-read + rename, then chmod. The `init_cli` write law, applied.

    Atomic because a half-written unit is a unit `systemctl` loads anyway (it parses what it
    can see), and a unit with a truncated `ExecStart` is an agent that does not run. The
    re-read check is what makes the rename safe: the bytes on disk must still carry the marker
    and the credential block the renderer produced.
    """
    path = plan.paths.unit_path
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.parent / f".{path.name}.gateclerk-tmp"
    try:
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(plan.unit_text)
            handle.flush()
            os.fsync(handle.fileno())
        written = tmp.read_text(encoding="utf-8")
        if svc.read_marker(tmp) is None or written != plan.unit_text:
            raise svc.ServiceError(
                svc.Refusal.BAD_VALUE,
                f"{path} did not round-trip the rendered unit (marker missing or bytes "
                "differ) — nothing was installed",
                path=str(path),
            )
        os.replace(tmp, path)  # noqa: PTH105 — atomic rename IS the point
    except BaseException:
        tmp.unlink(missing_ok=True)
        raise


def _remove_unit(plan: svc.ServicePlan) -> None:
    """Remove the file the plan already proved this tool wrote. Nothing else is deleted.

    The credential source files, the state dir, the sqlite store and any `*.service.d` drop-in
    are never touched: they are the operator's data and the park is on disk on purpose
    (docs/P2-SITE-AGENT.md — an unacked park must survive an uninstall, not vanish with the
    unit that started the process that made it).
    """
    plan.paths.unit_path.unlink(missing_ok=True)


def _exec_follow(plan: svc.ServicePlan) -> None:
    """Replace this process with the follow command the planner composed. Guarded by argv[0].

    The guard is the whole reason this is allowed to exist in a command group that never runs
    a service manager: whatever the flags said, the program can only be `tail` or
    `journalctl`, and it is the argv the plan already printed — not a string rebuilt here.
    `execvp` (not `subprocess`) because a follow should BE the command: ^C ends the follow and
    nothing is left behind, and no second process has to be reaped by the caller's shell.
    """
    follow = plan.follow
    if follow is None:  # pragma: no cover - plan_logs always sets it
        raise svc.ServiceError(
            svc.Refusal.BAD_VALUE, "no follow command was composed", site=plan.site
        )
    program = follow.argv[0] if follow.argv else ""
    if program not in svc.FOLLOW_COMMANDS:
        raise svc.ServiceError(
            svc.Refusal.BAD_VALUE,
            f"refusing to run {program!r}: `gateclerk service logs --exec` only ever execs "
            f"{', '.join(svc.FOLLOW_COMMANDS)}",
            site=plan.site,
        )
    os.execvp(program, list(follow.argv))  # noqa: S606 — argv[0] is pinned to FOLLOW_COMMANDS
    raise svc.ServiceError(  # pragma: no cover - execvp does not return
        svc.Refusal.BAD_VALUE,
        f"could not start {program}",
        site=plan.site,
    )


def _print_unit(plan: svc.ServicePlan) -> None:
    make_console().print(plan.unit_text, markup=False)


# --- reporting -------------------------------------------------------------------------------


def _report(plan: svc.ServicePlan, output: OutputFormat, *, wrote: bool) -> None:
    """Print the outcome, then the next commands, then (machine forms) the status block.

    Two renderings on purpose. `-o table` gets the human block — the path, the notes, and the
    commands with a `#` reason each, which is the part an operator actually reads and copies.
    `-o json`/`-o jsonl` get the whole plan as one row: paths, commands as argv arrays, notes,
    the refusal kind when this was a refusal, and the status block. The row's nested values are
    why the human path does not go through `render()`: a table of argv arrays is unreadable, and
    the commands are already printed one per line above.
    """
    row = plan.as_row()
    row["wrote"] = wrote
    row["status"] = _status_row(plan)
    if output is OutputFormat.TABLE:
        console = make_console()
        head = {
            "install": "wrote" if wrote else "would write",
            "uninstall": "removed",
            "logs": "follow",
        }[plan.action]
        console.print(
            f"{head}: {plan.paths.unit_path}"
            if plan.action != "logs"
            else f"logs for {plan.site} ({plan.platform})",
            markup=False,
        )
        for note in plan.notes:
            console.print(f"  note: {note}", markup=False)
        console.print("", markup=False)
        for command in plan.commands:
            console.print(f"  {command.text}", markup=False)
            console.print(f"      # {command.when}", markup=False)
        if plan.action != "logs":
            console.print(
                "  # nothing above was run — the load/unload step is the operator's "
                "(deploy/README.md step 4 / step 8)",
                markup=False,
            )
        return
    render([row], fmt=output.value)


def _status_row(plan: svc.ServicePlan) -> dict[str, Any]:
    """The status block: the command that answers "is it running", plus what only this tool knows.

    `unit_file_present` is the one status field this command can answer for itself. Whether
    the manager thinks the unit is ACTIVE is not this tool's knowledge — asking it would mean
    running `launchctl`/`systemctl`, which the whole group refuses to do — so the JSON form
    hands over the query command and the field names it returns instead of a made-up value.
    """
    spec = plan.spec
    if spec is None:  # pragma: no cover - every planner sets it
        spec = svc.ServiceSpec(
            site=plan.site,
            platform=plan.platform,
            python=sys.executable,
            entrypoint=DEFAULT_ENTRYPOINT,
            config=svc.default_config_path(),
            state_dir=svc.default_state_dir(plan.platform, plan.site),
            label=plan.paths.label.replace(svc.PLIST_LABEL_PREFIX, "")
            if plan.paths.label
            else None,
        )
    query = svc.status_query(spec)
    return {
        "query_command": query.text,
        "query_argv": list(query.argv),
        "fields": _status_fields(plan.platform),
        "unit_file_present": plan.paths.unit_path.is_file(),
    }


def _status_fields(platform: str) -> tuple[str, ...]:
    if platform == svc.PLATFORM_LAUNCHD:
        return ("state", "pid", "last exit code", "throttle", "paths")
    return (
        "ActiveState",
        "SubState",
        "MainPID",
        "ExecMainStartTimestamp",
        "ExecMainStatus",
    )


def register(app: typer.Typer) -> None:
    """Attach the `service` group to the root app.

    Called by `gateclerk.cli` AFTER every existing group is registered, so the `--help` order of
    the surface the fleet already shipped is byte-preserved and `service` is appended.
    """
    app.add_typer(service_app)
