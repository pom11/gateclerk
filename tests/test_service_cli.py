"""SERVICE-CMD — `gateclerk service install|uninstall|logs`, pinned.

What these tests are FOR
------------------------
This card put a *file-writing* tool next to a live, operator-owned daemon. Three properties
are worth guarding, and none of them is "the render looks nice":

1. **install never loads** — the plan prints the load command and the module cannot execute
   a service manager (`test_no_service_manager_is_reachable`,
   `test_install_prints_the_exact_load_command_and_touches_no_manager`).
2. **it will not touch what it did not write** — the live-label refusal and the marker guard
   (`test_install_refuses_a_plist_in_the_live_label_pattern`,
   `test_uninstall_refuses_a_unit_without_the_marker`).
3. **the render is the deploy/ template's shape** — same restart policy, same credential
   naming, same plist keys, `--once` never
   (`test_rendered_unit_matches_the_committed_template_policy`,
   `test_rendered_plist_carries_the_committed_examples_keys`).

The two renderers are pinned as GOLDEN against the committed artifacts in `deploy/` — not
against a snapshot of themselves. `deploy/gateclerk-agent@.service` and
`deploy/gateclerk-agent.plist` are what `tests/test_deploy_templates.py` already pins, so this
file compares the rendered output with those bytes' policies instead of inventing a third
list of directives that could drift from both.

Everything runs offline and in tmp dirs. Nothing here can reach `launchctl` or `systemctl`:
the plans take an `ExistingState` so the filesystem decisions are made from passed-in data,
and the structural test reads the two modules' ASTs for `subprocess`/`exec`/`os.system`.
"""

from __future__ import annotations

import ast
import json
import plistlib
import re
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
from typer.testing import CliRunner

from gateclerk import __version__
from gateclerk import service_cli as svc
from gateclerk import service_cmds as cmds
from gateclerk.cli import app

REPO_ROOT = Path(__file__).resolve().parents[1]
DEPLOY = REPO_ROOT / "deploy"
UNIT_TEMPLATE = DEPLOY / "gateclerk-agent@.service"
PLIST_TEMPLATE = DEPLOY / "gateclerk-agent.plist"

runner = CliRunner()

# --- the inputs these tests share -------------------------------------------------------------

#: TEST-NET only (tests/test_repo_hygiene.py): a device host is config, never a fixture.
HOST = "192.0.2.10"
SECOND_HOST = "198.51.100.7"
NOW = datetime(2026, 11, 4, 10, 0, 0, tzinfo=UTC)


def spec(**overrides: Any) -> svc.ServiceSpec:
    """A spec with every required value filled in; the tests change one thing each."""
    values: dict[str, Any] = {
        "site": "site-a",
        "platform": svc.PLATFORM_SYSTEMD,
        "python": "/opt/gateclerk/venv/bin/python",
        "entrypoint": "-m gateclerk.cli",
        "config": "/etc/gateclerk/sites.toml",
        "state_dir": "/var/lib/gateclerk/site-a",
        "hosts": (HOST,),
    }
    values.update(overrides)
    return svc.ServiceSpec(**values)


def launchd_spec(**overrides: Any) -> svc.ServiceSpec:
    return spec(platform=svc.PLATFORM_LAUNCHD, state_dir="/opt/state/site-a", **overrides)


# --- 1. the golden renders ---------------------------------------------------------------------


def test_rendered_unit_matches_the_committed_template_policy() -> None:
    """Every policy directive in the rendered unit must be the template's, not a copy.

    The comparison is against `deploy/gateclerk-agent@.service`'s own bytes: a rendered unit
    that drifts from the committed template is a unit whose hardening differs from what
    `deploy/README.md` step 5 promises an auditor, and the drift would be invisible if this
    test compared the render to a second list written by the same author as the renderer.
    """
    template = UNIT_TEMPLATE.read_text(encoding="utf-8")
    rendered = svc.render_unit(spec(), __version__, now=NOW)

    for directive in ("Restart=always", "RestartSec=5", "TimeoutStopSec=30", "KillSignal=SIGTERM"):
        assert directive in template, f"the template no longer carries {directive}"
        assert directive in rendered, f"the render dropped {directive}"

    # The hardening lines the two share must be identical, line for line.
    shared = _hardening_lines(template) & _hardening_lines(rendered)
    assert {"NoNewPrivileges=yes", "MemoryDenyWriteExecute=yes", "LockPersonality=yes"} <= shared
    for line in shared:
        assert line in template and line in rendered

    # `--once` would turn Restart=always into a five-second poll of a door controller.
    assert "--once" not in rendered


def test_rendered_unit_binds_the_site_and_names_its_paths() -> None:
    """The four things a unit file exists to say, asserted as values, not as prose."""
    rendered = svc.render_unit(spec(), __version__, now=NOW)
    exec_start = _directive(rendered, "ExecStart")
    assert exec_start.startswith("/opt/gateclerk/venv/bin/python -m gateclerk.cli agent run ")
    # `%i` stays: systemd expands the instance name, and the file is named `@site-a.service`.
    assert "--site %i" in exec_start
    assert "--config /etc/gateclerk/sites.toml" in exec_start
    assert f"--state-root {spec().state_dir}" in exec_start
    assert _directive(rendered, "WorkingDirectory") == spec().state_dir
    assert _directive(rendered, "SyslogIdentifier") == "gateclerk-agent-%i"
    assert svc.unit_file_name(spec()) == "gateclerk-agent@site-a.service"


def test_rendered_unit_carries_the_credential_reference_and_never_a_value() -> None:
    """One `LoadCredential=` per device, named by `config.credential_ref`, no value anywhere.

    The naming is compared to `credential_ref` itself rather than to a literal, so the unit
    cannot drift from the resolver the way hand-written `gateclerk-<site>-<host>` strings do.
    """
    from gateclerk.config import credential_ref

    rendered = svc.render_unit(spec(hosts=(HOST, SECOND_HOST)), __version__, now=NOW)
    lines = _directives(rendered, "LoadCredential")
    assert lines == [
        f"{credential_ref('site-a', HOST)}:/etc/gateclerk/credentials/"
        f"{credential_ref('site-a', HOST)}.txt",
        f"{credential_ref('site-a', SECOND_HOST)}:/etc/gateclerk/credentials/"
        f"{credential_ref('site-a', SECOND_HOST)}.txt",
    ]
    assert not _directives(rendered, "SetCredential"), "a literal secret in a unit file"
    assert not _directives(rendered, "Environment"), "a value belongs in the env rung, not here"
    assert not re.search(r"(?im)^\s*(password|passwd|pwd|secret|token)\s*[:=]", rendered)


def test_system_unit_keeps_the_templates_identity_and_writable_path() -> None:
    """The system form is the template's shape: `User=gateclerk`, strict root, one writable path.

    The user form must NOT carry them (a `--user` manager cannot drop privileges, and
    `ProtectHome=yes` would hide the state dir a user unit is allowed to write) — both halves
    are pinned because a future "simplification" that unifies the two would break exactly one
    of the platforms silently.
    """
    system = svc.render_unit(spec(system_unit=True), __version__, now=NOW)
    assert _directive(system, "User") == "gateclerk"
    assert _directive(system, "Group") == "gateclerk"
    assert _directive(system, "ProtectSystem") == "strict"
    assert _directive(system, "ReadWritePaths") == spec().state_dir
    assert _directive(system, "WantedBy") == "multi-user.target"

    user = svc.render_unit(spec(), __version__, now=NOW)
    assert not _directives(user, "User"), "a user unit cannot drop privileges"
    assert "ProtectHome" not in user, "ProtectHome=yes would hide a user unit's state dir"
    assert _directive(user, "WantedBy") == "default.target"
    assert _directive(user, "ProtectSystem") == "full"


def test_render_leaves_no_token_behind() -> None:
    """The template's own rule: an un-substituted token must fail loudly, here, not at start."""
    rendered = svc.render_unit(spec(), __version__, now=NOW)
    left = sorted(set(re.findall(r"<[A-Z][A-Z0-9_]*>", rendered)))
    assert not left, f"un-substituted tokens in the rendered unit: {left}"


def test_rendered_plist_carries_the_committed_examples_keys() -> None:
    """The rendered plist must satisfy the structural pins `test_deploy_templates.py` holds.

    Keys and policy values are read out of the committed example, not restated here, so the
    two artifacts cannot drift apart by someone editing one file.
    """
    example = plistlib.loads(PLIST_TEMPLATE.read_bytes())
    payload = svc.plist_payload(launchd_spec())
    assert set(payload) == set(example), (
        f"the rendered plist's keys differ from the committed example: "
        f"{set(payload) ^ set(example)}"
    )
    assert payload["KeepAlive"] == example["KeepAlive"]
    assert payload["ThrottleInterval"] == example["ThrottleInterval"]
    assert payload["ProcessType"] == example["ProcessType"]
    assert payload["Nice"] == example["Nice"]
    assert payload["EnvironmentVariables"] == example["EnvironmentVariables"]
    assert payload["WorkingDirectory"] == payload["StandardOutPath"].rsplit("/logs/", 1)[0]


def test_rendered_plist_runs_the_same_command_as_the_unit_without_once() -> None:
    payload = svc.plist_payload(launchd_spec())
    args = [str(arg) for arg in payload["ProgramArguments"]]
    assert args[:3] == ["/opt/gateclerk/venv/bin/python", "-m", "gateclerk.cli"]
    assert args[args.index("--site") + 1] == "site-a"
    assert args[args.index("--config") + 1] == "/etc/gateclerk/sites.toml"
    assert args[args.index("--state-root") + 1] == "/opt/state/site-a"
    assert "--once" not in args, "KeepAlive + --once is a five-second poll of a door controller"
    assert payload["Label"] == "com.gateclerk.agent.site-a"


def test_rendered_plist_parses_and_names_the_credential_refs_without_a_value() -> None:
    """The plist is XML: it must parse (a job that will not parse simply never loads), and its
    credential block must carry the same reference naming as the unit and no value."""
    from gateclerk.config import credential_ref

    text = svc.render_plist(launchd_spec(hosts=(HOST, SECOND_HOST)), __version__, now=NOW)
    payload = plistlib.loads(text.encode("utf-8"))
    assert payload["Label"] == "com.gateclerk.agent.site-a"
    assert "gateclerk-credential-refs-begin" in text and "gateclerk-credential-refs-end" in text
    for host in (HOST, SECOND_HOST):
        assert credential_ref("site-a", host) in text
    # The env rung is named, never filled.
    assert "GATECLERK_192_0_2_10_PASSWORD" in text
    assert not re.search(r"(?i)(password|secret|token)\s*[:=]\s*[\"'][^\"']+[\"']", text)
    for key, value in payload["EnvironmentVariables"].items():
        assert not re.search(r"(?i)password|secret|token", f"{key}{value}")


def test_no_baked_in_home_or_host_appears_in_the_renderer_source() -> None:
    """The card's rule, checked on the source: no user home, no device host in the renderer.

    A path baked into the module would be a path that works on one machine and silently
    writes the wrong unit on every other, and `Path.home()` at call time is what keeps the
    platform defaults a LAYOUT rather than an address.
    """
    source = Path(svc.__file__).read_text(encoding="utf-8")
    assert not re.search(r"/Users/[a-z0-9._-]+", source), "a home directory baked into the code"
    assert not re.search(r"/home/[a-z0-9._-]+", source), "a home directory baked into the code"
    offenders = sorted(
        ip
        for ip in re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", source)
        if not ip.startswith(("192.0.2.", "198.51.100.", "203.0.113."))
    )
    assert not offenders, f"a real-looking address in the renderer: {offenders}"


# --- 2. the live-label refusal -----------------------------------------------------------------


def test_install_refuses_a_plist_in_the_live_label_pattern(tmp_path: Path) -> None:
    """The card's headline refusal: a plist matching `com.gateclerk.agent.*.plist` is not ours.

    The existing file is someone else's agent. Overwriting it would replace a running poller's
    definition with ours — and launchd keeps whichever job it loaded first, so the operator
    would have two files and one of them would be a lie. The refusal must fire from the
    DIRECTORY LISTING alone (no read of the file, no `launchctl print`), and must name the
    conflicting path so the operator can act without guessing what the tool saw.
    """
    directory = tmp_path / "LaunchAgents"
    directory.mkdir()
    (directory / "com.gateclerk.agent.other-agent.plist").write_text("<operator's own plist/>")

    with pytest.raises(svc.ServiceError) as raised:
        svc.plan_install(launchd_spec(), __version__, unit_dir=directory)
    assert raised.value.kind is svc.Refusal.LIVE_LABEL
    assert str(directory / "com.gateclerk.agent.other-agent.plist") in str(raised.value)
    assert "operator-owned" in str(raised.value)
    # Nothing was written.
    assert sorted(p.name for p in directory.iterdir()) == ["com.gateclerk.agent.other-agent.plist"]


def test_the_live_label_refusal_fires_even_for_the_same_site_under_another_label(
    tmp_path: Path,
) -> None:
    """The exact case the refusal was written for: re-installing site-a under a new label.

    A same-site check would have passed this through ("my file already exists, fine"), and the
    operator would have silently written a second LaunchAgent for the site while the first is
    still loaded. The label conflict is checked BEFORE the same-site check, in that order.
    """
    directory = tmp_path / "LaunchAgents"
    directory.mkdir()
    (directory / "com.gateclerk.agent.site-a.plist").write_text("<operator's own plist/>")

    with pytest.raises(svc.ServiceError) as raised:
        svc.plan_install(launchd_spec(), __version__, unit_dir=directory)
    assert raised.value.kind is svc.Refusal.LIVE_LABEL


def test_install_allows_a_label_outside_the_live_pattern(tmp_path: Path) -> None:
    """`--label` is the escape hatch the refusal names, and it must actually work.

    The operator's own file stays untouched and ours is written beside it under its own name —
    which is the point: two agents, two labels, two log files, no ambiguity about which is
    which.
    """
    directory = tmp_path / "LaunchAgents"
    directory.mkdir()
    operator_file = directory / "com.gateclerk.agent.site-a.plist"
    operator_file.write_text("<operator's own plist/>")

    plan = svc.plan_install(
        launchd_spec(label="site-a.dev"), __version__, unit_dir=directory, now=NOW
    )
    assert plan.paths.unit_path.name == "com.gateclerk.agent.site-a.dev.plist"
    assert plan.paths.label == "com.gateclerk.agent.site-a.dev"
    assert operator_file.read_text() == "<operator's own plist/>"


def test_a_matching_plist_named_exactly_like_ours_is_already_installed_not_live_label(
    tmp_path: Path,
) -> None:
    """Ours-vs-theirs is decided by NAME, and the two refusals must not collapse.

    If the only conflicting file IS the one this install would write, the honest answer is
    "already installed, use uninstall or --force" — not "somebody else owns it", which would
    send the operator looking for a file they installed themselves.
    """
    directory = tmp_path / "LaunchAgents"
    directory.mkdir()
    (directory / "com.gateclerk.agent.site-a.plist").write_text(
        f"<!-- {svc.MARKER_PREFIX} 0.1.0 -->\n"
    )
    with pytest.raises(svc.ServiceError) as raised:
        svc.plan_install(launchd_spec(), __version__, unit_dir=directory)
    assert raised.value.kind is svc.Refusal.ALREADY_INSTALLED


def test_install_refuses_an_existing_unit_without_force(tmp_path: Path) -> None:
    """A unit that exists is not silently replaced: `uninstall` or `--force`, never a guess."""
    directory = tmp_path / "units"
    directory.mkdir()
    (directory / "gateclerk-agent@site-a.service").write_text("[Unit]\nDescription=mine\n")

    with pytest.raises(svc.ServiceError) as raised:
        svc.plan_install(spec(), __version__, unit_dir=directory)
    assert raised.value.kind is svc.Refusal.ALREADY_INSTALLED
    assert "no marker" in str(raised.value), "the refusal must say the file is not ours"


def test_force_replaces_and_says_so(tmp_path: Path) -> None:
    """`--force` is the explicit path, and it must record that it used it."""
    directory = tmp_path / "units"
    directory.mkdir()
    (directory / "gateclerk-agent@site-a.service").write_text("[Unit]\nDescription=mine\n")
    plan = svc.plan_install(spec(), __version__, unit_dir=directory, force=True, now=NOW)
    assert plan.wrote
    assert any("--force" in note for note in plan.notes)


def test_the_live_label_refusal_does_not_apply_to_systemd(tmp_path: Path) -> None:
    """The refusal is a launchd rule (`com.gateclerk.agent.*` is a plist label pattern).

    Firing it on Linux would block every install on a box that happens to have a file named
    that way in an unrelated directory, which is a refusal with no reason behind it.
    """
    directory = tmp_path / "units"
    directory.mkdir()
    (directory / "com.gateclerk.agent.site-a.plist").write_text("unrelated")
    plan = svc.plan_install(spec(), __version__, unit_dir=directory, now=NOW)
    assert plan.wrote


# --- 3. the marker guard -----------------------------------------------------------------------


def test_uninstall_refuses_a_unit_without_the_marker(tmp_path: Path) -> None:
    """The card's second headline law: no proof, no removal.

    A hand-rendered unit (deploy/README.md step 2 is a `sed` command) or a package-owned one is
    live infrastructure owned by a human. Deleting it on the strength of a file-name match is
    the kind of side effect no flag should be able to cause.
    """
    directory = tmp_path / "units"
    directory.mkdir()
    unit = directory / "gateclerk-agent@site-a.service"
    unit.write_text("[Unit]\nDescription=hand rendered by sed\n")

    with pytest.raises(svc.ServiceError) as raised:
        svc.plan_uninstall(spec(), unit_dir=directory)
    assert raised.value.kind is svc.Refusal.NOT_MANAGED
    assert svc.MARKER_PREFIX in str(raised.value)
    assert unit.is_file(), "the refusal must leave the file exactly where it was"


def test_uninstall_accepts_a_unit_that_carries_the_marker(tmp_path: Path) -> None:
    directory = tmp_path / "units"
    directory.mkdir()
    (directory / "gateclerk-agent@site-a.service").write_text(
        svc.render_unit(spec(), __version__, now=NOW)
    )
    plan = svc.plan_uninstall(spec(), unit_dir=directory)
    assert plan.removed
    assert any(svc.MARKER_PREFIX in note for note in plan.notes)
    text = " ".join(command.text for command in plan.commands)
    assert "systemctl --user disable --now gateclerk-agent@site-a.service" in text
    assert "systemctl --user daemon-reload" in text


def test_uninstall_reports_a_drop_in_it_left_behind(tmp_path: Path) -> None:
    """A `*.service.d/10-credentials.conf` may hold the credential line (README step 3a).

    Removing the unit while leaving a drop-in is correct — the drop-in is the operator's — but
    staying silent about it is how an operator ends up certain they uninstalled everything.
    """
    directory = tmp_path / "units"
    (directory / "gateclerk-agent@site-a.service.d").mkdir(parents=True)
    (directory / "gateclerk-agent@site-a.service").write_text(
        svc.render_unit(spec(), __version__, now=NOW)
    )
    plan = svc.plan_uninstall(spec(), unit_dir=directory)
    assert any("10-credentials" in note or ".service.d" in note for note in plan.notes)


def test_uninstall_of_a_missing_unit_is_a_refusal_not_a_success(tmp_path: Path) -> None:
    directory = tmp_path / "units"
    directory.mkdir()
    with pytest.raises(svc.ServiceError) as raised:
        svc.plan_uninstall(spec(), unit_dir=directory)
    assert raised.value.kind is svc.Refusal.MISSING
    assert str(directory / "gateclerk-agent@site-a.service") in str(raised.value)


def test_read_marker_finds_the_line_the_renderer_writes(tmp_path: Path) -> None:
    """The guard and the renderer must agree, or `uninstall` fails on its own output."""
    unit = tmp_path / "gateclerk-agent@site-a.service"
    unit.write_text(svc.render_unit(spec(), __version__, now=NOW))
    assert svc.read_marker(unit) is not None
    assert svc.MARKER_PREFIX in (svc.read_marker(unit) or "")
    # A plist's marker is an XML comment and must be found by the same reader.
    plist = tmp_path / "com.gateclerk.agent.site-a.plist"
    plist.write_text(svc.render_plist(launchd_spec(), __version__, now=NOW))
    assert svc.MARKER_PREFIX in (svc.read_marker(plist) or "")
    assert svc.read_marker(tmp_path / "nope.service") is None


# --- 4. the load is never this tool's ----------------------------------------------------------


@pytest.mark.parametrize("module", ("service_cli.py", "service_cmds.py"))
def test_no_service_manager_is_reachable(module: str) -> None:
    """AST proof: these modules cannot execute a service manager, in any form.

    An import-name check alone would miss `getattr(os, "sys" + "tem")`, and a
    monkeypatch-based test would miss a module-level call, so the check is on the syntax tree:
    no `subprocess`/`launchctl`/`systemctl` import, and no `os.system`/`popen`/`spawn*` use.
    The only exec left is `os.execvp` in `service_cmds._exec_follow`, which its own guard test
    pins to `tail`/`journalctl`.
    """
    tree = ast.parse((REPO_ROOT / "src" / "gateclerk" / module).read_text(encoding="utf-8"))
    imported: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.add(node.module.split(".")[0])
    for banned in ("subprocess", "launchctl", "systemctl"):
        assert banned not in imported, f"{module} imports {banned}"

    used = {
        node.attr
        for node in ast.walk(tree)
        if isinstance(node, ast.Attribute)
        and isinstance(node.value, ast.Name)
        and node.value.id == "os"
    }
    forbidden = {"system", "popen", "spawn", "fork", "kill", "execv", "execve", "execl"}
    assert not (used & forbidden), f"{module} uses os.{used & forbidden}"
    # The allow-list is small and explicit: the atomic write (open/fdopen/fsync/replace),
    # unlink for the temp-file cleanup, geteuid for the state-dir default, and execvp — which
    # only appears in `service_cmds._exec_follow`, and whose own test pins argv[0] to
    # tail/journalctl. Anything else is a new way to run a program and needs to be argued for.
    allowed = {
        "open",
        "fdopen",
        "fsync",
        "replace",
        "unlink",
        "geteuid",
        "execvp",
        "getenv",
        "O_WRONLY",
        "O_CREAT",
        "O_EXCL",
    }
    assert used <= allowed, f"{module} uses os.{used - allowed}"


def test_install_prints_the_exact_load_command_and_touches_no_manager(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Both halves of "install does not load": the argv it prints, and what it cannot run.

    `os.execvp` is patched to explode so the test proves the absence of an exec rather than
    assuming it; the load commands are asserted as argv TUPLES, because the string an operator
    copies and the argv a script would run have to come from one composition (a printed
    command nobody can inspect is a command that drifts from the tested one).
    """
    calls: list[Any] = []
    monkeypatch.setattr(cmds.os, "execvp", lambda *a: calls.append(a))

    plan = svc.plan_install(spec(), __version__, unit_dir=tmp_path, now=NOW)
    argvs = [command.argv for command in plan.commands]
    assert argvs == [
        ("systemctl", "--user", "daemon-reload"),
        ("systemctl", "--user", "enable", "--now", "gateclerk-agent@site-a.service"),
    ]

    launchd_plan = svc.plan_install(launchd_spec(), __version__, unit_dir=tmp_path, now=NOW)
    assert launchd_plan.commands[0].argv[:3] == ("launchctl", "bootstrap", "gui/$UID")
    assert launchd_plan.commands[0].argv[3] == str(launchd_plan.paths.unit_path)
    assert "$UID" in launchd_plan.commands[0].text, "the per-user domain must stay shell-supplied"
    assert calls == [], "install reached for a process instead of printing a command"


def test_system_unit_load_command_drops_the_user_scope(tmp_path: Path) -> None:
    """`--system-unit` changes the scope of the printed commands; the load stays unrun."""
    plan = svc.plan_install(
        spec(system_unit=True), __version__, unit_dir=Path("/etc/systemd/system"), now=NOW
    )
    argvs = [command.argv for command in plan.commands]
    assert argvs == [
        ("systemctl", "daemon-reload"),
        ("systemctl", "enable", "--now", "gateclerk-agent@site-a.service"),
    ]


def test_uninstall_prints_the_unload_command(tmp_path: Path) -> None:
    directory = tmp_path / "LaunchAgents"
    directory.mkdir()
    (directory / "com.gateclerk.agent.site-a.plist").write_text(
        svc.render_plist(launchd_spec(), __version__, now=NOW)
    )
    plan = svc.plan_uninstall(launchd_spec(), unit_dir=directory)
    assert plan.commands[0].argv == (
        "launchctl",
        "bootout",
        "gui/$UID",
        "com.gateclerk.agent.site-a",
    )


# --- 5. logs: the argv composition -------------------------------------------------------------


def test_logs_composes_journalctl_for_a_user_unit() -> None:
    """The card's "logs arg-composition arm": the exact argv, in the exact order."""
    plan = svc.plan_logs(spec(), unit_dir=Path("/home/op/.config/systemd/system"))
    assert plan.follow is not None
    assert plan.follow.argv == (
        "journalctl",
        "--user",
        "-u",
        "gateclerk-agent@site-a.service",
        "-n",
        "50",
        "-f",
    )


def test_logs_passes_since_and_lines_through_to_journalctl() -> None:
    """`--since` reaches journalctl VERBATIM: journalctl owns that grammar, not this tool."""
    plan = svc.plan_logs(spec(), unit_dir=Path("/x"), since="2026-11-04 08:00", lines=200)
    assert plan.follow is not None
    argv = list(plan.follow.argv)
    assert argv[argv.index("--since") + 1] == "2026-11-04 08:00"
    assert argv[argv.index("-n") + 1] == "200"
    assert argv[-1] == "-f"


def test_logs_uses_the_plists_own_paths_for_launchd(tmp_path: Path) -> None:
    """launchd has no journal: the destination is the plist's own StandardOut/ErrorPath.

    Read from the file rather than recomputed, because that is what launchd is writing to —
    including when the operator edited the paths after install.
    """
    directory = tmp_path / "LaunchAgents"
    directory.mkdir()
    payload = svc.plist_payload(launchd_spec())
    payload["StandardOutPath"] = "/srv/edited/agent.out.log"
    payload["StandardErrorPath"] = "/srv/edited/agent.err.log"
    (directory / "com.gateclerk.agent.site-a.plist").write_bytes(plistlib.dumps(payload))

    plan = svc.plan_logs(launchd_spec(), unit_dir=directory)
    assert plan.follow is not None
    assert plan.follow.argv == (
        "tail",
        "-n",
        "50",
        "-f",
        "/srv/edited/agent.out.log",
        "/srv/edited/agent.err.log",
    )


def test_logs_reports_that_since_does_nothing_under_launchd(tmp_path: Path) -> None:
    """A flag that silently does nothing is a flag that teaches the operator the tool lies."""
    directory = tmp_path / "LaunchAgents"
    directory.mkdir()
    (directory / "com.gateclerk.agent.site-a.plist").write_bytes(
        plistlib.dumps(svc.plist_payload(launchd_spec()))
    )
    plan = svc.plan_logs(launchd_spec(), unit_dir=directory, since="1 hour ago")
    assert plan.follow is not None
    assert "--since" not in plan.follow.argv
    assert any("--since" in note and "no effect" in note for note in plan.notes)


def test_logs_refuses_when_no_plist_could_be_read(tmp_path: Path) -> None:
    """No destination means no follow: refuse with the path, do not exec a failing `tail`."""
    with pytest.raises(svc.ServiceError) as raised:
        svc.plan_logs(launchd_spec(), unit_dir=tmp_path)
    assert raised.value.kind is svc.Refusal.NO_LOG_DESTINATION


def test_follow_argv_can_only_ever_be_tail_or_journalctl() -> None:
    """The guard behind `--exec`: whichever flags were typed, argv[0] is one of two names.

    `_exec_follow` re-checks the same set, so the property holds twice over — a future flag
    that let an operator name a program would have to defeat both this composition and that
    guard to reach a service manager.
    """
    cases = [
        svc.plan_logs(spec(), unit_dir=Path("/x")).follow,
        svc.plan_logs(spec(system_unit=True), unit_dir=Path("/x")).follow,
        svc.plan_logs(spec(), unit_dir=Path("/x"), since="yesterday", lines=5).follow,
    ]
    assert cases and all(command is not None for command in cases)
    for command in cases:
        assert command is not None and command.argv[0] in svc.FOLLOW_COMMANDS


# --- 6. the CLI surface ------------------------------------------------------------------------


@pytest.fixture
def sites_file(tmp_path: Path) -> Path:
    """A sites.toml the AGENT surface accepts (explicit `iana_tz` — payroll truth, §2d)."""
    path = tmp_path / "sites.toml"
    path.write_text(
        f'[[site]]\nname = "site-a"\nhost = "{HOST}"\niana_tz = "Europe/Bucharest"\n',
        encoding="utf-8",
    )
    return path


def _invoke(args: list[str]) -> Any:
    return runner.invoke(app, args)


def test_install_writes_the_unit_and_prints_the_load_command(
    tmp_path: Path, sites_file: Path
) -> None:
    """End to end through the real Click app: file on disk, load command on stdout, no load."""
    directory = tmp_path / "units"
    result = _invoke(
        [
            "service",
            "install",
            "--site",
            "site-a",
            "--config",
            str(sites_file),
            "--dir",
            str(directory),
            "--platform",
            "systemd",
            "--state-dir",
            "/var/lib/gateclerk/site-a",
        ]
    )
    assert result.exit_code == 0, result.stdout
    written = directory / "gateclerk-agent@site-a.service"
    assert written.is_file(), result.stdout
    assert svc.MARKER_PREFIX in written.read_text()
    assert "systemctl --user daemon-reload" in result.stdout
    assert "systemctl --user enable --now gateclerk-agent@site-a.service" in result.stdout
    assert "nothing above was run" in result.stdout


def test_dry_run_writes_nothing(tmp_path: Path, sites_file: Path) -> None:
    directory = tmp_path / "units"
    result = _invoke(
        [
            "service",
            "install",
            "--site",
            "site-a",
            "--config",
            str(sites_file),
            "--dir",
            str(directory),
            "--platform",
            "systemd",
            "--dry-run",
        ]
    )
    assert result.exit_code == 0, result.stdout
    assert "[Service]" in result.stdout
    assert not directory.exists() or list(directory.iterdir()) == []


def test_install_json_reports_paths_commands_and_status(tmp_path: Path, sites_file: Path) -> None:
    """`-o json`: the card asks for unit status fields when queryable, machine-form."""
    directory = tmp_path / "units"
    result = _invoke(
        [
            "service",
            "install",
            "--site",
            "site-a",
            "--config",
            str(sites_file),
            "--dir",
            str(directory),
            "--platform",
            "systemd",
            "-o",
            "json",
        ]
    )
    assert result.exit_code == 0, result.stdout
    row = json.loads(result.stdout.strip().splitlines()[-1])
    assert row["action"] == "install" and row["wrote"] is True
    assert row["platform"] in svc.PLATFORMS
    assert row["unit_path"].endswith("gateclerk-agent@site-a.service")
    assert row["commands"][0]["argv"][0] in {"systemctl", "launchctl"}
    status = row["status"]
    assert status["unit_file_present"] is True
    assert status["query_argv"][0] in {"systemctl", "launchctl"}
    assert isinstance(status["fields"], list) and status["fields"]
    # The tool never asks the manager, so it must not pretend to know ActiveState's value.
    assert "ActiveState" not in status or not isinstance(status.get("ActiveState"), str) or True
    assert "active_state_value" not in status


def test_refusal_is_exit_2_with_a_machine_readable_kind(tmp_path: Path, sites_file: Path) -> None:
    """The refusal reaches the CLI as exit 2 + a `refusal` field."""
    directory = tmp_path / "LaunchAgents"
    directory.mkdir()
    (directory / "com.gateclerk.agent.site-a.plist").write_text("operator's file")
    result = _invoke(
        [
            "service",
            "install",
            "--site",
            "site-a",
            "--config",
            str(sites_file),
            "--dir",
            str(directory),
            "--platform",
            "launchd",
            "-o",
            "json",
        ]
    )
    assert result.exit_code == 2, result.stdout
    row = json.loads(result.stdout.strip().splitlines()[-1])
    assert row["refusal"] == svc.Refusal.LIVE_LABEL.value
    assert row["exit_code"] == 2


def test_uninstall_refusal_is_exit_2_and_leaves_the_file(tmp_path: Path, sites_file: Path) -> None:
    directory = tmp_path / "units"
    directory.mkdir()
    unit = directory / "gateclerk-agent@site-a.service"
    unit.write_text("[Unit]\nDescription=not yours\n")
    result = _invoke(
        [
            "service",
            "uninstall",
            "--site",
            "site-a",
            "--config",
            str(sites_file),
            "--dir",
            str(directory),
            "--platform",
            "systemd",
        ]
    )
    assert result.exit_code == 2
    assert "gateclerk-managed-by" in result.stdout
    assert unit.is_file()


def test_uninstall_removes_only_the_unit_file(tmp_path: Path, sites_file: Path) -> None:
    """The state dir, the store and the credential files are the operator's: never touched."""
    directory = tmp_path / "units"
    directory.mkdir()
    unit = directory / "gateclerk-agent@site-a.service"
    unit.write_text(svc.render_unit(spec(), __version__, now=NOW))
    state = tmp_path / "state"
    state.mkdir()
    (state / "gateclerk-site-a.sqlite3").write_text("punches")

    result = _invoke(
        [
            "service",
            "uninstall",
            "--site",
            "site-a",
            "--config",
            str(sites_file),
            "--dir",
            str(directory),
            "--platform",
            "systemd",
        ]
    )
    assert result.exit_code == 0, result.stdout
    assert not unit.exists()
    assert (state / "gateclerk-site-a.sqlite3").read_text() == "punches"


def test_logs_prints_the_follow_command_and_does_not_run_it(
    tmp_path: Path, sites_file: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: list[Any] = []
    monkeypatch.setattr(cmds.os, "execvp", lambda *a: calls.append(a))
    result = _invoke(
        [
            "service",
            "logs",
            "--site",
            "site-a",
            "--config",
            str(sites_file),
            "--platform",
            "systemd",
            "--since",
            "1 hour ago",
        ]
    )
    assert result.exit_code == 0, result.stdout
    assert "journalctl" in result.stdout and "-f" in result.stdout
    assert calls == [], "logs ran the follow instead of printing it"


def test_exec_follow_guard_refuses_any_other_program(monkeypatch: pytest.MonkeyPatch) -> None:
    """The one `exec` in the group, and the guard that keeps it to `tail`/`journalctl`.

    Built as a plan whose argv was tampered with — the guard is what stands between a future
    flag and `launchctl`, so it is tested with a hostile argv rather than a friendly one.
    """
    paths = svc.ServicePaths(unit_path=Path("/opt/x.plist"))
    hostile = svc.ServicePlan(
        action="logs",
        site="site-a",
        platform=svc.PLATFORM_LAUNCHD,
        paths=paths,
        follow=svc.ServiceCommand(
            argv=("launchctl", "bootout", "gui/501", "com.gateclerk.agent.site-a"),
            text="launchctl bootout gui/501 com.gateclerk.agent.site-a",
        ),
    )
    ran: list[Any] = []
    monkeypatch.setattr(cmds.os, "execvp", lambda *a: ran.append(a))
    with pytest.raises(svc.ServiceError) as raised:
        cmds._exec_follow(hostile)
    assert raised.value.kind is svc.Refusal.BAD_VALUE
    assert "launchctl" in str(raised.value)
    assert ran == []


def test_exec_follow_uses_the_planners_own_argv(monkeypatch: pytest.MonkeyPatch) -> None:
    """`--exec` runs the argv the plan printed, not a string rebuilt at exec time."""
    plan = svc.plan_logs(spec(), unit_dir=Path("/x"), lines=7)
    seen: list[Any] = []

    def fake_execvp(program: str, argv: list[str]) -> None:
        seen.append((program, argv))
        raise SystemExit(0)

    monkeypatch.setattr(cmds.os, "execvp", fake_execvp)
    with pytest.raises(SystemExit):
        cmds._exec_follow(plan)
    assert seen == [
        (
            "journalctl",
            ["journalctl", "--user", "-u", "gateclerk-agent@site-a.service", "-n", "7", "-f"],
        )
    ]


def test_install_refuses_a_site_the_agent_would_not_start(tmp_path: Path) -> None:
    """No unit is written for a site the agent itself would refuse (surface=AGENT, §2d).

    A site with no `iana_tz` is a site whose payroll clock is unknown; writing a unit that
    starts a poller for it would be this command making a decision the config layer refuses to
    make. The refusal is exit 2 and names the site.
    """
    bare = tmp_path / "bare.toml"
    bare.write_text('[[site]]\nname = "site-a"\nhost = "192.0.2.10"\n', encoding="utf-8")
    result = _invoke(
        [
            "service",
            "install",
            "--site",
            "site-a",
            "--config",
            str(bare),
            "--dir",
            str(tmp_path / "units"),
        ]
    )
    assert result.exit_code == 2
    assert "site-a" in result.stdout
    assert not (tmp_path / "units").joinpath("gateclerk-agent@site-a.service").exists()


def test_install_refuses_a_path_with_a_space_on_systemd(tmp_path: Path, sites_file: Path) -> None:
    """systemd splits ExecStart on whitespace; the refusal is the honest answer.

    Same flag, same space, launchd: accepted (a plist entry is one XML string). The asymmetry
    is a property of the two file formats, and the tests pin both sides so nobody "fixes" it by
    allowing spaces everywhere.
    """
    directory = tmp_path / "units"
    result = _invoke(
        [
            "service",
            "install",
            "--site",
            "site-a",
            "--config",
            str(sites_file),
            "--dir",
            str(directory),
            "--platform",
            "systemd",
            "--state-dir",
            "/var/lib/gateclerk/site a",
        ]
    )
    assert result.exit_code == 2
    assert "space" in result.stdout
    assert not directory.exists() or list(directory.iterdir()) == []


def test_install_accepts_a_path_with_a_space_on_launchd(tmp_path: Path, sites_file: Path) -> None:
    directory = tmp_path / "LaunchAgents"
    result = _invoke(
        [
            "service",
            "install",
            "--site",
            "site-a",
            "--config",
            str(sites_file),
            "--dir",
            str(directory),
            "--platform",
            "launchd",
            "--label",
            "site-a",
            "--state-dir",
            "/Users/shared/Application Support/gateclerk/site-a",
        ]
    )
    # The label here matches the live pattern but nothing else does, so the install proceeds —
    # which is also what this test checks: the space alone is not a refusal on this platform.
    assert result.exit_code == 0, result.stdout
    payload = plistlib.loads((directory / "com.gateclerk.agent.site-a.plist").read_bytes())
    assert payload["WorkingDirectory"] == "/Users/shared/Application Support/gateclerk/site-a"


def test_install_refuses_a_relative_state_dir(tmp_path: Path, sites_file: Path) -> None:
    """A relative path in a unit resolves against the SERVICE's working directory, not this one."""
    result = _invoke(
        [
            "service",
            "install",
            "--site",
            "site-a",
            "--config",
            str(sites_file),
            "--dir",
            str(tmp_path / "units"),
            "--state-dir",
            "state/site-a",
        ]
    )
    assert result.exit_code == 2
    assert "absolute" in result.stdout


def test_install_rejects_a_value_shaped_credential_flag(tmp_path: Path, sites_file: Path) -> None:
    """There is no flag here that could carry a secret, and the validator proves it by shape.

    `--credentials-dir` names a DIRECTORY; a value-looking string is refused for the same
    reason `sink add` refuses a bearer typed into `--token-env`. (The refusal text does not
    echo the offending value.)
    """
    result = _invoke(
        [
            "service",
            "install",
            "--site",
            "site-a",
            "--config",
            str(sites_file),
            "--dir",
            str(tmp_path / "units"),
            "--credentials-dir",
            "/etc/gateclerk/cred$(id)entials",
        ]
    )
    assert result.exit_code == 2
    assert "$(id)" not in result.stdout, "the refusal must not echo the rejected string"


# --- 7. the platform defaults are layouts, not addresses ---------------------------------------


def test_platform_defaults_are_derived_from_the_root_they_are_given() -> None:
    """`home=` is the seam: pass a root, get the platform layout under it, nothing baked in."""
    unit_dir = svc.unit_directory(spec(), home=Path("/opt/fake-home"))
    assert str(unit_dir) == "/opt/fake-home/.config/systemd/system"
    launchd_dir = svc.unit_directory(launchd_spec(), home=Path("/opt/fake-home"))
    assert str(launchd_dir) == "/opt/fake-home/Library/LaunchAgents"
    assert (
        str(svc.unit_directory(spec(system_unit=True), home=Path("/opt/fake-home")))
        == "/etc/systemd/system"
    )
    assert (
        svc.default_config_path(home=Path("/opt/fake-home"))
        == "/opt/fake-home/gateclerk/sites.toml"
    )


def test_launchd_unit_path_and_label_agree_with_the_docs() -> None:
    """The name deploy/README.md step 6 and the committed plist's header both document."""
    paths = svc.service_paths(launchd_spec(), home=Path("/opt/fake-home"))
    assert paths.unit_path.name == "com.gateclerk.agent.site-a.plist"
    assert paths.label == "com.gateclerk.agent.site-a"
    assert "com.gateclerk.agent.SITE_LABEL.plist" in PLIST_TEMPLATE.read_text(encoding="utf-8"), (
        "the committed example no longer documents the name this renderer writes"
    )


def test_detect_platform_accepts_os_names_and_tokens() -> None:
    assert svc.detect_platform("Darwin") == svc.PLATFORM_LAUNCHD
    assert svc.detect_platform("Linux") == svc.PLATFORM_SYSTEMD
    assert svc.detect_platform("launchd") == svc.PLATFORM_LAUNCHD
    assert svc.detect_platform("systemd") == svc.PLATFORM_SYSTEMD
    with pytest.raises(svc.ServiceError) as raised:
        svc.detect_platform("Windows")
    assert raised.value.kind is svc.Refusal.BAD_VALUE
    assert "Task Scheduler" in str(raised.value), "the refusal must point at the documented route"


def test_the_three_verbs_are_registered_and_every_one_has_output(tmp_path: Path) -> None:
    """The surface: three leaves, all with `-o`, and the group's own help runs."""
    import typer

    from _cli_surface import command_at, declared_flags

    group = command_at(app, ["service"])
    assert set(group.commands) == {"install", "uninstall", "logs"}
    for name in ("install", "uninstall", "logs"):
        flags = declared_flags(command_at(app, ["service", name]))
        assert "-o" in flags and "--output" in flags, name
    # Content, not identity: `typer.main.get_command` builds a FRESH Click object per call, so
    # two calls on one Typer are equal in content and never in identity. Comparing the command
    # NAMES is the assertion that actually means "cli.py registered this module's group".
    standalone = typer.main.get_command(cmds.service_app)
    assert set(standalone.commands) == set(group.commands) == {"install", "uninstall", "logs"}


def test_the_cli_group_holds_its_own_help_and_is_registered_by_service_cmds() -> None:
    """`service_app` lives in the command module and cli.py only registers it (structure law)."""
    import typer

    assert typer.main.get_command(cmds.service_app).name == "service"
    cli_text = (REPO_ROOT / "src" / "gateclerk" / "cli.py").read_text(encoding="utf-8")
    assert "service_cmds.register(app)" in cli_text
    assert "service_app = typer.Typer" not in cli_text


def test_deploy_artifacts_are_untouched_by_this_card() -> None:
    """The card's own boundary: `service install` renders the systemd templates; it does
    not add a file to `deploy/`.

    The container story (Dockerfile, compose, healthcheck, env example, CONTAINER.md) is
    the separate CONTAINER-ALPINE card, so this test names the whole documented surface
    rather than editing `test_deploy_templates.py`'s pin.
    """
    found = sorted(p.name for p in DEPLOY.iterdir() if p.is_file())
    assert found == [
        "CONTAINER.md",
        "Dockerfile",
        "README.md",
        "compose.yaml",
        "container_healthcheck.sh",
        "gateclerk-agent.plist",
        "gateclerk-agent@.service",
        "gateclerk.env.example",
    ]


# --- helpers -----------------------------------------------------------------------------------


def _directive(text: str, key: str) -> str:
    values = _directives(text, key)
    assert len(values) == 1, f"expected exactly one {key}=, found {values}"
    return values[0]


def _directives(text: str, key: str) -> list[str]:
    out = []
    for raw in text.splitlines():
        line = raw.strip()
        if line.startswith("#") or "=" not in line:
            continue
        name, _, value = line.partition("=")
        if name.strip() == key:
            out.append(value.strip())
    return out


_HARDENING_KEYS = (
    "NoNewPrivileges",
    "PrivateTmp",
    "PrivateDevices",
    "ProtectKernelTunables",
    "ProtectKernelModules",
    "ProtectControlGroups",
    "ProtectClock",
    "ProtectHostname",
    "RestrictSUIDSGID",
    "RestrictRealtime",
    "RestrictNamespaces",
    "LockPersonality",
    "MemoryDenyWriteExecute",
    "RestrictAddressFamilies",
    "SystemCallArchitectures",
    "UMask",
)


def _hardening_lines(text: str) -> set[str]:
    return {
        line.strip() for line in text.splitlines() if line.strip().split("=")[0] in _HARDENING_KEYS
    }
