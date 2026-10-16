"""CLI contract tests: version, command tree, and the shared connection flags.

All offline — Typer's CliRunner, no sockets, no device. The command *behaviour* is
p1-08's suite (`test_cli_commands.py`); this file owns the scaffold contract p1-01
established: the tree, the version, the shared flags, and the rule that a device is
never guessed at.

Card p1-08 replaced the four scaffold stubs with real device readers, so the stub
assertions here became "a command that needs a device refuses to guess one": the exit
code moved from the stub's 3 to the config-error 2, and the reason moved from "nobody has
written this yet" to "you have not told me how to reach it".
"""

from __future__ import annotations

import re

import pytest
from typer.testing import CliRunner

from gateclerk import __version__
from gateclerk.cli import CONFIG_ERROR_EXIT, app

runner = CliRunner()

_ANSI = re.compile(r"\x1b\[[0-9;]*m")


def _clean(text: str) -> str:
    """Strip the ANSI styling rich puts into help output.

    Typer renders help through rich, which colourises option names and splits a flag
    into separate spans (`-` + `host`), so a naive `'--host' in out` passes on a
    colourless terminal and fails on a coloured one. Strip before matching.
    """
    return _ANSI.sub("", text)


def _squash(text: str) -> str:
    """Whitespace-free form, for flag-presence checks that wrapping could break."""
    return re.sub(r"\s+", "", _clean(text))


#: (command words, full args) for every command that reads a device. p1-08 implemented
#: these; they are kept here as the list the shared-flag contract applies to.
#:
#: The command words are separate from the args on purpose: deriving them by slicing the
#: arg list (`args[:2]`) worked while every command was a two-word group+subcommand, and
#: silently produced `["events", "--host"]` the moment `events` became a bare command with
#: required flags — an invocation that fails for the wrong reason and asserts nothing.
DEVICE_COMMANDS: list[tuple[list[str], list[str]]] = [
    (["device", "info"], ["--host", "192.0.2.10"]),
    (["device", "time"], ["--host", "192.0.2.10"]),
    (["device", "capabilities"], ["--host", "192.0.2.10"]),
    (["users", "list"], ["--host", "192.0.2.10"]),
    (
        ["events"],
        [
            "--host",
            "192.0.2.10",
            "--since",
            "2026-10-15T00:00:00",
            "--until",
            "2026-10-16T00:00:00",
        ],
    ),
]


def run(args: list[str]) -> tuple[int, str]:
    result = runner.invoke(app, args)
    out = result.stdout or ""
    if result.exception is not None and not isinstance(result.exception, SystemExit):
        raise result.exception
    return result.exit_code, out


def test_version_flag_without_subcommand() -> None:
    code, out = run(["--version"])
    assert code == 0
    assert __version__ in out
    assert out.strip().startswith("gateclerk")


def test_version_short_flag() -> None:
    code, out = run(["-V"])
    assert code == 0
    assert __version__ in out


def test_version_is_the_package_version() -> None:
    # Drift guard: the CLI must report the real package version, not a literal.
    code, out = run(["--version"])
    assert code == 0
    assert f"gateclerk {__version__}" in out


def test_help_works() -> None:
    code, out = run(["--help"])
    assert code == 0
    cleaned = _clean(out)
    for group in ("device", "users", "events"):
        assert group in cleaned


def test_no_args_shows_help() -> None:
    """no_args_is_help: shows the tree. Click reports that as a usage exit, not a crash."""
    code, out = run([])
    assert code in (0, 2)
    cleaned = _clean(out)
    assert "Commands" in cleaned and "device" in cleaned


@pytest.mark.parametrize(("cmd", "args"), DEVICE_COMMANDS)
def test_device_commands_refuse_to_guess_a_device(cmd: list[str], args: list[str]) -> None:
    """A device is never guessed at: omitting --host/--site is a usage error, not a default.

    This was p1-01's stub test ("a stub must name the card that implements it"). The
    invariant underneath it is the one worth keeping — the tool must never pick which door
    controller to talk to — and it now asserts more than the stub ever could, because the
    commands really would go out to the network if a target could be invented.
    """
    without = [a for a in args if a != "--host" and a != "192.0.2.10"]
    code, out = run([*cmd, *without])
    assert code == CONFIG_ERROR_EXIT, f"{without} exited {code}: {out}"
    assert "host" in out.lower() or "site" in out.lower(), out


@pytest.mark.parametrize(("cmd", "args"), DEVICE_COMMANDS)
def test_device_commands_refuse_without_a_credential(
    cmd: list[str], args: list[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    """A target with no credential exits 2 and never reaches for the network.

    `shutil.which` is stubbed so the macOS Keychain cannot answer and the two password env
    vars are cleared: without that, the exit code would depend on the machine running the
    suite rather than on the CLI's contract.
    """
    monkeypatch.setattr("shutil.which", lambda _name: None)
    for var in ("GATECLERK_PASSWORD", "GATECLERK_192_0_2_10_PASSWORD"):
        monkeypatch.delenv(var, raising=False)
    code, out = run([*cmd, *args])
    assert code == CONFIG_ERROR_EXIT, f"{cmd} {args} exited {code}: {out}"
    assert "password" in out.lower(), out


@pytest.mark.parametrize(("cmd", "args"), DEVICE_COMMANDS)
def test_device_commands_accept_json_output(cmd: list[str], args: list[str]) -> None:
    """`--output json` parses on every device command.

    The run still fails (there is no device to read) and that is fine — what is being
    pinned is that `json`/`jsonl`/`table` are accepted choices rather than rejected by
    click before the command body ever runs.
    """
    for fmt in ("json", "jsonl", "table"):
        _code, out = run([*cmd, *args, "--output", fmt])
        # The run itself cannot succeed (there is no device), but click must not reject the
        # format before the command body runs: that rejection is the only failure this
        # asserts on, so an unrelated exit stays a pass.
        assert "Invalid value" not in out, f"--output {fmt} was rejected: {out}"


def test_output_rejects_unknown_format() -> None:
    code, _ = run([*["device", "info", "--host", "192.0.2.10"], "--output", "yaml"])
    assert code != 0


def test_connection_flags_are_shared_across_commands() -> None:
    """--host/--port/--user/--password/--timeout exist on every device-reading command."""
    for cmd, _args in DEVICE_COMMANDS:
        code, out = run([*cmd, "--help"])
        assert code == 0
        squashed = _squash(out)
        for flag in ("--host", "--port", "--user", "--password", "--timeout"):
            assert flag in squashed, f"{cmd} is missing {flag}"


def test_shared_flag_defaults_match_the_design() -> None:
    """Port 80 / 30s read timeout / Europe-Bucharest are DESIGN.md decisions, not whims."""
    for cmd, _args in DEVICE_COMMANDS:
        code, out = run([*cmd, "--help"])
        assert code == 0
        cleaned = _clean(out)
        assert "default: 80" in cleaned, "ISAPI default port must be 80 (HTTP, TLS out of scope)"
        assert "default: 30.0" in cleaned, "read timeout default is 30s"
    code, out = run(["events", "--help"])
    assert "Europe/Bucharest" in _clean(out)


def test_ansi_helpers_survive_the_output_ci_actually_produced() -> None:
    """Regression test for the CI-only failure this file used to have.

    CI's run failed `assert '--host' in out` while passing locally, because rich wrote
    the option name as two colourised spans. This is the literal byte sequence from that
    run's log, so the helper is pinned against the real failure and not a guess at it.
    """
    ci_bytes = (
        "\x1b[2m│\x1b[0m \x1b[31m*\x1b[0m  \x1b[1;36m-\x1b[0m\x1b[1;36m-host\x1b[0m"
        "              \x1b[1;2;33m<\x1b[0m\x1b[1;33mstr\x1b[0m\x1b[1;2;33m>\x1b[0m"
        "                 Device hostname or IP on the"
    )
    assert "--host" not in ci_bytes, "precondition: the raw bytes really do not contain it"
    assert "--host" in _clean(ci_bytes)
    assert "--host" in _squash(ci_bytes)


def test_password_flag_is_not_echoed() -> None:
    """A rejected invocation must not echo the password back (hide_input).

    `--output yaml` makes click refuse the invocation before any device is contacted, so
    this asserts the property — the secret does not come back on stdout — without needing
    a device to fail against. The offline suite covers the same property on the success and
    failure paths (`test_cli_commands.py`, `test_cli_credentials.py`).
    """
    code, out = run(
        [
            "device",
            "info",
            "--host",
            "192.0.2.10",
            "--password",
            "fake-pw",
            "--output",
            "yaml",
        ]
    )
    assert code != 0
    assert "fake-pw" not in out, "the password leaked into the CLI output"
