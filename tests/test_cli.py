"""CLI contract tests: version, command tree, and the stub exit codes.

All offline — Typer's CliRunner, no sockets, no device.
"""

from __future__ import annotations

import re

import pytest
from typer.testing import CliRunner

from gateclerk import __version__
from gateclerk.cli import NOT_IMPLEMENTED_EXIT, app

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


# (args) for every command that is a scaffold stub.
STUB_COMMANDS = [
    ["device", "info", "--host", "192.0.2.10"],
    ["device", "time", "--host", "192.0.2.10"],
    ["users", "list", "--host", "192.0.2.10"],
    ["events", "search", "--host", "192.0.2.10", "--since", "2026-10-15T00:00:00"],
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
    assert code != NOT_IMPLEMENTED_EXIT
    cleaned = _clean(out)
    assert "Commands" in cleaned and "device" in cleaned


@pytest.mark.parametrize("args", STUB_COMMANDS)
def test_stub_exits_not_implemented(args: list[str]) -> None:
    """Stubs must be unmistakable: a distinct exit code + 'not implemented' + owner card."""
    code, out = run(args)
    combined = out.lower()
    assert code == NOT_IMPLEMENTED_EXIT, f"{args} exited {code}, expected {NOT_IMPLEMENTED_EXIT}"
    assert "not implemented" in combined or "scaffold stub" in combined, out
    assert "p1-0" in combined, "a stub must name the card that implements it"


@pytest.mark.parametrize("args", STUB_COMMANDS)
def test_stub_commands_require_host(args: list[str]) -> None:
    """A device is never guessed at: omitting --host is a usage error, not a default."""
    without = [a for a in args if a != "--host" and a != "192.0.2.10"]
    code, _ = run(without)
    assert code != 0
    assert code != NOT_IMPLEMENTED_EXIT


@pytest.mark.parametrize("args", STUB_COMMANDS)
def test_stub_accepts_json_output(args: list[str]) -> None:
    code, _ = run([*args, "--output", "json"])
    assert code == NOT_IMPLEMENTED_EXIT


def test_output_rejects_unknown_format() -> None:
    code, _ = run([*["device", "info", "--host", "192.0.2.10"], "--output", "yaml"])
    assert code != 0


def test_connection_flags_are_shared_across_commands() -> None:
    """--host/--port/--user/--password/--timeout exist on every device-reading command."""
    for args in STUB_COMMANDS:
        code, out = run([*args[:2], "--help"])
        assert code == 0
        squashed = _squash(out)
        for flag in ("--host", "--port", "--user", "--password", "--timeout"):
            assert flag in squashed, f"{args[:2]} is missing {flag}"


def test_shared_flag_defaults_match_the_design() -> None:
    """Port 80 / 30s read timeout / Europe-Bucharest are DESIGN.md decisions, not whims."""
    for args in STUB_COMMANDS:
        code, out = run([*args[:2], "--help"])
        assert code == 0
        cleaned = _clean(out)
        assert "default: 80" in cleaned, "ISAPI default port must be 80 (HTTP, TLS out of scope)"
        assert "default: 30.0" in cleaned, "read timeout default is 30s"
    code, out = run(["events", "search", "--help"])
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
    """--password must not echo the value back (hide_input)."""
    code, out = run(["device", "info", "--host", "192.0.2.10", "--password", "fake-pw"])
    assert code == NOT_IMPLEMENTED_EXIT
    assert "fake-pw" not in out, "the password leaked into the CLI output"
