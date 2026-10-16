"""CLI surface p1-02 adds: credential flags wired to resolution, exit codes, no leaks.

Complements tests/test_cli.py (which owns the scaffold contract: version, stubs exiting
3, shared flags). This file covers what p1-02 put behind those flags — `--site`/`--config`
resolution and the `creds` diagnostic group — and the rule that matters most on a tool
that reads door-hardware credentials: **nothing that prints may contain the password**,
including on the failure path.

`device info` etc. still exit 3 (p1-01's contract): they resolve the *site*, not the
credential, so a CI runner with no Keychain never turns a stub into an exit 2.
"""

from __future__ import annotations

import json
import re
import shlex
import subprocess
from pathlib import Path

import pytest
from typer.testing import CliRunner

from gateclerk.cli import CONFIG_ERROR_EXIT, NOT_IMPLEMENTED_EXIT, app
from gateclerk.config import DEFAULT_ISAPI_USER

runner = CliRunner()

_ANSI = re.compile(r"\x1b\[[0-9;]*m")
HOST = "192.0.2.10"
PER_HOST_PW_VAR = "GATECLERK_192_0_2_10_PASSWORD"

SITE_TOML = """
[[site]]
name = "site-a"
host = "192.0.2.10"
port = 8080
iana_tz = "Europe/Bucharest"
isapi_user = "isapi-svc"
keychain_service = "gateclerk-hikvision"
"""

BAD_PORT_TOML = """
[[site]]
name = "broken"
host = "192.0.2.10"
port = 99999
"""


def clean(text: str) -> str:
    return _ANSI.sub("", text)


def squashed(text: str) -> str:
    return re.sub(r"\s+", "", clean(text))


def run(args: list[str], env: dict[str, str] | None = None) -> tuple[int, str]:
    """Invoke with a *controlled* environment.

    We clear the real environment rather than trusting whatever the developer has
    exported: an inherited GATECLERK_PASSWORD would make credential tests pass for the
    wrong reason, and on a machine with a real keychain item it would make them resolve
    against a live device credential.
    """
    import os

    base = {"PATH": "/usr/bin:/bin", "HOME": str(Path.home()), "PYTHONDONTWRITEBYTECODE": "1"}
    base.update(env or {})
    saved = dict(os.environ)
    os.environ.clear()
    os.environ.update(base)
    try:
        result = runner.invoke(app, args)
    finally:
        os.environ.clear()
        os.environ.update(saved)
    out = result.stdout or ""
    if result.exception is not None and not isinstance(result.exception, SystemExit):
        raise result.exception
    return result.exit_code, out


def json_rows(out: str) -> list[dict[str, object]]:
    return [json.loads(line) for line in clean(out).strip().splitlines() if line.strip()]


@pytest.fixture
def sites_file(tmp_path: Path) -> Path:
    path = tmp_path / "sites.toml"
    path.write_text(SITE_TOML, encoding="utf-8")
    return path


@pytest.fixture
def no_security(monkeypatch: pytest.MonkeyPatch) -> None:
    """Pretend this host has no `/usr/bin/security`, so the keychain rung is unreachable.

    Needed so the failure-path tests behave the same on a macOS laptop (where a real
    keychain exists and could even be consulted) and on a Linux CI runner (where it
    cannot be). It also guarantees no test in this file spawns a process.
    """
    import gateclerk.config as cfg

    monkeypatch.setattr(cfg.shutil, "which", lambda _path: None)


# --- device commands: site resolution ----------------------------------------------------


def test_device_info_help_shows_the_credential_flags() -> None:
    """Definition of done: `gateclerk device info --help` shows the flags."""
    code, out = run(["device", "info", "--help"])
    assert code == 0
    joined = squashed(out)
    for flag in ("--host", "--port", "--user", "--password", "--timeout", "--site", "--config"):
        assert flag in joined, f"missing {flag}"
    cleaned = clean(out)
    assert "default: 80" in cleaned, "ISAPI default port must stay 80"
    assert "default: 30.0" in cleaned, "read timeout default is 30s"


def test_site_flag_resolves_host_from_sites_toml(sites_file: Path) -> None:
    """--site supplies the host; the stub still exits 3 and echoes the resolved host."""
    code, out = run(["device", "info", "--site", "site-a", "--config", str(sites_file)])
    assert code == NOT_IMPLEMENTED_EXIT, clean(out)
    cleaned = clean(out)
    assert HOST in cleaned, "the resolved host must reach the command"
    assert "not implemented" in cleaned.lower()
    assert "p1-0" in cleaned, "a stub must still name the card that implements it"
    assert "8080" in cleaned, "the site's port must be honoured, not the flag default"


def test_site_and_host_are_mutually_exclusive(sites_file: Path) -> None:
    code, out = run(
        ["device", "info", "--site", "site-a", "--host", "192.0.2.99", "--config", str(sites_file)]
    )
    assert code == CONFIG_ERROR_EXIT
    assert "mutually exclusive" in clean(out)


def test_no_device_given_is_a_config_error_not_a_guess(sites_file: Path) -> None:
    """Even with exactly one site configured, the device must be named explicitly."""
    code, out = run(["device", "info", "--config", str(sites_file)])
    assert code == CONFIG_ERROR_EXIT
    assert "no device given" in clean(out)


def test_unknown_site_lists_what_exists(sites_file: Path) -> None:
    code, out = run(["device", "info", "--site", "site-z", "--config", str(sites_file)])
    assert code == CONFIG_ERROR_EXIT
    cleaned = clean(out)
    assert "site-z" in cleaned and "site-a" in cleaned


def test_missing_sites_file_names_the_path(tmp_path: Path) -> None:
    missing = tmp_path / "absent.toml"
    code, out = run(["device", "info", "--site", "site-a", "--config", str(missing)])
    assert code == CONFIG_ERROR_EXIT
    assert str(missing) in clean(out)


def test_bad_site_block_surfaces_the_validation_message(tmp_path: Path) -> None:
    bad = tmp_path / "sites.toml"
    bad.write_text(BAD_PORT_TOML, encoding="utf-8")
    code, out = run(["device", "info", "--site", "broken", "--config", str(bad)])
    assert code == CONFIG_ERROR_EXIT
    assert "port 99999" in clean(out)


@pytest.mark.parametrize(
    ("group", "command"),
    [("device", "info"), ("device", "time"), ("users", "list"), ("events", "search")],
)
def test_site_and_config_flags_are_shared_across_device_commands(group: str, command: str) -> None:
    """p1-08 builds on one spelling of these; per-command drift is the bug this pins."""
    code, out = run([group, command, "--help"])
    assert code == 0
    joined = squashed(out)
    for flag in ("--host", "--site", "--config", "--user", "--password"):
        assert flag in joined, f"{group} {command} lacks {flag}"


# --- creds check ------------------------------------------------------------------------


def test_creds_check_uses_the_flag_as_the_highest_rung() -> None:
    code, out = run(
        ["creds", "check", "--host", HOST, "--user", "svc", "--password", "fake-flag-pw"]
    )
    assert code == 0, clean(out)
    cleaned = clean(out)
    assert "flag" in cleaned
    assert "svc" in cleaned
    assert "fake-flag-pw" not in cleaned, "the password must never be printed"


def test_creds_check_json_is_machine_readable_and_secret_free() -> None:
    code, out = run(["creds", "check", "--host", HOST, "--password", "fake-flag-pw", "-o", "json"])
    assert code == 0, clean(out)
    (row,) = json_rows(out)
    assert row["host"] == HOST
    assert row["source"] == "flag"
    assert row["user"] == DEFAULT_ISAPI_USER, "no --user, no env: documented default"
    assert row["password"] == "***", "the field is present and explicitly masked"
    assert "fake-flag-pw" not in out


def test_creds_check_takes_the_password_from_the_per_host_env_var() -> None:
    code, out = run(["creds", "check", "--host", HOST], env={PER_HOST_PW_VAR: "fake-env-pw"})
    assert code == 0, clean(out)
    cleaned = clean(out)
    assert "env" in cleaned and "fake-env-pw" not in cleaned


def test_creds_check_flag_beats_the_env_var() -> None:
    """With both present, the reported source must be `flag`, not `env`."""
    code, out = run(
        ["creds", "check", "--host", HOST, "--password", "fake-flag-pw", "-o", "json"],
        env={PER_HOST_PW_VAR: "fake-env-pw"},
    )
    assert code == 0, clean(out)
    (row,) = json_rows(out)
    assert row["source"] == "flag", row
    assert "fake-env-pw" not in out and "fake-flag-pw" not in out


def test_creds_check_takes_the_user_from_the_env_and_the_password_from_the_flag() -> None:
    code, out = run(
        ["creds", "check", "--host", HOST, "--password", "fake-flag-pw"],
        env={"GATECLERK_USER": "env-svc"},
    )
    assert code == 0, clean(out)
    cleaned = clean(out)
    assert "env-svc" in cleaned, "user and password resolve on independent rungs"


def test_creds_check_is_unreachable_keychain_reported_as_exit_two(no_security: None) -> None:
    """No flag, no env, no keychain binary: exit 2 naming the variable that would fix it."""
    code, out = run(["creds", "check", "--host", HOST])
    assert code == CONFIG_ERROR_EXIT
    cleaned = clean(out)
    assert PER_HOST_PW_VAR in cleaned
    assert "fake-flag-pw" not in cleaned


def test_creds_check_error_in_json_is_still_json(no_security: None) -> None:
    code, out = run(["creds", "check", "--host", HOST, "-o", "json"])
    assert code == CONFIG_ERROR_EXIT
    (row,) = json_rows(out)
    assert row["exit_code"] == CONFIG_ERROR_EXIT
    assert row.get("error"), "a json error row must carry the message, not just a code"


def test_creds_check_reads_the_site_block_for_the_keychain_service(
    sites_file: Path, no_security: None
) -> None:
    """A --site failure must still name the env var that resolves THIS host."""
    code, out = run(["creds", "check", "--site", "site-a", "--config", str(sites_file)])
    assert code == CONFIG_ERROR_EXIT
    assert "GATECLERK_192_0_2_10_PASSWORD" in clean(out)


def test_site_isapi_user_reaches_the_suggested_keychain_command() -> None:
    """The command we print must create the item for the site's user, not `admin`."""
    from gateclerk.config import SiteConfig

    site = SiteConfig(name="s", host=HOST, isapi_user="isapi-svc")
    assert "-j user=isapi-svc" in site.target().add_command()


def test_creds_check_refuses_an_implicit_site_like_the_device_commands(
    sites_file: Path,
) -> None:
    code, out = run(["creds", "check", "--config", str(sites_file)])
    assert code == CONFIG_ERROR_EXIT
    assert "no device given" in clean(out)


# --- creds explain -----------------------------------------------------------------------


def test_creds_explain_lists_the_resolution_plan_in_order() -> None:
    code, out = run(["creds", "explain", HOST, "-o", "json"])
    assert code == 0, clean(out)
    rows = json_rows(out)
    assert [r["source"] for r in rows] == ["flag", "env", "env", "keychain", "keychain"]
    where = " ".join(str(r["where"]) for r in rows)
    assert PER_HOST_PW_VAR in where, "per-host var must be named before the global one"
    assert "GATECLERK_PASSWORD" in where
    assert "find-generic-password" in where
    assert "add-generic-password" in where
    assert int(str(rows[0]["rung"])) < int(str(rows[-1]["rung"])), "rung order IS the precedence"


def test_creds_explain_touches_no_process_and_resolves_no_secret() -> None:
    real_run = subprocess.run

    def explode(*args: object, **kwargs: object) -> object:
        raise AssertionError("creds explain must not spawn a process")

    subprocess.run = explode  # type: ignore[assignment]
    try:
        code, out = run(["creds", "explain", HOST])
    finally:
        subprocess.run = real_run  # type: ignore[assignment]
    assert code == 0, clean(out)
    assert "Secret(" not in out, "nothing was resolved, so no Secret should surface"


def test_creds_explain_quotes_a_host_that_would_break_the_suggested_command() -> None:
    """The suggested command is copy-pasted into a shell — a hostile host must not split."""
    hostile = "evil';touch /tmp/gateclerk-pwn;'"
    code, out = run(["creds", "explain", hostile, "-o", "json"])
    assert code == 0, clean(out)
    rows = json_rows(out)
    add = next(str(r["where"]) for r in rows if "add-generic-password" in str(r["where"]))
    argv = shlex.split(add)
    # Parsed back, the account must be ONE argv token equal to the host: no word splitting,
    # so `touch /tmp/gateclerk-pwn` can never become separate arguments.
    assert argv[argv.index("-a") + 1] == hostile, add
    assert "touch" not in argv, f"command injection survived quoting: {argv}"


# --- group contract ----------------------------------------------------------------------


def test_creds_group_appears_in_root_help() -> None:
    code, out = run(["--help"])
    assert code == 0
    assert "creds" in clean(out)


@pytest.mark.parametrize("args", [["creds"], ["creds", "check"], ["creds", "explain"]])
def test_creds_help_never_advertises_a_device_write(args: list[str]) -> None:
    """Hard rule from DESIGN.md: this connector must not grow a write surface.

    Whole-word match: a naive `"put " in text` trips over "out**put** format", which is
    in every command's help — a tripwire that fires on the word "output" is a tripwire
    nobody keeps.
    """
    code, out = run([*args, "--help"])
    assert code == 0
    lowered = clean(out).lower()
    for verb in ("put", "delete", "reboot", "shutdown", "update", "set "):
        assert not re.search(rf"\b{re.escape(verb.strip())}\b", lowered), (
            f"{args} mentions {verb!r}"
        )
