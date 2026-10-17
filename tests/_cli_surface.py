"""The declared CLI surface, read from Click's parameter objects instead of rendered help.

Why not `assert "--host" in help_output`

    Typer renders help through Rich, and Rich's output depends on the terminal it believes
    it is writing to. Typer tells Rich it has a terminal whenever `GITHUB_ACTIONS` is set
    (no pty needed), so CI and a developer laptop get different bytes for the same command:
    CI splits `-` and `-host` into separate styled spans, and the CI log for card p1-08 also
    showed Rich collapsing a block of the options panel to `...`, which is how `--host` and
    `--since` went missing there while passing locally.

    Stripping the ANSI fixes the first problem (and the suite does strip it, as
    `test_cli.py` / `test_cli_credentials.py` already did). It cannot fix the second: text
    Rich decided not to print is not recoverable by any amount of post-processing.

    So the questions these tests actually ask — does this command accept `--host`, is the
    port default 80, does the help promise a write — are answered from the command
    definition, which Click already holds in a form that has nothing to do with terminal
    geometry. Rendering is still exercised (the `--help` path must run and print), just not
    used as the source of truth for flag presence.

A test helper, not product code: nothing under `src/gateclerk` imports it.
"""

from __future__ import annotations

import re
from typing import Any

import typer


def command_at(app: typer.Typer, words: list[str]) -> Any:
    """Resolve the Click command for words like ["device", "info"].

    Raises KeyError rather than returning None: a command that is not there is either a test
    bug or a real regression, and in both cases the caller must not go on asserting against
    None and call it a pass.
    """
    cmd: Any = typer.main.get_command(app)
    for word in words:
        sub = getattr(cmd, "commands", {}).get(word)
        if sub is None:
            raise KeyError(f"no command at {' '.join(words)} (stopped at {word!r})")
        cmd = sub
    return cmd


def declared_flags(cmd: Any) -> set[str]:
    """Every option name the command declares, long and short."""
    names: set[str] = set()
    for param in cmd.params:
        names.update(getattr(param, "opts", ()) or ())
        names.update(getattr(param, "secondary_opts", ()) or ())
    return names


def declared_param(cmd: Any, flag: str) -> Any:
    """The Click parameter declaring `flag` (e.g. "--port"). KeyError if the command has none."""
    for param in cmd.params:
        if flag in (getattr(param, "opts", ()) or ()) or flag in (
            getattr(param, "secondary_opts", ()) or ()
        ):
            return param
    raise KeyError(f"{cmd.name} declares no {flag}")


def declared_prose(cmd: Any) -> str:
    """Every piece of help text a command can show, whitespace collapsed.

    Assembled from the definition rather than the render, deliberately: this is the input to
    the "no mutating verb in any help screen" tripwire, and a tripwire that reads a render
    Rich may have truncated can pass *because* the offending line was elided. Reading the
    definition makes that failure mode impossible.
    """
    parts: list[str] = [cmd.short_help or "", cmd.help or ""]
    for param in cmd.params:
        parts.append(" ".join(getattr(param, "opts", ()) or ()))
        parts.append(getattr(param, "help", "") or "")
        metavar = getattr(param, "metavar", None)
        if metavar:
            parts.append(str(metavar))
    return re.sub(r"\s+", " ", " ".join(part for part in parts if part))
