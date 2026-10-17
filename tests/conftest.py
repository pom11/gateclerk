"""Offline test setup for the whole suite.

Three hard guarantees, all mechanical rather than advisory:

1. No test may reach the network. A real Hikvision terminal sits on a site LAN and a
   stray socket here would either hang CI or, worse, hit a door controller. `netoff`
   (autouse) monkeypatches socket to raise. `tests/live/` re-enables it deliberately
   and only under GATECLERK_LIVE=1.
2. The live suite is inert unless a human opts in, twice: `-m "not live"` in
   pyproject addopts, plus the GATECLERK_LIVE gate below.
3. `cli_child` runs the real CLI in a **subprocess** whose socket layer is guarded, for
   the cases the in-process guard cannot express: code paths where the network failure
   itself is the thing under test (a host name that dies in the IDNA encoder, say), and
   the `main()`/console-script entry point, which the in-process CliRunner does not use.
   The child refuses to resolve a name or build a socket; the only way a test there can
   pass is if the code handles the failure without ever needing either.
4. The run must import `gateclerk` from the checkout it lives in, never from another
   checkout's editable install. See `_source_guard.py`: the main checkout installs
   gateclerk editable, so a bare `pytest` in a git worktree imports MAIN's `src/gateclerk`
   and can print a green suite for code the worktree does not contain (this happened on
   t_7b073d11). `pytest_configure` below aborts before collection when it detects that.
"""

from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

import pytest

from _source_guard import mismatch_message, resolve_package_origin


class NetworkBlockedError(RuntimeError):
    """Raised when an offline test tries to open a socket."""


def _blocked(*args: object, **kwargs: object) -> None:
    raise NetworkBlockedError(
        "offline test tried to use the network — tests must run against fixtures "
        "(tests/fixtures/) or httpx.MockTransport; see docs/DESIGN.md 'Testing'"
    )


def enforce_source_guard(checkout_root: Path) -> None:
    """Raise `pytest.UsageError` unless `gateclerk` resolves under `checkout_root`.

    Takes the plain root path rather than a `Config` so the decision is testable without
    fabricating a pytest session; the hook below is the only caller.
    """
    message = mismatch_message(resolve_package_origin(), checkout_root)
    if message is not None:
        raise pytest.UsageError(message)


def pytest_configure(config: pytest.Config) -> None:
    """Abort the session (exit 4, nothing collected or run) on a wrong-checkout gateclerk.

    Runs before collection, so no green result can ever be printed for a tree that
    the imported package does not belong to. See tests/_source_guard.py for why.
    """
    enforce_source_guard(Path(config.rootpath))


@pytest.fixture(autouse=True)
def netoff(monkeypatch: pytest.MonkeyPatch, request: pytest.FixtureRequest) -> None:
    """Kill socket I/O for offline tests. Live tests opt out via their own marker."""
    if request.node.get_closest_marker("live"):
        return
    for name in ("socket", "create_connection", "getaddrinfo"):
        monkeypatch.setattr(socket, name, _blocked, raising=False)


@pytest.fixture
def live_opt_in() -> None:
    """Live tests depend on this: hard gate on an explicit human opt-in."""
    if os.environ.get("GATECLERK_LIVE") != "1":
        pytest.skip("live tests need GATECLERK_LIVE=1 (a human runs them; CI never sets it)")


def is_live_enabled() -> bool:
    return os.environ.get("GATECLERK_LIVE") == "1"


def pytest_collection_modifyitems(
    session: object, config: object, items: list[pytest.Item]
) -> None:
    """Mark every non-live test `unit`, so `-m unit` selects the offline set.

    Without this the `unit` marker is registered but carried by nothing, and
    `-m unit` would silently run zero tests — a selector that looks like it works.
    """
    for item in items:
        if item.get_closest_marker("live") is None:
            item.add_marker("unit")


@pytest.fixture
def network_blocked() -> type[Exception]:
    """Hand the guard's exception class to a test that asserts the guard bites.

    Passed as a fixture rather than imported so tests never depend on sys.path
    games around importing `tests.conftest` itself.
    """
    return NetworkBlockedError


# --- the guarded subprocess ---------------------------------------------------------------
#
# Why a subprocess at all: the in-process `netoff` guard replaces socket I/O with a
# raise, which is right for almost everything but cannot express two cases —
#   * a test whose SUBJECT is the failure to encode/resolve a host name (patching
#     getaddrinfo wholesale would hide the very IDNA step under test), and
#   * the `main()`/console-script path, which `typer.testing.CliRunner` bypasses.
#
# The child reproduces the OS's behaviour deterministically, with no egress:
# `socket.getaddrinfo` performs the idna encode CPython would do (so a malformed name
# still fails exactly as it fails in production) and then refuses the lookup as
# `gaierror(8, ...)`, which is what a real resolver answers for a name it does not know.
# httpx wraps that as `ConnectError`, so the transport behaves as it would on the LAN —
# but no packet can leave, and the child also refuses to construct a socket at all.
# Every name that survives the encode is recorded, so a test can assert whether the code
# under test died *before* or *after* the resolver was reached.

_CHILD_PROGRAM = r"""
import json, sys
import gateclerk.cli                     # FIRST: importing httpx/ssl needs a real socket
import socket

_reached_resolver = []

def _encode_then_refuse(name, *args, **kwargs):
    str(name).encode("idna")           # the exact step production fails in
    _reached_resolver.append(str(name))  # only a name that ENCODES gets this far
    raise socket.gaierror(8, "nodename nor servname provided, or not known")

socket.getaddrinfo = _encode_then_refuse
socket.socket = lambda *a, **k: (_ for _ in ()).throw(
    AssertionError("child constructed a socket"))

_exit = 99
try:
    _exit = gateclerk.cli.main()
except BaseException:                   # noqa: BLE001
    import traceback
    traceback.print_exc(file=sys.stderr)
print("@@GATECLERK_CHILD@@" + json.dumps(
    {"exit": _exit, "reached_resolver": _reached_resolver}))
sys.exit(_exit)
"""


@dataclass(frozen=True, slots=True)
class ChildResult:
    """What the guarded child reported: the CLI's exit code, its stdout, and every name
    that got as far as a resolver lookup (empty means the code died before DNS)."""

    exit_code: int
    stdout: str
    stderr: str
    reached_resolver: list[str] = field(default_factory=list)

    @property
    def json_rows(self) -> list[dict]:
        """JSON lines the CLI printed, for --json assertions."""
        rows = []
        for line in self.stdout.splitlines():
            line = line.strip()
            if line.startswith("{") or line.startswith("["):
                rows.append(json.loads(line))
        return rows

    def last_json(self) -> dict:
        return self.json_rows[-1]

    @property
    def all_output(self) -> str:
        return self.stdout + self.stderr


@pytest.fixture
def cli_child() -> Callable[..., ChildResult]:
    """Run `gateclerk.cli.main()` in a socket-guarded child process.

    Deliberately NOT the CliRunner: this exercises the real entry point over the real
    httpx transport (no monkeypatching), which is the only way to test a failure that
    happens *inside* the transport.

    Proxy variables are stripped from the child's environment. These tests assert
    WHERE the request died (before/after the resolver), and httpx's `trust_env` would
    otherwise obey any HTTP(S)_PROXY the harness sets — CI's no-egress wall points the
    proxy at a blackhole (see .github/workflows/ci.yml), which would move the failure
    site to the proxy hop and break the assertion without any egress. Stripping the
    proxy does not weaken the wall: the child still refuses to resolve a name or build
    a socket, whatever the environment says.
    """

    def run(*args: str, timeout: float = 120.0) -> ChildResult:
        env = {
            k: v
            for k, v in os.environ.items()
            if k.upper() not in {"HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY"}
        }
        proc = subprocess.run(  # noqa: S603 — argv list, no shell, fixed program text
            [sys.executable, "-c", _CHILD_PROGRAM, *args],
            capture_output=True,
            text=True,
            timeout=timeout,
            env=env,
        )
        marker = "@@GATECLERK_CHILD@@"
        lines = [ln for ln in proc.stdout.splitlines() if ln.startswith(marker)]
        if not lines:
            raise AssertionError(
                "the guarded child did not report; its stderr was:\n" + proc.stderr
            )
        report = json.loads(lines[-1][len(marker) :])
        stdout = "\n".join(ln for ln in proc.stdout.splitlines() if not ln.startswith(marker))
        assert report["exit"] == proc.returncode, (report, proc.returncode)
        return ChildResult(
            exit_code=proc.returncode,
            stdout=stdout,
            stderr=proc.stderr,
            reached_resolver=report["reached_resolver"],
        )

    return run
