"""The one sanctioned way for a single offline test to re-admit loopback sockets.

Why this is a module and not `monkeypatch.setattr(socket, "socket", socket.socket)`:
the autouse `netoff` fixture (tests/conftest.py) has ALREADY replaced those three
attributes by the time any test-scoped fixture runs, so a seam that "restores" them
from the live module would capture the blocker and re-install it — a seam that looks
like an opt-out and is silently a no-op. The only honest capture is one taken at
import time, before any patch exists, which is exactly what this module's import does
(conftest imports it at collection, before fixture setup ever runs).

Scope discipline: `netoff` exists to stop a stray socket reaching site LAN hardware,
not to forbid a loopback listener to a server living in this same pytest process.
Tests that need one (the DEMO-DEVICE contract, tests/test_demo_device.py) call
`release(monkeypatch)`; every other test keeps the guard. The SYNTHETIC-ONLY LAW
(still enforced by tests/test_repo_hygiene.py) is what keeps even a released test
from naming a real host.

`release` also unsets the proxy variables for the test's duration, and this is not a
convenience — it is the same wall CI itself enforces (".github/workflows/ci.yml"
points HTTP(S)_PROXY at a dead port with NO_PROXY emptied; httpx honors those vars
per-request). A released test connecting to 127.0.0.1 would otherwise be CONNECT-ed
to the dead proxy: the CI failure this line prevents. The in-process socket guard
stays primary; a proxy setting is only how a *released* test could still fail to
reach the loopback server it is meant to talk to.

A test helper, not product code: nothing under `src/gateclerk` imports it.
"""

from __future__ import annotations

import socket
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    import pytest

#: The genuine attributes, captured at import time — the ONLY trustworthy snapshot,
#: because after fixture setup starts, `socket.socket` may already be the blocker.
REAL = {name: getattr(socket, name) for name in ("socket", "create_connection", "getaddrinfo")}

#: Env vars that would route even a loopback connection through a proxy (CI sets them
#: as the outer network wall; httpx reads them per-request).
_PROXY_VARS = ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy")


def release(monkeypatch: pytest.MonkeyPatch) -> None:
    """Put the real socket layer back for THIS test; monkeypatch restores whatever
    `netoff` had installed when the test's own teardown (which runs first) undoes this.
    """
    for name, value in REAL.items():
        monkeypatch.setattr(socket, name, value, raising=False)
    # Same teardown order logic: the proxy env comes back as CI had it afterwards.
    for name in _PROXY_VARS:
        monkeypatch.delenv(name, raising=False)
