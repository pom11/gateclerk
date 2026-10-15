"""Offline test setup for the whole suite.

Two hard guarantees, both mechanical rather than advisory:

1. No test may reach the network. A real Hikvision terminal sits on a site LAN and a
   stray socket here would either hang CI or, worse, hit a door controller. `netoff`
   (autouse) monkeypatches socket to raise. `tests/live/` re-enables it deliberately
   and only under GATECLERK_LIVE=1.
2. The live suite is inert unless a human opts in, twice: `-m "not live"` in
   pyproject addopts, plus the GATECLERK_LIVE gate below.
"""

from __future__ import annotations

import os
import socket

import pytest


class NetworkBlockedError(RuntimeError):
    """Raised when an offline test tries to open a socket."""


def _blocked(*args: object, **kwargs: object) -> None:
    raise NetworkBlockedError(
        "offline test tried to use the network — tests must run against fixtures "
        "(tests/fixtures/) or httpx.MockTransport; see docs/DESIGN.md 'Testing'"
    )


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
