"""Proves the offline guard in tests/conftest.py actually bites.

If this test ever passes while sockets work, the CI 'no device in CI' promise is
decorative — fix the guard before trusting any other test in this repo.
"""

from __future__ import annotations

import socket

import httpx
import pytest


def test_raw_connect_is_blocked(network_blocked: type[Exception]) -> None:
    with pytest.raises(network_blocked):
        socket.create_connection(("192.0.2.10", 80), timeout=1)


def test_dns_is_blocked(network_blocked: type[Exception]) -> None:
    with pytest.raises(network_blocked):
        socket.getaddrinfo("example.com", 80)


def test_constructing_a_socket_is_blocked(network_blocked: type[Exception]) -> None:
    with pytest.raises(network_blocked):
        socket.socket(socket.AF_INET, socket.SOCK_STREAM)


def test_httpx_cannot_escape_the_guard(network_blocked: type[Exception]) -> None:
    """httpx is the real client here, so the guard has to hold for it too."""
    with pytest.raises(network_blocked):
        httpx.get("http://192.0.2.10/ISAPI/System/deviceInfo?format=json", timeout=1)


def test_mocks_are_allowed() -> None:
    """Blocking the network must not block test doubles (MockTransport is the way)."""
    transport = httpx.MockTransport(lambda request: httpx.Response(200, json={"ok": True}))
    with httpx.Client(transport=transport, base_url="http://device") as client:
        assert client.get("/ISAPI/System/deviceInfo").json() == {"ok": True}
