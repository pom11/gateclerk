"""Live device smoke tests — human-run only, never CI.

Two independent gates: `-m "not live"` in pyproject addopts excludes this directory,
and the `live_opt_in` fixture skips unless GATECLERK_LIVE=1. Running these at all means
talking to real door hardware on a site LAN, so the concrete commands stay a human's
call.

Run (by a human, on the site LAN, after the transport + creds cards land):

    GATECLERK_LIVE=1 uv run pytest -m live tests/live -s
"""

from __future__ import annotations

import pytest


@pytest.mark.live
def test_placeholder_device_reachable(live_opt_in: None) -> None:
    """Proves the live lane is wired and the opt-in gate works.

    Deliberately does NOT open a socket yet: p1-03 owns the transport and p1-02 owns
    credentials, and this card must never contact the device (hard rule). Replace the
    body with a real `device info` round-trip once those land.
    """
    pytest.skip(
        "live smoke assertions arrive with p1-03 (transport) + p1-02 (creds); "
        "see docs/internal/DESIGN.md P1 exit criteria"
    )
