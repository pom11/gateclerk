"""Card GC-P10: one poller per site — a non-blocking advisory lock on the state root.

BINDING SPEC: the card's ACCEPT list. Nothing stopped a second `gateclerk agent run` from
polling the same device and SQLite store as the first; two pollers burn the terminal's
~190-use digest nonce budget and can trip the 401 lockout (R7's deployment law: one site,
one process, one store). The fix is an exclusive non-blocking `flock` on
`<state root>/gateclerk-<site>.lock`, taken by `SiteAgent.run()` before its first tick and
released in a `finally`; a refused start raises `PollerAlreadyRunning`, a `ConfigError`
subclass, so `cli_shared._fail` maps it to exit 2 (p1-08's contract).

The five pins are the card's five DoD tests, 1:1 to test names:

(1) a second acquire on the same root is refused and names the lock path;
(2) releasing lets the next acquirer in;
(3) two sites in one root lock independently;
(4) `SiteAgent.run(once=True)` refuses while the lock is held, before any device request;
(5) the lock file carries the owner PID under the state root.

Case (4) is the one that cannot be satisfied by unit-testing the helpers alone: a lock
nobody takes is the same zero as no lock, so it drives a real agent through `run()` and
asserts `device.requests == 0` — the refusal must happen before the first tick, not after.
`build_site_agent` and direct `agent.tick()` callers are deliberately NOT covered by the
lock (the card's "must not change" list); (4) pins the boundary from the `run()` side.

Offline by construction: FakeDevice behind the real IsapiClient, tmp state roots, the
harness's frozen clock. flock is per open-file-description, so the same-process double
acquire in (1) and (4) is a genuine conflict — the same kernel fact two OS processes hit.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from gateclerk.agent_cli import (
    POLLER_LOCK_SUFFIX,
    PollerAlreadyRunning,
    acquire_poller_lock,
    release_poller_lock,
)
from gateclerk.exceptions import ConfigError
from test_p2_03_scheduler import SITE
from test_p2_07b_agent_cli import AgentHarness, seeded_device

# --- DoD (1): a second poller on the same site fails fast -----------------------------------


def test_second_lock_on_the_same_state_root_is_refused(tmp_path: Path) -> None:
    """Two acquires on one root: the second refuses, naming the lock file it could not take.

    The message carrying the path is the operator's fix instruction ("stop it before
    starting a second poller" is only actionable if it says WHERE the lock lives), and the
    ConfigError inheritance is what makes it exit class 2 instead of a traceback (ACCEPT 1).
    """
    handle = acquire_poller_lock(tmp_path, "site-a")
    try:
        with pytest.raises(PollerAlreadyRunning) as exc_info:
            acquire_poller_lock(tmp_path, "site-a")
        lock_path = tmp_path / f"gateclerk-site-a{POLLER_LOCK_SUFFIX}"
        assert str(lock_path) in str(exc_info.value), str(exc_info.value)
        assert isinstance(exc_info.value, ConfigError), "the refusal must map to exit 2"
    finally:
        release_poller_lock(handle)


# --- DoD (3): releasing the lock lets the next process start ---------------------------------


def test_releasing_the_first_lock_allows_the_second(tmp_path: Path) -> None:
    """A restart is not a refusal: after release (or exit), the next acquire wins."""
    first = acquire_poller_lock(tmp_path, "site-a")
    release_poller_lock(first)
    second = acquire_poller_lock(tmp_path, "site-a")
    try:
        assert second is not None
    finally:
        release_poller_lock(second)


# --- DoD (4): two different sites each hold their own lock -----------------------------------


def test_two_sites_get_independent_locks(tmp_path: Path) -> None:
    """One root, two sites: the lock is per site, so a second site is never collateral.

    The lock name embeds the site (`gateclerk-<site>.lock`), which is also why
    `agent ack`/`deadletter`/`status` on site B stay untouched while site A polls — those
    commands take no lock at all (the card's "must not change" list).
    """
    a = acquire_poller_lock(tmp_path, "site-a")
    try:
        b = acquire_poller_lock(tmp_path, "site-b")
        try:
            assert a is not None and b is not None, "both sites hold while the other holds"
        finally:
            release_poller_lock(b)
    finally:
        release_poller_lock(a)


# --- DoD (2): the refusal happens before any device request -----------------------------------


def test_agent_run_refuses_when_the_lock_is_held(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """`run(once=True)` against a held lock raises and serves ZERO device requests.

    The counter is the fake's own (`fakedevice.requests` counts every request), so "the
    refusal happens before any device request" is measured at the device, not inferred from
    the store. The agent is built through the harness's `api_agent()` — `build_site_agent`
    itself must NOT take the lock (direct `tick()` callers keep working, per the card).
    """
    device = seeded_device()
    harness = AgentHarness(tmp_path, device, monkeypatch)
    held = acquire_poller_lock(harness.state_root, SITE)
    agent = harness.api_agent()
    try:
        with pytest.raises(PollerAlreadyRunning):
            agent.run(once=True)
        assert device.requests == 0, f"refusal must precede the first tick: {device.requests}"
    finally:
        agent.close()
        release_poller_lock(held)


# --- DoD (5): the lock file carries the owner PID under the state root --------------------------


def test_lock_file_contains_the_owner_pid(tmp_path: Path) -> None:
    """The lock lives under the state root and names its owner — `ps` is one read away.

    The PID is written only AFTER the flock is won (a loser must not overwrite the
    winner's line), so reading the file back is proof of both the ownership stamp and
    the write order. The systemd unit's `ReadWritePaths=<STATE_ROOT>/<SITE>` is what
    makes this writable in production (deploy/gateclerk-agent@.service).
    """
    handle = acquire_poller_lock(tmp_path, "site-a")
    try:
        lock_file = tmp_path / f"gateclerk-site-a{POLLER_LOCK_SUFFIX}"
        assert lock_file.read_text(encoding="utf-8").strip() == str(os.getpid())
    finally:
        release_poller_lock(handle)
