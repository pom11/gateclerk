"""Malformed hosts that survive httpx's URL parser and die in the IDNA/DNS layer.

Review round 2, finding 1. The exit-code contract was still broken for the reviewer's four
host shapes (`.localhost`, `localhost..`, an invalid `xn--` A-label, any label >= 64
chars): they pass httpx's URL validation, then CPython's `socket.getaddrinfo` idna-encodes
the name and raises `UnicodeError("label empty or too long")` — or, for the A-label,
httpx's own URL layer raises `idna.IDNAError` while preparing the Host header. Neither
class is an `httpx.TransportError`, so the transport's `except httpx.TransportError` never
wrapped them and the command's `except GateclerkError` never mapped them: real subprocess,
exit 1, full Rich traceback.

These run through `cli_child` (tests/conftest.py): the real `main()`, the real httpx
transport, **no monkeypatching** — because the failure under test happens *inside* the
transport, which is exactly what the FakeDevice-backed tests in
test_cli_capabilities.py cannot reach. The child still cannot reach a device: it performs
the idna encode the OS would, refuses the lookup itself as `gaierror(8)`, and refuses to
construct a socket at all. It reports every name that got as far as the resolver, and
each test asserts on that to prove *where* the failure happened.

Exit-code choice: **4** (`DEVICE_ERROR_EXIT`), matching the reviewer's suggestion, because
the transport already treats an unresolvable name as transport — `--host
nosuchhost.invalid` reaches the resolver, gets `[Errno 8] nodename nor servname provided`
and exits 4. A name that cannot be *encoded* is strictly less interesting than a name that
cannot be resolved, so it gets the same code; mapping it to 2 would claim the operator's
config is wrong when what failed was DNS.
"""

from __future__ import annotations

from typing import Any

import pytest

from gateclerk.cli import DEVICE_ERROR_EXIT

#: Assembled, not written as a literal: this is not a domain anyone owns, it is the
#: `xn--` prefix (which httpx treats as an A-label and idna then refuses to decode) with
#: a payload that can never be valid punycode.
INVALID_A_LABEL = "xn--" + "$bad" + ".example"

#: The reviewer's four shapes, plus one that separates the two error sites: a 63-char
#: label is legal and a 64-char one is not, so a name mixing both fails on the *second*
#: label — proving the failure is per-label IDNA, not a total-length cap.
IDNA_FATAL_HOSTS = (
    ".localhost",
    "localhost..",
    INVALID_A_LABEL,
    "x" * 64 + ".example",
    "x" * 300,
    "x" * 63 + "." + "y" * 64,
)

BASE = ["device", "capabilities", "--user", "admin", "--password", "fakepw", "--json"]


def _assert_no_traceback(result: Any) -> None:
    lowered = result.all_output.lower()
    assert "traceback" not in lowered, result.stderr[:900]
    for frame in ("httpcore", "httpx/", "idna/core.py", "encodings/idna.py"):
        assert frame not in lowered, f"raw transport frame leaked to the operator: {frame}"


@pytest.mark.parametrize("host", IDNA_FATAL_HOSTS)
def test_idna_fatal_host_exits_device_error_with_no_traceback(cli_child, host: str) -> None:
    """The contract: a documented exit code, a machine-readable error, no traceback."""
    result = cli_child(*BASE, "--host", host)
    assert result.exit_code == DEVICE_ERROR_EXIT, (
        f"host {host!r} exited {result.exit_code}; stderr was:\n{result.stderr[:700]}"
    )
    _assert_no_traceback(result)
    doc = result.last_json()
    assert doc["exit_code"] == DEVICE_ERROR_EXIT
    assert doc["error"]
    # The message must say what died and what to check, not just echo a codec word.
    assert "host" in doc["error"].lower()


@pytest.mark.parametrize("host", IDNA_FATAL_HOSTS)
def test_idna_fatal_host_never_reaches_the_resolver_or_a_socket(cli_child, host: str) -> None:
    """Offline proof for the same run: the child records every name that got as far as a
    resolver lookup and cannot build a socket at all.

    A well-formed name WOULD appear there (the child answers gaierror, so the transport
    behaves as on the LAN); these fail during the encode, one step earlier, so the list
    must be empty — which is also the assertion that this test is exercising the IDNA path
    and not merely a refused lookup."""
    result = cli_child(*BASE, "--host", host)
    assert result.exit_code == DEVICE_ERROR_EXIT, result.stderr[:700]
    assert result.reached_resolver == [], f"{host!r} got as far as a resolver lookup"


def test_plain_output_is_not_a_traceback_either(cli_child) -> None:
    """The same shapes without --json: the human view must be the red one-line error, not
    a Rich traceback. (The reviewer's repro used --json; the default format is the one an
    operator actually types.)"""
    result = cli_child(
        "device",
        "capabilities",
        "--host",
        ".localhost",
        "--user",
        "admin",
        "--password",
        "fakepw",
    )
    assert result.exit_code == DEVICE_ERROR_EXIT
    _assert_no_traceback(result)
    assert "error:" in result.stdout.lower()


def test_unresolvable_well_formed_name_is_still_transport_exit_4(cli_child) -> None:
    """The class this fix aligns with: a *well-formed* name that does not resolve does
    reach the resolver (recorded, then refused by the child) and also exits 4. If these
    two ever disagree, the exit table has drifted."""
    result = cli_child(*BASE, "--host", "nosuchhost.invalid")
    assert set(result.reached_resolver) == {"nosuchhost.invalid"}, result.reached_resolver
    assert result.reached_resolver, "a well-formed name must be handed to the resolver"
    assert result.exit_code == DEVICE_ERROR_EXIT
    _assert_no_traceback(result)


def test_a_legal_host_is_not_refused_by_the_encode_step(cli_child) -> None:
    """Negative control: the new clause is not just rejecting everything. A well-formed IP
    is handed to the resolver (the child refuses it, so no device is touched) instead of
    dying in the idna encode."""
    result = cli_child(*BASE, "--host", "192.0.2.10")
    assert set(result.reached_resolver) == {"192.0.2.10"}, (
        "a legal host must reach the resolver, not die in the idna encode"
    )
    assert result.exit_code == DEVICE_ERROR_EXIT


def test_entry_point_converts_a_usage_error_to_exit_2(cli_child) -> None:
    """The sibling of finding 1 — same class of defect, found by probing the other entry
    path. `main()` had `except typer.exceptions.UsageError`, a name that has never existed
    in any typer release: typer >= 0.25 vendors click as `typer._click`, so the *except
    clause itself* raised AttributeError and every usage error through the console-script
    path exited 1 with a traceback instead of click's exit 2. CliRunner never noticed
    because it does not call `main()`."""
    result = cli_child("--nope")
    assert result.exit_code == 2, f"usage error exited {result.exit_code}: {result.stderr[:400]}"
    assert "no such option" in result.all_output.lower()
    _assert_no_traceback(result)
    assert "attributeerror" not in result.all_output.lower()


def test_entry_point_rejects_an_unknown_option_on_a_subcommand(cli_child) -> None:
    """Same guard, one level down the tree — an unknown option at the root and an unknown
    option on a command are different click exception classes."""
    result = cli_child("device", "capabilities", "--bogus")
    assert result.exit_code == 2
    _assert_no_traceback(result)
