"""Repo hygiene: nothing in the offline test surface may name a real device.

The hard rule from docs/DESIGN.md is that fixtures and tests are synthetic — a recorded
response shape is fine, a recorded *address or credential* is not. Enforced
mechanically and generically, so this test never has to repeat a real address in order
to ban it, and keeps catching the mistake after the first live smoke run.
"""

from __future__ import annotations

import ipaddress
import re
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
TESTS = REPO_ROOT / "tests"

IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

# Only these ranges may appear as a device host in test material. Note Python's
# `is_private` also returns True for them, so a bare is_private check would reject the
# very addresses this repo is supposed to use — hence the explicit allowlist.
DOC_RANGES = tuple(
    ipaddress.ip_network(net) for net in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24")
)

#: A password-looking value in test material must be recognisably fake.
PLACEHOLDER = re.compile(
    r"^(?:$|x+$|\*+$|(?i:fake|test|dummy|example|changeme|secret|placeholder|pw)[-_a-z0-9]*)$"
)
SECRET_ASSIGN = re.compile(
    r"""(?i)\b(?:password|passwd|pwd|secret|token)\s*["']?\s*[:=]\s*["']([^"']*)["']"""
)


def hygiene_targets() -> list[Path]:
    return sorted(
        p for p in TESTS.rglob("*") if p.is_file() and p.suffix in {".py", ".json", ".md"}
    )


def test_hygiene_has_targets() -> None:
    assert hygiene_targets(), "sanity: the hygiene test must actually have files to read"


@pytest.mark.parametrize("path", hygiene_targets(), ids=lambda p: str(p.relative_to(REPO_ROOT)))
def test_no_real_device_address_in_test_surface(path: Path) -> None:
    offenders = [
        ip for ip in IPV4.findall(path.read_text(encoding="utf-8")) if not _allowed_host(ip)
    ]
    assert not offenders, (
        f"{path.relative_to(REPO_ROOT)} hard-codes {offenders} — use a TEST-NET address "
        "(192.0.2.x / 198.51.100.x / 203.0.113.x); a real device host is config, not a fixture"
    )


def _allowed_host(addr: str) -> bool:
    try:
        ip = ipaddress.ip_address(addr)
    except ValueError:
        return False
    return ip.is_loopback or any(ip in net for net in DOC_RANGES)


def test_allowlist_is_only_the_documented_ranges() -> None:
    """Guard the guard: widening the allowlist to a routable range is the loophole."""
    for net in DOC_RANGES:
        assert net.network_address.is_global is False, f"{net} must not be a routable range"
    assert len(DOC_RANGES) == 3


def test_no_non_placeholder_secret_values_in_test_surface() -> None:
    """Test material may carry a fake password, never anything that looks real."""
    bad: list[str] = []
    for path in hygiene_targets():
        text = path.read_text(encoding="utf-8")
        for match in SECRET_ASSIGN.finditer(text):
            value = match.group(1)
            if not PLACEHOLDER.match(value):
                bad.append(
                    f"{path.relative_to(REPO_ROOT)}:{text[: match.start()].count(chr(10)) + 1}"
                )
    assert not bad, "non-placeholder secret-looking value in test material: " + "; ".join(bad)


def test_no_env_file_in_the_working_tree() -> None:
    """`.env` is gitignored from commit 1; one appearing here means a credential shipped."""
    stray = [
        p.name
        for p in REPO_ROOT.iterdir()
        if p.name.startswith(".env") and p.name != ".env.example"
    ]
    assert not stray, f"credential file present in the working tree: {stray}"
