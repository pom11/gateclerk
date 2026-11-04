"""Public-release tree audit (card t_78f958d5, HISTORY-PUBLIC-AUDIT).

Sweeps every tracked file at HEAD (`git ls-files`) to guarantee:
  1. Zero occurrences of the pre-cutover internal product/tenant names.
  2. Zero private LAN or CGNAT/tailnet IPv4 addresses outside RFC 5737 (`192.0.2.0/24`,
     `198.51.100.0/24`, `203.0.113.0/24`), loopback (`127.0.0.1`), and the unspecified
     address.
  3. Zero deployed Cloud Run / Cloud Functions ingest hostnames or tenant GUIDs.
  4. Zero AI attribution lines in tracked files.
  5. Root `LICENSE` (MIT) and `docs/PUBLIC-RELEASE-AUDIT.md` exist and agree with
     `pyproject.toml`.
"""

from __future__ import annotations

import ipaddress
import re
import shutil
import subprocess
import tomllib
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]

DOC_NETWORKS = (
    ipaddress.ip_network("192.0.2.0/24"),
    ipaddress.ip_network("198.51.100.0/24"),
    ipaddress.ip_network("203.0.113.0/24"),
)
CGNAT_NETWORK = ipaddress.IPv4Network(((100 << 24) | (64 << 16), 10))

IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

# Constructed by concatenation so this file itself contains zero forbidden tokens.
_LEGACY_A = "p" + "ontaj"
_LEGACY_B = "eco" + "fire"
_LEGACY_C = "pom_" + "251026"
_LEGACY_D = "bbrytgvt" + "2q"
_LEGACY_E = "09ed69" + "63"
_LEGACY_F = "bdb01c" + "50"
_RUN_APP = "a.run" + ".app"
_CF_NET = "cloudfunctions" + ".net"
_CO_AUTH = "co-authored" + "-by:"
_GEN_CLAUDE = "generated with " + "claude"

FORBIDDEN_TOKEN_RE = re.compile(
    rf"(?i)(?:{_LEGACY_A}|{_LEGACY_B}|{_LEGACY_C}|{_LEGACY_D}|{_LEGACY_E}|{_LEGACY_F}"
    rf"|{re.escape(_RUN_APP)}|{re.escape(_CF_NET)}|{_CO_AUTH}|{_GEN_CLAUDE})"
)


def _tracked_files() -> list[Path]:
    git_bin = shutil.which("git") or "/usr/bin/git"
    out = subprocess.check_output(  # noqa: S603
        [git_bin, "ls-files"], cwd=REPO_ROOT, text=True
    ).splitlines()
    return [REPO_ROOT / rel for rel in out if (REPO_ROOT / rel).is_file()]


def test_head_tree_has_zero_legacy_or_tenant_or_attribution_tokens() -> None:
    hits: list[str] = []
    for path in _tracked_files():
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        rel = path.relative_to(REPO_ROOT).as_posix()
        for lineno, line in enumerate(text.splitlines(), 1):
            m = FORBIDDEN_TOKEN_RE.search(line)
            if m:
                hits.append(f"{rel}:{lineno}: {m.group(0)}")
    assert not hits, f"forbidden token(s) in tracked files: {hits[:20]}"


def test_head_tree_has_zero_private_or_tailnet_ipv4_addresses() -> None:
    hits: list[str] = []
    for path in _tracked_files():
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        rel = path.relative_to(REPO_ROOT).as_posix()
        for lineno, line in enumerate(text.splitlines(), 1):
            for m in IPV4_RE.finditer(line):
                raw_ip = m.group(0)
                try:
                    ip = ipaddress.IPv4Address(raw_ip)
                except ValueError:
                    continue
                if ip.is_loopback or ip.is_unspecified or any(ip in net for net in DOC_NETWORKS):
                    continue
                if ip.is_private or ip in CGNAT_NETWORK:
                    hits.append(f"{rel}:{lineno}: {raw_ip}")
    assert not hits, f"private/CGNAT IPv4 address(es) in tracked files: {hits[:20]}"


def test_mit_license_and_public_audit_doc_present() -> None:
    license_path = REPO_ROOT / "LICENSE"
    assert license_path.is_file()
    license_text = license_path.read_text(encoding="utf-8")
    assert "MIT License" in license_text
    assert "Permission is hereby granted, free of charge" in license_text

    pyproject = tomllib.loads((REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    assert pyproject["project"]["license"] == {"text": "MIT"}
    assert (REPO_ROOT / "docs" / "PUBLIC-RELEASE-AUDIT.md").is_file()
