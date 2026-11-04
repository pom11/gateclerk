"""Tests for `scripts/build_dist.py`, `scripts/smoke_artifact.py`, and Homebrew formula
(cards t_f9254c12 RELEASE-PACKAGING & t_6be29819 SMOKE-BUILD).
"""

from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]


def _load_script(name: str):
    path = REPO_ROOT / "scripts" / name
    spec = importlib.util.spec_from_file_location(name.removesuffix(".py"), path)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_version_single_source_and_build_dist_creates_artifacts_and_formula(
    tmp_path: Path,
) -> None:
    build_dist = _load_script("build_dist.py")
    ver = build_dist.verify_version_parity(REPO_ROOT)
    assert ver == "0.1.0"

    dist_dir = tmp_path / "dist"
    tap_dir = tmp_path / "tap"
    built = build_dist.build_all(repo_dir=REPO_ROOT, dist_dir=dist_dir, tap_dir=tap_dir)

    assert built["tarball"].is_file()
    assert built["sha256sums"].is_file()
    assert built["formula"].is_file()
    assert (tap_dir / "Formula" / "gateclerk.rb").is_file()

    formula_text = built["formula"].read_text(encoding="utf-8")
    assert "class Gateclerk < Formula" in formula_text
    assert f'version "{ver}"' in formula_text
    assert "{{" not in formula_text

    # Deterministic rebuild produces identical SHA256SUMS
    dist_dir_2 = tmp_path / "dist2"
    built_2 = build_dist.build_all(repo_dir=REPO_ROOT, dist_dir=dist_dir_2)
    assert built["sha256sums"].read_text() == built_2["sha256sums"].read_text()


def test_smoke_artifact_verifies_sha256sums_and_runs_end_to_end(tmp_path: Path) -> None:
    build_dist = _load_script("build_dist.py")
    smoke_mod = _load_script("smoke_artifact.py")

    dist_dir = tmp_path / "dist"
    built = build_dist.build_all(repo_dir=REPO_ROOT, dist_dir=dist_dir)
    verified = smoke_mod.verify_sha256sums(dist_dir)
    assert len(verified) == 4  # tarball + 3 OS zipapps

    target = smoke_mod.detect_host_target()
    report = smoke_mod.smoke_artifact(built[target])
    assert report["version"] == "gateclerk 0.1.0"
    assert report["demo_ok"] is True
    assert report["status_verdict"] in ("ok", "warn")

    # Tampering with an artifact must fail verify_sha256sums before execution
    built[target].write_bytes(built[target].read_bytes() + b"\n# tampered\n")
    with pytest.raises(RuntimeError, match="SHA256 mismatch"):
        smoke_mod.verify_sha256sums(dist_dir)
