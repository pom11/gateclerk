"""Tests for `scripts/build_dist.py`, `scripts/smoke_artifact.py`, and Homebrew formula
(cards t_f9254c12 RELEASE-PACKAGING & t_6be29819 SMOKE-BUILD).
"""

from __future__ import annotations

import importlib.util
import re
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


def test_host_target_assertion_refuses_cross_platform_smoke(monkeypatch, tmp_path) -> None:
    """A portable `.pyz` runs anywhere, so CI must refuse to prove a target on the wrong host."""
    smoke_mod = _load_script("smoke_artifact.py")

    monkeypatch.setattr(smoke_mod.platform, "system", lambda: "Linux")
    monkeypatch.setattr(smoke_mod.platform, "machine", lambda: "x86_64")
    assert smoke_mod.detect_host_target() == "linux-x86_64"
    # Matching pairing is a no-op that reports the host.
    assert smoke_mod.assert_host_matches_target("linux-x86_64") == "linux-x86_64"

    # The old CI shape: linux-arm64 smoked from the x86_64 runner. Must be a hard error.
    with pytest.raises(RuntimeError, match="refusing to cross-smoke"):
        smoke_mod.assert_host_matches_target("linux-arm64")

    monkeypatch.setattr(smoke_mod.platform, "system", lambda: "Darwin")
    assert smoke_mod.detect_host_target() == "macos-arm64"
    with pytest.raises(RuntimeError, match="refusing to cross-smoke"):
        smoke_mod.assert_host_matches_target("linux-x86_64")


def test_main_refuses_mismatched_target_before_executing(monkeypatch, tmp_path) -> None:
    """`--expect-host-target` failure must happen before the artifact is executed."""
    smoke_mod = _load_script("smoke_artifact.py")
    build_dist = _load_script("build_dist.py")
    dist_dir = tmp_path / "dist"
    build_dist.build_all(repo_dir=REPO_ROOT, dist_dir=dist_dir)

    monkeypatch.setattr(smoke_mod.platform, "system", lambda: "Linux")
    monkeypatch.setattr(smoke_mod.platform, "machine", lambda: "x86_64")

    def _boom(*args, **kwargs):  # pragma: no cover - must never run
        raise AssertionError("artifact executed despite host/target mismatch")

    monkeypatch.setattr(smoke_mod, "smoke_artifact", _boom)

    with pytest.raises(RuntimeError, match="refusing to cross-smoke"):
        smoke_mod.main(
            [
                "--dist-dir",
                str(dist_dir),
                "--target",
                "linux-arm64",
                "--expect-host-target",
                "linux-arm64",
            ]
        )


def test_print_checks_emits_sha256sum_verdict_lines(tmp_path, capsys) -> None:
    build_dist = _load_script("build_dist.py")
    smoke_mod = _load_script("smoke_artifact.py")

    dist_dir = tmp_path / "dist"
    build_dist.build_all(repo_dir=REPO_ROOT, dist_dir=dist_dir)
    verified = smoke_mod.verify_sha256sums(dist_dir)

    smoke_mod.print_sha256_check_lines(dist_dir, verified)
    lines = capsys.readouterr().out.strip().splitlines()
    assert len(lines) == 4
    digests = {}
    for line in lines:
        digest, name_verdict = line.split("  ", 1)
        name, _, verdict = name_verdict.rpartition(": ")
        assert verdict == "OK", line
        assert len(digest) == 64, line
        digests[name] = digest
    assert digests["gateclerk-0.1.0-linux-arm64.pyz"] == smoke_mod.sha256_of(
        dist_dir / "gateclerk-0.1.0-linux-arm64.pyz"
    )


def _guard_base_workflow() -> str:
    return (
        "name: release\non:\n  workflow_dispatch:\npermissions:\n  contents: read\n"
        "jobs:\n  x:\n    steps:\n      - run: uv run python scripts/build_dist.py "
        "--dist-dir dist\n"
    )


def test_release_workflow_guard_rejects_publishing_steps(tmp_path) -> None:
    """The workflow's own guard step must go red if a publishing step is ever added."""
    guard = _load_script("ci_proof_guard.py")
    workflow = tmp_path / "release.yml"

    workflow.write_text(_guard_base_workflow(), encoding="utf-8")
    assert guard.check_workflow(workflow) == []

    cases = (
        ("gh release creat", "      - run: gh release create v1.0.0 dist/*\n"),
        ("upload-release-asset", "      - uses: actions/upload-release-asset@v1\n"),
        ("release-action", "      - uses: ncipollo/release-action@v1\n"),
        ("create-release", "      - uses: softprops/create-release@v1\n"),
        ("push --tags", "      - run: git push --tags\n"),
        ("--tap-dir", "      - run: python scripts/build_dist.py --tap-dir ../homebrew-tap\n"),
    )
    for fragment, payload in cases:
        # Fresh base each iteration: a violation must be attributable to THIS payload.
        workflow.write_text(_guard_base_workflow() + payload, encoding="utf-8")
        violations = guard.check_workflow(workflow)
        assert violations, f"guard missed {fragment!r}"
        assert any(fragment in v for v in violations), f"{fragment}: {violations}"


def test_release_workflow_guard_rejects_write_permissions(tmp_path) -> None:
    guard = _load_script("ci_proof_guard.py")
    workflow = tmp_path / "release.yml"
    workflow.write_text(
        "name: release\non:\n  workflow_dispatch:\npermissions:\n  contents: write\n"
        "jobs:\n  x:\n    steps:\n      - run: echo build\n",
        encoding="utf-8",
    )
    violations = guard.check_workflow(workflow)
    assert any("write permission" in v for v in violations)


def test_shipped_release_workflow_satisfies_its_own_guard() -> None:
    """The committed workflow must pass the guard it runs as a step (self-consistency)."""
    guard = _load_script("ci_proof_guard.py")
    workflow = REPO_ROOT / ".github" / "workflows" / "release.yml"
    assert guard.check_workflow(workflow) == []


def test_shipped_release_workflow_proves_every_target_on_its_own_runner() -> None:
    """Each build_dist TARGET must appear in the matrix with a distinct runner, and the
    matrix must pair it to the runner via --expect-host-target (no cross-smoking)."""
    build_dist = _load_script("build_dist.py")
    text = (REPO_ROOT / ".github" / "workflows" / "release.yml").read_text(encoding="utf-8")

    runners: dict[str, list[str]] = {}
    for block in re.findall(r"- os: (\S+)\s*\n\s*target: (\S+)", text):
        runners.setdefault(block[1], []).append(block[0])
    assert set(runners) == set(build_dist.TARGETS), (
        f"matrix targets {sorted(runners)} != build_dist TARGETS {sorted(build_dist.TARGETS)}"
    )
    for target, os_list in runners.items():
        assert len(os_list) == 1, f"{target} mapped to more than one runner: {os_list}"

    assert text.count("--expect-host-target") >= 1, "matrix does not pin runner<->target"
    assert "actions/upload-artifact@v4" in text
    assert "name: dist-${{ matrix.target }}" in text
