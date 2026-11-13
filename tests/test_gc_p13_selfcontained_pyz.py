"""GC-P13 — the `.pyz` release artifact must be self-contained.

`scripts/build_dist.py` used to write only `src/gateclerk/**/*.py` into the zipapp, so a
host with a bare `python3` died on `ModuleNotFoundError: No module named 'typer'`. The
smoke script hid that by running the artifact with the developer's own virtualenv
interpreter, where the dependency was present but not from the archive.

These tests close both holes:

  * the vendored runtime packages are actually inside the archive, and
  * the artifact runs under `python -I -S`, which strips every site-packages entry from
    `sys.path`, so anything not carried in the archive fails loudly.

`-I -S` is what makes the second group honest; without it the artifact would import
`typer` from the build venv and the test would pass while proving nothing.
"""

from __future__ import annotations

import importlib.util
import shutil
import subprocess
import sys
import zipfile
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


@pytest.fixture(scope="module")
def build_dist():
    return _load_script("build_dist.py")


@pytest.fixture(scope="module")
def one_zipapp(build_dist, tmp_path_factory) -> Path:
    """One `.pyz` built by the real builder, shared by the archive/exec tests."""
    out = tmp_path_factory.mktemp("gc-p13-dist") / "gateclerk-0.1.0-linux-x86_64.pyz"
    return build_dist.build_target_zipapp(REPO_ROOT, "0.1.0", "linux-x86_64", out)


def _members(artifact: Path) -> set[str]:
    with zipfile.ZipFile(artifact) as zf:
        return set(zf.namelist())


def _run_isolated(artifact: Path, *args: str) -> subprocess.CompletedProcess[str]:
    """Run the artifact with every site-packages path removed from sys.path."""
    return subprocess.run(  # noqa: S603
        [sys.executable, "-I", "-S", str(artifact), *args],
        capture_output=True,
        text=True,
        timeout=180,
        check=False,
    )


def test_zipapp_contains_the_runtime_packages(one_zipapp: Path) -> None:
    """Every runtime dependency the CLI needs must ride inside the archive.

    The card named `click` as one of these. `click` has no top-level package in this
    lockfile: typer 0.27.3 vendors its own fork as `typer/_click/` and its metadata
    requires `shellingham`/`rich`/`annotated-doc`, not click. So click's CODE does ship
    in the artifact, under `typer/_click/`, and that is what is asserted here. Building a
    top-level `click/` out of typer's private fork would ship a package nothing imports
    and would shadow a real click if one ever appeared on the path.
    """
    members = _members(one_zipapp)
    for pkg in ("typer", "httpx", "rich"):
        assert f"{pkg}/__init__.py" in members, f"{pkg} is not vendored into {one_zipapp.name}"

    click_top_level = "click/__init__.py" in members
    click_vendored = "typer/_click/__init__.py" in members
    assert click_top_level or click_vendored, (
        "neither click/ nor typer/_click/ is in the archive — the CLI could not parse "
        "argv on a host with a bare python3"
    )


def test_zipapp_vendors_every_package_the_cli_imports(one_zipapp: Path) -> None:
    """Drift guard: the vendored set must cover what `gateclerk.cli` really imports.

    The runtime list in `build_dist.py` is hand-maintained, so a dependency bump that
    adds a package (typer 0.27 added `annotated_doc` and `shellingham`) silently breaks
    the release artifact. This test compares the archive against the real import closure
    and fails when the two diverge.
    """
    vendored = _members(one_zipapp)
    for name in ("shellingham", "annotated_doc", "httpcore", "anyio", "certifi", "h11"):
        assert f"{name}/__init__.py" in vendored, f"{name} missing from the zipapp"
    # `typing_extensions` ships as a single-file module, not a package directory.
    assert "typing_extensions.py" in vendored
    # openpyxl backs the optional `excel` extra; it is in the dev group, so a normal
    # build vendors it. ACCEPT asks for it in the artifact.
    assert "openpyxl/__init__.py" in vendored
    assert "et_xmlfile/__init__.py" in vendored


def test_zipapp_runs_with_site_packages_disabled(one_zipapp: Path) -> None:
    proc = _run_isolated(one_zipapp, "--version")
    assert proc.returncode == 0, f"--version failed under -I -S:\n{proc.stdout}\n{proc.stderr}"
    assert proc.stdout.strip().startswith("gateclerk ")


def test_zipapp_help_runs_with_site_packages_disabled(one_zipapp: Path) -> None:
    proc = _run_isolated(one_zipapp, "--help")
    assert proc.returncode == 0, f"--help failed under -I -S:\n{proc.stdout}\n{proc.stderr}"
    assert "status" in proc.stdout


def test_isolated_run_fails_without_the_vendored_packages(tmp_path: Path, build_dist) -> None:
    """Prove `-I -S` really has teeth: an artifact with no vendored deps must fail here.

    Without this control the two isolated-run tests could pass by quietly importing
    `typer` from the developer's venv.
    """
    bare = tmp_path / "gateclerk-0.1.0-linux-x86_64.pyz"
    src = tmp_path / "src" / "gateclerk"
    src.parent.mkdir(parents=True)
    shutil.copytree(
        REPO_ROOT / "src" / "gateclerk",
        src,
        ignore=shutil.ignore_patterns("__pycache__", "*.pyc", "*.pyo"),
    )

    def _no_vendoring(_staging: Path) -> None:
        return None

    original = build_dist._vendor_runtime_packages
    build_dist._vendor_runtime_packages = _no_vendoring
    try:
        build_dist.build_target_zipapp(tmp_path, "0.1.0", "linux-x86_64", bare)
    finally:
        build_dist._vendor_runtime_packages = original

    proc = _run_isolated(bare, "--version")
    assert proc.returncode != 0, "a dependency-free artifact must NOT run under -I -S"
    assert "No module named" in (proc.stderr + proc.stdout)


def test_entry_point_is_unchanged(one_zipapp: Path) -> None:
    """The card froze the entry point: `gateclerk.cli:main` must still be what runs."""
    with zipfile.ZipFile(one_zipapp) as zf:
        main_src = zf.read("__main__.py").decode("utf-8")
    assert "from gateclerk.cli import main" in main_src
    assert "raise SystemExit(main())" in main_src
    assert one_zipapp.read_bytes().startswith(b"#!/usr/bin/env python3\n")


def test_older_host_python_gets_a_plain_message_not_a_traceback(one_zipapp: Path) -> None:
    """A pre-3.12 host must be told the floor, not shown typer's `TypeGuard` ImportError."""
    candidates = [c for c in ("/usr/bin/python3", shutil.which("python3")) if c]
    old = next((c for c in candidates if _version_of(c) < (3, 12)), None)
    if old is None:
        pytest.skip("no pre-3.12 interpreter on this host to exercise the guard")

    proc = subprocess.run(  # noqa: S603
        [old, "-I", "-S", str(one_zipapp), "--version"],
        capture_output=True,
        text=True,
        timeout=180,
        check=False,
    )
    assert proc.returncode == 2, proc.stderr
    assert "requires Python 3.12" in proc.stderr, proc.stderr
    assert "TypeGuard" not in proc.stderr, "guard must fire before typer is imported"


def _version_of(exe: str) -> tuple[int, int]:
    proc = subprocess.run(  # noqa: S603
        [exe, "-I", "-S", "-c", "import sys;print(sys.version_info[0],sys.version_info[1])"],
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    if proc.returncode != 0:
        return (0, 0)
    major, _, minor = proc.stdout.strip().partition(" ")
    return (int(major), int(minor))


def test_missing_runtime_package_fails_the_build_rather_than_the_release(
    tmp_path: Path, build_dist
) -> None:
    """Silently skipping an absent dependency is how this bug shipped in the first place."""
    src = tmp_path / "src" / "gateclerk"
    src.parent.mkdir(parents=True)
    shutil.copytree(
        REPO_ROOT / "src" / "gateclerk",
        src,
        ignore=shutil.ignore_patterns("__pycache__", "*.pyc", "*.pyo"),
    )
    original = build_dist.RUNTIME_PACKAGES
    build_dist.RUNTIME_PACKAGES = (*original, "definitely_not_installed_pkg_gc_p13")
    try:
        with pytest.raises(ValueError, match="not installed in this build env"):
            build_dist.build_target_zipapp(tmp_path, "0.1.0", "linux-x86_64", tmp_path / "gone.pyz")
    finally:
        build_dist.RUNTIME_PACKAGES = original


def test_smoke_does_not_run_the_artifact_inside_the_build_venv() -> None:
    """The smoke must step outside the venv, and prove it did.

    `smoke_artifact` used to default to `sys.executable`, so the artifact imported
    `typer` from the very venv that had just built it — the smoke could never see a
    missing dependency. Whatever interpreter it picks, `-I -S` has to leave no
    site-packages entry on `sys.path`.
    """
    smoke = _load_script("smoke_artifact.py")
    chosen = smoke.default_python_exe()

    non_venv_capable = [
        c
        for c in smoke._candidate_interpreters()
        if not smoke._is_build_venv(c) and smoke._interpreter_runs_gateclerk(c)
    ]
    if non_venv_capable:
        assert not smoke._is_build_venv(chosen), (
            f"a usable Python exists outside the venv ({non_venv_capable[0]}) "
            f"but the smoke still chose the venv: {chosen}"
        )

    proc = subprocess.run(  # noqa: S603
        [
            chosen,
            "-I",
            "-S",
            "-c",
            "import sys; print([p for p in sys.path if 'site-packages' in p])",
        ],
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout.strip() == "[]", f"site-packages leaked into the smoke: {proc.stdout}"


def test_build_all_still_emits_three_zipapps_and_the_tarball(build_dist, tmp_path: Path) -> None:
    built = build_dist.build_all(repo_dir=REPO_ROOT, dist_dir=tmp_path / "dist")

    assert built["tarball"].name == "gateclerk-0.1.0.tar.gz"
    for target in build_dist.TARGETS:
        pyz = built[target]
        assert pyz.name == f"gateclerk-0.1.0-{target}.pyz"
        assert pyz.is_file()

    lines = [
        line
        for line in built["sha256sums"].read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    assert len(lines) == 4  # tarball + 3 zipapps
    assert len(built) == 6  # tarball, sha256sums, formula + the 3 targets
    for line in lines:
        digest, _, name = line.partition("  ")
        assert len(digest) == 64
        assert (tmp_path / "dist" / name).is_file()
