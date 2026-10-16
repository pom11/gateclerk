"""Pins for the wrong-checkout guard (tests/_source_guard.py + conftest pytest_configure).

The hazard is real, not theoretical: the main checkout's venv carries
`_editable_impl_gateclerk.pth` -> /…/gateclerk/src, so a bare `pytest` run inside a git
worktree imports the MAIN checkout's package and prints a fully green suite for code
the worktree does not contain (t_7b073d11's first green run).

Two layers of pin here:

* the pure helpers, which is where the decision lives and is cheap to pin exhaustively;
* two end-to-end subprocess probes that run the REAL conftest guard under the REAL
  pytest against a scratch checkout — one where gateclerk lives outside the checkout
  (must abort with exit 4 and name the fixes) and one where it lives inside (must stay
  silent and run the test). An in-process monkeypatch cannot pin this, because what
  matters is which path pytest's own configure hook sees at session start.

Everything is offline: the scratch checkouts hold a one-line stub `gateclerk`, never the
real package, and no socket is opened (the guard fires before any test body runs).
"""

from __future__ import annotations

import shutil
import subprocess
import sys
import sysconfig
from pathlib import Path

import pytest

from _source_guard import FIX_HINT, mismatch_message

REPO_ROOT = Path(__file__).resolve().parents[1]
GUARD_FILES = (REPO_ROOT / "tests" / "conftest.py", REPO_ROOT / "tests" / "_source_guard.py")

#: A stub that satisfies find_spec without dragging in the real package's deps.
STUB = '"""stub gateclerk used only to pin where the interpreter would find it"""\n'


# --- the pure decision: mismatch_message -------------------------------------------------


def test_helper_flags_a_package_from_another_checkout(tmp_path: Path) -> None:
    """The exact worktree shape: gateclerk resolves under /…/main/src, run is /…/worktree."""
    other = tmp_path / "main-checkout" / "src" / "gateclerk"
    other.mkdir(parents=True)
    (other / "__init__.py").write_text(STUB, encoding="utf-8")

    message = mismatch_message(other / "__init__.py", tmp_path / "worktree")
    assert message is not None, "a package from another checkout must never run silently"
    assert "REFUSING TO RUN" in message
    # The message must show both sides of the mismatch, or the reader cannot act on it.
    assert str(other) in message
    assert str(tmp_path / "worktree") in message


@pytest.mark.parametrize(
    "origin",
    [
        pytest.param("src/gateclerk/__init__.py", id="src-layout-file"),
        pytest.param("src/gateclerk", id="src-layout-package-dir"),
        pytest.param("gateclerk/__init__.py", id="flat-layout-file"),
    ],
)
def test_helper_stays_silent_when_the_package_is_inside_the_checkout(
    tmp_path: Path, origin: str
) -> None:
    """Both layouts CI and `PYTHONPATH=<root>/src` produce: inside the run = no message."""
    inside = tmp_path / origin
    inside.parent.mkdir(parents=True, exist_ok=True)
    inside.write_text(STUB, encoding="utf-8")
    assert mismatch_message(inside, tmp_path) is None


def test_helper_stays_silent_when_the_package_cannot_be_found(tmp_path: Path) -> None:
    """A missing package is the tests' own import error to report, not the guard's."""
    assert mismatch_message(None, tmp_path) is None


def test_message_names_both_documented_fixes() -> None:
    """The point of the guard is that the next worker does not rediscover the workaround."""
    assert "uv run --frozen pytest" in FIX_HINT
    assert "PYTHONPATH={root}/src pytest" in FIX_HINT
    # The placeholder must actually be substituted, not printed literally.
    message = mismatch_message(Path("/elsewhere/gateclerk/__init__.py"), Path("/checkout"))
    assert message is not None
    assert "{root}" not in message
    assert "/checkout/src" in message


def test_helper_is_case_and_symlink_insensitive_on_the_root(tmp_path: Path) -> None:
    """A symlinked or relative root must not turn a correct run into a false alarm."""
    real = tmp_path / "real" / "src" / "gateclerk"
    real.mkdir(parents=True)
    (real / "__init__.py").write_text(STUB, encoding="utf-8")
    link = tmp_path / "link"
    link.symlink_to(tmp_path / "real", target_is_directory=True)
    # Run rooted at the symlink: the resolved package sits under the resolved root.
    assert mismatch_message(real / "__init__.py", link) is None


# --- resolve_package_origin -------------------------------------------------------------


def test_resolve_finds_the_repo_own_package_from_a_clean_importer(tmp_path: Path) -> None:
    """`find_spec` path: with <root>/src on sys.path, the repo's own package is found."""
    script = (
        "import sys\n"
        f"sys.path.insert(0, {str(REPO_ROOT / 'src')!r})\n"
        f"sys.path.insert(0, {str(REPO_ROOT / 'tests')!r})\n"
        "from _source_guard import resolve_package_origin\n"
        "print(resolve_package_origin('gateclerk'))"
    )
    proc = subprocess.run(  # noqa: S603 — argv list, no shell, fixed program text
        [sys.executable, "-c", script],
        capture_output=True,
        text=True,
        timeout=60,
        env={"PATH": "/usr/bin:/bin", "HOME": str(tmp_path)},
    )
    assert proc.returncode == 0, proc.stderr
    resolved = Path(proc.stdout.strip())
    assert resolved == (REPO_ROOT / "src" / "gateclerk" / "__init__.py").resolve()


def test_resolve_returns_none_for_a_package_that_is_not_installed(tmp_path: Path) -> None:
    """No gateclerk anywhere -> None, so the guard defers to the tests' own import error.

    The child gets a sys.path of stdlib + tests only: the interpreter running this
    suite has gateclerk editable-installed via a site-packages .pth, and that entry must
    not leak into the probe. `-S` alone is not enough (it also drops the stdlib).
    """
    stdlib = sysconfig.get_paths()["stdlib"]
    script = (
        "import sys\n"
        f"sys.path[:] = [{stdlib!r}, {str(REPO_ROOT / 'tests')!r}]\n"
        "from _source_guard import resolve_package_origin\n"
        "print(resolve_package_origin('gateclerk'))"
    )
    proc = subprocess.run(  # noqa: S603 — argv list, no shell, fixed program text
        [sys.executable, "-S", "-c", script],
        capture_output=True,
        text=True,
        timeout=60,
        env={"PATH": "/usr/bin:/bin", "HOME": str(tmp_path), "PYTHONPATH": ""},
    )
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout.strip() == "None"


# --- end-to-end: the real hook under the real pytest -------------------------------------


def _scratch_checkout(tmp_path: Path, *, package_inside: bool) -> tuple[Path, Path]:
    """A minimal checkout holding the real guard files and a stub gateclerk.

    Returns (checkout_root, src_dir). The stub package sits inside the checkout when
    `package_inside`, otherwise in a sibling directory that stands in for the main
    checkout's editable install.
    """
    root = tmp_path / "checkout"
    (root / "tests").mkdir(parents=True)
    for src in GUARD_FILES:
        shutil.copy2(src, root / "tests" / src.name)

    src_dir = root / "src" if package_inside else tmp_path / "other-checkout" / "src"
    (src_dir / "gateclerk").mkdir(parents=True)
    (src_dir / "gateclerk" / "__init__.py").write_text(STUB, encoding="utf-8")

    (root / "pyproject.toml").write_text(
        '[tool.pytest.ini_options]\npythonpath = ["tests"]\n', encoding="utf-8"
    )
    (root / "tests" / "test_trivial.py").write_text(
        "def test_reached_the_test_body():\n    assert True\n", encoding="utf-8"
    )
    return root, src_dir


def _run_pytest(root: Path, src_dir: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-m", "pytest", "-q", "tests"],
        cwd=root,
        capture_output=True,
        text=True,
        timeout=120,
        # Deliberately minimal env: the point is which sys.path pytest ends up with, and
        # inheriting a developer's PYTHONPATH/venv would make the probe flaky.
        env={
            "PATH": "/usr/bin:/bin",
            "HOME": str(root.parent),
            "PYTHONPATH": str(src_dir),
            "PYTHONDONTWRITEBYTECODE": "1",
            "GATECLERK_LIVE": "0",
        },
    )


def test_guard_aborts_the_session_when_gateclerk_is_from_another_checkout(tmp_path: Path) -> None:
    """The false-green case: collection must not happen and the fix must be printed."""
    root, src_dir = _scratch_checkout(tmp_path, package_inside=False)
    proc = _run_pytest(root, src_dir)

    assert proc.returncode == 4, f"expected usage error, got {proc.returncode}:\n{proc.stdout}"
    combined = proc.stdout + proc.stderr
    assert "REFUSING TO RUN" in combined
    assert "uv run --frozen pytest" in combined
    # No test ran, and no green line was printed — that is the whole point.
    assert "test_reached_the_test_body" not in combined
    assert "passed" not in combined


def test_guard_stays_silent_when_gateclerk_is_the_checkout_under_test(tmp_path: Path) -> None:
    """The correct run must be indistinguishable from an unguarded one."""
    root, src_dir = _scratch_checkout(tmp_path, package_inside=True)
    proc = _run_pytest(root, src_dir)

    assert proc.returncode == 0, f"expected a normal pass, got {proc.returncode}:\n{proc.stdout}"
    combined = proc.stdout + proc.stderr
    assert "REFUSING TO RUN" not in combined
    assert "1 passed" in combined


def test_hook_abstains_when_the_package_cannot_be_located(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Regression pin for the None branch, at the hook's own decision point.

    An environment with gateclerk genuinely absent cannot be built around a pytest whose
    own venv carries it (that is why the two end-to-end probes above use an installed
    package), so the abstain path is pinned where it is decided: a missing package must
    not be reported as a wrong-checkout problem, or the next worker chases the wrong fix.
    """
    import conftest

    monkeypatch.setattr(conftest, "resolve_package_origin", lambda *a: None)
    conftest.enforce_source_guard(tmp_path)  # raises nothing


def test_hook_raises_usage_error_naming_the_fixes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The severity pin: the hook must raise UsageError (exit 4), not merely warn.

    A warning would let pytest collect and print a green suite — exactly the false
    green this guard exists to prevent.
    """
    import conftest

    outside = tmp_path / "other" / "src" / "gateclerk" / "__init__.py"
    outside.parent.mkdir(parents=True)
    outside.write_text(STUB, encoding="utf-8")
    monkeypatch.setattr(conftest, "resolve_package_origin", lambda *a: outside)

    with pytest.raises(pytest.UsageError) as excinfo:
        conftest.enforce_source_guard(tmp_path / "checkout")
    assert "REFUSING TO RUN" in str(excinfo.value)
    assert "uv run --frozen pytest" in str(excinfo.value)


def test_guard_files_are_copied_verbatim_into_the_scratch_probe(tmp_path: Path) -> None:
    """Guard the probe: if the copies drifted, the two probes above prove nothing."""
    root, src_dir = _scratch_checkout(tmp_path, package_inside=True)
    for src in GUARD_FILES:
        assert (root / "tests" / src.name).read_text(encoding="utf-8") == src.read_text(
            encoding="utf-8"
        )
    assert (src_dir / "gateclerk" / "__init__.py").exists()
