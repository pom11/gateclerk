"""Build multi-OS release artifacts, `SHA256SUMS`, and Homebrew formula for `gateclerk`.

Cards t_f9254c12 (RELEASE-PACKAGING) & t_6be29819 (SMOKE-BUILD).

Distribution decision (documented in PR body & module docstring):
  * Primary distribution is a deterministic source tarball (`gateclerk-<version>.tar.gz`)
    plus a Homebrew Python virtualenv formula (`packaging/Formula/gateclerk.rb.tmpl`,
    matching `micro-notify`'s pattern) and portable executable Python zipapps
    (`gateclerk-<version>-<target>.pyz` for `macos-arm64`, `linux-x86_64`, `linux-arm64`).
  * Why virtualenv formula + zipapp over PyInstaller single-file binary: `gateclerk` is
    100% pure Python (`httpx`, `typer`, `rich` + stdlib `sqlite3`, `tomllib`, `zoneinfo`)
    and shells out only to `/usr/bin/security` on macOS. A PyInstaller bundle embeds an
    unsigned shared-library extraction payload that triggers macOS Gatekeeper / quarantine
    prompts on LaunchAgent startup and adds ~35 MB per target without eliminating any C
    runtime dependency. The Homebrew virtualenv formula + deterministic `.pyz` artifacts
    build offline in <1s, carry exact `SHA256SUMS`, and run identically on macOS arm64,
    Linux x86_64, and Linux arm64.
"""

from __future__ import annotations

import argparse
import gzip
import hashlib
import io
import re
import stat
import tarfile
import tomllib
import zipfile
from pathlib import Path

REPO_ROOT_DEFAULT = Path(__file__).resolve().parents[1]
FORMULA_TEMPLATE = Path("packaging/Formula/gateclerk.rb.tmpl")
FORMULA_NAME = "gateclerk.rb"
GITHUB_ORG = "pom11"
GITHUB_REPO = "gateclerk"
VERSION_RE = re.compile(r"^\d+\.\d+\.\d+$")

TARGETS: tuple[str, ...] = (
    "macos-arm64",
    "linux-x86_64",
    "linux-arm64",
)

# GC-P13: a release artifact must run on a host that has nothing but a bare `python3`,
# so the `.pyz` carries its own copy of every third-party module `gateclerk.cli`
# imports. These are IMPORT names, not distribution names.
#
# The list is the real import closure, not the transitive `Requires-Dist` graph:
#   * typer 0.27 vendors click as `typer/_click` and no longer needs a top-level `click`;
#   * typer 0.27 does need `shellingham` and `annotated_doc`, which an older list missed;
#   * anyio 4.15 imports `sniffio` only inside a try/except, so it is optional;
#   * anyio 4.15 imports `typing_extensions` unconditionally, and it ships as a single
#     `.py` file rather than a package directory.
# `tests/test_gc_p13_selfcontained_pyz.py` asserts the archive covers the closure, so a
# dependency bump that adds a package fails the suite instead of the release.
RUNTIME_PACKAGES: tuple[str, ...] = (
    "typer",
    "shellingham",
    "annotated_doc",
    "rich",
    "markdown_it",
    "mdurl",
    "pygments",
    "httpx",
    "httpcore",
    "h11",
    "anyio",
    "idna",
    "certifi",
    "typing_extensions",
)

# Vendored when the build environment happens to have them, skipped when it does not.
# Three reasons each name here is optional rather than required:
#   * `click`/`sniffio` are not in this lockfile at all (see above). Keeping them here
#     means a future typer that un-vendors click still produces a working artifact.
#   * `openpyxl`/`et_xmlfile` back the optional `excel` extra — `users import` explains
#     the missing extra instead of crashing, so the package must remain buildable and
#     runnable without them. A hard requirement here would fail a release build over a
#     feature that is deliberately optional. They are installed in the dev group, so a
#     normal `uv run --frozen` build does vendor them.
OPTIONAL_RUNTIME_PACKAGES: tuple[str, ...] = (
    "click",
    "sniffio",
    "openpyxl",
    "et_xmlfile",
)

_ARCHIVE_STAMP = (2026, 11, 4, 0, 0, 0)


def read_pyproject_version(repo_dir: Path) -> str:
    data = tomllib.loads((repo_dir / "pyproject.toml").read_text(encoding="utf-8"))
    version = str(data.get("project", {}).get("version", "")).strip()
    if not VERSION_RE.match(version):
        raise ValueError(f"pyproject.toml version {version!r} is not X.Y.Z")
    return version


def read_package_version(repo_dir: Path) -> str:
    init_path = repo_dir / "src" / "gateclerk" / "__init__.py"
    text = init_path.read_text(encoding="utf-8")
    match = re.search(r'^__version__\s*=\s*["\']([^"\']+)["\']', text, re.MULTILINE)
    if not match:
        raise ValueError(f"no __version__ found in {init_path}")
    return match.group(1)


def verify_version_parity(repo_dir: Path, expected: str | None = None) -> str:
    py_ver = read_pyproject_version(repo_dir)
    pkg_ver = read_package_version(repo_dir)
    if py_ver != pkg_ver:
        raise ValueError(
            f"version mismatch: pyproject.toml has {py_ver!r}, "
            f"src/gateclerk/__init__.py has {pkg_ver!r}"
        )
    if expected is not None and py_ver != expected:
        raise ValueError(f"requested version {expected!r} != repo version {py_ver!r}")
    return py_ver


def sha256_of(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def build_source_tarball(repo_dir: Path, version: str, out_path: Path) -> Path:
    """Build a deterministic `.tar.gz` source tarball containing `pyproject.toml` and `src/`."""
    out_path.parent.mkdir(parents=True, exist_ok=True)
    prefix = f"gateclerk-{version}"

    files_to_pack: list[Path] = []
    for rel in ("pyproject.toml", "README.md", "CHANGELOG.md", "LICENSE"):
        candidate = repo_dir / rel
        if candidate.is_file():
            files_to_pack.append(candidate)
    for directory in ("src/gateclerk", "deploy", "examples", "docs"):
        base = repo_dir / directory
        if base.is_dir():
            for path in sorted(base.rglob("*")):
                if (
                    path.is_file()
                    and "__pycache__" not in path.parts
                    and not path.name.endswith(".pyc")
                ):
                    files_to_pack.append(path)

    with (
        out_path.open("wb") as raw_fh,
        gzip.GzipFile(filename="", mode="wb", fileobj=raw_fh, mtime=0) as gz_fh,
        tarfile.open(fileobj=gz_fh, mode="w", format=tarfile.PAX_FORMAT) as tar,
    ):
        for file_path in sorted(files_to_pack):
            rel_name = file_path.relative_to(repo_dir).as_posix()
            data = file_path.read_bytes()
            info = tarfile.TarInfo(name=f"{prefix}/{rel_name}")
            info.size = len(data)
            info.mtime = 1762214400
            info.mode = 0o644
            info.uid = 0
            info.gid = 0
            info.uname = "root"
            info.gname = "root"
            tar.addfile(info, io.BytesIO(data))
    return out_path


def _copy_runtime_member(name: str, staging: Path) -> bool:
    """Copy one import name into `staging`. Returns False when it is not installed.

    Handles both package directories (`rich/`) and single-file modules
    (`typing_extensions.py`), which `submodule_search_locations` alone would reject.
    """
    import importlib.util
    import shutil

    spec = importlib.util.find_spec(name)
    if spec is None:
        return False

    if spec.submodule_search_locations:
        source = Path(next(iter(spec.submodule_search_locations)))
        shutil.copytree(
            source,
            staging / name,
            ignore=shutil.ignore_patterns("__pycache__", "*.pyc", "*.pyo"),
        )
        return True

    if spec.origin and spec.origin.endswith(".py"):
        shutil.copy2(spec.origin, staging / Path(spec.origin).name)
        return True

    return False


def _vendor_runtime_packages(staging: Path) -> None:
    """Copy every third-party module the CLI needs into the staging directory.

    A package in `RUNTIME_PACKAGES` that is missing from the build environment is a hard
    error: shipping an artifact that dies with `ModuleNotFoundError` on a production host
    is worse than a build that fails here.
    """
    for name in RUNTIME_PACKAGES:
        if not _copy_runtime_member(name, staging):
            raise ValueError(f"runtime package {name!r} is not installed in this build env")
    for name in OPTIONAL_RUNTIME_PACKAGES:
        _copy_runtime_member(name, staging)


def build_target_zipapp(repo_dir: Path, version: str, target: str, out_path: Path) -> Path:
    """Build an executable, self-contained `.pyz` archive for `target`.

    The archive stages `gateclerk` plus every runtime dependency in a temp directory and
    is then written with a FIXED member timestamp rather than `zipapp.create_archive`,
    which stamps `__main__.py` with the wall clock and would make `SHA256SUMS` differ
    between two builds of the same tree (asserted by tests/test_release_packaging.py).
    """
    import shutil
    import tempfile

    out_path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="gateclerk-pyz-") as tmp:
        staging = Path(tmp)
        shutil.copytree(
            repo_dir / "src" / "gateclerk",
            staging / "gateclerk",
            ignore=shutil.ignore_patterns("__pycache__", "*.pyc", "*.pyo"),
        )
        _vendor_runtime_packages(staging)
        # A host Python older than the project floor fails inside typer's typing imports
        # with a cryptic `cannot import name 'TypeGuard'`. Say what is actually wrong.
        (staging / "__main__.py").write_text(
            f"# target: {target} version: {version}\n"
            "import sys\n"
            "\n"
            "if sys.version_info < (3, 12):\n"
            "    sys.stderr.write(\n"
            f"        'gateclerk {version} requires Python 3.12 or newer; "
            "this is %d.%d.%d.\\n'\n"
            "        % sys.version_info[:3]\n"
            "    )\n"
            "    raise SystemExit(2)\n"
            "\n"
            "from gateclerk.cli import main\n"
            "if __name__ == '__main__':\n"
            "    raise SystemExit(main())\n",
            encoding="utf-8",
        )

        buf = io.BytesIO()
        with zipfile.ZipFile(buf, mode="w", compression=zipfile.ZIP_DEFLATED) as zf:
            for member in sorted(staging.rglob("*")):
                if not member.is_file():
                    continue
                zinfo = zipfile.ZipInfo(
                    member.relative_to(staging).as_posix(), date_time=_ARCHIVE_STAMP
                )
                zinfo.compress_type = zipfile.ZIP_DEFLATED
                zinfo.external_attr = (0o644 & 0xFFFF) << 16
                zf.writestr(zinfo, member.read_bytes())

    shebang = b"#!/usr/bin/env python3\n"
    out_path.write_bytes(shebang + buf.getvalue())
    out_path.chmod(out_path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    return out_path


def render_formula(template_text: str, *, version: str, url: str, sha256: str) -> str:
    rendered = (
        template_text.replace("{{VERSION}}", version)
        .replace("{{URL}}", url)
        .replace("{{SHA256}}", sha256)
    )
    leftovers = sorted(set(re.findall(r"\{\{[A-Z_]+\}\}", rendered)))
    if leftovers:
        raise ValueError(f"template placeholders left unsubstituted: {leftovers}")
    return rendered


def build_all(
    *,
    repo_dir: Path = REPO_ROOT_DEFAULT,
    dist_dir: Path | None = None,
    version: str | None = None,
    tap_dir: Path | None = None,
) -> dict[str, Path]:
    """Build source tarball, per-OS `.pyz` artifacts, `SHA256SUMS`, and rendered formula."""
    ver = verify_version_parity(repo_dir, expected=version)
    out_dir = (repo_dir / "dist") if dist_dir is None else Path(dist_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    artifacts: list[Path] = []
    tarball = build_source_tarball(repo_dir, ver, out_dir / f"gateclerk-{ver}.tar.gz")
    artifacts.append(tarball)

    for target in TARGETS:
        pyz = build_target_zipapp(repo_dir, ver, target, out_dir / f"gateclerk-{ver}-{target}.pyz")
        artifacts.append(pyz)

    sums_lines = [f"{sha256_of(p)}  {p.name}" for p in artifacts]
    sums_path = out_dir / "SHA256SUMS"
    sums_path.write_text("\n".join(sums_lines) + "\n", encoding="utf-8")

    tmpl_path = repo_dir / FORMULA_TEMPLATE
    formula_text = render_formula(
        tmpl_path.read_text(encoding="utf-8"),
        version=ver,
        url=(
            f"https://github.com/{GITHUB_ORG}/{GITHUB_REPO}/releases/download/v{ver}/{tarball.name}"
        ),
        sha256=sha256_of(tarball),
    )
    rendered_formula = out_dir / FORMULA_NAME
    rendered_formula.write_text(formula_text, encoding="utf-8")

    if tap_dir is not None:
        tap_formula = Path(tap_dir) / "Formula" / FORMULA_NAME
        tap_formula.parent.mkdir(parents=True, exist_ok=True)
        tap_formula.write_text(formula_text, encoding="utf-8")

    return {
        "tarball": tarball,
        "sha256sums": sums_path,
        "formula": rendered_formula,
        **{target: out_dir / f"gateclerk-{ver}-{target}.pyz" for target in TARGETS},
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Build gateclerk release artifacts + SHA256SUMS.")
    parser.add_argument("--version", default=None, help="Expected X.Y.Z version.")
    parser.add_argument(
        "--dist-dir", type=Path, default=None, help="Output directory (default ./dist)."
    )
    parser.add_argument(
        "--tap-dir", type=Path, default=None, help="Optional homebrew tap checkout."
    )
    args = parser.parse_args(argv)

    built = build_all(
        repo_dir=REPO_ROOT_DEFAULT,
        dist_dir=args.dist_dir,
        version=args.version,
        tap_dir=args.tap_dir,
    )
    print((built["sha256sums"]).read_text(encoding="utf-8"), end="")
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
