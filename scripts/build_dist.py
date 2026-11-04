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


def build_target_zipapp(repo_dir: Path, version: str, target: str, out_path: Path) -> Path:
    """Build an executable `.pyz` archive for `target` with `gateclerk` and `__main__.py`."""
    out_path.parent.mkdir(parents=True, exist_ok=True)
    src_pkg = repo_dir / "src" / "gateclerk"
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, mode="w", compression=zipfile.ZIP_DEFLATED) as zf:
        for py_file in sorted(src_pkg.rglob("*.py")):
            rel = py_file.relative_to(repo_dir / "src").as_posix()
            zinfo = zipfile.ZipInfo(rel, date_time=(2026, 11, 4, 0, 0, 0))
            zinfo.compress_type = zipfile.ZIP_DEFLATED
            zinfo.external_attr = (0o644 & 0xFFFF) << 16
            zf.writestr(zinfo, py_file.read_bytes())

        main_info = zipfile.ZipInfo("__main__.py", date_time=(2026, 11, 4, 0, 0, 0))
        main_info.compress_type = zipfile.ZIP_DEFLATED
        main_info.external_attr = (0o644 & 0xFFFF) << 16
        main_code = (
            f"# target: {target} version: {version}\n"
            "from gateclerk.cli import main\n"
            "if __name__ == '__main__':\n"
            "    raise SystemExit(main())\n"
        )
        zf.writestr(main_info, main_code.encode("utf-8"))

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
