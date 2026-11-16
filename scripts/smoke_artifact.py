"""Smoke-test built `gateclerk` release artifacts (card t_6be29819, SMOKE-BUILD).

Given a built distribution directory (`--dist-dir dist`):
  1. Verifies every artifact listed in `SHA256SUMS` against its SHA-256 digest BEFORE
     executing anything.
  2. Executes the target artifact (`--target macos-arm64|linux-x86_64|linux-arm64`, or
     auto-detected for the host OS) inside an isolated temporary `HOME` directory:
       * `<artifact> --version`
       * `<artifact> --help`
       * `<artifact> demo demo --root <tmp>/demo --ticks 1`
       * `<artifact> status --config <tmp>/sites.toml --state-root <tmp>/state -o json`
       * `<artifact> doctor --config <tmp>/sites.toml --state-root <tmp>/state -o json`
       * `<artifact> creds set/get/remove` against a `0600` credential file (proving the
         keychain-free Linux credential path too).

CI pairing note (card t_eb4004b7, RELEASE-CI-PROOF): a `.pyz` is portable, so a smoke run
proves the HOST it executed on, not the artifact's target name. `.github/workflows/release.yml`
therefore passes `--expect-host-target <matrix target>` and `assert_host_matches_target`
refuses a target whose platform differs from the runner's — an arm64 zipapp smoke executed
on an x86_64 box would otherwise go green while proving nothing about arm64.
`--print-checks` puts the `sha256sum -c`-style verdict lines in the CI log.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any


def sha256_of(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def verify_sha256sums(dist_dir: Path) -> dict[str, Path]:
    """Verify every line in `dist_dir / SHA256SUMS` and return `{filename: path}`."""
    sums_file = dist_dir / "SHA256SUMS"
    if not sums_file.is_file():
        raise RuntimeError(f"missing {sums_file}")
    verified: dict[str, Path] = {}
    for line in sums_file.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        parts = line.strip().split()
        if len(parts) != 2:
            raise RuntimeError(f"malformed SHA256SUMS line: {line!r}")
        expected_sha, name = parts
        artifact = dist_dir / name
        if not artifact.is_file():
            raise RuntimeError(f"artifact listed in SHA256SUMS does not exist: {artifact}")
        actual_sha = sha256_of(artifact)
        if actual_sha != expected_sha:
            raise RuntimeError(
                f"SHA256 mismatch for {name}: expected {expected_sha}, got {actual_sha}"
            )
        verified[name] = artifact
    if not verified:
        raise RuntimeError("SHA256SUMS is empty")
    return verified


def detect_host_target() -> str:
    sysname = platform.system().lower()
    machine = platform.machine().lower()
    if sysname == "darwin":
        return "macos-arm64"
    if machine in ("aarch64", "arm64"):
        return "linux-arm64"
    return "linux-x86_64"


def assert_host_matches_target(expected: str) -> str:
    """Refuse to smoke `expected` on a runner that is not that platform.

    CI passes `--expect-host-target <matrix target>`. Without this, a matrix entry that
    named the wrong runner would still go green by executing, say, the linux-arm64 zipapp
    on an x86_64 host — a portable zipapp imports fine there, so the run would prove
    nothing about arm64 while reporting success. The failure below is the point.
    """
    host = detect_host_target()
    if host != expected:
        raise RuntimeError(
            f"refusing to cross-smoke: artifact target {expected!r} does not match "
            f"the host platform {host!r} — pair each matrix target with its own runner"
        )
    return host


def print_sha256_check_lines(dist_dir: Path, verified: dict[str, Path]) -> None:
    """Print `sha256sum -c`-style OK lines for every artifact verified from `SHA256SUMS`.

    Pure evidence for the CI log: the digest the build produced, the file name, and the
    verdict, for each artifact the smoke step is about to execute.
    """
    for name, path in sorted(verified.items()):
        digest = sha256_of(path)
        expected = next(
            (
                line.split()[0]
                for line in (dist_dir / "SHA256SUMS").read_text(encoding="utf-8").splitlines()
                if line.strip().endswith(f"  {name}")
            ),
            digest,
        )
        if digest != expected:  # verify_sha256sums already raised; belt and braces
            raise RuntimeError(f"digest drift for {name} between verify and report")
        print(f"{digest}  {name}: OK")


def _interpreter_runs_gateclerk(candidate: str) -> bool:
    """True when `candidate` is a Python new enough to run the artifact.

    The smoke must not use the build venv, so a bare `python3` is preferred. But a
    runner's `python3` can be older than the project floor, and then the artifact dies
    on `SyntaxError`/`ModuleNotFoundError: tomllib` and the release looks broken when
    only the probe interpreter was too old.
    """
    try:
        proc = subprocess.run(  # noqa: S603
            [
                candidate,
                "-I",
                "-S",
                "-c",
                "import sys; sys.exit(0 if sys.version_info >= (3, 12) else 1)",
            ],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return False
    return proc.returncode == 0


def _candidate_interpreters() -> list[str]:
    """Every `python3`/`python` on PATH, in PATH order, de-duplicated.

    `shutil.which` alone returns only the first hit, and inside `uv run` that is the
    venv's own shim — so the card's `shutil.which("python3")` default quietly keeps the
    smoke inside the venv it was meant to step outside of. This walks PATH instead.
    """
    found: list[str] = []
    seen: set[Path] = set()
    for directory in os.environ.get("PATH", "").split(os.pathsep):
        if not directory:
            continue
        for name in ("python3", "python"):
            candidate = Path(directory) / name
            if not candidate.is_file():
                continue
            if candidate in seen:
                continue
            seen.add(candidate)
            found.append(str(candidate))
    return found


def _is_build_venv(candidate: str) -> bool:
    """True for an interpreter living in the venv that built the artifact.

    Symlinks are deliberately NOT resolved: a venv's `bin/python` resolves out to the
    base CPython, which would hide the very venv this check exists to detect.
    """
    return Path(candidate).parent == Path(sys.prefix) / "bin"


def default_python_exe() -> str:
    """Interpreter for the smoke: a bare Python outside the build venv, if one is usable.

    Preferred order is (1) a non-venv Python new enough to run gateclerk, (2) any other
    usable Python, (3) `sys.executable`. Falling back to the venv is still honest,
    because every run carries `-I -S`, which keeps site-packages off `sys.path` — the
    venv cannot lend the artifact a module the archive is missing.
    """
    capable = [c for c in _candidate_interpreters() if _interpreter_runs_gateclerk(c)]
    for pool in ([c for c in capable if not _is_build_venv(c)], capable):
        if pool:
            return pool[0]
    return sys.executable


def smoke_artifact(
    artifact: Path,
    *,
    python_exe: str | None = None,
) -> dict[str, Any]:
    """Run the end-to-end smoke battery against `artifact` in an isolated temporary HOME.

    Every invocation carries `-I -S`: `-S` skips `site`, so no site-packages directory
    lands on `sys.path` and any dependency the `.pyz` failed to vendor fails here instead
    of on a production host (card GC-P13).
    """
    if python_exe is None:
        python_exe = default_python_exe()
    if not artifact.is_file():
        raise RuntimeError(f"artifact not found: {artifact}")

    with tempfile.TemporaryDirectory(prefix="gateclerk-smoke-") as tmp:
        tmp_root = Path(tmp)
        home_dir = tmp_root / "home"
        home_dir.mkdir(parents=True)
        cred_file = home_dir / "credentials.json"

        env = {
            **os.environ,
            "HOME": str(home_dir),
            "GATECLERK_CREDENTIALS_FILE": str(cred_file),
            "HTTP_PROXY": "http://127.0.0.1:9",
            "HTTPS_PROXY": "http://127.0.0.1:9",
            "NO_PROXY": "127.0.0.1,localhost",
            "PYTHONDONTWRITEBYTECODE": "1",
        }

        def _run(*args: str) -> subprocess.CompletedProcess[str]:
            return subprocess.run(  # noqa: S603
                [python_exe, "-I", "-S", str(artifact), *args],
                capture_output=True,
                text=True,
                env=env,
                timeout=120,
                check=False,
            )

        # 1. --version
        ver_proc = _run("--version")
        if ver_proc.returncode != 0 or not ver_proc.stdout.strip().startswith("gateclerk "):
            raise RuntimeError(f"--version failed: {ver_proc.stdout} {ver_proc.stderr}")

        # 2. --help
        help_proc = _run("--help")
        if help_proc.returncode != 0 or "status" not in help_proc.stdout:
            raise RuntimeError(f"--help failed: {help_proc.stdout} {help_proc.stderr}")

        # 3. creds set / get / remove (Linux/keychain-free 0600 file backend)
        pw_file = tmp_root / "pw.txt"
        pw_file.write_text("fake-smoke-pw\n", encoding="utf-8")
        set_proc = _run(
            "creds",
            "set",
            "gateclerk-demo-site-a-192.0.2.10",
            "--file",
            str(pw_file),
            "-o",
            "json",
        )
        if set_proc.returncode != 0:
            raise RuntimeError(f"creds set failed: {set_proc.stdout} {set_proc.stderr}")

        # 4. demo demo (one-command offline loop: fake device + sqlite + mock https + csv sinks)
        demo_dir = tmp_root / "demo-run"
        demo_proc = _run("demo", "demo", "--root", str(demo_dir), "--ticks", "1", "-o", "json")
        if demo_proc.returncode != 0:
            raise RuntimeError(f"demo demo failed: {demo_proc.stdout} {demo_proc.stderr}")

        # 5. status & export config on a synthetic sites.toml
        state_dir = tmp_root / "state"
        state_dir.mkdir()
        sites_toml = tmp_root / "sites.toml"
        sites_toml.write_text(
            f"""\
[[site]]
name = "demo-site-a"
host = "192.0.2.10"
iana_tz = "Europe/Bucharest"
device_code = "DEMO-A-1"
db_path = "{state_dir / "gateclerk-demo-site-a.sqlite3"}"
""",
            encoding="utf-8",
        )
        status_proc = _run(
            "status",
            "--config",
            str(sites_toml),
            "--state-root",
            str(state_dir),
            "-o",
            "json",
        )
        if status_proc.returncode != 0:
            raise RuntimeError(f"status failed: {status_proc.stdout} {status_proc.stderr}")
        status_row = json.loads(status_proc.stdout.strip().splitlines()[-1])

        export_proc = _run("export", "config", "--config", str(sites_toml), "--format", "jsonl")
        if export_proc.returncode != 0:
            raise RuntimeError(f"export config failed: {export_proc.stdout} {export_proc.stderr}")

        return {
            "artifact": artifact.name,
            "sha256": sha256_of(artifact),
            "python": python_exe,
            "isolated": True,
            "version": ver_proc.stdout.strip(),
            "status_verdict": status_row.get("verdict"),
            "demo_ok": True,
        }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Verify SHA256SUMS and smoke-test built artifact.")
    parser.add_argument("--dist-dir", type=Path, default=Path("dist"))
    parser.add_argument("--target", default=None, help="Target name (default: auto-detect host).")
    parser.add_argument(
        "--expect-host-target",
        default=None,
        help="Fail unless the host platform auto-detects to this target (CI pairing gate).",
    )
    parser.add_argument(
        "--print-checks",
        action="store_true",
        help="Print a `sha256sum -c`-style OK line per verified artifact before executing.",
    )
    args = parser.parse_args(argv)

    verified = verify_sha256sums(args.dist_dir)
    target = args.target or detect_host_target()
    host = detect_host_target()
    if args.expect_host_target:
        host = assert_host_matches_target(args.expect_host_target)
    if args.print_checks:
        print_sha256_check_lines(args.dist_dir, verified)
    print(f"host target: {host}; artifact target: {target}")
    matches = [p for name, p in verified.items() if name.endswith(f"-{target}.pyz")]
    if not matches:
        raise RuntimeError(f"no artifact for target {target!r} in {list(verified)}")

    report = smoke_artifact(matches[0])
    report["host_target"] = host
    print(json.dumps(report, indent=2))
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
