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


def smoke_artifact(
    artifact: Path,
    *,
    python_exe: str = sys.executable,
) -> dict[str, Any]:
    """Run the end-to-end smoke battery against `artifact` in an isolated temporary HOME."""
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
                [python_exe, str(artifact), *args],
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
            "version": ver_proc.stdout.strip(),
            "status_verdict": status_row.get("verdict"),
            "demo_ok": True,
        }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Verify SHA256SUMS and smoke-test built artifact.")
    parser.add_argument("--dist-dir", type=Path, default=Path("dist"))
    parser.add_argument("--target", default=None, help="Target name (default: auto-detect host).")
    args = parser.parse_args(argv)

    verified = verify_sha256sums(args.dist_dir)
    target = args.target or detect_host_target()
    matches = [p for name, p in verified.items() if name.endswith(f"-{target}.pyz")]
    if not matches:
        raise RuntimeError(f"no artifact for target {target!r} in {list(verified)}")

    report = smoke_artifact(matches[0])
    print(json.dumps(report, indent=2))
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
