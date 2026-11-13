# GC-P13 — Self-contained `.pyz` release artifact

BOARD: gateclerk   DEPENDS ON: —   GATED: no   COVERS: GC-10 / —

## WHY

`scripts/build_dist.py` builds per-OS `.pyz` zipapps that contain only `src/gateclerk`.
On a host with a bare `python3` the artifact exits with `ModuleNotFoundError: No module
named 'typer'`. `scripts/smoke_artifact.py` hides this by running the `.pyz` with the
developer's virtualenv interpreter. R7: a release artifact must run on the production host
without the dev environment.

## VERIFY

```bash
uv run --frozen python - <<'PY'
import zipfile
from pathlib import Path
import scripts.build_dist as b
out = Path(tempfile.gettempdir()) / "gc-p13-verify.pyz"
b.build_target_zipapp(Path.cwd(), "0.1.0", "linux-x86_64", out)
names = zipfile.ZipFile(out).namelist()
print("typer vendored:", any(n.startswith("typer/") for n in names))
print("httpx vendored:", any(n.startswith("httpx/") for n in names))
print("rich vendored:", any(n.startswith("rich/") for n in names))
PY
```

Still broken while all three print `False`.

## FILES

- `scripts/build_dist.py:126-153` — `build_target_zipapp` writes only
  `src/gateclerk/**/*.py` plus `__main__.py`.
- `scripts/build_dist.py:175-214` — `build_all` publishes the three `.pyz` files in
  `SHA256SUMS`.
- `scripts/smoke_artifact.py:124` — `python_exe: str = sys.executable`; the smoke runs the
  artifact inside the dev venv.
- `scripts/smoke_artifact.py:146-157` — `_run` invokes `[python_exe, str(artifact), *args]`.
- `tests/test_release_packaging.py:59` — expects four artifacts (tarball + three zipapps).
- `.github/workflows/release.yml:110` — uploads `dist/gateclerk-*.pyz`.

## CHANGE

1. In `scripts/build_dist.py`, add the pure-Python runtime packages. Names are import
   names, not distribution names:
   ```python
   RUNTIME_PACKAGES: tuple[str, ...] = (
       "typer", "click", "httpx", "httpcore", "anyio", "idna", "sniffio",
       "certifi", "h11", "rich", "markdown_it", "mdurl", "pygments",
       "openpyxl", "et_xmlfile",
   )
   ```
2. Add a vendoring helper:
   ```python
   def _vendor_runtime_packages(staging: Path) -> None:
       import importlib.util
       import shutil

       for name in RUNTIME_PACKAGES:
           spec = importlib.util.find_spec(name)
           if spec is None or not spec.submodule_search_locations:
               raise ValueError(f"runtime package {name!r} is not installed in this build env")
           source = Path(next(iter(spec.submodule_search_locations)))
           shutil.copytree(
               source,
               staging / name,
               ignore=shutil.ignore_patterns("__pycache__", "*.pyc", "*.pyo"),
           )
   ```
3. Rewrite `build_target_zipapp` to stage then archive:
   ```python
   import shutil
   import tempfile
   import zipapp

   out_path.parent.mkdir(parents=True, exist_ok=True)
   with tempfile.TemporaryDirectory(prefix="gateclerk-pyz-") as tmp:
       staging = Path(tmp)
       shutil.copytree(
           repo_dir / "src" / "gateclerk",
           staging / "gateclerk",
           ignore=shutil.ignore_patterns("__pycache__", "*.pyc", "*.pyo"),
       )
       _vendor_runtime_packages(staging)
       (staging / "__main__.py").write_text(
           f"# target: {target} version: {version}\n"
           "from gateclerk.cli import main\n"
           "if __name__ == '__main__':\n"
           "    raise SystemExit(main())\n",
           encoding="utf-8",
       )
       zipapp.create_archive(
           staging,
           target=out_path,
           interpreter="/usr/bin/env python3",
           compressed=True,
       )
   out_path.chmod(out_path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
   return out_path
   ```
   Remove the old `io`/`zipfile` use only if nothing else in the module needs it.
4. In `scripts/smoke_artifact.py`, make the smoke run outside the venv:
   - default `python_exe` to `shutil.which("python3") or sys.executable`;
   - invoke `[python_exe, "-I", "-S", str(artifact), *args]` in `_run`.
   `-S` disables site-packages, so a missing vendored package fails the smoke.
5. Keep the tarball, formula and `SHA256SUMS` output unchanged.

What must NOT change:

- The artifact names (`gateclerk-<ver>-<target>.pyz`), the `SHA256SUMS` format and the
  Homebrew formula input (the tarball).
- The zipapp's `__main__` entry point (`gateclerk.cli:main`).
- No third-party package is added to `pyproject.toml` by this card.

## TESTS

Write `tests/test_gc_p13_selfcontained_pyz.py` first and run:

```bash
uv run --frozen pytest -q tests/test_gc_p13_selfcontained_pyz.py
```

Copy the artifact build from `tests/test_release_packaging.py:40-70`.

Tests:

- `test_zipapp_contains_the_runtime_packages` — build one `.pyz`; assert
  `typer/__init__.py`, `httpx/__init__.py`, `rich/__init__.py` and `click/__init__.py`
  are in the archive.
- `test_zipapp_runs_with_site_packages_disabled` — run
  `[sys.executable, "-I", "-S", str(pyz), "--version"]`; exit 0 and output starts with
  `gateclerk `.
- `test_zipapp_help_runs_with_site_packages_disabled` — same for `--help`; exit 0 and the
  output contains `status`.
- `test_build_all_still_emits_three_zipapps_and_the_tarball` — `build_all` returns the same
  four paths and `SHA256SUMS` has four lines.

## GATE

```bash
uv run --frozen pytest -q
uv run --frozen ruff check src/gateclerk
uv run --frozen ruff check scripts
```

## ACCEPT

- [ ] The `.pyz` contains `typer`, `click`, `httpx`, `httpcore`, `anyio`, `idna`,
  `sniffio`, `certifi`, `h11`, `rich`, `markdown_it`, `mdurl`, `pygments`, `openpyxl`,
  `et_xmlfile`.
- [ ] `python3 -I -S dist/gateclerk-*.pyz --version` exits 0 on a host without the dev venv.
- [ ] `--help` exits 0.
- [ ] `SHA256SUMS` and the formula still cover the tarball and three zipapps.
- [ ] Full pytest and ruff are green.

## OUT

`pyproject.toml` dependencies, the Docker image, the systemd/launchd install, and the
tarball contents. Do not remove the `.pyz` from the release; make it self-contained.

## HANDOFF

Branch base `origin/main`; PR target `feat/gateclerk-finish`.

1. Run the GATE.
2. Open the PR against `feat/gateclerk-finish`.
3. When the gate is green and the PR is mergeable, run `gh pr merge <number> --squash`
   yourself.
4. Never merge into `main`/`master`; never force-push.
5. If the PR is not mergeable (conflict), rebase on `origin/feat/gateclerk-finish`, re-run
   the GATE, then merge. If that fails twice, stop and report `LEFT:`.

The card is complete only after the merge.

DONE: PR URL and merge commit.
LEFT: anything not merged, with the reason.
