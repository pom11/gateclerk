# GC-P16c — TTL cleanup for enrollment bundles and run journals

BOARD: gateclerk   DEPENDS ON: GC-P16b   GATED: no   COVERS: GC-14 / —

## WHY

E1 bundles and run journals contain full names, card numbers and biometric templates and
stay on disk forever. After a hardware swap is verified in BC, the local rollback copy is
no longer needed. GC-14 asks for a TTL purge. This card adds `gateclerk migrate clean`,
dry-run by default, and never touches `probes/` or a bundle newer than the cutoff.

## VERIFY

```bash
grep -rn "migrate clean\|clean_artifacts\|older.than" src/gateclerk --include='*.py'
```

Still broken while the command prints nothing (no `clean` subcommand under `migrate`).

## FILES

- `src/gateclerk/migrate_apply.py:180-182` — `BUNDLES_DIR_NAME = "bundles"`,
  `PROBES_DIR_NAME = "probes"`, `RUNS_DIR_NAME = "runs"`.
- `src/gateclerk/migrate_apply.py:404-421` — `bundle_root(explicit)` returns
  `~/gateclerk/bundles` by default; `probes_root(root)` and `runs_root(root)`.
- `src/gateclerk/migrate_bundle.py:758-950` — `write_bundle` / `read_bundle`; bundle
  directories live under `<root>/bundles/`.
- `src/gateclerk/migrate_cmds.py:100-120` — the `probe` command is the pattern for a new
  `@migrate_app.command("clean")`; `BundleRootOpt` is at `:59-66`.
- `src/gateclerk/migrate_cmds.py:38-46` — `__all__`; add any new public name.

## CHANGE

1. Add a report dataclass and a cleaner to `src/gateclerk/migrate_bundle.py`:
   ```python
   @dataclass(frozen=True, slots=True)
   class CleanReport:
       root: Path
       older_than: datetime
       apply: bool
       bundles: tuple[Path, ...] = ()
       runs: tuple[Path, ...] = ()

       @property
       def count(self) -> int:
           return len(self.bundles) + len(self.runs)


   def clean_artifacts(
       root: Path,
       *,
       older_than: datetime,
       apply: bool = False,
       now: datetime | None = None,
   ) -> CleanReport:
       """List (and with `apply`, delete) bundle/run dirs older than the cutoff.

       `probes/` is never touched: the 7-day probe cache is a read gate, not a PII
       artifact. A path is old when its directory mtime is before `older_than`.
       """
       import shutil

       root = Path(root)
       chosen_bundles: list[Path] = []
       chosen_runs: list[Path] = []
       for base, bucket in ((root / "bundles", chosen_bundles), (root / "runs", chosen_runs)):
           if not base.is_dir():
               continue
           for child in sorted(base.iterdir()):
               if not child.is_dir():
                   continue
               try:
                   mtime = datetime.fromtimestamp(child.stat().st_mtime, tz=UTC)
               except OSError:
                   continue
               if mtime < older_than:
                   bucket.append(child)
       if apply:
           for path in (*chosen_bundles, *chosen_runs):
               shutil.rmtree(path)
       return CleanReport(
           root=root, older_than=older_than, apply=apply,
           bundles=tuple(chosen_bundles), runs=tuple(chosen_runs),
       )
   ```
   Export `CleanReport`/`clean_artifacts` in `migrate_bundle.__all__` (check the existing
   `__all__` and add them in order).
2. Add the command in `src/gateclerk/migrate_cmds.py` after `undo`:
   ```python
   @migrate_app.command("clean")
   def migrate_clean(
       bundles_root: BundleRootOpt = None,
       older_than: Annotated[
           str,
           typer.Option("--older-than", help="Delete artifacts older than this age (e.g. 7d)."),
       ] = "7d",
       apply_writes: Annotated[
           bool,
           typer.Option("--apply", help="Actually delete. Without it this is a dry run."),
       ] = False,
       output: OutputOpt = OutputFormat.TABLE,
   ) -> None:
       """Remove old enrollment bundles and run journals (dry-run by default)."""
       from gateclerk import migrate_apply as apply_mod
       from gateclerk import migrate_bundle as bundle_mod

       fmt = output
       try:
           days = int(older_than.strip().rstrip("d"))
           if days <= 0:
               raise ValueError("--older-than must be a positive number of days")
       except ValueError as exc:
           raise _config_exit(fmt, f"invalid --older-than {older_than!r}: use e.g. 7d") from exc
       root = apply_mod.bundle_root(bundles_root)
       cutoff = cli_shared._now() - timedelta(days=days)
       report = bundle_mod.clean_artifacts(root, older_than=cutoff, apply=apply_writes)
       payload = {
           "root": str(report.root),
           "older_than": report.older_than.isoformat(),
           "apply": report.apply,
           "bundles": [str(p) for p in report.bundles],
           "runs": [str(p) for p in report.runs],
           "count": report.count,
       }
       if fmt is OutputFormat.TABLE:
           typer.echo(f"{'deleted' if report.apply else 'would delete'} {report.count} artifact(s)")
           for path in (*report.bundles, *report.runs):
               typer.echo(str(path))
       else:
           render([payload], fmt=fmt.value)
   ```
   Add the `timedelta` import (`from datetime import timedelta`). Use `cli_shared._now()`
   for the cutoff so the command follows the repo's injected-clock rule.
   `OutputFormat` and `render` are already imported.
3. The default is a dry run; only `--apply` deletes. Keep the root resolution through
   `bundle_root` so `$GATECLERK_BUNDLE_ROOT` and `--bundles-root` behave like the other
   migrate commands.

What must NOT change:

- `probes/` is never scanned or deleted.
- A bundle/journal newer than the cutoff is kept.
- `migrate export`, `diff`, `apply`, `undo` and their journals are unchanged.
- No recursive delete outside `<root>/bundles` and `<root>/runs`.

## TESTS

Write `tests/test_gc_p16c_migrate_clean.py` first and run:

```bash
uv run --frozen pytest -q tests/test_gc_p16c_migrate_clean.py
```

Copy the bundle root setup from `tests/test_e1_01_bundle_export.py:227` and the Typer
invocation pattern from `tests/test_e1_07_cli.py`.

Tests:

- `test_dry_run_lists_old_bundles_and_deletes_nothing` — create an old bundle dir and an
  old run dir under a temp root; `clean_artifacts(root, older_than=cutoff, apply=False)`
  reports both and both still exist.
- `test_apply_removes_only_old_artifacts` — old bundle/run removed; a new bundle, a new run
  and `probes/old.json` remain.
- `test_clean_command_defaults_to_dry_run` — invoke `migrate clean --bundles-root <tmp>`;
  exit 0, output says `would delete`, files remain.
- `test_clean_command_apply_deletes` — same with `--apply`; files gone.
- `test_invalid_older_than_is_exit_2` — `--older-than 0d` refuses with exit 2.

## GATE

```bash
uv run --frozen pytest -q
uv run --frozen ruff check src/gateclerk
```

## ACCEPT

- [ ] `gateclerk migrate clean` exists and is dry-run by default.
- [ ] `--apply` deletes only `<root>/bundles` and `<root>/runs` entries older than the
  cutoff.
- [ ] `probes/`, newer artifacts and non-directory files are untouched.
- [ ] Invalid `--older-than` exits 2.
- [ ] Full pytest and ruff are green.

## OUT

`src/gateclerk/migrate_export.py`, `migrate_apply.py`, `migrate_write*.py`,
`migrate_faces.py`, `migrate_fingerprints.py`, and the probe cache.

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
