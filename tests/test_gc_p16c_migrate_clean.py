"""GC-P16c — `gateclerk migrate clean`: a TTL purge for enrollment bundles and run journals.

What a reviewer should be able to read out of this file
-------------------------------------------------------
Bundles hold full names, card numbers and biometric templates, and run journals hold the
same payloads; both used to live forever. The command is a *report first* verb, so every
case below states what the inventory is and what survived, and the two properties the card
refuses to trade away are pinned separately:

* dry-run by default            `test_dry_run_lists_old_bundles_and_deletes_nothing`
                                 `test_clean_command_defaults_to_dry_run`
* nothing outside bundles/ runs/ dies
                                `test_apply_removes_only_old_artifacts` (a `probes/`
                                 DIRECTORY and a stray FILE under `bundles/` both survive)
                                 `test_mtime_exactly_at_cutoff_is_kept` (the cutoff is
                                 strict, not inclusive)

The age model is the directory's own mtime, so the fixtures stamp mtimes with `os.utime`
instead of sleeping or faking a clock: a TTL that could only be exercised through an
injected clock would never be exercised against a real filesystem.
"""

from __future__ import annotations

import json
import os
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from typer.testing import CliRunner

from gateclerk.cli import app
from gateclerk.migrate_bundle import CleanReport, clean_artifacts

runner = CliRunner()

#: The card's default TTL, spelled once so a change to it has to touch these tests.
TTL_DAYS = 7
OLD_DAYS = 30


def _dir(path: Path, *, age_days: float) -> Path:
    """Create a directory holding one file, then stamp its mtime `age_days` in the past.

    The file is written BEFORE the stamp: writing into a directory bumps its mtime, and a
    fixture that aged the dir first would silently measure the wrong thing.
    """
    path.mkdir(parents=True)
    (path / "manifest.json").write_text("{}\n", encoding="utf-8")
    _stamp(path, age_days=age_days)
    return path


def _file(path: Path, *, age_days: float) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("{}\n", encoding="utf-8")
    moment = (datetime.now(UTC) - timedelta(days=age_days)).timestamp()
    os.utime(path, (moment, moment))
    return path


def _stamp(path: Path, *, age_days: float) -> Path:
    moment = (datetime.now(UTC) - timedelta(days=age_days)).timestamp()
    os.utime(path, (moment, moment))
    return path


def _cutoff(now: datetime | None = None) -> datetime:
    """The cutoff the command derives for `--older-than 7d`, at whole-second precision.

    `microsecond=0` keeps the boundary fixture exact: the mtime is stamped from this same
    value's `timestamp()`, so `mtime == cutoff` is arithmetic that actually holds.
    """
    return ((now or datetime.now(UTC)) - timedelta(days=TTL_DAYS)).replace(microsecond=0)


def _layout(root: Path) -> dict[str, Path]:
    """A private root with the shape the migrate group actually writes (§2/§5a).

    Two old artifacts (one per bucket), one new artifact per bucket, a stray FILE inside
    `bundles/` (the writer's `*.partial` sibling is exactly this shape) and an old
    DIRECTORY plus an old file under `probes/` — the probe cache is a read gate, not PII.
    """
    return {
        "old_bundle": _dir(root / "bundles" / "site-a-20260101", age_days=OLD_DAYS),
        "new_bundle": _dir(root / "bundles" / "site-a-today", age_days=0),
        "stray_file": _file(root / "bundles" / "site-a.partial", age_days=OLD_DAYS),
        "old_run": _dir(root / "runs" / "run-old", age_days=OLD_DAYS),
        "new_run": _dir(root / "runs" / "run-new", age_days=0),
        "old_probe": _dir(root / "probes" / "site-a", age_days=OLD_DAYS),
        "old_probe_file": _file(root / "probes" / "site-a.json", age_days=OLD_DAYS),
    }


# --- the cleaner, offline ------------------------------------------------------------------


def test_bucket_names_match_the_root_layout_owner() -> None:
    """`clean_artifacts` may not spell its buckets differently from the layout's owner.

    ``migrate_apply`` owns ``BUNDLES_DIR_NAME`` / ``RUNS_DIR_NAME`` and imports
    ``migrate_bundle``, so the constants cannot be imported back without a cycle — this
    test is the non-cycle form of that import. A rename on one side only would leave the
    purge walking a directory that never exists: a no-op that reports success.
    """
    from gateclerk import migrate_apply, migrate_bundle

    assert migrate_bundle._BUNDLES_BUCKET == migrate_apply.BUNDLES_DIR_NAME
    assert migrate_bundle._RUNS_BUCKET == migrate_apply.RUNS_DIR_NAME
    assert migrate_apply.PROBES_DIR_NAME not in {
        migrate_bundle._BUNDLES_BUCKET,
        migrate_bundle._RUNS_BUCKET,
    }, "probes/ must never become a purge bucket"


def test_a_future_cutoff_is_refused_not_run(tmp_path: Path) -> None:
    """The one job of `clean_artifacts(now=...)`: a cutoff ahead of the clock matches all.

    `mtime < older_than` with a cutoff in the future is true for every artifact on disk, so
    a sign error in a caller would be a total wipe. The guard makes it a refusal, and it is
    reachable only through `now` — which is why the CLI threads its own clock value in.
    """
    root = tmp_path / "gateclerk"
    made = _layout(root)
    now = datetime.now(UTC)

    with pytest.raises(ValueError, match="ahead of now"):
        clean_artifacts(root, older_than=now + timedelta(days=1), apply=True, now=now)

    assert made["old_bundle"].is_dir()
    assert made["old_run"].is_dir()


def test_the_library_default_is_a_dry_run_too(tmp_path: Path) -> None:
    """`clean_artifacts(root, older_than=...)` with NO `apply` deletes nothing.

    Every other case here passes `apply` explicitly, so without this one the keyword's
    DEFAULT — the thing that makes the whole feature "report first" — is unpinned: flipping
    `apply: bool = False` to `True` leaves the suite green, and the CLI's own default is a
    separate default. Probe P4 is what found that.
    """
    root = tmp_path / "gateclerk"
    made = _layout(root)

    report = clean_artifacts(root, older_than=_cutoff())

    assert report.apply is False
    assert report.count == 2
    assert made["old_bundle"].is_dir()
    assert made["old_run"].is_dir()


def test_dry_run_lists_old_bundles_and_deletes_nothing(tmp_path: Path) -> None:
    root = tmp_path / "gateclerk"
    made = _layout(root)
    cutoff = _cutoff()

    report = clean_artifacts(root, older_than=cutoff, apply=False)

    assert isinstance(report, CleanReport)
    assert report.root == root
    assert report.older_than == cutoff
    assert report.apply is False, "apply must default to False: a report is not a delete"
    assert report.bundles == (made["old_bundle"],)
    assert report.runs == (made["old_run"],)
    assert report.count == 2
    # Nothing was deleted: the report is the only effect of a default run.
    for key in ("old_bundle", "new_bundle", "old_run", "new_run", "old_probe"):
        assert made[key].is_dir(), key
    assert made["stray_file"].is_file()


def test_apply_removes_only_old_artifacts(tmp_path: Path) -> None:
    root = tmp_path / "gateclerk"
    made = _layout(root)
    cutoff = _cutoff()

    report = clean_artifacts(root, older_than=cutoff, apply=True)

    assert report.apply is True
    assert report.count == 2
    assert not made["old_bundle"].exists()
    assert not made["old_run"].exists()
    # Newer artifacts, the probe cache (a DIRECTORY here, not just a file) and a
    # non-directory entry inside bundles/ are all untouched.
    assert made["new_bundle"].is_dir()
    assert made["new_run"].is_dir()
    assert made["old_probe"].is_dir(), "probes/ is never scanned or deleted"
    assert made["old_probe_file"].is_file()
    assert made["stray_file"].is_file(), "only directories are candidates"
    assert (root / "bundles").is_dir() and (root / "runs").is_dir(), "the buckets remain"


@pytest.mark.parametrize("seconds_before_cutoff", [0, 1])
def test_mtime_exactly_at_cutoff_is_kept(tmp_path: Path, seconds_before_cutoff: int) -> None:
    """The cutoff is strict: a path stamped AT the cutoff is not "older than" it.

    Paired with its sibling case one second on the older side, so the comparison cannot be
    flipped to inclusive (or dropped to "everything") without one of the two failing.
    """
    root = tmp_path / "gateclerk"
    cutoff = _cutoff()
    bundle = root / "bundles" / "boundary"
    bundle.mkdir(parents=True)
    (bundle / "manifest.json").write_text("{}\n", encoding="utf-8")
    _stamp(bundle, age_days=0)
    moment = cutoff.timestamp() - seconds_before_cutoff
    os.utime(bundle, (moment, moment))

    report = clean_artifacts(root, older_than=cutoff, apply=True)

    kept = seconds_before_cutoff == 0
    assert (report.count == 0) is kept, f"at -{seconds_before_cutoff}s: {report}"
    assert bundle.exists() is kept


def test_missing_buckets_are_an_empty_report_not_an_error(tmp_path: Path) -> None:
    """A site that never migrated has no `bundles/` and no `runs/` — that is not a failure."""
    report = clean_artifacts(tmp_path / "never-used", older_than=_cutoff(), apply=True)
    assert report.count == 0
    assert report.bundles == ()
    assert report.runs == ()


# --- the CLI surface -----------------------------------------------------------------------


def test_clean_command_defaults_to_dry_run(tmp_path: Path) -> None:
    root = tmp_path / "gateclerk"
    made = _layout(root)

    result = runner.invoke(app, ["migrate", "clean", "--bundles-root", str(root)])

    assert result.exit_code == 0, result.output
    assert "would delete 2 artifact(s)" in result.output
    assert str(made["old_bundle"]) in result.output
    assert str(made["old_run"]) in result.output
    assert str(made["new_bundle"]) not in result.output
    for key in ("old_bundle", "new_bundle", "old_run", "new_run", "old_probe"):
        assert made[key].is_dir(), f"{key} survived a DRY RUN only by luck"
    assert made["old_probe_file"].is_file()


def test_clean_command_apply_deletes(tmp_path: Path) -> None:
    root = tmp_path / "gateclerk"
    made = _layout(root)

    result = runner.invoke(app, ["migrate", "clean", "--bundles-root", str(root), "--apply"])

    assert result.exit_code == 0, result.output
    assert "deleted 2 artifact(s)" in result.output
    assert not made["old_bundle"].exists()
    assert not made["old_run"].exists()
    assert made["new_bundle"].is_dir()
    assert made["new_run"].is_dir()
    assert made["old_probe"].is_dir()
    assert made["stray_file"].is_file()


def test_clean_command_json_reports_the_inventory(tmp_path: Path) -> None:
    root = tmp_path / "gateclerk"
    made = _layout(root)

    result = runner.invoke(app, ["migrate", "clean", "--bundles-root", str(root), "-o", "json"])

    assert result.exit_code == 0, result.output
    (payload,) = [json.loads(line) for line in result.stdout.splitlines() if line.strip()]
    assert payload["root"] == str(root)
    assert payload["apply"] is False
    assert payload["bundles"] == [str(made["old_bundle"])]
    assert payload["runs"] == [str(made["old_run"])]
    assert payload["count"] == 2
    assert payload["older_than"]
    assert datetime.fromisoformat(payload["older_than"]).tzinfo is not None


@pytest.mark.parametrize("value", ["0d", "-3d", "abc", "7w", ""])
def test_invalid_older_than_is_exit_2(tmp_path: Path, value: str) -> None:
    """A TTL nobody can read is not executed, and it exits 2 (usage/config, CLI-CONVENTIONS)."""
    root = tmp_path / "gateclerk"
    made = _layout(root)

    result = runner.invoke(
        app, ["migrate", "clean", "--bundles-root", str(root), "--older-than", value]
    )

    assert result.exit_code == 2, f"{value!r} exited {result.exit_code}: {result.output}"
    for key in ("old_bundle", "old_run"):
        assert made[key].is_dir(), f"{value!r} was refused but still deleted something"
