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
* a purge that would eat the only undo evidence says so, and still purges
                                `test_a_run_with_no_undo_journal_is_unresolved`
                                `test_unresolved_runs_are_still_deleted_and_exit_stays_0`

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


def _run(root: Path, name: str, *, journals: tuple[str, ...], age_days: float) -> Path:
    """A `runs/<name>` dir as §5a lays it out: one file per journal, then aged.

    `_dir` is not enough here because this card's question is about WHICH files a run dir
    holds — a manifest-shaped fixture cannot distinguish a finished run from one that
    stopped halfway. Files are written before the stamp for `_dir`'s reason: writing into
    a directory bumps its mtime, and an aged-first fixture silently measures the stamp.
    """
    path = root / "runs" / name
    path.mkdir(parents=True)
    for file_name in journals:
        (path / file_name).write_text('{"phase": "cards"}\n', encoding="utf-8")
    return _stamp(path, age_days=age_days)


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


# --- unresolved runs: what a purge would take the undo of (GC-P16c follow-up) ----------------


def test_journal_suffix_matches_the_journal_owner() -> None:
    """The undo-journal check must spell the file name as the naming rule's owner does.

    Same non-cycle argument as `test_bucket_names_match_the_root_layout_owner`: the rule is
    `migrate_apply`'s (`JOURNAL_SUFFIX`) and `migrate_apply` imports `migrate_bundle`, so the
    spelling is repeated and pinned equal instead of imported. The failure mode this guards
    is the worst one available to a warning: a rename on the owner's side alone would make
    every run dir look FINISHED, and every other test in this file would stay green.
    """
    from gateclerk import migrate_apply, migrate_bundle

    assert migrate_bundle._JOURNAL_SUFFIX == migrate_apply.JOURNAL_SUFFIX
    # Spelled-out side first: SIM300 reads a computed right-hand side as the Yoda form.
    assert f".undo.{migrate_apply.JOURNAL_SUFFIX}" == migrate_bundle._UNDO_SUFFIX


def test_a_run_with_no_undo_journal_is_unresolved(tmp_path: Path) -> None:
    """`<phase>.jsonl` without `<phase>.undo.jsonl` is a write nothing has rolled back.

    The phase here is spelled `apply` and is deliberately NOT one of `migrate_apply.PHASES`:
    the check is mechanical about the naming rule rather than a list of phases someone
    decided may lack an undo journal, and pinning it with a name outside that list is what
    keeps the list from creeping back in.
    """
    root = tmp_path / "gateclerk"
    half = _run(root, "run-half-done", journals=("apply.jsonl",), age_days=OLD_DAYS)

    report = clean_artifacts(root, older_than=_cutoff())

    assert report.runs == (half,), "it is still an artifact the purge lists"
    assert report.unresolved_runs == (half,)
    assert report.count == 1, "naming the loss must not change what is being deleted"


def test_a_run_whose_undo_journal_exists_is_not_unresolved(tmp_path: Path) -> None:
    """The same directory with BOTH files is a rolled-back run — purging it loses nothing."""
    root = tmp_path / "gateclerk"
    done = _run(root, "run-done", journals=("apply.jsonl", "apply.undo.jsonl"), age_days=OLD_DAYS)

    report = clean_artifacts(root, older_than=_cutoff())

    assert report.runs == (done,)
    assert report.unresolved_runs == ()


def test_any_phase_missing_its_undo_journal_makes_the_run_unresolved(tmp_path: Path) -> None:
    """The rule is per journal, not "the first file decides".

    One paired phase and one unpaired phase is exactly the shape of a run that stopped
    between phases, which is the case the warning is for.
    """
    root = tmp_path / "gateclerk"
    stalled = _run(
        root,
        "run-stalled",
        journals=("cards.jsonl", "cards.undo.jsonl", "faces.jsonl"),
        age_days=OLD_DAYS,
    )

    report = clean_artifacts(root, older_than=_cutoff())

    assert report.unresolved_runs == (stalled,)


def test_an_undo_journal_alone_is_not_an_unfinished_run(tmp_path: Path) -> None:
    """An undo journal is the answer to a journal, not evidence of a write of its own."""
    root = tmp_path / "gateclerk"
    odd = _run(root, "run-odd", journals=("apply.undo.jsonl",), age_days=OLD_DAYS)

    report = clean_artifacts(root, older_than=_cutoff())

    assert report.runs == (odd,)
    assert report.unresolved_runs == ()


def test_an_unfinished_run_that_is_not_aged_is_not_named(tmp_path: Path) -> None:
    """`unresolved_runs` is a view of what the purge LISTS, not a watchdog over every run.

    A run in flight has no undo journal yet. Naming it would be wrong twice — it is not
    being deleted, and it is not unfinished.
    """
    root = tmp_path / "gateclerk"
    live = _run(root, "run-live", journals=("apply.jsonl",), age_days=0)

    report = clean_artifacts(root, older_than=_cutoff(), apply=True)

    assert report.runs == ()
    assert report.unresolved_runs == ()
    assert live.is_dir()


def test_the_apply_report_still_names_what_it_destroyed(tmp_path: Path) -> None:
    """The check runs BEFORE the delete, so an `--apply` pass is not an all-clear.

    Asked afterwards it would glob a directory it had just removed and report every run as
    resolved — the silent all-clear, in the one pass where the loss actually happened.
    """
    root = tmp_path / "gateclerk"
    half = _run(root, "run-half-done", journals=("apply.jsonl",), age_days=OLD_DAYS)

    report = clean_artifacts(root, older_than=_cutoff(), apply=True)

    assert not half.exists()
    assert report.unresolved_runs == (half,), "the destroyed run must still be named"


def test_unresolved_runs_are_still_deleted_and_exit_stays_0(tmp_path: Path) -> None:
    """The warning is not a gate: `--apply` deletes it and the exit code does not move.

    The card refuses a refusal, a new flag and a new exit code. A later change that turns
    this line into a block passes every other test here and fails this one.
    """
    root = tmp_path / "gateclerk"
    half = _run(root, "run-half-done", journals=("apply.jsonl",), age_days=OLD_DAYS)

    result = runner.invoke(app, ["migrate", "clean", "--bundles-root", str(root), "--apply"])

    assert result.exit_code == 0, result.output
    assert "deleted 1 artifact(s)" in result.output
    assert not half.exists(), "a warning that stopped the purge would be a policy, not a report"


def test_dry_run_table_names_the_unresolved_run(tmp_path: Path) -> None:
    """The dry-run report says which dirs hold the only thing `migrate undo` can replay."""
    root = tmp_path / "gateclerk"
    half = _run(root, "run-half-done", journals=("apply.jsonl",), age_days=OLD_DAYS)

    result = runner.invoke(app, ["migrate", "clean", "--bundles-root", str(root)])

    assert result.exit_code == 0, result.output
    (line,) = [ln for ln in result.output.splitlines() if "undo" in ln]
    assert "1 of those run dirs" in line, line
    assert str(half) in line, "the line names the directory, not just a count"
    assert "only thing `migrate undo` can replay" in line, line
    assert half.is_dir(), "a dry run is still a dry run"


def test_dry_run_table_adds_no_warning_when_nothing_is_unresolved(tmp_path: Path) -> None:
    """The trailing line is conditional, so the ordinary case stays the ordinary report."""
    root = tmp_path / "gateclerk"
    _layout(root)

    result = runner.invoke(app, ["migrate", "clean", "--bundles-root", str(root)])

    assert result.exit_code == 0, result.output
    assert "would delete 2 artifact(s)" in result.output
    assert "warning" not in result.output


def test_json_payload_carries_the_unresolved_key(tmp_path: Path) -> None:
    """The same fact in the machine-readable report, as a list of the same paths."""
    root = tmp_path / "gateclerk"
    half = _run(root, "run-half-done", journals=("apply.jsonl",), age_days=OLD_DAYS)
    _run(root, "run-done", journals=("faces.jsonl", "faces.undo.jsonl"), age_days=OLD_DAYS)

    result = runner.invoke(app, ["migrate", "clean", "--bundles-root", str(root), "-o", "json"])

    assert result.exit_code == 0, result.output
    (payload,) = [json.loads(line) for line in result.stdout.splitlines() if line.strip()]
    assert payload["unresolved_runs"] == [str(half)]
    assert payload["count"] == 2
    assert len(payload["runs"]) == 2, "the key is a subset of runs, not a third bucket"


def test_json_payload_carries_the_key_when_nothing_is_unresolved(tmp_path: Path) -> None:
    """The key is part of the schema, not a conditional field a consumer has to guess at."""
    root = tmp_path / "gateclerk"
    _layout(root)

    result = runner.invoke(app, ["migrate", "clean", "--bundles-root", str(root), "-o", "json"])

    assert result.exit_code == 0, result.output
    (payload,) = [json.loads(line) for line in result.stdout.splitlines() if line.strip()]
    assert payload["unresolved_runs"] == []
