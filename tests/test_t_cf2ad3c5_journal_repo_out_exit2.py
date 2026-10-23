"""Card t_cf2ad3c5: the journal's repo-out refusal must land on the CONFIG class (exit 2).

Found while auditing the callers for t_0d635ee2 (which fixed the same CLASS of mismatch on
the BUNDLE guard). `migrate_write._refuse_repo_path` raises a bare `JournalError`
(migrate_write.py:699), and `JournalError` is a plain `GateclerkError`, so on the
``apply --apply`` path the composer's `_Guard`/`_fail` maps it to exit 4 — the DEVICE class.
A run refused because the operator pointed the journal root inside a git repo never
touched the device: exit 4 tells the next reader "the box said no", which is wrong
(p1-08's table: 2 = fix your input). `migrate undo` already maps the same refusal to exit 2
through its own try/except ("undo refused: …") — the two commands disagree about one
refusal.

The contract pinned here, in the card's own order (FakeDevice-strict, offline):

* ``apply --apply --run-dir <inside a git repo>`` exits 2 (not 4), for BOTH ``-o table``
  and ``-o json``;
* the ``-o json`` error names the repo root and carries exit_code 2 — the guard's own
  wording, no CLI re-wording;
* zero journal bytes under the repo, and ZERO write requests on the fake's wire (the
  refusal precedes the transport, like the bundle guard precedes its first mkdir);
* a run dir outside any repo still runs normally — the mapping must not over-refuse;
* reuse: the refusal comes from `migrate_write._refuse_repo_path` (stub it -> the run
  proceeds and journals under the repo), so no second copy of the rule was added;
* the exception stays a `JournalError` (the module-level pins at
  test_e1_04_write_foundation.py:498 and test_e1_05_cards_phase.py:1346 name it) AND is now
  a `ConfigError` — that is what puts it on exit 2 through the ONE existing `_fail`
  mapping. Corruption refusals (schema/state on replay) deliberately stay where they are:
  a journal this module cannot read is not "fix your input" (the card's design decision).
* undo's exit-2 behavior for the SAME refusal is unchanged, pinned so a refactor cannot
  regress it.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

import gateclerk.migrate_write as migrate_write
from gateclerk.exceptions import ConfigError
from gateclerk.migrate_write import JournalError, WriteJournal
from test_e1_07_cli import (  # the E1-07 harness, reused not duplicated
    _export_pending_box,
    _last_bundle,
    _pending_target_box,
    conn,
    rows,
    run,
)

CONFIG_ERROR_EXIT = 2
DEVICE_ERROR_EXIT = 4


@pytest.fixture
def root(tmp_path: Path) -> Path:
    """E1-07's private bundles root, same shape (OUTSIDE any repo — the guards allow it)."""
    base = tmp_path / "gateclerk-private"
    base.mkdir()
    base.chmod(0o700)
    return base


@pytest.fixture
def git_repo(tmp_path: Path) -> Path:
    """A fake checkout under tmp_path — the `.git` DIRECTORY spelling (E1-01 precedent)."""
    repo = tmp_path / "public-repo"
    repo.mkdir()
    (repo / ".git").mkdir()
    return repo


# --- the CLI: apply --apply with a repo-resolving journal dir is exit 2 --------------------------


def test_apply_refuses_a_repo_run_dir_with_exit_2_json(
    monkeypatch: pytest.MonkeyPatch, root: Path, git_repo: Path
) -> None:
    """`apply --apply --run-dir <inside a git init repo>` exits 2 with the guard's message.

    Before this card the same command exited 4 — the device class — through `_fail`'s
    bare-`GateclerkError` arm, telling the next reader the box refused. Nothing was ever
    sent to a device: this is the "fix your input" class (§2, p1-08's table).
    """
    _export_pending_box(monkeypatch, root)
    target = _pending_target_box(monkeypatch, root, armed=True)
    target.tag("apply")
    run_dir = git_repo / "runs" / "today"
    code, out = run(
        [
            "migrate",
            "apply",
            "--bundle",
            _last_bundle(root),
            *conn(),
            "--bundles-root",
            str(root),
            "--apply",
            "--run-dir",
            str(run_dir),
            "-o",
            "json",
        ]
    )
    assert code != DEVICE_ERROR_EXIT, (
        f"exit {DEVICE_ERROR_EXIT} is the DEVICE class — 'the box said no' — and this run "
        f"never reached a box:\n{out}"
    )
    assert code == CONFIG_ERROR_EXIT, (
        f"a repo journal dir must exit {CONFIG_ERROR_EXIT} (config class), got {code}:\n{out}"
    )
    (payload,) = rows(out)
    assert payload["exit_code"] == CONFIG_ERROR_EXIT
    assert "inside the repository" in payload["error"], (
        f"the guard's own wording must survive:\n{out}"
    )
    assert str(git_repo.resolve()) in payload["error"], (
        f"the refusal must name the repo root:\n{out}"
    )


def test_apply_refuses_a_repo_run_dir_with_exit_2_table(
    monkeypatch: pytest.MonkeyPatch, root: Path, git_repo: Path
) -> None:
    """Same refusal on the human path: exit 2, the message rendered, no traceback."""
    _export_pending_box(monkeypatch, root)
    target = _pending_target_box(monkeypatch, root, armed=True)
    target.tag("apply")
    code, out = run(
        [
            "migrate",
            "apply",
            "--bundle",
            _last_bundle(root),
            *conn(),
            "--bundles-root",
            str(root),
            "--apply",
            "--run-dir",
            str(git_repo / "runs" / "today"),
        ]
    )
    assert code == CONFIG_ERROR_EXIT, f"table mode must map the refusal too, got {code}:\n{out}"
    assert "Traceback" not in out, f"a traceback leaked into table output:\n{out}"
    assert "inside the repository" in out, f"table mode lost the guard's message:\n{out}"


def test_apply_refusal_writes_no_journal_bytes_and_no_wire_writes(
    monkeypatch: pytest.MonkeyPatch, root: Path, git_repo: Path
) -> None:
    """The refusal is still refusal-first: no journal file anywhere under the repo, and
    not one authenticated write verb reached the fake's wire (the transport is built
    AFTER `WriteJournal.open`, so the refusal structurally precedes the device)."""
    _export_pending_box(monkeypatch, root)
    target = _pending_target_box(monkeypatch, root, armed=True)
    target.tag("apply")
    code, out = run(
        [
            "migrate",
            "apply",
            "--bundle",
            _last_bundle(root),
            *conn(),
            "--bundles-root",
            str(root),
            "--apply",
            "--run-dir",
            str(git_repo / "runs" / "today"),
            "-o",
            "json",
        ]
    )
    assert code == CONFIG_ERROR_EXIT, out
    assert [str(p) for p in git_repo.rglob("*.jsonl")] == [], "a journal landed under the repo"
    assert target.write_calls() == [], f"the refusal must precede the wire: {target.write_calls()}"


def test_apply_still_runs_with_a_run_dir_outside_any_repo(
    monkeypatch: pytest.MonkeyPatch, root: Path, tmp_path: Path
) -> None:
    """No over-refusal: the same command with a private run dir journals normally and runs
    to the harness's known FP abort (exit 1) with its per-phase journals on disk."""
    _export_pending_box(monkeypatch, root)
    target = _pending_target_box(monkeypatch, root, armed=True)
    target.tag("apply")
    run_dir = tmp_path / "gateclerk-private" / "runs" / "today"
    code, out = run(
        [
            "migrate",
            "apply",
            "--bundle",
            _last_bundle(root),
            *conn(),
            "--bundles-root",
            str(root),
            "--apply",
            "--run-dir",
            str(run_dir),
            "-o",
            "json",
        ]
    )
    assert code == 1, f"the FP phase must still abort the run:\n{out}"
    assert sorted(p.name for p in run_dir.glob("*.jsonl")) == [
        "cards.jsonl",
        "fingerprints.jsonl",
        "users.jsonl",
    ], f"the run must have journalled its phases: {sorted(p.name for p in run_dir.rglob('*'))}"
    assert target.write_calls(), "the armed run must have put writes on the wire"


def test_apply_refuses_a_repo_bundles_root_with_exit_2_json(
    monkeypatch: pytest.MonkeyPatch, root: Path, git_repo: Path
) -> None:
    """The card's other spelling of the same refusal: no `--run-dir` at all, but
    `--bundles-root` resolves under a repo, so the DEFAULT run dir
    (<root>/runs/<stamp>) lands inside it. Same guard, same exit 2.

    The probe document is COPIED under the repo root (not probed there): probe persist
    has no repo guard on main yet — the known E1-08 finding E1-09 is fixing on its own
    branch — and this test must stay green whether or not that guard lands first.
    """
    import shutil

    _export_pending_box(monkeypatch, root)
    target = _pending_target_box(monkeypatch, root, armed=True)  # probes into the private root
    target.tag("apply")
    repo_root = git_repo / "bundles"
    repo_root.mkdir()
    shutil.copytree(root / "probes", repo_root / "probes")
    code, out = run(
        [
            "migrate",
            "apply",
            "--bundle",
            _last_bundle(root),
            *conn(),
            "--bundles-root",
            str(repo_root),
            "--apply",
            "-o",
            "json",
        ]
    )
    assert code == CONFIG_ERROR_EXIT, (
        f"a repo-derived default run dir must exit {CONFIG_ERROR_EXIT}, got {code}:\n{out}"
    )
    (payload,) = rows(out)
    assert payload["exit_code"] == CONFIG_ERROR_EXIT
    assert "inside the repository" in payload["error"]
    assert str(git_repo.resolve()) in payload["error"], f"must name the repo root:\n{out}"
    assert [str(p) for p in git_repo.rglob("*.jsonl")] == [], "a journal landed under the repo"


# --- reuse: one guard, and it keeps both exception contracts ------------------------------------


def test_refusal_goes_through_the_shared_journal_guard(
    monkeypatch: pytest.MonkeyPatch, root: Path, git_repo: Path
) -> None:
    """Call-through spy: the shared journal guard is what refuses, and it sees the journal
    file the users phase is about to open (not a CLI-side copy of the rule)."""
    seen: list[Path] = []
    real = migrate_write._refuse_repo_path

    def spy(path: Path) -> None:
        seen.append(Path(path))
        real(path)

    monkeypatch.setattr(migrate_write, "_refuse_repo_path", spy)
    _export_pending_box(monkeypatch, root)
    target = _pending_target_box(monkeypatch, root, armed=True)
    target.tag("apply")
    run_dir = git_repo / "runs" / "today"
    code, out = run(
        [
            "migrate",
            "apply",
            "--bundle",
            _last_bundle(root),
            *conn(),
            "--bundles-root",
            str(root),
            "--apply",
            "--run-dir",
            str(run_dir),
            "-o",
            "json",
        ]
    )
    assert code == CONFIG_ERROR_EXIT, out
    assert seen == [run_dir / "users.jsonl"], (
        f"the guard must be consulted with the phase journal path: {seen}"
    )


def test_stubbing_the_shared_guard_lets_the_run_journal_under_the_repo(
    monkeypatch: pytest.MonkeyPatch, root: Path, git_repo: Path
) -> None:
    """Mutation probe: guard -> no-op means the run proceeds and journals under the repo.

    If the CLI had grown its own repo check instead of reusing the journal guard, this run
    would STILL be refused with the guard stubbed and the test goes red (§5a's probe, the
    same shape t_0d635ee2 pinned for the bundle guard).
    """
    monkeypatch.setattr(migrate_write, "_refuse_repo_path", lambda _path: None)
    _export_pending_box(monkeypatch, root)
    target = _pending_target_box(monkeypatch, root, armed=True)
    target.tag("apply")
    run_dir = git_repo / "runs" / "today"
    code, out = run(
        [
            "migrate",
            "apply",
            "--bundle",
            _last_bundle(root),
            *conn(),
            "--bundles-root",
            str(root),
            "--apply",
            "--run-dir",
            str(run_dir),
            "-o",
            "json",
        ]
    )
    assert code == 1, f"a no-op guard must not refuse anything (FP abort only):\n{out}"
    assert (run_dir / "users.jsonl").is_file(), "the stubbed run must have journaled"


def test_the_refusal_is_a_journal_error_and_a_config_error(git_repo: Path) -> None:
    """The exception contract, at the module level.

    `JournalError` stays in the MRO — the module-level pins
    (test_e1_04_write_foundation.py:498, test_e1_05_cards_phase.py:1346) name it, exactly
    like t_0d635ee2's `ValueError` base — and `ConfigError` is what puts the refusal on the
    documented exit-2 class through the ONE existing `_fail` mapping.

    The run dir exists first because the composer `_ensure_private_dir`s it before opening
    any journal — the same shape the CLI produces.
    """
    (git_repo / "runs").mkdir()
    with pytest.raises(JournalError, match="inside the repository") as raised:
        migrate_write._refuse_repo_path(git_repo / "runs" / "users.jsonl")
    err: Any = raised.value
    assert isinstance(err, ConfigError), (
        "the hygiene refusal must be the config class so _fail maps it to exit 2 "
        f"(p1-08 contract); got {type(err).__name__}"
    )


def test_replay_corruption_stays_off_the_config_class(tmp_path: Path) -> None:
    """The card's design decision, pinned in both directions.

    Repo HYGIENE (where the operator pointed the journal) is the config class. A journal
    that cannot be replayed — an unknown schema, i.e. a file this module does not recognise
    — is NOT "fix your input": it is unreadable state that a human has to adjudicate (§0.7),
    so it stays a plain `JournalError` and keeps its current exit code.
    """
    outside = tmp_path / "private"
    outside.mkdir()
    torn = outside / "users.jsonl"
    torn.write_text('{"schema":"not-the-journal-schema/1","seq":1}\n', encoding="utf-8")
    with pytest.raises(JournalError) as raised:
        WriteJournal.open(torn, phase="users")
    assert not isinstance(raised.value, ConfigError), (
        "corruption on replay must not move onto the config class — only hygiene does"
    )


def test_undo_second_pass_refuses_a_repo_undo_journal_with_exit_2(
    monkeypatch: pytest.MonkeyPatch, root: Path, git_repo: Path
) -> None:
    """The card's other `_Guard` arm: undo's SEAM pass journals into `--undo-journal`.

    A cards journal outside the repo (so the no-seams first pass answers `refused`
    cleanly and a client gets built) plus `--undo-journal <dir inside a repo>` makes the
    seam pass open its undo journal inside `_Guard`. The same refusal, same command:
    exit 2, not 4.
    """
    source_journal = root / "cards.jsonl"
    source_journal.write_text(
        '{"schema":"gateclerk-migrate-journal/1","seq":1,"state":"confirmed",'
        '"phase":"cards","op":"card_setup","employeeNo":"1","employeeHash":"aaaaaaaaaaaa",'
        '"classification":"add","cardNo":"30000003"}\n',
        encoding="utf-8",
    )
    target = _pending_target_box(monkeypatch, root, armed=True)  # the seam for pass 2
    undo_dir = git_repo / "undo-runs"
    undo_dir.mkdir()
    code, out = run(
        [
            "migrate",
            "undo",
            "--journal",
            str(source_journal),
            *conn(),
            "--undo-journal",
            str(undo_dir),
            "-o",
            "json",
        ]
    )
    assert code == CONFIG_ERROR_EXIT, (
        f"a repo undo-journal dir on the seam pass must exit {CONFIG_ERROR_EXIT}, "
        f"got {code} (4 = it still runs bare through _Guard's device arm):\n{out}"
    )
    (payload,) = rows(out)
    assert payload["exit_code"] == CONFIG_ERROR_EXIT
    assert "inside the repository" in payload["error"]
    assert [str(p) for p in git_repo.rglob("*.jsonl")] == [], "an undo journal landed in the repo"
    assert target.write_calls() == [], f"refusal must precede the wire: {target.write_calls()}"


def test_fail_maps_the_refusal_onto_the_documented_exit_2(git_repo: Path) -> None:
    """`_fail` — the single mapping — converts the refusal; it must not re-raise it.

    Today the bare `JournalError` reaches `_fail`'s catch-all `GateclerkError` arm and lands
    on exit 4; the pin is that the ConfigError arm fires first and lands it on 2.
    """
    import typer

    from gateclerk.cli import CONFIG_ERROR_EXIT, _fail
    from gateclerk.output import OutputFormat

    (git_repo / "runs").mkdir()
    with pytest.raises(JournalError) as raised:
        migrate_write._refuse_repo_path(git_repo / "runs" / "users.jsonl")
    result = _fail(OutputFormat.JSON, raised.value)
    assert isinstance(result, typer.Exit), (
        f"_fail must CONVERT the refusal, not re-raise it: got {type(result).__name__}"
    )
    assert result.exit_code == CONFIG_ERROR_EXIT


# --- undo: the SAME refusal keeps its exit-2 behavior --------------------------------------------


def test_undo_refuses_a_journal_inside_a_repo_with_exit_2(
    git_repo: Path,
) -> None:
    """undo's own mapping (its try/except -> 'undo refused: …') must stay exit 2.

    A leftover journal file written by hand (an older build, or an operator move) under a
    repo is refused by the shared guard on open; undo already reports that as a bad
    argument. Pinned so a refactor of the class cannot silently move it to 4.
    """
    stray = git_repo / "runs" / "users.jsonl"
    stray.parent.mkdir(parents=True)
    stray.write_text(
        '{"schema":"gateclerk-migrate-journal/1","seq":1,"state":"confirmed",'
        '"phase":"users","op":"user_setup","employeeNo":"1",'
        '"employeeHash":"aaaaaaaaaaaa","classification":"add"}\n',
        encoding="utf-8",
    )
    code, out = run(["migrate", "undo", "--journal", str(stray), "-o", "json"])
    assert code == CONFIG_ERROR_EXIT, f"undo must keep exit 2 for this refusal, got {code}:\n{out}"
    (payload,) = rows(out)
    assert payload["exit_code"] == CONFIG_ERROR_EXIT
    assert payload["error"].startswith("undo refused:"), f"undo's wording must survive:\n{out}"
    assert "inside the repository" in payload["error"]


def test_undo_still_exits_2_for_a_journal_it_cannot_read(tmp_path: Path) -> None:
    """The neighbouring refusal (a journal that mixes phases) is untouched by this card:
    exit 2 with undo's own wording."""
    mixed = tmp_path / "mixed.journal.jsonl"
    lines = [
        '{"schema":"gateclerk-migrate-journal/1","seq":1,"state":"confirmed",'
        '"phase":"users","op":"user_setup","employeeNo":"1","employeeHash":"aaaaaaaaaaaa",'
        '"classification":"add"}',
        '{"schema":"gateclerk-migrate-journal/1","seq":2,"state":"confirmed",'
        '"phase":"cards","op":"card_setup","employeeNo":"1","employeeHash":"aaaaaaaaaaaa",'
        '"classification":"add","cardNo":"30000003"}',
    ]
    mixed.write_text("\n".join(lines) + "\n", encoding="utf-8")
    code, out = run(["migrate", "undo", "--journal", str(mixed), "-o", "json"])
    assert code == CONFIG_ERROR_EXIT, f"a mixed-phase journal must stay a config refusal: {out}"
    (payload,) = rows(out)
    assert payload["error"].startswith("undo refused:")
    assert "mixes phases" in payload["error"]
