"""Card t_0d635ee2: `migrate export`'s repo-out refusal must exit 2, not crash.

Found while doing E1-09. The E1-09 card body asserted probe must exit 2 "exactly like
export does" — that premise was FALSE: ``migrate_bundle._refuse_repo_out`` raises a plain
``ValueError`` (migrate_bundle.py:607), which escapes ``_Guard``/``_fail`` (``_fail``
re-raises any class outside the documented vocabulary) and surfaces as an unhandled
traceback with exit 1 — in ``main()`` too, not just under CliRunner. The refusal itself
is correct and correct-first (§2, before any filesystem touch); only its EXCEPTION CLASS
was wrong: it is not a bug, it is an unusable operator input, i.e. the config class.

The contract pinned here, in the card's own order (FakeDevice-strict, offline):

* ``export --out`` under a ``git init`` dir exits 2 (the documented p1-08 config class),
  for BOTH ``-o table`` and ``-o json``;
* the ``-o json`` error names the repo root and carries exit_code 2 (the guard's own
  message, not a CLI re-wording);
* no bundle dir and no ``*.partial`` is created anywhere under the repo — the refusal
  still precedes the first mkdir (no behavior change to the guard itself);
* a root outside any repo still exports normally (exit 0, the bundle exists) — the
  mapping must not over-refuse;
* reuse: the refusal comes from ``migrate_bundle._refuse_repo_out`` (stub it -> the
  refusal disappears), and the exception is a ``ValueError`` subclass, because every
  module-level pin (E1-01, E1-01b) still names it as a ValueError.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

import gateclerk.migrate_bundle as migrate_bundle
from gateclerk.exceptions import ConfigError
from test_e1_07_cli import (
    Box,
    _source_seed,
    conn,
    rows,
    run,
)

CONFIG_ERROR_EXIT = 2


@pytest.fixture
def git_repo(tmp_path: Path) -> Path:
    """A fake checkout under tmp_path — the `.git` DIRECTORY spelling (E1-01 precedent)."""
    repo = tmp_path / "public-repo"
    repo.mkdir()
    (repo / ".git").mkdir()
    return repo


@pytest.fixture
def box(monkeypatch: pytest.MonkeyPatch) -> Box:
    """A SOURCE box (bench-A users/cards/faces/FP) the CLI exports from."""
    b = Box(monkeypatch)
    _source_seed(b.device)
    return b


# --- the CLI: export --out under a repo is exit 2, both formats, zero writes ------------------


def test_export_refuses_a_repo_out_with_exit_2_json(box: Box, git_repo: Path) -> None:
    """`export --out <inside a git init repo>` exits 2 with the guard's message (§2).

    Before this card the same command raised an UNHANDLED ValueError: exit 1 and a
    traceback. The refusal must land on the documented config class instead, and the
    message must be the bundle module's own wording naming the repo root.
    """
    destination = git_repo / "bundles" / "site-a"
    code, out = run(
        [
            "migrate",
            "export",
            *conn(),
            "--out",
            str(destination),
            "-o",
            "json",
        ]
    )
    assert code == CONFIG_ERROR_EXIT, (
        f"repo-out export must exit {CONFIG_ERROR_EXIT} (config class), got {code}:\n{out}"
    )
    (payload,) = rows(out)
    assert payload["exit_code"] == CONFIG_ERROR_EXIT
    assert "inside a git repo" in payload["error"], f"guard's wording must survive:\n{out}"
    assert str(git_repo) in payload["error"], f"refusal must name the repo root:\n{out}"


def test_export_refuses_a_repo_out_with_exit_2_table(box: Box, git_repo: Path) -> None:
    """Same refusal on the human path: exit 2 and the message rendered, no traceback."""
    destination = git_repo / "bundles" / "site-a"
    code, out = run(["migrate", "export", *conn(), "--out", str(destination)])
    assert code == CONFIG_ERROR_EXIT, f"table mode must map the refusal too, got {code}:\n{out}"
    assert "Traceback" not in out, f"a traceback leaked into table output:\n{out}"
    assert "inside a git repo" in out, f"table mode lost the guard's message:\n{out}"


def test_export_refusal_leaves_no_bundle_and_no_partial(box: Box, git_repo: Path) -> None:
    """No behavior change to the guard: it still refuses BEFORE touching the filesystem."""
    destination = git_repo / "bundles" / "site-a"
    code, out = run(["migrate", "export", *conn(), "--out", str(destination), "-o", "json"])
    assert code == CONFIG_ERROR_EXIT, out
    assert not destination.exists()
    assert not (git_repo / "bundles").exists()
    assert [str(p) for p in git_repo.rglob("*.partial")] == []
    assert [str(p) for p in git_repo.rglob("manifest.json")] == []
    # the refusal is a PERSIST-seam refusal, not a crash on the way to the device
    assert box.served_count() > 0, "export must still perform its read pass"


def test_export_still_succeeds_outside_any_repo(box: Box, tmp_path: Path) -> None:
    """The mapping must not over-refuse: a private destination writes the bundle (exit 0)."""
    root = tmp_path / "gateclerk-private"
    root.mkdir()
    code, out = run(
        [
            "migrate",
            "export",
            *conn(),
            "--bundles-root",
            str(root),
            "--out",
            str(root / "bundles" / "site-a"),
            "-o",
            "json",
        ]
    )
    assert code == 0, out
    (payload,) = rows(out)
    assert Path(payload["bundle"]).is_dir()
    assert (Path(payload["bundle"]) / "manifest.json").is_file()


# --- reuse: one guard, and it stays a ValueError for the module-level pins --------------------


def test_refusal_goes_through_the_shared_bundle_guard(
    box: Box, git_repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Call-through spy: the shared guard is what refuses, and it sees the `--out` dir.

    The stub-to-no-op direction (the E1-09 mutation probe, pinned below) is what proves
    no second copy of the rule was added in the export path.
    """
    seen: list[Path] = []
    real = migrate_bundle._refuse_repo_out

    def spy(out: Path) -> None:
        seen.append(Path(out))
        real(out)

    monkeypatch.setattr(migrate_bundle, "_refuse_repo_out", spy)
    destination = git_repo / "bundles" / "site-a"
    code, out = run(["migrate", "export", *conn(), "--out", str(destination), "-o", "json"])
    assert code == CONFIG_ERROR_EXIT, out
    assert seen == [destination], f"the guard must be consulted with the --out dir: {seen}"


def test_stubbing_the_shared_guard_disables_the_export_refusal(
    box: Box, git_repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Mutation probe: guard -> no-op means the export writes and exits 0.

    If the CLI grew its own repo check instead of reusing the bundle guard, this write
    would STILL be refused with the guard stubbed and the test goes red (§5a).
    """
    monkeypatch.setattr(migrate_bundle, "_refuse_repo_out", lambda _out: None)
    destination = git_repo / "bundles" / "site-a"
    code, out = run(["migrate", "export", *conn(), "--out", str(destination), "-o", "json"])
    assert code == 0, f"a no-op guard must not refuse anything:\n{out}"
    assert Path(rows(out)[0]["bundle"]).is_dir()


def test_the_refusal_is_a_value_error_and_a_config_error(git_repo: Path) -> None:
    """The exception contract, at the module level.

    ValueError stays (E1-01 / E1-01b pin the refusal as ``pytest.raises(ValueError)`` —
    those 4 tests must stay green) and ConfigError is added, which is what puts the
    refusal on the documented exit-2 class through the ONE existing `_fail` mapping.
    """
    with pytest.raises(ValueError, match="inside a git repo") as raised:
        migrate_bundle._refuse_repo_out(git_repo / "bundles" / "site-a")
    err: Any = raised.value
    assert isinstance(err, ConfigError), (
        "the refusal must be the config class so _fail maps it to exit 2 "
        f"(p1-08 contract); got {type(err).__name__}"
    )


def test_fail_maps_the_refusal_onto_the_documented_exit_2(git_repo: Path) -> None:
    """`_fail` — the single mapping — converts the refusal; it must not re-raise it.

    `_fail` re-raises unknown classes (that re-raise is what produced the traceback this
    card fixes), so this is the pin that the refusal is IN the vocabulary now.
    """
    import typer

    from gateclerk.cli import CONFIG_ERROR_EXIT, _fail
    from gateclerk.output import OutputFormat

    with pytest.raises(ValueError) as raised:
        migrate_bundle._refuse_repo_out(git_repo / "bundles" / "site-a")
    result = _fail(OutputFormat.JSON, raised.value)
    assert isinstance(result, typer.Exit), (
        f"_fail must CONVERT the refusal, not re-raise it (the re-raise is the bug): "
        f"got {type(result).__name__}"
    )
    assert result.exit_code == CONFIG_ERROR_EXIT
