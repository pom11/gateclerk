"""Card E1-09: probe persistence must honor the repo-out guard (§9.1 finding 1).

Live-validated on bench A (E1-08, docs/ENROLLMENT-MIGRATION.md §9.1): `export --out`
refuses a destination inside a git repo via ``migrate_bundle._refuse_repo_out``, but
`migrate probe` persisted its schema-2 document to ``probes_root(bundle_root())`` with
no check at all — and the DEFAULT root resolves under ``~/gateclerk``, itself a git repo
on the ops machine. The probe document is arguably the worse leak of the pair: the
device HOST rides in the filename and identity hashes ride inside (§9.1 finding 1).

The contract pinned here, in the card's own order:

* the refusal lives in ``save_matrix`` (the write seam) and comes from
  ``migrate_bundle._refuse_repo_out`` — the SHARED guard, not a copy of its logic;
* a stubbed (no-op) guard makes the refusal disappear: the mutation probe that proves
  no second copy of the rule exists in the probe path;
* the CLI refuses to persist with exit 2 and the bundle module's message naming the
  repo root, and NO file appears anywhere under the repo tree;
* a root outside any git repo persists exactly as before (dir 0700 / file 0600).

FakeDevice-strict and offline: the CLI cases reuse the E1-07 harness (the real
``IsapiClient`` over ``FakeDevice``'s MockTransport, per-box redirection), and the
autouse ``netoff`` guard blocks every real socket.
"""

from __future__ import annotations

from pathlib import Path

import pytest

import gateclerk.migrate_bundle as migrate_bundle
from gateclerk.migrate_probe import (
    CapabilityMatrix,
    load_matrix,
    probes_dir,
    save_matrix,
)
from test_e1_07_cli import Box, conn, rows, run

SITE = "site-a"
HOST_IP = "192.0.2.7"


def a_matrix() -> CapabilityMatrix:
    """A persisted-shape matrix: the guard question is about the PATH, not the content."""
    return CapabilityMatrix(site=SITE, host=HOST_IP, probed_at="2026-10-23T09:00:00+00:00")


@pytest.fixture
def root(tmp_path: Path) -> Path:
    """A private bundles root OUTSIDE any repo (same discipline as E1-07's fixture)."""
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


# --- the write seam: save_matrix refuses a repo target via the SHARED guard --------------------


def test_save_matrix_refuses_a_target_under_a_git_repo(git_repo: Path) -> None:
    private = git_repo / "gateclerk-private"  # the incident shape: a "private" root inside
    #                                       the ops repo (E1-08: ~/gateclerk IS a repo)
    with pytest.raises(ValueError, match="inside a git repo") as raised:
        save_matrix(a_matrix(), private)
    assert str(git_repo) in str(raised.value), f"refusal must name the repo root: {raised.value}"
    # refused BEFORE touching the filesystem: not even the probes/ dir exists
    assert not private.exists()
    assert list(git_repo.rglob("*.json")) == []


def test_save_matrix_refuses_the_worktree_spelling_of_a_repo(tmp_path: Path) -> None:
    repo = tmp_path / "wt-repo"
    repo.mkdir()
    (repo / ".git").write_text("gitdir: /elsewhere\n", encoding="utf-8")  # linked worktree
    with pytest.raises(ValueError, match="inside a git repo"):
        save_matrix(a_matrix(), repo / "bundles")
    assert not (repo / "bundles").exists()


def test_save_matrix_still_persists_outside_any_repo(tmp_path: Path) -> None:
    """The guard must not over-refuse: a private root with no `.git` ancestor writes as today."""
    root = tmp_path / "gateclerk-private"
    path = save_matrix(a_matrix(), root)
    assert path == probes_dir(root) / f"{SITE}-{HOST_IP}.json"
    assert path.is_file()
    assert oct(path.stat().st_mode)[-3:] == "600"
    assert oct(path.parent.stat().st_mode)[-3:] == "700"
    assert load_matrix(root, SITE, HOST_IP) == a_matrix()


# --- the reuse contract: one guard, no second copy (§5a no-duplication) ------------------------


def test_refusal_goes_through_the_shared_bundle_guard(
    git_repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The refusal must come from `migrate_bundle._refuse_repo_out`, on the probe dir.

    A call-through spy (the real guard still runs) proves BOTH that the shared seam is
    the one consulted and that it is consulted with the probe file's target directory —
    not, say, only the cwd or the final file path after the mkdir.
    """
    seen: list[Path] = []
    real = migrate_bundle._refuse_repo_out

    def spy(out: Path) -> None:
        seen.append(out)
        real(out)

    monkeypatch.setattr(migrate_bundle, "_refuse_repo_out", spy)
    private = git_repo / "gateclerk-private"
    with pytest.raises(ValueError, match="inside a git repo"):
        save_matrix(a_matrix(), private)
    assert seen == [probes_dir(private)]


def test_stubbing_the_shared_guard_disables_the_probe_refusal(
    git_repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Reviewer mutation probe, pinned as a test: guard -> no-op means NO refusal.

    If anyone re-implements the repo check inside the probe path instead of reusing the
    bundle guard, this write would STILL be refused with the guard stubbed and the test
    goes red — which is exactly the duplication §5a forbids (and the reason `save_matrix`
    resolves the guard through the module rather than a from-import binding).
    """
    monkeypatch.setattr(migrate_bundle, "_refuse_repo_out", lambda _out: None)
    private = git_repo / "gateclerk-private"
    path = save_matrix(a_matrix(), private)  # must NOT raise with the guard no-op'd
    assert path.is_file()


# --- the CLI: refusal is exit 2, nothing under the repo; outside stays as today ----------------


def _box_with_probe_surface(monkeypatch: pytest.MonkeyPatch) -> Box:
    """The E1-07 fake box, enrollment caps armed — the surface `migrate probe` reads."""
    box = Box(monkeypatch)
    box.device.install_enrollment()
    return box


def test_cli_probe_refuses_to_persist_inside_a_git_repo(
    monkeypatch: pytest.MonkeyPatch, git_repo: Path
) -> None:
    """§9.1 finding 1 end-to-end: the default-style root under a repo exits 2, writes zero.

    `-o json` for a parseable refusal; the message is the BUNDLE module's wording and it
    names the repo root, so the operator sees which repo they tripped.
    """
    _box_with_probe_surface(monkeypatch)
    private = git_repo / "gateclerk-private"
    code, out = run(["migrate", "probe", *conn(), "--bundles-root", str(private), "-o", "json"])
    assert code == 2, f"repo-out probe persist must exit 2 (config class):\n{out}"
    (payload,) = rows(out)
    assert "inside a git repo" in payload["error"]
    assert str(git_repo) in payload["error"], f"refusal must name the repo root:\n{out}"
    # Nothing written anywhere under the repo — the persist refused before the first mkdir.
    assert not private.exists()
    assert list(git_repo.rglob("*.json")) == []


def test_cli_probe_refuses_the_env_default_root_inside_a_repo(
    monkeypatch: pytest.MonkeyPatch, git_repo: Path
) -> None:
    """The incident path itself: no --bundles-root, GATECLERK_BUNDLE_ROOT under the repo.

    §9.1 found the file via the DEFAULT root (`~/gateclerk/bundles`, a repo on the ops
    box); `GATECLERK_BUNDLE_ROOT` exercises that same default-resolution rung of
    `bundle_root()` without touching the real home directory.
    """
    _box_with_probe_surface(monkeypatch)
    private = git_repo / "gateclerk-default"
    monkeypatch.setenv("GATECLERK_BUNDLE_ROOT", str(private))
    code, out = run(["migrate", "probe", *conn(), "-o", "json"])
    assert code == 2, f"the default-root path must refuse too:\n{out}"
    (payload,) = rows(out)
    assert "inside a git repo" in payload["error"]
    assert not private.exists()
    assert list(git_repo.rglob("*.json")) == []


def test_cli_probe_still_persists_outside_any_repo(
    monkeypatch: pytest.MonkeyPatch, root: Path
) -> None:
    """Everything else about probe stays: outside a repo, probe runs and persists as today."""
    box = _box_with_probe_surface(monkeypatch)
    code, out = run(["migrate", "probe", *conn(), "--bundles-root", str(root), "-o", "json"])
    assert code == 0, out
    (payload,) = rows(out)
    persisted = Path(payload["persisted_to"])
    assert persisted.parent == probes_dir(root)
    assert persisted.is_file()
    assert oct(persisted.stat().st_mode)[-3:] == "600"
    # the probe ran on the wire first — the refusal above is a PERSIST-seam refusal,
    # not an early bail that changes what probe asks the device.
    assert box.served_count() > 0
