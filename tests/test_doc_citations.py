"""Doc-citation integrity (card t_2fcf27ad).

Every citation of a file in this repository's ``docs/`` tree, from anywhere in the tracked
tree, must name a path that exists.

Why this test exists. PR #104 de-identified the card docs and moved them under
``docs/internal/``, and the citations did not move with them. Measured at the merge that
followed: 190 citations across 92 files still named the pre-move path — 50 of them the
probe record, the rest the design/spec/reference docs that moved in the same commit. Every
reader (or later agent) who followed "see the probe record" hit a file that is not there.
That is the same quiet doc lie the GC-P09/GC-P12 follow-ups fixed, and no code test can
see it, because the claim sits in a comment.

The convention, decided on the card before the sweep:

    a citation states a location its reader can actually open.

  * an in-repo citation names the tracked path, or the bare filename (which greps to
    exactly one file). A path that does not exist is never acceptable — that is the
    assertion below;
  * a runtime-visible string names no path at all, because the shipped artefact has no
    ``docs/`` directory to resolve one against: ``deploy/Dockerfile`` sends only
    ``pyproject.toml``, ``README.md`` and ``src`` into the image ("the test suite, docs and
    .git are not sent into the image") and ``pyproject.toml`` ships
    ``packages = ["src/gateclerk"]``. Those surfaces name the record in prose instead.
    That is the second assertion;
  * a citation to another repository's documentation is out of scope — this suite cannot
    vouch for a tree it does not own, and rewriting such a mention to a gateclerk path
    would be a different kind of lie. ``docs/SERVICE-INTEGRATION.md`` and
    ``docs/DELEGATED-SETUP.md`` are micro-notify's, which is why they read as dead here
    and are not.

Scope of the first assertion, so it cannot invent failures:

  * ``docs/`` only. A citation to ``tests/…`` names an artefact that may legitimately not
    exist yet — the go-live card specs list the test file each card must add — so it is
    not a claim about the current tree.
  * a token carrying a glob or placeholder (``*``, ``<…>``, ``$…``, ``{…}``) is a sketch
    of a future file, not a pointer to an existing one.
"""

from __future__ import annotations

import ast
import re
import shutil
import subprocess
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]

_EXTENSIONS = (
    "md",
    "py",
    "txt",
    "json",
    "toml",
    "yaml",
    "yml",
    "cfg",
    "ini",
    "sh",
    "sql",
    "csv",
    "xlsx",
    "plist",
    "service",
)

# ``@`` is in the character class because ``deploy/gateclerk-agent@.service`` is a real
# cited unit name.
CITED_DOC_RE = re.compile(
    r"\bdocs/(?P<tail>[A-Za-z0-9_.\-/@]+?\.(?:" + "|".join(_EXTENSIONS) + r"))"
)

# A ``path:168-169`` suffix is part of the citation, not part of the filename.
_LINE_SUFFIX_RE = re.compile(r":\d+(?:[-,]\d+)*$")

# Sketch markers: a token carrying one is a plan for a file, not a pointer to one.
_SKETCH_CHARS = frozenset("*<>${}")

# Repositories whose documentation this repo legitimately cites. Matched
# case-insensitively in the text surrounding the citation, because the attribution often
# sits on the wrapped line above it. The window is measured, not guessed: across all 13
# such citations the nearest attribution word sits 43 characters away (12 of them within
# 7), so 60 covers the prose with margin while still refusing to exempt a dead citation
# that merely happens to live near the word.
_FOREIGN_REPOS = ("micro-notify", "micro_notify", "micronotify")
_ATTRIBUTION_WINDOW = 60


def _tracked_files() -> list[Path]:
    git_bin = shutil.which("git") or "/usr/bin/git"
    out = subprocess.check_output(  # noqa: S603
        [git_bin, "ls-files", "-z"], cwd=REPO_ROOT, text=True
    ).split("\0")
    return [REPO_ROOT / rel for rel in out if rel and (REPO_ROOT / rel).is_file()]


def _attributed_to_foreign_repo(text: str, start: int, end: int) -> bool:
    window = text[max(0, start - _ATTRIBUTION_WINDOW) : end + _ATTRIBUTION_WINDOW].lower()
    return any(repo in window for repo in _FOREIGN_REPOS)


def _read(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        # A tracked binary (docs/users-import-template.xlsx) carries no citations, and the
        # public audit makes the same call.
        return ""


def _line_of(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


def _live_doc_citations(text: str) -> list[tuple[int, str]]:
    """Citations of a ``docs/`` file that claim this tree owns it, as (lineno, path)."""
    found: list[tuple[int, str]] = []
    for match in CITED_DOC_RE.finditer(text):
        raw = f"docs/{match['tail']}"
        if _SKETCH_CHARS & set(raw):
            continue
        if _attributed_to_foreign_repo(text, match.start(), match.end()):
            continue
        found.append((_line_of(text, match.start()), _LINE_SUFFIX_RE.sub("", raw)))
    return found


def test_every_cited_doc_path_exists() -> None:
    """No tracked file may cite a ``docs/`` path that is not in the tree.

    A doc move is a rename *plus* a sweep; this is what makes the sweep non-optional and
    is the whole point of the card.
    """
    dead: list[str] = []
    for path in _tracked_files():
        rel = path.relative_to(REPO_ROOT).as_posix()
        for lineno, cited in _live_doc_citations(_read(path)):
            if not (REPO_ROOT / cited).is_file():
                dead.append(f"{rel}:{lineno}: {cited}")
    assert not dead, f"cited doc path(s) do not exist ({len(dead)}): {dead[:30]}"


def test_the_probe_records_sit_where_the_citations_say_they_do() -> None:
    """Pin the two probe records, so moving one is a deliberate act, not a surprise.

    These are the files the sweep re-points: 190 citations were naming them at a path
    that had not existed since PR #104.
    """
    assert (REPO_ROOT / "docs" / "internal" / "OBSERVED.md").is_file()
    assert (REPO_ROOT / "docs" / "internal" / "OBSERVED-site-B.md").is_file()


def _runtime_string_literals(source: str) -> list[tuple[int, str]]:
    """Every ``str`` literal in *source* that is not a docstring, with its line number.

    Docstrings are the developer-facing surface (read in the repository, where ``docs/``
    exists) and are allowed to cite a path. A docstring is recognised as the leading
    ``Expr(Constant(str))`` of a module, class or function body — the same rule ``ast``
    uses for ``get_docstring``.
    """
    tree = ast.parse(source)
    docstring_lines: frozenset[int] = frozenset()
    for node in ast.walk(tree):
        if (
            isinstance(node, (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef))
            and node.body
        ):
            head = node.body[0]
            if (
                isinstance(head, ast.Expr)
                and isinstance(head.value, ast.Constant)
                and isinstance(head.value.value, str)
            ):
                docstring_lines = docstring_lines | frozenset(
                    range(head.value.lineno, (head.value.end_lineno or head.value.lineno) + 1)
                )
    literals: list[tuple[int, str]] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            if node.lineno in docstring_lines:
                continue
            literals.append((node.lineno, node.value))
    return literals


def test_runtime_visible_strings_name_no_doc_path() -> None:
    """Nothing the shipped artefact can print may cite a repository path.

    Help text, exception messages and CLI output are read by whoever runs the wheel or the
    container, and neither has a ``docs/`` directory (``deploy/Dockerfile`` copies only
    ``pyproject.toml``, ``README.md`` and ``src``; the wheel ships ``src/gateclerk``). A
    path in that surface is a dead end by construction, so those strings name the record
    in prose — "the device probe record" — and the real path lives in the comment above
    them, where a reader who has the repository will find it.
    """
    offenders: list[str] = []
    for path in sorted((REPO_ROOT / "src" / "gateclerk").rglob("*.py")):
        rel = path.relative_to(REPO_ROOT).as_posix()
        for lineno, literal in _runtime_string_literals(_read(path)):
            match = CITED_DOC_RE.search(literal)
            if match and not _attributed_to_foreign_repo(literal, match.start(), match.end()):
                offenders.append(f"{rel}:{lineno}: {_LINE_SUFFIX_RE.sub('', match.group(0))}")
    assert not offenders, (
        f"runtime-visible string(s) cite a repository doc path ({len(offenders)}): {offenders[:20]}"
    )
