"""Guard: a test run must exercise the checkout it lives in, not another checkout.

Why this exists: the main checkout installs gateclerk *editable* — a
`_editable_impl_gateclerk.pth` in its venv's site-packages pointing at
`/…/gateclerk/src`. A site-packages `.pth` is visible to every run of that interpreter,
so a bare `pytest` inside a **git worktree** of the same repo imports the MAIN
checkout's `src/gateclerk` and can report a fully green run against code the worktree
does not contain. This happened for real on t_7b073d11: its first green run had
validated main's code, not the worktree's.

The guard resolves where `gateclerk` would be imported from and refuses to start unless
that sits under the checkout root of the run. The same rule catches a stale editable
install of an older branch, or a wheel install shadowing the tree under test.

Two invocations satisfy it (both already used by this repo and by CI):

    uv run --frozen pytest             # per-checkout .venv — what CI does
    PYTHONPATH=<worktree>/src pytest   # one-off, no venv needed

`pytest_configure` raises `pytest.UsageError`, so pytest exits 4 with the message
*before* collecting or running anything — no green result is ever printed.

Kept deliberately import-light: the guard uses `importlib.util.find_spec` rather than
importing gateclerk, so deciding whether the environment is trustworthy never depends on
gateclerk's own dependencies being installed. A package that cannot be found at all is
left alone on purpose — the test modules' own imports fail loudly in that case, and
this guard does not restate someone else's error.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

PACKAGE = "gateclerk"

#: Printed verbatim when the guard bites. The fix lines are the point of the guard:
#: a worker hitting this must not have to rediscover the workaround.
FIX_HINT = (
    "A green run here would validate a DIFFERENT tree (usually the main checkout's\n"
    "  editable install), which is a false green, not a pass.\n"
    "Fix — run the suite against THIS checkout:\n"
    "  uv run --frozen pytest                 # per-checkout .venv, what CI does\n"
    "  PYTHONPATH={root}/src pytest  # one-off, no venv"
)


def resolve_package_origin(package: str = PACKAGE) -> Path | None:
    """Absolute path of the `package` this interpreter would import, or None.

    Consults an already-imported module first (a plugin or an earlier conftest may
    have pulled it in before this hook runs) and otherwise uses `find_spec`, which
    locates the package without executing it.
    """
    candidates: list[object] = []
    module = sys.modules.get(package)
    if module is not None:
        candidates.append(getattr(module, "__file__", None))
        candidates.extend(getattr(module, "__path__", None) or [])
    else:
        try:
            spec = importlib.util.find_spec(package)
        except (ImportError, ValueError):
            return None
        if spec is not None:
            candidates.append(spec.origin)
            candidates.extend(spec.submodule_search_locations or [])

    for candidate in candidates:
        if isinstance(candidate, str) and candidate and candidate != "namespace":
            return Path(candidate).resolve()
    return None


def mismatch_message(package_origin: Path | None, checkout_root: Path) -> str | None:
    """Why `package_origin` is not inside `checkout_root`; None when it is fine.

    None means "stay silent": the package is inside the checkout under test, or it
    cannot be located at all (then the tests' own imports fail — loud already).
    """
    if package_origin is None:
        return None
    root = checkout_root.resolve()
    if package_origin.is_relative_to(root):
        return None
    return (
        f"REFUSING TO RUN: `import {PACKAGE}` resolves outside the checkout under test.\n"
        f"  package : {package_origin}\n"
        f"  checkout: {root}\n" + FIX_HINT.replace("{root}", str(root))
    )
