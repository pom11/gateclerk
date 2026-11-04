"""Every internal import in src/ must resolve, including ones inside functions.

Lazy imports only run on the path that reaches them, so an injected test double can hide
a broken one: `gateclerk doctor` crashed on a real device while its suite stayed green.
"""

from __future__ import annotations

import ast
import importlib
from pathlib import Path

import gateclerk

SRC = Path(gateclerk.__file__).parent


def _internal_imports():
    for path in sorted(SRC.rglob("*.py")):
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            if isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
                if node.module.split(".")[0] == "gateclerk":
                    yield path, node.lineno, node.module, [a.name for a in node.names]
            elif isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name.split(".")[0] == "gateclerk":
                        yield path, node.lineno, alias.name, []


def _resolves(module: str, names: list[str]) -> bool:
    try:
        loaded = importlib.import_module(module)
    except ImportError:
        return False
    for name in names:
        if name == "*" or hasattr(loaded, name):
            continue
        try:
            importlib.import_module(f"{module}.{name}")
        except ImportError:
            return False
    return True


def test_every_internal_import_resolves() -> None:
    broken = [
        f"{path.relative_to(SRC)}:{line} {module} {names}"
        for path, line, module, names in _internal_imports()
        if not _resolves(module, names)
    ]
    assert not broken, "unresolved internal imports:\n" + "\n".join(broken)
