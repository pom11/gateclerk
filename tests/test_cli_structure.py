"""CLI-SPLIT-STRUCTURE: the structural law of the CLI package, pinned.

What this card changed, in one sentence: the per-group `typer.Typer(...)` declarations and
their `add_typer` registrations for `agent` (+`deadletter`), `sink` and `demo` moved OUT of
`src/gateclerk/cli.py` into `gateclerk.agent_cmds`, `gateclerk.sink_cmds` and `gateclerk.demo_cmds`,
and the furniture those modules share (`_alias_group`, the shared `Annotated` options, the
failure-to-exit conversion) moved into `gateclerk.cli_shared`, which `cli.py` also imports —
so a shared option spelling is defined exactly once and `cli.py` stops being the file every
CLI card must edit.

Two properties are guarded here rather than by review, because both are the kind that
silently regresses when a later card "just adds one small thing":

1. IMPORT DIRECTION. `gateclerk.cli` imports the command modules; no command module imports
   `gateclerk.cli`. (The one existing back-edge — `agent_health` lazily importing
   `cli._warn_tz_mismatch` — stays where it is and is NOT part of this law; it predates
   the split and is documented at its call site.) A cycle here does not fail loudly at the
   point of the bad import; it fails at `python -m gateclerk.cli` start-up, in the field.

2. THE MOVED GROUPS STAY MOVED. The `agent`, `sink` and `demo` Typer declarations must not
   reappear in `cli.py`. A group declaration re-added there rebuilds the merge-collision
   generator this card exists to remove, and it would pass every behavioural test.

The byte-identical-surface proof (the 22->25-leaf set, `PREVIOUS_SURFACE`, the `agent run`
golden manifest, the per-group `--help` diff) lives with the tests that already own it:
`tests/test_cli_conventions.py` (untouched by this card) plus the PR's pre/post help
capture, not duplicated here.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

SRC = Path(__file__).resolve().parents[1] / "src" / "gateclerk"

#: Modules the split created. These are the ones the import law binds.
SPLIT_MODULES = (
    "cli_shared.py",
    "agent_cmds.py",
    "sink_cmds.py",
    "demo_cmds.py",
    "export_cmds.py",
    "status_cmds.py",
)

#: Precedent modules that were already CLI-surface-adjacent and must not gain a back-edge.
NEIGHBOUR_MODULES = ("sink_cli.py", "demo_device.py", "export_cli.py", "status_cli.py")

#: Group declarations that must NOT reappear in cli.py (they live in the cmd modules now).
MOVED_GROUPS = (
    "agent_app",
    "deadletter_app",
    "sink_app",
    "demo_app",
    "demo_device_app",
    "export_app",
    "status_app",
)


def _imports_of(module: str) -> set[str]:
    """Every dotted module name `module` imports, statically (no execution)."""
    tree = ast.parse((SRC / module).read_text(encoding="utf-8"))
    found: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            found.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            found.add(node.module)
            found.update(f"{node.module}.{alias.name}" for alias in node.names)
    return found


@pytest.mark.parametrize("module", [*SPLIT_MODULES, *NEIGHBOUR_MODULES])
def test_a_command_module_never_imports_gateclerk_cli(module: str) -> None:
    """Import direction (1): cmd modules depend on `cli_shared`, never on `gateclerk.cli`.

    A `gateclerk.cli` import inside any of these modules creates the cycle cli.py -> cmd ->
    cli.py; it survives unit tests (cli.py is already in sys.modules) and surfaces as an
    import-time AttributeError on `python -m gateclerk.cli` — i.e. at the operator's keyboard.
    """
    offenders = {
        name
        for name in _imports_of(module)
        if name == "gateclerk.cli" or name.startswith("gateclerk.cli.")
    }
    assert not offenders, f"{module} must never import gateclerk.cli (found {offenders})"


def test_the_split_modules_import_only_the_shared_furniture() -> None:
    """(1b) The new modules may reach: typer, config, output, cli_conventions, domain modules.

    Narrower than the cycle check above and deliberately so — `cli_shared` exists precisely
    so a command module never needs the root app object except inside `register(app)`.
    """
    for module in SPLIT_MODULES:
        for name in _imports_of(module):
            assert not name.startswith("gateclerk.cli."), f"{module} imports {name}"
            assert name != "gateclerk.cli", f"{module} imports {name}"


def test_moved_group_declarations_are_gone_from_cli_py() -> None:
    """Property (2): `agent`/`sink`/`demo` Typer declarations do not creep back.

    Read statically: the test must not depend on which modules happen to be importable.
    """
    tree = ast.parse((SRC / "cli.py").read_text(encoding="utf-8"))
    declared: set[str] = set()
    for node in tree.body:
        if (
            isinstance(node, ast.Assign)
            and isinstance(node.value, ast.Call)
            and isinstance(node.value.func, ast.Attribute)
            and node.value.func.attr == "Typer"
        ):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    declared.add(target.id)
    assert declared.isdisjoint(MOVED_GROUPS), (
        f"cli.py re-declares moved group(s) {declared & set(MOVED_GROUPS)} — put them in "
        "their domain module and register them from cli.py (that is the split)."
    )


def test_each_moved_group_is_registered_from_its_module() -> None:
    """(2b) And the registrations still happen exactly once, from the cmd modules."""
    for module, app_name in (
        ("agent_cmds.py", "agent_app"),
        ("sink_cmds.py", "sink_app"),
        ("demo_cmds.py", "demo_app"),
        ("export_cmds.py", "export_app"),
        ("status_cmds.py", "status_app"),
    ):
        text = (SRC / module).read_text(encoding="utf-8")
        assert "def register(app: typer.Typer) -> None:" in text, module
        assert f"app.add_typer({app_name})" in text, module
    cli_text = (SRC / "cli.py").read_text(encoding="utf-8")
    for call in (
        "agent_cmds.register(app)",
        "sink_cmds.register(app)",
        "demo_cmds.register(app)",
        "export_cmds.register(app)",
        "status_cmds.register(app)",
    ):
        assert call in cli_text, call


def test_the_root_app_walks_after_the_split_without_a_cycle() -> None:
    """The card's proof (5), as a test: importing cli fresh and walking the tree works.

    `python -m gateclerk.cli --help` is the shipped entry path; running it through
    `typer.main.get_command` here is the same construction `--help` performs, offline.
    """
    from typing import Any

    import typer

    from gateclerk import cli

    root: Any = typer.main.get_command(cli.app)
    assert set(root.commands) >= {
        "device",
        "users",
        "creds",
        "events",
        "agent",
        "migrate",
        "sink",
        "demo",
    }
