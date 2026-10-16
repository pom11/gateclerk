"""Output rendering: `table` (human), `json` (machine) and `jsonl` (streaming) via rich.

`json` is the stable, pipeable form — one JSON document (or JSONL for a sequence) on
stdout with nothing else mixed in. `table` is the only place rich formatting lives, so
a later card can add columns without touching command logic.

`jsonl` is the third format and it is NOT cosmetic: `OutputFormat` is a closed choice
list, so a command cannot expose a format this enum does not name. Card p1-08's
definition of done asks for `gateclerk events --format jsonl` whose output feeds
`gateclerk.model.from_jsonl()` losslessly, which is one line per record — i.e. exactly
what `_render_json` already does. The two spellings are therefore kept as synonyms of
one behaviour rather than two code paths that can drift; which one a caller reaches for
is a naming preference, and `test_output.py` pins that the bytes are identical.

Deliberately no business logic here: it takes rows of plain dicts.
"""

from __future__ import annotations

import json
import sys
from collections.abc import Iterable, Mapping, Sequence
from enum import StrEnum
from typing import Any, TextIO

from rich.console import Console
from rich.table import Table

__all__ = ["CHOICES", "OutputFormat", "make_console", "render"]


# orjson is an optional accelerator (`uv sync --extra fast`). The stdlib fallback is
# mandatory: the base install has no orjson, so the code must not require it. Both
# functions are module-level (not hidden in the except arm) so tests can prove the
# fallback produces identical bytes — otherwise the fallback is untested dead code.
def _dumps_std(obj: Any) -> str:
    return json.dumps(obj, ensure_ascii=False, default=str, separators=(",", ":"))


try:  # pragma: no cover - depends on whether the optional extra is installed
    import orjson  # type: ignore[import-not-found]

    def _dumps_orjson(obj: Any) -> str:
        return orjson.dumps(obj, default=str).decode()

    _dumps = _dumps_orjson
except ImportError:  # pragma: no cover - the base-install path
    _dumps = _dumps_std


def make_console(**kwargs: Any) -> Console:
    """A Console that never wraps data into unreadable columns and never colours pipes."""
    return Console(no_color=True, highlight=False, soft_wrap=True, **kwargs)


#: The table's width floor for a non-terminal stream (a pipe, a CI log, a captured test
#: run). Rich falls back to 80 columns there, and the events table is nine columns wide
#: with two ISO-8601 timestamps in it: at 80 it renders as `serial`/`_no` and
#: `2026-0`/`5-21T1` — technically "both timestamps visible", practically unreadable, and
#: unreadable is exactly what the payroll triage view exists to prevent. A real terminal
#: keeps its own width (this floor only lifts it, never narrows it).
TABLE_MIN_WIDTH = 200


def _table_console(stream: TextIO | None) -> Console:
    """The console the table renderer prints to, wide enough to show what it has.

    `width` is passed only when the target is not a terminal: on a terminal rich's own
    detection is right and overriding it would clip a user who made their window wide.
    """
    handle = stream if stream is not None else sys.stdout
    if hasattr(handle, "isatty") and handle.isatty():
        return make_console(file=stream)
    return make_console(file=stream, width=TABLE_MIN_WIDTH)


class OutputFormat(StrEnum):
    """The three supported renderings. `json` is the stable machine form.

    `jsonl` is a synonym for `json` at this layer (both are one record per line — see
    the module docstring); it exists because p1-08's contract names `--format jsonl`
    for the stream that feeds `gateclerk.model.from_jsonl()`, and a command cannot offer
    a format this enum does not list.
    """

    JSON = "json"
    JSONL = "jsonl"
    TABLE = "table"


#: Tuple form for CLI choice lists and tests (keeps ordering explicit).
CHOICES = tuple(fmt.value for fmt in OutputFormat)


def render(
    rows: Sequence[Mapping[str, Any]],
    *,
    fmt: str,
    columns: Sequence[str] | None = None,
    stream: TextIO | None = None,
) -> None:
    """Write `rows` to `stream` (stdout by default) in `fmt`.

    `columns` selects and orders the table view; json always emits whole records so a
    consumer never silently loses a field because someone tidied a table.
    """
    if fmt == OutputFormat.JSON or fmt == OutputFormat.JSONL:
        # Same renderer on purpose: `model.to_jsonl()`/`from_jsonl()` are one compact
        # object per line, which is exactly what `_render_json` emits. Two renderers would
        # be two places for the framing rule (separators, ensure_ascii, trailing newline)
        # to drift, and a drifted frame is a silently unparseable payroll stream.
        _render_json(rows, stream=stream)
    elif fmt == OutputFormat.TABLE:
        _render_table(rows, columns=columns, stream=stream)
    else:  # pragma: no cover - guarded by the CLI choice
        raise ValueError(f"unknown output format {fmt!r}")


def _render_json(
    rows: Sequence[Mapping[str, Any]],
    *,
    stream: TextIO | None,
) -> None:
    console = make_console(file=stream)
    for row in rows:
        console.print(_dumps(dict(row)), markup=False)


def _render_table(
    rows: Sequence[Mapping[str, Any]],
    *,
    columns: Sequence[str] | None,
    stream: TextIO | None,
) -> None:
    console = _table_console(stream)
    if not rows:
        console.print("(no rows)", markup=False)
        return
    cols = list(columns) if columns else list(rows[0].keys())
    table = Table(show_lines=False, header_style="bold")
    for col in cols:
        table.add_column(col, overflow="fold")
    for row in rows:
        table.add_row(*[_cell(row.get(col)) for col in cols])
    console.print(table)


def _cell(value: Any) -> str:
    if value is None:
        return "-"
    if isinstance(value, bool):
        return "yes" if value else "no"
    if isinstance(value, Mapping | Sequence | Iterable) and not isinstance(value, str | bytes):
        return _dumps(value)
    return str(value)
