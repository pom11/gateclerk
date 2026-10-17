"""Output rendering: json is stable and parseable, table never crashes on odd values."""

from __future__ import annotations

import io
import json

import pytest

from gateclerk.output import CHOICES, OutputFormat, _cell, render


def rows() -> list[dict[str, object]]:
    return [
        {
            "employee_no": "007",
            "name": "Andrei Păurescu",
            "serial_no": 12,
            "ok": True,
            "note": None,
        },
        {"employee_no": "008", "name": "Ana-Maria", "serial_no": 13, "ok": False, "note": "x"},
    ]


def test_json_output_is_one_json_object_per_line() -> None:
    buf = io.StringIO()
    render(rows(), fmt=OutputFormat.JSON, stream=buf)
    lines = [ln for ln in buf.getvalue().splitlines() if ln.strip()]
    assert len(lines) == 2
    parsed = [json.loads(ln) for ln in lines]
    assert parsed[0]["employee_no"] == "007", "leading zeros must survive (employee ids!)"
    assert parsed[0]["name"] == "Andrei Păurescu", "unicode must not be escaped away"


def test_json_output_preserves_none_and_bool() -> None:
    buf = io.StringIO()
    render(rows(), fmt=OutputFormat.JSON, stream=buf)
    first = json.loads(buf.getvalue().splitlines()[0])
    assert first["note"] is None
    assert first["ok"] is True


def test_empty_rows_json_prints_nothing() -> None:
    buf = io.StringIO()
    render([], fmt=OutputFormat.JSON, stream=buf)
    assert buf.getvalue() == ""


def test_empty_rows_table_says_so() -> None:
    buf = io.StringIO()
    render([], fmt=OutputFormat.TABLE, stream=buf)
    assert "no rows" in buf.getvalue()


def test_table_renders_selected_columns_only() -> None:
    buf = io.StringIO()
    render(rows(), fmt=OutputFormat.TABLE, columns=["employee_no", "name"], stream=buf)
    out = buf.getvalue()
    assert "employee_no" in out and "Andrei" in out
    assert "serial_no" not in out, "columns= must restrict the view"


def test_table_without_columns_uses_record_keys() -> None:
    buf = io.StringIO()
    render(rows(), fmt=OutputFormat.TABLE, stream=buf)
    out = buf.getvalue()
    for key in rows()[0]:
        assert key in out


def test_cell_formats() -> None:
    assert _cell(None) == "-"
    assert _cell(True) == "yes"
    assert _cell(False) == "no"
    assert _cell("x") == "x"
    assert _cell(3) == "3"


def test_cell_serialises_nested_structures() -> None:
    assert "a" in _cell({"a": 1})
    assert "1" in _cell([1, 2])


def test_unknown_format_raises() -> None:
    with pytest.raises(ValueError, match="unknown output format"):
        render(rows(), fmt="yaml", stream=io.StringIO())


def test_output_format_choices_are_the_documented_triple() -> None:
    """Card p1-08 added `jsonl`; the CLI's `--format`/`--output` metavar is generated from
    this tuple, so a drift here is a drift in what operators can type.

    `jsonl` is a *second spelling* of the json stream, not a second renderer
    (`gateclerk.model.to_jsonl`/`from_jsonl` are one compact object per line, which is what
    `--format json` already prints), which is why the two share a code path and the tuple
    has three names for two renderers.
    """
    assert CHOICES == ("json", "jsonl", "table")


def test_stdlib_fallback_matches_whichever_backend_is_active() -> None:
    """orjson is optional: the stdlib fallback must produce the same bytes.

    Proves the base install (no orjson) renders identically to the `fast` extra, so a
    machine without the extra cannot silently produce different payroll records.
    """
    from gateclerk.output import _dumps, _dumps_std

    for payload in rows():
        assert _dumps_std(payload) == _dumps(payload)


def test_json_backend_is_ascii_safe_and_compact() -> None:
    from gateclerk.output import _dumps

    out = _dumps({"name": "Păurescu", "n": 1})
    assert "ă" in out, "diacritics must not be \\u-escaped (readable fixtures/logs)"
    assert ", " not in out and ": " not in out, "jsonl must stay compact"
