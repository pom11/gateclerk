"""GC-P02: the captured FP write shape ships with the package, not with ``tests/``.

``migrate_fingerprints._capture_shape()`` used to read
``tests/fixtures/recorded/site-a-ds-k1t341amf-s/enrollment/fpdownload_accept_request.json``
off the *source checkout* at runtime (``Path(__file__).parents[2] / "tests" / ...``).
Wheels, Docker images, tarballs and zipapps do not contain ``tests/``, so on an
installed product ``gateclerk migrate apply`` raised ``FpShapeError`` the moment one
fingerprint write was planned — before a byte reached the device.

The shape is now the embedded ``CAPTURED_FP_COND_KEYS`` tuple. The fixture stays in the
repo as the *test* authority for that tuple: this file is what keeps the embedded copy
honest, so the contract did not become folklore (R2, R3 — the real path works from the
installed product).
"""

from __future__ import annotations

import ast
import base64
import hashlib
import inspect
import json
from pathlib import Path
from typing import Any

import pytest

from gateclerk import migrate_fingerprints
from gateclerk.migrate_fingerprints import (
    CAPTURED_FP_COND_KEYS,
    FpShapeError,
    FpWrite,
    _assert_capture_shape,
    build_fingerprint_download_body,
    person_hash,
)

FIXTURES = Path(__file__).parent / "fixtures/recorded/site-a-ds-k1t341amf-s"
ENROLLMENT = FIXTURES / "enrollment"

#: The capture is the contract (loader copied from tests/test_e1_06b_fingerprints.py:86).
FP_CAPTURE_REQUEST = json.loads((ENROLLMENT / "fpdownload_accept_request.json").read_text())

#: A tiny synthetic template of the recorded third-party family (ASCII "301" header).
TPL_BYTES = b"301" + bytes((i * 7 + 3) % 251 for i in range(40))
TPL_B64 = base64.b64encode(TPL_BYTES).decode("ascii")
FAMILY_NOTE = "301-header (third-party sensor family, not self-identified — OBSERVED.md)"


def write_for(no: str, *, b64: str = TPL_B64, raw: bytes = TPL_BYTES) -> FpWrite:
    """One planned write, captured key set, template base64 verbatim."""
    template: dict[str, Any] = {
        "enableCardReader": [1],
        "employeeNo": no,
        "fingerPrintID": 1,
        "fingerType": "normalFP",
        "fingerData": b64,
    }
    return FpWrite(
        employee_no=no,
        employee_hash=person_hash(no),
        template=template,
        finger_data_b64=b64,
        intended_sha256=hashlib.sha256(raw).hexdigest(),
        sensor_family=FAMILY_NOTE,
    )


def code_string_literals(src: str) -> set[str]:
    """Every string literal in *executable code* — docstrings and comments excluded.

    The distinction is the whole point of this card: prose may (and should) name the
    fixture it rests on, a *runtime path* into ``tests/`` may not exist. Comments never
    reach the AST; docstrings are stripped by node identity.
    """
    tree = ast.parse(src)
    docstrings: set[int] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Module | ast.ClassDef | ast.FunctionDef | ast.AsyncFunctionDef):
            head = node.body[0] if node.body else None
            if (
                isinstance(head, ast.Expr)
                and isinstance(head.value, ast.Constant)
                and isinstance(head.value.value, str)
            ):
                docstrings.add(id(head.value))
    return {
        node.value
        for node in ast.walk(tree)
        if isinstance(node, ast.Constant)
        and isinstance(node.value, str)
        and id(node) not in docstrings
    }


# --- the embedded shape IS the recorded capture -------------------------------------------


def test_captured_keys_match_the_recorded_fixture() -> None:
    """The embedded tuple is the capture's key set — this is what keeps it honest."""
    assert set(CAPTURED_FP_COND_KEYS) == set(FP_CAPTURE_REQUEST["FingerPrintCfg"])
    # The tuple is ordered and immutable: a wheel has no fixture to re-derive it from.
    assert isinstance(CAPTURED_FP_COND_KEYS, tuple)
    assert len(CAPTURED_FP_COND_KEYS) == len(set(CAPTURED_FP_COND_KEYS)) == 5


def test_assert_capture_shape_rejects_an_extra_key() -> None:
    """Key-set drift still fails closed, with the drift message (ACCEPT #3)."""
    write = write_for("9")
    body = build_fingerprint_download_body(write)
    body["FingerPrintCfg"]["fpIndex"] = 0  # the substitution the capture never showed
    with pytest.raises(FpShapeError, match="drifted from the capture"):
        _assert_capture_shape(body, write)


def test_capture_shape_never_reads_the_tests_tree() -> None:
    """No runtime path into ``tests/`` survives in the module (ACCEPT #1).

    ``parents[2]`` is the checkout-relative walk that broke installed products; it must
    be gone outright. A code-level string pointing at the tests tree is checked through
    the AST, because the module's *prose* legitimately cites the fixture it rests on —
    and the pinned comment on ``CAPTURED_FP_COND_KEYS`` cites it too.
    """
    src = inspect.getsource(migrate_fingerprints)
    assert "parents[2]" not in src
    offenders = {
        literal
        for literal in code_string_literals(src)
        if literal == "tests" or literal.startswith("tests/") or "/tests/" in literal
    }
    assert offenders == set()
    # And the guard is still live: the recorded body passes it.
    write = write_for("9")
    _assert_capture_shape(build_fingerprint_download_body(write), write)


def test_capture_shape_works_from_a_temp_cwd(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Installed-product shape: no cwd, no checkout, no fixture — the guard still holds."""
    monkeypatch.chdir(tmp_path)
    write = write_for("9")
    body = build_fingerprint_download_body(write)  # calls _assert_capture_shape
    _assert_capture_shape(body, write)
    assert set(body["FingerPrintCfg"]) == set(CAPTURED_FP_COND_KEYS)
