# GC-P02 — Fingerprint write schema ships with the package

BOARD: gateclerk   DEPENDS ON: —   GATED: no   COVERS: GC-02 / —

## WHY

`migrate_fingerprints._capture_shape()` reads a test fixture from the source checkout at
runtime. Wheels, Docker images, tarballs and zipapps do not contain `tests/`, so
`gateclerk migrate apply` crashes as soon as one fingerprint write is planned. The shape
must travel with the package (R2, R3: the real path must work from the installed product).

## VERIFY

```bash
uv run --frozen python - <<'PY'
import inspect
from gateclerk import migrate_fingerprints as m
src = inspect.getsource(m._capture_shape)
print("reads tests/fixtures:", "parents[2]" in src and "tests" in src)
print("module name:", m._CAPTURE_NAME)
PY
```

Still broken while the output is:

```text
reads tests/fixtures: True
module name: fpdownload_accept_request.json
```

If `reads tests/fixtures` is `False`, stop and close the card with that output.

## FILES

- `src/gateclerk/migrate_fingerprints.py:604-632` — `_assert_capture_shape` calls
  `_capture_shape()` and compares the body's `FingerPrintCfg` key set.
- `src/gateclerk/migrate_fingerprints.py:635-663` — the defect:
  ```python
  path = (
      Path(__file__).resolve().parents[2]
      / "tests"
      / "fixtures"
      / "recorded"
      / "site-a-ds-k1t341amf-s"
      / "enrollment"
      / _CAPTURE_NAME
  )
  payload = json.loads(path.read_text(encoding="utf-8"))
  ```
  The cache `_CAPTURE_SHAPE` and the `json`/`Path` use in this function go away with it.
- `tests/fixtures/recorded/site-a-ds-k1t341amf-s/enrollment/fpdownload_accept_request.json`
  — stays in the repo as the test authority. It is not read at runtime after this card.
- `tests/test_e1_06b_fingerprints.py:471` — `test_the_download_body_is_the_captured_shape`
  already pins the fixture shape.

## CHANGE

1. Replace the `_CAPTURE_NAME`/`_CAPTURE_SHAPE`/`_capture_shape` block in
   `src/gateclerk/migrate_fingerprints.py` with one immutable constant. Use the exact keys
   the capture carries:
   ```python
   #: The captured FingerPrintCfg key set (fixture:
   #: tests/fixtures/recorded/site-a-ds-k1t341amf-s/enrollment/fpdownload_accept_request.json).
   #: Embedded, not read at runtime: wheels, containers and zipapps do not ship tests/.
   CAPTURED_FP_COND_KEYS: tuple[str, ...] = (
       "employeeNo",
       "enableCardReader",
       "fingerPrintID",
       "fingerType",
       "fingerData",
   )
   ```
2. In `_assert_capture_shape`, replace `expected = _capture_shape()` with:
   ```python
   expected = CAPTURED_FP_COND_KEYS
   ```
   Keep the existing `raise FpShapeError(...)` messages and the `fingerData` verbatim check
   unchanged.
3. Remove imports that become unused (`json` only if nothing else in the module uses it;
   check with ruff). Do not remove `Path` if other code uses it.

What must NOT change:

- `FpWrite`, `plan_fingerprint_writes`, `run_fingerprints_phase`, the one-shot
  `FingerPrintDownload` body builder, and every `FpShapeError` message.
- The fixture file and `tests/test_e1_06b_fingerprints.py`; the test must keep reading the
  fixture as the contract.

## TESTS

Write `tests/test_gc_p02_fp_schema.py` first and run:

```bash
uv run --frozen pytest -q tests/test_gc_p02_fp_schema.py
```

Copy the fixture loader from `tests/test_e1_06b_fingerprints.py:471`.

Tests:

- `test_captured_keys_match_the_recorded_fixture` — load
  `fpdownload_accept_request.json`, assert
  `set(CAPTURED_FP_COND_KEYS) == set(payload["FingerPrintCfg"])`.
- `test_assert_capture_shape_rejects_an_extra_key` — build a valid body, add one key, and
  assert `FpShapeError` with the key-set drift message.
- `test_capture_shape_never_reads_the_tests_tree` — `inspect.getsource(migrate_fingerprints)`
  does not contain `parents[2]` or `tests/fixtures`; `_assert_capture_shape` still accepts
  the recorded body.
- `test_capture_shape_works_from_a_temp_cwd` — `monkeypatch.chdir(tmp_path)` and assert a
  valid body still passes (no file-system lookup).

## GATE

```bash
uv run --frozen pytest -q
uv run --frozen ruff check src/gateclerk
```

## ACCEPT

- [ ] No runtime code reads `tests/` or `parents[2]`.
- [ ] The key tuple lives in `migrate_fingerprints.py` and matches the fixture.
- [ ] The shape guard still rejects a renamed, extra or missing key.
- [ ] `plan_fingerprint_writes` and `run_fingerprints_phase` work from a temp cwd.
- [ ] New tests and the full suite pass.

## OUT

`migrate_export.py`, `migrate_apply.py`, `migrate_write.py`, the fingerprint fixture, and
`scripts/build_dist.py` (GC-P13 owns packaging).

## HANDOFF

Branch base `origin/main`; PR target `feat/gateclerk-finish`.

1. Run the GATE.
2. Open the PR against `feat/gateclerk-finish`.
3. When the gate is green and the PR is mergeable, run `gh pr merge <number> --squash`
   yourself.
4. Never merge into `main`/`master`; never force-push.
5. If the PR is not mergeable (conflict), rebase on `origin/feat/gateclerk-finish`, re-run
   the GATE, then merge. If that fails twice, stop and report `LEFT:`.

The card is complete only after the merge.

DONE: PR URL and merge commit.
LEFT: anything not merged, with the reason.
