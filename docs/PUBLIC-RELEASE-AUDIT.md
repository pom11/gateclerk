# Public Release Audit & Fresh-History Export Procedure

Card `t_78f958d5` (`HISTORY-PUBLIC-AUDIT`). Enforced continuously at `HEAD` by
`tests/test_public_audit.py`.

## 1. HEAD-tree audit summary (`0` findings remaining)

Every tracked file in the repository (`git ls-files`) is swept by `tests/test_public_audit.py`
on every test run:

| Category | Rule | HEAD status |
|---|---|---|
| Legacy product / tenant / ERP names | Zero occurrences of the legacy internal project or tenant names anywhere in tracked files | **0 matches** |
| Private / LAN / CGNAT IPv4 addresses | Only RFC 5737 documentation ranges (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`) and loopback (`127.0.0.1`) are permitted | **0 matches** (scrubbed 4 historical doc lines in `docs/internal/`) |
| Cloud ingest URLs | Zero hardcoded Cloud Run / Cloud Functions URLs in `src/`, `tests/`, `docs/`, or `examples/` (`push_target` and sink URLs have no default) | **0 matches** |
| Personal / employee / card / serial data | All test and example fixtures are synthetic (`DEMO-*` serials/cards, `Demo*` names) | **0 matches** |
| Credentials & secrets | Zero `.env` files, bearer tokens, or non-placeholder passwords | **0 matches** |
| AI attribution trailers | Zero automated attribution trailers in tracked files | **0 matches** |
| License | Root `LICENSE` file (MIT) + `pyproject.toml` `license = { text = "MIT" }` (all runtime dependencies MIT/BSD-3 compatible: `httpx` BSD-3-Clause, `typer` MIT, `rich` MIT, `orjson` Apache-2.0/MIT) | **Verified** |

### Internal planning docs

`docs/internal/go-live-finish/` holds the go-live card index and the worker card specs.
They stay in-tree (a worker reads them from its own worktree) and carry no pre-cutover
spelling: an identifier whose *name* is itself a legacy token — the integration branch,
the tenant sandbox, the receiver repository and its env-var constants — is written as a
placeholder (`INTEGRATION_BRANCH`, `<RECEIVER>_…`) and resolved from the board card or
the private plan. `docs/internal/go-live-finish/INDEX.md` § Conventions is the
authoritative table. Board card titles keep their own spellings; the board database is
not part of the exported tree.

---

## 2. Commit-history audit & why fresh-history export is required

Sweeping `git log --all` (340+ commits prior to the `gateclerk` cutover):

1. **Historical file paths & diffs (`421f076..02f8d10`):** Early commits developed the
   package under its pre-cutover internal directory name (`src/<legacy>/...`) before
   `5b20fa1` renamed the tree to `src/gateclerk/`.
2. **Historical commit messages & author emails (`421f076..3f328eb`):** 44 commit subjects
   and local worker emails (`*@*.local`) reference internal card IDs and the pre-cutover
   name.
3. **Why `git filter-repo --replace-text` is not sufficient:** Text replacement on blobs
   does not rewrite commit messages, branch/tag refs, or author emails, and rewriting
   history in place on the working private remote would invalidate local worktrees.

### Recommended public release procedure (orphan single-commit export of `HEAD`)

Keep the private work repository intact as engineering history, and publish the public
`pom11/gateclerk` tree from a clean `git archive` of `HEAD` (so the public commit graph
starts at a single clean initial commit containing only the audited `HEAD` tree):

```bash
# 1. Verify the full offline test + public-audit suite is green at HEAD
uv run --frozen ruff check .
uv run --frozen ruff format --check .
uv run --frozen pytest -q

# 2. Export the audited HEAD tree into a fresh orphan repository
PUB_DIR=$(mktemp -d /tmp/gateclerk-public-XXXX)
git archive --format=tar HEAD | tar -x -C "$PUB_DIR"

cd "$PUB_DIR"
git init -b main
git config user.name "pom11"
git config user.email "60760299+pom11@users.noreply.github.com"
git add -A
git commit -m "gateclerk 0.1.0 — initial public release"

# 3. Build and smoke-verify the release artifacts from the clean export
uv run --frozen python scripts/build_dist.py --dist-dir dist
uv run --frozen python scripts/smoke_artifact.py --dist-dir dist
```
