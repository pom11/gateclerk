# gateclerk

Read-only attendance reader: Hikvision face/card terminals → normalized punch records,
heading to Business Central in a later phase. `gateclerk` = time attendance, read-only.

The contract is [docs/DESIGN.md](docs/DESIGN.md). The phase list is
[ROADMAP.md](ROADMAP.md). Everything below is P1 scaffolding; the device-reading
commands are stubs until their own cards land.

## Quickstart

```bash
uv sync --extra fast            # python 3.12 is fetched by uv, not your system python
uv run gateclerk --version        # gateclerk 0.1.0
uv run gateclerk --help           # device | users | events
uv run gateclerk device info --host 192.0.2.10   # exit 3 = 'not implemented yet' (p1-03)
uv run ruff check . && uv run pytest          # both offline, both must stay green
```

`--output json` on any read command gives one JSON object per line — the stable,
pipeable form. `--output table` (default) is the human view.

## Credentials

No credential ever goes in this repo (`.env` is gitignored from commit 1). Resolution
order, highest first — implemented by card p1-02:

1. `--user` / `--password` flags (one-off debugging only; they land in shell history)
2. `GATECLERK_USER` / `GATECLERK_PASSWORD`, or per-host `GATECLERK_<SANITIZED_HOST>_USER` / `_PASSWORD`
3. macOS Keychain, service `gateclerk-hikvision`, account = the device host:

```bash
security add-generic-password -s gateclerk-hikvision -a 192.0.2.10 -w \
  -C 'user=admin'   # comment field carries user=
```

## Read-only, enforced by CI

This tool must never change device state: only `GET`, plus the two stateless search
`POST`s (`UserInfo/Search`, `AcsEvent`). Every callable path is declared in
`src/gateclerk/endpoints.py`, and `tests/test_endpoints_registry.py` fails the build if a
mutating verb ever appears there. Adding a write path is a design change, not a diff.

## Tests

```bash
uv run pytest                    # offline only — a socket in a test raises
uv run pytest -m live            # needs GATECLERK_LIVE=1: a HUMAN runs these on the site LAN
```

CI never opens a socket to a device: `pytest -m "not live"` is the default in
`pyproject.toml`, `GATECLERK_LIVE=0` is set in the workflow, and `tests/conftest.py`
monkeypatches `socket` so an accidental network call fails loudly instead of hanging.
Recorded-response fixtures will live in `tests/fixtures/` (card p1-09) with credentials,
serials and names synthetic; `tests/test_repo_hygiene.py` already rejects any real
device address or non-placeholder secret anywhere under `tests/`.

## CI and branch protection

One job, `.github/workflows/ci.yml`: `uv sync --frozen` → `ruff check` →
`ruff format --check` → pytest on the base install → pytest with `[fast]` →
console-script import check. Python 3.12 is provisioned by uv, not the runner.

`main` is **not** branch-protected: this is a private repo on GitHub's free plan and
the protection API returns `403 Upgrade to GitHub Pro or make this repository public`.
Until that changes, "CI must be green before merge" is a process rule, not a platform
enforcement — the required check name to look for is `lint + test (offline)`. Flip on
protection (require that check + one approving review) the moment the repo goes public
or upgrades.

## Layout

| Path | Owner card | What it is |
|---|---|---|
| `src/gateclerk/cli.py` | p1-01 | command tree + shared connection flags (stubs) |
| `src/gateclerk/endpoints.py` | p1-01 | the read-only endpoint registry |
| `src/gateclerk/output.py` | p1-01 | json / rich-table rendering |
| `src/gateclerk/exceptions.py` | p1-01 | shared ISAPI error vocabulary |
| `src/gateclerk/config.py` | p1-02 | config + credential resolution (Keychain/env/flags) |
| `src/gateclerk/isapi.py` | p1-03 | httpx digest transport, retries, error envelope |
| `src/gateclerk/tz_dialect.py` | p1-06b | Hikvision tz dialect → **diagnostic** offsets only (never UTC math) |
| `src/gateclerk/time.py` | p1-06 | site-tz resolver: naive device wall time + site IANA zone → UTC |
| `src/gateclerk/models.py` | p1-07 | `EventRecord` / `UserRecord` — the output contract |

## Status

P1 in progress. `gateclerk --version` works; `device info`, `device time`, `users list`
and `events search` exit `3` with a pointer to the card that implements them.
