# gateclerk

Read-only attendance reader: Hikvision face/card terminals → normalized punch records,
heading to Business Central in a later phase. `gateclerk` = time attendance, read-only.

The contract is [docs/DESIGN.md](docs/DESIGN.md). The phase list is
[ROADMAP.md](ROADMAP.md). The read commands are live as of card p1-08; there are no
write commands and there never will be — this tool is read-only by design.

## Quickstart

```bash
uv sync --extra fast            # python 3.12 is fetched by uv, not your system python
uv run gateclerk --version        # gateclerk 0.1.0
uv run gateclerk --help           # device | users | events | creds
uv run ruff check . && uv run pytest          # both offline, both must stay green
```

Against a real controller on the site LAN, with credentials resolved as below:

```bash
uv run gateclerk device info  --host 192.0.2.10                 # model, serial, firmware
uv run gateclerk device time  --host 192.0.2.10 --tz Europe/Bucharest
uv run gateclerk users list   --site site-a --config sites.toml
uv run gateclerk events --host 192.0.2.10 \
    --since 2026-05-21T00:00:00 --until 2026-05-22T00:00:00 --output jsonl > punches.jsonl
```

`--output json` (or the `--json` switch) on any read command gives one JSON object per
line — the stable, pipeable form; `--output table` (default) is the human view.
`--output jsonl` is the same stream with the record keys `gateclerk.model.from_jsonl()`
consumes, so `gateclerk events ... --output jsonl | python -c 'from gateclerk.model import
from_jsonl, sys; print(len(from_jsonl(sys.stdin.read())))'` round-trips it. Every field
carries the provenance the payroll question needs (`tz_source`, `direction_source`,
`tz_offset_min_device`) and the untouched device row in `raw`.

## Credentials

No credential ever goes in this repo (`.env` is gitignored from commit 1). Resolution
order, highest first — implemented by card p1-02:

1. `--user` / `--password` flags (one-off debugging only; they land in shell history)
2. `GATECLERK_USER` / `GATECLERK_PASSWORD`, or per-host `GATECLERK_<SANITIZED_HOST>_USER` / `_PASSWORD`
   (every non-alphanumeric becomes `_`, so host `192.0.2.10` → `GATECLERK_192_0_2_10_PASSWORD`).
   An empty variable counts as unset, so a half-filled `.env` falls through instead of
   sending a blank password at the device's lockout counter.
3. macOS Keychain, service `gateclerk-hikvision`, account = the device host:

```bash
# -j is the comment flag (-C is a four-char TYPE code, it will not store this).
# -w last so the password is prompted, never typed into shell history.
security add-generic-password -U -s gateclerk-hikvision -a 192.0.2.10 -j 'user=admin' -w
```

The `user=` inside that comment is the ISAPI username, used unless a flag, an env var, or
`sites.toml`'s `isapi_user` overrides it. Check what would be used, without touching the
device or printing a secret:

```bash
uv run gateclerk creds explain 192.0.2.10          # the resolution plan for this host
uv run gateclerk creds check --host 192.0.2.10     # resolve + print the SOURCE, never the pw
```

`creds check` exits `2` and prints the exact `security` command to run when nothing
resolves. A password never appears in a repr, a log line, or an error message: it lives in
a `Secret` whose `repr` is `Secret(***)`, and the ISAPI client is handed a *callable* that
returns one rather than a password attribute.

## Site config

`sites.toml` (see `sites.toml.example`) holds the non-secret half of a connection — hosts
are config, passwords never are:

```toml
[[site]]
name = "site-a"
host = "192.0.2.10"
port = 80
iana_tz = "Europe/Bucharest"
isapi_user = "admin"
keychain_service = "gateclerk-hikvision"
```

`--site site-a --config sites.toml` resolves host/port/user/service in one step. The tool
never picks a site for you: `--host` or `--site` is required, even when the file holds
exactly one block — a leftover `sites.toml` in the current directory must not silently
choose which door controller to talk to. Unknown keys and out-of-range values are refused
before any request is built.

## Read-only, enforced by CI

This tool must never change device state: only `GET`, plus the stateless search `POST`s
declared in `gateclerk.endpoints.SEARCH_ENDPOINTS` (`UserInfo/Search`, `AcsEvent`, and
`AcsEventTotalNum` — the `--count` cross-check, which displays a number and is never a
loop bound). Every callable path is declared in `src/gateclerk/endpoints.py`, and
`tests/test_endpoints_registry.py` fails the build if a mutating verb ever appears there.
Adding a write path is a design change, not a diff.

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
| `src/gateclerk/cli.py` | p1-01, p1-08 | command tree, shared connection flags, the exit-code contract, rendering choice |
| `src/gateclerk/pipeline.py` | p1-08 | the command pipeline: device reads, record assembly, the paged walks, the request log |
| `src/gateclerk/endpoints.py` | p1-01 | the read-only endpoint registry |
| `src/gateclerk/output.py` | p1-01 | json / jsonl / rich-table rendering |
| `src/gateclerk/exceptions.py` | p1-01 | shared ISAPI error vocabulary |
| `src/gateclerk/config.py` | p1-02 | config + credential resolution (Keychain/env/flags) |
| `src/gateclerk/isapi_response.py` | p1-03 | ISAPI response truth: XML/JSON sniffing, the three envelope shapes, XML guard, envelope→typed-error mapping |
| `src/gateclerk/isapi_transport.py` | p1-03 | `IsapiClient`: digest session, timeouts, bounded retries, 401 circuit, read-only verbs from the registry |
| `src/gateclerk/capabilities.py` | p1-04 | capability discovery + the event-code classifier |
| `src/gateclerk/paging.py` | p1-05 | the paged-search engine: cursor, chunking, termination rules, page cap |
| `src/gateclerk/tz_dialect.py` | p1-06b | Hikvision tz dialect → **diagnostic** offsets only (never UTC math) |
| `src/gateclerk/tz.py` | p1-06 | site-tz resolver: naive device wall time + site IANA zone → UTC |
| `src/gateclerk/tz_mismatch.py` | p1-06d | the offset-mismatch flag, computed after resolution and unable to move the instant |
| `src/gateclerk/model.py` | p1-07 | `EventRecord` / `UserRecord` + `to_jsonl` / `from_jsonl` — the output contract |

## Status

P1 in progress. `gateclerk --version` works, and as of card p1-08 the read commands are live:
`device info`, `device time`, `device capabilities`, `users list` and `gateclerk events
--since ... --until ...` against a real controller. `device time` prints both halves of
the clock story — the wall-clock skew and the three-valued `tz_offset_mismatch` verdict
(site-a in summer: skew ~4 s, offset wrong on every record) — so an operator at the
device cannot read a healthy skew as "the time is fine"; a null verdict means the device
claimed no offset and says so, never that the offsets agree.
Exit codes: `0` ok, `2` config/input,
`3` auth (check the credential before the account locks), `4` device error, `5` the paging
engine refused to loop on a misbehaving device. There is no local store yet — that is P2 —
so `--output jsonl` is where the records go.
