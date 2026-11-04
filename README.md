# gateclerk

Read-only attendance reader: Hikvision face/card terminals → normalized punch records,
heading to Business Central in a later phase. `gateclerk` = time attendance, read-only.

The contract is [docs/DESIGN.md](docs/DESIGN.md). The phase list is
[ROADMAP.md](ROADMAP.md). The read commands are live as of card p1-08 and remain the
whole P1 surface: nothing there ever writes. The one exception the roadmap planned is
the E1 enrollment-migration group (`gateclerk migrate`, [docs/ENROLLMENT-MIGRATION.md](docs/ENROLLMENT-MIGRATION.md)
§7): probe/export/diff are read-only, and the group writes to a device ONLY under its
explicitly gated `apply --apply` — every other path is provably zero-byte. One device
wall is documented truth, not a bug (E1-11, docs/OBSERVED-site-B.md): face *templates*
are firmware-generation-bound (`FR500005` templates are rejected by V4.13.0 firmware
with `badJsonContent`/`errorMsg: faceURL`), so cross-generation face carry needs
re-enrollment on the target — `migrate diff` says so up front as a report-only
`facePortability` warning, and the faces phase journals the rejection by class.

## Quickstart

```bash
uv sync --extra fast            # python 3.12 is fetched by uv, not your system python
uv run gateclerk --version        # gateclerk 0.1.0
uv run gateclerk --help           # device | users | events | creds | agent | migrate | demo
uv run ruff check . && uv run pytest          # both offline, both must stay green
```

No device on your desk? `uv run gateclerk demo device serve` runs a loopback fake of the
`webs` server — same ISAPI envelope shapes the client reads (digest challenge, XML
System/*, silent maxResults clamp, recorded rejections), SYNTHETIC values only (RFC 5737
addresses, `Demo*` identities, `DEMO-*` serials/cards): point `--host 127.0.0.1` at it
and the whole read path runs offline. `demo device urls` prints the URLs and the
placeholder credential pair.

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
uv run gateclerk creds test --host 192.0.2.10      # resolve + print the SOURCE, never the pw
```

`creds test` exits `2` and prints the exact `security` command to run when nothing
resolves. A password never appears in a repr, a log line, or an error message: it lives in
a `Secret` whose `repr` is `Secret(***)`, and the ISAPI client is handed a *callable* that
returns one rather than a password attribute.

The canonical verb is `test`; `creds check` is the pre-vocabulary spelling and still works,
hidden from `--help` (docs/CLI-CONVENTIONS.md has the verb list, the alias table, and the
exit-code table every command obeys).

## Site config

`sites.toml` (see `sites.toml.example`) holds the non-secret half of a connection — hosts
are config, passwords never are:

```toml
[[site]]
name = "site-a"
host = "192.0.2.10"
port = 80
iana_tz = "Europe/Bucharest"
device_tz = "Europe/Bucharest"
isapi_user = "admin"
keychain_service = "gateclerk-hikvision"
```

`device_tz` (optional) is the p1-12 owner decision for clocks that will never be fixed:
it declares the zone the device's wall digits actually live in — site-a stamps `+02:00`
year-round while the digits ARE Bucharest (OBSERVED.md "time/offset bug"). When set, the
mapped zone is what `gateclerk events` resolves punches in (authoritative over the
device's claimed offset) and the run-level tz-mismatch warning stays silent for that
device, because the wrongness is declared and accepted; record provenance
(`tz_offset_mismatch` and both offset fields) still populates exactly as before, and
`gateclerk device time` labels its verdict `mapped via sites.toml`. An explicitly typed
`--tz` overrides the mapping — and then the warning fires again, because the mapping is
no longer what made the run's zone. Omit the key for a device whose clock is not
known-bad; absent it, behaviour is byte-for-byte the previous one.

P2 (site agent) keys are already part of the schema — every one is read by the agent,
optional for the CLI, and documented in `sites.toml.example`: `cadence_s`/`overlap_s`
(5-min poll + 5-min gap-healing window), `db_path` (defaults to `./gateclerk-<site>.sqlite3`),
`db_warn_bytes` (2 GiB store watermark), `push_target` (`stub://` or `https://` ref,
never a default endpoint) and `push_dead_letter_after_s` (24 h). One rule changes with
the agent surface: **`iana_tz` becomes REQUIRED** — the P2 agent refuses a block without
an explicit zone (site tz is payroll truth, never defaulted; docs/P2-SITE-AGENT.md §2d).
The P1 CLI keeps working on a zoneless block byte-for-byte but prints one `warning:`
line naming the site, because its fallback is a compiled-in site-a value. Credential
*references* follow the name `gateclerk-<site>-<host>` (the systemd `LoadCredential=`
name; macOS keeps the keychain scheme unchanged) — password values remain refused in
every config surface, unknown-key style.

`--site site-a --config sites.toml` resolves host/port/user/service in one step. The tool
never picks a site for you: `--host` or `--site` is required, even when the file holds
exactly one block — a leftover `sites.toml` in the current directory must not silently
choose which door controller to talk to. Unknown keys and out-of-range values are refused
before any request is built.

Bundles, probe files and run journals are PII and live under the private `--bundles-root`
(`GATECLERK_BUNDLE_ROOT`, default `~/gateclerk/bundles` — e.g. `~/gateclerk-bundles`), **never
inside a git repo**: `export`/`write_bundle` refuse an `--out` inside one, and so does the
journal (§2).

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
