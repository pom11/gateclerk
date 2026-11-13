# gateclerk

Read-only attendance collector and site agent for Hikvision face/card access-control
terminals (ISAPI).

## What it is

`gateclerk` connects to Hikvision door/attendance terminals over your local site LAN,
reads badge and face events in a strictly read-only manner, normalizes timestamps in the
site's IANA timezone, stores every record in a local crash-safe SQLite database, and
delivers them to the sinks you configure (HTTPS webhook/ERP ingest, rotating CSV files,
or rotating JSONL files).

## What it is NOT

- **Not a device configurator or door controller:** `gateclerk` never unlocks doors, never
  changes device clocks, never reboots hardware, and never writes to a terminal (the two
  opt-in exceptions are `gateclerk migrate apply --apply` for explicitly gated
  terminal-to-terminal enrollment migration and `gateclerk users import --apply` for gated
  Excel enrollment).
- **Not a cloud service:** `gateclerk` has zero hardcoded endpoints and zero telemetry. If
  you do not configure a sink in `sites.toml`, data stays on disk in your local SQLite store.

---

## Install

```bash
# Homebrew (macOS / Linux — once the release tap is published)
brew install pom11/tap/gateclerk

# pipx / pip (from a checkout or wheel)
pipx install .
# or:
pip install .

# Development / from source (provisions Python 3.12 via uv)
uv sync --extra fast
uv run gateclerk --version
```

---

## 5-minute quickstart

### 1. Run the offline demo first (no hardware, no Keychain required)

```bash
uv run gateclerk demo demo
```

`gateclerk demo demo` starts an in-process loopback fake Hikvision controller and a mock
HTTPS ingest receiver, polls synthetic punches and device users, drains them to both an
`https` sink and a `csv` sink, and prints the resulting files. Ready-to-inspect sample
configs and outputs live in [`examples/`](examples/):

- [`examples/sites.toml`](examples/sites.toml) — annotated multi-site config (`https`, `csv`, `jsonl`, and legacy `push_target`)
- [`examples/sample_scans.csv`](examples/sample_scans.csv) & [`examples/sample_scans.jsonl`](examples/sample_scans.jsonl) — normalized scan records
- [`examples/sample_roster_line.json`](examples/sample_roster_line.json) — hourly device-user roster payload
- [`examples/mock_receiver.py`](examples/mock_receiver.py) — ~100-line stdlib reference HTTPS ingest server

### 2. Guided setup for a real terminal (`gateclerk init`)

```bash
uv run gateclerk init
```

`gateclerk init` walks through five safe steps: chooses where `sites.toml` lives, records
credential **reference names** (never plaintext passwords), runs one read-only device
probe, configures your delivery sink, and writes `sites.toml` atomically.

### 3. Verify health and read events

```bash
uv run gateclerk status --config sites.toml
uv run gateclerk doctor --config sites.toml
uv run gateclerk device info --host 192.0.2.10
uv run gateclerk device time --host 192.0.2.10 --tz Europe/Bucharest
uv run gateclerk users list  --site site-a --config sites.toml
uv run gateclerk events --host 192.0.2.10 \
    --since 2026-05-21T00:00:00 --until 2026-05-22T00:00:00 --output jsonl > punches.jsonl
```

---

## Common commands

Every read command accepts `-o table` (default human view) or `-o json` / `-o jsonl`
(machine-readable, one JSON object per line, PII- and secret-free).

| Command | What it does |
|---|---|
| `gateclerk demo demo` | Run the self-contained offline loop (fake device + SQLite store + mock HTTPS & CSV sinks) |
| `gateclerk init` | Interactive, non-clobbering first-site setup wizard |
| `gateclerk status` | One-screen health per site (queue depth, dead-letter count, drain age, agent loop, cached device state) |
| `gateclerk doctor` | Exhaustive read-only self-check (config, credential refs, live device + clock skew, sink TLS/paths, SQLite `quick_check`) |
| `gateclerk device info\|time\|capabilities` | Read model/serial/firmware, wall-clock skew vs site timezone, or ISAPI capabilities |
| `gateclerk users list` | Enumerate enrolled users on the terminal (`employee_no`, `name`, `cardNo`, `hasFace`) |
| `gateclerk events --since ... --until ...` | Stream normalized attendance events over a time window |
| `gateclerk creds test\|explain\|set\|get\|remove` | Verify or manage credential references (Keychain on macOS, `0600` `credentials.json` on Linux) |
| `gateclerk sink list\|add\|remove\|test` | Inspect, edit, or probe per-site delivery sinks (`https`, `csv`, `jsonl`) and the `mnotify` alert route |
| `gateclerk export config` | Export sanitized site/device inventory to CSV or JSONL (allowlist columns, ref names only, `dropped_keys` audit) |
| `gateclerk export scans` | Stream stored scans from the local SQLite database to CSV or JSONL (`--redact` strips personal identifiers) |
| `gateclerk service install\|uninstall\|logs` | Render `launchd` plist (macOS) or `systemd` unit (Linux) and print load/unload/log commands (never auto-loads) |
| `gateclerk agent run \| ack \| deadletter list\|remove` | Run the poll+drain loop, clear a 401 device park after fixing credentials, or inspect/remove dead-letter rows |
| `gateclerk migrate probe\|export\|diff\|apply\|undo` | Terminal-to-terminal user/card/face enrollment migration pipeline |
| `gateclerk migrate clean` | Report enrollment bundles and run journals older than `--older-than` (default `7d`) — a dry run by default; `--apply` deletes them. `probes/` is never touched (GC-14 retention) |

### Delivery sinks decision table (`[[site.sink]]` vs `push_target`)

A site can fan out every stored punch to multiple named sinks (`[[site.sink]]`), or use a
single legacy `push_target` (which maps to one implicit `https` sink named `legacy`). See
[`examples/sites.toml`](examples/sites.toml) and [`examples/mock_receiver.py`](examples/mock_receiver.py).

| Sink type | What it is | Config snippet (`examples/sites.toml`) | Token / credentials | Rotation | Failure behavior | When to use |
|---|---|---|---|---|---|---|
| `https` | POSTs JSONL batches + hourly device-user rosters to an HTTPS ingest (`https://` or `stub://`) | `[[site.sink]]`<br>`name = "cloud_ingest"`<br>`type = "https"`<br>`url = "https://..."` | Bearer token **reference** (`token_env` / `token_keychain`, or default `GATECLERK_INGEST_TOKEN_<SITE>` / `gateclerk-ingest-<site>`) | N/A (remote endpoint) | Independent per-sink `push_queue` retry backoff + `dead_letter` after `push_dead_letter_after_s` (24 h) | Production cloud / ERP ingest (`examples/mock_receiver.py` contract) |
| `csv` | Appends stable-header UTF-8 CSV rows + `.roster.csv` companion to a local absolute path | `[[site.sink]]`<br>`name = "daily_csv"`<br>`type = "csv"`<br>`path = "/abs/path/events.csv"` | None (local filesystem permissions) | `daily` (default, `<stem>-YYYY-MM-DD.csv`) or `monthly` (`<stem>-YYYY-MM.csv`) | Independent per-sink `push_queue` + `dead_letter` if disk/dir is unwritable | Local spreadsheet / HR share / daily file drop |
| `jsonl` | Appends one self-describing JSONL record per line to a local absolute path | `[[site.sink]]`<br>`name = "monthly_jsonl"`<br>`type = "jsonl"`<br>`path = "/abs/path/events.jsonl"` | None (local filesystem permissions) | `daily` (default) or `monthly` | Independent per-sink `push_queue` + `dead_letter` | Local log shipper, SIEM, or audit archive |
| `mnotify` | Routes the agent's P2-05 alerts (critical/warning) to micro-notify mail; NOT an event sink | `[[site.sink]]`<br>`name = "alerts"`<br>`type = "mnotify"`<br>`to = "alerts@example.com"` | mnotify's own config/keychain/file backend; gateclerk passes no token | N/A | The stderr journald line is written first; one daemon worker then runs a serialised `mnotify mail send` with a hard timeout. Any failure only warns (no second line); a full queue drops the page. Exit drains briefly and warns on an unfinished page | Operator paging via micro-notify, with journald as the evidence-of-record fallback |
| Legacy `push_target` | Single top-level key on `[[site]]`; creates one implicit sink named `legacy` (cannot be combined with `[[site.sink]]` on the same site) | `push_target = "https://..."` (or `"stub:///abs/path"`) | Default site rungs (`GATECLERK_INGEST_TOKEN_<SITE>` / `gateclerk-ingest-<site>`) | N/A | Queues and dead-letters under `sink_name = "legacy"` | Backward compatibility with single-target configs |

---

## Exit codes

Single source: [`docs/CLI-CONVENTIONS.md`](docs/CLI-CONVENTIONS.md) (`src/gateclerk/cli_conventions.py`).

| Code | Class | Meaning |
|---|---|---|
| `0` | `OK` | Everything succeeded |
| `1` | `ERROR` | Reserved (unexpected crash; never returned as a normal branchable code) |
| `2` | `USAGE_OR_CONFIG` | Bad CLI flag, invalid `sites.toml`, missing/unreadable credential reference, or stopped agent loop |
| `3` | `AUTH_TERMINAL` | HTTP `401` from the terminal — circuit opened / device parked to prevent account lockout; verify with `gateclerk creds test` |
| `4` | `DEVICE` | Terminal unreachable, timeout, or invalid ISAPI payload |
| `5` | `RUNAWAY` | Paging safety cap tripped (device kept reporting `MORE` past 10,000 pages) |
| `6` | `PUSH_FAILURE` | Delivery sink failure (dead-letter rows present or sink TLS/probe failure) |

---

## FAQ & macOS vs Linux host comparison

| Topic | macOS gate host | Linux gate host |
|---|---|---|
| **Where secrets live** | macOS Keychain (`security add-generic-password -U -s gateclerk-hikvision -a <host> -j 'user=admin' -w` and `-s gateclerk-ingest-<site> -a <site> -w`) | `~/.config/gateclerk/credentials.json` (mode `0600` required; managed via `gateclerk creds set <ref> --file ...`) or `systemd` `LoadCredential=` |
| **Env var override** | `GATECLERK_<HOST>_PASSWORD` / `GATECLERK_INGEST_TOKEN_<SITE>` | `GATECLERK_<HOST>_PASSWORD` / `GATECLERK_INGEST_TOKEN_<SITE>` |
| **Background service** | `launchd` LaunchAgent (`~/Library/LaunchAgents/com.gateclerk.agent.<site>.plist`) | `systemd` user or system unit (`gateclerk-agent@<site>.service`) |
| **How to generate unit** | `gateclerk service install --site <site>` (prints `launchctl bootstrap` command; never auto-loads) | `gateclerk service install --site <site>` (prints `systemctl --user enable --now` command; never auto-loads) |
| **How to check health** | `gateclerk status` (instant, cached) / `gateclerk doctor` (live read-only probe) | `gateclerk status` / `gateclerk doctor` |

**Q: Why does `gateclerk` refuse passwords inside `sites.toml`?**
Because `sites.toml` is configuration that gets copied into tickets, backups, and handoffs.
`sites.toml` stores only **reference names** (`keychain_service`, `token_env`,
`token_keychain`); secrets stay in Keychain or a `0600` credential file.

**Q: What happens if a terminal returns `401 Unauthorized`?**
`gateclerk` opens its auth circuit and parks the device immediately (exit `3`) after a
single failed attempt so a mistyped password never trips the Hikvision terminal's lockout
counter (which would also lock out human admin login at the door). Fix the credential,
verify with `gateclerk creds test`, then run `gateclerk agent ack --site <site>`.

---

## Privacy & data ownership

Attendance scans (`employee_no`, `name`, `cardNo`, timestamps) are **personal data**
(GDPR-adjacent workforce records). All data lives locally in your site's SQLite database
(`./gateclerk-<site>.sqlite3`) and is sent **only** to the sink URLs or file paths you
explicitly declare in `sites.toml`. There are zero default endpoints and zero telemetry
calls anywhere in the codebase (`rg -n "https://" src/` matches only scheme validators and
docstrings). When exporting scans for debugging or support (`gateclerk export scans`),
interactive TTY output is refused without `--output <path>` to prevent accidental terminal
dumps, and `--redact` strips `employee_no`, `cardNo`, and `name` from both the columns and
the embedded `raw` JSON.

---

## Links

- [`examples/`](examples/) — sample `sites.toml`, CSV/JSONL scan outputs, roster payload, and `mock_receiver.py`
- [`deploy/README.md`](deploy/README.md) — step-by-step `systemd` and `launchd` deployment runbook
- [`docs/CLI-CONVENTIONS.md`](docs/CLI-CONVENTIONS.md) — canonical verb vocabulary, hidden aliases, and exit-code contract
- [`docs/EXPORT-COLUMNS.md`](docs/EXPORT-COLUMNS.md) — column specification for `gateclerk export scans` and `gateclerk export config`
- [`docs/internal/`](docs/internal/) — architecture design, hardware protocol captures, and engineering notes
