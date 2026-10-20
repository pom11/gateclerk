# Deploying the gateclerk site agent

Two files live here, and both are **templates** — they are the shape of a working install,
not an install you can copy blind:

| File | What it is |
|---|---|
| `gateclerk-agent@.service` | the supported deploy target: one systemd unit **per site** (Linux agent hosts) |
| `gateclerk-agent.plist` | **EXAMPLE ONLY**: the same seams for launchd, for a developer's macOS laptop |

Windows agent hosts have no unit file here (the supported route is a Task Scheduler task
running the same `agent run` command line; see step 6). The spec is explicit about this
split: `docs/P2-SITE-AGENT.md` §2d — agents run on Linux/Windows, macOS is the dev box, so
launchd is an example and not a product.

These are static artifacts. **This directory contains no code**, and the command the unit
runs — `gateclerk agent run` — arrives in card **P2-07b** (the `agent` subcommand group on
`gateclerk.cli`). The template references it on purpose; until P2-07b merges, a rendered unit
fails at `ExecStart` with "command not found". Nothing here imports anything.

Tests: `tests/test_deploy_templates.py` parses the unit's directives, parses the plist with
`plistlib`, renders both for a couple of sites, and scans every byte here for secret shapes
and for addresses outside the RFC 5737 documentation ranges. A green run means the committed
bytes are what §2d requires.

---

## The two rules everything else follows

1. **References, never values.** A device credential is named by
   `gateclerk.config.credential_ref(site, host)` → `gateclerk-<site>-<host>`. That NAME appears
   in `LoadCredential=`, in the plist's credential block and in the drop-in. The password
   appears in **none** of them. `gateclerk.config` has no password default and the agent
   refuses to guess one (spec §2d, and `sites.toml.example` says the same).
2. **The push target is a reference too.** `push_target` in `sites.toml` accepts only
   `config.PUSH_TARGET_SCHEMES` — `stub://` (append JSONL to a local file, what tests and a
   dry run use) and `https://`. There is **no default endpoint**: omitted means the pusher
   is off (spec §3 — P3 is out of scope, so nothing here may invent an ingest host).

Device hosts and the site's `iana_tz` are config, in `sites.toml` (`--config`), not in the
unit file. `iana_tz` is required per site and never defaulted — site time is payroll truth.
Every example address in this directory is a TEST-NET address (`192.0.2.0/24`,
`198.51.100.0/24`, `203.0.113.0/24`) precisely so that no real device host can ever be
committed here by accident.

---

## 1. Prepare the host

```
sudo useradd --system --home-dir /var/lib/gateclerk --shell /usr/sbin/nologin gateclerk
sudo install -d -m 0750 -o gateclerk -g gateclerk /var/lib/gateclerk
sudo install -d -m 0770 -o gateclerk -g gateclerk /var/lib/gateclerk/site-a     # <STATE_ROOT>/<SITE>
sudo install -d -m 0755 -o root     -g root     /etc/gateclerk/credentials
uv venv /opt/gateclerk/venv --python 3.12          # the venv whose bin/gateclerk is <EXEC_START>
uv pip install --python /opt/gateclerk/venv/bin/python /path/to/this/checkout
/opt/gateclerk/venv/bin/gateclerk --version
```

Create the site's state dir before the first start: the store layer
(`gateclerk.agent_store.store_events`) takes an already-open sqlite connection, so opening the
store is the caller's job — the CLI that does it is P2-07b, and `ProtectSystem=strict` means
a directory the unit does not have cannot be created by the agent at all. `ReadWritePaths`
opens exactly this one directory.

`/var/lib/gateclerk` is the `<STATE_ROOT>` of the template: the unit's `WorkingDirectory`, and
the parent of the one writable path (`ReadWritePaths=<STATE_ROOT>/<SITE>` — that site's
sqlite store + WAL sidecars, its `park/` dir and its `logs/`). `/etc/gateclerk/credentials` is
where the 0600 credential **source** files live. Keep them out of `/run`: it is tmpfs, so a
credential there is gone at the next reboot and `Restart=always` would restart the unit into
a missing credential forever.

## 2. Render the unit for one site

systemd expands only its own specifiers — here, `%i`, the instance name, which **is** the
site name. The angle-bracket tokens are the operator's substitution:

| Token | Meaning | Example |
|---|---|---|
| `%i` | instance name = site name (systemd expands this) | `site-a` |
| `<SITE>` | the same site name, in paths and credential names | `site-a` |
| `<HOST>` | this site's device host, from `sites.toml` (config, not a secret) | `192.0.2.10` |
| `<STATE_ROOT>` | parent of each site's state dir | `/var/lib/gateclerk` |
| `<CONFIG_PATH>` | the `sites.toml` this unit reads | `/etc/gateclerk/sites.toml` |
| `<EXEC_START>` | the `gateclerk` entry point of the venv | `/opt/gateclerk/venv/bin/gateclerk` |

```
sed -e 's|<SITE>|site-a|g' \
    -e 's|<HOST>|192.0.2.10|g' \
    -e 's|<STATE_ROOT>|/var/lib/gateclerk|g' \
    -e 's|<CONFIG_PATH>|/etc/gateclerk/sites.toml|g' \
    -e 's|<EXEC_START>|/opt/gateclerk/venv/bin/gateclerk|g' \
    deploy/gateclerk-agent@.service | sudo tee /etc/systemd/system/gateclerk-agent@site-a.service
sudo systemctl daemon-reload
```

Install the template file itself too (`sudo cp deploy/gateclerk-agent@.service
/etc/systemd/system/`) if you want `systemctl enable gateclerk-agent@<site>` to work for
future sites — the per-site rendered copy is what runs, and the drop-in in step 4 is what
provisions it.

Never install it with a token still in it: a wrong path is a silently dead agent, and a
dead agent means silent punch loss (the device log ring rolls over). Note also that
`gateclerk agent run` itself arrives in card **P2-07b** — until that merges, a correctly
rendered unit still fails at `ExecStart` with "command not found", which is expected and is
not a template bug. `systemd-run` proves a render before anything is installed:

```
systemd-run --wait --property "ReadWritePaths=/var/lib/gateclerk/site-a" \
  /opt/gateclerk/venv/bin/gateclerk agent run --site site-a \
  --config /etc/gateclerk/sites.toml --state-root /var/lib/gateclerk/site-a --once
```

(`--once` is a smoke-test affordance and must **not** go in the unit: one tick then exit,
under `Restart=always`, becomes a five-second poll of a door controller — the hammering
spec §1.9 forbids. `RestartSec=5` is for crashes, not for a happy exit.)

### Where the state files actually come from

Both flags on that line belong to `gateclerk agent`, which is P2-07b. The one that is worth
understanding **today**, because it decides whether the unit's hardening works, is the store
location:

- `sites.toml`'s `db_path` defaults to `./gateclerk-<site>.sqlite3`
  (`config.DEFAULT_DB_PATH_TEMPLATE`) — a **relative** path, so it resolves against the
  process's working directory. That is why the unit sets `WorkingDirectory=<STATE_ROOT>` and
  why `ReadWritePaths` is `<STATE_ROOT>/<SITE>`: the agent must be writing inside the one
  path the mount policy opens, or `ProtectSystem=strict` turns the first write into a failure
  (`Restart=always` then loops it, which is the loud outcome we want).
- `--state-root <STATE_ROOT>/<SITE>` is the P2-07b flag that says the same thing explicitly
  and also relocates the `park/` dir (P2-05's policy creates it itself —
  `agent_alert.AgentAlertPolicy._write_park` does `mkdir(parents=True, exist_ok=True)`, which
  works because the site's state dir is the one writable path). On Linux there is no log dir
  at all: `StandardOutput=journal` sends the alerts to journald. The launchd example is the
  case that wants `<state dir>/logs/`, because it redirects to files there.

Either way, exactly one directory is writable and it is named in the unit file. There is no
search path, no fallback location and no default endpoint anywhere in this install.

## 3. Provision the credential, then prove it

One root-owned 0600 file per device, named with the `gateclerk-<site>-<host>` reference:

```
sudo install -m 0600 -o root -g root /path/to/secret \
     /etc/gateclerk/credentials/gateclerk-site-a-192.0.2.10.txt
```

Two ways to attach it. Pick one and record which in your site's runbook:

**a. Per-site drop-in (survives an update of the template — recommended).** The template is
shared by every site on the box and the credential name embeds the device host, which
systemd cannot know (`%i` is the site; the host lives in `sites.toml`, a file systemd never
reads). So the per-site delta goes in a drop-in — the directory is always
`/etc/systemd/system/gateclerk-agent@<site>.service.d/` and the file
`10-credentials.conf` (the `10-` prefix just fixes the order if you add more):

```
sudo install -d -m 0755 -o root -g root \
  /etc/systemd/system/gateclerk-agent@site-a.service.d
sudo tee /etc/systemd/system/gateclerk-agent@site-a.service.d/10-credentials.conf <<'EOF'
[Service]
LoadCredential=gateclerk-site-a-192.0.2.10:/etc/gateclerk/credentials/gateclerk-site-a-192.0.2.10.txt
EOF
sudo systemctl daemon-reload
```

**b. Render it in.** The template carries the commented line
`LoadCredential=gateclerk-<SITE>-<HOST>:/etc/gateclerk/credentials/gateclerk-<SITE>-<HOST>.txt`;
rendering `<SITE>` and `<HOST>` (step 2) makes it real. One device per render; for a second
controller on the same site, use a drop-in.

Prove the secret reached the service without printing it:

```
sudo systemctl restart gateclerk-agent@site-a
journalctl -u gateclerk-agent@site-a -n 5          # a missing credential is a loud start failure
sudo systemctl show gateclerk-agent@site-a -p LoadCredential   # names + source paths, never values
sudo systemd-run --wait --property LoadCredential=demo:/etc/hostname \
     /bin/sh -c 'cd "$CREDENTIALS_DIRECTORY" && ls -l && wc -c demo'
```

`systemd-creds` (v250+) is the same proof from *inside* a service context — it lists the
names and sizes of `$CREDENTIALS_DIRECTORY` and never a value:

```
sudo systemd-run --wait --property LoadCredential=demo:/etc/hostname /usr/bin/systemd-creds list
```

The agent reads `$CREDENTIALS_DIRECTORY/gateclerk-<site>-<host>` and feeds it to the
resolver's **flag rung**, so precedence stays flag > env > keychain (`gateclerk.config`) and no
ISAPI code changes. `LoadCredential=` never puts the value in the environment. Where no
credentials directory exists — a dev laptop, a launchd job, a hand-run test — the env rung
(`GATECLERK_192_0_2_10_PASSWORD`, i.e. `config.env_var_names(host)[1]`, every
non-alphanumeric host character folded to `_`) and the macOS Keychain rung (service
`gateclerk-hikvision`, account = the host) keep working unchanged.

## 4. Start it

```
sudo systemctl enable --now gateclerk-agent@site-a
systemctl status gateclerk-agent@site-a
journalctl -u gateclerk-agent@site-a -f
```

The unit is the supervisor: `Restart=always` + `RestartSec=5`, `TimeoutStopSec=30` on
`SIGTERM` (a tick is at most one chunk-walk and the checkpoint advances only over completed
chunks, so a kill between chunks is already safe). What a restart must *not* undo is the
park: after a terminal 401 the device is parked and the park lives on disk at
`/var/lib/gateclerk/<site>/park`, outside the sqlite store, so an unacked park still blocks
every tick after systemd brings the process back until `gateclerk agent ack`. That is why the
park is on disk and not in memory.

Two sites on one box are two instances — `gateclerk-agent@site-a` and `gateclerk-agent@site-b` —
with separate stores, parks and credentials and no shared writable path. One codebase, N
configs (spec §1.5).

## 5. What "installed correctly" looks like

```
systemctl show gateclerk-agent@site-a -p Restart,RestartSec,ExecMainStartTimestamp
sudo systemd-analyze security gateclerk-agent@site-a      # the hardening set is no-new-privileges,
                                                        # ProtectSystem=strict, one ReadWritePaths
journalctl -u gateclerk-agent@site-a -n 50                  # one line per page: level, site label,
                                                        # kind, serial — never a host, never a payload
```

Then the four canary numbers the rollout gate counts (`docs/P2-SITE-AGENT.md` §5 / the
P2-06 `/healthz` vocabulary): checkpoint advancing, `auth_terminal_failures` 0,
`tz_offset_mismatch` warning-count 0, `site_labeled_windows` 0.

## 6. launchd (macOS dev box) and Windows

**launchd — EXAMPLE, not a product.** Render `gateclerk-agent.plist`'s tokens
(`SITE_LABEL`, `STATE_DIR`, `CONFIG_PATH`, `PYTHON_BIN`, plus one credential-reference line
per device between the `gateclerk-credential-refs` markers), save it as
`~/Library/LaunchAgents/com.gateclerk.agent.<site>.plist`, then `launchctl load` it.
`KeepAlive` + `ThrottleInterval` are launchd's stand-ins for `Restart=always` +
`RestartSec=5`. launchd has **no** `LoadCredential=` equivalent, and `EnvironmentVariables`
in a plist is plaintext to the whole user session — so the plist carries only names, and the
value comes from the Keychain rung (preferred on a dev box) or a 0600 file that exports the
env rung. Nothing in this repo installs or supervises a launchd job.

**Windows.** Same command line as the unit, started by Task Scheduler at boot under a
dedicated service account, with the store under a directory only that account can write:

```
gateclerk agent run --site site-c --config C:\gateclerk\sites.toml --state-root D:\gateclerk\site-c
```

Windows has no systemd credentials: use the env rung from a secret the account can read, or
the keychain rung's Windows equivalent if you have one — the resolver reads flag > env >
keychain either way (`gateclerk.config`). The read-only device invariant is the same on every
OS: the agent only GETs and issues the two stateless searches registered in
`gateclerk.endpoints`; any device write stays the owner's.

## 7. Rotating a credential

Rotate on the device, write the new value into the 0600 source file, then
`sudo systemctl restart gateclerk-agent@<site>`. If the site is already parked (terminal 401),
restart is not enough — the park is deliberate and survives restarts, so ack it explicitly
(`gateclerk agent ack --site <site>`, P2-07b) after the new credential is in place. Do not
work around the park: a lockout-counting device is the reason it exists
(`docs/OBSERVED.md` "lockout accounting").

## 8. Uninstall

```
sudo systemctl disable --now gateclerk-agent@site-a
sudo rm -f /etc/systemd/system/gateclerk-agent@site-a.service
sudo rm -rf /etc/systemd/system/gateclerk-agent@site-a.service.d
sudo rm -f /etc/gateclerk/credentials/gateclerk-site-a-*.txt
sudo systemctl daemon-reload
```

Leave `/var/lib/gateclerk/site-a` alone until you have exported the sqlite store: it is the
only copy of the punches the pusher had not delivered, and the store is keep-everything by
policy (spec §2b — a watermark alert, never a purge).
