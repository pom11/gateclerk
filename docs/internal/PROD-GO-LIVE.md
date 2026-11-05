# PROD GO-LIVE — fresh Linux install and device cutover

Status: **read-only plan. Nothing in this document has been executed by the card that
wrote it, and nothing here is a live action by itself.** Production is a **fresh install**
on a new Linux box; the current Mac stays the development machine. The only artifact of
this card is this file.

Every line that would write to a live host, restart/boot out a unit, enroll a person on a
device, flip the public release, or touch BC data is tagged **[OPERATOR-ONLY]**.

The one safety rule that outranks everything else: **two agents must never poll the same
device at the same time.** The cutover is a **device swap plus a host swap**, not two agents
racing on one controller: production polls the **newer** unit installed at SITE-A, while the
Mac's `com.gateclerk.agent.site-a` polls the **old** unit, a different device. The real
overlap risk is on the Mac: its live `sites.toml` has a `site-b` block whose host is the
newer device. No launchd unit runs `site-b` today, but a manual `gateclerk agent run --site
site-b` would poll the new device while production does. §9 removes or disables that block
before production starts, then uses the different-device fact to keep a working scanner at
the door for as long as possible.

## 1. Install method per OS

### 1a. Linux native — the primary path for this box

One site = one systemd unit = one SQLite store = one push target
(`deploy/gateclerk-agent@.service:4-8`). The venv, service account, state root and
credential directory come straight from the deployment runbook:

```bash
sudo useradd --system --home-dir /var/lib/gateclerk --shell /usr/sbin/nologin gateclerk
sudo install -d -m 0750 -o gateclerk -g gateclerk /var/lib/gateclerk
sudo install -d -m 0770 -o gateclerk -g gateclerk /var/lib/gateclerk/site-a
sudo install -d -m 0755 -o root     -g root     /etc/gateclerk/credentials
uv venv /opt/gateclerk/venv --python 3.12
uv pip install --python /opt/gateclerk/venv/bin/python /path/to/this/checkout
/opt/gateclerk/venv/bin/gateclerk --version
```

Source: `deploy/README.md:51-57`. The state directory must exist before first start:
the store layer takes an already-open SQLite connection, and `ProtectSystem=strict` plus
`ReadWritePaths=<STATE_ROOT>/<SITE>` means the unit cannot create it itself
(`deploy/README.md:60-71`, `deploy/gateclerk-agent@.service:122-130`).

Render the unit for `site-a`, replacing every angle-bracket token with a real value; do
not install a unit that still contains a placeholder:

```bash
sed -e 's|<SITE>|site-a|g' \
    -e 's|<HOST>|192.0.2.20|g' \
    -e 's|<STATE_ROOT>|/var/lib/gateclerk|g' \
    -e 's|<CONFIG_PATH>|/etc/gateclerk/sites.toml|g' \
    -e 's|<EXEC_START>|/opt/gateclerk/venv/bin/gateclerk|g' \
    deploy/gateclerk-agent@.service | sudo tee /etc/systemd/system/gateclerk-agent@site-a.service
sudo systemctl daemon-reload
```

Source: `deploy/README.md:87-95`. `192.0.2.20` is a TEST-NET placeholder; the real host is
the new device IP, still an open question (§11). The rendered unit's `ExecStart` is exactly
`agent run --site %i --config <CONFIG_PATH> --state-root <STATE_ROOT>/<SITE>`
(`deploy/gateclerk-agent@.service:60`), and it deliberately has no `--once`
(`deploy/gateclerk-agent@.service:56-58`).

Do **not** run the usual `--once` smoke test yet. `--once` is one real poll of the door
controller (`src/gateclerk/agent_cmds.py:90-118`); on this cutover it counts as starting an
agent and is allowed only after §9(a) preconditions are complete (BC row, enrollment,
Mac `site-b` block removed) and as part of §9(b). It does not need the Mac unit stopped,
because the two agents poll different devices.

### 1b. Alpine / musl container — sibling card, not this doc

Production is most likely Alpine in a Docker container (§11). The image is owned by the
**CONTAINER-ALPINE** sibling card, now merged (PR #93): `deploy/Dockerfile`,
`deploy/compose.yaml`, `deploy/CONTAINER.md` and `deploy/container_healthcheck.sh` are the
container install (the compose project is named `gateclerk`, so the running container is
`gateclerk-site-a-1`). Inside a container there is no systemd unit and no
`LoadCredential=`; use the environment rungs in §2 and §3. Keep the same
one-site/one-store/one-push-target rule. The container equivalents in §9 and §10 were
re-checked against the merged `deploy/compose.yaml` and `deploy/CONTAINER.md`.

### 1c. Homebrew — operator-gated by the public flip

`brew install pom11/tap/gateclerk` is documented as available **once the release tap is
published** (`README.md:28-29`). The formula in this repo is a template rendered into a tap
by `scripts/build_dist.py` (`packaging/Formula/gateclerk.rb.tmpl:5-7`), so the public flip
is what turns that command into a working install. **[OPERATOR-ONLY]** for the flip itself.

What depends on the flip: only `brew install`. What does **not** depend on it:

- git clone + `uv venv` + `uv pip install` from the checkout (`deploy/README.md:55-56`);
- `pipx install .` / `pip install .` from a checkout or wheel (`README.md:31-34`);
- the systemd unit in `deploy/` (§1a);
- the container image in `deploy/` (PR #93, §1b).

The operator can therefore go live without flipping anything.

## 2. Device credentials on the new machine

There is **no keychain on Linux/Alpine**, so never assume `KeychainReader` answers. The
resolver's order is **flag > env > platform store > credential file**
(`src/gateclerk/config.py:838-840`). On a systemd host, `LoadCredential=` feeds the flag
rung without putting the value in the environment (`deploy/README.md:190-196`).

The credential reference is `gateclerk-<site>-<host>` (`src/gateclerk/config.py:576-589`).
For this cutover with the placeholder host that is:

```text
gateclerk-site-a-192.0.2.20
```

**Preferred: systemd credential file.** One root-owned `0600` source file, named with the
reference, plus a per-site drop-in so a later update of the template does not erase it:

```bash
sudo install -m 0600 -o root -g root /path/to/secret \
     /etc/gateclerk/credentials/gateclerk-site-a-192.0.2.20.txt

sudo install -d -m 0755 -o root -g root \
  /etc/systemd/system/gateclerk-agent@site-a.service.d
sudo tee /etc/systemd/system/gateclerk-agent@site-a.service.d/10-credentials.conf <<'EOF'
[Service]
LoadCredential=gateclerk-site-a-192.0.2.20:/etc/gateclerk/credentials/gateclerk-site-a-192.0.2.20.txt
EOF
sudo systemctl daemon-reload
```

**[OPERATOR-ONLY]** — this writes the secret to the production host. Sources:
`deploy/README.md:142-146`, `deploy/README.md:158-166`,
`deploy/gateclerk-agent@.service:84`. The agent reads
`$CREDENTIALS_DIRECTORY/gateclerk-site-a-192.0.2.20` and trims the trailing newline
(`src/gateclerk/agent_cli.py:1346-1370`); a missing file is a loud config error, never a
fall-through to a keychain that does not exist.

**Alternative: env rung.** `GATECLERK_<HOST>_PASSWORD`, with every non-alphanumeric host
character folded to `_` (`src/gateclerk/config.py:688-713`). For the placeholder:

```text
GATECLERK_192_0_2_20_PASSWORD
```

If the host changes, the variable name changes with it. The env rung is also what a
container deployment uses. Do not put the value in the unit file; unit files are
world-readable (`deploy/gateclerk-agent@.service:95-100`).

**Last resort: credential file rung.** `GATECLERK_CREDENTIALS_FILE` points at an
owner-only JSON file (`0600` required); the default is
`~/.config/gateclerk/credentials.json` (`src/gateclerk/credentials.py:90-100`). This is the
CREDSTORE-LINUX file rung and works without a keychain. Refs only, never values, in any
tracked config.

Whichever rung is chosen, prove it **without printing the secret**:

```bash
sudo systemctl show gateclerk-agent@site-a -p LoadCredential   # names + paths, never values
```

Source: `deploy/README.md:178`.

## 3. Ingest token for BC push

BC keeps the same ingest endpoint and the same Secret Manager name; the token is
supplied by the operator and its **value never appears in this doc, in `sites.toml`, or in
a unit file** (`sites.toml.example:64-80`).

On Linux the token comes from the environment rung (or a credentials file), not a keychain:

```text
GATECLERK_INGEST_TOKEN_SITE-A
```

Source: `src/gateclerk/agent_push.py:1034-1040`. The macOS keychain equivalent, for the dev
box only, is service `gateclerk-ingest-site-a` (`src/gateclerk/agent_push.py:1043-1045`).
The token is resolved lazily on first send and cached; the site claim in
`X-GateClerk-Site` only confirms what the token already determines
(`src/gateclerk/agent_push.py:1076-1090`).

On a systemd host, put the variable in a `0600` `EnvironmentFile=` drop-in rather than in
the unit:

```bash
sudo install -m 0600 -o root -g root /path/to/ingest.env /etc/gateclerk/ingest.env
sudo install -d -m 0755 -o root -g root \
  /etc/systemd/system/gateclerk-agent@site-a.service.d
sudo tee /etc/systemd/system/gateclerk-agent@site-a.service.d/20-ingest-env.conf <<'EOF'
[Service]
EnvironmentFile=/etc/gateclerk/ingest.env
EOF
sudo systemctl daemon-reload
```

**[OPERATOR-ONLY]** — writes the token to the production host. The file contains exactly
one line, `GATECLERK_INGEST_TOKEN_SITE-A=<value>`, and is never committed or quoted.

## 4. State directory and a fresh store

`--state-root /var/lib/gateclerk/site-a` is the site's one writable directory; the store,
`park/` and `health/` all live under it (`src/gateclerk/agent_cli.py:1155-1164`). With the
default relative `db_path`, the SQLite file is:

```text
/var/lib/gateclerk/site-a/gateclerk-site-a.sqlite3
```

Sources: `src/gateclerk/config.py:119` (`./gateclerk-{site}.sqlite3`),
`src/gateclerk/agent_cli.py:1130-1152` (state-root resolution),
`deploy/gateclerk-agent@.service:52-60` (`WorkingDirectory` and `ExecStart`).

A fresh empty store has no checkpoint row, so the **first tick reads only one
cadence + overlap of history** — by default about 10 minutes (300 s + 300 s). That is the
deliberate cold-start floor; it keeps a fresh install from flooding BC with old device
events (`src/gateclerk/agent_loop.py:91-96`, `src/gateclerk/agent_loop.py:986-995`).

A full-history backfill to BC is **not available in this repository**. `gateclerk events`
is a read-only device query: it fetches the window and prints it to stdout; it never writes
to the local store, never enqueues a `push_queue` row and never sends to BC
(`src/gateclerk/events_cmds.py:189-193`, `src/gateclerk/events_cmds.py:269-271`). There is
no push or enqueue path in `events_cmds.py`.

The command is therefore useful for inspection only, not as a BC backfill:

```bash
/opt/gateclerk/venv/bin/gateclerk events \
  --site site-a --config /etc/gateclerk/sites.toml \
  --since 2026-01-01 --until 2026-11-05
```

It requires an explicit bounded window (`src/gateclerk/events_cmds.py:80-99`) and is a
separate read, not the agent loop's cold-start path (`src/gateclerk/agent_loop.py:91-96`).
If the operator needs pre-cutover device history in BC, that needs a separate backfill
mechanism; none of the commands in this doc delivers old device events to BC (§11).

## 5. `sites.toml` worked example for the new device

`[[site]]` keys are the `SiteConfig` fields in `src/gateclerk/config.py:203-247`. The file
is local-only and gitignored; this example uses TEST-NET placeholders and no secret values.
Replace the host with the new device IP when the operator supplies it (§11).

```toml
[[site]]
name = "site-a"
host = "192.0.2.20"                 # placeholder: the new device IP (open question)
port = 80                           # ISAPI is HTTP:80 (see sites.toml.example:20)
iana_tz = "Europe/Bucharest"        # REQUIRED by the agent surface (config.py:203-218)
# device_tz = "Europe/Bucharest"    # enable ONLY if the new unit repeats the known
                                    # site-a wall-clock quirk; otherwise leave it out
isapi_user = "admin"
keychain_service = "gateclerk-hikvision"   # unused on Linux, harmless
timeout_s = 30.0
page_delay_ms = 100

cadence_s = 300                     # defaults; shown for clarity (config.py:230-233)
overlap_s = 300
db_path = "./gateclerk-site-a.sqlite3"
db_warn_bytes = 2147483648
push_target = "https://INGEST-HOST/gateclerk_ingest"
push_dead_letter_after_s = 86400
device_code = "BC-DEVICE-CODE"      # set to the code registered in §8; omit if equal to serial
```

Sources for the keys and defaults: `src/gateclerk/config.py:213-247`,
`src/gateclerk/config.py:115-119`, `sites.toml.example:20-88`.
`iana_tz` is non-negotiable on the agent surface; a block without it is refused
(`docs/internal/P2-SITE-AGENT.md:137-155`). `device_tz` is the declared zone of the
device's wall digits and is authoritative over a known-bad claimed offset
(`src/gateclerk/config.py:219-226`); do not copy it unless the new unit has the same
accepted quirk. `device_code` is the BC device code when it differs from the serial
(`src/gateclerk/config.py:242-245`).

## 6. Alerts to micro-notify

The alert sink is still **one stderr line** first. Under the systemd unit that line lands
in journald next to systemd's own output (`src/gateclerk/agent_alert.py:156-171`,
`deploy/gateclerk-agent@.service:151-153`, `deploy/README.md:118-130`); in the container it
is the compose service log (`deploy/README.md:201-203`). That line is the evidence of
record. micro-notify is an **additional** page, never a replacement for it.

A site may declare ONE alert route in the same typed-sink vocabulary as the push sinks:

```toml
[[site.sink]]
name = "alerts"
type = "mnotify"          # alert-only: SiteConfig.event_sinks excludes it
to = "gateclerk-alerts@<TENANT-DOMAIN>"   # operator mailbox; placeholder
# timeout_s = 300         # optional override; the mail budget default
```

`to` is the single recipient field and `timeout_s` defaults to the 300 s mail budget. A
`mnotify` block with no recipient or a non-positive timeout is refused
(`src/gateclerk/sinks.py:174-180`, `src/gateclerk/sinks.py:216-223`). `agent_cli` picks
the site's one alert route (`src/gateclerk/agent_cli.py:1179-1194`) and `gateclerk sink
add` writes the block (`src/gateclerk/sink_cli.py:351-365`, `src/gateclerk/sink_cli.py:453`).

The journald-first law is absolute. The sink writes the same stderr line immediately on
the calling thread, BEFORE it touches the queue; only then does one daemon worker attempt
delivery (`src/gateclerk/agent_mnotify.py:175-206`,
`src/gateclerk/agent_mnotify.py:237-246`). A missing binary, timeout, non-zero exit or
unexpected runner failure only adds a warning; the line is never written twice, and
alerting never blocks or raises into the polling loop
(`src/gateclerk/agent_mnotify.py:263-286`, `src/gateclerk/agent_cli.py:1179-1194`).

The exec timeout is **300 s** for mail (`MNOTIFY_TIMEOUT_S`,
`src/gateclerk/agent_mnotify.py:56-57`). A timeout is an **unknown outcome**, not a clean
failure: mnotify may already have delivered, so the sink warns and never resends
(`src/gateclerk/agent_mnotify.py:299-311`).

Exit-code policy is micro-notify's `docs/SERVICE-INTEGRATION.md` §1-§3 at commit
`afeab10`: branch on the process exit code; 0 sent, 2 usage/config, 3 guardrail, 4 auth,
5 remote, 6 daily cap, 130 interrupted; any other code is a crash/infrastructure failure.
Invoke with an argv array and `--body-file`: alert text is untrusted input and is never
shell-interpolated (§1). Exit 5 is never retried blindly because a lost response may
already have delivered (§3).

Citation note: #94 merged the alert sink and #93 the container install doc at commit
`341aba0`; PR #92's later merge removed those paths from `main`. Open a
`src/gateclerk/...` or `deploy/CONTAINER.md` reference with `git show 341aba0:<path>`
until that revert is repaired.

### mnotify decisions

Answers to micro-notify `docs/SERVICE-INTEGRATION.md` §10 at `afeab10`. Operator-owned
items stay placeholders; no real mailbox, token, host or tenant value is recorded here.

- **Q1 sender and allowlist.** Sender is a dedicated mailbox
  `gateclerk-alerts@<TENANT-DOMAIN>` (`[mail] sender`). The `[allow]` list contains exact
  recipient addresses only — NO domain wildcard — and includes at least the operator's
  alert mailbox `[OPERATOR-ONLY value]`.
- **Q2 recipient caps.** `limits.max_recipients = 5` explicit (the default 20 is too
  loose). cc and bcc count toward the cap. No Teams DMs.
- **Q3 channels.** MAIL-ONLY at go-live; no `[teams.targets]`. Teams is later, deliberate,
  and the operator provisions the `teams__<target>` webhook secret.
- **Q4 timeout.** Exec timeout 300 s (contract §4 budget). Timeout = unknown outcome →
  warn with the alert id, never resend. The sink never blocks the polling loop (single
  worker thread).
- **Q5 exit 5.** NEVER auto-retry. Dedupe key = alert id `(site, device serial, kind,
  park key, timestamp)`, logged next to mnotify's mail `requestId`. Resend only
  operator-manually after checking the mnotify audit JSONL `[OPERATOR-ONLY]`.
- **Q6 image.** SAME IMAGE (contract §5 default): mnotify inside the gateclerk image at
  `/opt/mnotify/bin`, no sidecar (matches the #93 container install doc at `341aba0:deploy/CONTAINER.md`).
- **Q7 secrets.** Operator provisions on the prod host: `/etc/mnotify/config.toml` mode
  0600; one file per account under `/run/secrets/mnotify` (root-owned 0444; read-only
  mount accepted). `MICRO_NOTIFY_CONFIG` / `MICRO_NOTIFY_SECRETS=file` /
  `MICRO_NOTIFY_SECRETS_DIR` are PATHS, never values. Go-live is APP MODE
  (certificate/client-secret), so the read-only secrets mount suffices. Delegated mode is
  NOT chosen; if ever used its secrets dir must be WRITABLE (micro-notify
  `docs/DELEGATED-SETUP.md`, container section, `afeab10`). Rotation = operator re-runs
  admin setup.
- **Q8 concurrency — HARD RULE.** mnotify's daily counter (`state_dir/counter.json`) is an
  UNLOCKED read-modify-write. Any mnotify processes sharing a `state_dir` must NEVER send
  concurrently: serialise the WHOLE invocation (check + send + record), e.g. one `flock`
  around the exec. Locking only the counter write is too late (micro-notify
  `docs/SERVICE-INTEGRATION.md` §6 at `afeab10`). Production satisfies this structurally:
  one agent per site plus one dedicated per-site mnotify volume/`state_dir`
  (`341aba0:deploy/CONTAINER.md`), and #94's sink serialises in-process (single worker + lock,
  `src/gateclerk/agent_mnotify.py:168-169`). Any future deployment that shares a
  `state_dir` must use the same `flock` around the exec.
- **Q9 audit.** `/var/lib/mnotify/audit/sent.jsonl` on the per-site mnotify volume
  (already in `341aba0:deploy/CONTAINER.md`); metadata-only, no bodies. The subject carries site
  + device serial and no PII, so verbatim recording is acceptable. Rotation/shipping =
  operator, alongside the volume backup `[OPERATOR-ONLY]`.
- **Q10 daily cap.** `limits.daily_max` stays at the default 200 (expected volume is far
  below the cap). Exit 6 = no retry today (UTC rollover); the journald evidence line
  remains.

## 7. Network reach from the production box

The production box reaches devices **by IP**; there is no mDNS or discovery assumption
(§11). The device port is the config `port`, default **80/TCP**, and ISAPI is plain HTTP;
8000 is Hikvision's SDK port, not used here (`src/gateclerk/config.py:96`,
`sites.toml.example:20`). The agent's device surface is a closed registry of GETs plus the
named stateless search POSTs; no PUT/DELETE/PATCH exists (`src/gateclerk/endpoints.py:1-22`,
`src/gateclerk/endpoints.py:85-95`).

Run the **read-only doctor** first. `--probe` performs the same two GETs as the read path —
`deviceInfo` and `System/time` — and writes nothing, restarts nothing
(`src/gateclerk/doctor_cmds.py:39-69`):

```bash
/opt/gateclerk/venv/bin/gateclerk doctor \
  --config /etc/gateclerk/sites.toml \
  --site site-a \
  --state-root /var/lib/gateclerk/site-a \
  --probe
```

This is a probe, not an agent: it does not poll, store, or advance a checkpoint. It is safe
to run while the Mac unit is still serving. The production **unit** starts only in §9(b),
after the §9(a) preconditions (BC row, enrollment, Mac `site-b` block removed).

## 8. BC side — all operator-only live data

**Everything in this section is [OPERATOR-ONLY] live BC data.** This card does not connect
to BC, does not run a job, and does not write a row.

### 8a. Register the new device under SITE-A

Use the **device list page, page 70604** in the BC client (objects live in the BC
repository under its legacy-named module directory — not vendored in this repo). Its
source table is the device table **70602**, with the fields that matter here:

- `Code` — the BC device code (device-table fields, table 70602, lines 14-18);
- `Site Code` — `SITE-A` (lines 19-24);
- `Serial No.` — the new unit's serial (lines 25-29).

**[OPERATOR-ONLY]** Create the row **before the production agent's first push**. The ingest
needs the new device row on its side before it can accept a scan for that device. Record the
`Code` for `sites.toml`'s `device_code` if it differs from the serial
(`src/gateclerk/config.py:242-245`).

### 8b. Relink device users

The roster/link work is on **page 70610** (device-user list), whose link action opens
**page 70613** (managed link dialog) — BC client objects in the same legacy-named module
directory. **[OPERATOR-ONLY]** — these are live
BC link rows. The new unit has nobody linked to it yet.

### 8c. Enrollment on the new unit

Nobody is enrolled on the new unit. **[OPERATOR-ONLY]** for the first real enrollment write.
The planned method is the **USERS-IMPORT-XLSX** card; the first real write to the device is
operator-gated and is **not** part of this doc.
This plan does not enroll anybody and does not write to a terminal; the product's only
opted-in write path is separately gated (`README.md:16-19`).

### 8d. The old unit and its already-pushed scans

Scans already pushed from the old unit are normal, permanent BC rows. The ingest's
`InsertDeviceScan` only inserts; on a replay it finds the existing
`(Device Code, Fingerprint)` row and exits `false` without writing
(BC codeunit **70601**, the scan-ingest manager, lines 75-83; the unique-key contract is
documented at lines 22-28 of the same object). Nothing in that
path deletes the old rows.

The fate of the old hardware/config is an **open question** for the operator (§11): keep it
as a site-a backup, repurpose it, or return it.

## 9. Switch-over order — device swap plus host swap

Production polls the **newer** unit at SITE-A. The Mac's `com.gateclerk.agent.site-a` polls
the **old** unit, a different device. **Never let two agents poll one device**, but do not
confuse that rule with this cutover: the old and new units can both run while the swap is
staged. The one same-device risk is the Mac's `site-b` block (top of this doc), and step
(a)(3) removes it.

The order below keeps a working scanner at the door until the new one is proven; the old
unit is stopped and unplugged only after the new unit has completed a push.

**(a) Do the preconditions while the old unit still works.**

1. **[OPERATOR-ONLY] Register the new device row in BC before its first push** (§8a).
   Without the row the ingest cannot accept scans for the new device.
2. **[OPERATOR-ONLY] Enroll the people who scan at the door on the new unit** (§8c).
   Nobody can scan on the new unit before enrollment, so doing this first is what lets the
   new unit take over without a no-scanner gap.
3. **[OPERATOR-ONLY] Remove or disable the `site-b` block on the Mac.** The Mac's live
   `sites.toml` has a `site-b` block pointing at the newer device. There is no `site-b`
   launchd unit today, but a manual `gateclerk agent run --site site-b` would be a second
   poller on the new device. Delete the block or comment it out; confirm the file has only
   the `site-a` block before continuing.
4. **Finish the production install and config, but do NOT start it.** Unit/compose service
   rendered, state dir/volume created, credential and ingest token provisioned. Do not run
   `agent run --once` yet: that is already a device poll
   (`src/gateclerk/agent_cmds.py:90-118`).

**(b) [OPERATOR-ONLY] Start production and watch the first ok tick.** Starting production
while the Mac still polls the old unit is safe: they are different devices. Do not walk away
until a tick has completed and pushed:

Systemd:

```bash
sudo systemctl enable --now gateclerk-agent@site-a
journalctl -u gateclerk-agent@site-a -f
/opt/gateclerk/venv/bin/gateclerk status \
  --config /etc/gateclerk/sites.toml --state-root /var/lib/gateclerk/site-a --site site-a
```

Container (container install, deploy/compose.yaml; verified against the merged file):

```bash
docker compose -f deploy/compose.yaml up -d site-a
docker compose -f deploy/compose.yaml logs -f site-a
docker inspect --format '{{.State.Health.Status}}' gateclerk-site-a-1
docker compose -f deploy/compose.yaml exec site-a gateclerk status \
  --config /etc/gateclerk/sites.toml --state-root /var/lib/gateclerk/site-a --site site-a
```

Source for the systemd start: `deploy/README.md:198-203`. `status` reads the store and
cached health only; it never contacts the device or the ingest
(`src/gateclerk/status_cli.py:10-26`). In the container, the healthcheck reports `healthy`
only after a completed pass (`deploy/CONTAINER.md` in the sibling card; re-check).

**(c) [OPERATOR-ONLY] Give the old unit one final ok tick, then stop the Mac unit.** Each
`agent run` tick polls, stores and then pushes at the end of the same cycle
(`src/gateclerk/agent_cli.py:690-695`, `src/gateclerk/agent_cli.py:700-720`), so wait for
one successful tick before stopping the Mac. That tick pushes the last scans the old unit
has already read. Then boot the Mac unit out; do not just close a terminal:

```bash
launchctl bootout gui/$(id -u)/com.gateclerk.agent.site-a
```

The label comes from the example plist's `com.gateclerk.agent.SITE_LABEL`
(`deploy/gateclerk-agent.plist:49`), instantiated as `site-a`.

**(d) Verify the Mac's queue is drained before unplugging the old unit.** Plain read-only
SQLite query (use the Mac state dir in place of the placeholder):

```bash
sqlite3 -readonly <MAC_STATE_DIR>/gateclerk-site-a.sqlite3 \
  "SELECT (SELECT COUNT(*) FROM push_queue) AS pending,
          (SELECT COUNT(*) FROM dead_letter) AS dead_letter;"
```

`push_queue` is the send buffer and `dead_letter` is the never-sent pile
(`src/gateclerk/agent_db.py:158-165`, `src/gateclerk/agent_db.py:195-214`). A successful
send **deletes** the queue row; it is not kept with a `sent` status
(`src/gateclerk/agent_push.py:704-727`). A row that exhausts
`push_dead_letter_after_s` is inserted into `dead_letter` and deleted from `push_queue` in
one transaction (`src/gateclerk/agent_push.py:733-782`). So `pending = 0` really means no
queued send remains, but it does **not** prove delivery: dead-lettered rows also leave the
queue and never reach BC unless replayed. **Require `pending = 0` and `dead_letter = 0`**
before unplugging. If either is non-zero, do not remove the old unit: re-bootstrap the Mac
unit and let it drain, and resolve/replay the dead letters (a dead letter is a punch BC has
not received).

**(e) [OPERATOR-ONLY] Remove the old unit.** Only after (b) shows production polling and
pushing and (d) shows both counters zero, take the old unit out of service and unplug/move
it. From that point no one may scan on the old unit: its poller is stopped and a later scan
would never be pushed. If production later needs to be rolled back, §10 applies.

**Which order avoids the gap:** new unit registered, enrolled and proven pushing → old unit
final tick, stop and drain → unplug old. The old unit remains the working scanner until the
new one is ready. If the two units cannot both be powered/networked at the door at the same
time, the physical swap has an unavoidable no-scanner interval; that is an operator
decision, listed in §11.

### Why overlap on one device is forbidden

- **The real way it can happen here is the Mac's `site-b` block** pointing at the new
  device; (a)(3) removes it. A manual run of that block while production polls the new unit
  is the two-pollers-one-device case.
- **BC writes are idempotent.** `InsertDeviceScan` keys on the UNIQUE
  `(Device Code, Fingerprint)` pair; a replay finds the existing row and exits `false`, so
  the same event pushed twice lands exactly once
  (BC codeunit 70601, lines 75-83).
- **The agents are not idempotent as pollers.** Each keeps its own checkpoint, circuit and
  ring arithmetic, and two pollers double the request load against the device's
  ~190-request nonce use-cap and the shared event ring
  (`src/gateclerk/config.py:104-109`, `src/gateclerk/agent_loop.py:388-423`,
  `src/gateclerk/isapi_transport.py:327-358`). That is why overlap is forbidden even though
  BC dedupes.
- **The Mac's already-pushed scans stay.** They are normal BC rows; the fingerprint dedupe
  makes a later re-push harmless (BC codeunit 70601, lines 22-28 and 81-83).

## 10. Rollback

If production is unhealthy after cutover, reverse the host move. **[OPERATOR-ONLY]** for
both service actions.

**1. Stop production first — never run both pollers on one device.**

Systemd:

```bash
sudo systemctl disable --now gateclerk-agent@site-a
```

Container (container install, deploy/compose.yaml; verified against the merged file):

```bash
# `stop` preserves the container and its named volume. Do not use `down -v`.
docker compose -f deploy/compose.yaml stop site-a
docker compose -f deploy/compose.yaml ps
docker inspect --format '{{.State.Health.Status}}' gateclerk-site-a-1
```

**2. Bring the Mac unit back.**

```bash
launchctl bootstrap gui/$(id -u) ~/Library/LaunchAgents/com.gateclerk.agent.site-a.plist
```

The bootstrap form is the load command the service tool prints on macOS
(`src/gateclerk/service_cmds.py:17-22`); the example plist documents the same
`launchctl`/`LaunchAgents` layout (`deploy/gateclerk-agent.plist:37-42`).

**3. Prove the Mac resumed** by reading its state, not by guessing. `<MAC_PYTHON_BIN>` is
the plist's `PYTHON_BIN` token — the python of the venv gateclerk was installed into on the
Mac (`deploy/gateclerk-agent.plist:32`, `deploy/gateclerk-agent.plist:59`). It is **not**
the Linux `/opt/gateclerk/venv` path:

```bash
<MAC_PYTHON_BIN> -m gateclerk.cli status \
  --config <MAC_CONFIG> --state-root <MAC_STATE_DIR> --site site-a

sqlite3 -readonly <MAC_STATE_DIR>/gateclerk-site-a.sqlite3 \
  "SELECT device_serial, checkpoint_serial, checkpoint_time, updated_at FROM checkpoint;"
```

`status` is read-only and never touches the device (`src/gateclerk/status_cli.py:10-26`); the
`checkpoint` row is the per-device progress record (`src/gateclerk/agent_db.py:134-144`).
A `checkpoint_serial` that advances between two reads means the Mac poller is running again.

**What rollback means once the old unit has been unplugged or moved.** Bootstrapping the Mac
only restores a poller for the old device; it does not put that device back at the door or
back on the network. If the old unit is unplugged, moved or returned, rollback is not a
working scanner: the operator must restore the old hardware to its configured host, or fix
forward on production. The Mac's checkpoint is also frozen at the old device's last poll; if
that device's event ring rolled while it was disconnected, the missing events cannot be
recovered by pushing again. Treat rollback as available only while the old unit is still
powered and reachable at its configured address; after §9(e) it is a hardware-restore
decision.

## 11. Open questions

### Answered by the operator (recorded here)

- Production OS is **Linux**, most likely **Alpine in a Docker container** (lightweight).
  The **CONTAINER-ALPINE** card owns the image; this doc does not define it.
- The production machine reaches devices **by IP**. There are no mDNS or discovery
  assumptions; hosts come from `sites.toml` (`src/gateclerk/config.py:213-215`).

### Still open — operator owes, do not invent

- **New device IP.** Every `192.0.2.20` above is a placeholder; the real host belongs in
  the local `sites.toml` only.
- **Fate of the old unit** (the current dev-bench device): keep as a site-a backup,
  repurpose, or return it. Its already-pushed BC scans are permanent either way (§8d).
- **Enrollment timing and operator.** Who performs the first real enrollment write, and
  when; the USERS-IMPORT-XLSX card owns the method.
- **Excel column mapping** for the user import; owned by USERS-IMPORT-XLSX.
- **Door-scanner gap.** If both units cannot be powered/networked at the door at the same
  time, choose the physical swap window and accept that no scanner works during it. The
  preferred order in §9 avoids the gap by proving the new unit before removing the old one.
- **Pre-cutover BC history.** Whether any old-device history must be backfilled into BC, and
  by what mechanism. `gateclerk events` only reads and prints; this repository contains no
  backfill-to-BC tool (§4).
