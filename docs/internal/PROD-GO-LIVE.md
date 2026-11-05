# PROD GO-LIVE — fresh Linux install and device cutover

Status: **read-only plan. Nothing in this document has been executed by the card that
wrote it, and nothing here is a live action by itself.** Production is a **fresh install**
on a new Linux box; the current Mac stays the development machine. The only artifact of
this card is this file.

Every line that would write to a live host, restart/boot out a unit, enroll a person on a
device, flip the public release, or touch BC data is tagged **[OPERATOR-ONLY]**.

The one safety rule that outranks everything else: **two agents must never poll the same
device at the same time.** The Mac's `com.gateclerk.agent.site-a` pushes to the live ingest
today, and the production unit would poll the same door controller. The cutover order in
§9 exists to keep exactly one poller alive at every moment.

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
agent and is allowed only after the Mac unit is stopped (§9).

### 1b. Alpine / musl container — sibling card, not this doc

Production is most likely Alpine in a Docker container (§11). The image is owned by the
**CONTAINER-ALPINE** sibling card; this repository has no Dockerfile or image target today.
Inside a container there is no systemd unit and no `LoadCredential=`; use the environment
rungs in §2 and §3. Keep the same one-site/one-store/one-push-target rule. The cutover
order in §9 is unchanged.

### 1c. Homebrew — operator-gated by the public flip

`brew install pom11/tap/gateclerk` is documented as available **once the release tap is
published** (`README.md:28-29`). The formula in this repo is a template rendered into a tap
by `scripts/build_dist.py` (`packaging/Formula/gateclerk.rb.tmpl:5-7`), so the public flip
is what turns that command into a working install. **[OPERATOR-ONLY]** for the flip itself.

What depends on the flip: only `brew install`. What does **not** depend on it:

- git clone + `uv venv` + `uv pip install` from the checkout (`deploy/README.md:55-56`);
- `pipx install .` / `pip install .` from a checkout or wheel (`README.md:31-34`);
- the systemd unit in `deploy/` (§1a);
- the future container image (CONTAINER-ALPINE).

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

BC keeps the same Gateclerk ingest endpoint and the same Secret Manager name; the token is
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

A full-history backfill is **not** the unit's job. It is the operator-invoked CLI:

```bash
/opt/gateclerk/venv/bin/gateclerk events \
  --site site-a --config /etc/gateclerk/sites.toml \
  --since 2026-01-01 --until 2026-11-05
```

`events` requires an explicit bounded window (`src/gateclerk/events_cmds.py:80-99`) and is
a separate read, not the agent loop's cold-start path (`src/gateclerk/agent_loop.py:91-96`).

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

Today the alert sink is **one stderr line**. Under the systemd unit that line lands in
journald next to systemd's own output (`src/gateclerk/agent_alert.py:156-171`,
`deploy/gateclerk-agent@.service:151-153`, `deploy/README.md:118-130`).

**Until the ALERT-SINK-MNOTIFY card lands, production alerts = journald log only.** This
doc does not configure micro-notify and does not implement the alert transport. Watch the
log with:

```bash
journalctl -u gateclerk-agent@site-a -f
journalctl -u gateclerk-agent@site-a -n 50
```

Source: `deploy/README.md:201-203`.

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
to run while the Mac unit is still serving, but the production **unit** may not start until
§9 step (b) is done.

## 8. BC side — all operator-only live data

**Everything in this section is [OPERATOR-ONLY] live BC data.** This card does not connect
to BC, does not run a job, and does not write a row.

### 8a. Register the new device under SITE-A

Use the **Attendance Devices** list page, **page 70604**
(`Gateclerk/Pages/AttendanceDevicesEfsPOM.Page.al:2`; BC source, not vendored in this repo). Its
source table is `AttendanceDeviceEfsPOM` (table 70602), with the fields that matter here:

- `Code` — the BC device code (`Gateclerk/Tables/AttendanceDeviceEfsPOM.Table.al:14-18`);
- `Site Code` — `SITE-A` (`Gateclerk/Tables/AttendanceDeviceEfsPOM.Table.al:19-24`);
- `Serial No.` — the new unit's serial (`Gateclerk/Tables/AttendanceDeviceEfsPOM.Table.al:25-29`).

**[OPERATOR-ONLY]** Create the row. Record the `Code` for `sites.toml`'s `device_code` if it
differs from the serial (`src/gateclerk/config.py:242-245`).

### 8b. Relink device users

The roster/link work is on **page 70610**, `AttendanceDeviceUsersEfsPOM`
(`Gateclerk/Pages/AttendanceDeviceUsersEfsPOM.Page.al:10`), whose link action opens **page
70613**, `AttendanceLinkDeviceUserEfsPOM`
(`Gateclerk/Pages/AttendanceDeviceUsersEfsPOM.Page.al:66-71`,
`Gateclerk/Pages/AttendanceLinkDeviceUserEfsPOM.Page.al:10`). **[OPERATOR-ONLY]** — these are live
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
(`Gateclerk/Codeunits/AttendanceScanMgtEfsPOM.Codeunit.al:75-83`; the unique-key contract is
documented at `Gateclerk/Codeunits/AttendanceScanMgtEfsPOM.Codeunit.al:22-28`). Nothing in that
path deletes the old rows.

The fate of the old hardware/config is an **open question** for the operator (§11): keep it
as a site-a backup, repurpose it, or return it.

## 9. Switch-over order — the hard safety rule

The Mac's `com.gateclerk.agent.site-a` pushes to LIVE today. **Do not let two agents poll
one device.** Follow this order exactly.

**(a) Finish the production install and config, but do NOT start it.** Unit rendered,
state dir created, credential and ingest token provisioned. Do not run `agent run --once`
yet: that is already a device poll (`src/gateclerk/agent_cmds.py:90-118`).

**(b) [OPERATOR-ONLY] Stop the Mac unit.** Boot it out; do not just close a terminal:

```bash
launchctl bootout gui/$(id -u)/com.gateclerk.agent.site-a
```

The label comes from the example plist's `com.gateclerk.agent.SITE_LABEL`
(`deploy/gateclerk-agent.plist:49`), instantiated as `site-a`; the card names this unit
explicitly.

**(c) Verify the Mac's `push_queue` is drained.** This is a plain read-only SQLite query
against the Mac's store (use the Mac state dir in place of the placeholder):

```bash
sqlite3 -readonly <MAC_STATE_DIR>/gateclerk-site-a.sqlite3 \
  "SELECT COUNT(*) AS pending FROM push_queue;"
```

`push_queue` is the send buffer (`src/gateclerk/agent_db.py:155-191`). **0 = drained =
clean stop.** If the count is not 0, do not cut over: re-bootstrap the Mac unit and let it
drain, or resolve the outage first. A non-zero queue is punches that exist only in that
store until a later push.

**(d) [OPERATOR-ONLY] Start the production unit:**

```bash
sudo systemctl enable --now gateclerk-agent@site-a
```

Source: `deploy/README.md:198-203`.

**(e) Watch the first ok tick.** Do not walk away until a tick has completed:

```bash
journalctl -u gateclerk-agent@site-a -f
/opt/gateclerk/venv/bin/gateclerk status \
  --config /etc/gateclerk/sites.toml --state-root /var/lib/gateclerk/site-a --site site-a
```

`status` reads the store and cached health only; it never contacts the device or the ingest
(`src/gateclerk/status_cli.py:10-26`).

### What happens if they overlap anyway

- **BC writes are idempotent.** `InsertDeviceScan` keys on the UNIQUE
  `(Device Code, Fingerprint)` pair; a replay finds the existing row and exits `false`, so
  the same event pushed twice lands exactly once
  (`Gateclerk/Codeunits/AttendanceScanMgtEfsPOM.Codeunit.al:75-83`).
- **The agents are not idempotent as pollers.** Each keeps its own checkpoint, circuit and
  ring arithmetic, and two pollers double the request load against the device's
  ~190-request nonce use-cap and the shared event ring
  (`src/gateclerk/config.py:104-109`, `src/gateclerk/agent_loop.py:388-423`,
  `src/gateclerk/isapi_transport.py:327-358`). That is why overlap is forbidden even though
  BC dedupes.
- **The Mac's already-pushed scans stay.** They are normal BC rows; the fingerprint dedupe
  makes a later re-push harmless (`Gateclerk/Codeunits/AttendanceScanMgtEfsPOM.Codeunit.al:22-28`,
  `Gateclerk/Codeunits/AttendanceScanMgtEfsPOM.Codeunit.al:81-83`).

## 10. Rollback

If the production unit is unhealthy after cutover, reverse §9 in order. **[OPERATOR-ONLY]**
for both service actions.

```bash
# 1. Stop production first — never run both agents.
sudo systemctl disable --now gateclerk-agent@site-a

# 2. Bring the Mac unit back.
launchctl bootstrap gui/$(id -u) ~/Library/LaunchAgents/com.gateclerk.agent.site-a.plist
```

The bootstrap form is the load command the service tool prints on macOS
(`src/gateclerk/service_cmds.py:17-22`); the example plist documents the same
`launchctl`/`LaunchAgents` layout (`deploy/gateclerk-agent.plist:37-42`).

Prove the Mac resumed by reading its state, not by guessing:

```bash
/opt/gateclerk/venv/bin/gateclerk status \
  --config <MAC_CONFIG> --state-root <MAC_STATE_DIR> --site site-a

sqlite3 -readonly <MAC_STATE_DIR>/gateclerk-site-a.sqlite3 \
  "SELECT device_serial, checkpoint_serial, checkpoint_time, updated_at FROM checkpoint;"
```

`status` is read-only and never touches the device (`src/gateclerk/status_cli.py:10-26`); the
`checkpoint` row is the per-device progress record (`src/gateclerk/agent_db.py:134-144`).
A `checkpoint_serial` that advances between two reads means the Mac poller is running again.

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
