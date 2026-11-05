# Running the site agent in a container (Alpine)

This is the container install: the alternative to `deploy/gateclerk-agent@.service` for a
Linux host whose production shape is "Alpine in Docker". It runs the same
`gateclerk agent run` command line, keeps the same per-site split, and follows the same
credential rules. Only the supervisor changes: one compose service and one named volume
per site instead of one systemd unit per site.

The files in this directory:

| File | What it is |
|---|---|
| `Dockerfile` | multi-stage Alpine/musl image, non-root uid 10001, no secrets; default target includes `mnotify`, `runtime` target is alert-less |
| `compose.yaml` | site-a only by default; site-b behind the `second-site` profile; env-file credentials, named state volumes, read-only rootfs |
| `container_healthcheck.sh` | Docker `HEALTHCHECK`: reads the agent's health snapshot and checks its AGE |
| `gateclerk.env.example` | the exact credential/notify env-var names, values left as placeholders |
| `mnotify.toml.example` | micro-notify config with `[paths]` on the mnotify volume; no secret values |

Nothing here is a second agent implementation. The image installs the wheel and starts the
shipped CLI; the systemd path remains the fully documented reference install.

## Build

From the repository root (the wheel needs `pyproject.toml`, `README.md` and `src/`):

```
docker build -f deploy/Dockerfile -t gateclerk-agent:local .
```

The default (last) stage is `alerts`: `gateclerk` in `/opt/gateclerk` and `mnotify` in a
**separate** `/opt/mnotify` virtualenv, both on `PATH`. That is micro-notify's "same image"
contract: gateclerk execs `mnotify` as a child process, so the binary must exist in this
container, not in a sidecar. `mnotify` is fetched from the public repository
`pom11/micro-notify` as the GitHub archive tarball for the commit in the
`MICRO_NOTIFY_SHA` build arg (default `f923ffcaa300af62e910049c7bb5c11d6ca3c495`).

The alert-less image is the earlier stage:

```
docker build -f deploy/Dockerfile --target runtime -t gateclerk-agent:no-alerts .
```

`cryptography` publishes musllinux wheels, so neither stage needs `gcc`, `rust` or
`musl-dev` for the current dependency sets. The gateclerk build stage stays disposable so a
future C-extension dependency can be compiled there only, never in `runtime`.

The state directories for the documented sites (`site-a` and `site-b`) are created in the
image. Docker gives an empty named volume the ownership of its image mount point; without
that directory, Docker makes the mount point root-owned and uid 10001 cannot write. Add a
new site at build time with, for example,
`--build-arg GATECLERK_SITES="site-a site-b site-c"`.

## What the image guarantees

- **Non-root.** `USER 10001:10001`; the state directories are owned by that uid. There is
  no login shell.
- **No secrets in the image.** Credentials are mounted or injected at run time. The image
  sets `GATECLERK_CREDENTIALS_FILE=off`, so the optional `~/.config/gateclerk/credentials.json`
  rung cannot silently answer inside a container; the env rung and a mounted credentials
  directory still work exactly as on a host.
- **State on a volume.** `--state-root` is the one writable directory:
  `agent_cli.resolve_state_root` says the sqlite store, `park/` and `health/` all live
  under it. The compose services mount a named volume there.
- **Alerts in the same container.** `mnotify` is on `PATH`; its config and secret files are
  read-only mounts; its `[paths]` audit and state directory is a second writable volume.
- **Time zone.** The image sets `TZ=Europe/Bucharest` and installs Alpine's `tzdata`, so
  `ZoneInfo` and process-local time work on musl. `iana_tz` in `sites.toml` is still the
  payroll truth the agent computes windows from; `TZ` only aligns the process locale.
- **Read-only root.** Compose runs with `read_only: true`; only the state volumes and a
  small `/tmp` tmpfs are writable.

## Configuration

`deploy/compose.yaml` mounts two config files read-only:

- `./sites.toml` at `/etc/gateclerk/sites.toml` — gateclerk sites. Keep it to references and
  documentation-range hosts:

```toml
[[site]]
name = "site-a"
host = "192.0.2.10"
port = 80
iana_tz = "Europe/Bucharest"
isapi_user = "admin"
# Omit push_target for no push, use stub:// for a dry run, or the real HTTPS ingest:
# push_target = "https://INGEST-HOST/gateclerk_ingest"
```

The `iana_tz` key is required on the agent surface. A block without it is refused before
the first request; that rule is unchanged in a container.

- `./mnotify.toml` at `/etc/mnotify/config.toml` — copy `mnotify.toml.example`. Its
  `[paths]` must be absolute and under the writable volume:

```toml
[paths]
audit = "/var/lib/mnotify/audit/sent.jsonl"
state_dir = "/var/lib/mnotify/state"
```

`state_dir` holds `counter.json`, the per-container daily send counter. One mnotify process
per site means one counter per site; two agents sharing a counter would need an external
lock (micro-notify `docs/SERVICE-INTEGRATION.md` §6).

## Credentials without a keychain

Alpine has no macOS Keychain. Use the rungs that already exist — do not add a container-only
credential format:

- **Env-file (the compose default).** `deploy/gateclerk.env.example` names exactly:

  | What | Variable | Code that names it |
  |---|---|---|
  | Device password | `GATECLERK_192_0_2_10_PASSWORD` | `config.env_var_names(host)` (non-alphanumerics become `_`, uppercased) |
  | Ingest bearer | `GATECLERK_INGEST_TOKEN_SITE-A` | `agent_push.ingest_token_env_var(site)` (site uppercased, dash kept) |

  Copy the example to `deploy/gateclerk.env`, fill in the values, and `chmod 0600` it.
  `deploy/compose.yaml` injects it with `env_file:`. The file is a secret: do not commit
  it, and do not put the values in `compose.yaml` or the image.

- **Mounted credentials directory (the systemd `LoadCredential=` shape).** Mount a
  read-only directory and pass `--credentials-dir`; each file is named by
  `config.credential_ref(site, host)` → `gateclerk-<site>-<host>`, and the agent reads it
  through the same resolver as the unit. This is the alternative when the operator prefers
  files to environment variables.

- **mnotify secrets (file backend).** Put one file per account in `./mnotify-secrets` and
  mount it read-only at `/run/secrets/mnotify`. Build sets `MICRO_NOTIFY_SECRETS=file` and
  `MICRO_NOTIFY_SECRETS_DIR=/run/secrets/mnotify`; the config path comes from
  `MICRO_NOTIFY_CONFIG=/etc/mnotify/config.toml`. These are **paths, never values**. The
  file names are micro-notify's account names (`graph.certificate_pem`,
  `graph.certificate_thumbprint`, `graph.client_secret`, and `teams__<target>` for a Teams
  webhook). The directory is read-only: provision the files yourself (root-owned `0444` is
  accepted on a read-only mount), do not expect `mnotify setup` to write into it.

## Run

```
cp deploy/gateclerk.env.example deploy/gateclerk.env
cp deploy/mnotify.toml.example deploy/mnotify.toml
# fill in deploy/gateclerk.env and deploy/mnotify.toml, then:
docker compose -f deploy/compose.yaml up -d --build
```

That starts **site-a only**. A second site is opt-in through the profile, so a host that
serves one site never starts a second agent or polls a device nobody meant:

```
docker compose -f deploy/compose.yaml --profile second-site up -d site-b
```

Each service runs the exact shipped command:

```
gateclerk agent run --site site-a \
  --config /etc/gateclerk/sites.toml \
  --state-root /var/lib/gateclerk/site-a
```

A second site is a second compose service with its own `--site`, `--state-root`, env vars
and named volume. Do not share a state volume between sites: one site is one sqlite store.

## Alerts: mnotify in the same image

gateclerk invokes `mnotify` as a child process (`mnotify mail send ... --json` or
`mnotify teams send ... --json`). The image puts it at `/opt/mnotify/bin/mnotify`, which is
on `PATH`, and compose runs it under the same hardening as the agent:

- `read_only: true` root filesystem;
- `cap_drop: ALL`, `no-new-privileges:true`;
- `USER 10001:10001`;
- config and secrets read-only mounts;
- a writable named volume at `/var/lib/mnotify` for `[paths] audit` and `state_dir`.

`MICRO_NOTIFY_CONFIG`, `MICRO_NOTIFY_SECRETS=file` and `MICRO_NOTIFY_SECRETS_DIR` are set
both in `compose.yaml` and in `gateclerk.env.example`. The volume is per service
(`site-a-mnotify`, `site-b-mnotify`); it survives container replacement and is the only
place mnotify writes.

Alert-less installs use the `runtime` target and simply omit the mnotify mounts; gateclerk
then falls back to its stderr alert sink rather than exec'ing a missing binary. The default
image is the alerts target because production wants both on the same machine.

## Health

`agent run` writes `<state dir>/health/agent.json` after every pass
(`agent_cli.HEALTH_DIR_NAME = "health"`, `HEALTH_FILE_NAME = "agent.json"`, written by
`_write_health` with an atomic replace). The image's `HEALTHCHECK` runs
`gateclerk-healthcheck`, which reads that snapshot from the state volume and fails when:

- the file is missing or unreadable (the agent has not completed a pass yet), or
- its mtime is older than `GATECLERK_HEALTH_MAX_AGE_S` (default `900`, i.e. three default
  `300`-second polls), or
- its `status` is not `ok` or `degraded`.

The age check is deliberate: a live process with a stale snapshot means the poll loop is
not completing passes. Compose sets `GATECLERK_HEALTH_FILE` per service because the path
is under that service's state root.

```
docker inspect --format '{{.State.Health.Status}}' gateclerk-site-a-1
docker exec gateclerk-site-a-1 gateclerk-healthcheck
```

The snapshot carries no credential value and no device host beyond the site label; it is
the P2-06 export format, not a second source of truth.

## State, backup and the systemd path

The store, its WAL sidecars, `park/` and `health/` are all on the site's named volume. The
mnotify audit and counter are on that site's mnotify volume. Back up or move those volumes
the same way you would back up `<STATE_ROOT>/<SITE>` on the systemd host; there is no extra
state in the container layer.

This file does not replace `deploy/README.md`; it documents the alternative install. Keep
the two in sync on the parts they share: the `agent run` flags, the credential reference
naming, and the rule that `sites.toml` carries references, never values.
