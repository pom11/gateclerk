# DOCTOR-REAL-DEVICE (t_a063374a) — findings and fix

## Root cause (the TypeError)

`doctor_cli.default_device_prober` — the real device probe the tests always replace — was
written against an API that does not exist. #79 fixed only the *import*; the call was
still fictional. Every one of these is a separate defect, all invisible to the suite
because it monkeypatches this exact name (`tests/test_cli_doctor.py` replaces
`doctor_cli.default_device_prober`, `doctor_cli.default_tls_prober` and
`doctor_cli.sink_cli.default_keychain_probe` — the doubles are precisely why the real
path never ran):

1. `IsapiClient(site.host, port=site.port, credentials=provider, timeout_s=...)` — the real
   signature (`isapi_transport.py:145`) is
   `IsapiClient(base_url, username, password, *, connect_timeout, read_timeout, ...)`. No
   `port`, no `credentials`, no `timeout_s` → the TypeError at `doctor_cli.py:283`.
2. `client.get_xml("/ISAPI/System/time")` — `get_xml` does not exist, and the client takes
   **registry names**, not URL paths (`get_response("system_time")`, `endpoints.py:109`).
3. `device_identity(client)` — `capabilities.device_identity` takes a parsed **body dict**,
   not a client (`capabilities.py:529`); `pipeline.read_device_identity(client)` is the
   client-shaped helper (`pipeline.py:331`).
4. `ident.model` / `ident.serial_no` — the real return is a 3-tuple
   `(serial, firmware, model)`; the attribute access would have died even after 1–3.
5. `trust_env`: the module docstring promised "Honors local-LAN `NO_PROXY`
   (`trust_env=False`)" and httpx defaults to `True`. On a shell with a proxy exported the
   real probe would CONNECT through the proxy and die, printing "device unreachable" about
   a healthy box — the exact failure `demo_walkthrough.py:748` documents. There was no seam
   on `IsapiClient` to honour that promise at all.

## The class: every real `default_*` path the suite replaces with a double

Swept `doctor_cli` / `status_cli` / `init_cli` / `service_cli` / `export_cli`, plus the
shared client factories the read commands build through. `verdict` = is the *real* body
correct, and is it now proven by at least one test that runs it unpatched?

| seam the tests replace | real path | verdict |
|---|---|---|
| `doctor_cli.default_device_prober` | `IsapiClient` ctor + device reads | **BROKEN — fixed here** (5 defects above) |
| `doctor_cli.default_tls_prober` | `ssl.create_default_context` + handshake | correct; now proven by a real pinned-cert handshake + a negative verification arm |
| `doctor_cli.sink_cli.default_keychain_probe` | `security find-generic-password` (no `-w`) | correct; proven for both `None` (no binary) and exit-code→bool |
| `sink_cli.default_keychain_secret` (sink probe) | `KeychainReader().read(...)` | correct signature |
| `init_cli.keychain_item_exists` (probe of the credential rung) | same `security` argv | correct (argv pinned by existing suite) |
| `init_cli.probe_device` → `IsapiClient` | `f"http://{host}:{port}", user, password` | **correct ctor shape, never proven against a live socket** — now proven (demo box) |
| `status_cli._pid_alive` | `os.kill(pid, 0)` | correct |
| `status_cli._open_store` / `_read_json_object` / `_mtime_age` | sqlite read-only / file reads | correct |
| `service_cli.default_config_path` / `default_state_dir` | `HOME` / `XDG_STATE_HOME` reads | correct; proven for the real env read (suite always injects `home=`) |
| `service_cli` install/uninstall/start argv builders | `launchctl` / `systemctl` argv | builders correct; module never invokes a manager (its own "no subprocess" law) |
| `export_cli._stdout_is_tty` | `sys.stdout.isatty` | correct |
| `cli_shared._client_for` (client factory for EVERY read command) | `f"http://{host}:{port}"` positional | ctor correct; now also carries the `trust_env` seam |
| `agent_loop` default client (agent path, outside the 5 named commands) | same positional ctor | correct; unchanged |

`export_cli`/`export_cmds` have no OS/wire `default_*` factory left — the only seam is
`_stdout_is_tty`, and the export device reads go through `cli_shared._migrate_client` →
`_client_for`, which is the factory now covered by the shared-prober arm.

## Fix

* `doctor_cli.default_device_prober` now speaks the sanctioned surface every read command
  uses: `pipeline.read_device_identity(client)` + `pipeline.device_time_reading(client)`
  (both read-only GETs through the registry), `site.target()` +
  `cfg.resolve_credentials(target, env=env)` for the ladder, and
  `IsapiClient(f"http://{host}:{port}", user, password, read_timeout=…, trust_env=False)`.
  Exactly two GETs; nothing written; no service restart; the summary carries model + serial
  only. Resolving the credential *before* the socket opens keeps a missing credential a
  `CredentialUnavailable` (config exit 2) instead of surfacing later as an auth 401.
* `IsapiClient` gains a `trust_env: bool = True` parameter (httpx's own), so a caller with a
  LAN-local `NO_PROXY` law can honour it. Default keeps the posture
  `demo_walkthrough.py:748` documents as deliberate, so nothing existing changes.
* `cli_shared` gains `default_device_prober(site, *, env=None, now=None)` — the probe built
  through `_client_for`, i.e. the factory every read command shares. `gateclerk doctor
  --probe` selects it, so the operator (and the offline demo arm) proves the SHARED
  construction rather than a parallel one that can silently drift again. `_client_for`
  gained the pass-through `trust_env` for that caller.

## Real-device run (read-only, mandatory acceptance)

Device address, serial and the ingest host are masked as `[REDACTED-*]`. The two runs below
are the same command with and without `--probe`; the live agent
`com.gateclerk.agent.site-a` was not touched (verified with `launchctl print`: same `pid`
before and after — no bootout, no kickstart, no branch switch in `~/dev/gateclerk`).

```console
$ gateclerk doctor --config ~/gateclerk/sites.toml --state-root ~/gateclerk --site site-a
┏━━━━━━━━━━┳━━━━━━━━━━━━━┳━━━━━━━━┳━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ site     ┃ section     ┃ status ┃ exit_code ┃ detail                                                                                    ┃
┡━━━━━━━━━━╇━━━━━━━━━━━━━╇━━━━━━━━╇━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┩
│ (global) │ runtime     │ pass   │ 0         │ gateclerk=0.1.0 python=3.12.13 platform=Darwin-arm64 no_proxy=local-lan                   │
│ site-a   │ config      │ pass   │ 0         │ host=[REDACTED-LAN-IP]:80 iana_tz=Europe/Bucharest device_code=SITE-A-1                   │
│ site-a   │ credentials │ pass   │ 0         │ device credential ref resolvable via keychain service=gateclerk-hikvision                 │
│          │             │        │           │ account=[REDACTED-LAN-IP]                                                                 │
│ site-a   │ device      │ pass   │ 0         │ reachable (model=[REDACTED-MODEL] serial=[REDACTED-SERIAL]); clock skew -0.9s (within    │
│          │             │        │           │ 120s)                                                                                     │
│ site-a   │ sinks       │ pass   │ 0         │ legacy:https([REDACTED-INGEST-HOST]:443, TLSv1.3 cert verified)                          │
│ site-a   │ db          │ warn   │ 0         │ no store yet at ~/gateclerk/gateclerk-site-a.sqlite3                           │
└──────────┴─────────────┴────────┴───────────┴───────────────────────────────────────────────────────────────────────────────────────────┘
EXIT=0
```

```console
$ gateclerk doctor --config ~/gateclerk/sites.toml --state-root ~/gateclerk --site site-a --probe
# identical table, byte-for-byte (the device row is the same two GETs through the shared
# _client_for factory) — EXIT=0; full table reproduced in the PR body.
```

Before the fix the same command died with
`TypeError: IsapiClient.__init__() got an unexpected keyword argument 'port'`.

The `db` `warn` is honest and pre-existing: the canary's store lives under
`~/gateclerk/site-a/` while `--state-root ~/gateclerk` resolves
`gateclerk-site-a.sqlite3` one level up. Out of scope for this card (the row reports the
path it checked); flagged for a follow-up card rather than silently "fixed" by widening the
lookup.

## Tests

`tests/test_doctor_real_prober.py` (15 arms) — the demo fake device
(`gateclerk.demo_device`, a loopback server) through the **unreplaced** real defaults:

* `default_device_prober` against the live demo box (real `IsapiClient`, real socket, real
  digest handshake), asserting the model/serial read, the skew arithmetic, and — read off
  the box's own request log — that every request was a GET through the read-only registry;
* wrong password → `IsapiAuthError` (exit 3 mapping), unreachable port → `IsapiError`
  (exit 4), missing credential → `CredentialUnavailable` (exit 2): the three failure arms
  the doctor section mapper distinguishes, reached through the real prober;
* `trust_env=False` asserted at the seam (the NO_PROXY law, not inferred from a pass);
* `cli_shared.default_device_prober` proves `_client_for` — the factory every read command
  uses — reads the box correctly;
* the whole `gateclerk doctor --config … --state-root … --site …` command with nothing
  patched but the sanctioned socket seam, and `--probe` routing through the shared factory;
* `init_cli.probe_device` against the live demo box (the other real ctor);
* the real `default_tls_prober`: a verified handshake against the walkthrough's HTTPS mock
  ingest pinned via `SSL_CERT_FILE`, then the **negative** arm — the same handshake must
  raise `CERTIFICATE_VERIFY_FAILED` with the pin removed (a prober that skipped
  verification would print "cert verified" for both);
* `sink_cli.default_keychain_probe` both answers (`None` without the binary, `True` from
  the exit code, and `"-w" not in argv` — metadata lookup, never a value read);
* `service_cli.default_config_path` / `default_state_dir` against the real `HOME`/`XDG`
  (the suite always injects `home=`).

Mutation check (why these arms are not decoration): checking out `main`'s
`doctor_cli.py` over the fix makes **7 of the 15 fail**; the fix restored, 15/15 pass. The
offline suite at large is 2539 passed / 5 skipped (the pre-existing baseline plus these 15),
`ruff check` + `ruff format --check` clean, `tests/test_public_audit.py` green (no LAN
addresses, serials, legacy names or attribution lines in any tracked file — the real values
appear only in this report as `[REDACTED-*]`).
