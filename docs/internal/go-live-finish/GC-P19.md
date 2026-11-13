# GC-P19 — Production install per site and enrollment import (operator + hardware)

BOARD: gateclerk   DEPENDS ON: GC-P17, GC-P18, GC-P21   GATED: operator   COVERS: G3, operator step 6 / —

## WHY

G3 proves the agent locally; this card is the production install and the first enrollment
on the new terminal. Only the operator and the hardware owner can do it: it writes to a
production host, creates real credentials, and enrolls real people. The plan's section 8
step 6 and `docs/internal/PROD-GO-LIVE.md` are the source. No cluster work, no LIVE BC
write, no device write by the cluster.

## VERIFY

```bash
sed -n '1,120p' docs/internal/PROD-GO-LIVE.md
sed -n '430,520p' docs/internal/PROD-GO-LIVE.md
```

The operator reads both sections before starting. If `GC-P17` (container) or `GC-P18`
(bench) is not DONE, stop; this card is not startable.

## FILES

- `docs/internal/PROD-GO-LIVE.md:21-68` — Linux native install.
- `docs/internal/PROD-GO-LIVE.md:69-78` — Alpine/container install; the production shape.
- `docs/internal/PROD-GO-LIVE.md:96-190` — device credential and ingest token rungs.
- `docs/internal/PROD-GO-LIVE.md:193-265` — state root, fresh store and `sites.toml`.
- `docs/internal/PROD-GO-LIVE.md:268-357` — alerts and micro-notify.
- `docs/internal/PROD-GO-LIVE.md:383-428` — BC device row, relink, enrollment, old-unit scans.
- `docs/internal/PROD-GO-LIVE.md:430-548` — switch-over order and the two-pollers rule.
- `deploy/gateclerk-agent@.service`, `deploy/compose.yaml`, `deploy/CONTAINER.md` — the two
  install shapes.

## CHANGE

No code. Operator checklist. Work one site at a time. Use placeholders in the record; the
real host, credentials and people stay in the operator's local files.

1. **Preconditions.** `GC-P17`, `GC-P18` and `GC-P21` are DONE. The BC device row for the
   new unit exists (`PROD-GO-LIVE.md:388-401`). The Mac `site-b` block is removed or
   disabled so no second poller can reach the new unit (`:430-455`). Record the BC device
   code; it goes in `sites.toml` only if it differs from the serial.
2. **Host and state.** Create the service account, `/var/lib/gateclerk/<site>` and the
   credential directory. Install the wheel or start the container per
   `PROD-GO-LIVE.md:21-78`. Confirm the store path is
   `/var/lib/gateclerk/<site>/gateclerk-<site>.sqlite3`.
3. **Credentials.** Provision the device credential and the ingest token through the
   chosen rung: systemd `LoadCredential=` (`:110-156`), env/`EnvironmentFile`
   (`:158-190`), or the container secret mount. Prove names only; never print a value.
4. **Config.** Write `sites.toml` with the real host, `iana_tz`, `device_code`, state root
   and one push target. No secret value in the file. Keep `device_tz` only if the unit
   repeats the known site-a quirk (`:231-265`).
5. **Alerts.** Install `/etc/mnotify/config.toml` (0600), the per-account secret files
   under `/run/secrets/mnotify` (root-owned 0444), and the per-site mnotify state/audit
   volume. Set `MICRO_NOTIFY_CONFIG`, `MICRO_NOTIFY_SECRETS=file`,
   `MICRO_NOTIFY_SECRETS_DIR` as paths only (`:268-357`).
6. **Doctor.** Run the read-only `doctor --probe` from `PROD-GO-LIVE.md:367-380`. Record
   exit 0 and the device/sink/db rows. Do not start the unit on a failed doctor.
7. **Enrollment.** Enroll the people who scan at the door with `gateclerk users import`
   (the USERS-IMPORT-XLSX path) or `migrate apply`, on the operator's word. This is the
   first real write to the new terminal; the cluster does not do it. Verify a test card
   opens the door before the switch-over.
8. **Start and watch.** Systemd: `systemctl enable --now gateclerk-agent@<site>`; container:
   `docker compose -f deploy/compose.yaml up -d <site>`. Watch `journalctl`/`docker logs`
   and `gateclerk status` until one tick is `ok` and `pushed > 0`. Do not walk away before
   that (`:470-490`).
9. **Drain the old unit.** One final `ok` tick on the Mac, then
   `launchctl bootout gui/$(id -u)/com.gateclerk.agent.<site>`. Require
   `push_queue = 0` and `dead_letter = 0` before unplugging (`:500-530`).
10. **Record.** Evidence file `docs/internal/go-live-finish/evidence/GC-P19-<site>.md`
    with: date, operator initials, install shape, host placeholder, doctor exit, first
    `pushed` count, enrollment count, old-unit drain counts. No secret, no real host, no
    person's name.

What must NOT change:

- Never run two agents on one device (`PROD-GO-LIVE.md:531-548`).
- No LIVE BC publish, no production deploy by the cluster; this is operator-only.
- No credential value, serial, host or employee name in the repo.
- Rollback stays `PROD-GO-LIVE.md:549-600`; do not improvise.

## TESTS

No automated test. The evidence file is the proof. The operator may attach redacted
`doctor -o json` and `status -o json` output; strip hosts, serials, names and credentials.

## GATE

```bash
uv run --frozen pytest -q
```

The gate is a formality for this docs card; the real gate is the operator's step 6 and
step 8 evidence. GATED: operator. No cluster work.

## ACCEPT

- [ ] One site installed with the documented shape (systemd or container).
- [ ] Device credential and ingest token resolve without printing a value.
- [ ] `doctor --probe` exits 0 before the unit starts.
- [ ] Enrollment is done and a test card opens the door.
- [ ] First production tick is `ok` with `pushed > 0`.
- [ ] Old unit is stopped only after `pending = 0` and `dead_letter = 0`.
- [ ] Evidence file is committed with placeholders only.

## OUT

The cluster, BC LIVE writes, the sandbox tenant, other sites, and the old unit's hardware
fate (operator decision).

## HANDOFF

GATED: operator. No branch, no PR from the cluster.

DONE: evidence path, site placeholder, date, initials.
LEFT: the step that stopped and why.
