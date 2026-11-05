# Decision Note & Spec: `--state-root` Resolution (`t_559d6e85`)

## Decision: Option (c) — `--state-root` resolves to whatever `agent run` uses for the site

**Named choice**: **Option (c)** ("whatever `agent run` would use for this site, resolved by the same code path" in `agent_cli.resolve_db_path`, preferring a per-site subdirectory `<state_root>/<site.name>` when present).

### Why Option (c) over (a) and (b)
- `service_cli.default_state_dir` (`src/gateclerk/service_cli.py:479-497`) renders `<base>/<site>` and sets both `--state-root` and `WorkingDirectory` to that per-site directory in systemd (`src/gateclerk/service_cli.py:612-635`) and launchd (`src/gateclerk/service_cli.py:785-797`).
- When `agent run` executes inside the unit (`src/gateclerk/agent_cli.py:1130`), `resolve_db_path(site, state_root)` (`src/gateclerk/agent_cli.py:1048-1058`) joins `site.db_path_resolved` (`./gateclerk-<site>.sqlite3`, `src/gateclerk/config.py:315-323`) directly onto `state_root` (Option b).
- However, when an operator runs `gateclerk doctor --state-root ~/gateclerk --site site-a` (passing the parent root that contains per-site dirs `<state_root>/<site>/` as laid out on the host or by `service install`), `doctor_cli._check_db_section` (`src/gateclerk/doctor_cli.py:480-495`) checks `<state_root>/gateclerk-site-a.sqlite3` instead of `<state_root>/site-a/gateclerk-site-a.sqlite3`, emitting a false `"no store yet"` warning on a healthy running agent.
- Pure **(a)** (always appending `<site>` to `--state-root`) would break existing unit files that already pass `--state-root <base>/<site>` (`src/gateclerk/service_cli.py:631`, `795`), doubling the path to `<base>/<site>/<site>/`.
- Pure **(b)** (current behavior) forces operators to pass `--state-root <root>/<site>` even on multi-site commands (`doctor` and `status` without `--site`), where a single `--state-root` parent must resolve each site's store.
- **Option (c)** unifies both: `agent_cli.resolve_db_path(site, state_root)` resolves relative `db_path` under `<state_root>/<site.name>` when `Path(state_root).name != site.name` and `(Path(state_root) / site.name).is_dir()`, and otherwise under `Path(state_root)`. Because `resolve_state_root` (`src/gateclerk/agent_cli.py:1061-1070`) returns `Path(resolve_db_path(site, state_root)).parent`, all state artifacts (`park/`, `health/agent.json`, `push-ledger.jsonl`) resolve to the exact same directory.

### Consistency Across `ack`, `deadletter`, `sink`, and `status`
1. **`agent run`, `agent ack`, `agent deadletter list|remove`, and `sink list|remove`**:
   All call `agent_cli.resolve_db_path(site, state_root)` and `agent_cli.resolve_state_root(site, state_root)` (`src/gateclerk/agent_cmds.py:178, 196, 236, 289-290` and `src/gateclerk/sink_cmds.py:174`). Changing `resolve_db_path` once keeps `run`, `ack`, `deadletter`, `sink`, and `doctor` (`src/gateclerk/doctor_cli.py:487`) 100% consistent with zero caller edits.
2. **`gateclerk status`**:
   `status_cli.collect_site_status` (`src/gateclerk/status_cli.py:244-248`) already derives `db_path = Path(agent_cli.resolve_db_path(site, state_root))` and `state_dir = agent_cli.resolve_state_root(site, state_root)` before passing `db_path` into `status_cli._open_store(db_path)` (`src/gateclerk/status_cli.py:351-374`). Thus `status` automatically resolves the store, `health/agent.json` (`status_cli.py:246`), `agent.pid` (`status_cli.py:432`), and `status/device-probe.json` (`status_cli.py:633`) from the same per-site directory. (Follow-up may optionally share a read-only sqlite opener between `status_cli._open_store` and `doctor_cli._check_db_section`.)

---

## Smallest Change Spec (for follow-up backend card)

### 1. Function to Change
- **`src/gateclerk/agent_cli.py::resolve_db_path`** (lines `1048-1058`):
  ```python
  def resolve_db_path(site: SiteConfig, state_root: Path | str | None) -> str:
      db_path = Path(site.db_path_resolved)
      if state_root is not None and not db_path.is_absolute():
          root = Path(state_root)
          per_site = root / site.name
          if root.name != site.name and per_site.is_dir():
              root = per_site
          return str(root / db_path)
      return str(db_path)
  ```
- **No changes needed** in `resolve_state_root` (`src/gateclerk/agent_cli.py:1061-1070`), `doctor_cli._check_db_section` (`src/gateclerk/doctor_cli.py:480-495`), `agent_cmds.py`, or `status_cli.py::collect_site_status` (`src/gateclerk/status_cli.py:224-248`) / `_open_store` (`src/gateclerk/status_cli.py:351-374`), as they all delegate path resolution to `resolve_db_path`.

### 2. Required Test
- Add **`tests/test_cli_doctor.py::test_doctor_resolves_per_site_store_under_service_install_layout`**:
  1. Compute per-site dir via `service_cli.default_state_dir("launchd", "site-a", home=tmp_path)` (`src/gateclerk/service_cli.py:479`) or `<state_root>/site-a`, and seed the store there via `agent_cli.build_site_agent(site, state_root=per_site_dir)` (matching the unit `service_cli.plist_payload` / `render_unit` writes at `src/gateclerk/service_cli.py:631, 795`).
  2. Run `doctor_cli.run_doctor(config_path=cfg_file, site="site-a", state_root=per_site_dir.parent)` (and ` state_root=per_site_dir`) plus `status_cli.collect_site_status`, `agent ack`, and `agent deadletter list` with `state_root=per_site_dir.parent`.
  3. Assert the `db` row status is `"pass"` with `"integrity=ok"` (not `"warn"` / `"no store yet"`), and `status`, `ack`, and `deadletter` resolve the same `<state_root>/site-a/gateclerk-site-a.sqlite3` store.
