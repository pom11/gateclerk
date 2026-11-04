# Changelog

All notable changes to `gateclerk` are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html). Release
tags are `vX.Y.Z` and every release builds a deterministic source tarball,
target zipapps (`macos-arm64`, `linux-x86_64`, `linux-arm64`), and `SHA256SUMS`
via `scripts/build_dist.py` and verifies them with `scripts/smoke_artifact.py`.

## [0.1.0] - 2026-11-04

First public release under the `gateclerk` name (MIT license).

### Added

- Read-only Hikvision ISAPI connector (`gateclerk device info|time|capabilities`,
  `gateclerk users list`, `gateclerk events --since ... --until ...`) with
  site-timezone wall-clock resolution, DST fold/gap flags, and `401` lockout
  circuit protection.
- Platform-symmetric credential resolver (`gateclerk creds test|explain|set|get|remove`):
  CLI flag > `GATECLERK_*` env > macOS Keychain (`gateclerk-hikvision`) >
  `0600` `~/.config/gateclerk/credentials.json` file store.
- Crash-safe SQLite site agent (`gateclerk agent run|ack|deadletter list|remove`)
  with per-sink delivery queues, exponential retry backoff, 24 h dead-lettering,
  and named sinks (`gateclerk sink list|add|remove|test`: `https`, rotating `csv`,
  rotating `jsonl`).
- Interactive first-site setup (`gateclerk init`), one-command offline walkthrough
  (`gateclerk demo demo` + `gateclerk demo device serve|urls`), one-screen health
  (`gateclerk status`), exhaustive self-check (`gateclerk doctor`), inventory &
  streaming scan exports (`gateclerk export config|scans`), and `launchd`/`systemd`
  service unit generator (`gateclerk service install|uninstall|logs`).
- Terminal-to-terminal enrollment migration pipeline
  (`gateclerk migrate probe|export|diff|apply|undo`).
- Multi-OS release builder (`scripts/build_dist.py`), artifact smoke verifier
  (`scripts/smoke_artifact.py`), `.github/workflows/release.yml`, and Homebrew
  formula template (`packaging/Formula/gateclerk.rb.tmpl`).
