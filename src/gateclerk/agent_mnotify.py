"""The mnotify alert sink (card ALERT-SINK-MNOTIFY): exec the CLI, never the loop.

Contract (micro-notify ``docs/SERVICE-INTEGRATION.md``, PR #44): exec ``mnotify`` with an
argv ARRAY, put the untrusted alert body in a FILE (``--body-file``), ask for ``--json``,
branch on the EXIT CODE, and never interpolate alert text into a shell string. Exit 0
means Microsoft accepted the request; every non-zero code is a result, not a crash, and
must not be retried here (mnotify already retries its own transient network failures).

The three laws this module exists to keep:

* **The alert path bends, never breaks.** ``MnotifySink.__call__`` never raises. Any
  failure — missing binary, timeout, non-zero exit, unexpected runner exception — writes
  today's stderr line through the injected fallback and emits one warning naming the
  concrete failure. Losing the mail route must never lose the evidence.
* **One writer at a time.** mnotify's daily counter is a read-modify-write with no lock,
  so the whole exec is serialised inside this sink (one ``threading.Lock``). The agent is
  one process/site (§2d); a deployment that runs several senders sharing one mnotify
  ``state_dir`` must give each its own or add an outer lock (contract §6).
* **No credential ever travels through us.** mnotify reads its own config/keychain; this
  module passes only a recipient and a subject on argv, and the alert body in a file.
"""

from __future__ import annotations

import contextlib
import json
import subprocess
import tempfile
import threading
from collections.abc import Callable
from pathlib import Path
from typing import Any

from gateclerk.agent_alert import Alert, default_sink

__all__ = ["MNOTIFY_BINARY", "MNOTIFY_TIMEOUT_S", "MnotifySink", "alert_mail"]

#: The CLI name on PATH (or an absolute path a deployment chooses). mnotify owns its own
#: configuration, so there is no guarded default endpoint here.
MNOTIFY_BINARY = "mnotify"

#: Mail's exec budget from the contract (mnotify can spend ~210 s on Graph retries).
MNOTIFY_TIMEOUT_S = 300.0

_Warn = Callable[[str], None]
_Runner = Callable[..., Any]


def _one_line(text: object) -> str:
    """Warning text is one journald line; error messages may carry newlines."""
    return " ".join(str(text).split())


def _restart_hint(alert: Alert) -> str:
    """Tell a human which unit to restart, and that a restart is operator-only.

    A restart alone does NOT clear a terminal-401 park (the park is disk state, P2-05's
    lockout invariant); the hint therefore names both the unit and the ack command.
    """
    unit = f"gateclerk-agent@{alert.site}"
    return (
        f"operator only: restart {unit} (systemctl restart {unit}) after fixing the "
        "cause; a restart does NOT clear a park — run "
        f"`gateclerk agent ack --site {alert.site}` once the credential is fixed"
    )


def alert_mail(alert: Alert) -> tuple[str, str]:
    """Map one structured ``Alert`` to mnotify's (subject, body) message shape.

    Subject and body carry only safe pieces the alert policy already authored (site,
    serial, kind, park state, note). The body is a file, never argv; the subject is
    recorded verbatim by mnotify's audit, so it stays a short summary with no secret or
    personal detail.
    """
    serial = alert.device_serial or "-"
    subject = f"gateclerk {alert.level.upper()} {alert.kind} site={alert.site} device={serial}"
    body = "\n".join(
        (
            "gateclerk alert",
            f"level: {alert.level}",
            f"kind: {alert.kind}",
            f"site: {alert.site}",
            f"device_serial: {serial}",
            f"device_key: {alert.device_key or '-'}",
            f"park_state: {alert.park_state or '-'}",
            f"at: {alert.at}",
            f"note: {alert.note}",
            f"restart_hint: {_restart_hint(alert)}",
            "",
        )
    )
    return subject, body


class MnotifySink:
    """Callable ``Alert`` sink: one serialised ``mnotify mail send`` + stderr fallback.

    ``runner`` is the test seam (default ``subprocess.run``); ``fallback`` is today's
    journald line (default P2-05's ``default_sink``), and ``warn`` is the agent's single
    warning funnel. Everything is injected so the offline suite can prove all failure
    branches without a binary, a socket or a sleep.
    """

    def __init__(
        self,
        *,
        to: str,
        timeout_s: float = MNOTIFY_TIMEOUT_S,
        binary: str = MNOTIFY_BINARY,
        warn: _Warn | None = None,
        fallback: Callable[[Alert], None] = default_sink,
        runner: _Runner | None = None,
        body_dir: Path | str | None = None,
    ) -> None:
        if not to or not to.strip():
            raise ValueError("mnotify sink needs a non-empty recipient")
        if timeout_s <= 0:
            raise ValueError("mnotify sink timeout_s must be > 0")
        self.to = to
        self.timeout_s = float(timeout_s)
        self.binary = binary
        self._warn = warn if warn is not None else (lambda _text: None)
        self._fallback = fallback
        self._runner = runner if runner is not None else subprocess.run
        self._body_dir = Path(body_dir) if body_dir is not None else None
        # The daily counter has no cross-process lock; serialise the whole invocation.
        self._send_lock = threading.Lock()

    def __call__(self, alert: Alert) -> None:
        """Deliver one alert. NEVER raises: failures fall back to the stderr line."""
        failure: str | None = None
        try:
            with self._send_lock:
                failure = self._deliver(alert)
        except Exception as exc:  # the alert path must not take the agent down
            failure = f"unexpected {type(exc).__name__}: {_one_line(exc)}"
        if failure is None:
            return
        # Even the evidence line failing must not escape into the tick loop.
        with contextlib.suppress(Exception):
            self._fallback(alert)
        serial = alert.device_serial or "-"
        self._safe_warn(
            f"warning: mnotify alert delivery failed for site={alert.site} "
            f"device={serial} kind={alert.kind}: {failure}; wrote the stderr fallback line"
        )

    # --- internals ------------------------------------------------------------------

    def _safe_warn(self, text: str) -> None:
        with contextlib.suppress(Exception):
            self._warn(_one_line(text))

    def _deliver(self, alert: Alert) -> str | None:
        """One exec. Returns the failure text, or None on exit 0 (the contract's verdict)."""
        subject, body = alert_mail(alert)
        try:
            body_path = self._write_body(body)
        except OSError as exc:
            return f"could not write the alert body file ({type(exc).__name__}: {exc})"
        try:
            argv = [
                self.binary,
                "mail",
                "send",
                "--to",
                self.to,
                "--subject",
                subject,
                "--body-file",
                body_path,
                "--json",
            ]
            try:
                proc = self._runner(
                    argv,
                    capture_output=True,
                    text=True,
                    timeout=self.timeout_s,
                    check=False,
                )
            except subprocess.TimeoutExpired:
                return (
                    f"timed out after {self.timeout_s:g}s — the outcome is UNKNOWN "
                    "(mnotify may still have delivered; do not resend blindly)"
                )
            except FileNotFoundError:
                return f"binary {self.binary!r} not found on PATH"
            except OSError as exc:
                return f"could not run {self.binary!r} ({type(exc).__name__}: {exc})"
            document = self._document(getattr(proc, "stdout", "") or "")
            code = int(getattr(proc, "returncode", 1))
            if code == 0:
                # The contract: trust the exit code over the presence of output. A
                # requestId is recorded by mnotify's own audit; gateclerk has no place to
                # store it here, so the subject/site/serial are the correlation key.
                return None
            message = ""
            if isinstance(document, dict):
                message = _one_line(document.get("message") or "")
            detail = f"exit {code}" + (f": {message}" if message else "")
            return f"{detail} — not retried (mnotify's exit-code contract)"
        finally:
            with contextlib.suppress(OSError):
                Path(body_path).unlink(missing_ok=True)

    def _write_body(self, body: str) -> str:
        kwargs: dict[str, Any] = {
            "mode": "w",
            "encoding": "utf-8",
            "prefix": "gateclerk-alert-",
            "suffix": ".md",
            "delete": False,
        }
        if self._body_dir is not None:
            kwargs["dir"] = str(self._body_dir)
        with tempfile.NamedTemporaryFile(**kwargs) as handle:
            handle.write(body)
            handle.flush()
            return handle.name

    @staticmethod
    def _document(stdout: str) -> Any:
        """mnotify's one JSON document, or None when the stream is not JSON."""
        if not stdout.strip():
            return None
        try:
            return json.loads(stdout)
        except (TypeError, ValueError):
            return None
