"""The mnotify alert sink (card ALERT-SINK-MNOTIFY): exec the CLI, never the loop.

Contract (micro-notify ``docs/SERVICE-INTEGRATION.md``, PR #44): exec ``mnotify`` with an
argv ARRAY, put the untrusted alert body in a FILE (``--body-file``), ask for ``--json``,
branch on the EXIT CODE, and never interpolate alert text into a shell string. Exit 0
means Microsoft accepted the request; every non-zero code is a result, not a crash, and
must not be retried here (mnotify already retries its own transient network failures).

The three laws this module exists to keep:

* **The alert path bends, never breaks.** ``MnotifySink.__call__`` never raises. It writes
  today's stderr line through the injected fallback IMMEDIATELY, on the calling thread,
  then hands the mail to one daemon worker thread over a small bounded queue. A missing
  binary, timeout, non-zero exit or unexpected runner exception only produces one warning;
  the evidence line is never written twice. Losing the mail route must never lose the
  evidence, and a mail outage must never stall the polling loop.
* **One writer at a time.** mnotify's daily counter is a read-modify-write with no lock,
  so every exec is serialised through the sink's single worker thread. The agent is one
  process/site (§2d); a deployment that runs several senders sharing one mnotify
  ``state_dir`` must give each its own or add an outer lock (contract §6).
* **Exit is bounded.** ``close()`` queues a stop marker behind the alerts already accepted
  and joins the worker for a bounded time; if a page is still in flight it warns and lets
  the daemon thread die with the process. The local line is already on disk/journald.
* **No credential ever travels through us.** mnotify reads its own config/keychain; this
  module passes only a recipient and a subject on argv, and the alert body in a file.
"""

from __future__ import annotations

import contextlib
import json
import queue
import subprocess
import tempfile
import threading
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

from gateclerk.agent_alert import Alert, default_sink

__all__ = [
    "ALERT_QUEUE_MAX",
    "MNOTIFY_BINARY",
    "MNOTIFY_DRAIN_TIMEOUT_S",
    "MNOTIFY_TIMEOUT_S",
    "MnotifySink",
    "alert_mail",
]

#: The CLI name on PATH (or an absolute path a deployment chooses). mnotify owns its own
#: configuration, so there is no guarded default endpoint here.
MNOTIFY_BINARY = "mnotify"

#: Mail's exec budget from the contract (mnotify can spend ~210 s on Graph retries).
MNOTIFY_TIMEOUT_S = 300.0

#: One tick can fire a handful of alerts; a small queue absorbs that burst without letting
#: a dead mail route grow unbounded memory. Full means drop the PAGE (never the evidence).
ALERT_QUEUE_MAX = 16

#: How long process exit waits for an accepted page to finish before warning. Deliberately
#: short: systemd is restarting the unit and journald already has the evidence line.
MNOTIFY_DRAIN_TIMEOUT_S = 5.0

_STOP = object()

_Warn = Callable[[str], None]
_Runner = Callable[..., Any]


def _one_line(text: object) -> str:
    """Warning text is one journald line; error messages may carry newlines."""
    return " ".join(str(text).split())


def _restart_hint(alert: Alert) -> str:
    """Tell a human which service to restart, and that a restart is operator-only.

    Production is the Alpine container (CONTAINER-ALPINE), where there is no systemd at
    all, so the hint names both supported shapes instead of assuming one init system. A
    restart alone does NOT clear a terminal-401 park (the park is disk state, P2-05's
    lockout invariant); the hint therefore names both the service and the ack command.
    """
    unit = f"gateclerk-agent@{alert.site}"
    return (
        f"operator only: restart the site's service after fixing the cause "
        f"(systemd unit {unit}, or compose service {alert.site}); a restart does NOT "
        "clear a park — run "
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
    """Callable ``Alert`` sink: immediate local evidence, then one queued mail worker.

    ``__call__`` writes ``fallback`` (today's journald line, default P2-05's
    ``default_sink``) on the CALLING thread before touching the queue, then hands the alert
    to exactly one daemon worker so a slow mnotify can never stall polling. The bounded
    queue absorbs a tick's burst; when it is full the page is dropped with a warning and
    the already-written line remains the evidence. ``close()`` drains accepted pages for a
    bounded time and warns about any page still in flight.

    ``runner`` is the test seam (default ``subprocess.run``); ``warn`` is the agent's single
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
        queue_max: int = ALERT_QUEUE_MAX,
        drain_timeout_s: float = MNOTIFY_DRAIN_TIMEOUT_S,
    ) -> None:
        if not to or not to.strip():
            raise ValueError("mnotify sink needs a non-empty recipient")
        if timeout_s <= 0:
            raise ValueError("mnotify sink timeout_s must be > 0")
        if queue_max <= 0:
            raise ValueError("mnotify sink queue_max must be > 0")
        if drain_timeout_s < 0:
            raise ValueError("mnotify sink drain_timeout_s must be >= 0")
        self.to = to
        self.timeout_s = float(timeout_s)
        self.binary = binary
        self.queue_max = int(queue_max)
        self.drain_timeout_s = float(drain_timeout_s)
        self._warn = warn if warn is not None else (lambda _text: None)
        self._fallback = fallback
        self._runner = runner if runner is not None else subprocess.run
        self._body_dir = Path(body_dir) if body_dir is not None else None
        # The daily counter has no cross-process lock; serialise the whole invocation.
        self._send_lock = threading.Lock()
        self._queue: queue.Queue[Alert | object] = queue.Queue(maxsize=self.queue_max)
        self._state_lock = threading.Lock()
        self._worker: threading.Thread | None = None
        self._closed = False

    def __call__(self, alert: Alert) -> None:
        """Write the evidence line now, then enqueue the page. NEVER raises or blocks."""
        self._write_evidence(alert)
        with self._state_lock:
            if self._closed:
                worker = None
            else:
                if self._worker is None:
                    self._worker = threading.Thread(
                        target=self._work,
                        name=f"gateclerk-mnotify-{self.to}",
                        daemon=True,
                    )
                    self._worker.start()
                worker = self._worker
                try:
                    self._queue.put_nowait(alert)
                except queue.Full:
                    self._safe_warn(
                        f"warning: mnotify alert queue full ({self.queue_max} pending) for "
                        f"site={alert.site} device={alert.device_serial or '-'} "
                        f"kind={alert.kind}; dropped the page — the local alert line "
                        "was already written"
                    )
                    return
        if worker is None:
            serial = alert.device_serial or "-"
            self._safe_warn(
                f"warning: mnotify sink already closed for site={alert.site} device={serial} "
                f"kind={alert.kind}; dropped the page — the local alert line was already written"
            )

    def close(self, timeout_s: float | None = None) -> None:
        """Stop after the accepted pages, waiting at most ``timeout_s`` for the worker.

        A page still running at the deadline is reported once; its daemon thread cannot
        hold the process open, and the local evidence line was written before it started.
        """
        timeout = self.drain_timeout_s if timeout_s is None else max(0.0, float(timeout_s))
        with self._state_lock:
            self._closed = True
            worker = self._worker
        if worker is None or not worker.is_alive():
            return
        started = time.monotonic()
        try:
            self._queue.put(_STOP, timeout=timeout)
        except queue.Full:
            self._safe_warn(
                f"warning: mnotify alert queue still full after {timeout:g}s at exit; "
                "a page is unfinished — the local alert line was already written"
            )
            return
        worker.join(max(0.0, timeout - (time.monotonic() - started)))
        if worker.is_alive():
            self._safe_warn(
                f"warning: mnotify alert page unfinished after {timeout:g}s at exit; "
                "the local alert line was already written"
            )

    # --- internals ------------------------------------------------------------------

    def _write_evidence(self, alert: Alert) -> None:
        """The line goes out before any queue/worker machinery can fail or block."""
        try:
            self._fallback(alert)
        except Exception as exc:  # even THIS must not escape into the tick loop
            self._safe_warn(
                f"warning: could not write the local alert line for site={alert.site} "
                f"device={alert.device_serial or '-'} kind={alert.kind}: "
                f"{type(exc).__name__}: {_one_line(exc)}"
            )

    def _work(self) -> None:
        while True:
            item = self._queue.get()
            try:
                if item is _STOP:
                    return
                self._send(item)  # type: ignore[arg-type]
            finally:
                self._queue.task_done()

    def _send(self, alert: Alert) -> None:
        """One queued page; failure warns only (the evidence line already went out)."""
        failure: str | None = None
        try:
            with self._send_lock:
                failure = self._deliver(alert)
        except Exception as exc:  # the alert path must not take the agent down
            failure = f"unexpected {type(exc).__name__}: {_one_line(exc)}"
        if failure is None:
            return
        serial = alert.device_serial or "-"
        self._safe_warn(
            f"warning: mnotify alert delivery failed for site={alert.site} "
            f"device={serial} kind={alert.kind}: {failure}; "
            "the local alert line was already written"
        )

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
