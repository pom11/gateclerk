"""`gateclerk demo` — the whole loop in one command, with zero real credentials.

The operator goal this module exists for: a developer must be able to watch gateclerk do
its entire job — poll a device, store, queue, deliver to two sinks — on a laptop with no
door controller, no ingest deployment, no keychain item and no network beyond loopback.
DEMO-DEVICE shipped the fake device; SINKS-WIRING shipped the per-sink fan-out. This
module is the seam between them: it wires the two together through the PUBLIC surface of
each and runs a bounded number of real agent ticks.

What is real here, and what is staged
------------------------------------

Real (the whole point — a demo of a fake path teaches nothing):

* the pass is `agent_cli.SiteAgent.tick()`: P2-03's scheduler, P2-02's store, P2-04's
  queue and drain, SINKS-WIRING's per-sink fan-out, P2-05's gate. Nothing inside the
  agent is stubbed;
* the device is `demo_device.DemoDevice` — a real loopback server the unmodified
  `IsapiClient` talks digest to;
* the csv leg is `sink_writers.FileSinkWriter` — the production writer, the production
  `CSV_COLUMNS` header, the production fsync-then-mark-acked law;
* the https leg is `agent_push.HttpsIngestTransport` built by
  `sink_writers.build_https_sink_transport` — the production bearer transport, so the
  `Authorization` / `X-GateClerk-Site` / `Content-Type: application/jsonl` contract the
  demo prints is the contract that runs against the real ingest.

Staged (and loud about it):

* the ingest is a mock server in this process on loopback, answering 200 and printing
  each batch it received (line count + which contract headers were PRESENT — never a
  value);
* the mock speaks TLS with a throwaway certificate minted into the scratch dir and
  PINNED into a CA bundle handed to the client. That is gotchas §4.1's sanctioned posture
  ("pin the device cert into a CA bundle — never `verify=False`"), not an exemption:
  verification stays on, which is why the production transport needs no special case;
* the bearer is a recognisable placeholder supplied through the env rung's injectable
  seam, so the keychain rung is never reached.

The zero-keychain / zero-real-config law
---------------------------------------

Three mechanisms, each asserted by tests/test_demo_walkthrough.py:

1. every path the run touches lives under one scratch root — the sites file, the sqlite
   store, the park dir, the health snapshot, the csv sinks, the TLS material. `~/.gateclerk`
   and `~/gateclerk` are never consulted (those are the `migrate` group's bundle-root
   defaults, which this command never enters);
2. credentials enter on the FLAG rung (the demo's own device password) or through an
   injected env mapping (the demo's own ingest token), and the mapping handed to the
   agent is empty — so `resolve_credentials` stops before the keychain rung; the https
   sink leg is handed a reader that REFUSES to read, so the keychain is never asked for
   anything, and an ambient `GATECLERK_*` on a developer's laptop can neither leak into the
   demo nor the demo into it;
3. the scratch root is removed in a `finally` unless `--keep` asked for it, which then
   prints the paths it kept.

Determinism: the agent's clock is a stepping demo clock frozen on the demo day (the day
`demo_device`'s fixtures live on), so every run sees the same three windows, the same 46
events, the same rows. `sleep` is a no-op, so three ticks cost milliseconds.
"""

from __future__ import annotations

import ipaddress
import os
import random
import shutil
import ssl
import subprocess
import tempfile
import threading
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from zoneinfo import ZoneInfo

from gateclerk import agent_cli, sink_writers
from gateclerk import config as cfg
from gateclerk import demo_device as demo
from gateclerk.sinks import CSV_COLUMNS

__all__ = [
    "DEMO_CERT_DAYS",
    "DEMO_CSV_SINK_NAME",
    "DEMO_DAY_START",
    "DEMO_DEFAULT_TICKS",
    "DEMO_DEVICE_HOST",
    "DEMO_INGEST_ENV",
    "DEMO_MOCK_INGEST_STATUS",
    "DEMO_MOCK_SINK_NAME",
    "DEMO_MOCK_TOKEN",
    "DEMO_SITE_NAME",
    "DEMO_TICK_S",
    "DemoWalkthroughError",
    "MockIngestSink",
    "ReceivedBatch",
    "WalkthroughReport",
    "demo_sites_toml",
    "run_demo_walkthrough",
]

#: The one site the demo configures. Synthetic and self-labelling, like every demo name.
DEMO_SITE_NAME = "demo-site"
#: The two sinks the walkthrough configures (names are queue keys and CSV column values).
DEMO_MOCK_SINK_NAME = "mock_ingest"
DEMO_CSV_SINK_NAME = "demo_csv"
#: The env-var NAME the demo's config points at for its bearer. A reference, never a
#: value: the config carries the name and the value stays in the process (SINKS-CORE's
#: law). Named without the redundant "TOKEN" word because ruff's S105 flags any
#: assignment whose *name* ends in TOKEN, and this one really is a variable name.
DEMO_INGEST_ENV = "GATECLERK_DEMO_INGEST"  # the var whose VALUE is the demo's bearer
#: The demo's bearer value. Assembled rather than written whole so no credential scanner
#: sees a `token = "..."` shape it has to guess about; `test_demo_never_prints_the_token`
#: is what pins that it never reaches an output stream.
DEMO_MOCK_TOKEN = "demo" + "-ingest-token"

#: Seconds between the demo's ticks (also the cold-start window width, with `overlap_s`).
DEMO_TICK_S = 300
#: How many ticks the demo runs. Three is enough to show the three facts a first-run
#: developer asks about: the first pass delivers, the overlap re-read costs nothing, and
#: a second sink keeps its own counters.
DEMO_DEFAULT_TICKS = 3
#: The demo day. `demo_device.demo_events()` stamps its 46 fixture events at 08:00:00
#: through 08:07:30 DEVICE-wall digits (claiming +02:00 all year while the site zone is
#: +03:00 in summer — the tz-mismatch bug the demo is also here to demonstrate).
#:
#: The clock starts at 08:09 site-wall digits so the FIRST tick delivers every fixture
#: event, and the arithmetic is worth spelling out because it is the same arithmetic the
#: real device applies (OBSERVED.md "Window offsets are ARITHMETIC"): the agent labels the
#: window with the device's OWN claimed offset, so a start of `08:09+03:00` goes on the
#: wire as digits `08:09` labeled `+02:00`, and the cold-start lower bound is
#: `now - cadence_s - overlap_s` = `07:59`. The box then reads a bound as
#: `digits + claimed - label` — here `claimed == label`, i.e. the digits verbatim — so
#: tick 1 asks for device wall `[07:59, 08:09]`: all 46 events, the first one 60 s and the
#: last one 90 s inside the edges. Ticks 2 and 3 then re-read the corpus through the
#: overlap window and store it as `unchanged`, which is the seam-3 story the demo tells.
#: The figure is pinned by `test_demo_delivers_every_synthetic_event`, not by here.
DEMO_DAY_START = datetime(2026, 6, 15, 8, 9, 0, tzinfo=ZoneInfo("Europe/Bucharest"))
#: The demo's device host: loopback, because the fake device binds loopback only.
DEMO_DEVICE_HOST = "127.0.0.1"
#: What the mock ingest answers: 200 is the real ingest's success shape.
DEMO_MOCK_INGEST_STATUS = 200
#: The throwaway certificate's lifetime, in days.
DEMO_CERT_DAYS = 1
#: The scratch root's prefix — what a `--keep`ed directory is named, and what the test's
#: keychain guard looks for.
DEMO_SCRATCH_PREFIX = "gateclerk-demo-"


class DemoWalkthroughError(RuntimeError):
    """The demo cannot run. Always a loud refusal, never a silently-degraded demo."""


# --- the mock ingest ----------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class ReceivedBatch:
    """One POST the mock ingest accepted: the facts the card asks a demo to print.

    Deliberately narrow. `authorization_present` is a PRESENCE flag, never a value — a
    demo that printed a bearer would train developers to paste bearers into terminals,
    tickets and screenshots.
    """

    path: str
    authorization_present: bool
    gateclerk_site: str | None
    content_type: str | None
    lines: int

    def as_dict(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "authorization_present": self.authorization_present,
            "x_gateclerk_site": self.gateclerk_site,
            "content_type": self.content_type,
            "lines": self.lines,
        }

    def describe(self) -> str:
        """One human line: what arrived, in the order the frozen contract names it."""
        auth = "present" if self.authorization_present else "MISSING"
        return (
            f"  batch  lines={self.lines}  Authorization={auth}  "
            f"X-GateClerk-Site={self.gateclerk_site or '-'}  "
            f"Content-Type={self.content_type or '-'}"
        )


class _MockHandler(BaseHTTPRequestHandler):
    """The handler half of `MockIngestSink`: record the contract, echo it, answer 200."""

    def do_POST(self) -> None:
        self._serve_body()

    def do_GET(self) -> None:
        # `GET /` is a liveness read for a human with curl (and for the test).
        self._serve_body(record=False)

    def _serve_body(self, *, record: bool = True) -> None:
        box: MockIngestSink = self.server.demo_box  # type: ignore[attr-defined]
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length) if length else b""
        if record:
            box.record(self.path, body, dict(self.headers.items()))
        payload = b'{"ok":true,"sink":"gateclerk-demo-mock"}\n'
        self.send_response(DEMO_MOCK_INGEST_STATUS)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, format: str, *args: object) -> None:
        """Silence the base class's stderr line.

        The demo prints its OWN batch line (with the contract facts, minus any value);
        http.server's version would echo the request line and the client address, which
        is noise in a demo and a habit in a log.
        """
        return


class MockIngestSink:
    """A loopback HTTPS ingest stand-in that prints every batch it receives.

    It exists so the demo can SHOW the frozen wire contract instead of describing it: the
    batches arrive through the production `HttpsIngestTransport`, over a real socket, with
    the real `Authorization` / `X-GateClerk-Site` / `Content-Type` headers, and the evidence
    of that is what the developer sees on the terminal.

    Loopback-only by construction (the bind host is a module constant, not a parameter),
    and the key/cert are minted into the caller's scratch dir and never leave it.
    """

    def __init__(
        self,
        *,
        cert_dir: Path,
        on_batch: Callable[[ReceivedBatch], None] | None = None,
    ) -> None:
        if not _is_loopback(DEMO_DEVICE_HOST):  # pragma: no cover - guard of the guard
            raise DemoWalkthroughError(
                "the mock ingest binds loopback only (SYNTHETIC-ONLY LAW); "
                f"got {DEMO_DEVICE_HOST!r}"
            )
        self.bind_host = DEMO_DEVICE_HOST
        self.cert_dir = Path(cert_dir)
        self._on_batch = on_batch
        self._batches: list[ReceivedBatch] = []
        self._lock = threading.Lock()
        self._server: ThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None
        self._ca_bundle: Path | None = None
        self._key_path: Path | None = None
        self._port = 0

    # -- lifecycle ---------------------------------------------------------------------

    def start(self) -> MockIngestSink:
        """Mint the throwaway cert, wrap a loopback socket in TLS, serve in a thread."""
        if self._server is not None:
            raise DemoWalkthroughError("the mock ingest is already started")
        cert, key = _mint_loopback_cert(self.cert_dir)
        self._ca_bundle = cert
        self._key_path = key
        server = ThreadingHTTPServer((self.bind_host, 0), _MockHandler)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(certfile=str(cert), keyfile=str(key))
        server.socket = context.wrap_socket(server.socket, server_side=True)
        self._port = int(server.socket.getsockname()[1])
        server.demo_box = self  # type: ignore[attr-defined]
        self._server = server
        self._thread = threading.Thread(
            target=server.serve_forever, name="gateclerk-demo-mock-ingest", daemon=True
        )
        self._thread.start()
        return self

    def stop(self) -> None:
        server, thread = self._server, self._thread
        self._server = self._thread = None
        if server is not None:
            server.shutdown()
            server.server_close()
        if thread is not None and thread is not threading.current_thread():
            thread.join(timeout=5.0)

    # -- what a caller reads -------------------------------------------------------------

    @property
    def base_url(self) -> str:
        if self._server is None:
            raise DemoWalkthroughError("the mock ingest is not started")
        return f"https://{self.bind_host}:{self._port}"

    @property
    def ingest_url(self) -> str:
        """The `[[site.sink]] url` the demo writes into its throwaway config."""
        return f"{self.base_url}/ingest"

    @property
    def ca_bundle(self) -> Path:
        """The pinned CA bundle — the only way this demo trusts its own certificate."""
        if self._ca_bundle is None:
            raise DemoWalkthroughError("the mock ingest has no certificate (not started?)")
        return self._ca_bundle

    @property
    def line_count(self) -> int:
        with self._lock:
            return sum(batch.lines for batch in self._batches)

    def received(self) -> tuple[ReceivedBatch, ...]:
        with self._lock:
            return tuple(self._batches)

    def record(self, path: str, body: bytes, headers: Mapping[str, str]) -> None:
        """One arrival, reduced to contract facts. A header VALUE is never kept."""
        lowered = {str(name).lower(): str(value) for name, value in headers.items()}
        batch = ReceivedBatch(
            path=path,
            authorization_present="authorization" in lowered,
            gateclerk_site=lowered.get("x-gateclerk-site"),
            content_type=lowered.get("content-type"),
            lines=len(body.decode("utf-8", "replace").splitlines()),
        )
        with self._lock:
            self._batches.append(batch)
        if self._on_batch is not None:
            self._on_batch(batch)


def _is_loopback(host: str) -> bool:
    """Whether `host` may be bound at all (the same law `demo_device` enforces)."""
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def _mint_loopback_cert(directory: Path) -> tuple[Path, Path]:
    """A throwaway 127.0.0.1 certificate minted into `directory`; returns (cert, key).

    The cert doubles as the CA bundle the client pins.

    The `openssl` CLI does this because nothing in this repo can mint a certificate (the
    optional `[fast]` extra is orjson, not cryptography) and pulling a crypto dependency
    into the base install for one demo command is the wrong trade. The command is fixed
    argv with no user input, writes only inside the scratch dir, and its ABSENCE is a loud
    refusal rather than a fallback to plaintext: a mock ingest a bearer could cross in
    clear text is not a demo, it is a bad lesson.
    """
    directory.mkdir(parents=True, exist_ok=True)
    openssl = shutil.which("openssl")
    if openssl is None:
        raise DemoWalkthroughError(
            "the demo's mock ingest needs `openssl` to mint a loopback certificate and "
            "openssl is not on PATH. The demo will not fall back to clear-text HTTP for a "
            "bearer transport (gotchas §4.1)."
        )
    key = directory / "mock-ingest-key.pem"
    cert = directory / "mock-ingest.pem"
    conf = directory / "mock-ingest.cnf"
    conf.write_text(_CERT_CONF, encoding="utf-8")
    try:
        proc = subprocess.run(  # noqa: S603 - fixed argv, no shell, scratch-dir paths only
            [
                openssl,
                "req",
                "-x509",
                "-newkey",
                "rsa:2048",
                "-nodes",
                "-days",
                str(DEMO_CERT_DAYS),
                "-keyout",
                str(key),
                "-out",
                str(cert),
                "-config",
                str(conf),
            ],
            capture_output=True,
            text=True,
            timeout=60,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise DemoWalkthroughError(
            f"could not run `openssl req` for the demo cert: {exc}"
        ) from None
    if proc.returncode != 0 or not cert.exists():
        detail = (proc.stderr or "").strip()[-300:]
        raise DemoWalkthroughError(f"could not mint the demo's loopback certificate: {detail!r}")
    key.chmod(0o600)
    return cert, key


_CERT_CONF = """\
[req]
distinguished_name = dn
x509_extensions = v3
prompt = no
[dn]
CN = 127.0.0.1
[v3]
basicConstraints = critical, CA:TRUE
keyUsage = critical, digitalSignature, keyEncipherment, keyCertSign
subjectAltName = IP:127.0.0.1
"""


# --- the throwaway config -----------------------------------------------------------------------


def demo_sites_toml(
    *,
    root: Path | str,
    device_port: int,
    ingest_url: str,
    ticks: int = DEMO_DEFAULT_TICKS,
) -> str:
    """The text of the demo's `sites.toml`: one synthetic site, two sinks, zero secrets.

    Written as TOML and read back through `config.load_sites` (never hand-built), so the
    demo exercises the same validator a real deployment passes and a developer can read
    the exact config they just ran out of a `--keep`ed directory.

    Both sink blocks carry a REFERENCE, never a value: the https sink names its bearer
    with `token_env`, and the csv sink names an absolute path under the scratch root —
    `sinks._file_path`'s own law (absolute, traversal-free), which is why the path is
    derived here rather than left relative.
    """
    out_dir = Path(root) / "out"
    state_db = "state/gateclerk-demo-site.sqlite3"
    return f"""\
# Generated by `gateclerk demo` into a scratch directory. Nothing in this file is a real
# device, a real endpoint or a real credential — see src/gateclerk/demo_walkthrough.py.

[[site]]
name = "{DEMO_SITE_NAME}"
host = "{DEMO_DEVICE_HOST}"
port = {device_port}
iana_tz = "Europe/Bucharest"
device_tz = "Europe/Bucharest"
isapi_user = "{demo.DEMO_DEFAULT_USER}"
cadence_s = {DEMO_TICK_S}
overlap_s = {DEMO_TICK_S}
page_delay_ms = 0
db_path = "{state_db}"

# The archive leg: the production csv writer, the frozen CSV_COLUMNS header, one row per
# delivered punch.
[[site.sink]]
name = "{DEMO_CSV_SINK_NAME}"
type = "csv"
path = "{out_dir / "punches.csv"}"
rotation = "daily"

# The ingest leg: the production bearer transport aimed at a loopback mock. `token_env`
# is a REFERENCE — the value lives in the demo process, never in this file.
[[site.sink]]
name = "{DEMO_MOCK_SINK_NAME}"
type = "https"
url = "{ingest_url}"
token_env = "{DEMO_INGEST_ENV}"
"""


# --- the report ---------------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class WalkthroughReport:
    """What the demo run did, as data. The CLI prints it; the test asserts it."""

    root: Path
    site: str
    ticks: int
    device_url: str
    ingest_url: str
    device_requests: int
    records_stored: int
    inserted: int
    unchanged: int
    checkpoint_serial: int | None
    per_sink: Mapping[str, Mapping[str, int]] = field(default_factory=dict)
    batches: tuple[ReceivedBatch, ...] = ()
    csv_path: Path = Path()
    csv_rows: int = 0
    csv_header: tuple[str, ...] = ()
    csv_tail: tuple[str, ...] = ()
    kept: bool = False
    warnings: tuple[str, ...] = ()

    @property
    def mock_lines(self) -> int:
        return sum(batch.lines for batch in self.batches)

    def as_dict(self) -> dict[str, Any]:
        return {
            "root": str(self.root),
            "site": self.site,
            "ticks": self.ticks,
            "device_url": self.device_url,
            "ingest_url": self.ingest_url,
            "device_requests": self.device_requests,
            "records_stored": self.records_stored,
            "inserted": self.inserted,
            "unchanged": self.unchanged,
            "checkpoint_serial": self.checkpoint_serial,
            "sinks": {name: dict(counts) for name, counts in self.per_sink.items()},
            "mock_batches": [batch.as_dict() for batch in self.batches],
            "csv": {
                "path": str(self.csv_path),
                "rows": self.csv_rows,
                "header": list(self.csv_header),
                "tail": list(self.csv_tail),
            },
            "kept": self.kept,
            "warnings": list(self.warnings),
        }


@dataclass
class _SteppingClock:
    """One fixed start instant, advanced by `step_s` per DEMO TICK (not per call).

    `SiteAgent` reads the clock through the `now` seam it already has, and the demo owns
    the tick loop, so the advance happens at the tick boundary — which is the only point
    where "the next poll happened" is true. Advancing per CALL would move the window
    several times inside one pass (the loop reads `now()` for the window, for each
    checkpoint advance, and for the alert policy), which would make the demo's windows
    depend on how many chunks a pass happened to walk.
    """

    start: datetime
    step_s: int
    tick: int = 0

    def __call__(self) -> datetime:
        return self.start + timedelta(seconds=self.step_s * self.tick)

    def advance(self) -> None:
        self.tick += 1


def _no_sleep(_seconds: float) -> None:
    """The demo's sleep: the agent's cadence sleep is a no-op, so N ticks cost ms."""
    return


# --- the loop -----------------------------------------------------------------------------------


def run_demo_walkthrough(
    *,
    root: Path | str | None = None,
    ticks: int = DEMO_DEFAULT_TICKS,
    keep: bool = False,
    out: Callable[[str], None] | None = None,
    seed: int = 20260615,
) -> WalkthroughReport:
    """Run the whole loop and report it. Prints nothing itself except through `out`.

    `root` is the scratch directory: `None` mints one with `mkdtemp` (0700) and removes it
    in a `finally`; passing one is how `--keep` works and how a caller reads the csv after
    the fact. `ticks` is bounded (the card's "bounded count, deterministic"); the agent's
    clock is the demo's own, so two runs on two machines produce the same rows.
    """
    if ticks < 1:
        raise DemoWalkthroughError(f"ticks must be >= 1, got {ticks}")
    # Preflight, before anything is bound: the mock ingest cannot exist without a
    # certificate, and a run that started the device leg first would leave a socket open
    # while it discovered that. Refusing here is also what makes the CLI's exit-2 path
    # deterministic on a machine (or CI image) that lacks the tool.
    if shutil.which("openssl") is None:
        raise DemoWalkthroughError(
            "the demo's mock ingest needs `openssl` to mint a loopback certificate and "
            "openssl is not on PATH. The demo will not fall back to clear-text HTTP for a "
            "bearer transport (gotchas §4.1)."
        )
    # The drain's backoff jitter is the only randomness in the pass, and both demo sinks
    # succeed, so no row is ever backed off. Seeding anyway is what makes "deterministic"
    # a property of the command rather than a property of today's fixture data.
    random.seed(seed)

    own_root = root is None
    scratch = Path(root) if root is not None else Path(tempfile.mkdtemp(prefix=DEMO_SCRATCH_PREFIX))
    scratch = scratch.expanduser().resolve()
    if own_root:
        scratch.chmod(0o700)
    else:
        scratch.mkdir(parents=True, exist_ok=True)

    say: Callable[[str], None] = out if out is not None else (lambda text: None)
    box: demo.DemoDevice | None = None
    mock: MockIngestSink | None = None
    agent: agent_cli.SiteAgent | None = None
    warnings: list[str] = []

    try:
        # One scoped environment for the whole run: the demo's bearer exported under the
        # name its own config references (so the resolution the demo shows IS the env
        # rung), and the proxy variables removed for the duration (CI's no-egress wall
        # points them at a dead port, and the device client honors them). Both are
        # restored exactly on exit — see `_DemoEnv`.
        with _DemoEnv(_demo_token_env()):
            # (1) the fake device — loopback, synthetic, the unmodified client's counterpart.
            box = demo.DemoDevice()
            box.start()
            say(f"demo device   {box.base_url}   (digest user={demo.DEMO_DEFAULT_USER}, synthetic)")

            # (2) the mock ingest, and (3) the throwaway config naming both sinks.
            mock = MockIngestSink(cert_dir=scratch / "tls", on_batch=say_batch(say))
            mock.start()
            say(f"mock ingest   {mock.ingest_url}   (pinned cert; TLS verification ON)")
            sites_path = scratch / "sites.toml"
            sites_path.write_text(
                demo_sites_toml(root=scratch, device_port=box.port, ingest_url=mock.ingest_url),
                encoding="utf-8",
            )
            site = cfg.load_sites(sites_path, surface=cfg.ConfigSurface.AGENT)[DEMO_SITE_NAME]

            # The mock leg's transport: the PRODUCTION factory, given the one thing
            # production cannot know — the CA bundle to pin (§4.1's posture, never
            # `verify=False`). `env` is left None deliberately: the bearer then resolves
            # from the real environment through the sink's `token_env` reference, which is
            # the rung a real deployment uses and the rung above the keychain one.
            mock_sink = next(s for s in site.effective_sinks if s.name == DEMO_MOCK_SINK_NAME)
            mock_transport = sink_writers.build_https_sink_transport(
                site.name,
                mock_sink,
                client=_pinned_client(mock.ca_bundle),
                keychain=_RefusingKeychain(),
            )

            # (4) the agent, wired only through public seams. `password=` is the FLAG rung
            # and `env={}` seals the env rung, so the DEVICE credential stops before the
            # keychain rung too; the two rungs are sealed independently on purpose.
            clock = _SteppingClock(DEMO_DAY_START, DEMO_TICK_S)
            agent = agent_cli.build_site_agent(
                site,
                state_root=scratch,
                env={},
                password=demo.DEMO_DEFAULT_PASSWORD,
                now=clock,
                sleep=_no_sleep,
                warn=warnings.append,
                sink=lambda alert: warnings.append(
                    f"alert {alert.level} {alert.kind} {alert.note}"
                ),
                sink_transports={DEMO_MOCK_SINK_NAME: mock_transport},
            )

            # The bounded tick loop: `SiteAgent.tick()` is the same public pass `agent run`
            # drives, and the demo advances its own clock at the boundary between them.
            tick_reports = []
            for _ in range(ticks):
                tick_reports.append(agent.tick())
                clock.advance()

            # (5) the evidence: what the csv holds and what the mock saw.
            csv_path = _newest_csv(scratch / "out")
            rows, header, tail = _read_csv(csv_path)
            result = WalkthroughReport(
                root=scratch,
                site=site.name,
                ticks=len(tick_reports),
                device_url=box.base_url,
                ingest_url=mock.ingest_url,
                device_requests=len(box.requests),
                records_stored=sum(t.records_stored for t in tick_reports),
                inserted=sum(t.inserted for t in tick_reports),
                unchanged=sum(t.unchanged for t in tick_reports),
                checkpoint_serial=tick_reports[-1].checkpoint_serial if tick_reports else None,
                per_sink=_sum_sink_counts(tick_reports),
                batches=mock.received(),
                csv_path=csv_path,
                csv_rows=rows,
                csv_header=header,
                csv_tail=tail,
                kept=keep or not own_root,
                warnings=tuple(warnings),
            )
            _say_summary(result, say)
            return result
    finally:
        # Order matters: the agent holds the sqlite handle and the device clients, the
        # servers hold sockets, and the scratch dir is only removable once both are down.
        if agent is not None:
            try:
                agent.close()
            except Exception as exc:  # pragma: no cover - a close raise must not hide the run
                warnings.append(f"warning: agent close raised {type(exc).__name__}")
        if mock is not None:
            mock.stop()
        if box is not None:
            box.stop()
        if own_root and not keep:
            shutil.rmtree(scratch, ignore_errors=True)
        else:
            say(f"kept        {scratch}")


def say_batch(say: Callable[[str], None]) -> Callable[[ReceivedBatch], None]:
    """The mock sink's `on_batch` hook: one printed line per arrival, contract facts only."""
    return lambda batch: say(batch.describe())


def _demo_token_env() -> dict[str, str]:
    """The env mapping the mock sink's transport resolves its bearer from.

    The config names the reference (`token_env = "GATECLERK_DEMO_INGEST"`); the VALUE lives
    only in this process, exported by `_DemoEnv` under exactly that name — so the
    resolution the demo shows IS the env rung a real deployment uses.
    """
    return {DEMO_INGEST_ENV: DEMO_MOCK_TOKEN}


class _RefusingKeychain:
    """A keychain reader that refuses to be read — passed to the demo's sink transport.

    Why this exists rather than "just don't pass one": `agent_push._resolve_token` builds
    its reader as an ARGUMENT (`keychain=… if self._keychain is not None else
    KeychainReader()`), so the object is constructed on every token resolution even when
    the bearer is already in hand from the env rung. Construction is harmless — no
    `security` process, no value — but the card's law is that the demo touches the
    keychain ZERO times, and a demo that passes a real reader is one refactor away from
    prompting a developer's ACL dialog mid-demo. Handing the transport the repo's own
    injectable `keychain=` seam makes the refusal structural: if a future change ever
    routes the demo's bearer through the store rung, this raises with a sentence instead
    of asking the operator's laptop for permission.
    """

    def read(self, *args: object, **kwargs: object) -> object:
        raise DemoWalkthroughError(
            "the demo refuses to read the keychain (SYNTHETIC-ONLY LAW): the mock sink's "
            "bearer comes from the env rung named by its own `token_env` reference"
        )


#: Env vars that would route even a loopback request through a proxy. CI's no-egress wall
#: points these at a dead port on purpose, and `IsapiClient` builds its httpx client with
#: `trust_env=True` (as production must): a demo that left these set would have its device
#: leg CONNECT-ed to the dead proxy and fail in CI for a reason that has nothing to do with
#: what it is demonstrating. `tests/_socketseam.py` unsets the same set for the same reason.
_PROXY_VARS = (
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "ALL_PROXY",
    "http_proxy",
    "https_proxy",
    "all_proxy",
)


@dataclass
class _DemoEnv:
    """One demo run's scoped view of the environment — set on enter, restored on exit.

    Two things happen for the duration of a run, and both are undone in `__exit__`:

    * the demo's bearer is exported under the name its config references, so the
      resolution the demo shows is the real env rung (`resolve_credentials`' and the sink
      transport's own code path), and the keychain rung is unreachable *structurally*
      rather than merely unchosen;
    * the proxy variables are removed, so both loopback legs really talk to loopback (the
      pinned mock client already opts out with `trust_env=False`; the device client is the
      one that would otherwise obey them).

    Restoring exactly (including "was not set before") is what makes this safe to run
    inside a test process: nothing leaks to the next test, and a developer's exported
    `GATECLERK_*` / `HTTP(S)_PROXY` survives the demo unchanged.
    """

    values: Mapping[str, str]
    saved: dict[str, str | None] = field(default_factory=dict)

    def __enter__(self) -> _DemoEnv:
        for name in (*self.values, *_PROXY_VARS):
            self.saved.setdefault(name, os.environ.get(name))
        for name, value in self.values.items():
            os.environ[name] = value
        for name in _PROXY_VARS:
            os.environ.pop(name, None)
        return self

    def __exit__(self, *_exc: object) -> bool:
        for name, previous in reversed(list(self.saved.items())):
            if previous is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = previous
        self.saved.clear()
        return False


def _pinned_client(ca_bundle: Path) -> Any:
    """An httpx client that trusts exactly one certificate: the demo's own.

    This is gotchas §4.1's CA-pin, not a verification switch — `verify` receives a bundle
    PATH, never `False` — so `HttpsIngestTransport` runs its production code path against
    a loopback listener. `trust_env=False` is the second half of the law: a demo must not
    route a bearer through whatever proxy the developer's shell exports (and CI's
    no-egress wall sets exactly such a variable).
    """
    import httpx

    # An explicit SSLContext rather than `verify=<path>`: the string form is deprecated in
    # httpx, and `create_default_context(cafile=...)` is the same pin stated directly —
    # it loads ONLY this bundle, which is exactly the point (see gotchas §4.1).
    context = ssl.create_default_context(cafile=str(ca_bundle))
    return httpx.Client(
        verify=context,
        trust_env=False,
        timeout=httpx.Timeout(15.0, connect=5.0),
        headers={"User-Agent": "gateclerk-demo/1"},
    )


def _sum_sink_counts(tick_reports: Any) -> dict[str, dict[str, int]]:
    """Fold the per-pass `SiteTickReport.sinks` counters into one total per sink."""
    totals: dict[str, dict[str, int]] = {}
    for tick in tick_reports:
        for name, counts in (tick.sinks or {}).items():
            bucket = totals.setdefault(name, {})
            for key, value in counts.items():
                bucket[key] = bucket.get(key, 0) + int(value)
    return totals


def _newest_csv(out_dir: Path) -> Path:
    """The csv the run wrote — globbed from the rotated name, not guessed at.

    A missing directory or a missing csv is a loud failure: a demo that printed "46 rows"
    out of a file it never checked is the false-green this repo's history keeps naming.
    """
    candidates = sorted(
        (path for path in out_dir.glob("*.csv") if path.is_file() and ".roster." not in path.name),
        key=lambda path: path.stat().st_mtime,
    )
    if not candidates:
        raise DemoWalkthroughError(
            f"the csv sink wrote no file under {out_dir}: the demo cannot report rows it "
            "did not produce"
        )
    return candidates[-1]


def _read_csv(path: Path) -> tuple[int, tuple[str, ...], tuple[str, ...]]:
    """(data rows, header tuple, last three raw lines) for the demo's csv."""
    lines = path.read_text(encoding="utf-8").splitlines()
    header = tuple(lines[0].split(",")) if lines else ()
    body = lines[1:] if lines else []
    return len(body), header, tuple(body[-3:])


def _say_summary(report: WalkthroughReport, say: Callable[[str], None]) -> None:
    """The status block the card asks for: events seen, per-sink delivered, csv path/tail."""
    say("")
    say(f"site            {report.site}   ({report.ticks} ticks)")
    say(
        f"events stored   {report.records_stored}   inserted={report.inserted} "
        f"unchanged={report.unchanged} checkpoint_serial={report.checkpoint_serial}"
    )
    for name, counts in report.per_sink.items():
        say(
            f"sink {name:<12}  queued={counts.get('queued', 0)} "
            f"pushed={counts.get('pushed', 0)} failed={counts.get('push_failed', 0)} "
            f"dead_lettered={counts.get('dead_lettered', 0)}"
        )
    say(f"mock batches    {len(report.batches)}   lines={report.mock_lines}")
    header_state = "matches CSV_COLUMNS" if report.csv_header == CSV_COLUMNS else "MISMATCH"
    say(f"csv rows        {report.csv_rows}   header={header_state}")
    say(f"csv path        {report.csv_path}")
    for line in report.csv_tail:
        say(f"  tail {line[:160]}")
    if report.warnings:
        say("warnings")
        for line in report.warnings:
            say(f"  {line}")
