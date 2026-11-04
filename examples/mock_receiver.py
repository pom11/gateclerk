"""Reference HTTP ingest receiver for `gateclerk` (`https` sink contract).

Demonstrates the wire contract `gateclerk`'s HTTPS sink pushes against:
  * Method: `POST` (`405 method_not_allowed` otherwise)
  * Header `Authorization: Bearer <token>` (`401 unauthorized` if missing/unknown)
  * Header `X-Gateclerk-Site: <SITE>` (`403 site_token_mismatch` if it contradicts the
    site bound to the bearer token)
  * Body: UTF-8 JSONL lines (either `EventRecord` scan lines or `{"deviceCode", "users"}`
    hourly device-user roster lines; `400 invalid_jsonl` on malformed JSON)
  * Status codes for downstream handling:
      - `200`: batch accepted (idempotent on re-push)
      - `401`: missing/unknown/revoked bearer token
      - `403`: `X-Gateclerk-Site` contradicts the token's site
      - `422`: `unknown_device_serials` when a device serial is not registered upstream
      - `502`: `bc_unavailable` when the upstream ERP/database is temporarily unreachable

No real secrets live here — `DEMO_TOKENS` uses a placeholder token for local testing.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any

#: Placeholder token map (`token -> site_code`) for local dry-runs only.
DEMO_TOKENS: dict[str, str] = {
    "demo-placeholder-ingest-token": "DEMO-SITE-A",
}


def evaluate_ingest_request(
    *,
    method: str,
    headers: Mapping[str, str],
    body: bytes,
    tokens: Mapping[str, str] = DEMO_TOKENS,
    known_devices: set[str] | None = None,
) -> tuple[int, dict[str, Any]]:
    """Pure contract evaluator for an ingest request -> `(http_status, json_body)`."""
    if method.upper() != "POST":
        return 405, {"status": False, "error": "method_not_allowed"}

    lowered = {k.lower(): v for k, v in headers.items()}
    auth = lowered.get("authorization", "")
    bearer = auth[7:].strip() if auth.lower().startswith("bearer ") else ""
    matched_site = tokens.get(bearer) if bearer else None
    if not matched_site:
        return 401, {"status": False, "error": "unauthorized"}

    declared = (lowered.get("x-gateclerk-site") or "").strip().upper()
    if declared and declared != matched_site.upper():
        return 403, {"status": False, "error": "site_token_mismatch", "site": declared}

    try:
        text = body.decode("utf-8")
    except UnicodeDecodeError:
        return 400, {"status": False, "error": "invalid_jsonl", "line": 1}

    scans = 0
    rosters = 0
    unknown_serials: list[str] = []
    for idx, line in enumerate(text.splitlines(), start=1):
        if not line.strip():
            continue
        try:
            obj = json.loads(line)
        except ValueError:
            return 400, {"status": False, "error": "invalid_jsonl", "line": idx}
        if not isinstance(obj, dict):
            return 400, {"status": False, "error": "invalid_jsonl", "line": idx}
        if "users" in obj and "deviceCode" in obj:
            rosters += 1
        else:
            scans += 1
            serial = str(obj.get("device_serial") or "")
            if known_devices is not None and serial and serial not in known_devices:
                unknown_serials.append(serial)

    if unknown_serials:
        return 422, {
            "status": False,
            "error": "unknown_device_serials",
            "unknown": sorted(set(unknown_serials)),
        }

    return 200, {
        "status": True,
        "site": matched_site,
        "scans_received": scans,
        "rosters_received": rosters,
    }


class MockIngestHandler(BaseHTTPRequestHandler):
    """Minimal stdlib HTTP handler wrapping `evaluate_ingest_request`."""

    def do_POST(self) -> None:
        length = int(self.headers.get("Content-Length", "0") or "0")
        raw = self.rfile.read(length) if length > 0 else b""
        code, payload = evaluate_ingest_request(
            method="POST",
            headers=dict(self.headers.items()),
            body=raw,
        )
        encoded = json.dumps(payload).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)


def main(host: str = "127.0.0.1", port: int = 8787) -> None:  # pragma: no cover
    with HTTPServer((host, port), MockIngestHandler) as server:
        print(f"mock ingest receiver listening on http://{host}:{port}")
        server.serve_forever()


if __name__ == "__main__":  # pragma: no cover
    main()
