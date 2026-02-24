#!/usr/bin/env python3
"""
tools/mock_server.py — Lightweight mock HTTPS/HTTP server for transport tests.

Validates Splunk HEC and Bearer auth; records received event bodies;
exposes /_events, /_health, /_reset for test assertions.

Usage:
    python3 tools/mock_server.py [--port PORT] [--mode http|https] [--token TOKEN]

Requires stdlib only (no pip). For HTTPS mode, generates a self-signed cert via
`openssl` subprocess at startup.

SPDX-License-Identifier: GPL-3.0-or-later
"""

import argparse
import http.server
import json
import os
import ssl
import subprocess
import sys
import tempfile
import threading

# ── Shared state ──────────────────────────────────────────────────────────────
_events = []          # list of parsed JSON bodies received
_events_raw = []      # raw body bytes for non-JSON payloads
_lock = threading.Lock()

DEFAULT_PORT = 18765
DEFAULT_TOKEN = "test-token-12345"


# ── Request handler ───────────────────────────────────────────────────────────
class MockHandler(http.server.BaseHTTPRequestHandler):
    """Handle ingest POST and control GET requests."""

    valid_token: str = DEFAULT_TOKEN

    def log_message(self, fmt, *args):
        # Silence default stderr logging; tests use /_events to assert
        pass

    # ── Control endpoints ──────────────────────────────────────────────────────
    def do_GET(self):
        if self.path == "/_health":
            self._send_json(200, {"status": "ok", "events": len(_events)})
        elif self.path == "/_events":
            with _lock:
                payload = list(_events)
            self._send_json(200, payload)
        elif self.path == "/_reset":
            with _lock:
                _events.clear()
                _events_raw.clear()
            self._send_json(200, {"status": "reset"})
        else:
            self._send_json(404, {"error": "not found"})

    # ── Ingest endpoint ────────────────────────────────────────────────────────
    def do_POST(self):
        # Validate authorization
        auth = self.headers.get("Authorization", "")
        token_ok = (
            auth == f"Splunk {self.valid_token}"
            or auth == f"Bearer {self.valid_token}"
        )
        if not token_ok:
            self._send_json(403, {"text": "Invalid token", "code": 4})
            return

        # Read body
        content_length = int(self.headers.get("Content-Length", 0))
        body_bytes = self.rfile.read(content_length) if content_length else b""

        # Try to parse JSON
        try:
            body_json = json.loads(body_bytes.decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            body_json = {"_raw": body_bytes.decode("utf-8", errors="replace")}

        with _lock:
            _events.append(body_json)
            _events_raw.append(body_bytes)

        self._send_json(200, {"text": "Success", "code": 0})

    # ── Helpers ────────────────────────────────────────────────────────────────
    def _send_json(self, code: int, data: object):
        body = json.dumps(data).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


# ── Self-signed cert generation ───────────────────────────────────────────────
def generate_self_signed_cert(cert_path: str, key_path: str) -> bool:
    """Generate a self-signed cert via openssl CLI. Returns True on success."""
    try:
        result = subprocess.run(
            [
                "openssl", "req", "-x509",
                "-newkey", "rsa:2048",
                "-keyout", key_path,
                "-out", cert_path,
                "-days", "1",
                "-nodes",
                "-subj", "/CN=localhost",
            ],
            capture_output=True,
            timeout=15,
        )
        return result.returncode == 0
    except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
        print(f"[mock_server] openssl failed: {exc}", file=sys.stderr)
        return False


# ── Main ──────────────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(description="macguard-audit mock ingest server")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT, help="Listen port")
    parser.add_argument(
        "--mode", choices=["http", "https"], default="http",
        help="Protocol (http = plain, https = TLS with self-signed cert)"
    )
    parser.add_argument(
        "--token", default=DEFAULT_TOKEN,
        help="Expected auth token (Splunk or Bearer)"
    )
    args = parser.parse_args()

    MockHandler.valid_token = args.token

    server = http.server.HTTPServer(("127.0.0.1", args.port), MockHandler)

    cert_dir = None
    if args.mode == "https":
        cert_dir = tempfile.mkdtemp(prefix="macguard_mock_")
        cert_path = os.path.join(cert_dir, "cert.pem")
        key_path  = os.path.join(cert_dir, "key.pem")
        if not generate_self_signed_cert(cert_path, key_path):
            print("[mock_server] ERROR: could not generate self-signed cert; "
                  "falling back to HTTP", file=sys.stderr)
        else:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.load_cert_chain(certfile=cert_path, keyfile=key_path)
            server.socket = ctx.wrap_socket(server.socket, server_side=True)
            print(f"[mock_server] HTTPS listening on 127.0.0.1:{args.port} "
                  f"(cert: {cert_path})", flush=True)

    if args.mode == "http" or cert_dir is None:
        print(f"[mock_server] HTTP listening on 127.0.0.1:{args.port}", flush=True)

    # Signal readiness (tests wait for this line)
    print("[mock_server] READY", flush=True)

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
        if cert_dir:
            import shutil
            shutil.rmtree(cert_dir, ignore_errors=True)


if __name__ == "__main__":
    main()
