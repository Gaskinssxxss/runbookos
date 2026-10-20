"""Loopback-only Alertmanager signing bridge, separate from execution and lifecycle paths."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import re
import secrets
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.error import HTTPError, URLError
from urllib.request import HTTPRedirectHandler, Request, build_opener

MAX_BODY = 64 * 1024
DOWNSTREAM_TIMEOUT = 5


class _BoundedServer(ThreadingHTTPServer):
    daemon_threads = True
    request_queue_size = 16

    def __init__(self, address, handler, slots: int):
        self.slots = threading.BoundedSemaphore(slots)
        super().__init__(address, handler)

    def process_request(self, request, client_address):
        if not self.slots.acquire(blocking=False):
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except Exception:
            self.slots.release()
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self.slots.release()


def create_server(
    *,
    host: str = "127.0.0.1",
    port: int = 8764,
    downstream_port: int = 8765,
    max_concurrent: int = 8,
    upstream_user: str | None = None,
    upstream_password: str | None = None,
    key_id: str | None = None,
    signing_secret: str | None = None,
):
    """Create the bridge. Its trusted upstream is loopback plus a configured Basic credential."""
    if host != "127.0.0.1" or not 0 <= port <= 65535 or not 1 <= downstream_port <= 65535:
        raise ValueError("bridge and downstream must use explicit loopback TCP ports")
    if port == downstream_port or not 1 <= max_concurrent <= 16:
        raise ValueError("bridge limits are invalid")
    upstream_user = upstream_user or os.environ.get("RUNBOOKOS_BRIDGE_USER", "")
    upstream_password = upstream_password or os.environ.get("RUNBOOKOS_BRIDGE_PASSWORD", "")
    key_id = key_id or os.environ.get("RUNBOOKOS_BRIDGE_KEY_ID", "")
    signing_secret = signing_secret or os.environ.get("RUNBOOKOS_BRIDGE_HMAC_KEY", "")
    if (
        not re.fullmatch(r"[A-Za-z0-9_.-]{1,128}", upstream_user)
        or len(upstream_password.encode()) < 24
        or any(ord(char) < 32 or ord(char) == 127 for char in upstream_password)
    ):
        raise ValueError("bridge upstream credentials are missing or too short")
    if (
        not key_id
        or len(key_id) > 64
        or any(
            c not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.-"
            for c in key_id
        )
    ):
        raise ValueError("bridge key ID is invalid")
    if len(signing_secret.encode()) < 32:
        raise ValueError("bridge HMAC key must contain at least 32 bytes")
    expected_auth = "Basic " + base64.b64encode(
        f"{upstream_user}:{upstream_password}".encode()
    ).decode("ascii")

    class RejectRedirects(HTTPRedirectHandler):
        def redirect_request(self, req, fp, code, msg, headers, newurl):
            return None

    downstream_opener = build_opener(RejectRedirects())

    class Handler(BaseHTTPRequestHandler):
        server_version = "RunbookOSAlertmanagerBridge/0.3"
        sys_version = ""

        def log_message(self, fmt, *args):
            return

        def reply(self, status: int, body: bytes = b'{"error":"delivery failed"}'):
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)

        def do_POST(self):
            self.close_connection = True
            self.connection.settimeout(DOWNSTREAM_TIMEOUT)
            if self.client_address[0] != "127.0.0.1":
                self.reply(403)
                return
            if self.path != "/api/v2/alerts":
                self.reply(404)
                return
            supplied = self.headers.get_all("Authorization", [])
            if len(supplied) != 1 or not hmac.compare_digest(
                supplied[0].encode("latin-1"), expected_auth.encode("ascii")
            ):
                self.reply(401)
                return
            lengths = self.headers.get_all("Content-Length", [])
            content_types = self.headers.get_all("Content-Type", [])
            if (
                self.headers.get("Transfer-Encoding")
                or len(lengths) != 1
                or len(lengths[0]) > 6
                or not lengths[0].isdecimal()
                or len(content_types) != 1
            ):
                self.reply(400)
                return
            size = int(lengths[0])
            if size > MAX_BODY:
                self.reply(413)
                return
            if content_types[0].split(";", 1)[0].strip().lower() != "application/json":
                self.reply(415)
                return
            body = self.rfile.read(size)
            if len(body) != size:
                self.reply(400)
                return

            timestamp = str(int(time.time()))
            nonce = secrets.token_urlsafe(24)
            canonical = (
                key_id.encode() + b"\n" + timestamp.encode() + b"\n" + nonce.encode() + b"\n" + body
            )
            signature = hmac.new(signing_secret.encode(), canonical, hashlib.sha256).hexdigest()
            downstream = Request(
                f"http://127.0.0.1:{downstream_port}/v1/alerts",
                data=body,
                method="POST",
                headers={
                    "Content-Type": "application/vnd.prometheus.alertmanager.v2+json",
                    "X-RunbookOS-Key-Id": key_id,
                    "X-RunbookOS-Timestamp": timestamp,
                    "X-RunbookOS-Nonce": nonce,
                    "X-RunbookOS-Signature": signature,
                },
            )
            try:
                with downstream_opener.open(downstream, timeout=DOWNSTREAM_TIMEOUT) as response:
                    status = response.status
                    accepted = response.read(4097) if status == 200 else b""
            except HTTPError as exc:
                status, accepted = exc.code, b""
            except (URLError, TimeoutError, OSError):
                self.reply(502)
                return
            try:
                receipt = json.loads(accepted)
                durable_receipt = (
                    isinstance(receipt, dict)
                    and isinstance(receipt.get("incident_id"), str)
                    and isinstance(receipt.get("duplicate_delivery"), bool)
                )
            except (ValueError, UnicodeDecodeError):
                durable_receipt = False
            if status != 200 or len(accepted) > 4096 or not durable_receipt:
                self.reply(502)
                return
            # The downstream returns 200 only after its SQLite ingestion transaction commits.
            # Relay a generic durable-acceptance response; never expose the incident response.
            self.reply(200, b'{"accepted":true}')

    return _BoundedServer((host, port), Handler, max_concurrent)


def main() -> None:
    import argparse

    parser = argparse.ArgumentParser(description="Loopback Alertmanager HMAC signing bridge")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8764)
    parser.add_argument("--downstream-port", type=int, default=8765)
    parser.add_argument("--max-concurrent", type=int, default=8)
    args = parser.parse_args()
    server = create_server(
        host=args.host,
        port=args.port,
        downstream_port=args.downstream_port,
        max_concurrent=args.max_concurrent,
    )
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
