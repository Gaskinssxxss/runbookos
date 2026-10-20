"""Opt-in, loopback-only HMAC authenticated alert webhook using the standard library."""

from __future__ import annotations

import hashlib
import re
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from .adapters.alertmanager import normalize_alertmanager
from .incidents import IncidentStore, parse_alert, validate_target
from .store import SQLiteStore
from .webhook_auth import (
    AuthConfig,
    load_auth_config,
    validate_active_key_material,
    verify_request,
)

MAX_BODY = 64 * 1024
_NONCE = re.compile(r"^[A-Za-z0-9_-]{16,128}$")


class _LimitedServer(ThreadingHTTPServer):
    daemon_threads = True
    request_queue_size = 16

    def __init__(self, address, handler, *, max_concurrent: int = 8):
        self.slots = threading.BoundedSemaphore(max_concurrent)
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
    store_path,
    inventory_path,
    auth_config: AuthConfig,
    host: str = "127.0.0.1",
    port: int = 8765,
    *,
    max_concurrent: int = 8,
    rate_per_minute: int = 60,
) -> ThreadingHTTPServer:
    if host != "127.0.0.1":
        raise ValueError("webhook listener must bind to loopback")
    if not 1 <= max_concurrent <= 32 or not 1 <= rate_per_minute <= 600:
        raise ValueError("webhook limits out of range")
    validate_active_key_material(auth_config)
    db_store = SQLiteStore(store_path)
    incidents = IncidentStore(db_store)
    config_digest = hashlib.sha256(auth_config.model_dump_json().encode()).hexdigest()
    with db_store._connection() as db:
        db.execute("BEGIN IMMEDIATE")
        db_store._audit(
            db,
            "webhook.keyring_loaded",
            {
                "config_sha256": config_digest,
                "mode": auth_config.mode,
                "sources": {
                    source: {
                        "enabled": source_config.enabled,
                        "active_key_id": source_config.active_key_id,
                        "keys": {
                            key_id: {
                                "state": key.state,
                                "expires_at": key.expires_at.isoformat()
                                if key.expires_at
                                else None,
                            }
                            for key_id, key in source_config.keys.items()
                        },
                    }
                    for source, source_config in auth_config.sources.items()
                },
            },
        )
        db.commit()
    rate_lock = threading.Lock()
    requests: dict[str, list[float]] = {}

    class Handler(BaseHTTPRequestHandler):
        server_version = "RunbookOSWebhook/0.3"
        sys_version = ""

        def log_message(self, fmt, *args):
            # Avoid logging headers, signatures, bodies, or alert summaries.
            return

        def reply(self, status: int, body: bytes = b'{"error":"request rejected"}') -> None:
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)

        def do_POST(self):
            self.close_connection = True
            self.connection.settimeout(5)
            if self.path != "/v1/alerts":
                self.reply(404)
                return
            peer = self.client_address[0]
            now_mono = time.monotonic()
            with rate_lock:
                window = [stamp for stamp in requests.get(peer, []) if now_mono - stamp < 60]
                if len(window) >= rate_per_minute:
                    requests[peer] = window
                    self.reply(429)
                    return
                window.append(now_mono)
                requests[peer] = window
            lengths = self.headers.get_all("Content-Length", [])
            raw_len = lengths[0] if len(lengths) == 1 else ""
            if self.headers.get("Transfer-Encoding") or len(lengths) != 1:
                self.reply(400)
                return
            security_headers = (
                "Content-Type",
                "X-RunbookOS-Timestamp",
                "X-RunbookOS-Nonce",
                "X-RunbookOS-Signature",
            )
            if any(len(self.headers.get_all(name, [])) != 1 for name in security_headers):
                self.reply(400)
                return
            key_ids = self.headers.get_all("X-RunbookOS-Key-Id", [])
            if len(key_ids) > 1 or (auth_config.mode == "per_source" and len(key_ids) != 1):
                self.reply(400)
                return
            content_type = self.headers.get_content_type()
            if content_type not in {
                "application/json",
                "application/vnd.prometheus.alertmanager.v2+json",
            }:
                self.reply(415)
                return
            if not raw_len.isdecimal() or int(raw_len) > MAX_BODY:
                self.reply(413)
                return
            body = self.rfile.read(int(raw_len))
            if len(body) != int(raw_len):
                self.reply(400)
                return
            timestamp = self.headers.get("X-RunbookOS-Timestamp", "")
            nonce = self.headers.get("X-RunbookOS-Nonce", "")
            signature = self.headers.get("X-RunbookOS-Signature", "")
            key_id = self.headers.get("X-RunbookOS-Key-Id", "")
            if not _NONCE.fullmatch(nonce):
                self.reply(401)
                return
            try:
                authenticated_source = verify_request(
                    auth_config,
                    key_id=key_id,
                    timestamp=timestamp,
                    nonce=nonce,
                    signature=signature,
                    body=body,
                )
            except Exception:
                self.reply(401)
                return
            try:
                if content_type == "application/vnd.prometheus.alertmanager.v2+json":
                    alerts = normalize_alertmanager(body, authenticated_source)
                else:
                    alert = parse_alert(body)
                    if alert.source != authenticated_source:
                        self.reply(403)
                        return
                    alerts = [alert]
                if len(alerts) != 1:
                    self.reply(400)
                    return
                alert = alerts[0]
                validate_target(alert, inventory_path)
                result = incidents.ingest(
                    alert,
                    nonce=nonce,
                    request_timestamp=int(timestamp),
                    auth_key_id=key_id,
                )
            except Exception:
                self.reply(400)
                return
            payload = (
                '{"incident_id":"'
                + result["incident_id"]
                + '","duplicate_delivery":'
                + str(result["duplicate_delivery"]).lower()
                + "}"
            ).encode()
            self.reply(200, payload)

    return _LimitedServer((host, port), Handler, max_concurrent=max_concurrent)


def serve_from_environment(
    store_path, inventory_path, auth_config_path, *, host="127.0.0.1", port=8765
):
    config = load_auth_config(auth_config_path)
    server = create_server(store_path, inventory_path, config, host, port)
    try:
        server.serve_forever()
    finally:
        server.server_close()
