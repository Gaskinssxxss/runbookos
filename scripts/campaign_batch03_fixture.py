#!/usr/bin/env python3
"""Bounded HTTP, DNS, and worker services for the disposable B03 campaign."""

from __future__ import annotations

import http.client
import json
import os
import socket
import socketserver
import struct
import sys
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

ROOT = Path("/var/lib/runbookos-campaign-b03")
STATE = ROOT / "state"
CONFIG = ROOT / "app.json"
HOST = "10.60.20.10"
BACKEND_PORT = 18901
APP_PORT = 18890
WORKER_PORT = 18902
DNS_PORT = 18953


def marker(name: str) -> Path:
    return STATE / name


def prepare(role: str) -> None:
    """Fixture-owned, deterministic recovery performed only on unit start."""
    clear = {
        "backend": ("backend-unavailable", "backend-partition"),
        "app": ("app-invalid",),
        "worker": ("worker-pressure",),
        "dns": ("dns-wrong-answer", "dns-packet-drop"),
    }.get(role)
    if clear:
        for name in clear:
            marker(name).unlink(missing_ok=True)
    if role == "app" and marker("app-crash-loop").exists():
        count_path = marker("app-crash-loop-attempts")
        try:
            count = int(count_path.read_text()) + 1
        except (OSError, ValueError):
            count = 1
        count_path.write_text(str(count))
        if count >= 4:
            marker("app-crash-loop").unlink(missing_ok=True)
            count_path.unlink(missing_ok=True)
            restore_config()


def restore_config() -> None:
    good = ROOT / "app.good.json"
    if good.is_file():
        CONFIG.write_bytes(good.read_bytes())


def dns_query(name: str) -> str:
    ident = os.urandom(2)
    labels = b"".join(bytes((len(part),)) + part.encode("ascii") for part in name.split("."))
    question = labels + b"\0" + struct.pack("!HH", 1, 1)
    packet = ident + struct.pack("!HHHHH", 0x0100, 1, 0, 0, 0) + question
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
        client.settimeout(0.4)
        client.sendto(packet, (HOST, DNS_PORT))
        response, _ = client.recvfrom(1024)
    if response[:2] != ident or len(response) < 12:
        raise ValueError("invalid fixture DNS response")
    if struct.unpack("!H", response[6:8])[0] < 1:
        raise LookupError("fixture DNS returned no address")
    pos = 12
    while response[pos] != 0:
        pos += response[pos] + 1
    pos += 5
    if response[pos : pos + 2] == b"\xc0\x0c":
        pos += 2
    else:
        while response[pos] != 0:
            pos += response[pos] + 1
        pos += 1
    rtype, rclass, _, length = struct.unpack("!HHIH", response[pos : pos + 10])
    pos += 10
    if (rtype, rclass, length) != (1, 1, 4):
        raise LookupError("fixture DNS returned a non-A answer")
    return socket.inet_ntoa(response[pos : pos + 4])


def app_health() -> tuple[bool, str]:
    if marker("app-invalid").exists():
        return False, "invalid-application-configuration"
    try:
        config = json.loads(CONFIG.read_text())
        if set(config) != {"backend_name", "backend_port"}:
            return False, "invalid-application-configuration"
        address = dns_query(config["backend_name"])
        connection = http.client.HTTPConnection(address, int(config["backend_port"]), timeout=0.5)
        try:
            connection.request("GET", "/health", headers={"Connection": "close"})
            response = connection.getresponse()
            healthy = response.status == 200
            response.read(64)
            if not healthy:
                return False, "backend-readiness-failed"
        finally:
            connection.close()
    except Exception as exc:
        return False, f"dependency-{type(exc).__name__}"
    started = time.monotonic()
    try:
        # The worker fault intentionally consumes a bounded 150 ms CPU slice.
        # A 500 ms socket deadline made the fault oracle race guest scheduling
        # under model load and report a transport timeout instead of the
        # resource-pressure signal. Keep the wait bounded but above that load.
        with socket.create_connection((HOST, WORKER_PORT), timeout=2.0) as worker:
            worker.settimeout(2.0)
            worker.sendall(b"health\n")
            if worker.recv(32).strip() != b"ready":
                return False, "worker-readiness-failed"
    except Exception as exc:
        return False, f"worker-{type(exc).__name__}"
    if time.monotonic() - started > 0.12:
        return False, "worker-resource-pressure"
    return True, "ready"


class Handler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        if self.path != "/health":
            status, body = 404, "not-found"
        elif self.server.role == "backend":
            status, body = (
                (503, "backend-unavailable")
                if marker("backend-unavailable").exists()
                else (200, "backend-ready")
            )
        else:
            healthy, body = app_health()
            status = 200 if healthy else 503
        payload = (body + "\n").encode()
        self.send_response(status)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, *_: object) -> None:
        return


class FixtureHTTP(ThreadingHTTPServer):
    def __init__(self, address: tuple[str, int], role: str):
        self.role = role
        super().__init__(address, Handler)


def dns_response(query: bytes) -> bytes:
    if marker("dns-packet-drop").exists():
        # The isolated fixture resolver receives the UDP datagram but does not
        # reply, reproducing a bounded DNS-path blackhole without host routing
        # or gateway changes.
        return b""
    if len(query) < 17:
        raise ValueError("short DNS query")
    pos = 12
    labels: list[str] = []
    while pos < len(query) and query[pos] != 0:
        size = query[pos]
        pos += 1
        labels.append(query[pos : pos + size].decode("ascii"))
        pos += size
    pos += 1
    question = query[12 : pos + 4]
    if ".".join(labels) != "backend.b03.test" or query[pos : pos + 4] != b"\0\1\0\1":
        return query[:2] + struct.pack("!HHHHH", 0x8183, 1, 0, 0, 0) + question
    address = "10.60.20.99" if marker("dns-wrong-answer").exists() else HOST
    answer = b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 15, 4) + socket.inet_aton(address)
    return query[:2] + struct.pack("!HHHHH", 0x8180, 1, 1, 0, 0) + question + answer


class DNSUDP(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        if marker("dns-packet-drop").exists():
            return
        try:
            response = dns_response(self.request[0])
            self.request[1].sendto(response, self.client_address)
        except Exception:
            return


class Worker(socketserver.StreamRequestHandler):
    def handle(self) -> None:
        self.rfile.readline(32)
        if marker("worker-pressure").exists():
            deadline = time.process_time() + 0.15
            value = 1
            while time.process_time() < deadline:
                value = (value * 31 + 7) % 1_000_003
        self.wfile.write(b"ready\n")


class ReusableServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


def serve(role: str) -> None:
    if role in {"backend", "app"}:
        if role == "app" and marker("app-crash-loop").exists():
            # Fail the disposable app unit so its configured systemd
            # Restart=on-failure/start limit observes a genuine crash loop.
            raise SystemExit(1)
        port = BACKEND_PORT if role == "backend" else APP_PORT
        server = FixtureHTTP((HOST, port), role)
        server.serve_forever(poll_interval=0.2)
    elif role == "worker":
        ReusableServer((HOST, WORKER_PORT), Worker).serve_forever(poll_interval=0.2)
    elif role == "dns":
        socketserver.ThreadingUDPServer((HOST, DNS_PORT), DNSUDP).serve_forever(poll_interval=0.2)
    else:
        raise SystemExit("unsupported B03 fixture role")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit("expected one fixture role")
    if sys.argv[1].startswith("prepare-"):
        prepare(sys.argv[1].removeprefix("prepare-"))
    else:
        serve(sys.argv[1])
