#!/usr/bin/python3
"""Network, service, and storage workloads for disposable RunbookOS Batch 04."""

from __future__ import annotations

import http.client
import http.server
import json
import os
import socket
import socketserver
import struct
import time
from pathlib import Path

ROOT = Path("/var/lib/runbookos-campaign-b04")
STATE = ROOT / "state"
CONFIG = ROOT / "config"
APP_ADDR = "10.60.20.10"
APP_PORT = 18891
PROXY_PORT = 18892
BACKEND_PORT = 18911
WORKER_PORT = 18912
DNS_PORT = 18954
NET_ADDR = "10.254.4.2"
NET_PORT = 18920


def dns_query() -> str:
    name = "backend.b04.test"
    ident = os.urandom(2)
    labels = b"".join(bytes((len(x),)) + x.encode() for x in name.split("."))
    packet = ident + struct.pack("!HHHHH", 0x0100, 1, 0, 0, 0) + labels + b"\0\0\1\0\1"
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
        client.settimeout(0.5)
        client.sendto(packet, (APP_ADDR, DNS_PORT))
        answer, _ = client.recvfrom(512)
    if answer[:2] != ident or struct.unpack("!H", answer[6:8])[0] != 1:
        raise LookupError("dns-answer-invalid")
    return socket.inet_ntoa(answer[-4:])


def backend_health() -> tuple[bool, str]:
    try:
        address = dns_query()
        connection = http.client.HTTPConnection(address, BACKEND_PORT, timeout=0.75)
        try:
            connection.request("GET", "/health", headers={"Connection": "close"})
            response = connection.getresponse()
            body = response.read(64).decode("ascii", "replace").strip()
            if response.status != 200:
                return False, "backend-readiness-failed"
            return True, body
        finally:
            connection.close()
    except Exception as exc:
        return False, f"dependency-{type(exc).__name__}"


def worker_health() -> tuple[bool, float]:
    start = time.monotonic()
    try:
        with socket.create_connection((APP_ADDR, WORKER_PORT), timeout=1.5) as worker:
            worker.settimeout(1.5)
            worker.sendall(b"health\n")
            healthy = worker.recv(16).strip() == b"ready"
    except OSError:
        return False, time.monotonic() - start
    return healthy and time.monotonic() - start < 1.0, time.monotonic() - start


def postgres_health(address: str = "10.60.30.10") -> bool:
    try:
        with socket.create_connection((address, 55434), timeout=0.75) as connection:
            connection.settimeout(0.75)
            connection.sendall(struct.pack("!II", 8, 80877103))
            return connection.recv(1) in (b"S", b"N")
    except OSError:
        return False


def app_health() -> tuple[int, str]:
    try:
        config_path = CONFIG / "app.json"
        if config_path.is_symlink():
            return 503, "application-configuration-invalid"
        config = json.loads(config_path.read_text())
        if (
            set(config) != {"backend_host", "backend_port"}
            or config["backend_host"] != "backend.b04.test"
            or config["backend_port"] != BACKEND_PORT
        ):
            return 503, "application-configuration-invalid"
    except Exception:
        return 503, "application-configuration-invalid"
    ready, detail = backend_health()
    if not ready:
        return 503, detail
    healthy_worker, latency = worker_health()
    if not healthy_worker:
        return 503, "worker-resource-pressure" if latency >= 1.0 else "worker-unavailable"
    if os.statvfs(ROOT / "volume").f_bavail * os.statvfs(ROOT / "volume").f_frsize < 4096:
        return 503, "storage-capacity-exhausted"
    try:
        with socket.create_connection((NET_ADDR, NET_PORT), timeout=0.5) as conn:
            conn.sendall(b"health\n")
            if conn.recv(16).strip() != b"ready":
                return 503, "isolated-network-not-ready"
    except OSError as exc:
        return 503, f"isolated-network-{type(exc).__name__}"
    return 200, "ready"


class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        if self.path != "/health":
            status, body = 404, "not-found"
        elif self.server.role == "backend":
            status, body = (200, "backend-ready")
        elif self.server.role == "dbclient":
            status, body = (
                (200, "database-dependent-client-ready")
                if postgres_health("127.0.0.1")
                else (503, "database-dependency-unavailable")
            )
        elif self.server.role == "app":
            status, body = app_health()
        else:
            try:
                conf = json.loads((CONFIG / "proxy.json").read_text())
                if (
                    set(conf) != {"upstream_host", "upstream_port"}
                    or conf["upstream_host"] != APP_ADDR
                    or conf["upstream_port"] != APP_PORT
                ):
                    raise ValueError
                connection = http.client.HTTPConnection(
                    conf["upstream_host"], conf["upstream_port"], timeout=1
                )
                try:
                    connection.request("GET", "/health", headers={"Connection": "close"})
                    response = connection.getresponse()
                    body = response.read(64).decode("ascii", "replace").strip()
                    status = response.status
                finally:
                    connection.close()
            except Exception:
                status, body = 503, "proxy-upstream-unavailable"
        data = (body + "\n").encode()
        self.send_response(status)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *_: object) -> None:
        return


class HTTPFixture(http.server.ThreadingHTTPServer):
    def __init__(self, port: int, role: str, host: str = APP_ADDR):
        self.role = role
        super().__init__((host, port), Handler)


class Worker(socketserver.StreamRequestHandler):
    def handle(self) -> None:
        self.rfile.readline(32)
        if (STATE / "worker-pressure").exists():
            until = time.process_time() + 0.2
            value = 1
            while time.process_time() < until:
                value = (value * 31 + 7) % 1_000_003
        self.wfile.write(b"ready\n")


class TCPFixture(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


class NetHandler(socketserver.StreamRequestHandler):
    def handle(self) -> None:
        self.rfile.readline(32)
        self.wfile.write(b"ready\n")


class DNSHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        query, sock = self.request
        if len(query) < 17:
            return
        pos = 12
        labels = []
        while pos < len(query) and query[pos] != 0:
            size = query[pos]
            pos += 1
            labels.append(query[pos : pos + size].decode("ascii", "replace"))
            pos += size
        pos += 1
        question = query[12 : pos + 4]
        if ".".join(labels) != "backend.b04.test":
            return
        data = json.loads((CONFIG / "dns.json").read_text())
        address = data["backend_address"]
        answer = b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 10, 4) + socket.inet_aton(address)
        response = query[:2] + struct.pack("!HHHHH", 0x8180, 1, 1, 0, 0) + question + answer
        sock.sendto(response, self.client_address)


class UDPFixture(socketserver.ThreadingUDPServer):
    allow_reuse_address = True
    daemon_threads = True


def serve(role: str) -> None:
    if role == "app":
        HTTPFixture(APP_PORT, "app").serve_forever(poll_interval=0.2)
    elif role == "proxy":
        HTTPFixture(PROXY_PORT, "proxy").serve_forever(poll_interval=0.2)
    elif role == "backend":
        HTTPFixture(BACKEND_PORT, "backend").serve_forever(poll_interval=0.2)
    elif role == "worker":
        TCPFixture((APP_ADDR, WORKER_PORT), Worker).serve_forever(poll_interval=0.2)
    elif role == "dns":
        UDPFixture((APP_ADDR, DNS_PORT), DNSHandler).serve_forever(poll_interval=0.2)
    elif role == "netns":
        TCPFixture((NET_ADDR, NET_PORT), NetHandler).serve_forever(poll_interval=0.2)
    elif role == "dbclient":
        HTTPFixture(18893, "dbclient", host="10.60.30.10").serve_forever(poll_interval=0.2)
    else:
        raise SystemExit("unknown campaign fixture role")


if __name__ == "__main__":
    if len(os.sys.argv) != 2:
        raise SystemExit("expected one role")
    serve(os.sys.argv[1])
