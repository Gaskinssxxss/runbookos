#!/usr/bin/python3
"""Root helper for narrowly scoped Batch 04 disposable fixture recovery."""

from __future__ import annotations

import http.client
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path("/var/lib/runbookos-campaign-b04")
APP_UNIT = "runbookos-campaign-b04-app.service"
PROXY_UNIT = "runbookos-campaign-b04-proxy.service"
BACKEND_UNIT = "runbookos-campaign-b04-backend.service"
WORKER_UNIT = "runbookos-campaign-b04-worker.service"
DNS_UNIT = "runbookos-campaign-b04-dns.service"


def run(argv: list[str], timeout: int = 12) -> None:
    result = subprocess.run(
        argv,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        timeout=timeout,
        check=False,
        close_fds=True,
    )
    if result.returncode:
        raise RuntimeError("fixed fixture operation failed")


def restore_file(source: Path, target: Path, *, uid: int = 65534, gid: int = 65534) -> None:
    if source.is_symlink() or target.is_symlink() or not source.is_file():
        raise RuntimeError("fixture config identity check failed")
    data = source.read_bytes()
    if len(data) > 4096:
        raise RuntimeError("fixture config exceeds bound")
    if target.name == "app.json" and set(json.loads(data)) != {"backend_host", "backend_port"}:
        raise RuntimeError("known-good app config schema check failed")
    target.parent.mkdir(parents=True, exist_ok=True)
    fd, temp_name = tempfile.mkstemp(prefix=".b04-restore-", dir=target.parent)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.chown(temp_name, uid, gid)
        os.chmod(temp_name, 0o644)
        os.replace(temp_name, target)
    except Exception:
        Path(temp_name).unlink(missing_ok=True)
        raise


def tcp_ready(host: str, port: int) -> bool:
    try:
        with socket.create_connection((host, port), timeout=1):
            return True
    except OSError:
        return False


def wait_tcp_ready(host: str, port: int, seconds: float = 4) -> bool:
    deadline = time.monotonic() + seconds
    while True:
        if tcp_ready(host, port):
            return True
        if time.monotonic() >= deadline:
            return False
        time.sleep(0.1)


def execute(operation: str, fixture_id: str) -> dict[str, object]:
    if (operation, fixture_id) == ("restore-config", "app_config"):
        restore_file(ROOT / "config/app.good.json", ROOT / "config/app.json")
        run(["/usr/bin/systemctl", "restart", APP_UNIT])
        return {"fixture_id": fixture_id, "restored": True, "unit": APP_UNIT}
    if (operation, fixture_id) == ("restore-config", "proxy_config"):
        restore_file(ROOT / "config/proxy.good.json", ROOT / "config/proxy.json")
        run(["/usr/bin/systemctl", "restart", PROXY_UNIT])
        return {"fixture_id": fixture_id, "restored": True, "unit": PROXY_UNIT}
    if (operation, fixture_id) == ("restore-dns", "resolver_config"):
        (ROOT / "state/dns-invalid").unlink(missing_ok=True)
        restore_file(ROOT / "config/dns.good.json", ROOT / "config/dns.json")
        run(["/usr/bin/systemctl", "restart", DNS_UNIT])
        return {"fixture_id": fixture_id, "restored": True, "unit": DNS_UNIT}
    if (operation, fixture_id) == ("restore-network", "isolated_link"):
        run(
            [
                "/usr/sbin/ip",
                "netns",
                "exec",
                "runbookos-b04",
                "/usr/sbin/ip",
                "link",
                "set",
                "b04-ns0",
                "up",
            ]
        )
        run(
            [
                "/usr/sbin/ip",
                "route",
                "replace",
                "10.254.4.0/30",
                "dev",
                "b04-host0",
            ]
        )
        return {"fixture_id": fixture_id, "link_up": True, "route_restored": True}
    if (operation, fixture_id) == ("release-storage", "bounded_volume"):
        directory = ROOT / "volume"
        if directory.is_symlink() or not directory.is_dir():
            raise RuntimeError("bounded fixture volume is unavailable")
        removed = 0
        for item in directory.iterdir():
            if item.name.startswith("pressure-") and item.is_file() and not item.is_symlink():
                item.unlink()
                removed += 1
                if removed > 16:
                    raise RuntimeError("fixture pressure file count exceeded bound")
        free_bytes = shutil.disk_usage(directory).free
        if free_bytes < 1024 * 1024:
            raise RuntimeError("fixture volume still lacks recovery capacity")
        return {"fixture_id": fixture_id, "released_files": removed, "free_bytes": free_bytes}
    if (operation, fixture_id) == ("restore-resource", "worker_quota"):
        dropin = Path("/etc/systemd/system") / (WORKER_UNIT + ".d/10-b04-pressure.conf")
        if dropin.is_symlink():
            raise RuntimeError("worker resource drop-in identity check failed")
        dropin.unlink(missing_ok=True)
        (ROOT / "state/worker-pressure").unlink(missing_ok=True)
        run(["/usr/bin/systemctl", "daemon-reload"])
        run(["/usr/bin/systemctl", "restart", WORKER_UNIT])
        if not wait_tcp_ready("10.60.20.10", 18912):
            raise RuntimeError("worker readiness did not return")
        return {"fixture_id": fixture_id, "quota_restored": True, "worker_ready": True}
    if (operation, fixture_id) == ("restore-dependency", "backend_service"):
        run(["/usr/bin/systemctl", "start", BACKEND_UNIT])
        if not wait_tcp_ready("10.60.20.10", 18911):
            raise RuntimeError("backend listener did not become ready")
        connection = http.client.HTTPConnection("10.60.20.10", 18911, timeout=2)
        try:
            connection.request("GET", "/health", headers={"Connection": "close"})
            response = connection.getresponse()
            body = response.read(64).decode("ascii", "replace").strip()
        finally:
            connection.close()
        if response.status != 200 or body != "backend-ready":
            raise RuntimeError("backend readiness did not return")
        return {"fixture_id": fixture_id, "unit": BACKEND_UNIT, "ready": True}
    if (operation, fixture_id) == ("recover-worker", "worker_service"):
        run(["/usr/bin/systemctl", "restart", WORKER_UNIT])
        if not wait_tcp_ready("10.60.20.10", 18912):
            raise RuntimeError("worker readiness did not return")
        return {"fixture_id": fixture_id, "unit": WORKER_UNIT, "ready": True}
    if (operation, fixture_id) == ("start-postgres", "16-b04"):
        run(["/usr/bin/systemctl", "start", "postgresql@16-b04.service"], timeout=40)
        run(["/usr/bin/pg_isready", "-h", "10.60.30.10", "-p", "55434", "-t", "5"], timeout=8)
        return {"cluster": fixture_id, "started": True, "protocol_ready": True}
    raise ValueError("unregistered fixture recovery identity")


def main() -> int:
    if len(sys.argv) != 3:
        print(json.dumps({"ok": False, "data": {}, "error": "invalid_arguments"}))
        return 2
    try:
        data = execute(sys.argv[1], sys.argv[2])
        print(json.dumps({"ok": True, "data": data, "error": None}, sort_keys=True))
        return 0
    except Exception as exc:
        print(json.dumps({"ok": False, "data": {}, "error": type(exc).__name__}, sort_keys=True))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
