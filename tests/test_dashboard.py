from __future__ import annotations

import concurrent.futures
import http.client
import json
import os
import re
import socket
import sqlite3
import subprocess
import sys
import time
from datetime import UTC, datetime
from pathlib import Path

import pytest

from runbookos.dashboard import (
    _MAX_SESSIONS,
    AuthConfig,
    DashboardState,
    Session,
    _hash_password,
    create_auth_file,
)
from runbookos.errors import ConfigurationError
from runbookos.incidents import IncidentStore, parse_alert
from runbookos.store import SQLiteStore

ROOT = Path(__file__).parents[1]


def _alert(summary: str = "<script>alert(1)</script>") -> dict[str, object]:
    return {
        "alert_id": "dash-alert-1",
        "source": "synthetic-monitor",
        "event_timestamp": datetime.now(UTC).isoformat(),
        "severity": "error",
        "target_alias": "example-web-01",
        "service": "nginx",
        "category": "service",
        "summary": summary,
        "fingerprint": "dash-fingerprint",
        "metadata": {"check": "healthz"},
    }


def test_auth_file_is_hashed_owner_only_and_rejects_symlink(tmp_path: Path) -> None:
    path = tmp_path / "auth.json"
    phrase = "sample-login-phrase-123"
    create_auth_file(path, "operator-from-config", phrase)
    assert path.stat().st_mode & 0o777 == 0o600
    assert phrase not in path.read_text()
    auth = AuthConfig.load(path)
    assert auth.operator_id == "operator-from-config"
    assert auth.verify(phrase)
    assert not auth.verify("wrong-password")

    link = tmp_path / "auth-link.json"
    link.symlink_to(path)
    with pytest.raises(ConfigurationError):
        AuthConfig.load(link)


def test_auth_config_missing_or_permissive_fails_closed(tmp_path: Path) -> None:
    with pytest.raises(ConfigurationError):
        AuthConfig.load(tmp_path / "missing.json")
    path = tmp_path / "auth.json"
    create_auth_file(path, "operator", "a-long-operator-password")
    os.chmod(path, 0o644)
    with pytest.raises(ConfigurationError, match="permissions"):
        AuthConfig.load(path)


def test_authentication_rate_limit_and_session_cap(tmp_path: Path) -> None:
    import secrets

    salt = secrets.token_bytes(16)
    auth = AuthConfig(
        "operator", salt, _hash_password("sample-login-phrase-123", salt, 100_000), 100_000
    )
    state = DashboardState(tmp_path / "auth-limit.sqlite3", auth)
    for _ in range(5):
        assert state.authenticate("127.0.0.1", "wrong-password") is None
    assert state.authenticate("127.0.0.1", "sample-login-phrase-123") is None
    state.attempts.clear()
    state.sessions = {
        str(idx): Session("operator", "csrf", time.monotonic() + 3600)
        for idx in range(_MAX_SESSIONS)
    }
    assert state.authenticate("local-overflow", "sample-login-phrase-123") is None


def test_expired_dashboard_session_is_rejected(tmp_path: Path) -> None:
    import secrets

    auth = AuthConfig("operator", secrets.token_bytes(16), "0" * 64, 100_000)
    state = DashboardState(tmp_path / "expired.sqlite3", auth)
    state.sessions["expired-token"] = Session("operator", "csrf", time.monotonic() - 1)
    assert state.session("expired-token") is None
    assert "expired-token" not in state.sessions


def test_authenticated_dashboard_lifecycle_csrf_xss_and_restart(tmp_path: Path) -> None:
    database = tmp_path / "dashboard.sqlite3"
    incident_store = IncidentStore(SQLiteStore(database))
    created = incident_store.ingest(parse_alert(json.dumps(_alert()).encode()))
    incident_id = created["incident_id"]
    incident_store.ingest(
        parse_alert(
            json.dumps(
                _alert("bounded-" + "x" * 900)
                | {"alert_id": "dash-alert-long", "fingerprint": "dash-long"}
            ).encode()
        )
    )
    # Model a legacy event row created before transition fields were recorded.
    with sqlite3.connect(database) as db:
        db.execute(
            "UPDATE incident_events SET from_status=NULL,to_status=NULL WHERE incident_id=?",
            (incident_id,),
        )
    auth_file = tmp_path / "dashboard-auth.json"
    create_auth_file(auth_file, "trusted-operator", "sample-login-phrase-123")

    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    env = os.environ.copy()
    env["PYTHONPATH"] = str(ROOT / "src")

    def start() -> subprocess.Popen[bytes]:
        process = subprocess.Popen(
            [
                sys.executable,
                "-m",
                "runbookos",
                "--db",
                str(database),
                "dashboard",
                "serve",
                "--auth-file",
                str(auth_file),
                "--port",
                str(port),
            ],
            cwd=ROOT,
            env=env,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            if process.poll() is not None:
                pytest.fail("dashboard process exited before readiness")
            try:
                connection = http.client.HTTPConnection("127.0.0.1", port, timeout=1)
                connection.request("GET", "/login")
                response = connection.getresponse()
                response.read()
                connection.close()
                if response.status == 200:
                    return process
            except OSError:
                time.sleep(0.05)
        process.terminate()
        pytest.fail("dashboard did not become ready")

    def request(method: str, path: str, body: str = "", cookie: str | None = None):
        connection = http.client.HTTPConnection("127.0.0.1", port, timeout=3)
        headers = {"Content-Type": "application/x-www-form-urlencoded"}
        if cookie:
            headers["Cookie"] = cookie
        connection.request(method, path, body=body, headers=headers)
        response = connection.getresponse()
        data = response.read().decode()
        result = response.status, dict(response.getheaders()), data
        connection.close()
        return result

    process = start()
    try:
        status, _, body = request("GET", "/")
        assert status == 303
        assert "<script>alert(1)</script>" not in body
        status, headers, _ = request("POST", "/login", "password=wrong-password")
        assert status == 401
        status, headers, _ = request("POST", "/login", "password=sample-login-phrase-123")
        assert status == 303
        cookie = headers["Set-Cookie"].split(";", 1)[0]
        assert "HttpOnly" in headers["Set-Cookie"]
        assert "SameSite=Strict" in headers["Set-Cookie"]

        status, _, detail = request("GET", f"/incidents/{incident_id}", cookie=cookie)
        assert status == 200
        assert "&lt;script&gt;alert(1)&lt;/script&gt;" in detail
        assert "<script>alert(1)</script>" not in detail
        assert "— → —" in detail  # Older/non-transition event details remain renderable.
        status, _, queue = request("GET", "/", cookie=cookie)
        assert status == 200
        assert "synthetic-monitor" in queue
        assert "&lt;script&gt;alert(1)&lt;/script&gt;" in queue
        assert "<script>alert(1)</script>" not in queue
        assert "<th>Source</th>" in queue and "<th>Summary</th>" in queue
        assert "bounded-" + "x" * 230 in queue
        assert "x" * 240 not in queue
        csrf = re.search(r"name='csrf' value='([^']+)'", detail)
        assert csrf

        status, _, _ = request(
            "POST", f"/incidents/{incident_id}/acknowledge", "reason=reviewed", cookie
        )
        assert status == 403
        assert incident_store.show(incident_id)["status"] == "NEW"

        status, _, _ = request(
            "POST",
            f"/incidents/{incident_id}/acknowledge",
            f"csrf={csrf.group(1)}&reason=reviewed",
            cookie,
        )
        assert status == 303
        acknowledged = incident_store.show(incident_id)
        assert acknowledged["status"] == "ACKNOWLEDGED"
        assert acknowledged["events"][-1]["actor"] == "trusted-operator"
        status, _, detail = request("GET", f"/incidents/{incident_id}", cookie=cookie)
        assert status == 200 and "NEW → ACKNOWLEDGED" in detail

        # The UI does not accept user-supplied evidence references and cannot skip a state.
        status, _, _ = request(
            "POST",
            f"/incidents/{incident_id}/resolve",
            f"csrf={csrf.group(1)}&reason=forged&evidence_status=verified&evidence_refs=fake",
            cookie,
        )
        assert status == 409
        assert incident_store.show(incident_id)["status"] == "ACKNOWLEDGED"

        incident_store.mark_investigating(incident_id, "trusted-operator")
        detail_status, _, detail = request("GET", f"/incidents/{incident_id}", cookie=cookie)
        assert detail_status == 200
        csrf = re.search(r"name='csrf' value='([^']+)'", detail)
        assert csrf
        status, _, _ = request(
            "POST",
            f"/incidents/{incident_id}/resolve",
            f"csrf={csrf.group(1)}&reason=forged&evidence_status=verified&evidence_refs=fake",
            cookie,
        )
        assert status == 409
        assert incident_store.show(incident_id)["status"] == "INVESTIGATING"
        status, _, _ = request(
            "POST",
            f"/incidents/{incident_id}/resolve",
            f"csrf={csrf.group(1)}&reason=operator+attestation&evidence_status=not_available",
            cookie,
        )
        assert status == 303
        status, _, detail = request("GET", f"/incidents/{incident_id}", cookie=cookie)
        csrf = re.search(r"name='csrf' value='([^']+)'", detail)
        assert status == 200 and csrf
        assert "not_available" in detail
        status, _, _ = request(
            "POST",
            f"/incidents/{incident_id}/close",
            f"csrf={csrf.group(1)}&reason=closed",
            cookie,
        )
        assert status == 303
        assert incident_store.show(incident_id)["status"] == "CLOSED"

        second = IncidentStore(SQLiteStore(database)).ingest(
            parse_alert(
                json.dumps(
                    _alert("second alert") | {"alert_id": "dash-alert-2", "fingerprint": "second"}
                ).encode()
            )
        )
        concurrent_body = f"csrf={csrf.group(1)}&reason=concurrent-review"
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            statuses = list(
                pool.map(
                    lambda _: request(
                        "POST",
                        f"/incidents/{second['incident_id']}/acknowledge",
                        concurrent_body,
                        cookie,
                    )[0],
                    range(2),
                )
            )
        assert sorted(statuses) == [303, 409]
        assert (
            IncidentStore(SQLiteStore(database)).show(second["incident_id"])["status"]
            == "ACKNOWLEDGED"
        )
    finally:
        process.send_signal(2)  # SIGINT exercises the server's orderly close path.
        process.wait(timeout=5)

    # Restart invalidates the session but preserves the incident and audit history.
    process = start()
    try:
        status, _, _ = request("GET", "/", cookie=cookie)
        assert status == 303
        status, _, login = request("GET", "/login")
        assert status == 200
        assert incident_store.show(incident_id)["status"] == "CLOSED"
        valid, count = SQLiteStore(database).verify_audit_chain()
        assert valid and count >= 5
    finally:
        process.send_signal(2)
        process.wait(timeout=5)


def test_dashboard_rejects_non_loopback_bind() -> None:
    from runbookos.dashboard import serve_dashboard

    with pytest.raises(ValueError, match="fixed to 127.0.0.1"):
        serve_dashboard(Path("unused.sqlite"), Path("unused-auth.json"), host="0.0.0.0")


def test_dashboard_rejects_occupied_port_without_disturbing_listener() -> None:
    from http.server import BaseHTTPRequestHandler

    from runbookos.dashboard import _Server

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802
            self.send_response(204)
            self.end_headers()

    with socket.socket() as occupied:
        occupied.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        occupied.bind(("127.0.0.1", 0))
        occupied.listen(1)
        address = occupied.getsockname()
        with pytest.raises(OSError):
            _Server(address, Handler)
        # The failed bind must not close or otherwise replace the unrelated listener.
        occupied.settimeout(0.1)
        client = socket.create_connection(address, timeout=1)
        conn, _ = occupied.accept()
        client.close()
        conn.close()
