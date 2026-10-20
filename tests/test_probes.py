from __future__ import annotations

import base64
import http.client
import json
import socket
import ssl
import sys
from pathlib import Path

import pytest
import yaml
from conftest import write_config_tree
from pydantic import ValidationError

from runbookos.actions import validate_action
from runbookos.engine import RunbookEngine, validate_runbook
from runbookos.errors import ConfigurationError
from runbookos.models import ProbeTarget
from runbookos.remote import REMOTE_SOURCE


@pytest.mark.parametrize(
    "address",
    ["127.0.0.1", "169.254.169.254", "8.8.8.8", "224.0.0.1", "localhost", "0.0.0.0"],
)
def test_probe_target_rejects_loopback_metadata_public_and_non_ip(address: str) -> None:
    with pytest.raises(ValidationError):
        ProbeTarget(protocol="tcp", address=address, port=443)


@pytest.mark.parametrize("path", ["//evil.example", "/../admin", "/health?token=x", "/%2fadmin"])
def test_http_target_rejects_redirect_or_path_injection(path: str) -> None:
    with pytest.raises(ValidationError):
        ProbeTarget(protocol="https", address="10.20.30.40", port=443, path=path)


def test_probe_target_requires_fixed_http_path_and_protocol_specific_fields() -> None:
    with pytest.raises(ValidationError):
        ProbeTarget(protocol="https", address="10.20.30.40", port=443)
    with pytest.raises(ValidationError):
        ProbeTarget(protocol="postgresql", address="10.20.30.40", port=5432, path="/health")


def test_probe_arguments_are_strict_and_endpoint_is_an_alias() -> None:
    assert validate_action("network.tcp_connect", {"endpoint_id": "postgres_listener"}).read_only
    for args in (
        {"endpoint_id": "postgres_listener", "address": "10.0.0.1"},
        {"endpoint_id": "https://example.com"},
        {"endpoint_id": "pg;touch /tmp/x"},
    ):
        with pytest.raises(ConfigurationError):
            validate_action("network.tcp_connect", args)


def test_probe_plan_requires_inventory_and_separate_policy_allowlist(tmp_path: Path) -> None:
    paths = write_config_tree(tmp_path)
    inventory = yaml.safe_load(paths.inventory.read_text())
    inventory["hosts"]["test-web"]["probe_targets"] = {
        "postgres_listener": {
            "protocol": "postgresql",
            "address": "10.250.30.10",
            "port": 5432,
        }
    }
    paths.inventory.write_text(yaml.safe_dump(inventory))
    policy = yaml.safe_load(paths.policy.read_text())
    policy["hosts"]["test-web"]["allowed_probe_targets"] = ["postgres_listener"]
    policy["hosts"]["test-web"]["diagnostic_actions"].append("postgresql.protocol_available")
    paths.policy.write_text(yaml.safe_dump(policy))
    runbook = tmp_path / "probe.yml"
    runbook.write_text(
        "api_version: runbookos/v1\nkind: Runbook\nmetadata:\n"
        "  id: pg-probe-test\n  name: PG probe\n  description: bounded test\n  risk: low\n"
        "targets: [test-web]\nsteps:\n  - id: pg-protocol\n"
        "    action: postgresql.protocol_available\n"
        "    with: {endpoint_id: postgres_listener}\n    timeout_seconds: 5\n"
    )
    plan = RunbookEngine(paths).plan(runbook)
    assert plan.status == "ready"
    assert plan.actions[0].arguments == {"endpoint_id": "postgres_listener"}

    policy = yaml.safe_load(paths.policy.read_text())
    policy["hosts"]["test-web"]["allowed_probe_targets"] = []
    paths.policy.write_text(yaml.safe_dump(policy))
    denied = RunbookEngine(paths).plan(runbook)
    assert denied.status == "denied"
    assert "explicitly policy-allowed" in denied.actions[0].reason

    inventory["hosts"]["test-web"]["probe_targets"]["postgres_listener"]["protocol"] = "tcp"
    paths.inventory.write_text(yaml.safe_dump(inventory))
    mismatch = RunbookEngine(paths).plan(runbook)
    assert mismatch.status == "denied"
    assert "probe endpoint is not configured" in mismatch.actions[0].reason


def test_probe_action_timeout_above_hard_limit_is_rejected() -> None:
    runbook = yaml.safe_load(
        "api_version: runbookos/v1\nkind: Runbook\nmetadata:\n"
        "  id: bounded-probe\n  name: Bounded probe\n  description: timeout test\n  risk: low\n"
        "targets: [test-web]\nsteps:\n  - id: tcp-check\n"
        "    action: network.tcp_connect\n    with: {endpoint_id: listener}\n"
        "    timeout_seconds: 11\n"
    )
    from runbookos.models import Runbook

    with pytest.raises(ConfigurationError, match="exceeds its 10s limit"):
        validate_runbook(Runbook.model_validate(runbook))


class FakeSocket:
    def __init__(self, response: bytes = b""):
        self.response = response
        self.sent = b""

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return None

    def sendall(self, data: bytes):
        self.sent += data

    def recv(self, count: int) -> bytes:
        return self.response[:count]

    def settimeout(self, timeout):
        self.timeout = timeout


def run_remote(monkeypatch: pytest.MonkeyPatch, capsys, action: str, endpoint: dict, timeout=4):
    request = {
        "action": action,
        "arguments": {"endpoint_id": "service_probe", "_endpoint": endpoint},
        "timeout_seconds": timeout,
    }
    encoded = base64.b64encode(json.dumps(request).encode()).decode()
    monkeypatch.setattr(sys, "argv", ["runbookos-remote", encoded])
    namespace = {"__name__": "__main__"}
    exec(compile(REMOTE_SOURCE, "<runbookos-remote-test>", "exec"), namespace)
    return json.loads(capsys.readouterr().out)


def test_tcp_probe_reports_result_without_exposing_payload(monkeypatch, capsys) -> None:
    fake = FakeSocket()
    called = {}

    def connect(address, timeout):
        called.update(address=address, timeout=timeout)
        return fake

    monkeypatch.setattr(socket, "create_connection", connect)
    result = run_remote(
        monkeypatch,
        capsys,
        "network.tcp_connect",
        {"protocol": "tcp", "address": "10.250.30.10", "port": 5432, "path": None},
    )
    assert result["ok"] is True
    assert result["data"]["tcp_connected"] is True
    assert called == {"address": ("10.250.30.10", 5432), "timeout": 4}
    assert "secret" not in json.dumps(result).lower()


def test_remote_probe_rejects_metadata_address_before_socket(monkeypatch, capsys) -> None:
    def forbidden(*args, **kwargs):
        raise AssertionError("socket must not be opened")

    monkeypatch.setattr(socket, "create_connection", forbidden)
    result = run_remote(
        monkeypatch,
        capsys,
        "network.tcp_connect",
        {"protocol": "tcp", "address": "169.254.169.254", "port": 80, "path": None},
    )
    assert result["ok"] is False
    assert "endpoint address denied" in result["error"]


def test_tcp_timeout_is_recorded_as_negative_evidence(monkeypatch, capsys) -> None:
    def timeout(*args, **kwargs):
        raise TimeoutError("do not persist transport details")

    monkeypatch.setattr(socket, "create_connection", timeout)
    result = run_remote(
        monkeypatch,
        capsys,
        "network.reachability",
        {"protocol": "tcp", "address": "10.250.30.10", "port": 5432, "path": None},
    )
    assert result["ok"] is True
    assert result["data"]["reachable"] is False
    assert result["error"] == "TimeoutError"
    assert "do not persist" not in json.dumps(result)


def test_http_redirect_not_followed_and_response_body_not_recorded(monkeypatch, capsys) -> None:
    calls = []

    class Response:
        status = 302
        length = 4096

        def getheader(self, name, default=""):
            return "https://169.254.169.254/latest/meta-data" if name == "Location" else default

        def read(self, count):
            raise AssertionError("readiness probe must not read the response body")

    class Connection:
        def __init__(self, *args, **kwargs):
            calls.append(("init", args, kwargs))

        def request(self, method, path, headers):
            calls.append((method, path, headers))

        def getresponse(self):
            return Response()

        def close(self):
            calls.append(("close",))

    monkeypatch.setattr(http.client, "HTTPConnection", Connection)
    result = run_remote(
        monkeypatch,
        capsys,
        "http.readiness",
        {"protocol": "http", "address": "10.250.20.20", "port": 8080, "path": "/ready"},
    )
    assert result["data"]["http_status"] == 302
    assert result["data"]["ready"] is False
    assert result["data"]["redirect_followed"] is False
    assert result["data"]["body_bytes_sampled"] == 0
    assert len([call for call in calls if call[0] == "GET"]) == 1
    assert not any("Authorization" in call[-1] for call in calls if call[0] == "GET")


def test_https_uses_default_certificate_validation(monkeypatch, capsys) -> None:
    captured = {}

    class Response:
        status = 204

        def getheader(self, name, default=""):
            return default

        def read(self, count):
            return b""

    class Connection:
        def __init__(self, host, port, timeout, context):
            captured.update(host=host, port=port, timeout=timeout, context=context)

        def request(self, method, path, headers):
            captured["request"] = (method, path)

        def getresponse(self):
            return Response()

        def close(self):
            pass

    monkeypatch.setattr(http.client, "HTTPSConnection", Connection)
    result = run_remote(
        monkeypatch,
        capsys,
        "http.readiness",
        {"protocol": "https", "address": "10.250.20.20", "port": 8443, "path": "/health"},
    )
    assert result["data"]["ready"] is True
    assert result["data"]["tls_verified"] is True
    assert captured["context"].check_hostname is True
    assert captured["context"].verify_mode == ssl.CERT_REQUIRED


def test_postgresql_probe_only_sends_ssl_negotiation_without_auth(monkeypatch, capsys) -> None:
    fake = FakeSocket(b"S")
    monkeypatch.setattr(socket, "create_connection", lambda *args, **kwargs: fake)
    result = run_remote(
        monkeypatch,
        capsys,
        "postgresql.protocol_available",
        {"protocol": "postgresql", "address": "10.250.30.10", "port": 5432, "path": None},
    )
    assert result["data"]["protocol_available"] is True
    assert result["data"]["ssl_supported"] is True
    assert result["data"]["authentication_attempted"] is False
    assert result["data"]["database_readiness_verified"] is False
    assert fake.sent == bytes.fromhex("0000000804d2162f")


def test_probe_source_has_redirects_disabled_and_verified_tls() -> None:
    assert "ssl.create_default_context()" in REMOTE_SOURCE
    assert '"redirect_followed":False' in REMOTE_SOURCE
    assert "response.status" in REMOTE_SOURCE
