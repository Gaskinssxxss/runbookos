from __future__ import annotations

import base64
import io
import json
import os
import socket
import ssl
import struct
import subprocess
import sys
from pathlib import Path

import pytest
import yaml
from conftest import write_config_tree
from pydantic import ValidationError

from runbookos.actions import validate_action
from runbookos.engine import RunbookEngine
from runbookos.errors import ConfigurationError
from runbookos.models import ProbeTarget
from runbookos.remote import REMOTE_SOURCE
from runbookos.ssh import SSHResult

ENDPOINT = {
    "protocol": "https",
    "address": "10.20.30.40",
    "port": 443,
    "path": "/health",
    "dns_name": "service.example.test",
    "resolver_address": "10.20.30.53",
}


def remote(monkeypatch, capsys, action, endpoint=ENDPOINT, timeout=5):
    arguments = {"endpoint_id": "service_health", "_endpoint": endpoint}
    encoded = base64.b64encode(
        json.dumps({"action": action, "arguments": arguments, "timeout_seconds": timeout}).encode()
    ).decode()
    monkeypatch.setattr(sys, "argv", ["remote", encoded])
    exec(compile(REMOTE_SOURCE, "<network-diagnostic-test>", "exec"), {"__name__": "__main__"})
    return json.loads(capsys.readouterr().out)


@pytest.mark.parametrize(
    "action", ["network.dns_resolve", "network.listener", "network.tls_certificate"]
)
def test_new_endpoint_actions_have_strict_alias_only_schema(action):
    assert validate_action(action, {"endpoint_id": "service_health"}).read_only
    for bad in (
        {"endpoint_id": "https://evil.example"},
        {"endpoint_id": "service_health", "hostname": "169.254.169.254"},
        {"endpoint_id": "service_health", "command": "id; touch /tmp/untrusted"},
    ):
        with pytest.raises(ConfigurationError):
            validate_action(action, bad)
    assert validate_action(action, {"endpoint_id": "service_health"}).max_timeout_seconds <= 10


def test_endpoint_dns_configuration_is_fixed_and_private():
    assert ProbeTarget.model_validate(ENDPOINT).dns_name == "service.example.test"
    for update in (
        {"dns_name": "service.example.test;id"},
        {"dns_name": "http://service.example.test"},
        {"resolver_address": "169.254.169.254"},
        {"resolver_address": "8.8.8.8"},
        {"dns_name": None},
    ):
        with pytest.raises(ValidationError):
            ProbeTarget.model_validate({**ENDPOINT, **update})


def test_dns_and_tls_plans_require_configuration_and_protocol(tmp_path):
    paths, runbook = configured_engine(tmp_path)
    inventory = yaml.safe_load(paths.inventory.read_text())
    endpoint = inventory["hosts"]["test-web"]["probe_targets"]["service_health"]
    endpoint["dns_name"] = None
    endpoint["resolver_address"] = None
    paths.inventory.write_text(yaml.safe_dump(inventory))
    denied = RunbookEngine(paths).plan(runbook)
    assert denied.status == "denied"
    assert denied.actions[1].allowed is False
    assert denied.actions[4].allowed is False
    endpoint["dns_name"] = ENDPOINT["dns_name"]
    endpoint["resolver_address"] = ENDPOINT["resolver_address"]
    endpoint["protocol"] = "tcp"
    endpoint["path"] = None
    paths.inventory.write_text(yaml.safe_dump(inventory))
    denied_tls = RunbookEngine(paths).plan(runbook)
    assert denied_tls.actions[4].allowed is False


def configured_engine(tmp_path: Path, *, allowed=True):
    paths = write_config_tree(tmp_path)
    inventory = yaml.safe_load(paths.inventory.read_text())
    inventory["hosts"]["test-web"]["probe_targets"] = {"service_health": ENDPOINT}
    paths.inventory.write_text(yaml.safe_dump(inventory))
    policy = yaml.safe_load(paths.policy.read_text())
    policy["hosts"]["test-web"]["diagnostic_actions"].extend(
        [
            "network.routes",
            "network.dns_resolve",
            "network.listener",
            "network.tcp_connect",
            "network.tls_certificate",
        ]
    )
    policy["hosts"]["test-web"]["allowed_probe_targets"] = ["service_health"] if allowed else []
    paths.policy.write_text(yaml.safe_dump(policy))
    runbook = tmp_path / "network.yml"
    runbook.write_text(
        "api_version: runbookos/v1\nkind: Runbook\nmetadata:\n"
        "  id: network-diagnostics\n  name: Network diagnostics\n"
        "  description: Synthetic multi-signal evidence\n  risk: low\n"
        "targets: [test-web]\nsteps:\n"
        "  - id: routes\n    action: network.routes\n    timeout_seconds: 5\n"
        "  - id: dns\n    action: network.dns_resolve\n"
        "    with: {endpoint_id: service_health}\n    timeout_seconds: 5\n"
        "  - id: listener\n    action: network.listener\n"
        "    with: {endpoint_id: service_health}\n    timeout_seconds: 3\n"
        "  - id: tcp\n    action: network.tcp_connect\n"
        "    with: {endpoint_id: service_health}\n    timeout_seconds: 5\n"
        "  - id: tls\n    action: network.tls_certificate\n"
        "    with: {endpoint_id: service_health}\n    timeout_seconds: 10\n",
        encoding="utf-8",
    )
    return paths, runbook


def test_policy_denial_and_multi_fault_evidence_are_distinct(tmp_path):
    paths, runbook = configured_engine(tmp_path, allowed=False)
    assert RunbookEngine(paths).plan(runbook).status == "denied"
    policy = yaml.safe_load(paths.policy.read_text())
    policy["hosts"]["test-web"]["allowed_probe_targets"] = ["service_health"]
    paths.policy.write_text(yaml.safe_dump(policy))

    class FakeExecutor:
        def execute(self, host, action, arguments, timeout_seconds):
            assert host.role == "web-server"
            if action != "network.routes":
                assert arguments["_endpoint"]["address"] == ENDPOINT["address"]
            data = {
                "network.routes": {"routes": [{"dst": "10.20.0.0/16"}]},
                "network.dns_resolve": {"status": "mismatch", "matches_expected": False},
                "network.listener": {"listening": False, "scan_truncated": False},
                "network.tcp_connect": {"tcp_connected": False},
                "network.tls_certificate": {"certificate_status": "timeout"},
            }[action]
            return SSHResult(ok=True, data=data)

    engine = RunbookEngine(paths, executor=FakeExecutor())
    plan = engine.plan(runbook)
    assert plan.status == "ready"
    execution_id, status = engine.execute(plan.plan_id, diagnostic_only=True)
    assert status == "succeeded"
    steps = engine.store.execution(execution_id)["steps"]
    assert [step["action"] for step in steps] == [
        "network.routes",
        "network.dns_resolve",
        "network.listener",
        "network.tcp_connect",
        "network.tls_certificate",
    ]
    assert [step["evidence"]["data"] for step in steps] == [
        {"routes": [{"dst": "10.20.0.0/16"}]},
        {"status": "mismatch", "matches_expected": False},
        {"listening": False, "scan_truncated": False},
        {"tcp_connected": False},
        {"certificate_status": "timeout"},
    ]
    assert engine.store.verify_audit_chain()[0] is True


def dns_response(request, code=0, address=None):
    question = request[12:]
    header = struct.pack(
        "!HHHHHH",
        struct.unpack("!H", request[:2])[0],
        0x8180 | code,
        1,
        int(address is not None),
        0,
        0,
    )
    answer = (
        b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 30, 4) + socket.inet_aton(address)
        if address is not None
        else b""
    )
    return header + question + answer


class FakeDNS:
    def __init__(self, *, code=0, address=None, failure=None):
        self.code, self.address, self.failure = code, address, failure
        self.request = b""

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return None

    def settimeout(self, timeout):
        assert 0 < timeout <= 5

    def sendto(self, request, destination):
        assert destination == (ENDPOINT["resolver_address"], 53)
        self.request = request

    def recvfrom(self, maximum):
        assert maximum == 2049
        if self.failure:
            raise self.failure
        return dns_response(self.request, self.code, self.address), (
            ENDPOINT["resolver_address"],
            53,
        )


@pytest.mark.parametrize(
    ("code", "address", "failure", "status", "uncertain"),
    [
        (0, "10.20.30.40", None, "matched", False),
        (0, "10.20.30.41", None, "mismatch", False),
        (3, None, None, "nxdomain", False),
        (2, None, None, "resolver_failure", True),
        (0, None, socket.timeout(), "timeout", True),
    ],
)
def test_dns_response_classifies_observation_without_guessing_cause(
    monkeypatch, capsys, code, address, failure, status, uncertain
):
    monkeypatch.setattr(
        socket, "socket", lambda *args: FakeDNS(code=code, address=address, failure=failure)
    )
    result = remote(monkeypatch, capsys, "network.dns_resolve")
    assert result["ok"] is True
    assert result["data"]["status"] == status
    assert result["uncertain"] is uncertain
    assert result["data"]["matches_expected"] is (status == "matched")
    assert "root_cause" not in result["data"]


def test_dns_rejects_forged_response_and_public_endpoint(monkeypatch, capsys):
    class ForgedDNS(FakeDNS):
        def recvfrom(self, maximum):
            response, source = super().recvfrom(maximum)
            return b"\x00\x00" + response[2:], source

    monkeypatch.setattr(socket, "socket", lambda *args: ForgedDNS(address="10.20.30.40"))
    result = remote(monkeypatch, capsys, "network.dns_resolve")
    assert result["data"]["status"] == "invalid_response"
    assert result["uncertain"] is True
    public = remote(monkeypatch, capsys, "network.dns_resolve", {**ENDPOINT, "address": "8.8.8.8"})
    assert public["ok"] is False


def test_dns_rejects_truncated_response_without_claiming_nxdomain(monkeypatch, capsys):
    class TruncatedDNS(FakeDNS):
        def recvfrom(self, maximum):
            response, source = super().recvfrom(maximum)
            return response[:15], source

    monkeypatch.setattr(socket, "socket", lambda *args: TruncatedDNS(address="10.20.30.40"))
    result = remote(monkeypatch, capsys, "network.dns_resolve")
    assert result["data"]["status"] == "invalid_response"
    assert result["data"]["matches_expected"] is False
    assert result["uncertain"] is True


def test_listener_uses_only_configured_port_and_reports_absence_or_partial_scan(
    monkeypatch, capsys
):
    original_open = open

    def fake_open(path, *args, **kwargs):
        if path == "/proc/net/tcp":
            return io.StringIO("header\n0: 00000000:01BB 00000000:0000 0A\n")
        if path == "/proc/net/tcp6":
            return io.StringIO("header\n")
        return original_open(path, *args, **kwargs)

    monkeypatch.setattr("builtins.open", fake_open)
    present = remote(monkeypatch, capsys, "network.listener", timeout=3)
    assert present["data"]["listening"] is True
    assert present["data"]["status"] == "listening"
    assert present["data"]["listener_count"] == 1
    assert "address" not in present["data"]
    monkeypatch.setattr(
        "builtins.open",
        lambda path, *a, **kw: (
            io.StringIO("header\n")
            if path.startswith("/proc/net/tcp")
            else original_open(path, *a, **kw)
        ),
    )
    absent = remote(monkeypatch, capsys, "network.listener", timeout=3)
    assert absent["data"]["listening"] is False
    assert absent["data"]["status"] == "port_closed"

    monkeypatch.setattr(
        "builtins.open",
        lambda path, *a, **kw: (
            io.StringIO("header\n0: 0100007F:01BB 00000000:0000 0A\n")
            if path == "/proc/net/tcp"
            else original_open(path, *a, **kw)
        ),
    )
    mismatch = remote(monkeypatch, capsys, "network.listener", timeout=3)
    assert mismatch["data"]["status"] == "address_mismatch"
    assert mismatch["data"]["listening"] is False

    monkeypatch.setattr(
        "builtins.open",
        lambda path, *a, **kw: (
            io.StringIO("header\n" * 4100)
            if path == "/proc/net/tcp"
            else original_open(path, *a, **kw)
        ),
    )
    truncated = remote(monkeypatch, capsys, "network.listener", timeout=3)
    assert truncated["ok"] is False
    assert truncated["uncertain"] is True
    assert truncated["data"]["scan_truncated"] is True


def test_tls_reports_verified_and_invalid_certificates_without_raw_details(monkeypatch, capsys):
    class Connection:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            return None

        def settimeout(self, timeout):
            assert 0 < timeout <= 5

        def getpeercert(self):
            return {"notAfter": "Jan  1 00:00:00 2030 GMT"}

    class Context:
        def wrap_socket(self, connection, server_hostname):
            assert server_hostname == ENDPOINT["dns_name"]
            return connection

    monkeypatch.setattr(socket, "create_connection", lambda address, timeout: Connection())
    monkeypatch.setattr(ssl, "create_default_context", Context)
    good = remote(monkeypatch, capsys, "network.tls_certificate")
    assert good["data"]["certificate_status"] == "valid"
    assert good["data"]["chain_valid"] is True
    assert good["data"]["hostname_valid"] is True
    assert good["data"]["days_remaining"] > 0
    assert "subject" not in json.dumps(good).lower()

    class RejectedContext:
        def wrap_socket(self, connection, server_hostname):
            raise ssl.SSLCertVerificationError(1, "untrusted sensitive details")

    monkeypatch.setattr(ssl, "create_default_context", RejectedContext)
    rejected = remote(monkeypatch, capsys, "network.tls_certificate")
    assert rejected["data"]["certificate_status"] == "invalid_certificate"
    assert rejected["data"]["chain_valid"] is False
    assert "sensitive details" not in json.dumps(rejected)

    monkeypatch.setattr(
        socket,
        "create_connection",
        lambda address, timeout: (_ for _ in ()).throw(socket.timeout()),
    )
    timed_out = remote(monkeypatch, capsys, "network.tls_certificate")
    assert timed_out["data"]["certificate_status"] == "timeout"
    assert timed_out["uncertain"] is True
    monkeypatch.setattr(socket, "create_connection", lambda address, timeout: Connection())

    for code, status in ((10, "expired"), (20, "invalid_chain"), (62, "hostname_mismatch")):

        class SpecificRejection:
            def wrap_socket(self, connection, server_hostname):
                error = ssl.SSLCertVerificationError(1, "private certificate detail")
                error.verify_code = code
                raise error

        monkeypatch.setattr(ssl, "create_default_context", SpecificRejection)
        outcome = remote(monkeypatch, capsys, "network.tls_certificate")
        assert outcome["data"]["certificate_status"] == status
        assert outcome["data"]["chain_valid"] is False
        assert "private certificate detail" not in json.dumps(outcome)


def test_firewall_summary_is_read_only_and_unavailable_without_privilege(monkeypatch, capsys):
    assert validate_action("network.firewall_summary", {}).read_only
    with pytest.raises(ConfigurationError):
        validate_action("network.firewall_summary", {"command": "sudo nft flush ruleset"})

    def denied(*args, **kwargs):
        raise PermissionError("untrusted local reason")

    monkeypatch.setattr(subprocess, "Popen", denied)
    request = base64.b64encode(
        json.dumps(
            {"action": "network.firewall_summary", "arguments": {}, "timeout_seconds": 5}
        ).encode()
    ).decode()
    monkeypatch.setattr(sys, "argv", ["remote", request])
    exec(
        compile(REMOTE_SOURCE, "<network-firewall-dispatch-test>", "exec"), {"__name__": "__main__"}
    )
    dispatched = json.loads(capsys.readouterr().out)
    assert dispatched["ok"] is False
    assert dispatched["uncertain"] is True
    assert dispatched["error"] == "firewall_inspection_unavailable"
    assert "untrusted local reason" not in json.dumps(dispatched)
    namespace = {}
    helpers = REMOTE_SOURCE.split("\ntry:\n", 1)[0]
    exec(compile(helpers, "<network-diagnostic-helpers-test>", "exec"), namespace)
    namespace["bounded_stdout"] = lambda argv, timeout, limit: (None, "command_failed")
    unavailable, error = namespace["firewall_summary"](5)
    assert unavailable["status"] == "unavailable"
    assert error == "firewall_inspection_unavailable"
    namespace["bounded_stdout"] = lambda argv, timeout, limit: (None, "output_limit")
    limited, error = namespace["firewall_summary"](5)
    assert limited["status"] == "unavailable"
    assert error == "firewall_inspection_unavailable"
    namespace["bounded_stdout"] = lambda argv, timeout, limit: (
        json.dumps(
            {
                "nftables": [
                    {"table": {"name": "secret"}},
                    {"chain": {}},
                    {"rule": {"expr": "secret"}},
                ]
            }
        ).encode(),
        None,
    )
    summary, error = namespace["firewall_summary"](5)
    assert error is None
    assert (summary["tables"], summary["chains"], summary["rules"]) == (1, 1, 1)
    assert "secret" not in json.dumps(summary)


def test_existing_route_and_interface_inventory_uses_fixed_bounded_commands(monkeypatch, capsys):
    calls = []

    class FakeProcess:
        def __init__(self, argv, **kwargs):
            calls.append(argv)
            read_fd, write_fd = os.pipe()
            os.write(write_fd, b'[{"dst":"10.20.0.0/16"}]')
            os.close(write_fd)
            self.stdout = os.fdopen(read_fd, "rb", buffering=0)
            self.returncode = 0

        def wait(self, timeout=None):
            return 0

        def poll(self):
            return 0

        def kill(self):
            raise AssertionError("completed process must not be killed")

    monkeypatch.setattr(subprocess, "Popen", FakeProcess)
    for action, field, argv in (
        ("network.routes", "routes", ["/usr/sbin/ip", "-j", "route", "show"]),
        ("network.interfaces", "interfaces", ["/usr/sbin/ip", "-j", "address", "show"]),
    ):
        request = base64.b64encode(
            json.dumps({"action": action, "arguments": {}, "timeout_seconds": 5}).encode()
        ).decode()
        monkeypatch.setattr(sys, "argv", ["remote", request])
        exec(compile(REMOTE_SOURCE, "<network-inventory-test>", "exec"), {"__name__": "__main__"})
        result = json.loads(capsys.readouterr().out)
        assert result["ok"] is True
        assert result["data"][field] == [{"dst": "10.20.0.0/16"}]
        assert calls[-1] == argv
        assert validate_action(action, {}).max_timeout_seconds == 15
