"""Offline application and web diagnostics with registered synthetic sources only."""

from __future__ import annotations

import hashlib
import http.client
import os
import ssl
from pathlib import Path
from types import SimpleNamespace

import pytest
import yaml
from conftest import write_config_tree
from pydantic import ValidationError

from runbookos.actions import validate_action
from runbookos.application_correlation import correlate_application
from runbookos.engine import RunbookEngine
from runbookos.errors import ConfigurationError, PolicyDenied
from runbookos.models import ApplicationProfile, Host
from runbookos.remote import REMOTE_SOURCE
from runbookos.ssh import SSHResult


def remote_helpers():
    namespace = {}
    exec(compile(REMOTE_SOURCE.split("\ntry:\n", 1)[0], "<application-remote>", "exec"), namespace)
    return namespace


def profile(**updates):
    data = {
        "health_endpoint_id": "app_health",
        "dependency_endpoint_ids": ["upstream"],
        "queue_endpoint_id": "queue_health",
        "queue_max_depth": 10,
        "queue_max_age_seconds": 60,
        "worker_unit": "worker.service",
    }
    data.update(updates)
    return data


def endpoint(path="/health", *, protocol="http", name=None):
    return {
        "protocol": protocol,
        "address": "10.1.2.3",
        "port": 8080,
        "path": path,
        "dns_name": name,
        "resolver_address": None,
        "local_listener": False,
    }


class Response:
    def __init__(self, status, headers=None):
        self.status = status
        self.headers = headers or {}

    def getheader(self, name, default=None):
        return self.headers.get(name, default)


def fake_http(namespace, status, headers=None, *, failure=None):
    calls = []

    class Connection:
        def __init__(self, address, port, timeout):
            calls.append((address, port, timeout))

        def request(self, method, path, headers):
            calls.append((method, path, headers))
            if failure:
                raise failure

        def getresponse(self):
            return Response(status, headers)

        def close(self):
            pass

    namespace["http"] = SimpleNamespace(
        client=SimpleNamespace(HTTPConnection=Connection, HTTPException=http.client.HTTPException)
    )
    return calls


def http_args(action="application.health"):
    app = profile()
    key = "app_health" if action == "application.health" else "queue_health"
    return {
        "application_id": "sample_app",
        "_application": app,
        "_endpoint_id": key,
        "_endpoint": endpoint("/health" if key == "app_health" else "/metrics"),
    }


@pytest.mark.parametrize(
    "status,expected", [(200, "healthy"), (302, "redirect"), (502, "unhealthy"), (503, "unhealthy")]
)
def test_application_health_fixed_endpoint_no_body_or_secret_headers(status, expected):
    namespace = remote_helpers()
    calls = fake_http(
        namespace,
        status,
        {"Content-Type": "application/json; token=hidden", "Set-Cookie": "secret"},
    )
    data, error = namespace["application_diagnostic"]("application.health", http_args(), 3)
    assert error is None and data["status"] == expected and data["redirect_followed"] is False
    assert data["content_type_category"] == "json" and data["body_bytes_sampled"] == 0
    assert "secret" not in str(data) and "hidden" not in str(data)
    assert calls[0] == ("10.1.2.3", 8080, 3)
    assert calls[1][1] == "/health"


@pytest.mark.parametrize(
    "headers,status",
    [
        ({"X-Queue-Depth": "11", "X-Queue-Oldest-Age-Seconds": "0"}, "backlog"),
        ({"X-Queue-Depth": "2", "X-Queue-Oldest-Age-Seconds": "60"}, "healthy"),
        ({"X-Queue-Depth": "secret", "X-Queue-Oldest-Age-Seconds": "2"}, "unknown"),
        ({"X-Queue-Depth": "9999999", "X-Queue-Oldest-Age-Seconds": "2"}, "unknown"),
    ],
)
def test_queue_metrics_only_accept_bounded_numeric_headers(headers, status):
    namespace = remote_helpers()
    fake_http(namespace, 200, headers)
    data, error = namespace["application_diagnostic"](
        "application.queue_health", http_args("application.queue_health"), 3
    )
    assert error is None and data["status"] == status
    assert "secret" not in str(data)


def test_application_timeout_and_invalid_endpoint_fail_closed():
    namespace = remote_helpers()
    fake_http(namespace, 200, failure=TimeoutError())
    data, error = namespace["application_diagnostic"]("application.health", http_args(), 2)
    assert error == "timeout" and data["status"] == "unknown"
    args = http_args()
    args["_endpoint"]["address"] = "169.254.169.254"
    with pytest.raises(ValueError, match="endpoint denied"):
        namespace["application_diagnostic"]("application.health", args, 2)
    args = http_args()
    args["_endpoint"]["path"] = "/redirect/../secret"
    with pytest.raises(ValueError, match="endpoint denied"):
        namespace["application_diagnostic"]("application.health", args, 2)


def test_https_uses_pinned_name_and_reports_tls_failure():
    namespace = remote_helpers()

    class Connection:
        def __init__(self, address, port, timeout):
            assert address == "10.1.2.3"
            self.sock = object()

        def connect(self):
            pass

        def close(self):
            pass

    class Context:
        def wrap_socket(self, sock, server_hostname):
            assert server_hostname == "app.example.test"
            raise ssl.SSLError("certificate expired; private detail")

    namespace["http"] = SimpleNamespace(
        client=SimpleNamespace(HTTPConnection=Connection, HTTPException=http.client.HTTPException)
    )
    namespace["ssl"] = SimpleNamespace(create_default_context=Context, SSLError=ssl.SSLError)
    args = http_args()
    args["_endpoint"] = endpoint(protocol="https", name="app.example.test")
    data, error = namespace["application_diagnostic"]("application.health", args, 2)
    assert error == "tls_invalid" and data["status"] == "unknown"
    assert "private detail" not in str(data)


def file_args(path, action, **updates):
    app = profile(
        config_storage_id="config_file",
        expected_config_sha256="0" * 64,
        version_storage_id="version_file",
        expected_version="1.2.3",
    )
    app.update(updates)
    storage_id = "config_file" if action == "application.config_fingerprint" else "version_file"
    return {
        "application_id": "sample_app",
        "_application": app,
        "_storage_id": storage_id,
        "_storage": {"path": str(path), "kind": "file"},
    }


def test_config_fingerprint_and_version_are_metadata_only(tmp_path):
    namespace = remote_helpers()
    config = tmp_path / "config"
    config.write_bytes(b"non-secret-config")
    digest = hashlib.sha256(config.read_bytes()).hexdigest()
    args = file_args(config, "application.config_fingerprint", expected_config_sha256=digest)
    data, error = namespace["application_diagnostic"]("application.config_fingerprint", args, 3)
    assert error is None and data["status"] == "matched" and "non-secret-config" not in str(data)
    args["_application"]["expected_config_sha256"] = "0" * 64
    data, error = namespace["application_diagnostic"]("application.config_fingerprint", args, 3)
    assert error is None and data["status"] == "drift"
    version = tmp_path / "version"
    version.write_text("1.2.3\n")
    data, error = namespace["application_diagnostic"](
        "application.deploy_version", file_args(version, "application.deploy_version"), 3
    )
    assert error is None and data["status"] == "matched" and data["version"] == "1.2.3"


def test_artifact_symlink_oversize_and_wrong_binding_are_unknown_or_rejected(tmp_path):
    namespace = remote_helpers()
    secret = tmp_path / "secret"
    secret.write_text("secret")
    link = tmp_path / "link"
    link.symlink_to(secret)
    args = file_args(link, "application.config_fingerprint")
    data, error = namespace["application_diagnostic"]("application.config_fingerprint", args, 3)
    assert error == "artifact_unavailable" and data["status"] == "unknown"
    large = tmp_path / "large"
    large.write_bytes(b"x" * 65537)
    data, error = namespace["application_diagnostic"](
        "application.config_fingerprint", file_args(large, "application.config_fingerprint"), 3
    )
    assert error == "artifact_unavailable" and data["status"] == "unknown"
    pipe = tmp_path / "pipe"
    os.mkfifo(pipe)
    data, error = namespace["application_diagnostic"](
        "application.config_fingerprint", file_args(pipe, "application.config_fingerprint"), 3
    )
    assert error == "artifact_unavailable" and data["status"] == "unknown"
    args = file_args(secret, "application.config_fingerprint")
    args["_storage_id"] = "other"
    with pytest.raises(ValueError, match="binding denied"):
        namespace["application_diagnostic"]("application.config_fingerprint", args, 3)
    args = file_args(secret, "application.config_fingerprint")
    args["_storage"]["path"] = str(tmp_path / ".." / "secret")
    with pytest.raises(ValueError, match="path denied"):
        namespace["application_diagnostic"]("application.config_fingerprint", args, 3)


def test_artifact_permission_denied_is_unknown(tmp_path):
    namespace = remote_helpers()
    config = tmp_path / "config"
    config.write_text("safe")
    original_open = os.open
    replacement = SimpleNamespace(**vars(os))

    def denied_open(path, flags, *args, **kwargs):
        if path == "config":
            raise PermissionError("private detail")
        return original_open(path, flags, *args, **kwargs)

    replacement.open = denied_open
    namespace["os"] = replacement
    data, error = namespace["application_diagnostic"](
        "application.config_fingerprint", file_args(config, "application.config_fingerprint"), 3
    )
    assert error == "artifact_unavailable" and data["status"] == "unknown"
    assert "private detail" not in str(data)


def configured_engine(tmp_path: Path):
    paths = write_config_tree(tmp_path)
    config = tmp_path / "app-config"
    config.write_text("safe")
    version = tmp_path / "app-version"
    version.write_text("1.2.3")
    inventory = yaml.safe_load(paths.inventory.read_text())
    host = inventory["hosts"]["test-web"]
    host["probe_targets"] = {
        "app_health": endpoint(),
        "queue_health": endpoint("/metrics"),
        "upstream": {"protocol": "tcp", "address": "10.1.2.4", "port": 9000},
    }
    host["storage_targets"] = {
        "config_file": {"path": str(config), "kind": "file"},
        "version_file": {"path": str(version), "kind": "file"},
    }
    host["applications"] = {
        "sample_app": profile(
            config_storage_id="config_file",
            expected_config_sha256=hashlib.sha256(b"safe").hexdigest(),
            version_storage_id="version_file",
            expected_version="1.2.3",
        )
    }
    paths.inventory.write_text(yaml.safe_dump(inventory))
    policy = yaml.safe_load(paths.policy.read_text())
    host_policy = policy["hosts"]["test-web"]
    host_policy["diagnostic_actions"] = [
        "application.health",
        "application.queue_health",
        "application.config_fingerprint",
        "application.deploy_version",
        "network.tcp_connect",
        "systemd.service_status",
    ]
    host_policy["allowed_applications"] = ["sample_app"]
    host_policy["allowed_probe_targets"] = ["app_health", "queue_health", "upstream"]
    host_policy["allowed_storage_targets"] = ["config_file", "version_file"]
    host_policy["allowed_units"] = ["worker.service"]
    paths.policy.write_text(yaml.safe_dump(policy))
    return paths


def runbook(tmp_path, steps):
    path = tmp_path / "app-review.yml"
    path.write_text(
        yaml.safe_dump(
            {
                "api_version": "runbookos/v1",
                "kind": "Runbook",
                "metadata": {
                    "id": "app-review",
                    "name": "Application review",
                    "description": "Synthetic review",
                    "risk": "low",
                },
                "targets": ["test-web"],
                "steps": steps,
            }
        )
    )
    return path


def test_policy_scope_and_stale_plan(tmp_path):
    paths = configured_engine(tmp_path)
    app_runbook = runbook(
        tmp_path,
        [
            {
                "id": "health",
                "action": "application.health",
                "with": {"application_id": "sample_app"},
                "timeout_seconds": 3,
            }
        ],
    )
    plan = RunbookEngine(paths).plan(app_runbook)
    assert plan.status == "ready"
    policy = yaml.safe_load(paths.policy.read_text())
    policy["hosts"]["test-web"]["allowed_probe_targets"].remove("app_health")
    paths.policy.write_text(yaml.safe_dump(policy))
    assert RunbookEngine(paths).plan(app_runbook).status == "denied"
    with pytest.raises(PolicyDenied, match="configuration changed"):
        RunbookEngine(paths).execute(plan.plan_id, diagnostic_only=True)
    policy["hosts"]["test-web"]["allowed_probe_targets"].append("app_health")
    policy["hosts"]["test-web"]["allowed_applications"] = []
    paths.policy.write_text(yaml.safe_dump(policy))
    assert RunbookEngine(paths).plan(app_runbook).status == "denied"


@pytest.mark.parametrize(
    ("action", "blocked_key", "blocked_value"),
    [
        ("application.queue_health", "allowed_probe_targets", "queue_health"),
        ("application.config_fingerprint", "allowed_storage_targets", "config_file"),
        ("application.deploy_version", "allowed_storage_targets", "version_file"),
    ],
)
def test_every_application_source_requires_separate_policy_allow(
    tmp_path, action, blocked_key, blocked_value
):
    paths = configured_engine(tmp_path)
    app_runbook = runbook(
        tmp_path,
        [
            {
                "id": "inspect",
                "action": action,
                "with": {"application_id": "sample_app"},
                "timeout_seconds": 3,
            }
        ],
    )
    assert RunbookEngine(paths).plan(app_runbook).status == "ready"
    policy = yaml.safe_load(paths.policy.read_text())
    policy["hosts"]["test-web"][blocked_key].remove(blocked_value)
    paths.policy.write_text(yaml.safe_dump(policy))
    assert RunbookEngine(paths).plan(app_runbook).status == "denied"


def test_changed_inventory_invalidates_application_plan(tmp_path):
    paths = configured_engine(tmp_path)
    app_runbook = runbook(
        tmp_path,
        [
            {
                "id": "health",
                "action": "application.health",
                "with": {"application_id": "sample_app"},
                "timeout_seconds": 3,
            }
        ],
    )
    plan = RunbookEngine(paths).plan(app_runbook)
    inventory = yaml.safe_load(paths.inventory.read_text())
    inventory["hosts"]["test-web"]["probe_targets"]["app_health"]["port"] = 8081
    paths.inventory.write_text(yaml.safe_dump(inventory))
    with pytest.raises(PolicyDenied, match="configuration changed"):
        RunbookEngine(paths).execute(plan.plan_id, diagnostic_only=True)


def test_schema_rejects_unregistered_source_and_arbitrary_arguments(tmp_path):
    paths = configured_engine(tmp_path)
    inventory = yaml.safe_load(paths.inventory.read_text())
    inventory["hosts"]["test-web"]["applications"]["sample_app"]["health_endpoint_id"] = "missing"
    with pytest.raises(ValidationError):
        Host.model_validate(inventory["hosts"]["test-web"])
    for invalid_storage_id in ("missing", "config_file"):
        invalid = yaml.safe_load(paths.inventory.read_text())["hosts"]["test-web"]
        invalid["applications"]["sample_app"]["pressure_storage_ids"] = [invalid_storage_id]
        with pytest.raises(ValidationError):
            Host.model_validate(invalid)
    with pytest.raises(ConfigurationError):
        validate_action(
            "application.health", {"application_id": "sample_app", "url": "http://evil.test/"}
        )
    with pytest.raises(ConfigurationError):
        validate_action("application.health", {"application_id": "sample_app", "command": "id"})
    with pytest.raises(ValidationError):
        ApplicationProfile.model_validate(profile(queue_endpoint_id=None))


def test_engine_persists_application_evidence_and_conservative_correlation(tmp_path):
    paths = configured_engine(tmp_path)
    steps = [
        {
            "id": "health",
            "action": "application.health",
            "with": {"application_id": "sample_app"},
            "timeout_seconds": 3,
        },
        {
            "id": "upstream",
            "action": "network.tcp_connect",
            "with": {"endpoint_id": "upstream"},
            "timeout_seconds": 3,
        },
        {
            "id": "worker",
            "action": "systemd.service_status",
            "with": {"unit": "worker.service"},
            "timeout_seconds": 3,
        },
    ]

    class Fake:
        def execute(self, host, action, arguments, timeout_seconds):
            if action == "application.health":
                assert arguments["_endpoint_id"] == "app_health"
                return SSHResult(
                    ok=True,
                    data={
                        "application_id": "sample_app",
                        "http_status": 503,
                        "status": "unhealthy",
                    },
                )
            if action == "network.tcp_connect":
                return SSHResult(ok=True, data={"endpoint_id": "upstream", "connected": False})
            return SSHResult(ok=True, data={"unit": "worker.service", "active": False})

    engine = RunbookEngine(paths, executor=Fake())
    plan = engine.plan(runbook(tmp_path, steps))
    assert plan.status == "ready"
    execution_id, status = engine.execute(plan.plan_id, diagnostic_only=True)
    assert status == "succeeded"
    execution = engine.store.execution(execution_id)
    summary = execution["execution"]["summary"]["application_correlation"][0]
    assert summary["dependencies"] == {"upstream": "unhealthy"}
    assert {signal["signal"] for signal in summary["signals"]} == {
        "http_gateway_unavailable",
        "upstream_unavailable",
        "worker_stopped",
    }
    assert summary["verified_root_cause"] is False
    assert engine.store.verify_audit_chain()[0] is True


def test_offline_end_to_end_registered_application_sources(tmp_path):
    paths = configured_engine(tmp_path)
    namespace = remote_helpers()
    fake_http(
        namespace,
        200,
        {
            "Content-Type": "application/json",
            "X-Queue-Depth": "2",
            "X-Queue-Oldest-Age-Seconds": "5",
        },
    )
    steps = [
        {
            "id": action.split(".")[-1],
            "action": action,
            "with": {"application_id": "sample_app"},
            "timeout_seconds": 3,
        }
        for action in (
            "application.config_fingerprint",
            "application.deploy_version",
            "application.health",
            "application.queue_health",
        )
    ]
    steps.append(
        {
            "id": "upstream",
            "action": "network.tcp_connect",
            "with": {"endpoint_id": "upstream"},
            "timeout_seconds": 3,
        }
    )

    class Fake:
        def execute(self, host, action, arguments, timeout_seconds):
            if action == "network.tcp_connect":
                assert arguments["_endpoint"]["address"] == "10.1.2.4"
                return SSHResult(ok=True, data={"endpoint_id": "upstream", "connected": True})
            data, error = namespace["application_diagnostic"](action, arguments, timeout_seconds)
            return SSHResult(
                ok=error is None, data=data, error=error, uncertain=data["status"] == "unknown"
            )

    engine = RunbookEngine(paths, executor=Fake())
    plan = engine.plan(runbook(tmp_path, steps))
    assert plan.status == "ready"
    execution_id, status = engine.execute(plan.plan_id, diagnostic_only=True)
    assert status == "succeeded"
    persisted = engine.store.execution(execution_id)
    assert len(persisted["steps"]) == 5
    assert persisted["execution"]["summary"]["application_correlation"][0]["dependencies"] == {
        "upstream": "healthy"
    }
    assert engine.store.verify_audit_chain()[0] is True


def test_missing_dependency_and_unknown_never_become_healthy():
    result = correlate_application(
        [], "test-web", "sample_app", ApplicationProfile.model_validate(profile())
    )
    assert result["dependencies"] == {"upstream": "missing"}
    assert result["verified_root_cause"] is False
    timed_out = [
        {
            "target": "test-web",
            "action": "network.tcp_connect",
            "step_id": "dependency",
            "status": "succeeded",
            "evidence": {
                "error": "TimeoutError",
                "data": {"endpoint_id": "upstream", "connected": False},
            },
        }
    ]
    result = correlate_application(
        timed_out, "test-web", "sample_app", ApplicationProfile.model_validate(profile())
    )
    assert result["dependencies"] == {"upstream": "unknown"}
    assert result["signals"] == []


def test_multifault_correlation_keeps_observations_separate_from_cause():
    items = [
        (
            "application.queue_health",
            "queue",
            {"application_id": "sample_app", "status": "backlog"},
        ),
        (
            "application.config_fingerprint",
            "config",
            {"application_id": "sample_app", "status": "drift"},
        ),
        (
            "network.tls_certificate",
            "tls",
            {"endpoint_id": "app_health", "certificate_status": "expired"},
        ),
        ("network.listener", "listener", {"endpoint_id": "app_health", "status": "port_closed"}),
        ("filesystem.pressure", "pressure", {"storage_id": "app_pressure", "status": "inode_full"}),
    ]
    steps = [
        {
            "target": "test-web",
            "action": action,
            "step_id": step_id,
            "status": "succeeded",
            "evidence": {"data": data},
        }
        for action, step_id, data in items
    ]
    result = correlate_application(
        steps,
        "test-web",
        "sample_app",
        ApplicationProfile.model_validate(profile(pressure_storage_ids=["app_pressure"])),
        frozenset({"app_pressure"}),
    )
    assert {item["signal"] for item in result["signals"]} == {
        "queue_backlog",
        "config_drift",
        "tls_invalid",
        "listener_unavailable",
        "resource_pressure",
    }
    assert result["verified_root_cause"] is False


@pytest.mark.parametrize(
    ("storage_id", "status", "step_status", "authorized", "expected_signal"),
    [
        (None, "byte_full", "succeeded", True, "storage_pressure"),
        ("unknown_storage", "inode_full", "succeeded", True, "storage_pressure"),
        ("app_pressure", "byte_full", "succeeded", False, "storage_pressure"),
        ("app_pressure", "unknown", "unknown", True, None),
        (None, "unknown", "unknown", True, None),
        ("app_pressure", "both_full", "succeeded", True, "resource_pressure"),
        ("app_pressure", "available", "succeeded", True, None),
    ],
)
def test_pressure_requires_authorized_application_storage_mapping(
    storage_id, status, step_status, authorized, expected_signal
):
    data = {"status": status}
    if storage_id is not None:
        data["storage_id"] = storage_id
    steps = [
        {
            "target": "test-web",
            "action": "filesystem.pressure",
            "step_id": "pressure",
            "status": step_status,
            "evidence": {"data": data},
        }
    ]
    result = correlate_application(
        steps,
        "test-web",
        "sample_app",
        ApplicationProfile.model_validate(profile(pressure_storage_ids=["app_pressure"])),
        frozenset({"app_pressure"}) if authorized else frozenset(),
    )
    specific = {entry["signal"] for entry in result["signals"]}
    context = {entry["signal"] for entry in result["host_context"]}
    if expected_signal == "resource_pressure":
        assert specific == {"resource_pressure"} and context == set()
    elif expected_signal == "storage_pressure":
        assert specific == set() and context == {"storage_pressure"}
        assert result["host_context"][0]["scope"] == "host_context"
        assert result["host_context"][0]["step_id"] == "pressure"
    else:
        assert specific == set()
        if status == "unknown":
            assert result["unknown_steps"] == ["pressure"]
    assert result["verified_root_cause"] is False


def test_two_applications_on_one_host_keep_storage_pressure_attribution(tmp_path):
    paths = configured_engine(tmp_path)
    inventory = yaml.safe_load(paths.inventory.read_text())
    host = inventory["hosts"]["test-web"]
    host["probe_targets"]["other_health"] = endpoint("/other-health")
    for storage_id in ("app_pressure", "other_pressure"):
        directory = tmp_path / storage_id
        directory.mkdir()
        host["storage_targets"][storage_id] = {"path": str(directory), "kind": "directory"}
    host["applications"]["sample_app"]["pressure_storage_ids"] = ["app_pressure"]
    host["applications"]["other_app"] = profile(
        health_endpoint_id="other_health", pressure_storage_ids=["other_pressure"]
    )
    paths.inventory.write_text(yaml.safe_dump(inventory))
    policy = yaml.safe_load(paths.policy.read_text())
    host_policy = policy["hosts"]["test-web"]
    host_policy["allowed_applications"].append("other_app")
    host_policy["allowed_probe_targets"].append("other_health")
    host_policy["allowed_storage_targets"].extend(["app_pressure", "other_pressure"])
    host_policy["diagnostic_actions"].append("filesystem.pressure")
    paths.policy.write_text(yaml.safe_dump(policy))
    steps = [
        {
            "id": "healthy_app",
            "action": "application.health",
            "with": {"application_id": "sample_app"},
            "timeout_seconds": 3,
        },
        {
            "id": "other_pressure",
            "action": "filesystem.pressure",
            "with": {"storage_id": "other_pressure"},
            "timeout_seconds": 3,
        },
    ]

    class Fake:
        def execute(self, host, action, arguments, timeout_seconds):
            if action == "application.health":
                return SSHResult(
                    ok=True,
                    data={
                        "application_id": "sample_app",
                        "status": "healthy",
                        "http_status": 200,
                    },
                )
            assert arguments["_storage"]["path"] == str(tmp_path / "other_pressure")
            return SSHResult(ok=True, data={"storage_id": "other_pressure", "status": "byte_full"})

    engine = RunbookEngine(paths, executor=Fake())
    plan = engine.plan(runbook(tmp_path, steps))
    assert plan.status == "ready"
    execution_id, status = engine.execute(plan.plan_id, diagnostic_only=True)
    assert status == "succeeded"
    summaries = {
        item["application_id"]: item
        for item in engine.store.execution(execution_id)["execution"]["summary"][
            "application_correlation"
        ]
    }
    assert summaries["sample_app"]["health"] == {
        "status": "healthy",
        "http_status": 200,
        "step_id": "healthy_app",
    }
    assert summaries["sample_app"]["signals"] == []
    assert summaries["sample_app"]["host_context"][0]["storage_id"] == "other_pressure"
    assert summaries["other_app"]["signals"] == [
        {
            "signal": "resource_pressure",
            "step_id": "other_pressure",
            "claim_status": "observed",
        }
    ]
    assert summaries["other_app"]["health"]["status"] == "missing"
    assert all(not item["verified_root_cause"] for item in summaries.values())
    assert engine.store.verify_audit_chain()[0] is True


def test_http_503_probe_execution_succeeds_but_observed_service_is_unhealthy(tmp_path):
    paths = configured_engine(tmp_path)
    namespace = remote_helpers()
    fake_http(namespace, 503, {"Content-Type": "text/plain"})
    steps = [
        {
            "id": "health",
            "action": "application.health",
            "with": {"application_id": "sample_app"},
            "timeout_seconds": 3,
        }
    ]

    class Fake:
        def execute(self, host, action, arguments, timeout_seconds):
            data, error = namespace["application_diagnostic"](action, arguments, timeout_seconds)
            return SSHResult(ok=error is None, data=data, error=error)

    engine = RunbookEngine(paths, executor=Fake())
    plan = engine.plan(runbook(tmp_path, steps))
    assert plan.status == "ready"
    execution_id, status = engine.execute(plan.plan_id, diagnostic_only=True)
    assert status == "succeeded"  # The read-only measurement completed.
    detail = engine.store.execution(execution_id)
    assert detail["steps"][0]["status"] == "succeeded"
    assert detail["steps"][0]["evidence"]["data"]["status"] == "unhealthy"
    summary = detail["execution"]["summary"]["application_correlation"][0]
    assert summary["health"] == {"status": "unhealthy", "http_status": 503, "step_id": "health"}
    assert summary["signals"] == [
        {
            "signal": "http_gateway_unavailable",
            "step_id": "health",
            "claim_status": "observed",
        }
    ]
    assert summary["verified_root_cause"] is False
