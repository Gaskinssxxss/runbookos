from __future__ import annotations

import base64
import json
import os
import pwd
import socket
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest
import yaml
from conftest import write_config_tree
from pydantic import ValidationError

from runbookos.actions import validate_action
from runbookos.database_correlation import correlate_database
from runbookos.engine import RunbookEngine
from runbookos.errors import ConfigurationError
from runbookos.models import ProbeTarget
from runbookos.remote import REMOTE_SOURCE
from runbookos.ssh import SSHResult

REAL_POPEN = subprocess.Popen

ENDPOINT = {
    "protocol": "postgresql",
    "address": "10.21.30.40",
    "port": 5432,
    "path": None,
    "dns_name": "db.example.test",
    "resolver_address": None,
    "local_listener": False,
    "database_name": "testdb",
    "database_user": "diagnostic",
    "credential_id": "test-credential",
    "pressure_storage_ids": [],
}


def dispatch_remote(monkeypatch, capsys, action, arguments, timeout=4):
    request = {
        "action": action,
        "arguments": arguments,
        "timeout_seconds": timeout,
    }
    monkeypatch.setattr(
        sys, "argv", ["remote", base64.b64encode(json.dumps(request).encode()).decode()]
    )
    exec(compile(REMOTE_SOURCE, "<remote-test>", "exec"), {"__name__": "__main__"})
    return json.loads(capsys.readouterr().out)


def remote(monkeypatch, capsys, check="readiness", endpoint=None, timeout=4):
    return dispatch_remote(
        monkeypatch,
        capsys,
        "postgresql.inspect",
        {"endpoint_id": "db_one", "check": check, "_endpoint": endpoint or ENDPOINT},
        timeout,
    )


def authorized_files(monkeypatch, tmp_path):
    home = tmp_path / "home"
    home.mkdir(mode=0o700)
    directory = home / ".config" / "runbookos" / "pgpass"
    directory.mkdir(parents=True, mode=0o700)
    for part in (home / ".config", home / ".config" / "runbookos", directory):
        part.chmod(0o700)
    (directory / "test-credential").write_text("synthetic-only\n")
    (directory / "test-credential").chmod(0o600)
    monkeypatch.setattr(pwd, "getpwuid", lambda _: SimpleNamespace(pw_dir=str(home)))
    monkeypatch.setattr(os.path, "isfile", lambda _: True)
    return directory / "test-credential"


def response(monkeypatch, payload, returncode=0, stderr=b""):
    calls = []
    original = REAL_POPEN

    def fake_popen(argv, **kwargs):
        calls.append((argv, kwargs))
        code = (
            "import base64,sys;"
            "sys.stdout.buffer.write(base64.b64decode(sys.argv[1]));"
            "sys.stderr.buffer.write(base64.b64decode(sys.argv[2]));"
            "sys.exit(int(sys.argv[3]))"
        )
        return original(
            [
                sys.executable,
                "-c",
                code,
                base64.b64encode(payload).decode(),
                base64.b64encode(stderr).decode(),
                str(returncode),
            ],
            **kwargs,
        )

    monkeypatch.setattr(subprocess, "Popen", fake_popen)
    return calls


def test_inventory_requires_complete_pinned_sql_source():
    for key in ("dns_name", "database_name", "database_user", "credential_id"):
        invalid = dict(ENDPOINT)
        invalid[key] = None
        with pytest.raises(ValidationError):
            ProbeTarget.model_validate(invalid)
    assert ProbeTarget.model_validate(ENDPOINT).protocol == "postgresql"


@pytest.mark.parametrize("check", ["readiness", "connections", "replication", "sessions"])
def test_strict_registered_queries_and_arguments(check):
    assert validate_action(
        "postgresql.inspect", {"endpoint_id": "db_one", "check": check}
    ).read_only
    for bad in (
        {"endpoint_id": "db_one", "check": "DROP TABLE"},
        {"endpoint_id": "db_one", "check": check, "sql": "SELECT secret"},
        {"endpoint_id": "https://evil", "check": check},
    ):
        with pytest.raises(ConfigurationError):
            validate_action("postgresql.inspect", bad)


def test_plan_requires_registered_policy_allowed_database(tmp_path: Path):
    paths = write_config_tree(tmp_path)
    inventory = yaml.safe_load(paths.inventory.read_text())
    inventory["hosts"]["test-web"]["probe_targets"] = {"db_one": dict(ENDPOINT)}
    paths.inventory.write_text(yaml.safe_dump(inventory))
    runbook = tmp_path / "db.yml"
    runbook.write_text(
        "api_version: runbookos/v1\nkind: Runbook\nmetadata:\n"
        "  id: db-check\n  name: DB check\n  description: safe query\n  risk: low\n"
        "targets: [test-web]\nsteps:\n  - id: readiness\n"
        "    action: postgresql.inspect\n"
        "    with: {endpoint_id: db_one, check: readiness}\n    timeout_seconds: 5\n"
    )
    assert RunbookEngine(paths).plan(runbook).status == "denied"
    policy = yaml.safe_load(paths.policy.read_text())
    policy["hosts"]["test-web"]["diagnostic_actions"].append("postgresql.inspect")
    policy["hosts"]["test-web"]["allowed_probe_targets"] = ["db_one"]
    paths.policy.write_text(yaml.safe_dump(policy))
    assert RunbookEngine(paths).plan(runbook).status == "ready"
    inventory["hosts"]["test-web"]["probe_targets"]["db_one"]["database_name"] = None
    paths.inventory.write_text(yaml.safe_dump(inventory))
    with pytest.raises(ConfigurationError):
        RunbookEngine(paths).plan(runbook)


def test_readiness_uses_fixed_query_and_sanitized_environment(monkeypatch, capsys, tmp_path):
    authorized_files(monkeypatch, tmp_path)
    calls = response(monkeypatch, b'{"query_succeeded":true,"in_recovery":false}\n')
    result = remote(monkeypatch, capsys)
    assert result["ok"] and result["data"]["query_succeeded"]
    argv, kwargs = calls[0]
    assert argv[0] == "/usr/bin/psql" and "BEGIN" not in " ".join(argv)
    assert kwargs["env"]["PGSSLMODE"] == "verify-full"
    assert kwargs["env"]["PGPASSFILE"] == f"/proc/self/fd/{kwargs['pass_fds'][0]}"
    assert len(kwargs["pass_fds"]) == 1
    assert "default_transaction_read_only=on" in kwargs["env"]["PGOPTIONS"]
    assert "password" not in json.dumps(result).lower()


@pytest.mark.parametrize(
    ("check", "payload", "signal"),
    [
        (
            "connections",
            b'{"stats_visible":true,"active":9,"idle":1,"total":10,"max_connections":10,"superuser_reserved":1,"reserved_connections":0}',
            "possible_exhaustion",
        ),
        (
            "replication",
            b'{"stats_visible":true,"in_recovery":false,"sender_count":1,"receiver_count":0,"max_replay_lag_seconds":35}',
            "role",
        ),
        (
            "sessions",
            b'{"stats_visible":true,"active":2,"idle":3,"long_transaction_count":1,"long_query_count":1,"waiting_count":2,"oldest_transaction_seconds":450}',
            "waiting_count",
        ),
    ],
)
def test_bounded_aggregate_checks(monkeypatch, capsys, tmp_path, check, payload, signal):
    authorized_files(monkeypatch, tmp_path)
    response(monkeypatch, payload)
    result = remote(monkeypatch, capsys, check)
    assert result["ok"] and result["data"][signal]
    assert "query_text" not in json.dumps(result)
    if check == "sessions":
        assert result["data"]["long_query_count"] == 1


def test_reserved_capacity_contributes_to_pressure(monkeypatch, capsys, tmp_path):
    authorized_files(monkeypatch, tmp_path)
    response(
        monkeypatch,
        b'{"stats_visible":true,"active":6,"idle":2,"total":8,"max_connections":10,"superuser_reserved":1,"reserved_connections":1}',
    )
    result = remote(monkeypatch, capsys, "connections")
    assert result["ok"]
    assert result["data"]["possible_exhaustion"] is True
    assert result["data"]["utilization_percent"] == 80.0


@pytest.mark.parametrize(
    ("payload", "returncode", "stderr", "category"),
    [
        (b"", 1, b"28P01", "authentication_denied"),
        (b"", 1, b"42501", "permission_denied"),
        (b"not json", 0, b"", "invalid_query_response"),
        (b'{"query_succeeded":true,"in_recovery":false}\n{}', 0, b"", "invalid_query_response"),
        (b"x" * 4097, 0, b"", "output_limit_exceeded"),
    ],
)
def test_failures_are_sanitized(
    monkeypatch, capsys, tmp_path, payload, returncode, stderr, category
):
    authorized_files(monkeypatch, tmp_path)
    response(monkeypatch, payload, returncode, stderr)
    result = remote(monkeypatch, capsys)
    assert result["ok"] is False and result["error"] == category
    if stderr:
        assert stderr.decode(errors="ignore") not in json.dumps(result)


def test_missing_stats_privilege_is_unknown(monkeypatch, capsys, tmp_path):
    authorized_files(monkeypatch, tmp_path)
    response(
        monkeypatch,
        b'{"stats_visible":false,"active":1,"idle":1,"total":2,"max_connections":100,"superuser_reserved":3,"reserved_connections":0}',
    )
    result = remote(monkeypatch, capsys, "connections")
    assert result["error"] == "statistics_privilege_unavailable"
    assert "total" not in result["data"] and result["data"]["status"] == "unknown"


def test_excessive_sql_stderr_is_bounded_and_not_persisted(monkeypatch, capsys, tmp_path):
    authorized_files(monkeypatch, tmp_path)
    response(monkeypatch, b"", 1, b"secret-token-" * 100)
    result = remote(monkeypatch, capsys)
    assert result["error"] == "output_limit_exceeded"
    assert "secret-token" not in json.dumps(result)


def test_credential_metadata_failure_never_runs_sql(monkeypatch, capsys, tmp_path):
    authorized_files(monkeypatch, tmp_path).chmod(0o644)
    monkeypatch.setattr(subprocess, "Popen", lambda *a, **k: pytest.fail("SQL invoked"))
    result = remote(monkeypatch, capsys)
    assert result["error"] == "credential_unavailable"


@pytest.mark.parametrize(
    "unsafe", ["symlink_file", "symlink_directory", "public_file", "public_directory"]
)
def test_credential_path_rejects_symlinks_and_public_permissions(
    monkeypatch, capsys, tmp_path, unsafe
):
    credential = authorized_files(monkeypatch, tmp_path)
    if unsafe == "symlink_file":
        credential.rename(credential.with_name("original"))
        credential.symlink_to(credential.with_name("original"))
    elif unsafe == "symlink_directory":
        directory = credential.parent
        directory.rename(directory.with_name("original_pgpass"))
        directory.symlink_to(directory.with_name("original_pgpass"), target_is_directory=True)
    elif unsafe == "public_file":
        credential.chmod(0o644)
    else:
        credential.parent.chmod(0o755)
    monkeypatch.setattr(subprocess, "Popen", lambda *a, **k: pytest.fail("SQL invoked"))
    assert remote(monkeypatch, capsys)["error"] == "credential_unavailable"


def test_credential_inode_remains_bound_if_path_is_replaced(monkeypatch, capsys, tmp_path):
    credential = authorized_files(monkeypatch, tmp_path)
    response(monkeypatch, b'{"query_succeeded":true,"in_recovery":false}')
    fake_popen = subprocess.Popen

    def replace_after_validation(argv, **kwargs):
        fd = kwargs["pass_fds"][0]
        credential.unlink()
        credential.write_text("replacement\n")
        credential.chmod(0o600)
        assert os.pread(fd, 64, 0) == b"synthetic-only\n"
        return fake_popen(argv, **kwargs)

    monkeypatch.setattr(subprocess, "Popen", replace_after_validation)
    assert remote(monkeypatch, capsys)["ok"] is True


class ProtocolSocket:
    def __init__(self, response=b"S"):
        self.response = response

    def __enter__(self):
        return self

    def __exit__(self, *_):
        return None

    def settimeout(self, _):
        return None

    def sendall(self, _):
        return None

    def recv(self, _):
        return self.response


def test_protocol_and_sql_inspection_share_typed_endpoint(monkeypatch, capsys, tmp_path):
    authorized_files(monkeypatch, tmp_path)
    response(monkeypatch, b'{"query_succeeded":true,"in_recovery":false}')
    monkeypatch.setattr(socket, "create_connection", lambda *_a, **_k: ProtocolSocket())
    endpoint = ProbeTarget.model_validate(ENDPOINT).model_dump()
    protocol = dispatch_remote(
        monkeypatch,
        capsys,
        "postgresql.protocol_available",
        {"endpoint_id": "db_one", "_endpoint": endpoint},
    )
    inspection = dispatch_remote(
        monkeypatch,
        capsys,
        "postgresql.inspect",
        {"endpoint_id": "db_one", "check": "readiness", "_endpoint": endpoint},
    )
    assert protocol["ok"] is True and protocol["data"]["protocol_available"] is True
    assert protocol["data"]["authentication_attempted"] is False
    assert protocol["data"]["database_readiness_verified"] is False
    assert inspection["ok"] is True and inspection["data"]["query_succeeded"] is True


def test_example_runbook_executes_protocol_and_sql_on_one_authorized_alias(
    monkeypatch, capsys, tmp_path
):
    authorized_files(monkeypatch, tmp_path)
    monkeypatch.setattr(socket, "create_connection", lambda *_a, **_k: ProtocolSocket())
    paths = write_config_tree(tmp_path)
    inventory = yaml.safe_load(paths.inventory.read_text())
    inventory["hosts"]["example-db-01"] = inventory["hosts"].pop("test-web")
    inventory["hosts"]["example-db-01"]["probe_targets"] = {
        "db_main": ProbeTarget.model_validate(ENDPOINT).model_dump()
    }
    paths.inventory.write_text(yaml.safe_dump(inventory))
    policy = yaml.safe_load(paths.policy.read_text())
    policy["hosts"]["example-db-01"] = policy["hosts"].pop("test-web")
    policy["hosts"]["example-db-01"]["diagnostic_actions"] = [
        "postgresql.protocol_available",
        "postgresql.inspect",
    ]
    paths.policy.write_text(yaml.safe_dump(policy))
    example = Path(__file__).resolve().parents[1] / "examples/runbooks/database-data-review.yml"
    assert RunbookEngine(paths).plan(example).status == "denied"
    policy["hosts"]["example-db-01"]["allowed_probe_targets"] = ["db_main"]
    paths.policy.write_text(yaml.safe_dump(policy))

    payloads = {
        "readiness": b'{"query_succeeded":true,"in_recovery":false}',
        "connections": b'{"stats_visible":true,"active":1,"idle":1,"total":2,"max_connections":100,"superuser_reserved":3,"reserved_connections":0}',
        "replication": b'{"stats_visible":true,"in_recovery":false,"sender_count":0,"receiver_count":0,"max_replay_lag_seconds":null}',
        "sessions": b'{"stats_visible":true,"active":1,"idle":1,"long_transaction_count":0,"long_query_count":0,"waiting_count":0,"oldest_transaction_seconds":null}',
    }

    class Fake:
        def execute(self, host, action, arguments, timeout_seconds):
            assert arguments["endpoint_id"] == "db_main"
            assert (
                arguments["_endpoint"]
                == inventory["hosts"]["example-db-01"]["probe_targets"]["db_main"]
            )
            if action == "postgresql.inspect":
                response(monkeypatch, payloads[arguments["check"]])
            result = dispatch_remote(monkeypatch, capsys, action, arguments, timeout_seconds)
            return SSHResult(
                ok=result["ok"],
                data=result["data"],
                error=result["error"],
                uncertain=result["uncertain"],
            )

    engine = RunbookEngine(paths, executor=Fake())
    plan = engine.plan(example)
    assert plan.status == "ready"
    execution_id, status = engine.execute(plan.plan_id, diagnostic_only=True)
    assert status == "succeeded"
    execution = engine.store.execution(execution_id)
    assert len(execution["steps"]) == 5
    correlation = execution["execution"]["summary"]["database_correlation"][0]
    assert correlation["checks"]["protocol"] == "healthy"
    assert correlation["checks"]["readiness"] == "observed"
    assert engine.store.verify_audit_chain()[0] is True


@pytest.mark.parametrize(
    "action",
    [
        "postgresql.protocol_available",
        "network.tcp_connect",
        "network.reachability",
        "network.dns_resolve",
    ],
)
def test_existing_probes_accept_sql_metadata_without_confusing_health(monkeypatch, capsys, action):
    endpoint = ProbeTarget.model_validate(ENDPOINT).model_dump()
    endpoint["resolver_address"] = "10.21.30.53"
    monkeypatch.setattr(socket, "create_connection", lambda *_a, **_k: ProtocolSocket(b"X"))

    class TimeoutDNS:
        def __enter__(self):
            return self

        def __exit__(self, *_):
            return None

        def settimeout(self, _):
            return None

        def sendto(self, *_):
            return None

        def recvfrom(self, *_):
            raise TimeoutError()

    monkeypatch.setattr(socket, "socket", lambda *_a, **_k: TimeoutDNS())
    result = dispatch_remote(
        monkeypatch, capsys, action, {"endpoint_id": "db_one", "_endpoint": endpoint}
    )
    assert result["error"] != "ValueError: invalid endpoint"
    if action == "postgresql.protocol_available":
        assert result["data"]["protocol_available"] is False
        assert result["data"]["database_readiness_verified"] is False
    elif action == "network.dns_resolve":
        assert result["data"]["status"] == "timeout"


@pytest.mark.parametrize(
    "mutation",
    [
        {"unexpected": "value"},
        {"database_name": ["invalid"]},
        {"credential_id": "../escape"},
        {"pressure_storage_ids": ["a", "a"]},
        {"address": "169.254.169.254"},
    ],
)
def test_remote_rejects_invalid_complete_endpoint_before_network(monkeypatch, capsys, mutation):
    endpoint = {**ProbeTarget.model_validate(ENDPOINT).model_dump(), **mutation}
    monkeypatch.setattr(
        socket, "create_connection", lambda *_a, **_k: pytest.fail("network called")
    )
    protocol = dispatch_remote(
        monkeypatch,
        capsys,
        "postgresql.protocol_available",
        {"endpoint_id": "db_one", "_endpoint": endpoint},
    )
    inspection = dispatch_remote(
        monkeypatch,
        capsys,
        "postgresql.inspect",
        {"endpoint_id": "db_one", "check": "readiness", "_endpoint": endpoint},
    )
    assert protocol["ok"] is False and inspection["ok"] is False


def step(action, endpoint, step_id, data, status="succeeded", error=None):
    return {
        "target": "db-host",
        "action": action,
        "step_id": step_id,
        "status": status,
        "evidence": {"data": {"endpoint_id": endpoint, **data}, "error": error},
    }


def test_two_databases_and_storage_are_isolated():
    steps = [
        step(
            "postgresql.inspect",
            "db_a",
            "a",
            {"check": "connections", "query_succeeded": True, "possible_exhaustion": False},
        ),
        step(
            "postgresql.inspect",
            "db_b",
            "b",
            {"check": "connections", "query_succeeded": True, "possible_exhaustion": True},
        ),
        step(
            "filesystem.pressure", "", "storage", {"storage_id": "volume_b", "status": "byte_full"}
        ),
    ]
    a = correlate_database(steps, "db-host", "db_a", frozenset({"volume_a"}))
    b = correlate_database(steps, "db-host", "db_b", frozenset({"volume_b"}))
    assert a["observations"] == []
    assert {v["signal"] for v in b["observations"]} == {"connection_pressure", "storage_pressure"}
    assert a["verified_root_cause"] is False and b["verified_root_cause"] is False


def test_tcp_success_does_not_override_authentication_denial():
    steps = [
        step("postgresql.protocol_available", "db_a", "tcp", {"protocol_available": True}),
        step(
            "postgresql.inspect",
            "db_a",
            "sql",
            {"check": "readiness", "status": "unknown"},
            "failed",
            "authentication_denied",
        ),
    ]
    summary = correlate_database(steps, "db-host", "db_a")
    assert summary["checks"]["protocol"] == "healthy"
    assert summary["checks"]["readiness"] == "unknown"
    assert summary["observations"][0]["signal"] == "authentication_denied"


def test_engine_persists_scoped_database_evidence_and_rejects_stale_policy(tmp_path: Path):
    paths = write_config_tree(tmp_path)
    inventory = yaml.safe_load(paths.inventory.read_text())
    inventory["hosts"]["test-web"]["probe_targets"] = {"db_one": dict(ENDPOINT)}
    paths.inventory.write_text(yaml.safe_dump(inventory))
    policy = yaml.safe_load(paths.policy.read_text())
    policy["hosts"]["test-web"]["diagnostic_actions"].append("postgresql.inspect")
    policy["hosts"]["test-web"]["allowed_probe_targets"] = ["db_one"]
    paths.policy.write_text(yaml.safe_dump(policy))
    runbook = tmp_path / "db.yml"
    runbook.write_text(
        "api_version: runbookos/v1\nkind: Runbook\nmetadata:\n"
        "  id: db-check\n  name: DB check\n  description: safe query\n  risk: low\n"
        "targets: [test-web]\nsteps:\n  - id: readiness\n"
        "    action: postgresql.inspect\n"
        "    with: {endpoint_id: db_one, check: readiness}\n    timeout_seconds: 5\n"
    )

    class Fake:
        def execute(self, host, action, arguments, timeout_seconds):
            assert action == "postgresql.inspect"
            assert arguments["_endpoint"]["credential_id"] == "test-credential"
            return SSHResult(
                ok=True,
                data={
                    "endpoint_id": "db_one",
                    "check": "readiness",
                    "query_succeeded": True,
                    "in_recovery": False,
                },
            )

    engine = RunbookEngine(paths, executor=Fake())
    plan = engine.plan(runbook)
    execution_id, status = engine.execute(plan.plan_id, diagnostic_only=True)
    assert status == "succeeded"
    result = engine.store.execution(execution_id)
    assert (
        result["execution"]["summary"]["database_correlation"][0]["checks"]["readiness"]
        == "observed"
    )
    assert result["steps"][0]["evidence"]["data"]["endpoint_id"] == "db_one"
    assert engine.store.verify_audit_chain()[0] is True

    stale = engine.plan(runbook)
    policy["hosts"]["test-web"]["allowed_probe_targets"] = []
    paths.policy.write_text(yaml.safe_dump(policy))
    with pytest.raises(Exception):
        engine.execute(stale.plan_id, diagnostic_only=True)


def test_sql_timeout_and_malformed_values_fail_closed(monkeypatch, capsys, tmp_path):
    authorized_files(monkeypatch, tmp_path)
    original = REAL_POPEN

    def timeout(*args, **kwargs):
        return original([sys.executable, "-c", "import time; time.sleep(10)"], **kwargs)

    monkeypatch.setattr(subprocess, "Popen", timeout)
    assert remote(monkeypatch, capsys, timeout=1)["error"] == "query_timeout"
    response(
        monkeypatch,
        b'{"stats_visible":true,"active":1,"idle":0,"total":1,"max_connections":100,"superuser_reserved":true,"reserved_connections":0}',
    )
    assert remote(monkeypatch, capsys, "connections")["error"] == "invalid_query_response"
    response(
        monkeypatch,
        b'{"stats_visible":true,"active":1,"idle":0,"total":1,"max_connections":100,"superuser_reserved":NaN,"reserved_connections":0}',
    )
    assert remote(monkeypatch, capsys, "connections")["error"] == "invalid_query_response"
