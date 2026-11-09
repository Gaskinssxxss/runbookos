from __future__ import annotations

import base64
import json
import os
import stat
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


def remote(monkeypatch, capsys, check="readiness", endpoint=None, timeout=4):
    request = {
        "action": "postgresql.inspect",
        "arguments": {
            "endpoint_id": "db_one",
            "check": check,
            "_endpoint": endpoint or ENDPOINT,
        },
        "timeout_seconds": timeout,
    }
    monkeypatch.setattr(
        sys, "argv", ["remote", base64.b64encode(json.dumps(request).encode()).decode()]
    )
    exec(compile(REMOTE_SOURCE, "<remote-test>", "exec"), {"__name__": "__main__"})
    return json.loads(capsys.readouterr().out)


def authorized_files(monkeypatch):
    monkeypatch.setattr(
        os,
        "lstat",
        lambda _: SimpleNamespace(
            st_mode=stat.S_IFREG | 0o600
            if str(_).endswith("test-credential")
            else stat.S_IFDIR | 0o700,
            st_uid=os.getuid(),
            st_size=10,
        ),
    )
    monkeypatch.setattr(os.path, "isfile", lambda _: True)


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


def test_readiness_uses_fixed_query_and_sanitized_environment(monkeypatch, capsys):
    authorized_files(monkeypatch)
    calls = response(monkeypatch, b'{"query_succeeded":true,"in_recovery":false}\n')
    result = remote(monkeypatch, capsys)
    assert result["ok"] and result["data"]["query_succeeded"]
    argv, kwargs = calls[0]
    assert argv[0] == "/usr/bin/psql" and "BEGIN" not in " ".join(argv)
    assert kwargs["env"]["PGSSLMODE"] == "verify-full"
    assert "default_transaction_read_only=on" in kwargs["env"]["PGOPTIONS"]
    assert "password" not in json.dumps(result).lower()


@pytest.mark.parametrize(
    ("check", "payload", "signal"),
    [
        (
            "connections",
            b'{"stats_visible":true,"active":9,"idle":1,"total":10,"max_connections":10,"superuser_reserved":1}',
            "possible_exhaustion",
        ),
        (
            "replication",
            b'{"stats_visible":true,"in_recovery":false,"sender_count":1,"receiver_count":0,"max_replay_lag_seconds":35}',
            "role",
        ),
        (
            "sessions",
            b'{"stats_visible":true,"active":2,"idle":3,"long_transaction_count":1,"waiting_count":2,"oldest_transaction_seconds":450}',
            "waiting_count",
        ),
    ],
)
def test_bounded_aggregate_checks(monkeypatch, capsys, check, payload, signal):
    authorized_files(monkeypatch)
    response(monkeypatch, payload)
    result = remote(monkeypatch, capsys, check)
    assert result["ok"] and result["data"][signal]
    assert "query_text" not in json.dumps(result)


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
def test_failures_are_sanitized(monkeypatch, capsys, payload, returncode, stderr, category):
    authorized_files(monkeypatch)
    response(monkeypatch, payload, returncode, stderr)
    result = remote(monkeypatch, capsys)
    assert result["ok"] is False and result["error"] == category
    if stderr:
        assert stderr.decode(errors="ignore") not in json.dumps(result)


def test_missing_stats_privilege_is_unknown(monkeypatch, capsys):
    authorized_files(monkeypatch)
    response(
        monkeypatch,
        b'{"stats_visible":false,"active":1,"idle":1,"total":2,"max_connections":100,"superuser_reserved":3}',
    )
    result = remote(monkeypatch, capsys, "connections")
    assert result["error"] == "statistics_privilege_unavailable"
    assert "total" not in result["data"] and result["data"]["status"] == "unknown"


def test_excessive_sql_stderr_is_bounded_and_not_persisted(monkeypatch, capsys):
    authorized_files(monkeypatch)
    response(monkeypatch, b"", 1, b"secret-token-" * 100)
    result = remote(monkeypatch, capsys)
    assert result["error"] == "output_limit_exceeded"
    assert "secret-token" not in json.dumps(result)


def test_credential_metadata_failure_never_runs_sql(monkeypatch, capsys):
    monkeypatch.setattr(os, "lstat", lambda _: (_ for _ in ()).throw(FileNotFoundError()))
    monkeypatch.setattr(subprocess, "Popen", lambda *a, **k: pytest.fail("SQL invoked"))
    result = remote(monkeypatch, capsys)
    assert result["error"] == "credential_unavailable"


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


def test_sql_timeout_and_malformed_values_fail_closed(monkeypatch, capsys):
    authorized_files(monkeypatch)
    original = REAL_POPEN

    def timeout(*args, **kwargs):
        return original([sys.executable, "-c", "import time; time.sleep(10)"], **kwargs)

    monkeypatch.setattr(subprocess, "Popen", timeout)
    assert remote(monkeypatch, capsys, timeout=1)["error"] == "query_timeout"
    response(
        monkeypatch,
        b'{"stats_visible":true,"active":1,"idle":0,"total":1,"max_connections":100,"superuser_reserved":true}',
    )
    assert remote(monkeypatch, capsys, "connections")["error"] == "invalid_query_response"
    response(
        monkeypatch,
        b'{"stats_visible":true,"active":1,"idle":0,"total":1,"max_connections":100,"superuser_reserved":NaN}',
    )
    assert remote(monkeypatch, capsys, "connections")["error"] == "invalid_query_response"
