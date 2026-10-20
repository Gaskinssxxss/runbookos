from __future__ import annotations

import json
import threading
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest
import yaml
from conftest import write_config_tree

from runbookos.engine import RunbookEngine
from runbookos.errors import ApprovalError, ConfigurationError, PolicyDenied
from runbookos.ssh import SSHResult


class ScriptedExecutor:
    def __init__(self, results: list[SSHResult | BaseException]) -> None:
        self.results = list(results)
        self.calls: list[tuple[str, str]] = []
        self.lock = threading.Lock()

    def execute(self, host, action, arguments, timeout_seconds) -> SSHResult:
        with self.lock:
            self.calls.append((host.role, action))
            result = self.results.pop(0)
        if isinstance(result, BaseException):
            raise result
        return result


def _result(data: dict, *, ok: bool = True, uncertain: bool = False) -> SSHResult:
    return SSHResult(ok, data, None if ok else "fixture failure", uncertain, 0.01)


def _approved(paths, executor: ScriptedExecutor):
    engine = RunbookEngine(paths, executor=executor)
    plan = engine.plan(paths.database.parent.parent / "runbook.yml")
    assert plan.status == "approval_required"
    approval_id = engine.approve(plan.plan_id, "test-operator", "approved disposable fixture")
    return engine, plan, approval_id


def _assert_audit(engine: RunbookEngine) -> None:
    valid, count = engine.store.verify_audit_chain()
    assert valid and count > 0


def test_precondition_failure_blocks_mutation_and_records_not_executed(tmp_path: Path) -> None:
    paths = write_config_tree(tmp_path, remediation=True)
    executor = ScriptedExecutor([_result({"active": False})])
    engine, plan, _ = _approved(paths, executor)

    execution_id, status = engine.execute(
        plan.plan_id, confirm_remediation=True, confirming_actor="test-operator"
    )

    assert status == "failed"
    assert [action for _, action in executor.calls] == ["systemd.is_active"]
    execution = engine.store.execution(execution_id)
    assert execution["execution"]["summary"]["remediation_outcome"] == "NOT_EXECUTED"
    _assert_audit(engine)


def test_uncertain_mutation_is_unknown_and_never_retried(tmp_path: Path) -> None:
    from runbookos.errors import ExecutionUnknown

    paths = write_config_tree(tmp_path, remediation=True)
    executor = ScriptedExecutor(
        [_result({"active": True}), ExecutionUnknown("timed out after dispatch")]
    )
    engine, plan, _ = _approved(paths, executor)
    execution_id, status = engine.execute(
        plan.plan_id, confirm_remediation=True, confirming_actor="test-operator"
    )

    assert status == "unknown"
    assert [action for _, action in executor.calls] == [
        "systemd.is_active",
        "systemd.restart",
    ]
    execution = engine.store.execution(execution_id)
    assert execution["execution"]["summary"]["remediation_outcome"] == "UNKNOWN"
    assert execution["steps"][-1]["evidence"]["retry"] is False
    _assert_audit(engine)


def test_interruption_after_dispatch_is_persisted_unknown(tmp_path: Path) -> None:
    paths = write_config_tree(tmp_path, remediation=True)
    executor = ScriptedExecutor([_result({"active": True}), SystemExit("simulated process stop")])
    engine, plan, _ = _approved(paths, executor)

    with pytest.raises(SystemExit, match="simulated process stop"):
        engine.execute(plan.plan_id, confirm_remediation=True, confirming_actor="test-operator")

    history = engine.store.history()
    assert len(history) == 1
    assert history[0]["status"] == "running"
    assert history[0]["summary"]["remediation_outcome"] == "UNKNOWN"
    with engine.store._connection() as db:
        dispatches = db.execute(
            "SELECT payload_json FROM audit_events WHERE kind='remediation.dispatching'"
        ).fetchall()
    assert len(dispatches) == 1
    assert json.loads(dispatches[0][0])["action"] == "systemd.restart"
    _assert_audit(engine)


def test_postflight_failure_is_persisted_as_verified_failure(tmp_path: Path) -> None:
    paths = write_config_tree(tmp_path, remediation=True)
    executor = ScriptedExecutor(
        [
            _result({"active": True}),
            _result({"restarted": True}),
            _result({"active": False}),
        ]
    )
    engine, plan, _ = _approved(paths, executor)
    execution_id, status = engine.execute(
        plan.plan_id, confirm_remediation=True, confirming_actor="test-operator"
    )

    assert status == "failed"
    execution = engine.store.execution(execution_id)
    assert execution["execution"]["summary"]["remediation_outcome"] == "VERIFIED_FAILURE"
    assert execution["steps"][-1]["phase"] == "postflight"
    assert execution["steps"][-1]["evidence"]["assertions"][0]["passed"] is False
    with engine.store._connection() as db:
        events = [
            json.loads(row[0])
            for row in db.execute(
                "SELECT payload_json FROM audit_events WHERE kind='remediation.outcome'"
            )
        ]
    assert events[-1]["outcome"] == "VERIFIED_FAILURE"
    _assert_audit(engine)


def test_definitive_restart_failure_is_checked_by_postflight(tmp_path: Path) -> None:
    paths = write_config_tree(tmp_path, remediation=True)
    executor = ScriptedExecutor(
        [
            _result({"active": True}),
            _result({"restarted": False}, ok=False),
            _result({"active": False}),
        ]
    )
    engine, plan, _ = _approved(paths, executor)
    execution_id, status = engine.execute(
        plan.plan_id, confirm_remediation=True, confirming_actor="test-operator"
    )

    assert status == "failed"
    assert [action for _, action in executor.calls] == [
        "systemd.is_active",
        "systemd.restart",
        "systemd.is_active",
    ]
    saved = engine.store.execution(execution_id)
    assert saved["execution"]["summary"]["remediation_outcome"] == "VERIFIED_FAILURE"
    _assert_audit(engine)


def test_forged_postflight_type_does_not_verify_success(tmp_path: Path) -> None:
    paths = write_config_tree(tmp_path, remediation=True)
    executor = ScriptedExecutor(
        [
            _result({"active": True}),
            _result({"restarted": True}),
            _result({"active": "true"}),
        ]
    )
    engine, plan, _ = _approved(paths, executor)
    execution_id, status = engine.execute(
        plan.plan_id, confirm_remediation=True, confirming_actor="test-operator"
    )

    assert status == "failed"
    saved = engine.store.execution(execution_id)
    assert saved["execution"]["summary"]["remediation_outcome"] == "VERIFIED_FAILURE"
    assert saved["steps"][-1]["evidence"]["data"]["active"] == "true"
    _assert_audit(engine)


def test_default_deny_blocks_remediation_before_executor(tmp_path: Path) -> None:
    paths = write_config_tree(tmp_path, remediation=True)
    paths.policy.write_text(paths.policy.read_text().replace("[systemd.restart]", "[]"))
    executor = ScriptedExecutor([])
    engine = RunbookEngine(paths, executor=executor)
    plan = engine.plan(paths.database.parent.parent / "runbook.yml")

    assert plan.status == "denied"
    with pytest.raises(PolicyDenied):
        engine.execute(plan.plan_id, confirm_remediation=True, confirming_actor="test-operator")
    assert executor.calls == []
    assert engine.store.history() == []


def test_missing_approval_blocks_remediation_before_executor(tmp_path: Path) -> None:
    paths = write_config_tree(tmp_path, remediation=True)
    executor = ScriptedExecutor([])
    engine = RunbookEngine(paths, executor=executor)
    plan = engine.plan(paths.database.parent.parent / "runbook.yml")
    with pytest.raises(ApprovalError, match="no valid, unused approval"):
        engine.execute(plan.plan_id, confirm_remediation=True, confirming_actor="test-operator")
    assert executor.calls == []
    assert engine.store.history() == []
    _assert_audit(engine)


def test_remediation_runbook_requires_one_target_and_verified_phases(tmp_path: Path) -> None:
    paths = write_config_tree(tmp_path, remediation=True)
    runbook_path = paths.database.parent.parent / "runbook.yml"
    runbook_path.write_text(
        runbook_path.read_text().replace("targets: [test-web]", "targets: [test-web, test-app]")
    )
    engine = RunbookEngine(paths, executor=ScriptedExecutor([]))
    with pytest.raises(ConfigurationError, match="exactly one host"):
        engine.plan(runbook_path)

    content = yaml.safe_load(runbook_path.read_text())
    content["targets"] = ["test-web"]
    del content["postflight"]
    runbook_path.write_text(yaml.safe_dump(content, sort_keys=False))
    with pytest.raises(ConfigurationError, match="preflight and postflight"):
        engine.plan(runbook_path)


def test_expired_approval_fails_before_executor(tmp_path: Path, monkeypatch) -> None:
    import runbookos.store as store_module

    paths = write_config_tree(tmp_path, remediation=True)
    executor = ScriptedExecutor([])
    engine, plan, _ = _approved(paths, executor)
    original = store_module.time.time
    monkeypatch.setattr(store_module.time, "time", lambda: original() + 1000)

    with pytest.raises(ApprovalError, match="no valid"):
        engine.execute(plan.plan_id, confirm_remediation=True, confirming_actor="test-operator")
    assert executor.calls == []


def test_tampered_target_is_rejected_before_execution(tmp_path: Path) -> None:
    paths = write_config_tree(tmp_path, remediation=True)
    executor = ScriptedExecutor([])
    engine, plan, _ = _approved(paths, executor)
    document = engine.store.get_plan(plan.plan_id)
    document["actions"][0]["target"] = "different-host"
    with engine.store._connection() as db:
        db.execute(
            "UPDATE plans SET document_json=? WHERE plan_id=?",
            (json.dumps(document), plan.plan_id),
        )

    with pytest.raises(PolicyDenied, match="stored plan hash is invalid"):
        engine.execute(plan.plan_id, confirm_remediation=True, confirming_actor="test-operator")
    assert executor.calls == []


def test_concurrent_execution_consumes_one_approval_once(tmp_path: Path) -> None:
    paths = write_config_tree(tmp_path, remediation=True)
    executor = ScriptedExecutor(
        [
            _result({"active": True}),
            _result({"restarted": True}),
            _result({"active": True}),
        ]
    )
    engine, plan, _ = _approved(paths, executor)

    def execute():
        try:
            return engine.execute(
                plan.plan_id, confirm_remediation=True, confirming_actor="test-operator"
            )[1]
        except ApprovalError:
            return "approval-rejected"

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda _: execute(), range(2)))

    assert sorted(results) == ["approval-rejected", "succeeded"]
    assert len(executor.calls) == 3
    assert len(engine.store.history()) == 1
    _assert_audit(engine)
