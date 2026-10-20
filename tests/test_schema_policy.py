from __future__ import annotations

from pathlib import Path

import pytest
from conftest import ROOT, write_config_tree

from runbookos.config import load_runbook, read_yaml
from runbookos.engine import Paths, RunbookEngine, validate_parameters, validate_runbook
from runbookos.errors import ApprovalError, ConfigurationError, PolicyDenied
from runbookos.models import Runbook


@pytest.mark.parametrize("runbook", sorted((ROOT / "examples/runbooks").glob("*.yml")))
def test_read_only_runbook_examples_validate(runbook: Path) -> None:
    document, _ = load_runbook(runbook)
    validate_runbook(document)
    assert document.metadata.risk == "low"


def test_portable_service_examples_plan_ready_without_ssh(tmp_path: Path) -> None:
    paths = Paths(
        inventory=ROOT / "config/inventory.example.yml",
        policy=ROOT / "config/policy.example.yml",
        ssh_profiles=ROOT / "config/ssh_profiles.example.yml",
        database=tmp_path / "plans.sqlite3",
    )
    engine = RunbookEngine(paths)
    for name in (
        "basic-host-health.yml",
        "web-server-health.yml",
        "application-server-health.yml",
        "database-server-health.yml",
        "network-gateway-health.yml",
    ):
        plan = engine.plan(ROOT / "examples/runbooks" / name)
        assert plan.status == "ready"
        assert all(item.allowed and item.read_only for item in plan.actions)
    dependency = engine.plan(ROOT / "examples/runbooks/dependency-readiness.yml")
    assert dependency.status == "denied"


def test_parameter_defaults_and_types() -> None:
    raw = {
        "api_version": "runbookos/v1",
        "kind": "Runbook",
        "metadata": {
            "id": "parameter-check",
            "name": "Check",
            "description": "test",
            "risk": "low",
        },
        "targets": ["test-web"],
        "parameters": {
            "threshold": {
                "type": "integer",
                "required": False,
                "default": 80,
                "minimum": 1,
                "maximum": 99,
            }
        },
        "steps": [{"id": "disk-check", "action": "os.disk", "with": {"path": "/"}}],
    }
    model = Runbook.model_validate(raw)
    assert validate_parameters(model, {}) == {"threshold": 80}
    with pytest.raises(ConfigurationError, match="integer"):
        validate_parameters(model, {"threshold": "80"})
    with pytest.raises(ConfigurationError, match="<= 99"):
        validate_parameters(model, {"threshold": 100})


def test_unknown_action_and_secret_parameters_rejected() -> None:
    raw = {
        "api_version": "runbookos/v1",
        "kind": "Runbook",
        "metadata": {"id": "bad-command", "name": "Bad", "description": "test", "risk": "low"},
        "targets": ["test-web"],
        "steps": [{"id": "evil", "action": "shell.exec", "with": {"command": "id"}}],
    }
    with pytest.raises(ConfigurationError, match="unregistered"):
        validate_runbook(Runbook.model_validate(raw))
    raw["metadata"]["id"] = "secret-input"
    raw["steps"] = [{"id": "disk-check", "action": "os.disk", "with": {"path": "/"}}]
    raw["parameters"] = {"db_password": {"type": "string"}}
    with pytest.raises(ValueError, match="secret-like"):
        Runbook.model_validate(raw)


def test_duplicate_yaml_keys_rejected(tmp_path: Path) -> None:
    path = tmp_path / "duplicate.yml"
    path.write_text("schema_version: 1\nschema_version: 1\nhosts: {}\n")
    with pytest.raises(ConfigurationError, match="duplicate YAML key"):
        read_yaml(path)


def test_policy_default_deny_and_plan_is_not_execution(tmp_path: Path, key_material) -> None:
    paths = write_config_tree(tmp_path)
    paths.policy.write_text(
        paths.policy.read_text().replace("[systemd.is_active, systemd.failed_units]", "[]")
    )
    engine = RunbookEngine(paths)
    plan = engine.plan(tmp_path / "runbook.yml")
    assert plan.status == "denied"
    with pytest.raises(PolicyDenied):
        engine.execute(plan.plan_id)
    with pytest.raises(ApprovalError, match="only applies"):
        engine.approve(plan.plan_id, "pytest-user", "cannot override default deny")
    assert engine.store.history() == []


def test_approval_is_bound_to_plan_and_one_time(tmp_path: Path) -> None:
    paths = write_config_tree(tmp_path, remediation=True)
    engine = RunbookEngine(paths)
    plan = engine.plan(tmp_path / "runbook.yml")
    assert plan.status == "approval_required"
    approval = engine.approve(plan.plan_id, "pytest-user", "approved controlled test action")
    assert approval
    assert engine.store.consume_approval(plan.plan_id, plan.plan_hash) == approval
    with pytest.raises(ApprovalError, match="no valid"):
        engine.store.consume_approval(plan.plan_id, plan.plan_hash)


def test_policy_change_invalidates_existing_plan(tmp_path: Path) -> None:
    paths = write_config_tree(tmp_path)
    engine = RunbookEngine(paths)
    plan = engine.plan(tmp_path / "runbook.yml")
    paths.policy.write_text(paths.policy.read_text() + "\n# changed after approval review\n")
    with pytest.raises(PolicyDenied, match="changed since planning"):
        engine.execute(plan.plan_id)


def test_action_implementation_change_invalidates_existing_plan(
    tmp_path: Path, monkeypatch
) -> None:
    paths = write_config_tree(tmp_path, remediation=True)
    engine = RunbookEngine(paths)
    plan = engine.plan(tmp_path / "runbook.yml")
    assert plan.status == "approval_required"
    approval_id = engine.approve(plan.plan_id, "pytest-user", "approve exact action implementation")
    monkeypatch.setattr("runbookos.engine.REMOTE_SOURCE", "changed dispatcher implementation")
    with pytest.raises(PolicyDenied, match="changed since planning"):
        engine.execute(plan.plan_id)
    assert engine.store.consume_approval(plan.plan_id, plan.plan_hash) == approval_id
