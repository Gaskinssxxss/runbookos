from __future__ import annotations

import concurrent.futures
import json
import sqlite3
from datetime import UTC, datetime
from pathlib import Path

import pytest
from conftest import write_config_tree
from typer.testing import CliRunner

from runbookos.cli import app
from runbookos.engine import RunbookEngine
from runbookos.errors import ConfigurationError, ExecutionUnknown, PolicyDenied
from runbookos.incidents import IncidentStore, parse_alert
from runbookos.ssh import SSHResult
from runbookos.store import SQLiteStore


def _alert(alert_id: str = "workflow-alert", target: str = "test-web", fingerprint: str = "f1"):
    return parse_alert(
        json.dumps(
            {
                "alert_id": alert_id,
                "source": "test-monitor",
                "event_timestamp": datetime.now(UTC).isoformat(),
                "severity": "error",
                "target_alias": target,
                "service": "nginx",
                "category": "service",
                "summary": "Synthetic unit-test incident",
                "fingerprint": fingerprint,
                "metadata": {},
            }
        ).encode()
    )


def _setup(tmp_path: Path):
    paths = write_config_tree(tmp_path, remediation=True)
    engine = RunbookEngine(paths)
    plan = engine.plan(tmp_path / "runbook.yml")
    incidents = IncidentStore(engine.store)
    incident = incidents.ingest(_alert())
    return paths, engine, plan, incidents, incident["incident_id"]


def _associate(incidents, incident_id, plan):
    return incidents.associate_remediation_plan(
        incident_id, plan.plan_id, plan.plan_hash, "unit-operator"
    )


def test_incident_plan_association_is_immutable_audited_and_not_approval(tmp_path: Path):
    _, engine, plan, incidents, incident_id = _setup(tmp_path)

    linked = _associate(incidents, incident_id, plan)
    assert linked["approval_granted"] is False
    assert linked["execution_started"] is False
    assert linked["actor"] == "unit-operator"
    assert incidents.show(incident_id)["remediation_plans"][0]["plan_hash"] == plan.plan_hash
    with engine.store._connection() as db:
        assert db.execute("SELECT count(*) FROM approvals").fetchone()[0] == 0
        assert db.execute("SELECT count(*) FROM executions").fetchone()[0] == 0
        event = db.execute(
            "SELECT payload_json FROM audit_events WHERE kind='incident.remediation_plan_linked'"
        ).fetchone()
    assert json.loads(event[0])["association_is_approval"] is False
    assert engine.store.verify_audit_chain()[0]


def test_unknown_incident_and_plan_are_rejected(tmp_path: Path):
    _, _, plan, incidents, incident_id = _setup(tmp_path)
    with pytest.raises(ConfigurationError, match="incident not found"):
        incidents.associate_remediation_plan("missing", plan.plan_id, plan.plan_hash, "op")
    with pytest.raises(ConfigurationError, match="plan not found"):
        incidents.associate_remediation_plan(incident_id, "missing", "0" * 64, "op")


def test_cross_target_and_forged_plan_identity_or_hash_are_rejected(tmp_path: Path):
    _, engine, plan, incidents, incident_id = _setup(tmp_path)
    other = incidents.ingest(_alert("other-target-alert", "other-host", "f2"))["incident_id"]
    with pytest.raises(PolicyDenied, match="target must match"):
        _associate(incidents, other, plan)
    with pytest.raises(PolicyDenied, match="hash"):
        incidents.associate_remediation_plan(incident_id, plan.plan_id, "0" * 64, "op")

    forged = engine.store.get_plan(plan.plan_id)
    forged["plan_id"] = "forged-plan-id"
    with engine.store._connection() as db:
        db.execute(
            "UPDATE plans SET document_json=? WHERE plan_id=?",
            (json.dumps(forged), plan.plan_id),
        )
    with pytest.raises(PolicyDenied, match="identity or hash"):
        incidents.associate_remediation_plan(incident_id, plan.plan_id, plan.plan_hash, "op")


def test_corrupt_plan_projection_is_flagged_without_breaking_incident_view(tmp_path: Path):
    _, engine, plan, incidents, incident_id = _setup(tmp_path)
    _associate(incidents, incident_id, plan)
    with engine.store._connection() as db:
        db.execute(
            "UPDATE plans SET document_json=? WHERE plan_id=?",
            (json.dumps({"plan_hash": plan.plan_hash, "actions": [None, "invalid"]}), plan.plan_id),
        )

    context = incidents.show(incident_id)["remediation_plans"][0]
    assert context["plan_integrity"] == "invalid"
    assert context["preflight"] == []
    assert context["postflight"] == []


def test_association_is_idempotent_but_plan_cannot_link_to_another_incident(tmp_path: Path):
    _, engine, plan, incidents, incident_id = _setup(tmp_path)
    first = _associate(incidents, incident_id, plan)
    duplicate = _associate(incidents, incident_id, plan)
    assert duplicate["duplicate"] is True
    assert duplicate["association_id"] == first["association_id"]
    other = incidents.ingest(_alert("another-incident", fingerprint="f2"))["incident_id"]
    with pytest.raises(PolicyDenied, match="already associated"):
        _associate(incidents, other, plan)
    assert len(incidents.remediation_context(incident_id)) == 1
    assert engine.store.verify_audit_chain()[0]


def test_concurrent_duplicate_association_creates_one_link(tmp_path: Path):
    _, engine, plan, incidents, incident_id = _setup(tmp_path)

    def associate(_):
        return IncidentStore(SQLiteStore(engine.store.path)).associate_remediation_plan(
            incident_id, plan.plan_id, plan.plan_hash, "unit-operator"
        )

    with concurrent.futures.ThreadPoolExecutor(max_workers=6) as pool:
        result = list(pool.map(associate, range(12)))
    assert len({item["association_id"] for item in result}) == 1
    assert sum(not item["duplicate"] for item in result) == 1
    assert len(incidents.remediation_context(incident_id)) == 1
    assert engine.store.verify_audit_chain()[0]


def test_stale_source_fingerprint_blocks_cli_association(tmp_path: Path):
    paths, engine, plan, incidents, incident_id = _setup(tmp_path)
    paths.policy.write_text(paths.policy.read_text() + "\n# changed after planning\n")
    with pytest.raises(PolicyDenied, match="changed since planning"):
        engine.remediation_preview(plan.plan_id)
    with pytest.raises(PolicyDenied):
        engine._verify_plan(plan)
    root_args = [
        "--inventory",
        str(paths.inventory),
        "--policy",
        str(paths.policy),
        "--ssh-profiles",
        str(paths.ssh_profiles),
        "--db",
        str(paths.database),
    ]
    result = CliRunner().invoke(
        app,
        root_args + ["incidents", "associate-plan", incident_id, plan.plan_id],
    )
    assert result.exit_code != 0
    assert incidents.remediation_context(incident_id) == []


class _UnknownExecutor:
    def __init__(self):
        self.calls = 0

    def execute(self, host, action, arguments, timeout_seconds):
        self.calls += 1
        if action == "systemd.restart":
            raise ExecutionUnknown("synthetic transport loss")
        return SSHResult(True, {"active": True}, None, False, 0.01)


class _SuccessfulExecutor:
    def __init__(self):
        self.calls = []

    def execute(self, host, action, arguments, timeout_seconds):
        self.calls.append(action)
        if action == "systemd.restart":
            return SSHResult(True, {"restarted": True}, None, False, 0.01)
        return SSHResult(True, {"active": True}, None, False, 0.01)


def test_verified_remediation_does_not_change_incident_lifecycle(tmp_path: Path):
    paths = write_config_tree(tmp_path, remediation=True)
    executor = _SuccessfulExecutor()
    engine = RunbookEngine(paths, executor=executor)
    plan = engine.plan(tmp_path / "runbook.yml")
    incidents = IncidentStore(engine.store)
    incident_id = incidents.ingest(_alert())["incident_id"]
    _associate(incidents, incident_id, plan)
    engine.approve(plan.plan_id, "unit-operator", "reviewed synthetic plan")

    execution_id, status = engine.execute(
        plan.plan_id, confirm_remediation=True, confirming_actor="unit-operator"
    )

    assert status == "succeeded"
    execution = engine.store.execution(execution_id)
    assert execution["execution"]["summary"]["remediation_outcome"] == "VERIFIED_SUCCESS"
    assert [item["action"] for item in execution["steps"]][-1] == "systemd.is_active"
    assert incidents.show(incident_id)["status"] == "NEW"
    assert (
        incidents.show(incident_id)["remediation_plans"][0]["executions"][0]["outcome"]
        == "VERIFIED_SUCCESS"
    )
    assert executor.calls == ["systemd.is_active", "systemd.restart", "systemd.is_active"]
    assert engine.store.verify_audit_chain()[0]


def test_expired_approval_and_unknown_execution_are_visible_in_review(tmp_path: Path):
    paths = write_config_tree(tmp_path, remediation=True)
    executor = _UnknownExecutor()
    engine = RunbookEngine(paths, executor=executor)
    plan = engine.plan(tmp_path / "runbook.yml")
    incidents = IncidentStore(engine.store)
    incident_id = incidents.ingest(_alert())["incident_id"]
    _associate(incidents, incident_id, plan)

    approval_id = engine.approve(plan.plan_id, "unit-operator", "reviewed synthetic plan")
    with engine.store._connection() as db:
        db.execute("UPDATE approvals SET expires_at=0 WHERE approval_id=?", (approval_id,))
    context = incidents.remediation_context(incident_id)[0]
    assert context["approval"]["state"] == "expired"

    engine.store.create_approval(plan.plan_id, plan.plan_hash, "unit-operator", "fresh review", 300)
    execution_id, status = engine.execute(
        plan.plan_id, confirm_remediation=True, confirming_actor="unit-operator"
    )
    assert status == "unknown"
    assert executor.calls == 2
    context = incidents.remediation_context(incident_id)[0]
    assert context["unknown_outcome_warning"] is True
    assert context["executions"][0]["execution_id"] == execution_id
    assert context["executions"][0]["outcome"] == "UNKNOWN"
    assert incidents.store.verify_audit_chain()[0]


def test_review_event_is_audited_and_does_not_execute(tmp_path: Path):
    _, engine, plan, incidents, incident_id = _setup(tmp_path)
    _associate(incidents, incident_id, plan)
    incidents.record_remediation_review(incident_id, "unit-operator")
    with engine.store._connection() as db:
        assert db.execute("SELECT count(*) FROM executions").fetchone()[0] == 0
        event = db.execute(
            "SELECT actor FROM incident_events WHERE event_type='incident.remediation_reviewed'"
        ).fetchone()
    assert event["actor"] == "unit-operator"
    assert engine.store.verify_audit_chain()[0]


def test_v3_database_migrates_additively_and_preserves_audit(tmp_path: Path):
    database = tmp_path / "legacy-v3.sqlite3"
    store = SQLiteStore(database)
    with store._connection() as db:
        db.execute("BEGIN IMMEDIATE")
        db.execute("DROP TABLE incident_remediation_plans")
        store._audit(db, "legacy.v3_marker", {"preserve": True})
        db.execute("PRAGMA user_version=3")
        db.commit()

    migrated = SQLiteStore(database)
    with migrated._connection() as db:
        assert db.execute("PRAGMA user_version").fetchone()[0] == 4
        assert (
            db.execute(
                "SELECT count(*) FROM sqlite_master WHERE type='table' "
                "AND name='incident_remediation_plans'"
            ).fetchone()[0]
            == 1
        )
        assert (
            db.execute(
                "SELECT count(*) FROM audit_events WHERE kind='legacy.v3_marker'"
            ).fetchone()[0]
            == 1
        )
    assert migrated.verify_audit_chain()[0]

    reopened = SQLiteStore(database)
    with reopened._connection() as db:
        assert db.execute("PRAGMA user_version").fetchone()[0] == 4
    assert reopened.verify_audit_chain()[0]


def test_failed_v3_migration_rolls_back_without_rewriting_audit(tmp_path: Path):
    database = tmp_path / "failed-v3.sqlite3"
    store = SQLiteStore(database)
    with store._connection() as db:
        db.execute("BEGIN IMMEDIATE")
        db.execute("DROP TABLE incident_remediation_plans")
        store._audit(db, "legacy.v3_marker", {"preserve": True})
        db.execute("CREATE VIEW incident_remediation_plans AS SELECT 1 AS value")
        db.execute("PRAGMA user_version=3")
        db.commit()

    with pytest.raises(sqlite3.OperationalError, match="view"):
        SQLiteStore(database)

    with store._connection() as db:
        assert db.execute("PRAGMA user_version").fetchone()[0] == 3
        assert (
            db.execute(
                "SELECT type FROM sqlite_master WHERE name='incident_remediation_plans'"
            ).fetchone()[0]
            == "view"
        )
        assert (
            db.execute(
                "SELECT count(*) FROM audit_events WHERE kind='legacy.v3_marker'"
            ).fetchone()[0]
            == 1
        )
    assert store.verify_audit_chain()[0]
