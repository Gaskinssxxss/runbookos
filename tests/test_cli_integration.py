from __future__ import annotations

import getpass
import json
from datetime import UTC, datetime
from pathlib import Path

from conftest import write_config_tree
from typer.testing import CliRunner

from runbookos.cli import app
from runbookos.engine import RunbookEngine
from runbookos.incidents import IncidentStore, parse_alert
from runbookos.store import SQLiteStore


def test_cli_check_history_and_audit(tmp_path: Path, key_material, monkeypatch) -> None:
    private, known_hosts = key_material
    paths = write_config_tree(tmp_path)
    bindir = tmp_path / "fake-bin"
    bindir.mkdir()
    capture = tmp_path / "remote-command.json"
    fake_ssh = bindir / "ssh"
    response = json.dumps(
        {
            "ok": True,
            "data": {"unit": "nginx.service", "active": True},
            "error": None,
            "uncertain": False,
        }
    )
    fake_ssh.write_text(
        "#!/usr/bin/python3\n"
        "import json,sys\n"
        f"open({str(capture)!r},'w').write(json.dumps(sys.argv[1:]))\n"
        f"print({response!r})\n"
    )
    fake_ssh.chmod(0o700)
    monkeypatch.setenv("PATH", str(bindir) + ":/usr/bin:/bin")
    monkeypatch.setenv("RUNBOOKOS_TEST_KEY", str(private))
    monkeypatch.setenv("RUNBOOKOS_TEST_KNOWN_HOSTS", str(known_hosts))
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
    runner = CliRunner()
    check_result = runner.invoke(app, root_args + ["check", str(tmp_path / "runbook.yml")])
    assert check_result.exit_code == 0, check_result.output
    assert "succeeded" in check_result.output
    argv = json.loads(capture.read_text())
    assert "-oStrictHostKeyChecking=yes" in argv
    assert "-oPasswordAuthentication=no" in argv

    history_result = runner.invoke(app, root_args + ["history"])
    assert history_result.exit_code == 0, history_result.output
    history = json.loads(history_result.output)
    assert len(history) == 1 and history[0]["status"] == "succeeded"
    execution_id = history[0]["execution_id"]
    detail = runner.invoke(app, root_args + ["history", execution_id])
    assert detail.exit_code == 0, detail.output
    assert json.loads(detail.output)["steps"][0]["evidence"]["data"]["active"] is True

    audit = runner.invoke(app, root_args + ["audit"])
    assert audit.exit_code == 0, audit.output
    assert "AUDIT OK" in audit.output


def test_approval_command_executes_once_only(tmp_path: Path, key_material, monkeypatch) -> None:
    private, known_hosts = key_material
    paths = write_config_tree(tmp_path, remediation=True)
    bindir = tmp_path / "fake-bin"
    bindir.mkdir()
    calls = tmp_path / "calls.txt"
    fake_ssh = bindir / "ssh"
    responses = [
        {"ok": True, "data": {"unit": "nginx.service", "active": True}},
        {"ok": True, "data": {"unit": "nginx.service", "restarted": True}},
        {"ok": True, "data": {"unit": "nginx.service", "active": True}},
    ]
    fake_ssh.write_text(
        "#!/usr/bin/python3\nimport json,sys\n"
        f"calls={str(calls)!r}\n"
        "with open(calls,'a+') as f:\n"
        " f.seek(0); index=len(f.readlines()); f.write('called\\n')\n"
        f"responses={responses!r}\n"
        "response=responses[index]\nresponse.update(error=None,uncertain=False)\n"
        "print(json.dumps(response))\n"
    )
    fake_ssh.chmod(0o700)
    monkeypatch.setenv("PATH", str(bindir) + ":/usr/bin:/bin")
    monkeypatch.setenv("RUNBOOKOS_TEST_KEY", str(private))
    monkeypatch.setenv("RUNBOOKOS_TEST_KNOWN_HOSTS", str(known_hosts))
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
    runner = CliRunner()
    planned = runner.invoke(app, root_args + ["plan", str(tmp_path / "runbook.yml"), "--json"])
    assert planned.exit_code == 0, planned.output
    plan_id = json.loads(planned.output)["plan_id"]
    assert json.loads(planned.output)["status"] == "approval_required"
    preview = runner.invoke(app, root_args + ["remediation-preview", plan_id])
    assert preview.exit_code == 0, preview.output
    preview_doc = json.loads(preview.output)
    assert preview_doc["target"]["alias"] == "test-web"
    assert preview_doc["action_id"] == "systemd.restart"
    assert preview_doc["explicit_execution_confirmation_required"] is True
    assert preview_doc["rollback"]["available"] is False
    assert "interrupted" in preview_doc["expected_service_impact"]
    assert len(preview_doc["read_only_preconditions"]) == 1
    assert len(preview_doc["postflight_checks"]) == 1
    approval = runner.invoke(
        app, root_args + ["approve", plan_id, "--reason", "Approved isolated fixture test"]
    )
    assert approval.exit_code == 0, approval.output
    cancelled = runner.invoke(app, root_args + ["run", plan_id])
    assert cancelled.exit_code == 2 and "explicit execution confirmation" in cancelled.output
    assert not calls.exists()
    executed = runner.invoke(app, root_args + ["run", plan_id, "--confirm"])
    assert executed.exit_code == 0, executed.output
    assert "succeeded" in executed.output
    assert calls.read_text().splitlines() == ["called"] * 3
    history = runner.invoke(app, root_args + ["history"])
    history_doc = json.loads(history.output)[0]
    assert history_doc["summary"]["remediation_outcome"] == "VERIFIED_SUCCESS"
    audit = runner.invoke(app, root_args + ["audit"])
    assert audit.exit_code == 0 and "AUDIT OK" in audit.output
    with SQLiteStore(paths.database)._connection() as db:
        started = db.execute(
            "SELECT payload_json FROM audit_events WHERE kind='execution.started'"
        ).fetchone()
    authorization = json.loads(started[0])["operator_confirmation"]
    assert authorization["confirmed_by"] == getpass.getuser()
    assert authorization["confirmation"] == "explicit CLI --confirm"
    replay = runner.invoke(app, root_args + ["run", plan_id, "--confirm"])
    assert replay.exit_code == 2, replay.output
    assert "no valid, unused approval" in replay.output
    assert calls.read_text().splitlines() == ["called"] * 3


def test_incident_remediation_cli_association_and_review_are_human_controlled(
    tmp_path: Path,
) -> None:
    paths = write_config_tree(tmp_path, remediation=True)
    engine = RunbookEngine(paths)
    plan = engine.plan(tmp_path / "runbook.yml")
    incidents = IncidentStore(engine.store)
    alert = parse_alert(
        json.dumps(
            {
                "alert_id": "cli-incident-alert",
                "source": "test-monitor",
                "event_timestamp": datetime.now(UTC).isoformat(),
                "severity": "error",
                "target_alias": "test-web",
                "service": "nginx",
                "category": "service",
                "summary": "Synthetic CLI test incident",
                "fingerprint": "cli-incident-fingerprint",
                "metadata": {},
            }
        ).encode()
    )
    incident_id = incidents.ingest(alert)["incident_id"]
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
    runner = CliRunner()

    linked = runner.invoke(
        app, root_args + ["incidents", "associate-plan", incident_id, plan.plan_id]
    )
    assert linked.exit_code == 0, linked.output
    link_doc = json.loads(linked.output)
    assert link_doc["approval_granted"] is False
    assert link_doc["execution_started"] is False

    reviewed = runner.invoke(app, root_args + ["incidents", "remediation-review", incident_id])
    assert reviewed.exit_code == 0, reviewed.output
    review_doc = json.loads(reviewed.output)
    assert review_doc["remediation_plans"][0]["preview_status"] == "valid_current_plan"
    assert review_doc["remediation_plans"][0]["approval"]["state"] == "not_issued"
    assert review_doc["audit"]["valid"] is True
    with SQLiteStore(paths.database)._connection() as db:
        assert db.execute("SELECT count(*) FROM approvals").fetchone()[0] == 0
        assert db.execute("SELECT count(*) FROM executions").fetchone()[0] == 0
        assert (
            db.execute(
                "SELECT count(*) FROM incident_events WHERE event_type='incident.remediation_reviewed'"
            ).fetchone()[0]
            == 1
        )

    paths.policy.write_text(paths.policy.read_text() + "\n# policy changed after planning\n")
    stale = runner.invoke(app, root_args + ["incidents", "remediation-review", incident_id])
    assert stale.exit_code == 0, stale.output
    assert json.loads(stale.output)["remediation_plans"][0]["preview_status"] == "stale_or_invalid"


def test_propose_remediation_cli_reads_yaml_candidate_mapping(tmp_path: Path, monkeypatch) -> None:
    from runbookos import cli as cli_module

    paths = write_config_tree(tmp_path, remediation=True)
    incident_store = IncidentStore(SQLiteStore(paths.database))
    alert = parse_alert(
        json.dumps(
            {
                "alert_id": "proposal-cli-alert",
                "source": "test-monitor",
                "event_timestamp": datetime.now(UTC).isoformat(),
                "severity": "error",
                "target_alias": "test-web",
                "service": "nginx",
                "category": "service",
                "summary": "Synthetic proposal CLI test incident",
                "fingerprint": "proposal-cli-fingerprint",
                "metadata": {},
            }
        ).encode()
    )
    incident_id = incident_store.ingest(alert)["incident_id"]
    incident_store.transition(incident_id, "ACKNOWLEDGED", "test-operator", "test acknowledgement")
    incident_store.mark_investigating(incident_id, "test-operator")

    ai_config = tmp_path / "investigation.yml"
    ai_config.write_text(
        "schema_version: 1\n"
        "provider:\n"
        "  type: openai_compatible\n"
        "  base_url: http://127.0.0.1:18080/v1\n"
        "  model: test-model\n"
        "  timeout_seconds: 10\n"
        "  max_tokens: 700\n"
        "catalog:\n"
        "  - id: test-diagnostic\n"
        "    runbook: test.yml\n"
        "    description: Test diagnostic catalog entry.\n"
    )
    candidates = tmp_path / "candidates.yml"
    candidates.write_text(
        "schema_version: 1\n"
        "candidates:\n"
        "  - action_id: systemd.restart\n"
        "    target_ref: fixture-web\n"
        "    target_name: test-web\n"
        "    arguments:\n"
        "      unit: nginx.service\n"
        "    required_evidence_actions: []\n"
        "    compatible_categories: [service_failure]\n"
    )
    captured = {}

    class FakeInvestigator:
        def __init__(self, *_args, **_kwargs):
            pass

        def propose_remediation(self, incident, investigation, action_candidates):
            captured["incident"] = incident
            captured["investigation"] = investigation
            captured["candidate"] = action_candidates[0].model_dump(mode="json")
            return {"status": "accepted", "proposal": {"test": True}}

    monkeypatch.setattr(cli_module, "IncidentInvestigator", FakeInvestigator)
    monkeypatch.setattr(cli_module, "build_provider", lambda _config: object())
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
        root_args
        + [
            "incidents",
            "propose-remediation",
            incident_id,
            "--investigation",
            "investigation-test",
            "--ai-config",
            str(ai_config),
            "--candidates",
            str(candidates),
        ],
    )
    assert result.exit_code == 0, result.output
    assert json.loads(result.output) == {"status": "accepted", "proposal": {"test": True}}
    assert captured["candidate"]["action_id"] == "systemd.restart"
    assert captured["candidate"]["target_name"] == "test-web"


def test_incident_remediation_cli_rejects_cross_target_association(tmp_path: Path) -> None:
    paths = write_config_tree(tmp_path, remediation=True)
    engine = RunbookEngine(paths)
    plan = engine.plan(tmp_path / "runbook.yml")
    incidents = IncidentStore(engine.store)
    alert = parse_alert(
        json.dumps(
            {
                "alert_id": "cross-target-alert",
                "source": "test-monitor",
                "event_timestamp": datetime.now(UTC).isoformat(),
                "severity": "error",
                "target_alias": "other-host",
                "service": "nginx",
                "category": "service",
                "summary": "Mismatched target",
                "fingerprint": "cross-target-fingerprint",
                "metadata": {},
            }
        ).encode()
    )
    incident_id = incidents.ingest(alert)["incident_id"]
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
        app, root_args + ["incidents", "associate-plan", incident_id, plan.plan_id]
    )
    assert result.exit_code == 2
    assert "target must exactly match" in result.output
    assert incidents.remediation_context(incident_id) == []


def test_unknown_ssh_result_is_persisted_without_retry(
    tmp_path: Path, key_material, monkeypatch
) -> None:
    private, known_hosts = key_material
    paths = write_config_tree(tmp_path)
    bindir = tmp_path / "fake-bin"
    bindir.mkdir()
    calls = tmp_path / "calls.txt"
    fake_ssh = bindir / "ssh"
    fake_ssh.write_text(
        "#!/usr/bin/python3\n"
        "import sys\n"
        f"open({str(calls)!r},'a').write('called\\n')\n"
        "raise SystemExit(255)\n"
    )
    fake_ssh.chmod(0o700)
    monkeypatch.setenv("PATH", str(bindir) + ":/usr/bin:/bin")
    monkeypatch.setenv("RUNBOOKOS_TEST_KEY", str(private))
    monkeypatch.setenv("RUNBOOKOS_TEST_KNOWN_HOSTS", str(known_hosts))
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
    runner = CliRunner()
    planned = runner.invoke(app, root_args + ["plan", str(tmp_path / "runbook.yml"), "--json"])
    assert planned.exit_code == 0, planned.output
    plan_id = json.loads(planned.output)["plan_id"]
    executed = runner.invoke(app, root_args + ["run", plan_id])
    assert executed.exit_code == 3, executed.output
    assert "unknown" in executed.output
    assert calls.read_text().splitlines() == ["called"]
    history = runner.invoke(app, root_args + ["history"])
    assert json.loads(history.output)[0]["status"] == "unknown"
