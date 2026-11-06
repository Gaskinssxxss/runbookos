from __future__ import annotations

import hashlib
import http.client
import json
import os
import socket
import subprocess
import sys
import time
from datetime import UTC, datetime
from pathlib import Path

from conftest import write_config_tree
from typer.testing import CliRunner

from runbookos.ai import (
    IncidentInvestigator,
    InvestigationConfig,
    InvestigationFailure,
    ModelReply,
)
from runbookos.assessment import (
    ClassificationAssessment,
    EvidenceObservation,
    StructuredAssessment,
)
from runbookos.assessment_evaluation import (
    CasePrediction,
    EvaluationInput,
    evaluate,
    load_dataset,
)
from runbookos.cli import app
from runbookos.dashboard import create_auth_file
from runbookos.incidents import IncidentStore, parse_alert
from runbookos.store import SQLiteStore

ROOT = Path(__file__).parents[1]
M3_FIXTURE = ROOT / "tests/fixtures/assessment_m3/heldout-v1.json"


class _MockProvider:
    provider_name = "m5-synthetic-provider"

    def __init__(self):
        self.requests: list[tuple[str, str]] = []

    def complete(self, system, user, max_tokens, temperature):
        self.requests.append((system, user))
        if len(self.requests) == 1:
            response = {"diagnostic_ids": ["web_health"]}
        else:
            refs = json.loads(user)["evidence_refs"]
            response = {
                "reply_version": 2,
                "category": "service_failure",
                "confidence": 0.7,
                "evidence_ids": refs,
                "reason": "The web service process may not be running.",
                "abstain": False,
                "overall_uncertainty": 0.55,
            }
        return ModelReply(json.dumps(response), "synthetic-reference-only", 0.001)


def _synthetic_reference_predictions(dataset) -> EvaluationInput:
    """Build explicitly synthetic gold-derived predictions to test evaluator mechanics."""
    predictions = []
    for case in dataset.cases:
        observations = [
            EvidenceObservation(
                statement=f"Synthetic test observation {index + 1}.",
                ref=item.evidence_id,
                evidence_refs=[item.evidence_id],
                execution_id=f"synthetic-exec-{case.case_id}-{index}",
                diagnostic_id=item.diagnostic_id,
                source_action="diagnostic.synthetic_read_only",
                target=f"synthetic-target-{case.case_id}",
                step_id=f"synthetic-step-{index}",
                observed_result=item.observed_result,
                execution_status="succeeded",
                assertion_outcome="not_present",
                verification_status="verified",
                incident_id=case.input.incident_id,
                investigation_id=f"synthetic-investigation-{case.case_id}",
            )
            for index, item in enumerate(case.input.observations)
        ]
        category = case.gold.classification
        classifications = []
        if category is not None:
            classifications = [
                ClassificationAssessment(
                    category=category,
                    confidence=0.75,
                    supporting_evidence_refs=[item.ref for item in observations],
                    status="undetermined" if category == "unknown" else "suspected",
                )
            ]
        abstained = category in {None, "unknown"}
        assessment = StructuredAssessment(
            schema_version=1,
            classification_catalog_version=2,
            incident_id=case.input.incident_id,
            investigation_id=f"synthetic-investigation-{case.case_id}",
            observations=observations,
            inferences=[],
            hypotheses=[],
            classifications=classifications,
            unknowns=[],
            recommended_next_steps=[],
            overall_uncertainty=0.25,
            assessment_status="abstained" if abstained else "assessed",
        )
        predictions.append(
            CasePrediction(
                case_id=case.case_id,
                diagnostic_ids=list(case.gold.expected_diagnostic_ids),
                assessment=assessment,
            )
        )
    return EvaluationInput(
        schema_version=1,
        dataset_version=dataset.dataset_version,
        predictions=predictions,
    )


def test_m5_synthetic_incident_to_authenticated_review_and_reference_evaluation(
    tmp_path: Path, monkeypatch, key_material
):
    paths = write_config_tree(tmp_path / "runtime")
    fake_bin = tmp_path / "fake-bin"
    fake_bin.mkdir()
    fake_calls = tmp_path / "fake-executor-calls.txt"
    fake_ssh = fake_bin / "ssh"
    remote_response = {
        "ok": True,
        "data": {
            "unit": "nginx.service",
            "active": False,
            "api_key": "synthetic-m5-secret-value",
        },
        "error": None,
        "uncertain": False,
    }
    fake_ssh.write_text(
        "#!/usr/bin/python3\nimport json\n"
        f"open({str(fake_calls)!r}, 'a').write('dispatch\\n')\n"
        f"print({json.dumps(remote_response)!r})\n",
        encoding="utf-8",
    )
    fake_ssh.chmod(0o700)
    monkeypatch.setenv("PATH", str(fake_bin) + ":/usr/bin:/bin")

    summary = "Synthetic nginx unavailable alert"
    alert = {
        "alert_id": "m5-alert-1",
        "source": "synthetic-monitor",
        "event_timestamp": datetime.now(UTC).isoformat(),
        "severity": "error",
        "target_alias": "test-web",
        "service": "nginx",
        "category": "service",
        "summary": summary,
        "fingerprint": "m5-synthetic-fingerprint",
        "metadata": {},
    }
    incidents = IncidentStore(SQLiteStore(paths.database))
    incident_id = incidents.ingest(parse_alert(json.dumps(alert).encode()))["incident_id"]
    incidents.transition(
        incident_id, "ACKNOWLEDGED", "synthetic-operator", "reviewed synthetic alert"
    )
    incidents.mark_investigating(incident_id, "synthetic-operator")

    config = InvestigationConfig.model_validate(
        {
            "schema_version": 1,
            "provider": {
                "type": "openai_compatible",
                "base_url": "http://127.0.0.1:8080/v1",
                "model": "mock-only",
            },
            "limits": {
                "max_diagnostic_runbooks": 1,
                "max_tool_calls": 2,
                "execution_budget_seconds": 60,
                "max_incident_chars": 1000,
            },
            "catalog": [
                {
                    "id": "web_health",
                    "runbook": str(tmp_path / "runtime/runbook.yml"),
                    "description": "Check synthetic web service status.",
                }
            ],
        }
    )
    provider = _MockProvider()
    investigation = IncidentInvestigator(
        paths,
        config,
        tmp_path / "runtime",
        provider,
        allowed_targets={"test-web"},
    ).investigate(summary, incident_id=incident_id)
    assert len(provider.requests) == 2
    assert investigation["selected_diagnostics"] == ["web_health"]
    assert investigation["status"] == "partial"
    assert len(investigation["evidence"]) == 1
    evidence = investigation["evidence"][0]
    assert evidence["action"] == "systemd.is_active"
    assert evidence["status"] == "failed"
    assert evidence["evidence"]["data"]["active"] is False
    assessment = investigation["assessment"]
    assert assessment["schema_version"] == 1
    assert assessment["investigation_id"] == investigation["investigation_id"]
    assert assessment["observations"][0]["ref"] == evidence["ref"]
    assert assessment["observations"][0]["assertion_outcome"] == "failed"
    assert assessment["observations"][0]["verification_status"] == "not_verified"
    assert assessment["hypotheses"][0]["evidence_refs"] == [evidence["ref"]]
    assert assessment["semantic_support_status"] == "unverified"
    incidents.link_investigation(incident_id, investigation["investigation_id"], [], [])

    record = SQLiteStore(paths.database).investigation_detail(investigation["investigation_id"])
    assert record is not None and record["result_integrity"] == "valid"
    assert "synthetic-m5-secret-value" not in json.dumps(record["result"])
    assert record["result"]["evidence"][0]["evidence"]["data"]["api_key"] == "[REDACTED]"
    valid, audit_count = SQLiteStore(paths.database).verify_audit_chain()
    assert valid

    cli_result = CliRunner().invoke(
        app, ["--db", str(paths.database), "incidents", "show", incident_id]
    )
    assert cli_result.exit_code == 0, cli_result.output
    cli_doc = json.loads(cli_result.output)
    cli_projection = cli_doc["latest_investigation_assessment"]
    assert cli_projection["availability"] == "available"
    assert cli_projection["observations"][0]["assertion_outcome"] == "failed"
    assert cli_projection["observations"][0]["verification_status"] == "not_verified"
    assert cli_projection["hypotheses"] == assessment["hypotheses"]
    assert cli_projection["evaluation_status"] == "NOT MEASURED"
    assert cli_doc["assessment_review_audit"] == {"valid": True, "event_count": audit_count}

    auth_file = tmp_path / "dashboard-auth.json"
    create_auth_file(auth_file, "synthetic-operator", "m5-synthetic-login-phrase")
    with socket.socket() as reservation:
        reservation.bind(("127.0.0.1", 0))
        port = reservation.getsockname()[1]
    env = os.environ.copy()
    env["PYTHONPATH"] = str(ROOT / "src")
    dashboard = subprocess.Popen(
        [
            sys.executable,
            "-m",
            "runbookos",
            "--db",
            str(paths.database),
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

    def request(method: str, path: str, body: str = "", cookie: str | None = None):
        connection = http.client.HTTPConnection("127.0.0.1", port, timeout=3)
        headers = {"Content-Type": "application/x-www-form-urlencoded"}
        if cookie:
            headers["Cookie"] = cookie
        connection.request(method, path, body=body, headers=headers)
        response = connection.getresponse()
        result = (response.status, dict(response.getheaders()), response.read().decode())
        connection.close()
        return result

    try:
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            if dashboard.poll() is not None:
                raise AssertionError("synthetic dashboard exited before readiness")
            try:
                status, _, _ = request("GET", "/login")
                if status == 200:
                    break
            except OSError:
                time.sleep(0.05)
        else:
            raise AssertionError("synthetic dashboard did not become ready")
        status, _, denied = request("GET", f"/incidents/{incident_id}")
        assert status == 303 and "Sign in" in denied
        status, headers, _ = request("POST", "/login", "password=m5-synthetic-login-phrase")
        assert status == 303
        cookie = headers["Set-Cookie"].split(";", 1)[0]
        status, _, html = request("GET", f"/incidents/{incident_id}", cookie=cookie)
        assert status == 200
        assert investigation["investigation_id"] in html
        assert "assertion: failed" in html and "verification: not_verified" in html
        assert "model-reported; uncalibrated: 0.7" in html
        assert "semantic support: unverified" in html
        assert "NOT MEASURED" in html
        assert "synthetic-m5-secret-value" not in html
        assert "<form method='post' action='/incidents/" in html
        assert "investigate" not in html
        assert SQLiteStore(paths.database).verify_audit_chain() == (True, audit_count)
    finally:
        dashboard.send_signal(2)
        dashboard.wait(timeout=5)

    with SQLiteStore(paths.database)._connection() as db:
        assert db.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
        assert db.execute("PRAGMA foreign_key_check").fetchall() == []
        assert db.execute("PRAGMA user_version").fetchone()[0] == 4
        assert db.execute("SELECT count(*) FROM executions").fetchone()[0] == 1
        assert db.execute("SELECT count(*) FROM approvals").fetchone()[0] == 0
    assert fake_calls.read_text().splitlines() == ["dispatch"]
    assert incidents.show(incident_id)["status"] == "INVESTIGATING"

    # These gold-derived predictions exercise evaluator math only; they are not model output.
    dataset = load_dataset(M3_FIXTURE)
    evaluation = evaluate(dataset, _synthetic_reference_predictions(dataset))
    assert evaluation["diagnostic_selection"]["exact_match_accuracy"] == 1.0
    assert evaluation["classification"]["exact_accuracy"] == 1.0
    assert evaluation["evaluation_status"] == "COMPLETE"


def test_cli_links_sanitized_investigation_failure_without_showing_a_diagnosis(
    tmp_path: Path, monkeypatch
):
    paths = write_config_tree(tmp_path / "failure-runtime")
    summary = "Synthetic application diagnostic failure"
    alert = {
        "alert_id": "failure-alert-1",
        "source": "synthetic-monitor",
        "event_timestamp": datetime.now(UTC).isoformat(),
        "severity": "error",
        "target_alias": "test-web",
        "service": "nginx",
        "category": "service",
        "summary": summary,
        "fingerprint": "failure-fingerprint",
        "metadata": {},
    }
    incidents = IncidentStore(SQLiteStore(paths.database))
    incident_id = incidents.ingest(parse_alert(json.dumps(alert).encode()))["incident_id"]
    incidents.transition(
        incident_id, "ACKNOWLEDGED", "synthetic-operator", "approved synthetic investigation"
    )
    investigation_id = "sanitized-failure-investigation"
    store = SQLiteStore(paths.database)
    store.create_investigation(
        {
            "incident_sha256": hashlib.sha256(summary.encode()).hexdigest(),
            "status": "failed",
            "selected_diagnostics": [],
            "tool_calls": 0,
            "evidence": [],
            "verified_evidence": [],
            "assessment_failure": {
                "stage": "assessment",
                "category": "provider_or_contract_error",
                "reason_category": "provider_or_contract_error",
                "error_type": "RunbookOSError",
            },
            "model_metadata": {"provider": "synthetic", "model": "mock", "model_calls": 2},
        },
        investigation_id=investigation_id,
    )

    class FailedInvestigator:
        def __init__(self, *args, **kwargs):
            pass

        def investigate(self, *args, **kwargs):
            raise InvestigationFailure(
                investigation_id,
                "assessment",
                [],
                public_detail="provider or assessment contract failed",
            )

    config_path = tmp_path / "investigation.yml"
    config_path.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "provider": {
                    "type": "openai_compatible",
                    "base_url": "http://127.0.0.1:8080/v1",
                    "model": "mock-only",
                },
                "limits": {"max_diagnostic_runbooks": 1},
                "catalog": [
                    {
                        "id": "web_health",
                        "runbook": str(tmp_path / "failure-runtime/runbook.yml"),
                        "description": "Synthetic read-only check",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr("runbookos.cli.IncidentInvestigator", FailedInvestigator)
    monkeypatch.setattr("runbookos.cli.build_provider", lambda _: object())
    common = [
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
    invoked = runner.invoke(
        app,
        common + ["incidents", "investigate", incident_id, "--ai-config", str(config_path)],
    )
    assert invoked.exit_code == 2
    assert "sanitized record" in invoked.stderr
    shown = runner.invoke(app, common + ["incidents", "show", incident_id])
    assert shown.exit_code == 0, shown.output
    projection = json.loads(shown.output)["latest_investigation_assessment"]
    assert projection["availability"] == "assessment_failed"
    assert projection["failure_stage"] == "assessment"
    assert "hypotheses" not in projection
    assert "classifications" not in projection
    assert store.verify_audit_chain()[0]
