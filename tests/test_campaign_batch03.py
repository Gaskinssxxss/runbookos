from __future__ import annotations

import base64
import importlib.util
import json
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from runbookos.remediation_proposal import (
    RegisteredActionCandidate,
    request_remediation_proposal,
)

ROOT = Path(__file__).parents[1]


def load_script(name: str):
    path = ROOT / "scripts" / f"{name}.py"
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


b03 = load_script("campaign_batch03")
b03_live = load_script("campaign_batch03_live")


def test_fixture_restore_requires_successful_commands_and_stable_readiness():
    states = iter([False, True, True])
    executed = []
    result = b03.restore_fixture(
        [("systemctl", "restart", "fixture.service")],
        lambda command: executed.append(command) or {"exit_code": 0},
        lambda: next(states),
        bool,
        timeout_seconds=1,
    )
    assert executed == [("systemctl", "restart", "fixture.service")]
    assert result is True


def test_restore_aborts_if_command_failed_or_readiness_never_returns():
    with pytest.raises(RuntimeError, match="restoration command failed"):
        b03.restore_fixture(
            [("systemctl", "restart", "fixture.service")],
            lambda _: {"exit_code": 1},
            lambda: False,
            bool,
            timeout_seconds=0.1,
        )
    with pytest.raises(TimeoutError):
        b03.stable_condition(lambda: False, bool, timeout_seconds=0.02, poll_interval_seconds=0.005)


def test_state_machine_rejects_skipping_ai_proposal_and_authorization():
    state = b03.advance(b03.WorkflowState.CREATED, b03.WorkflowState.PROVISIONED)
    with pytest.raises(ValueError, match="invalid campaign transition"):
        b03.advance(state, b03.WorkflowState.REMEDIATED)


def test_ledger_only_accepts_ai_pass_if_proposed_action_was_executed():
    attempt = {
        "run_id": "run-1",
        "result": "AI_DRIVEN_PASS",
        **{
            key: {"status": "PASS"}
            for key in (
                "baseline",
                "fault",
                "incident",
                "diagnostics",
                "assessment",
                "proposal",
                "authorization",
                "remediation",
                "postflight",
                "audit",
                "closure",
                "cleanup",
            )
        },
    }
    attempt["proposal"]["selected_action_id"] = "systemd.restart"
    attempt["proposal"]["target_ref"] = "fixture-web"
    attempt["proposal"]["validated_candidate"] = {"arguments": {"unit": "x.service"}}
    attempt["remediation"].update(
        action_id="systemd.restart",
        target_ref="fixture-web",
        arguments={"unit": "x.service"},
    )
    b03.validate_ledger({"attempts": [attempt]})
    attempt["remediation"]["action_id"] = "different.action"
    with pytest.raises(ValueError, match="differs from the accepted AI proposal"):
        b03.validate_ledger({"attempts": [attempt]})


def test_ledger_rejects_duplicate_attempt_and_invalid_retry_parent():
    with pytest.raises(ValueError, match="unique"):
        b03.validate_ledger({"attempts": [{"run_id": "same"}, {"run_id": "same"}]})
    with pytest.raises(ValueError, match="retry parent"):
        b03.validate_ledger({"attempts": [{"run_id": "retry", "retry_of": "missing"}]})


def test_failed_investigation_projection_keeps_only_sanitized_metadata(monkeypatch):
    monkeypatch.setattr(
        b03_live,
        "cli",
        lambda *args, **kwargs: {
            "exit_code": 0,
            "stdout": json.dumps({"investigations": [{"investigation_id": "investigation-1"}]}),
        },
    )
    observed = {}

    def guest_exec(vm, path, args, **kwargs):
        observed["query"] = args[1]
        return {
            "exit_code": 0,
            "stdout": json.dumps(
                {
                    "status": "failed",
                    "failure_stage": "assessment",
                    "failure_category": "reply_schema_invalid",
                    "selected_diagnostics": ["b03_web_diagnostics"],
                    "evidence_count": 6,
                    "execution_ids": ["execution-1"],
                }
            ),
        }

    monkeypatch.setattr(b03_live, "guest_exec", guest_exec)
    result = b03_live.persisted_investigation_failure("incident-1")
    assert result["failure_category"] == "reply_schema_invalid"
    assert result["execution_ids"] == ["execution-1"]
    assert "result_json" in observed["query"]
    assert "raw" not in result


@pytest.mark.parametrize("body", ["dependency-ConnectionRefusedError", "dependency-TimeoutError"])
def test_dns_misdirection_requires_wrong_answer_and_observed_http_failure(body):
    assert b03_live.dns_misdirection_confirmed(
        {"dns_answer": "10.60.20.99", "http_status": 503, "http_body": body}
    )
    assert not b03_live.dns_misdirection_confirmed(
        {"dns_answer": "10.60.20.10", "http_status": 503, "http_body": body}
    )
    assert not b03_live.dns_misdirection_confirmed(
        {"dns_answer": "10.60.20.99", "http_status": 200, "http_body": "ready"}
    )


def test_dns_blackhole_requires_live_resolver_missing_reply_and_http_timeout():
    observed = {
        "dns_answer": None,
        "http_status": 503,
        "http_body": "dependency-TimeoutError",
        "unit_states": {b03_live.WEB_UNITS["dns"]: "active"},
    }
    assert b03_live.dns_blackhole_confirmed(observed)
    no_resolver = {**observed, "unit_states": {b03_live.WEB_UNITS["dns"]: "inactive"}}
    assert not b03_live.dns_blackhole_confirmed(no_resolver)
    malformed_empty_reply = {**observed, "http_body": "dependency-ValueError"}
    assert not b03_live.dns_blackhole_confirmed(malformed_empty_reply)


def test_ledger_binds_each_compound_followup_to_ai_proposal_and_approval():
    phases = {
        name: {"status": "PASS"}
        for name in (
            "baseline",
            "fault",
            "incident",
            "diagnostics",
            "assessment",
            "proposal",
            "authorization",
            "remediation",
            "postflight",
            "audit",
            "closure",
            "cleanup",
        )
    }
    phases["proposal"].update(
        selected_action_id="systemd.restart",
        target_ref="b03-app-unit",
        validated_candidate={"arguments": {"unit": b03_live.WEB_UNITS["app"]}},
    )
    phases["remediation"].update(
        action_id="systemd.restart",
        target_ref="b03-app-unit",
        arguments={"unit": b03_live.WEB_UNITS["app"]},
    )
    phases["proposal_followups"] = [
        {
            "status": "PASS",
            "selected_action_id": "systemd.restart",
            "target_ref": "b03-backend-unit",
            "validated_candidate": {"arguments": {"unit": b03_live.WEB_UNITS["backend"]}},
        }
    ]
    phases["authorization_followups"] = [{"status": "PASS", "plan_id": "followup-plan"}]
    phases["remediation_followups"] = [
        {
            "status": "PASS",
            "action_id": "systemd.restart",
            "target_ref": "b03-backend-unit",
            "arguments": {"unit": b03_live.WEB_UNITS["backend"]},
            "plan_id": "followup-plan",
        }
    ]
    attempt = {"run_id": "compound-1", "result": "AI_DRIVEN_PASS", "steps": phases}
    b03.validate_ledger({"attempts": [attempt]})
    phases["remediation_followups"][0]["target_ref"] = "forged-target"
    with pytest.raises(ValueError, match="follow-up execution differs"):
        b03.validate_ledger({"attempts": [attempt]})


def test_compound_followup_candidates_come_from_observed_remaining_failure():
    scenario = next(item for item in b03_live.SCENARIOS if item["id"] == "B03-10")
    active = {unit: "active" for unit in b03_live.WEB_UNITS.values()}
    app_still_invalid = {
        "snapshot": {
            "unit_states": active,
            "http_status": 503,
            "http_body": "invalid-application-configuration",
        }
    }
    candidates = b03_live.remaining_recovery_candidates(scenario, app_still_invalid)
    assert len(candidates) == 1
    assert candidates[0]["arguments"]["unit"] == b03_live.WEB_UNITS["app"]

    backend_still_down = {
        "snapshot": {
            "unit_states": {
                **active,
                b03_live.WEB_UNITS["backend"]: "inactive",
            },
            "http_status": 503,
            "http_body": "dependency-ConnectionRefusedError",
        }
    }
    candidates = b03_live.remaining_recovery_candidates(scenario, backend_still_down)
    assert len(candidates) == 1
    assert candidates[0]["arguments"]["unit"] == b03_live.WEB_UNITS["backend"]


def test_ledger_enforces_proposal_target_and_arguments_match_executed_plan():
    attempt = {
        "run_id": "run-binding",
        "result": "AI_DRIVEN_PASS",
        "steps": {
            name: {"status": "PASS"}
            for name in (
                "baseline",
                "fault",
                "incident",
                "diagnostics",
                "assessment",
                "proposal",
                "authorization",
                "remediation",
                "postflight",
                "audit",
                "closure",
                "cleanup",
            )
        },
    }
    attempt["steps"]["proposal"].update(
        selected_action_id="systemd.restart",
        target_ref="b03-app-unit",
        validated_candidate={"arguments": {"unit": "runbookos-campaign-b03-app.service"}},
    )
    attempt["steps"]["remediation"].update(
        action_id="systemd.restart",
        target_ref="b03-app-unit",
        arguments={"unit": "runbookos-campaign-b03-app.service"},
    )
    b03.validate_ledger({"attempts": [attempt]})
    attempt["steps"]["remediation"]["arguments"] = {"unit": "other.service"}
    with pytest.raises(ValueError, match="arguments differ"):
        b03.validate_ledger({"attempts": [attempt]})


def test_guest_exec_binds_qga_commands_to_the_requested_vm(monkeypatch):
    calls = []

    def fake_qga(vm, payload, timeout=15):
        calls.append((vm, payload))
        if payload["execute"] == "guest-exec":
            return {"pid": 42}
        return {
            "exited": True,
            "exitcode": 0,
            "out-data": base64.b64encode(b"ok").decode(),
            "err-data": "",
        }

    monkeypatch.setattr(b03_live, "qga", fake_qga)
    result = b03_live.guest_exec("runbookos-svc-web-01", "/bin/true", [])
    assert result["stdout"] == "ok"
    assert [call[0] for call in calls] == ["runbookos-svc-web-01", "runbookos-svc-web-01"]


def test_monitored_cli_returns_one_result_with_resource_report(monkeypatch):
    events = []

    class FakeWatch:
        def start(self):
            events.append("start")

        def check(self):
            events.append("check")

        def report(self):
            return {"status": "passed", "sample_count": 1}

        def stop(self):
            events.append("stop")

    monkeypatch.setattr(b03_live, "resource_watch", FakeWatch)
    monkeypatch.setattr(
        b03_live,
        "guest_exec",
        lambda *args, **kwargs: {"exit_code": 0, "stdout": "{}", "stderr": ""},
    )

    result = b03_live.cli("incidents", "investigate", "incident", monitored=True)

    assert result["exit_code"] == 0
    assert result["stdout"] == "{}"
    assert result["resource_watch"] == {"status": "passed", "sample_count": 1}
    assert events == ["start", "check", "stop", "check"]


def test_monitored_cli_sanitizes_transport_exception(monkeypatch):
    class FakeWatch:
        def start(self):
            return None

        def report(self):
            return {"status": "passed"}

        def stop(self):
            return None

    monkeypatch.setattr(b03_live, "resource_watch", FakeWatch)

    def fail_transport(*args, **kwargs):
        raise ValueError("sensitive command output must not escape")

    monkeypatch.setattr(b03_live, "guest_exec", fail_transport)
    result = b03_live.cli("incidents", "investigate", "incident", monitored=True, check=False)

    assert result["exit_code"] is None
    assert result["transport_failure_category"] == "ValueError"
    assert result["transport_failure_component"] == "guest_command"
    assert "sensitive command output" not in json.dumps(result)


def test_campaign_database_integrity_uses_python_sqlite(monkeypatch):
    calls = []

    def fake_guest_exec(vm, path, args, **kwargs):
        calls.append((vm, path, args))
        return {"exit_code": 0, "stdout": "ok\n", "stderr": ""}

    monkeypatch.setattr(b03_live, "guest_exec", fake_guest_exec)

    assert b03_live.sqlite_integrity() == "ok"
    assert calls[0][1] == "/usr/bin/python3"
    assert "PRAGMA integrity_check" in calls[0][2][1]
    assert calls[0][2][-1] == b03_live.DB


def test_investigation_projection_records_execution_evidence_without_claiming_support():
    result = {
        "selected_diagnostics": ["b03_web_diagnostics"],
        "evidence": [
            {"ref": "exec-1:app-http", "execution_id": "exec-1"},
            {"ref": "exec-1:backend-tcp", "execution_id": "exec-1"},
        ],
        "assessment": {
            "assessment_status": "assessed",
            "classifications": [{"category": "service_failure", "confidence": 0.85}],
        },
    }
    summary = {
        "status": "PASS",
        "category": "service_failure",
        "confidence": 0.85,
        "evidence_refs": ["exec-1:app-http", "exec-1:backend-tcp"],
    }

    steps = b03_live.investigation_ledger_steps(result, summary)

    assert steps["diagnostics"]["status"] == "PASS"
    assert steps["diagnostics"]["execution_ids"] == ["exec-1"]
    assert steps["assessment"]["status"] == "PASS"
    assert steps["assessment"]["semantic_support"] == "unverified"


def test_campaign_alert_uses_a_supported_alert_category():
    from runbookos.incidents import parse_alert

    alert = {
        "alert_id": "batch03-test-1",
        "source": "runbookos-campaign-batch03",
        "event_timestamp": "2026-10-27T10:00:00+00:00",
        "severity": "error",
        "target_alias": "svc-web-01",
        "service": "campaign-application",
        "category": "dependency",
        "summary": "A disposable campaign health check reported an unexpected condition.",
        "fingerprint": "batch03-test-1",
        "metadata": {"campaign": "batch03"},
    }
    assert parse_alert(json.dumps(alert).encode()).category.value == "dependency"


def test_ledger_sync_retries_only_exact_byte_copy_and_verifies_digest():
    state = {"writes": 0, "stored": None}

    def write(payload):
        state["writes"] += 1
        state["stored"] = payload

    def verify(payload):
        return state["writes"] >= 2 and state["stored"] == payload

    result = b03.synchronize_ledger(b"immutable-ledger", write, verify, attempts=2)
    assert result == {"status": "PASS", "attempts": 2}
    assert state["stored"] == b"immutable-ledger"


def test_ledger_sync_reports_failure_without_unbounded_retry():
    state = {"writes": 0}

    def write(_payload):
        state["writes"] += 1
        raise OSError("sync failed")

    result = b03.synchronize_ledger(b"ledger", write, lambda _: False, attempts=2)
    assert result["status"] == "FAIL"
    assert result["attempts"] == 2
    assert state["writes"] == 2


class OneReplyProvider:
    def __init__(self, body: str):
        self.body = body
        self.calls = []

    def complete(self, system, user, max_tokens, temperature):
        self.calls.append((system, user, max_tokens, temperature))
        return SimpleNamespace(
            content=self.body,
            model="mock-qwen-contract-test",
            duration_seconds=0.01,
            token_usage={"completion_tokens": 10},
        )


def test_proposal_request_is_one_bounded_call_and_binds_registered_candidate():
    body = (
        '{"proposal_version":1,"incident_id":"i1","investigation_id":"x1",'
        '"evidence_refs":["E01"],"suspected_fault_category":"service_failure",'
        '"uncertainty":0.2,"causal_hypothesis":"The fixture service is inactive.",'
        '"candidate_action_id":"systemd.restart","target_ref":"fixture",'
        '"expected_recovery_effect":"The service may return to readiness.",'
        '"rationale":"The cited observation reports an inactive service.",'
        '"contraindications":[],"abstain":false}'
    )
    provider = OneReplyProvider(body)
    candidate = RegisteredActionCandidate(
        action_id="systemd.restart",
        target_ref="fixture",
        target_name="fixture-web",
        arguments={"unit": "runbookos-campaign-b03-api.service"},
        required_evidence_actions=("systemd.is_active",),
        compatible_categories=("service_failure",),
    )
    reply, metadata = request_remediation_proposal(
        provider,
        incident_id="i1",
        investigation_id="x1",
        evidence=[
            {
                "ref": "e1",
                "source_action": "systemd.is_active",
                "evidence": {
                    "data": {"unit": "runbookos-campaign-b03-api.service", "active": True}
                },
            }
        ],
        candidates=[candidate],
        evidence_actions={"e1": "systemd.is_active"},
    )
    assert reply.candidate_action_id == "systemd.restart"
    assert metadata["validation"]["candidate"]["arguments"] == {
        "unit": "runbookos-campaign-b03-api.service"
    }
    assert metadata["request_count"] == 1
    assert len(provider.calls) == 1
    assert provider.calls[0][2:] == (384, 0)
    assert "contraindications (array of strings" in provider.calls[0][0]
    assert "evidence_refs (array of unique case-local aliases" in provider.calls[0][0]
    assert "abstain boolean is mandatory in every response" in provider.calls[0][0]
    assert "For abstain=true" in provider.calls[0][0]
    assert "ground_truth" not in provider.calls[0][1]


def test_proposal_timeout_is_not_retried():
    class TimeoutProvider:
        calls = 0

        def complete(self, *args, **kwargs):
            self.calls += 1
            raise TimeoutError("provider timed out")

    provider = TimeoutProvider()
    candidate = RegisteredActionCandidate(
        action_id="systemd.restart",
        target_ref="fixture",
        target_name="fixture-web",
        arguments={"unit": "runbookos-campaign-b03-api.service"},
        compatible_categories=("service_failure",),
    )
    with pytest.raises(TimeoutError):
        request_remediation_proposal(
            provider,
            incident_id="i1",
            investigation_id="x1",
            evidence=[{"ref": "e1"}],
            candidates=[candidate],
        )
    assert provider.calls == 1


def test_late_resource_failure_is_checked_after_monitor_stops(monkeypatch):
    class Watch:
        stopped = False

        def start(self):
            pass

        def check(self):
            if self.stopped:
                raise RuntimeError("sanitized guard failure")

        def stop(self):
            self.stopped = True

        def report(self):
            return {"status": "failed", "failure_category": "resource_threshold_exceeded"}

    monkeypatch.setattr(b03_live, "resource_watch", Watch)
    monkeypatch.setattr(
        b03_live, "guest_exec", lambda *a, **k: {"exit_code": 0, "stdout": "{}", "stderr": ""}
    )
    result = b03_live.cli("incidents", "investigate", "i", monitored=True, check=False)
    assert result["exit_code"] is None
    assert result["resource_watch"]["status"] == "failed"
    assert result["transport_failure_component"] == "resource_watch_postflight"
