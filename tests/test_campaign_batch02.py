from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

MODULE_PATH = Path(__file__).parents[1] / "scripts" / "campaign_batch02.py"
SPEC = importlib.util.spec_from_file_location("campaign_batch02", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
batch02 = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = batch02
SPEC.loader.exec_module(batch02)


def test_four_bounded_diagnostics_fit_existing_budget_without_widening() -> None:
    budget = batch02.calculate_investigation_budget([5, 5, 5, 5])
    assert budget.configured_seconds == 90
    assert budget.conservative_required_seconds == 68
    assert budget.action_count == 4


def test_budget_rejects_cost_above_existing_limit() -> None:
    with pytest.raises(ValueError, match="existing bounded execution budget"):
        batch02.calculate_investigation_budget([10] * 5)


@pytest.mark.parametrize(
    "assessment",
    [
        None,
        {},
        {"accepted": False, "assessment_status": "assessed"},
        {"accepted": True, "assessment_status": "invalid"},
    ],
)
def test_rejected_or_missing_assessment_cannot_authorize_workflow_close(assessment) -> None:
    assert not batch02.accepted_assessment(assessment)
    assert not batch02.workflow_can_close(
        assessment=assessment,
        remediation_succeeded=True,
        postflight_recovered=True,
        audit_valid=True,
        sqlite_valid=True,
    )


@pytest.mark.parametrize("status", ["assessed", "abstained"])
def test_valid_persisted_assessment_is_necessary_but_not_sufficient_to_close(status) -> None:
    assessment = {"accepted": True, "assessment_status": status}
    assert batch02.accepted_assessment(assessment)
    assert not batch02.workflow_can_close(
        assessment=assessment,
        remediation_succeeded=False,
        postflight_recovered=True,
        audit_valid=True,
        sqlite_valid=True,
    )


def test_incident_closes_only_after_execution_recovery_and_integrity_pass() -> None:
    assert batch02.workflow_can_close(
        assessment={"accepted": True, "assessment_status": "assessed"},
        remediation_succeeded=True,
        postflight_recovered=True,
        audit_valid=True,
        sqlite_valid=True,
    )
    for field in ("postflight_recovered", "audit_valid", "sqlite_valid"):
        values = {
            "assessment": {"accepted": True, "assessment_status": "assessed"},
            "remediation_succeeded": True,
            "postflight_recovered": True,
            "audit_valid": True,
            "sqlite_valid": True,
        }
        values[field] = False
        assert not batch02.workflow_can_close(**values)


def test_retries_have_unique_non_overwriting_run_ids() -> None:
    ids = {batch02.retry_run_id("B02-01", n) for n in range(1, 4)}
    assert len(ids) == 3
    assert "batch02-B02-01-attempt03" in ids
    with pytest.raises(ValueError):
        batch02.retry_run_id("B02-01", 0)


def test_evidence_refs_must_match_incident_execution_refs_exactly() -> None:
    available = ["execution-1:health", "execution-1:backend"]
    assert batch02.evidence_references_valid(["execution-1:health"], available)
    assert batch02.evidence_references_valid([], available)
    assert not batch02.evidence_references_valid(["forged:health"], available)
    assert not batch02.evidence_references_valid(["execution-1:health"] * 2, available)


def test_observation_adjudication_uses_persisted_values_not_ground_truth() -> None:
    observations = [
        {
            "ref": "execution-1:http-health",
            "step_id": "http-health",
            "source_action": "http.readiness",
            "observed_result": {"data": {"http_status": 503, "ready": False}},
        }
    ]
    result = batch02.adjudicate_observation_claims(
        "The HTTP readiness check returned HTTP 503.", observations
    )
    assert result["observation_claim_support"] == "supported"
    assert result["causal_claim_support"] == "insufficient"
    assert result["uses_ground_truth"] is False


def test_observation_adjudication_flags_claim_contradicted_by_http_result() -> None:
    observations = [
        {
            "ref": "execution-1:http-health",
            "step_id": "http-health",
            "source_action": "http.readiness",
            "observed_result": {"data": {"http_status": 503, "ready": False}},
        }
    ]
    result = batch02.adjudicate_observation_claims("The local HTTP checks succeed.", observations)
    assert result["observation_claim_support"] == "contradicted"


def test_runuser_resolution_uses_verified_guest_path_order() -> None:
    assert (
        batch02.resolve_runuser_path(("/absent/runuser", "/usr/sbin/runuser"))
        == "/usr/sbin/runuser"
    )
    with pytest.raises(FileNotFoundError):
        batch02.resolve_runuser_path(("/absent/runuser",))


def test_fixture_restart_limit_is_short_and_bounded() -> None:
    assert batch02.fixture_start_limit() == "StartLimitIntervalSec=5\nStartLimitBurst=3"
    with pytest.raises(ValueError):
        batch02.fixture_start_limit(interval_seconds=300)


def test_resource_fault_uses_bounded_cpu_throttle_not_host_oom() -> None:
    profile = batch02.resource_fault_profile()
    assert profile["cpu_quota_percent"] == 20
    assert profile["memory_max_bytes"] <= 384 * 1024 * 1024
    assert profile["host_wide_resource_exhaustion"] is False
    assert profile["oom_injection"] is False
