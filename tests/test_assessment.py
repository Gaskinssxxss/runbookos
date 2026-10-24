from __future__ import annotations

from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from runbookos.assessment import (
    ClassificationAssessment,
    EvidenceObservation,
    HypothesisClaim,
    InferenceClaim,
    ModelAssessmentReply,
    StructuredAssessment,
    UnknownClaim,
    make_observations,
    validate_assessment,
)


def _observation(
    ref: str = "exec-1:step-1",
    *,
    status: str = "succeeded",
    active: bool = True,
    observed_at: str = "2026-10-22T00:00:00+00:00",
    diagnostic_id: str = "web_health",
    step_id: str = "check-service",
) -> EvidenceObservation:
    result = {
        "ok": True,
        "data": {"unit": "nginx.service", "active": active},
        "assertions": [{"passed": active, "detail": "synthetic assertion"}],
    }
    row = make_observations(
        [
            {
                "ref": ref,
                "execution_id": ref.split(":", 1)[0],
                "diagnostic_id": diagnostic_id,
                "action": "systemd.is_active",
                "target": "synthetic-web",
                "step_id": step_id,
                "observed_at": observed_at,
                "status": status,
                "evidence": result,
            }
        ],
        incident_id="incident-synthetic",
        investigation_id="investigation-synthetic",
    )
    return row[0]


def _assessment(**overrides) -> StructuredAssessment:
    values = {
        "schema_version": 1,
        "classification_catalog_version": 2,
        "incident_id": "incident-synthetic",
        "investigation_id": "investigation-synthetic",
        "observations": [_observation()],
        "inferences": [],
        "hypotheses": [],
        "classifications": [],
        "unknowns": [],
        "recommended_next_steps": [],
        "overall_uncertainty": 1.0,
        "assessment_status": "abstained",
        "semantic_support_status": "unverified",
        "recommendations_are_executable": False,
    }
    values.update(overrides)
    return StructuredAssessment.model_validate(values)


def test_service_not_active_is_direct_observation_and_failed_assertion_stays_unverified():
    observation = _observation("exec-inactive:step-1", status="failed", active=False)
    assert observation.claim_type == "observation"
    assert observation.observed_result["data"]["active"] is False
    assert observation.assertion_outcome == "failed"
    assert observation.execution_status == "failed"
    assert observation.verification_status == "not_verified"
    assert observation.observed_at is not None
    assert observation.incident_id == "incident-synthetic"
    assert observation.investigation_id == "investigation-synthetic"


def test_citation_validity_does_not_claim_semantic_support_for_corrupt_config_claim():
    item = _observation()
    claim = InferenceClaim(
        statement="The service configuration file is corrupt.", evidence_refs=[item.ref]
    )
    result = validate_assessment(
        _assessment(inferences=[claim], assessment_status="partial", overall_uncertainty=0.6)
    )
    assert result.semantic_support_status == "unverified"


def test_missing_reference_is_rejected():
    with pytest.raises(ValueError, match="outside this investigation"):
        validate_assessment(
            _assessment(
                inferences=[InferenceClaim(statement="Observed", evidence_refs=["forged:ref"])],
                assessment_status="partial",
            )
        )


def test_duplicate_claim_references_are_rejected():
    with pytest.raises(ValidationError, match="duplicate evidence references"):
        InferenceClaim(statement="Observed", evidence_refs=["exec-1:step-1"] * 2)


@pytest.mark.parametrize("value", [float("nan"), float("inf"), float("-inf")])
def test_non_finite_confidence_values_are_rejected(value: float):
    with pytest.raises(ValidationError):
        HypothesisClaim(statement="Possible", confidence=value)
    with pytest.raises(ValidationError):
        ClassificationAssessment(category="unknown", confidence=value, status="undetermined")


def test_unsupported_classification_category_is_rejected():
    with pytest.raises(ValidationError):
        ClassificationAssessment(category="config_corruption", confidence=0.5, status="suspected")


def test_insufficient_evidence_supports_explicit_abstention():
    item = UnknownClaim(question="Is the service reachable?", missing_evidence=["a live probe"])
    result = validate_assessment(
        _assessment(
            observations=[],
            unknowns=[item],
            assessment_status="abstained",
            overall_uncertainty=1.0,
        )
    )
    assert result.assessment_status == "abstained"
    assert result.classifications == []


def test_undetermined_classification_is_a_valid_abstention():
    classification = ClassificationAssessment(
        category="unknown", confidence=0.95, status="undetermined"
    )
    result = validate_assessment(
        _assessment(
            observations=[],
            classifications=[classification],
            assessment_status="abstained",
            overall_uncertainty=1.0,
        )
    )
    assert result.classifications[0].status == "undetermined"


def test_no_evidence_can_be_persisted_as_abstention():
    result = validate_assessment(
        _assessment(observations=[], assessment_status="abstained", overall_uncertainty=1.0)
    )
    assert result.observations == []
    assert result.assessment_status == "abstained"


def test_contradictory_direct_observations_cannot_support_completed_classification():
    first = _observation("exec-a:step-1", active=True)
    second = _observation("exec-b:step-1", active=False)
    classification = ClassificationAssessment(
        category="service_failure",
        confidence=0.9,
        supporting_evidence_refs=[first.ref],
        status="supported",
    )
    with pytest.raises(ValueError, match="contradictory observations"):
        validate_assessment(
            _assessment(
                observations=[first, second],
                classifications=[classification],
                assessment_status="assessed",
                overall_uncertainty=0.2,
            )
        )


def test_distinct_hypotheses_keep_independent_confidence_values():
    hypotheses = [
        HypothesisClaim(
            statement="Service process is inactive.",
            confidence=0.8,
            evidence_refs=["exec-1:step-1"],
        ),
        HypothesisClaim(
            statement="A dependency may be unavailable.",
            confidence=0.35,
            evidence_refs=["exec-1:step-1"],
        ),
    ]
    result = validate_assessment(
        _assessment(hypotheses=hypotheses, assessment_status="partial", overall_uncertainty=0.4)
    )
    assert [item.confidence for item in result.hypotheses] == [0.8, 0.35]


def test_schema_version_mismatch_is_rejected():
    with pytest.raises(ValidationError):
        _assessment(schema_version=2)


def test_duplicate_observation_references_are_rejected():
    item = _observation()
    with pytest.raises(ValueError, match="duplicate evidence observations"):
        validate_assessment(_assessment(observations=[item, item]))


def test_supported_classification_requires_verified_evidence():
    failed = _observation("exec-failed:step-1", status="failed", active=False)
    classification = ClassificationAssessment(
        category="service_failure",
        confidence=0.9,
        supporting_evidence_refs=[failed.ref],
        status="supported",
    )
    with pytest.raises(ValueError, match="verified evidence only"):
        validate_assessment(
            _assessment(
                observations=[failed],
                classifications=[classification],
                assessment_status="assessed",
            )
        )


def test_unreferenced_high_confidence_hypothesis_is_rejected():
    hypothesis = HypothesisClaim(statement="Unsupported claim", confidence=0.9)
    with pytest.raises(ValueError, match="unsupported hypotheses"):
        validate_assessment(_assessment(hypotheses=[hypothesis], assessment_status="partial"))


def test_advisory_recommendations_are_allowed_but_commands_are_rejected():
    reply = ModelAssessmentReply(
        recommended_next_steps=["An operator may inspect the service health evidence."]
    )
    assert reply.recommended_next_steps
    with pytest.raises(ValidationError, match="advisory"):
        ModelAssessmentReply(recommended_next_steps=["systemctl restart nginx.service"])


def test_model_cannot_claim_recommendations_are_executable():
    with pytest.raises(ValidationError):
        ModelAssessmentReply.model_validate({"recommendations_are_executable": True})


def test_observation_timestamps_are_source_timestamps_not_model_claims():
    expected = datetime.now(UTC).isoformat()
    item = _observation(observed_at=expected)
    assert item.observed_at == expected
