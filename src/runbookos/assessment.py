"""Versioned, evidence-aware investigation assessments.

Model-authored claims are kept separate from observations derived from stored
diagnostic step results. Validation proves schema and reference integrity only;
semantic support remains an independent review question.
"""

from __future__ import annotations

import json
import math
import re
from typing import Any, Literal

from pydantic import (
    AliasChoices,
    BaseModel,
    ConfigDict,
    Field,
    ValidationError,
    field_validator,
    model_validator,
)

from .errors import RunbookOSError
from .store import canonical_json, redact

ASSESSMENT_SCHEMA_VERSION = 1
CLASSIFICATION_CATALOG_VERSION = 2
CLASSIFICATION_CATEGORIES = (
    "healthy",
    "service_failure",
    "connectivity_failure",
    "network_failure",
    "dependency_failure",
    "resource_pressure",
    "unknown",
)

_MUTATING_ADVICE = re.compile(
    r"(^\s*(sudo|systemctl|service|kill|pkill|rm|mv|chmod|chown|iptables|nft)\b)"
    r"|(`|\$\(|&&|\|\||[;|<>])"
    r"|\b(restart|stop|start|disable|enable|kill|terminate|remediate|apply\s+change)\b",
    re.IGNORECASE,
)


def _validate_advisory_steps(values: list[str]) -> list[str]:
    if any(not value.strip() or len(value) > 500 for value in values):
        raise ValueError("each next step must contain 1–500 characters")
    if any(_MUTATING_ADVICE.search(value) for value in values):
        raise ValueError("next steps must remain advisory and non-executable")
    return values


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class EvidenceObservation(StrictModel):
    """One direct observation copied from a persisted execution step."""

    claim_type: Literal["observation"] = "observation"
    statement: str = Field(min_length=1, max_length=500)
    ref: str = Field(min_length=3, max_length=256)
    evidence_refs: list[str] = Field(min_length=1, max_length=1)
    execution_id: str = Field(min_length=1, max_length=128)
    diagnostic_id: str = Field(min_length=1, max_length=64)
    source_action: str = Field(min_length=1, max_length=128)
    target: str = Field(min_length=1, max_length=128)
    step_id: str = Field(min_length=1, max_length=128)
    observed_at: str | None = Field(default=None, max_length=64)
    observed_result: dict[str, Any]
    execution_status: Literal["succeeded", "failed", "unknown"]
    assertion_outcome: Literal["passed", "failed", "not_present", "unknown"]
    verification_status: Literal["verified", "not_verified", "unknown"]
    incident_id: str | None = Field(default=None, max_length=128)
    investigation_id: str = Field(min_length=1, max_length=128)

    @model_validator(mode="after")
    def self_reference_only(self) -> EvidenceObservation:
        if self.evidence_refs != [self.ref]:
            raise ValueError("observation evidence_refs must contain its own stable ref")
        return self


class InferenceClaim(StrictModel):
    claim_type: Literal["inference"] = "inference"
    statement: str = Field(min_length=1, max_length=1000)
    evidence_refs: list[str] = Field(min_length=1, max_length=32)

    @field_validator("evidence_refs")
    @classmethod
    def refs_are_unique(cls, refs: list[str]) -> list[str]:
        if len(refs) != len(set(refs)):
            raise ValueError("duplicate evidence references are not allowed")
        return refs


class HypothesisClaim(StrictModel):
    claim_type: Literal["hypothesis"] = "hypothesis"
    statement: str = Field(
        min_length=1,
        max_length=1000,
        validation_alias=AliasChoices("statement", "hypothesis"),
    )
    evidence_refs: list[str] = Field(default_factory=list, max_length=32)
    confidence: float = Field(ge=0, le=1)
    missing_evidence: list[str] = Field(default_factory=list, max_length=16)
    disconfirming_checks: list[str] = Field(default_factory=list, max_length=16)

    @field_validator("confidence", mode="before")
    @classmethod
    def numeric_confidence(cls, value: Any) -> Any:
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise ValueError("confidence must be a JSON number")
        return value

    @field_validator("confidence")
    @classmethod
    def finite_confidence(cls, value: float) -> float:
        if not math.isfinite(value):
            raise ValueError("confidence must be finite")
        return value

    @field_validator("evidence_refs")
    @classmethod
    def refs_are_unique(cls, refs: list[str]) -> list[str]:
        if len(refs) != len(set(refs)):
            raise ValueError("duplicate evidence references are not allowed")
        return refs

    @field_validator("missing_evidence", "disconfirming_checks")
    @classmethod
    def bounded_check_text(cls, values: list[str]) -> list[str]:
        if any(not value.strip() or len(value) > 500 for value in values):
            raise ValueError("each evidence gap or check must contain 1–500 characters")
        return values


class UnknownClaim(StrictModel):
    claim_type: Literal["unknown"] = "unknown"
    question: str = Field(min_length=1, max_length=1000)
    evidence_refs: list[str] = Field(default_factory=list, max_length=32)
    missing_evidence: list[str] = Field(default_factory=list, max_length=16)

    @field_validator("evidence_refs")
    @classmethod
    def refs_are_unique(cls, refs: list[str]) -> list[str]:
        if len(refs) != len(set(refs)):
            raise ValueError("duplicate evidence references are not allowed")
        return refs

    @field_validator("missing_evidence")
    @classmethod
    def bounded_missing_evidence(cls, values: list[str]) -> list[str]:
        if any(not value.strip() or len(value) > 500 for value in values):
            raise ValueError("each missing-evidence item must contain 1–500 characters")
        return values


class ClassificationAssessment(StrictModel):
    category: Literal[
        "healthy",
        "service_failure",
        "connectivity_failure",
        "network_failure",
        "dependency_failure",
        "resource_pressure",
        "unknown",
    ]
    confidence: float = Field(ge=0, le=1)
    supporting_evidence_refs: list[str] = Field(default_factory=list, max_length=32)
    status: Literal["suspected", "supported", "undetermined"]

    @field_validator("confidence", mode="before")
    @classmethod
    def numeric_confidence(cls, value: Any) -> Any:
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise ValueError("confidence must be a JSON number")
        return value

    @field_validator("confidence")
    @classmethod
    def finite_confidence(cls, value: float) -> float:
        if not math.isfinite(value):
            raise ValueError("confidence must be finite")
        return value

    @field_validator("supporting_evidence_refs")
    @classmethod
    def refs_are_unique(cls, refs: list[str]) -> list[str]:
        if len(refs) != len(set(refs)):
            raise ValueError("duplicate evidence references are not allowed")
        return refs

    @model_validator(mode="after")
    def unknown_is_undetermined(self) -> ClassificationAssessment:
        if self.category == "unknown" and self.status != "undetermined":
            raise ValueError("unknown classification must have undetermined status")
        return self


class ModelAssessmentReply(StrictModel):
    """Provider reply; optional fields accept legacy v0.6.0 analysis JSON."""

    inferences: list[InferenceClaim] = Field(default_factory=list, max_length=16)
    hypotheses: list[HypothesisClaim] = Field(default_factory=list, max_length=12)
    classifications: list[ClassificationAssessment] = Field(default_factory=list, max_length=8)
    unknowns: list[UnknownClaim] = Field(default_factory=list, max_length=12)
    recommended_next_steps: list[str] = Field(default_factory=list, max_length=12)
    overall_uncertainty: float = Field(default=1.0, ge=0, le=1)
    assessment_status: Literal["assessed", "partial", "abstained"] | None = None

    @field_validator("overall_uncertainty", mode="before")
    @classmethod
    def numeric_uncertainty(cls, value: Any) -> Any:
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise ValueError("overall_uncertainty must be a JSON number")
        return value

    @field_validator("overall_uncertainty")
    @classmethod
    def finite_uncertainty(cls, value: float) -> float:
        if not math.isfinite(value):
            raise ValueError("overall_uncertainty must be finite")
        return value

    @field_validator("recommended_next_steps")
    @classmethod
    def advisory_only(cls, values: list[str]) -> list[str]:
        return _validate_advisory_steps(values)

    @field_validator("inferences", "hypotheses", "classifications", "unknowns")
    @classmethod
    def bounded_lists(cls, values: list[Any]) -> list[Any]:
        if any(item is None for item in values):
            raise ValueError("assessment lists cannot contain null items")
        return values


class StructuredAssessment(StrictModel):
    schema_version: Literal[1]
    classification_catalog_version: Literal[2]
    incident_id: str | None
    investigation_id: str = Field(min_length=1, max_length=128)
    observations: list[EvidenceObservation] = Field(max_length=256)
    inferences: list[InferenceClaim] = Field(max_length=16)
    hypotheses: list[HypothesisClaim] = Field(max_length=12)
    classifications: list[ClassificationAssessment] = Field(max_length=8)
    unknowns: list[UnknownClaim] = Field(max_length=12)
    recommended_next_steps: list[str] = Field(max_length=12)
    overall_uncertainty: float = Field(ge=0, le=1)
    assessment_status: Literal["assessed", "partial", "abstained"]
    semantic_support_status: Literal["unverified"] = "unverified"
    recommendations_are_executable: Literal[False] = False

    @field_validator("overall_uncertainty", mode="before")
    @classmethod
    def numeric_uncertainty(cls, value: Any) -> Any:
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise ValueError("overall_uncertainty must be a JSON number")
        return value

    @field_validator("recommended_next_steps")
    @classmethod
    def advisory_only(cls, values: list[str]) -> list[str]:
        return _validate_advisory_steps(values)

    @field_validator("overall_uncertainty")
    @classmethod
    def finite_uncertainty(cls, value: float) -> float:
        if not math.isfinite(value):
            raise ValueError("overall_uncertainty must be finite")
        return value


def _assertion_outcome(result: dict[str, Any]) -> str:
    assertions = result.get("assertions")
    if not isinstance(assertions, list) or not assertions:
        return "not_present"
    if any(
        not isinstance(item, dict) or not isinstance(item.get("passed"), bool)
        for item in assertions
    ):
        return "unknown"
    return "failed" if any(item["passed"] is False for item in assertions) else "passed"


def make_observations(
    evidence: list[dict[str, Any]], incident_id: str | None, investigation_id: str
) -> list[EvidenceObservation]:
    observations = []
    for item in evidence:
        status = item.get("status")
        verification = {
            "succeeded": "verified",
            "failed": "not_verified",
            "unknown": "unknown",
        }.get(status, "unknown")
        observed_result = item.get("evidence")
        if not isinstance(observed_result, dict):
            observed_result = {"value": observed_result}
        observations.append(
            EvidenceObservation(
                statement=(
                    f"Diagnostic step {item['step_id']} used {item['action']} on "
                    f"{item['target']} and finished with status {status}."
                ),
                ref=item["ref"],
                evidence_refs=[item["ref"]],
                execution_id=item["execution_id"],
                diagnostic_id=item["diagnostic_id"],
                source_action=item["action"],
                target=item["target"],
                step_id=item["step_id"],
                observed_at=item.get("observed_at"),
                observed_result=observed_result,
                execution_status=status,
                assertion_outcome=_assertion_outcome(observed_result),
                verification_status=verification,
                incident_id=incident_id,
                investigation_id=investigation_id,
            )
        )
    return observations


def _refs_for_claims(reply: ModelAssessmentReply) -> list[list[str]]:
    return [
        *(item.evidence_refs for item in reply.inferences),
        *(item.evidence_refs for item in reply.hypotheses),
        *(item.evidence_refs for item in reply.unknowns),
        *(item.supporting_evidence_refs for item in reply.classifications),
    ]


def _has_contradictory_observations(observations: list[EvidenceObservation]) -> bool:
    seen: dict[tuple[str, str, str, str, str | None], str] = {}
    for observation in observations:
        key = (
            observation.target,
            observation.diagnostic_id,
            observation.source_action,
            observation.step_id,
            observation.observed_at,
        )
        value = canonical_json(observation.observed_result)
        previous = seen.get(key)
        if previous is not None and previous != value:
            return True
        seen[key] = value
    return False


def validate_assessment(
    assessment: StructuredAssessment,
) -> StructuredAssessment:
    observations = assessment.observations
    refs = [item.ref for item in observations]
    if len(refs) != len(set(refs)):
        raise ValueError("duplicate evidence observations are not allowed")
    evidence_by_ref = {item.ref: item for item in observations}
    all_claim_refs = [
        ref
        for group in (
            *(item.evidence_refs for item in assessment.inferences),
            *(item.evidence_refs for item in assessment.hypotheses),
            *(item.evidence_refs for item in assessment.unknowns),
            *(item.supporting_evidence_refs for item in assessment.classifications),
        )
        for ref in group
    ]
    missing = set(all_claim_refs) - set(evidence_by_ref)
    if missing:
        raise ValueError("assessment references evidence outside this investigation")
    for hypothesis in assessment.hypotheses:
        if not hypothesis.evidence_refs and hypothesis.confidence > 0.25:
            raise ValueError("unsupported hypotheses must have confidence <= 0.25")
    for inference in assessment.inferences:
        if not inference.evidence_refs:
            raise ValueError("inferences require at least one evidence reference")
    for classification in assessment.classifications:
        refs_for_class = classification.supporting_evidence_refs
        if (
            classification.status == "suspected"
            and not refs_for_class
            and classification.confidence > 0.25
        ):
            raise ValueError("unsupported suspected classifications must have confidence <= 0.25")
        if classification.status == "supported":
            if not refs_for_class:
                raise ValueError("supported classifications require evidence references")
            if any(
                evidence_by_ref[ref].verification_status != "verified" for ref in refs_for_class
            ):
                raise ValueError("supported classifications require verified evidence only")
    if assessment.assessment_status == "assessed" and not any(
        item.status in {"supported", "suspected"} and item.category != "unknown"
        for item in assessment.classifications
    ):
        raise ValueError("assessed status requires a non-unknown classification")
    if assessment.assessment_status == "abstained" and any(
        item.status != "undetermined" for item in assessment.classifications
    ):
        raise ValueError("abstained assessments may contain only undetermined classifications")
    if _has_contradictory_observations(observations) and (
        assessment.assessment_status == "assessed"
        or any(item.status == "supported" for item in assessment.classifications)
    ):
        raise ValueError("contradictory observations cannot support a completed assessment")
    # Ensure bounded JSON serialization and reject non-JSON values deterministically.
    json.dumps(assessment.model_dump(mode="json"), allow_nan=False)
    return assessment


def build_structured_assessment(
    reply: ModelAssessmentReply,
    evidence: list[dict[str, Any]],
    *,
    incident_id: str | None,
    investigation_id: str,
) -> StructuredAssessment:
    observations = make_observations(evidence, incident_id, investigation_id)
    status = reply.assessment_status
    if status is None:
        if any(
            item.category != "unknown" and item.status in {"supported", "suspected"}
            for item in reply.classifications
        ):
            status = "assessed"
        elif reply.classifications:
            status = "abstained"
        elif not (reply.hypotheses or reply.inferences or reply.recommended_next_steps):
            status = "abstained"
        else:
            status = "partial"
    try:
        result = StructuredAssessment(
            schema_version=ASSESSMENT_SCHEMA_VERSION,
            classification_catalog_version=CLASSIFICATION_CATALOG_VERSION,
            incident_id=incident_id,
            investigation_id=investigation_id,
            observations=observations,
            inferences=reply.inferences,
            hypotheses=reply.hypotheses,
            classifications=reply.classifications,
            unknowns=reply.unknowns,
            recommended_next_steps=reply.recommended_next_steps,
            overall_uncertainty=reply.overall_uncertainty,
            assessment_status=status,
        )
        return validate_assessment(result)
    except (ValueError, TypeError) as exc:
        raise RunbookOSError("AI structured assessment failed deterministic validation") from exc


def project_investigation_assessment(
    record: dict[str, Any] | None,
    *,
    incident_id: str,
    incident_summary_sha256: str,
    linked: bool,
) -> dict[str, Any]:
    """Create a deterministic, read-only operator view of a linked investigation.

    Failure states intentionally expose a reason code, not malformed persisted
    content. The projection never changes evidence verification provenance.
    """
    base = {
        "projection_version": 1,
        "incident_id": incident_id,
        "investigation_id": record.get("investigation_id") if isinstance(record, dict) else None,
        "assessment_status": "unavailable",
        "availability": "unavailable",
        "evaluation_status": "NOT AVAILABLE",
        "semantic_support_status": "unverified",
        "confidence_label": "model-reported; uncalibrated",
    }
    if record is None:
        return base | {"availability": "missing_investigation", "reason": "investigation_not_found"}
    if not linked:
        return base | {"availability": "unlinked", "reason": "investigation_not_linked_to_incident"}
    if record.get("result_integrity") != "valid":
        return base | {
            "availability": "integrity_error",
            "reason": "investigation_audit_hash_mismatch",
        }
    result = record.get("result")
    if not isinstance(result, dict):
        return base | {"availability": "malformed", "reason": "investigation_result_malformed"}
    if result.get("incident_sha256") != incident_summary_sha256:
        return base | {
            "availability": "incident_mismatch",
            "reason": "investigation_incident_digest_mismatch",
        }
    assessment_raw = result.get("assessment")
    if assessment_raw is None:
        return base | {
            "availability": "legacy",
            "assessment_status": "legacy_unavailable",
            "reason": "structured_assessment_not_present",
        }
    if not isinstance(assessment_raw, dict):
        return base | {"availability": "malformed", "reason": "assessment_not_an_object"}
    if assessment_raw.get("schema_version") != ASSESSMENT_SCHEMA_VERSION:
        return base | {
            "availability": "unsupported_version",
            "reason": "assessment_schema_version_unsupported",
        }
    try:
        assessment = StructuredAssessment.model_validate(assessment_raw)
        validate_assessment(assessment)
        if assessment.investigation_id != record.get("investigation_id"):
            raise ValueError("assessment investigation identity mismatch")
        if assessment.incident_id != incident_id:
            raise ValueError("assessment incident identity mismatch")
        source_evidence = result.get("evidence")
        if not isinstance(source_evidence, list):
            raise ValueError("source evidence is unavailable")
        expected_observations = make_observations(
            source_evidence, incident_id, assessment.investigation_id
        )
        if [item.model_dump(mode="json") for item in expected_observations] != [
            item.model_dump(mode="json") for item in assessment.observations
        ]:
            raise ValueError("assessment observations differ from persisted diagnostic evidence")
    except (ValidationError, ValueError, KeyError, TypeError):
        return base | {"availability": "malformed", "reason": "assessment_validation_failed"}

    return {
        **base,
        "availability": "available",
        "assessment_status": assessment.assessment_status,
        "assessment_schema_version": assessment.schema_version,
        "classification_catalog_version": assessment.classification_catalog_version,
        "investigation_status": record.get("status"),
        "investigation_created_at": record.get("created_at"),
        "observations": [
            item.model_dump(mode="json") | {"observed_result": redact(item.observed_result)}
            for item in assessment.observations
        ],
        "inferences": [item.model_dump(mode="json") for item in assessment.inferences],
        "hypotheses": [item.model_dump(mode="json") for item in assessment.hypotheses],
        "classifications": [item.model_dump(mode="json") for item in assessment.classifications],
        "unknowns": [item.model_dump(mode="json") for item in assessment.unknowns],
        "recommended_next_steps": list(assessment.recommended_next_steps),
        "overall_uncertainty": assessment.overall_uncertainty,
        "semantic_support_status": assessment.semantic_support_status,
        "recommendations_are_executable": assessment.recommendations_are_executable,
        "confidence_label": "model-reported; uncalibrated",
        "evaluation_status": "NOT MEASURED",
        "reason": None,
    }
