from __future__ import annotations

import ast
import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from runbookos.ai import AnalysisReply
from runbookos.assessment import (
    ClassificationAssessment,
    EvidenceObservation,
    HypothesisClaim,
    ModelAssessmentReply,
    StructuredAssessment,
    validate_assessment,
)
from runbookos.assessment_evaluation import (
    CasePrediction,
    EvaluationDataset,
    EvaluationInput,
    SemanticAdjudication,
    _set_scores,
    evaluate,
    load_dataset,
    load_taxonomy,
    model_facing_input,
)

FIXTURES = Path(__file__).parent / "fixtures" / "assessment_m3"


@pytest.fixture(scope="module")
def dataset():
    return load_dataset(FIXTURES / "heldout-v1.json")


def _assessment(case, *, category=None, confidence=0.8, hypothesis=None):
    observations = []
    for index, item in enumerate(case.input.observations):
        observations.append(
            EvidenceObservation(
                statement=f"Synthetic observation {index + 1}.",
                ref=item.evidence_id,
                evidence_refs=[item.evidence_id],
                execution_id=f"exec-{case.case_id}",
                diagnostic_id=item.diagnostic_id,
                source_action="diagnostic.synthetic_read_only",
                target=f"synthetic-{case.case_id}",
                step_id=f"step-{index + 1}",
                observed_result=item.observed_result,
                execution_status="succeeded",
                assertion_outcome="passed",
                verification_status="verified",
                incident_id=case.input.incident_id,
                investigation_id=f"invest-{case.case_id}",
            )
        )
    classification = case.gold.classification if category is None else category
    classes = []
    if classification is not None:
        classes = [
            ClassificationAssessment(
                category=classification,
                confidence=confidence,
                supporting_evidence_refs=[item.ref for item in observations],
                status="undetermined" if classification == "unknown" else "suspected",
            )
        ]
    hypotheses = []
    if hypothesis is not None:
        hypotheses = [
            HypothesisClaim(
                statement=hypothesis,
                evidence_refs=[item.ref for item in observations[:1]],
                confidence=0.4,
            )
        ]
    status = "abstained" if classification in {None, "unknown"} else "assessed"
    return StructuredAssessment(
        schema_version=1,
        classification_catalog_version=2,
        incident_id=case.input.incident_id,
        investigation_id=f"invest-{case.case_id}",
        observations=observations,
        inferences=[],
        hypotheses=hypotheses,
        classifications=classes,
        unknowns=[],
        recommended_next_steps=[],
        overall_uncertainty=0.2,
        assessment_status=status,
    )


def _submission(dataset, *, wrong_diagnostics=None, wrong_classes=None, confidence=0.8):
    wrong_diagnostics = wrong_diagnostics or set()
    wrong_classes = wrong_classes or set()
    predictions = []
    for case in dataset.cases:
        ids = list(case.gold.expected_diagnostic_ids)
        category = case.gold.classification
        if case.case_id in wrong_diagnostics:
            ids = [] if ids else ["web_health"]
        if case.case_id in wrong_classes:
            category = "network_failure" if category != "network_failure" else "healthy"
        predictions.append(
            CasePrediction(
                case_id=case.case_id,
                diagnostic_ids=ids,
                assessment=_assessment(case, category=category, confidence=confidence),
            )
        )
    return EvaluationInput(
        schema_version=1, dataset_version=dataset.dataset_version, predictions=predictions
    )


def test_dataset_and_taxonomy_are_versioned_and_cover_required_conditions(dataset):
    taxonomy = load_taxonomy(FIXTURES / "taxonomy-v2.yml")
    assert len(dataset.cases) == 24
    assert dataset.dataset_version == "m3-1.0"
    assert taxonomy.classification_catalog_version == dataset.classification_catalog_version
    assert {case.category for case in dataset.cases} == {
        "web",
        "application",
        "database",
        "network",
        "insufficient_evidence",
    }
    assert sum(not case.input.observations for case in dataset.cases) >= 3
    assert any(case.gold.semantic_test_claims for case in dataset.cases)
    false_claims = [
        claim.statement for case in dataset.cases for claim in case.gold.semantic_test_claims
    ]
    assert any("configuration file is corrupt" in statement for statement in false_claims)
    legacy_path = Path(__file__).parent / "fixtures" / "ai_acceptance_v060" / "scenarios.json"
    legacy_ids = {row["id"] for row in json.loads(legacy_path.read_text())}
    assert len(legacy_ids) == 5
    assert not legacy_ids.intersection(case.case_id for case in dataset.cases)


def test_gold_labels_do_not_leak_into_model_facing_input(dataset):
    case = dataset.cases[0]
    exposed = model_facing_input(case)
    assert set(exposed) == {
        "incident_id",
        "incident_summary",
        "diagnostic_catalog",
        "observations",
    }
    assert "gold" not in json.dumps(exposed)
    assert "expected_diagnostic_ids" not in json.dumps(exposed)
    assert "classification" not in json.dumps(exposed)
    with pytest.raises(ValidationError, match="frozen"):
        case.gold.classification = "network_failure"
    with pytest.raises(ValidationError):
        CasePrediction(
            case_id=case.case_id,
            diagnostic_ids=[],
            classification="service_failure",
        )


def test_evaluator_has_no_provider_executor_or_local_orchestrator_imports():
    source = Path(__file__).parents[1] / "src/runbookos/assessment_evaluation.py"
    tree = ast.parse(source.read_text(encoding="utf-8"))
    modules = {
        node.module for node in ast.walk(tree) if isinstance(node, ast.ImportFrom) and node.module
    }
    modules.update(
        alias.name
        for node in ast.walk(tree)
        if isinstance(node, ast.Import)
        for alias in node.names
    )
    assert not any(
        name.startswith(
            ("runbookos.ai", "runbookos.engine", "runbookos.ssh", "tests.ai_acceptance")
        )
        for name in modules
    )
    assert "sqlite3" not in modules and "subprocess" not in modules


def test_perfect_predictions_produce_independently_expected_metrics(dataset):
    result = evaluate(dataset, _submission(dataset))
    assert result["diagnostic_selection"]["exact_match_accuracy"] == 1
    assert result["diagnostic_selection"]["micro"] == {"precision": 1, "recall": 1, "f1": 1}
    assert result["classification"]["exact_accuracy"] == 1
    assert result["abstention"]["precision"] == 1
    assert result["abstention"]["recall"] == 1


def test_completely_incorrect_diagnostic_predictions_have_zero_micro_f1(dataset):
    predictions = []
    for case in dataset.cases:
        chosen = next(
            (
                item
                for item in (
                    "web_health",
                    "application_health",
                    "database_health",
                    "network_health",
                )
                if item not in case.gold.expected_diagnostic_ids
            ),
            "network_health",
        )
        predictions.append(CasePrediction(case_id=case.case_id, diagnostic_ids=[chosen]))
    result = evaluate(
        dataset,
        EvaluationInput(
            schema_version=1, dataset_version=dataset.dataset_version, predictions=predictions
        ),
    )
    assert result["diagnostic_selection"]["micro"] == {"precision": 0, "recall": 0, "f1": 0}
    assert result["diagnostic_selection"]["exact_match_accuracy"] == 0


def test_partial_overlap_and_empty_empty_zero_denominator_policy():
    assert _set_scores({"web_health", "network_health"}, {"web_health", "database_health"}) == {
        "precision": 0.5,
        "recall": 0.5,
        "f1": 0.5,
    }
    assert _set_scores(set(), set()) == {"precision": None, "recall": None, "f1": None}
    assert _set_scores({"web_health"}, set()) == {"precision": None, "recall": 0, "f1": 0}


def test_wrong_and_correct_abstention_are_counted_separately(dataset):
    submission = _submission(dataset)
    first_non_abstain = next(case for case in dataset.cases if not case.gold.expected_abstention)
    prediction = next(
        item for item in submission.predictions if item.case_id == first_non_abstain.case_id
    )
    changed = prediction.model_copy(
        update={"assessment": _assessment(first_non_abstain, category="unknown")}
    )
    replaced = [
        changed if item.case_id == changed.case_id else item for item in submission.predictions
    ]
    result = evaluate(dataset, submission.model_copy(update={"predictions": replaced}))
    assert result["abstention"]["false_abstention_rate"] == pytest.approx(
        1 / sum(not c.gold.expected_abstention for c in dataset.cases)
    )
    assert result["abstention"]["missed_abstention_count"] == 0


def test_missing_assessment_is_treated_as_abstention_and_unanswered(dataset):
    result = evaluate(
        dataset,
        EvaluationInput(schema_version=1, dataset_version=dataset.dataset_version, predictions=[]),
    )
    assert result["classification"]["coverage"] is None
    assert result["classification"]["exact_accuracy"] is None
    assert result["abstention"]["recall"] is None
    assert result["ground_truth_availability"]["evaluated_cases"] == 0


def test_prediction_without_assessment_is_an_abstention(dataset):
    case = next(item for item in dataset.cases if not item.gold.expected_abstention)
    prediction = CasePrediction(
        case_id=case.case_id, diagnostic_ids=case.gold.expected_diagnostic_ids
    )
    result = evaluate(
        dataset,
        EvaluationInput(
            schema_version=1,
            dataset_version=dataset.dataset_version,
            predictions=[prediction],
        ),
    )
    assert result["classification"]["coverage"] == 0
    assert result["abstention"]["false_abstention_rate"] == 1


def test_unsupported_classification_and_nonfinite_confidence_are_rejected():
    with pytest.raises(ValidationError):
        ClassificationAssessment(category="made_up", confidence=0.5, status="suspected")
    with pytest.raises(ValidationError):
        ClassificationAssessment(category="healthy", confidence=float("nan"), status="suspected")
    with pytest.raises(ValidationError):
        HypothesisClaim(statement="x", confidence=float("inf"))
    assert (
        ClassificationAssessment(category="healthy", confidence=0, status="suspected").confidence
        == 0
    )
    assert (
        ClassificationAssessment(category="healthy", confidence=1, status="suspected").confidence
        == 1
    )


def test_missing_classification_is_abstention_and_unknown_diagnostic_rate_is_reported(dataset):
    case = next(item for item in dataset.cases if item.gold.classification not in {None, "unknown"})
    assessment = _assessment(case).model_copy(
        update={"classifications": [], "assessment_status": "partial"}
    )
    prediction = CasePrediction(
        case_id=case.case_id, diagnostic_ids=["not_registered"], assessment=assessment
    )
    result = evaluate(
        dataset,
        EvaluationInput(
            schema_version=1, dataset_version=dataset.dataset_version, predictions=[prediction]
        ),
    )
    summary = next(item for item in result["case_summaries"] if item["case_id"] == case.case_id)
    assert summary["predicted_abstention"] is True
    assert result["diagnostic_selection"]["invalid_unknown_id_count"] == 1
    assert result["diagnostic_selection"]["invalid_unknown_id_rate_per_selected_id"] == 1


def test_duplicate_predicted_diagnostic_ids_are_rejected():
    with pytest.raises(ValidationError, match="must be unique"):
        CasePrediction(case_id="case-001", diagnostic_ids=["web_health", "web_health"])


def test_unknown_evidence_reference_is_rejected(dataset):
    case = dataset.cases[0]
    assessment = _assessment(case)
    forged = assessment.model_copy(
        update={
            "hypotheses": [
                HypothesisClaim(statement="claim", evidence_refs=["forged:ref"], confidence=0.1)
            ]
        }
    )
    with pytest.raises(ValueError, match="outside this investigation"):
        validate_assessment(forged)


def test_assessment_cannot_rewrite_an_existing_observation(dataset):
    case = dataset.cases[0]
    assessment = _assessment(case)
    altered = assessment.observations[0].model_copy(
        update={"observed_result": {"http_status": 599}}
    )
    forged_assessment = assessment.model_copy(update={"observations": [altered]})
    prediction = CasePrediction(
        case_id=case.case_id,
        diagnostic_ids=case.gold.expected_diagnostic_ids,
        assessment=forged_assessment,
    )
    with pytest.raises(ValueError, match="differs from source evidence"):
        evaluate(
            dataset,
            EvaluationInput(
                schema_version=1,
                dataset_version=dataset.dataset_version,
                predictions=[prediction],
            ),
        )


def test_contradicted_and_unadjudicated_claims_are_not_marked_supported(dataset):
    case = next(item for item in dataset.cases if item.input.observations)
    assessment = _assessment(case, hypothesis="A causal hypothesis that needs review.")
    assessment = assessment.model_copy(
        update={
            "hypotheses": [
                *assessment.hypotheses,
                HypothesisClaim(
                    statement="A second independently reviewable claim.",
                    evidence_refs=[assessment.observations[0].ref],
                    confidence=0.3,
                ),
            ]
        }
    )
    prediction = CasePrediction(
        case_id=case.case_id,
        diagnostic_ids=case.gold.expected_diagnostic_ids,
        assessment=assessment,
    )
    adjudications = [
        SemanticAdjudication(case_id=case.case_id, claim_id="hypothesis:0", label="contradicted"),
        SemanticAdjudication(
            case_id=case.case_id,
            claim_id=f"classification:{assessment.classifications[0].category}:0",
            label="insufficient",
        ),
        SemanticAdjudication(case_id=case.case_id, claim_id="hypothesis:1", label="supported"),
    ]
    result = evaluate(
        dataset,
        EvaluationInput(
            schema_version=1,
            dataset_version=dataset.dataset_version,
            predictions=[prediction],
            semantic_adjudications=adjudications,
        ),
    )
    assert result["semantic_support"]["unsupported_claim_rate_over_adjudicated"] == pytest.approx(
        2 / 3
    )
    assert result["semantic_support"]["contradicted_claim_rate_over_adjudicated"] == pytest.approx(
        1 / 3
    )
    assert result["semantic_support"]["not_adjudicated_claim_count"] == 0

    unreviewed = evaluate(
        dataset,
        EvaluationInput(
            schema_version=1, dataset_version=dataset.dataset_version, predictions=[prediction]
        ),
    )
    assert unreviewed["semantic_support"]["unsupported_claim_rate_over_adjudicated"] is None
    assert unreviewed["semantic_support"]["not_adjudicated_claim_count"] == 3


def test_duplicate_adjudications_and_case_ids_are_rejected(dataset):
    case = dataset.cases[0]
    prediction = CasePrediction(case_id=case.case_id, diagnostic_ids=[])
    adjudication = SemanticAdjudication(case_id=case.case_id, claim_id="x", label="not_adjudicated")
    with pytest.raises(ValidationError, match="duplicate semantic adjudications"):
        EvaluationInput(
            schema_version=1,
            dataset_version=dataset.dataset_version,
            predictions=[prediction],
            semantic_adjudications=[adjudication, adjudication],
        )
    duplicate = dataset.cases[1].model_copy(update={"case_id": case.case_id})
    with pytest.raises(ValidationError, match="unique"):
        EvaluationDataset(
            schema_version=1,
            dataset_version="m3-1.0",
            assessment_schema_version=1,
            classification_catalog_version=2,
            diagnostic_catalog_version=1,
            cases=[*dataset.cases[:-1], duplicate],
        )


def test_empty_dataset_and_version_mismatch_are_rejected(dataset):
    with pytest.raises(ValidationError):
        EvaluationDataset(
            schema_version=1,
            dataset_version="m3-1.0",
            assessment_schema_version=1,
            classification_catalog_version=2,
            diagnostic_catalog_version=1,
            cases=[],
        )
    bad = EvaluationInput(schema_version=1, dataset_version="m3-2.0", predictions=[])
    with pytest.raises(ValueError, match="does not match"):
        evaluate(dataset, bad)


def test_calibration_edges_are_reported_and_exclusions_counted(dataset):
    rows = []
    for case in dataset.cases:
        category = case.gold.classification
        confidence = 1 if category == "healthy" else 0
        rows.append(
            CasePrediction(
                case_id=case.case_id,
                diagnostic_ids=case.gold.expected_diagnostic_ids,
                assessment=_assessment(case, category=category, confidence=confidence),
            )
        )
    result = evaluate(
        dataset,
        EvaluationInput(
            schema_version=1, dataset_version=dataset.dataset_version, predictions=rows
        ),
    )
    assert result["calibration"]["included_classification_count"] > 0
    assert (
        result["calibration"]["excluded_abstained_count"]
        == result["classification"]["abstained_cases"]
    )
    assert (
        result["calibration"]["excluded_unlabeled_count"]
        == result["ground_truth_availability"]["classification_unlabeled"]
    )
    assert result["calibration"]["bins"][0]["count"] > 0
    assert result["calibration"]["bins"][-1]["count"] > 0


def test_repeated_evaluation_is_identical_and_legacy_reply_is_compatible(dataset):
    submission = _submission(dataset)
    assert evaluate(dataset, submission) == evaluate(dataset, submission)
    legacy = ModelAssessmentReply.model_validate({"hypotheses": [], "recommended_next_steps": []})
    assert legacy.assessment_status is None
    assert AnalysisReply.model_validate({"hypotheses": [], "recommended_next_steps": []})


def test_executable_recommendations_are_rejected_and_unknown_class_abstains():
    with pytest.raises(ValidationError):
        ModelAssessmentReply.model_validate(
            {"recommended_next_steps": ["sudo systemctl restart nginx"]}
        )
    unknown = ClassificationAssessment(category="unknown", confidence=1, status="undetermined")
    assert unknown.category == "unknown"


def test_unlabeled_case_does_not_enter_classification_calibration(dataset):
    result = evaluate(dataset, None)
    assert result["prediction_count"] == 0
    assert result["classification"]["exact_accuracy"] is None
    assert result["calibration"]["brier_score"] is None
    assert result["diagnostic_selection"]["micro"]["precision"] is None
