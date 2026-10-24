"""Offline deterministic evaluation for versioned structured assessments.

This module deliberately imports neither the AI provider nor execution, storage,
SSH, webhook, or remediation components. Gold labels are kept in a separate
``gold`` object and are never returned by :func:`model_facing_input`.
"""

from __future__ import annotations

import json
from collections import Counter
from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator

from .assessment import CLASSIFICATION_CATEGORIES, StructuredAssessment, validate_assessment

DATASET_SCHEMA_VERSION = 1
EVALUATION_SCHEMA_VERSION = 1
DIAGNOSTIC_IDS = frozenset(
    {"web_health", "application_health", "database_health", "network_health"}
)
SEMANTIC_LABELS = frozenset({"supported", "contradicted", "insufficient", "not_adjudicated"})


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class InputObservation(StrictModel):
    evidence_id: str = Field(min_length=3, max_length=256)
    diagnostic_id: str
    observed_result: dict[str, Any]

    @model_validator(mode="after")
    def json_safe(self) -> InputObservation:
        if self.diagnostic_id not in DIAGNOSTIC_IDS:
            raise ValueError("input observation uses an unknown diagnostic ID")
        try:
            json.dumps(self.observed_result, allow_nan=False)
        except (TypeError, ValueError) as exc:
            raise ValueError("observed_result must be finite JSON data") from exc
        return self


class ModelFacingInput(StrictModel):
    incident_id: str = Field(min_length=1, max_length=128)
    incident_summary: str = Field(min_length=1, max_length=2000)
    diagnostic_catalog: dict[str, str] = Field(min_length=1, max_length=8)
    observations: list[InputObservation] = Field(max_length=64)

    @model_validator(mode="after")
    def unique_refs(self) -> ModelFacingInput:
        refs = [item.evidence_id for item in self.observations]
        if len(refs) != len(set(refs)):
            raise ValueError("model-facing evidence IDs must be unique")
        if set(self.diagnostic_catalog) - DIAGNOSTIC_IDS:
            raise ValueError("model-facing input contains an unknown available diagnostic")
        if any(not text.strip() for text in self.diagnostic_catalog.values()):
            raise ValueError("model-facing diagnostic descriptions must be non-empty")
        return self


class SemanticGoldClaim(StrictModel):
    claim_id: str = Field(min_length=1, max_length=128)
    statement: str = Field(min_length=1, max_length=1000)
    evidence_refs: list[str] = Field(max_length=32)
    expected_adjudication: Literal["supported", "contradicted", "insufficient"]


class GoldLabels(StrictModel):
    expected_diagnostic_ids: list[str] = Field(max_length=8)
    classification: (
        Literal[
            "healthy",
            "service_failure",
            "connectivity_failure",
            "network_failure",
            "dependency_failure",
            "resource_pressure",
            "unknown",
        ]
        | None
    )
    reference_evidence_ids: list[str] = Field(max_length=64)
    expected_abstention: bool
    annotation_rationale: str = Field(min_length=1, max_length=1000)
    semantic_test_claims: list[SemanticGoldClaim] = Field(default_factory=list, max_length=8)

    @model_validator(mode="after")
    def unique_known_values(self) -> GoldLabels:
        if len(self.expected_diagnostic_ids) != len(set(self.expected_diagnostic_ids)):
            raise ValueError("gold diagnostic IDs must be unique")
        if set(self.expected_diagnostic_ids) - DIAGNOSTIC_IDS:
            raise ValueError("gold labels contain unknown diagnostic IDs")
        if len(self.reference_evidence_ids) != len(set(self.reference_evidence_ids)):
            raise ValueError("gold evidence IDs must be unique")
        claims = [item.claim_id for item in self.semantic_test_claims]
        if len(claims) != len(set(claims)):
            raise ValueError("semantic gold claim IDs must be unique")
        if self.expected_abstention != (self.classification in {None, "unknown"}):
            raise ValueError("gold abstention must agree with unknown or unlabeled classification")
        return self


class EvaluationCase(StrictModel):
    case_id: str = Field(pattern=r"^[a-z0-9][a-z0-9-]{1,63}$")
    category: Literal["web", "application", "database", "network", "insufficient_evidence"]
    case_type: Literal[
        "normal",
        "failure",
        "conflicting",
        "ambiguous",
        "no_evidence",
        "observation_without_cause",
    ]
    input: ModelFacingInput
    gold: GoldLabels

    @model_validator(mode="after")
    def evidence_alignment(self) -> EvaluationCase:
        available = {item.evidence_id for item in self.input.observations}
        if not set(self.gold.reference_evidence_ids) <= available:
            raise ValueError("gold references evidence absent from the model-facing input")
        if not set(self.gold.expected_diagnostic_ids) <= set(self.input.diagnostic_catalog):
            raise ValueError("gold diagnostics are not available to the model-facing case")
        if any(not set(item.evidence_refs) <= available for item in self.gold.semantic_test_claims):
            raise ValueError("semantic gold claim references absent evidence")
        return self


class EvaluationDataset(StrictModel):
    schema_version: Literal[1]
    dataset_version: str = Field(pattern=r"^m3-[0-9]+\.[0-9]+$")
    assessment_schema_version: Literal[1]
    classification_catalog_version: Literal[2]
    diagnostic_catalog_version: Literal[1]
    cases: list[EvaluationCase] = Field(min_length=20, max_length=500)

    @model_validator(mode="after")
    def unique_cases(self) -> EvaluationDataset:
        ids = [case.case_id for case in self.cases]
        if len(ids) != len(set(ids)):
            raise ValueError("dataset case IDs must be unique")
        return self


class EvaluationTaxonomy(StrictModel):
    classification_catalog_version: Literal[2]
    assessment_schema_version: Literal[1]
    classifications: dict[str, str]
    diagnostic_catalog_version: Literal[1]
    diagnostic_ids: list[str]
    diagnostic_descriptions: dict[str, str]

    @model_validator(mode="after")
    def catalog_matches_contract(self) -> EvaluationTaxonomy:
        if set(self.classifications) != set(CLASSIFICATION_CATEGORIES):
            raise ValueError("taxonomy classifications differ from assessment schema v2")
        if set(self.diagnostic_ids) != DIAGNOSTIC_IDS or len(self.diagnostic_ids) != len(
            set(self.diagnostic_ids)
        ):
            raise ValueError("taxonomy diagnostics differ from the registered evaluation catalog")
        if set(self.diagnostic_descriptions) != DIAGNOSTIC_IDS:
            raise ValueError("taxonomy must describe each registered diagnostic exactly once")
        if any(not text.strip() for text in self.diagnostic_descriptions.values()):
            raise ValueError("diagnostic descriptions must be non-empty")
        if any(not text.strip() for text in self.classifications.values()):
            raise ValueError("taxonomy descriptions must be non-empty")
        return self


class SemanticAdjudication(StrictModel):
    case_id: str
    claim_id: str
    label: Literal["supported", "contradicted", "insufficient", "not_adjudicated"]


class CasePrediction(StrictModel):
    case_id: str
    diagnostic_ids: list[str] = Field(max_length=32)
    assessment: StructuredAssessment | None = None

    @model_validator(mode="after")
    def unique_ids(self) -> CasePrediction:
        if len(self.diagnostic_ids) != len(set(self.diagnostic_ids)):
            raise ValueError("predicted diagnostic IDs must be unique")
        return self


class EvaluationInput(StrictModel):
    schema_version: Literal[1]
    dataset_version: str
    predictions: list[CasePrediction]
    semantic_adjudications: list[SemanticAdjudication] = Field(default_factory=list)

    @model_validator(mode="after")
    def unique_prediction_cases(self) -> EvaluationInput:
        ids = [item.case_id for item in self.predictions]
        if len(ids) != len(set(ids)):
            raise ValueError("each case may have only one prediction")
        keys = [(item.case_id, item.claim_id) for item in self.semantic_adjudications]
        if len(keys) != len(set(keys)):
            raise ValueError("duplicate semantic adjudications are not allowed")
        return self


def load_dataset(path: Path) -> EvaluationDataset:
    """Load a bounded JSON/YAML dataset and reject malformed or oversized input."""
    try:
        if path.stat().st_size > 2 * 1024 * 1024:
            raise ValueError("evaluation dataset exceeds 2 MiB")
        text = path.read_text(encoding="utf-8")
        raw = json.loads(text) if path.suffix.lower() == ".json" else yaml.safe_load(text)
        dataset = EvaluationDataset.model_validate(raw)
    except (OSError, json.JSONDecodeError, yaml.YAMLError, ValidationError) as exc:
        raise ValueError(f"invalid M3 evaluation dataset: {type(exc).__name__}") from exc
    return dataset


def load_taxonomy(path: Path) -> EvaluationTaxonomy:
    try:
        if path.stat().st_size > 128 * 1024:
            raise ValueError("taxonomy exceeds 128 KiB")
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
        return EvaluationTaxonomy.model_validate(raw)
    except (OSError, yaml.YAMLError, ValidationError) as exc:
        raise ValueError(f"invalid M3 taxonomy: {type(exc).__name__}") from exc


def model_facing_input(case: EvaluationCase) -> dict[str, Any]:
    """Return only incident context and observations; never expose gold labels."""
    return case.input.model_dump(mode="json")


def _safe_div(numerator: float, denominator: float) -> float | None:
    return numerator / denominator if denominator else None


def _set_scores(expected: set[str], predicted: set[str]) -> dict[str, float | None]:
    tp = len(expected & predicted)
    fp = len(predicted - expected)
    fn = len(expected - predicted)
    precision = _safe_div(tp, len(predicted))
    recall = _safe_div(tp, len(expected))
    f1 = _safe_div(2 * tp, 2 * tp + fp + fn)
    return {"precision": precision, "recall": recall, "f1": f1}


def _claim_ids(assessment: StructuredAssessment) -> set[str]:
    return {
        *(f"inference:{index}" for index, _ in enumerate(assessment.inferences)),
        *(f"hypothesis:{index}" for index, _ in enumerate(assessment.hypotheses)),
        *(
            f"classification:{item.category}:{index}"
            for index, item in enumerate(assessment.classifications)
        ),
        *(f"unknown:{index}" for index, _ in enumerate(assessment.unknowns)),
    }


def _claim_evidence_refs(assessment: StructuredAssessment | None) -> set[str]:
    if assessment is None:
        return set()
    return {
        *(ref for item in assessment.inferences for ref in item.evidence_refs),
        *(ref for item in assessment.hypotheses for ref in item.evidence_refs),
        *(ref for item in assessment.classifications for ref in item.supporting_evidence_refs),
        *(ref for item in assessment.unknowns for ref in item.evidence_refs),
    }


def _prediction_class(
    assessment: StructuredAssessment | None,
) -> tuple[str | None, bool, float | None]:
    if assessment is None:
        return None, True, None
    explicit_unknown = any(item.category == "unknown" for item in assessment.classifications)
    active = [item for item in assessment.classifications if item.status != "undetermined"]
    if assessment.assessment_status == "abstained" or not active:
        return ("unknown" if explicit_unknown else None), True, None
    selected = sorted(active, key=lambda item: (-item.confidence, item.category))[0]
    if selected.category == "unknown":
        return "unknown", True, None
    return selected.category, False, selected.confidence


def evaluate(dataset: EvaluationDataset, submission: EvaluationInput | None) -> dict[str, Any]:
    """Compute deterministic metrics; absent predictions produce NOT_MEASURED fields."""
    if submission is not None and submission.dataset_version != dataset.dataset_version:
        raise ValueError("prediction dataset_version does not match the loaded dataset")
    by_case = {item.case_id: item for item in (submission.predictions if submission else [])}
    unknown_cases = set(by_case) - {item.case_id for item in dataset.cases}
    if unknown_cases:
        raise ValueError("predictions reference unknown case IDs")
    adjudications: dict[tuple[str, str], str] = {}
    if submission:
        submitted_case_ids = {item.case_id for item in submission.predictions}
        if any(
            item.case_id not in submitted_case_ids for item in submission.semantic_adjudications
        ):
            raise ValueError("semantic adjudication references a case without a prediction")
        adjudications = {
            (item.case_id, item.claim_id): item.label for item in submission.semantic_adjudications
        }

    diag_exact: list[bool] = []
    diag_sets: list[dict[str, float | None]] = []
    tp = fp = fn = invalid_count = selected_count = invalid_case_count = 0
    citation_exact: list[bool] = []
    citation_tp = citation_fp = citation_fn = 0
    scored_classes: list[tuple[str, str | None, bool, float | None]] = []
    semantic_total = semantic_adjudicated = semantic_unsupported = semantic_contradicted = 0
    case_summaries: list[dict[str, Any]] = []

    for case in dataset.cases:
        prediction = by_case.get(case.case_id)
        predicted_ids = set(prediction.diagnostic_ids) if prediction else set()
        expected_ids = set(case.gold.expected_diagnostic_ids)
        invalid_ids = predicted_ids - DIAGNOSTIC_IDS
        if prediction:
            invalid_count += len(invalid_ids)
            selected_count += len(predicted_ids)
            invalid_case_count += bool(invalid_ids)
            diag_exact.append(predicted_ids == expected_ids)
            diag_sets.append(_set_scores(expected_ids, predicted_ids))
            tp += len(expected_ids & predicted_ids)
            fp += len(predicted_ids - expected_ids)
            fn += len(expected_ids - predicted_ids)

        assessment = prediction.assessment if prediction else None
        predicted_refs = _claim_evidence_refs(assessment)
        expected_refs = set(case.gold.reference_evidence_ids)
        if prediction:
            citation_exact.append(predicted_refs == expected_refs)
            citation_tp += len(predicted_refs & expected_refs)
            citation_fp += len(predicted_refs - expected_refs)
            citation_fn += len(expected_refs - predicted_refs)
        if assessment is not None:
            if assessment.incident_id not in {None, case.input.incident_id}:
                raise ValueError(f"assessment incident mismatch for case {case.case_id}")
            input_by_ref = {item.evidence_id: item for item in case.input.observations}
            refs = {observation.ref for observation in assessment.observations}
            if refs - set(input_by_ref):
                raise ValueError(
                    f"assessment has unknown evidence reference for case {case.case_id}"
                )
            if any(
                observation.diagnostic_id != input_by_ref[observation.ref].diagnostic_id
                or observation.observed_result != input_by_ref[observation.ref].observed_result
                for observation in assessment.observations
            ):
                raise ValueError(
                    f"assessment observation differs from source evidence for case {case.case_id}"
                )
            validate_assessment(assessment)
            allowed_claims = _claim_ids(assessment)
            submitted_claims = {
                claim_id for (case_id, claim_id) in adjudications if case_id == case.case_id
            }
            if submitted_claims - allowed_claims:
                raise ValueError(f"adjudication references unknown claim for case {case.case_id}")
            for claim_id in allowed_claims:
                semantic_total += 1
                label = adjudications.get((case.case_id, claim_id), "not_adjudicated")
                if label != "not_adjudicated":
                    semantic_adjudicated += 1
                    semantic_unsupported += label in {"contradicted", "insufficient"}
                    semantic_contradicted += label == "contradicted"
        elif any(case_id == case.case_id for case_id, _ in adjudications):
            raise ValueError("semantic adjudication supplied without a model assessment")

        predicted_class, abstained, confidence = _prediction_class(assessment)
        if prediction and case.gold.classification is not None:
            scored_classes.append(
                (case.gold.classification, predicted_class, abstained, confidence)
            )
        case_summaries.append(
            {
                "case_id": case.case_id,
                "category": case.category,
                "case_type": case.case_type,
                "prediction_present": prediction is not None,
                "diagnostic_exact_match": predicted_ids == expected_ids if prediction else None,
                "predicted_diagnostic_ids": sorted(predicted_ids) if prediction else None,
                "invalid_diagnostic_ids": sorted(invalid_ids),
                "classification_scored": case.gold.classification is not None,
                "expected_classification": case.gold.classification,
                "predicted_classification": predicted_class,
                "classification_correct": (
                    predicted_class == case.gold.classification
                    if prediction and case.gold.classification is not None
                    else None
                ),
                "expected_abstention": case.gold.expected_abstention,
                "predicted_abstention": abstained if prediction else None,
                "abstention_correct": (
                    abstained == case.gold.expected_abstention if prediction else None
                ),
            }
        )

    predicted_count = len(by_case)
    diagnostic_p = _safe_div(tp, tp + fp)
    diagnostic_r = _safe_div(tp, tp + fn)
    macro = {
        key: _safe_div(
            sum(item[key] for item in diag_sets if item[key] is not None),
            sum(item[key] is not None for item in diag_sets),
        )
        for key in ("precision", "recall", "f1")
    }
    # For an empty gold/prediction pair, set equality is true; P/R/F1 are undefined
    # and excluded from macro averages. State counts make that convention visible.
    empty_empty = sum(
        not case.gold.expected_diagnostic_ids and not by_case[case.case_id].diagnostic_ids
        for case in dataset.cases
        if case.case_id in by_case
    )

    scored = [(gold, pred, abstain, conf) for gold, pred, abstain, conf in scored_classes]
    correct = sum(gold == pred for gold, pred, _, _ in scored)
    answered = [(gold, pred, conf) for gold, pred, abstain, conf in scored if not abstain]
    labels = sorted(set(CLASSIFICATION_CATEGORIES) | {gold for gold, *_ in scored})
    confusion = {label: {other: 0 for other in labels} for label in labels}
    confusion = {**confusion, "__abstain__": {other: 0 for other in labels}}
    for gold, pred, _, _ in scored:
        confusion["__abstain__" if pred is None else pred][gold] += 1
    class_metrics: dict[str, Any] = {}
    f1_values: list[float] = []
    for label in labels:
        class_tp = sum(gold == label and pred == label for gold, pred, _, _ in scored)
        class_fp = sum(pred == label and gold != label for gold, pred, _, _ in scored)
        class_fn = sum(gold == label and pred != label for gold, pred, _, _ in scored)
        p = _safe_div(class_tp, class_tp + class_fp)
        r = _safe_div(class_tp, class_tp + class_fn)
        f = _safe_div(2 * class_tp, 2 * class_tp + class_fp + class_fn)
        class_metrics[label] = {
            "precision": p,
            "recall": r,
            "f1": f,
            "support": sum(g == label for g, *_ in scored),
        }
        if f is not None:
            f1_values.append(f)

    evaluated_cases = [case for case in dataset.cases if case.case_id in by_case]
    abstention_truth = [case.gold.expected_abstention for case in evaluated_cases]
    predicted_abstentions = [
        _prediction_class(by_case[case.case_id].assessment)[1] for case in evaluated_cases
    ]
    abstain_tp = sum(
        expected and predicted
        for expected, predicted in zip(abstention_truth, predicted_abstentions, strict=True)
    )
    abstain_precision = _safe_div(abstain_tp, sum(predicted_abstentions))
    abstain_recall = _safe_div(abstain_tp, sum(abstention_truth))
    false_abstentions = sum(
        not expected and predicted
        for expected, predicted in zip(abstention_truth, predicted_abstentions, strict=True)
    )
    false_abstention_rate = _safe_div(false_abstentions, sum(not item for item in abstention_truth))
    missed_abstention = sum(
        expected and not predicted
        for expected, predicted in zip(abstention_truth, predicted_abstentions, strict=True)
    )
    selective_accuracy = _safe_div(sum(gold == pred for gold, pred, _ in answered), len(answered))

    calibration_rows = [
        (gold, pred, conf)
        for gold, pred, abstain, conf in scored
        if not abstain and pred is not None and conf is not None
    ]
    bin_rows = [
        {
            "bin": f"[{i / 10:.1f},{(i + 1) / 10:.1f}{']' if i == 9 else ')'}",
            "count": 0,
            "mean_confidence": None,
            "accuracy": None,
        }
        for i in range(10)
    ]
    for gold, pred, conf in calibration_rows:
        index = min(9, int(conf * 10))
        bin_rows[index]["count"] += 1
    for index, row in enumerate(bin_rows):
        values = [
            (gold, pred, conf)
            for gold, pred, conf in calibration_rows
            if min(9, int(conf * 10)) == index
        ]
        if values:
            row["mean_confidence"] = sum(conf for _, _, conf in values) / len(values)
            row["accuracy"] = sum(gold == pred for gold, pred, _ in values) / len(values)
    brier = _safe_div(
        sum((conf - float(gold == pred)) ** 2 for gold, pred, conf in calibration_rows),
        len(calibration_rows),
    )
    ece = _safe_div(
        sum(
            row["count"] * abs(row["accuracy"] - row["mean_confidence"])
            for row in bin_rows
            if row["count"]
        ),
        len(calibration_rows),
    )

    categories = Counter(case.category for case in dataset.cases)
    case_types = Counter(case.case_type for case in dataset.cases)
    return {
        "schema_version": EVALUATION_SCHEMA_VERSION,
        "dataset_version": dataset.dataset_version,
        "assessment_schema_version": dataset.assessment_schema_version,
        "classification_catalog_version": dataset.classification_catalog_version,
        "diagnostic_catalog_version": dataset.diagnostic_catalog_version,
        "dataset_case_count": len(dataset.cases),
        "evaluation_status": (
            "NO_PREDICTIONS"
            if predicted_count == 0
            else "COMPLETE"
            if predicted_count == len(dataset.cases)
            else "PARTIAL"
        ),
        "case_counts_by_category": dict(sorted(categories.items())),
        "case_counts_by_type": dict(sorted(case_types.items())),
        "ground_truth_availability": {
            "classification_labeled": sum(
                case.gold.classification is not None for case in dataset.cases
            ),
            "classification_unlabeled": sum(
                case.gold.classification is None for case in dataset.cases
            ),
            "abstention_labeled": len(dataset.cases),
            "evaluated_cases": predicted_count,
            "evaluated_classification_labeled": sum(
                case.gold.classification is not None for case in evaluated_cases
            ),
        },
        "prediction_count": predicted_count,
        "diagnostic_selection": {
            "exact_match_accuracy": _safe_div(sum(diag_exact), len(diag_exact))
            if submission
            else None,
            "exact_match_scored_cases": len(diag_exact) if submission else 0,
            "micro": {
                "precision": diagnostic_p,
                "recall": diagnostic_r,
                "f1": _safe_div(2 * tp, 2 * tp + fp + fn),
            }
            if submission
            else {"precision": None, "recall": None, "f1": None},
            "macro_per_case_excluding_undefined_empty_sets": macro
            if submission
            else {"precision": None, "recall": None, "f1": None},
            "empty_empty_case_count": empty_empty,
            "invalid_unknown_id_count": invalid_count,
            "invalid_unknown_id_rate_per_selected_id": _safe_div(invalid_count, selected_count),
            "cases_with_invalid_unknown_ids": invalid_case_count,
        },
        "evidence_reference_selection": {
            "exact_match_accuracy": _safe_div(sum(citation_exact), len(citation_exact))
            if submission
            else None,
            "micro": {
                "precision": _safe_div(citation_tp, citation_tp + citation_fp),
                "recall": _safe_div(citation_tp, citation_tp + citation_fn),
                "f1": _safe_div(2 * citation_tp, 2 * citation_tp + citation_fp + citation_fn),
            }
            if submission
            else {"precision": None, "recall": None, "f1": None},
            "validity": "fail_closed_against_input_evidence",
            "valid_references_are_not_semantic_support": True,
        },
        "classification": {
            "exact_accuracy": _safe_div(correct, len(scored)) if submission else None,
            "scored_cases": len(scored) if submission else 0,
            "confusion_matrix_rows_predicted_columns_actual": confusion if submission else None,
            "per_class": class_metrics if submission else None,
            "macro_f1_over_defined_classes": _safe_div(sum(f1_values), len(f1_values))
            if submission and f1_values
            else None,
            "coverage": _safe_div(len(answered), len(scored)) if submission else None,
            "answered_cases": len(answered) if submission else 0,
            "abstained_cases": sum(abstain for _, _, abstain, _ in scored) if submission else 0,
        },
        "abstention": {
            "precision": abstain_precision if submission else None,
            "recall": abstain_recall if submission else None,
            "false_abstention_rate": false_abstention_rate if submission else None,
            "missed_abstention_count": missed_abstention if predicted_count else None,
            "selective_accuracy": selective_accuracy if submission else None,
            "expected_abstention_cases": sum(abstention_truth),
            "predicted_abstention_cases": sum(predicted_abstentions) if submission else 0,
        },
        "semantic_support": {
            "unsupported_claim_rate_over_adjudicated": _safe_div(
                semantic_unsupported, semantic_adjudicated
            ),
            "contradicted_claim_rate_over_adjudicated": _safe_div(
                semantic_contradicted, semantic_adjudicated
            ),
            "adjudication_coverage": _safe_div(semantic_adjudicated, semantic_total),
            "claim_count": semantic_total,
            "adjudicated_claim_count": semantic_adjudicated,
            "not_adjudicated_claim_count": semantic_total - semantic_adjudicated,
        },
        "calibration": {
            "brier_score": brier,
            "expected_calibration_error": ece,
            "bins": bin_rows if submission else None,
            "included_classification_count": len(calibration_rows),
            "excluded_abstained_count": sum(abstain for _, _, abstain, _ in scored),
            "excluded_unlabeled_count": sum(
                case.gold.classification is None for case in evaluated_cases
            ),
            "missing_prediction_count": len(dataset.cases) - predicted_count,
            "confidence_definition": "confidence of highest-confidence non-undetermined non-unknown classification; correctness is exact class match",
        },
        "case_summaries": case_summaries,
        "limitations": [
            "No model performance is measured unless an explicit prediction submission is supplied.",
            "Valid evidence references do not establish semantic support.",
            "Semantic metrics require independent human adjudication; not_adjudicated claims count as uncovered, not supported.",
            "Small synthetic samples cannot establish production calibration.",
        ],
    }


def render_markdown(report: dict[str, Any]) -> str:
    """Render a compact human-readable report from the machine report."""
    metrics = report["diagnostic_selection"]
    classification = report["classification"]
    semantic = report["semantic_support"]
    calibration = report["calibration"]
    status = (
        "prediction submission supplied"
        if report["prediction_count"]
        else "NO MODEL PREDICTIONS — PERFORMANCE NOT MEASURED"
    )

    def show(value: Any) -> Any:
        return "NOT MEASURED" if value is None else value

    lines = [
        f"# M3 Offline Structured Assessment Evaluation — {report['dataset_version']}",
        "",
        f"Evaluation status: **{status}**",
        "",
        f"Dataset cases: {report['dataset_case_count']}",
        "",
        "## Metrics",
        "",
        "| Area | Metric | Value |",
        "|---|---|---:|",
        f"| Diagnostics | Exact-set accuracy | {show(metrics['exact_match_accuracy'])} |",
        f"| Diagnostics | Micro precision / recall / F1 | {show(metrics['micro']['precision'])} / {show(metrics['micro']['recall'])} / {show(metrics['micro']['f1'])} |",
        f"| Diagnostics | Macro per-case precision / recall / F1 | {show(metrics['macro_per_case_excluding_undefined_empty_sets']['precision'])} / {show(metrics['macro_per_case_excluding_undefined_empty_sets']['recall'])} / {show(metrics['macro_per_case_excluding_undefined_empty_sets']['f1'])} |",
        f"| Diagnostics | Invalid IDs | {metrics['invalid_unknown_id_count']} (rate {show(metrics['invalid_unknown_id_rate_per_selected_id'])}) |",
        f"| Evidence refs | Exact-set accuracy | {show(report['evidence_reference_selection']['exact_match_accuracy'])} |",
        f"| Classification | Exact accuracy | {show(classification['exact_accuracy'])} |",
        f"| Classification | Macro F1 | {show(classification['macro_f1_over_defined_classes'])} |",
        f"| Classification | Coverage | {show(classification['coverage'])} |",
        f"| Abstention | Precision / recall | {show(report['abstention']['precision'])} / {show(report['abstention']['recall'])} |",
        f"| Abstention | False rate / missed | {show(report['abstention']['false_abstention_rate'])} / {report['abstention']['missed_abstention_count']} |",
        f"| Abstention | Selective accuracy | {show(report['abstention']['selective_accuracy'])} |",
        f"| Semantics | Unsupported rate / adjudication coverage | {show(semantic['unsupported_claim_rate_over_adjudicated'])} / {show(semantic['adjudication_coverage'])} |",
        f"| Semantics | Contradicted rate | {show(semantic['contradicted_claim_rate_over_adjudicated'])} |",
        f"| Calibration | Brier / ECE | {show(calibration['brier_score'])} / {show(calibration['expected_calibration_error'])} |",
        f"| Calibration | Included / excluded abstained / excluded unlabeled | {calibration['included_classification_count']} / {calibration['excluded_abstained_count']} / {calibration['excluded_unlabeled_count']} |",
        "",
        "## Coverage by case category",
        "",
    ]
    lines.extend(
        f"- Domain `{category}`: {count}"
        for category, count in report["case_counts_by_category"].items()
    )
    lines.extend(
        f"- Case type `{case_type}`: {count}"
        for case_type, count in report["case_counts_by_type"].items()
    )
    lines.extend(
        [
            "",
            "## Per-class results",
            "",
            "| Class | Precision | Recall | F1 | Support |",
            "|---|---:|---:|---:|---:|",
        ]
    )
    if classification["per_class"] is None:
        lines.append("| Not measured | — | — | — | — |")
    else:
        for label, values in classification["per_class"].items():
            lines.append(
                f"| `{label}` | {show(values['precision'])} | {show(values['recall'])} | {show(values['f1'])} | {values['support']} |"
            )
    lines.extend(["", "## Confusion matrix (predicted rows × actual columns)", ""])
    matrix = classification["confusion_matrix_rows_predicted_columns_actual"]
    if matrix is None:
        lines.append("Not measured (no prediction submission).")
    else:
        labels = list(next(iter(matrix.values())))
        lines.append("| Predicted | " + " | ".join(labels) + " |")
        lines.append("|---|" + "---:|" * len(labels))
        lines.extend(
            f"| `{row}` | " + " | ".join(str(matrix[row][column]) for column in labels) + " |"
            for row in matrix
        )
    lines.extend(
        [
            "",
            "## Calibration bands",
            "",
            "| Confidence bin | N | Mean confidence | Accuracy |",
            "|---|---:|---:|---:|",
        ]
    )
    if calibration["bins"] is None:
        lines.append("| Not measured | — | — | — |")
    else:
        lines.extend(
            f"| {item['bin']} | {item['count']} | {show(item['mean_confidence'])} | {show(item['accuracy'])} |"
            for item in calibration["bins"]
        )
    lines.extend(["", "## Per-case failure summary", ""])
    if not report["prediction_count"]:
        lines.append("No model predictions supplied; no model failure rate is assessed.")
    else:
        failures = [
            item
            for item in report["case_summaries"]
            if item["prediction_present"]
            and (
                item["diagnostic_exact_match"] is False
                or item["classification_correct"] is False
                or item["abstention_correct"] is False
            )
        ]
        if not failures:
            lines.append("No scored failures in the supplied prediction file.")
        else:
            lines.extend(
                f"- `{item['case_id']}`: diagnostic exact={item['diagnostic_exact_match']}; classification correct={item['classification_correct']}; abstention correct={item['abstention_correct']}"
                for item in failures
            )
    lines.extend(
        [
            "",
            "## Zero-denominator and interpretation policy",
            "",
            "Undefined ratios are `null`, not zero. Empty/empty diagnostic sets match exactly, but their per-case precision, recall, and F1 are undefined and excluded from macro averages. Semantic rates use only explicitly adjudicated claims; `not_adjudicated` is uncovered.",
            "",
            "## Limitations",
            "",
        ]
    )
    lines.extend(f"- {item}" for item in report["limitations"])
    return "\n".join(lines) + "\n"
