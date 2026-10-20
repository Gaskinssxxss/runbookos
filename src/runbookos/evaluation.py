"""Offline incident scenario validation and diagnostic quality evaluation.

Scenario evidence is synthetic fixture data. It is deliberately separate from the
production execution engine and must never be treated as live host telemetry.
"""

from __future__ import annotations

import hashlib
import json
import re
import time
from collections.abc import Iterable
from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator

from .actions import REGISTRY
from .ai import ChatProvider, ModelReply, ProviderConfig, _decode_model_json
from .errors import ConfigurationError, PolicyDenied, RunbookOSError

_SAFE_DIAGNOSTIC_IDS = {
    "web_health",
    "application_health",
    "database_health",
    "network_health",
}
MAX_EVALUATION_CONFIG_BYTES = 64 * 1024


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class EvaluationProviderConfig(StrictModel):
    schema_version: Literal[1]
    provider: ProviderConfig


def load_evaluation_provider_config(path: Path) -> EvaluationProviderConfig:
    try:
        if path.stat().st_size > MAX_EVALUATION_CONFIG_BYTES:
            raise ConfigurationError("evaluation provider config exceeds 64 KiB")
        config = EvaluationProviderConfig.model_validate(
            yaml.safe_load(path.read_text(encoding="utf-8"))
        )
    except (OSError, yaml.YAMLError, ValidationError) as exc:
        raise ConfigurationError(f"invalid evaluation provider config: {exc}") from exc
    return config


class EvidenceFixture(StrictModel):
    ref: str = Field(pattern=r"^FX-[A-Z0-9_-]{2,48}$")
    diagnostic_id: str = Field(pattern=r"^[a-z][a-z0-9_-]{1,63}$")
    target: str = Field(pattern=r"^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,62}$")
    action: str = Field(pattern=r"^[a-z][a-z0-9_]*\.[a-z][a-z0-9_]*$")
    status: Literal["succeeded", "failed"]
    evidence: dict[str, Any]


class MockPrediction(StrictModel):
    """A scripted provider response, not a claim about model quality."""

    classification: str = Field(min_length=1, max_length=100)
    root_cause: str = Field(min_length=1, max_length=300)
    evidence_refs: list[str] = Field(min_length=1, max_length=32)
    diagnostic_ids: list[str] = Field(min_length=1, max_length=8)


class IncidentScenario(StrictModel):
    schema_version: Literal[1]
    incident_id: str = Field(pattern=r"^[a-z][a-z0-9_-]{2,63}$")
    name: str = Field(min_length=1, max_length=120)
    target: str = Field(pattern=r"^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,62}$")
    service: str = Field(min_length=1, max_length=128)
    failure_type: Literal[
        "healthy",
        "service_failure",
        "connectivity_failure",
        "resource_pressure",
        "network_failure",
    ]
    incident: str = Field(min_length=1, max_length=1000)
    ground_truth: str = Field(min_length=1, max_length=300)
    expected_classification: str = Field(pattern=r"^[a-z][a-z0-9_-]{1,63}$")
    expected_root_cause: str = Field(min_length=1, max_length=300)
    expected_diagnostics: list[str] = Field(min_length=1, max_length=16)
    available_diagnostics: list[str] = Field(min_length=1, max_length=32)
    expected_evidence_refs: list[str] = Field(min_length=1, max_length=32)
    evidence: list[EvidenceFixture] = Field(min_length=1, max_length=64)
    recovery_criteria: list[str] = Field(min_length=1, max_length=12)
    mock_prediction: MockPrediction

    @field_validator("incident_id")
    @classmethod
    def valid_incident_id(cls, value: str) -> str:
        if not re.fullmatch(r"[a-z][a-z0-9_-]{2,63}", value):
            raise ValueError("invalid incident ID")
        return value

    @field_validator("expected_diagnostics", "expected_evidence_refs")
    @classmethod
    def unique_values(cls, values: list[str]) -> list[str]:
        if len(values) != len(set(values)):
            raise ValueError("scenario lists must not contain duplicates")
        return values

    @field_validator("evidence")
    @classmethod
    def unique_evidence_refs(cls, values: list[EvidenceFixture]) -> list[EvidenceFixture]:
        refs = [item.ref for item in values]
        if len(refs) != len(set(refs)):
            raise ValueError("fixture evidence refs must be unique")
        return values

    def validate_cross_references(self) -> IncidentScenario:
        refs = {item.ref for item in self.evidence}
        missing = set(self.expected_evidence_refs) - refs
        if missing:
            raise ValueError(f"expected evidence refs missing from fixture: {sorted(missing)}")
        if set(self.mock_prediction.evidence_refs) - refs:
            raise ValueError("mock prediction references evidence absent from fixture")
        allowed_diagnostics = set(self.available_diagnostics)
        if (
            set(self.expected_diagnostics) - allowed_diagnostics
            or set(self.mock_prediction.diagnostic_ids) - allowed_diagnostics
            or allowed_diagnostics - _SAFE_DIAGNOSTIC_IDS
        ):
            raise ValueError("scenario diagnostic catalog contains an unsupported ID")
        if any(item.target != self.target for item in self.evidence):
            raise ValueError("fixture evidence target must match scenario target")
        if any(item.diagnostic_id not in allowed_diagnostics for item in self.evidence):
            raise ValueError("fixture evidence references a diagnostic outside its catalog")
        if any(
            item.action not in REGISTRY or not REGISTRY[item.action].read_only
            for item in self.evidence
        ):
            raise ValueError("fixture evidence uses an unregistered or mutating action")
        return self


class EvaluationPrediction(StrictModel):
    classification: Literal[
        "healthy",
        "service_failure",
        "connectivity_failure",
        "resource_pressure",
        "network_failure",
        "unknown",
    ]
    root_cause: str = Field(min_length=1, max_length=300)
    evidence_refs: list[str] = Field(default_factory=list, max_length=32)
    confidence: float | None = Field(default=None, ge=0, le=1)


class EvaluationSelection(StrictModel):
    model_config = ConfigDict(extra="forbid")
    diagnostic_ids: list[str] = Field(min_length=1, max_length=8)


def load_scenarios(path: Path) -> list[IncidentScenario]:
    """Load one scenario YAML or a directory of YAML fixture files."""
    paths = [path] if path.is_file() else sorted([*path.glob("*.yml"), *path.glob("*.yaml")])
    if not paths:
        raise ConfigurationError(f"no incident scenario YAML files found in {path}")
    if len(paths) > 100:
        raise ConfigurationError("scenario set exceeds 100 files")
    scenarios: list[IncidentScenario] = []
    identifiers: set[str] = set()
    for file_path in paths:
        if file_path.stat().st_size > 128 * 1024:
            raise ConfigurationError(f"scenario exceeds 128 KiB: {file_path.name}")
        try:
            raw = yaml.safe_load(file_path.read_text(encoding="utf-8"))
            scenario = IncidentScenario.model_validate(raw).validate_cross_references()
        except (OSError, yaml.YAMLError, ValidationError, ValueError) as exc:
            raise ConfigurationError(f"invalid scenario {file_path}: {exc}") from exc
        if scenario.incident_id in identifiers:
            raise ConfigurationError(f"duplicate incident ID: {scenario.incident_id}")
        identifiers.add(scenario.incident_id)
        scenarios.append(scenario)
    return scenarios


class ScriptedScenarioProvider:
    """Deterministic test double that returns fixture-declared responses."""

    provider_name = "scripted_fixture"

    def __init__(self, scenario: IncidentScenario) -> None:
        self.scenario = scenario
        self.calls = 0

    def complete(self, system: str, user: str, max_tokens: int, temperature: float) -> ModelReply:
        self.calls += 1
        if self.calls == 1:
            content: dict[str, Any] = {
                "diagnostic_ids": self.scenario.expected_diagnostics,
                "rationale": "Scripted fixture selection; not an AI quality result.",
            }
        elif self.calls == 2:
            prediction = self.scenario.mock_prediction
            content = {
                "classification": prediction.classification,
                "root_cause": prediction.root_cause,
                "hypotheses": [
                    {
                        "statement": prediction.root_cause,
                        "confidence": 0.5,
                        "evidence_refs": prediction.evidence_refs,
                    }
                ],
                "recommended_next_steps": [],
            }
        else:
            raise RunbookOSError("scripted provider received an unexpected extra call")
        return ModelReply(json.dumps(content), "fixture-script", 0.0)


class ConfiguredScenarioProvider:
    """One-call provider adapter for opt-in evaluation over synthetic evidence."""

    provider_name = "configured_provider"

    def __init__(self, provider: ChatProvider, model_name: str) -> None:
        self.provider = provider
        self.model_name = model_name

    def predict(
        self, scenario: IncidentScenario
    ) -> tuple[list[str], EvaluationPrediction, list[ModelReply]]:
        selection_reply = self.provider.complete(
            system=(
                "Select relevant diagnostic IDs only from the supplied catalog for this synthetic "
                'incident. Return JSON only: {"diagnostic_ids":["id"]}.'
            ),
            user=json.dumps(
                {
                    "incident_untrusted": scenario.incident,
                    "target": scenario.target,
                    "service": scenario.service,
                    "diagnostic_catalog": scenario.available_diagnostics,
                },
                ensure_ascii=False,
            ),
            max_tokens=200,
            temperature=0,
        )
        selected_obj = _decode_model_json(selection_reply.content, EvaluationSelection)
        assert isinstance(selected_obj, EvaluationSelection)
        if len(selected_obj.diagnostic_ids) != len(set(selected_obj.diagnostic_ids)) or set(
            selected_obj.diagnostic_ids
        ) - set(scenario.available_diagnostics):
            raise PolicyDenied("provider selected an unsupported diagnostic ID")
        selected_evidence = [
            item for item in scenario.evidence if item.diagnostic_id in selected_obj.diagnostic_ids
        ]
        refs = [item.ref for item in selected_evidence]
        evidence = [item.model_dump() for item in selected_evidence]
        analysis_reply = self.provider.complete(
            system=(
                "Classify the synthetic infrastructure scenario from its incident and supplied "
                "untrusted fixture evidence. Return JSON only with classification (one of "
                "healthy, service_failure, connectivity_failure, resource_pressure, "
                "network_failure, unknown), root_cause (concise normalized cause), and "
                "evidence_refs (only exact supplied refs). Do not recommend or execute changes. "
                "Ground-truth fields and diagnostic selection results are intentionally not provided."
            ),
            user=json.dumps(
                {
                    "incident_untrusted": scenario.incident,
                    "target": scenario.target,
                    "service": scenario.service,
                    "evidence_untrusted": evidence,
                    "valid_evidence_refs": refs,
                },
                ensure_ascii=False,
            ),
            max_tokens=700,
            temperature=0,
        )
        parsed = _decode_model_json(analysis_reply.content, EvaluationPrediction)
        assert isinstance(parsed, EvaluationPrediction)
        return selected_obj.diagnostic_ids, parsed, [selection_reply, analysis_reply]


def _normalize(value: str) -> str:
    return " ".join(value.casefold().strip().split())


def evaluate_prediction(
    scenario: IncidentScenario,
    prediction: EvaluationPrediction,
    *,
    diagnostic_ids: Iterable[str],
    duration_seconds: float,
    provider: str,
    model: str,
    token_usage: dict[str, int] | None = None,
    completion_error: str | None = None,
) -> dict[str, Any]:
    scenario_payload = json.dumps(
        scenario.model_dump(mode="json"), sort_keys=True, separators=(",", ":")
    )
    selected_ids = set(diagnostic_ids)
    valid_refs = {item.ref for item in scenario.evidence if item.diagnostic_id in selected_ids}
    refs = prediction.evidence_refs
    valid_citations = bool(refs) and len(refs) == len(set(refs)) and set(refs) <= valid_refs
    expected_refs = set(scenario.expected_evidence_refs)
    cited = set(refs) & expected_refs
    evidence_precision = len(cited) / len(set(refs)) if refs else 0.0
    evidence_recall = len(cited) / len(expected_refs) if expected_refs else 1.0
    diagnosis_correct = _normalize(prediction.classification) == _normalize(
        scenario.expected_classification
    )
    root_cause_correct = _normalize(prediction.root_cause) == _normalize(
        scenario.expected_root_cause
    )
    expected_incident = scenario.expected_classification != "healthy"
    predicted_incident = prediction.classification != "healthy"
    return {
        "incident_id": scenario.incident_id,
        "scenario_sha256": hashlib.sha256(scenario_payload.encode("utf-8")).hexdigest(),
        "provider": provider,
        "model": model,
        "diagnostic_ids": list(diagnostic_ids),
        "expected_diagnostic_ids": scenario.expected_diagnostics,
        "diagnostics_match": set(diagnostic_ids) == set(scenario.expected_diagnostics),
        "diagnostic_selection_accuracy": set(diagnostic_ids) == set(scenario.expected_diagnostics),
        "expected_classification": scenario.expected_classification,
        "predicted_classification": prediction.classification,
        "classification_correct": diagnosis_correct,
        "expected_root_cause": scenario.expected_root_cause,
        "predicted_root_cause": prediction.root_cause,
        "root_cause_correct": root_cause_correct,
        "citation_validity": valid_citations,
        "cited_evidence_refs": refs,
        "expected_evidence_refs": sorted(expected_refs),
        "evidence_precision": round(evidence_precision, 4),
        "evidence_recall": round(evidence_recall, 4),
        "false_positive": predicted_incident and not expected_incident,
        "false_negative": expected_incident and not predicted_incident,
        "completed": completion_error is None,
        "error_type": completion_error,
        "duration_seconds": round(max(0.0, duration_seconds), 4),
        "token_usage": token_usage,
        "confidence": prediction.confidence,
        "confidence_is_calibrated": False,
        "safety_policy_violations": int(not valid_citations),
        "evidence_source": "synthetic_fixture",
        "confidence_interpretation": "unavailable for this deterministic exact-label evaluator",
    }


def summarize_results(results: list[dict[str, Any]]) -> dict[str, Any]:
    count = len(results)
    if not count:
        raise ConfigurationError("evaluation produced no scenario results")
    positives = sum(item["expected_classification"] != "healthy" for item in results)
    negatives = sum(item["expected_classification"] == "healthy" for item in results)
    false_positive = sum(item["false_positive"] for item in results)
    false_negative = sum(item["false_negative"] for item in results)
    usage_results = [item["token_usage"] or {} for item in results]
    token_keys = {key for item in usage_results for key in item}
    labels = sorted(
        {item["expected_classification"] for item in results}
        | {item["predicted_classification"] for item in results}
    )
    confusion = {expected: {predicted: 0 for predicted in labels} for expected in labels}
    for item in results:
        confusion[item["expected_classification"]][item["predicted_classification"]] += 1
    per_class = {}
    for label in labels:
        tp = confusion[label][label]
        fp = sum(confusion[other][label] for other in labels if other != label)
        fn = sum(confusion[label][other] for other in labels if other != label)
        per_class[label] = {
            "true_positive": tp,
            "false_positive": fp,
            "false_negative": fn,
            "precision": round(tp / (tp + fp), 4) if tp + fp else None,
            "recall": round(tp / (tp + fn), 4) if tp + fn else None,
        }
    scenario_groups: dict[str, list[dict[str, Any]]] = {}
    for item in results:
        scenario_groups.setdefault(item["incident_id"], []).append(item)
    per_scenario = {
        incident_id: {
            "trial_count": len(items),
            "classification_accuracy": round(
                sum(item["classification_correct"] for item in items) / len(items), 4
            ),
            "root_cause_exact_accuracy": round(
                sum(item["root_cause_correct"] for item in items) / len(items), 4
            ),
            "diagnostic_selection_accuracy": round(
                sum(item["diagnostic_selection_accuracy"] for item in items) / len(items), 4
            ),
            "citation_validity_rate": round(
                sum(item["citation_validity"] for item in items) / len(items), 4
            ),
            "completion_rate": round(sum(item["completed"] for item in items) / len(items), 4),
        }
        for incident_id, items in sorted(scenario_groups.items())
    }
    return {
        "scenario_count": count,
        "confusion_matrix": confusion,
        "per_class_precision_recall": per_class,
        "per_scenario": per_scenario,
        "diagnostic_classification_accuracy": round(
            sum(item["classification_correct"] for item in results) / count, 4
        ),
        "diagnostic_selection_accuracy": round(
            sum(item["diagnostic_selection_accuracy"] for item in results) / count, 4
        ),
        "root_cause_identification_accuracy": round(
            sum(item["root_cause_correct"] for item in results) / count, 4
        ),
        "citation_validity_rate": round(
            sum(item["citation_validity"] for item in results) / count, 4
        ),
        "mean_evidence_precision": round(
            sum(item["evidence_precision"] for item in results) / count, 4
        ),
        "mean_evidence_recall": round(sum(item["evidence_recall"] for item in results) / count, 4),
        "false_positive_rate": round(false_positive / negatives, 4) if negatives else None,
        "false_negative_rate": round(false_negative / positives, 4) if positives else None,
        "completion_rate": round(sum(item["completed"] for item in results) / count, 4),
        "mean_end_to_end_latency_seconds": round(
            sum(item["duration_seconds"] for item in results) / count, 4
        ),
        "provider_token_usage_available": any(item["token_usage"] is not None for item in results),
        "total_prompt_tokens": (
            sum(item.get("prompt_tokens", 0) for item in usage_results)
            if "prompt_tokens" in token_keys
            else None
        ),
        "total_completion_tokens": (
            sum(item.get("completion_tokens", 0) for item in usage_results)
            if "completion_tokens" in token_keys
            else None
        ),
        "total_tokens": (
            sum(item.get("total_tokens", 0) for item in usage_results)
            if "total_tokens" in token_keys
            else None
        ),
        "safety_policy_violation_count": sum(item["safety_policy_violations"] for item in results),
    }


def render_report(dataset: dict[str, Any]) -> str:
    summary = dataset["summary"]
    lines = [
        f"# RunbookOS Diagnostic Evaluation — {dataset['evaluation_id']}",
        "",
        f"- Created: {dataset['created_at']}",
        f"- Mode: `{dataset['mode']}`",
        f"- Evidence source: `{dataset['evidence_source']}`",
        f"- Model: `{dataset['model']}`",
        f"- Scenarios: {summary['scenario_count']}",
        "",
        "## Metrics",
        "",
        "| Metric | Value |",
        "|---|---:|",
    ]
    for key, value in summary.items():
        if key in {"confusion_matrix", "per_class_precision_recall", "per_scenario"}:
            continue
        lines.append(f"| {key.replace('_', ' ')} | {value} |")
    labels = sorted(summary["confusion_matrix"])
    lines += [
        "",
        "## Classification confusion matrix",
        "",
        "Rows are expected labels; columns are model predictions.",
        "",
        "| Expected / predicted | " + " | ".join(labels) + " |",
        "|---|" + "---:|" * len(labels),
    ]
    for expected in labels:
        values = summary["confusion_matrix"][expected]
        lines.append(f"| {expected} | " + " | ".join(str(values[label]) for label in labels) + " |")
    lines += [
        "",
        "## Per-class precision and recall",
        "",
        "| Class | Precision | Recall |",
        "|---|---:|---:|",
    ]
    for label, values in summary["per_class_precision_recall"].items():
        lines.append(f"| {label} | {values['precision']} | {values['recall']} |")
    lines += [
        "",
        "## Per-scenario accuracy and completion",
        "",
        "| Incident | Trials | Classification | Root cause exact | Diagnostic selection | Citation validity | Completion |",
        "|---|---:|---:|---:|---:|---:|---:|",
    ]
    for incident_id, values in summary["per_scenario"].items():
        lines.append(
            f"| {incident_id} | {values['trial_count']} | "
            f"{values['classification_accuracy']} | {values['root_cause_exact_accuracy']} | "
            f"{values['diagnostic_selection_accuracy']} | {values['citation_validity_rate']} | "
            f"{values['completion_rate']} |"
        )
    lines += [
        "",
        "## Per-scenario results",
        "",
        "| Incident | Expected | Predicted | Classification | Root cause | Citations | Latency |",
        "|---|---|---|---:|---:|---:|---:|",
    ]
    for item in dataset["results"]:
        lines.append(
            f"| {item['incident_id']} | {item['expected_classification']} | "
            f"{item['predicted_classification']} | {item['classification_correct']} | "
            f"{item['root_cause_correct']} | {item['citation_validity']} | "
            f"{item['duration_seconds']}s |"
        )
    lines += [
        "",
        "## Interpretation limits",
        "",
        "Scenario evidence is synthetic fixture data, not live infrastructure evidence. "
        "Exact root-cause matching is intentionally strict and does not provide semantic credit. "
        "Provider confidence values are not calibrated probabilities and are not used as accuracy. "
        "The scripted mock returns fixture-declared answers; its scores validate evaluator plumbing, "
        "not AI diagnostic quality. No fault injection or remediation was performed.",
        "",
    ]
    return "\n".join(lines)


def run_mock_evaluation(scenarios: list[IncidentScenario], repeat: int = 1) -> list[dict[str, Any]]:
    results = []
    for trial in range(repeat):
        for scenario in scenarios:
            prediction = EvaluationPrediction(
                classification=scenario.mock_prediction.classification,
                root_cause=scenario.mock_prediction.root_cause,
                evidence_refs=scenario.mock_prediction.evidence_refs,
            )
            result = evaluate_prediction(
                scenario,
                prediction,
                diagnostic_ids=scenario.mock_prediction.diagnostic_ids,
                duration_seconds=0,
                provider="scripted_fixture",
                model="fixture-script",
            )
            result["trial"] = trial + 1
            results.append(result)
    return results


def run_provider_evaluation(
    scenarios: list[IncidentScenario], configured: ConfiguredScenarioProvider, repeat: int = 1
) -> list[dict[str, Any]]:
    results = []
    for trial in range(repeat):
        for scenario in scenarios:
            start = time.monotonic()
            try:
                selected_ids, prediction, replies = configured.predict(scenario)
                elapsed = time.monotonic() - start
                usage_parts = [reply.token_usage for reply in replies if reply.token_usage]
                token_usage = (
                    {
                        key: sum(part.get(key, 0) for part in usage_parts)
                        for key in {key for part in usage_parts for key in part}
                    }
                    if usage_parts
                    else None
                )
                result = evaluate_prediction(
                    scenario,
                    prediction,
                    diagnostic_ids=selected_ids,
                    duration_seconds=elapsed,
                    provider=configured.provider.provider_name,
                    model=configured.model_name,
                    token_usage=token_usage,
                )
            except Exception as exc:
                elapsed = time.monotonic() - start
                scenario_payload = json.dumps(
                    scenario.model_dump(mode="json"), sort_keys=True, separators=(",", ":")
                )
                result = {
                    "incident_id": scenario.incident_id,
                    "scenario_sha256": hashlib.sha256(scenario_payload.encode("utf-8")).hexdigest(),
                    "provider": configured.provider.provider_name,
                    "model": configured.model_name,
                    "diagnostic_ids": [],
                    "expected_diagnostic_ids": scenario.expected_diagnostics,
                    "diagnostics_match": False,
                    "diagnostic_selection_accuracy": False,
                    "expected_classification": scenario.expected_classification,
                    "predicted_classification": "unknown",
                    "classification_correct": False,
                    "expected_root_cause": scenario.expected_root_cause,
                    "predicted_root_cause": "unavailable",
                    "root_cause_correct": False,
                    "citation_validity": False,
                    "cited_evidence_refs": [],
                    "expected_evidence_refs": sorted(scenario.expected_evidence_refs),
                    "evidence_precision": 0.0,
                    "evidence_recall": 0.0,
                    "false_positive": False,
                    "false_negative": scenario.expected_classification != "healthy",
                    "completed": False,
                    "error_type": type(exc).__name__,
                    "duration_seconds": round(elapsed, 4),
                    "token_usage": None,
                    "confidence": None,
                    "confidence_is_calibrated": False,
                    "safety_policy_violations": int(isinstance(exc, PolicyDenied)),
                    "evidence_source": "synthetic_fixture",
                }
            result["trial"] = trial + 1
            results.append(result)
    return results


def build_dataset(results: list[dict[str, Any]], mode: str) -> dict[str, Any]:
    from datetime import UTC, datetime
    from uuid import uuid4

    providers = sorted({item["provider"] for item in results})
    models = sorted({item["model"] for item in results})
    return {
        "schema_version": 1,
        "evaluation_id": str(uuid4()),
        "created_at": datetime.now(UTC).isoformat(),
        "mode": mode,
        "provider": ",".join(providers),
        "model": ",".join(models),
        "evidence_source": "synthetic_fixture",
        "summary": summarize_results(results),
        "results": results,
    }


def save_dataset(dataset: dict[str, Any], json_path: Path, report_path: Path) -> None:
    if json_path.exists() or report_path.exists():
        raise ConfigurationError("evaluation output already exists; choose a new output directory")
    json_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.parent.mkdir(parents=True, exist_ok=True)
    json_path.write_text(json.dumps(dataset, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    report_path.write_text(render_report(dataset), encoding="utf-8")
