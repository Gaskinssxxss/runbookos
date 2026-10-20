from __future__ import annotations

import json
from pathlib import Path

import pytest

from runbookos.ai import ModelReply
from runbookos.errors import RunbookOSError
from runbookos.evaluation import (
    ConfiguredScenarioProvider,
    EvaluationPrediction,
    evaluate_prediction,
    load_evaluation_provider_config,
    load_scenarios,
    run_mock_evaluation,
    run_provider_evaluation,
    summarize_results,
)

SCENARIOS = Path(__file__).parents[1] / "scenarios"


class Provider:
    provider_name = "mock-provider"

    def __init__(self, answers: list[dict]):
        self.answers = answers
        self.calls: list[tuple[str, str]] = []

    def complete(self, system, user, max_tokens, temperature):
        self.calls.append((system, user))
        answer = self.answers.pop(0)
        return ModelReply(json.dumps(answer), "fake-model", 0.01, {"total_tokens": 12})


def test_all_scenario_fixtures_validate_and_have_expected_shapes() -> None:
    scenarios = load_scenarios(SCENARIOS)
    assert len(scenarios) == 6
    assert {item.failure_type for item in scenarios} == {
        "healthy",
        "service_failure",
        "connectivity_failure",
        "resource_pressure",
        "network_failure",
    }
    assert all(item.recovery_criteria for item in scenarios)


def test_provider_only_evaluation_config_is_independent_of_homelab_catalog(tmp_path: Path) -> None:
    path = tmp_path / "provider.yml"
    path.write_text(
        "schema_version: 1\nprovider:\n"
        "  type: openai_compatible\n"
        "  base_url: http://127.0.0.1:8080/v1\n"
        "  model: local-qwen\n"
        "  api_key_env: RUNBOOKOS_TEST_KEY\n"
        "  timeout_seconds: 450\n",
        encoding="utf-8",
    )
    config = load_evaluation_provider_config(path)
    assert config.provider.model == "local-qwen"
    assert config.provider.timeout_seconds == 450


def test_evaluator_separates_classification_root_cause_and_citation_quality() -> None:
    scenario = next(
        item for item in load_scenarios(SCENARIOS) if item.incident_id == "nginx-service-failure"
    )
    result = evaluate_prediction(
        scenario,
        EvaluationPrediction(
            classification="service_failure",
            root_cause="wrong_root_cause",
            evidence_refs=["FX-NGX-ACTIVE", "FAKE-REF"],
        ),
        diagnostic_ids=["web_health"],
        duration_seconds=1.5,
        provider="test",
        model="fake",
    )
    assert result["classification_correct"] is True
    assert result["root_cause_correct"] is False
    assert result["citation_validity"] is False
    assert result["safety_policy_violations"] == 1
    assert result["evidence_precision"] == 0.5
    assert result["evidence_recall"] == 0.5


def test_mock_benchmark_is_repeatable_and_labeled_as_fixture() -> None:
    scenarios = load_scenarios(SCENARIOS)
    results = run_mock_evaluation(scenarios, repeat=2)
    assert len(results) == 12
    assert {item["evidence_source"] for item in results} == {"synthetic_fixture"}
    assert {item["trial"] for item in results} == {1, 2}
    assert summarize_results(results)["diagnostic_classification_accuracy"] == 1.0


def test_false_positive_and_false_negative_rates_use_correct_denominators() -> None:
    scenarios = load_scenarios(SCENARIOS)
    results = run_mock_evaluation(scenarios)
    results[0]["false_positive"] = True
    results[1]["false_negative"] = True
    summary = summarize_results(results)
    assert summary["false_positive_rate"] == 1.0
    assert summary["false_negative_rate"] == 0.2


def test_summary_contains_confusion_matrix_and_per_class_rates() -> None:
    results = run_mock_evaluation(load_scenarios(SCENARIOS))
    healthy = next(item for item in results if item["expected_classification"] == "healthy")
    healthy["predicted_classification"] = "network_failure"
    healthy["classification_correct"] = False
    summary = summarize_results(results)
    assert summary["confusion_matrix"]["healthy"]["network_failure"] == 1
    assert summary["per_class_precision_recall"]["healthy"]["recall"] == 0.0
    assert summary["per_class_precision_recall"]["network_failure"]["false_positive"] == 1
    assert summary["per_scenario"][healthy["incident_id"]]["classification_accuracy"] == 0.0


def test_configured_provider_receives_no_ground_truth_and_usage_is_aggregated() -> None:
    scenario = load_scenarios(SCENARIOS)[0]
    answers = [
        {"diagnostic_ids": [scenario.expected_diagnostics[0]]},
        {
            "classification": scenario.expected_classification,
            "root_cause": scenario.expected_root_cause,
            "evidence_refs": scenario.expected_evidence_refs,
            "confidence": 0.7,
        },
    ]
    provider = Provider(answers)
    configured = ConfiguredScenarioProvider(provider, "fake-model")
    results = run_provider_evaluation([scenario], configured)
    assert results[0]["token_usage"] == {"total_tokens": 24}
    assert results[0]["confidence"] == 0.7
    assert results[0]["confidence_is_calibrated"] is False
    assert all("ground_truth" not in user for _, user in provider.calls)
    assert all(scenario.expected_root_cause not in user for _, user in provider.calls)


def test_configured_provider_rejects_unsupported_diagnostic() -> None:
    scenario = load_scenarios(SCENARIOS)[0]
    provider = Provider([{"diagnostic_ids": ["shell.exec"]}])
    configured = ConfiguredScenarioProvider(provider, "fake-model")
    with pytest.raises(RunbookOSError, match="unsupported diagnostic"):
        configured.predict(scenario)


def test_scenario_loading_rejects_fake_citation(tmp_path: Path) -> None:
    source = SCENARIOS / "healthy-baseline.yml"
    raw = source.read_text(encoding="utf-8").replace(
        "FX-WEB-UNIT, FX-WEB-DISK", "FAKE-REF, FX-WEB-DISK"
    )
    path = tmp_path / "bad.yml"
    path.write_text(raw, encoding="utf-8")
    with pytest.raises(Exception, match="missing from fixture"):
        load_scenarios(path)


def test_scenario_loading_rejects_arbitrary_or_mutating_action(tmp_path: Path) -> None:
    source = SCENARIOS / "healthy-baseline.yml"
    raw = source.read_text(encoding="utf-8").replace(
        "action: systemd.is_active", "action: shell.exec"
    )
    path = tmp_path / "unsafe.yml"
    path.write_text(raw, encoding="utf-8")
    with pytest.raises(Exception, match="unregistered or mutating"):
        load_scenarios(path)
