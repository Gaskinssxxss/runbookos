from __future__ import annotations

import json
import stat
from pathlib import Path

import pytest
import yaml

from runbookos.blind_review import export_blind_review, reviewer_agreement
from runbookos.errors import ConfigurationError
from runbookos.evaluation import load_scenarios

ROOT = Path(__file__).parents[1]


def synthetic_dataset(tmp_path: Path) -> Path:
    """Create test input locally; never depend on a private/historical benchmark artifact."""
    taxonomy = yaml.safe_load(
        (ROOT / "scenarios/metadata/ground-truth-taxonomy-v2.yml").read_text()
    )
    root_causes = {
        incident_id: details["root_cause_id"]
        for incident_id, details in taxonomy["scenarios"].items()
    }
    rows = []
    for scenario in load_scenarios(ROOT / "scenarios"):
        selected = scenario.expected_diagnostics
        citations = scenario.expected_evidence_refs
        if scenario.incident_id == "network-reachability-failure":
            citations = [*citations, "forged-evidence-ref"]
        for trial in range(1, 4):
            rows.append(
                {
                    "incident_id": scenario.incident_id,
                    "trial": trial,
                    "selected_diagnostic_ids": selected,
                    "predicted_claims": [
                        {"statement": "Synthetic explanation", "evidence_refs": citations}
                    ],
                    "root_cause_explanation": "Synthetic explanation",
                    "model_claimed_evidence_refs": citations,
                    "expected_classification": scenario.expected_classification,
                    "predicted_classification": scenario.expected_classification,
                    "expected_root_cause_id": root_causes[scenario.incident_id],
                    "predicted_root_cause_id": root_causes[scenario.incident_id],
                    "expected_evidence_refs": scenario.expected_evidence_refs,
                }
            )
    path = tmp_path / "synthetic-review-dataset.json"
    path.write_text(json.dumps({"schema_version": 2, "results": rows}))
    return path


def test_blind_review_export_hides_truth_and_has_separate_answer_key(tmp_path: Path) -> None:
    paths = export_blind_review(
        synthetic_dataset(tmp_path), ROOT / "scenarios", tmp_path / "packet", seed=42
    )
    reviewer_1 = json.loads(paths["reviewer_1"].read_text())
    reviewer_2 = json.loads(paths["reviewer_2"].read_text())
    key = json.loads(paths["answer_key"].read_text())
    ids_1 = [item["review_item_id"] for item in reviewer_1["items"]]
    ids_2 = [item["review_item_id"] for item in reviewer_2["items"]]
    assert len(ids_1) == 18
    assert set(ids_1) == set(ids_2)
    assert ids_1 != ids_2
    for item in reviewer_1["items"]:
        assert "scenario_id" not in item
        assert not any(name.startswith("expected_") for name in item)
        assert not any("root_cause_id" in name for name in item)
        assert all(value is None for value in item["rubric"].values())
    assert {item["expected_root_cause_id"] for item in key["items"]} == {
        "rc-000",
        "rc-100",
        "rc-101",
        "rc-102",
        "rc-200",
        "rc-300",
    }
    assert stat.S_IMODE(paths["answer_key"].stat().st_mode) == 0o600


def test_blind_review_rekeys_evidence_and_retains_unresolved_model_refs(tmp_path: Path) -> None:
    paths = export_blind_review(
        synthetic_dataset(tmp_path), ROOT / "scenarios", tmp_path / "packet", seed=7
    )
    reviewer = json.loads(paths["reviewer_1"].read_text())
    network = next(
        item
        for item in reviewer["items"]
        if any(ref.startswith("UNRESOLVED-") for ref in item["model_citations"])
    )
    available = {item["review_ref"] for item in network["diagnostic_evidence"]}
    assert available
    assert set(network["model_citations"]) - available
    assert all(ref.startswith("E") or ref.startswith("UNRESOLVED-") for ref in available)


def test_reviewer_agreement_requires_complete_human_scores(tmp_path: Path) -> None:
    paths = export_blind_review(
        synthetic_dataset(tmp_path), ROOT / "scenarios", tmp_path / "packet", seed=7
    )
    with pytest.raises(ConfigurationError, match="missing or invalid human score"):
        reviewer_agreement(paths["reviewer_1"], paths["reviewer_2"])


def test_reviewer_agreement_reports_exact_agreement_and_kappa(tmp_path: Path) -> None:
    first = tmp_path / "reviewer-1.json"
    second = tmp_path / "reviewer-2.json"
    first.write_text(
        json.dumps(
            {
                "items": [
                    {
                        "review_item_id": "a",
                        "rubric": {
                            "explanation_accuracy": 0,
                            "evidence_support": 1,
                            "unsupported_claims": 2,
                            "abstention_appropriateness": 1,
                        },
                    },
                    {
                        "review_item_id": "b",
                        "rubric": {
                            "explanation_accuracy": 2,
                            "evidence_support": 1,
                            "unsupported_claims": 2,
                            "abstention_appropriateness": 2,
                        },
                    },
                ]
            }
        )
    )
    second.write_text(first.read_text())
    result = reviewer_agreement(first, second)
    assert result["items"] == 2
    assert result["dimensions"]["explanation_accuracy"]["exact_agreement"] == 1.0
    assert result["dimensions"]["explanation_accuracy"]["cohen_kappa"] == 1.0
