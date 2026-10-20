"""Prepare a blinded, human-only review packet from a synthetic v2 dataset."""

from __future__ import annotations

import json
import random
import re
import secrets
from pathlib import Path
from typing import Any
from uuid import uuid4

from .errors import ConfigurationError
from .evaluation import load_scenarios

_SCORE_FIELDS = (
    "explanation_accuracy",
    "evidence_support",
    "unsupported_claims",
    "abstention_appropriateness",
)


def _write_new(path: Path, payload: dict[str, Any], mode: int = 0o644) -> None:
    if path.exists():
        raise ConfigurationError(f"review output already exists: {path.name}")
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    path.chmod(mode)


def export_blind_review(
    dataset_path: Path,
    scenarios_dir: Path,
    output_dir: Path,
    *,
    seed: int | None = None,
) -> dict[str, Path]:
    """Write independent randomized reviewer packets and a separate answer key."""
    try:
        dataset = json.loads(dataset_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ConfigurationError("cannot read benchmark dataset") from exc
    if dataset.get("schema_version") != 2 or not isinstance(dataset.get("results"), list):
        raise ConfigurationError("blind review export requires an evaluation schema v2 dataset")

    scenarios = {item.incident_id: item for item in load_scenarios(scenarios_dir)}
    output_dir = output_dir.expanduser().resolve()
    output_dir.mkdir(parents=True, exist_ok=False)
    actual_seed = seed if seed is not None else secrets.randbits(64)
    rng = random.Random(actual_seed)
    reviewer_records: list[dict[str, Any]] = []
    answer_records: list[dict[str, Any]] = []
    seen: set[tuple[str, int]] = set()

    for row in dataset["results"]:
        incident_id = row.get("incident_id")
        scenario = scenarios.get(incident_id)
        if scenario is None:
            raise ConfigurationError(
                "dataset contains a scenario absent from the local fixture set"
            )
        trial = row.get("trial")
        if not isinstance(trial, int) or (incident_id, trial) in seen:
            raise ConfigurationError("dataset trial identity is missing or duplicated")
        seen.add((incident_id, trial))

        item_id = f"review-{uuid4().hex[:12]}"
        selected = set(row.get("selected_diagnostic_ids", []))
        evidence = [item for item in scenario.evidence if item.diagnostic_id in selected]
        ref_map = {item.ref: f"E{index:02d}" for index, item in enumerate(evidence, 1)}
        unknown_refs: dict[str, str] = {}

        def blind_ref(ref: str) -> str:
            if ref in ref_map:
                return ref_map[ref]
            if ref not in unknown_refs:
                unknown_refs[ref] = f"UNRESOLVED-{len(unknown_refs) + 1:02d}"
            return unknown_refs[ref]

        claims = []
        for claim in row.get("predicted_claims", []):
            claims.append(
                {
                    "statement": claim.get("statement", ""),
                    "evidence_refs": [blind_ref(ref) for ref in claim.get("evidence_refs", [])],
                }
            )
        cited = row.get("model_claimed_evidence_refs")
        if cited is None:
            cited = row.get("cited_evidence_refs", [])
        narrative = re.sub(
            r"\brc-[0-9]{3}\b", "[STRUCTURED ROOT ID]", row.get("root_cause_explanation", "")
        )
        record = {
            "review_item_id": item_id,
            "incident_context_untrusted": scenario.incident,
            "selected_diagnostics": row.get("selected_diagnostic_ids", []),
            "diagnostic_evidence": [
                {
                    "review_ref": ref_map[item.ref],
                    "diagnostic_id": item.diagnostic_id,
                    "action": item.action,
                    "status": item.status,
                    "evidence": item.evidence,
                }
                for item in evidence
            ],
            "model_explanation": narrative,
            "model_claims": claims,
            "model_citations": [blind_ref(ref) for ref in cited],
            "rubric": {field: None for field in _SCORE_FIELDS},
            "rationale": "",
        }
        reviewer_records.append(record)
        answer_records.append(
            {
                "review_item_id": item_id,
                "scenario_id": incident_id,
                "trial": trial,
                "expected_classification": row.get("expected_classification"),
                "predicted_classification": row.get("predicted_classification"),
                "expected_root_cause_id": row.get("expected_root_cause_id"),
                "predicted_root_cause_id": row.get("predicted_root_cause_id"),
                "expected_evidence_refs": row.get("expected_evidence_refs", []),
                "reference_map": ref_map,
                "unresolved_reference_map": unknown_refs,
            }
        )

    if not reviewer_records:
        raise ConfigurationError("dataset contains no reviewable trials")

    reviewer_1 = list(reviewer_records)
    reviewer_2 = list(reviewer_records)
    rng.shuffle(reviewer_1)
    rng.shuffle(reviewer_2)
    adjudicator = [
        {
            "review_item_id": item["review_item_id"],
            "reviewer_1_scores": {field: None for field in _SCORE_FIELDS},
            "reviewer_2_scores": {field: None for field in _SCORE_FIELDS},
            "disagreement_summary": "",
            "adjudicated_scores": {field: None for field in _SCORE_FIELDS},
            "adjudicator_rationale": "",
        }
        for item in reviewer_records
    ]
    answer = {
        "warning": "Ground truth and identity key. Do not distribute to reviewers.",
        "source_dataset": dataset_path.name,
        "randomization_seed": actual_seed,
        "items": answer_records,
    }
    paths = {
        "reviewer_1": output_dir / "reviewer-1.json",
        "reviewer_2": output_dir / "reviewer-2.json",
        "adjudicator": output_dir / "adjudicator.json",
        "answer_key": output_dir / "answer-key.json",
        "readme": output_dir / "README.md",
    }
    _write_new(paths["reviewer_1"], {"reviewer": "reviewer-1", "items": reviewer_1})
    _write_new(paths["reviewer_2"], {"reviewer": "reviewer-2", "items": reviewer_2})
    _write_new(paths["adjudicator"], {"adjudication": adjudicator})
    _write_new(paths["answer_key"], answer, mode=0o600)
    paths["readme"].write_text(
        "# Blind review packet\n\n"
        "Use reviewer-1.json and reviewer-2.json independently. Do not open or share "
        "answer-key.json before both reviews are complete. Each rubric dimension is scored "
        "0–2 with rationale. Adjudicate disagreements only after independent scoring. "
        "The answer key contains scenario identities and expected labels. No human scores "
        "are populated by this export. Evidence references are anonymized; unresolved "
        "model citations intentionally have no evidence item.\n",
        encoding="utf-8",
    )
    return paths


def reviewer_agreement(first_path: Path, second_path: Path) -> dict[str, Any]:
    """Calculate per-dimension exact agreement and Cohen's kappa after human scoring."""
    try:
        first = json.loads(first_path.read_text(encoding="utf-8"))
        second = json.loads(second_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ConfigurationError("cannot read completed reviewer sheets") from exc
    first_items = first.get("items")
    second_items = second.get("items")
    if not isinstance(first_items, list) or not isinstance(second_items, list):
        raise ConfigurationError("reviewer sheets must contain an items list")

    def index(items: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
        indexed = {item.get("review_item_id"): item for item in items}
        if None in indexed or len(indexed) != len(items):
            raise ConfigurationError("review item IDs must be present and unique")
        return indexed

    left, right = index(first_items), index(second_items)
    if not left or left.keys() != right.keys():
        raise ConfigurationError("reviewer sheets must contain the same non-empty item set")
    result: dict[str, Any] = {"items": len(left), "dimensions": {}}
    for dimension in _SCORE_FIELDS:
        pairs = []
        for item_id in sorted(left):
            score_a = left[item_id].get("rubric", {}).get(dimension)
            score_b = right[item_id].get("rubric", {}).get(dimension)
            if (
                not isinstance(score_a, int)
                or isinstance(score_a, bool)
                or score_a not in {0, 1, 2}
                or not isinstance(score_b, int)
                or isinstance(score_b, bool)
                or score_b not in {0, 1, 2}
            ):
                raise ConfigurationError(f"missing or invalid human score for {dimension}")
            pairs.append((score_a, score_b))
        observed = sum(a == b for a, b in pairs) / len(pairs)
        categories = (0, 1, 2)
        expected = sum(
            (sum(a == category for a, _ in pairs) / len(pairs))
            * (sum(b == category for _, b in pairs) / len(pairs))
            for category in categories
        )
        result["dimensions"][dimension] = {
            "exact_agreement": round(observed, 4),
            "cohen_kappa": round((observed - expected) / (1 - expected), 4)
            if expected < 1
            else None,
            "rated_items": len(pairs),
        }
    return result
