#!/usr/bin/env python3
"""Offline-only M3 report generator; consumes files and performs no inference."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from runbookos.assessment_evaluation import (  # noqa: E402
    EvaluationInput,
    evaluate,
    load_dataset,
    load_taxonomy,
    render_markdown,
)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--dataset", type=Path, default=ROOT / "tests/fixtures/assessment_m3/heldout-v1.json"
    )
    parser.add_argument(
        "--taxonomy", type=Path, default=ROOT / "tests/fixtures/assessment_m3/taxonomy-v2.yml"
    )
    parser.add_argument(
        "--predictions", type=Path, help="optional JSON prediction/adjudication submission"
    )
    parser.add_argument("--json-out", type=Path, required=True)
    parser.add_argument("--markdown-out", type=Path, required=True)
    args = parser.parse_args()

    dataset = load_dataset(args.dataset)
    taxonomy = load_taxonomy(args.taxonomy)
    if dataset.classification_catalog_version != taxonomy.classification_catalog_version:
        parser.error("dataset and taxonomy versions do not match")
    if dataset.assessment_schema_version != taxonomy.assessment_schema_version:
        parser.error("dataset and assessment schema versions do not match")
    if dataset.diagnostic_catalog_version != taxonomy.diagnostic_catalog_version:
        parser.error("dataset and diagnostic catalog versions do not match")
    if any(
        case.input.diagnostic_catalog != taxonomy.diagnostic_descriptions for case in dataset.cases
    ):
        parser.error("model-facing diagnostic catalog differs from the versioned taxonomy")
    submission = None
    if args.predictions:
        if args.predictions.stat().st_size > 4 * 1024 * 1024:
            parser.error("prediction file exceeds 4 MiB")
        submission = EvaluationInput.model_validate_json(
            args.predictions.read_text(encoding="utf-8")
        )
    report = evaluate(dataset, submission)
    args.json_out.parent.mkdir(parents=True, exist_ok=True)
    args.markdown_out.parent.mkdir(parents=True, exist_ok=True)
    args.json_out.write_text(
        json.dumps(report, indent=2, sort_keys=True, allow_nan=False) + "\n", encoding="utf-8"
    )
    args.markdown_out.write_text(render_markdown(report), encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
