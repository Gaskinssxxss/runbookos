# ADR: Independent structured assessment evaluation (M3)

- Status: accepted for offline M3 implementation
- Baseline: `03e05a53b75888019d2be69193a932b795e37d65`
- Dataset: `m3-1.0`
- Assessment schema: v1; classification catalog: v2; diagnostic catalog: v1

## Contract mapping

M1/M2 source of truth is `runbookos.assessment.StructuredAssessment`. Its
machine output carries `observations`, `inferences`, `hypotheses`,
`classifications`, `unknowns`, `recommended_next_steps`, `overall_uncertainty`,
and `assessment_status`. Direct observations use stable `ref` identifiers and
retain `diagnostic_id`, `source_action`, execution status, assertion outcome,
verification status, incident, and investigation. M3 consumes the assessment
as-is; it does not introduce a replacement assessment contract.

The existing closed classification set is `healthy`, `service_failure`,
`connectivity_failure`, `network_failure`, `dependency_failure`,
`resource_pressure`, and `unknown` (catalog v2). The diagnostic IDs are
`web_health`, `application_health`, `database_health`, and `network_health`.
The five records in `ai_acceptance_v060/scenarios.json` remain regression-only.

M3 inputs use `input` for model-facing synthetic observations and `gold` for
expected diagnostic sets, classification, reference evidence IDs, abstention,
and hand-authored semantic validator examples. `model_facing_input()` returns
only the `input` object. Predictions are a separate artifact and cannot assign
or overwrite gold labels.

## Decision

Implement pure deterministic metric functions in
`runbookos.assessment_evaluation`, using Pydantic and the already-declared
PyYAML dependency. Reuse the M1/M2 assessment validator for assessment schema,
reference, and verification invariants. Compare assessment observations to the
provided input evidence before scoring. Do not import an AI provider, engine,
SSH adapter, storage connection, or local inference orchestrator in this M3
module. A small offline script loads fixtures and optional prediction JSON and
writes JSON/Markdown reports; it never produces predictions.

Zero denominators serialize as JSON `null`. Empty/empty diagnostic sets are
exact matches, but their per-case P/R/F1 are undefined and excluded from the
respective macro average. Per-case F1 is the count-based ratio and is zero when
there are false negatives but no selected IDs. Semantic claim labels are
explicit independent inputs. Missing adjudications count as
`not_adjudicated`; unsupported rate denominator is adjudicated claims only.
Calibration uses the top-confidence non-undetermined, non-unknown classification
as a binary exact-correctness event. Abstained and unlabeled cases are excluded
and counted separately. ECE uses ten fixed-width bins, with confidence 1.0 in
the final inclusive bin.

## Consequences and limits

The evaluator can establish arithmetic and contract correctness with tests. It
cannot establish causal entailment from references or model confidence. The
held-out report intentionally contains no model performance values because no
predictions were measured in this task. Human semantic adjudication remains
separate. The small synthetic set is for reproducibility and regression, not a
production calibration claim.
