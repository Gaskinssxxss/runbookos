# M3 Synthetic Assessment Annotation Guidelines

Dataset: `m3-1.0`; assessment schema: v1; classification catalog: v2;
diagnostic catalog: v1.

## Separation and use

Each case has two sibling objects. `input` contains only synthetic incident
context, the versioned diagnostic catalog, and observations intended for a
model-facing workflow. `gold` contains
the independently authored expected diagnostic IDs, classification (or null
when intentionally unlabeled), reference evidence IDs, abstention decision,
and optional semantic validator examples. The evaluator exposes only `input`
through `model_facing_input`; it never serializes `gold` in that projection.
The five historical v0.6.0 cases remain regression-only and are not part of
this held-out dataset.

## Label rules

- Choose a diagnostic ID only when its registered scope could supply relevant
  evidence. `[]` is valid when no diagnostic is justified by available context.
- `healthy` requires an observation of expected behavior. A clean observation
  does not establish unrelated service state.
- `service_failure` describes the local service state. `connectivity_failure`
  describes a failed transport/protocol check. `network_failure` describes
  evidence about route or network capability. Do not infer the last two from a
  service symptom alone.
- Use `unknown` when evidence is missing, conflicting, or insufficient. Cases
  whose class cannot be reliably annotated use `classification: null` and are
  excluded from classification scoring while retaining their abstention label.
- A reference evidence ID means the observation is available as context. It is
  not a claim that a model citation is correct or that a causal explanation is
  supported.
- The `semantic_test_claims` are hand-authored validator examples. They are
  not model outputs and must never be counted as model performance. The false
  causal examples intentionally state more than their observations establish.

## Rationale and known limits

The 24 cases cover web, application, database, network, and insufficient
evidence categories, with normal, failure, conflicting, ambiguous, and absent
observations. Synthetic values are deterministic and targets are documentation
identifiers only. Labels are a compact test benchmark, not a representative
production distribution. A reviewer should independently inspect each case
before using it for comparative model claims. Semantic support scores require
separate adjudications by a qualified reviewer; citation validity, execution
status, assertion status, and model confidence are not substitutes.
