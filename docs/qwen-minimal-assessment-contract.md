# Minimal Qwen Assessment Contract (test-only)

## Result

Implemented semantic reply v2 in the local M3 benchmark adapter. The production
`StructuredAssessment` schema and `validate_assessment()` are unchanged. This
offline result establishes contract compatibility, not live Qwen compliance or
diagnostic accuracy.

## Model-facing JSON

The response is one strict JSON object with exactly these fields:

```json
{
  "reply_version": 2,
  "category": "service_failure",
  "confidence": 0.72,
  "evidence_ids": ["E01"],
  "reason": "The supplied observation reports the service is inactive.",
  "abstain": false,
  "overall_uncertainty": 0.28
}
```

`category` is one of `healthy`, `service_failure`, `connectivity_failure`,
`network_failure`, `dependency_failure`, `resource_pressure`, or `unknown`.
Confidence and uncertainty are finite JSON numbers in `[0, 1]`. `evidence_ids`
is an array of distinct, exact aliases shown for that case; an empty array is
allowed. The bounded reason is 1–500 characters. Unknown keys, malformed JSON,
invalid types, unsupported aliases, duplicate aliases, and output that violates
the contract are rejected; there is no repair or conversion to abstention.

Abstention is explicit and paired exactly with `category: "unknown"`:

```json
{
  "reply_version": 2,
  "category": "unknown",
  "confidence": 0.8,
  "evidence_ids": [],
  "reason": "The available observations do not determine a cause.",
  "abstain": true,
  "overall_uncertainty": 0.9
}
```

## Deterministic conversion and validation

The adapter resolves aliases only through the current case's alias map. It
copies fixture observations as unverified provenance and supplies trusted
incident/investigation IDs and fixed claim-type discriminators. It preserves
the model's category, confidence, selected aliases, reason, abstention, and
uncertainty. A non-abstained reply becomes a *suspected* classification and a
hypothesis with the same model reason and evidence; it is never promoted to
`supported` because fixture observations are unverified. A valid abstention
becomes an `unknown`/`undetermined` classification and an unknown claim, with
the model's reason and confidence retained. The existing validator then checks
the resulting `StructuredAssessment`.

When evidence references are empty, the unchanged validator permits a
non-abstained classification/hypothesis only at confidence `<= 0.25`; otherwise
conversion fails. Unknown category/status combinations and invalid references
fail closed. The reason guard rejects command-shaped/executable advice and
explicit verification/proof wording. It is deliberately conservative and may
reject even negated wording such as “not verified”; this is a safe rejection,
not a semantic evaluator. Valid citations do not prove that a causal statement
is true. Recommendations remain adapter-owned empty arrays; no execution,
approval, SSH, or remediation path is added.

Example semantic portion after converting the classification response above
(the adapter also supplies schema/catalog versions, IDs, and copied fixture
observations):

```json
{
  "hypotheses": [{
    "claim_type": "hypothesis",
    "statement": "A supplied observation is consistent with this category.",
    "evidence_refs": ["fixture:case-01:step-01"],
    "confidence": 0.72,
    "missing_evidence": [],
    "disconfirming_checks": []
  }],
  "classifications": [{
    "category": "service_failure",
    "confidence": 0.72,
    "supporting_evidence_refs": ["fixture:case-01:step-01"],
    "status": "suspected"
  }],
  "assessment_status": "assessed"
}
```

Example semantic portion after converting the explicit abstention above:

```json
{
  "hypotheses": [],
  "classifications": [{
    "category": "unknown",
    "confidence": 0.8,
    "supporting_evidence_refs": [],
    "status": "undetermined"
  }],
  "unknowns": [{
    "claim_type": "unknown",
    "question": "The available observations do not determine a cause.",
    "evidence_refs": [],
    "missing_evidence": []
  }],
  "assessment_status": "abstained"
}
```

| Field | Owner | Conversion/validation |
| --- | --- | --- |
| `category`, `confidence`, `evidence_ids`, `reason`, `abstain`, `overall_uncertainty` | Qwen | Preserved; checked against closed types, ranges, alias allowlist, and abstention invariant |
| `reply_version` | Qwen contract | Must equal `2` |
| incident/investigation IDs and observations/provenance | Adapter | Taken from the synthetic case and fixture context; never requested from model |
| claim discriminators, classification status, assessment status | Adapter | Deterministically mapped from reply type/abstention; then checked by unchanged validator |
| inferences and recommendations | Adapter | Empty; no semantic content is fabricated |

Diagnostic selection prompt, validation, and request budget remain unchanged.
M3 prediction-submission schema and evaluator input remain unchanged, so the
existing artifact round-trip and evaluator tests continue to pass. Historical
pilot reports and benchmark fixtures were not edited.

## Offline verification

- Focused M3 adapter, assessment, AI, evaluator, and v0.6.0 acceptance tests:
  **153 passed**.
- Full offline suite with coverage: **313 passed, 11 live tests skipped**;
  package coverage **82%**.
- Ruff lint and format checks: **passed**.
- `git diff --check`: **passed**.
- No model server, inference, SSH, operational database, or infrastructure was
  used.

## Files and fingerprints

Files changed for this work:

- `tests/ai_m3_benchmark_v070.py` — local test-only adapter (existing local
  untracked tooling).
- `tests/test_ai_m3_benchmark_v070.py` — offline contract/regression tests
  (existing local untracked tests).
- `docs/qwen-minimal-assessment-contract.md` — this report.

SHA-256 of the two Python files at verification:

```text
f6e1d1167a064a49348c8dd858be9013a411dd30bcebcfc789a16cdacd7ce121  tests/ai_m3_benchmark_v070.py
c32e258e0def35e28ee30739ee5d57df6eb7408c1e085157ad73936c37886637  tests/test_ai_m3_benchmark_v070.py
```

No production validator, gold label, approval manifest, historical report, or
Qwen runtime was changed. Mocked success does not establish that Qwen will
follow this contract.
