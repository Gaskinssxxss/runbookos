# Diagnostic taxonomy and root-cause evaluation v2

## Taxonomy

The evaluator uses explicit definitions in [diagnostic-taxonomy.v2.example.yml](../config/diagnostic-taxonomy.v2.example.yml). Classification describes the symptom layer indicated by the incident/evidence:

| Classification | Meaning | Example evidence |
|---|---|---|
| `service_failure` | The service being checked on the target is inactive, failed, or unable to serve locally. | `systemd.is_active` reports the target service inactive. |
| `connectivity_failure` | A configured endpoint/protocol cannot be reached, but available evidence does not locate the fault in the local service or route. | TCP probe times out; no route evidence is available. |
| `network_failure` | Evidence identifies a path fault such as a missing route, interface, or gateway. | The required route is absent on the gateway. |
| `dependency_failure` | A caller's dependency is unavailable; the caller may itself be running. | The application reports database unavailable and PostgreSQL evidence shows its service inactive. |
| `resource_pressure` | A measured resource crosses a stated threshold. | Root filesystem usage exceeds the scenario threshold. |
| `healthy` | Required checks are sufficient and support no observed fault. | Required baseline service and capacity evidence is healthy. |
| `unknown` | Evidence is missing, conflicting, or insufficient to distinguish categories. This is an explicit abstention. | Only a generic client error is present, without target or path evidence. |

Root-cause identifiers are opaque stable IDs (`rc-100` … `rc-999`) whose descriptions are sent as a candidate taxonomy. The expected ID mapping is held in `scenarios/metadata/ground-truth-taxonomy-v2.yml` and is loaded only by the evaluator after model output. Neither this mapping nor v1 expected root-cause strings, expected diagnostic IDs, or `ground_truth` fields are included in provider prompts. Opaque IDs prevent the model from merely copying a ground-truth slug; descriptions make the candidate taxonomy interpretable.

The v2 taxonomy reclassifies the existing PostgreSQL scenario as `dependency_failure`: the application reports its dependency unavailable and the fixture confirms the PostgreSQL service is inactive. This is an explicit taxonomy change, not a fixture/evidence change. v0.2.3 scenario files and datasets remain unchanged. `scenario_sha256` values in the v2 dataset bind the original fixture content used for each trial.

## Metrics

- Classification accuracy and confusion matrix use exact class IDs.
- Root-cause ID correctness is a deterministic exact match against the separate v2 expected map.
- Diagnostic set metrics include exact match, per-trial precision/recall, unnecessary selected count, and missed required count. Expected selections are inherited unchanged from the six original fixtures.
- Citation validity checks that citations are unique and belong to diagnostics actually selected and supplied.
- Evidence-support precision/recall measures overlap with fixture-declared expected evidence references. It is a reference/coverage score, not semantic entailment.
- `unsupported_claim_count_reference_only` counts claims without citations or with citations outside the supplied evidence. A syntactically valid citation can still fail to support the prose; semantic support is deliberately not declared by this deterministic metric.
- `unknown` classification or root ID `rc-999` is recorded as abstention, not healthy. Known fixture cases make an abstention incorrect but do not count it as a policy violation.
- Confidence is retained as uncalibrated metadata only.

The v0.2.3 exact-string root-cause score remains in its raw baseline JSON and is not rewritten. Because that benchmark expected slugs while the provider emitted prose, its 0% is not numerically comparable to structured-ID accuracy.

## Blind human review rubric

Natural-language explanation quality and semantic evidence support require human review; the model is never used as its own judge. Prepare one review record per anonymous trial, omit incident ID, expected class, expected root ID, and expected evidence, randomize order, and give two reviewers the incident text, selected diagnostics, emitted explanation/claims, and cited fixture evidence. Reviewers independently score:

1. **Explanation accuracy (0–2):** 0 materially wrong; 1 partly correct or underspecified; 2 consistent with available evidence.
2. **Evidence support (0–2):** 0 cited evidence does not support the statement; 1 partial support; 2 each material claim is supported by the cited evidence.
3. **Unsupported claims (0–2):** 0 multiple/material uncited assertions; 1 one minor unsupported assertion; 2 none observed.
4. **Abstention appropriateness (0–2):** 0 decisive answer despite insufficient/conflicting evidence, or abstention despite decisive evidence; 1 debatable; 2 appropriate to evidence.

Record reviewer rationale and disagreement. Resolve disagreements by a third reviewer and report initial agreement and adjudicated scores separately. Do not use this rubric to modify expected labels after inspecting model output. No human review has been conducted for this milestone; scores remain pending.

## Benchmark protocol

Run `runbookos evaluate-v2 --provider configured --provider-config config/evaluation.qwen.example.yml --repeat 3 --output-dir <new-directory>`. This sends only the original synthetic incident/evidence, taxonomy definitions, and selected evidence to the provider; it makes no SSH connection and runs no diagnostic engine action. The first request selects the minimum sufficient diagnostic set; the second returns class ID, root-cause ID, explanation, claims, citations, and optional confidence. Temperature is zero and the same local Qwen/llama.cpp setup and provider bounds are used as v0.2.3. The prompt/schema changed, so any score difference is a protocol/taxonomy comparison, not proof that the model's underlying capabilities improved.

## Live probe status and approvals

The shipped homelab inventory and policy files are examples. Inventory lists addresses for five hosts but contains no `probe_targets`; its policy does not allow the four new probe actions or any endpoint aliases. Therefore a real plan is default-denied. No active operator-specific config was available in this repository audit. Do not edit active policy to make the tests pass.

The opt-in `tests/test_live_probes.py` requires each endpoint's exact approval tuple in `RUNBOOKOS_LIVE_PROBE_APPROVED_<PROTOCOL>` (source alias, endpoint alias, protocol, address, port, path), verifies it against inventory and active policy, uses a separate probe SQLite database, caps each action at 10 seconds, and records evidence/audit history. It also requires a read-only source-service postflight. It is skipped by default. It has not been run against the homelab.
