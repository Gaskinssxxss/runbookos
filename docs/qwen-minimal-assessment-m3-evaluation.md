# RunbookOS — Full M3 Diagnostic Evaluation

**Verdict: `M3_FULL_EVALUATION_COMPLETE`** (exploratory synthetic benchmark; evaluator status `PARTIAL`).

## Scope and outcome

- Dataset `m3-1.0`: exactly 24 held-out synthetic cases, unchanged fixture and gold labels.
- Physical host only; authenticated loopback endpoint `127.0.0.1:18080`; Qwen 3.5 9B Q5_K_M and the approved canonical llama-server.
- Source branch/HEAD: `feat/v0.7.0-evidence-aware-assessment` / `d68197c3ac37336e1b9bfa8d66059e5eb8ecd001`. Adapter SHA-256: `f6e1d1167a064a49348c8dd858be9013a411dd30bcebcfc789a16cdacd7ce121`.
- Model SHA-256: `dc2a39aef291f91a9116ad214058da0d86eb648743a124bd8c333787c4b9c91c`; llama-server SHA-256: `98a8581124ccf8ba775a89e1899c895b2d4a2053b9830f8b044fe69b928c02ac`.
- **47/48** maximum serial requests: 24 selection attempts and 23 assessment attempts; no retries. One failed selection correctly prevented the second-stage request.
- Prediction submission contains 24 case records. Evaluator accepted 23 selection predictions; one case had no usable selection prediction. Assessments: **21 accepted**, **2 rejected**, and **1 absent because selection parsing failed**.
- No SSH, tunnel, managed VM, real diagnostic execution, remediation, deployment, or operational database access occurred.

## Case results

`Exact` is selection set match against the fixed gold. Parse/schema is shown as JSON syntax/schema. `∅` denotes an empty selection. Stage figures are latency/completion tokens.

| Case | Diagnostic IDs | Selection | Exact | Assessment JSON/schema | Assessment result | Classification (model confidence) | Selection; assessment latency/tokens |
|---|---|---|---:|---|---|---|---|
| `web-normal-01` | ∅ | JSON/catalog valid | no | valid/valid | assessed | healthy (1.00) | 19.07s/54t; 27.99s/93t |
| `web-failure-01` | web_health | JSON/catalog valid | yes | valid/valid | assessed | service_failure (0.90) | 13.26s/52t; 21.18s/96t |
| `web-failure-02` | web_health | JSON/catalog valid | yes | valid/valid | assessed | service_failure (0.95) | 13.38s/56t; 21.74s/101t |
| `web-conflict-01` | web_health | JSON/catalog valid | yes | valid/valid | abstained | unknown (0.00) | 21.24s/93t; 26.17s/122t |
| `web-ambiguous-01` | ∅ | JSON/catalog valid | no | valid/valid | abstained | unknown (0.10) | 14.04s/59t; 20.96s/101t |
| `app-normal-01` | ∅ | JSON/catalog valid | no | valid/valid | assessed | healthy (0.95) | 11.15s/45t; 15.36s/66t |
| `app-failure-01` | application_health | JSON/catalog valid | yes | valid/valid | assessed | service_failure (0.85) | 13.15s/52t; 20.98s/102t |
| `app-failure-02` | application_health | JSON/catalog valid | yes | valid/valid | assessed | service_failure (0.90) | 12.90s/55t; 12.41s/52t |
| `app-ambiguous-01` | application_health | JSON/catalog valid | yes | valid/valid | abstained | unknown (0.10) | 11.75s/45t; 22.25s/112t |
| `db-normal-01` | ∅ | JSON/catalog valid | no | valid/valid | assessed | healthy (1.00) | 11.40s/47t; 12.11s/51t |
| `db-failure-01` | database_health | JSON/catalog valid | yes | valid/valid | assessed | connectivity_failure (0.95) | 14.19s/57t; 22.52s/110t |
| `db-failure-02` | database_health | JSON/catalog valid | yes | valid/valid | assessed | service_failure (0.90) | 13.05s/56t; 23.39s/110t |
| `db-conflict-01` | database_health | JSON/catalog valid | yes | valid/valid | abstained | unknown (0.50) | 17.99s/74t; 18.95s/79t |
| `network-normal-01` | ∅ | JSON/catalog valid | no | valid/valid | assessed | healthy (0.95) | 12.72s/48t; 20.12s/97t |
| `network-failure-01` | network_health | JSON/catalog valid | yes | valid/valid | assessed | network_failure (0.95) | 11.96s/48t; 21.86s/107t |
| `network-failure-02` | network_health | JSON/catalog valid | yes | valid/valid | assessed | connectivity_failure (0.95) | 11.26s/42t; 20.90s/99t |
| `network-ambiguous-01` | network_health | JSON/catalog valid | yes | valid/invalid | assessment_schema_invalid | — | 12.74s/49t; 22.86s/108t |
| `insufficient-empty-01` | ∅ | JSON/catalog valid | yes | valid/valid | abstained | unknown (0.00) | 9.17s/34t; 16.80s/78t |
| `insufficient-empty-02` | ∅ | JSON/catalog valid | yes | valid/valid | abstained | unknown (0.00) | 10.19s/42t; 13.81s/62t |
| `insufficient-ambiguous-01` | ∅ | JSON/catalog valid | yes | valid/invalid | assessment_schema_invalid | — | 10.41s/41t; 17.73s/85t |
| `insufficient-conflict-01` | ∅ | JSON/catalog valid | yes | valid/valid | abstained | unknown (0.00) | 15.92s/66t; 23.73s/110t |
| `insufficient-causal-01` | application_health | JSON/catalog valid | yes | valid/valid | abstained | unknown (0.00) | 18.64s/82t; 23.24s/114t |
| `web-observation-only-01` | web_health | JSON/catalog valid | yes | valid/valid | assessed | service_failure (0.60) | 14.29s/60t; 20.98s/99t |
| `db-observation-only-01` | ∅ | truncated_or_incomplete_json_suspected | — | not requested | truncated_or_incomplete_json_suspected | — | 12.60s/47t; — |

## Aggregate metrics

- **Diagnostic selection:** JSON and catalog validation **23/24 (95.8%)**; zero unknown IDs among parsed selections. Exact match **18/23 (78.3%)** over usable selections; including the single missing prediction as not exact gives **18/24 (75.0%)**. Micro precision **1.000**, recall **0.737**, F1 **0.848**; macro per-case precision **1.000**, recall **0.737**, F1 **0.737**.
- **Assessment contract:** assessment JSON syntax **23/23**; v2 reply schema plus conversion/unchanged StructuredAssessment validation **21/23 (91.3%)**. Accepted assessment rate over all cases **21/24 (87.5%)**. Failures were not repaired.
- **Coverage:** 13 accepted, non-abstained classifications / 24 cases = **54.2%** overall coverage. Among the evaluator's 19 scored labeled cases, classification coverage was **13/19 (68.4%)**. The other accepted assessments include valid abstentions; three cases have no accepted assessment.
- **Classification:** exact accuracy on accepted answered, labeled cases **11/13 (84.6%)**. Evaluator exact accuracy including valid `unknown` abstentions was **17/19 (89.5%)**. These are separate denominators. The evaluator's macro F1 over defined classes was **0.905**.
- **Abstention:** on accepted assessment cases only, precision **1.000**, recall **0.889 (8/9)**, false-abstention rate **0**, missed abstentions **1**. Missing assessments are excluded, not counted as abstentions.
- **Evidence references:** all references in the **21 accepted assessments** resolved to issued case-local aliases; no forged reference was accepted. Evidence-reference selection exact match was **22/23 (95.7%)** (micro P **1.000**, R **0.957**, F1 **0.978**). Selection accuracy is not reference validity and neither establishes semantic support.
- **Confidence:** descriptive Brier **0.0944**, ECE **0.0885**, based on 13 non-abstained labeled predictions. This small synthetic set does not establish calibration; retain confidence as model-reported only.
- **Semantic support and root-cause correctness:** **NOT MEASURED**; 0/42 claims were independently adjudicated. Citations alone are not semantic validation.

## Failures and latency/token usage

- `network-ambiguous-01`, `insufficient-ambiguous-01`: `assessment_schema_invalid`, sanitized validator location `reason`, error type `value_error`. Raw responses were not retained, so the specific reason guard that rejected them cannot be determined.
- `db-observation-only-01`: selection parser category `truncated_or_incomplete_json_suspected`; this is a parser classification, not confirmation of why the JSON was incomplete. No assessment request followed.
- No provider timeouts, catalog-invalid IDs, forged evidence references accepted, retry, or automatic repair.
- Selection: 24 requests, 1304 completion tokens total; latency mean/median/max 13.60/12.97/21.24s; completion-token range 34–93.
- Assessment: 23 requests, 2154 completion tokens total; latency mean/median/max 20.35/20.98/27.99s; completion-token range 51–122.

## Resource and cleanup

- ResourceWatch **PASS**: 1591 samples, 0.5s polling, nominal maximum detection delay 0.5s. Peak main-server RSS **7.14 GiB**; minimum `MemAvailable` **19.64 GiB**. Startup preflight met the 16 GiB requirement; in-run minimum exceeded 6 GiB and peak RSS stayed below 10 GiB.
- Monitor boundary: main llama-server PID only; descendants are not aggregated. This is not a kernel-enforced memory limit.
- Server exit code **0**; no acceptance-owned server remained and port `18080` was released. Listener during run was loopback only.
- Synthetic SQLite `integrity_check=ok`, **0** foreign-key violations. Audit chain valid with **0 events**; no diagnostic execution or audit mutation was performed.
- Owner-only result directory: `/tmp/runbookos-qwen-m3-full-avb5invg/runbookos-ai-v060-rerun-nx32zv86/`; prediction artifact SHA-256 `5c2dff21b165da1e6b41a003785998465c0f3a9e6688d212e4c472bf5c31072d`. Evaluation report SHA-256 `4b5c09dc4d89d6aa9b53dd11a2838e89a852c8cc97f66e802025f6e1e3c62c82`. Both artifacts remain outside the repository with owner-only permissions; prior pilot artifacts were preserved.

## Recommendation

Treat this as one exploratory full-set evaluation, not production certification. The v2 reply contract was accepted for 21 cases, but three cases lacked accepted assessments and the benchmark still contains selection errors and a non-abstained classification where abstention was expected. Keep semantic support and root-cause correctness unverified; do not infer service or production readiness from these synthetic results.
