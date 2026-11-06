# RunbookOS Minimal Semantic Reply v2 — Live Pilot 4

**Verdict: `MINIMAL_REPLY_LIVE_PASS`**

One authorized local run processed the six fixed synthetic cases in order. The
model server used the approved Qwen 3.5 9B Q5_K_M artifact and canonical
llama.cpp runtime. No SSH, tunnel, managed VM, real diagnostic execution,
remediation, or operational database was used. No raw provider response or
credential was retained in this report.

## Per-case results

| Case | Selection | Catalog valid | Exact match | Assessment JSON / schema | Conversion and validator | Result |
| --- | --- | --- | --- | --- | --- | --- |
| `web-normal-01` | `[]` | PASS | FAIL | valid / valid | PASS | `assessed`; `healthy`, suspected, confidence 1.00; 1 valid evidence ref |
| `app-failure-01` | `application_health` | PASS | PASS | valid / valid | PASS | `assessed`; `service_failure`, suspected, 0.85; 1 valid ref |
| `network-ambiguous-01` | `network_health` | PASS | PASS | valid / invalid | REJECTED | `assessment_schema_invalid`; safe validator location `reason`, error type `value_error`; selection retained |
| `insufficient-empty-02` | `[]` | PASS | PASS | valid / valid | PASS | `abstained`; `unknown`/undetermined, 0.00; no evidence refs |
| `web-observation-only-01` | `web_health` | PASS | PASS | valid / valid | PASS | `assessed`; `service_failure`, suspected, 0.60; 1 valid ref |
| `db-failure-01` | `database_health` | PASS | PASS | valid / valid | PASS | `assessed`; `connectivity_failure`, suspected, 0.95; 1 valid ref |

“JSON valid” means the response parsed as JSON. The network case passed JSON
parsing but failed the strict v2 reply validation at `reason`; its raw reason
is not available, so the specific guard that rejected it cannot be determined.
No output was repaired, retried, or counted as abstention after rejection.

## Metrics (six-case denominator)

- Diagnostic selection: catalog-valid **6/6**; exact match **5/6 (83.3%)**.
  Micro precision **1.00**, recall **0.80**, F1 **0.889**. Macro per-case
  precision **1.00**, recall **0.80**, F1 **0.80**. `web-normal-01` returned an
  empty selection and was the sole exact-match miss.
- Assessment JSON syntax: **6/6**. Minimal reply schema and
  StructuredAssessment conversion/validation: **5/6 (83.3%)**.
- Accepted outcomes: **4 non-abstained assessments**, **1 valid explicit
  abstention**, **1 rejected assessment**. The rejected network assessment is
  missing, not an abstention.
- Classification accuracy among the four non-abstained cases: **3/4 (75%)**;
  `web-observation-only-01` was classified `service_failure` where the fixture
  expects abstention/unknown. Evaluator accuracy over its five scored
  assessments, including the valid `unknown` prediction, is **4/5 (80%)**.
- Abstention precision **1.00**, recall **0.50**: among the two gold abstention
  cases with accepted assessments, one abstained and one did not. The rejected
  assessment is excluded from this denominator.
- The four scored non-abstained confidence values produce Brier **0.0963** and
  ECE **0.20** in the existing evaluator. These four synthetic examples are
  too few to establish calibration; confidence is not a calibrated probability.
- Evidence aliases: all references in the **five accepted assessments** passed
  the case-local alias resolver; no forged reference was accepted. Evaluator
  evidence-reference *selection* exact match is **5/6 (83.3%)**, a different
  metric from reference validity.
- Semantic support/root-cause correctness: **NOT MEASURED**. The evaluation
  artifact has 10 claims, zero independently adjudicated (coverage 0%); valid
  references do not establish support.

## Requests and latency

Exactly **12** serial requests were made: six selection and six assessment;
no retries or timeouts. Completion tokens were 314 total for selection and 574
for assessment. Per-case request latency in seconds, with completion tokens in
parentheses:

| Case | Selection | Assessment |
| --- | ---: | ---: |
| `web-normal-01` | 17.242 (54) | 24.989 (93) |
| `app-failure-01` | 12.505 (52) | 21.125 (102) |
| `network-ambiguous-01` | 12.096 (49) | 23.263 (108) |
| `insufficient-empty-02` | 9.867 (42) | 13.156 (62) |
| `web-observation-only-01` | 13.543 (60) | 19.535 (99) |
| `db-failure-01` | 12.960 (57) | 21.967 (110) |

## Resource, persistence, and cleanup

- Prelaunch `MemAvailable` passed the 16 GiB minimum; first monitor sample was
  20.94 GiB.
- ResourceWatch: **PASS**, 411 samples at 0.5-second intervals; peak main
  server RSS **7.14 GiB**, minimum `MemAvailable` **14.19 GiB**. Limits were
  10 GiB RSS and 6 GiB available memory. Measurement covered the main server
  PID, not descendants, and was not a kernel-enforced memory cap.
- Listener was verified as `127.0.0.1`; after cleanup no `llama-server` process
  remained and port `18080` had no listener. Server exit code: **0**.
- Synthetic SQLite: `integrity_check=ok`, zero foreign-key violations.
  Audit-chain verification: **valid**, zero events (the pre-provided M3
  observations require no RunbookOS execution or audit mutation).
- Output parent and generated acceptance tree are owner-only (`0700`); result,
  prediction, and checksum files are `0600`. The synthetic database and
  sanitized outputs remain outside the repository at:
  `/tmp/runbookos-qwen-pilot4-qbizyinc/runbookos-ai-v060-rerun-4jv08pmz/`.

## Pilot comparison and decision

| Pilot | Selection valid | Selection exact | Accepted assessment |
| --- | ---: | ---: | ---: |
| Pilot 3 — nested output contract | 6/6 | 5/6 | 2/6 |
| Pilot 4 — minimal semantic reply v2 | 6/6 | 5/6 | 5/6 |

Pilot 4 improved accepted assessments from 2/6 to 5/6 while preserving the
selection result. One reply was rejected by the reason validator. The
engineering acceptance targets are met: selection valid 6/6, accepted
assessments at least 5/6, at least one non-abstained assessment, no forged
reference accepted, and no silent repair. The separate `web-normal-01`
selection mismatch and observation-only overclassification remain observed
quality limitations. This six-case synthetic pilot does not establish
production diagnostic accuracy, semantic support, calibration, or readiness for
the full benchmark.

## Reproducibility identities

```text
branch: feat/v0.7.0-evidence-aware-assessment
HEAD: d68197c3ac37336e1b9bfa8d66059e5eb8ecd001
adapter SHA-256: f6e1d1167a064a49348c8dd858be9013a411dd30bcebcfc789a16cdacd7ce121
adapter-tests SHA-256: c32e258e0def35e28ee30739ee5d57df6eb7408c1e085157ad73936c37886637
model SHA-256: dc2a39aef291f91a9116ad214058da0d86eb648743a124bd8c333787c4b9c91c
llama-server SHA-256: 98a8581124ccf8ba775a89e1899c895b2d4a2053b9830f8b044fe69b928c02ac
prediction SHA-256: e0fe82074df52a61a506047f9e2358be4f26f70634c26e38138543e1c845a411
```

Pilot 1–3 artifacts and unrelated working-tree changes were left untouched. No
Git staging or commit was performed.
