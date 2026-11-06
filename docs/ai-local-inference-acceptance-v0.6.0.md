# RunbookOS v0.6.0 — Local Qwen Inference Acceptance

**Date:** 2026-10-21  
**Repository baseline:** `c080a37c24a6d3ae09356e68d7c5cc249db6e69f`  
**Scope:** Physical Ubuntu host only; synthetic fixtures and fake read-only executor.

## Summary

The local Qwen provider authenticated and returned seven responses across five synthetic scenarios. Two investigations completed and were persisted; three were rejected with `PolicyDenied` before the fake executor ran. No model request was retried. SQLite integrity, foreign keys, and the audit chain passed.

This is **partial acceptance**. The model selected the expected diagnostic in the two completed cases, but both produced only failed synthetic diagnostic evidence, not verified evidence. Several PostgreSQL causal explanations went beyond that evidence. The RSS monitor in the temporary runner was defective and reported zero, so resource safety cannot be certified even though the available-memory guard remained above its stop threshold.

## Immutable inputs and runtime

| Item | Observed |
|---|---|
| Model | Qwen 3.5 9B Instruct Q5_K_M; `qwen3.5-9b-instruct-q5_k_m.gguf` |
| Model SHA-256 | `dc2a39aef291f91a9116ad214058da0d86eb648743a124bd8c333787c4b9c91c` — matched |
| Runtime | llama.cpp `0.6.0-dev` (build 11479, commit `42c787e8c`) |
| Runtime SHA-256 | `98a8581124ccf8ba775a89e1899c895b2d4a2053b9830f8b044fe69b928c02ac` — matched |
| Listener | `127.0.0.1:8080` only; `/health` became ready after three checks |
| API key | Existing protected file, owner `morphious`, mode `0600`; value was not printed, copied, or logged |

The development `.venv` supplies Python 3.12.3 and runtime dependencies. Its installed distribution metadata without the source path reports an older version; the acceptance explicitly imported the checked-out RunbookOS source, which reports v0.6.0. No environment was installed or changed.

## Scope and safety controls

- The real `IncidentInvestigator`, RunbookOS planning/validation, and OpenAI-compatible provider were used.
- The test-only `SyntheticReadOnlyExecutor` was fixed to `synthetic-acceptance.invalid` / `192.0.2.54` and the three registered read-only action IDs. The harness patched SSH adapter construction to fail if reached.
- No production CLI executor override, SSH adapter, tunnel, managed VM, mutable action, or operational SQLite database was used.
- The harness ran five synthetic cases serially. It made seven actual provider HTTP attempts (below the limit of ten), with a 120-second configured timeout and no retries.
- The adversarial pre-provider guard was exercised offline by the harness regression suite: **8 tests passed**, including the test asserting zero provider and executor calls for the adversarial case.
- The host had 22,149,263,360 bytes of `MemAvailable` before launch. The monitor observed a minimum of 20,474,269,696 bytes during the run, above the 6 GiB stop threshold.

## Scenario results

| Scenario | Provider requests | Outcome | Diagnostic/evidence result |
|---|---:|---|---|
| `nginx-unavailable` | 1 | Rejected with `PolicyDenied`; no fake action and no persisted investigation | Selection/plan rejection stage was not retained by the harness, so the exact denial reason is unavailable. |
| `fastapi-service-failure` | 1 | Rejected with `PolicyDenied`; no fake action and no persisted investigation | Exact denial reason unavailable for the same reason. |
| `postgresql-protocol-failure` | 2 | Investigation completed; one fake action | Selected `database_health` exactly. Three citations referred to the produced evidence; zero evidence items had a successful verification status. |
| `network-connectivity-failure` | 2 | Investigation completed; one fake action | Selected `network_health` exactly. Two citations referred to the produced evidence; zero evidence items had a successful verification status. |
| `insufficient-evidence` | 1 | Rejected with `PolicyDenied`; no fake action and no persisted investigation | Exact denial reason unavailable. |

There were **7 requests total**, **2 completed investigations**, **3 rejected cases**, **2 fake executions**, **2 step-result records**, and **10 audit events**. No classification or root-cause accuracy score is reported: those structured fields are not part of the v0.6.0 investigator output.

## Output and evidence review

All five citations in the two persisted investigations resolved to evidence references actually produced by the fake executor. No fabricated evidence reference was accepted. Citation validity establishes reference integrity only; it does not prove the cited evidence supports a claim.

The PostgreSQL evidence recorded protocol availability as false, SSL support as false, authentication not attempted, and database readiness not verified. The model correctly described protocol unavailability, but additionally suggested that the service was down or misconfigured, that a configuration issue prevented connection initiation, or that there was a protocol mismatch/server-side SSL disablement. Those causal explanations were **not established by the fixture evidence** and should remain unverified hypotheses. The evidence did not report a verified action result.

The network fixture returned an empty route list. Its two cited statements—that the route table was empty and the diagnostic found no routes—matched the synthetic observation. The step assertion failed because the fixture intentionally expected a non-empty route list; these citations refer to real synthetic step evidence, not verified live network state.

For the three rejected cases, no investigation record or executor action was created. Because the harness retained only the exception type, it cannot distinguish invalid model selection from another `PolicyDenied` condition. This limits diagnosis of those failures.

## Latency and token usage

Seven provider response latencies, in seconds: **29.938, 19.483, 17.509, 51.020, 17.411, 33.625, 20.327**. Total: **189.313 s**; median: **20.327 s**. Reported usage totaled **2,234 prompt**, **814 completion**, and **3,048 combined tokens**. These measurements describe synthetic inference only.

## Persistence, audit, and cleanup

- SQLite `integrity_check`: `ok`.
- Foreign-key errors: **0**.
- Audit hash chain: **valid**, 10 events.
- Investigations/executions/step results: **2 / 2 / 2**.
- The temporary llama-server exited with status **0**. After cleanup, no `llama-server` process and no listener on port 8080 remained.
- Temporary synthetic config and runbooks were removed. No temporary credential file was created; the existing API key was read into the runner process environment and disappeared when it exited.
- The sanitized summary and synthetic SQLite evidence were retained under `/tmp/runbookos-ai-local-v060-egf_c2wv/`, with directories mode `0700` and files mode `0600`. This database contains synthetic investigation records only.
- No SSH, tunnel, managed-VM, firewall, route, service, or infrastructure change occurred. The tunnel approval manifest remains `NOT_AUTHORIZED`.

## Resource-monitor defect

The temporary runner's `/proc/<pid>/status` RSS parser used an incorrectly escaped regular expression and recorded `peak_rss_bytes=0`. Therefore the required 10 GiB RSS stop guard was **not effectively verified or enforced** during this run. The available-memory guard worked and stayed above 6 GiB, but it does not replace an RSS limit. This report does not claim local resource safety passed. Do not repeat inference under this acceptance; a corrected RSS monitor and a separately authorized acceptance run are required for a resource-safety verdict.

## Verdicts

- **Local Qwen provider connectivity:** PASS — authenticated local provider returned seven responses.
- **Live structured inference:** FAIL — only two of five scenarios completed; three were rejected by policy validation.
- **Diagnostic selection:** PARTIAL — exact expected selection in both completed cases; no successful selection result for the other three.
- **Evidence citation validity:** PASS for the five persisted citations; **zero** cited items were successful verification evidence, and citation integrity is not semantic support.
- **Local resource safety:** FAIL / NOT VERIFIED — available-memory threshold held, but RSS guard measurement was defective.
- **ops-01 tunnel integration:** NOT RUN.
- **Live SSH remediation:** NOT RUN.
- **Operational deployment:** NOT AUTHORIZED.

## Follow-up

Fix and test the RSS monitor in the test-only acceptance runner, and improve per-case rejection-stage recording without retaining raw model responses unnecessarily. Any repeat inference run requires a new explicit authorization and a corrected resource guard. Do not change the model, fixture ground truth, or expected labels to improve scores.
