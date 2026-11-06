# RunbookOS v0.6.0 Local Qwen Acceptance — Offline Reliability Addendum

**Date:** 2026-10-21
**Historical report:** `ai-local-inference-acceptance-v0.6.0.md` (preserved unchanged)
**Scope:** Offline evidence review, test-only harness instrumentation, and procfs resource-monitor tests. No model, tunnel, SSH, or managed VM was contacted.

## Historical evidence review

The original acceptance summary and SQLite database were inspected without mutation. SQLite was opened with `mode=ro&immutable=1`; `integrity_check` returned `ok`, `foreign_key_check` returned no rows, and the database contains two investigations, two executions, two step results, and ten audit events. Both stored investigations are `partial`, selected `database_health` and `network_health`, and contain one failed step each with zero verified evidence items. The three rejected cases have no investigation records.

The saved summary records the three scenario IDs (`nginx-unavailable`, `fastapi-service-failure`, `insufficient-evidence`), one provider request for each, `PolicyDenied`, zero fake executor calls, and no persisted investigation. It does **not** retain their model response, selected diagnostic IDs, detailed stage, or denial reason. Consequently, the actual rejection point for each case remains unknown. No output or cause was reconstructed from the two unrelated persisted investigations.

| Scenario | Historical facts retained | Historical stage / model selection | Offline candidate analysis |
|---|---|---|---|
| `nginx-unavailable` | One provider request; `PolicyDenied`; executor not called; no investigation persisted | Unknown; response/IDs were not retained | An unsupported returned ID is rejected during catalog selection validation. Separately, a catalogued `web_health` selection can reach the planner and be denied if the isolated test policy denies that action. Both paths are reproduced offline; neither is attributed to the historical event. |
| `fastapi-service-failure` | One provider request; `PolicyDenied`; executor not called; no investigation persisted | Unknown; response/IDs were not retained | Same two candidate boundaries as above, using the catalogued application diagnostic for the plan-denial mock. No historical cause is inferred. |
| `insufficient-evidence` | One provider request; `PolicyDenied`; executor not called; no investigation persisted | Unknown; response/IDs were not retained | Empty diagnostic selection is accepted by the v0.6.0 investigator and proceeds to analysis; offline test confirms it creates a `no_diagnostics` investigation. Thus empty selection alone is not a `PolicyDenied` cause. The historical model output is unavailable, so the actual cause remains unknown. |

Offline mocks also confirm that invalid structured selection and unsupported catalog IDs fail closed before executor invocation, and that a denied deterministic plan does not execute or persist an investigation. These are candidate reproductions, not proof of what the live model returned.

## Harness changes

The test-only runner now emits per-case, sanitized diagnostics: stage, per-case provider request count, identifier-shaped returned diagnostic IDs when parseable, catalog validation, plan/policy outcomes, exception type, allowlisted reason category, executor invocation, evidence validation, and persistence. It does not retain raw prompts, model response text, rationale, secrets, or exception messages. The original live summary remains unchanged.

The corrected RSS parser reads the `VmRSS` field from `/proc/<llama-server-pid>/status`, accepts only one positive integer in kB, and converts it to bytes. The monitor verifies that the measured PID's `/proc/<pid>/exe` resolves to the expected llama-server executable. It reads `MemAvailable` from procfs, requires at least 16 GiB before launch, and stops the acceptance-owned `Popen` server process on missing/untrusted measurements, RSS above 10 GiB, or available memory below 6 GiB. Termination is bounded and escalates only against that owned process handle.

The previous zero measurement came from an over-escaped `VmRSS` regular expression in the temporary inline runner, outside the repository test harness; the temporary script itself was not retained. The historical report documents the defect and zero result. The replacement parser is `r"^VmRSS:\s+(\d+)\s+kB\s*$"` in `tests/ai_acceptance_harness_v060.py`.

**Measurement boundary:** RSS covers the llama-server process leader, not a sum of descendants. The current llama-server acceptance invocation owns the model/runtime process; a future runtime that delegates substantial model memory to child processes must extend the monitor to aggregate or otherwise account for those children before acceptance. This is a measurement boundary, not a hard host memory cap.

## Evidence semantics

The two historical diagnostic executions returned observed data, but the runbook assertions failed. Their persisted execution and step statuses are `failed`; `verified_evidence` is empty. The stored citations refer to evidence references that exist, so citation integrity passed for those five references. Citation validity does not establish semantic support, and the failed assertion is not relabeled as verified. The PostgreSQL causal statements noted in the original report remain unsupported hypotheses; the network result is limited to the fake empty-route observation.

## Offline verification

- Targeted acceptance harness and existing AI tests: **29 passed**.
- Full offline suite: **161 passed, 11 skipped**. Skips are opt-in live AI, SSH, probe, and tunnel tests; none were enabled.
- Resource parser tests cover realistic procfs text, missing/malformed/zero RSS, missing/malformed `MemAvailable`, exact thresholds, RSS and memory threshold violations, process identity mismatch, and stopping only the injected acceptance-owned process handle.
- Harness tests cover sanitized `PolicyDenied` reporting, executor non-invocation for denied selections/plans, valid empty-selection abstention, and fake-executor isolation.
- Ruff lint on changed Python files: **passed**.
- Ruff format check on changed Python files: **passed** after formatting.
- `git diff --check`: **passed**.
- Approval manifest still reads `authorization_status: NOT_AUTHORIZED`.

No live inference, llama-server process, SSH tunnel, network probe, managed VM access, or remediation was performed for this addendum.

## Future rerun criteria

A future live run requires separate explicit operator authorization. Before any model request, the runner must use the corrected monitor against the acceptance-owned llama-server PID, verify its executable identity, pass the 16 GiB pre-launch check, and fail closed if procfs measurements become unavailable or malformed. Keep the existing five synthetic cases, request maximum of ten, serial execution, 120-second timeout, and zero retries. Preserve failed assertion statuses and report diagnostic-selection, citation integrity, evidence verification, and semantic quality separately. Do not change expected labels or policy to improve scores.

## Changed-file allowlist for this offline fix

- `tests/ai_acceptance_harness_v060.py`
- `tests/test_ai_acceptance_harness_v060.py`
- `docs/ai-local-inference-addendum-v0.6.0.md`

No files were staged or committed. The historical live acceptance report, approval manifest, prior evidence, unrelated modified file, and unrelated historical untracked report were left untouched.
