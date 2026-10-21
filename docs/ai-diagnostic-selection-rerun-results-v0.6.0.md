# RunbookOS v0.6.0 — Corrected Diagnostic Selection Rerun Results

**Overall: PASS for this bounded synthetic acceptance.** The five configured
synthetic scenarios completed with exact diagnostic selections, including a
valid empty selection for insufficient evidence. This is not a measure of
accuracy on production incidents.

## Scope and preflight

- Repository HEAD: `c080a37c24a6d3ae09356e68d7c5cc249db6e69f` on
  `feat/v0.6.0-incident-remediation-workflow`.
- Imported RunbookOS source: repository `src/runbookos`, version `0.6.0`.
- Model: Qwen 3.5 9B Q5_K_M; SHA-256 matched
  `dc2a39aef291f91a9116ad214058da0d86eb648743a124bd8c333787c4b9c91c`.
- Runtime: canonical `llama-server`; SHA-256 matched
  `98a8581124ccf8ba775a89e1899c895b2d4a2053b9830f8b044fe69b928c02ac`.
- API-key file was verified as an owner-only regular file (`0600`). Its value
  was not recorded or printed.
- Listener was authenticated and verified on `127.0.0.1:18080` only.
- Prelaunch MemAvailable: `19.79 GiB`.
- Five fixed synthetic cases ran serially. There were ten provider calls total,
  no retries, and no call exceeded the 120-second timeout.
- Only the harness's synthetic target and fake read-only executor were used.
  No SSH, tunnel, managed VM, remediation, or external model endpoint was used.

## Scenario results

| Scenario | Investigation | Selected diagnostic | Selection | Catalog / plan policy | Executor | Evidence and citations |
|---|---|---|---|---|---:|---|
| `nginx-unavailable` | Completed | `web_health` | Exact match; 1 ID | Accepted / accepted | 1 action | Citation valid; step assertion `failed`; verified evidence: 0 |
| `fastapi-service-failure` | Completed | `application_health` | Exact match; 1 ID | Accepted / accepted | 1 action | Citation valid; step assertion `failed`; verified evidence: 0 |
| `postgresql-protocol-failure` | Completed | `database_health` | Exact match; 1 ID | Accepted / accepted | 1 action | Citation valid; step assertion `failed`; verified evidence: 0 |
| `network-connectivity-failure` | Completed | `network_health` | Exact match; 1 ID | Accepted / accepted | 1 action | Citation valid; step assertion `failed`; verified evidence: 0 |
| `insufficient-evidence` | Completed | none (`[]`) | Valid abstention; exact match | Accepted; no plan needed | 0 actions | No citations or evidence expected |

Each investigation was persisted. The four synthetic execution IDs were:

- Nginx: `1b7d7cb6-6985-45c3-85f9-175a3f2554a0`
- FastAPI: `6649ceb8-4d34-4fb7-b7f7-82240021edd6`
- PostgreSQL: `3c5cff96-d282-4e65-929e-f9e0375c902d`
- Network: `0151773a-8335-4721-bd3f-1f574de3c7cf`

Across the first four cases, all nine citations referenced evidence records
that existed in the corresponding investigation. Those records have
`failed` step status and zero verified-evidence count. Citation integrity
therefore passed, while diagnostic assertions did not become verified facts.
The run did not score semantic support of causal hypotheses. The v0.6.0
investigator output does not provide structured classification or root-cause
fields, so those metrics remain unscored.

## Comparison with the earlier partial rerun

| Measure | Earlier partial run | Corrected rerun |
|---|---:|---:|
| Completed investigations | 2/5 | 5/5 |
| Exact diagnostic selection / valid abstention | 2/5 | 5/5 |
| Selection-limit rejections | 3 | 0 |
| Provider requests | 7 | 10 |
| Citation validity among completed diagnostic cases | 2/2 | 9/9 citations valid across 4 cases |

This confirms the revised prompt and current model produced compliant
selections in this run. It does not establish that the model will behave
consistently on other prompts, runs, or real incidents. No fixture expectation
or deterministic policy was changed for this rerun.

## Latency and resources

- Provider calls: `10`; average latency `26.550 s`, median `22.575 s`, nearest
  rank p95 `46.236 s`, maximum `46.236 s`.
- Summed per-scenario investigation duration: `265.835 s`.
- ResourceWatch: **PASS**, `536` samples at `0.5 s` polling; nominal maximum
  detection delay `0.5 s`.
- Peak RSS: `7,669,919,744` bytes (`7.143 GiB`), below the 10 GiB stop
  threshold.
- Minimum MemAvailable: `20,185,407,488` bytes (`18.799 GiB`), above the 6
  GiB in-run stop threshold.
- Resource measurements cover the main `llama-server` PID only; descendant
  processes are not aggregated. These are userspace guardrails, not a kernel
  memory limit.

## Persistence and cleanup

- SQLite `integrity_check`: `ok`.
- Foreign-key violations: `0`.
- Persisted records: 5 investigations, 4 plans, 4 executions, 4 step results,
  and 21 audit events.
- Audit hash chain: **valid**.
- Acceptance server exit code: `0`; acceptance-owned PID `103435` was no longer
  running after completion.
- No listener remained on port `18080` after cleanup.
- Sanitized summary and isolated synthetic SQLite were preserved with mode
  `0600` under the mode `0700` acceptance directory:
  - Summary: `acceptance/results/summary.json` under the local temporary
    acceptance directory, outside the repository.
  - SQLite: `acceptance/state/investigation.sqlite3` under that same protected
    temporary directory.
- Generated configuration and synthetic runbook files were removed by the
  harness. No existing acceptance database was reused.

## Verdicts

- Local Qwen provider connectivity/authentication: **PASS**.
- Structured investigation completion: **PASS (5/5 synthetic cases)**.
- Diagnostic selection and selection-limit compliance: **PASS (5/5)**.
- Insufficient-evidence abstention: **PASS**.
- Catalog and policy validation: **PASS** for selected diagnostics.
- Evidence citation integrity: **PASS** for all emitted citations.
- Diagnostic assertions / verified evidence: **FAILED assertions; zero verified
  evidence**. This preserves the synthetic outage observations without
  overstating verification.
- Semantic support of causal hypotheses: **NOT SCORED**.
- Classification and root-cause accuracy: **NOT SCORED by the v0.6.0 schema**.
- Resource monitoring: **PASS** within the stated userspace measurement
  boundary.
- SQLite and audit integrity: **PASS**.
- Process cleanup: **PASS**.
- SSH, tunnel, managed VM diagnostics, remediation: **NOT RUN**.
- Operational deployment: **NOT AUTHORIZED**.

The previous partial report remains unchanged. The tunnel acceptance manifest
remains `NOT_AUTHORIZED`; no commit or push was performed.
