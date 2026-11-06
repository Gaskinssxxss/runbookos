# RunbookOS v0.6.0 — Local Qwen Inference Rerun Results

**Overall: PARTIAL.** The local provider and resource guard operated, but only
two of five scenarios completed investigation. Three were rejected during
diagnostic selection validation. No live infrastructure was accessed.

The earlier partial acceptance report and the separate readiness report were
preserved. This document records the new run only.

## Scope and preflight

- Repository HEAD: `c080a37c24a6d3ae09356e68d7c5cc249db6e69f`.
- RunbookOS source: `0.6.0`.
- Model: Qwen 3.5 9B Q5_K_M; SHA-256 matched the approved value.
- llama-server: canonical regular executable; SHA-256 matched the approved value.
- Listener: verified on `127.0.0.1:8080` only.
- Provider authentication: local authenticated `/v1/models` readiness succeeded.
- API key: read from the protected file for the run; never printed or included in the report.
- Prelaunch MemAvailable: `19.77 GiB`.
- No SSH, tunnel, managed VM, remediation, or external model endpoint was used.

## Scenario results

| Scenario | Result | Selection / rejection | Calls | Executor | Evidence |
|---|---|---|---:|---:|---|
| `nginx-unavailable` | Rejected | Selection validation rejected with `diagnostic_selection_limit`; safely parsed IDs: `web_health`, `application_health`, `network_health` | 1 | 0 | Not reached |
| `fastapi-service-failure` | Rejected | Selection validation rejected with `diagnostic_selection_limit`; returned IDs were not safely parseable and are not reported | 1 | 0 | Not reached |
| `postgresql-protocol-failure` | Completed | Selected `database_health`; catalog and plan/policy validation accepted | 2 | 1 | Citation references valid; diagnostic assertion status `failed`; verified evidence count 0 |
| `network-connectivity-failure` | Completed | Selected `network_health`; catalog and plan/policy validation accepted | 2 | 1 | Citation references valid; diagnostic assertion status `failed`; verified evidence count 0 |
| `insufficient-evidence` | Rejected | Selection validation rejected with `diagnostic_selection_limit`; safely parsed IDs: all four catalog diagnostics | 1 | 0 | Not reached; model did not abstain |

The two persisted diagnostic execution IDs were:

- PostgreSQL synthetic diagnostic: `50c59fb0-fb0b-4fc7-ab0e-1ead76eac6ae`
- Network synthetic diagnostic: `257c1d6e-511a-4c86-be1d-24c97571d5ca`

The three rejected scenarios did not invoke the executor or persist an
investigation. No policy was relaxed and no fixture or expected label was
changed. The FastAPI model selection was not retained as safely parseable
diagnostic IDs; the recorded deterministic rejection stage/category is
`catalog_selection_validation` / `diagnostic_selection_limit`.

## Evaluation

- **Provider connectivity:** PASS — seven authenticated provider requests returned; no request was retried.
- **Structured investigation completion:** PARTIAL — 2/5 investigations completed; 3/5 were rejected before execution.
- **Diagnostic selection:** PARTIAL — two completed selections exactly matched their expected single diagnostic. Nginx and insufficient-evidence selections exceeded the allowed selection count; FastAPI was rejected at selection validation.
- **Evidence citation integrity:** PASS for completed cases, 2/2; rejected cases never reached evidence analysis.
- **Evidence semantic support:** Not scored automatically. Both completed diagnostic steps have status `failed` and verified evidence count is zero. Their citations are valid references to those observations; this does not establish verified recovery or independent root-cause correctness.
- **Classification/root-cause accuracy:** Not scored by the v0.6.0 investigator schema.
- **Automatic retries:** None.

Provider call latency by scenario, in seconds:

- Nginx: `29.259`
- FastAPI: `20.320`
- PostgreSQL: `18.278`, `53.749`
- Network: `17.640`, `33.802`
- Insufficient evidence: `20.266`

The orchestrator’s monitored run duration was approximately `195.756` seconds.

## Resource, persistence, and cleanup

- Resource monitor: **PASS**, 392 samples at 0.5-second polling.
- Peak main-server RSS: `8,180,297,728` bytes (about `7.62 GiB`), below the 10 GiB stop threshold.
- Minimum MemAvailable: `20,015,472,640` bytes (about `18.64 GiB`), above the 6 GiB stop threshold.
- Measurement boundary: main llama-server PID only; descendant RSS was not aggregated. This is a userspace guard, not a kernel memory limit.
- SQLite `integrity_check`: `ok`; foreign-key violations: `0`.
- Persisted counts: 2 investigations, 2 executions, 10 audit events.
- Audit hash chain: valid.
- Server exit code: `0`; no `llama-server` process remained.
- No listener remained on port 8080; the port could be rebound after a short TCP `TIME_WAIT` period.
- Generated configuration and runbook files were removed. The sanitized summary and synthetic database were preserved with mode `0600` under a mode `0700` acceptance directory:
  - Summary: `/tmp/runbookos-ai-v060-rerun-0l96_v0g/acceptance/results/summary.json`
  - SQLite: `/tmp/runbookos-ai-v060-rerun-0l96_v0g/acceptance/state/investigation.sqlite3`

## Final verdicts

- Local Qwen provider connectivity: **PASS**.
- Live structured inference: **PARTIAL**.
- Diagnostic selection: **PARTIAL**.
- Evidence citation validity: **PASS for the two completed investigations**.
- Resource safety: **PASS for the monitored main process during this run**.
- Process cleanup and evidence persistence: **PASS**.
- SSH, tunnel, managed VM diagnostics, remediation: **NOT RUN**.
- Operational deployment: **NOT AUTHORIZED**.

The result demonstrates that the provider works and that policy rejected
over-selection before execution. It does not demonstrate complete scenario
coverage or production incident accuracy. The tunnel approval manifest remains
`NOT_AUTHORIZED`; no Git commit or push was performed.
