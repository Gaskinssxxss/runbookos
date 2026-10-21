# RunbookOS v0.6.0 — Isolated Full-Workflow Acceptance

## Verdict

Offline synthetic full-workflow acceptance: **PASS**. This acceptance used a newly created temporary SQLite database, a loopback RunbookOS webhook, documentation-only target `docs-test-web` at TEST-NET address `192.0.2.42`, and a fake executor. No command reached a real target.

This does not establish real SSH remediation, production recovery, naturally generated monitoring alerts, AI accuracy, or operational deployment. Real Alertmanager v0.3.2 acceptance is a separate historical result and is not evidence from this synthetic v0.6.0 run.

## Acceptance results

| Area | Result | Evidence |
|---|---|---|
| Synthetic alert ingestion | PASS | Authenticated Alertmanager-v2-shaped firing and resolved payloads accepted by the real RunbookOS webhook handler on loopback. |
| Correlation and deduplication | PASS | Firing delivery repeated with a fresh nonce was deduplicated; same-nonce replay was rejected; resolved delivery correlated to the same open incident. |
| Synthetic investigation evidence | PASS | Explicit CLI investigation used registered `systemd.is_active` with fake executor, generated one verified step reference, and linked it to the incident. Forged evidence reference was rejected. |
| Incident-plan association | PASS | CLI `incidents associate-plan` associated the current plan to the exact incident target. Wrong target and forged plan hash were denied. No approval or remediation execution was created by association. |
| One-time approval | PASS | Existing CLI approval was plan-bound. Run without `--confirm` did not dispatch; confirmed run consumed approval; second confirmed run was denied. Expiry is covered by regression tests. |
| Fake remediation execution | PASS | Fake executor returned a successful `systemd.restart`; registered postflight assertion passed and outcome was `VERIFIED_SUCCESS`. |
| Postflight verification | PASS | `systemd.is_active` postflight evidence was persisted; command return alone was not used as the success criterion. |
| Incident lifecycle independence | PASS | Incident remained `INVESTIGATING` after verified remediation. Operator then explicitly resolved with `evidence_status=verified` after reviewing linked diagnostic evidence and remediation postflight, and explicitly closed it. |
| Dashboard read-only remediation review | PASS | Temporary authenticated dashboard showed linked investigation, plan/hash, consumed approval, pre/postflight, `VERIFIED_SUCCESS`, timeline, and audit status. An associated `UNKNOWN` plan showed the warning. Execute and approval POST paths returned 404 and did not change approval or execution counts. |
| Persistence and audit integrity | PASS | Reopened SQLite retained associations and outcomes. `PRAGMA integrity_check` returned `ok`, foreign-key check was empty, and the hash chain verified. |
| Security-negative regression set | PASS | Direct acceptance negatives and the v0.6.0 full offline regression suite passed; case mapping is below. |
| Real SSH remediation | NOT RUN | No SSH adapter or live host was used. |
| Real AI inference | NOT RUN | No provider or model was invoked. |
| Real Alertmanager process | NOT RUN in this acceptance | The tested input was provider-equivalent synthetic JSON; no Alertmanager process was started here. A separate historical v0.3.2 isolated staging acceptance did pass with Prometheus Alertmanager v0.34.1. |
| Natural monitoring rule | NOT RUN | No monitoring system/rule was used. |
| Operational deployment | NOT AUTHORIZED | No operational state or infrastructure was accessed. |

## Isolated records

All IDs below are synthetic acceptance data:

- Primary incident: `7383997d-532f-4f05-8589-aa06d48357f3` (final state `CLOSED`).
- Separate unknown-outcome incident: `518c2a28-c7e8-4469-81f3-ce7b5ca6a2c7`.
- Investigation: `18c1c591-e619-4e72-9aa8-56c411ef3548`.
- Diagnostic execution: `01a218ec-3d6d-42d2-acc9-1a9149f50b69`.
- Remediation plan: `e8e7423b-8eb0-470b-8d3f-65cc2e5c3bba`.
- Verified remediation execution: `aa5489e3-2804-47c5-9d45-d936534199d9`.
- Unknown remediation execution: `b14db2d1-bbcb-4a90-8ddb-0a38c34aff50`.
- Verified diagnostic evidence reference: `01a218ec-3d6d-42d2-acc9-1a9149f50b69:service-active`.
- Alertmanager-normalized refs, authenticated as `synthetic-monitor`:
  - `am-96368078b28ec45474dec110a1b081c83987039c6f9200f3`
  - `am-f6a7e9559cc9c5f09623cdd79454df0ec464107abd87d1ef`

Final synthetic database counts: **4 alert rows** (two normalized webhook alerts plus two direct synthetic negative-case alerts), **3 incidents**, **3 executions** (diagnostic, verified remediation, unknown remediation), **1 investigation**, **4 webhook nonce records**, and **46 audit events**. Duplicate delivery did not add an alert row. The resolved notification added a correlated informational alert but did not change incident state.

A synthetic-only SQLite copy was retained outside the repository with mode `0600` for acceptance evidence. Its machine-local path is intentionally omitted. Temporary configuration, HMAC material, and dashboard verifier were not retained.

## CLI and protocol actions exercised

Invocations used the temporary inventory, policy, SSH profile, and SQLite arguments:

```text
runbookos incidents acknowledge INCIDENT --reason "synthetic operator reviewed alert"
runbookos incidents investigate INCIDENT --runbook diagnostic.yml
runbookos plan remediation.yml --json
runbookos remediation-preview PLAN
runbookos incidents associate-plan INCIDENT PLAN
runbookos incidents remediation-review INCIDENT
runbookos approve PLAN --reason "synthetic acceptance reviewed plan"
runbookos run PLAN
runbookos run PLAN --confirm
runbookos incidents resolve INCIDENT --reason "operator reviewed verified diagnostic and postflight evidence" --evidence-status verified
runbookos incidents close INCIDENT --reason "operator confirmed workflow complete"
runbookos audit
```

The signed webhook requests used `POST /v1/alerts` to a `127.0.0.1` ephemeral port with per-source HMAC authentication. A repeated signed nonce returned HTTP 400. The temporary dashboard used authenticated login on `127.0.0.1` and the v0.4.1 lifecycle/read-only rendering routes.

## Security-negative evidence

The direct acceptance exercised wrong-target association, forged plan hash, forged evidence reference, missing execution confirmation, reused approval, nonce replay, dashboard execute/approve route rejection, and a transport `UNKNOWN` result. The unknown mutation was dispatched exactly once for that plan; no retry or rollback occurred.

Additional independently isolated regression cases passed in the full suite:

- Expired approval: `tests/test_remediation.py::test_expired_approval_fails_before_executor`.
- Stale implementation fingerprint: separately altered the current implementation fingerprint in a temporary plan verification and confirmed preview was denied before approval or execution. Stale configuration fingerprint: `tests/test_incident_remediation.py::test_stale_source_fingerprint_blocks_cli_association`.
- Failed precondition: `tests/test_remediation.py::test_precondition_failure_blocks_mutation_and_records_not_executed`.
- Failed postflight: `tests/test_remediation.py::test_postflight_failure_is_persisted_as_verified_failure`.
- Concurrent one-time approval consumption: `tests/test_remediation.py::test_concurrent_execution_consumes_one_approval_once`.
- Unauthorized lifecycle transition and verified-evidence requirements: `tests/test_incidents.py::test_correlation_is_scoped_and_lifecycle_default_deny` and `tests/test_incidents.py::test_resolution_requires_explicit_evidence_status_and_accurate_attestation`.
- Evidence provenance/forgery: `tests/test_incidents.py::test_investigation_link_requires_stored_verified_reference`.
- Dashboard CSRF, XSS, authentication and mutation boundaries: `tests/test_dashboard.py::test_authenticated_dashboard_lifecycle_csrf_xss_and_restart`.

## Persistence, cleanup, and verification

- SQLite: `integrity_check=ok`; `foreign_key_check` returned no rows.
- Audit hash chain: valid after reopening and before retaining the synthetic database copy.
- Remediation and unknown outcomes remained queryable after database reopen.
- Loopback webhook thread stopped and joined. Dashboard process terminated and exited. Acceptance-created password verifier was removed after shutdown. No acceptance service was left running.
- Fresh wheel and sdist installs were performed in isolated virtual environments and reported version `0.6.0` through metadata, import, and CLI.
- Full offline suite: **144 passed, 11 opt-in live tests skipped**; coverage **80.62%**. Ruff, formatting, packaging, and whitespace checks passed.

## Deviations and remaining limitations

- No real Alertmanager process was started; therefore this is authenticated provider-equivalent webhook acceptance, not real Alertmanager delivery acceptance.
- The remediation operation was executed only by the injected fake executor against a documentation-only address. This validates workflow and audit behavior, not operating-system permission, SSH, or actual service recovery.
- The suite does not claim that an incident is resolved merely because remediation succeeded. Resolution and closure were separate explicit operator CLI actions.
- No product assertion failed. The first standalone stale-fingerprint check attempt could not import the test helper because `tests/` was not on that one-off script's import path; rerunning with the repository test directory on `sys.path` exercised the check and confirmed rejection before approval/execution. The remaining gaps are environment-level live acceptance and deployment authorization.
- The pre-existing local edit to `docs/disposable-remediation-approval-v0.5.0.yml` and untracked historical v0.4.0 staging report remain untouched.
