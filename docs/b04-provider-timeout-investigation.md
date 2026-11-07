# Batch 04 proposal timeout investigation (Issue #3)

Baseline: 7e39e3bfc9d23de84ef13b143de935659fa45fd2.

## Findings

| Scenario | Faults recorded in the checked-in scenario definition | Repository evidence of result | Root cause |
| --- | --- | --- | --- |
| B04-19 | backend_stopped + invalid_app_config; partial recovery scenario | Project summary says the proposal stage failed with sanitized category provider_timeout; attempt detail is not checked in | **UNKNOWN** |
| B04-20 | backend_stopped + worker_stopped; two independent components | Project summary says the proposal stage failed with sanitized category provider_timeout; attempt detail is not checked in | **UNKNOWN** |

The scenarios share a provider-failure label and proposal stage, but their fault patterns differ. That does not establish that either fault pattern caused the timeout. The repository does not contain the private Batch 04 ledger, raw per-attempt resource_watch measurements, Qwen server logs, request/response timing, token usage for failed requests, finish reason, or transport phase. Per Issue #3, these sources were not accessed.

## Verified code path

1. The Batch 04 investigation configuration writes timeout_seconds 120, max_tokens 700, and schema-constrained proposals.
2. campaign_batch04_live.py invokes incidents propose-remediation after a successful investigation, with a separate outer CLI timeout of 180 seconds.
3. IncidentInvestigator.propose_remediation() calls request_remediation_proposal() once. It does not retry. A provider timeout is converted into a rejected, sanitized proposal record; it does not create a plan or execute remediation.
4. OpenAICompatibleProvider.complete() and complete_with_schema() both issue one non-streaming HTTP request. The configured timeout is passed to urllib opener.open. Timeout exceptions from opening or reading are mapped to AI provider request timed out.
5. The provider records duration_seconds and token usage only after a complete response. Before this change, a timeout retained neither elapsed time nor token/finish metadata. The campaign ledger therefore could not distinguish a near-budget timeout from a short transport interruption based on checked-in data.

The client timeout value is known, but urllib socket timeout does not identify whether a timeout happened during connect, waiting for response data, or reading a stalled response. The repository has no provider queue-depth, server-side generation timing, or completion-token telemetry for a request that did not return. The configured proposal completion budget is 384 tokens (MAX_PROPOSAL_COMPLETION_TOKENS); it is a request cap, not evidence that generation reached the cap.

## Root-cause matrix

| Candidate explanation | Evidence available | Assessment |
| --- | --- | --- |
| Provider-side generation latency/token exhaustion | Proposal cap and client timeout are configured; no failed-request token count, finish reason, or provider-side timing is present | **UNKNOWN** |
| Client/provider queueing | No queue-depth or scheduler telemetry in checked-in artifacts | **UNKNOWN** |
| Network/connect/read stall | Timeout classification is consistent with a socket timeout; the specific transport phase and elapsed duration were not preserved | **UNKNOWN** |
| Outer campaign command timeout | The proposal subprocess budget is 180 seconds versus the configured provider timeout of 120 seconds; no raw process timing is available | Not established by the recorded provider_timeout label |
| Scenario complexity caused the timeout | Both are compound scenarios but have different faults; there is no request-level timing or controlled comparison | **UNKNOWN** |

## Minimal diagnostic change

Provider socket timeouts now raise a sanitized ProviderRequestTimeout carrying client-observed elapsed seconds. The proposal failure audit may persist only failure_stage=proposal and duration_seconds alongside its unavailable outcome; bounds and exact keys are enforced by the store. The CLI response and Batch 04 ledger projection retain the same allowlisted fields. Raw prompts, responses, exception text, credentials, token estimates, and inferred timeout causes are not recorded. Successful proposal format, policy, approval, execution, retry behavior, and historical records are unchanged.

This instrumentation can classify the client-observed duration on a future attempt. It cannot by itself identify provider queueing, generation progress, transport phase, or semantic behavior. No live attempt was made as part of Issue #3.

## Offline verification

- Provider timeout tests use simulated timeout exceptions and a controlled monotonic clock.
- Audit persistence tests verify bounded sanitized failure metadata and reject extra fields, invalid stage, non-finite duration, and raw response content.
- Campaign projection tests verify only proposal-stage bounded timing is copied.
- Existing one-request/no-retry behavior remains asserted.

Root cause for B04-19 and B04-20 remains **UNKNOWN** unless sanitized request-level evidence is later supplied.
