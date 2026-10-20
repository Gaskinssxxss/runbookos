# RunbookOS v0.3.0: Alert Ingestion and Incident Workflow

## Scope and compatibility

This release adds alert intake and operator-managed incidents above the existing RunbookEngine. It does not replace planning, policy enforcement, SSH, execution evidence, AI citation validation, or the audit chain. Existing CLI commands and v0.2.x evaluation artifacts remain readable. SQLite schema version 3 is an additive migration; plans, approvals, executions, investigations, and audit events are preserved.

No diagnostics run when an alert arrives. Investigation requires an operator to acknowledge the incident and explicitly invoke `incidents investigate`; each selected runbook is still planned and checked by the existing policy engine and runs in diagnostic-only mode.

## Alert JSON

One JSON object is accepted, up to 64 KiB. Unknown fields, duplicate JSON keys, invalid enum values, naive timestamps, command-like metadata keys, excessive nesting, and unknown inventory aliases are rejected. `summary` and metadata are untrusted descriptive text. They never become shell input, policy, approval, or evidence.

```json
{
  "alert_id": "monitor-2026-001",
  "source": "example-monitor",
  "event_timestamp": "2026-10-20T09:00:00Z",
  "severity": "error",
  "target_alias": "example-web-01",
  "service": "nginx",
  "category": "service",
  "summary": "Readiness endpoint did not return success",
  "fingerprint": "nginx-healthz-failure",
  "metadata": {"check": "healthz", "region": "example"}
}
```

Allowed severity values: `info`, `warning`, `error`, `critical`. Categories: `service`, `connectivity`, `network`, `dependency`, `capacity`, `security`, `unknown`. Metadata is limited to 8 KiB, 32 keys/elements at each list, depth four, and bounded strings. Secret-like values are redacted by the existing storage redactor; command/shell/exec/script keys are rejected.

## Deduplication and correlation

Idempotency uses the `(source, alert_id)` primary key. Re-delivery with the same canonical payload returns the existing incident; reuse of an alert ID for different content is rejected. Correlation is exact and deterministic over `(source, fingerprint, target_alias, service, category)`. Severity may rise on a correlated alert. Summaries are not correlation keys. No cross-source, cross-target, cross-service, or cross-category merge is performed.

Closed incidents are not silently reopened. A new matching alert after closure creates a new incident. Operators may use an explicit reopen operation when that workflow is enabled in a later release; v0.3.0 requires a new incident or direct lifecycle review rather than implicit reopening.

## Incident lifecycle

Allowed transitions are `NEW → ACKNOWLEDGED → INVESTIGATING → RESOLVED → CLOSED`. There are no shortcuts. Each change uses `BEGIN IMMEDIATE`, checks the current state, records an incident timeline entry, and adds a hash-chained audit event. Resolution and closure require a reason. `RESOLVED` additionally requires an explicit evidence status: `verified` requires linked verified evidence references, while `not_available` or `inconclusive` records an operator attestation without claiming that evidence was verified. Ingestion, exact duplicate delivery, correlation, transitions, and investigation linkage are audited. Investigations can only link to stored investigation IDs and references present in their `verified_evidence` set.

## CLI

The common global options (`--inventory`, `--policy`, `--ssh-profiles`, `--db`) precede the command.

```sh
runbookos alerts ingest alert.json
cat alert.json | runbookos alerts ingest -
runbookos alerts list --limit 50
runbookos incidents list --status NEW
runbookos incidents show INCIDENT_ID
runbookos incidents acknowledge INCIDENT_ID --reason 'Reviewed alert'
runbookos incidents investigate INCIDENT_ID --runbook examples/runbooks/web-diagnostics.yml
runbookos incidents investigate INCIDENT_ID --ai-config config/investigation.yml
runbookos incidents timeline INCIDENT_ID
runbookos incidents resolve INCIDENT_ID --reason 'Service verified healthy' --evidence-status verified
# Or explicitly attest that RunbookOS has no conclusive evidence:
runbookos incidents resolve INCIDENT_ID --reason 'Resolved through external operator check' --evidence-status not_available
runbookos incidents close INCIDENT_ID --reason 'Follow-up complete'
runbookos audit
```

The direct `--runbook` and AI path both require an acknowledged incident and exact target scope. Direct runs are bounded to 16 actions and an estimated 90-second budget; the AI path also uses its existing configured tool-call/time limits. AI is optional and explicit; its catalog is filtered so every catalog entry must target only the incident's alias. Ingestion does not call the model. A failed investigation leaves status at `INVESTIGATING` for operator review; an operator may still resolve it only with a recorded `not_available` or `inconclusive` attestation, never by labelling absent evidence `verified`.

## Optional webhook

Webhook is a foreground opt-in command, disabled unless an operator starts it. It binds only `127.0.0.1`, accepts only `POST /v1/alerts`, and has no persistent service definition. **The single-key procedure below describes v0.3.0 only and is superseded for v0.3.1.** For current per-source authentication, key rotation, signed headers, explicit legacy mode, and configuration, follow [Webhook authentication and rotation (v0.3.1)](webhook-authentication-v0.3.1.md). The v0.3.1 listener requires `--auth-config`; it does not silently fall back to the old environment variable.

```sh
runbookos webhook serve --auth-config config/webhook-sources.example.yml --host 127.0.0.1 --port 8765
```

Stop with Ctrl-C. Do not bind to a non-loopback address, create a systemd unit, reverse proxy, firewall rule, or public listener under this release. A webhook rejection returns a generic response and does not log headers or body.

## Storage, backup, and recovery

Schema version 3 adds `alerts`, `incidents`, `incident_alerts`, `incident_events`, `incident_investigations`, and `webhook_nonces` with foreign keys and indexes. The migration is additive. Back up the SQLite database using the SQLite backup API or a consistent filesystem/database snapshot, including WAL state when copying files. Restore into a separate path first, then run `runbookos audit`; never overwrite the operational database during validation. Existing execution/audit retention is unchanged.

## Security boundaries and limitations

- Alert fields are data only; there is no command/action mapping in alert schema.
- Network webhook deployment, TLS termination, remote authentication, rate controls across multiple processes, and service supervision are out of scope.
- v0.3.0 used one configured listener secret; v0.3.1 adds per-source keys. See the current authentication guide for remaining shared-secret risks.
- The default integration uses SQLite's write serialization. High-volume multi-process ingestion should be load-tested before deployment.
- `metadata` supports bounded JSON values, not arbitrary log/event blobs.
- The local HTTP webhook is intentionally unsuitable for untrusted remote networks.
- Incident workflow is not production-ready until deployment authorization, filesystem ownership, backup/restore, webhook secret distribution, and operational recovery are validated in the target environment.

## v0.3.0 offline acceptance

`tests/test_incidents.py` exercises schema rejection, exact-scope correlation, concurrent duplicate delivery, lifecycle policy, forged evidence linkage rejection, HMAC authentication, replay rejection, malformed JSON, oversized body rejection, and loopback-only binding with temporary SQLite. Its end-to-end case sends authenticated webhook alerts through duplicate handling and then invokes the existing read-only engine against fake SSH, continuing through evidence linkage and operator lifecycle transitions. These are local tests, not live homelab validation. No homelab VM or operational state is modified by these tests.
