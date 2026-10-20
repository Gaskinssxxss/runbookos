# RunbookOS v0.3.2 — Implementation Report

**Status:** development branch, offline implementation. No commit or push has been made.

## Reused baseline

v0.3.2 builds on v0.3.1's typed runbook engine, policies, execution store, audit chain, strict SSH adapter, incident lifecycle, per-source HMAC verification, and Alertmanager v2 normalizer. Existing public action IDs and runbook planning/execution semantics are unchanged. Alert ingestion does not start diagnostics, SSH, or AI.

## New implementation

- A separate standard-library Alertmanager signing bridge runs only on `127.0.0.1`. Its upstream trust boundary is loopback plus a configured HTTP Basic credential. It accepts only `POST /api/v2/alerts`, JSON, bounded bodies, and bounded concurrency. It generates a fresh timestamp, random nonce, and source key signature over the exact downstream body for every delivery attempt.
- The bridge forwards only to the RunbookOS loopback endpoint, rejects redirects, has a 5-second downstream timeout, and returns success only after a structurally valid RunbookOS receipt (`incident_id`, `duplicate_delivery`) is received. A lost response yields failure to Alertmanager; its retry gets a new nonce and ingestion deduplicates the event.
- `scripts/staging-v032.py` creates a separate venv, copied example inventory/policy/SSH profiles, a distinct state directory and SQLite file, generated staging-only secrets stored in a mode-0600 ignored file, and foreground-process controls (`start`, `status`, `stop`, `restart`). The listener endpoints are fixed to loopback. It refuses to overwrite an existing staging directory and stop preserves state.
- CLI already provided incident list/show/timeline, acknowledgment, explicit investigation, resolution evidence status, and closure. Those commands remain the operator interface; no duplicate business logic or dashboard was added.
- Version metadata and CI artifact parity checks now target 0.3.2.

## Verification evidence

See [`staging-acceptance-v0.3.2.md`](staging-acceptance-v0.3.2.md) for the exact test runs and evidence level. Automated integration sends a provider-shaped Alertmanager v2 payload through the authenticated bridge and the real RunbookOS webhook to temporary SQLite; it tests rejected sender credentials, two repeated deliveries with distinct nonces, one deduplicated alert/incident, operator acknowledgment, explicitly invoked read-only diagnostics through fake SSH, verified evidence linkage, resolution, closure, restart persistence, and audit verification.

No real Alertmanager process, monitoring-generated alert, homelab SSH session, live Qwen inference, persistent service, or operational deployment was run.

Final local verification on this branch: **110 passed, 11 opt-in live tests skipped**, 79.55% coverage against CI's 70% threshold, Ruff check/format passed, all example runbooks validated, wheel/sdist built, and fresh wheel/sdist metadata/import/CLI parity passed at 0.3.2. SHA-256 values were computed for both final local artifacts and are reported with this implementation result; they are not signed provenance.

## Remaining limitations

- Upstream Basic authentication assumes Alertmanager and bridge share a trusted local host/user boundary. It is not suitable for a remote untrusted network; add a separately approved authenticated transport if deployment crosses hosts.
- A local user who can read the bridge environment can impersonate the sender. RunbookOS is not multi-user RBAC; OS ownership remains the operator trust boundary.
- The staging launcher is Linux-oriented (`/proc`, POSIX signals) and intended for local development; it is not a supervisor or production service manager.
- Automated tests use a provider-equivalent fixture. Real Alertmanager compatibility and live SSH evidence remain unverified.

## Release state

Development version `0.3.2` is not a release. No Git commit, tag, remote update, or push is authorized or performed. Operational deployment requires a separate approval and staging acceptance.
