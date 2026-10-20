# Implementation report: RunbookOS v0.3.0

## Implemented

- Strict JSON alert contract with bounded metadata, inventory alias validation, duplicate-key rejection, and no execution-capable fields.
- Additive SQLite schema v3 for alerts, incidents, alert links, timelines, investigation references, and replay nonces.
- Transactional alert ID idempotency and deterministic source/fingerprint/target/service/category correlation.
- Explicit, concurrency-safe human incident transitions and hash-chained audit records.
- CLI groups for alert ingestion/listing, incident listing/show/acknowledge/investigate/resolve/close/timeline, and an opt-in webhook.
- Optional direct read-only runbook or AI investigation linkage through the existing policy engine. New workflow requires acknowledgment and explicit operator invocation; AI catalog filtering is restricted to the incident target.
- Direct incident runbooks are bounded to 16 registered actions and a 90-second estimated execution budget; AI path retains its configured limits.
- Foreground HMAC-SHA256 webhook, loopback-only, timestamp window, nonce replay prevention, body/concurrency/rate bounds, with no permanent service deployment.
- Documentation, CLI examples, security boundaries, and isolated SQLite integration tests.

## Verification status

Offline verification completed:

- Full suite: **94 passed, 11 skipped**. Skips are opt-in live homelab, live probe, live AI, and tunnel checks.
- Ruff lint and format checks: passed.
- CLI smoke: version `0.3.0`, alert/incident/webhook command help, and existing web runbook validation passed.
- End-to-end integration test: HMAC-authenticated alert ingestion, duplicate delivery with a fresh nonce, acknowledgment, fake-SSH read-only diagnostic execution, evidence linkage/timeline, resolution, closure, and audit verification passed using temporary SQLite.
- Webhook test: loopback binding, HMAC rejection/acceptance, replay rejection, malformed JSON, oversized payload, and audit validation passed.
- SQLite backup/restore and v1-to-v3 additive migration checks passed; legacy plan records remain readable.
- Wheel and sdist: built successfully to `/tmp/runbookos-v030-dist` so existing `dist/` artifacts were not replaced.
- `git diff --check`: run. This checkout presents repository files as untracked, so Git cannot enumerate the full new tree in its diff check; Ruff formatting and tests covered edited Python files.

No real alert source, live webhook deployment, live RunbookOS investigation, or homelab probe was performed for v0.3.0. No homelab VM, SSH identity, network policy, service, operational SQLite database, or historical benchmark dataset was modified.

## Known limitations

- Webhook secret is a single process environment variable; multi-source credentials and key rotation are future work.
- Webhook is a single-process loopback foreground listener; remote deployment, TLS, durable queueing, proxy integration, systemd service deployment, and cross-process rate limiting are not included.
- There is no automatic incident reopening after CLOSED; a later matching alert starts a new incident.
- A failed explicitly started investigation remains `INVESTIGATING` for human review.
- Human role-based authorization is not implemented; CLI local account ownership is the operator boundary.
- Production readiness requires a separate deployment approval and environment-specific backup, restore, authorization, secret-handling, and recovery validation.

## Recommended next milestone

Before any v0.3.0 deployment, run a separately approved acceptance in a disposable environment: migrate a copy of a v0.2.5 database, validate restore, exercise webhook key rotation and source-specific credentials, verify filesystem permissions and operational access controls, and test real alert-provider payload compatibility. Do not expose the webhook beyond loopback without a distinct network and authentication design review.
