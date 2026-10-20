# RunbookOS v0.3.1 implementation report

## Implemented

- Per-source webhook HMAC identity via a statically configured key ID → source mapping. The key ID is signed with the exact body, timestamp, and nonce. Native alert `source` must match the authenticated identity; Alertmanager source is assigned from credentials.
- Active key, grace key with explicit expiry, revocation, disabled-source handling, unique key IDs, minimum 32-byte secret, and explicit `legacy_single_source` compatibility without silent fallback.
- Webhook startup audit includes configuration hash and key IDs/states/expiry metadata only. Accepted alert audit includes key ID and never stores key values.
- Alertmanager webhook v2 payload adapter for homogeneous groups. Stable group fingerprints support dedup/correlation; `resolved` notifications are informational and cannot resolve incidents.
- Stronger `.gitignore`, staged-file manifest, operator readiness checklist, authentication/rotation guide, and staging/restore runbook.
- v0.3.1 package version.

## Verification

Offline verification completed on 2026-10-20:

- Full suite on the working checkout: **99 passed, 11 skipped**. The skipped tests are the opt-in live homelab, live probe, AI/tunnel tests; none were enabled.
- Full suite on a clean source copy with ignored/private report JSON, `.venv`, state, and build artifacts excluded: **99 passed, 11 skipped**.
- Ruff lint: passed. Ruff format check: passed.
- CLI smoke: `runbookos version` reported `0.3.1`; webhook, webhook serve, alerts, and incidents help commands loaded successfully.
- Wheel and sdist built from the final clean source copy: `runbookos-0.3.1-py3-none-any.whl` (90,790 bytes) and `runbookos-0.3.1.tar.gz` (99,628 bytes). Artifact inspection confirmed example configs, Alertmanager fixtures, scenarios, and runtime modules are present while raw evaluation JSON and SQLite data are absent.
- Schema-v2-to-v3 additive migration test preserved an existing plan and audit marker and verified the resulting hash chain. SQLite backup/restore, an interrupted uncommitted transaction, duplicate delivery after commit, and end-to-end authenticated Alertmanager → incident → mocked read-only investigation → evidence link → resolution are covered with temporary databases.
- Security tests cover per-source identity, forged source, invalid/unknown/revoked/expired keys, disabled source, explicit legacy mode, replay across key IDs, oversized/malformed input, duplicate authentication headers, loopback-only binding, missing active key fail-closed startup, and absence of HMAC secret values from audit payloads.
- `.gitignore` checks confirmed environment files, SSH identities, known-hosts, SQLite state, Qwen raw results, and blind-review answer keys are ignored. Historical files remain present locally.
- `git diff --check` returned clean. Since this repository has no commits and all release files are untracked, that command has no tracked diff to inspect; a scoped whitespace scan of 73 source/config/example/test/release-doc files also returned clean.

No test connected to a real monitoring source or homelab service.

## Not performed

- No live Alertmanager was configured or contacted.
- No persistent webhook listener was started for a deployment. HTTP tests bind only ephemeral loopback ports.
- No VM, homelab service, firewall, route, SSH access, operational SQLite file, or historical benchmark data was changed.
- No Git commit, staging, remote configuration, push, or publication was made.
- No clean Git worktree was possible because branch `main` has no commits. A clean source copy was used instead.

## Risks and next gates

- HMAC keys are shared per source; compromise permits sender impersonation until revocation. Secret provisioning/rotation remains an operator responsibility.
- Rate limiting and nonce cleanup are local to a single process; multi-process or high-volume deployments need an external coordination design.
- Alertmanager mapping intentionally rejects heterogeneous groups and needs a real payload acceptance test before compatibility claims.
- CLI authorization is based on local OS account access; there is no role-based authorization or multi-party approval model.
- SQLite schema v3 is forward-only; older binaries reject it. Recovery uses a pre-migration backup copy, never in-place downgrade.
- Operational listener, DB migration, proxy/network path, secret injection, and recovery require distinct deployment approval and evidence.
