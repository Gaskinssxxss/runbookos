# Security model and operational limits

## Enforced in code

- Default-deny policy; actions must be registered and explicitly allowed per host.
- Runbook YAML cannot supply arbitrary shell, Python, executable paths, sudo commands, SSH options, or policy overrides.
- Read-only diagnostics and remediation actions are separated. All mutating actions require policy allow and a plan-bound, expiring, one-use approval.
- SSH uses public key auth only, `StrictHostKeyChecking=yes`, the configured host pin, an explicit identity, no SSH config file, no proxy, no forwarding, no agent, bounded timeouts, and hard stdout/stderr/response limits while output is produced. Oversize, malformed, partial, or timed-out results are `unknown`; no automatic retry occurs.
- The pinned `known_hosts` file must be a regular file owned by the current user or root, must not be group/world-writable, and is opened without following a final-component symlink. Ordinary read-only modes such as `0644` remain valid.
- Host key mismatch/config problems fail before network dispatch. A timeout or lost connection after dispatch produces `unknown`; the engine stops and never retries automatically.
- Plans bind config hashes and an implementation fingerprint covering the package version, registered action schemas/permissions/timeouts, and remote dispatcher source; execution refuses stale approvals after those semantics change, invalid plan hashes, or an invalid audit chain.
- SQLite file and state directory permissions are owner-only. Audit events are hash chained; evidence keys matching common credential names are redacted.
- The optional AI workflow is disabled unless explicitly invoked. It can select registered diagnostic IDs and return the constrained Minimal Semantic Reply v2 fields: category, confidence, issued evidence aliases, short reason, abstention, and uncertainty. Selected IDs are resolved to local runbooks and revalidated by the core planner. Every diagnostic action must be registered, read-only, host-policy-allowed, and within configured budgets before dispatch.
- AI output cannot change policy, provide action arguments or commands, invoke the remediation registry, approve a plan, set identity/provenance/verification metadata, or access SSH credentials. Python resolves evidence aliases and constructs observations from persisted engine steps; the unchanged assessment validator rejects invalid outputs. A model classification is recorded as suspected, never as verified support.
- Provider HTTP is restricted to loopback; other HTTP(S) URLs must use HTTPS. Provider credentials are referenced only by environment variable. Requests are bounded, non-streaming, and responses have a size limit.
- Network diagnostics accept only inventory endpoint aliases. Each endpoint is a private IPv4 literal with an exact protocol/port/fixed HTTP path, and must be separately allowlisted per source host and action. Probe calls have a 10-second hard maximum. HTTP redirects are not followed, response bodies are not retained, and HTTPS uses certificate/hostname verification.
- PostgreSQL protocol availability sends only an SSL negotiation request; it does not authenticate, execute SQL, or prove a database/user is ready. It cannot grant or expand network/server access.
- The explicit `tunnel` command binds locally only to `127.0.0.1`, forwards only to the pinned `127.0.0.1:8080` endpoint, rejects insecure key/known-host file modes, disables SSH config and password/agent/TTY access, and requires strict host-key checking. It does not provision SSH access or persist a tunnel process.
- Raw incident descriptions, provider prompts, and model responses are not persisted. Successful investigation records retain an incident hash, model metadata, bounded redacted evidence, a validated structured assessment, and a result-hash audit event. Failed provider/contract attempts retain only a sanitized failure stage/category, selected diagnostics, and already-collected evidence.

## Not a privilege boundary

The configured SSH account has only the permissions its target OS grants. RunbookOS does not call sudo, request a password, alter SSH access, or install agents. A policy allow is not a grant of Linux permissions. If an action cannot run as the configured account, it fails; do not solve this by adding passwordless sudo. Create a narrowly constrained OS identity and explicitly review that design in a later change if remediation is required.

Incident resolution is an operator decision. Resolution with `evidence_status=verified` is accepted only when verified evidence references are linked to the incident. `not_available` and `inconclusive` are explicit operator attestations recorded with the reason in the timeline and audit chain; they never claim missing evidence as verified.

AI investigation sends the incident description and bounded diagnostic evidence to the configured provider. A local model service should bind to `127.0.0.1`; do not expose its listener publicly. If inference is remote, use an authenticated, narrowly scoped transport approved for that environment. Prompt-injection text may still influence model prose, so no generated recommendation is executed and hypotheses must cite actual engine evidence. The detector for suspicious instructions is heuristic; the capability boundary and engine policy are the security controls.

## Residual risks

- The local operator controls policy, identity, state DB, provider config, and approval; RunbookOS does not provide multi-person approvals, MFA, remote policy signatures, or an HSM.
- The SQLite hash chain is tamper-evident against casual edits, not tamper-proof against a user who can rewrite the database and recompute hashes. Store signed/off-host evidence for stronger requirements.
- No secrets are supported as runbook parameters. Never place private key material or passwords in YAML, plans, terminal history, or audit notes.
- The remote Python shim runs fixed diagnostic subprocesses. Compromise of the trusted controller or Python package remains in scope for host hardening and supply-chain controls.
- Provider-side logging, retention, model quality, and confidentiality are outside RunbookOS control. Review the provider before sending incident details. Local SQLite evidence can still contain operational topology and health data.
- Local audit data is only as confidential as the OS account and filesystem; back it up securely.
