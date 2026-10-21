# RunbookOS v0.6.0 — Incident-linked remediation security

## Trust boundaries

Alert senders can submit data and create/correlate incidents under the existing authenticated ingestion rules. They cannot associate plans, approve plans, execute actions, or change incident lifecycle state. AI remains advisory and cannot invoke remediation. Dashboard routes are read-only with respect to remediation: they expose reviewed metadata but cannot associate, approve, or execute plans.

Only an explicit local CLI operator action can associate a plan or review it. Actor identity is derived from the local OS account. Association is not approval and does not dispatch work.

## Association invariants

The existing incident and plan must exist. The persisted plan must validate as a typed `PlanDocument`; its ID, stored hash, supplied hash, recomputed canonical hash, and `plan.created` audit record must agree. The plan must be in `approval_required` state and contain exactly one registered policy-allowed mutable step, targeted at the incident's exact target. It must also contain assertion-bearing, registered read-only preflight and postflight checks. The association is unique by plan ID and incident-plan pair. Repeating the same association is idempotent and audited; conflicting target, hash, action, or incident associations are rejected.

An association writes only the v4 relation row, incident timeline event, and audit event in one SQLite transaction. It does not create an approval, execution, or lifecycle transition. It can be reviewed against the existing current preview; changed source/configuration/implementation fingerprints make the plan stale and prevent CLI association or preview acceptance.

## Review and execution boundary

`runbookos incidents remediation-review` calls the existing remediation preview, reports approval state and stored outcomes, and audits that the operator reviewed the context. An `UNKNOWN` outcome is a stop condition for replay: it requires independent investigation. RunbookOS never retries an uncertain mutation or automatically rolls it back.

Execution continues through the existing v0.5.0 CLI workflow: policy-allowed plan, expiring one-time plan-bound approval, explicit confirmation, dispatch-intent audit, bounded SSH, and postflight verification. This milestone does not alter those semantics. Because the implementation fingerprint includes the package version, plans created before upgrading to v0.6.0 are stale by design; operators must create a fresh plan and approval after reviewing it. It adds no execution endpoint, arbitrary command path, privilege, or remediation automation.

## Incident lifecycle

Even `VERIFIED_SUCCESS` only describes the registered action and its postflight assertions. It does not resolve or close the incident. The operator must independently review the evidence and use the existing transition command with its evidence-status rules. Incident closure is not represented as proof of infrastructure recovery.

## Data handling and audit

The relation stores IDs, hashes, target/action identifiers, OS actor, and timestamp. The review projection omits raw evidence payloads and summarizes only phase, registered action, assertion count, outcome, status, and time. Hash-chain verification is required before association. Audit entries distinguish association and review from approval and execution.

SQLite schema v4 is additive. It retains plan and execution foreign keys and does not rewrite v0.5 records, raw benchmark datasets, or earlier audit events. Back up the database before upgrades using the established operations procedure. Schema downgrade is not supported; rollback should use a copy/restore procedure and must not delete newer audit history.

## Limitations

- OS username is a local actor identifier, not external identity proof, MFA, or multi-person approval.
- The existing system-level `systemd.restart` permission limits remain; no privilege expansion is provided.
- Dashboard plan/outcome information is a read-only projection and can lag until the next request.
- Offline fake-executor acceptance does not prove SSH authorization or service recovery on any real target.
- The disposable target manifest remains `NOT_AUTHORIZED`.
