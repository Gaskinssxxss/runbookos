# RunbookOS v0.5.0 — Human-controlled remediation security

## Scope and trust boundaries

The remediation path reuses the existing YAML runbook, action registry, planner, default-deny host policy, plan persistence, approval table, strict OpenSSH adapter, step evidence, and hash-chained audit log. There is no separate remediation executor or approval database. Dashboard, alert ingestion, and AI investigation do not invoke mutable actions.

Only registered actions can be planned. `systemd.restart` is the only registered mutating action and remains denied by shipped policies. Runbooks containing a mutable action must target exactly one inventory host and contain exactly one mutable step, with at least one assertion-bearing read-only preflight and postflight check. All pre/post phases are validated against the read-only registry. A failed or unknown preflight halts execution before the mutable action.

## Operator workflow

1. Create a plan using `runbookos plan RUNBOOK.yml` and inspect the plan ID and status.
2. Review `runbookos remediation-preview PLAN_ID`. Its impact and rollback statements come from trusted action registry metadata; AI output is not used.
3. If status is `approval_required`, create the existing one-time, expiring approval with `runbookos approve PLAN_ID --reason '...'`.
4. Execute only after the approval review with `runbookos run PLAN_ID --confirm`. The CLI derives the confirmation actor from the local OS account. The engine rejects mutable execution without both explicit confirmation and actor identity, and checks plan/configuration/implementation hashes before consuming approval.
5. Inspect `runbookos history EXECUTION_ID` and `runbookos audit`.

The approval is bound to the immutable plan ID and hash. The plan hash includes the exact target, action arguments, source hashes, inventory, policy, SSH profiles, and implementation fingerprint. That fingerprint covers the action registry, CLI confirmation boundary, planner, approval/store logic, models, remote dispatcher, and SSH transport, in addition to the package version. Approval is consumed atomically before the first execution step. An approval for one plan or host cannot authorize another plan.

## Preview and impact

`remediation-preview` displays target, action ID, typed parameters, read-only preconditions, policy decision, implementation fingerprint, approval TTL/one-time requirements, postflight checks, expected impact, and rollback limits. For `systemd.restart`, the expected impact warns that requests or active connections can be interrupted. Restart is not reversible: the engine will not automatically issue a second restart.

## Outcome states

Remediation outcome is separately persisted in execution `summary_json` and a `remediation.outcome` audit event:

- `NOT_EXECUTED`: a policy/approval/preflight/local configuration boundary prevented dispatch.
- `VERIFIED_SUCCESS`: the mutating action returned a definitive successful response and every postflight assertion passed.
- `VERIFIED_FAILURE`: a definitive mutating action failure or a postflight assertion positively showed the requested postcondition was not met.
- `UNKNOWN`: transport, timeout, output, or evidence uncertainty prevents a conclusion.

An SSH timeout, lost connection, or malformed/partial response stays unknown with `retry=false`; it is never replayed. A command return code alone is not sufficient for verified success. Postflight evidence must also pass. If postflight cannot establish state, the outcome is unknown. Step evidence records action, target, result, assertion results, timestamps, and bounded response data; the hash-chained audit stores the corresponding authorization, execution, and outcome events.

## Rollback and manual recovery

No automatic rollback is attempted. For `systemd.restart`, manual recovery is to inspect the service status and relevant service logs through an authorized operator channel, determine impact, and plan a separate action if needed. A new action requires a new plan, policy evaluation, preview, approval, and confirmation. Never retry an uncertain action until an operator independently establishes the actual target state.

## Disposable target boundary

`docs/disposable-remediation-approval-v0.5.0.yml` is a NOT_AUTHORIZED review manifest using reserved documentation address `192.0.2.50`; it does not provision or start a VM. Live acceptance requires a separate operator authorization naming an actual disposable target, source identity, verified pinned host key, policy scope, allowed service, time window, and recovery procedure. No privilege, sudo, firewall, route, hypervisor, VM, or service changes are included in this milestone.

The example runbook targets `disposable-test-01`, absent from shipped inventory and policy. The default policy denies it. Do not copy the example into operational homelab policy. If the test account cannot restart its unit without administrative privilege, report that limitation; do not grant sudo or change system authorization.

## Verification limits

v0.5.0 is validated with offline fake executors and temporary SQLite only. This proves deterministic engine behavior and audit persistence under test conditions; it does not prove real systemd restart behavior, SSH privilege sufficiency, recovery of any service, or production readiness.
