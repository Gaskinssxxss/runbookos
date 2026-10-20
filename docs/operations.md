# Operations

## Local setup

Use a Python virtual environment and install the package in editable mode. OpenSSH client and `ssh-keygen` are required for remote execution. No root access is required to install or run RunbookOS. The default state DB is `state/runbookos.sqlite3` in a source checkout or `~/.local/state/runbookos/runbookos.sqlite3` in a normal install. AI inference is optional and uses the configured HTTP provider only when `investigate` is invoked. The separately configured `tunnel` command runs in the foreground and exits when interrupted.

Inspect `runbookos --help`. Validate a runbook first; create a plan and review every target/action/argument and policy decision before executing. `check` is read-only-only. Remediation uses the explicit sequence: plan → operator review → approve with reason → run. An approval is valid once and expires according to policy.

## State lifecycle

- Plans remain in SQLite for audit and can be re-run only when unchanged; approval for mutations is one-time.
- Executions use `running`, `succeeded`, `failed`, or `unknown`. An unclean controller exit can leave `running`; treat it as interrupted/uncertain and inspect the target before any new plan.
- SSH `unknown` means dispatch may have reached the host. Inspect `runbookos history EXECUTION_UUID`, target service state, and logs manually. Do not replay a mutating step just because SSH timed out.
- Run `runbookos audit` to verify the local event chain. Back up the DB with restrictive permissions and send an independent copy to trusted storage for recovery.
- `runbookos investigate --incident-stdin` reads bounded incident text from stdin, selects from the configured diagnostic catalog, and stores the result. Review every `verified_evidence` reference against `runbookos history EXECUTION_UUID`; hypotheses and recommendations remain model output, not facts or executable plans.
- `runbookos investigations` lists investigation metadata and evidence references without echoing incident text. SQLite `user_version=3` adds alert/incident tables while retaining prior plan, approval, execution, investigation, and audit tables.
- Provider timeouts, invalid JSON, unknown diagnostic IDs, unsupported evidence references, or policy denial stop the investigation. No tool call is retried and no recommendation is executed.
- For local host inference from a VM, use a dedicated tunnel identity and pinned host key. Start `runbookos tunnel config/tunnel.yml` in a supervised terminal, then run `investigate` in another shell with `RUNBOOKOS_LLAMA_API_KEY` present. Do not put the API key in command arguments or shell history. Stop the tunnel with Ctrl-C after the investigation. No service persistence is configured by RunbookOS.

## Approval and access

The local OS username is recorded as the approval actor. The operator must state a useful change/incident reason. The approval stores the plan hash, expires in 900 seconds by default, and is consumed atomically before dispatch. A policy denial cannot be overridden by approval. Do not grant remediation in policy until the target OS permissions and recovery procedure are reviewed. No action invokes sudo.

## Recovery

If the controller process stops, inspect SQLite history. If a row remains `running`, classify the result as uncertain; RunbookOS does not resume or retry an in-flight plan or investigation. Restore the SQLite DB from a protected backup if damaged, then run `audit`; do not edit chain rows to make verification pass. A lost DB also loses local plan/approval/investigation state, so re-plan and obtain fresh approval.

For a controller or managed-host outage, use the environment owner's independent console/recovery path. RunbookOS does not change network topology, firewall policy, or install agents as part of diagnosis. Its optional inference tunnel is foreground-only and must be stopped by its operator; RunbookOS does not create a service unit or auto-start configuration.

For synthetic incident fixtures and evaluation semantics, see [incident-evaluation.md](incident-evaluation.md). `runbookos evaluate` does not connect to managed hosts or inject faults.

## SSH access changes

Provisioning or rolling back a managed account is an operator-approved environment change and is outside automatic RunbookOS execution. Keep exact key fingerprints and before/after metadata in the environment's protected change record. Remove only the exact authorized key entry introduced for the change; preserve administrator accounts, unrelated keys, and SSH configuration. Do not change routes, firewall policy, sshd, or services to work around reachability without separate approval.
