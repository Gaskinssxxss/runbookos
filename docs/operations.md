# Operations

## Local setup

Use a Python virtual environment and install the package in editable mode. OpenSSH client and `ssh-keygen` are required for remote execution. No root access is required to install or run RunbookOS. The default state DB is `state/runbookos.sqlite3` in a source checkout or `~/.local/state/runbookos/runbookos.sqlite3` in a normal install. AI inference is optional and uses the configured HTTP provider only when `investigate` is invoked. The separately configured `tunnel` command runs in the foreground and exits when interrupted.

Inspect `runbookos --help`. Validate a runbook first; create a plan and review every target/action/argument and policy decision before executing. `check` is read-only-only. Remediation uses the explicit sequence: plan → operator review → approve with reason → run. An approval is valid once and expires according to policy.

## State lifecycle

- Plans remain in SQLite for audit and can be re-run only when unchanged; approval for mutations is one-time.
- Executions use `running`, `succeeded`, `failed`, or `unknown`. An unclean controller exit can leave `running`; treat it as interrupted/uncertain and inspect the target before any new plan.
- SSH `unknown` means dispatch may have reached the host. Inspect `runbookos history EXECUTION_UUID`, target service state, and logs manually. Do not replay a mutating step just because SSH timed out.
- Run `runbookos audit` to verify the local event chain. Back up the DB with restrictive permissions and send an independent copy to trusted storage for recovery.
- `runbookos investigate --incident-stdin` reads bounded incident text from stdin, selects from the configured diagnostic catalog, executes only policy-allowed read-only diagnostics, and stores a validated Minimal Semantic Reply v2 assessment. Review linked evidence and assertion/verification states through `runbookos history EXECUTION_UUID` and the incident assessment projection. Model classifications remain suspected, confidence is uncalibrated, and citations do not prove semantic support. Provider or contract failures are persisted as sanitized failed investigations; they are not abstentions or diagnoses. Assessment text is advisory and cannot approve or execute a plan.
- `runbookos investigations` lists investigation metadata and evidence references without echoing incident text. Additive migrations have advanced SQLite to `user_version=4` while retaining prior plan, approval, execution, investigation, incident, and audit data. Downgrade is unsupported.
- SQLite schema version is currently v4. Use the SQLite backup API for a consistent backup while the controller is running; never copy only the main database file when WAL mode may be active. Write backups to a new owner-only path and verify the copy before considering recovery.
- Read-only `systemd.journal_tail` is available only when explicitly allowed by the target policy. It accepts a registered unit and at most 50 lines, enforces a 10-second maximum timeout and a 64 KiB remote-output cap, and redacts common credential patterns. Logs remain sensitive and redaction is not exhaustive; keep the action default-deny unless the data handling is approved.
- `network.resolver_config` reads at most 4 KiB from `/etc/resolv.conf` and reports configured nameservers/search domains. It does not perform a DNS query and does not establish that resolution works. It also remains subject to the normal per-host default-deny policy.
- Provider timeouts, invalid JSON, unknown diagnostic IDs, unsupported evidence references, or policy denial stop the investigation. No tool call is retried and no recommendation is executed.
- For local host inference from a VM, use a dedicated tunnel identity and pinned host key. Start `runbookos tunnel config/tunnel.yml` in a supervised terminal, then run `investigate` in another shell with `RUNBOOKOS_LLAMA_API_KEY` present. Do not put the API key in command arguments or shell history. Stop the tunnel with Ctrl-C after the investigation. No service persistence is configured by RunbookOS.

## Approval and access

The local OS username is recorded as the approval actor. The operator must state a useful change/incident reason. The approval stores the plan hash, expires in 900 seconds by default, and is consumed atomically before dispatch. A policy denial cannot be overridden by approval. Do not grant remediation in policy until the target OS permissions and recovery procedure are reviewed. No action invokes sudo.

## Recovery

If the controller process stops, inspect SQLite history. If a row remains `running`, classify the result as uncertain; RunbookOS does not resume or retry an in-flight plan or investigation. Restore the SQLite DB from a protected backup if damaged, then run `audit`; do not edit chain rows to make verification pass. A lost DB also loses local plan/approval/investigation state, so re-plan and obtain fresh approval.

### Schema-v4 backup and restore rehearsal

Use a fresh private directory and a destination that does not already exist. The SQLite backup API produces a consistent copy while WAL mode is active:

```sh
umask 077
install -d -m 700 "$BACKUP_DIR"
test ! -e "$BACKUP_DIR/runbookos.sqlite3"
python - "$DB_PATH" "$BACKUP_DIR/runbookos.sqlite3" <<'PY'
import sqlite3, sys
source, destination = sys.argv[1:]
with sqlite3.connect(f"file:{source}?mode=ro", uri=True) as src:
    with sqlite3.connect(destination) as dst:
        src.backup(dst)
with sqlite3.connect(f"file:{destination}?mode=ro", uri=True) as restored:
    assert restored.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
    assert restored.execute("PRAGMA foreign_key_check").fetchall() == []
    assert restored.execute("PRAGMA user_version").fetchone()[0] == 4
PY
chmod 600 "$BACKUP_DIR/runbookos.sqlite3"
runbookos --db "$BACKUP_DIR/runbookos.sqlite3" audit
```

The repository regression suite exercises the SQLite backup API on a disposable schema-v4 database and checks incident links and the audit chain. For recovery, restore to a **new** path, run integrity, foreign-key, and audit checks there, and compare expected configuration/identity references. Do not overwrite the active database or change its configured path without separate deployment authorization. Schema downgrade is unsupported; package rollback does not roll back a database migration.

For a controller or managed-host outage, use the environment owner's independent console/recovery path. RunbookOS does not change network topology, firewall policy, or install agents as part of diagnosis. Its optional inference tunnel is foreground-only and must be stopped by its operator; RunbookOS does not create a service unit or auto-start configuration.

For synthetic incident fixtures and evaluation semantics, see [incident-evaluation.md](incident-evaluation.md). `runbookos evaluate` does not connect to managed hosts or inject faults.

## SSH access changes

Provisioning or rolling back a managed account is an operator-approved environment change and is outside automatic RunbookOS execution. Keep exact key fingerprints and before/after metadata in the environment's protected change record. Remove only the exact authorized key entry introduced for the change; preserve administrator accounts, unrelated keys, and SSH configuration. Do not change routes, firewall policy, sshd, or services to work around reachability without separate approval.
