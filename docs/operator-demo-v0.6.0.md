# RunbookOS v0.6.0 — Reproducible Operator Demo

This optional demo exercises the incident-to-remediation workflow using a new temporary SQLite database, a loopback-only authenticated webhook, a temporary authenticated dashboard, synthetic alerts, and a fake executor. It does not connect to a host. Its only configured target is `docs-test-web` at the documentation-only TEST-NET address `192.0.2.42`; the demo executor asserts that target before returning any synthetic result.

The fake executor is confined to `scripts/demo-v060.py` and the existing engine's embedded/test injection interface. It is not a production CLI option. Production CLI execution continues to use the configured OpenSSH adapter and normal policy, plan, approval, confirmation, audit, and postflight controls. The demo has no target override.

The authenticated webhook and dashboard bind to `127.0.0.1` on ephemeral ports. The demo uses generated HMAC material and a generated dashboard password in process memory; it does not print them. The dashboard verifier, configuration, and SQLite file live under a temporary directory and are removed when the script exits. Do not interrupt cleanup with `SIGKILL`; if the process is forcibly killed, inspect and remove only the printed demo temporary directory after verifying its prefix and contents.

## 1. Fresh isolated install

Run from a clean checkout of the v0.6.0 source. The commands use fresh tooling and demo venvs and place build artifacts outside the repository:

```bash
python3 -m venv /tmp/runbookos-v060-build-venv
/tmp/runbookos-v060-build-venv/bin/python -m pip install -r requirements-ci-py312.lock
mkdir -p /tmp/runbookos-v060-dist
/tmp/runbookos-v060-build-venv/bin/python -m build --wheel --sdist --outdir /tmp/runbookos-v060-dist

python3 -m venv /tmp/runbookos-v060-demo-venv
/tmp/runbookos-v060-demo-venv/bin/python -m pip install -r requirements-ci-py312.lock
/tmp/runbookos-v060-demo-venv/bin/python -m pip install --no-deps /tmp/runbookos-v060-dist/runbookos-0.6.0-py3-none-any.whl
```

The build frontend uses isolated PEP 517 build dependencies pinned in `pyproject.toml`. The CI/tooling venv is pinned by `requirements-ci-py312.lock`; using the complete lock in the demo venv also fixes runtime dependency versions. Do not reuse a stale project `.venv` or install a system-wide service.

Confirm parity:

```bash
/tmp/runbookos-v060-demo-venv/bin/python -c 'from importlib.metadata import version; import runbookos; assert version("runbookos") == runbookos.__version__ == "0.6.0"'
/tmp/runbookos-v060-demo-venv/bin/runbookos version
```

## 2. Run the isolated demonstration

From the source checkout containing `scripts/demo-v060.py`:

```bash
/tmp/runbookos-v060-demo-venv/bin/python scripts/demo-v060.py
```

The script creates its own synthetic inventory, default-deny policy with only the demo's explicit action grants, unused SSH profile paths, diagnostic/remediation runbooks, and fresh SQLite database. `192.0.2.42` is not contacted: all engine actions are sent to the fake executor. No SSH identity is read.

The walkthrough performs:

1. Authenticated synthetic firing, duplicate, replay, and resolved webhook deliveries. Resolution of an alert does not close the incident.
2. Operator acknowledgment and a registered read-only diagnostic via the fake executor, with persisted, linked evidence references.
3. Deterministic remediation plan preview and incident-plan association through the existing operator CLI command. Association creates neither approval nor execution.
4. One-time plan-bound approval and explicit confirmation for fake execution; preflight and postflight assertions are evaluated by the existing engine.
5. An isolated `UNKNOWN` outcome case demonstrating that no automatic retry or rollback occurs.
6. Dashboard login, incident/evidence/remediation review, and rejected approval/execution browser paths.
7. Explicit operator resolution and closure in the primary synthetic workflow, followed by SQLite integrity, foreign-key, and audit-chain checks.

The CLI app is invoked in-process by the demo harness for operator commands. Only the demo process substitutes its engine instance with the fake executor. Do not copy this substitution into application startup, production CLI flags, webhook handling, or dashboard routes.

## 3. Interpreting output

The script emits JSON containing synthetic incident, investigation, plan, execution, and evidence-reference IDs; record counts; integrity results; whether the loopback processes stopped; and a statement that all execution calls used the fake executor. These IDs are generated per run. The temporary database and verifier are deleted automatically, so save only the redacted console summary if a demonstration record is needed. Do not save the temporary database as operational history.

The demonstration is not a real SSH, service restart, Alertmanager process, monitoring rule, AI inference, or deployment acceptance. A real Alertmanager v0.3.2 acceptance passed historically in a separate isolated staging activity; it is distinct from this synthetic demonstration.

## 4. SQLite backup and recovery

The v0.6.0 schema is additive schema v4. Back up an operational SQLite database before a real upgrade using the documented SQLite online-backup procedure in `docs/operations.md`, verify the backup with `PRAGMA integrity_check`, and retain a protected copy before migration. Downgrade from schema v4 is unsupported. Recovery from an upgrade problem is a controlled restore of a verified pre-upgrade backup; do not overwrite newer audit history without an explicit recovery decision.

This demo never opens or migrates an operational database. Its temporary database is disposable and is removed with its temporary directory after normal exit.

## 5. Cleanup and stop behavior

The webhook server is shut down and joined; the dashboard subprocess is terminated and waited for with a bounded timeout; the temporary dashboard verifier is removed; and `TemporaryDirectory` removes generated configuration and SQLite state. The script reports process shutdown and verifier cleanup status. If an assertion fails, `finally` cleanup still runs for started listeners and the dashboard.

Do not run the demo with a modified copy that points to real targets, persistent databases, non-loopback listeners, SSH credentials, or services. No persistent service is installed or started.
