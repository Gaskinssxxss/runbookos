# RunbookOS v0.3.2 — Staging Acceptance

## Evidence classification

| Acceptance layer | Result | Evidence |
|---|---|---|
| Synthetic fixture and unit tests | **PASS** | Bridge validation, credentials, size limit, unavailable downstream, provider payload normalization, strict HMAC, replay, and incident lifecycle tests. |
| Isolated staging runtime walkthrough | **PASS** | Local venv, generated isolated credentials/config/state, loopback bridge and webhook startup, signed Alertmanager-shaped delivery, duplicate delivery, status, clean stop, and state verification. |
| Real Alertmanager process | **NOT RUN** | No Alertmanager binary/container/process was installed or started. |
| Real monitoring-generated alert | **NOT RUN** | No monitoring source was connected. |
| Real SSH diagnostics | **NOT RUN** | End-to-end diagnostic dispatch uses a fake SSH executable; no live host was contacted. |
| AI live inference | **NOT RUN** | AI remains optional; provider behavior is covered by existing mocked tests. |
| Operational deployment | **NOT AUTHORIZED** | No homelab/host service, firewall, route, account, SSH, or operational database was changed. |

The local staging launcher was exercised with its actual isolated venv and loopback processes. It created a mode-0700 staging tree, mode-0600 auth/environment/password files, started both processes on 127.0.0.1, accepted two identical synthetic deliveries, and showed `alerts=1`, `incidents=1`, `executions=0`, `webhook_nonces=2`. The audit chain was valid with 5 events after ingestion and 6 after the subsequent webhook restart/keyring audit event. `restart`, `status`, and `stop` succeeded; the SQLite file was preserved and final process status was stopped. No command secret was printed. This runtime walkthrough is distinct from the automated fake-SSH diagnostic test below.

## End-to-end workflow exercised offline

1. Local Alertmanager-shaped JSON arrives at the bridge with Basic authentication.
2. Bridge verifies the sender, creates a new timestamp/nonce, signs the unchanged raw body, and forwards only to loopback.
3. Existing RunbookOS HMAC middleware authenticates the configured source and the existing Alertmanager adapter validates and normalizes the payload.
4. SQLite ingestion commits before the bridge acknowledges. A second identical delivery uses a distinct nonce and is deduplicated to the same incident.
5. CLI lists/shows the incident; an operator acknowledges it.
6. A separate explicit CLI call runs a target-scoped, policy-allowed read-only runbook through the existing planner/engine and fake SSH fixture.
7. Successful step evidence is linked to the incident. Resolution is marked `verified` only with valid evidence references, followed by operator closure.
8. Webhook restart reopens the same SQLite state; timeline and audit chain remain valid.

Automated E2E tests use temporary directories and SQLite databases. They do not touch local operational state or the homelab operational database.

## Recovery and failure behavior

- Bridge unavailable, timeout, redirect, malformed downstream receipt, or non-200 response returns non-success to the sender. No success is acknowledged before a durable RunbookOS receipt.
- Sender retry receives a fresh cryptographic nonce and timestamp; the RunbookOS persistent nonce table validates replay while alert fingerprint/idempotency prevents a duplicate incident.
- A process interruption before SQLite commit is covered by transaction rollback regression tests. A process interruption after commit followed by duplicate delivery preserves one alert/incident.
- Staging `stop` terminates bridge and webhook only; state and SQLite are preserved. `restart` starts the same isolated paths.
- Existing backup/restore test uses SQLite backup API and verifies incident plus hash chain. Staging data is not auto-deleted.

## Staging walkthrough

From repository root, after reviewing and accepting dependency installation into a dedicated local venv:

```sh
python3 scripts/staging-v032.py init
python3 scripts/staging-v032.py start
python3 scripts/staging-v032.py status
```

The launcher writes generated secrets into `.runbookos-staging-v032/.env` with mode 0600 and the sender password to a separate mode-0600 password file; it never prints them and refuses to overwrite an existing staging directory. Configure Alertmanager with the example in [`../examples/alertmanager/receiver.example.yml`](../examples/alertmanager/receiver.example.yml), pointing `password_file` at that generated file. To stop without deleting data:

```sh
python3 scripts/staging-v032.py stop
```

State is retained in `.runbookos-staging-v032/state/runbookos.sqlite3`. Do not point this staging launcher at an operational database, SSH key, inventory, or policy. Generated local staging state is ignored by Git.

This walkthrough is a local development harness. It is not approval to run a persistent or network-reachable listener.

After an alert is ingested, the operator uses the staging paths explicitly:

```sh
R='./.runbookos-staging-v032/venv/bin/runbookos'
COMMON="--inventory .runbookos-staging-v032/config/inventory.yml --policy .runbookos-staging-v032/config/policy.yml --ssh-profiles .runbookos-staging-v032/config/ssh_profiles.yml --db .runbookos-staging-v032/state/runbookos.sqlite3"
$R $COMMON incidents list
$R $COMMON incidents show INCIDENT_ID
$R $COMMON incidents acknowledge INCIDENT_ID --reason 'reviewed alert'
$R $COMMON incidents investigate INCIDENT_ID --runbook examples/runbooks/web-server-health.yml
$R $COMMON incidents timeline INCIDENT_ID
```

The sample inventory uses documentation-only addresses, so it is suitable for validation/plan inspection but cannot provide real SSH evidence. On an explicitly approved disposable SSH target, configure a separate staging inventory/profile and diagnostic-only policy. Resolve with `--evidence-status verified` only after valid evidence is linked; otherwise use an explicit `not_available` or `inconclusive` operator attestation. Then close with a recorded reason. Never point this staging database at operational state.
