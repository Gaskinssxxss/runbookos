# Integrated Dashboard Staging Acceptance Procedure — v0.4.0

**Approval gate:** this procedure is prepared only. Do not run it until the operator explicitly approves the exact scope in [`dashboard-staging-approval-v0.4.0.yml`](dashboard-staging-approval-v0.4.0.yml). Approval for prior Alertmanager acceptance does not authorize these dashboard processes or additional SQLite records.

## State and process scope

The inspected isolated staging tree is `.runbookos-staging-v032/` (mode 0700). At preparation time the existing bridge and webhook were stopped; the isolated SQLite file exists with mode 0600. Use only that staging tree, existing staging credentials/configuration, and the existing isolated SQLite file. Do not touch the operational database. Install v0.4.0 into a new `dashboard-venv` under this staging root so the existing bridge/webhook virtual environment remains unchanged. The wheel is built into a staging-local `artifacts/` directory, and only declared runtime dependencies may be installed. The additional verifier is created at `run/dashboard-auth-v040.json` with mode 0600 by the `auth-init` command; its password is entered interactively and is never written in plaintext.

Temporary listeners:

| Process | Bind | Purpose |
|---|---|---|
| Existing webhook | `127.0.0.1:8765` | HMAC-authenticated normalized alert ingestion |
| Existing signing bridge | `127.0.0.1:8764` | Authenticated Alertmanager-shaped delivery and signing |
| Dashboard | `127.0.0.1:8780` | Authenticated operator view and lifecycle controls |

No reverse proxy, public bind, SSH, Qwen, remediation, or persistent service is involved. The acceptance creates one synthetic incident, related alert/link/audit rows, a fresh replay nonce per bridge delivery, and lifecycle audit events. It does not edit pre-existing incidents. Duplicate firing delivery should not add another alert or incident. The resolved update should link to the same incident but must not resolve it automatically. Expected SSH executions, investigations, and remediation events are all zero.

## Preflight and startup

1. Confirm the repository is the reviewed v0.4.0 branch and the isolated staging directory is still ignored. Do not print `.env`, the bridge password, HMAC key, or Authorization headers.
2. Run `python3 scripts/staging-v032.py status`. Continue only if both `bridge` and `webhook` report stopped and the staging database exists. If either process is active, abort rather than stopping/adopting it.
3. Confirm ports 8764, 8765, and 8780 are available. Abort if any is held by an unknown process.
4. Confirm the paths and permissions in the approval manifest, and confirm `dashboard-venv`, `artifacts/`, and the new auth verifier path do not already exist. Do not edit bridge/webhook credentials or configuration.
5. Build and install the local wheel into the separate dashboard environment. The install may download only the runtime dependency families listed in the approval manifest, including their declared transitive dependencies; do not install development tools:

   ```sh
   mkdir -m 700 .runbookos-staging-v032/artifacts
   .venv/bin/python -m build --no-isolation --wheel \
     --outdir .runbookos-staging-v032/artifacts
   python3 -m venv .runbookos-staging-v032/dashboard-venv
   .runbookos-staging-v032/dashboard-venv/bin/pip install \
     .runbookos-staging-v032/artifacts/runbookos-0.4.0-py3-none-any.whl
   .runbookos-staging-v032/dashboard-venv/bin/runbookos version
   ```

   Confirm version output is 0.4.0 before proceeding. If the version differs or dependency installation needs additional packages, stop for review.

6. Create the separate dashboard password verifier interactively:

   ```sh
   ./.runbookos-staging-v032/dashboard-venv/bin/runbookos dashboard auth-init \
     --operator-id dashboard-staging-operator \
     --auth-file ./.runbookos-staging-v032/run/dashboard-auth-v040.json
   ```

7. Start the existing isolated bridge and webhook using `python3 scripts/staging-v032.py start`. This is permitted only after approval and only from the stopped preflight state. Confirm their status and listeners remain on loopback.
8. In a second terminal, start the dashboard using the staging SQLite and exact staging config:

   ```sh
   ./.runbookos-staging-v032/dashboard-venv/bin/runbookos \
     --inventory ./.runbookos-staging-v032/config/inventory.yml \
     --policy ./.runbookos-staging-v032/config/policy.yml \
     --ssh-profiles ./.runbookos-staging-v032/config/ssh_profiles.yml \
     --db ./.runbookos-staging-v032/state/runbookos.sqlite3 \
     dashboard serve --auth-file ./.runbookos-staging-v032/run/dashboard-auth-v040.json \
     --host 127.0.0.1 --port 8780
   ```

## Synthetic alert delivery

Use a short-lived Python harness (standard library only) to construct an Alertmanager v2-shaped payload in memory and POST it to `http://127.0.0.1:8764/api/v2/alerts`. The harness reads the already-provisioned `.env` file in memory, constructs Basic authentication in memory, and must print only HTTP status codes, never secrets or headers. A sample follows; run it from the repository root only after the approval gate is satisfied.

```python
import base64, http.client, json, secrets
from datetime import UTC, datetime
from pathlib import Path

env = {}
for line in Path(".runbookos-staging-v032/.env").read_text().splitlines():
    key, _, value = line.partition("=")
    env[key] = value
auth = base64.b64encode(
    f"{env['RUNBOOKOS_BRIDGE_USER']}:{env['RUNBOOKOS_BRIDGE_PASSWORD']}".encode()
).decode("ascii")
fingerprint = secrets.token_hex(16)
group_key = "dashboard-v040-" + secrets.token_hex(8)
now = datetime.now(UTC).isoformat().replace("+00:00", "Z")
labels = {
    "alertname": "RunbookOSDashboardAcceptance",
    "target_alias": "example-web-01",
    "service": "nginx",
    "category": "service",
    "severity": "warning",
}
summary = "v040-dashboard-acceptance-" + secrets.token_hex(8)

def send(status):
    end = (
        datetime.now(UTC).isoformat().replace("+00:00", "Z")
        if status == "resolved"
        else "0001-01-01T00:00:00Z"
    )
    payload = {
        "version": "4", "status": status, "receiver": "runbookos-staging",
        "groupKey": group_key, "groupLabels": {"alertname": labels["alertname"]},
        "commonLabels": labels, "commonAnnotations": {"summary": summary},
        "externalURL": "http://localhost/unused", "alerts": [{
            "status": status, "labels": labels,
            "annotations": {"summary": summary}, "startsAt": now,
            "endsAt": end, "generatorURL": "http://localhost/unused",
            "fingerprint": fingerprint,
        }],
    }
    body = json.dumps(payload, separators=(",", ":")).encode()
    connection = http.client.HTTPConnection("127.0.0.1", 8764, timeout=5)
    connection.request("POST", "/api/v2/alerts", body, {
        "Authorization": "Basic " + auth,
        "Content-Type": "application/json",
    })
    response = connection.getresponse()
    response.read(4096)
    code = response.status
    connection.close()
    print("delivery HTTP status:", code)
    if code != 200:
        raise SystemExit("delivery failed; do not broaden access or retry blindly")

send("firing")
send("firing")  # semantic duplicate; bridge issues a fresh nonce per request
send("resolved")
```

Use a newly generated random fingerprint and `groupKey`, labels `target_alias=example-web-01`, `service=nginx`, `category=service`, `severity=warning`, and a summary prefixed `v040-dashboard-acceptance-` followed by a random identifier. Send the exact same firing payload twice. Then send a resolved payload with the same `groupKey`, fingerprint, and labels, setting both group and alert status to `resolved`. Do not run a real Alertmanager process for this procedure; real process delivery remains the separate v0.3.2 acceptance evidence.

Inspect the isolated database using the existing staging CLI. Capture the incident IDs before sending; verify exactly one new incident and the expected firing/resolved alert linkage. Verify no pre-existing incident changed. Do not use database reset, migration rollback, or delete records.

## Operator workflow and evidence

1. Sign in at `http://127.0.0.1:8780/`; verify that unauthenticated requests do not reveal incident records.
2. Open the newly generated incident. Verify source alert history, correlation reason, timeline, target/service, timestamps, and valid audit-chain status.
3. Acknowledge from the dashboard with a reason. Confirm the authenticated operator identity—not alert content or a form field—is the event actor.
4. To exercise dashboard resolution without running SSH or AI, use the explicitly approved harness-only call to `IncidentStore.mark_investigating(new_incident_id, trusted_operator_id)`. Record that this is a synthetic lifecycle transition only; it creates no investigation or evidence.
5. Resolve in the dashboard with `evidence_status=not_available` and a reason. Verify the timeline records both evidence status and operator attestation. Do not select `verified` without linked verified references.
6. Close in the dashboard with a reason. Verify status, actor, reason, and timeline.
7. Using a temporary test client that keeps the authenticated session cookie only in memory, submit a lifecycle POST without the session-bound CSRF token and confirm HTTP 403; do not log the cookie or use a valid token for this negative check.
8. Verify the staging CLI `audit` command reports a valid hash chain and execution/investigation counts have not increased.

## Restart and cleanup

1. Save the authenticated session cookie only in the temporary test client/browser memory. Stop the dashboard with Ctrl-C, restart it with the same command, and confirm the old cookie is redirected to login. Re-authenticate and verify the synthetic closed incident is still present. The one-hour expiry behavior is covered by the automated unit test; the process acceptance verifies restart invalidation without waiting an hour.
2. Verify the audit hash chain again and verify the pre-existing incident snapshot is unchanged.
3. Stop dashboard. Run `python3 scripts/staging-v032.py stop` only if preflight showed both bridge/webhook stopped and this acceptance started them.
4. Confirm all three listeners are stopped. Preserve SQLite and logs as evidence. Remove only the newly created dashboard verifier if the approved cleanup scope includes it; do not remove `.env`, prior credentials, prior state, or prior logs.

## Required report

Record process/listener status, number of synthetic deliveries (three), new alert/incident counts, duplicate result, lifecycle states, exact audit verification result, zero execution/investigation count, restart persistence, cookie invalidation, cleanup status, and any deviations. Label this as **synthetic bridge/webhook staging acceptance**, separate from the prior real Alertmanager process test. It is not natural monitoring-rule, live SSH/AI, or operational deployment acceptance.
