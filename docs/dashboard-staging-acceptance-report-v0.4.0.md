# RunbookOS v0.4.0 — Integrated Dashboard Staging Acceptance Report

**Date:** 2026-10-20  
**Scope:** Temporary loopback-only synthetic staging acceptance, under the approval in [`dashboard-staging-approval-v0.4.0.yml`](dashboard-staging-approval-v0.4.0.yml).

## Verdict

The integrated synthetic workflow **passed** through alert delivery, authenticated operator actions, incident persistence, and audit verification. No live SSH diagnostics, Qwen inference, remediation, or operational deployment occurred.

The acceptance has two recorded limitations:

- The incident queue does not display the summary or source; those appear in incident detail.
- The dashboard timeline omits `from_status` and `to_status` columns. Those transitions are present and correctly ordered in the SQLite incident timeline and hash-chained audit, but are not explicit in the rendered table. Treat transition-state presentation as a dashboard usability gap.

## Staging artifacts and processes

The existing isolated database was `.runbookos-staging-v032/state/runbookos.sqlite3` (SQLite schema v3, file mode `0600`). The new dashboard environment was `.runbookos-staging-v032/dashboard-venv/`; the staging-local wheel was `.runbookos-staging-v032/artifacts/runbookos-0.4.0-py3-none-any.whl`.

The installed CLI reported `RunbookOS 0.4.0`. Wheel SHA-256:

```text
3280f405d4828661f1160bb6c20fdafd0e608865f5edd73843d0dac8f9b83249
```

The wheel was copied from the previously verified local release artifact after a fresh build attempt failed because the repository build environment lacked `setuptools.build_meta`. The wheel metadata was v0.4.0, all 23 Python modules matched the current source byte-for-byte, and only declared runtime dependencies and their transitive dependencies were installed. No build tooling was downloaded or added. The password verifier was generated with a cryptographically random password held only in the harness process, created at mode `0600`, and removed after testing. No password, HMAC key, Authorization header, or credential value was printed or added to the report.

Temporary listeners were:

| Process | Bind | Result |
|---|---|---|
| Signing bridge | `127.0.0.1:8764` | Started from the existing staging launcher and stopped after delivery. |
| Webhook | `127.0.0.1:8765` | Started from the existing staging launcher and stopped after delivery. |
| Dashboard | `127.0.0.1:8780` | Started as a foreground staging process; stopped and restarted for persistence/session checks, then stopped. |

`ss` confirmed loopback-only listeners. At final cleanup, launcher status reported bridge and webhook stopped, no listener remained on any of the three ports, the dashboard verifier was removed, and the SQLite database was preserved.

## Alert delivery and incident

The sender was an in-memory Alertmanager v2-shaped fixture sent to the existing bridge. This was not a real Alertmanager process or a naturally triggered monitoring rule.

- Invalid bridge Basic authentication: **401**, rejected before delivery.
- Correct staging Basic credentials with an intentionally invalid content type: **415**, confirming authentication without forwarding or changing alert state.
- Accepted delivery requests: **3** (`firing`, exact duplicate `firing`, and `resolved`), all returned **200**.
- Authenticated source identity: `alertmanager-staging`.
- New incident: `3687deeb-cf84-4265-9151-afe8601bd943`.
- New alert IDs:
  - `am-2e5e14c2d04c66bb0fe778d526f5b3f23ab297eb918679d9`
  - `am-177a046899f3371015f6638ac48b1e0b0baa3c951fc9d8b7`
- The duplicate firing delivery produced a duplicate audit event and no extra alert or incident.
- The resolved notification linked to the same incident and did **not** automatically resolve or close it.

The staging database contained 5 alerts, 3 incidents, and 5 incident-alert links before the accepted synthetic delivery sequence. Afterwards it contained 7 alerts, 4 incidents, and 7 links: two distinct alert rows (firing and resolved), two links, and exactly one new incident. The repeated firing delivery added no alert row.

The database had 12 nonce rows at initial preflight. The normal webhook replay-retention cleanup discarded expired entries during accepted ingestion; the final table contained 3 distinct, recent nonce records, one for each accepted request. No raw nonce value is included here.

## Authenticated dashboard workflow

The dashboard view and lifecycle actions were exercised over loopback:

| Check | Result |
|---|---:|
| Unauthenticated incident queue request | 303 to login; no incident record exposed |
| Unauthenticated lifecycle POST | 401 |
| Invalid login | 401 |
| Valid login | 303; authenticated session established |
| Session cookie | `HttpOnly`, `SameSite=Strict`, `Path=/`, one-hour max age; no `Secure` attribute on the loopback-only HTTP listener |
| CSRF POST without token | 403 |
| Acknowledge | 303, actor `dashboard-staging-operator` |
| Resolve as `verified` with no linked evidence | 409, rejected |
| Resolve as `not_available` | 303 |
| Close with a reason | 303 |
| Old session cookie after process restart | 303 to login |
| Re-login after restart and incident queue/detail | Incident remained `CLOSED`; state persisted |

The audited status sequence was:

```text
NEW → ACKNOWLEDGED → INVESTIGATING → RESOLVED → CLOSED
```

`INVESTIGATING` was a harness-only `IncidentStore` transition with the explicit reason “synthetic acceptance transition; no diagnostics executed”. It did not run a runbook and did not create an investigation or execution record. Resolution used `evidence_status=not_available`; no diagnostic evidence was asserted or fabricated. The dashboard detail page rendered alert correlation, actor, reasons, and evidence status. The database timeline and audit payloads retained each from/to status, although the page does not currently render those two fields.

No XSS payload was introduced into staging data. Existing dashboard security regression tests cover escaping; the synthetic summary was rendered as plain text in this acceptance.

## Database and audit evidence

| Measure | Initial preflight | Final |
|---|---:|---:|
| Alerts | 5 | 7 |
| Incidents | 3 | 4 |
| Incident-alert links | 5 | 7 |
| Incident timeline rows | 5 | 11 |
| Audit events | 24 | 36 |
| Retained webhook nonce rows | 12 | 3 recent unique nonces |
| Executions | 0 | 0 |
| Investigations | 0 | 0 |

The final audit chain verified **36/36 events** and SQLite `PRAGMA integrity_check` returned `ok`. The 12 added audit events comprise three webhook keyring-load events from temporary startup/retry cycles, five alert ingestion/correlation/deduplication events, and four operator lifecycle transitions. The event payloads after the original 24-event baseline refer only to the new synthetic incident and its two alerts; no pre-existing incident was transitioned.

All three pre-existing incidents remained outside the synthetic workflow. No execution or investigation rows were added. The only SQLite writes were staging alert/incident, replay-retention, and audit records described above.

## Failures and deviations

Several harness attempts stopped safely before completing the workflow:

1. The first harness could not import RunbookOS from the system interpreter. It stopped before starting services or writing alert data.
2. The next harness incorrectly expected the incident summary to appear in the queue. The queue intentionally shows severity, status, target, service, and update time; the summary is in incident detail. The alert delivery itself had succeeded and was not repeated in later workflow tests.
3. One initial delivery harness request received HTTP 401. No incident was created by that request. A subsequent scoped check proved bad credentials returned 401 and the existing staging credentials passed bridge authentication (415 at the deliberately invalid content-type check); the final three deliveries all returned 200. No credentials or configuration were changed.
4. An immediate dashboard restart returned `EADDRINUSE` because a prior loopback connection remained in `TIME_WAIT` and the server has address reuse disabled. After the socket cleared, restart, old-session invalidation, and persistence checks succeeded without changing the port or server configuration.
5. A final rendered-timeline assertion expected state names in the HTML. The page omits `from_status`/`to_status`, so that assertion did not pass. Read-only inspection confirmed the dashboard-rendered event rows and that the complete transition sequence and reasons persisted in SQLite and audit. This remains a presentation gap, not a state or audit integrity failure.

No source code, homelab VM, firewall, route, SSH configuration, operational database, persistent service, or Git history was changed. The existing `tests/test_dashboard.py` suite passed: **6 passed**.

## Final acceptance classification

- Synthetic bridge/webhook delivery: **PASS**.
- Authentication, deduplication, and resolved-notification behavior: **PASS**.
- Dashboard authenticated lifecycle: **PASS**.
- Evidence status and rejection of unsupported `verified`: **PASS**.
- Incident persistence and session invalidation after restart: **PASS**, after waiting for the prior loopback socket to leave `TIME_WAIT`.
- Audit chain and SQLite integrity: **PASS**.
- Dashboard timeline state-transition presentation: **PARTIAL**; storage is correct, rendered transition endpoints are omitted.
- SSH diagnostics: **NOT RUN**.
- Qwen/live AI inference: **NOT RUN**.
- Remediation: **NOT RUN**.
- Operational deployment: **NOT AUTHORIZED / NOT RUN**.

