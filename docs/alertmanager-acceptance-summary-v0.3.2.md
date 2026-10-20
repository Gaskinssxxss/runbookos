# Sanitized Alertmanager Acceptance Summary — v0.3.2

## Result

Real Prometheus Alertmanager **v0.34.1** was exercised as a temporary foreground process on Linux AMD64 against the isolated RunbookOS staging signing bridge and webhook. The official release archive SHA-256 verified as `265b9d1e55ef0d5306a436018af6d2b686c2ce051f03d968f7464ecb1372a7e8` before extraction; the tested executable SHA-256 was `154890307c382a186d4ddf9354cfa0cab08771f818aac1e647d0cf277ecef854`.

The test submitted synthetic firing and resolved notifications through Alertmanager's API and verified downstream webhook delivery, bridge authentication, RunbookOS HMAC validation, deterministic duplicate handling, persistence across staging process restart, and audit-chain integrity. Ingestion created no SSH execution and invoked no AI or remediation. Acceptance processes were stopped after the test. The isolated staging records were retained locally and are not part of this repository.

## Evidence level and limits

- **Real Alertmanager process and delivery:** passed for synthetic alerts.
- **Alertmanager API submission, duplicate delivery, and resolved update behavior:** passed; a resolved notification did not itself close the incident.
- **Staging persistence and audit verification:** passed after restart.
- **Naturally triggered monitoring rule:** not tested; this does not establish a live Prometheus rule-to-alert path.
- **Live SSH diagnostics, live Qwen inference, and operational deployment:** not run.

This summary intentionally excludes host-specific staging locations, credentials, logs, database contents, alert payloads, nonces, and incident identifiers.
