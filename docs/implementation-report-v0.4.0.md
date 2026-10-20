# RunbookOS v0.4.0 — Operator Dashboard MVP Report

## Implementation

- Added an optional standard-library HTTP dashboard on loopback; no web framework or runtime dependency was added.
- Added local password-verifier initialization, PBKDF2-HMAC-SHA256 verification, in-memory expiring sessions, login throttling, CSRF checks, secure response headers, and escaped HTML rendering.
- Reused the existing SQLite store and `IncidentStore` lifecycle methods. The dashboard supports filtering, detail, alert correlation, timeline, linked investigation/evidence-reference overview, and acknowledge/resolve/close transitions.
- Investigation execution is intentionally CLI-only in this MVP. No AI, SSH, runbook execution, or remediation path is reachable from the dashboard.
- Added a sanitized summary of the successful real Alertmanager v0.3.2 acceptance. Local staging secrets, logs, payloads, and SQLite state remain excluded.

## Verification

Recorded after implementation checks:

- Full suite: 116 passed, 11 opt-in live tests skipped; final fresh coverage output 75.90% (reconciles earlier 75.4%, 75.99%, 76.17%, and 76.18% reports from prior source snapshots).
- Ruff lint and formatting: passed.
- CLI smoke: `runbookos version` reports 0.4.0 and `runbookos dashboard --help` lists `auth-init` and `serve`.
- Local authenticated HTTP workflow: passed against a temporary SQLite database, including restart persistence and audit-chain verification.
- Wheel and sdist: built successfully; archive content checks passed. Fresh virtualenv installs of both artifacts reported matching package/import version 0.4.0, and installed CLI smoke passed.
- `detect-secrets` 1.5.0: zero findings on the exact 17 staged files exported from the Git index.
- Staged path allowlist: exact match, 17/17 files, no extra or missing paths.
- `git diff --check`: passed.
- Operational deployment, live SSH, and live AI: not run.

## Acceptance boundaries

- Offline integration: **PASS** — temporary SQLite, synthetic alert, authenticated lifecycle workflow, restart persistence, and audit check.
- Local dashboard smoke: **PASS** — authenticated HTTP flow exercised by tests on loopback.
- Isolated persistent staging dashboard: **NOT RUN** — no persistent dashboard process was started.
- Real Alertmanager process/delivery: **PASS (v0.3.2 acceptance carried forward)** — synthetic alert delivery as summarized in `alertmanager-acceptance-summary-v0.3.2.md`; no natural monitoring rule was tested.
- Live SSH: **NOT RUN**.
- Live AI inference: **NOT RUN**.
- Operational deployment/public exposure: **NOT AUTHORIZED**.

- The dashboard serves plain HTTP on loopback, does not provide TLS or external identity integration, and requires a protected local auth verifier file.
- Integrated persistent staging acceptance is **pending explicit operator approval** in `dashboard-staging-approval-v0.4.0.yml`; its procedure uses a dedicated v0.4.0 staging virtual environment and the isolated v0.3.2 SQLite file, without modifying prior incident records.
