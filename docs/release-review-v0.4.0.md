# RunbookOS v0.4.0 Release Review

## Baseline and source review

- Expected branch: `feat/v0.4.0-operator-dashboard`.
- Reviewed baseline: `54cf7e5f3003713aac6a1444804754cf149c9db2`.
- v0.4.0 changes add an optional standard-library dashboard and CLI commands. Existing `IncidentStore` remains the sole lifecycle implementation; dashboard does not add execution, SSH, AI, approval, or remediation routes.
- No runtime or development dependencies were added. Existing dependency constraints and pinned CI action SHAs remain unchanged.
- The Alertmanager v0.3.2 acceptance summary is sanitized. It contains public release checksums and omits local paths, credentials, logs, payload records, nonces, and SQLite contents. The earlier v0.3.2 staging report is explicitly labeled historical to explain the later real-process acceptance.

## Security review

- Dashboard is disabled by default and accepts only `127.0.0.1` as bind address.
- Auth verifier is opened with `O_NOFOLLOW`, checked with `fstat` for regular-file type, current-user ownership, and no group/other permissions; JSON schema, digest, operator identity, and PBKDF2 iteration bounds are validated.
- Passwords are prompted hidden and stored only as salted PBKDF2-HMAC-SHA256 digests. Failed login attempts are limited to five per five-minute window per local address; requests are bounded to 16 concurrent sockets with a 10-second timeout; live sessions are capped at 256 and expire after one hour.
- Session cookie uses `HttpOnly`, `SameSite=Strict`, `Path=/`, and a bounded `Max-Age`; it has no `Secure` attribute because the MVP is plain HTTP on loopback. Do not proxy or expose it beyond loopback.
- Every state-changing POST checks a per-session CSRF token. Actor identity comes from protected auth configuration, not request content.
- Alert, timeline, and model-originated text is HTML-escaped. No external resources are loaded. CSP, `nosniff`, and `no-store` headers are sent.
- Lifecycle controls call `IncidentStore.transition`; existing state/evidence rules and hash-chain audit remain authoritative. HTTP routes do not invoke SSH, runbooks, AI, approvals, or remediation.
- Offline security tests cover failed authentication, rate limiting, session expiry/restart, CSRF, XSS, invalid transitions, forged evidence status, concurrent updates, audit integrity, and persistent state.

## Verification results

- Full pytest suite: **116 passed, 11 opt-in live tests skipped**.
- Fresh coverage output: **75.90%**. Older report values 75.4%, 75.99%, 76.17%, and 76.18% came from previous source snapshots; this final full run is authoritative for this candidate.
- Ruff lint and format: **PASS**.
- CLI version/help and authenticated loopback workflow: **PASS**.
- `git diff --check`: **PASS**.
- Wheel and sdist build: **PASS**.
- Fresh wheel install: **PASS**, metadata/import/CLI version 0.4.0.
- Fresh sdist install: **PASS**, separate virtualenv, metadata/import/CLI version 0.4.0.
- Exact staged-content detect-secrets scan: **PASS**, detect-secrets 1.5.0 reported zero findings on all 17 Git-index-exported files.
- Staged path manifest: **PASS**, exact 17/17 allowlist match.

## Git staging allowlist

See [`release-staging-manifest-v0.4.0.md`](release-staging-manifest-v0.4.0.md). Only its listed paths may be staged. The ignored `.runbookos-staging-v032/` tree, `.venv`, SQLite files, credentials, logs, and local benchmark evidence are excluded. No remote, tag, push, merge, or publication is part of this task.

## Integrated staging preparation

A concrete procedure and approval request are provided in [`dashboard-staging-acceptance-v0.4.0.md`](dashboard-staging-acceptance-v0.4.0.md) and [`dashboard-staging-approval-v0.4.0.yml`](dashboard-staging-approval-v0.4.0.yml). At preparation time, bridge/webhook were stopped and isolated staging SQLite existed with mode 0600. No dashboard acceptance process or new staging record was started or created. Staging acceptance remains **PENDING OPERATOR APPROVAL**.

## Verdict

Source and offline verification passed the release gates for a local development commit. The local commit result is recorded in Git history and the final operator report. This is not an operational deployment or production-readiness declaration. Real Alertmanager process/delivery acceptance is carried forward from the earlier synthetic v0.3.2 test; natural monitoring-rule delivery, live SSH, live AI, and operational deployment remain unverified.
