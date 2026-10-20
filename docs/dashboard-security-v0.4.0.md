# Dashboard Security Model — v0.4.0

## Scope and startup

The dashboard is optional and disabled until an operator runs `runbookos dashboard serve`. It uses Python's standard-library HTTP server, is fixed to `127.0.0.1`, and rejects any other bind address. It is intended for local operator use, not as an internet-facing service or reverse-proxy backend. No service unit or listener is installed automatically.

Create an authentication verifier interactively:

```sh
runbookos dashboard auth-init --operator-id alice --auth-file ~/.config/runbookos/dashboard-auth.json
runbookos --db ~/.local/state/runbookos/runbookos.sqlite3 dashboard serve \
  --auth-file ~/.config/runbookos/dashboard-auth.json --port 8780
```

The password is entered through a hidden prompt and is not saved. The verifier contains a random salt and PBKDF2-HMAC-SHA256 digest; the file must be owned by the current OS account and inaccessible to group/other users. Use mode `0600`. The operator identity is trusted startup configuration and is used as the actor for lifecycle audit records; there is no actor field in forms.

## Sessions and requests

- Incident records and controls require a valid in-memory authenticated session. Missing, malformed, or unsafe auth configuration prevents startup; there is no unauthenticated read-only data mode.
- Password verification uses constant-time digest comparison. Failed login attempts are limited per loopback client address in a bounded five-attempt/five-minute window, the server accepts at most 16 concurrent requests with a 10-second socket timeout, and the process caps live sessions at 256. These in-memory controls reset on process restart and are local defenses, not account lockout infrastructure.
- Sessions expire after one hour and are invalidated on process restart. Cookies are `HttpOnly`, `SameSite=Strict`, path-scoped, and `Cache-Control: no-store` is set for pages. The listener is plain HTTP on loopback; do not expose it through a network proxy. TLS is not provided by this MVP.
- All POST lifecycle actions require a session-bound CSRF token. Forms do not accept actor identity, evidence references, runbook IDs, commands, policy, or approval data.
- Responses use HTML escaping, a restrictive Content-Security-Policy, `X-Content-Type-Options: nosniff`, and no external assets. Alert summaries and timeline reasons remain untrusted text.

## Authorization and audit

The dashboard calls `IncidentStore.transition` for acknowledge, resolve, and close. The existing lifecycle graph, evidence-status checks, transaction behavior, and audit events remain authoritative. A failed or invalid transition is rejected. Audit-chain validity is displayed, but a valid hash chain is tamper-evident rather than a signed remote log.

Investigation execution is intentionally absent from the dashboard. Operators can inspect linked investigation IDs and verified evidence references; evidence payloads are omitted from HTML to reduce accidental disclosure. The existing CLI remains the explicit route to read-only investigation. Alerts never trigger diagnostics, SSH, AI, or remediation. There are no remediation controls.

## Limitations

The dashboard has no TLS, external identity provider, multi-user role model, persistent session store, cross-process rate limiting, or CSRF token rotation during a session. Local OS account security and protection of the SQLite file remain part of the trust boundary. Do not bind beyond loopback or put this MVP behind a publicly reachable proxy.
