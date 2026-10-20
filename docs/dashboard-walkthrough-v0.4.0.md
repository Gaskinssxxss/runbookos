# Dashboard Walkthrough — v0.4.0

1. Create an auth verifier with `runbookos dashboard auth-init --operator-id <operator> --auth-file <private-path>`; enter a password of at least 14 characters in the hidden prompt.
2. Start `runbookos --db <state-db> dashboard serve --auth-file <private-path> --port 8780` in a foreground terminal. It binds only to `127.0.0.1`; Ctrl-C stops it.
3. Open `http://127.0.0.1:8780/` and sign in. Filter by status, severity, or target. Without a valid session, the queue and incident records are not returned.
4. Open an incident to review its summary, source alert references and correlation reasons, status/timestamps, incident timeline, audit-chain validity, linked investigation IDs, and verified evidence-reference IDs. Evidence payloads are intentionally omitted from HTML.
5. Acknowledge a new incident with an operator reason. For diagnostics, use the existing CLI after reviewing the target and policy; alert receipt itself never runs diagnostics.
6. Resolve only an `INVESTIGATING` incident, selecting `verified`, `not_available`, or `inconclusive` and recording a reason. The existing engine rejects `verified` when there are no linked verified evidence references.
7. Close a resolved incident with a reason. Each state change uses the existing incident lifecycle API and appears in the audit timeline.
8. Stop the foreground process. Sessions expire on restart; incident and audit records remain in the selected SQLite database.

This workflow is covered with synthetic alerts and temporary SQLite by `tests/test_dashboard.py`; it does not imply operational deployment.
