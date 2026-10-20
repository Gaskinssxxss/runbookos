# v0.4.0 Initial Release Staging Manifest

Branch: `feat/v0.4.0-operator-dashboard`
Base: `54cf7e5f3003713aac6a1444804754cf149c9db2`
Commit subject: `feat: add RunbookOS v0.4.0 operator dashboard`

Stage exactly these 17 paths for the local release commit:

1. `.github/workflows/validate.yml`
2. `MANIFEST.in`
3. `README.md`
4. `pyproject.toml`
5. `src/runbookos/__init__.py`
6. `src/runbookos/cli.py`
7. `src/runbookos/dashboard.py`
8. `tests/test_dashboard.py`
9. `docs/alertmanager-acceptance-summary-v0.3.2.md`
10. `docs/dashboard-security-v0.4.0.md`
11. `docs/dashboard-walkthrough-v0.4.0.md`
12. `docs/dashboard-staging-acceptance-v0.4.0.md`
13. `docs/implementation-report-v0.4.0.md`
14. `docs/release-review-v0.4.0.md`
15. `docs/release-staging-manifest-v0.4.0.md`
16. `docs/staging-acceptance-v0.3.2.md`
17. `docs/dashboard-staging-approval-v0.4.0.yml`

No new dependencies were added. Do not stage `.runbookos-staging-v032/`, `.venv/`, build outputs, local logs, credentials, verifier files, SQLite state, or benchmark/report artifacts. The staging approval manifest contains only paths relative to the worktree and no secret values.
