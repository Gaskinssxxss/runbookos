# RunbookOS v0.3.2 Release Staging Manifest

This file is the exact allowlist for the local v0.3.2 development commit, relative
to base commit `9a169746f5a3e2d8bd8fe73e92b3182330d8f6c0`. Stage only these 16
paths after review.

```text
.github/workflows/validate.yml
.gitignore
MANIFEST.in
README.md
docs/approval-manifest-v0.3.2.yml
docs/implementation-report-v0.3.2.md
docs/release-staging-manifest-v0.3.2.md
docs/staging-acceptance-v0.3.2.md
examples/alertmanager/receiver.example.yml
pyproject.toml
scripts/staging-v032.py
src/runbookos/__init__.py
src/runbookos/adapters/alertmanager_bridge.py
tests/test_alertmanager_bridge.py
tests/test_incidents.py
docs/security.md
```

The local `.runbookos-staging-v032/` runtime is intentionally excluded. It
contains generated credentials, a staging SQLite database, logs, process state,
and a virtual environment. Also excluded are SQLite files, local configuration,
private keys, raw operational evidence, benchmark result data, build outputs,
and machine-specific homelab configuration. The ignore rule for
`.runbookos-staging-v032/` is part of this allowlisted change.

This allowlist describes a local development commit only. It does not authorize
publishing, tagging, pushing, or operational deployment.
