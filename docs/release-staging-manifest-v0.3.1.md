# Initial Git candidate manifest — RunbookOS v0.3.1

This is an allowlist for a future operator-reviewed initial source commit. The repository currently has no commits on `main`; all allowlisted paths are untracked. **Nothing is staged by this manifest.** Do not use blanket `git add .`; inspect this list and the final release review first.

## Allowlisted portable candidate paths

- Root metadata: `.gitignore`, `LICENSE`, `MANIFEST.in`, `README.md`, `pyproject.toml`, `requirements-ci-py312.lock`.
- CI: `.github/workflows/validate.yml`.
- Runtime source: all `src/runbookos/**/*.py` modules.
- Generic configuration: `config/diagnostic-taxonomy.v2.example.yml`, `config/evaluation.qwen.example.yml`, `config/inventory.example.yml`, `config/investigation.example.yml`, `config/policy.example.yml`, `config/ssh_profiles.example.yml`, `config/webhook-legacy-single-source.example.yml`, and `config/webhook-sources.example.yml`.
- Generic user examples: all `examples/alerts/*` and `examples/runbooks/*`.
- Synthetic scenarios: `scenarios/*.yml` and `scenarios/metadata/ground-truth-taxonomy-v2.yml`. Host aliases and sample network ranges are genericized; scenario IDs, classes, root-cause IDs, evidence IDs, and historical result datasets are preserved.
- Portable documentation: `docs/ai-investigation.md`, `docs/alert-incident-workflow-v0.3.0.md`, `docs/architecture.md`, `docs/blind-review-v0.2.5.md`, `docs/deployment-recovery-v0.3.1.md`, `docs/diagnostic-actions-v0.2.3.md`, `docs/diagnostic-taxonomy-review-v0.2.5.md`, `docs/diagnostic-taxonomy-v2.md`, `docs/implementation-report-v0.3.0.md`, `docs/implementation-report-v0.3.1.md`, `docs/incident-evaluation.md`, `docs/operations.md`, `docs/release-readiness-v0.3.1.md`, this manifest, `docs/runbook-schema.md`, `docs/security.md`, `docs/webhook-authentication-v0.3.1.md`, and `docs/final-release-review-v0.3.1.md`.
- Portable tests: `tests/conftest.py`, `tests/test_ai.py`, `tests/test_blind_review.py`, `tests/test_cli_integration.py`, `tests/test_evaluation.py`, `tests/test_evaluation_v2.py`, `tests/test_incidents.py`, `tests/test_probes.py`, `tests/test_schema_policy.py`, `tests/test_store_ssh.py`, and `tests/test_tunnel.py`.

The manifest intentionally omits homelab-only SSH live tests and `tests/test_probe_approval_manifest.py`, which validates a private, historical endpoint approval record rather than product behavior. All non-lab unit/security/integration tests remain in the source distribution.

## Keep local / do not stage for a public baseline

- `.git`, virtual environments, build output, caches, `*.egg-info`, coverage, local state, temporary files, and `reports/`.
- SQLite databases and WAL/SHM files, backups/dumps, `.env*`, private keys/certificates, `known_hosts`, `authorized_keys`, secret/config overlays, raw Qwen results, blind-review answers, and live evidence.
- Homelab-specific `config/*.homelab.example.yml`, tunnel provisioning/export/rollback scripts, and associated operator rollback guide.
- Detailed live acceptance records, self-SSH review, homelab testing guide, old v0.1/v0.2 implementation reports, obsolete v0.2.0 implementation report, and this environment-specific conformance audit.

These files remain in the local workspace where applicable. The `.gitignore` rules and sdist allowlist prevent accidental inclusion in the portable candidate/package. The release review's secret scan covers all allowlisted source candidates; private/local artifacts are separately excluded and preserved.

## Git safety state

- Branch `main` has no initial commit and no configured remote was added by this work.
- No file was staged; no commit, tag, push, remote, or publication was created.
- Before operator approval, re-run `git status --short --untracked-files=all`, verify every candidate against this allowlist, and re-run the scan/build checks from the final workspace state.
