# RunbookOS v0.3.1 release readiness checklist

## Offline gates

- [x] Full portable unit/security/integration suite passes on an allowlist-clean source copy (106 passed, no live tests included). The complete local checkout also passes all 107 non-live tests; 11 lab-only tests remain opt-in and were not run.
- [x] Per-source key IDs are unique, secrets are environment-only, signature binds key ID/timestamp/nonce/raw body.
- [x] Active, grace-before-expiry, expired, revoked, disabled, unknown-key, wrong-source, and replay cases are covered.
- [x] Alertmanager v2 fixture is normalized deterministically; unsupported/mixed groups and unknown aliases reject.
- [x] SQLite copy migration, backup/restore, duplicate-after-interruption behavior, and audit chain are verified offline.
- [x] Fresh Python 3.12 venv reports package metadata, imported code, and CLI as 0.3.1; CI dependency tooling is pinned in `requirements-ci-py312.lock`.
- [x] Ruff, CLI smoke, wheel/sdist checks, artifact inventory, and allowlist secret scan pass; package artifacts exclude homelab configs and reports.
- [x] Release staging manifest and historical data classification reviewed; files remain unstaged.

These are offline source/package checks only. Live monitoring compatibility, signed artifact provenance, and deployment authorization remain open gates. An initial source commit is safe only when staged strictly from `release-staging-manifest-v0.3.1.md`; the current Git tree remains unstaged.

## Separate operator deployment approval required

- [ ] Actual monitoring sender identity, source mapping, key delivery, rotation window, and network path approved.
- [ ] Destination host/account/bind/port/proxy and service supervision approved. v0.3.1 itself does not add a persistent service.
- [ ] Operational database backup/restore and migration window approved and rehearsed on a copy.
- [ ] Filesystem permissions, OS account authorization, secret injection, audit retention, and incident operator roles accepted.
- [ ] Post-deployment health, rollback owner, and recovery decision tree approved.

No production-readiness claim is valid until the deployment-specific gates have evidence.
