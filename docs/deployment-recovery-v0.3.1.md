# Staging deployment, migration, and recovery procedure

## Staging-only upgrade rehearsal

Do not point v0.3.1 at operational SQLite for this rehearsal. Make a consistent copy using SQLite's backup API, or use a filesystem snapshot while the application is stopped. Preserve the original file, WAL, SHM, owner, and mode. Keep the copy in a private temporary directory with mode `0700` and DB mode `0600`.

1. Record source package version, DB `PRAGMA user_version`, file hash, and audit verification result.
2. Copy the v0.2.5 DB to a disposable staging path. Never use the original path in commands below.
3. Install the v0.3.1 wheel into a new isolated virtual environment (do not upgrade in place).
4. Open only the copy with the v0.3.1 CLI/store to apply additive schema v3. Check that plans, approvals, executions, investigations, and prior audit sequence remain present and the audit chain verifies.
5. In staging, ingest an authenticated fixture, create an incident, exercise deduplication/lifecycle, then use SQLite backup API to restore a second copy. Validate both audit chains and row relationships.
6. Test package rollback by switching the staging venv back to v0.2.5 while leaving the migrated DB untouched. v0.2.5 must reject schema version 3; do not attempt downgrade SQL. Restore a pre-migration DB copy into a fresh staging path only if testing v0.2.5 compatibility.
7. Preserve both copies and reports until the rehearsal is reviewed; securely delete disposable copies only under the environment's retention procedure.

## Migration and rollback boundary

Migration v3 adds tables and indexes and sets `user_version=3`. It does not rewrite historical execution, investigation, audit, or benchmark rows. Schema v3 is forward-only: an older binary rejects it. Package rollback and DB rollback are separate operations. The database must not be downgraded in place. Recovery means restore the pre-migration SQLite backup to a separate path, verify data and audit first, then obtain operator authorization before any production path switch. Never overwrite/delete the post-migration DB or logs during recovery.

## Interruption and duplicate delivery

SQLite `BEGIN IMMEDIATE` transactions commit each alert/incident/link/audit unit atomically. An interruption before commit leaves no partial committed alert record; after commit but before HTTP response, the sender may retry with a new nonce. `(source, alert_id)` payload hash idempotency returns the existing incident; same ID with different body is rejected. Reusing the same nonce (including under another key ID) is rejected. Alertmanager group normalization is deterministic, and firing/resolved status produces distinct delivery IDs while retaining a common correlation fingerprint.

## Production deployment remains gated

No persistent listener, VM package upgrade, firewall/reverse-proxy rule, systemd unit, or operational DB migration is authorized by this runbook. Before an operational deployment, require a distinct approval for host, account, bind address, port, DB path, backup location/retention, secret delivery, service supervision, recovery owner, and monitoring source. The loopback listener cannot receive remote senders without a separately reviewed relay/proxy design.
