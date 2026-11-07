"""Explicit, local SQLite backup and read-only verification."""

from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import stat
import time
import uuid
from contextlib import closing
from pathlib import Path
from urllib.parse import quote

from .store import SQLiteStore

SCHEMA_VERSION = 4
_DATA_TABLES = (
    "plans",
    "approvals",
    "executions",
    "step_results",
    "investigations",
    "incidents",
    "alerts",
    "incident_alerts",
    "incident_events",
    "incident_investigations",
    "incident_remediation_plans",
    "webhook_nonces",
)
_SCHEMA_COLUMNS = {
    "alerts": (
        "source",
        "alert_id",
        "fingerprint",
        "event_timestamp",
        "received_at",
        "severity",
        "target_alias",
        "service",
        "category",
        "summary",
        "metadata_json",
        "payload_sha256",
    ),
    "approvals": (
        "approval_id",
        "plan_id",
        "plan_hash",
        "actor",
        "reason",
        "created_at",
        "expires_at",
        "used_at",
    ),
    "audit_events": (
        "sequence",
        "created_at",
        "kind",
        "payload_json",
        "previous_hash",
        "event_hash",
    ),
    "executions": (
        "execution_id",
        "plan_id",
        "status",
        "started_at",
        "finished_at",
        "summary_json",
    ),
    "incident_alerts": ("source", "alert_id", "incident_id", "linked_at", "correlation_reason"),
    "incident_events": (
        "event_id",
        "incident_id",
        "event_type",
        "actor",
        "from_status",
        "to_status",
        "reason",
        "created_at",
        "details_json",
    ),
    "incident_investigations": (
        "incident_id",
        "investigation_id",
        "linked_at",
        "execution_ids_json",
        "evidence_refs_json",
    ),
    "incident_remediation_plans": (
        "association_id",
        "incident_id",
        "plan_id",
        "plan_hash",
        "target",
        "action_id",
        "actor",
        "associated_at",
    ),
    "incidents": (
        "incident_id",
        "severity",
        "target_alias",
        "service",
        "category",
        "summary",
        "status",
        "correlation_key",
        "correlation_reason",
        "created_at",
        "updated_at",
        "resolved_at",
        "closed_at",
        "version",
    ),
    "investigations": (
        "investigation_id",
        "status",
        "created_at",
        "incident_sha256",
        "result_json",
    ),
    "plans": ("plan_id", "plan_hash", "document_json", "created_at"),
    "sqlite_sequence": ("name", "seq"),
    "step_results": (
        "id",
        "execution_id",
        "target",
        "phase",
        "step_id",
        "action",
        "status",
        "started_at",
        "finished_at",
        "evidence_json",
    ),
    "webhook_nonces": ("source", "nonce", "timestamp", "received_at"),
}


class BackupError(Exception):
    def __init__(self, reason_code: str, status: str = "FAIL") -> None:
        super().__init__(reason_code)
        self.reason_code = reason_code
        self.status = status


def _path(path: Path) -> Path:
    path = path.expanduser()
    if ".." in path.parts or path.name in {"", ".", ".."}:
        raise BackupError("unsafe_path")
    if not path.is_absolute():
        path = Path.cwd() / path
    current = Path("/")
    for part in path.parts[1:-1]:
        current /= part
        try:
            metadata = current.lstat()
        except OSError as exc:
            raise BackupError("unsafe_parent") from exc
        if not stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
            raise BackupError("unsafe_parent")
        if metadata.st_uid not in {0, os.getuid()}:
            raise BackupError("unsafe_parent")
        if metadata.st_mode & 0o022 and not (
            metadata.st_uid == 0 and metadata.st_mode & stat.S_ISVTX
        ):
            raise BackupError("unsafe_parent")
    parent = current.stat()
    if parent.st_uid != os.getuid() or parent.st_mode & 0o077:
        raise BackupError("unsafe_parent")
    return path


def _file(path: Path) -> os.stat_result:
    try:
        metadata = path.lstat()
    except FileNotFoundError as exc:
        raise BackupError("file_missing") from exc
    except OSError as exc:
        raise BackupError("file_unavailable", "UNKNOWN") from exc
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != os.getuid():
        raise BackupError("unsafe_file")
    if metadata.st_mode & 0o077:
        raise BackupError("unsafe_permissions")
    return metadata


def _uri(path: Path, *, immutable: bool = False) -> str:
    suffix = "&immutable=1" if immutable else ""
    return f"file:{quote(str(path), safe='/')}?mode=ro{suffix}"


def _inspect(path: Path) -> dict[str, object]:
    # The completed backup must be self-contained, not dependent on sidecar data.
    if any(Path(str(path) + suffix).exists() for suffix in ("-wal", "-shm", "-journal")):
        raise BackupError("backup_has_sidecars")
    try:
        with closing(sqlite3.connect(_uri(path, immutable=True), uri=True)) as db:
            db.row_factory = sqlite3.Row
            if db.execute("PRAGMA integrity_check").fetchone()[0] != "ok":
                raise BackupError("integrity_failed")
            if db.execute("PRAGMA foreign_key_check").fetchone() is not None:
                raise BackupError("foreign_keys_failed")
            if db.execute("PRAGMA user_version").fetchone()[0] != SCHEMA_VERSION:
                raise BackupError("unsupported_schema")
            tables = {
                row[0] for row in db.execute("SELECT name FROM sqlite_master WHERE type='table'")
            }
            if tables != set(_SCHEMA_COLUMNS):
                raise BackupError("schema_mismatch")
            for table, columns in _SCHEMA_COLUMNS.items():
                actual = tuple(row[1] for row in db.execute(f'PRAGMA table_info("{table}")'))
                if actual != columns:
                    raise BackupError("schema_mismatch")
            try:
                valid, count = SQLiteStore.verify_audit_chain_connection(db)
            except (ValueError, TypeError, KeyError) as exc:
                raise BackupError("audit_failed") from exc
            if not valid:
                raise BackupError("audit_failed")
            if count == 0 and any(
                db.execute(f"SELECT 1 FROM {table} LIMIT 1").fetchone() is not None
                for table in _DATA_TABLES
            ):
                raise BackupError("audit_missing")
            return {
                "schema_version": SCHEMA_VERSION,
                "audit_events": count,
                "audit_empty": count == 0,
            }
    except sqlite3.DatabaseError as exc:
        raise BackupError("invalid_database") from exc


def verify_backup(input_path: Path) -> dict[str, object]:
    """Check an existing private snapshot without changing it."""
    try:
        path = _path(input_path)
        _file(path)
        return {"status": "PASS", "reason_code": "verified", **_inspect(path)}
    except BackupError as exc:
        return {"status": exc.status, "reason_code": exc.reason_code}
    except OSError:
        return {"status": "UNKNOWN", "reason_code": "io_error"}


def _copy(source: Path, temporary: Path, *, immutable_source: bool = False) -> None:
    with closing(
        sqlite3.connect(_uri(source, immutable=immutable_source), uri=True, timeout=10)
    ) as src:
        with closing(sqlite3.connect(temporary)) as dst:
            src.backup(dst)


def _logical_assertions(path: Path) -> dict[str, object]:
    """Return content identity and row counts without returning database rows."""
    digest = hashlib.sha256()
    row_counts: dict[str, int] = {}
    try:
        with closing(sqlite3.connect(_uri(path, immutable=True), uri=True)) as db:
            for table in ("audit_events", *_DATA_TABLES):
                count = 0
                digest.update(table.encode("ascii") + b"\0")
                for row in db.execute(f'SELECT * FROM "{table}" ORDER BY rowid'):
                    normalized = [
                        value.hex() if isinstance(value, bytes) else value for value in row
                    ]
                    encoded = json.dumps(
                        normalized, ensure_ascii=False, sort_keys=True, separators=(",", ":")
                    ).encode("utf-8")
                    digest.update(len(encoded).to_bytes(8, "big"))
                    digest.update(encoded)
                    count += 1
                digest.update(count.to_bytes(8, "big"))
                row_counts[table] = count
    except sqlite3.DatabaseError as exc:
        raise BackupError("snapshot_unreadable") from exc
    return {"logical_sha256": digest.hexdigest(), "row_counts": row_counts}


def _review_summary(path: Path) -> dict[str, object]:
    """Summarize operator review state without exposing records or changing approvals."""
    now = time.time()
    try:
        with closing(sqlite3.connect(_uri(path, immutable=True), uri=True)) as db:
            incidents = _grouped_status_counts(
                db,
                "incidents",
                "status",
                ("NEW", "ACKNOWLEDGED", "INVESTIGATING", "RESOLVED", "CLOSED"),
            )
            investigations = _grouped_status_counts(
                db,
                "investigations",
                "status",
                ("succeeded", "partial", "failed", "no_diagnostics", "running"),
            )
            executions = _grouped_status_counts(
                db, "executions", "status", ("running", "succeeded", "failed", "unknown")
            )
            approvals = {
                "unused": db.execute(
                    "SELECT COUNT(*) FROM approvals WHERE used_at IS NULL AND expires_at>?", (now,)
                ).fetchone()[0],
                "expired": db.execute(
                    "SELECT COUNT(*) FROM approvals WHERE used_at IS NULL AND expires_at<=?", (now,)
                ).fetchone()[0],
                "consumed": db.execute(
                    "SELECT COUNT(*) FROM approvals WHERE used_at IS NOT NULL"
                ).fetchone()[0],
            }
            return {
                "incidents": incidents,
                "investigations": investigations,
                "executions": executions,
                "approvals": approvals,
            }
    except sqlite3.DatabaseError as exc:
        raise BackupError("snapshot_unreadable") from exc


def _grouped_status_counts(
    db: sqlite3.Connection, table: str, column: str, allowed: tuple[str, ...]
) -> dict[str, int]:
    counts = {value: 0 for value in allowed}
    counts["other"] = 0
    for value, count in db.execute(
        f'SELECT "{column}",COUNT(*) FROM "{table}" GROUP BY "{column}"'
    ):
        counts[value if value in allowed else "other"] += count
    return counts


def rehearse_restore(backup_path: Path, staging_path: Path) -> dict[str, object]:
    """Materialize and verify a new staging copy; never activate or migrate it."""
    temporary: Path | None = None
    published_identity: tuple[int, int] | None = None
    succeeded = False
    directory_fd: int | None = None
    try:
        backup = _path(backup_path)
        staging = _path(staging_path)
        backup_stat = _file(backup)
        if backup == staging:
            raise BackupError("source_destination_alias")
        before = verify_backup(backup)
        if before["status"] != "PASS":
            return {"status": before["status"], "reason_code": f"source_{before['reason_code']}"}
        try:
            existing = staging.lstat()
        except FileNotFoundError:
            existing = None
        if existing is not None:
            if (existing.st_dev, existing.st_ino) == (backup_stat.st_dev, backup_stat.st_ino):
                raise BackupError("source_destination_alias")
            raise BackupError("destination_exists")
        source_assertions = _logical_assertions(backup)
        temporary = staging.with_name(f".{staging.name}.rehearsal-{uuid.uuid4().hex}")
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        os.close(fd)
        _copy(backup, temporary, immutable_source=True)
        os.chmod(temporary, 0o600, follow_symlinks=False)
        staged_validation = _inspect(temporary)
        staged_assertions = _logical_assertions(temporary)
        if source_assertions != staged_assertions:
            raise BackupError("staging_mismatch")
        final_source = verify_backup(backup)
        if final_source["status"] != "PASS" or _logical_assertions(backup) != source_assertions:
            raise BackupError("source_changed")
        review = _review_summary(temporary)
        directory_fd = os.open(staging.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        temp_stat = temporary.stat(follow_symlinks=False)
        with temporary.open("rb") as snapshot:
            os.fsync(snapshot.fileno())
        os.link(temporary, staging, follow_symlinks=False)
        published_identity = (temp_stat.st_dev, temp_stat.st_ino)
        os.fsync(directory_fd)
        succeeded = True
        return {
            "status": "PASS",
            "reason_code": "restore_rehearsed",
            "schema_version": SCHEMA_VERSION,
            "audit_events": staged_validation["audit_events"],
            "logical_sha256": staged_assertions["logical_sha256"],
            "data_match": True,
            "row_counts": staged_assertions["row_counts"],
            "review": review,
        }
    except BackupError as exc:
        return {"status": exc.status, "reason_code": exc.reason_code}
    except FileExistsError:
        return {"status": "FAIL", "reason_code": "destination_exists"}
    except sqlite3.DatabaseError as exc:
        if getattr(exc, "sqlite_errorcode", None) in {
            sqlite3.SQLITE_NOTADB,
            sqlite3.SQLITE_CORRUPT,
        }:
            return {"status": "FAIL", "reason_code": "invalid_database"}
        return {"status": "UNKNOWN", "reason_code": "staging_interrupted"}
    except OSError:
        return {"status": "UNKNOWN", "reason_code": "staging_interrupted"}
    finally:
        if directory_fd is not None:
            try:
                os.close(directory_fd)
            except OSError:
                pass
        if published_identity is not None and not succeeded:
            try:
                current = staging.lstat()
                if (current.st_dev, current.st_ino) == published_identity:
                    staging.unlink()
                    cleanup_fd = os.open(
                        staging.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
                    )
                    try:
                        os.fsync(cleanup_fd)
                    finally:
                        os.close(cleanup_fd)
            except OSError:
                pass
        if temporary is not None:
            for partial in (
                temporary,
                *(Path(str(temporary) + suffix) for suffix in ("-wal", "-shm", "-journal")),
            ):
                try:
                    partial.unlink(missing_ok=True)
                except OSError:
                    pass


def review_staging(staging_path: Path) -> dict[str, object]:
    """Read-only summary of a verified schema-v4 staging snapshot."""
    try:
        staging = _path(staging_path)
        _file(staging)
        validation = _inspect(staging)
        return {
            "status": "PASS",
            "reason_code": "staging_reviewed",
            "schema_version": SCHEMA_VERSION,
            "audit_events": validation["audit_events"],
            "review": _review_summary(staging),
        }
    except BackupError as exc:
        return {"status": exc.status, "reason_code": exc.reason_code}
    except OSError:
        return {"status": "UNKNOWN", "reason_code": "io_error"}


def create_backup(source_path: Path, output_path: Path) -> dict[str, object]:
    """Snapshot an existing DB to a new private file and publish only after validation."""
    temporary: Path | None = None
    try:
        source = _path(source_path)
        output = _path(output_path)
        source_stat = _file(source)
        if source == output:
            raise BackupError("source_destination_alias")
        try:
            existing = output.lstat()
        except FileNotFoundError:
            existing = None
        if existing is not None:
            if (existing.st_dev, existing.st_ino) == (source_stat.st_dev, source_stat.st_ino):
                raise BackupError("source_destination_alias")
            raise BackupError("destination_exists")
        temporary = output.with_name(f".{output.name}.partial-{uuid.uuid4().hex}")
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        os.close(fd)
        _copy(source, temporary)
        details = _inspect(temporary)
        with temporary.open("rb") as snapshot:
            os.fsync(snapshot.fileno())
        # A hard link fails atomically if the destination appeared during backup.
        os.link(temporary, output, follow_symlinks=False)
        directory = os.open(output.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
        return {"status": "PASS", "reason_code": "backup_created", **details}
    except BackupError as exc:
        return {"status": exc.status, "reason_code": exc.reason_code}
    except FileExistsError:
        return {"status": "FAIL", "reason_code": "destination_exists"}
    except sqlite3.DatabaseError as exc:
        if getattr(exc, "sqlite_errorcode", None) in {
            sqlite3.SQLITE_NOTADB,
            sqlite3.SQLITE_CORRUPT,
        }:
            return {"status": "FAIL", "reason_code": "invalid_database"}
        return {"status": "UNKNOWN", "reason_code": "backup_interrupted"}
    except OSError:
        return {"status": "UNKNOWN", "reason_code": "backup_interrupted"}
    finally:
        if temporary is not None:
            for partial in (
                temporary,
                *(Path(str(temporary) + suffix) for suffix in ("-wal", "-shm", "-journal")),
            ):
                try:
                    partial.unlink(missing_ok=True)
                except OSError:
                    pass
