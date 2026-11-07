"""Explicit, local SQLite backup and read-only verification."""

from __future__ import annotations

import os
import sqlite3
import stat
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


class BackupError(Exception):
    def __init__(self, reason_code: str, status: str = "FAIL") -> None:
        super().__init__(reason_code)
        self.reason_code = reason_code
        self.status = status


def _path(path: Path) -> Path:
    path = path.expanduser().absolute()
    if ".." in path.parts or path.name in {"", ".", ".."}:
        raise BackupError("unsafe_path")
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
            if not {"audit_events", *_DATA_TABLES} <= tables:
                raise BackupError("schema_incomplete")
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


def _copy(source: Path, temporary: Path) -> None:
    with closing(sqlite3.connect(_uri(source), uri=True, timeout=10)) as src:
        with closing(sqlite3.connect(temporary)) as dst:
            src.backup(dst)


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
            try:
                temporary.unlink(missing_ok=True)
            except OSError:
                pass
