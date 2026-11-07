from __future__ import annotations

import hashlib
import json
import os
import sqlite3
from contextlib import closing
from datetime import UTC, datetime
from pathlib import Path

import pytest
from typer.testing import CliRunner

from runbookos import state_backup
from runbookos.cli import app
from runbookos.incidents import IncidentStore, parse_alert
from runbookos.store import SQLiteStore


def private_dir(tmp_path: Path) -> Path:
    directory = tmp_path / "private"
    directory.mkdir(mode=0o700)
    return directory


def populated_source(tmp_path: Path) -> tuple[Path, str]:
    directory = private_dir(tmp_path)
    source = directory / "source.sqlite3"
    store = SQLiteStore(source)
    manager = IncidentStore(store)
    alert = parse_alert(
        json.dumps(
            {
                "alert_id": "offline-backup-alert",
                "source": "offline-test",
                "event_timestamp": datetime.now(UTC).isoformat(),
                "severity": "warning",
                "target_alias": "fixture-web",
                "service": "nginx",
                "category": "service",
                "summary": "Synthetic backup test",
                "fingerprint": "offline-backup",
                "metadata": {},
            }
        ).encode()
    )
    incident_id = manager.ingest(alert)["incident_id"]
    investigation_id = store.create_investigation(
        {
            "incident_sha256": hashlib.sha256(b"synthetic").hexdigest(),
            "status": "failed",
            "selected_diagnostics": [],
            "tool_calls": 0,
            "evidence": [],
            "verified_evidence": [],
            "model_metadata": {},
        }
    )
    manager.link_investigation(incident_id, investigation_id, [], [])
    store.create_plan(
        {
            "plan_id": "pending-approval-plan",
            "plan_hash": "pending-hash",
            "created_at": "synthetic",
            "status": "approval_required",
        }
    )
    store.create_approval("pending-approval-plan", "pending-hash", "offline", "synthetic", 3600)
    store.create_plan(
        {
            "plan_id": "running-execution-plan",
            "plan_hash": "running-hash",
            "created_at": "synthetic",
            "status": "ready",
        }
    )
    store.start_execution("running-execution", "running-execution-plan", "synthetic")
    return source, incident_id


def test_wal_active_backup_preserves_incident_links_and_audit(tmp_path: Path) -> None:
    source, incident_id = populated_source(tmp_path)
    backup = source.parent / "snapshot.sqlite3"
    with sqlite3.connect(source) as writer:
        writer.execute("PRAGMA wal_autocheckpoint=0")
        writer.execute("PRAGMA journal_mode=WAL")
        writer.execute(
            "UPDATE incidents SET summary=? WHERE incident_id=?",
            ("WAL committed state", incident_id),
        )
        writer.commit()
        assert Path(str(source) + "-wal").exists()
        result = state_backup.create_backup(source, backup)
        assert result == {
            "status": "PASS",
            "reason_code": "backup_created",
            "schema_version": 4,
            "audit_events": 8,
            "audit_empty": False,
        }
    assert backup.stat().st_mode & 0o777 == 0o600
    assert state_backup.verify_backup(backup)["status"] == "PASS"
    with sqlite3.connect(state_backup._uri(backup, immutable=True), uri=True) as db:
        assert (
            db.execute(
                "SELECT summary FROM incidents WHERE incident_id=?", (incident_id,)
            ).fetchone()[0]
            == "WAL committed state"
        )
        assert db.execute("SELECT COUNT(*) FROM incident_investigations").fetchone()[0] == 1
        assert db.execute("SELECT COUNT(*) FROM approvals WHERE used_at IS NULL").fetchone()[0] == 1
        assert db.execute("SELECT status FROM executions").fetchone()[0] == "running"
    staging_digest = hashlib.sha256(backup.read_bytes()).hexdigest()
    review = state_backup.review_staging(backup)
    assert review["status"] == "PASS"
    assert review["review"]["incidents"]["NEW"] == 1
    assert review["review"]["investigations"]["failed"] == 1
    assert review["review"]["approvals"]["unused"] == 1
    assert review["review"]["executions"]["running"] == 1
    assert hashlib.sha256(backup.read_bytes()).hexdigest() == staging_digest
    assert not list(source.parent.glob("*.partial-*"))


def test_empty_audit_chain_is_explicit_only_for_empty_state(tmp_path: Path) -> None:
    directory = private_dir(tmp_path)
    source = directory / "empty.sqlite3"
    SQLiteStore(source)
    backup = directory / "empty-backup.sqlite3"
    assert state_backup.create_backup(source, backup)["audit_empty"] is True
    assert state_backup.verify_backup(backup)["audit_events"] == 0
    with closing(sqlite3.connect(backup)) as db:
        db.execute("INSERT INTO plans VALUES(?,?,?,?)", ("p", "h", "{}", "now"))
        db.commit()
    assert state_backup.verify_backup(backup) == {"status": "FAIL", "reason_code": "audit_missing"}


@pytest.mark.parametrize(
    ("mutation", "reason"),
    [
        ("corrupt", "invalid_database"),
        ("schema", "unsupported_schema"),
        ("foreign_key", "foreign_keys_failed"),
        ("audit", "audit_failed"),
    ],
)
def test_verify_rejects_corruption_schema_foreign_keys_and_audit(
    tmp_path: Path, mutation: str, reason: str
) -> None:
    source, _ = populated_source(tmp_path)
    backup = source.parent / "verify.sqlite3"
    assert state_backup.create_backup(source, backup)["status"] == "PASS"
    if mutation == "corrupt":
        backup.write_bytes(b"not a SQLite database")
    else:
        with closing(sqlite3.connect(backup)) as db:
            if mutation == "schema":
                db.execute("PRAGMA user_version=999")
            elif mutation == "foreign_key":
                db.execute(
                    "INSERT INTO incident_investigations VALUES(?,?,?,?,?)",
                    ("missing", "missing", "now", "[]", "[]"),
                )
            else:
                db.execute("UPDATE audit_events SET payload_json='{}' WHERE sequence=1")
            db.commit()
    before = backup.read_bytes()
    assert state_backup.verify_backup(backup) == {"status": "FAIL", "reason_code": reason}
    assert backup.read_bytes() == before


def test_missing_source_does_not_create_database(tmp_path: Path) -> None:
    directory = private_dir(tmp_path)
    source, backup = directory / "missing.sqlite3", directory / "backup.sqlite3"
    assert state_backup.create_backup(source, backup) == {
        "status": "FAIL",
        "reason_code": "file_missing",
    }
    assert not source.exists() and not backup.exists()


def test_rehearsal_validates_copy_and_returns_sanitized_equivalence(tmp_path: Path) -> None:
    source, incident_id = populated_source(tmp_path)
    backup = source.parent / "backup.sqlite3"
    staging = source.parent / "staging.sqlite3"
    assert state_backup.create_backup(source, backup)["status"] == "PASS"
    source_digest = hashlib.sha256(backup.read_bytes()).hexdigest()
    result = state_backup.rehearse_restore(backup, staging)
    assert result["status"] == "PASS"
    assert result["reason_code"] == "restore_rehearsed"
    assert result["schema_version"] == 4
    assert result["data_match"] is True
    assert result["logical_sha256"] == state_backup._logical_assertions(backup)["logical_sha256"]
    assert result["row_counts"]["incidents"] == 1
    assert result["row_counts"]["incident_investigations"] == 1
    assert result["row_counts"]["approvals"] == 1
    assert result["row_counts"]["executions"] == 1
    assert result["review"]["incidents"]["NEW"] == 1
    assert result["review"]["approvals"]["unused"] == 1
    assert result["review"]["executions"]["running"] == 1
    assert staging.stat().st_mode & 0o777 == 0o600
    assert hashlib.sha256(backup.read_bytes()).hexdigest() == source_digest
    assert not list(source.parent.glob(".staging.sqlite3.rehearsal-*"))
    assert incident_id not in json.dumps(result)
    assert str(tmp_path) not in json.dumps(result)
    with closing(sqlite3.connect(state_backup._uri(staging, immutable=True), uri=True)) as db:
        db.row_factory = sqlite3.Row
        assert db.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
        assert db.execute("PRAGMA foreign_key_check").fetchall() == []
        assert db.execute("PRAGMA user_version").fetchone()[0] == 4
        assert SQLiteStore.verify_audit_chain_connection(db) == (True, result["audit_events"])


def test_rehearsal_accepts_empty_audit_state(tmp_path: Path) -> None:
    directory = private_dir(tmp_path)
    source = directory / "empty.sqlite3"
    SQLiteStore(source)
    backup = directory / "empty-backup.sqlite3"
    stage = directory / "empty-stage.sqlite3"
    assert state_backup.create_backup(source, backup)["status"] == "PASS"
    result = state_backup.rehearse_restore(backup, stage)
    assert result["status"] == "PASS"
    assert result["audit_events"] == 0
    assert result["review"]["approvals"]["unused"] == 0


def test_rehearsal_rejects_unrecognized_schema_at_version_four(tmp_path: Path) -> None:
    source, _ = populated_source(tmp_path)
    backup = source.parent / "backup.sqlite3"
    stage = source.parent / "stage.sqlite3"
    assert state_backup.create_backup(source, backup)["status"] == "PASS"
    with closing(sqlite3.connect(backup)) as db:
        db.execute("CREATE TABLE unexpected_table (value TEXT)")
        db.commit()
    assert state_backup.verify_backup(backup) == {
        "status": "FAIL",
        "reason_code": "schema_mismatch",
    }
    assert state_backup.rehearse_restore(backup, stage) == {
        "status": "FAIL",
        "reason_code": "source_schema_mismatch",
    }
    assert not stage.exists()


@pytest.mark.parametrize("mutation", ["corrupt", "tampered_audit", "wrong_schema"])
def test_rehearsal_rejects_invalid_backup_before_stage_creation(
    tmp_path: Path, mutation: str
) -> None:
    source, _ = populated_source(tmp_path)
    backup = source.parent / "invalid-backup.sqlite3"
    assert state_backup.create_backup(source, backup)["status"] == "PASS"
    if mutation == "corrupt":
        backup.write_bytes(b"invalid")
    else:
        with closing(sqlite3.connect(backup)) as db:
            if mutation == "tampered_audit":
                db.execute("UPDATE audit_events SET payload_json='{}' WHERE sequence=1")
            else:
                db.execute("PRAGMA user_version=3")
            db.commit()
    stage = source.parent / "stage.sqlite3"
    result = state_backup.rehearse_restore(backup, stage)
    assert result["status"] == "FAIL"
    assert not stage.exists()
    assert not list(source.parent.glob(".stage.sqlite3.rehearsal-*"))


def test_rehearsal_rejects_existing_alias_symlink_and_unsafe_path(tmp_path: Path) -> None:
    source, _ = populated_source(tmp_path)
    backup = source.parent / "backup.sqlite3"
    assert state_backup.create_backup(source, backup)["status"] == "PASS"
    existing = source.parent / "existing-stage.sqlite3"
    existing.write_bytes(b"preserve")
    existing.chmod(0o600)
    assert state_backup.rehearse_restore(backup, existing)["reason_code"] == "destination_exists"
    assert existing.read_bytes() == b"preserve"
    assert (
        state_backup.rehearse_restore(backup, backup)["reason_code"] == "source_destination_alias"
    )
    hardlink = source.parent / "backup-hardlink.sqlite3"
    os.link(backup, hardlink)
    assert (
        state_backup.rehearse_restore(backup, hardlink)["reason_code"] == "source_destination_alias"
    )
    symlink = source.parent / "stage-link.sqlite3"
    symlink.symlink_to(existing)
    assert state_backup.rehearse_restore(backup, symlink)["reason_code"] == "destination_exists"
    assert (
        state_backup.rehearse_restore(backup, source.parent / ".." / "escape.sqlite3")[
            "reason_code"
        ]
        == "unsafe_path"
    )


def test_rehearsal_rejects_symlinked_parent_and_broad_parent(tmp_path: Path) -> None:
    source, _ = populated_source(tmp_path)
    backup = source.parent / "backup.sqlite3"
    assert state_backup.create_backup(source, backup)["status"] == "PASS"
    link_parent = tmp_path / "parent-link"
    link_parent.symlink_to(source.parent, target_is_directory=True)
    assert (
        state_backup.rehearse_restore(backup, link_parent / "stage.sqlite3")["reason_code"]
        == "unsafe_parent"
    )
    broad_parent = tmp_path / "broad"
    broad_parent.mkdir(mode=0o700)
    broad_parent.chmod(0o750)
    assert (
        state_backup.rehearse_restore(backup, broad_parent / "stage.sqlite3")["reason_code"]
        == "unsafe_parent"
    )


def test_rehearsal_copy_interruption_cleans_only_its_partial(tmp_path: Path, monkeypatch) -> None:
    source, _ = populated_source(tmp_path)
    backup = source.parent / "backup.sqlite3"
    stage = source.parent / "stage.sqlite3"
    assert state_backup.create_backup(source, backup)["status"] == "PASS"
    source_digest = hashlib.sha256(backup.read_bytes()).hexdigest()
    unrelated = source.parent / ".stage.sqlite3.rehearsal-unrelated"
    unrelated.write_bytes(b"keep")

    def interrupted(_source, temporary, **_kwargs):
        temporary.write_bytes(b"partial")
        Path(str(temporary) + "-journal").write_bytes(b"partial journal")
        raise sqlite3.OperationalError("sensitive internal detail")

    monkeypatch.setattr(state_backup, "_copy", interrupted)
    result = state_backup.rehearse_restore(backup, stage)
    assert result == {"status": "UNKNOWN", "reason_code": "staging_interrupted"}
    assert not stage.exists()
    assert unrelated.read_bytes() == b"keep"
    assert hashlib.sha256(backup.read_bytes()).hexdigest() == source_digest
    assert list(source.parent.glob(".stage.sqlite3.rehearsal-*")) == [unrelated]
    assert not list(source.parent.glob(".stage.sqlite3.rehearsal-*-journal"))


def test_rehearsal_rejects_copy_mismatch_without_publish(tmp_path: Path, monkeypatch) -> None:
    source, _ = populated_source(tmp_path)
    backup = source.parent / "backup.sqlite3"
    stage = source.parent / "stage.sqlite3"
    assert state_backup.create_backup(source, backup)["status"] == "PASS"
    original = state_backup._logical_assertions
    calls = 0

    def mismatch(path):
        nonlocal calls
        calls += 1
        assertions = original(path)
        if calls == 2:
            return assertions | {"logical_sha256": "0" * 64}
        return assertions

    monkeypatch.setattr(state_backup, "_logical_assertions", mismatch)
    assert state_backup.rehearse_restore(backup, stage) == {
        "status": "FAIL",
        "reason_code": "staging_mismatch",
    }
    assert not stage.exists()
    assert not list(source.parent.glob(".stage.sqlite3.rehearsal-*"))


def test_rehearsal_removes_its_publish_if_directory_sync_fails(tmp_path: Path, monkeypatch) -> None:
    source, _ = populated_source(tmp_path)
    backup = source.parent / "backup.sqlite3"
    stage = source.parent / "stage.sqlite3"
    assert state_backup.create_backup(source, backup)["status"] == "PASS"
    original_fsync = state_backup.os.fsync

    def fail_sync(fd):
        if stage.exists() and fd not in {0, 1, 2}:
            raise OSError("private sync error")
        return original_fsync(fd)

    monkeypatch.setattr(state_backup.os, "fsync", fail_sync)
    assert state_backup.rehearse_restore(backup, stage) == {
        "status": "UNKNOWN",
        "reason_code": "staging_interrupted",
    }
    assert not stage.exists()
    assert not list(source.parent.glob(".stage.sqlite3.rehearsal-*"))


@pytest.mark.parametrize("mutation", ["corrupt", "schema", "audit"])
def test_invalid_source_never_publishes_destination(tmp_path: Path, mutation: str) -> None:
    source, _ = populated_source(tmp_path)
    output = source.parent / "rejected.sqlite3"
    if mutation == "corrupt":
        source.write_bytes(b"invalid SQLite")
    else:
        with closing(sqlite3.connect(source)) as db:
            if mutation == "schema":
                db.execute("PRAGMA user_version=999")
            else:
                db.execute("UPDATE audit_events SET payload_json='{}' WHERE sequence=1")
            db.commit()
    result = state_backup.create_backup(source, output)
    assert result["status"] == "FAIL"
    assert not output.exists()
    assert not list(source.parent.glob(".rejected.sqlite3.partial-*"))


def test_rejects_existing_destination_and_alias_without_deleting_data(tmp_path: Path) -> None:
    source, _ = populated_source(tmp_path)
    existing = source.parent / "existing.sqlite3"
    existing.write_bytes(b"keep me")
    existing.chmod(0o600)
    assert state_backup.create_backup(source, existing)["reason_code"] == "destination_exists"
    assert existing.read_bytes() == b"keep me"
    assert state_backup.create_backup(source, source)["reason_code"] == "source_destination_alias"
    alias = source.parent / "alias.sqlite3"
    os.link(source, alias)
    assert state_backup.create_backup(source, alias)["reason_code"] == "source_destination_alias"
    assert source.exists() and alias.exists()


def test_rejects_symlinks_unsafe_parents_and_permissions(tmp_path: Path) -> None:
    source, _ = populated_source(tmp_path)
    link = source.parent / "linked.sqlite3"
    link.symlink_to(source)
    assert state_backup.verify_backup(link)["status"] == "FAIL"
    assert state_backup.create_backup(link, source.parent / "new.sqlite3")["status"] == "FAIL"
    assert state_backup.create_backup(source, link)["reason_code"] in {
        "destination_exists",
        "source_destination_alias",
    }
    broad = tmp_path / "broad"
    broad.mkdir(mode=0o700)
    broad.chmod(0o777)
    assert (
        state_backup.create_backup(source, broad / "new.sqlite3")["reason_code"] == "unsafe_parent"
    )
    source.chmod(0o644)
    assert (
        state_backup.create_backup(source, source.parent / "new.sqlite3")["reason_code"]
        == "unsafe_permissions"
    )


def test_failed_validation_cleans_only_own_partial_file(tmp_path: Path, monkeypatch) -> None:
    source, _ = populated_source(tmp_path)
    output = source.parent / "snapshot.sqlite3"
    unrelated = source.parent / ".unrelated.partial-keep"
    unrelated.write_bytes(b"keep me")

    def reject(_path):
        raise state_backup.BackupError("integrity_failed")

    monkeypatch.setattr(state_backup, "_inspect", reject)
    assert state_backup.create_backup(source, output) == {
        "status": "FAIL",
        "reason_code": "integrity_failed",
    }
    assert not output.exists()
    assert unrelated.read_bytes() == b"keep me"
    assert len(list(source.parent.glob(".snapshot.sqlite3.partial-*"))) == 0


def test_interrupted_backup_cleans_partial_without_touching_source(
    tmp_path: Path, monkeypatch
) -> None:
    source, _ = populated_source(tmp_path)
    output = source.parent / "snapshot.sqlite3"
    before = source.read_bytes()

    def interrupted(_source, temporary):
        temporary.write_bytes(b"incomplete private data")
        Path(str(temporary) + "-wal").write_bytes(b"partial WAL")
        raise sqlite3.OperationalError("private interruption detail")

    monkeypatch.setattr(state_backup, "_copy", interrupted)
    assert state_backup.create_backup(source, output) == {
        "status": "UNKNOWN",
        "reason_code": "backup_interrupted",
    }
    assert not output.exists()
    assert source.read_bytes() == before
    assert not list(source.parent.glob(".snapshot.sqlite3.partial-*"))
    assert not list(source.parent.glob(".snapshot.sqlite3.partial-*-wal"))


def test_cli_json_help_and_exit_codes(tmp_path: Path) -> None:
    source, _ = populated_source(tmp_path)
    backup = source.parent / "cli.sqlite3"
    runner = CliRunner()
    help_result = runner.invoke(app, ["state", "--help"])
    assert help_result.exit_code == 0
    assert "verify-backup" in help_result.output
    assert "rehearse-restore" in help_result.output
    assert "review-staging" in help_result.output
    created = runner.invoke(app, ["--db", str(source), "state", "backup", "--output", str(backup)])
    assert created.exit_code == 0, created.output
    assert json.loads(created.output)["status"] == "PASS"
    verified = runner.invoke(app, ["state", "verify-backup", str(backup)])
    assert verified.exit_code == 0
    assert json.loads(verified.output)["status"] == "PASS"
    active_db = source.parent / "must-not-be-created.sqlite3"
    stage = source.parent / "stage.sqlite3"
    rehearsed = runner.invoke(
        app,
        [
            "--db",
            str(active_db),
            "state",
            "rehearse-restore",
            str(backup),
            "--output",
            str(stage),
        ],
    )
    assert rehearsed.exit_code == 0, rehearsed.output
    result = json.loads(rehearsed.output)
    assert result["status"] == "PASS" and result["data_match"] is True
    assert str(tmp_path) not in rehearsed.output
    assert not active_db.exists()
    before_review = hashlib.sha256(stage.read_bytes()).hexdigest()
    reviewed = runner.invoke(app, ["state", "review-staging", str(stage)])
    assert reviewed.exit_code == 0
    assert json.loads(reviewed.output)["review"]["approvals"]["unused"] == 1
    assert hashlib.sha256(stage.read_bytes()).hexdigest() == before_review
    assert not active_db.exists()
    existing = runner.invoke(app, ["--db", str(source), "state", "backup", "--output", str(backup)])
    assert existing.exit_code == 1
    assert json.loads(existing.output) == {"status": "FAIL", "reason_code": "destination_exists"}
    assert str(tmp_path) not in existing.output
    linked_source = source.parent / "source-link.sqlite3"
    linked_source.symlink_to(source)
    symlink_result = runner.invoke(
        app,
        [
            "--db",
            str(linked_source),
            "state",
            "backup",
            "--output",
            str(source.parent / "no.sqlite3"),
        ],
    )
    assert symlink_result.exit_code == 1
    assert json.loads(symlink_result.output) == {"status": "FAIL", "reason_code": "unsafe_file"}
