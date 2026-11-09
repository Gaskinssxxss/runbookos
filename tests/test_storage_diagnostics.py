from __future__ import annotations

import base64
import contextlib
import io
import json
import os
import socket
import sys
from types import SimpleNamespace

import pytest
import yaml
from conftest import write_config_tree
from pydantic import ValidationError

from runbookos.actions import validate_action
from runbookos.engine import RunbookEngine
from runbookos.errors import ConfigurationError, PolicyDenied
from runbookos.models import HostPolicy, StorageTarget
from runbookos.remote import REMOTE_SOURCE
from runbookos.ssh import SSHResult
from runbookos.storage_correlation import correlate_storage


def helpers():
    namespace = {}
    exec(compile(REMOTE_SOURCE.split("\ntry:\n", 1)[0], "<storage-helpers>", "exec"), namespace)
    namespace["mount_records"] = lambda limit=256: ([], False)
    return namespace


def dispatch_raw(monkeypatch, action, arguments, *, timeout=5):
    request = {
        "action": action,
        "arguments": arguments,
        "timeout_seconds": timeout,
    }
    encoded = base64.b64encode(json.dumps(request).encode()).decode()
    monkeypatch.setattr(sys, "argv", ["remote", encoded])
    output = io.StringIO()
    with contextlib.redirect_stdout(output):
        exec(compile(REMOTE_SOURCE, "<storage-dispatch>", "exec"), {"__name__": "__main__"})
    return json.loads(output.getvalue())


def dispatch(monkeypatch, action, target, *, timeout=5, **arguments):
    return dispatch_raw(
        monkeypatch,
        action,
        {"storage_id": "sample", "_storage": target, **arguments},
        timeout=timeout,
    )


@pytest.mark.parametrize(
    ("action", "args"),
    [
        ("filesystem.mount_status", {"storage_id": "sample"}),
        ("filesystem.pressure", {"storage_id": "sample"}),
        ("filesystem.path_metadata", {"storage_id": "sample"}),
        ("filesystem.usage_summary", {"storage_id": "sample", "max_entries": 8}),
        ("filesystem.log_growth", {"storage_id": "sample", "interval_seconds": 1}),
    ],
)
def test_registered_actions_have_strict_alias_only_schema(action, args):
    definition = validate_action(action, args)
    assert definition.read_only and definition.max_timeout_seconds <= 5
    for invalid in ({**args, "path": "/etc/shadow"}, {**args, "command": "rm -rf /"}):
        with pytest.raises(ConfigurationError):
            validate_action(action, invalid)


def test_legacy_disk_and_inode_evidence_keeps_old_fields_and_marks_capacity(tmp_path, monkeypatch):
    disk = dispatch_raw(monkeypatch, "os.disk", {"path": str(tmp_path)}, timeout=3)
    assert disk["ok"] is True
    assert {"path", "total_bytes", "used_bytes", "free_bytes", "percent"} <= set(disk["data"])
    assert disk["data"]["capacity_known"] is True
    assert disk["data"]["status"] in {"available", "full"}
    inode = dispatch_raw(monkeypatch, "filesystem.inodes", {"path": str(tmp_path)}, timeout=3)
    assert inode["ok"] is True
    assert {
        "path",
        "filesystem_type",
        "total_inodes",
        "free_inodes",
        "used_percent",
        "inode_capacity_known",
    } <= set(inode["data"])
    assert inode["data"]["status"] in {"available", "full", "unknown"}


@pytest.mark.parametrize("action", ["os.disk", "filesystem.inodes"])
def test_legacy_storage_diagnostics_reject_symlink_even_if_explicitly_selected(
    tmp_path, monkeypatch, action
):
    real = tmp_path / "real"
    real.mkdir()
    link = tmp_path / "link"
    link.symlink_to(real, target_is_directory=True)
    result = dispatch_raw(monkeypatch, action, {"path": str(link)}, timeout=3)
    assert result["ok"] is False
    assert result["data"]["status"] == "unknown"


@pytest.mark.parametrize(
    "path", ["/tmp/../etc", "//tmp/x", "/tmp//x", "/tmp/./x", "/tmp/x/", "/tmp/evil\n"]
)
def test_storage_inventory_rejects_unsafe_paths(path):
    with pytest.raises(ValidationError):
        StorageTarget(path=path, kind="directory")


@pytest.mark.parametrize(
    "path", ["/var/../etc", "//var", "/var//log", "/var/./log", "/var/log/", "relative"]
)
def test_legacy_storage_policy_rejects_noncanonical_paths(path):
    with pytest.raises(ValidationError):
        HostPolicy(allowed_storage_paths=[path])


def test_legacy_storage_paths_require_exact_host_allowlist_at_plan_and_execution(tmp_path):
    paths = write_config_tree(tmp_path)
    policy = yaml.safe_load(paths.policy.read_text())
    policy["hosts"]["test-web"]["diagnostic_actions"] = ["os.disk", "filesystem.inodes"]
    paths.policy.write_text(yaml.safe_dump(policy))
    runbook = tmp_path / "legacy-storage.yml"

    def plan_for(action, arguments):
        runbook.write_text(
            yaml.safe_dump(
                {
                    "api_version": "runbookos/v1",
                    "kind": "Runbook",
                    "metadata": {
                        "id": "legacy-storage",
                        "name": "Legacy storage",
                        "description": "Offline check",
                        "risk": "low",
                    },
                    "targets": ["test-web"],
                    "steps": [
                        {"id": "check", "action": action, "with": arguments, "timeout_seconds": 3}
                    ],
                }
            )
        )
        return RunbookEngine(paths).plan(runbook)

    for action in ("os.disk", "filesystem.inodes"):
        assert plan_for(action, {"path": "/var"}).status == "denied"
        with pytest.raises(ConfigurationError):
            plan_for(action, {"path": "/var/../etc"})
    # The historical pathless disk check remains a root-only default.
    assert plan_for("os.disk", {}).status == "ready"
    policy["hosts"]["test-web"]["allowed_storage_paths"] = ["/"]
    paths.policy.write_text(yaml.safe_dump(policy))
    assert plan_for("os.disk", {"path": "/"}).status == "ready"
    assert plan_for("filesystem.inodes", {"path": "/"}).status == "ready"
    assert plan_for("os.disk", {"path": "/var"}).status == "denied"

    # A symlink spelling cannot borrow the allowlist entry of its target.
    real = tmp_path / "real"
    real.mkdir()
    link = tmp_path / "link"
    link.symlink_to(real, target_is_directory=True)
    policy["hosts"]["test-web"]["allowed_storage_paths"] = [str(real)]
    paths.policy.write_text(yaml.safe_dump(policy))
    assert plan_for("os.disk", {"path": str(link)}).status == "denied"
    assert plan_for("filesystem.inodes", {"path": str(link)}).status == "denied"

    plan = plan_for("os.disk", {"path": str(real)})
    assert plan.status == "ready"
    policy["hosts"]["test-web"]["allowed_storage_paths"] = []
    paths.policy.write_text(yaml.safe_dump(policy))
    with pytest.raises(PolicyDenied, match="configuration changed"):
        RunbookEngine(paths).execute(plan.plan_id, diagnostic_only=True)

    policy["hosts"]["test-web"]["allowed_storage_paths"] = [str(real)]
    paths.policy.write_text(yaml.safe_dump(policy))
    plan = plan_for("os.disk", {"path": str(real)})
    inventory = yaml.safe_load(paths.inventory.read_text())
    inventory["hosts"]["test-web"]["role"] = "app-server"
    paths.inventory.write_text(yaml.safe_dump(inventory))
    with pytest.raises(PolicyDenied, match="configuration changed"):
        RunbookEngine(paths).execute(plan.plan_id, diagnostic_only=True)


def test_metadata_never_reads_contents_or_follows_symlinks(tmp_path):
    root = tmp_path / "root"
    root.mkdir()
    file = root / "service.log"
    file.write_bytes(b"private contents")
    (root / "link").symlink_to(file)
    (root / "broken").symlink_to(root / "missing")
    namespace = helpers()
    for path, kind in ((file, "file"), (root / "link", "symlink"), (root / "broken", "symlink")):
        record, error = namespace["storage_metadata"]("sample", str(path))
        assert error is None
        assert record["type"] == kind
        assert record["contents_included"] is False
        assert "private contents" not in json.dumps(record)
    (root / "parent").symlink_to(root)
    rejected, error = namespace["storage_metadata"]("sample", str(root / "parent" / "service.log"))
    assert rejected["status"] == "unknown"
    assert error == "path_unavailable"


def test_usage_deduplicates_hardlinks_and_skips_special_files(tmp_path):
    root = tmp_path / "root"
    root.mkdir()
    file = root / "a"
    file.write_bytes(b"12345")
    os.link(file, root / "b")
    (root / "link").symlink_to(file)
    os.mkfifo(root / "pipe")
    socket_path = root / "sock"
    with socket.socket(socket.AF_UNIX) as sock:
        sock.bind(str(socket_path))
        data, error = helpers()["storage_usage"]("sample", str(root), 16, 3)
    assert error is None
    assert data["total_bytes"] == 5
    assert data["hardlinks_deduplicated"] == 1
    assert data["symlinks_skipped"] == 1
    assert data["special_files_skipped"] == 2
    assert data["inventory_complete"] is True


def test_usage_truncation_and_mount_crossing_are_unknown_or_skipped(tmp_path):
    root = tmp_path / "root"
    root.mkdir()
    (root / "a").write_text("a")
    (root / "b").write_text("b")
    namespace = helpers()
    truncated, error = namespace["storage_usage"]("sample", str(root), 1, 3)
    assert error is None
    assert truncated["status"] == "unknown"
    assert truncated["truncated"] is True
    namespace["mount_records"] = lambda limit=256: ([{"mountpoint": str(root / "a")}], False)
    complete, error = namespace["storage_usage"]("sample", str(root), 16, 3)
    assert error is None
    assert complete["mounts_skipped"] == 1
    assert complete["total_bytes"] == 1
    namespace["mount_records"] = lambda limit=256: ([], False)
    mounts = iter([1, 2, 2])
    namespace["storage_mount_id"] = lambda fd: next(mounts)
    crossed, error = namespace["storage_usage"]("sample", str(root), 16, 3)
    assert error is None
    assert crossed["mounts_skipped"] == 2
    assert crossed["total_bytes"] == 0
    namespace["mount_records"] = lambda limit=256: ([], True)
    unknown, error = namespace["storage_usage"]("sample", str(root), 16, 3)
    assert error == "mount_inventory_unavailable"
    assert unknown["status"] == "unknown"


def test_usage_timeout_and_directory_replacement_fail_closed(tmp_path):
    root = tmp_path / "root"
    root.mkdir()
    (root / "child").mkdir()
    namespace = helpers()
    ticks = iter([0, 0, 4])
    namespace["time"] = SimpleNamespace(monotonic=lambda: next(ticks))
    timed_out, error = namespace["storage_usage"]("sample", str(root), 16, 3)
    assert error is None
    assert timed_out["truncated"] is True and timed_out["status"] == "unknown"

    namespace = helpers()
    real_open = os.open
    switched = False

    def replace_during_open(path, flags, *args, **kwargs):
        nonlocal switched
        if path == "child" and flags & os.O_DIRECTORY and not switched:
            switched = True
            (root / "child").rename(root / "former")
            (root / "child").mkdir()
        return real_open(path, flags, *args, **kwargs)

    namespace["os"] = SimpleNamespace(**vars(os))
    namespace["os"].open = replace_during_open
    changed, error = namespace["storage_usage"]("sample", str(root), 16, 3)
    assert error == "entry_changed"
    assert changed["status"] == "unknown"


def test_usage_entry_budget_stops_before_queued_directories(tmp_path):
    root = tmp_path / "root"
    root.mkdir()
    for name in ("first", "second"):
        child = root / name
        child.mkdir()
        (child / "payload").write_text("unvisited")
    result, error = helpers()["storage_usage"]("sample", str(root), 2, 3)
    assert error is None
    assert result["entries_scanned"] == 2
    assert result["directories"] == 1
    assert result["regular_files"] == 0
    assert result["truncated"] is True
    assert result["status"] == "unknown"


def test_usage_timeout_stops_before_queued_directories(tmp_path):
    root = tmp_path / "root"
    root.mkdir()
    for name in ("first", "second"):
        (root / name).mkdir()
    namespace = helpers()
    ticks = iter([0, 0, 0, 0, 4])
    namespace["time"] = SimpleNamespace(monotonic=lambda: next(ticks))
    result, error = namespace["storage_usage"]("sample", str(root), 16, 3)
    assert error is None
    assert result["entries_scanned"] == 2
    assert result["directories"] == 1
    assert result["truncated"] is True
    assert result["status"] == "unknown"


def test_usage_missing_mount_identity_and_permission_denial_are_unknown(tmp_path):
    root = tmp_path / "root"
    root.mkdir()
    namespace = helpers()
    namespace["storage_mount_id"] = lambda fd: None
    unknown, error = namespace["storage_usage"]("sample", str(root), 16, 3)
    assert error == "mount_identity_unavailable"
    assert unknown["status"] == "unknown"

    namespace = helpers()
    namespace["storage_fd"] = lambda path, directory=False: (_ for _ in ()).throw(PermissionError())
    denied, error = namespace["storage_usage"]("sample", str(root), 16, 3)
    assert error == "permission_denied"
    assert denied["status"] == "unknown"


@pytest.mark.parametrize(
    ("available_blocks", "free_inodes", "expected"),
    [(0, 0, "both_full"), (0, 10, "byte_full"), (10, 0, "inode_full"), (10, 10, "available")],
)
def test_pressure_distinguishes_byte_and_inode_exhaustion(
    tmp_path, monkeypatch, available_blocks, free_inodes, expected
):
    namespace = helpers()
    monkeypatch.setattr(
        os,
        "fstatvfs",
        lambda fd: SimpleNamespace(
            f_blocks=100,
            f_frsize=4096,
            f_bfree=available_blocks,
            f_bavail=available_blocks,
            f_files=100,
            f_ffree=free_inodes,
            f_flag=os.ST_RDONLY,
        ),
    )
    data, error = namespace["storage_pressure"]("sample", str(tmp_path))
    assert error is None
    assert data["status"] == expected
    assert data["read_only"] is True
    assert data["available_bytes"] == available_blocks * 4096


def test_pressure_unknown_capacity_and_permission_failure(tmp_path, monkeypatch):
    namespace = helpers()
    monkeypatch.setattr(
        os,
        "fstatvfs",
        lambda fd: SimpleNamespace(
            f_blocks=0,
            f_frsize=4096,
            f_bfree=0,
            f_bavail=0,
            f_files=0,
            f_ffree=0,
            f_flag=0,
        ),
    )
    unknown, error = namespace["storage_pressure"]("sample", str(tmp_path))
    assert error is None and unknown["status"] == "unknown"
    monkeypatch.setattr(
        os, "open", lambda *args, **kwargs: (_ for _ in ()).throw(PermissionError())
    )
    denied, error = namespace["storage_pressure"]("sample", str(tmp_path))
    assert error == "permission_denied" and denied["status"] == "unknown"


def test_growth_requires_two_snapshots_and_stable_inode(tmp_path, monkeypatch):
    file = tmp_path / "service.log"
    file.write_bytes(b"one")
    namespace = helpers()
    monkeypatch.setattr(namespace["time"], "sleep", lambda seconds: file.write_bytes(b"one-two"))
    growing, error = namespace["storage_growth"]("sample", str(file), 1)
    assert error is None
    assert growing["status"] == "growing"
    assert growing["growth_bytes"] == 4
    assert len(growing["snapshots"]) == 2
    assert growing["interval_seconds"] is not None
    monkeypatch.setattr(namespace["time"], "sleep", lambda seconds: file.rename(tmp_path / "old"))
    unknown, error = namespace["storage_growth"]("sample", str(file), 1)
    assert error == "path_unavailable"
    assert unknown["status"] == "unknown"


def test_dispatch_rejects_forged_scope_and_wrong_kind(monkeypatch, tmp_path):
    target = {"path": str(tmp_path), "kind": "directory"}
    valid = dispatch(monkeypatch, "filesystem.path_metadata", target, timeout=3)
    assert valid["ok"] is True
    assert valid["data"]["type"] == "directory"
    assert valid["data"]["contents_included"] is False
    forged = dispatch(
        monkeypatch,
        "filesystem.path_metadata",
        {"path": "/tmp/../etc", "kind": "directory"},
        timeout=3,
    )
    assert forged["ok"] is False
    command = dispatch(
        monkeypatch,
        "filesystem.path_metadata",
        target,
        timeout=3,
        command="sudo chmod -R 777 /",
    )
    assert command["ok"] is False
    wrong_kind = dispatch(monkeypatch, "filesystem.log_growth", target, timeout=5)
    assert wrong_kind["ok"] is False


def test_mount_status_separates_missing_read_only_and_incomplete_inventory(tmp_path):
    target = {"path": str(tmp_path / "expected"), "kind": "mount"}
    namespace = helpers()
    namespace["mount_records"] = lambda limit=256: (
        [{"mountpoint": target["path"], "filesystem_type": "ext4", "read_only": True}],
        False,
    )
    found, error = namespace["storage_mount_status"]("sample", target["path"])
    assert error is None
    assert found["status"] == "present" and found["read_only"] is True
    namespace["mount_records"] = lambda limit=256: ([], False)
    missing, error = namespace["storage_mount_status"]("sample", target["path"])
    assert error is None
    assert missing["status"] == "missing" and missing["present"] is False
    namespace["mount_records"] = lambda limit=256: ([], True)
    incomplete, error = namespace["storage_mount_status"]("sample", target["path"])
    assert error is None
    assert incomplete["status"] == "unknown" and incomplete["present"] is None
    namespace["mount_records"] = lambda limit=256: (None, False)
    unavailable, error = namespace["storage_mount_status"]("sample", target["path"])
    assert error == "mount_inventory_unavailable" and unavailable["status"] == "unknown"


def test_planning_requires_exact_storage_target_and_host_policy(tmp_path):
    paths = write_config_tree(tmp_path)
    inventory = yaml.safe_load(paths.inventory.read_text())
    inventory["hosts"]["test-web"]["storage_targets"] = {
        "sample": {"path": str(tmp_path), "kind": "directory"}
    }
    paths.inventory.write_text(yaml.safe_dump(inventory))
    policy = yaml.safe_load(paths.policy.read_text())
    policy["hosts"]["test-web"]["diagnostic_actions"] = ["filesystem.usage_summary"]
    paths.policy.write_text(yaml.safe_dump(policy))
    runbook = tmp_path / "storage.yml"
    runbook.write_text(
        "api_version: runbookos/v1\nkind: Runbook\nmetadata:\n"
        "  id: storage-review\n  name: Storage review\n  description: Synthetic storage.\n  risk: low\n"
        "targets: [test-web]\nsteps:\n"
        "  - id: usage\n    action: filesystem.usage_summary\n"
        "    with: {storage_id: sample, max_entries: 5}\n    timeout_seconds: 5\n"
    )
    engine = RunbookEngine(paths)
    assert engine.plan(runbook).status == "denied"
    policy["hosts"]["test-web"]["allowed_storage_targets"] = ["sample"]
    paths.policy.write_text(yaml.safe_dump(policy))

    class Fake:
        def execute(self, host, action, arguments, timeout_seconds):
            assert action == "filesystem.usage_summary"
            assert arguments["_storage"] == {"path": str(tmp_path), "kind": "directory"}
            return SSHResult(ok=True, data={"status": "unknown"}, uncertain=True)

    engine = RunbookEngine(paths, executor=Fake())
    plan = engine.plan(runbook)
    assert plan.status == "ready"
    execution_id, status = engine.execute(plan.plan_id, diagnostic_only=True)
    assert status == "unknown"
    assert engine.store.execution(execution_id)["steps"][0]["status"] == "unknown"
    assert engine.store.execution(execution_id)["execution"]["summary"]["storage_correlation"] == {
        "signals": [],
        "unknown_steps": ["usage"],
        "verified_root_cause": False,
    }
    assert engine.store.verify_audit_chain()[0] is True


def test_multi_fault_correlation_keeps_provenance_and_unknowns():
    def step(step_id, action, data, status="succeeded"):
        return {"step_id": step_id, "action": action, "status": status, "evidence": {"data": data}}

    result = correlate_storage(
        [
            step("pressure", "filesystem.pressure", {"status": "both_full", "read_only": True}),
            step(
                "mount",
                "filesystem.mount_status",
                {"status": "missing", "inventory_complete": True},
            ),
            step("growth", "filesystem.log_growth", {"status": "growing", "snapshots": [{}, {}]}),
            {
                **step("permission", "filesystem.path_metadata", {"status": "unknown"}, "unknown"),
                "evidence": {"data": {"status": "unknown"}, "error": "permission_denied"},
            },
            step(
                "truncated",
                "filesystem.mount_status",
                {"status": "unknown", "inventory_complete": False},
                "unknown",
            ),
        ]
    )
    assert {signal["signal"] for signal in result["signals"]} == {
        "byte_capacity_exhausted",
        "inode_capacity_exhausted",
        "filesystem_read_only",
        "expected_mount_missing",
        "log_size_increased",
        "inspection_permission_denied",
    }
    assert all(signal["claim_status"] == "observed" for signal in result["signals"])
    assert result["unknown_steps"] == ["permission", "truncated"]
    assert result["verified_root_cause"] is False
