from __future__ import annotations

import base64
import contextlib
import io
import json
import os
import subprocess
import sys
import threading
from pathlib import Path
from types import SimpleNamespace

import pytest
import yaml
from conftest import write_config_tree

from runbookos.actions import REGISTRY, validate_action
from runbookos.engine import RunbookEngine
from runbookos.errors import ConfigurationError
from runbookos.remote import REMOTE_SOURCE
from runbookos.ssh import SSHResult


def run_remote(monkeypatch, action: str, arguments: dict, *, timeout: int = 5) -> dict:
    request = {"action": action, "arguments": arguments, "timeout_seconds": timeout}
    encoded = base64.b64encode(json.dumps(request).encode()).decode()
    monkeypatch.setattr(sys, "argv", ["runbookos-remote", encoded])
    output = io.StringIO()
    with contextlib.redirect_stdout(output):
        exec(compile(REMOTE_SOURCE, "<runbookos-server-os-test>", "exec"), {"__name__": "__main__"})
    return json.loads(output.getvalue())


class PipeProcess:
    def __init__(self, output: bytes, *, exit_code: int = 0, delay: float = 0):
        read_fd, self.write_fd = os.pipe()
        self.stdout = os.fdopen(read_fd, "rb", buffering=0)
        self.returncode: int | None = None
        self.exit_code = exit_code
        self.killed = False

        def writer() -> None:
            try:
                if delay:
                    import time

                    time.sleep(delay)
                for offset in range(0, len(output), 4096):
                    os.write(self.write_fd, output[offset : offset + 4096])
            except OSError:
                pass
            finally:
                try:
                    os.close(self.write_fd)
                except OSError:
                    pass
                self.returncode = -9 if self.killed else self.exit_code

        self.thread = threading.Thread(target=writer, daemon=True)
        self.thread.start()

    def wait(self, timeout: float | None = None) -> int:
        self.thread.join(timeout)
        if self.thread.is_alive():
            raise subprocess.TimeoutExpired("fixture-command", timeout)
        if self.returncode is None:
            self.returncode = self.exit_code
        return self.returncode

    def poll(self) -> int | None:
        return self.returncode

    def kill(self) -> None:
        self.killed = True
        try:
            os.close(self.write_fd)
        except OSError:
            pass
        self.returncode = -9


def fake_command(monkeypatch, output: bytes, *, exit_code: int = 0, delay: float = 0):
    calls: list[list[str]] = []

    def popen(argv, **kwargs):
        calls.append(argv)
        return PipeProcess(output, exit_code=exit_code, delay=delay)

    monkeypatch.setattr(subprocess, "Popen", popen)
    return calls


def fake_process_table(
    monkeypatch, processes: list[tuple[int, int]], *, truncate_scan: bool = False
):
    original_open = open
    original_stat = os.stat
    original_scandir = os.scandir
    entries = [str(pid) for pid, _ in processes]
    if truncate_scan:
        entries.extend(f"fixture-{index}" for index in range(8192))

    class Entry:
        def __init__(self, name: str):
            self.name = name

    class Scan:
        def __enter__(self):
            return iter(Entry(name) for name in entries)

        def __exit__(self, *args):
            return None

    rss_by_pid = dict(processes)

    def fake_scandir(path):
        if path == "/proc":
            return Scan()
        return original_scandir(path)

    def fake_open(path, *args, **kwargs):
        if path in {f"/proc/{pid}/stat" for pid, _ in processes}:
            pid = int(path.split("/")[2])
            fields = ["0"] * 22
            fields[0] = "R"
            fields[1] = "1"
            fields[19] = "100"
            fields[21] = str(rss_by_pid[pid])
            return io.StringIO(f"{pid} (fixture-{pid}) " + " ".join(fields))
        return original_open(path, *args, **kwargs)

    def fake_stat(path, *args, **kwargs):
        if path in {f"/proc/{pid}" for pid, _ in processes}:
            return SimpleNamespace(st_uid=1000)
        return original_stat(path, *args, **kwargs)

    monkeypatch.setattr(os, "scandir", fake_scandir)
    monkeypatch.setattr(os, "stat", fake_stat)
    monkeypatch.setattr("builtins.open", fake_open)


@pytest.mark.parametrize(
    ("action", "valid", "invalid"),
    [
        ("os.cpu", {}, {"interval": 1}),
        ("os.release", {}, {"field": "anything"}),
        ("process.list", {"limit": 10, "order_by": "memory_rss"}, {"limit": 101}),
        ("process.inspect", {"pid": 1}, {"pid": True}),
        ("process.tree", {"pid": 1, "max_depth": 4, "max_nodes": 50}, {"pid": 1, "max_depth": 9}),
        ("filesystem.mounts", {}, {"path": "/"}),
        ("filesystem.inodes", {"path": "/var/lib"}, {"path": "/var/../etc"}),
        ("systemd.service_status", {"unit": "nginx.service"}, {"unit": "nginx.service;id"}),
        (
            "systemd.journal_summary",
            {"unit": "nginx.service", "window_minutes": 60},
            {"unit": "nginx.service", "max_entries": 201},
        ),
        ("systemd.timers", {"limit": 20}, {"limit": 0}),
        ("os.packages", {"limit": 20}, {"limit": 101}),
        ("os.cron", {"limit": 20}, {"limit": True}),
    ],
)
def test_server_os_actions_have_strict_typed_argument_schemas(action, valid, invalid):
    definition = validate_action(action, valid)
    assert definition.read_only is True
    assert definition.max_timeout_seconds <= 10
    with pytest.raises(ConfigurationError):
        validate_action(action, invalid)
    with pytest.raises(ConfigurationError):
        validate_action(action, {**valid, "command": "id; touch /tmp/pwned"})


def test_new_diagnostics_are_registered_read_only_actions():
    required = {
        "os.cpu",
        "os.release",
        "process.list",
        "process.inspect",
        "process.tree",
        "filesystem.mounts",
        "filesystem.inodes",
        "systemd.service_status",
        "systemd.journal_summary",
        "systemd.timers",
        "os.packages",
        "os.cron",
    }
    assert required <= REGISTRY.keys()
    assert all(REGISTRY[name].read_only for name in required)


def test_runbook_policy_is_target_scoped_and_default_deny(tmp_path: Path):
    paths = write_config_tree(tmp_path)
    runbook = tmp_path / "cpu.yml"
    runbook.write_text(
        "api_version: runbookos/v1\nkind: Runbook\nmetadata:\n"
        "  id: server-cpu-test\n  name: CPU inspection\n  description: synthetic test\n  risk: low\n"
        "targets: [test-web]\nsteps:\n  - id: cpu-check\n    action: os.cpu\n"
        "    timeout_seconds: 3\n    verify: [{path: data.logical_cpu_count, operator: gt, value: 0}]\n",
        encoding="utf-8",
    )
    engine = RunbookEngine(paths)
    assert engine.plan(runbook).status == "denied"

    policy = yaml.safe_load(paths.policy.read_text())
    policy["hosts"]["test-web"]["diagnostic_actions"].append("os.cpu")
    paths.policy.write_text(yaml.safe_dump(policy), encoding="utf-8")
    assert engine.plan(runbook).status == "ready"


def test_service_diagnostics_require_both_explicit_action_and_unit_allowlists(tmp_path: Path):
    paths = write_config_tree(tmp_path)
    runbook = tmp_path / "service-status.yml"
    runbook.write_text(
        "api_version: runbookos/v1\nkind: Runbook\nmetadata:\n"
        "  id: service-status-test\n  name: Service status\n  description: synthetic test\n  risk: low\n"
        "targets: [test-web]\nsteps:\n  - id: service-status\n"
        "    action: systemd.service_status\n    with: {unit: nginx.service}\n"
        "    timeout_seconds: 10\n    verify: [{path: data.loaded, operator: is_true}]\n",
        encoding="utf-8",
    )
    engine = RunbookEngine(paths)
    assert engine.plan(runbook).status == "denied"
    policy = yaml.safe_load(paths.policy.read_text())
    policy["hosts"]["test-web"]["diagnostic_actions"].append("systemd.service_status")
    policy["hosts"]["test-web"]["allowed_units"] = []
    paths.policy.write_text(yaml.safe_dump(policy), encoding="utf-8")
    assert engine.plan(runbook).status == "denied"
    policy["hosts"]["test-web"]["allowed_units"] = ["nginx.service"]
    paths.policy.write_text(yaml.safe_dump(policy), encoding="utf-8")
    assert engine.plan(runbook).status == "ready"


def test_multi_signal_diagnostics_persist_bounded_evidence_and_audit(tmp_path: Path):
    paths = write_config_tree(tmp_path)
    policy = yaml.safe_load(paths.policy.read_text())
    policy["hosts"]["test-web"]["diagnostic_actions"].extend(["os.cpu", "process.list"])
    paths.policy.write_text(yaml.safe_dump(policy), encoding="utf-8")
    runbook = tmp_path / "multi-signal.yml"
    runbook.write_text(
        "api_version: runbookos/v1\nkind: Runbook\nmetadata:\n"
        "  id: multi-signal-test\n  name: Multi-signal inspection\n  description: synthetic test\n  risk: low\n"
        "targets: [test-web]\nsteps:\n  - id: cpu\n    action: os.cpu\n"
        "    timeout_seconds: 3\n    verify: [{path: data.logical_cpu_count, operator: gt, value: 0}]\n"
        "  - id: processes\n    action: process.list\n    with: {limit: 2}\n"
        "    timeout_seconds: 5\n    verify: [{path: data.processes, operator: nonempty}]\n",
        encoding="utf-8",
    )

    class FakeExecutor:
        def execute(self, host, action, arguments, timeout_seconds):
            if action == "os.cpu":
                data = {"logical_cpu_count": 4, "load_average_1m": 0.1}
            else:
                data = {"processes": [{"pid": 42, "name": "fixture", "rss_bytes": 4096}]}
            return SSHResult(ok=True, data=data)

    engine = RunbookEngine(paths, executor=FakeExecutor())
    plan = engine.plan(runbook)
    assert plan.status == "ready"
    execution_id, status = engine.execute(plan.plan_id, diagnostic_only=True)
    assert status == "succeeded"
    persisted = engine.store.execution(execution_id)
    assert [step["action"] for step in persisted["steps"]] == ["os.cpu", "process.list"]
    assert all(step["target"] == "test-web" for step in persisted["steps"])
    assert persisted["steps"][0]["evidence"]["data"]["logical_cpu_count"] == 4
    assert persisted["steps"][1]["evidence"]["data"]["processes"][0]["pid"] == 42
    assert engine.store.verify_audit_chain()[0] is True


def test_local_os_process_mount_and_inode_observations_are_bounded_and_safe(
    monkeypatch, tmp_path: Path
):
    cpu = run_remote(monkeypatch, "os.cpu", {}, timeout=3)
    assert cpu["ok"] is True
    assert cpu["data"]["logical_cpu_count"] > 0
    assert cpu["data"]["cpu_count_includes_aggregate"] is True
    assert cpu["data"]["cpu_counters"]

    release = run_remote(monkeypatch, "os.release", {}, timeout=3)
    assert release["ok"] is True
    assert release["data"]["kernel_name"] == os.uname().sysname
    assert release["data"]["machine_architecture"]

    processes = run_remote(monkeypatch, "process.list", {"limit": 3, "order_by": "memory_rss"})
    assert processes["ok"] is True
    assert len(processes["data"]["processes"]) <= 3
    assert processes["data"]["command_lines_included"] is False
    assert all("command" not in item for item in processes["data"]["processes"])

    inspected = run_remote(monkeypatch, "process.inspect", {"pid": os.getpid()})
    assert inspected["ok"] is True
    assert inspected["data"]["process"]["pid"] == os.getpid()
    assert inspected["data"]["command_line_included"] is False

    tree = run_remote(
        monkeypatch, "process.tree", {"pid": os.getpid(), "max_depth": 2, "max_nodes": 3}
    )
    assert tree["ok"] is True
    assert tree["data"]["processes"][0]["pid"] == os.getpid()
    assert len(tree["data"]["processes"]) <= 3

    mounts = run_remote(monkeypatch, "filesystem.mounts", {})
    assert mounts["ok"] is True
    assert mounts["data"]["mounts"]
    assert mounts["data"]["device_sources_included"] is False
    assert all(
        set(mount) == {"mountpoint", "filesystem_type", "read_only"}
        for mount in mounts["data"]["mounts"]
    )

    inodes = run_remote(monkeypatch, "filesystem.inodes", {"path": str(tmp_path)}, timeout=3)
    assert inodes["ok"] is True
    assert inodes["data"]["total_inodes"] >= inodes["data"]["free_inodes"] >= 0


def test_process_list_memory_order_returns_highest_rss_top_k_and_marks_output_truncation(
    monkeypatch,
):
    fake_process_table(monkeypatch, [(11, 100), (22, 800), (33, 500), (44, 200), (55, 600)])

    result = run_remote(
        monkeypatch, "process.list", {"order_by": "memory_rss", "limit": 3}, timeout=5
    )

    assert result["ok"] is True
    assert [item["pid"] for item in result["data"]["processes"]] == [22, 55, 33]
    assert [item["rss_bytes"] for item in result["data"]["processes"]] == [
        800 * os.sysconf("SC_PAGE_SIZE"),
        600 * os.sysconf("SC_PAGE_SIZE"),
        500 * os.sysconf("SC_PAGE_SIZE"),
    ]
    assert result["data"]["truncated"] is True
    assert result["data"]["scan_truncated"] is False
    assert result["data"]["inventory_complete"] is False
    assert result["data"]["scanned_processes"] == 5
    assert result["data"]["command_lines_included"] is False

    fake_process_table(monkeypatch, [(202, 400), (201, 400), (203, 100)])
    tied = run_remote(
        monkeypatch, "process.list", {"order_by": "memory_rss", "limit": 2}, timeout=5
    )
    assert [item["pid"] for item in tied["data"]["processes"]] == [201, 202]


def test_process_list_pid_order_and_process_tree_report_incomplete_scans(monkeypatch):
    fake_process_table(monkeypatch, [(30, 300), (10, 100), (20, 200)])
    pid_order = run_remote(monkeypatch, "process.list", {"limit": 2}, timeout=5)
    assert [item["pid"] for item in pid_order["data"]["processes"]] == [10, 20]
    assert pid_order["data"]["truncated"] is True
    assert pid_order["data"]["scan_truncated"] is False
    assert pid_order["data"]["inventory_complete"] is False

    fake_process_table(monkeypatch, [(100, 64)], truncate_scan=True)
    tree = run_remote(
        monkeypatch,
        "process.tree",
        {"pid": 100, "max_depth": 2, "max_nodes": 5},
        timeout=5,
    )
    assert tree["ok"] is True
    assert [item["pid"] for item in tree["data"]["processes"]] == [100]
    assert tree["data"]["truncated"] is True
    assert tree["data"]["scan_truncated"] is True
    assert tree["data"]["inventory_complete"] is False

    missing = run_remote(monkeypatch, "process.inspect", {"pid": 999999}, timeout=3)
    assert missing["ok"] is False
    assert missing["error"] == "process_unavailable"


def test_os_release_metadata_is_parsed_as_data_not_executed(monkeypatch, tmp_path: Path):
    marker = tmp_path / "injected-command-ran"
    payload = f'ID=fixture\nNAME="Demo; touch {marker}"\nVERSION_ID=1.2\n'
    original_open = open

    def fake_open(path, *args, **kwargs):
        if path == "/etc/os-release":
            return io.StringIO(payload)
        return original_open(path, *args, **kwargs)

    monkeypatch.setattr("builtins.open", fake_open)
    result = run_remote(monkeypatch, "os.release", {}, timeout=3)
    assert result["ok"] is True
    assert "touch" in result["data"]["distribution_name"]
    assert not marker.exists()


def test_service_journal_timer_and_failed_unit_diagnostics_use_fixed_commands(monkeypatch):
    status_output = (
        b"Id=nginx.service\nLoadState=loaded\nActiveState=active\nSubState=running\n"
        b"UnitFileState=enabled\nResult=success\nExecMainStatus=0\n"
    )
    calls = fake_command(monkeypatch, status_output)
    status = run_remote(
        monkeypatch, "systemd.service_status", {"unit": "nginx.service"}, timeout=10
    )
    assert status["ok"] is True and status["data"]["active"] is True
    assert calls[0][:2] == ["/usr/bin/systemctl", "show"]
    assert calls[0][-1] == "nginx.service"

    fake_command(monkeypatch, b"ActiveState=active\n")
    incomplete = run_remote(
        monkeypatch, "systemd.service_status", {"unit": "nginx.service"}, timeout=10
    )
    assert incomplete["ok"] is False
    assert incomplete["error"] == "invalid_service_status_output"

    journal = (
        json.dumps(
            {"PRIORITY": "3", "__REALTIME_TIMESTAMP": "100", "MESSAGE": "token=must-not-escape"}
        ).encode()
        + b"\n"
        + json.dumps(
            {"PRIORITY": "6", "__REALTIME_TIMESTAMP": "200", "MESSAGE": "private diagnostic text"}
        ).encode()
        + b"\n"
    )
    fake_command(monkeypatch, journal)
    summary = run_remote(
        monkeypatch,
        "systemd.journal_summary",
        {"unit": "nginx.service", "window_minutes": 30, "max_entries": 10},
        timeout=10,
    )
    assert summary["ok"] is True
    assert summary["data"]["priority_counts"]["3"] == 1
    assert summary["data"]["messages_included"] is False
    assert summary["data"]["sample_limit_reached"] is False
    assert "must-not-escape" not in json.dumps(summary)
    assert "private diagnostic text" not in json.dumps(summary)

    fake_command(monkeypatch, b"- - - - maintenance.timer maintenance.service\n")
    timers = run_remote(monkeypatch, "systemd.timers", {"limit": 4}, timeout=10)
    assert timers["ok"] is True
    assert timers["data"]["timers"] == [
        {
            "unit": "maintenance.timer",
            "activates": "maintenance.service",
            "schedule_summary": "- - - -",
        }
    ]

    fake_command(monkeypatch, b"broken.service loaded failed failed\n")
    failed = run_remote(monkeypatch, "systemd.failed_units", {}, timeout=10)
    assert failed["ok"] is True and failed["data"]["units"] == ["broken.service"]


def test_systemd_and_package_diagnostics_fail_closed_on_timeout_and_output_limit(monkeypatch):
    calls = fake_command(monkeypatch, b"", delay=1.5)
    timed_out = run_remote(
        monkeypatch,
        "systemd.journal_summary",
        {"unit": "nginx.service"},
        timeout=1,
    )
    assert timed_out["ok"] is False
    assert timed_out["error"] == "TimeoutError"
    assert len(calls) == 1

    calls = fake_command(monkeypatch, b"x" * 262145)
    oversized = run_remote(monkeypatch, "os.packages", {"limit": 1}, timeout=10)
    assert oversized["ok"] is False
    assert oversized["error"] == "output_limit"
    assert len(calls) == 1


def test_package_and_cron_summaries_are_bounded_and_omit_cron_commands(monkeypatch):
    original_isfile = os.path.isfile
    monkeypatch.setattr(
        os.path, "isfile", lambda path: path == "/usr/bin/dpkg-query" or original_isfile(path)
    )
    calls = fake_command(
        monkeypatch,
        b"alpha\t1.0\tii \nbeta\t2.0\tii \nnot-installed\t3.0\trc \n",
    )
    packages = run_remote(monkeypatch, "os.packages", {"limit": 1}, timeout=10)
    assert calls[0][0] == "/usr/bin/dpkg-query"
    if packages["ok"]:
        assert packages["data"]["packages"] == [{"name": "alpha", "version": "1.0"}]
        assert packages["data"]["output_truncated"] is True
    fake_command(monkeypatch, b"malformed package output\n")
    malformed = run_remote(monkeypatch, "os.packages", {"limit": 1}, timeout=10)
    assert malformed["ok"] is False
    assert malformed["error"] == "invalid_package_record"

    namespace = {}
    encoded = base64.b64encode(
        json.dumps({"action": "load_helpers", "arguments": {}}).encode()
    ).decode()
    monkeypatch.setattr(sys, "argv", ["runbookos-remote", encoded])
    with contextlib.redirect_stdout(io.StringIO()):
        exec(compile(REMOTE_SOURCE, "<runbookos-helper-test>", "exec"), namespace)
    original_scandir = os.scandir

    class Entry:
        def __init__(self, name: str):
            self.name = name

        def is_file(self, *, follow_symlinks=True):
            return True

        def is_symlink(self):
            return False

    class Scan:
        def __init__(self, names):
            self.names = [Entry(name) for name in names]

        def __enter__(self):
            return iter(self.names)

        def __exit__(self, *args):
            return None

    def fake_scandir(path):
        if path == "/etc/cron.d":
            return Scan(["fixture-job"])
        if path.startswith("/etc/cron."):
            return Scan([])
        return original_scandir(path)

    monkeypatch.setattr(os, "scandir", fake_scandir)
    namespace["read_bounded_regular"] = lambda path, limit: (
        "*/5 * * * * root /usr/bin/echo SECRET_COMMAND\n"
    )
    cron = namespace["cron_records"](10)
    assert cron["entries"] == [
        {"source": "crontab", "schedule": "*/5 * * * *"},
        {"source": "fixture-job", "schedule": "*/5 * * * *"},
    ]
    assert "SECRET_COMMAND" not in json.dumps(cron)
    assert "command" not in json.dumps(cron).lower()


def test_example_server_os_runbooks_and_policy_parse_and_plan(tmp_path: Path):
    paths = write_config_tree(tmp_path)
    inventory = yaml.safe_load(paths.inventory.read_text())
    inventory["hosts"]["example-web-01"] = inventory["hosts"].pop("test-web")
    inventory["hosts"]["example-web-01"]["role"] = "web-server"
    inventory["hosts"]["example-app-01"] = dict(inventory["hosts"]["example-web-01"])
    inventory["hosts"]["example-app-01"]["role"] = "application-server"
    paths.inventory.write_text(yaml.safe_dump(inventory), encoding="utf-8")

    policy = yaml.safe_load(paths.policy.read_text())
    web = [
        "os.cpu",
        "os.release",
        "process.list",
        "filesystem.mounts",
        "filesystem.inodes",
        "systemd.service_status",
        "systemd.failed_units",
        "systemd.journal_summary",
        "systemd.timers",
        "os.packages",
        "os.cron",
    ]
    policy["hosts"] = {
        "example-web-01": {
            "diagnostic_actions": web,
            "remediation_actions": [],
            "allowed_storage_paths": ["/"],
            "allowed_units": ["nginx.service"],
        },
        "example-app-01": {
            "diagnostic_actions": web + ["process.inspect", "process.tree"],
            "remediation_actions": [],
            "allowed_storage_paths": ["/"],
            "allowed_units": ["runbookos-sample.service"],
        },
    }
    paths.policy.write_text(yaml.safe_dump(policy), encoding="utf-8")
    repo = Path(__file__).resolve().parents[1]
    for filename in ("server-os-inspection.yml", "server-os-process-tree.yml"):
        plan = RunbookEngine(paths).plan(repo / "examples/runbooks" / filename)
        assert plan.status == "ready", plan.actions
        assert all(action.read_only and action.allowed for action in plan.actions)
