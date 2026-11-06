from __future__ import annotations

import functools
import importlib.util
import json
import socket
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest
from ai_acceptance_config_v060 import ACCEPTANCE_PORT, LOOPBACK, PROVIDER_ENDPOINT
from ai_acceptance_harness_v060 import (
    ResourceLimitExceeded,
    ResourceMonitorError,
    create_synthetic_tree,
    run_five_scenario_acceptance,
    sample_acceptance_server,
)

from runbookos.ai import ModelReply
from runbookos.store import SQLiteStore

SCRIPT = Path(__file__).resolve().parents[1] / "scripts/ai-local-acceptance-v060.py"


def _load_script():
    name = "ai_local_acceptance_v060_test_module"
    spec = importlib.util.spec_from_file_location(name, SCRIPT)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


class FakePopen:
    def __init__(self, pid: int = 4321):
        self.pid = pid
        self._exit_code = None
        self.terminated = False
        self.killed = False
        self.terminate_calls = 0
        self._event = threading.Event()

    def poll(self):
        return self._exit_code

    def terminate(self):
        self.terminate_calls += 1
        self.terminated = True
        self._exit_code = 0
        self._event.set()

    def kill(self):
        self.killed = True
        self._exit_code = -9
        self._event.set()

    def wait(self, timeout=None):
        return self._exit_code

    def wait_terminated(self, timeout=2):
        return self._event.wait(timeout)


def _proc_tree(root: Path, pid: int, executable: Path, rss_kib: int = 1024):
    pid_dir = root / str(pid)
    (pid_dir / "fd").mkdir(parents=True)
    (pid_dir / "exe").symlink_to(executable)
    (pid_dir / "status").write_text(f"Name:\tllama-server\nVmRSS:\t{rss_kib} kB\n")
    meminfo = root / "meminfo"
    meminfo.write_text("MemAvailable: 17000000 kB\n")
    return pid_dir, meminfo


def _proc_sampler():

    return sample_acceptance_server


def test_import_has_no_process_or_network_activity(monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError("import must not start a process or open a socket")

    monkeypatch.setattr(subprocess, "Popen", forbidden)
    monkeypatch.setattr(socket, "socket", forbidden)
    module = _load_script()
    assert callable(module.run_live_acceptance)


def test_dry_run_only_invokes_offline_pytest(monkeypatch):
    module = _load_script()
    calls = []

    class OfflinePytest:
        @staticmethod
        def main(args):
            calls.extend(args)
            return 0

    monkeypatch.setitem(sys.modules, "pytest", OfflinePytest)
    monkeypatch.setattr(module.subprocess, "Popen", lambda *a, **k: pytest.fail("Popen called"))
    assert module.main(["--dry-run"]) == 0
    assert any("test_ai_local_orchestrator_v060.py" in str(item) for item in calls)
    assert not any("--live" in str(item) for item in calls)


def test_live_mode_without_interactive_confirmation_never_starts_server(monkeypatch):
    module = _load_script()
    monkeypatch.setattr(
        module.subprocess, "Popen", lambda *args, **kwargs: pytest.fail("server launched")
    )
    with pytest.raises(SystemExit) as error:
        module.main(["--live"])
    assert error.value.code == 2


def test_live_harness_requires_repository_v070_source(monkeypatch):
    module = _load_script()
    fake_package = type("RunbookOS", (), {"__version__": "0.2.1", "__file__": "/tmp/old.py"})
    monkeypatch.setitem(sys.modules, "runbookos", fake_package)
    with pytest.raises(module.OrchestrationError, match="v0.7.0 source"):
        module._import_test_harness()


def test_artifact_verifier_rejects_runtime_symlink(tmp_path: Path):
    module = _load_script()
    model = tmp_path / "model.gguf"
    runtime_target = tmp_path / "llama-server.real"
    runtime_link = tmp_path / "llama-server"
    model.write_bytes(b"model fixture")
    runtime_target.write_bytes(b"runtime fixture")
    runtime_target.chmod(0o700)
    runtime_link.symlink_to(runtime_target)
    with pytest.raises(module.OrchestrationError, match="server artifact"):
        module.verify_artifacts(
            model,
            runtime_link,
            module.sha256_file(model),
            module.sha256_file(runtime_target),
        )


def test_artifact_verifier_accepts_canonical_regular_runtime(tmp_path: Path):
    module = _load_script()
    model = tmp_path / "model.gguf"
    runtime = tmp_path / "llama-server"
    model.write_bytes(b"model fixture")
    runtime.write_bytes(b"runtime fixture")
    runtime.chmod(0o700)
    result = module.verify_artifacts(
        model, runtime, module.sha256_file(model), module.sha256_file(runtime)
    )
    assert result == {
        "model_sha256": module.sha256_file(model),
        "server_sha256": module.sha256_file(runtime),
    }


@pytest.mark.parametrize("artifact", ["model", "runtime"])
def test_wrong_artifact_checksum_blocks_launch(tmp_path: Path, artifact: str):
    module = _load_script()
    model = tmp_path / "model.gguf"
    runtime = tmp_path / "llama-server"
    model.write_bytes(b"synthetic model bytes")
    runtime.write_bytes(b"synthetic runtime bytes")
    runtime.chmod(0o700)
    expected_model = module.sha256_file(model)
    expected_server = module.sha256_file(runtime)
    verifier = functools.partial(
        module.verify_artifacts,
        expected_model_sha256=("0" * 64 if artifact == "model" else expected_model),
        expected_server_sha256=("0" * 64 if artifact == "runtime" else expected_server),
    )
    popen_calls = []
    with pytest.raises(module.OrchestrationError, match="SHA-256"):
        module.run_live_acceptance(
            artifact_verifier=verifier,
            popen_factory=lambda *a, **k: popen_calls.append((a, k)),
            model_path=model,
            server_path=runtime,
            output_parent=tmp_path,
        )
    assert popen_calls == []


@pytest.mark.parametrize(
    ("family", "address"),
    [
        (socket.AF_INET, (LOOPBACK, ACCEPTANCE_PORT)),
        (socket.AF_INET6, ("::1", ACCEPTANCE_PORT)),
    ],
)
def test_existing_port_conflict_blocks_live_preflight(family, address):
    module = _load_script()

    class OccupiedSocket:
        closed = False

        def __init__(self, socket_family, *args):
            self.family = socket_family

        def bind(self, bind_address):
            if self.family == family:
                assert bind_address == address
                raise OSError("address already in use")

        def close(self):
            self.closed = True

    holder = []

    def factory(*args):
        item = OccupiedSocket(*args)
        holder.append(item)
        return item

    popen_calls = []
    with pytest.raises(module.OrchestrationError, match="already occupied"):
        module.run_live_acceptance(
            artifact_verifier=lambda *a: {"model_sha256": "m", "server_sha256": "s"},
            port_checker=lambda port, socket_factory: module.ensure_loopback_port_free(
                port, socket_factory
            ),
            socket_factory=factory,
            popen_factory=lambda *a, **k: popen_calls.append((a, k)),
            output_parent=Path("/tmp"),
        )
    assert holder[0].closed
    if family == socket.AF_INET6:
        assert holder[1].closed
    assert popen_calls == []


def test_acceptance_endpoint_is_consistent_and_never_targets_8080(monkeypatch):
    module = _load_script()
    harness = module._import_test_harness()
    assert module.PORT == ACCEPTANCE_PORT == 18080
    assert module.PROVIDER_ENDPOINT == PROVIDER_ENDPOINT
    assert PROVIDER_ENDPOINT.endswith(f":{ACCEPTANCE_PORT}/v1")
    args = module.server_arguments()
    assert args[args.index("--host") + 1] == LOOPBACK
    assert args[args.index("--port") + 1] == str(ACCEPTANCE_PORT)

    connections = []

    class Response:
        status = 200

        @staticmethod
        def read(limit):
            assert limit <= 16 * 1024
            return b"{}"

    class Connection:
        def __init__(self, host, port, timeout):
            connections.append((host, port, timeout))

        def request(self, method, path, headers):
            assert method == "GET"
            assert path == "/v1/models"
            assert headers["Authorization"] == "Bearer synthetic-key"

        @staticmethod
        def getresponse():
            return Response()

        @staticmethod
        def close():
            pass

    class Watch:
        @staticmethod
        def check():
            pass

    monkeypatch.setattr(module.http.client, "HTTPConnection", Connection)
    module.wait_for_authenticated_provider("synthetic-key", Watch())
    assert connections == [(LOOPBACK, ACCEPTANCE_PORT, 2)]
    assert harness.PROVIDER_ENDPOINT == PROVIDER_ENDPOINT


def test_insufficient_prelaunch_memory_prevents_server_launch(monkeypatch, tmp_path: Path):
    module = _load_script()
    harness = module._import_test_harness()
    monkeypatch.setattr(
        module, "verify_artifacts", lambda *a: {"model_sha256": "x", "server_sha256": "y"}
    )
    monkeypatch.setattr(module, "ensure_loopback_port_free", lambda *a: None)
    monkeypatch.setattr(
        harness,
        "require_prelaunch_memory",
        lambda text: (_ for _ in ()).throw(ResourceLimitExceeded("low memory")),
    )
    popen_calls = []
    with pytest.raises(ResourceLimitExceeded):
        module.run_live_acceptance(
            popen_factory=lambda *a, **k: popen_calls.append((a, k)),
            artifact_verifier=lambda *a: {"model_sha256": "m", "server_sha256": "s"},
            port_checker=lambda *a: None,
            meminfo_reader=lambda: "MemAvailable: 1000000 kB\n",
            secret_reader=lambda path: "synthetic-key",
            output_parent=tmp_path,
        )
    assert popen_calls == []


def test_initial_rss_failure_aborts_before_provider_and_cleans_owned_server(
    monkeypatch, tmp_path: Path
):
    module = _load_script()
    process = FakePopen()
    provider_calls = []

    class InvalidWatch:
        def __init__(self, *args):
            self.failure_category = "resource_measurement_or_process_identity_failed"

        def start(self):
            raise ResourceMonitorError("invalid initial RSS")

        def stop(self):
            pass

        def abort_requested(self):
            return True

        def report(self):
            return {"status": "failed", "sample_count": 0}

    monkeypatch.setattr(
        module, "_import_test_harness", lambda: __import__("ai_acceptance_harness_v060")
    )
    result = module.run_live_acceptance(
        popen_factory=lambda *a, **k: process,
        watch_factory=InvalidWatch,
        artifact_verifier=lambda *a: {"model_sha256": "m", "server_sha256": "s"},
        port_checker=lambda *a: None,
        meminfo_reader=lambda: "MemAvailable: 17000000 kB\n",
        secret_reader=lambda path: "synthetic-key",
        readiness_checker=lambda *a: pytest.fail("readiness called after invalid initial RSS"),
        listener_verifier=lambda *a: pytest.fail("listener check called after invalid RSS"),
        provider_builder=lambda config: provider_calls.append(config),
        output_parent=tmp_path,
    )
    assert result["status"] == "aborted"
    assert result["failure_type"] == "ResourceMonitorError"
    assert provider_calls == []
    assert process.terminated
    assert result["server_exit_code"] == 0


def test_live_orchestrator_wires_resource_guard_into_existing_harness(monkeypatch, tmp_path: Path):
    module = _load_script()
    harness = module._import_test_harness()
    process = FakePopen()
    launch = {}

    class Watch:
        instance = None

        def __init__(self, process_arg, executable, sampler):
            self.process = process_arg
            self.executable = executable
            self.sampler = sampler
            self.check_count = 0
            self.stopped = False
            self.failure_category = None
            Watch.instance = self

        def start(self):
            assert self.sampler is not None
            self.sampler = "used-by-watch"

        def check(self):
            self.check_count += 1
            if self.process.poll() is not None:
                raise module.OrchestrationError("server exited")

        def abort_requested(self):
            return False

        def stop(self):
            self.stopped = True

        def report(self):
            return {"status": "passed", "sample_count": 1, "measurement_boundary": "main PID"}

    class OfflineLiveProvider:
        provider_name = "offline-orchestrator-test"

        def complete(self, system, user, max_tokens, temperature):
            payload = json.loads(user)
            if "diagnostic_catalog" in payload:
                text = payload["incident_untrusted"]
                chosen = (
                    "web_health"
                    if "Nginx" in text
                    else "application_health"
                    if "FastAPI" in text
                    else "database_health"
                    if "PostgreSQL" in text
                    else "network_health"
                    if "network route" in text
                    else None
                )
                value = {"diagnostic_ids": [chosen] if chosen else [], "rationale": "synthetic"}
            else:
                refs = payload["evidence_refs"]
                abstain = not refs
                value = {
                    "reply_version": 2,
                    "category": "unknown" if abstain else "service_failure",
                    "confidence": 0.2,
                    "evidence_ids": refs[:1],
                    "reason": "The synthetic fixture has no evidence."
                    if abstain
                    else "The synthetic observation may indicate a service issue.",
                    "abstain": abstain,
                    "overall_uncertainty": 0.8 if abstain else 0.5,
                }
            return ModelReply(json.dumps(value), self.provider_name, 0.001, {"total_tokens": 1})

    monkeypatch.setattr(module, "_import_test_harness", lambda: harness)
    monkeypatch.setattr(
        module, "verify_artifacts", lambda *a: {"model_sha256": "m", "server_sha256": "s"}
    )
    monkeypatch.setattr(module, "ensure_loopback_port_free", lambda *a: None)
    monkeypatch.setattr(module, "wait_for_authenticated_provider", lambda key, watch: watch.check())
    result = module.run_live_acceptance(
        popen_factory=lambda *a, **k: launch.update(args=a, kwargs=k) or process,
        watch_factory=Watch,
        artifact_verifier=lambda *a: {"model_sha256": "m", "server_sha256": "s"},
        port_checker=lambda *a: None,
        meminfo_reader=lambda: "MemAvailable: 17000000 kB\n",
        secret_reader=lambda path: "synthetic-key",
        readiness_checker=lambda key, watch: watch.check(),
        listener_verifier=lambda pid: ["127.0.0.1"],
        provider_builder=lambda config: OfflineLiveProvider(),
        output_parent=tmp_path,
    )
    assert result["status"] == "completed", (
        result.get("failure_stage"),
        result.get("failure_type"),
        result.get("failure_category"),
    )
    assert result["provider_requests"] == 10
    assert len(result["cases"]) == 5
    assert result["sqlite_integrity"] == "ok"
    assert result["audit_chain_valid"] is True
    assert result["resource_monitor"]["status"] == "passed"
    assert Watch.instance.check_count >= 22
    assert Watch.instance.stopped
    assert process.terminated
    launch_args = launch["args"][0]
    launch_env = launch["kwargs"]["env"]
    assert launch_args[0] == str(module.SERVER_PATH)
    assert launch_args[launch_args.index("--host") + 1] == "127.0.0.1"
    assert launch_args[launch_args.index("--port") + 1] == str(ACCEPTANCE_PORT)
    assert "synthetic-key" not in " ".join(launch_args)
    assert module.API_KEY_ENV not in launch_env
    assert module.PROVIDER_ENDPOINT == PROVIDER_ENDPOINT
    assert module.PORT == ACCEPTANCE_PORT
    output = Path(result["database_path"]).parents[1]
    assert (output / "results/summary.json").is_file()
    assert (output / "state/investigation.sqlite3").is_file()
    assert not (output / "config").exists()
    assert not (output / "runbooks").exists()


def test_live_orchestrator_accepts_benchmark_callback_under_existing_resource_watch(
    monkeypatch, tmp_path: Path
):
    module = _load_script()
    harness = module._import_test_harness()
    process = FakePopen()
    callback = {}

    class Watch:
        def __init__(self, process_arg, executable, sampler):
            self.process = process_arg
            self.failure_category = None
            self.checked = 0

        def start(self):
            pass

        def check(self):
            self.checked += 1
            if self.process.poll() is not None:
                raise module.OrchestrationError("unexpected server exit")

        def abort_requested(self):
            return False

        def stop(self):
            pass

        def report(self):
            return {"status": "passed", "sample_count": 1}

    monkeypatch.setattr(module, "_import_test_harness", lambda: harness)

    class Provider:
        provider_name = "offline-callback-test"

    def acceptance_runner(**kwargs):
        callback.update(kwargs)
        kwargs["request_guard"]()
        return {"status": "completed", "provider_requests": 48, "case_count": 24}

    result = module.run_live_acceptance(
        popen_factory=lambda *a, **k: process,
        watch_factory=Watch,
        artifact_verifier=lambda *a: {"model_sha256": "m", "server_sha256": "s"},
        port_checker=lambda *a: None,
        meminfo_reader=lambda: "MemAvailable: 17000000 kB\n",
        secret_reader=lambda path: "synthetic-key",
        readiness_checker=lambda key, watch: watch.check(),
        listener_verifier=lambda pid: ["127.0.0.1"],
        provider_builder=lambda config: Provider(),
        acceptance_runner=acceptance_runner,
        output_parent=tmp_path,
    )
    assert result["status"] == "completed"
    assert result["provider_requests"] == 48
    assert result["case_count"] == 24
    assert callable(callback["request_guard"])
    assert callback["results_dir"].is_dir()
    assert process.terminated


@pytest.mark.parametrize("breach", ["rss", "memavailable"])
def test_resource_monitor_stays_active_during_blocked_provider_and_aborts_more_calls(
    tmp_path: Path, breach: str
):
    module = _load_script()
    proc_root = tmp_path / "proc"
    proc_root.mkdir()
    executable = tmp_path / "llama-server"
    executable.write_bytes(b"fixture")
    pid_dir, meminfo = _proc_tree(proc_root, 4321, executable)
    process = FakePopen(4321)
    watch = module.ResourceWatch(
        process,
        executable,
        _proc_sampler(),
        proc_root,
        meminfo,
        poll_interval=0.05,
    )
    watch.start()
    paths = create_synthetic_tree(tmp_path / "db")

    class BlockingProvider:
        provider_name = "offline-blocking-test"

        def __init__(self):
            self.calls = 0

        def complete(self, *args, **kwargs):
            self.calls += 1
            if breach == "rss":
                (pid_dir / "status").write_text(
                    f"Name:\tllama-server\nVmRSS:\t{10 * 1024 * 1024 + 1} kB\n"
                )
            else:
                meminfo.write_text(f"MemAvailable: {6 * 1024 * 1024 - 1} kB\n")
            assert process.wait_terminated(2)
            time.sleep(0.03)
            return ModelReply('{"diagnostic_ids":[]}', self.provider_name, 0.01, {})

    provider = BlockingProvider()
    try:
        summary = run_five_scenario_acceptance(
            paths,
            provider,
            request_guard=watch.check,
            abort_requested=watch.abort_requested,
        )
    finally:
        watch.stop()
    assert provider.calls == 1
    assert summary["provider_requests"] == 1
    assert summary["stopped_early"] is True
    assert len(summary["cases"]) == 1
    assert summary["cases"][0]["status"] == "aborted_by_resource_monitor"
    assert summary["cases"][0]["executor_action_count"] == 0
    assert process.terminate_calls == 1
    store = SQLiteStore(paths.database)
    investigations = store.investigations()
    assert len(investigations) == 1
    assert investigations[0]["result"]["status"] == "failed"
    assert investigations[0]["result"]["assessment_failure"]
    assert store.verify_audit_chain()[0]
    assert watch.report()["status"] == "failed"


def test_live_entrypoint_persists_partial_report_after_resource_abort(tmp_path: Path):
    module = _load_script()
    proc_root = tmp_path / "proc"
    proc_root.mkdir()
    executable = tmp_path / "llama-server"
    executable.write_bytes(b"fixture")
    pid_dir, meminfo = _proc_tree(proc_root, 4321, executable)
    process = FakePopen(4321)

    def watch_factory(server, expected, sampler):
        return module.ResourceWatch(
            server,
            expected,
            sampler,
            proc_root,
            meminfo,
            poll_interval=0.05,
        )

    class BlockingProvider:
        provider_name = "offline-resource-stop-test"

        def complete(self, system, user, max_tokens, temperature):
            (pid_dir / "status").write_text(
                f"Name:\tllama-server\nVmRSS:\t{10 * 1024 * 1024 + 1} kB\n"
            )
            assert process.wait_terminated(2)
            time.sleep(0.03)
            return ModelReply('{"diagnostic_ids":[]}', self.provider_name, 0.01, {})

    result = module.run_live_acceptance(
        popen_factory=lambda *a, **k: process,
        watch_factory=watch_factory,
        artifact_verifier=lambda *a: {"model_sha256": "m", "server_sha256": "s"},
        port_checker=lambda *a: None,
        meminfo_reader=lambda: "MemAvailable: 17000000 kB\n",
        secret_reader=lambda path: "synthetic-key",
        readiness_checker=lambda key, watch: watch.check(),
        listener_verifier=lambda pid: ["127.0.0.1"],
        provider_builder=lambda config: BlockingProvider(),
        server_path=executable,
        output_parent=tmp_path,
    )
    assert result["status"] == "aborted"
    assert result["provider_requests"] == 1
    assert result["stopped_early"] is True
    assert result["cases"][0]["status"] == "aborted_by_resource_monitor"
    assert result["resource_monitor"]["status"] == "failed"
    assert result["server_exit_code"] == 0
    assert result["sqlite_integrity"] == "ok"
    assert result["audit_chain_valid"] is True
    output_root = Path(result["database_path"]).parents[1]
    saved = json.loads((output_root / "results/summary.json").read_text())
    assert saved["status"] == "aborted"
    assert saved["provider_requests"] == 1
    assert (output_root / "state/investigation.sqlite3").is_file()
    assert not (output_root / "config").exists()
    assert not (output_root / "runbooks").exists()
    store = SQLiteStore(Path(result["database_path"]))
    investigations = store.investigations()
    assert len(investigations) == 1
    assert investigations[0]["result"]["status"] == "failed"
    assert investigations[0]["result"]["assessment_failure"]
    assert store.verify_audit_chain()[0]


def test_server_exit_is_detected_by_watchdog_and_unrelated_process_is_untouched(tmp_path: Path):
    module = _load_script()
    proc_root = tmp_path / "proc"
    proc_root.mkdir()
    executable = tmp_path / "llama-server"
    executable.write_bytes(b"fixture")
    _proc_tree(proc_root, 4321, executable)
    owned = FakePopen(4321)
    unrelated = FakePopen(9999)
    watch = module.ResourceWatch(
        owned, executable, _proc_sampler(), proc_root, proc_root / "meminfo"
    )
    watch.start()
    owned._exit_code = 1
    with pytest.raises(module.OrchestrationError, match="exited"):
        watch.check()
    watch.stop()
    assert watch.abort_requested()
    assert watch.report()["failure_category"] == "acceptance_server_exited"
    assert unrelated.terminate_calls == 0
    assert owned.terminate_calls == 0


def test_provider_timeout_is_not_retried_and_request_limit_is_ten():
    module = _load_script()

    class TimeoutProvider:
        provider_name = "offline-timeout-test"

        def __init__(self):
            self.calls = 0

        def complete(self, *args, **kwargs):
            self.calls += 1
            raise TimeoutError("synthetic timeout")

    provider = TimeoutProvider()
    bounded = module._import_test_harness().BoundedProvider(provider, maximum_requests=10)
    with pytest.raises(TimeoutError):
        bounded.complete("system", "user", 1, 0)
    assert provider.calls == 1
    assert bounded.request_count == 1
    assert len(bounded.request_latencies) == 1


def test_loopback_listener_verifier_rejects_non_loopback_and_unowned_listener(tmp_path: Path):
    module = _load_script()
    proc_root = tmp_path / "proc"
    (proc_root / "net").mkdir(parents=True)
    (proc_root / "1234/fd").mkdir(parents=True)
    (proc_root / "1234/fd/3").symlink_to("socket:[999]")
    header = (
        "sl local_address rem_address st tx_queue:rx_queue tr:tm->when retrnsmt uid timeout inode\n"
    )

    def row(address: str, inode: int) -> str:
        return (
            f"0: {address}:{ACCEPTANCE_PORT:04X} 00000000:0000 0A "
            f"00000000:00000000 00:00000000 00000000 1000 0 {inode}\n"
        )

    (proc_root / "net/tcp").write_text(header + row("0100007F", 999))
    assert module.verify_loopback_listener(1234, proc_root) == ["127.0.0.1"]
    (proc_root / "net/tcp").write_text(header + row("00000000", 999))
    with pytest.raises(module.OrchestrationError, match="loopback-only"):
        module.verify_loopback_listener(1234, proc_root)
    (proc_root / "net/tcp").write_text(header + row("0100007F", 998))
    with pytest.raises(module.OrchestrationError, match="not owned"):
        module.verify_loopback_listener(1234, proc_root)


def test_guard_retains_threshold_cause_when_sampler_terminates_owned_server():
    module = _load_script()
    process = FakePopen()

    def sampler(*args):
        process.terminate()
        raise ResourceLimitExceeded("test threshold")

    watch = module.ResourceWatch(process, Path("/expected/server"), sampler)
    with pytest.raises(ResourceLimitExceeded):
        watch.start()
    assert watch.failure_category == "resource_threshold_exceeded"
    assert watch.report()["status"] == "failed"
