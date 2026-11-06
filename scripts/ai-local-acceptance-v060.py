#!/usr/bin/env python3
"""Test-only offline/live harness for the local RunbookOS v0.6.0 Qwen acceptance.

Importing this module performs no process launch, network request, or filesystem
write. The live path is deliberately local-only and requires an interactive
confirmation after separate operator authorization.
"""

from __future__ import annotations

import argparse
import hashlib
import http.client
import importlib
import json
import os
import re
import shutil
import socket
import sqlite3
import stat
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path
from typing import Any, Callable

REPOSITORY = Path(__file__).resolve().parents[1]
TESTS_DIRECTORY = REPOSITORY / "tests"
if str(TESTS_DIRECTORY) not in sys.path:
    sys.path.insert(0, str(TESTS_DIRECTORY))

from ai_acceptance_config_v060 import (  # noqa: E402
    ACCEPTANCE_PORT,
    LOOPBACK,
    PROVIDER_ENDPOINT,
)

MODEL_PATH = Path("/home/morphious/models/llama.cpp/qwen3.5-9b-instruct-q5_k_m.gguf")
SERVER_PATH = Path("/home/morphious/.local/src/llama.cpp/build/bin/llama-server")
API_KEY_PATH = Path("/home/morphious/.config/runbookos/llama-api-key")
MODEL_SHA256 = "dc2a39aef291f91a9116ad214058da0d86eb648743a124bd8c333787c4b9c91c"
SERVER_SHA256 = "98a8581124ccf8ba775a89e1899c895b2d4a2053b9830f8b044fe69b928c02ac"
API_KEY_ENV = "RUNBOOKOS_LLAMA_API_KEY"
PORT = ACCEPTANCE_PORT
MODEL_ALIAS = "qwen3.5-9b-instruct"
MAX_REQUESTS = 10
REQUEST_TIMEOUT_SECONDS = 120
POLL_INTERVAL_SECONDS = 0.5
MAX_READINESS_SECONDS = 120
CONFIRMATION = "RUN LOCAL QWEN ACCEPTANCE"


class OrchestrationError(RuntimeError):
    """Sanitized, non-secret acceptance orchestration failure."""


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def verify_artifacts(
    model_path: Path = MODEL_PATH,
    server_path: Path = SERVER_PATH,
    expected_model_sha256: str = MODEL_SHA256,
    expected_server_sha256: str = SERVER_SHA256,
) -> dict[str, str]:
    for label, path in (("model", model_path), ("server", server_path)):
        if path.is_symlink() or not path.is_file():
            raise OrchestrationError(f"{label} artifact is missing or not a regular file")
    model_hash = sha256_file(model_path)
    server_hash = sha256_file(server_path)
    if model_hash != expected_model_sha256:
        raise OrchestrationError("model SHA-256 does not match the approved artifact")
    if server_hash != expected_server_sha256:
        raise OrchestrationError("llama-server SHA-256 does not match the approved artifact")
    if not os.access(server_path, os.X_OK):
        raise OrchestrationError("llama-server is not executable")
    return {"model_sha256": model_hash, "server_sha256": server_hash}


def ensure_loopback_port_free(
    port: int = PORT, socket_factory: Callable[..., Any] = socket.socket
) -> None:
    bindings = [
        (socket.AF_INET, (LOOPBACK, port)),
        (socket.AF_INET6, ("::1", port)),
    ]
    for family, address in bindings:
        probe = socket_factory(family, socket.SOCK_STREAM)
        try:
            try:
                probe.bind(address)
            except OSError as exc:
                raise OrchestrationError(
                    f"loopback port {port} is already occupied or unavailable"
                ) from exc
        finally:
            probe.close()


def read_protected_api_key(path: Path = API_KEY_PATH) -> str:
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode):
        raise OrchestrationError("API key path is not a regular file")
    if info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o600:
        raise OrchestrationError("API key ownership or permissions are not exactly owner-only")
    value = path.read_text(encoding="utf-8").strip()
    if not value or "\n" in value or "\r" in value:
        raise OrchestrationError("API key file is empty or malformed")
    return value


def server_arguments(
    model_path: Path = MODEL_PATH,
    api_key_path: Path = API_KEY_PATH,
    server_path: Path = SERVER_PATH,
) -> list[str]:
    """Fixed server arguments; caller-supplied command or flags are not accepted."""
    return [
        str(server_path),
        "--model",
        str(model_path),
        "--host",
        LOOPBACK,
        "--port",
        str(PORT),
        "--alias",
        MODEL_ALIAS,
        "--ctx-size",
        "12288",
        "--parallel",
        "1",
        "--threads",
        "4",
        "--threads-batch",
        "4",
        "--timeout",
        "130",
        "--reasoning",
        "off",
        "--reasoning-format",
        "none",
        "--reasoning-budget",
        "0",
        "--api-key-file",
        str(api_key_path),
        "--no-webui",
    ]


def _proc_listener_rows(path: Path, port: int) -> list[tuple[str, str]]:
    if not path.is_file():
        return []
    rows: list[tuple[str, str]] = []
    lines = path.read_text(encoding="ascii").splitlines()[1:]
    for line in lines:
        columns = line.split()
        if len(columns) < 10 or columns[3] != "0A":
            continue
        address_hex, port_hex = columns[1].split(":", 1)
        if int(port_hex, 16) != port:
            continue
        if path.name == "tcp":
            address = socket.inet_ntop(socket.AF_INET, bytes.fromhex(address_hex)[::-1])
        else:
            raw = bytes.fromhex(address_hex)
            address = socket.inet_ntop(
                socket.AF_INET6,
                b"".join(raw[index : index + 4][::-1] for index in range(0, 16, 4)),
            )
        rows.append((address, columns[9]))
    return rows


def verify_loopback_listener(
    pid: int,
    proc_root: Path = Path("/proc"),
    port: int = PORT,
) -> list[str]:
    rows = _proc_listener_rows(proc_root / "net/tcp", port)
    rows += _proc_listener_rows(proc_root / "net/tcp6", port)
    if not rows:
        raise OrchestrationError("acceptance server listener was not found")
    if any(address not in {"127.0.0.1", "::1"} for address, _ in rows):
        raise OrchestrationError("acceptance server listener is not loopback-only")
    fd_dir = proc_root / str(pid) / "fd"
    try:
        owned_inodes = {
            match.group(1)
            for fd in fd_dir.iterdir()
            if (match := re.fullmatch(r"socket:\[(\d+)\]", os.readlink(fd)))
        }
    except OSError as exc:
        raise OrchestrationError("cannot verify listener ownership by acceptance server") from exc
    if any(inode not in owned_inodes for _, inode in rows):
        raise OrchestrationError(f"port {port} includes a listener not owned by acceptance server")
    return sorted({address for address, _ in rows})


class ResourceWatch:
    """Polling guard integrated with the provider request path."""

    def __init__(
        self,
        process: Any,
        expected_executable: Path,
        sampler: Callable[..., dict[str, int]],
        proc_root: Path = Path("/proc"),
        meminfo_path: Path = Path("/proc/meminfo"),
        poll_interval: float = POLL_INTERVAL_SECONDS,
    ):
        if not 0.05 <= poll_interval <= 1.0:
            raise ValueError("resource polling interval must be between 0.05 and 1.0 seconds")
        self.process = process
        self.expected_executable = expected_executable
        self.sampler = sampler
        self.proc_root = proc_root
        self.meminfo_path = meminfo_path
        self.poll_interval = poll_interval
        self.samples: list[dict[str, int | float]] = []
        self.failure_category: str | None = None
        self._abort = threading.Event()
        self._stop = threading.Event()
        self._lock = threading.Lock()
        self._thread: threading.Thread | None = None
        self._started_at = 0.0

    def _sample(self) -> None:
        try:
            sample = self.sampler(
                self.process,
                self.expected_executable,
                self.proc_root,
                self.meminfo_path,
            )
        except Exception as exc:
            with self._lock:
                if type(exc).__name__ == "ResourceLimitExceeded":
                    self.failure_category = "resource_threshold_exceeded"
                elif self.process.poll() is not None:
                    self.failure_category = "acceptance_server_exited"
                else:
                    self.failure_category = "resource_measurement_or_process_identity_failed"
            self._abort.set()
            raise
        with self._lock:
            self.samples.append(
                {
                    "elapsed_seconds": round(time.monotonic() - self._started_at, 3),
                    "rss_bytes": sample["rss_bytes"],
                    "memavailable_bytes": sample["memavailable_bytes"],
                }
            )

    def start(self) -> None:
        if self._thread is not None:
            raise OrchestrationError("resource monitor cannot be started twice")
        self._started_at = time.monotonic()
        # Mandatory valid, nonzero process identity and RSS before readiness or inference.
        self._sample()
        self._thread = threading.Thread(
            target=self._poll, name="runbookos-ai-resource-watch", daemon=True
        )
        self._thread.start()

    def _poll(self) -> None:
        while not self._stop.wait(self.poll_interval):
            try:
                self._sample()
            except Exception:
                return

    def check(self) -> None:
        if self._abort.is_set():
            raise OrchestrationError("resource monitor requested acceptance abort")
        if self.process.poll() is not None:
            self.failure_category = "acceptance_server_exited"
            self._abort.set()
            raise OrchestrationError("acceptance server exited during investigation")

    def abort_requested(self) -> bool:
        return self._abort.is_set()

    def stop(self) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=max(2.0, 4 * self.poll_interval))
            if self._thread.is_alive():
                self.failure_category = "resource_monitor_thread_did_not_stop"
                self._abort.set()

    def report(self) -> dict[str, Any]:
        with self._lock:
            samples = list(self.samples)
        return {
            "status": "failed" if self._abort.is_set() else "passed",
            "failure_category": self.failure_category,
            "sample_count": len(samples),
            "samples": samples,
            "peak_rss_bytes": max((int(item["rss_bytes"]) for item in samples), default=None),
            "minimum_memavailable_bytes": min(
                (int(item["memavailable_bytes"]) for item in samples), default=None
            ),
            "poll_interval_seconds": self.poll_interval,
            "nominal_detection_delay_seconds": self.poll_interval,
            "measurement_boundary": "main llama-server PID only; descendants not aggregated",
        }


def wait_for_authenticated_provider(api_key: str, watch: ResourceWatch) -> None:
    deadline = time.monotonic() + MAX_READINESS_SECONDS
    last_category = "provider_not_ready"
    while time.monotonic() < deadline:
        watch.check()
        connection = http.client.HTTPConnection(LOOPBACK, PORT, timeout=2)
        try:
            connection.request(
                "GET",
                "/v1/models",
                headers={"Authorization": f"Bearer {api_key}", "Accept": "application/json"},
            )
            response = connection.getresponse()
            response.read(16 * 1024)
            if response.status == 200:
                watch.check()
                return
            last_category = "provider_readiness_http_error"
        except (OSError, http.client.HTTPException):
            last_category = "provider_readiness_connection_error"
        finally:
            connection.close()
        time.sleep(1)
    raise OrchestrationError(last_category)


def _write_private_json(path: Path, value: dict[str, Any]) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    fd = os.open(path, flags, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as stream:
        json.dump(value, stream, indent=2, sort_keys=True)
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())


def _import_test_harness() -> Any:
    source_path = str(REPOSITORY / "src")
    tests_path = str(REPOSITORY / "tests")
    if source_path in sys.path:
        sys.path.remove(source_path)
    sys.path.insert(0, source_path)
    if tests_path not in sys.path:
        sys.path.insert(0, tests_path)
    package = importlib.import_module("runbookos")
    package_file = Path(package.__file__).resolve()
    expected_source = (REPOSITORY / "src/runbookos").resolve()
    if package.__version__ != "0.7.0" or expected_source not in package_file.parents:
        raise OrchestrationError("acceptance requires the repository's RunbookOS v0.7.0 source")
    return importlib.import_module("ai_acceptance_harness_v060")


def run_live_acceptance(
    *,
    popen_factory: Callable[..., Any] = subprocess.Popen,
    socket_factory: Callable[..., Any] = socket.socket,
    resource_sampler: Callable[..., dict[str, int]] | None = None,
    watch_factory: Callable[..., ResourceWatch] = ResourceWatch,
    artifact_verifier: Callable[..., dict[str, str]] = verify_artifacts,
    port_checker: Callable[..., None] = ensure_loopback_port_free,
    meminfo_reader: Callable[[], str] | None = None,
    secret_reader: Callable[[Path], str] = read_protected_api_key,
    readiness_checker: Callable[[str, ResourceWatch], None] = wait_for_authenticated_provider,
    listener_verifier: Callable[[int], list[str]] = verify_loopback_listener,
    provider_builder: Callable[[Any], Any] | None = None,
    acceptance_runner: Callable[..., dict[str, Any]] | None = None,
    model_path: Path = MODEL_PATH,
    server_path: Path = SERVER_PATH,
    api_key_path: Path = API_KEY_PATH,
    output_parent: Path | None = None,
) -> dict[str, Any]:
    """Execute a single local-only acceptance; never called on import or dry-run."""
    harness = _import_test_harness()
    stage = "artifact_verification"
    hashes = artifact_verifier(model_path, server_path)
    stage = "loopback_port_preflight"
    port_checker(PORT, socket_factory)
    read_meminfo = meminfo_reader or (lambda: Path("/proc/meminfo").read_text(encoding="ascii"))
    stage = "prelaunch_memory_check"
    harness.require_prelaunch_memory(read_meminfo())
    stage = "protected_api_key_validation"
    api_key = secret_reader(api_key_path)

    parent = output_parent or Path(tempfile.gettempdir())
    root = Path(tempfile.mkdtemp(prefix="runbookos-ai-v060-rerun-", dir=parent))
    root.chmod(0o700)
    paths = None
    server: Any = None
    watch: ResourceWatch | None = None
    provider_requests_started = 0
    previous_key = os.environ.get(API_KEY_ENV)
    summary: dict[str, Any] = {
        "status": "failed_before_inference",
        "model": MODEL_ALIAS,
        "artifact_hashes": hashes,
        "provider_requests": 0,
        "cases": [],
        "resource_monitor": None,
        "sqlite_integrity": "not_checked",
        "audit_chain_valid": False,
    }
    try:
        stage = "acceptance_tree_creation"
        paths = harness.create_synthetic_tree(root / "acceptance")
        results_dir = paths.database.parent.parent / "results"
        results_dir.mkdir(mode=0o700)
        stage = "acceptance_process_start"
        os.environ[API_KEY_ENV] = api_key
        server_environment = os.environ.copy()
        server_environment.pop(API_KEY_ENV, None)
        server = popen_factory(
            server_arguments(model_path, api_key_path, server_path),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            close_fds=True,
            start_new_session=True,
            env=server_environment,
        )
        stage = "initial_resource_sample"
        sampler = resource_sampler or harness.sample_acceptance_server
        watch = watch_factory(server, server_path, sampler)
        watch.start()
        stage = "authenticated_loopback_readiness"
        readiness_checker(api_key, watch)
        stage = "loopback_listener_verification"
        listeners = listener_verifier(server.pid)

        from runbookos import ai

        stage = "provider_configuration"
        config, _ = ai.load_investigation_config(paths.inventory.parent / "investigation.yml")
        if (
            config.provider.base_url != PROVIDER_ENDPOINT
            or config.provider.model != MODEL_ALIAS
            or config.provider.timeout_seconds > REQUEST_TIMEOUT_SECONDS
            or config.provider.temperature != 0
        ):
            raise OrchestrationError(
                "local provider configuration is outside fixed acceptance scope"
            )
        provider = (provider_builder or ai.build_provider)(config.provider)
        summary["status"] = "running"
        summary["listeners"] = listeners
        stage = "acceptance_investigation"
        runner = acceptance_runner or harness.run_five_scenario_acceptance
        if acceptance_runner is None:
            runner_result = runner(
                paths,
                provider,
                request_guard=watch.check,
                abort_requested=watch.abort_requested,
            )
        else:
            runner_result = runner(
                paths=paths,
                provider=provider,
                request_guard=watch.check,
                abort_requested=watch.abort_requested,
                results_dir=results_dir,
                model_sha256=hashes["model_sha256"],
                runtime_sha256=hashes["server_sha256"],
            )
        summary.update(runner_result)
        provider_requests_started = int(summary.get("provider_requests", 0))
        if watch.abort_requested() or summary.get("stopped_early"):
            summary["status"] = "aborted"
        elif runner_result.get("status") == "partial":
            summary["status"] = "partial"
        elif any(case.get("status") != "completed" for case in summary.get("cases", [])):
            summary["status"] = "partial"
        else:
            summary["status"] = "completed"
    except Exception as exc:
        # Only exception type/category is retained; messages may contain local details.
        summary["status"] = "aborted" if watch and watch.abort_requested() else "failed"
        summary["failure_type"] = type(exc).__name__
        summary["failure_stage"] = stage
        summary["provider_requests"] = provider_requests_started
        if watch and watch.abort_requested():
            summary["failure_category"] = watch.failure_category
        else:
            summary["failure_category"] = "orchestration_or_provider_failure"
    finally:
        if watch:
            watch.stop()
        if server is not None:
            harness._terminate_acceptance_process(server)
            summary["server_exit_code"] = server.poll()
        if previous_key is None:
            os.environ.pop(API_KEY_ENV, None)
        else:
            os.environ[API_KEY_ENV] = previous_key
        if paths is not None:
            from runbookos.store import SQLiteStore

            store = SQLiteStore(paths.database)
            audit_valid, audit_count = store.verify_audit_chain()
            with sqlite3.connect(f"file:{paths.database}?mode=ro", uri=True) as database:
                summary["sqlite_integrity"] = database.execute("PRAGMA integrity_check").fetchone()[
                    0
                ]
                summary["foreign_key_violations"] = len(
                    database.execute("PRAGMA foreign_key_check").fetchall()
                )
            summary["audit_chain_valid"] = audit_valid
            summary["audit_event_count"] = audit_count
            summary["database_path"] = str(paths.database)
            summary["resource_monitor"] = watch.report() if watch else None
            _write_private_json(results_dir / "summary.json", summary)
            # Keep the synthetic DB and sanitized report; discard only generated
            # config/runbooks that contain no credentials or operational values.
            shutil.rmtree(paths.inventory.parent)
            shutil.rmtree(paths.database.parent.parent / "runbooks")
        else:
            summary["resource_monitor"] = watch.report() if watch else None
            shutil.rmtree(root)
    return summary


def run_offline_dry_run() -> int:
    import pytest

    return int(
        pytest.main(
            [
                "-q",
                str(REPOSITORY / "tests/test_ai_acceptance_harness_v060.py"),
                str(REPOSITORY / "tests/test_ai_local_orchestrator_v060.py"),
            ]
        )
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    modes = parser.add_mutually_exclusive_group(required=True)
    modes.add_argument("--dry-run", action="store_true", help="run offline tests only")
    modes.add_argument(
        "--live", action="store_true", help="run local model acceptance after approval"
    )
    parser.add_argument("--confirm-live", action="store_true", help=argparse.SUPPRESS)
    args = parser.parse_args(argv)
    if args.dry_run:
        return run_offline_dry_run()
    if not args.confirm_live or not sys.stdin.isatty():
        parser.error("--live requires --confirm-live and an interactive terminal")
    print(
        f"Local-only scope: Qwen 3.5 9B, {LOOPBACK}:{PORT}, five synthetic cases, "
        "<=10 serial requests, <=120 seconds/request, no retries, no SSH/remediation."
    )
    if input(f"Type exactly '{CONFIRMATION}' to continue: ").strip() != CONFIRMATION:
        parser.error("live confirmation phrase did not match")
    result = run_live_acceptance()
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result.get("status") == "completed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
