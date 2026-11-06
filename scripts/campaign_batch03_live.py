"""Live Batch 03 orchestration over QGA and the real RunbookOS CLI."""

from __future__ import annotations

import base64
import datetime as dt
import hashlib
import importlib.util
import json
import os
import re
import signal
import subprocess
import sys
import time
import uuid
from pathlib import Path
from typing import Any

import yaml
from campaign_batch03 import stable_condition, validate_ledger, write_ledger

REPO = Path(__file__).resolve().parents[1]
LOCAL = Path("/home/morphious/.local/state/runbookos/campaign-batch03")
LEDGER_PATH = LOCAL / "batch03-ledger.json"
OPS = "runbookos-ops-01"
WEB = "runbookos-svc-web-01"
DBVM = "runbookos-db-01"
REMOTE = "/var/lib/runbookos/acceptance-v070/campaign-batch03"
CONFIG = REMOTE + "/config"
RUNBOOKS = CONFIG + "/runbooks"
STATE = REMOTE + "/state"
DB = STATE + "/batch03.sqlite3"
SOURCE = REMOTE + "/source"
PYTHON = "/var/lib/runbookos/acceptance-v070/venv/bin/python"
SSH_PROFILES = "/var/lib/runbookos/acceptance-v070/config/ssh_profiles.yml"
API_KEY = "/var/lib/runbookos/v021/secrets/llama-api-key"
FIXTURE_ROOT = "/var/lib/runbookos-campaign-b03"
FIXTURE_SCRIPT = FIXTURE_ROOT + "/fixture.py"
WEB_UNITS = {
    "app": "runbookos-campaign-b03-app.service",
    "backend": "runbookos-campaign-b03-backend.service",
    "worker": "runbookos-campaign-b03-worker.service",
    "dns": "runbookos-campaign-b03-dns.service",
}
DB_UNIT = "postgresql@16-b03.service"
PROBES = {
    "app": {"protocol": "http", "address": "10.60.20.10", "port": 18890, "path": "/health"},
    "backend": {"protocol": "tcp", "address": "10.60.20.10", "port": 18901},
    "worker": {"protocol": "tcp", "address": "10.60.20.10", "port": 18902},
    "db": {"protocol": "postgresql", "address": "10.60.30.10", "port": 55433},
    "db_tcp": {"protocol": "tcp", "address": "10.60.30.10", "port": 55433},
}
CATEGORIES = (
    "service_failure",
    "connectivity_failure",
    "network_failure",
    "dependency_failure",
    "resource_pressure",
)
SCENARIOS = [
    {
        "id": "B03-01",
        "title": "Backend process crash with frontend active",
        "fault": "backend_crash",
        "oracle": "dependency_failure",
        "target": "svc-web-01",
        "units": ["backend"],
    },
    {
        "id": "B03-02",
        "title": "Invalid application configuration while process remains active",
        "fault": "invalid_app_config",
        "oracle": "service_failure",
        "target": "svc-web-01",
        "units": ["app"],
    },
    {
        "id": "B03-03",
        "title": "Isolated DNS resolver outage",
        "fault": "dns_stop",
        "oracle": "dependency_failure",
        "target": "svc-web-01",
        "units": ["dns"],
    },
    {
        "id": "B03-04",
        "title": "Disposable PostgreSQL cluster unavailable",
        "fault": "postgres_stop",
        "oracle": "service_failure",
        "target": "db-01",
        "units": ["db"],
    },
    {
        "id": "B03-05",
        "title": "CPU-throttled disposable worker",
        "fault": "worker_pressure",
        "oracle": "resource_pressure",
        "target": "svc-web-01",
        "units": ["worker"],
    },
    {
        "id": "B03-06",
        "title": "Reverse-proxy upstream process unavailable",
        "fault": "backend_stop",
        "oracle": "dependency_failure",
        "target": "svc-web-01",
        "units": ["backend"],
    },
    {
        "id": "B03-07",
        "title": "Application readiness dependency failure",
        "fault": "dns_wrong_answer",
        "oracle": "connectivity_failure",
        "target": "svc-web-01",
        "units": ["dns"],
    },
    {
        "id": "B03-08",
        "title": "Configuration-induced application start failures",
        "fault": "app_crash_loop",
        "oracle": "service_failure",
        "target": "svc-web-01",
        "units": ["app"],
    },
    {
        "id": "B03-09",
        "title": "Isolated DNS packet partition with resolver process still active",
        "fault": "dns_drop",
        "oracle": "network_failure",
        "target": "svc-web-01",
        "units": ["dns"],
    },
    {
        "id": "B03-10",
        "title": "Compound backend and application configuration faults",
        "fault": "compound",
        "oracle": "dependency_failure",
        "target": "svc-web-01",
        "units": ["backend", "app"],
    },
]


def now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat()


def qga(vm: str, payload: dict[str, Any], timeout: float = 15) -> dict[str, Any]:
    result = subprocess.run(
        ["virsh", "-c", "qemu:///system", "qemu-agent-command", vm, json.dumps(payload)],
        capture_output=True,
        text=True,
        check=True,
        timeout=timeout,
    )
    return json.loads(result.stdout)["return"]


def guest_exec(
    vm: str, path: str, args: list[str], *, timeout: float = 30, check: bool = True
) -> dict[str, Any]:
    pid = qga(
        vm,
        {
            "execute": "guest-exec",
            "arguments": {"path": path, "arg": args, "capture-output": True},
        },
    )["pid"]
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        status = qga(vm, {"execute": "guest-exec-status", "arguments": {"pid": pid}})
        if status.get("exited"):
            result = {
                "exit_code": status.get("exitcode"),
                "stdout": base64.b64decode(status.get("out-data", "")).decode(errors="replace"),
                "stderr": base64.b64decode(status.get("err-data", "")).decode(errors="replace"),
                "pid": pid,
            }
            if check and result["exit_code"] != 0:
                raise RuntimeError(f"guest command failed: {path} ({result['exit_code']})")
            return result
        time.sleep(0.1)
    raise TimeoutError(f"guest command timed out: {path}")


def write_guest(
    vm: str, path: str, data: bytes, *, uid: int = 0, gid: int = 0, mode: int = 0o600
) -> None:
    code = (
        "import base64,os,pathlib,sys; p=pathlib.Path(sys.argv[1]); p.parent.mkdir(parents=True,exist_ok=True); "
        "p.write_bytes(base64.b64decode(sys.argv[2])); os.chown(p,int(sys.argv[3]),int(sys.argv[4])); "
        "os.chmod(p,int(sys.argv[5],8))"
    )
    encoded = base64.b64encode(data).decode()
    if len(encoded) < 30000:
        guest_exec(
            vm, "/usr/bin/python3", ["-c", code, path, encoded, str(uid), str(gid), oct(mode)]
        )
        return
    trunc = "import pathlib,sys; p=pathlib.Path(sys.argv[1]); p.parent.mkdir(parents=True,exist_ok=True); p.write_bytes(b'')"
    guest_exec(vm, "/usr/bin/python3", ["-c", trunc, path])
    append = "import base64,sys; f=open(sys.argv[1],'ab'); f.write(base64.b64decode(sys.argv[2])); f.close()"
    for start in range(0, len(data), 24000):
        part = base64.b64encode(data[start : start + 24000]).decode()
        guest_exec(vm, "/usr/bin/python3", ["-c", append, path, part])
    guest_exec(vm, "/usr/bin/chown", [f"{uid}:{gid}", path])
    guest_exec(vm, "/usr/bin/chmod", [format(mode, "o"), path])


def write_yaml(
    vm: str, path: str, document: Any, *, uid: int = 999, gid: int = 988, mode: int = 0o600
) -> None:
    write_guest(
        vm, path, yaml.safe_dump(document, sort_keys=False).encode(), uid=uid, gid=gid, mode=mode
    )


def cli_args(*args: str) -> list[str]:
    wrapper = (
        "import os,sys,pathlib; os.environ['RUNBOOKOS_LLAMA_API_KEY']=pathlib.Path("
        + repr(API_KEY)
        + ").read_text().strip(); os.environ['PYTHONPATH']="
        + repr(SOURCE)
        + "; os.execv(sys.argv[1],sys.argv[1:])"
    )
    return [
        "-u",
        "runbookos",
        "--",
        "/usr/bin/python3",
        "-c",
        wrapper,
        PYTHON,
        "-m",
        "runbookos",
        "--inventory",
        CONFIG + "/inventory.yml",
        "--policy",
        CONFIG + "/policy.yml",
        "--ssh-profiles",
        SSH_PROFILES,
        "--db",
        DB,
        *args,
    ]


def cli(
    *args: str, monitored: bool = False, timeout: int = 300, check: bool = True
) -> dict[str, Any]:
    if not monitored:
        return guest_exec(OPS, "/usr/sbin/runuser", cli_args(*args), timeout=timeout, check=check)
    watch = None
    watch_stopped = False
    component = "resource_watch_preflight"
    try:
        watch = resource_watch()
        watch.start()
        component = "guest_command"
        result = guest_exec(OPS, "/usr/sbin/runuser", cli_args(*args), timeout=timeout, check=check)
        component = "resource_watch_postflight"
        watch.check()
        watch.stop()
        watch_stopped = True
        watch.check()
        component = "resource_watch_report"
        return {**result, "resource_watch": watch.report()}
    except Exception as exc:
        if check:
            raise
        # Preserve only the exception class and local stage; guest output, command
        # arguments, prompts, and exception text can contain sensitive data.
        failure = {
            "exit_code": None,
            "stdout": "",
            "stderr": "",
            "transport_failure_category": type(exc).__name__,
            "transport_failure_component": component,
        }
        if watch is not None:
            failure["resource_watch"] = watch.report()
        return failure
    finally:
        if watch is not None and not watch_stopped:
            watch.stop()


class ExternalServerProcess:
    """Minimal process handle for the identity-verified acceptance-owned server."""

    def __init__(self, pid: int):
        self.pid = pid

    def poll(self) -> int | None:
        try:
            os.kill(self.pid, 0)
        except (ProcessLookupError, PermissionError):
            return 1
        return None

    def terminate(self) -> None:
        os.kill(self.pid, signal.SIGTERM)

    def kill(self) -> None:
        os.kill(self.pid, signal.SIGKILL)

    def wait(self, timeout: float | None = None) -> int:
        deadline = time.monotonic() + (timeout or 3)
        while time.monotonic() < deadline:
            result = self.poll()
            if result is not None:
                return result
            time.sleep(0.05)
        raise TimeoutError("acceptance-owned Qwen process did not stop within its bounded wait")


def resource_watch() -> Any:
    identity_path = LOCAL / "runtime" / "server-identity.json"
    identity = json.loads(identity_path.read_text(encoding="utf-8"))
    pid = identity.get("pid")
    if not isinstance(pid, int) or pid <= 1:
        raise RuntimeError("acceptance Qwen process identity is missing")
    actual_executable = Path(os.readlink(f"/proc/{pid}/exe")).resolve()
    expected_executable = Path(
        "/home/morphious/.local/src/llama.cpp/build/bin/llama-server"
    ).resolve()
    cmdline = Path(f"/proc/{pid}/cmdline").read_bytes().split(b"\0")
    required = (
        str(expected_executable).encode(),
        b"--port",
        b"18080",
        b"--api-key-file",
        b"/home/morphious/.config/runbookos/llama-api-key",
    )
    if actual_executable != expected_executable or not all(item in cmdline for item in required):
        raise RuntimeError("acceptance Qwen process command identity mismatch")
    script = REPO / "scripts" / "ai-local-acceptance-v060.py"
    spec = importlib.util.spec_from_file_location("b03_resource_orchestrator", script)
    if spec is None or spec.loader is None:
        raise RuntimeError("resource monitor implementation is unavailable")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    process = ExternalServerProcess(pid)
    return module.ResourceWatch(
        process,
        expected_executable,
        module._import_test_harness().sample_acceptance_server,
        poll_interval=0.5,
    )


def json_out(result: dict[str, Any]) -> dict[str, Any]:
    if result.get("exit_code") != 0:
        raise RuntimeError("RunbookOS CLI rejected the campaign step")
    try:
        value = json.loads(result["stdout"])
    except (KeyError, json.JSONDecodeError):
        raise RuntimeError("RunbookOS CLI returned an invalid JSON result") from None
    if not isinstance(value, dict):
        raise RuntimeError("RunbookOS CLI returned an unexpected result shape")
    return value


def persisted_investigation_failure(incident_id: str) -> dict[str, Any]:
    """Read only sanitized failed-investigation metadata for durable diagnostics."""
    incident = json_out(cli("incidents", "show", incident_id))
    links = incident.get("investigations", [])
    if not links or not isinstance(links[-1].get("investigation_id"), str):
        return {"status": "unavailable"}
    investigation_id = links[-1]["investigation_id"]
    query = (
        "import json,sqlite3,sys; c=sqlite3.connect(sys.argv[1]); "
        "r=c.execute('SELECT result_json FROM investigations WHERE investigation_id=?', "
        "(sys.argv[2],)).fetchone(); d=json.loads(r[0]) if r else {}; "
        "f=d.get('assessment_failure') or {}; "
        "print(json.dumps({'status':d.get('status'),'failure_stage':f.get('stage'),"
        "'failure_category':f.get('reason_category'),"
        "'validator_location':f.get('validator_location') if f.get('validator_location') in ('reply_version','category','confidence','evidence_ids','reason','abstain','overall_uncertainty','unknown_field') else None,"
        "'validator_error':f.get('validator_error') if f.get('validator_error') in ('missing','extra','literal','range','invalid_type','advisory_text_command','advisory_text_verification') else None,'selected_diagnostics':"
        "d.get('selected_diagnostics',[]),'evidence_count':len(d.get('evidence',[])),"
        "'execution_ids':sorted({x.get('execution_id') for x in d.get('evidence',[]) "
        "if isinstance(x,dict) and x.get('execution_id')})}))"
    )
    result = guest_exec(OPS, "/usr/bin/python3", ["-c", query, DB, investigation_id], timeout=10)
    try:
        summary = json.loads(result["stdout"])
    except (KeyError, json.JSONDecodeError):
        return {"status": "unavailable", "investigation_id": investigation_id}
    return {"investigation_id": investigation_id, **summary}


def remote_read(vm: str, path: str) -> str:
    return guest_exec(vm, "/bin/cat", [path])["stdout"]


def configure_controller() -> None:
    # Clone the accepted inventory and policy into a fresh, campaign-only config.
    inv_raw = remote_read(
        OPS, "/var/lib/runbookos/acceptance-v070/campaign-batch02/config/inventory.yml"
    )
    policy_raw = remote_read(
        OPS, "/var/lib/runbookos/acceptance-v070/campaign-batch02/config/policy.yml"
    )
    inventory = yaml.safe_load(inv_raw)
    policy = yaml.safe_load(policy_raw)
    inventory["hosts"]["svc-web-01"].setdefault("probe_targets", {}).update(
        {
            f"b03-{key}": value
            for key, value in PROBES.items()
            if key in {"app", "backend", "worker"}
        }
    )
    inventory["hosts"]["db-01"].setdefault("probe_targets", {}).update(
        {"b03-db": PROBES["db"], "b03-db-tcp": PROBES["db_tcp"]}
    )
    web_policy = policy["hosts"]["svc-web-01"]
    web_policy["diagnostic_actions"] = sorted(
        set(web_policy.get("diagnostic_actions", []))
        | {"systemd.failed_units", "systemd.is_active", "http.readiness", "network.tcp_connect"}
    )
    web_policy["remediation_actions"] = sorted(
        set(web_policy.get("remediation_actions", [])) | {"systemd.restart"}
    )
    web_policy["allowed_units"] = sorted(
        set(web_policy.get("allowed_units", [])) | set(WEB_UNITS.values())
    )
    web_policy["allowed_probe_targets"] = sorted(
        set(web_policy.get("allowed_probe_targets", [])) | {"b03-app", "b03-backend", "b03-worker"}
    )
    db_policy = policy["hosts"]["db-01"]
    db_policy["diagnostic_actions"] = sorted(
        set(db_policy.get("diagnostic_actions", []))
        | {"systemd.is_active", "postgresql.protocol_available", "network.tcp_connect"}
    )
    db_policy["remediation_actions"] = sorted(
        set(db_policy.get("remediation_actions", [])) | {"systemd.restart"}
    )
    db_policy["allowed_units"] = sorted(set(db_policy.get("allowed_units", [])) | {DB_UNIT})
    db_policy["allowed_probe_targets"] = sorted(
        set(db_policy.get("allowed_probe_targets", [])) | {"b03-db", "b03-db-tcp"}
    )
    guest_exec(
        OPS,
        "/usr/bin/install",
        ["-d", "-o", "runbookos", "-g", "runbookos", "-m", "700", CONFIG, RUNBOOKS, STATE],
    )
    guest_exec(OPS, "/bin/chown", ["runbookos:runbookos", STATE])
    guest_exec(OPS, "/bin/chmod", ["700", STATE])
    write_yaml(OPS, CONFIG + "/inventory.yml", inventory)
    write_yaml(OPS, CONFIG + "/policy.yml", policy)
    catalog = {
        "schema_version": 1,
        "provider": {
            "type": "openai_compatible",
            "base_url": "http://127.0.0.1:8080/v1",
            "model": "qwen3.5-9b-instruct",
            "api_key_env": "RUNBOOKOS_LLAMA_API_KEY",
            "timeout_seconds": 120,
            "max_tokens": 700,
            "temperature": 0,
        },
        "limits": {
            "max_diagnostic_runbooks": 1,
            "max_tool_calls": 8,
            "execution_budget_seconds": 90,
            "max_incident_chars": 4000,
        },
        "catalog": [
            {
                "id": "b03_web_diagnostics",
                "runbook": "runbooks/diagnostic-web.yml",
                "description": "Read-only fixture service state, readiness, and endpoint connectivity observations.",
            },
            {
                "id": "b03_worker_diagnostics",
                "runbook": "runbooks/diagnostic-worker.yml",
                "description": "Read-only application readiness and bounded worker observations.",
            },
            {
                "id": "b03_database_diagnostics",
                "runbook": "runbooks/diagnostic-database.yml",
                "description": "Read-only disposable PostgreSQL unit, protocol, and TCP observations.",
            },
        ],
    }
    write_yaml(OPS, CONFIG + "/investigation.yml", catalog)

    def step(
        name: str,
        action: str,
        args: dict[str, Any],
        timeout: int = 2,
        verify: list[dict[str, Any]] | None = None,
    ) -> dict[str, Any]:
        value = {"id": name, "action": action, "timeout_seconds": timeout, "with": args}
        if verify:
            value["verify"] = verify
        return value

    def doc(
        runbook_id: str,
        title: str,
        target: str,
        steps: list[dict[str, Any]],
        *,
        pre: list[dict[str, Any]] | None = None,
        post: list[dict[str, Any]] | None = None,
    ) -> dict[str, Any]:
        result = {
            "api_version": "runbookos/v1",
            "kind": "Runbook",
            "metadata": {
                "id": runbook_id,
                "name": title,
                "description": "Bounded read-only observations on the isolated Batch 03 fixture.",
                "risk": "low",
            },
            "targets": [target],
            "steps": steps,
        }
        if pre is not None:
            result["preflight"] = pre
        if post is not None:
            result["postflight"] = post
        return result

    web_steps = [
        step("failed-units", "systemd.failed_units", {}),
        step("app-state", "systemd.is_active", {"unit": WEB_UNITS["app"]}),
        step("backend-state", "systemd.is_active", {"unit": WEB_UNITS["backend"]}),
        step("dns-state", "systemd.is_active", {"unit": WEB_UNITS["dns"]}),
        step("app-http", "http.readiness", {"endpoint_id": "b03-app"}, 3),
        step("backend-tcp", "network.tcp_connect", {"endpoint_id": "b03-backend"}, 3),
    ]
    worker_steps = [
        step("failed-units", "systemd.failed_units", {}),
        step("worker-state", "systemd.is_active", {"unit": WEB_UNITS["worker"]}),
        step("worker-tcp", "network.tcp_connect", {"endpoint_id": "b03-worker"}, 3),
        step("app-http", "http.readiness", {"endpoint_id": "b03-app"}, 3),
    ]
    db_steps = [
        step("cluster-state", "systemd.is_active", {"unit": DB_UNIT}),
        step("postgres-protocol", "postgresql.protocol_available", {"endpoint_id": "b03-db"}, 3),
        step("postgres-tcp", "network.tcp_connect", {"endpoint_id": "b03-db-tcp"}, 3),
    ]
    for name, runbook in (
        (
            "diagnostic-web.yml",
            doc("b03-diagnostic-web", "B03 web diagnostics", "svc-web-01", web_steps),
        ),
        (
            "diagnostic-worker.yml",
            doc("b03-diagnostic-worker", "B03 worker diagnostics", "svc-web-01", worker_steps),
        ),
        (
            "diagnostic-database.yml",
            doc("b03-diagnostic-database", "B03 database diagnostics", "db-01", db_steps),
        ),
    ):
        write_yaml(OPS, RUNBOOKS + "/" + name, runbook)


def install_web_fixture() -> None:
    fixture_bytes = (REPO / "scripts" / "campaign_batch03_fixture.py").read_bytes()
    guest_exec(
        WEB, "/usr/bin/install", ["-d", "-o", "root", "-g", "root", "-m", "755", FIXTURE_ROOT]
    )
    guest_exec(
        WEB,
        "/usr/bin/install",
        ["-d", "-o", "nobody", "-g", "nogroup", "-m", "755", FIXTURE_ROOT + "/state"],
    )
    write_guest(WEB, FIXTURE_SCRIPT, fixture_bytes, mode=0o755)
    good = (
        json.dumps(
            {"backend_name": "backend.b03.test", "backend_port": 18901}, sort_keys=True
        ).encode()
        + b"\n"
    )
    write_guest(WEB, FIXTURE_ROOT + "/app.good.json", good, uid=65534, gid=65534, mode=0o644)
    write_guest(WEB, FIXTURE_ROOT + "/app.json", good, uid=65534, gid=65534, mode=0o644)
    definitions = {
        "backend": ("B03 disposable backend", "backend", ""),
        "app": (
            "B03 disposable HTTP application",
            "app",
            "Restart=on-failure\nRestartSec=0.5\n",
        ),
        "worker": ("B03 bounded disposable worker", "worker", "CPUQuota=20%\n"),
        "dns": ("B03 isolated disposable DNS endpoint", "dns", ""),
    }
    for role, (description, command, extra) in definitions.items():
        start_limit = "StartLimitIntervalSec=10\nStartLimitBurst=3\n" if role == "app" else ""
        restart_setting = "" if role == "app" else "Restart=no\n"
        unit = (
            "[Unit]\nDescription="
            + description
            + "\nAfter=network.target\n"
            + start_limit
            + "[Service]\nType=simple\nUser=nobody\nGroup=nogroup\n"
            f"WorkingDirectory={FIXTURE_ROOT}\nExecStartPre=/usr/bin/python3 {FIXTURE_SCRIPT} prepare-{role}\n"
            f"ExecStart=/usr/bin/python3 {FIXTURE_SCRIPT} {command}\n"
            + restart_setting
            + "TimeoutStartSec=8\nTimeoutStopSec=5\n"
            "NoNewPrivileges=yes\nPrivateTmp=yes\nProtectSystem=strict\n"
            f"ReadWritePaths={FIXTURE_ROOT}/state {FIXTURE_ROOT}/app.json\n"
            "RestrictAddressFamilies=AF_INET AF_UNIX\n"
            + extra
            + "[Install]\nWantedBy=multi-user.target\n"
        ).encode()
        unit_path = "/etc/systemd/system/" + WEB_UNITS[role]
        write_guest(WEB, unit_path, unit, mode=0o644)
    guest_exec(WEB, "/bin/systemctl", ["daemon-reload"])
    for unit in WEB_UNITS.values():
        guest_exec(WEB, "/bin/systemctl", ["enable", "--now", unit], timeout=30)
    # enable --now leaves active processes on the old script after a prior
    # partial provisioning attempt. Restart only campaign-owned fixtures on
    # every provision pass so loaded code and installed bytes cannot diverge.
    for unit in WEB_UNITS.values():
        guest_exec(WEB, "/bin/systemctl", ["restart", unit], timeout=30)


def install_database_fixture() -> None:
    clusters = guest_exec(DBVM, "/usr/bin/pg_lsclusters", ["--no-header"])["stdout"]
    if not any(" b03 " in f" {line} " for line in clusters.splitlines()):
        result = guest_exec(
            DBVM,
            "/usr/bin/pg_createcluster",
            ["16", "b03", "--port", "55433"],
            timeout=90,
            check=False,
        )
        if result["exit_code"] != 0:
            raise RuntimeError("could not create isolated PostgreSQL B03 cluster")
        guest_exec(DBVM, "/bin/systemctl", ["enable", "--now", DB_UNIT], timeout=60)
    guest_exec(
        DBVM,
        "/usr/bin/pg_conftool",
        ["16", "b03", "set", "listen_addresses", "10.60.30.10,localhost"],
    )
    guest_exec(DBVM, "/bin/systemctl", ["restart", DB_UNIT], timeout=60)


def snapshot_web() -> dict[str, Any]:
    code = (
        "import json,socket,urllib.request,urllib.error,subprocess\nunits="
        + repr(list(WEB_UNITS.values()))
        + "\nstates={u:subprocess.run(['/bin/systemctl','is-active',u],capture_output=True,text=True).stdout.strip() for u in units}\n"
        + "try:\n r=urllib.request.urlopen('http://10.60.20.10:18890/health',timeout=2); status=r.status; body=r.read(100).decode(errors='replace').strip()\n"
        + "except urllib.error.HTTPError as e:\n status=e.code; body=e.read(100).decode(errors='replace').strip()\n"
        + "except Exception as e:\n status=0; body=type(e).__name__\n"
        + "tcp={}\nfor k,p in [('backend',18901),('worker',18902)]:\n try:\n  s=socket.create_connection(('10.60.20.10',p),timeout=.5); s.close(); tcp[k]=True\n except OSError:\n  tcp[k]=False\n"
        + "query=b'\\x12\\x34\\x01\\x00\\x00\\x01\\x00\\x00\\x00\\x00\\x00\\x00\\x07backend\\x03b03\\x04test\\x00\\x00\\x01\\x00\\x01'; d=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); d.settimeout(.5)\n"
        + "try:\n d.sendto(query,('10.60.20.10',18953)); answer=d.recv(512); dns_answer=socket.inet_ntoa(answer[-4:]) if len(answer)>=16 and int.from_bytes(answer[6:8],'big')>0 else None\nexcept OSError:\n dns_answer=None\nd.close()\n"
        + "print(json.dumps({'unit_states':states,'http_status':status,'http_body':body,'tcp':tcp,'dns_answer':dns_answer},sort_keys=True))"
    )
    result = guest_exec(WEB, "/usr/bin/python3", ["-c", code], timeout=10)
    return json.loads(result["stdout"])


def snapshot_db() -> dict[str, Any]:
    code = (
        "import socket,json,subprocess; c=subprocess.run(['/usr/bin/pg_lsclusters','--no-header'],capture_output=True,text=True).stdout; "
        "s=socket.socket(); s.settimeout(.5); r=s.connect_ex(('10.60.30.10',55433)); s.close(); "
        "print(json.dumps({'clusters':c,'tcp':r==0,'unit':subprocess.run(['/bin/systemctl','is-active','postgresql@16-b03.service'],capture_output=True,text=True).stdout.strip()}))"
    )
    return json.loads(guest_exec(DBVM, "/usr/bin/python3", ["-c", code], timeout=10)["stdout"])


def dns_misdirection_confirmed(observed: dict[str, Any]) -> bool:
    """Require the injected wrong DNS answer and its real failed HTTP consequence."""
    body = str(observed.get("http_body", ""))
    return (
        observed.get("dns_answer") == "10.60.20.99"
        and observed.get("http_status") == 503
        and ("ConnectionRefused" in body or "TimeoutError" in body)
    )


def dns_blackhole_confirmed(observed: dict[str, Any]) -> bool:
    """Require a live DNS unit, missing UDP answer, and dependent HTTP timeout."""
    return (
        observed.get("dns_answer") is None
        and observed.get("http_status") == 503
        and "TimeoutError" in str(observed.get("http_body", ""))
        and observed.get("unit_states", {}).get(WEB_UNITS["dns"]) == "active"
    )


def baseline_ok(scenario: dict[str, Any], snapshot: dict[str, Any]) -> bool:
    if scenario["target"] == "db-01":
        return (
            "16 b03" in snapshot.get("clusters", "")
            and "online" in snapshot.get("clusters", "")
            and snapshot.get("tcp") is True
        )
    return (
        snapshot.get("http_status") == 200
        and snapshot.get("dns_answer") == "10.60.20.10"
        and all(
            snapshot.get("unit_states", {}).get(WEB_UNITS[key]) == "active" for key in WEB_UNITS
        )
        and all(snapshot.get("tcp", {}).get(key) is True for key in ("backend", "worker"))
    )


def inject_fault(scenario: dict[str, Any]) -> dict[str, Any]:
    fault = scenario["fault"]
    if fault == "backend_crash":
        result = guest_exec(
            WEB,
            "/bin/systemctl",
            ["kill", "--kill-who=main", "--signal=SIGKILL", WEB_UNITS["backend"]],
            check=False,
        )
        if result["exit_code"] != 0:
            result = guest_exec(WEB, "/bin/systemctl", ["stop", WEB_UNITS["backend"]])
    elif fault == "invalid_app_config":
        write_guest(
            WEB, FIXTURE_ROOT + "/state/app-invalid", b"fault\n", uid=65534, gid=65534, mode=0o600
        )
    elif fault == "dns_stop":
        guest_exec(WEB, "/bin/systemctl", ["stop", WEB_UNITS["dns"]])
    elif fault == "postgres_stop":
        guest_exec(DBVM, "/bin/systemctl", ["stop", DB_UNIT])
    elif fault == "worker_pressure":
        write_guest(
            WEB,
            FIXTURE_ROOT + "/state/worker-pressure",
            b"bounded-cpu-load\n",
            uid=65534,
            gid=65534,
            mode=0o600,
        )
    elif fault == "backend_stop":
        guest_exec(WEB, "/bin/systemctl", ["stop", WEB_UNITS["backend"]])
    elif fault == "dns_wrong_answer":
        write_guest(
            WEB,
            FIXTURE_ROOT + "/state/dns-wrong-answer",
            b"10.60.20.99\n",
            uid=65534,
            gid=65534,
            mode=0o600,
        )
    elif fault == "dns_drop":
        write_guest(
            WEB,
            FIXTURE_ROOT + "/state/dns-packet-drop",
            b"drop-fixture-replies\n",
            uid=65534,
            gid=65534,
            mode=0o600,
        )
    elif fault == "app_crash_loop":
        write_guest(
            WEB,
            FIXTURE_ROOT + "/state/app-crash-loop",
            b"enabled\n",
            uid=65534,
            gid=65534,
            mode=0o600,
        )
        write_guest(
            WEB,
            FIXTURE_ROOT + "/state/app-crash-loop-attempts",
            b"0\n",
            uid=65534,
            gid=65534,
            mode=0o600,
        )
        guest_exec(WEB, "/bin/systemctl", ["restart", WEB_UNITS["app"]], timeout=30, check=False)
        time.sleep(2)
    elif fault == "compound":
        guest_exec(WEB, "/bin/systemctl", ["stop", WEB_UNITS["backend"]])
        write_guest(
            WEB,
            FIXTURE_ROOT + "/state/app-invalid",
            b"compound\n",
            uid=65534,
            gid=65534,
            mode=0o600,
        )
    else:
        raise ValueError("unsupported Batch 03 fixture fault")
    if scenario["target"] == "db-01":
        observed = snapshot_db()
        confirmed = (
            observed.get("tcp") is False
            and "16 b03" in observed.get("clusters", "")
            and "down" in observed.get("clusters", "")
        )
    else:
        observed = snapshot_web()
        confirmed = observed.get("http_status") != 200
        if fault in {"backend_crash", "backend_stop"}:
            confirmed = (
                confirmed and observed.get("unit_states", {}).get(WEB_UNITS["backend"]) != "active"
            )
        elif fault == "dns_stop":
            confirmed = (
                confirmed and observed.get("unit_states", {}).get(WEB_UNITS["dns"]) != "active"
            )
        elif fault == "invalid_app_config":
            confirmed = (
                confirmed and observed.get("unit_states", {}).get(WEB_UNITS["app"]) == "active"
            )
        elif fault == "worker_pressure":
            confirmed = confirmed and "worker-resource-pressure" in observed.get("http_body", "")
        elif fault == "dns_wrong_answer":
            confirmed = dns_misdirection_confirmed(observed)
        elif fault == "dns_drop":
            confirmed = dns_blackhole_confirmed(observed)
        elif fault == "app_crash_loop":
            confirmed = confirmed and observed.get("unit_states", {}).get(WEB_UNITS["app"]) in {
                "failed",
                "activating",
            }
        elif fault == "compound":
            confirmed = (
                confirmed and observed.get("unit_states", {}).get(WEB_UNITS["backend"]) != "active"
            )
    return {"status": "PASS" if confirmed else "FAIL", "confirmed": confirmed, "observed": observed}


def restore_web_baseline() -> dict[str, Any]:
    """Clear known campaign markers and verify only the dedicated fixture units."""
    markers = (
        "backend-unavailable",
        "backend-partition",
        "app-invalid",
        "worker-pressure",
        "dns-wrong-answer",
        "dns-packet-drop",
        "app-crash-loop",
        "app-crash-loop-attempts",
    )
    cleanup = (
        "import pathlib,sys; root=pathlib.Path(sys.argv[1]); "
        "[(root/'state'/name).unlink(missing_ok=True) for name in sys.argv[2:]]; "
        "(root/'app.json').write_bytes((root/'app.good.json').read_bytes())"
    )
    guest_exec(WEB, "/usr/bin/python3", ["-c", cleanup, FIXTURE_ROOT, *markers])
    for unit in WEB_UNITS.values():
        guest_exec(WEB, "/bin/systemctl", ["reset-failed", unit], check=False)
        guest_exec(WEB, "/bin/systemctl", ["start", unit], timeout=30, check=False)
    snapshot = stable_condition(
        snapshot_web,
        lambda value: baseline_ok({"target": "svc-web-01"}, value),
        timeout_seconds=15,
        poll_interval_seconds=0.25,
    )
    healthy = baseline_ok({"target": "svc-web-01"}, snapshot)
    return {"status": "PASS" if healthy else "FAIL", "snapshot": snapshot}


def restore_db_baseline() -> dict[str, Any]:
    """Start and verify only the isolated Batch 03 PostgreSQL cluster."""
    guest_exec(DBVM, "/bin/systemctl", ["reset-failed", DB_UNIT], check=False)
    guest_exec(DBVM, "/bin/systemctl", ["start", DB_UNIT], timeout=60, check=False)
    snapshot = snapshot_db()
    healthy = (
        "16 b03" in snapshot.get("clusters", "")
        and "online" in snapshot.get("clusters", "")
        and snapshot.get("tcp") is True
    )
    return {"status": "PASS" if healthy else "FAIL", "snapshot": snapshot}


def candidate_catalog(scenario: dict[str, Any]) -> list[dict[str, Any]]:
    if scenario["target"] == "db-01":
        units = {"db": DB_UNIT}
        required = ["systemd.is_active", "postgresql.protocol_available", "network.tcp_connect"]
    else:
        units = {key: WEB_UNITS[key] for key in scenario["units"]}
        required = [
            "systemd.failed_units",
            "systemd.is_active",
            "http.readiness",
            "network.tcp_connect",
        ]
    return [
        {
            "action_id": "systemd.restart",
            "target_ref": "b03-" + role + "-unit",
            "target_name": scenario["target"],
            "arguments": {"unit": unit},
            "required_evidence_actions": required,
            "compatible_categories": list(CATEGORIES),
        }
        for role, unit in units.items()
    ]


def remaining_recovery_candidates(
    scenario: dict[str, Any], postflight: dict[str, Any]
) -> list[dict[str, Any]]:
    """Project only recovery candidates justified by independent failed state."""
    snapshot = postflight.get("snapshot", {})
    unit_states = snapshot.get("unit_states", {})
    http_body = str(snapshot.get("http_body", ""))
    unresolved_units = {unit for unit, state in unit_states.items() if state != "active"}
    if http_body == "invalid-application-configuration":
        unresolved_units.add(WEB_UNITS["app"])
    if http_body in {"backend-readiness-failed", "backend-unavailable"}:
        unresolved_units.add(WEB_UNITS["backend"])
    return [
        item
        for item in candidate_catalog(scenario)
        if item["arguments"]["unit"] in unresolved_units
    ]


def make_recovery_runbook(run_id: str, target: str, candidate: dict[str, Any]) -> str:
    unit = candidate["arguments"]["unit"]
    preflight = []
    if target == "db-01":
        preflight = [
            {
                "id": "database-protocol-fails",
                "action": "postgresql.protocol_available",
                "timeout_seconds": 3,
                "with": {"endpoint_id": "b03-db"},
                "verify": [{"path": "data.protocol_available", "operator": "eq", "value": False}],
            }
        ]
        postflight = [
            {
                "id": "database-unit-active",
                "action": "systemd.is_active",
                "timeout_seconds": 3,
                "with": {"unit": unit},
                "verify": [{"path": "data.active", "operator": "is_true"}],
            },
            {
                "id": "database-protocol-ready",
                "action": "postgresql.protocol_available",
                "timeout_seconds": 5,
                "with": {"endpoint_id": "b03-db"},
                "verify": [{"path": "data.protocol_available", "operator": "is_true"}],
            },
        ]
    else:
        preflight = [
            {
                "id": "application-not-ready",
                "action": "http.readiness",
                "timeout_seconds": 3,
                "with": {"endpoint_id": "b03-app"},
                "verify": [{"path": "data.ready", "operator": "eq", "value": False}],
            }
        ]
        postflight = [
            {
                "id": "selected-unit-active",
                "action": "systemd.is_active",
                "timeout_seconds": 3,
                "with": {"unit": unit},
                "verify": [{"path": "data.active", "operator": "is_true"}],
            }
        ]
    doc = {
        "api_version": "runbookos/v1",
        "kind": "Runbook",
        "metadata": {
            "id": "b03-recovery-" + re.sub(r"[^a-z0-9-]", "-", run_id.lower()),
            "name": "B03 AI-proposed registered recovery",
            "description": "One registered systemd restart selected by a validated advisory AI proposal.",
            "risk": "medium",
        },
        "targets": [target],
        "preflight": preflight,
        "steps": [
            {
                "id": "ai-selected-restart",
                "action": candidate["action_id"],
                "timeout_seconds": 30,
                "with": candidate["arguments"],
                "verify": [{"path": "data.restarted", "operator": "is_true"}],
            }
        ],
        "postflight": postflight,
    }
    return yaml.safe_dump(doc, sort_keys=False)


def status_summary(value: dict[str, Any]) -> dict[str, Any]:
    assessment = value.get("assessment")
    if not isinstance(assessment, dict):
        assessment = {}
    classification = (assessment.get("classifications") or [{}])[0]
    return {
        "status": "PASS"
        if value.get("status") == "succeeded"
        and assessment.get("assessment_status") in {"assessed", "abstained"}
        else "FAIL",
        "investigation_status": value.get("status"),
        "investigation_id": value.get("investigation_id"),
        "assessment_status": assessment.get("assessment_status"),
        "category": classification.get("category"),
        "confidence": classification.get("confidence"),
        "evidence_refs": [item.get("ref") for item in value.get("evidence", []) if item.get("ref")],
        "model_metadata": value.get("model_metadata", {}),
    }


def investigation_ledger_steps(
    investigation: dict[str, Any], summary: dict[str, Any]
) -> dict[str, dict[str, Any]]:
    """Project persisted diagnostic and assessment facts into ledger phases."""
    evidence = investigation.get("evidence", [])
    if not isinstance(evidence, list):
        evidence = []
    refs = summary.get("evidence_refs", [])
    assessment = investigation.get("assessment")
    if not isinstance(assessment, dict):
        assessment = {}
    assessment_status = assessment.get("assessment_status")
    classifications = assessment.get("classifications")
    first_classification = (
        classifications[0] if isinstance(classifications, list) and classifications else {}
    )
    execution_ids = sorted(
        {
            item["execution_id"]
            for item in evidence
            if isinstance(item, dict) and isinstance(item.get("execution_id"), str)
        }
    )
    return {
        "diagnostics": {
            "status": "PASS" if summary.get("status") == "PASS" and bool(refs) else "FAIL",
            "selected_diagnostics": investigation.get("selected_diagnostics", []),
            "execution_ids": execution_ids,
            "evidence_refs": refs,
            "evidence_count": len(evidence),
        },
        "assessment": {
            "status": "PASS"
            if assessment_status in {"assessed", "abstained"} and bool(refs)
            else "FAIL",
            "assessment_status": assessment_status,
            "category": summary.get("category"),
            "confidence": first_classification.get("confidence")
            if isinstance(first_classification, dict)
            else None,
            "evidence_refs": refs,
            "semantic_support": "unverified",
        },
    }


def independent_postflight(scenario: dict[str, Any]) -> dict[str, Any]:
    if scenario["target"] == "db-01":
        snap = snapshot_db()
        query_code = "import subprocess; r=subprocess.run(['/usr/sbin/runuser','-u','postgres','--','/usr/bin/psql','-p','55433','-d','postgres','-Atqc','SELECT 1'],capture_output=True,text=True); print(r.stdout.strip()); raise SystemExit(r.returncode)"
        query = guest_exec(DBVM, "/usr/bin/python3", ["-c", query_code], timeout=15, check=False)
        passed = (
            snap.get("tcp") is True
            and "16 b03" in snap.get("clusters", "")
            and "online" in snap.get("clusters", "")
            and query.get("exit_code") == 0
            and query.get("stdout", "").strip() == "1"
        )
        return {
            "status": "PASS" if passed else "FAIL",
            "snapshot": snap,
            "postgresql_query": query.get("stdout", "").strip()
            if query.get("exit_code") == 0
            else "failed",
        }
    snap = snapshot_web()
    passed = (
        snap.get("http_status") == 200
        and snap.get("dns_answer") == "10.60.20.10"
        and all(value == "active" for value in snap.get("unit_states", {}).values())
        and all(value is True for value in snap.get("tcp", {}).values())
    )
    return {
        "status": "PASS" if passed else "FAIL",
        "snapshot": snap,
        "oracle": "direct HTTP/TCP and systemd observations from the target guest",
    }


def sqlite_integrity() -> str:
    """Check the campaign database with Python's bundled sqlite3 module."""
    code = (
        "import sqlite3,sys; connection=sqlite3.connect(sys.argv[1]); "
        "print(connection.execute('PRAGMA integrity_check').fetchone()[0]); connection.close()"
    )
    result = guest_exec(OPS, "/usr/bin/python3", ["-c", code, DB])
    return result["stdout"].strip()


def initialize_ledger() -> dict[str, Any]:
    ledger = json.loads(LEDGER_PATH.read_text())
    live = ledger.setdefault("live_execution", {})
    live.setdefault("attempts", [])
    live["started"] = True
    live["status"] = "RUNNING"
    ledger["status"] = "LIVE_EXECUTION_IN_PROGRESS"
    return ledger


def checkpoint(ledger: dict[str, Any], *, sync_remote: bool = True) -> None:
    write_ledger(LEDGER_PATH, ledger)
    if not sync_remote:
        return
    payload = LEDGER_PATH.read_bytes()
    write_guest(OPS, REMOTE + "/batch03-ledger.json", payload, uid=999, gid=988, mode=0o600)
    remote_hash = guest_exec(OPS, "/usr/bin/sha256sum", [REMOTE + "/batch03-ledger.json"])[
        "stdout"
    ].split()[0]
    digest = hashlib.sha256(payload).hexdigest()
    sync = {"status": "PASS" if remote_hash == digest else "FAIL", "sha256": digest}
    ledger["controller_ledger_sync"] = sync
    write_ledger(LEDGER_PATH, ledger)
    payload = LEDGER_PATH.read_bytes()
    write_guest(OPS, REMOTE + "/batch03-ledger.json", payload, uid=999, gid=988, mode=0o600)
    final_hash = guest_exec(OPS, "/usr/bin/sha256sum", [REMOTE + "/batch03-ledger.json"])[
        "stdout"
    ].split()[0]
    ledger["controller_ledger_sync"]["status"] = (
        "PASS" if final_hash == hashlib.sha256(payload).hexdigest() else "FAIL"
    )
    write_ledger(LEDGER_PATH, ledger)


def run_scenario(
    scenario: dict[str, Any], ledger: dict[str, Any], attempt_number: int
) -> dict[str, Any]:
    previous = [
        item
        for item in ledger["live_execution"]["attempts"]
        if item.get("scenario_id") == scenario["id"]
    ]
    attempt = {
        "run_id": f"batch03-{scenario['id'].lower()}-attempt{attempt_number:02d}-{uuid.uuid4().hex[:8]}",
        "scenario_id": scenario["id"],
        "scenario": scenario["title"],
        "target": scenario["target"],
        "fixture_identity": "runbookos-campaign-b03",
        "fault_mechanism": scenario["fault"],
        "ground_truth_oracle": {"category": scenario["oracle"]},
        "retry_of": previous[-1]["run_id"] if previous else None,
        "started_at": now(),
        "result": "IN_PROGRESS",
        "steps": {},
    }
    ledger["live_execution"]["attempts"].append(attempt)
    checkpoint(ledger)
    phase = "baseline"
    try:
        restored = (
            restore_db_baseline() if scenario["target"] == "db-01" else restore_web_baseline()
        )
        if restored["status"] != "PASS":
            attempt["steps"]["baseline_restoration"] = restored
            raise RuntimeError("campaign fixture restoration did not establish a healthy baseline")
        before = snapshot_db() if scenario["target"] == "db-01" else snapshot_web()
        if not baseline_ok(scenario, before):
            attempt["steps"]["baseline"] = {"status": "FAIL", "observation": before}
            raise RuntimeError("fixture baseline is unhealthy")
        attempt["steps"]["baseline"] = {"status": "PASS", "observation": before}
        checkpoint(ledger)
        phase = "fault_injection"
        fault = inject_fault(scenario)
        attempt["steps"]["fault"] = fault
        if fault["status"] != "PASS":
            raise RuntimeError("fault injection did not produce its registered failure signal")
        checkpoint(ledger)
        phase = "incident_ingestion"
        alert = {
            "alert_id": attempt["run_id"],
            "source": "runbookos-campaign-batch03",
            "event_timestamp": now(),
            "severity": "error",
            "target_alias": scenario["target"],
            "service": "campaign-database"
            if scenario["target"] == "db-01"
            else "campaign-application",
            "category": "unknown",
            "summary": (
                "Disposable PostgreSQL readiness probe reported the cluster unavailable."
                if scenario["target"] == "db-01"
                else (
                    "Disposable HTTP readiness probe returned status "
                    + str(fault["observed"].get("http_status"))
                    + " with response class "
                    + str(fault["observed"].get("http_body", "unavailable"))[:80]
                    + "."
                )
            ),
            "fingerprint": attempt["run_id"],
            "metadata": {"campaign": "batch03"},
        }
        alert_path = STATE + "/alerts/" + attempt["run_id"] + ".json"
        write_guest(
            OPS,
            alert_path,
            json.dumps(alert, sort_keys=True).encode() + b"\n",
            uid=999,
            gid=988,
            mode=0o600,
        )
        ingest = cli("alerts", "ingest", alert_path)
        incident = json_out(ingest)
        incident_id = incident["incident_id"]
        attempt["incident_id"] = incident_id
        attempt["steps"]["incident"] = {"status": "PASS", "incident_id": incident_id}
        checkpoint(ledger)
        phase = "investigation"
        ack = cli(
            "incidents",
            "acknowledge",
            incident_id,
            "--reason",
            "Acknowledged the isolated Batch 03 fixture incident.",
        )
        if ack.get("exit_code") != 0:
            raise RuntimeError("incident acknowledgement failed")
        investigate = cli(
            "incidents",
            "investigate",
            incident_id,
            "--ai-config",
            CONFIG + "/investigation.yml",
            monitored=True,
            check=False,
        )
        watch = investigate.get("resource_watch", {})
        output_text = investigate.get("stdout", "")
        attempt["steps"]["investigation_transport"] = {
            "exit_code": investigate.get("exit_code"),
            "transport_failure_category": investigate.get("transport_failure_category"),
            "stdout_characters": len(output_text),
            "stdout_sha256": hashlib.sha256(output_text.encode()).hexdigest(),
            "stderr_characters": len(investigate.get("stderr", "")),
            "resource_watch": {
                key: watch.get(key)
                for key in (
                    "status",
                    "sample_count",
                    "peak_rss_bytes",
                    "minimum_memavailable_bytes",
                    "failure_category",
                )
            },
        }
        checkpoint(ledger)
        if investigate.get("exit_code") != 0:
            failure = persisted_investigation_failure(incident_id)
            attempt["investigation_id"] = failure.get("investigation_id")
            attempt["steps"]["investigation"] = {
                "status": "FAIL",
                "failure_category": failure.get("failure_category", "investigation_failed"),
                "failure_stage": failure.get("failure_stage", "unknown"),
                "selected_diagnostics": failure.get("selected_diagnostics", []),
                "evidence_count": failure.get("evidence_count", 0),
                "execution_ids": failure.get("execution_ids", []),
                "resource_watch": attempt["steps"]["investigation_transport"]["resource_watch"],
            }
            raise RuntimeError("RunbookOS investigation failed")
        try:
            investigation = json.loads(output_text)
        except (json.JSONDecodeError, TypeError):
            attempt["steps"]["investigation"] = {
                "status": "FAIL",
                "failure_category": "invalid_cli_json_output",
                "resource_watch": attempt["steps"]["investigation_transport"]["resource_watch"],
            }
            raise RuntimeError("RunbookOS investigation returned invalid CLI JSON") from None
        inv = status_summary(investigation)
        attempt["investigation_id"] = inv.get("investigation_id")
        attempt["steps"]["investigation"] = {
            **inv,
            "ground_truth_category": scenario["oracle"],
            "category_agreement": inv.get("category") == scenario["oracle"],
            "selected_diagnostics": investigation.get("selected_diagnostics", []),
            "evidence_count": len(investigation.get("evidence", []))
            if isinstance(investigation.get("evidence"), list)
            else 0,
            "resource_watch": watch,
            "provider_requests": inv.get("model_metadata", {}).get("model_calls", 0),
        }
        attempt["steps"].update(investigation_ledger_steps(investigation, inv))
        if inv["status"] != "PASS" or not inv.get("evidence_refs"):
            raise RuntimeError("assessment was missing or invalid")
        checkpoint(ledger)
        phase = "proposal"
        candidates = {"schema_version": 1, "candidates": candidate_catalog(scenario)}
        candidate_path = CONFIG + "/candidates-" + attempt["run_id"] + ".yml"
        write_yaml(OPS, candidate_path, candidates)
        proposal_result = cli(
            "incidents",
            "propose-remediation",
            incident_id,
            "--investigation",
            inv["investigation_id"],
            "--ai-config",
            CONFIG + "/investigation.yml",
            "--candidates",
            candidate_path,
            monitored=True,
            check=False,
        )
        proposal_watch = proposal_result.get("resource_watch", {})
        if not isinstance(proposal_result.get("stdout"), str):
            raise RuntimeError("RunbookOS proposal command returned no response document")
        try:
            proposal_doc = json.loads(proposal_result["stdout"])
        except json.JSONDecodeError:
            raise RuntimeError("RunbookOS proposal command returned invalid JSON") from None
        if not isinstance(proposal_doc, dict):
            raise RuntimeError("RunbookOS proposal command returned an unexpected response shape")
        proposal = proposal_doc.get("proposal", {})
        validation = proposal.get("validation", {})
        accepted = (
            proposal_doc.get("status") == "accepted"
            and validation.get("accepted") is True
            and validation.get("abstained") is False
        )
        proposal_step = {
            "status": "PASS" if accepted else "FAIL",
            "decision": proposal_doc.get("status"),
            "reason_code": proposal_doc.get("reason_code"),
            "proposal": proposal
            if accepted
            else {"proposal_version": proposal.get("proposal_version"), "rejected": True},
            "selected_action_id": proposal.get("candidate_action_id"),
            "target_ref": proposal.get("target_ref"),
            "validated_candidate": validation.get("candidate") if accepted else None,
            "resource_watch": proposal_watch,
            "provider_requests": 1,
        }
        attempt["steps"]["proposal"] = proposal_step
        if not accepted:
            raise RuntimeError("Qwen remediation proposal was rejected or abstained")
        candidate = validation["candidate"]
        if (
            candidate.get("action_id") != proposal.get("candidate_action_id")
            or candidate.get("target_ref") != proposal.get("target_ref")
            or candidate.get("target_name") != scenario["target"]
        ):
            raise RuntimeError(
                "proposal candidate did not preserve exact action and target binding"
            )
        checkpoint(ledger)
        phase = "planning"
        runbook_path = RUNBOOKS + "/recovery-" + attempt["run_id"] + ".yml"
        write_guest(
            OPS,
            runbook_path,
            make_recovery_runbook(attempt["run_id"], scenario["target"], candidate).encode(),
            uid=999,
            gid=988,
            mode=0o600,
        )
        planned = json_out(cli("plan", runbook_path, "--json"))
        mutating = [
            item
            for item in planned.get("actions", [])
            if item.get("phase") == "steps" and item.get("action") == candidate["action_id"]
        ]
        if (
            len(mutating) != 1
            or mutating[0].get("action") != proposal["candidate_action_id"]
            or mutating[0].get("target") != scenario["target"]
            or mutating[0].get("arguments") != candidate["arguments"]
        ):
            raise RuntimeError("RunbookOS plan differs from the validated Qwen proposal")
        if planned.get("status") not in {"approval_required", "ready"}:
            raise RuntimeError("RunbookOS policy denied the exact proposed action")
        plan_id = planned["plan_id"]
        phase = "authorization"
        linked = json_out(cli("incidents", "associate-plan", incident_id, plan_id))
        if linked.get("plan_id") != plan_id:
            raise RuntimeError("exact proposal plan was not linked to the incident")
        approved = cli(
            "approve",
            plan_id,
            "--reason",
            "One-time approval for the exact Qwen-proposed action on the disposable Batch 03 target.",
        )
        if approved.get("exit_code") != 0:
            raise RuntimeError("policy approval failed")
        attempt["steps"]["authorization"] = {
            "status": "PASS",
            "plan_id": plan_id,
            "plan_hash": planned.get("plan_hash"),
            "approval_recorded": True,
        }
        checkpoint(ledger)
        phase = "remediation"
        executed = cli("run", plan_id, "--confirm", timeout=180)
        if executed.get("exit_code") != 0:
            raise RuntimeError("RunbookOS remediation execution failed")
        match = re.search(r"Execution\s+([0-9a-f-]{36}):\s*(\w+)", executed.get("stdout", ""))
        if not match or match.group(2) != "succeeded":
            raise RuntimeError("RunbookOS remediation execution did not report success")
        execution_id = match.group(1)
        attempt["steps"]["remediation"] = {
            "status": "PASS",
            "action_id": proposal["candidate_action_id"],
            "target_ref": proposal["target_ref"],
            "target": candidate["target_name"],
            "arguments": candidate["arguments"],
            "plan_id": plan_id,
            "execution_id": execution_id,
            "output": executed["stdout"].strip(),
        }
        checkpoint(ledger)
        phase = "postflight"
        postflight = independent_postflight(scenario)
        attempt["steps"]["postflight"] = postflight
        if postflight["status"] != "PASS" and scenario["fault"] == "compound":
            # Coordinated recovery remains model-proposed and action-by-action.
            # Choose follow-up candidates only from independently observed
            # still-inactive fixture units, then ask Qwen to propose again.
            remaining = remaining_recovery_candidates(scenario, postflight)
            if len(remaining) != 1:
                raise RuntimeError(
                    "compound recovery requires exactly one independently observed remaining unit"
                )
            candidate_path = CONFIG + "/candidates-followup-" + attempt["run_id"] + ".yml"
            write_yaml(OPS, candidate_path, {"schema_version": 1, "candidates": remaining})
            followup_result = cli(
                "incidents",
                "propose-remediation",
                incident_id,
                "--investigation",
                inv["investigation_id"],
                "--ai-config",
                CONFIG + "/investigation.yml",
                "--candidates",
                candidate_path,
                monitored=True,
                check=False,
            )
            try:
                followup_doc = json.loads(followup_result.get("stdout", ""))
            except (json.JSONDecodeError, TypeError):
                raise RuntimeError("Qwen follow-up proposal returned invalid JSON") from None
            followup_proposal = followup_doc.get("proposal", {})
            followup_validation = followup_proposal.get("validation", {})
            followup_accepted = (
                followup_doc.get("status") == "accepted"
                and followup_validation.get("accepted") is True
                and followup_validation.get("abstained") is False
            )
            proposal_record = {
                "status": "PASS" if followup_accepted else "FAIL",
                "decision": followup_doc.get("status"),
                "reason_code": followup_doc.get("reason_code"),
                "proposal": followup_proposal
                if followup_accepted
                else {
                    "proposal_version": followup_proposal.get("proposal_version"),
                    "rejected": True,
                },
                "selected_action_id": followup_proposal.get("candidate_action_id"),
                "target_ref": followup_proposal.get("target_ref"),
                "validated_candidate": followup_validation.get("candidate")
                if followup_accepted
                else None,
                "provider_requests": 1,
                "resource_watch": followup_result.get("resource_watch", {}),
            }
            attempt["steps"].setdefault("proposal_followups", []).append(proposal_record)
            if not followup_accepted:
                raise RuntimeError("Qwen follow-up remediation proposal was rejected or abstained")
            candidate_followup = followup_validation["candidate"]
            if (
                candidate_followup.get("action_id") != followup_proposal.get("candidate_action_id")
                or candidate_followup.get("target_ref") != followup_proposal.get("target_ref")
                or candidate_followup.get("target_name") != scenario["target"]
                or candidate_followup.get("action_id") != remaining[0]["action_id"]
                or candidate_followup.get("target_ref") != remaining[0]["target_ref"]
            ):
                raise RuntimeError(
                    "Qwen follow-up candidate did not preserve observed target binding"
                )
            checkpoint(ledger)
            followup_runbook = RUNBOOKS + "/recovery-followup-" + attempt["run_id"] + ".yml"
            write_guest(
                OPS,
                followup_runbook,
                make_recovery_runbook(
                    attempt["run_id"] + "-followup", scenario["target"], candidate_followup
                ).encode(),
                uid=999,
                gid=988,
                mode=0o600,
            )
            followup_plan = json_out(cli("plan", followup_runbook, "--json"))
            followup_mutating = [
                item
                for item in followup_plan.get("actions", [])
                if item.get("phase") == "steps"
                and item.get("action") == candidate_followup["action_id"]
            ]
            if (
                len(followup_mutating) != 1
                or followup_mutating[0].get("action") != followup_proposal["candidate_action_id"]
                or followup_mutating[0].get("target") != scenario["target"]
                or followup_mutating[0].get("arguments") != candidate_followup["arguments"]
                or followup_plan.get("status") not in {"approval_required", "ready"}
            ):
                raise RuntimeError("RunbookOS denied or altered the Qwen follow-up action")
            followup_plan_id = followup_plan["plan_id"]
            linked_followup = json_out(
                cli("incidents", "associate-plan", incident_id, followup_plan_id)
            )
            if linked_followup.get("plan_id") != followup_plan_id:
                raise RuntimeError("follow-up plan was not linked to its incident")
            approved_followup = cli(
                "approve",
                followup_plan_id,
                "--reason",
                "One-time approval for the exact follow-up action proposed by Qwen on the disposable fixture.",
            )
            if approved_followup.get("exit_code") != 0:
                raise RuntimeError("follow-up action approval failed")
            attempt["steps"].setdefault("authorization_followups", []).append(
                {
                    "status": "PASS",
                    "plan_id": followup_plan_id,
                    "plan_hash": followup_plan.get("plan_hash"),
                    "approval_recorded": True,
                }
            )
            followup_execution = cli("run", followup_plan_id, "--confirm", timeout=180)
            followup_match = re.search(
                r"Execution\s+([0-9a-f-]{36}):\s*(\w+)",
                followup_execution.get("stdout", ""),
            )
            if (
                followup_execution.get("exit_code") != 0
                or not followup_match
                or followup_match.group(2) != "succeeded"
            ):
                raise RuntimeError("RunbookOS follow-up remediation execution failed")
            attempt["steps"].setdefault("remediation_followups", []).append(
                {
                    "status": "PASS",
                    "action_id": followup_proposal["candidate_action_id"],
                    "target_ref": followup_proposal["target_ref"],
                    "target": candidate_followup["target_name"],
                    "arguments": candidate_followup["arguments"],
                    "plan_id": followup_plan_id,
                    "execution_id": followup_match.group(1),
                }
            )
            checkpoint(ledger)
            postflight = independent_postflight(scenario)
            attempt["steps"]["postflight"] = postflight
            attempt["steps"]["compound_postflight_after_first_action"] = {
                "status": "PASS",
                "initially_partial": True,
                "remaining_action_selected_from_observed_state": True,
            }
        if postflight["status"] != "PASS":
            raise RuntimeError("independent target postflight did not confirm complete recovery")
        checkpoint(ledger)
        phase = "closure"
        resolved = cli(
            "incidents",
            "resolve",
            incident_id,
            "--reason",
            "The registered recovery was executed and independent disposable-fixture health checks passed.",
            "--evidence-status",
            "verified",
        )
        if resolved.get("exit_code") != 0:
            raise RuntimeError("incident resolution failed")
        closed = cli(
            "incidents", "close", incident_id, "--reason", "Batch 03 disposable recovery verified."
        )
        if closed.get("exit_code") != 0:
            raise RuntimeError("incident closure failed")
        phase = "audit"
        audit = cli("audit")
        if audit.get("exit_code") != 0 or "AUDIT OK" not in audit.get("stdout", ""):
            raise RuntimeError("SQLite audit-chain verification failed")
        integrity = sqlite_integrity()
        if integrity != "ok":
            raise RuntimeError("SQLite integrity check failed")
        attempt["steps"]["closure"] = {
            "status": "PASS",
            "resolved": True,
            "closed": True,
            "incident_id": incident_id,
        }
        attempt["steps"]["audit"] = {
            "status": "PASS",
            "result": audit["stdout"].strip(),
            "sqlite_integrity": integrity,
        }
        phase = "cleanup"
        cleanup = restore_db_baseline() if scenario["target"] == "db-01" else restore_web_baseline()
        attempt["steps"]["cleanup"] = {**cleanup, "baseline_restored": cleanup["status"] == "PASS"}
        if cleanup["status"] != "PASS":
            raise RuntimeError("campaign fixture cleanup failed to restore the baseline")
        attempt["result"] = "AI_DRIVEN_PASS"
        attempt["completed_at"] = now()
    except Exception as exc:
        attempt["result"] = "FAIL"
        attempt["failure_stage"] = phase
        attempt["failure_category"] = type(exc).__name__
        attempt["safe_failure"] = (
            f"Campaign attempt failed during {phase}; raw exception details omitted."
        )
        if "cleanup" not in attempt["steps"]:
            try:
                cleanup = (
                    restore_db_baseline()
                    if scenario["target"] == "db-01"
                    else restore_web_baseline()
                )
                attempt["steps"]["cleanup"] = {
                    **cleanup,
                    "baseline_restored": cleanup["status"] == "PASS",
                    "performed_after_failed_attempt": True,
                }
            except Exception:
                attempt["steps"]["cleanup"] = {
                    "status": "FAIL",
                    "baseline_restored": False,
                    "performed_after_failed_attempt": True,
                }
        attempt["completed_at"] = now()
    checkpoint(ledger)
    return attempt


def main() -> int:
    import argparse

    parser = argparse.ArgumentParser(description="Execute the live RunbookOS Batch 03 campaign.")
    parser.add_argument("--scenario", action="append", choices=[item["id"] for item in SCENARIOS])
    parser.add_argument("--install-only", action="store_true")
    args = parser.parse_args()
    if (
        hashlib.sha256((REPO / "scripts" / "campaign_batch03_fixture.py").read_bytes()).hexdigest()
        == ""
    ):
        raise SystemExit("fixture fingerprint unavailable")
    ledger = initialize_ledger()
    configure_controller()
    install_web_fixture()
    install_database_fixture()
    if args.install_only:
        ledger["live_execution"]["status"] = "FIXTURES_INSTALLED"
        checkpoint(ledger)
        return 0
    selected = [item for item in SCENARIOS if not args.scenario or item["id"] in args.scenario]
    for scenario in selected:
        prior = [
            item
            for item in ledger["live_execution"]["attempts"]
            if item.get("scenario_id") == scenario["id"]
        ]
        if any(item.get("result") == "AI_DRIVEN_PASS" for item in prior):
            continue
        run_scenario(scenario, ledger, len(prior) + 1)
    validate_ledger({"attempts": ledger["live_execution"]["attempts"]})
    successes = sum(
        item.get("result") == "AI_DRIVEN_PASS" for item in ledger["live_execution"]["attempts"]
    )
    ledger["live_execution"]["completed_workflows"] = successes
    ledger["live_execution"]["ai_driven_passes"] = successes
    ledger["live_execution"]["qwen_requests"] = sum(
        int(item.get("steps", {}).get("investigation", {}).get("provider_requests", 0))
        + int(item.get("steps", {}).get("proposal", {}).get("provider_requests", 0))
        + sum(
            int(followup.get("provider_requests", 0))
            for followup in item.get("steps", {}).get("proposal_followups", [])
        )
        for item in ledger["live_execution"]["attempts"]
    )
    ledger["live_execution"]["status"] = "COMPLETE" if successes == 10 else "PARTIAL"
    ledger["status"] = "LIVE_EXECUTION_COMPLETE" if successes == 10 else "LIVE_EXECUTION_PARTIAL"
    checkpoint(ledger)
    print(
        json.dumps(
            {
                "attempts": len(ledger["live_execution"]["attempts"]),
                "ai_driven_passes": successes,
                "status": ledger["status"],
            },
            sort_keys=True,
        )
    )
    return 0 if successes == 10 else 2


if __name__ == "__main__":
    raise SystemExit(main())
