"""Live B04 runner. Fault injection is limited to unique B04 disposable resources."""

from __future__ import annotations

import datetime as dt
import hashlib
import json
import math
import os
import re
import tempfile
import time
import uuid
from pathlib import Path
from typing import Any

import campaign_batch03_live as b03
import campaign_batch04 as spec
import yaml

from runbookos.actions import REGISTRY

ROOT = Path(__file__).resolve().parents[1]
LOCAL = Path("/home/morphious/.local/state/runbookos/campaign-batch04")
LEDGER = LOCAL / "batch04-ledger.json"
REMOTE = "/var/lib/runbookos/acceptance-v070/campaign-batch04"
CONFIG, RUNBOOKS, STATE = REMOTE + "/config", REMOTE + "/config/runbooks", REMOTE + "/state"
DB, SOURCE = STATE + "/batch04.sqlite3", REMOTE + "/source"
DBCLIENT = "runbookos-campaign-b04-dbclient.service"
WEB, DBVM = b03.WEB, b03.DBVM
FIXTURE = "/var/lib/runbookos-campaign-b04"
APP, PROXY = "runbookos-campaign-b04-app.service", "runbookos-campaign-b04-proxy.service"
BACKEND, WORKER = "runbookos-campaign-b04-backend.service", "runbookos-campaign-b04-worker.service"
DNS, NETNS = "runbookos-campaign-b04-dns.service", "runbookos-b04"
NETUNIT = "runbookos-campaign-b04-netns.service"
UNITS = [APP, PROXY, BACKEND, WORKER, DNS, NETUNIT]
PROBES = {
    "b04-app": {"protocol": "http", "address": "10.60.20.10", "port": 18891, "path": "/health"},
    "b04-proxy": {"protocol": "http", "address": "10.60.20.10", "port": 18892, "path": "/health"},
    "b04-backend": {"protocol": "http", "address": "10.60.20.10", "port": 18911, "path": "/health"},
    "b04-worker": {"protocol": "tcp", "address": "10.60.20.10", "port": 18912},
    "b04-netns": {"protocol": "tcp", "address": "10.254.4.2", "port": 18920},
    "b04-db": {"protocol": "postgresql", "address": "10.60.30.10", "port": 55434},
    "b04-db-tcp": {"protocol": "tcp", "address": "10.60.30.10", "port": 55434},
    "b04-dbclient": {
        "protocol": "http",
        "address": "10.60.30.10",
        "port": 18893,
        "path": "/health",
    },
}
MUTATING = sorted({x["action_id"] for group in spec.ACTION_CANDIDATES.values() for x in group})


def guest(
    vm: str, path: str, args: list[str], timeout: int = 30, check: bool = True
) -> dict[str, Any]:
    return b03.guest_exec(vm, path, args, timeout=timeout, check=check)


def put(vm: str, path: str, value: bytes, mode: int = 0o600) -> None:
    b03.write_guest(vm, path, value, mode=mode)


def cli(
    *args: str, monitored: bool = False, timeout: int = 300, check: bool = True
) -> dict[str, Any]:
    b03.CONFIG, b03.DB, b03.SOURCE = CONFIG, DB, SOURCE
    return b03.cli(*args, monitored=monitored, timeout=timeout, check=check)


def jcli(*args: str, timeout: int = 300) -> dict[str, Any]:
    result = cli(*args, timeout=timeout)
    if result.get("exit_code") != 0:
        raise RuntimeError("RunbookOS CLI command failed")
    return json.loads(result["stdout"])


def safe_provider_request_metadata(result: dict[str, Any]) -> dict[str, Any] | None:
    """Keep only bounded proposal-stage timeout telemetry from CLI output."""
    metadata = result.get("request_metadata")
    if not isinstance(metadata, dict) or set(metadata) != {"failure_stage", "duration_seconds"}:
        return None
    duration = metadata.get("duration_seconds")
    if (
        metadata.get("failure_stage") != "proposal"
        or isinstance(duration, bool)
        or not isinstance(duration, (int, float))
        or not math.isfinite(duration)
        or not 0 <= duration <= 3600
    ):
        return None
    return {"failure_stage": "proposal", "duration_seconds": round(float(duration), 3)}


def persist(ledger: dict[str, Any]) -> None:
    LOCAL.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd, temp_name = tempfile.mkstemp(prefix=".batch04-", dir=LOCAL)
    os.fchmod(fd, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as stream:
        json.dump(ledger, stream, sort_keys=True, indent=2)
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temp_name, LEDGER)
    dirfd = os.open(LOCAL, os.O_DIRECTORY)
    try:
        os.fsync(dirfd)
    finally:
        os.close(dirfd)
    payload = LEDGER.read_bytes()
    remote_temp = REMOTE + "/.batch04-ledger-" + uuid.uuid4().hex + ".tmp"
    b03.write_guest(b03.OPS, remote_temp, payload, uid=999, gid=988, mode=0o600)
    digest = hashlib.sha256(payload).hexdigest()
    remote = guest(b03.OPS, "/usr/bin/sha256sum", [remote_temp])["stdout"].split()[0]
    if remote != digest:
        raise RuntimeError("ledger synchronization digest mismatch")
    guest(
        b03.OPS,
        "/usr/bin/python3",
        [
            "-c",
            "import os,sys;os.replace(sys.argv[1],sys.argv[2]);fd=os.open(sys.argv[3],os.O_DIRECTORY);os.fsync(fd);os.close(fd)",
            remote_temp,
            REMOTE + "/batch04-ledger.json",
            REMOTE,
        ],
    )
    proof = json.dumps({"status": "PASS", "sha256": digest}, sort_keys=True).encode() + b"\n"
    local_proof = LOCAL / "controller-sync.json"
    local_proof.write_bytes(proof)
    local_proof.chmod(0o600)
    b03.write_guest(
        b03.OPS, REMOTE + "/batch04-ledger-sync.json", proof, uid=999, gid=988, mode=0o600
    )


def configure_controller() -> None:
    inv = yaml.safe_load(
        b03.remote_read(
            b03.OPS, "/var/lib/runbookos/acceptance-v070/campaign-batch02/config/inventory.yml"
        )
    )
    policy = yaml.safe_load(
        b03.remote_read(
            b03.OPS, "/var/lib/runbookos/acceptance-v070/campaign-batch02/config/policy.yml"
        )
    )
    inv["hosts"]["svc-web-01"].setdefault("probe_targets", {}).update(
        {k: v for k, v in PROBES.items() if not k.startswith("b04-db")}
    )
    inv["hosts"]["db-01"].setdefault("probe_targets", {}).update(
        {k: v for k, v in PROBES.items() if k.startswith("b04-db")}
    )
    web, db = policy["hosts"]["svc-web-01"], policy["hosts"]["db-01"]
    diagnostic = {
        "systemd.failed_units",
        "systemd.is_active",
        "systemd.journal_tail",
        "http.readiness",
        "network.tcp_connect",
        "network.routes",
        "os.disk",
        "os.memory",
        "resource.inspect_fixture",
        "application.inspect_fixture",
        "dns.resolve_fixture",
    }
    web["diagnostic_actions"] = sorted(set(web.get("diagnostic_actions", [])) | diagnostic)
    web["remediation_actions"] = sorted(set(web.get("remediation_actions", [])) | set(MUTATING))
    web["allowed_units"] = sorted(set(web.get("allowed_units", [])) | set(UNITS))
    web["allowed_probe_targets"] = sorted(
        set(web.get("allowed_probe_targets", []))
        | {k for k in PROBES if not k.startswith("b04-db")}
    )
    db["diagnostic_actions"] = sorted(
        set(db.get("diagnostic_actions", []))
        | {
            "systemd.is_active",
            "postgresql.protocol_available",
            "network.tcp_connect",
            "http.readiness",
        }
    )
    db["remediation_actions"] = sorted(
        set(db.get("remediation_actions", []))
        | {"postgresql.start_fixture", "systemd.start", "systemd.restart"}
    )
    db["allowed_units"] = sorted(
        set(db.get("allowed_units", [])) | {"postgresql@16-b04.service", DBCLIENT}
    )
    db["allowed_probe_targets"] = sorted(
        set(db.get("allowed_probe_targets", [])) | {"b04-db", "b04-db-tcp", "b04-dbclient"}
    )
    guest(
        b03.OPS,
        "/usr/bin/install",
        ["-d", "-o", "runbookos", "-g", "runbookos", "-m", "700", CONFIG, RUNBOOKS, STATE],
    )
    b03.write_yaml(b03.OPS, CONFIG + "/inventory.yml", inv)
    b03.write_yaml(b03.OPS, CONFIG + "/policy.yml", policy)
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
            "schema_constrained_proposals": True,
            "schema_constrained_replies": True,
        },
        "limits": {
            "max_diagnostic_runbooks": 2,
            "max_tool_calls": 6,
            "execution_budget_seconds": 90,
            "max_incident_chars": 4000,
        },
        "catalog": [
            {
                "id": "b04-" + name,
                "runbook": "runbooks/b04-" + name + ".yml",
                "description": description,
            }
            for name, description in (
                (
                    "core",
                    "Base application unit, configuration validity and HTTP health details. Always select this core diagnostic plus one targeted diagnostic below for a web fixture investigation.",
                ),
                ("dependency", "Backend HTTP, worker TCP and DNS observations."),
                (
                    "resource",
                    "Targeted isolated network TCP, disk capacity and worker CPU quota. Choose with core for network, storage or quota symptoms; an inactive worker alone is a dependency symptom.",
                ),
                ("db", "Disposable PostgreSQL unit, protocol and dependent HTTP readiness."),
            )
        ],
    }
    b03.write_yaml(b03.OPS, CONFIG + "/investigation.yml", catalog)

    def doc(rid: str, name: str, target: str, items: list[dict[str, Any]]) -> dict[str, Any]:
        return {
            "api_version": "runbookos/v1",
            "kind": "Runbook",
            "metadata": {
                "id": rid,
                "name": name,
                "description": "Read-only B04 observations.",
                "risk": "low",
            },
            "targets": [target],
            "steps": items,
        }

    groups = {
        "core": [
            ("systemd.is_active", {"unit": APP}),
            ("http.readiness", {"endpoint_id": "b04-app"}),
            ("application.inspect_fixture", {"fixture_id": "web_stack"}),
        ],
        "dependency": [
            ("http.readiness", {"endpoint_id": "b04-backend"}),
            ("network.tcp_connect", {"endpoint_id": "b04-worker"}),
            ("dns.resolve_fixture", {"fixture_id": "b04_resolver"}),
        ],
        "resource": [
            ("network.tcp_connect", {"endpoint_id": "b04-netns"}),
            ("os.disk", {"path": FIXTURE + "/volume"}),
            ("resource.inspect_fixture", {"fixture_id": "worker_quota"}),
        ],
    }
    for name, actions in groups.items():
        steps = [
            {
                "id": "observation-" + str(i),
                "action": action,
                "timeout_seconds": 4 if action == "application.inspect_fixture" else 1,
                "with": arguments,
            }
            for i, (action, arguments) in enumerate(actions)
        ]
        b03.write_yaml(
            b03.OPS,
            RUNBOOKS + "/b04-" + name + ".yml",
            doc("b04-" + name, "B04 " + name, "svc-web-01", steps),
        )
    dbsteps = [
        {
            "id": "dbclient-unit",
            "action": "systemd.is_active",
            "timeout_seconds": 1,
            "with": {"unit": DBCLIENT},
        },
        {
            "id": "pg-unit",
            "action": "systemd.is_active",
            "timeout_seconds": 1,
            "with": {"unit": "postgresql@16-b04.service"},
        },
        {
            "id": "pg-protocol",
            "action": "postgresql.protocol_available",
            "timeout_seconds": 1,
            "with": {"endpoint_id": "b04-db"},
        },
        {
            "id": "db-dependent-client",
            "action": "http.readiness",
            "timeout_seconds": 1,
            "with": {"endpoint_id": "b04-dbclient"},
        },
    ]
    b03.write_yaml(
        b03.OPS,
        RUNBOOKS + "/b04-db.yml",
        doc("b04-db-diagnostics", "B04 PG diagnostics", "db-01", dbsteps),
    )


def install_source() -> None:
    # Copy only Python package source to the isolated controller path.
    import io
    import tarfile

    blob = io.BytesIO()
    with tarfile.open(fileobj=blob, mode="w:gz") as tar:
        for path in sorted((ROOT / "src/runbookos").rglob("*.py")):
            tar.add(path, arcname=path.relative_to(ROOT / "src"))
    guest(b03.OPS, "/usr/bin/install", ["-d", "-o", "root", "-g", "runbookos", "-m", "755", SOURCE])
    b03.write_guest(b03.OPS, REMOTE + "/source.tar.gz", blob.getvalue(), mode=0o644)
    guest(b03.OPS, "/usr/bin/tar", ["-xzf", REMOTE + "/source.tar.gz", "-C", SOURCE])


def install_fixtures() -> None:
    # Only unique B04 identities and paths are created; existing campaign units are not touched.
    guest(
        WEB,
        "/usr/bin/install",
        [
            "-d",
            "-o",
            "root",
            "-g",
            "root",
            "-m",
            "755",
            FIXTURE,
            FIXTURE + "/config",
            FIXTURE + "/state",
            FIXTURE + "/volume",
        ],
    )
    put(
        WEB,
        FIXTURE + "/fixture.py",
        (ROOT / "scripts/campaign_batch04_fixture.py").read_bytes(),
        0o755,
    )
    helper = (ROOT / "scripts/campaign_batch04_recover.py").read_bytes()
    put(WEB, "/usr/local/sbin/runbookos-campaign-b04-recover", helper, 0o755)
    configs = {
        "app": {"backend_host": "backend.b04.test", "backend_port": 18911},
        "proxy": {"upstream_host": "10.60.20.10", "upstream_port": 18891},
        "dns": {"backend_address": "10.60.20.10"},
    }
    for name, value in configs.items():
        data = (json.dumps(value, sort_keys=True) + "\n").encode()
        put(WEB, FIXTURE + f"/config/{name}.good.json", data, 0o644)
        put(WEB, FIXTURE + f"/config/{name}.json", data, 0o644)
    guest(WEB, "/bin/chown", ["root:root", FIXTURE + "/config"])
    for d in ("state", "volume"):
        guest(WEB, "/bin/chown", ["nobody:nogroup", FIXTURE + "/" + d])
    ns = guest(WEB, "/usr/sbin/ip", ["netns", "list"], check=False)
    if NETNS not in ns.get("stdout", ""):
        for argv in (
            ["netns", "add", NETNS],
            ["link", "add", "b04-host0", "type", "veth", "peer", "name", "b04-ns0"],
            ["link", "set", "b04-ns0", "netns", NETNS],
            ["addr", "add", "10.254.4.1/30", "dev", "b04-host0"],
            ["link", "set", "b04-host0", "up"],
        ):
            guest(WEB, "/usr/sbin/ip", list(argv))
        for argv in (
            ["addr", "add", "10.254.4.2/30", "dev", "b04-ns0"],
            ["link", "set", "b04-ns0", "up"],
            ["route", "replace", "10.254.4.0/30", "dev", "b04-ns0"],
        ):
            guest(WEB, "/usr/sbin/ip", ["netns", "exec", NETNS, "/usr/sbin/ip", *argv])
    mounted = guest(WEB, "/usr/bin/mountpoint", ["-q", FIXTURE + "/volume"], check=False)
    if mounted.get("exit_code") != 0:
        guest(
            WEB,
            "/bin/mount",
            [
                "-t",
                "tmpfs",
                "-o",
                "size=16m,nodev,nosuid,noexec",
                "runbookos-b04",
                FIXTURE + "/volume",
            ],
        )
        guest(WEB, "/bin/chown", ["nobody:nogroup", FIXTURE + "/volume"])
    else:
        guest(WEB, "/bin/chown", ["nobody:nogroup", FIXTURE + "/volume"])
    unit_defs = {APP: "app", PROXY: "proxy", BACKEND: "backend", WORKER: "worker", DNS: "dns"}
    for unit, role in unit_defs.items():
        extra = "CPUQuota=30%\n" if role == "worker" else ""
        text = (
            "[Unit]\nDescription=RunbookOS disposable Batch 04 "
            + role
            + "\nAfter=network-online.target\n[Service]\nType=simple\nUser=nobody\nGroup=nogroup\nExecStart=/usr/bin/python3 "
            + FIXTURE
            + "/fixture.py "
            + role
            + "\nRestart=no\nTimeoutStartSec=8\nNoNewPrivileges=yes\nPrivateTmp=yes\nProtectSystem=strict\nProtectHome=yes\nRestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX\n"
            + extra
            + "[Install]\nWantedBy=multi-user.target\n"
        ).encode()
        put(WEB, "/etc/systemd/system/" + unit, text, 0o644)
    nettext = (
        "[Unit]\nDescription=RunbookOS disposable Batch 04 namespace endpoint\nAfter=network-online.target\n[Service]\nType=simple\nUser=nobody\nGroup=nogroup\nNetworkNamespacePath=/run/netns/"
        + NETNS
        + "\nExecStart=/usr/bin/python3 "
        + FIXTURE
        + "/fixture.py netns\nRestart=no\nNoNewPrivileges=yes\nProtectSystem=strict\n[Install]\nWantedBy=multi-user.target\n"
    ).encode()
    put(WEB, "/etc/systemd/system/" + NETUNIT, nettext, 0o644)
    helper_sudo = (
        "runbookos ALL=(root) NOPASSWD: /usr/local/sbin/runbookos-campaign-b04-recover *\nrunbookos ALL=(root) NOPASSWD: /usr/bin/systemctl start "
        + APP
        + ", /usr/bin/systemctl start "
        + BACKEND
        + ", /usr/bin/systemctl restart "
        + APP
        + ", /usr/bin/systemctl start "
        + DNS
        + ", /usr/bin/systemctl restart "
        + DNS
        + ", /usr/bin/systemctl restart "
        + WORKER
        + ", /usr/bin/systemctl start "
        + PROXY
        + ", /usr/bin/systemctl restart "
        + PROXY
        + "\n"
    ).encode()
    put(WEB, "/etc/sudoers.d/runbookos-campaign-b04", helper_sudo, 0o440)
    guest(WEB, "/usr/sbin/visudo", ["-cf", "/etc/sudoers.d/runbookos-campaign-b04"])
    guest(WEB, "/bin/systemctl", ["daemon-reload"])
    for unit in UNITS:
        guest(WEB, "/bin/systemctl", ["enable", "--now", unit], timeout=30)
    for unit in UNITS:
        guest(WEB, "/bin/systemctl", ["restart", unit], timeout=30)
    # Create or start only the isolated cluster named 16/b04.
    clusters = guest(DBVM, "/usr/bin/pg_lsclusters", ["--no-header"])["stdout"]
    if not any(
        len(line.split()) >= 2 and line.split()[:2] == ["16", "b04"]
        for line in clusters.splitlines()
    ):
        guest(DBVM, "/usr/bin/pg_createcluster", ["16", "b04", "--port", "55434"], timeout=90)
    guest(
        DBVM,
        "/usr/bin/pg_conftool",
        ["16", "b04", "set", "listen_addresses", "10.60.30.10,localhost"],
    )
    guest(DBVM, "/bin/systemctl", ["restart", "postgresql@16-b04.service"], timeout=60)
    put(DBVM, "/usr/local/sbin/runbookos-campaign-b04-recover", helper, 0o755)
    put(
        DBVM,
        FIXTURE + "/fixture.py",
        (ROOT / "scripts/campaign_batch04_fixture.py").read_bytes(),
        0o755,
    )
    dbunit = (
        "[Unit]\nDescription=RunbookOS disposable Batch 04 database dependent probe\nAfter=postgresql@16-b04.service\n"
        "[Service]\nType=simple\nUser=nobody\nGroup=nogroup\nExecStart=/usr/bin/python3 "
        + FIXTURE
        + "/fixture.py dbclient\nRestart=no\nTimeoutStartSec=8\nNoNewPrivileges=yes\nProtectSystem=strict\nProtectHome=yes\n"
        "[Install]\nWantedBy=multi-user.target\n"
    ).encode()
    put(DBVM, "/etc/systemd/system/runbookos-campaign-b04-dbclient.service", dbunit, 0o644)
    guest(DBVM, "/bin/systemctl", ["daemon-reload"])
    guest(DBVM, "/bin/systemctl", ["enable", "--now", "runbookos-campaign-b04-dbclient.service"])
    guest(DBVM, "/bin/systemctl", ["restart", "runbookos-campaign-b04-dbclient.service"])
    dbsudo = (
        "runbookos ALL=(root) NOPASSWD: /usr/local/sbin/runbookos-campaign-b04-recover *\nrunbookos ALL=(root) NOPASSWD: /usr/bin/systemctl start postgresql@16-b04.service, /usr/bin/systemctl restart postgresql@16-b04.service, /usr/bin/systemctl start runbookos-campaign-b04-dbclient.service\n"
    ).encode()
    put(DBVM, "/etc/sudoers.d/runbookos-campaign-b04", dbsudo, 0o440)
    guest(DBVM, "/usr/sbin/visudo", ["-cf", "/etc/sudoers.d/runbookos-campaign-b04"])
    marker = b"runbookos-campaign-b04-v1\n"
    put(WEB, FIXTURE + "/OWNER", marker, 0o600)
    guest(DBVM, "/usr/bin/install", ["-d", "-o", "root", "-g", "root", "-m", "755", FIXTURE])
    put(DBVM, FIXTURE + "/OWNER", marker, 0o600)
    put(b03.OPS, REMOTE + "/OWNER", marker, 0o600)


def setup() -> None:
    install_source()
    configure_controller()
    install_fixtures()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def preflight_resources() -> None:
    # Never replace a pre-existing B04 identity that this runner cannot prove it owns.
    marker = b"runbookos-campaign-b04-v1"
    marker_paths = (
        (b03.OPS, REMOTE + "/OWNER"),
        (WEB, FIXTURE + "/OWNER"),
        (DBVM, FIXTURE + "/OWNER"),
    )
    ownership_verified = True
    for vm, path in marker_paths:
        result = guest(vm, "/usr/bin/cat", [path], check=False)
        if result.get("exit_code") != 0 or result.get("stdout", "").strip().encode() != marker:
            ownership_verified = False
            break
    if ownership_verified:
        return
    for vm, path in (
        (b03.OPS, REMOTE),
        (WEB, FIXTURE),
        (WEB, "/etc/systemd/system/" + APP),
        (WEB, "/etc/systemd/system/" + PROXY),
        (WEB, "/etc/systemd/system/" + BACKEND),
        (WEB, "/etc/systemd/system/" + WORKER),
        (WEB, "/etc/systemd/system/" + DNS),
        (WEB, "/etc/systemd/system/" + NETUNIT),
        (WEB, "/usr/local/sbin/runbookos-campaign-b04-recover"),
        (WEB, "/etc/sudoers.d/runbookos-campaign-b04"),
        (DBVM, "/etc/sudoers.d/runbookos-campaign-b04"),
        (DBVM, "/usr/local/sbin/runbookos-campaign-b04-recover"),
        (DBVM, "/etc/systemd/system/runbookos-campaign-b04-dbclient.service"),
    ):
        result = guest(vm, "/usr/bin/test", ["-e", path], check=False)
        if result.get("exit_code") == 0:
            raise RuntimeError("B04 resource identity already exists; refusing to overwrite it")
    namespaces = guest(WEB, "/usr/sbin/ip", ["netns", "list"], check=False)
    if NETNS in namespaces.get("stdout", ""):
        raise RuntimeError("B04 network namespace already exists; ownership is unverified")
    clusters = guest(DBVM, "/usr/bin/pg_lsclusters", ["--no-header"])["stdout"]
    if any(
        len(line.split()) >= 2 and line.split()[:2] == ["16", "b04"]
        for line in clusters.splitlines()
    ):
        raise RuntimeError("B04 PostgreSQL cluster already exists; ownership is unverified")
    listeners = guest(WEB, "/usr/bin/ss", ["-H", "-lntu"])["stdout"]
    occupied = {18891, 18892, 18911, 18912, 18920, 18954}
    if any(
        re.search(rf":{port}(?:\s|$)", line) for port in occupied for line in listeners.splitlines()
    ):
        raise RuntimeError("a B04 fixture port is already listening; refusing to interfere")
    db_listeners = guest(DBVM, "/usr/bin/ss", ["-H", "-lntu"])["stdout"]
    if any(
        re.search(rf":{port}(?:\s|$)", line)
        for port in (55434, 18893)
        for line in db_listeners.splitlines()
    ):
        raise RuntimeError(
            "a B04 database fixture port is already listening; refusing to interfere"
        )


def observe(target: str) -> dict[str, Any]:
    if target == "db-01":
        code = "import json,socket,subprocess; c=subprocess.run(['/usr/bin/pg_lsclusters','--no-header'],capture_output=True,text=True).stdout;s=socket.socket();s.settimeout(.5);r=s.connect_ex(('10.60.30.10',55434));s.close();print(json.dumps({'clusters':c,'tcp':r==0,'unit':subprocess.run(['/bin/systemctl','is-active','postgresql@16-b04.service'],capture_output=True,text=True).stdout.strip()}))"
        state = json.loads(guest(DBVM, "/usr/bin/python3", ["-c", code])["stdout"])
        client = guest(
            DBVM,
            "/usr/bin/python3",
            [
                "-c",
                "import json,urllib.request,urllib.error;\ntry:r=urllib.request.urlopen('http://10.60.30.10:18893/health',timeout=1);d={'status':r.status,'body':r.read(80).decode(errors='replace').strip()}\nexcept Exception as e:d={'status':0,'body':type(e).__name__}\nprint(json.dumps(d))",
            ],
            check=False,
        )
        try:
            state["dbclient"] = json.loads(client["stdout"])
        except json.JSONDecodeError:
            state["dbclient"] = {"status": 0, "body": "probe_failed"}
        return state
    code = (
        "import json,urllib.request,urllib.error,socket,subprocess,os; units="
        + repr(UNITS)
        + "; states={u:subprocess.run(['/bin/systemctl','is-active',u],capture_output=True,text=True).stdout.strip() for u in units}; http={}\nfor n,p in [('app',18891),('proxy',18892),('backend',18911)]:\n try:r=urllib.request.urlopen('http://10.60.20.10:'+str(p)+'/health',timeout=1);http[n]=[r.status,r.read(80).decode(errors='replace').strip()]\n except urllib.error.HTTPError as e:http[n]=[e.code,e.read(80).decode(errors='replace').strip()]\n except Exception as e:http[n]=[0,type(e).__name__]\ns=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.settimeout(.3);q=b'\\x12\\x34\\x01\\x00\\x00\\x01\\x00\\x00\\x00\\x00\\x00\\x00\\x07backend\\x03b04\\x04test\\x00\\x00\\x01\\x00\\x01'\ntry:s.sendto(q,('10.60.20.10',18954));a=s.recv(512);dns=socket.inet_ntoa(a[-4:]) if len(a)>16 and int.from_bytes(a[6:8],'big') else None\nexcept OSError:dns=None\ntcp={}\nfor n,h,p in [('worker','10.60.20.10',18912),('netns','10.254.4.2',18920)]:\n c=socket.socket();c.settimeout(.5);tcp[n]=c.connect_ex((h,p))==0;c.close()\nv=os.statvfs('"
        + FIXTURE
        + "/volume');free=v.f_bavail*v.f_frsize\nprint(json.dumps({'states':states,'http':http,'dns':dns,'tcp':tcp,'volume_free_bytes':free},sort_keys=True))"
    )
    return json.loads(guest(WEB, "/usr/bin/python3", ["-c", code], timeout=12)["stdout"])


def healthy(target: str) -> bool:
    state = observe(target)
    if target == "db-01":
        return (
            "16 b04" in state["clusters"]
            and "online" in state["clusters"]
            and state["tcp"]
            and state.get("dbclient", {}).get("status") == 200
        )
    return (
        all(v == "active" for v in state["states"].values())
        and all(v[0] == 200 for v in state["http"].values())
        and state["dns"] == "10.60.20.10"
        and all(state.get("tcp", {}).values())
        and state.get("volume_free_bytes", 0) > 4096
    )


def wait_healthy(target: str, seconds: float = 8) -> bool:
    deadline = time.monotonic() + seconds
    while True:
        if healthy(target):
            return True
        if time.monotonic() >= deadline:
            return False
        time.sleep(0.2)


def reset(scenario: dict[str, Any]) -> bool:
    target = scenario["target"]
    if target == "db-01":
        guest(DBVM, "/bin/systemctl", ["reset-failed", "postgresql@16-b04.service"], check=False)
        guest(
            DBVM, "/bin/systemctl", ["start", "postgresql@16-b04.service"], timeout=60, check=False
        )
        guest(DBVM, "/bin/systemctl", ["start", DBCLIENT], timeout=30, check=False)
        return wait_healthy(target)
    for n in ("app", "proxy", "dns"):
        guest(
            WEB,
            "/usr/bin/cp",
            [FIXTURE + f"/config/{n}.good.json", FIXTURE + f"/config/{n}.json"],
            check=False,
        )
    guest(
        WEB,
        "/bin/rm",
        ["-f", "/etc/systemd/system/" + WORKER + ".d/10-b04-pressure.conf"],
        check=False,
    )
    guest(WEB, "/bin/systemctl", ["daemon-reload"], check=False)
    for unit in UNITS:
        guest(WEB, "/bin/systemctl", ["reset-failed", unit], check=False)
        guest(WEB, "/bin/systemctl", ["start", unit], timeout=30, check=False)
    guest(
        WEB,
        "/bin/rm",
        ["-f", FIXTURE + "/state/dns-invalid", FIXTURE + "/state/worker-pressure"],
        check=False,
    )
    guest(
        WEB,
        "/usr/sbin/ip",
        ["netns", "exec", NETNS, "/usr/sbin/ip", "link", "set", "b04-ns0", "up"],
        check=False,
    )
    guest(
        WEB,
        "/usr/sbin/ip",
        [
            "route",
            "replace",
            "10.254.4.0/30",
            "dev",
            "b04-host0",
        ],
        check=False,
    )
    for path in (FIXTURE + "/volume/pressure-01",):
        guest(WEB, "/bin/rm", ["-f", path], check=False)
    return wait_healthy(target)


def inject(s: dict[str, Any]) -> dict[str, Any]:
    for fault in s["faults"]:
        if fault == "app_stopped":
            guest(WEB, "/bin/systemctl", ["stop", APP])
        elif fault == "dbclient_stopped":
            guest(DBVM, "/bin/systemctl", ["stop", DBCLIENT])
        elif fault == "worker_stopped":
            guest(WEB, "/bin/systemctl", ["stop", WORKER])
        elif fault == "backend_stopped":
            guest(WEB, "/bin/systemctl", ["stop", BACKEND])
        elif fault == "postgres_stopped":
            guest(DBVM, "/bin/systemctl", ["stop", "postgresql@16-b04.service"], timeout=45)
        elif fault == "invalid_app_config":
            put(
                WEB,
                FIXTURE + "/config/app.json",
                b'{"backend_host":"wrong","backend_port":18911}\n',
                0o644,
            )
        elif fault == "proxy_config_invalid":
            put(
                WEB,
                FIXTURE + "/config/proxy.json",
                b'{"upstream_host":"127.0.0.1","upstream_port":1}\n',
                0o644,
            )
        elif fault == "dns_wrong_answer":
            put(WEB, FIXTURE + "/config/dns.json", b'{"backend_address":"10.60.20.99"}\n', 0o644)
            guest(WEB, "/bin/systemctl", ["restart", DNS])
        elif fault == "namespace_route_invalid":
            guest(WEB, "/usr/sbin/ip", ["route", "replace", "blackhole", "10.254.4.0/30"])
        elif fault == "namespace_link_down":
            guest(
                WEB,
                "/usr/sbin/ip",
                ["netns", "exec", NETNS, "/usr/sbin/ip", "link", "set", "b04-ns0", "down"],
            )
        elif fault == "storage_full":
            guest(
                WEB,
                "/usr/bin/python3",
                [
                    "-c",
                    "import os,sys;f=open(sys.argv[1],'wb');\ntry:f.write(b'X'*(16*1024*1024))\nexcept OSError:pass\nf.flush();os.fsync(f.fileno());f.close()",
                    FIXTURE + "/volume/pressure-01",
                ],
                timeout=12,
                check=False,
            )
        elif fault == "worker_quota_restricted":
            put(WEB, FIXTURE + "/state/worker-pressure", b"1\n", 0o644)
            put(
                WEB,
                "/etc/systemd/system/" + WORKER + ".d/10-b04-pressure.conf",
                b"[Service]\nCPUQuota=1%\n",
                0o644,
            )
            guest(WEB, "/bin/systemctl", ["daemon-reload"])
            guest(WEB, "/bin/systemctl", ["restart", WORKER])
        else:
            raise ValueError("unknown campaign fault")
    state = observe(s["target"])
    return {"confirmed": not healthy(s["target"]), "observed": state}


def recovery_doc(runid: str, target: str, candidate: dict[str, Any]) -> bytes:
    doc = {
        "api_version": "runbookos/v1",
        "kind": "Runbook",
        "metadata": {
            "id": "b04-recovery-" + re.sub(r"[^a-z0-9-]", "-", runid.lower()),
            "name": "AI-proposed B04 fixture recovery",
            "description": "Single registered recovery action bound to disposable fixture.",
            "risk": REGISTRY[candidate["action_id"]].risk,
        },
        "targets": [target],
        "steps": [
            {
                "id": "selected-recovery",
                "action": candidate["action_id"],
                "timeout_seconds": min(30, REGISTRY[candidate["action_id"]].max_timeout_seconds),
                "with": candidate["arguments"],
            }
        ],
    }
    endpoint = "b04-dbclient" if target == "db-01" else "b04-app"
    if candidate["target_ref"] == "b04-proxy-config":
        endpoint = "b04-proxy"
    doc["preflight"] = [
        {
            "id": "failure-confirmed",
            "action": "http.readiness",
            "timeout_seconds": 3,
            "with": {"endpoint_id": endpoint},
            "verify": [{"path": "data.ready", "operator": "eq", "value": False}],
        }
    ]
    post_action, post_args, path, operator, value = (
        "systemd.is_active",
        {"unit": APP},
        "data.active",
        "is_true",
        None,
    )
    ref = candidate["target_ref"]
    if ref == "b04-proxy-config":
        post_args = {"unit": PROXY}
    elif ref == "b04-backend":
        post_action, post_args, path = (
            "http.readiness",
            {"endpoint_id": "b04-backend"},
            "data.ready",
        )
    elif ref in {"b04-worker", "b04-worker-quota", "b04-network"}:
        post_action, post_args, path = (
            "network.tcp_connect",
            {"endpoint_id": "b04-netns" if ref == "b04-network" else "b04-worker"},
            "data.connected",
        )
    elif ref == "b04-dns":
        post_action, post_args, path, operator, value = (
            "dns.resolve_fixture",
            {"fixture_id": "b04_resolver"},
            "data.address",
            "eq",
            "10.60.20.10",
        )
    elif ref == "b04-volume":
        post_action, post_args, path, operator, value = (
            "os.disk",
            {"path": FIXTURE + "/volume"},
            "data.free_bytes",
            "gte",
            1048576,
        )
    elif ref == "b04-dbclient-unit":
        post_action, post_args, path = "systemd.is_active", {"unit": DBCLIENT}, "data.active"
    elif target == "db-01":
        post_action, post_args, path = (
            "postgresql.protocol_available",
            {"endpoint_id": "b04-db"},
            "data.protocol_available",
        )
    assertion = {"path": path, "operator": operator}
    if value is not None:
        assertion["value"] = value
    doc["postflight"] = [
        {
            "id": "selected-component-restored",
            "action": post_action,
            "timeout_seconds": 3,
            "with": post_args,
            "verify": [assertion],
        }
    ]
    return yaml.safe_dump(doc, sort_keys=False).encode()


class CampaignSafetyAbort(RuntimeError):
    pass


def assert_provider_identity() -> None:
    from campaign_batch04_runtime import IDENTITY, RUNTIME, start_ticks

    try:
        identity = json.loads(IDENTITY.read_text())
        pid = identity["pid"]
        if (
            Path(os.readlink(f"/proc/{pid}/exe")).resolve() != RUNTIME.resolve()
            or start_ticks(pid) != identity["start_ticks"]
        ):
            raise ValueError("identity mismatch")
    except (OSError, ValueError, KeyError, TypeError):
        raise CampaignSafetyAbort("provider_process_identity_unavailable") from None


def enforce_transport_guard(outcome: dict[str, Any]) -> None:
    watch = outcome.get("resource_watch", {})
    if watch.get("status") == "failed" or outcome.get("transport_failure_component", "").startswith(
        "resource_watch"
    ):
        raise CampaignSafetyAbort("provider_resource_or_identity_guard_failed")


def run_scenario(s: dict[str, Any], ledger: dict[str, Any]) -> dict[str, Any]:
    old = [x for x in ledger["attempts"] if x["scenario_id"] == s["id"]]
    row = {
        "run_id": "b04-" + s["id"].lower() + "-" + uuid.uuid4().hex[:10],
        "scenario_id": s["id"],
        "group": s["group"],
        "retry_of": old[-1]["run_id"] if old else None,
        "target": s["target"],
        "fixture": "runbookos-campaign-b04",
        "faults": s["faults"],
        "ground_truth": {"category": s["oracle"], "expected_actions": s["expected_actions"]},
        "started_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "steps": {},
        "result": "IN_PROGRESS",
    }
    ledger["attempts"].append(row)
    persist(ledger)
    phase = "baseline"
    try:
        assert_provider_identity()
        if not reset(s):
            raise RuntimeError("baseline_unhealthy")
        row["steps"]["baseline"] = {"status": "PASS", "observation": observe(s["target"])}
        phase = "fault"
        fault = inject(s)
        row["steps"]["fault"] = {"status": "PASS" if fault["confirmed"] else "FAIL", **fault}
        persist(ledger)
        if not fault["confirmed"]:
            raise RuntimeError("fault_not_confirmed")
        phase = "incident_ingestion"
        alert = {
            "alert_id": row["run_id"],
            "source": "runbookos-batch04",
            "event_timestamp": dt.datetime.now(dt.timezone.utc).isoformat(),
            "severity": "error",
            "target_alias": s["target"],
            "service": "b04-disposable-fixture",
            "category": "unknown",
            "summary": "Observed B04 health checks: "
            + json.dumps(fault["observed"], sort_keys=True)[:3500],
            "fingerprint": row["run_id"],
            "metadata": {"campaign": "batch04"},
        }
        ap = STATE + "/alerts/" + row["run_id"] + ".json"
        b03.write_guest(
            b03.OPS, ap, json.dumps(alert).encode() + b"\n", uid=999, gid=988, mode=0o600
        )
        iid = jcli("alerts", "ingest", ap)["incident_id"]
        row["incident_id"] = iid
        row["steps"]["incident"] = {"status": "PASS", "incident_id": iid}
        cli("incidents", "acknowledge", iid, "--reason", "Disposable B04 incident acknowledged.")
        row["recovery_rounds"] = []
        maximum_rounds = 3 if s["group"] == "B" else 1
        for round_index in range(maximum_rounds):
            phase = "investigation"
            out = cli(
                "incidents",
                "investigate",
                iid,
                "--ai-config",
                CONFIG + "/investigation.yml",
                monitored=True,
                check=False,
                timeout=300,
            )
            row["steps"]["provider_guard"] = {
                "resource_watch": {
                    k: v for k, v in out.get("resource_watch", {}).items() if k != "samples"
                },
                "transport_failure_component": out.get("transport_failure_component"),
                "transport_failure_category": out.get("transport_failure_category"),
            }
            enforce_transport_guard(out)
            stderr = out.get("stderr", "")
            safe_failure = next(
                (
                    code
                    for fragment, code in (
                        ("max_tool_calls", "diagnostic_action_budget_exceeded"),
                        ("execution budget", "diagnostic_time_budget_exceeded"),
                        ("ModuleNotFoundError", "controller_source_import_error"),
                        ("AI provider request timed out", "provider_timeout"),
                    )
                    if fragment.lower() in stderr.lower()
                ),
                "investigation_cli_rejected_or_failed",
            )
            row["steps"]["investigation_transport"] = {
                "exit_code": out.get("exit_code"),
                "stdout_characters": len(out.get("stdout", "")),
                "stderr_characters": len(stderr),
                "stderr_sha256": hashlib.sha256(stderr.encode()).hexdigest(),
                "failure_category": safe_failure if out.get("exit_code") != 0 else None,
                "resource_watch": {
                    k: v for k, v in out.get("resource_watch", {}).items() if k != "samples"
                },
            }
            if out.get("exit_code") != 0:
                row["steps"]["persisted_failure"] = b03.persisted_investigation_failure(iid)
                raise RuntimeError(safe_failure)
            inv = json.loads(out["stdout"])
            row["assessment_provider_requests"] = row.get(
                "assessment_provider_requests", 0
            ) + inv.get("model_calls", 2)
            inv_id = inv["investigation_id"]
            row["investigation_id"] = inv_id
            assessment = inv.get("assessment") or {}
            evidence = inv.get("evidence", [])
            row["steps"]["diagnostics"] = {
                "status": "PASS" if evidence else "FAIL",
                "execution_ids": sorted(
                    {e.get("execution_id") for e in evidence if e.get("execution_id")}
                ),
                "evidence_refs": [e.get("ref") for e in evidence],
                "count": len(evidence),
            }
            row["steps"]["assessment"] = {
                "status": "PASS"
                if assessment.get("assessment_status") in {"assessed", "abstained"}
                else "FAIL",
                "assessment_status": assessment.get("assessment_status"),
                "classifications": assessment.get("classifications"),
                "semantic_support": "NOT_MEASURED",
            }
            if row["steps"]["assessment"]["status"] != "PASS":
                raise RuntimeError("assessment_invalid")
            persist(ledger)
            phase = "proposal"
            candidates = spec.candidate_catalog(s["target"])
            cp = CONFIG + "/candidate-" + row["run_id"] + ".yml"
            b03.write_yaml(b03.OPS, cp, {"schema_version": 1, "candidates": candidates})
            po = cli(
                "incidents",
                "propose-remediation",
                iid,
                "--investigation",
                inv_id,
                "--ai-config",
                CONFIG + "/investigation.yml",
                "--candidates",
                cp,
                monitored=True,
                check=False,
                timeout=180,
            )
            enforce_transport_guard(po)
            pd = json.loads(po.get("stdout", "{}"))
            row["steps"]["proposal_transport"] = {
                "resource_watch": {
                    k: v for k, v in po.get("resource_watch", {}).items() if k != "samples"
                },
                "transport_failure_component": po.get("transport_failure_component"),
                "transport_failure_category": po.get("transport_failure_category"),
                "request_metadata": safe_provider_request_metadata(pd),
            }
            row["proposal_provider_requests"] = row.get("proposal_provider_requests", 0) + 1
            p = pd.get("proposal", {})
            val = p.get("validation", {})
            accepted = (
                pd.get("status") == "accepted"
                and val.get("accepted") is True
                and val.get("abstained") is False
            )
            action = p.get("candidate_action_id")
            target_ref = p.get("target_ref")
            cand = val.get("candidate")
            appropriate = bool(
                accepted and spec.action_is_oracle_appropriate(s, action, target_ref)
            )
            row["steps"]["proposal"] = {
                "status": "PASS" if accepted else "FAIL",
                "candidate_catalog": candidates,
                "selected_action_id": action,
                "target_ref": target_ref,
                "proposal": p if accepted else {"rejected": True},
                "oracle_appropriate": appropriate,
                "reason_code": pd.get("reason_code"),
            }
            if not accepted:
                raise RuntimeError("proposal_rejected")
            if not appropriate:
                raise RuntimeError("ai_decision_inappropriate")
            phase = "authorization"
            rb = RUNBOOKS + "/" + row["run_id"] + "-round-" + str(round_index) + ".yml"
            b03.write_guest(
                b03.OPS,
                rb,
                recovery_doc(row["run_id"] + "-round-" + str(round_index), s["target"], cand),
                uid=999,
                gid=988,
                mode=0o600,
            )
            plan = jcli("plan", rb, "--json")
            acts = [a for a in plan.get("actions", []) if a.get("phase") == "steps"]
            if (
                len(acts) != 1
                or acts[0].get("action") != action
                or acts[0].get("target") != s["target"]
                or acts[0].get("arguments") != cand.get("arguments")
                or plan.get("status") not in {"approval_required", "ready"}
            ):
                raise RuntimeError("proposal_plan_mismatch_or_denied")
            linked = jcli("incidents", "associate-plan", iid, plan["plan_id"])
            cli(
                "approve",
                plan["plan_id"],
                "--reason",
                "One-time approval for exact AI-selected B04 disposable action.",
            )
            row["steps"]["authorization"] = {
                "status": "PASS",
                "plan_id": plan["plan_id"],
                "plan_hash": plan.get("plan_hash"),
                "linked_plan_id": linked.get("plan_id"),
            }
            phase = "remediation"
            run = cli("run", plan["plan_id"], "--confirm", timeout=120)
            m = re.search(r"Execution\s+([0-9a-f-]{36}):\s*(\w+)", run.get("stdout", ""))
            if not m or m.group(2) != "succeeded":
                raise RuntimeError("remediation_execution_failed")
            row["steps"]["remediation"] = {
                "status": "PASS",
                "action_id": action,
                "target_ref": target_ref,
                "execution_id": m.group(1),
            }
            persist(ledger)
            phase = "postflight"
            recovered = wait_healthy(s["target"])
            row["steps"]["postflight"] = {
                "status": "PASS" if recovered else "FAIL",
                "observation": observe(s["target"]),
                "oracle": "independent HTTP/TCP/DNS/systemd/PostgreSQL checks",
            }
            row["recovery_rounds"].append(
                json.loads(
                    json.dumps(
                        {
                            key: row["steps"][key]
                            for key in (
                                "diagnostics",
                                "assessment",
                                "proposal",
                                "authorization",
                                "remediation",
                                "postflight",
                            )
                        }
                    )
                )
            )
            persist(ledger)
            if recovered:
                break
            if round_index == maximum_rounds - 1:
                raise RuntimeError("postflight_failed")
        cli(
            "incidents",
            "resolve",
            iid,
            "--reason",
            "Independent disposable fixture health check passed.",
            "--evidence-status",
            "verified",
        )
        cli("incidents", "close", iid, "--reason", "B04 recovery and audit complete.")
        row["steps"]["closure"] = {"status": "PASS"}
        audit = cli("audit")
        integrity_code = "import sqlite3,sys;c=sqlite3.connect(sys.argv[1]);print(c.execute('PRAGMA integrity_check').fetchone()[0]);c.close()"
        integrity = guest(b03.OPS, "/usr/bin/python3", ["-c", integrity_code, DB])["stdout"].strip()
        row["steps"]["audit"] = {
            "status": "PASS"
            if audit.get("exit_code") == 0
            and "AUDIT OK" in audit.get("stdout", "")
            and integrity == "ok"
            else "FAIL",
            "audit_output": audit.get("stdout", "").strip(),
            "sqlite_integrity": integrity,
        }
        row["steps"]["cleanup"] = {
            "status": "PASS" if reset(s) else "FAIL",
            "baseline_restored": healthy(s["target"]),
        }
        required = (
            "baseline",
            "fault",
            "incident",
            "diagnostics",
            "assessment",
            "proposal",
            "authorization",
            "remediation",
            "postflight",
            "closure",
            "audit",
            "cleanup",
        )
        row["result"] = (
            "AI_DRIVEN_PASS"
            if all(row["steps"].get(k, {}).get("status") == "PASS" for k in required)
            else "FAIL"
        )
    except (Exception, KeyboardInterrupt) as exc:
        row["result"] = "FAIL"
        row["failure_stage"] = phase
        row["campaign_abort"] = isinstance(exc, (CampaignSafetyAbort, KeyboardInterrupt))
        row["failure_category"] = type(exc).__name__
        row["failure_code"] = str(exc)[:120]
        try:
            row["steps"].setdefault(
                "cleanup",
                {
                    "status": "PASS" if reset(s) else "FAIL",
                    "baseline_restored": healthy(s["target"]),
                },
            )
        except Exception:
            row["steps"].setdefault("cleanup", {"status": "FAIL"})
    row["completed_at"] = dt.datetime.now(dt.timezone.utc).isoformat()
    persist(ledger)
    return row


def main() -> int:
    import argparse

    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--install-only", action="store_true")
    p.add_argument("--group", choices=("A", "B", "all"), default="all")
    p.add_argument("--scenario", choices=tuple(s["id"] for s in spec.SCENARIOS))
    args = p.parse_args()
    import fcntl

    LOCAL.mkdir(parents=True, exist_ok=True, mode=0o700)
    campaign_lock = (LOCAL / "runner.lock").open("a+")
    os.fchmod(campaign_lock.fileno(), 0o600)
    try:
        fcntl.flock(campaign_lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        raise SystemExit("another Batch 04 runner owns the campaign lock") from None
    if LEDGER.exists():
        ledger = json.loads(LEDGER.read_text())
    else:
        ledger = {"schema_version": 1, "dataset": "runbookos-batch04", "attempts": []}
    # Fail closed on an unexpected inference identity or insufficient launch margin.
    identity_path = b03.LOCAL / "runtime" / "server-identity.json"
    identity = json.loads(identity_path.read_text(encoding="utf-8"))
    pid = identity.get("pid")
    if not isinstance(pid, int) or pid <= 1:
        raise SystemExit("acceptance Qwen PID identity missing")
    exe = Path(os.readlink(f"/proc/{pid}/exe")).resolve()
    expected = Path("/home/morphious/.local/src/llama.cpp/build/bin/llama-server").resolve()
    if exe != expected:
        raise SystemExit("acceptance Qwen executable identity mismatch")
    cmdline = Path(f"/proc/{pid}/cmdline").read_bytes().split(b"\0")
    required = (
        str(expected).encode(),
        b"--port",
        b"18080",
        b"--api-key-file",
        b"/home/morphious/.config/runbookos/llama-api-key",
    )
    if not all(value in cmdline for value in required):
        raise SystemExit("acceptance Qwen process arguments do not match the approved endpoint")
    mem = next(
        (
            int(line.split()[1]) * 1024
            for line in Path("/proc/meminfo").read_text().splitlines()
            if line.startswith("MemAvailable:")
        ),
        0,
    )
    from campaign_batch04_runtime import start_ticks

    if identity.get("start_ticks") != start_ticks(pid):
        raise SystemExit("Qwen launch identity does not match recorded preflight")
    if identity.get("prelaunch_memavailable_bytes", 0) < 16 * 1024**3:
        raise SystemExit("verified prelaunch MemAvailable below 16 GiB")
    if mem < 6 * 1024**3:
        raise SystemExit("current MemAvailable below 6 GiB running threshold")
    key = Path("/home/morphious/.config/runbookos/llama-api-key")
    if not key.is_file() or key.stat().st_mode & 0o077:
        raise SystemExit("authenticated provider key file permissions are not owner-only")
    checks = (
        (
            Path("/home/morphious/models/llama.cpp/qwen3.5-9b-instruct-q5_k_m.gguf"),
            "dc2a39aef291f91a9116ad214058da0d86eb648743a124bd8c333787c4b9c91c",
        ),
        (expected, "98a8581124ccf8ba775a89e1899c895b2d4a2053b9830f8b044fe69b928c02ac"),
    )
    for artifact, digest in checks:
        actual = sha256_file(artifact)
        if actual != digest:
            raise SystemExit("approved model/runtime fingerprint mismatch")
    listener = __import__("subprocess").run(
        ["/usr/bin/ss", "-ltnp", "sport", "=", ":18080"],
        capture_output=True,
        text=True,
        check=False,
    )
    if listener.returncode != 0 or f"pid={pid}," not in listener.stdout:
        raise SystemExit("loopback inference listener is not owned by the verified Qwen PID")
    preflight_resources()
    install_source()
    configure_controller()
    install_fixtures()
    for target in ("svc-web-01", "db-01"):
        for index, candidate in enumerate(spec.candidate_catalog(target)):
            filename = RUNBOOKS + "/preflight-" + target + "-" + str(index) + ".yml"
            b03.write_guest(
                b03.OPS,
                filename,
                recovery_doc("preflight-" + target + "-" + str(index), target, candidate),
                uid=999,
                gid=988,
                mode=0o600,
            )
            planned = jcli("plan", filename, "--json")
            if planned.get("status") not in {"ready", "approval_required"}:
                raise SystemExit("candidate recovery plan rejected before fault injection")
    for diagnostic in ("core", "dependency", "resource", "db"):
        planned = jcli("plan", RUNBOOKS + "/b04-" + diagnostic + ".yml", "--json")
        if planned.get("status") != "ready":
            raise SystemExit("diagnostic plan rejected before fault injection")
    if args.install_only:
        version = cli("version", check=False)
        if version.get("exit_code") != 0 or "RunbookOS 0.7.0" not in version.get("stdout", ""):
            raise SystemExit(
                "isolated controller source failed the 0.7.0 import/version smoke check"
            )
        print(
            json.dumps(
                {
                    "status": "INSTALLED",
                    "controller_version": version["stdout"].strip(),
                    "web_healthy": healthy("svc-web-01"),
                    "db_healthy": healthy("db-01"),
                }
            )
        )
        return 0
    for s in spec.SCENARIOS:
        if s["group"] == "B":
            group_a_ids = {item["id"] for item in spec.SCENARIOS if item["group"] == "A"}
            passed_ids = {
                item["scenario_id"]
                for item in ledger["attempts"]
                if item.get("result") == "AI_DRIVEN_PASS"
            }
            if not group_a_ids <= passed_ids:
                break
        if args.scenario and args.scenario != s["id"]:
            continue
        if args.group not in {"all", s["group"]}:
            continue
        if any(
            a.get("scenario_id") == s["id"] and a.get("result") == "AI_DRIVEN_PASS"
            for a in ledger["attempts"]
        ):
            continue
        attempt = run_scenario(s, ledger)
        if attempt.get("campaign_abort"):
            break
    spec.validate_ledger(ledger["attempts"])
    a = sum(
        x.get("group") == "A" and x.get("result") == "AI_DRIVEN_PASS" for x in ledger["attempts"]
    )
    b = sum(
        x.get("group") == "B" and x.get("result") == "AI_DRIVEN_PASS" for x in ledger["attempts"]
    )
    ledger["summary"] = {
        "group_a_passes": a,
        "group_b_passes": b,
        "attempts": len(ledger["attempts"]),
        "completed": a + b,
        "qwen_requests": sum(
            x.get("assessment_provider_requests", 2 if x.get("investigation_id") else 0)
            + x.get("proposal_provider_requests", 1 if x.get("steps", {}).get("proposal") else 0)
            for x in ledger["attempts"]
        ),
    }
    persist(ledger)
    print(json.dumps(ledger["summary"], sort_keys=True))
    selected = {
        item["id"]
        for item in spec.SCENARIOS
        if args.group in {"all", item["group"]}
        and (not args.scenario or args.scenario == item["id"])
    }
    passed = {
        item["scenario_id"] for item in ledger["attempts"] if item.get("result") == "AI_DRIVEN_PASS"
    }
    return 0 if selected <= passed else 2


if __name__ == "__main__":
    raise SystemExit(main())
