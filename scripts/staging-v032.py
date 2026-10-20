#!/usr/bin/env python3
"""Create and control a disposable, loopback-only RunbookOS v0.3.2 staging runtime."""

from __future__ import annotations

import argparse
import json
import os
import secrets
import signal
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
STAGING = ROOT / ".runbookos-staging-v032"
VENV = STAGING / "venv"
STATE = STAGING / "state"
CONFIG = STAGING / "config"
RUN = STAGING / "run"
LOGS = STAGING / "logs"
ENV_FILE = STAGING / ".env"


def _secure_write(path: Path, content: str, mode: int = 0o600) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    with os.fdopen(fd, "w", encoding="utf-8") as stream:
        stream.write(content)


def initialize() -> None:
    if STAGING.exists():
        raise RuntimeError(f"staging path already exists; refusing overwrite: {STAGING}")
    STAGING.mkdir(mode=0o700)
    for path in (STATE, CONFIG, RUN, LOGS):
        path.mkdir(mode=0o700)
    subprocess.run([sys.executable, "-m", "venv", str(VENV)], check=True)
    pip = VENV / "bin/pip"
    subprocess.run([str(pip), "install", str(ROOT)], check=True)
    for source, name in (
        (ROOT / "config/inventory.example.yml", "inventory.yml"),
        (ROOT / "config/policy.example.yml", "policy.yml"),
        (ROOT / "config/ssh_profiles.example.yml", "ssh_profiles.yml"),
    ):
        (CONFIG / name).write_bytes(source.read_bytes())
    source_secret = secrets.token_urlsafe(48)
    bridge_password = secrets.token_urlsafe(32)
    environment = (
        f"RUNBOOKOS_HMAC_ALERTMANAGER_STAGING={source_secret}\n"
        f"RUNBOOKOS_BRIDGE_HMAC_KEY={source_secret}\n"
        f"RUNBOOKOS_BRIDGE_USER=alertmanager-staging\n"
        f"RUNBOOKOS_BRIDGE_PASSWORD={bridge_password}\n"
        f"RUNBOOKOS_BRIDGE_KEY_ID=am-staging-v1\n"
    )
    _secure_write(ENV_FILE, environment)
    _secure_write(RUN / "alertmanager-password", bridge_password + "\n")
    auth = """schema_version: 1
mode: per_source
max_timestamp_skew_seconds: 300
sources:
  alertmanager-staging:
    enabled: true
    active_key_id: am-staging-v1
    keys:
      am-staging-v1:
        secret_env: RUNBOOKOS_HMAC_ALERTMANAGER_STAGING
        state: active
"""
    _secure_write(CONFIG / "webhook-auth.yml", auth, 0o600)
    print(f"Initialized isolated staging at {STAGING}")
    print("Secret values were generated locally and were not printed.")


def _read_env() -> dict[str, str]:
    values = {}
    for line in ENV_FILE.read_text(encoding="utf-8").splitlines():
        key, value = line.split("=", 1)
        values[key] = value
    return values


def _processes() -> dict[str, list[str]]:
    exe = str(VENV / "bin/runbookos")
    return {
        "webhook": [
            exe,
            "--inventory",
            str(CONFIG / "inventory.yml"),
            "--policy",
            str(CONFIG / "policy.yml"),
            "--ssh-profiles",
            str(CONFIG / "ssh_profiles.yml"),
            "--db",
            str(STATE / "runbookos.sqlite3"),
            "webhook",
            "serve",
            "--auth-config",
            str(CONFIG / "webhook-auth.yml"),
            "--host",
            "127.0.0.1",
            "--port",
            "8765",
        ],
        "bridge": [
            str(VENV / "bin/python"),
            "-m",
            "runbookos.adapters.alertmanager_bridge",
            "--host",
            "127.0.0.1",
            "--port",
            "8764",
            "--downstream-port",
            "8765",
        ],
    }


def _pid_path(name: str) -> Path:
    return RUN / f"{name}.pid"


def _alive(name: str) -> int | None:
    try:
        pid = int(_pid_path(name).read_text())
        os.kill(pid, 0)
        command = Path(f"/proc/{pid}/cmdline").read_bytes()
        expected = "runbookos.adapters.alertmanager_bridge" if name == "bridge" else "webhook"
        if expected.encode() not in command:
            return None
        return pid
    except (OSError, ValueError):
        return None


def start() -> None:
    if not VENV.exists() or not ENV_FILE.exists():
        raise RuntimeError("staging is not initialized; run init first")
    env = os.environ | _read_env()
    for name, command in _processes().items():
        if _alive(name):
            continue
        log = (LOGS / f"{name}.log").open("ab", buffering=0)
        process = subprocess.Popen(
            command,
            cwd=ROOT,
            env=env,
            stdin=subprocess.DEVNULL,
            stdout=log,
            stderr=log,
            start_new_session=True,
            close_fds=True,
        )
        _pid_path(name).write_text(str(process.pid), encoding="ascii")
        os.chmod(_pid_path(name), 0o600)
        time.sleep(0.2)
        if process.poll() is not None:
            _pid_path(name).unlink(missing_ok=True)
            raise RuntimeError(f"{name} exited during startup; inspect {LOGS / (name + '.log')}")
    print("Loopback staging started: signing bridge 127.0.0.1:8764 → webhook 127.0.0.1:8765")


def status() -> None:
    state = {name: _alive(name) for name in _processes()}
    print(
        json.dumps({"processes": state, "database_exists": (STATE / "runbookos.sqlite3").exists()})
    )


def stop() -> None:
    for name in reversed(tuple(_processes())):
        pid = _alive(name)
        if not pid:
            _pid_path(name).unlink(missing_ok=True)
            continue
        os.kill(pid, signal.SIGTERM)
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            try:
                os.kill(pid, 0)
            except ProcessLookupError:
                break
            time.sleep(0.1)
        else:
            os.kill(pid, signal.SIGKILL)
        _pid_path(name).unlink(missing_ok=True)
    print("Staging processes stopped; state and database were preserved.")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("init", "start", "status", "stop", "restart"))
    args = parser.parse_args()
    try:
        if args.command == "init":
            initialize()
        elif args.command == "start":
            start()
        elif args.command == "status":
            status()
        elif args.command == "stop":
            stop()
        else:
            stop()
            start()
    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        raise SystemExit(2) from exc


if __name__ == "__main__":
    main()
