from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest

from runbookos.engine import Paths

ROOT = Path(__file__).resolve().parents[1]


def write_config_tree(base: Path, *, remediation: bool = False, profile_vars: bool = True) -> Paths:
    (base / "config").mkdir(parents=True, exist_ok=True)
    inventory = base / "config/inventory.yml"
    policy = base / "config/policy.yml"
    profiles = base / "config/ssh.yml"
    inventory.write_text("""schema_version: 1
hosts:
  test-web:
    address: 127.0.0.1
    user: runner
    role: web-server
    ssh_profile: test
    host_key_alias: runbookos-test-web
""")
    action = "systemd.restart" if remediation else "systemd.is_active"
    risk = "medium" if remediation else "low"
    remediation_actions = "[systemd.restart]" if remediation else "[]"
    verify_path = "data.restarted" if remediation else "data.active"
    verify_operator = "is_true"
    policy.write_text(f"""schema_version: 1
default_decision: deny
approval:
  required_for_remediation: true
  ttl_seconds: 300
  one_time: true
hosts:
  test-web:
    diagnostic_actions: [systemd.is_active, systemd.failed_units]
    remediation_actions: {remediation_actions}
    allowed_units: [nginx.service]
""")
    identity = "${ENV:RUNBOOKOS_TEST_KEY}" if profile_vars else str(base / "identity")
    known_hosts = "${ENV:RUNBOOKOS_TEST_KNOWN_HOSTS}" if profile_vars else str(base / "known_hosts")
    profiles.write_text(f"""schema_version: 1
profiles:
  test:
    identity_file: "{identity}"
    known_hosts_file: "{known_hosts}"
    connect_timeout_seconds: 1
    server_alive_interval_seconds: 1
""")
    runbook = base / "runbook.yml"
    runbook.write_text(f"""api_version: runbookos/v1
kind: Runbook
metadata:
  id: test-service-health
  name: Test service health
  description: Test only.
  risk: {risk}
targets: [test-web]
steps:
  - id: check-service
    action: {action}
    with: {{unit: nginx.service}}
    verify:
      - path: {verify_path}
        operator: {verify_operator}
""")
    return Paths(inventory, policy, profiles, base / "state/runbookos.sqlite3")


@pytest.fixture
def key_material(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> tuple[Path, Path]:
    if not shutil_which("ssh-keygen"):
        pytest.skip("OpenSSH ssh-keygen is required")
    private = tmp_path / "id_ed25519"
    host_private = tmp_path / "host_ed25519"
    subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(private)], check=True)
    subprocess.run(
        ["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(host_private)], check=True
    )
    os.chmod(private, 0o600)
    host_pub = Path(str(host_private) + ".pub").read_text().split()
    known_hosts = tmp_path / "known_hosts"
    known_hosts.write_text(f"runbookos-test-web {host_pub[0]} {host_pub[1]}\n")
    os.chmod(known_hosts, 0o600)
    monkeypatch.setenv("RUNBOOKOS_TEST_KEY", str(private))
    monkeypatch.setenv("RUNBOOKOS_TEST_KNOWN_HOSTS", str(known_hosts))
    return private, known_hosts


def shutil_which(command: str) -> str | None:
    import shutil

    return shutil.which(command)
