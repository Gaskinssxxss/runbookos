from __future__ import annotations

from pathlib import Path

import pytest
from pydantic import ValidationError
from typer.testing import CliRunner

from runbookos.cli import app
from runbookos.tunnel import TunnelConfig, build_ssh_command, load_tunnel_config


def _files(tmp_path: Path, *, identity_mode: int = 0o600) -> tuple[Path, Path]:
    identity = tmp_path / "tunnel_ed25519"
    known_hosts = tmp_path / "known_hosts"
    identity.write_text("private key fixture", encoding="utf-8")
    known_hosts.write_text("host-key fixture", encoding="utf-8")
    identity.chmod(identity_mode)
    known_hosts.chmod(0o600)
    return identity, known_hosts


def test_tunnel_command_is_pinned_loopback_only_and_noninteractive(tmp_path: Path):
    identity, known_hosts = _files(tmp_path)
    config = TunnelConfig(
        schema_version=1,
        host="host.example.test",
        user="runbookos-tunnel",
        identity_file=identity,
        known_hosts_file=known_hosts,
    )

    command = build_ssh_command(config)

    assert "-N" in command
    assert "-T" in command
    assert "-F" in command and command[command.index("-F") + 1] == "/dev/null"
    assert "-L" in command
    assert command[command.index("-L") + 1] == "127.0.0.1:8080:127.0.0.1:8080"
    assert "runbookos-tunnel@host.example.test" in command
    assert "StrictHostKeyChecking=yes" in command
    assert f"UserKnownHostsFile={known_hosts}" in command
    assert "GlobalKnownHostsFile=/dev/null" in command
    assert "BatchMode=yes" in command
    assert "PasswordAuthentication=no" in command
    assert "ClearAllForwardings=no" in command


def test_tunnel_rejects_targets_outside_the_pinned_inference_endpoint(tmp_path: Path):
    identity, known_hosts = _files(tmp_path)
    with pytest.raises(ValidationError, match="127.0.0.1"):
        TunnelConfig(
            schema_version=1,
            host="host.example.test",
            user="runbookos-tunnel",
            identity_file=identity,
            known_hosts_file=known_hosts,
            remote_host="192.0.2.1",
        )
    with pytest.raises(ValidationError):
        TunnelConfig(
            schema_version=1,
            host="host.example.test",
            user="runbookos-tunnel",
            identity_file=identity,
            known_hosts_file=known_hosts,
            remote_port=8081,
        )


def test_tunnel_can_forward_to_approved_18080_loopback_endpoint(tmp_path: Path):
    identity, known_hosts = _files(tmp_path)
    config = TunnelConfig(
        schema_version=1,
        host="host.example.test",
        user="runbookos-tunnel",
        identity_file=identity,
        known_hosts_file=known_hosts,
        local_port=8080,
        remote_port=18080,
    )

    command = build_ssh_command(config)

    assert command[command.index("-L") + 1] == "127.0.0.1:8080:127.0.0.1:18080"


def test_tunnel_rejects_ssh_option_injection_and_non_private_identity(tmp_path: Path):
    identity, known_hosts = _files(tmp_path, identity_mode=0o644)
    with pytest.raises(ValidationError, match="simple local SSH account"):
        TunnelConfig(
            schema_version=1,
            host="host.example.test",
            user="-oProxyCommand=touch /tmp/pwned",
            identity_file=identity,
            known_hosts_file=known_hosts,
        )
    config = TunnelConfig(
        schema_version=1,
        host="host.example.test",
        user="runbookos-tunnel",
        identity_file=identity,
        known_hosts_file=known_hosts,
    )
    with pytest.raises(Exception, match="group or others"):
        build_ssh_command(config)


def test_tunnel_config_loads_only_private_paths(tmp_path: Path):
    identity, known_hosts = _files(tmp_path)
    config_path = tmp_path / "tunnel.yml"
    config_path.write_text(
        f"""schema_version: 1
host: 192.0.2.20
user: runbookos-tunnel
identity_file: {identity}
known_hosts_file: {known_hosts}
""",
        encoding="utf-8",
    )
    config_path.chmod(0o600)
    config = load_tunnel_config(config_path)
    assert config.remote_host == "127.0.0.1"
    assert config.local_port == 8080


def test_tunnel_cli_runs_explicit_foreground_command(tmp_path: Path, monkeypatch):
    identity, known_hosts = _files(tmp_path)
    config_path = tmp_path / "tunnel.yml"
    config_path.write_text(
        f"""schema_version: 1
host: 192.0.2.20
user: runbookos-tunnel
identity_file: {identity}
known_hosts_file: {known_hosts}
""",
        encoding="utf-8",
    )
    config_path.chmod(0o600)
    started = []
    monkeypatch.setattr("runbookos.cli.run_tunnel", lambda config: started.append(config) or 0)

    result = CliRunner().invoke(app, ["tunnel", str(config_path)])

    assert result.exit_code == 0
    assert "127.0.0.1:8080" in result.output
    assert len(started) == 1
