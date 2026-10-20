"""Constrained OpenSSH local tunnel for loopback-only inference endpoints."""

from __future__ import annotations

import ipaddress
import os
import re
import shutil
import subprocess
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator

from .config import read_yaml
from .errors import ConfigurationError, RunbookOSError

MAX_TUNNEL_CONFIG_BYTES = 16 * 1024
_HOSTNAME = re.compile(
    r"^(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)(?:\.(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?))*\.?$"
)
_USER = re.compile(r"^[a-z_][a-z0-9_-]{0,31}\$?$")


class TunnelConfig(BaseModel):
    """Only permits a loopback listener forwarded to a loopback target."""

    model_config = ConfigDict(extra="forbid")

    schema_version: int = Field(ge=1, le=1)
    host: str = Field(min_length=1, max_length=253)
    port: int = Field(default=22, ge=1, le=65535)
    user: str = Field(min_length=1, max_length=32)
    identity_file: Path
    known_hosts_file: Path
    local_port: int = Field(default=8080, ge=1024, le=65535)
    remote_host: Literal["127.0.0.1"] = "127.0.0.1"
    remote_port: Literal[8080] = 8080

    @field_validator("host")
    @classmethod
    def validate_host(cls, value: str) -> str:
        try:
            ipaddress.ip_address(value)
            return value
        except ValueError:
            if not _HOSTNAME.fullmatch(value) or value.startswith("-"):
                raise ValueError("host must be an IP address or DNS hostname")
            return value

    @field_validator("user")
    @classmethod
    def validate_user(cls, value: str) -> str:
        if not _USER.fullmatch(value):
            raise ValueError("user must be a simple local SSH account name")
        return value


def load_tunnel_config(path: Path) -> TunnelConfig:
    path = path.expanduser().resolve()
    try:
        if path.stat().st_size > MAX_TUNNEL_CONFIG_BYTES:
            raise ConfigurationError("tunnel config exceeds 16 KiB")
        raw, _ = read_yaml(path)
        config = TunnelConfig.model_validate(raw)
    except (OSError, ConfigurationError, ValidationError) as exc:
        raise ConfigurationError(f"invalid tunnel config: {exc}") from exc

    config = config.model_copy(
        update={
            "identity_file": config.identity_file.expanduser().resolve(),
            "known_hosts_file": config.known_hosts_file.expanduser().resolve(),
        }
    )
    _validate_secret_files(config)
    return config


def _validate_secret_files(config: TunnelConfig) -> None:
    """Require regular, private local identity and pinned-host-key files."""
    for name, path in (
        ("identity_file", config.identity_file),
        ("known_hosts_file", config.known_hosts_file),
    ):
        try:
            info = path.stat()
        except OSError as exc:
            raise ConfigurationError(f"{name} is not readable") from exc
        if not path.is_file():
            raise ConfigurationError(f"{name} must be a regular file")
        if info.st_mode & 0o077:
            raise ConfigurationError(f"{name} must not be accessible by group or others")
    if config.identity_file == config.known_hosts_file:
        raise ConfigurationError("identity_file and known_hosts_file must be different files")


def build_ssh_command(config: TunnelConfig) -> list[str]:
    """Build a fixed-purpose SSH command; configuration cannot add shell arguments."""
    _validate_secret_files(config)
    ssh = shutil.which("ssh")
    if ssh is None:
        raise RunbookOSError("OpenSSH client is not installed")
    forward = f"127.0.0.1:{config.local_port}:{config.remote_host}:{config.remote_port}"
    options = [
        "-F",
        "/dev/null",
        "-N",
        "-T",
        "-p",
        str(config.port),
        "-i",
        str(config.identity_file),
    ]
    fixed_options = {
        "BatchMode": "yes",
        "IdentitiesOnly": "yes",
        "PreferredAuthentications": "publickey",
        "PasswordAuthentication": "no",
        "KbdInteractiveAuthentication": "no",
        "StrictHostKeyChecking": "yes",
        "UpdateHostKeys": "no",
        "UserKnownHostsFile": str(config.known_hosts_file),
        "GlobalKnownHostsFile": "/dev/null",
        # The SSH config is disabled with -F /dev/null; keep the one explicit -L
        # forward instead of letting OpenSSH clear it at connection setup.
        "ClearAllForwardings": "no",
        "ExitOnForwardFailure": "yes",
        "ForwardAgent": "no",
        "PermitLocalCommand": "no",
        "RequestTTY": "no",
        "ConnectTimeout": "8",
        "ServerAliveInterval": "15",
        "ServerAliveCountMax": "2",
    }
    for key, value in fixed_options.items():
        options.extend(["-o", f"{key}={value}"])
    options.extend(["-L", forward, f"{config.user}@{config.host}"])
    return [ssh, *options]


def run_tunnel(config: TunnelConfig) -> int:
    """Run in foreground so an operator owns the tunnel lifecycle explicitly."""
    command = build_ssh_command(config)
    env = {key: value for key, value in os.environ.items() if key not in {"SSH_AUTH_SOCK"}}
    try:
        return subprocess.run(command, check=False, env=env).returncode
    except OSError as exc:
        raise RunbookOSError(f"could not start OpenSSH tunnel: {type(exc).__name__}") from exc
