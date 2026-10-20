from __future__ import annotations

import ipaddress
import re
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, populate_by_name=True)


class RunbookMetadata(StrictModel):
    id: str = Field(pattern=r"^[a-z][a-z0-9-]{1,62}$")
    name: str = Field(min_length=1, max_length=120)
    description: str = Field(min_length=1, max_length=1000)
    risk: Literal["low", "medium", "high"]


class ParameterSpec(StrictModel):
    type: Literal["string", "integer", "boolean"]
    required: bool = True
    default: str | int | bool | None = None
    choices: list[str | int | bool] | None = None
    minimum: int | None = None
    maximum: int | None = None
    pattern: str | None = None

    @model_validator(mode="after")
    def valid_definition(self) -> ParameterSpec:
        if self.required and self.default is not None:
            raise ValueError("a required parameter cannot also have a default")
        if self.minimum is not None and self.maximum is not None and self.minimum > self.maximum:
            raise ValueError("parameter minimum must be <= maximum")
        if self.pattern:
            try:
                re.compile(self.pattern)
            except re.error as exc:
                raise ValueError(f"invalid parameter pattern: {exc}") from exc
        return self


class Assertion(StrictModel):
    path: str = Field(pattern=r"^(data|result)(\.[a-zA-Z_][a-zA-Z0-9_]*)+$")
    operator: Literal["eq", "neq", "lt", "lte", "gt", "gte", "empty", "nonempty", "is_true"]
    value: Any = None


class Step(StrictModel):
    id: str = Field(pattern=r"^[a-z][a-z0-9_-]{1,62}$")
    action: str = Field(pattern=r"^[a-z][a-z0-9_]*\.[a-z][a-z0-9_]*$")
    arguments: dict[str, Any] = Field(default_factory=dict, alias="with")
    timeout_seconds: int = Field(default=15, ge=1, le=300)
    verify: list[Assertion] = Field(default_factory=list)


class Runbook(StrictModel):
    api_version: Literal["runbookos/v1"]
    kind: Literal["Runbook"]
    metadata: RunbookMetadata
    targets: list[str] = Field(min_length=1)
    parameters: dict[str, ParameterSpec] = Field(default_factory=dict)
    preflight: list[Step] = Field(default_factory=list)
    steps: list[Step] = Field(min_length=1)
    postflight: list[Step] = Field(default_factory=list)

    @field_validator("targets")
    @classmethod
    def unique_targets(cls, value: list[str]) -> list[str]:
        if len(value) != len(set(value)):
            raise ValueError("targets must be unique")
        for host in value:
            if not re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9_.-]{0,62}", host):
                raise ValueError(f"invalid inventory host alias: {host!r}")
        return value

    @model_validator(mode="after")
    def unique_steps(self) -> Runbook:
        ids = [s.id for s in self.preflight + self.steps + self.postflight]
        if len(ids) != len(set(ids)):
            raise ValueError("step ids must be unique across preflight, steps, and postflight")
        for name in self.parameters:
            if not re.fullmatch(r"[a-z][a-z0-9_]{0,62}", name):
                raise ValueError(f"invalid parameter name: {name!r}")
            if any(
                word in name.lower()
                for word in ("password", "secret", "token", "credential", "private_key")
            ):
                raise ValueError(f"secret-like parameters are not accepted: {name!r}")
        return self


class SSHProfile(StrictModel):
    identity_file: str = Field(min_length=1)
    known_hosts_file: str = Field(min_length=1)
    connect_timeout_seconds: int = Field(default=5, ge=1, le=30)
    server_alive_interval_seconds: int = Field(default=5, ge=1, le=60)


class ProbeTarget(StrictModel):
    protocol: Literal["tcp", "http", "https", "postgresql"]
    address: str = Field(min_length=7, max_length=15)
    port: int = Field(ge=1, le=65535)
    path: str | None = Field(default=None, max_length=128)

    @field_validator("address")
    @classmethod
    def private_ipv4_only(cls, value: str) -> str:
        try:
            address = ipaddress.ip_address(value)
        except ValueError as exc:
            raise ValueError("probe target address must be an IPv4 literal") from exc
        if (
            not isinstance(address, ipaddress.IPv4Address)
            or not address.is_private
            or address.is_loopback
            or address.is_link_local
            or address.is_multicast
            or address.is_reserved
            or address.is_unspecified
        ):
            raise ValueError("probe target must be a private unicast IPv4 address")
        return str(address)

    @field_validator("path")
    @classmethod
    def safe_http_path(cls, value: str | None) -> str | None:
        if value is None:
            return value
        if (
            not value.startswith("/")
            or value.startswith("//")
            or ".." in value.split("/")
            or any(char in value for char in "?#\\%\x00\r\n")
            or not re.fullmatch(r"/[A-Za-z0-9_./-]{0,127}", value)
        ):
            raise ValueError("probe HTTP path must be a fixed safe absolute path")
        return value

    @model_validator(mode="after")
    def protocol_fields(self) -> ProbeTarget:
        if self.protocol in {"http", "https"} and self.path is None:
            raise ValueError("HTTP probe targets require a fixed path")
        if self.protocol not in {"http", "https"} and self.path is not None:
            raise ValueError("only HTTP probe targets accept a path")
        return self


class Host(StrictModel):
    address: str = Field(min_length=1, max_length=253)
    port: int = Field(default=22, ge=1, le=65535)
    user: str = Field(pattern=r"^[a-z_][a-z0-9_-]{0,31}$")
    role: str = Field(pattern=r"^[a-z][a-z0-9_-]{1,62}$")
    ssh_profile: str = Field(pattern=r"^[a-z][a-z0-9_-]{1,62}$")
    host_key_alias: str | None = Field(default=None, pattern=r"^[a-zA-Z0-9_.:-]{1,253}$")
    probe_targets: dict[str, ProbeTarget] = Field(default_factory=dict, max_length=64)

    @field_validator("address")
    @classmethod
    def safe_address(cls, value: str) -> str:
        if any(ch in value for ch in " \t\r\n/@;$`\\"):
            raise ValueError("address contains unsafe characters")
        try:
            ipaddress.ip_address(value)
        except ValueError:
            if not re.fullmatch(
                r"(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)(?:\.(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?))*\.?",
                value,
            ):
                raise ValueError("address must be an IP address or DNS hostname")
        return value

    @field_validator("probe_targets")
    @classmethod
    def safe_probe_target_names(cls, value: dict[str, ProbeTarget]) -> dict[str, ProbeTarget]:
        if any(not re.fullmatch(r"[a-z][a-z0-9_-]{1,62}", name) for name in value):
            raise ValueError("probe target IDs must be lowercase inventory aliases")
        return value


class Inventory(StrictModel):
    schema_version: Literal[1]
    hosts: dict[str, Host]


class HostPolicy(StrictModel):
    diagnostic_actions: list[str] = Field(default_factory=list)
    remediation_actions: list[str] = Field(default_factory=list)
    allowed_units: list[str] = Field(default_factory=list)
    allowed_probe_targets: list[str] = Field(default_factory=list)


class ApprovalPolicy(StrictModel):
    required_for_remediation: Literal[True] = True
    ttl_seconds: int = Field(default=900, ge=30, le=86400)
    one_time: Literal[True] = True


class Policy(StrictModel):
    schema_version: Literal[1]
    default_decision: Literal["deny"]
    approval: ApprovalPolicy = Field(default_factory=ApprovalPolicy)
    hosts: dict[str, HostPolicy]


class PlanAction(StrictModel):
    target: str
    phase: Literal["preflight", "steps", "postflight"]
    step_id: str
    action: str
    arguments: dict[str, Any]
    timeout_seconds: int
    read_only: bool
    verify: list[Assertion] = Field(default_factory=list)
    allowed: bool
    approval_required: bool
    reason: str


class PlanDocument(StrictModel):
    plan_id: str
    created_at: str
    runbook_id: str
    runbook_name: str
    runbook_path: str
    parameters: dict[str, Any]
    actions: list[PlanAction]
    status: Literal["ready", "approval_required", "denied"]
    plan_hash: str
    source_hashes: dict[str, str]
    risk: Literal["low", "medium", "high"]
