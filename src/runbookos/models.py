from __future__ import annotations

import ipaddress
import re
from enum import StrEnum
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
    dns_name: str | None = Field(default=None, max_length=253)
    resolver_address: str | None = Field(default=None, max_length=15)
    local_listener: bool = Field(default=False, strict=True)
    database_name: str | None = Field(default=None, pattern=r"^[a-zA-Z_][a-zA-Z0-9_]{0,62}$")
    database_user: str | None = Field(default=None, pattern=r"^[a-z_][a-z0-9_]{0,62}$")
    credential_id: str | None = Field(default=None, pattern=r"^[a-z][a-z0-9_-]{1,62}$")
    pressure_storage_ids: list[str] = Field(default_factory=list, max_length=8)

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

    @field_validator("dns_name")
    @classmethod
    def safe_dns_name(cls, value: str | None) -> str | None:
        if value is not None and (
            len(value) > 253
            or not re.fullmatch(
                r"(?=.{1,253}$)[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+",
                value,
            )
        ):
            raise ValueError("DNS name must be a fixed fully qualified name")
        return value.lower() if value is not None else None

    @field_validator("resolver_address")
    @classmethod
    def safe_resolver_address(cls, value: str | None) -> str | None:
        return cls.private_ipv4_only(value) if value is not None else None

    @model_validator(mode="after")
    def protocol_fields(self) -> ProbeTarget:
        if self.protocol in {"http", "https"} and self.path is None:
            raise ValueError("HTTP probe targets require a fixed path")
        if self.protocol not in {"http", "https"} and self.path is not None:
            raise ValueError("only HTTP probe targets accept a path")
        if self.resolver_address is not None and self.dns_name is None:
            raise ValueError("resolver address requires an explicit DNS name")
        if any(v is not None for v in (self.database_name, self.database_user, self.credential_id)):
            if self.protocol != "postgresql" or not all(
                v is not None
                for v in (self.database_name, self.database_user, self.credential_id, self.dns_name)
            ):
                raise ValueError(
                    "SQL inspection requires PostgreSQL, pinned hostname and complete credential metadata"
                )
        if self.pressure_storage_ids and (
            self.protocol != "postgresql"
            or len(self.pressure_storage_ids) != len(set(self.pressure_storage_ids))
            or any(not re.fullmatch(r"[a-z][a-z0-9_-]{1,62}", v) for v in self.pressure_storage_ids)
        ):
            raise ValueError("PostgreSQL pressure storage IDs must be unique aliases")
        return self


class StorageTarget(StrictModel):
    path: str = Field(min_length=1, max_length=256)
    kind: Literal["directory", "file", "mount"]

    @field_validator("path")
    @classmethod
    def safe_path(cls, value: str) -> str:
        if (
            not value.startswith("/")
            or value.startswith("//")
            or value != "/"
            and value.endswith("/")
            or any(part in {"", ".", ".."} for part in value.split("/")[1:])
            or any(character in value for character in "\x00\n\r")
        ):
            raise ValueError("storage target must be a normalized absolute path")
        return value


class ApplicationProfile(StrictModel):
    health_endpoint_id: str = Field(pattern=r"^[a-z][a-z0-9_-]{1,62}$")
    dependency_endpoint_ids: list[str] = Field(default_factory=list, max_length=8)
    pressure_storage_ids: list[str] = Field(default_factory=list, max_length=8)
    queue_endpoint_id: str | None = Field(default=None, pattern=r"^[a-z][a-z0-9_-]{1,62}$")
    queue_max_depth: int | None = Field(default=None, ge=0, le=1000000)
    queue_max_age_seconds: int | None = Field(default=None, ge=0, le=86400)
    worker_unit: str | None = Field(
        default=None, pattern=r"^[A-Za-z0-9][A-Za-z0-9_.@:-]{0,127}\.service$"
    )
    config_storage_id: str | None = Field(default=None, pattern=r"^[a-z][a-z0-9_-]{1,62}$")
    expected_config_sha256: str | None = Field(default=None, pattern=r"^[a-f0-9]{64}$")
    version_storage_id: str | None = Field(default=None, pattern=r"^[a-z][a-z0-9_-]{1,62}$")
    expected_version: str | None = Field(
        default=None, pattern=r"^[A-Za-z0-9][A-Za-z0-9._+-]{0,63}$"
    )

    @model_validator(mode="after")
    def valid_sources(self) -> ApplicationProfile:
        if len(self.dependency_endpoint_ids) != len(set(self.dependency_endpoint_ids)):
            raise ValueError("dependency endpoint IDs must be unique")
        if self.health_endpoint_id in self.dependency_endpoint_ids:
            raise ValueError("application health cannot be its own dependency")
        if len(self.pressure_storage_ids) != len(set(self.pressure_storage_ids)) or any(
            not re.fullmatch(r"[a-z][a-z0-9_-]{1,62}", storage_id)
            for storage_id in self.pressure_storage_ids
        ):
            raise ValueError("application pressure storage IDs must be unique inventory aliases")
        for pair in (
            (self.queue_endpoint_id, self.queue_max_depth),
            (self.queue_endpoint_id, self.queue_max_age_seconds),
            (self.config_storage_id, self.expected_config_sha256),
            (self.version_storage_id, self.expected_version),
        ):
            if (pair[0] is None) != (pair[1] is None):
                raise ValueError(
                    "application source and expected value must be configured together"
                )
        return self


class Host(StrictModel):
    address: str = Field(min_length=1, max_length=253)
    port: int = Field(default=22, ge=1, le=65535)
    user: str = Field(pattern=r"^[a-z_][a-z0-9_-]{0,31}$")
    role: str = Field(pattern=r"^[a-z][a-z0-9_-]{1,62}$")
    ssh_profile: str = Field(pattern=r"^[a-z][a-z0-9_-]{1,62}$")
    host_key_alias: str | None = Field(default=None, pattern=r"^[a-zA-Z0-9_.:-]{1,253}$")
    probe_targets: dict[str, ProbeTarget] = Field(default_factory=dict, max_length=64)
    storage_targets: dict[str, StorageTarget] = Field(default_factory=dict, max_length=64)
    applications: dict[str, ApplicationProfile] = Field(default_factory=dict, max_length=16)

    @model_validator(mode="after")
    def valid_applications(self) -> Host:
        for endpoint in self.probe_targets.values():
            for storage_id in endpoint.pressure_storage_ids:
                if (
                    storage_id not in self.storage_targets
                    or self.storage_targets[storage_id].kind != "directory"
                ):
                    raise ValueError("PostgreSQL pressure storage must be a registered directory")
        for name, app in self.applications.items():
            if not re.fullmatch(r"[a-z][a-z0-9_-]{1,62}", name):
                raise ValueError("application IDs must be lowercase inventory aliases")
            for endpoint_id in [app.health_endpoint_id, *app.dependency_endpoint_ids]:
                if endpoint_id not in self.probe_targets:
                    raise ValueError("application endpoint must exist in host probe targets")
            if self.probe_targets[app.health_endpoint_id].protocol not in {"http", "https"}:
                raise ValueError("application health endpoint must use HTTP or HTTPS")
            if (
                self.probe_targets[app.health_endpoint_id].protocol == "https"
                and self.probe_targets[app.health_endpoint_id].dns_name is None
            ):
                raise ValueError("HTTPS application health requires a pinned DNS name")
            if app.queue_endpoint_id is not None and (
                app.queue_endpoint_id not in self.probe_targets
                or self.probe_targets[app.queue_endpoint_id].protocol not in {"http", "https"}
            ):
                raise ValueError("application queue endpoint must use HTTP or HTTPS")
            if app.queue_endpoint_id is not None:
                queue = self.probe_targets[app.queue_endpoint_id]
                if queue.protocol == "https" and queue.dns_name is None:
                    raise ValueError("HTTPS application queue requires a pinned DNS name")
            for storage_id in (app.config_storage_id, app.version_storage_id):
                if storage_id is not None and (
                    storage_id not in self.storage_targets
                    or self.storage_targets[storage_id].kind != "file"
                ):
                    raise ValueError("application artifact must be a registered file target")
            for storage_id in app.pressure_storage_ids:
                if (
                    storage_id not in self.storage_targets
                    or self.storage_targets[storage_id].kind != "directory"
                ):
                    raise ValueError("application pressure storage must be a registered directory")
        return self

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

    @field_validator("storage_targets")
    @classmethod
    def safe_storage_target_names(cls, value: dict[str, StorageTarget]) -> dict[str, StorageTarget]:
        if any(not re.fullmatch(r"[a-z][a-z0-9_-]{1,62}", name) for name in value):
            raise ValueError("storage target IDs must be lowercase inventory aliases")
        return value


class Inventory(StrictModel):
    schema_version: Literal[1]
    hosts: dict[str, Host]


class HostPolicy(StrictModel):
    diagnostic_actions: list[str] = Field(default_factory=list)
    remediation_actions: list[str] = Field(default_factory=list)
    allowed_units: list[str] = Field(default_factory=list)
    allowed_probe_targets: list[str] = Field(default_factory=list)
    allowed_storage_targets: list[str] = Field(default_factory=list)
    allowed_storage_paths: list[str] = Field(default_factory=list, max_length=64)
    allowed_applications: list[str] = Field(default_factory=list, max_length=16)

    @field_validator("allowed_applications")
    @classmethod
    def safe_application_names(cls, value: list[str]) -> list[str]:
        if len(value) != len(set(value)) or any(
            not re.fullmatch(r"[a-z][a-z0-9_-]{1,62}", name) for name in value
        ):
            raise ValueError("allowed application IDs must be unique lowercase inventory aliases")
        return value

    @field_validator("allowed_storage_paths")
    @classmethod
    def safe_storage_paths(cls, value: list[str]) -> list[str]:
        for path in value:
            if (
                not isinstance(path, str)
                or len(path) > 256
                or (
                    path != "/"
                    and (
                        not path.startswith("/")
                        or path.startswith("//")
                        or path.endswith("/")
                        or any(part in {"", ".", ".."} for part in path.split("/")[1:])
                    )
                )
                or any(char in path for char in "\x00\n\r")
            ):
                raise ValueError("allowed storage paths must be normalized absolute paths")
        if len(value) != len(set(value)):
            raise ValueError("allowed storage paths must be unique")
        return value


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


class RemediationOutcome(StrEnum):
    VERIFIED_SUCCESS = "VERIFIED_SUCCESS"
    VERIFIED_FAILURE = "VERIFIED_FAILURE"
    UNKNOWN = "UNKNOWN"
    NOT_EXECUTED = "NOT_EXECUTED"
