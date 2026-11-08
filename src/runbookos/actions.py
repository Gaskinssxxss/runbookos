from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator

from .errors import ConfigurationError


class ProbeArguments(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    endpoint_id: str = Field(pattern=r"^[a-z][a-z0-9_-]{1,62}$")


class JournalTailArguments(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    unit: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9_.@:-]{0,127}\.(service|timer)$")
    lines: int = Field(default=20, ge=1, le=50)


class UnitStatusArguments(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    unit: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9_.@:-]{0,127}\.service$")


class JournalSummaryArguments(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    unit: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9_.@:-]{0,127}\.(service|timer)$")
    window_minutes: int = Field(default=60, ge=1, le=1440)
    max_entries: int = Field(default=100, ge=1, le=200)


class ProcessListArguments(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    order_by: Literal["pid", "memory_rss"] = "pid"
    limit: int = Field(default=50, ge=1, le=100)


class ProcessIdentityArguments(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    pid: int = Field(ge=1, le=4_194_304)


class ProcessTreeArguments(ProcessIdentityArguments):
    max_depth: int = Field(default=4, ge=1, le=8)
    max_nodes: int = Field(default=50, ge=1, le=100)


class FilesystemPathArguments(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    path: str = Field(min_length=1, max_length=256)

    @field_validator("path")
    @classmethod
    def absolute_normal_path(cls, value: str) -> str:
        if (
            not value.startswith("/")
            or any(character in value for character in "\x00\n\r")
            or ".." in value.split("/")
        ):
            raise ValueError("path must be an absolute normalized path")
        return value


class BoundedListArguments(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    limit: int = Field(default=50, ge=1, le=100)


class CronSummaryArguments(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    limit: int = Field(default=50, ge=1, le=100)


class FixtureConfigRestoreArguments(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    fixture_id: Literal["app_config", "proxy_config"]


class FixtureDNSRestoreArguments(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    fixture_id: Literal["resolver_config"]


class FixtureNetworkRestoreArguments(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    fixture_id: Literal["isolated_link"]


class FixtureStorageReleaseArguments(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    fixture_id: Literal["bounded_volume"]


class FixtureResourceRestoreArguments(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    fixture_id: Literal["worker_quota"]


class FixturePostgresStartArguments(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    cluster: Literal["16-b04"]


class FixtureDependencyRestoreArguments(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    fixture_id: Literal["backend_service"]


class FixtureApplicationRecoverArguments(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    fixture_id: Literal["worker_service"]


class FixtureDNSProbeArguments(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    fixture_id: Literal["b04_resolver"]


class FixtureInspectionArguments(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    fixture_id: Literal["web_stack"]


@dataclass(frozen=True)
class ActionDefinition:
    name: str
    read_only: bool
    required_arguments: frozenset[str]
    optional_arguments: frozenset[str] = frozenset()
    risk: str = "low"
    arguments_model: type[BaseModel] | None = None
    max_timeout_seconds: int = 300
    expected_impact: str = "No service impact is expected from this read-only action."
    rollback: str = "Not applicable; this action does not mutate system state."
    rollback_available: bool = False


REGISTRY: dict[str, ActionDefinition] = {
    "systemd.is_active": ActionDefinition("systemd.is_active", True, frozenset({"unit"})),
    "systemd.service_status": ActionDefinition(
        "systemd.service_status",
        True,
        frozenset({"unit"}),
        arguments_model=UnitStatusArguments,
        max_timeout_seconds=10,
    ),
    "systemd.failed_units": ActionDefinition(
        "systemd.failed_units", True, frozenset(), max_timeout_seconds=15
    ),
    "systemd.timers": ActionDefinition(
        "systemd.timers",
        True,
        frozenset(),
        frozenset({"limit"}),
        arguments_model=BoundedListArguments,
        max_timeout_seconds=10,
    ),
    "systemd.journal_tail": ActionDefinition(
        "systemd.journal_tail",
        True,
        frozenset({"unit"}),
        frozenset({"lines"}),
        arguments_model=JournalTailArguments,
        max_timeout_seconds=10,
    ),
    "systemd.journal_summary": ActionDefinition(
        "systemd.journal_summary",
        True,
        frozenset({"unit"}),
        frozenset({"window_minutes", "max_entries"}),
        arguments_model=JournalSummaryArguments,
        max_timeout_seconds=10,
    ),
    "systemd.restart": ActionDefinition(
        "systemd.restart",
        False,
        frozenset({"unit"}),
        risk="medium",
        max_timeout_seconds=30,
        expected_impact=(
            "The named systemd unit is restarted; active requests or connections may be interrupted."
        ),
        rollback=(
            "A restart is not reversible. Recovery requires a separately planned and approved action; "
            "RunbookOS will not restart again automatically."
        ),
    ),
    "systemd.start": ActionDefinition(
        "systemd.start",
        False,
        frozenset({"unit"}),
        risk="medium",
        max_timeout_seconds=30,
        expected_impact="The exact named campaign unit is started; the action does not restart active units.",
        rollback="A start is not reversible; stop requires a separate registered and approved action.",
    ),
    "dependency.restore_fixture": ActionDefinition(
        "dependency.restore_fixture",
        False,
        frozenset({"fixture_id"}),
        risk="medium",
        arguments_model=FixtureDependencyRestoreArguments,
        max_timeout_seconds=30,
        expected_impact="The named disposable upstream is started and its registered readiness endpoint is checked.",
        rollback="Only the campaign backend unit is addressed; a new approved plan is required for further changes.",
    ),
    "application.recover_worker": ActionDefinition(
        "application.recover_worker",
        False,
        frozenset({"fixture_id"}),
        risk="medium",
        arguments_model=FixtureApplicationRecoverArguments,
        max_timeout_seconds=30,
        expected_impact="The isolated worker unit is restarted and its bounded health socket is checked.",
        rollback="Only the campaign worker unit is addressed; a new approved plan is required for further changes.",
    ),
    "config.restore_fixture": ActionDefinition(
        "config.restore_fixture",
        False,
        frozenset({"fixture_id"}),
        risk="medium",
        arguments_model=FixtureConfigRestoreArguments,
        max_timeout_seconds=15,
        expected_impact="An allowlisted disposable fixture config is atomically restored from its root-owned known-good copy.",
        rollback="The fixture helper retains no operator-supplied path; a new plan is required for any further change.",
    ),
    "dns.restore_fixture": ActionDefinition(
        "dns.restore_fixture",
        False,
        frozenset({"fixture_id"}),
        risk="medium",
        arguments_model=FixtureDNSRestoreArguments,
        max_timeout_seconds=20,
        expected_impact="The isolated campaign resolver config is restored and its disposable resolver is reloaded.",
        rollback="Only the isolated fixture resolver is affected; a new plan is required for another change.",
    ),
    "network.restore_fixture": ActionDefinition(
        "network.restore_fixture",
        False,
        frozenset({"fixture_id"}),
        risk="high",
        arguments_model=FixtureNetworkRestoreArguments,
        max_timeout_seconds=15,
        expected_impact="Connectivity is restored only on the named campaign-owned network namespace link.",
        rollback="The helper is bound to the dedicated namespace and veth pair; shared host and gateway routes are not changed.",
    ),
    "storage.release_fixture": ActionDefinition(
        "storage.release_fixture",
        False,
        frozenset({"fixture_id"}),
        risk="medium",
        arguments_model=FixtureStorageReleaseArguments,
        max_timeout_seconds=15,
        expected_impact="Only bounded files in the disposable campaign volume are removed to release fixture capacity.",
        rollback="Deleted pressure files are not recoverable; the fixture generator can recreate bounded pressure for a new test.",
    ),
    "application.inspect_fixture": ActionDefinition(
        "application.inspect_fixture",
        True,
        frozenset({"fixture_id"}),
        arguments_model=FixtureInspectionArguments,
        max_timeout_seconds=4,
    ),
    "resource.inspect_fixture": ActionDefinition(
        "resource.inspect_fixture",
        True,
        frozenset({"fixture_id"}),
        arguments_model=FixtureResourceRestoreArguments,
        max_timeout_seconds=3,
    ),
    "resource.restore_fixture": ActionDefinition(
        "resource.restore_fixture",
        False,
        frozenset({"fixture_id"}),
        risk="medium",
        arguments_model=FixtureResourceRestoreArguments,
        max_timeout_seconds=20,
        expected_impact="The dedicated worker returns to its configured CPU quota and is restarted.",
        rollback="Only the disposable worker unit and its resource drop-in are changed.",
    ),
    "postgresql.start_fixture": ActionDefinition(
        "postgresql.start_fixture",
        False,
        frozenset({"cluster"}),
        risk="medium",
        arguments_model=FixturePostgresStartArguments,
        max_timeout_seconds=60,
        expected_impact="Only the dedicated PostgreSQL 16/b04 cluster is started.",
        rollback="The shared main cluster is not addressed; a separate plan is required to stop the disposable cluster.",
    ),
    "os.uptime": ActionDefinition("os.uptime", True, frozenset()),
    "os.cpu": ActionDefinition("os.cpu", True, frozenset(), max_timeout_seconds=3),
    "os.release": ActionDefinition("os.release", True, frozenset(), max_timeout_seconds=3),
    "os.memory": ActionDefinition("os.memory", True, frozenset()),
    "os.disk": ActionDefinition("os.disk", True, frozenset(), frozenset({"path"})),
    "os.packages": ActionDefinition(
        "os.packages",
        True,
        frozenset(),
        frozenset({"limit"}),
        arguments_model=BoundedListArguments,
        max_timeout_seconds=10,
    ),
    "os.cron": ActionDefinition(
        "os.cron",
        True,
        frozenset(),
        frozenset({"limit"}),
        arguments_model=CronSummaryArguments,
        max_timeout_seconds=5,
    ),
    "process.list": ActionDefinition(
        "process.list",
        True,
        frozenset(),
        frozenset({"order_by", "limit"}),
        arguments_model=ProcessListArguments,
        max_timeout_seconds=5,
    ),
    "process.inspect": ActionDefinition(
        "process.inspect",
        True,
        frozenset({"pid"}),
        arguments_model=ProcessIdentityArguments,
        max_timeout_seconds=3,
    ),
    "process.tree": ActionDefinition(
        "process.tree",
        True,
        frozenset({"pid"}),
        frozenset({"max_depth", "max_nodes"}),
        arguments_model=ProcessTreeArguments,
        max_timeout_seconds=5,
    ),
    "filesystem.mounts": ActionDefinition(
        "filesystem.mounts", True, frozenset(), max_timeout_seconds=5
    ),
    "filesystem.inodes": ActionDefinition(
        "filesystem.inodes",
        True,
        frozenset({"path"}),
        arguments_model=FilesystemPathArguments,
        max_timeout_seconds=3,
    ),
    "network.interfaces": ActionDefinition(
        "network.interfaces", True, frozenset(), max_timeout_seconds=15
    ),
    "network.routes": ActionDefinition("network.routes", True, frozenset(), max_timeout_seconds=15),
    "network.resolver_config": ActionDefinition("network.resolver_config", True, frozenset()),
    "network.dns_resolve": ActionDefinition(
        "network.dns_resolve",
        True,
        frozenset({"endpoint_id"}),
        arguments_model=ProbeArguments,
        max_timeout_seconds=5,
    ),
    "network.listener": ActionDefinition(
        "network.listener",
        True,
        frozenset({"endpoint_id"}),
        arguments_model=ProbeArguments,
        max_timeout_seconds=3,
    ),
    "network.tls_certificate": ActionDefinition(
        "network.tls_certificate",
        True,
        frozenset({"endpoint_id"}),
        arguments_model=ProbeArguments,
        max_timeout_seconds=10,
    ),
    "network.firewall_summary": ActionDefinition(
        "network.firewall_summary",
        True,
        frozenset(),
        max_timeout_seconds=5,
    ),
    "network.tcp_connect": ActionDefinition(
        "network.tcp_connect",
        True,
        frozenset({"endpoint_id"}),
        arguments_model=ProbeArguments,
        max_timeout_seconds=10,
    ),
    "network.reachability": ActionDefinition(
        "network.reachability",
        True,
        frozenset({"endpoint_id"}),
        arguments_model=ProbeArguments,
        max_timeout_seconds=10,
    ),
    "http.readiness": ActionDefinition(
        "http.readiness",
        True,
        frozenset({"endpoint_id"}),
        arguments_model=ProbeArguments,
        max_timeout_seconds=10,
    ),
    "postgresql.protocol_available": ActionDefinition(
        "postgresql.protocol_available",
        True,
        frozenset({"endpoint_id"}),
        arguments_model=ProbeArguments,
        max_timeout_seconds=10,
    ),
    "dns.resolve_fixture": ActionDefinition(
        "dns.resolve_fixture",
        True,
        frozenset({"fixture_id"}),
        arguments_model=FixtureDNSProbeArguments,
        max_timeout_seconds=3,
        expected_impact="Queries only the explicitly identified disposable Batch 04 DNS fixture.",
    ),
}
_UNIT = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.@:-]{0,127}\.(?:service|timer)$")


def validate_action(name: str, arguments: dict[str, Any]) -> ActionDefinition:
    definition = REGISTRY.get(name)
    if definition is None:
        raise ConfigurationError(
            f"unregistered action {name!r}; arbitrary commands are not supported"
        )
    keys = set(arguments)
    missing = definition.required_arguments - keys
    extra = keys - definition.required_arguments - definition.optional_arguments
    if missing or extra:
        raise ConfigurationError(
            f"invalid arguments for {name}: missing={sorted(missing)}, extra={sorted(extra)}"
        )
    if "unit" in arguments:
        unit = arguments["unit"]
        if not isinstance(unit, str) or not _UNIT.fullmatch(unit):
            raise ConfigurationError("unit must be a simple systemd .service unit name")
    if "path" in arguments:
        path = arguments["path"]
        if (
            not isinstance(path, str)
            or not path.startswith("/")
            or any(c in path for c in "\x00\n\r")
        ):
            raise ConfigurationError(
                "disk path must be an absolute path without control characters"
            )
    if definition.arguments_model is not None:
        try:
            definition.arguments_model.model_validate(arguments)
        except ValidationError as exc:
            raise ConfigurationError(f"invalid arguments for {name}") from exc
    return definition


def validate_argument_keys(name: str, arguments: dict[str, Any]) -> ActionDefinition:
    definition = REGISTRY.get(name)
    if definition is None:
        raise ConfigurationError(
            f"unregistered action {name!r}; arbitrary commands are not supported"
        )
    keys = set(arguments)
    missing = definition.required_arguments - keys
    extra = keys - definition.required_arguments - definition.optional_arguments
    if missing or extra:
        raise ConfigurationError(
            f"invalid arguments for {name}: missing={sorted(missing)}, extra={sorted(extra)}"
        )
    if definition.arguments_model is not None:
        try:
            definition.arguments_model.model_validate(arguments)
        except ValidationError as exc:
            raise ConfigurationError(f"invalid arguments for {name}") from exc
    return definition


def validate_phase_action(phase: str, name: str, arguments: dict[str, Any]) -> ActionDefinition:
    definition = validate_action(name, arguments)
    if phase in {"preflight", "postflight"} and not definition.read_only:
        raise ConfigurationError(f"{phase} action {name} must be read-only")
    return definition
