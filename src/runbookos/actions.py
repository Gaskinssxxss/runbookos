from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from .errors import ConfigurationError


class ProbeArguments(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    endpoint_id: str = Field(pattern=r"^[a-z][a-z0-9_-]{1,62}$")


@dataclass(frozen=True)
class ActionDefinition:
    name: str
    read_only: bool
    required_arguments: frozenset[str]
    optional_arguments: frozenset[str] = frozenset()
    risk: str = "low"
    arguments_model: type[BaseModel] | None = None
    max_timeout_seconds: int = 300


REGISTRY: dict[str, ActionDefinition] = {
    "systemd.is_active": ActionDefinition("systemd.is_active", True, frozenset({"unit"})),
    "systemd.failed_units": ActionDefinition("systemd.failed_units", True, frozenset()),
    "systemd.restart": ActionDefinition(
        "systemd.restart", False, frozenset({"unit"}), risk="medium"
    ),
    "os.uptime": ActionDefinition("os.uptime", True, frozenset()),
    "os.memory": ActionDefinition("os.memory", True, frozenset()),
    "os.disk": ActionDefinition("os.disk", True, frozenset(), frozenset({"path"})),
    "network.interfaces": ActionDefinition("network.interfaces", True, frozenset()),
    "network.routes": ActionDefinition("network.routes", True, frozenset()),
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
