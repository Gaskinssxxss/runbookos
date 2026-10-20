from __future__ import annotations

import hashlib
import os
import re
from pathlib import Path
from typing import Any, TypeVar

import yaml
from pydantic import ValidationError

from .errors import ConfigurationError
from .models import Inventory, Policy, Runbook, SSHProfile

T = TypeVar("T")
_ENV = re.compile(r"^\$\{ENV:([A-Z][A-Z0-9_]*)\}$")


class UniqueKeyLoader(yaml.SafeLoader):
    pass


def _construct_mapping(loader: UniqueKeyLoader, node: yaml.MappingNode, deep: bool = False) -> dict:
    loader.flatten_mapping(node)
    result: dict[Any, Any] = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        if key in result:
            raise ConfigurationError(f"duplicate YAML key: {key!r}")
        result[key] = loader.construct_object(value_node, deep=deep)
    return result


UniqueKeyLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _construct_mapping)


def read_yaml(path: Path) -> tuple[Any, str]:
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise ConfigurationError(f"cannot read {path}: {exc}") from exc
    if len(raw) > 1_000_000:
        raise ConfigurationError(f"configuration is too large (>1 MiB): {path}")
    try:
        document = yaml.load(raw, Loader=UniqueKeyLoader)
    except (yaml.YAMLError, ConfigurationError) as exc:
        raise ConfigurationError(f"invalid YAML in {path}: {exc}") from exc
    if not isinstance(document, dict):
        raise ConfigurationError(f"expected a YAML mapping in {path}")
    return document, hashlib.sha256(raw).hexdigest()


def _parse(model: type[T], raw: Any, path: Path) -> T:
    try:
        return model.model_validate(raw)
    except ValidationError as exc:
        raise ConfigurationError(f"schema validation failed for {path}: {exc}") from exc


def load_runbook(path: Path) -> tuple[Runbook, str]:
    raw, digest = read_yaml(path)
    return _parse(Runbook, raw, path), digest


def load_inventory(path: Path) -> tuple[Inventory, str]:
    raw, digest = read_yaml(path)
    return _parse(Inventory, raw, path), digest


def load_policy(path: Path) -> tuple[Policy, str]:
    raw, digest = read_yaml(path)
    return _parse(Policy, raw, path), digest


def _resolve_path(value: str, base: Path) -> str:
    match = _ENV.fullmatch(value)
    if match:
        variable = match.group(1)
        resolved = os.environ.get(variable)
        if not resolved:
            raise ConfigurationError(f"environment variable {variable} is required by SSH profile")
        value = resolved
    elif "${" in value or "$ENV" in value:
        raise ConfigurationError("only exact ${ENV:VARIABLE} SSH path references are supported")
    path = Path(value).expanduser()
    if not path.is_absolute():
        path = base / path
    return str(path.resolve())


def load_ssh_profiles(path: Path, resolve_paths: bool = True) -> tuple[dict[str, SSHProfile], str]:
    raw, digest = read_yaml(path)
    if raw.get("schema_version") != 1 or not isinstance(raw.get("profiles"), dict):
        raise ConfigurationError(f"{path}: expected schema_version: 1 and profiles mapping")
    profiles: dict[str, SSHProfile] = {}
    for name, data in raw["profiles"].items():
        try:
            item = SSHProfile.model_validate(data)
        except ValidationError as exc:
            raise ConfigurationError(f"invalid SSH profile {name!r} in {path}: {exc}") from exc
        if resolve_paths:
            item = item.model_copy(
                update={
                    "identity_file": _resolve_path(item.identity_file, path.parent),
                    "known_hosts_file": _resolve_path(item.known_hosts_file, path.parent),
                }
            )
        profiles[name] = item
    return profiles, digest


def file_digest(path: Path) -> str:
    try:
        digest = hashlib.sha256()
        with path.open("rb") as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(chunk)
        return digest.hexdigest()
    except OSError as exc:
        raise ConfigurationError(f"cannot hash {path}: {exc}") from exc
