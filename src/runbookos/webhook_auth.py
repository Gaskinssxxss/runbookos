"""Explicit per-source HMAC credentials and bounded key-rotation policy."""

from __future__ import annotations

import hashlib
import hmac
import os
import re
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator, model_validator

from .config import read_yaml
from .errors import ConfigurationError, PolicyDenied


class KeyConfig(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    secret_env: str = Field(pattern=r"^[A-Z][A-Z0-9_]{2,127}$")
    state: Literal["active", "grace", "revoked"]
    expires_at: datetime | None = None

    @model_validator(mode="after")
    def expiry_rules(self):
        if self.state == "grace" and self.expires_at is None:
            raise ValueError("grace keys require an explicit expiry")
        if self.state != "grace" and self.expires_at is not None:
            raise ValueError("only grace keys may specify expires_at")
        if self.expires_at and self.expires_at.tzinfo is None:
            raise ValueError("key expiry must include a timezone")
        return self


class SourceConfig(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    enabled: bool
    keys: dict[str, KeyConfig] = Field(min_length=1, max_length=8)
    active_key_id: str = Field(pattern=r"^[A-Za-z0-9_.-]{1,64}$")

    @field_validator("keys")
    @classmethod
    def valid_key_ids(cls, value):
        if any(not re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", key_id) for key_id in value):
            raise ValueError("key IDs must be bounded identifiers")
        return value

    @model_validator(mode="after")
    def active_key_valid(self):
        if self.active_key_id not in self.keys:
            raise ValueError("active_key_id must reference a configured key")
        if self.keys[self.active_key_id].state != "active":
            raise ValueError("active_key_id must reference a key in active state")
        if sum(key.state == "active" for key in self.keys.values()) != 1:
            raise ValueError("each source must have exactly one active key")
        return self


class AuthConfig(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    schema_version: Literal[1]
    mode: Literal["per_source", "legacy_single_source"]
    max_timestamp_skew_seconds: int = Field(default=300, ge=30, le=900)
    sources: dict[str, SourceConfig] = Field(min_length=1, max_length=32)

    @field_validator("sources")
    @classmethod
    def valid_source_names(cls, value):
        if any(not re.fullmatch(r"[A-Za-z0-9_.:-]{1,128}", source) for source in value):
            raise ValueError("source names must be bounded identifiers")
        all_key_ids = [key_id for source in value.values() for key_id in source.keys]
        if len(all_key_ids) != len(set(all_key_ids)):
            raise ValueError("key IDs must be unique across configured sources")
        return value

    @model_validator(mode="after")
    def legacy_is_explicit_and_single(self):
        if self.mode == "legacy_single_source" and len(self.sources) != 1:
            raise ValueError("legacy_single_source mode must define exactly one source")
        return self


def load_auth_config(path: Path) -> AuthConfig:
    path = path.expanduser().resolve()
    if path.stat().st_size > 32 * 1024:
        raise ConfigurationError("webhook auth config exceeds 32 KiB")
    try:
        raw, _ = read_yaml(path)
        return AuthConfig.model_validate(raw)
    except (OSError, ValidationError, ConfigurationError) as exc:
        raise ConfigurationError(f"invalid webhook auth config: {exc}") from exc


def verify_request(
    config: AuthConfig,
    *,
    key_id: str,
    timestamp: str,
    nonce: str,
    signature: str,
    body: bytes,
    now: int | None = None,
) -> str:
    """Return authenticated source identity or reject without revealing key status."""
    if config.mode == "legacy_single_source":
        source, source_config = next(iter(config.sources.items()))
        key_id = key_id or source_config.active_key_id
        if key_id != source_config.active_key_id:
            raise PolicyDenied("webhook authentication failed")
        key = source_config.keys[key_id]
    else:
        source = next(
            (name for name, entry in config.sources.items() if key_id in entry.keys), None
        )
        if source is None:
            raise PolicyDenied("webhook authentication failed")
        source_config = config.sources[source]
        key = source_config.keys[key_id]
    current = int(time.time()) if now is None else now
    if not source_config.enabled or key.state == "revoked":
        raise PolicyDenied("webhook authentication failed")
    if key.state == "grace":
        expires_at = int(key.expires_at.astimezone(UTC).timestamp())
        if current >= expires_at:
            raise PolicyDenied("webhook authentication failed")
    if (
        not timestamp.isdecimal()
        or abs(current - int(timestamp)) > config.max_timestamp_skew_seconds
    ):
        raise PolicyDenied("webhook authentication failed")
    if not re.fullmatch(r"[A-Za-z0-9_-]{16,128}", nonce):
        raise PolicyDenied("webhook authentication failed")
    if not re.fullmatch(r"[0-9a-f]{64}", signature):
        raise PolicyDenied("webhook authentication failed")
    secret = os.environ.get(key.secret_env)
    if not secret or len(secret.encode()) < 32:
        raise ConfigurationError(
            f"webhook key environment variable is missing or too short: {key.secret_env}"
        )
    # Key ID is signed as part of the canonical request, preventing cross-version replay
    # confusion while the database nonce uniqueness remains global across all key IDs.
    if config.mode == "legacy_single_source":
        message = timestamp.encode() + b"\n" + nonce.encode() + b"\n" + body
    else:
        message = (
            key_id.encode() + b"\n" + timestamp.encode() + b"\n" + nonce.encode() + b"\n" + body
        )
    expected = hmac.new(secret.encode(), message, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(signature, expected):
        raise PolicyDenied("webhook authentication failed")
    return source


def active_key_env_name(config: AuthConfig, source: str) -> tuple[str, str]:
    source_config = config.sources[source]
    key_id = source_config.active_key_id
    return key_id, source_config.keys[key_id].secret_env


def validate_active_key_material(config: AuthConfig) -> None:
    """Fail startup when an enabled source has no usable active HMAC key."""
    for source, source_config in config.sources.items():
        if not source_config.enabled:
            continue
        key = source_config.keys[source_config.active_key_id]
        secret = os.environ.get(key.secret_env)
        if secret is None or len(secret.encode()) < 32:
            raise ConfigurationError(
                f"active webhook key material is unavailable for source: {source}"
            )
