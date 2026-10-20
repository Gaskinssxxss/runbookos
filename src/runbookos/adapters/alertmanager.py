"""Narrow deterministic adapter for Prometheus Alertmanager webhook v2 payloads."""

from __future__ import annotations

import hashlib
from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from ..errors import ConfigurationError
from ..incidents import Alert, AlertCategory, Severity


class AMAlert(BaseModel):
    model_config = ConfigDict(extra="allow")
    status: str
    labels: dict[str, str]
    annotations: dict[str, str] = Field(default_factory=dict)
    startsAt: datetime
    fingerprint: str


class AMWebhook(BaseModel):
    model_config = ConfigDict(extra="allow")
    version: str
    status: str
    groupKey: str
    alerts: list[AMAlert] = Field(min_length=1, max_length=64)
    commonLabels: dict[str, str] = Field(default_factory=dict)
    commonAnnotations: dict[str, str] = Field(default_factory=dict)


def normalize_alertmanager(raw: bytes, authenticated_source: str) -> list[Alert]:
    """Normalize a v2 webhook group; only homogeneous target/service groups are accepted."""
    try:
        document = AMWebhook.model_validate_json(raw)
    except ValidationError as exc:
        raise ConfigurationError(f"invalid Alertmanager v2 payload: {exc}") from exc
    if document.version != "4" or document.status not in {"firing", "resolved"}:
        raise ConfigurationError("unsupported Alertmanager version or group status")
    if any(alert.status not in {"firing", "resolved"} for alert in document.alerts):
        raise ConfigurationError("unsupported Alertmanager alert status")
    targets = {item.labels.get("target_alias", "") for item in document.alerts}
    services = {item.labels.get("service", "") for item in document.alerts}
    if len(targets) != 1 or len(services) != 1:
        raise ConfigurationError("Alertmanager group must contain one target_alias and one service")
    target = next(iter(targets))
    service = next(iter(services))
    if not target or not service:
        raise ConfigurationError("Alertmanager labels must include target_alias and service")
    severities = [item.labels.get("severity", "warning") for item in document.alerts]
    if any(value not in {"info", "warning", "error", "critical"} for value in severities):
        raise ConfigurationError("Alertmanager severity label is invalid")
    severity = max(severities, key={"info": 0, "warning": 1, "error": 2, "critical": 3}.__getitem__)
    if document.status == "resolved":
        severity = "info"  # This is an informational alert only; it never resolves an incident.
    categories = {item.labels.get("category", "service") for item in document.alerts}
    if len(categories) != 1:
        raise ConfigurationError("Alertmanager group must have one category label")
    try:
        category = AlertCategory(next(iter(categories)))
        sev = Severity(severity)
    except ValueError as exc:
        raise ConfigurationError("Alertmanager category or severity is unsupported") from exc
    fingerprints = sorted(item.fingerprint for item in document.alerts)
    group_identity = document.groupKey + "\n" + "\n".join(fingerprints)
    digest = hashlib.sha256((authenticated_source + "\n" + group_identity).encode()).hexdigest()
    delivery_id = hashlib.sha256((digest + "\n" + document.status).encode()).hexdigest()
    summary = document.commonAnnotations.get("summary") or document.commonAnnotations.get(
        "description"
    )
    if not summary:
        summary = document.alerts[0].annotations.get("summary") or document.alerts[
            0
        ].annotations.get("description")
    if not summary:
        summary = (
            f"Alertmanager group {document.status} for {service} ({len(document.alerts)} alert(s))"
        )
    alert_time = min(item.startsAt for item in document.alerts)
    labels: dict[str, Any] = {"group_status": document.status, "alert_count": len(document.alerts)}
    # Preserve only bounded non-secret label names/values; strict Alert validation applies next.
    for key, value in sorted(document.commonLabels.items()):
        if key in {"alertname", "cluster", "namespace", "job"} and len(value) <= 128:
            labels[key.lower().replace("-", "_")] = value
    return [
        Alert(
            alert_id=f"am-{delivery_id[:48]}",
            source=authenticated_source,
            event_timestamp=alert_time,
            severity=sev,
            target_alias=target,
            service=service,
            category=category,
            summary=summary[:1000],
            fingerprint=f"am-{digest[:48]}",
            metadata=labels,
        )
    ]


def normalize_alertmanager_file(path, authenticated_source: str) -> list[Alert]:
    """File/CLI adapter entry point; the source must be provided by trusted configuration."""
    from pathlib import Path

    raw = Path(path).read_bytes()
    if len(raw) > 64 * 1024:
        raise ConfigurationError("Alertmanager payload exceeds 64 KiB")
    return normalize_alertmanager(raw, authenticated_source)
