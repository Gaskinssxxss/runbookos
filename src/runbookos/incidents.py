"""Alert ingestion and human-controlled incident lifecycle.

Alert data is descriptive only. It is never interpreted as a command or as authorization.
"""

from __future__ import annotations

import hashlib
import json
import re
import sqlite3
import time
import uuid
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator

from .config import load_inventory
from .errors import ConfigurationError, PolicyDenied
from .store import SQLiteStore, canonical_json, redact

MAX_ALERT_BYTES = 64 * 1024
_KEY = re.compile(r"^[a-z][a-z0-9_.-]{0,63}$")
_SENSITIVE_TEXT = (
    re.compile(r"(?i)\b(bearer\s+)[A-Za-z0-9._~+/=-]{12,}"),
    re.compile(r"(?i)\b(password|passwd|token|secret|api[_-]?key)\s*[:=]\s*[^\s,;]+"),
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----", re.S),
)


def _redact_text(value: str) -> str:
    for pattern in _SENSITIVE_TEXT:
        value = pattern.sub("[REDACTED]", value)
    return value


class Severity(StrEnum):
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"


class AlertCategory(StrEnum):
    SERVICE = "service"
    CONNECTIVITY = "connectivity"
    NETWORK = "network"
    DEPENDENCY = "dependency"
    CAPACITY = "capacity"
    SECURITY = "security"
    UNKNOWN = "unknown"


class Alert(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    alert_id: str = Field(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9_.:-]+$")
    source: str = Field(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9_.:-]+$")
    event_timestamp: datetime
    severity: Severity
    target_alias: str = Field(min_length=2, max_length=63, pattern=r"^[a-zA-Z0-9_.-]+$")
    service: str = Field(min_length=1, max_length=64, pattern=r"^[a-z][a-z0-9_.-]*$")
    category: AlertCategory
    summary: str = Field(min_length=1, max_length=1000)
    fingerprint: str = Field(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9_.:-]+$")
    metadata: dict[str, Any] = Field(default_factory=dict, max_length=32)

    @field_validator("event_timestamp")
    @classmethod
    def timestamp_has_timezone(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("event_timestamp must include a timezone")
        return value.astimezone(UTC)

    @field_validator("summary")
    @classmethod
    def bounded_plain_summary(cls, value: str) -> str:
        if not value.strip() or any(ord(char) < 32 and char not in "\t" for char in value):
            raise ValueError("summary must be non-empty and contain no control characters")
        return _redact_text(value.strip())

    @field_validator("metadata")
    @classmethod
    def bounded_metadata(cls, value: dict[str, Any]) -> dict[str, Any]:
        encoded = canonical_json(value).encode("utf-8")
        if len(encoded) > 8192:
            raise ValueError("metadata exceeds 8 KiB")

        def walk(item: Any, depth: int = 0) -> None:
            if depth > 4:
                raise ValueError("metadata nesting exceeds four levels")
            if isinstance(item, dict):
                for key, child in item.items():
                    if not isinstance(key, str) or not _KEY.fullmatch(key):
                        raise ValueError("metadata keys must be lowercase identifiers")
                    if any(
                        s in key
                        for s in (
                            "command",
                            "shell",
                            "exec",
                            "script",
                            "password",
                            "secret",
                            "token",
                            "credential",
                        )
                    ):
                        raise ValueError("metadata contains a prohibited command or secret field")
                    walk(child, depth + 1)
            elif isinstance(item, list):
                if len(item) > 32:
                    raise ValueError("metadata arrays are limited to 32 elements")
                for child in item:
                    walk(child, depth + 1)
            elif item is not None and not isinstance(item, (str, int, float, bool)):
                raise ValueError("metadata values must be JSON scalars, arrays, or objects")
            elif isinstance(item, str) and len(item) > 1000:
                raise ValueError("metadata strings are limited to 1000 characters")

        walk(value)

        def clean(item: Any) -> Any:
            if isinstance(item, dict):
                return {key: clean(child) for key, child in item.items()}
            if isinstance(item, list):
                return [clean(child) for child in item]
            if isinstance(item, str):
                return _redact_text(item)
            return item

        return clean(redact(value))


def _reject_duplicate_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON object key")
        result[key] = value
    return result


def parse_alert(raw: bytes) -> Alert:
    if len(raw) > MAX_ALERT_BYTES:
        raise ValueError("alert payload exceeds 64 KiB")
    try:
        data = json.loads(
            raw,
            object_pairs_hook=_reject_duplicate_pairs,
            parse_constant=lambda value: (_ for _ in ()).throw(ValueError(value)),
        )
        # JSON-mode validation permits JSON strings for enums and RFC3339 timestamps while
        # retaining strict rejection of coercions for all other fields.
        return Alert.model_validate_json(json.dumps(data, separators=(",", ":")))
    except (UnicodeDecodeError, json.JSONDecodeError, ValidationError, ValueError) as exc:
        raise ValueError(f"invalid alert: {exc}") from exc


def validate_target(alert: Alert, inventory_path: Path) -> None:
    inventory, _ = load_inventory(inventory_path)
    if alert.target_alias not in inventory.hosts:
        raise ConfigurationError(f"unknown target alias: {alert.target_alias}")


def _now() -> str:
    return datetime.now(UTC).isoformat()


_SEVERITY_ORDER = {"info": 0, "warning": 1, "error": 2, "critical": 3}
_TRANSITIONS = {
    "ACKNOWLEDGED": {"NEW"},
    "INVESTIGATING": {"ACKNOWLEDGED"},
    "RESOLVED": {"INVESTIGATING"},
    "CLOSED": {"RESOLVED"},
}


class IncidentStore:
    """Incident operations layered on the existing SQLite/audit database."""

    def __init__(self, store: SQLiteStore):
        self.store = store

    def ingest(
        self,
        alert: Alert,
        *,
        nonce: str | None = None,
        request_timestamp: int | None = None,
        auth_key_id: str | None = None,
    ) -> dict[str, Any]:
        now = _now()
        normalized = alert.model_dump(mode="json")
        fingerprint_payload = {
            "source": alert.source,
            "fingerprint": alert.fingerprint,
            "target_alias": alert.target_alias,
            "service": alert.service,
            "category": alert.category.value,
        }
        correlation_key = hashlib.sha256(canonical_json(fingerprint_payload).encode()).hexdigest()
        payload_hash = hashlib.sha256(canonical_json(normalized).encode()).hexdigest()
        with self.store._connection() as db:
            db.execute("BEGIN IMMEDIATE")
            if nonce:
                try:
                    db.execute(
                        "DELETE FROM webhook_nonces WHERE timestamp < ?",
                        (int(time.time()) - 300,),
                    )
                    db.execute(
                        "INSERT INTO webhook_nonces VALUES(?,?,?,?)",
                        ("webhook-v1", nonce, request_timestamp, now),
                    )
                except sqlite3.IntegrityError as exc:
                    self.store._audit(
                        db,
                        "webhook.replay_rejected",
                        {"nonce_sha256": hashlib.sha256(nonce.encode()).hexdigest()},
                    )
                    db.commit()
                    raise PolicyDenied("webhook request nonce has already been used") from exc
            prior = db.execute(
                "SELECT payload_sha256 FROM alerts WHERE source=? AND alert_id=?",
                (alert.source, alert.alert_id),
            ).fetchone()
            if prior:
                if prior["payload_sha256"] != payload_hash:
                    self.store._audit(
                        db,
                        "alert.id_conflict_rejected",
                        {"source": alert.source, "alert_id": alert.alert_id},
                    )
                    db.commit()
                    raise PolicyDenied("alert ID was already used with a different payload")
                link = db.execute(
                    "SELECT incident_id FROM incident_alerts WHERE source=? AND alert_id=?",
                    (alert.source, alert.alert_id),
                ).fetchone()
                self.store._audit(
                    db,
                    "alert.duplicate_delivery",
                    {
                        "source": alert.source,
                        "alert_id": alert.alert_id,
                        "payload_sha256": payload_hash,
                        "incident_id": link["incident_id"],
                    },
                )
                db.commit()
                return {"duplicate_delivery": True, "incident_id": link["incident_id"]}

            matched = db.execute(
                "SELECT incident_id,severity FROM incidents WHERE correlation_key=? AND status!='CLOSED' ORDER BY created_at LIMIT 1",
                (correlation_key,),
            ).fetchone()
            if matched:
                incident_id = matched["incident_id"]
                reason = "exact source+fingerprint+target+service+category match to open incident"
                new_severity = max(
                    (matched["severity"], alert.severity.value), key=_SEVERITY_ORDER.__getitem__
                )
                db.execute(
                    "UPDATE incidents SET severity=?,updated_at=?,version=version+1 WHERE incident_id=?",
                    (new_severity, now, incident_id),
                )
                created = False
            else:
                incident_id = str(uuid.uuid4())
                reason = "new incident: no exact open correlation key match"
                db.execute(
                    "INSERT INTO incidents(incident_id,severity,target_alias,service,category,summary,status,correlation_key,correlation_reason,created_at,updated_at) VALUES(?,?,?,?,?,?,'NEW',?,?,?,?)",
                    (
                        incident_id,
                        alert.severity.value,
                        alert.target_alias,
                        alert.service,
                        alert.category.value,
                        alert.summary,
                        correlation_key,
                        reason,
                        now,
                        now,
                    ),
                )
                created = True
                db.execute(
                    "INSERT INTO incident_events VALUES(?,?,?,?,?,?,?,?,?)",
                    (
                        str(uuid.uuid4()),
                        incident_id,
                        "incident.created",
                        alert.source,
                        None,
                        "NEW",
                        reason,
                        now,
                        "{}",
                    ),
                )
            db.execute(
                "INSERT INTO alerts VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
                (
                    alert.source,
                    alert.alert_id,
                    alert.fingerprint,
                    alert.event_timestamp.isoformat(),
                    now,
                    alert.severity.value,
                    alert.target_alias,
                    alert.service,
                    alert.category.value,
                    alert.summary,
                    canonical_json(alert.metadata),
                    payload_hash,
                ),
            )
            db.execute(
                "INSERT INTO incident_alerts VALUES(?,?,?,?,?)",
                (alert.source, alert.alert_id, incident_id, now, reason),
            )
            if not created:
                db.execute(
                    "INSERT INTO incident_events VALUES(?,?,?,?,?,?,?,?,?)",
                    (
                        str(uuid.uuid4()),
                        incident_id,
                        "alert.correlated",
                        alert.source,
                        None,
                        None,
                        reason,
                        now,
                        canonical_json({"alert_id": alert.alert_id}),
                    ),
                )
            self.store._audit(
                db,
                "alert.ingested",
                {
                    "source": alert.source,
                    "alert_id": alert.alert_id,
                    "payload_sha256": payload_hash,
                    "incident_id": incident_id,
                    "duplicate_delivery": False,
                    "auth_key_id": auth_key_id,
                },
            )
            self.store._audit(
                db,
                "alert.correlated",
                {
                    "source": alert.source,
                    "alert_id": alert.alert_id,
                    "incident_id": incident_id,
                    "reason": reason,
                    "created": created,
                },
            )
            db.commit()
        return {
            "duplicate_delivery": False,
            "created": created,
            "incident_id": incident_id,
            "correlation_reason": reason,
        }

    def transition(
        self,
        incident_id: str,
        to_status: str,
        actor: str,
        reason: str,
        *,
        evidence_status: str | None = None,
    ) -> dict[str, Any]:
        if (
            to_status not in _TRANSITIONS
            or not reason.strip()
            or len(reason) > 500
            or not actor.strip()
            or len(actor) > 128
        ):
            raise ValueError("invalid transition, actor, or reason")
        now = _now()
        with self.store._connection() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute(
                "SELECT status FROM incidents WHERE incident_id=?", (incident_id,)
            ).fetchone()
            if not row:
                db.rollback()
                raise ConfigurationError(f"incident not found: {incident_id}")
            old = row["status"]
            if old not in _TRANSITIONS[to_status]:
                db.rollback()
                raise PolicyDenied(f"incident transition {old} -> {to_status} is not allowed")
            event_details: dict[str, str] = {}
            if to_status == "RESOLVED":
                if evidence_status not in {"verified", "not_available", "inconclusive"}:
                    db.rollback()
                    raise PolicyDenied(
                        "resolution requires evidence_status: verified, not_available, or inconclusive"
                    )
                linked = db.execute(
                    "SELECT evidence_refs_json FROM incident_investigations WHERE incident_id=?",
                    (incident_id,),
                ).fetchall()
                has_linked_evidence = any(json.loads(item["evidence_refs_json"]) for item in linked)
                if evidence_status == "verified" and not has_linked_evidence:
                    db.rollback()
                    raise PolicyDenied(
                        "evidence_status=verified requires linked verified evidence references"
                    )
                if evidence_status != "verified" and has_linked_evidence:
                    db.rollback()
                    raise PolicyDenied("linked verified evidence requires evidence_status=verified")
                event_details["evidence_status"] = evidence_status
            resolved_at = now if to_status == "RESOLVED" else None
            closed_at = now if to_status == "CLOSED" else None
            db.execute(
                "UPDATE incidents SET status=?,updated_at=?,resolved_at=COALESCE(?,resolved_at),closed_at=COALESCE(?,closed_at),version=version+1 WHERE incident_id=? AND status=?",
                (to_status, now, resolved_at, closed_at, incident_id, old),
            )
            db.execute(
                "INSERT INTO incident_events VALUES(?,?,?,?,?,?,?,?,?)",
                (
                    str(uuid.uuid4()),
                    incident_id,
                    "incident.transition",
                    actor,
                    old,
                    to_status,
                    reason,
                    now,
                    canonical_json(event_details),
                ),
            )
            self.store._audit(
                db,
                "incident.transition",
                {
                    "incident_id": incident_id,
                    "actor": actor,
                    "from_status": old,
                    "to_status": to_status,
                    "reason": reason,
                    **event_details,
                },
            )
            db.commit()
        return self.show(incident_id)

    def mark_investigating(self, incident_id: str, actor: str) -> dict[str, Any]:
        return self.transition(
            incident_id, "INVESTIGATING", actor, "operator explicitly started diagnostics"
        )

    def link_investigation(
        self,
        incident_id: str,
        investigation_id: str,
        execution_ids: list[str],
        evidence_refs: list[str],
    ) -> None:
        if any(not re.fullmatch(r"[0-9a-f-]{36}:[a-zA-Z0-9_-]+", ref) for ref in evidence_refs):
            raise PolicyDenied("invalid evidence reference")
        now = _now()
        with self.store._connection() as db:
            db.execute("BEGIN IMMEDIATE")
            if not db.execute(
                "SELECT 1 FROM incidents WHERE incident_id=?", (incident_id,)
            ).fetchone():
                db.rollback()
                raise ConfigurationError("incident not found")
            inv = db.execute(
                "SELECT result_json FROM investigations WHERE investigation_id=?",
                (investigation_id,),
            ).fetchone()
            if not inv:
                db.rollback()
                raise PolicyDenied("investigation reference does not exist")
            result = json.loads(inv["result_json"])
            actual_refs = {item["ref"] for item in result.get("verified_evidence", [])}
            known_executions = {
                row["execution_id"]
                for row in db.execute("SELECT execution_id FROM executions").fetchall()
            }
            successful_steps = {
                f"{row['execution_id']}:{row['step_id']}"
                for row in db.execute(
                    "SELECT execution_id,step_id FROM step_results WHERE status='succeeded'"
                ).fetchall()
            }
            if (
                not set(evidence_refs) <= actual_refs
                or not set(evidence_refs) <= successful_steps
                or not set(execution_ids) <= known_executions
            ):
                db.rollback()
                raise PolicyDenied("investigation linkage contains forged evidence")
            db.execute(
                "INSERT INTO incident_investigations VALUES(?,?,?,?,?)",
                (
                    incident_id,
                    investigation_id,
                    now,
                    canonical_json(execution_ids),
                    canonical_json(evidence_refs),
                ),
            )
            db.execute(
                "INSERT INTO incident_events VALUES(?,?,?,?,?,?,?,?,?)",
                (
                    str(uuid.uuid4()),
                    incident_id,
                    "incident.investigation_linked",
                    "runbookos",
                    None,
                    None,
                    "verified references linked",
                    now,
                    canonical_json(
                        {
                            "investigation_id": investigation_id,
                            "execution_ids": execution_ids,
                            "evidence_refs": evidence_refs,
                        }
                    ),
                ),
            )
            self.store._audit(
                db,
                "incident.investigation_linked",
                {
                    "incident_id": incident_id,
                    "investigation_id": investigation_id,
                    "execution_ids": execution_ids,
                    "evidence_refs": evidence_refs,
                },
            )
            db.commit()

    def show(self, incident_id: str) -> dict[str, Any]:
        with self.store._connection() as db:
            row = db.execute(
                "SELECT * FROM incidents WHERE incident_id=?", (incident_id,)
            ).fetchone()
            if not row:
                raise ConfigurationError(f"incident not found: {incident_id}")
            alerts = db.execute(
                "SELECT a.source,a.alert_id,a.event_timestamp,a.received_at,ia.correlation_reason FROM alerts a JOIN incident_alerts ia USING(source,alert_id) WHERE ia.incident_id=? ORDER BY a.received_at",
                (incident_id,),
            ).fetchall()
            events = db.execute(
                "SELECT * FROM incident_events WHERE incident_id=? ORDER BY created_at,event_id",
                (incident_id,),
            ).fetchall()
            investigations = db.execute(
                "SELECT * FROM incident_investigations WHERE incident_id=? ORDER BY linked_at",
                (incident_id,),
            ).fetchall()
        return dict(row) | {
            "alerts": [dict(x) for x in alerts],
            "events": [dict(x) for x in events],
            "investigations": [
                dict(x)
                | {
                    "execution_ids": json.loads(x["execution_ids_json"]),
                    "evidence_refs": json.loads(x["evidence_refs_json"]),
                }
                for x in investigations
            ],
        }

    def list(self, status: str | None = None, limit: int = 100) -> list[dict[str, Any]]:
        if status and status not in {"NEW", "ACKNOWLEDGED", "INVESTIGATING", "RESOLVED", "CLOSED"}:
            raise ValueError("invalid incident status")
        with self.store._connection() as db:
            rows = db.execute(
                "SELECT incident_id,severity,target_alias,service,category,status,created_at,updated_at FROM incidents WHERE (? IS NULL OR status=?) ORDER BY updated_at DESC LIMIT ?",
                (status, status, limit),
            ).fetchall()
        return [dict(row) for row in rows]

    def alert_list(self, limit: int = 100) -> list[dict[str, Any]]:
        with self.store._connection() as db:
            rows = db.execute(
                "SELECT a.source,a.alert_id,a.event_timestamp,a.severity,a.target_alias,a.service,a.category,a.payload_sha256,ia.incident_id FROM alerts a JOIN incident_alerts ia USING(source,alert_id) ORDER BY a.received_at DESC LIMIT ?",
                (limit,),
            ).fetchall()
        return [dict(row) for row in rows]
