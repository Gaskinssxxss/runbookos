from __future__ import annotations

import hashlib
import json
import math
import os
import re
import sqlite3
import time
import uuid
from contextlib import contextmanager
from datetime import UTC
from pathlib import Path
from typing import Any

from .errors import ApprovalError, ConfigurationError

_ZERO_HASH = "0" * 64
_SECRET_KEYS = (
    "password",
    "secret",
    "token",
    "credential",
    "private_key",
    "api_key",
    "api-key",
    "authorization",
)


def canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def plan_document_hash(document: dict[str, Any]) -> str:
    body = {
        key: value
        for key, value in document.items()
        if key not in {"plan_id", "created_at", "plan_hash"}
    }
    return hashlib.sha256(canonical_json(body).encode()).hexdigest()


def redact(value: Any) -> Any:
    if isinstance(value, dict):
        return {
            key: (
                "[REDACTED]" if any(part in key.lower() for part in _SECRET_KEYS) else redact(item)
            )
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [redact(item) for item in value]
    return value


class SQLiteStore:
    def __init__(self, path: Path) -> None:
        self.path = path.expanduser().resolve()
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        old_umask = os.umask(0o077)
        try:
            self._initialize()
        finally:
            os.umask(old_umask)
        os.chmod(self.path, 0o600)

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, timeout=10, isolation_level=None)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute("PRAGMA busy_timeout=10000")
        return connection

    @contextmanager
    def _connection(self):
        connection = self._connect()
        try:
            yield connection
        finally:
            connection.close()

    def _initialize(self) -> None:
        with self._connection() as db:
            db.execute("PRAGMA journal_mode=WAL")
            version = db.execute("PRAGMA user_version").fetchone()[0]
            if version not in (0, 1, 2, 3, 4):
                raise ConfigurationError(f"unsupported RunbookOS database version: {version}")
            db.executescript("""
                CREATE TABLE IF NOT EXISTS plans (
                    plan_id TEXT PRIMARY KEY,
                    plan_hash TEXT NOT NULL,
                    document_json TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS approvals (
                    approval_id TEXT PRIMARY KEY,
                    plan_id TEXT NOT NULL REFERENCES plans(plan_id),
                    plan_hash TEXT NOT NULL,
                    actor TEXT NOT NULL,
                    reason TEXT NOT NULL,
                    created_at REAL NOT NULL,
                    expires_at REAL NOT NULL,
                    used_at REAL
                );
                CREATE INDEX IF NOT EXISTS approvals_plan_idx ON approvals(plan_id);
                CREATE TABLE IF NOT EXISTS executions (
                    execution_id TEXT PRIMARY KEY,
                    plan_id TEXT NOT NULL REFERENCES plans(plan_id),
                    status TEXT NOT NULL,
                    started_at TEXT NOT NULL,
                    finished_at TEXT,
                    summary_json TEXT NOT NULL DEFAULT '{}'
                );
                CREATE TABLE IF NOT EXISTS step_results (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    execution_id TEXT NOT NULL REFERENCES executions(execution_id),
                    target TEXT NOT NULL,
                    phase TEXT NOT NULL,
                    step_id TEXT NOT NULL,
                    action TEXT NOT NULL,
                    status TEXT NOT NULL,
                    started_at TEXT NOT NULL,
                    finished_at TEXT NOT NULL,
                    evidence_json TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS audit_events (
                    sequence INTEGER PRIMARY KEY,
                    created_at TEXT NOT NULL,
                    kind TEXT NOT NULL,
                    payload_json TEXT NOT NULL,
                    previous_hash TEXT NOT NULL,
                    event_hash TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS investigations (
                    investigation_id TEXT PRIMARY KEY,
                    status TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    incident_sha256 TEXT NOT NULL,
                    result_json TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS investigations_created_idx
                    ON investigations(created_at DESC);
            """)
            # Additive v0.3 incident schema. Existing execution/audit rows are untouched.
            migration = """
                CREATE TABLE IF NOT EXISTS incidents (
                    incident_id TEXT PRIMARY KEY,
                    severity TEXT NOT NULL CHECK(severity IN ('info','warning','error','critical')),
                    target_alias TEXT NOT NULL,
                    service TEXT NOT NULL,
                    category TEXT NOT NULL,
                    summary TEXT NOT NULL,
                    status TEXT NOT NULL CHECK(status IN ('NEW','ACKNOWLEDGED','INVESTIGATING','RESOLVED','CLOSED')),
                    correlation_key TEXT NOT NULL,
                    correlation_reason TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    resolved_at TEXT,
                    closed_at TEXT,
                    version INTEGER NOT NULL DEFAULT 0
                );
                CREATE INDEX IF NOT EXISTS incidents_status_updated_idx ON incidents(status, updated_at DESC);
                CREATE INDEX IF NOT EXISTS incidents_correlation_idx ON incidents(correlation_key, status);
                CREATE TABLE IF NOT EXISTS alerts (
                    source TEXT NOT NULL,
                    alert_id TEXT NOT NULL,
                    fingerprint TEXT NOT NULL,
                    event_timestamp TEXT NOT NULL,
                    received_at TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    target_alias TEXT NOT NULL,
                    service TEXT NOT NULL,
                    category TEXT NOT NULL,
                    summary TEXT NOT NULL,
                    metadata_json TEXT NOT NULL,
                    payload_sha256 TEXT NOT NULL,
                    PRIMARY KEY(source, alert_id)
                );
                CREATE TABLE IF NOT EXISTS incident_alerts (
                    source TEXT NOT NULL,
                    alert_id TEXT NOT NULL,
                    incident_id TEXT NOT NULL REFERENCES incidents(incident_id),
                    linked_at TEXT NOT NULL,
                    correlation_reason TEXT NOT NULL,
                    PRIMARY KEY(source, alert_id),
                    FOREIGN KEY(source, alert_id) REFERENCES alerts(source, alert_id)
                );
                CREATE INDEX IF NOT EXISTS incident_alerts_incident_idx ON incident_alerts(incident_id);
                CREATE TABLE IF NOT EXISTS incident_events (
                    event_id TEXT PRIMARY KEY,
                    incident_id TEXT NOT NULL REFERENCES incidents(incident_id),
                    event_type TEXT NOT NULL,
                    actor TEXT NOT NULL,
                    from_status TEXT,
                    to_status TEXT,
                    reason TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    details_json TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS incident_events_timeline_idx ON incident_events(incident_id, created_at);
                CREATE TABLE IF NOT EXISTS incident_investigations (
                    incident_id TEXT NOT NULL REFERENCES incidents(incident_id),
                    investigation_id TEXT NOT NULL REFERENCES investigations(investigation_id),
                    linked_at TEXT NOT NULL,
                    execution_ids_json TEXT NOT NULL,
                    evidence_refs_json TEXT NOT NULL,
                    PRIMARY KEY(incident_id, investigation_id)
                );
                CREATE TABLE IF NOT EXISTS webhook_nonces (
                    source TEXT NOT NULL,
                    nonce TEXT NOT NULL,
                    timestamp INTEGER NOT NULL,
                    received_at TEXT NOT NULL,
                    PRIMARY KEY(source, nonce)
                );
                CREATE INDEX IF NOT EXISTS webhook_nonces_timestamp_idx ON webhook_nonces(timestamp);
            """
            if version < 3:
                db.execute("BEGIN IMMEDIATE")
                try:
                    for statement in migration.split(";"):
                        if statement.strip():
                            db.execute(statement)
                    db.execute("PRAGMA user_version=3")
                    db.commit()
                except Exception:
                    db.rollback()
                    raise
            if version < 4:
                remediation_links = """
                    CREATE TABLE IF NOT EXISTS incident_remediation_plans (
                        association_id TEXT PRIMARY KEY,
                        incident_id TEXT NOT NULL REFERENCES incidents(incident_id),
                        plan_id TEXT NOT NULL UNIQUE REFERENCES plans(plan_id),
                        plan_hash TEXT NOT NULL,
                        target TEXT NOT NULL,
                        action_id TEXT NOT NULL,
                        actor TEXT NOT NULL,
                        associated_at TEXT NOT NULL,
                        UNIQUE(incident_id, plan_id)
                    );
                    CREATE INDEX IF NOT EXISTS incident_remediation_incident_idx
                        ON incident_remediation_plans(incident_id, associated_at);
                """
                db.execute("BEGIN IMMEDIATE")
                try:
                    for statement in remediation_links.split(";"):
                        if statement.strip():
                            db.execute(statement)
                    db.execute("PRAGMA user_version=4")
                    db.commit()
                except Exception:
                    db.rollback()
                    raise

    def _audit(self, db: sqlite3.Connection, kind: str, payload: dict[str, Any]) -> None:
        prior = db.execute(
            "SELECT sequence,event_hash FROM audit_events ORDER BY sequence DESC LIMIT 1"
        ).fetchone()
        seq = prior["sequence"] + 1 if prior else 1
        previous = prior["event_hash"] if prior else _ZERO_HASH
        from datetime import datetime

        created = datetime.now(UTC).isoformat()
        clean = redact(payload)
        body = {
            "sequence": seq,
            "created_at": created,
            "kind": kind,
            "payload": clean,
            "previous_hash": previous,
        }
        digest = hashlib.sha256(canonical_json(body).encode()).hexdigest()
        db.execute(
            "INSERT INTO audit_events VALUES (?,?,?,?,?,?)",
            (seq, created, kind, canonical_json(clean), previous, digest),
        )

    def create_plan(self, document: dict[str, Any]) -> None:
        with self._connection() as db:
            db.execute("BEGIN IMMEDIATE")
            db.execute(
                "INSERT INTO plans(plan_id,plan_hash,document_json,created_at) VALUES(?,?,?,?)",
                (
                    document["plan_id"],
                    document["plan_hash"],
                    canonical_json(document),
                    document["created_at"],
                ),
            )
            self._audit(
                db,
                "plan.created",
                {
                    "plan_id": document["plan_id"],
                    "plan_hash": document["plan_hash"],
                    "status": document["status"],
                },
            )
            db.commit()

    def get_plan(self, plan_id: str) -> dict[str, Any]:
        with self._connection() as db:
            row = db.execute(
                "SELECT document_json FROM plans WHERE plan_id=?", (plan_id,)
            ).fetchone()
        if not row:
            raise ConfigurationError(f"plan not found: {plan_id}")
        return json.loads(row["document_json"])

    def create_approval(
        self, plan_id: str, plan_hash: str, actor: str, reason: str, ttl: int
    ) -> str:
        now = time.time()
        approval_id = str(uuid.uuid4())
        with self._connection() as db:
            db.execute("BEGIN IMMEDIATE")
            plan = db.execute(
                "SELECT plan_hash,document_json FROM plans WHERE plan_id=?", (plan_id,)
            ).fetchone()
            if not plan or plan["plan_hash"] != plan_hash:
                db.rollback()
                raise ApprovalError("approval refused: plan is missing or hash does not match")
            document = json.loads(plan["document_json"])
            if document["status"] != "approval_required":
                db.rollback()
                raise ApprovalError("approval only applies to policy-allowed remediation plans")
            if db.execute(
                "SELECT 1 FROM approvals WHERE plan_id=? AND used_at IS NULL AND expires_at>?",
                (plan_id, now),
            ).fetchone():
                db.rollback()
                raise ApprovalError("an active approval already exists for this plan")
            db.execute(
                "INSERT INTO approvals VALUES(?,?,?,?,?,?,?,NULL)",
                (approval_id, plan_id, plan_hash, actor, reason, now, now + ttl),
            )
            self._audit(
                db,
                "approval.granted",
                {
                    "approval_id": approval_id,
                    "plan_id": plan_id,
                    "plan_hash": plan_hash,
                    "actor": actor,
                    "reason": reason,
                    "expires_at": now + ttl,
                },
            )
            db.commit()
        return approval_id

    def consume_approval(self, plan_id: str, plan_hash: str) -> str:
        now = time.time()
        with self._connection() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute(
                "SELECT * FROM approvals WHERE plan_id=? AND plan_hash=? AND used_at IS NULL AND expires_at>? ORDER BY created_at DESC LIMIT 1",
                (plan_id, plan_hash, now),
            ).fetchone()
            if not row:
                db.rollback()
                raise ApprovalError("no valid, unused approval is bound to this plan")
            db.execute(
                "UPDATE approvals SET used_at=? WHERE approval_id=? AND used_at IS NULL",
                (now, row["approval_id"]),
            )
            self._audit(
                db,
                "approval.consumed",
                {"approval_id": row["approval_id"], "plan_id": plan_id, "actor": row["actor"]},
            )
            db.commit()
        return row["approval_id"]

    def start_execution(
        self,
        execution_id: str,
        plan_id: str,
        started_at: str,
        authorization: dict[str, Any] | None = None,
        remediation_outcome: str | None = None,
    ) -> None:
        with self._connection() as db:
            db.execute("BEGIN IMMEDIATE")
            db.execute(
                "INSERT INTO executions(execution_id,plan_id,status,started_at,summary_json) VALUES(?,?,?,?,?)",
                (
                    execution_id,
                    plan_id,
                    "running",
                    started_at,
                    canonical_json(
                        {"remediation_outcome": remediation_outcome} if remediation_outcome else {}
                    ),
                ),
            )
            payload = {"execution_id": execution_id, "plan_id": plan_id}
            if authorization is not None:
                # `authorization` is a globally redacted key name; use an
                # explicitly safe audit label so actor and approval binding persist.
                payload["operator_confirmation"] = authorization
            self._audit(db, "execution.started", payload)
            db.commit()

    def mark_remediation_dispatch(
        self,
        execution_id: str,
        plan_id: str,
        target: str,
        action: str,
        approval_id: str,
    ) -> None:
        """Persist UNKNOWN before crossing the mutating transport boundary."""
        with self._connection() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute(
                "SELECT status,summary_json FROM executions WHERE execution_id=? AND plan_id=?",
                (execution_id, plan_id),
            ).fetchone()
            if not row or row["status"] != "running":
                db.rollback()
                raise ConfigurationError("remediation execution is not in a dispatchable state")
            summary = json.loads(row["summary_json"])
            if summary.get("remediation_outcome") != "NOT_EXECUTED":
                db.rollback()
                raise ConfigurationError("remediation dispatch boundary was already crossed")
            summary["remediation_outcome"] = "UNKNOWN"
            db.execute(
                "UPDATE executions SET summary_json=? WHERE execution_id=?",
                (canonical_json(summary), execution_id),
            )
            self._audit(
                db,
                "remediation.dispatching",
                {
                    "execution_id": execution_id,
                    "plan_id": plan_id,
                    "target": target,
                    "action": action,
                    "approval_id": approval_id,
                },
            )
            db.commit()

    def record_step(
        self,
        execution_id: str,
        action: dict[str, Any],
        status: str,
        started_at: str,
        finished_at: str,
        evidence: dict[str, Any],
    ) -> None:
        safe = redact(evidence)
        with self._connection() as db:
            db.execute("BEGIN IMMEDIATE")
            db.execute(
                """INSERT INTO step_results(execution_id,target,phase,step_id,action,status,started_at,finished_at,evidence_json)
                   VALUES(?,?,?,?,?,?,?,?,?)""",
                (
                    execution_id,
                    action["target"],
                    action["phase"],
                    action["step_id"],
                    action["action"],
                    status,
                    started_at,
                    finished_at,
                    canonical_json(safe),
                ),
            )
            self._audit(
                db,
                "step." + status,
                {
                    "execution_id": execution_id,
                    "target": action["target"],
                    "phase": action["phase"],
                    "step_id": action["step_id"],
                    "action": action["action"],
                    "evidence": safe,
                },
            )
            db.commit()

    def finish_execution(
        self, execution_id: str, status: str, finished_at: str, summary: dict[str, Any]
    ) -> None:
        clean = redact(summary)
        with self._connection() as db:
            db.execute("BEGIN IMMEDIATE")
            db.execute(
                "UPDATE executions SET status=?,finished_at=?,summary_json=? WHERE execution_id=?",
                (status, finished_at, canonical_json(clean), execution_id),
            )
            self._audit(db, "execution." + status, {"execution_id": execution_id, "summary": clean})
            if "remediation_outcome" in clean:
                self._audit(
                    db,
                    "remediation.outcome",
                    {
                        "execution_id": execution_id,
                        "plan_id": db.execute(
                            "SELECT plan_id FROM executions WHERE execution_id=?",
                            (execution_id,),
                        ).fetchone()["plan_id"],
                        "outcome": clean["remediation_outcome"],
                    },
                )
            db.commit()

    def history(self, limit: int = 50) -> list[dict[str, Any]]:
        with self._connection() as db:
            rows = db.execute(
                "SELECT * FROM executions ORDER BY started_at DESC LIMIT ?", (limit,)
            ).fetchall()
        return [dict(row) | {"summary": json.loads(row["summary_json"])} for row in rows]

    def execution(self, execution_id: str) -> dict[str, Any]:
        with self._connection() as db:
            row = db.execute(
                "SELECT * FROM executions WHERE execution_id=?", (execution_id,)
            ).fetchone()
            steps = db.execute(
                "SELECT * FROM step_results WHERE execution_id=? ORDER BY id", (execution_id,)
            ).fetchall()
        if not row:
            raise ConfigurationError(f"execution not found: {execution_id}")
        return {
            "execution": dict(row) | {"summary": json.loads(row["summary_json"])},
            "steps": [dict(s) | {"evidence": json.loads(s["evidence_json"])} for s in steps],
        }

    def verify_audit_chain(self) -> tuple[bool, int]:
        expected_prev = _ZERO_HASH
        count = 0
        with self._connection() as db:
            rows = db.execute("SELECT * FROM audit_events ORDER BY sequence").fetchall()
        for row in rows:
            if row["previous_hash"] != expected_prev:
                return False, count
            payload = json.loads(row["payload_json"])
            body = {
                "sequence": row["sequence"],
                "created_at": row["created_at"],
                "kind": row["kind"],
                "payload": payload,
                "previous_hash": expected_prev,
            }
            digest = hashlib.sha256(canonical_json(body).encode()).hexdigest()
            if digest != row["event_hash"]:
                return False, count
            expected_prev = digest
            count += 1
        return True, count

    def plan_hash_is_audited(self, plan_id: str, plan_hash: str) -> bool:
        with self._connection() as db:
            rows = db.execute(
                "SELECT payload_json FROM audit_events WHERE kind='plan.created'"
            ).fetchall()
        return any(
            (payload := json.loads(row["payload_json"])).get("plan_id") == plan_id
            and payload.get("plan_hash") == plan_hash
            for row in rows
        )

    def record_remediation_proposal(
        self,
        *,
        incident_id: str,
        investigation_id: str,
        proposal: dict[str, Any],
        decision: str,
        reason_code: str,
    ) -> str:
        """Append an advisory proposal to the audit chain after linkage checks.

        This does not create a plan, approval, or execution. The proposal is
        stored as an audit event so historical investigation hashes remain
        unchanged.
        """
        if decision not in {"accepted", "rejected", "abstained"}:
            raise ConfigurationError("invalid remediation proposal decision")
        if not re.fullmatch(r"[a-z0-9_]{1,80}", reason_code):
            raise ConfigurationError("invalid remediation proposal reason code")
        if decision in {"accepted", "abstained"}:
            from .remediation_proposal import RemediationProposalReplyV1

            try:
                model_fields = set(RemediationProposalReplyV1.model_fields)
                metadata_fields = {
                    "validation",
                    "provider",
                    "model",
                    "duration_seconds",
                    "token_usage",
                }
                if set(proposal) - model_fields - metadata_fields:
                    raise ValueError("unexpected persisted proposal field")
                reply = RemediationProposalReplyV1.model_validate(
                    {key: value for key, value in proposal.items() if key in model_fields}
                )
            except Exception as exc:
                raise ConfigurationError("invalid persisted remediation proposal") from exc
            if (
                reply.incident_id != incident_id
                or reply.investigation_id != investigation_id
                or (decision == "abstained") != reply.abstain
            ):
                raise ConfigurationError("proposal identity or decision mismatch")
            clean = reply.model_dump(mode="json")
            validation = proposal.get("validation")
            if not isinstance(validation, dict) or validation.get("accepted") is not True:
                raise ConfigurationError("proposal validation result is missing")
            if validation.get("abstained") is not reply.abstain:
                raise ConfigurationError("proposal validation decision mismatch")
            candidate = validation.get("candidate")
            if reply.abstain:
                if candidate is not None:
                    raise ConfigurationError("abstention cannot persist an action candidate")
            elif (
                not isinstance(candidate, dict)
                or candidate.get("action_id") != reply.candidate_action_id
                or candidate.get("target_ref") != reply.target_ref
            ):
                raise ConfigurationError("persisted action differs from model proposal")
            else:
                from .actions import validate_action

                try:
                    action = validate_action(
                        str(candidate.get("action_id")), candidate.get("arguments", {})
                    )
                except Exception as exc:
                    raise ConfigurationError("persisted proposal action is not registered") from exc
                if action.read_only:
                    raise ConfigurationError("persisted proposal action is not a remediation")
            clean = {
                **clean,
                "validation": {
                    "accepted": True,
                    "abstained": reply.abstain,
                    "candidate": redact(candidate),
                },
            }
            provider = proposal.get("provider")
            model = proposal.get("model")
            if isinstance(provider, str) and len(provider) <= 64:
                clean["provider"] = provider
            if isinstance(model, str) and len(model) <= 128:
                clean["model"] = model
            duration = proposal.get("duration_seconds")
            if isinstance(duration, (int, float)) and not isinstance(duration, bool):
                clean["duration_seconds"] = duration
            usage = proposal.get("token_usage")
            if isinstance(usage, dict) and all(
                key in {"prompt_tokens", "completion_tokens", "total_tokens"}
                and isinstance(value, int)
                and not isinstance(value, bool)
                for key, value in usage.items()
            ):
                clean["token_usage"] = usage
        else:
            base_failure = {"proposal_version": 1, "outcome": "unavailable"}
            timeout_keys = set(base_failure) | {"failure_stage", "duration_seconds"}
            timeout_duration = proposal.get("duration_seconds")
            if proposal != base_failure and not (
                set(proposal) == timeout_keys
                and proposal.get("proposal_version") == 1
                and proposal.get("outcome") == "unavailable"
                and proposal.get("failure_stage") == "proposal"
                and isinstance(timeout_duration, (int, float))
                and not isinstance(timeout_duration, bool)
                and math.isfinite(timeout_duration)
                and 0 <= timeout_duration <= 3600
            ):
                raise ConfigurationError("rejected proposals may store only a sanitized outcome")
            clean = dict(proposal)
        proposal_hash = hashlib.sha256(canonical_json(clean).encode("utf-8")).hexdigest()
        with self._connection() as db:
            db.execute("BEGIN IMMEDIATE")
            linked = db.execute(
                "SELECT 1 FROM incident_investigations WHERE incident_id=? AND investigation_id=?",
                (incident_id, investigation_id),
            ).fetchone()
            if linked is None:
                db.rollback()
                raise ConfigurationError("proposal incident/investigation linkage mismatch")
            self._audit(
                db,
                "remediation.proposal_recorded",
                {
                    "incident_id": incident_id,
                    "investigation_id": investigation_id,
                    "decision": decision,
                    "reason_code": reason_code,
                    "proposal_sha256": proposal_hash,
                    "proposal": clean,
                },
            )
            db.commit()
        return proposal_hash

    def remediation_proposals(self, incident_id: str) -> list[dict[str, Any]]:
        """Read proposals attached to an incident from the hash-chained audit."""
        result: list[dict[str, Any]] = []
        with self._connection() as db:
            rows = db.execute(
                "SELECT sequence,payload_json FROM audit_events "
                "WHERE kind='remediation.proposal_recorded' ORDER BY sequence"
            ).fetchall()
        for row in rows:
            try:
                payload = json.loads(row["payload_json"])
            except (json.JSONDecodeError, TypeError):
                continue
            if isinstance(payload, dict) and payload.get("incident_id") == incident_id:
                result.append({"sequence": row["sequence"], **payload})
        return result

    def investigation_is_linked(self, incident_id: str, investigation_id: str) -> bool:
        with self._connection() as db:
            return (
                db.execute(
                    "SELECT 1 FROM incident_investigations WHERE incident_id=? AND investigation_id=?",
                    (incident_id, investigation_id),
                ).fetchone()
                is not None
            )

    def create_investigation(
        self, result: dict[str, Any], *, investigation_id: str | None = None
    ) -> str:
        """Persist investigation output and append a compact, content-addressed audit event."""
        from datetime import datetime

        investigation_id = investigation_id or str(uuid.uuid4())
        assessment = result.get("assessment")
        if isinstance(assessment, dict) and assessment.get("investigation_id") != investigation_id:
            raise ConfigurationError(
                "assessment investigation ID does not match its storage record"
            )
        created_at = datetime.now(UTC).isoformat()
        clean = redact(result)
        result_json = canonical_json(clean)
        result_hash = hashlib.sha256(result_json.encode("utf-8")).hexdigest()
        model = clean.get("model_metadata", {})
        with self._connection() as db:
            db.execute("BEGIN IMMEDIATE")
            db.execute(
                "INSERT INTO investigations VALUES(?,?,?,?,?)",
                (
                    investigation_id,
                    clean["status"],
                    created_at,
                    clean["incident_sha256"],
                    result_json,
                ),
            )
            self._audit(
                db,
                "investigation.completed",
                {
                    "investigation_id": investigation_id,
                    "status": clean["status"],
                    "incident_sha256": clean["incident_sha256"],
                    "result_sha256": result_hash,
                    "provider": model.get("provider"),
                    "model": model.get("model"),
                    "execution_ids": sorted(
                        {item.get("execution_id") for item in clean.get("evidence", [])}
                    ),
                },
            )
            db.commit()
        return investigation_id

    def investigations(self, limit: int = 20) -> list[dict[str, Any]]:
        with self._connection() as db:
            rows = db.execute(
                "SELECT investigation_id,status,created_at,incident_sha256,result_json "
                "FROM investigations ORDER BY created_at DESC LIMIT ?",
                (limit,),
            ).fetchall()
        return [dict(row) | {"result": json.loads(row["result_json"])} for row in rows]

    def investigation_detail(self, investigation_id: str) -> dict[str, Any] | None:
        """Read one persisted investigation and its content-hash audit status."""
        with self._connection() as db:
            row = db.execute(
                "SELECT investigation_id,status,created_at,incident_sha256,result_json "
                "FROM investigations WHERE investigation_id=?",
                (investigation_id,),
            ).fetchone()
            if row is None:
                return None
            result_hash = hashlib.sha256(row["result_json"].encode("utf-8")).hexdigest()
            audited = False
            for event in db.execute(
                "SELECT payload_json FROM audit_events "
                "WHERE kind='investigation.completed' ORDER BY sequence"
            ):
                try:
                    payload = json.loads(event["payload_json"])
                except (json.JSONDecodeError, TypeError):
                    continue
                if (
                    isinstance(payload, dict)
                    and payload.get("investigation_id") == investigation_id
                    and payload.get("result_sha256") == result_hash
                ):
                    audited = True
                    break
        try:
            result = json.loads(row["result_json"])
        except (json.JSONDecodeError, TypeError):
            result = None
        return dict(row) | {
            "result": result,
            "result_integrity": "valid" if audited else "mismatch_or_missing_audit",
        }
