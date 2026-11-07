from __future__ import annotations

import hashlib

import pytest

from runbookos.errors import ConfigurationError
from runbookos.store import SQLiteStore


def linked_store(tmp_path):
    store = SQLiteStore(tmp_path / "timeout.sqlite3")
    incident_id = "incident-timeout"
    result = {
        "incident_sha256": hashlib.sha256(b"synthetic").hexdigest(),
        "status": "failed",
        "selected_diagnostics": [],
        "tool_calls": 0,
        "evidence": [],
        "verified_evidence": [],
        "model_metadata": {},
    }
    investigation_id = store.create_investigation(result)
    with store._connection() as db:
        db.execute(
            "INSERT INTO incidents(incident_id,severity,target_alias,service,category,summary,"
            "status,correlation_key,correlation_reason,created_at,updated_at) "
            "VALUES(?,?,?,?,?,?,?,?,?,?,?)",
            (
                incident_id,
                "warning",
                "fixture",
                "test",
                "application",
                "synthetic timeout test",
                "NEW",
                incident_id,
                "new incident",
                "t0",
                "t0",
            ),
        )
        db.execute(
            "INSERT INTO incident_investigations VALUES(?,?,?,?,?)",
            (incident_id, investigation_id, "t0", "[]", "[]"),
        )
    return store, incident_id, investigation_id


def test_rejected_proposal_persists_only_safe_timeout_metadata(tmp_path):
    store, incident_id, investigation_id = linked_store(tmp_path)
    store.record_remediation_proposal(
        incident_id=incident_id,
        investigation_id=investigation_id,
        proposal={
            "proposal_version": 1,
            "outcome": "unavailable",
            "failure_stage": "proposal",
            "duration_seconds": 120.003,
        },
        decision="rejected",
        reason_code="provider_timeout",
    )
    proposals = store.remediation_proposals(incident_id)
    assert proposals[0]["proposal"] == {
        "proposal_version": 1,
        "outcome": "unavailable",
        "failure_stage": "proposal",
        "duration_seconds": 120.003,
    }
    assert store.verify_audit_chain() == (True, 2)


def test_timeout_metadata_requires_provider_timeout_reason_code(tmp_path):
    store, incident_id, investigation_id = linked_store(tmp_path)
    with pytest.raises(ConfigurationError, match="sanitized outcome"):
        store.record_remediation_proposal(
            incident_id=incident_id,
            investigation_id=investigation_id,
            proposal={
                "proposal_version": 1,
                "outcome": "unavailable",
                "failure_stage": "proposal",
                "duration_seconds": 12.5,
            },
            decision="rejected",
            reason_code="proposal_contract_rejected",
        )
    assert store.remediation_proposals(incident_id) == []
    assert store.verify_audit_chain() == (True, 1)


@pytest.mark.parametrize(
    "metadata",
    [
        {"failure_stage": "assessment", "duration_seconds": 10.0},
        {"failure_stage": "proposal", "duration_seconds": float("inf")},
        {"failure_stage": "proposal", "duration_seconds": 10.0, "raw_response": "secret"},
    ],
)
def test_timeout_ledger_rejects_unsafe_or_inconsistent_metadata(tmp_path, metadata):
    store, incident_id, investigation_id = linked_store(tmp_path)
    proposal = {"proposal_version": 1, "outcome": "unavailable"} | metadata
    with pytest.raises(ConfigurationError, match="sanitized outcome"):
        store.record_remediation_proposal(
            incident_id=incident_id,
            investigation_id=investigation_id,
            proposal=proposal,
            decision="rejected",
            reason_code="provider_timeout",
        )
