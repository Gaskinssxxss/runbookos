from __future__ import annotations

import hashlib
import http.client
import importlib.util
import json
import os
import socket
import subprocess
import sys
import time
from pathlib import Path
from urllib.parse import urlencode

import pytest

from runbookos.assessment import project_investigation_assessment
from runbookos.dashboard import create_auth_file
from runbookos.incidents import IncidentStore, parse_alert
from runbookos.store import SQLiteStore

ROOT = Path(__file__).parents[1]
SPEC = importlib.util.spec_from_file_location(
    "operator_demo_v070", ROOT / "scripts" / "operator-demo-v070.py"
)
assert SPEC and SPEC.loader
DEMO = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(DEMO)


def test_synthetic_demo_persists_audited_nonexecution_and_cli_review(tmp_path: Path) -> None:
    database = tmp_path / "state" / "demo.sqlite3"
    demo = DEMO.build_synthetic_demo(database)
    incident = DEMO._run_cli_review(database, demo["incident_id"])
    projection = incident["latest_investigation_assessment"]

    assert incident["status"] == "NEW"
    assert incident["target_alias"] == "demo-app-01"
    assert incident["investigations"][0]["investigation_id"] == demo["investigation_id"]
    assert incident["investigations"][0]["execution_ids"] == []
    assert incident["investigations"][0]["evidence_refs"] == []
    assert projection["availability"] == "available"
    assert projection["investigation_id"] == demo["investigation_id"]
    assert projection["assessment_status"] == "assessed"
    assert projection["classifications"] == [
        {
            "category": "service_failure",
            "confidence": 0.2,
            "supporting_evidence_refs": [demo["evidence_ref"]],
            "status": "suspected",
        }
    ]
    assert projection["confidence_label"] == "synthetic demo fixture; not model output"
    assert projection["evidence_origin"] == "synthetic demo fixture; no diagnostic executed"
    assert projection["recommendations_are_executable"] is False
    assert projection["semantic_support_status"] == "unverified"
    observation = projection["observations"][0]
    assert observation["ref"] == demo["evidence_ref"]
    assert observation["target"] == "demo-app-01"
    assert observation["source_action"] == "synthetic.fixture.application_state"
    assert "not an executed diagnostic" in observation["statement"]
    assert observation["execution_status"] == "unknown"
    assert observation["assertion_outcome"] == "not_present"
    assert observation["verification_status"] == "unknown"
    assert observation["observed_result"] == {"service_state": "inactive", "synthetic": True}
    assert incident["assessment_review_audit"]["valid"] is True

    store = SQLiteStore(database)
    assert store.verify_audit_chain()[0]
    with store._connection() as db:
        assert db.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
        assert db.execute("PRAGMA foreign_key_check").fetchall() == []
        assert db.execute("SELECT COUNT(*) FROM executions").fetchone()[0] == 0
        assert db.execute("SELECT COUNT(*) FROM approvals").fetchone()[0] == 0
    assert database.stat().st_mode & 0o777 == 0o600
    assert database.parent.stat().st_mode & 0o777 == 0o700


def test_dashboard_authentication_renders_same_demo_and_get_is_read_only(tmp_path: Path) -> None:
    database = tmp_path / "state" / "demo.sqlite3"
    demo = DEMO.build_synthetic_demo(database)
    auth_file = tmp_path / "auth" / "verifier.json"
    password = "temporary-demo-password-4821"
    create_auth_file(auth_file, "demo-operator", password)
    env = os.environ.copy()
    env["PYTHONPATH"] = str(ROOT / "src")
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    process = subprocess.Popen(
        [
            sys.executable,
            "-m",
            "runbookos",
            "--db",
            str(database),
            "dashboard",
            "serve",
            "--auth-file",
            str(auth_file),
            "--host",
            "127.0.0.1",
            "--port",
            str(port),
        ],
        cwd=ROOT,
        env=env,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

    def request(method: str, path: str, body: str = "", cookie: str | None = None):
        connection = http.client.HTTPConnection("127.0.0.1", port, timeout=3)
        headers = {"Content-Type": "application/x-www-form-urlencoded"}
        if cookie:
            headers["Cookie"] = cookie
        connection.request(method, path, body=body, headers=headers)
        response = connection.getresponse()
        result = response.status, dict(response.getheaders()), response.read().decode()
        connection.close()
        return result

    try:
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            if process.poll() is not None:
                pytest.fail("dashboard exited before readiness")
            try:
                status, _, _ = request("GET", "/login")
                if status == 200:
                    break
            except OSError:
                time.sleep(0.05)
        else:
            pytest.fail("dashboard did not become ready")

        status, _, _ = request("GET", f"/incidents/{demo['incident_id']}")
        assert status == 303
        status, headers, _ = request("POST", "/login", urlencode({"password": password}))
        assert status == 303
        cookie = headers["Set-Cookie"].split(";", 1)[0]
        store = SQLiteStore(database)
        before = store.verify_audit_chain()[1]
        status, _, html = request("GET", f"/incidents/{demo['incident_id']}", cookie=cookie)
        after = store.verify_audit_chain()[1]
        assert status == 200
        assert demo["investigation_id"] in html
        assert "Synthetic fixture observation" in html
        assert "synthetic.fixture.application_state" in html
        assert "verification: unknown" in html
        assert "assertion: not_present" in html
        assert "service_failure: suspected" in html
        assert "synthetic demo fixture; not model output" in html
        assert "synthetic demo fixture; no diagnostic executed" in html
        assert "semantic support: unverified" in html
        assert "Advisory next steps (not executable)" in html
        assert before == after
        assert store.verify_audit_chain()[0]
    finally:
        DEMO._stop_owned_dashboard(process, port)


@pytest.mark.parametrize(
    ("result", "expected"),
    [
        ({"incident_sha256": "a" * 64}, "legacy"),
        (
            {
                "incident_sha256": "a" * 64,
                "assessment": {"schema_version": 1, "incident_id": "incident"},
            },
            "malformed",
        ),
    ],
)
def test_missing_or_invalid_assessment_is_not_presented_as_success(
    result: dict[str, object], expected: str
) -> None:
    projection = project_investigation_assessment(
        {
            "investigation_id": "review-investigation",
            "result_integrity": "valid",
            "result": result,
        },
        incident_id="incident",
        incident_summary_sha256="a" * 64,
        linked=True,
    )
    assert projection["availability"] == expected
    assert projection.get("classifications", []) == []
    assert projection.get("reason")


def test_invalid_persisted_assessment_is_rejected_by_cli_projection(tmp_path: Path) -> None:
    database = tmp_path / "invalid.sqlite3"
    store = SQLiteStore(database)
    manager = IncidentStore(store)
    summary = "Synthetic malformed assessment test."
    suffix = "invalid-demo"
    alert = {
        "alert_id": suffix,
        "source": "operator-demo-synthetic",
        "event_timestamp": "2026-10-26T00:00:00+00:00",
        "severity": "warning",
        "target_alias": "demo-app-02",
        "service": "demo-api",
        "category": "service",
        "summary": summary,
        "fingerprint": suffix,
        "metadata": {"origin": "synthetic_demo_fixture"},
    }
    incident_id = manager.ingest(parse_alert(json.dumps(alert).encode()))["incident_id"]
    investigation_id = "invalid-assessment-demo"
    store.create_investigation(
        {
            "status": "synthetic_fixture",
            "incident_sha256": hashlib.sha256(summary.encode()).hexdigest(),
            "evidence": [],
            "assessment": {
                "schema_version": 1,
                "incident_id": incident_id,
                "investigation_id": investigation_id,
            },
        },
        investigation_id=investigation_id,
    )
    manager.link_investigation(incident_id, investigation_id, [], [])
    incident = DEMO._run_cli_review(database, incident_id)
    projection = incident["latest_investigation_assessment"]
    assert projection["investigation_id"] == investigation_id
    assert projection["availability"] == "malformed"
    assert projection.get("classifications", []) == []
    assert incident["assessment_review_audit"]["valid"] is True
