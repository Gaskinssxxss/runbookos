#!/usr/bin/env python3
"""Run one isolated, synthetic incident-to-review operator demonstration."""

from __future__ import annotations

import errno
import getpass
import hashlib
import json
import os
import socket
import subprocess
import sys
import tempfile
import time
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from runbookos.assessment import (  # noqa: E402
    ClassificationAssessment,
    HypothesisClaim,
    ModelAssessmentReply,
    build_structured_assessment,
)
from runbookos.dashboard import create_auth_file  # noqa: E402
from runbookos.incidents import IncidentStore, parse_alert  # noqa: E402
from runbookos.store import SQLiteStore  # noqa: E402


def build_synthetic_demo(database: Path) -> dict[str, str]:
    """Populate a new demo database through existing incident/store APIs."""
    database = database.resolve()
    database.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(database.parent, 0o700)
    store = SQLiteStore(database)
    incident_store = IncidentStore(store)
    suffix = uuid.uuid4().hex[:12]
    target = "demo-app-01"
    summary = "Synthetic demo fixture: application service is reported inactive."
    alert = {
        "alert_id": f"operator-demo-{suffix}",
        "source": "operator-demo-synthetic",
        "event_timestamp": datetime.now(UTC).isoformat(),
        "severity": "error",
        "target_alias": target,
        "service": "demo-api",
        "category": "service",
        "summary": summary,
        "fingerprint": f"operator-demo-{suffix}",
        "metadata": {"origin": "synthetic_demo_fixture"},
    }
    incident = incident_store.ingest(parse_alert(json.dumps(alert).encode("utf-8")))
    incident_id = incident["incident_id"]
    investigation_id = f"demo-investigation-{suffix}"
    evidence_ref = f"{investigation_id}:fixture_application_state"
    evidence = [
        {
            "ref": evidence_ref,
            "execution_id": f"synthetic-not-executed-{suffix}",
            "diagnostic_id": "synthetic.application_state",
            "target": target,
            "step_id": "fixture_application_state",
            "action": "synthetic.fixture.application_state",
            "observed_at": None,
            "status": "unknown",
            "source": "synthetic_demo_fixture",
            "diagnostic_executed": False,
            "description": "fixture reports service_state=inactive",
            "evidence": {"service_state": "inactive", "synthetic": True},
        }
    ]
    reply = ModelAssessmentReply(
        hypotheses=[
            HypothesisClaim(
                statement=(
                    "The synthetic fixture reports an inactive application service; "
                    "this suggests a service failure."
                ),
                evidence_refs=[evidence_ref],
                confidence=0.2,
                missing_evidence=["A real service health check was not performed."],
            )
        ],
        classifications=[
            ClassificationAssessment(
                category="service_failure",
                confidence=0.2,
                supporting_evidence_refs=[evidence_ref],
                status="suspected",
            )
        ],
        overall_uncertainty=0.8,
        assessment_status="assessed",
    )
    assessment = build_structured_assessment(
        reply, evidence, incident_id=incident_id, investigation_id=investigation_id
    )
    result: dict[str, Any] = {
        "status": "synthetic_fixture",
        "incident_sha256": hashlib.sha256(summary.encode("utf-8")).hexdigest(),
        "selected_diagnostics": [],
        "tool_calls": 0,
        "evidence": evidence,
        "verified_evidence": [],
        "report": {
            "summary": "Synthetic operator-demo fixture; no diagnostic or mutation was run.",
            "non_executable": True,
        },
        "assessment_origin": "synthetic_demo_fixture",
        "model_metadata": {
            "provider": "none",
            "model": "synthetic_demo_fixture",
            "model_calls": 0,
        },
        "assessment": assessment.model_dump(mode="json"),
    }
    store.create_investigation(result, investigation_id=investigation_id)
    # The fixture has no execution or verified evidence refs; the link is identity-only.
    incident_store.link_investigation(incident_id, investigation_id, [], [])
    valid, audit_count = store.verify_audit_chain()
    if not valid:
        raise RuntimeError("synthetic demo audit chain failed verification")
    with store._connection() as db:
        integrity = db.execute("PRAGMA integrity_check").fetchone()[0]
        foreign_keys = db.execute("PRAGMA foreign_key_check").fetchall()
        executions = db.execute("SELECT COUNT(*) FROM executions").fetchone()[0]
        approvals = db.execute("SELECT COUNT(*) FROM approvals").fetchone()[0]
    if integrity != "ok" or foreign_keys or executions or approvals:
        raise RuntimeError("synthetic demo database integrity or read-only boundary failed")
    return {
        "incident_id": incident_id,
        "investigation_id": investigation_id,
        "evidence_ref": evidence_ref,
        "database": str(database),
        "audit_event_count": str(audit_count),
    }


def _run_cli_review(database: Path, incident_id: str) -> dict[str, Any]:
    env = os.environ.copy()
    env["PYTHONPATH"] = str(ROOT / "src")
    completed = subprocess.run(
        [
            sys.executable,
            "-m",
            "runbookos",
            "--db",
            str(database),
            "incidents",
            "show",
            incident_id,
        ],
        cwd=ROOT,
        env=env,
        check=True,
        capture_output=True,
        text=True,
        timeout=15,
    )
    return json.loads(completed.stdout)


def _available_loopback_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.bind(("127.0.0.1", 0))
        return int(probe.getsockname()[1])


def _wait_for_dashboard(process: subprocess.Popen[bytes], port: int) -> None:
    import http.client

    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError("owned dashboard process exited before readiness")
        try:
            connection = http.client.HTTPConnection("127.0.0.1", port, timeout=0.5)
            connection.request("GET", "/login")
            response = connection.getresponse()
            response.read()
            connection.close()
            if response.status == 200:
                return
        except OSError:
            time.sleep(0.05)
    raise TimeoutError("dashboard did not become ready within 10 seconds")


def _stop_owned_dashboard(process: subprocess.Popen[bytes], port: int) -> None:
    if process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)
    if process.poll() is None:
        raise RuntimeError("acceptance-owned dashboard process did not stop")
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.settimeout(0.5)
        result = probe.connect_ex(("127.0.0.1", port))
    if result == 0:
        raise RuntimeError("dashboard port remains occupied after stopping the owned process")
    if result != errno.ECONNREFUSED:
        raise RuntimeError("could not verify dashboard listener cleanup")


def run_demo() -> int:
    with tempfile.TemporaryDirectory(prefix="runbookos-operator-demo-") as temp_name:
        root = Path(temp_name)
        os.chmod(root, 0o700)
        database = root / "state" / "demo.sqlite3"
        auth_file = root / "auth" / "dashboard-verifier.json"
        demo = build_synthetic_demo(database)
        incident = _run_cli_review(database, demo["incident_id"])
        projection = incident["latest_investigation_assessment"]
        if not isinstance(projection, dict) or projection.get("availability") != "available":
            raise RuntimeError("CLI assessment projection was not available")
        classification = projection["classifications"][0]
        observation = projection["observations"][0]
        print("Synthetic incident review (no diagnostics or remediation executed)")
        print(
            f"Incident: {demo['incident_id']} · status {incident['status']} · target {incident['target_alias']}"
        )
        print(
            f"Investigation: {demo['investigation_id']} · projection {projection['availability']}"
        )
        print(
            f"Observation: {observation['ref']} · {observation['source_action']} · "
            f"verification {observation['verification_status']} · assertion {observation['assertion_outcome']}"
        )
        print(
            f"Assessment: {classification['category']} / {classification['status']} · "
            f"confidence {classification['confidence']} ({projection['confidence_label']})"
        )
        print(f"Hypothesis: {projection['hypotheses'][0]['statement']}")
        print(
            f"Evidence origin: {projection['evidence_origin']} · uncertainty "
            f"{projection['overall_uncertainty']} · semantic support {projection['semantic_support_status']}"
        )
        print(
            f"Audit chain: valid={incident['assessment_review_audit']['valid']} events={incident['assessment_review_audit']['event_count']}"
        )
        print("Assessment grants no execution or approval authority.")

        password = getpass.getpass("Set temporary dashboard password (min. 14 characters): ")
        confirmation = getpass.getpass("Confirm temporary dashboard password: ")
        if password != confirmation:
            raise ValueError("dashboard password confirmation did not match")
        create_auth_file(auth_file, "operator-demo", password)
        os.chmod(auth_file.parent, 0o700)
        port = _available_loopback_port()
        env = os.environ.copy()
        env["PYTHONPATH"] = str(ROOT / "src")
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
        try:
            _wait_for_dashboard(process, port)
            print(f"Authenticated dashboard: http://127.0.0.1:{port}/login")
            print(f"After login, open incident {demo['incident_id']} from the incident queue.")
            print("Temporary database and verifier are owner-only and removed on exit.")
            print("Press Ctrl-C here to stop the owned dashboard and clean up the demo.")
            process.wait()
            raise RuntimeError("dashboard stopped unexpectedly")
        except KeyboardInterrupt:
            print("Stopping the operator-demo dashboard.")
        finally:
            _stop_owned_dashboard(process, port)
        print("Dashboard stopped; temporary demo database and verifier removed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(run_demo())
