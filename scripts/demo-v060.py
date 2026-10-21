from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import secrets
import socket
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import UTC, datetime
from pathlib import Path
from tempfile import TemporaryDirectory

from typer.testing import CliRunner

import runbookos.cli as cli_module
from runbookos.dashboard import create_auth_file
from runbookos.engine import Paths, RunbookEngine
from runbookos.errors import ExecutionUnknown, PolicyDenied
from runbookos.incidents import IncidentStore, parse_alert
from runbookos.ssh import SSHResult
from runbookos.store import SQLiteStore
from runbookos.webhook import create_server
from runbookos.webhook_auth import AuthConfig


class FakeExecutor:
    def __init__(self):
        self.calls = []
        self.unknown_restart = False

    def execute(self, host, action, arguments, timeout_seconds):
        assert host.address == "192.0.2.42", "executor received non-documentation target"
        self.calls.append(action)
        if action == "systemd.restart" and self.unknown_restart:
            raise ExecutionUnknown("synthetic transport outcome unknown")
        data = {"active": True} if action == "systemd.is_active" else {"restarted": True}
        return SSHResult(True, data, None, False, 0.001)


def alertmanager_payload(status: str) -> bytes:
    return json.dumps(
        {
            "version": "4",
            "status": status,
            "receiver": "acceptance",
            "groupKey": '{}:{alertname="SyntheticServiceDown"}',
            "commonLabels": {"alertname": "SyntheticServiceDown"},
            "commonAnnotations": {"summary": "Synthetic documentation-only acceptance alert"},
            "alerts": [
                {
                    "status": status,
                    "labels": {
                        "alertname": "SyntheticServiceDown",
                        "target_alias": "docs-test-web",
                        "service": "demo",
                        "category": "service",
                        "severity": "error",
                    },
                    "annotations": {"summary": "Synthetic documentation-only acceptance alert"},
                    "startsAt": "2026-10-21T00:00:00Z",
                    "fingerprint": "synthetic-fp-060",
                }
            ],
        },
        separators=(",", ":"),
    ).encode()


def main():
    with TemporaryDirectory(prefix="runbookos-v060-acceptance-") as raw_root:
        root = Path(raw_root)
        config = root / "config"
        config.mkdir()
        state = root / "state"
        state.mkdir()
        inv = config / "inventory.yml"
        policy = config / "policy.yml"
        profiles = config / "ssh.yml"
        inv.write_text(
            """schema_version: 1\nhosts:\n  docs-test-web:\n    address: 192.0.2.42\n    user: synthetic-user\n    role: web-server\n    ssh_profile: fake\n    host_key_alias: docs-test-web\n"""
        )
        policy.write_text(
            """schema_version: 1\ndefault_decision: deny\napproval:\n  required_for_remediation: true\n  ttl_seconds: 300\n  one_time: true\nhosts:\n  docs-test-web:\n    diagnostic_actions: [systemd.is_active]\n    remediation_actions: [systemd.restart]\n    allowed_units: [demo.service]\n"""
        )
        profiles.write_text(
            """schema_version: 1\nprofiles:\n  fake:\n    identity_file: /nonexistent/not-used\n    known_hosts_file: /nonexistent/not-used\n    connect_timeout_seconds: 1\n    server_alive_interval_seconds: 1\n"""
        )
        diag = root / "diagnostic.yml"
        diag.write_text(
            """api_version: runbookos/v1\nkind: Runbook\nmetadata:\n  id: docs-demo-health\n  name: Documentation synthetic health check\n  description: Fake-only acceptance fixture.\n  risk: low\ntargets: [docs-test-web]\nsteps:\n  - id: service-active\n    action: systemd.is_active\n    with: {unit: demo.service}\n    verify: [{path: data.active, operator: is_true}]\n"""
        )
        rem = root / "remediation.yml"
        rem.write_text(
            """api_version: runbookos/v1\nkind: Runbook\nmetadata:\n  id: docs-demo-restart\n  name: Documentation synthetic restart\n  description: Fake-only acceptance fixture.\n  risk: medium\ntargets: [docs-test-web]\npreflight:\n  - id: before-active\n    action: systemd.is_active\n    with: {unit: demo.service}\n    verify: [{path: data.active, operator: is_true}]\nsteps:\n  - id: restart-demo\n    action: systemd.restart\n    with: {unit: demo.service}\n    verify: [{path: data.restarted, operator: is_true}]\npostflight:\n  - id: after-active\n    action: systemd.is_active\n    with: {unit: demo.service}\n    verify: [{path: data.active, operator: is_true}]\n"""
        )
        db_path = state / "acceptance.sqlite3"
        paths = Paths(inv, policy, profiles, db_path)
        fake = FakeExecutor()
        engine = RunbookEngine(paths, executor=fake)
        store = engine.store
        incidents = IncidentStore(store)

        secret = secrets.token_hex(32)
        os.environ["RUNBOOKOS_ACCEPTANCE_HMAC"] = secret
        auth = AuthConfig.model_validate(
            {
                "schema_version": 1,
                "mode": "per_source",
                "max_timestamp_skew_seconds": 300,
                "sources": {
                    "synthetic-monitor": {
                        "enabled": True,
                        "active_key_id": "accept-v1",
                        "keys": {
                            "accept-v1": {
                                "secret_env": "RUNBOOKOS_ACCEPTANCE_HMAC",  # pragma: allowlist secret (schema field name)
                                "state": "active",
                            }
                        },
                    }
                },
            }
        )
        server = create_server(db_path, inv, auth, port=0)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        port = server.server_address[1]

        def send_alert(body: bytes, nonce: str):
            ts = str(int(time.time()))
            key_id = "accept-v1"
            sig = hmac.new(
                secret.encode(),
                key_id.encode() + b"\n" + ts.encode() + b"\n" + nonce.encode() + b"\n" + body,
                hashlib.sha256,
            ).hexdigest()
            req = urllib.request.Request(
                f"http://127.0.0.1:{port}/v1/alerts",
                data=body,
                method="POST",
                headers={
                    "Content-Type": "application/vnd.prometheus.alertmanager.v2+json",
                    "X-RunbookOS-Key-Id": key_id,
                    "X-RunbookOS-Timestamp": ts,
                    "X-RunbookOS-Nonce": nonce,
                    "X-RunbookOS-Signature": sig,
                },
            )
            try:
                with urllib.request.urlopen(req, timeout=3) as resp:
                    return resp.status, json.loads(resp.read())
            except urllib.error.HTTPError as exc:
                return exc.code, {}

        try:
            firing = alertmanager_payload("firing")
            status, first = send_alert(firing, "fire_" + secrets.token_urlsafe(18))
            assert status == 200
            incident_id = first["incident_id"]
            status, duplicate = send_alert(firing, "dup_" + secrets.token_urlsafe(18))
            assert status == 200 and duplicate["duplicate_delivery"]
            replay_nonce = "replay_" + secrets.token_urlsafe(18)
            status, _ = send_alert(firing, replay_nonce)
            assert status == 200
            # Repeat exactly the same signed request to confirm nonce replay rejection.
            ts = str(int(time.time()))
            key_id = "accept-v1"
            sig = hmac.new(
                secret.encode(),
                key_id.encode()
                + b"\n"
                + ts.encode()
                + b"\n"
                + replay_nonce.encode()
                + b"\n"
                + firing,
                hashlib.sha256,
            ).hexdigest()
            replay_req = urllib.request.Request(
                f"http://127.0.0.1:{port}/v1/alerts",
                data=firing,
                method="POST",
                headers={
                    "Content-Type": "application/vnd.prometheus.alertmanager.v2+json",
                    "X-RunbookOS-Key-Id": key_id,
                    "X-RunbookOS-Timestamp": ts,
                    "X-RunbookOS-Nonce": replay_nonce,
                    "X-RunbookOS-Signature": sig,
                },
            )
            # Timestamp is separately signed, so submit the exact same request object/signature again.
            try:
                urllib.request.urlopen(replay_req, timeout=3).read()
                raise AssertionError("replayed nonce accepted")
            except urllib.error.HTTPError as exc:
                assert exc.code == 400
            status, resolved = send_alert(
                alertmanager_payload("resolved"), "resolved_" + secrets.token_urlsafe(18)
            )
            assert status == 200 and resolved["incident_id"] == incident_id
            assert incidents.show(incident_id)["status"] == "NEW"
            with store._connection() as conn:
                assert conn.execute("SELECT count(*) FROM executions").fetchone()[0] == 0
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=3)
        assert not thread.is_alive()

        root_args = [
            "--inventory",
            str(inv),
            "--policy",
            str(policy),
            "--ssh-profiles",
            str(profiles),
            "--db",
            str(db_path),
        ]
        runner = CliRunner()
        original_engine = cli_module.RunbookEngine
        cli_module.RunbookEngine = lambda passed: engine
        try:
            ack = runner.invoke(
                cli_module.app,
                root_args
                + [
                    "incidents",
                    "acknowledge",
                    incident_id,
                    "--reason",
                    "synthetic operator reviewed alert",
                ],
            )
            assert ack.exit_code == 0, ack.output
            inv_result = runner.invoke(
                cli_module.app,
                root_args + ["incidents", "investigate", incident_id, "--runbook", str(diag)],
            )
            assert inv_result.exit_code == 0, inv_result.output
            inv_doc = json.loads(inv_result.output)
            investigation_id = inv_doc["investigation_id"]
            execution_id = inv_doc["execution_id"]
            detail = incidents.show(incident_id)
            ref = detail["investigations"][0]["evidence_refs"][0]
            try:
                incidents.link_investigation(
                    incident_id,
                    investigation_id,
                    [execution_id],
                    ["00000000-0000-0000-0000-000000000000:forged"],
                )
                raise AssertionError("forged evidence reference accepted")
            except PolicyDenied:
                pass

            planned = runner.invoke(cli_module.app, root_args + ["plan", str(rem), "--json"])
            assert planned.exit_code == 0, planned.output
            plan_doc = json.loads(planned.output)
            plan_id = plan_doc["plan_id"]
            preview = runner.invoke(cli_module.app, root_args + ["remediation-preview", plan_id])
            assert preview.exit_code == 0, preview.output
            preview_doc = json.loads(preview.output)
            assert (
                preview_doc["target"]["alias"] == "docs-test-web"
                and preview_doc["action_id"] == "systemd.restart"
                and preview_doc["approval"]["one_time"]
            )
            assert (
                len(preview_doc["read_only_preconditions"]) == 1
                and len(preview_doc["postflight_checks"]) == 1
            )
            # Wrong target and forged hash are denied without creating another association.
            wrong = parse_alert(
                json.dumps(
                    {
                        "alert_id": "wrong-target",
                        "source": "synthetic-monitor",
                        "event_timestamp": datetime.now(UTC).isoformat(),
                        "severity": "error",
                        "target_alias": "docs-other",
                        "service": "demo",
                        "category": "service",
                        "summary": "synthetic wrong target",
                        "fingerprint": "wrong-target-fp",
                        "metadata": {},
                    }
                ).encode()
            )
            other_id = incidents.ingest(wrong)["incident_id"]
            try:
                incidents.associate_remediation_plan(
                    other_id, plan_id, plan_doc["plan_hash"], "operator"
                )
                raise AssertionError("wrong target accepted")
            except PolicyDenied:
                pass
            try:
                incidents.associate_remediation_plan(incident_id, plan_id, "0" * 64, "operator")
                raise AssertionError("forged plan hash accepted")
            except PolicyDenied:
                pass
            link = runner.invoke(
                cli_module.app, root_args + ["incidents", "associate-plan", incident_id, plan_id]
            )
            assert link.exit_code == 0, link.output
            assert json.loads(link.output)["approval_granted"] is False
            review = runner.invoke(
                cli_module.app, root_args + ["incidents", "remediation-review", incident_id]
            )
            assert review.exit_code == 0, review.output
            assert (
                json.loads(review.output)["remediation_plans"][0]["preview_status"]
                == "valid_current_plan"
            )
            with store._connection() as conn:
                assert conn.execute("SELECT count(*) FROM approvals").fetchone()[0] == 0
                assert conn.execute("SELECT count(*) FROM executions").fetchone()[0] == 1
            approved = runner.invoke(
                cli_module.app,
                root_args + ["approve", plan_id, "--reason", "synthetic acceptance reviewed plan"],
            )
            assert approved.exit_code == 0, approved.output
            missing_confirm = runner.invoke(cli_module.app, root_args + ["run", plan_id])
            assert missing_confirm.exit_code != 0
            run = runner.invoke(cli_module.app, root_args + ["run", plan_id, "--confirm"])
            assert run.exit_code == 0, run.output
            execution_match = re.search(r"Execution ([0-9a-f-]+): succeeded", run.output)
            assert execution_match, run.output
            remediation_execution = execution_match.group(1)
            replay_run = runner.invoke(cli_module.app, root_args + ["run", plan_id, "--confirm"])
            assert replay_run.exit_code != 0
            assert "no valid, unused approval" in replay_run.output
            assert incidents.show(incident_id)["status"] == "INVESTIGATING"
            review = runner.invoke(
                cli_module.app, root_args + ["incidents", "remediation-review", incident_id]
            )
            assert review.exit_code == 0
            reviewed = json.loads(review.output)
            assert (
                reviewed["remediation_plans"][0]["executions"][-1]["outcome"] == "VERIFIED_SUCCESS"
            )
            # Operator explicitly reviews the successful postflight, then transitions incident.
            resolved_result = runner.invoke(
                cli_module.app,
                root_args
                + [
                    "incidents",
                    "resolve",
                    incident_id,
                    "--reason",
                    "operator reviewed verified diagnostic and postflight evidence",
                    "--evidence-status",
                    "verified",
                ],
            )
            assert resolved_result.exit_code == 0, resolved_result.output
            closed = runner.invoke(
                cli_module.app,
                root_args
                + [
                    "incidents",
                    "close",
                    incident_id,
                    "--reason",
                    "operator confirmed workflow complete",
                ],
            )
            assert closed.exit_code == 0, closed.output

            # A separate synthetic incident creates an UNKNOWN result to verify review warning and no retry.
            unknown_alert = parse_alert(
                json.dumps(
                    {
                        "alert_id": "unknown-alert",
                        "source": "synthetic-monitor",
                        "event_timestamp": datetime.now(UTC).isoformat(),
                        "severity": "warning",
                        "target_alias": "docs-test-web",
                        "service": "demo",
                        "category": "service",
                        "summary": "synthetic uncertain outcome",
                        "fingerprint": "unknown-fp",
                        "metadata": {},
                    }
                ).encode()
            )
            unknown_id = incidents.ingest(unknown_alert)["incident_id"]
            unknown_plan = engine.plan(rem)
            incidents.associate_remediation_plan(
                unknown_id, unknown_plan.plan_id, unknown_plan.plan_hash, "synthetic-operator"
            )
            engine.approve(
                unknown_plan.plan_id, "synthetic-operator", "isolated unknown outcome test"
            )
            fake.unknown_restart = True
            unknown_exec, unknown_status = engine.execute(
                unknown_plan.plan_id,
                confirm_remediation=True,
                confirming_actor="synthetic-operator",
            )
            assert unknown_status == "unknown" and fake.calls.count("systemd.restart") == 2
            unknown_review = runner.invoke(
                cli_module.app, root_args + ["incidents", "remediation-review", unknown_id]
            )
            assert unknown_review.exit_code == 0
            assert (
                json.loads(unknown_review.output)["remediation_plans"][0]["unknown_outcome_warning"]
                is True
            )

            # Audit and persistence invariants.
            verify = runner.invoke(cli_module.app, root_args + ["audit"])
            assert verify.exit_code == 0, verify.output
            store = SQLiteStore(db_path)
            with store._connection() as conn:
                assert conn.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
                assert conn.execute("PRAGMA foreign_key_check").fetchall() == []
                alert_count = conn.execute("SELECT count(*) FROM alerts").fetchone()[0]
                source_names = [
                    row[0] for row in conn.execute("SELECT DISTINCT source FROM alerts")
                ]
                webhook_alerts = conn.execute(
                    "SELECT source,alert_id FROM alerts WHERE source='synthetic-monitor' ORDER BY alert_id"
                ).fetchall()
                incident_count = conn.execute("SELECT count(*) FROM incidents").fetchone()[0]
                exec_count = conn.execute("SELECT count(*) FROM executions").fetchone()[0]
                investigation_count = conn.execute(
                    "SELECT count(*) FROM investigations"
                ).fetchone()[0]
                nonce_count = conn.execute("SELECT count(*) FROM webhook_nonces").fetchone()[0]
                audit_count = conn.execute("SELECT count(*) FROM audit_events").fetchone()[0]
            reopened = IncidentStore(SQLiteStore(db_path))
            assert reopened.show(incident_id)["remediation_plans"][0]["plan_id"] == plan_id
            assert (
                reopened.store.execution(remediation_execution)["execution"]["summary"][
                    "remediation_outcome"
                ]
                == "VERIFIED_SUCCESS"
            )
            assert (
                reopened.store.execution(unknown_exec)["execution"]["summary"][
                    "remediation_outcome"
                ]
                == "UNKNOWN"
            )

            # Isolated authenticated dashboard process, loopback only.
            auth_file = root / "dashboard-auth.json"
            password = secrets.token_urlsafe(24)
            create_auth_file(auth_file, "synthetic-operator", password)
            with socket.socket() as sock:
                sock.bind(("127.0.0.1", 0))
                dash_port = sock.getsockname()[1]
            dash = subprocess.Popen(
                [
                    sys.executable,
                    "-m",
                    "runbookos",
                    *root_args,
                    "dashboard",
                    "serve",
                    "--auth-file",
                    str(auth_file),
                    "--port",
                    str(dash_port),
                ],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            cookiejar = urllib.request.HTTPCookieProcessor()
            opener = urllib.request.build_opener(cookiejar)
            try:
                for _ in range(80):
                    if dash.poll() is not None:
                        raise AssertionError("dashboard process exited during startup")
                    try:
                        opener.open(f"http://127.0.0.1:{dash_port}/login", timeout=1).read()
                        break
                    except OSError:
                        time.sleep(0.1)
                else:
                    raise AssertionError("dashboard did not start")
                req = urllib.request.Request(
                    f"http://127.0.0.1:{dash_port}/login",
                    data=urllib.parse.urlencode({"password": password}).encode(),
                    method="POST",
                    headers={"Content-Type": "application/x-www-form-urlencoded"},
                )
                with opener.open(req, timeout=3) as response:
                    assert response.status == 200
                with opener.open(
                    f"http://127.0.0.1:{dash_port}/incidents/{incident_id}", timeout=3
                ) as response:
                    page = response.read().decode()
                assert (
                    investigation_id in page
                    and plan_id in page
                    and "Approval: consumed" in page
                    and "VERIFIED_SUCCESS" in page
                )
                assert "Preflight:" in page and "postflight:" in page
                assert (
                    "incident.investigation_linked" in page
                    and "Audit chain" in page
                    and "VALID" in page
                )
                with opener.open(
                    f"http://127.0.0.1:{dash_port}/incidents/{unknown_id}", timeout=3
                ) as response:
                    unknown_page = response.read().decode()
                assert "UNKNOWN outcome" in unknown_page and "systemd.restart" in unknown_page
                csrf = re.search(r"name='csrf' value='([^']+)'", unknown_page)
                assert csrf
                attack = urllib.request.Request(
                    f"http://127.0.0.1:{dash_port}/incidents/{incident_id}/remediation/execute",
                    data=urllib.parse.urlencode(
                        {"csrf": csrf.group(1), "plan_id": plan_id}
                    ).encode(),
                    method="POST",
                    headers={"Content-Type": "application/x-www-form-urlencoded"},
                )
                try:
                    opener.open(attack, timeout=3)
                    raise AssertionError("dashboard remediation route unexpectedly accepted")
                except urllib.error.HTTPError as exc:
                    assert exc.code == 404
                approve_attack = urllib.request.Request(
                    f"http://127.0.0.1:{dash_port}/incidents/{incident_id}/remediation/approve",
                    data=urllib.parse.urlencode(
                        {"csrf": csrf.group(1), "plan_id": plan_id}
                    ).encode(),
                    method="POST",
                    headers={"Content-Type": "application/x-www-form-urlencoded"},
                )
                try:
                    opener.open(approve_attack, timeout=3)
                    raise AssertionError("dashboard approval route unexpectedly accepted")
                except urllib.error.HTTPError as exc:
                    assert exc.code == 404
                with store._connection() as conn:
                    assert (
                        conn.execute("SELECT count(*) FROM executions").fetchone()[0] == exec_count
                    )
            finally:
                dash.terminate()
                try:
                    dash.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    dash.kill()
                    dash.wait(timeout=3)
                    raise AssertionError("dashboard failed bounded shutdown")
                auth_file.unlink(missing_ok=True)
            assert dash.poll() is not None and not auth_file.exists()

            assert store.verify_audit_chain()[0]
            print(
                json.dumps(
                    {
                        "temporary_state": "all files removed with temporary directory after run",
                        "database": "new temporary acceptance.sqlite3; synthetic-only state",
                        "source_executor": "fake executor; target is documentation TEST-NET 192.0.2.42",
                        "alertmanager_process": "not run; provider-equivalent authenticated payload sent to temporary loopback RunbookOS webhook",
                        "incident_id": incident_id,
                        "unknown_incident_id": unknown_id,
                        "investigation_id": investigation_id,
                        "diagnostic_execution_id": execution_id,
                        "remediation_plan_id": plan_id,
                        "remediation_execution_id": remediation_execution,
                        "unknown_execution_id": unknown_exec,
                        "webhook_alert_refs": [
                            {"source": row[0], "alert_id": row[1]}
                            for row in webhook_alerts
                            if row[1].startswith("am-")
                        ],
                        "authenticated_source_identities": source_names,
                        "final_lifecycle": "CLOSED",
                        "linked_verified_evidence_refs": [ref],
                        "counts": {
                            "alerts": alert_count,
                            "incidents": incident_count,
                            "executions": exec_count,
                            "investigations": investigation_count,
                            "webhook_nonces": nonce_count,
                            "audit_events": audit_count,
                        },
                        "sqlite_integrity": "ok",
                        "foreign_key_check": "clean",
                        "audit": "valid",
                        "webhook_stopped": not thread.is_alive(),
                        "dashboard_stopped": dash.poll() is not None,
                        "dashboard_auth_removed": not auth_file.exists(),
                        "all_calls_fake": True,
                    },
                    indent=2,
                )
            )
        finally:
            cli_module.RunbookEngine = original_engine
            os.environ.pop("RUNBOOKOS_ACCEPTANCE_HMAC", None)


if __name__ == "__main__":
    main()
