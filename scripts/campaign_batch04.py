"""Batch 04 campaign definitions and independent ledger checks."""

from __future__ import annotations

from typing import Any

SCENARIOS: tuple[dict[str, Any], ...] = (
    {
        "id": "B04-01",
        "group": "A",
        "title": "Disposable app service stopped",
        "target": "svc-web-01",
        "faults": ["app_stopped"],
        "oracle": "service_failure",
        "expected_actions": ["systemd.start"],
    },
    {
        "id": "B04-02",
        "group": "A",
        "title": "Invalid application configuration",
        "target": "svc-web-01",
        "faults": ["invalid_app_config"],
        "oracle": "service_failure",
        "expected_actions": ["config.restore_fixture"],
    },
    {
        "id": "B04-03",
        "group": "A",
        "title": "Application worker unavailable",
        "target": "svc-web-01",
        "faults": ["worker_stopped"],
        "oracle": "dependency_failure",
        "expected_actions": ["application.recover_worker"],
    },
    {
        "id": "B04-04",
        "group": "A",
        "title": "Backend dependency unavailable",
        "target": "svc-web-01",
        "faults": ["backend_stopped"],
        "oracle": "dependency_failure",
        "expected_actions": ["dependency.restore_fixture"],
    },
    {
        "id": "B04-05",
        "group": "A",
        "title": "Disposable PostgreSQL instance unavailable",
        "target": "db-01",
        "faults": ["postgres_stopped"],
        "oracle": "service_failure",
        "expected_actions": ["postgresql.start_fixture", "systemd.start"],
    },
    {
        "id": "B04-06",
        "group": "A",
        "title": "Isolated resolver misconfigured",
        "target": "svc-web-01",
        "faults": ["dns_wrong_answer"],
        "oracle": "connectivity_failure",
        "expected_actions": ["dns.restore_fixture"],
    },
    {
        "id": "B04-07",
        "group": "A",
        "title": "Isolated network route invalid",
        "target": "svc-web-01",
        "faults": ["namespace_route_invalid"],
        "oracle": "network_failure",
        "expected_actions": ["network.restore_fixture"],
    },
    {
        "id": "B04-08",
        "group": "A",
        "title": "Disposable volume reaches capacity",
        "target": "svc-web-01",
        "faults": ["storage_full"],
        "oracle": "resource_pressure",
        "expected_actions": ["storage.release_fixture"],
    },
    {
        "id": "B04-09",
        "group": "A",
        "title": "Worker CPU quota is restrictive",
        "target": "svc-web-01",
        "faults": ["worker_quota_restricted"],
        "oracle": "resource_pressure",
        "expected_actions": ["resource.restore_fixture"],
    },
    {
        "id": "B04-10",
        "group": "A",
        "title": "Proxy upstream config invalid",
        "target": "svc-web-01",
        "faults": ["proxy_config_invalid"],
        "oracle": "service_failure",
        "expected_actions": ["config.restore_fixture"],
    },
    {
        "id": "B04-11",
        "group": "B",
        "title": "Application and backend dependency fail together",
        "target": "svc-web-01",
        "faults": ["app_stopped", "backend_stopped"],
        "oracle": "dependency_failure",
        "expected_actions": ["systemd.start", "dependency.restore_fixture"],
    },
    {
        "id": "B04-12",
        "group": "B",
        "title": "DNS misconfiguration plus service crash",
        "target": "svc-web-01",
        "faults": ["dns_wrong_answer", "app_stopped"],
        "oracle": "connectivity_failure",
        "expected_actions": ["dns.restore_fixture", "systemd.start"],
    },
    {
        "id": "B04-13",
        "group": "B",
        "title": "PostgreSQL and dependent application readiness failure",
        "target": "db-01",
        "faults": ["postgres_stopped", "dbclient_stopped"],
        "oracle": "dependency_failure",
        "expected_actions": ["postgresql.start_fixture", "systemd.start"],
    },
    {
        "id": "B04-14",
        "group": "B",
        "title": "Backend and proxy config fail together",
        "target": "svc-web-01",
        "faults": ["backend_stopped", "proxy_config_invalid"],
        "oracle": "dependency_failure",
        "expected_actions": ["dependency.restore_fixture", "config.restore_fixture"],
    },
    {
        "id": "B04-15",
        "group": "B",
        "title": "Network partition and backend unavailable",
        "target": "svc-web-01",
        "faults": ["namespace_link_down", "backend_stopped"],
        "oracle": "network_failure",
        "expected_actions": ["network.restore_fixture", "dependency.restore_fixture"],
    },
    {
        "id": "B04-16",
        "group": "B",
        "title": "App config drift and worker failure",
        "target": "svc-web-01",
        "faults": ["invalid_app_config", "worker_stopped"],
        "oracle": "service_failure",
        "expected_actions": ["config.restore_fixture", "application.recover_worker"],
    },
    {
        "id": "B04-17",
        "group": "B",
        "title": "Storage pressure and app failure",
        "target": "svc-web-01",
        "faults": ["storage_full", "app_stopped"],
        "oracle": "resource_pressure",
        "expected_actions": ["storage.release_fixture", "systemd.start"],
    },
    {
        "id": "B04-18",
        "group": "B",
        "title": "Restrictive worker quota and HTTP timeout",
        "target": "svc-web-01",
        "faults": ["worker_quota_restricted"],
        "oracle": "resource_pressure",
        "expected_actions": ["resource.restore_fixture"],
    },
    {
        "id": "B04-19",
        "group": "B",
        "title": "Partial first recovery leaves second fault",
        "target": "svc-web-01",
        "faults": ["backend_stopped", "invalid_app_config"],
        "oracle": "dependency_failure",
        "expected_actions": ["dependency.restore_fixture", "config.restore_fixture"],
    },
    {
        "id": "B04-20",
        "group": "B",
        "title": "Two independent component failures",
        "target": "svc-web-01",
        "faults": ["backend_stopped", "worker_stopped"],
        "oracle": "dependency_failure",
        "expected_actions": ["dependency.restore_fixture", "application.recover_worker"],
    },
)

EXPECTED_CANDIDATE_REFS: dict[str, tuple[str, ...]] = {
    "B04-01": ("b04-app-unit",),
    "B04-02": ("b04-app-config",),
    "B04-03": ("b04-worker",),
    "B04-04": ("b04-backend",),
    "B04-05": ("b04-postgres", "b04-postgres-unit"),
    "B04-06": ("b04-dns",),
    "B04-07": ("b04-network",),
    "B04-08": ("b04-volume",),
    "B04-09": ("b04-worker-quota",),
    "B04-10": ("b04-proxy-config",),
    "B04-11": ("b04-app-unit", "b04-backend"),
    "B04-12": ("b04-dns", "b04-app-unit"),
    "B04-13": ("b04-postgres", "b04-postgres-unit", "b04-dbclient-unit"),
    "B04-14": ("b04-backend", "b04-proxy-config"),
    "B04-15": ("b04-network", "b04-backend"),
    "B04-16": ("b04-app-config", "b04-worker"),
    "B04-17": ("b04-volume", "b04-app-unit"),
    "B04-18": ("b04-worker-quota",),
    "B04-19": ("b04-backend", "b04-app-config"),
    "B04-20": ("b04-backend", "b04-worker"),
}


ACTION_CANDIDATES: dict[str, list[dict[str, Any]]] = {
    "svc-web-01": [
        {
            "action_id": "systemd.start",
            "target_ref": "b04-app-unit",
            "target_name": "svc-web-01",
            "arguments": {"unit": "runbookos-campaign-b04-app.service"},
            "purpose": "Start the isolated application unit only when it is inactive.",
            "required_evidence_actions": ["systemd.is_active", "http.readiness"],
            "compatible_categories": ["service_failure", "dependency_failure", "unknown"],
        },
        {
            "action_id": "systemd.restart",
            "target_ref": "b04-app-unit",
            "target_name": "svc-web-01",
            "arguments": {"unit": "runbookos-campaign-b04-app.service"},
            "purpose": "Restart the isolated application unit when it is active but its runtime is stale.",
            "required_evidence_actions": ["systemd.is_active", "http.readiness"],
            "compatible_categories": ["service_failure", "dependency_failure", "unknown"],
        },
        {
            "action_id": "config.restore_fixture",
            "target_ref": "b04-app-config",
            "target_name": "svc-web-01",
            "arguments": {"fixture_id": "app_config"},
            "purpose": "Restore the application fixture's root-owned known-good config and restart only that app unit.",
            "required_evidence_actions": ["http.readiness", "application.inspect_fixture"],
            "compatible_categories": ["service_failure", "dependency_failure", "unknown"],
        },
        {
            "action_id": "config.restore_fixture",
            "target_ref": "b04-proxy-config",
            "target_name": "svc-web-01",
            "arguments": {"fixture_id": "proxy_config"},
            "purpose": "Restore the isolated proxy's known-good upstream config and restart only that proxy unit.",
            "required_evidence_actions": ["http.readiness", "application.inspect_fixture"],
            "compatible_categories": ["service_failure", "dependency_failure", "unknown"],
        },
        {
            "action_id": "application.recover_worker",
            "target_ref": "b04-worker",
            "target_name": "svc-web-01",
            "arguments": {"fixture_id": "worker_service"},
            "purpose": "Restart the isolated worker and verify its health socket responds.",
            "required_evidence_actions": [
                "systemd.is_active",
                "network.tcp_connect",
                "http.readiness",
            ],
            "compatible_categories": [
                "service_failure",
                "dependency_failure",
                "resource_pressure",
                "unknown",
            ],
        },
        {
            "action_id": "dependency.restore_fixture",
            "target_ref": "b04-backend",
            "target_name": "svc-web-01",
            "arguments": {"fixture_id": "backend_service"},
            "purpose": "Start the isolated upstream and verify its HTTP readiness response.",
            "required_evidence_actions": ["http.readiness", "network.tcp_connect"],
            "compatible_categories": [
                "service_failure",
                "dependency_failure",
                "connectivity_failure",
                "unknown",
            ],
        },
        {
            "action_id": "dns.restore_fixture",
            "target_ref": "b04-dns",
            "target_name": "svc-web-01",
            "arguments": {"fixture_id": "resolver_config"},
            "purpose": "Restore the isolated resolver's known-good mapping and verify through its fixture unit.",
            "required_evidence_actions": [
                "dns.resolve_fixture",
                "http.readiness",
                "network.tcp_connect",
            ],
            "compatible_categories": [
                "service_failure",
                "dependency_failure",
                "connectivity_failure",
                "network_failure",
                "unknown",
            ],
        },
        {
            "action_id": "network.restore_fixture",
            "target_ref": "b04-network",
            "target_name": "svc-web-01",
            "arguments": {"fixture_id": "isolated_link"},
            "purpose": "Restore the link and route only inside the dedicated campaign network namespace.",
            "required_evidence_actions": [
                "network.tcp_connect",
                "http.readiness",
            ],
            "compatible_categories": [
                "network_failure",
                "connectivity_failure",
                "dependency_failure",
                "service_failure",
                "unknown",
            ],
        },
        {
            "action_id": "storage.release_fixture",
            "target_ref": "b04-volume",
            "target_name": "svc-web-01",
            "arguments": {"fixture_id": "bounded_volume"},
            "purpose": "Remove only bounded pressure files from the campaign's size-limited tmpfs volume.",
            "required_evidence_actions": ["os.disk", "http.readiness"],
            "compatible_categories": ["resource_pressure", "service_failure", "unknown"],
        },
        {
            "action_id": "resource.restore_fixture",
            "target_ref": "b04-worker-quota",
            "target_name": "svc-web-01",
            "arguments": {"fixture_id": "worker_quota"},
            "purpose": "Remove the campaign worker's restrictive CPU drop-in, reload systemd, and verify worker readiness.",
            "required_evidence_actions": ["resource.inspect_fixture", "http.readiness"],
            "compatible_categories": ["resource_pressure", "service_failure", "unknown"],
        },
    ],
    "db-01": [
        {
            "action_id": "systemd.start",
            "target_ref": "b04-dbclient-unit",
            "target_name": "db-01",
            "arguments": {"unit": "runbookos-campaign-b04-dbclient.service"},
            "purpose": "Start the isolated database-dependent client when its exact unit is inactive.",
            "required_evidence_actions": ["systemd.is_active"],
            "compatible_categories": ["service_failure", "dependency_failure", "unknown"],
        },
        {
            "action_id": "postgresql.start_fixture",
            "target_ref": "b04-postgres",
            "target_name": "db-01",
            "arguments": {"cluster": "16-b04"},
            "purpose": "Start only the isolated PostgreSQL 16/b04 cluster.",
            "required_evidence_actions": [
                "systemd.is_active",
                "postgresql.protocol_available",
                "http.readiness",
            ],
            "compatible_categories": ["service_failure", "dependency_failure", "unknown"],
        },
        {
            "action_id": "systemd.start",
            "target_ref": "b04-postgres-unit",
            "target_name": "db-01",
            "arguments": {"unit": "postgresql@16-b04.service"},
            "purpose": "Start the isolated PostgreSQL unit when service state alone supports that recovery.",
            "required_evidence_actions": [
                "systemd.is_active",
                "postgresql.protocol_available",
                "http.readiness",
            ],
            "compatible_categories": ["service_failure", "dependency_failure", "unknown"],
        },
        {
            "action_id": "systemd.restart",
            "target_ref": "b04-postgres-unit",
            "target_name": "db-01",
            "arguments": {"unit": "postgresql@16-b04.service"},
            "purpose": "Restart the isolated PostgreSQL cluster if it is active but unresponsive.",
            "required_evidence_actions": [
                "systemd.is_active",
                "postgresql.protocol_available",
                "http.readiness",
            ],
            "compatible_categories": ["service_failure", "dependency_failure", "unknown"],
        },
    ],
}


def candidate_catalog(target: str) -> list[dict[str, Any]]:
    """Return every campaign-eligible action for the target, without oracle filtering."""
    return [dict(item) for item in ACTION_CANDIDATES[target]]


def action_is_oracle_appropriate(scenario: dict[str, Any], action_id: str, target_ref: str) -> bool:
    """Independent evaluator only; never called while building model context."""
    return (
        action_id in scenario["expected_actions"]
        and target_ref in EXPECTED_CANDIDATE_REFS[scenario["id"]]
    )


def validate_ledger(attempts: list[dict[str, Any]]) -> None:
    seen: set[str] = set()
    for item in attempts:
        run_id = item.get("run_id")
        if not isinstance(run_id, str) or run_id in seen:
            raise ValueError("batch 04 run IDs must be unique")
        retry_of = item.get("retry_of")
        if retry_of and retry_of not in seen:
            raise ValueError("batch 04 retry must reference a preceding attempt")
        seen.add(run_id)
        if item.get("result") != "AI_DRIVEN_PASS":
            continue
        steps = item.get("steps", {})
        required = (
            "baseline",
            "fault",
            "incident",
            "diagnostics",
            "assessment",
            "proposal",
            "authorization",
            "remediation",
            "postflight",
            "closure",
            "audit",
            "cleanup",
        )
        if any(steps.get(name, {}).get("status") != "PASS" for name in required):
            raise ValueError("batch 04 success is missing a required stage")
        execution_ids = []
        for recovery_round in item.get("recovery_rounds", []):
            proposed = recovery_round.get("proposal", {})
            executed = recovery_round.get("remediation", {})
            if proposed.get("status") != "PASS" or executed.get("status") != "PASS":
                raise ValueError("batch 04 success includes an unsuccessful recovery round")
            if proposed.get("selected_action_id") != executed.get("action_id") or proposed.get(
                "target_ref"
            ) != executed.get("target_ref"):
                raise ValueError("recovery round executed action differs from proposal")
            execution_id = executed.get("execution_id")
            if not execution_id or execution_id in execution_ids:
                raise ValueError("recovery rounds require unique execution IDs")
            execution_ids.append(execution_id)
        proposal = steps["proposal"]
        candidate_set = proposal.get("candidate_catalog")
        if not isinstance(candidate_set, list) or len(candidate_set) < 2:
            raise ValueError("AI proposal was not given multiple eligible alternatives")
        if proposal.get("selected_action_id") != steps["remediation"].get("action_id"):
            raise ValueError("executed action differs from the AI proposal")
        if proposal.get("target_ref") != steps["remediation"].get("target_ref"):
            raise ValueError("executed target differs from the AI proposal")
