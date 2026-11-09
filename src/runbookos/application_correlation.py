"""Conservative correlation of registered application observations."""

from __future__ import annotations

from typing import Any


def correlate_application(
    steps: list[dict[str, Any]],
    target: str,
    application_id: str,
    profile: Any,
    authorized_storage_ids: frozenset[str] = frozenset(),
) -> dict[str, Any]:
    signals: list[dict[str, str]] = []
    host_context: list[dict[str, Any]] = []
    unknown_steps: list[str] = []
    dependencies: dict[str, str] = {}
    health: dict[str, Any] = {"status": "missing", "http_status": None, "step_id": None}
    relevant = [step for step in steps if step.get("target") == target]

    def observed(signal: str, step_id: str) -> None:
        signals.append({"signal": signal, "step_id": step_id, "claim_status": "observed"})

    for endpoint_id in profile.dependency_endpoint_ids:
        matching = [
            step
            for step in relevant
            if step.get("action") in {"network.tcp_connect", "network.reachability"}
            and isinstance(step.get("evidence"), dict)
            and isinstance(step["evidence"].get("data"), dict)
            and step["evidence"]["data"].get("endpoint_id") == endpoint_id
        ]
        if not matching:
            dependencies[endpoint_id] = "missing"
            continue
        step = matching[-1]
        data = step["evidence"]["data"]
        if (
            step.get("status") != "succeeded"
            or type(data.get("connected")) is not bool
            or step["evidence"].get("error") in {"TimeoutError", "timeout"}
        ):
            dependencies[endpoint_id] = "unknown"
            unknown_steps.append(step["step_id"])
        elif data["connected"]:
            dependencies[endpoint_id] = "healthy"
        else:
            dependencies[endpoint_id] = "unhealthy"
            observed("upstream_unavailable", step["step_id"])

    for step in relevant:
        step_id = step.get("step_id")
        if not isinstance(step_id, str):
            continue
        evidence = step.get("evidence")
        data = evidence.get("data") if isinstance(evidence, dict) else None
        if not isinstance(data, dict):
            continue
        action = step.get("action")
        if (
            action
            in {
                "application.health",
                "application.queue_health",
                "application.config_fingerprint",
                "application.deploy_version",
            }
            and data.get("application_id") != application_id
        ):
            continue
        if action == "application.health":
            health = {
                "status": data.get("status")
                if step.get("status") == "succeeded"
                and data.get("status") in {"healthy", "unhealthy", "redirect"}
                else "unknown",
                "http_status": data.get("http_status")
                if type(data.get("http_status")) is int
                else None,
                "step_id": step_id,
            }
        if action == "filesystem.pressure":
            storage_id = data.get("storage_id")
            storage_related = isinstance(storage_id, str) and storage_id in authorized_storage_ids
            status = data.get("status")
            if step.get("status") != "succeeded" or status not in {
                "available",
                "byte_full",
                "inode_full",
                "both_full",
            }:
                unknown_steps.append(step_id)
                if not storage_related:
                    host_context.append(
                        {
                            "signal": "storage_pressure_unavailable",
                            "step_id": step_id,
                            "storage_id": storage_id if isinstance(storage_id, str) else None,
                            "scope": "host_context",
                            "claim_status": "unknown",
                        }
                    )
            elif status in {"byte_full", "inode_full", "both_full"}:
                if storage_related:
                    observed("resource_pressure", step_id)
                else:
                    host_context.append(
                        {
                            "signal": "storage_pressure",
                            "step_id": step_id,
                            "storage_id": storage_id if isinstance(storage_id, str) else None,
                            "scope": "host_context",
                            "claim_status": "observed",
                        }
                    )
            continue
        if step.get("status") != "succeeded" or data.get("status") == "unknown":
            if action and (
                action.startswith("application.")
                or action in {"network.tls_certificate", "network.listener"}
            ):
                unknown_steps.append(step_id)
            continue
        if action == "application.health" and data.get("http_status") in {502, 503}:
            observed("http_gateway_unavailable", step_id)
        elif action == "application.queue_health" and data.get("status") == "backlog":
            observed("queue_backlog", step_id)
        elif action == "application.config_fingerprint" and data.get("status") == "drift":
            observed("config_drift", step_id)
        elif action == "application.deploy_version" and data.get("status") == "drift":
            observed("version_drift", step_id)
        elif (
            action == "systemd.service_status"
            and data.get("unit") == profile.worker_unit
            and data.get("active") is False
        ):
            observed("worker_stopped", step_id)
        elif (
            action == "network.listener"
            and data.get("endpoint_id")
            in {profile.health_endpoint_id, *profile.dependency_endpoint_ids}
            and data.get("status") in {"port_closed", "address_mismatch"}
        ):
            observed("listener_unavailable", step_id)
        elif (
            action == "network.tls_certificate"
            and data.get("certificate_status")
            in {
                "expired",
                "hostname_mismatch",
                "invalid_chain",
                "invalid_certificate",
            }
            and data.get("endpoint_id")
            in {profile.health_endpoint_id, *profile.dependency_endpoint_ids}
        ):
            observed("tls_invalid", step_id)
    return {
        "application_id": application_id,
        "target": target,
        "health": health,
        "dependencies": dependencies,
        "signals": signals[:32],
        "host_context": host_context[:32],
        "unknown_steps": sorted(set(unknown_steps))[:32],
        "verified_root_cause": False,
    }
