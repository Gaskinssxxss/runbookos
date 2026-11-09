"""Conservative, endpoint-scoped correlation of database observations."""

from __future__ import annotations

from typing import Any


def correlate_database(
    steps: list[dict[str, Any]],
    target: str,
    endpoint_id: str,
    storage_ids: frozenset[str] = frozenset(),
) -> dict[str, Any]:
    observations: list[dict[str, str]] = []
    unknown: list[str] = []
    missing: list[str] = []
    checks: dict[str, str] = {}
    relevant = [step for step in steps if step.get("target") == target]

    def add(signal: str, step_id: str) -> None:
        observations.append({"signal": signal, "step_id": step_id, "claim_status": "observed"})

    for action, check in (
        ("postgresql.protocol_available", "protocol"),
        ("postgresql.inspect", "readiness"),
        ("postgresql.inspect", "connections"),
        ("postgresql.inspect", "replication"),
        ("postgresql.inspect", "sessions"),
    ):
        candidates = [
            step
            for step in relevant
            if step.get("action") == action
            and isinstance(step.get("evidence"), dict)
            and isinstance(step["evidence"].get("data"), dict)
            and step["evidence"]["data"].get("endpoint_id") == endpoint_id
            and (action != "postgresql.inspect" or step["evidence"]["data"].get("check") == check)
        ]
        if not candidates:
            checks[check] = "missing"
            missing.append(check)
            continue
        step = candidates[-1]
        step_id = step.get("step_id")
        data = step["evidence"]["data"]
        if not isinstance(step_id, str):
            checks[check] = "unknown"
            continue
        if step.get("status") != "succeeded" or step["evidence"].get("error"):
            checks[check] = "unknown"
            unknown.append(step_id)
            if check == "readiness" and step["evidence"].get("error") == "authentication_denied":
                add("authentication_denied", step_id)
            continue
        if check == "protocol":
            available = data.get("protocol_available")
            checks[check] = (
                "healthy" if available is True else "unhealthy" if available is False else "unknown"
            )
            if available is False:
                add("protocol_unavailable", step_id)
        elif data.get("query_succeeded") is not True:
            checks[check] = "unknown"
            unknown.append(step_id)
        else:
            checks[check] = "observed"
            if check == "connections" and data.get("possible_exhaustion") is True:
                add("connection_pressure", step_id)
            if check == "sessions":
                if (
                    type(data.get("long_transaction_count")) is int
                    and data["long_transaction_count"] > 0
                ):
                    add("long_transactions", step_id)
                if type(data.get("waiting_count")) is int and data["waiting_count"] > 0:
                    add("waiting_sessions", step_id)
            if check == "replication" and data.get("replication_evidence") == "observed":
                lag = data.get("max_replay_lag_seconds")
                if type(lag) in (float, int) and lag > 30:
                    add("replication_lag", step_id)
    for step in relevant:
        if step.get("action") != "filesystem.pressure" or not isinstance(
            step.get("evidence"), dict
        ):
            continue
        data = step["evidence"].get("data")
        if not isinstance(data, dict) or data.get("storage_id") not in storage_ids:
            continue
        if step.get("status") == "succeeded" and data.get("status") in {
            "byte_full",
            "inode_full",
            "both_full",
        }:
            if isinstance(step.get("step_id"), str):
                add("storage_pressure", step["step_id"])
    return {
        "target": target,
        "endpoint_id": endpoint_id,
        "checks": checks,
        "observations": observations[:32],
        "unknown_steps": sorted(set(unknown))[:32],
        "missing_checks": missing,
        "verified_root_cause": False,
    }
