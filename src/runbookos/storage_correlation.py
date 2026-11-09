"""Conservative correlation of persisted storage observations."""

from __future__ import annotations

from typing import Any


def correlate_storage(steps: list[dict[str, Any]]) -> dict[str, Any]:
    """Return observed signals without promoting them to verified causes."""
    signals: list[dict[str, str]] = []
    unknown_steps: list[str] = []
    for step in steps:
        action = step.get("action")
        if not isinstance(action, str) or not (
            action.startswith("filesystem.") or action == "os.disk"
        ):
            continue
        step_id = step.get("step_id")
        if not isinstance(step_id, str):
            continue
        if step.get("status") != "succeeded":
            unknown_steps.append(step_id)
            evidence = step.get("evidence")
            if isinstance(evidence, dict) and evidence.get("error") == "permission_denied":
                signals.append(
                    {
                        "signal": "inspection_permission_denied",
                        "step_id": step_id,
                        "claim_status": "observed",
                    }
                )
            continue
        evidence = step.get("evidence")
        if not isinstance(evidence, dict) or not isinstance(evidence.get("data"), dict):
            unknown_steps.append(step_id)
            continue
        data = evidence["data"]
        status = data.get("status")
        observed: list[str] = []
        if action == "filesystem.pressure":
            if status in {"byte_full", "both_full"}:
                observed.append("byte_capacity_exhausted")
            if status in {"inode_full", "both_full"}:
                observed.append("inode_capacity_exhausted")
            if data.get("read_only") is True:
                observed.append("filesystem_read_only")
        elif action == "os.disk" and status == "full":
            observed.append("byte_capacity_exhausted")
        elif action == "filesystem.inodes" and status == "full":
            observed.append("inode_capacity_exhausted")
        elif action == "filesystem.mount_status":
            if status == "missing" and data.get("inventory_complete") is True:
                observed.append("expected_mount_missing")
            if status == "present" and data.get("read_only") is True:
                observed.append("filesystem_read_only")
        elif (
            action == "filesystem.log_growth"
            and status == "growing"
            and isinstance(data.get("snapshots"), list)
            and len(data["snapshots"]) >= 2
        ):
            observed.append("log_size_increased")
        elif (
            action in {"filesystem.path_metadata", "filesystem.usage_summary"}
            and status == "unknown"
        ):
            unknown_steps.append(step_id)
        for signal in observed:
            signals.append({"signal": signal, "step_id": step_id, "claim_status": "observed"})
    return {"signals": signals, "unknown_steps": unknown_steps, "verified_root_cause": False}
