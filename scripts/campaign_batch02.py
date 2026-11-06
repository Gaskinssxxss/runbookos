"""Safety helpers for the local, disposable RunbookOS Batch 02 campaign.

This module is test-only orchestration support. It does not construct arbitrary
commands or alter RunbookOS authorization behavior.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class InvestigationBudget:
    configured_seconds: int
    conservative_required_seconds: int
    action_count: int


def calculate_investigation_budget(
    action_timeouts: list[int],
    *,
    ssh_connect_timeout: int = 5,
    ssh_alive_interval: int = 5,
    per_action_overhead: int = 2,
    configured_seconds: int = 90,
) -> InvestigationBudget:
    """Check a fixed budget against bounded remote-action cost, without widening it."""
    if not action_timeouts or any(
        isinstance(value, bool) or not isinstance(value, int) or value < 1 or value > 10
        for value in action_timeouts
    ):
        raise ValueError("diagnostic action timeouts must be integers from 1 through 10")
    if min(ssh_connect_timeout, ssh_alive_interval, per_action_overhead) < 0:
        raise ValueError("budget overhead values cannot be negative")
    required = sum(
        timeout + ssh_connect_timeout + ssh_alive_interval + per_action_overhead
        for timeout in action_timeouts
    )
    if required > configured_seconds:
        raise ValueError("diagnostic cost exceeds the existing bounded execution budget")
    return InvestigationBudget(configured_seconds, required, len(action_timeouts))


def accepted_assessment(assessment: dict[str, Any] | None) -> bool:
    """Only validated persisted M1/M2 assessments may proceed to a plan."""
    if not isinstance(assessment, dict) or assessment.get("accepted") is not True:
        return False
    return assessment.get("assessment_status") in {"assessed", "abstained"}


def workflow_can_close(
    *,
    assessment: dict[str, Any] | None,
    remediation_succeeded: bool,
    postflight_recovered: bool,
    audit_valid: bool,
    sqlite_valid: bool,
) -> bool:
    """Prevent a failed investigation, action, recovery, or integrity check closing an incident."""
    return (
        accepted_assessment(assessment)
        and remediation_succeeded is True
        and postflight_recovered is True
        and audit_valid is True
        and sqlite_valid is True
    )


def retry_run_id(scenario_id: str, attempt: int) -> str:
    if not scenario_id.startswith("B02-") or attempt < 1:
        raise ValueError("invalid Batch 02 retry identity")
    return f"batch02-{scenario_id}-attempt{attempt:02d}"


def evidence_references_valid(cited: list[str], available: list[str]) -> bool:
    """Check model citations against the incident's persisted execution references."""
    return (
        isinstance(cited, list)
        and all(isinstance(ref, str) for ref in cited)
        and len(cited) == len(set(cited))
        and set(cited) <= set(available)
    )


def adjudicate_observation_claims(
    statement: str, observations: list[dict[str, Any]]
) -> dict[str, Any]:
    """Compare explicit factual phrases only with their cited persisted values.

    This deliberately does not adjudicate causality. Unmatched prose stays
    insufficient, and a contradictory direct observation is surfaced.
    """
    text = statement.lower()
    indexed: list[tuple[dict[str, Any], dict[str, Any], str, str]] = []
    for observation in observations:
        result = observation.get("observed_result", {})
        data = result.get("data", {}) if isinstance(result, dict) else {}
        searchable = " ".join(
            str(value)
            for value in (
                observation.get("step_id", ""),
                observation.get("source_action", ""),
                observation.get("statement", ""),
            )
        ).lower()
        error = str(result.get("error") or "").lower() if isinstance(result, dict) else ""
        indexed.append((observation, data, searchable, error))

    checks: list[dict[str, Any]] = []

    def add(
        label: str, candidates: list[tuple[dict[str, Any], dict[str, Any], str, str]], predicate
    ) -> None:
        if not candidates:
            checks.append({"claim": label, "result": "insufficient", "evidence_refs": []})
            return
        matching = [item for item in candidates if predicate(item)]
        checks.append(
            {
                "claim": label,
                "result": "supported" if matching else "contradicted",
                "evidence_refs": [
                    item[0].get("ref") for item in (matching or candidates) if item[0].get("ref")
                ],
            }
        )

    status_match = re.search(r"\bhttp(?:\s+status)?\s+(\d{3})\b", text)
    if status_match and 100 <= int(status_match.group(1)) <= 599:
        expected = int(status_match.group(1))
        candidates = [item for item in indexed if "http" in item[2] and "http_status" in item[1]]
        add(
            f"HTTP status {expected}",
            candidates,
            lambda item: item[1].get("http_status") == expected,
        )

    if re.search(
        r"\bhttp(?:\s+readiness)?\s+checks?\s+succeed(?:ed)?\b|\blocal http checks succeed\b", text
    ):
        candidates = [item for item in indexed if "http" in item[2] and "http_status" in item[1]]
        add(
            "HTTP check succeeded",
            candidates,
            lambda item: (
                isinstance(item[1].get("http_status"), int) and 200 <= item[1]["http_status"] < 300
            ),
        )

    endpoint_terms = ("database", "postgres", "backend", "worker", "dns")
    mentioned = [term for term in endpoint_terms if term in text]
    selected = (
        [item for item in indexed if any(term in item[2] for term in mentioned)]
        if mentioned
        else indexed
    )
    if "database" in mentioned:
        selected = [item for item in indexed if "db-01" in item[2]] or selected
    if "connection refused" in text or "refused connections" in text:
        candidates = [
            item
            for item in selected
            if item[1].get("connected") is False or item[1].get("protocol_available") is False
        ]
        add(
            "connection refused",
            candidates,
            lambda item: "connectionrefusederror" in item[3] or "refused" in item[3],
        )
    if "times out" in text or "timed out" in text or "timeout" in text:
        candidates = [item for item in selected if item[1].get("connected") is False]
        add("connection timeout", candidates, lambda item: "timeout" in item[3])
    if "unreachable" in text or "cannot reach" in text or "not reachable" in text:
        candidates = [item for item in selected if "connected" in item[1] or "reachable" in item[1]]
        add(
            "endpoint unreachable",
            candidates,
            lambda item: item[1].get("connected", item[1].get("reachable")) is False,
        )
    if (
        "connectivity established" in text
        or "connectivity succeeded" in text
        or "connectivity ... succeeded" in text
    ):
        candidates = [item for item in selected if "connected" in item[1] or "reachable" in item[1]]
        add(
            "endpoint connectivity succeeded",
            candidates,
            lambda item: item[1].get("connected", item[1].get("reachable")) is True,
        )

    if "inactive" in text or "failed to start" in text or "unit failed" in text:
        candidates = [
            item
            for item in indexed
            if "systemd.is_active" in item[2] or "unit" in item[2] and "active" in item[1]
        ]
        add(
            "unit inactive or failed",
            candidates,
            lambda item: item[1].get("active") is False or item[1].get("state") == "failed",
        )
    elif (
        "unit active" in text
        or "service active" in text
        or "process remained active" in text
        or "unit being active" in text
    ):
        candidates = [
            item
            for item in indexed
            if "systemd.is_active" in item[2] or "unit" in item[2] and "active" in item[1]
        ]
        add("unit active", candidates, lambda item: item[1].get("active") is True)

    results = {item["result"] for item in checks}
    overall = (
        "contradicted"
        if "contradicted" in results
        else "supported"
        if checks and results == {"supported"}
        else "insufficient"
    )
    return {
        "rubric": "B02-direct-observation-v2",
        "observation_claim_support": overall,
        "checks": checks,
        "causal_claim_support": "insufficient",
        "uses_ground_truth": False,
        "semantic_root_cause": "NOT_MEASURED",
    }


def resolve_runuser_path(
    candidates: tuple[str, ...] = ("/usr/sbin/runuser", "/usr/bin/runuser"),
) -> str:
    """Resolve the actual guest executable path; do not assume it lives in /usr/bin."""
    for candidate in candidates:
        path = Path(candidate)
        if path.is_file() and path.stat().st_mode & 0o111:
            return str(path)
    raise FileNotFoundError("runuser executable not found in verified system paths")


def fixture_start_limit(*, interval_seconds: int = 5, burst: int = 3) -> str:
    if not 1 <= interval_seconds <= 60 or not 1 <= burst <= 5:
        raise ValueError("fixture restart limits must remain tightly bounded")
    return f"StartLimitIntervalSec={interval_seconds}\nStartLimitBurst={burst}"


def resource_fault_profile() -> dict[str, Any]:
    """Bounded CPU-throttling fixture profile; intentionally avoids OOM fault injection."""
    return {
        "mechanism": "fixture worker CPU loop under systemd CPUQuota",
        "cpu_quota_percent": 20,
        "memory_max_bytes": 384 * 1024 * 1024,
        "host_wide_resource_exhaustion": False,
        "oom_injection": False,
    }
