"""Reliability primitives for the disposable Batch 03 campaign runner."""

from __future__ import annotations

import json
import os
import tempfile
import time
from collections.abc import Callable, Iterable
from enum import StrEnum
from pathlib import Path
from typing import Any


class WorkflowState(StrEnum):
    CREATED = "created"
    PROVISIONED = "provisioned"
    BASELINE_VERIFIED = "baseline_verified"
    FAULT_CONFIRMED = "fault_confirmed"
    INCIDENT_RECORDED = "incident_recorded"
    DIAGNOSED = "diagnosed"
    PROPOSED = "proposed"
    AUTHORIZED = "authorized"
    REMEDIATED = "remediated"
    RECOVERED = "recovered"
    CLOSED = "closed"
    CLEANED = "cleaned"
    FAILED = "failed"


_NEXT = {
    WorkflowState.CREATED: {WorkflowState.PROVISIONED, WorkflowState.FAILED},
    WorkflowState.PROVISIONED: {WorkflowState.BASELINE_VERIFIED, WorkflowState.FAILED},
    WorkflowState.BASELINE_VERIFIED: {WorkflowState.FAULT_CONFIRMED, WorkflowState.FAILED},
    WorkflowState.FAULT_CONFIRMED: {WorkflowState.INCIDENT_RECORDED, WorkflowState.FAILED},
    WorkflowState.INCIDENT_RECORDED: {WorkflowState.DIAGNOSED, WorkflowState.FAILED},
    WorkflowState.DIAGNOSED: {WorkflowState.PROPOSED, WorkflowState.FAILED},
    WorkflowState.PROPOSED: {WorkflowState.AUTHORIZED, WorkflowState.FAILED},
    WorkflowState.AUTHORIZED: {WorkflowState.REMEDIATED, WorkflowState.FAILED},
    WorkflowState.REMEDIATED: {WorkflowState.RECOVERED, WorkflowState.FAILED},
    WorkflowState.RECOVERED: {WorkflowState.CLOSED, WorkflowState.FAILED},
    WorkflowState.CLOSED: {WorkflowState.CLEANED, WorkflowState.FAILED},
    WorkflowState.CLEANED: set(),
    WorkflowState.FAILED: set(),
}


def advance(state: WorkflowState, next_state: WorkflowState) -> WorkflowState:
    if next_state not in _NEXT[state]:
        raise ValueError(f"invalid campaign transition: {state} -> {next_state}")
    return next_state


def stable_condition(
    observe: Callable[[], Any],
    predicate: Callable[[Any], bool],
    *,
    timeout_seconds: float,
    poll_interval_seconds: float = 0.25,
    consecutive_successes: int = 2,
) -> Any:
    """Wait for repeated observed readiness under one bounded deadline."""
    if timeout_seconds <= 0 or poll_interval_seconds <= 0 or consecutive_successes < 1:
        raise ValueError("condition wait bounds must be positive")
    deadline = time.monotonic() + timeout_seconds
    consecutive = 0
    last: Any = None
    while time.monotonic() < deadline:
        last = observe()
        consecutive = consecutive + 1 if predicate(last) else 0
        if consecutive >= consecutive_successes:
            return last
        time.sleep(min(poll_interval_seconds, max(0.0, deadline - time.monotonic())))
    raise TimeoutError("bounded fixture readiness condition was not met")


def restore_fixture(
    commands: Iterable[tuple[str, ...]],
    execute: Callable[[tuple[str, ...]], dict[str, Any]],
    observe: Callable[[], Any],
    healthy: Callable[[Any], bool],
    *,
    timeout_seconds: float = 30,
) -> Any:
    """Run explicit restoration steps and prove stable health before reuse."""
    for command in commands:
        result = execute(command)
        if result.get("exit_code") != 0:
            raise RuntimeError("campaign fixture restoration command failed")
    return stable_condition(
        observe,
        healthy,
        timeout_seconds=timeout_seconds,
        consecutive_successes=2,
    )


def write_ledger(path: Path, ledger: dict[str, Any]) -> None:
    """Atomically checkpoint a private JSON ledger without replacing history."""
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd, name = tempfile.mkstemp(prefix=".batch03-", dir=path.parent)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(ledger, stream, sort_keys=True, indent=2, ensure_ascii=False)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(name, path)
        directory = os.open(path.parent, os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    except Exception:
        try:
            os.unlink(name)
        except FileNotFoundError:
            pass
        raise


def synchronize_ledger(
    payload: bytes,
    write: Callable[[bytes], None],
    verify: Callable[[bytes], bool],
    *,
    attempts: int = 2,
) -> dict[str, Any]:
    """Retry only idempotent exact-byte ledger copy, then verify its digest."""
    if not 1 <= attempts <= 2:
        raise ValueError("ledger synchronization permits at most two bounded attempts")
    failures: list[str] = []
    for attempt in range(1, attempts + 1):
        try:
            write(payload)
            if verify(payload):
                return {"status": "PASS", "attempts": attempt}
            failures.append("digest_mismatch")
        except Exception as exc:
            failures.append(type(exc).__name__)
    return {"status": "FAIL", "attempts": attempts, "failure_categories": failures}


def validate_ledger(ledger: dict[str, Any]) -> None:
    seen: set[str] = set()
    for attempt in ledger.get("attempts", []):
        run_id = attempt.get("run_id")
        if not isinstance(run_id, str) or run_id in seen:
            raise ValueError("campaign attempt IDs must be unique strings")
        seen.add(run_id)
        if attempt.get("retry_of") and attempt["retry_of"] not in seen:
            raise ValueError("retry parent must precede its retry")
        if attempt.get("result") == "AI_DRIVEN_PASS":
            phases = attempt.get("steps", attempt)
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
                "audit",
                "closure",
                "cleanup",
            )
            if any(phases.get(name, {}).get("status") != "PASS" for name in required):
                raise ValueError("AI-driven pass is missing a required verified phase")
            proposal = phases["proposal"]
            remediation = phases["remediation"]
            if proposal.get("selected_action_id") != remediation.get("action_id"):
                raise ValueError("executed action differs from the accepted AI proposal")
            if proposal.get("target_ref") != remediation.get("target_ref"):
                raise ValueError("executed target differs from the accepted AI proposal")
            if proposal.get("validated_candidate", {}).get("arguments") != remediation.get(
                "arguments"
            ):
                raise ValueError("executed arguments differ from the accepted AI proposal")
            proposal_followups = phases.get("proposal_followups", [])
            remediation_followups = phases.get("remediation_followups", [])
            authorization_followups = phases.get("authorization_followups", [])
            if not (
                isinstance(proposal_followups, list)
                and isinstance(remediation_followups, list)
                and isinstance(authorization_followups, list)
                and len(proposal_followups)
                == len(remediation_followups)
                == len(authorization_followups)
            ):
                raise ValueError("compound proposal, authorization, and execution records differ")
            for proposed, authorized, executed in zip(
                proposal_followups, authorization_followups, remediation_followups, strict=True
            ):
                if (
                    proposed.get("status") != "PASS"
                    or authorized.get("status") != "PASS"
                    or executed.get("status") != "PASS"
                    or proposed.get("selected_action_id") != executed.get("action_id")
                    or proposed.get("target_ref") != executed.get("target_ref")
                    or proposed.get("validated_candidate", {}).get("arguments")
                    != executed.get("arguments")
                    or not authorized.get("plan_id")
                    or authorized.get("plan_id") != executed.get("plan_id")
                ):
                    raise ValueError("follow-up execution differs from the accepted AI proposal")
