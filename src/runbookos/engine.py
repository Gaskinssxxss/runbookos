from __future__ import annotations

import hashlib
import re
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from . import __version__
from .actions import REGISTRY, validate_argument_keys, validate_phase_action
from .config import file_digest, load_inventory, load_policy, load_runbook, load_ssh_profiles
from .errors import ApprovalError, ConfigurationError, ExecutionUnknown, PolicyDenied
from .models import Assertion, PlanAction, PlanDocument, Runbook
from .remote import REMOTE_SOURCE
from .ssh import SSHAdapter
from .store import SQLiteStore, canonical_json

_RANK = {"low": 0, "medium": 1, "high": 2}
_PARAM_REF = re.compile(r"^\$param\.([a-z][a-z0-9_]*)$")


@dataclass(frozen=True)
class Paths:
    inventory: Path
    policy: Path
    ssh_profiles: Path
    database: Path


def now() -> str:
    return datetime.now(UTC).isoformat()


def validate_parameters(runbook: Runbook, supplied: dict[str, Any]) -> dict[str, Any]:
    unknown = set(supplied) - set(runbook.parameters)
    if unknown:
        raise ConfigurationError(f"unknown runbook parameter(s): {', '.join(sorted(unknown))}")
    values: dict[str, Any] = {}
    for name, spec in runbook.parameters.items():
        if name in supplied:
            value = supplied[name]
        elif spec.default is not None:
            value = spec.default
        elif spec.required:
            raise ConfigurationError(f"required parameter missing: {name}")
        else:
            value = None
        if value is None and not spec.required:
            values[name] = None
            continue
        if spec.type == "string" and not isinstance(value, str):
            raise ConfigurationError(f"parameter {name} must be a string")
        if spec.type == "integer" and (type(value) is not int):
            raise ConfigurationError(f"parameter {name} must be an integer")
        if spec.type == "boolean" and type(value) is not bool:
            raise ConfigurationError(f"parameter {name} must be a boolean")
        if spec.choices is not None and value not in spec.choices:
            raise ConfigurationError(f"parameter {name} must be one of {spec.choices!r}")
        if type(value) is int:
            if spec.minimum is not None and value < spec.minimum:
                raise ConfigurationError(f"parameter {name} must be >= {spec.minimum}")
            if spec.maximum is not None and value > spec.maximum:
                raise ConfigurationError(f"parameter {name} must be <= {spec.maximum}")
        if isinstance(value, str) and spec.pattern and not re.fullmatch(spec.pattern, value):
            raise ConfigurationError(f"parameter {name} does not match its required pattern")
        values[name] = value
    return values


def _expand(value: Any, parameters: dict[str, Any]) -> Any:
    if isinstance(value, str):
        match = _PARAM_REF.fullmatch(value)
        if match:
            name = match.group(1)
            if name not in parameters:
                raise ConfigurationError(f"unknown parameter reference: {name}")
            return parameters[name]
        if "$param." in value:
            raise ConfigurationError("parameter references must occupy the entire YAML scalar")
        return value
    if isinstance(value, list):
        return [_expand(item, parameters) for item in value]
    if isinstance(value, dict):
        return {key: _expand(item, parameters) for key, item in value.items()}
    return value


def _walk_values(value: Any):
    if isinstance(value, dict):
        for item in value.values():
            yield from _walk_values(item)
    elif isinstance(value, list):
        for item in value:
            yield from _walk_values(item)
    else:
        yield value


def _get_path(value: dict[str, Any], path: str) -> Any:
    current: Any = value
    for part in path.split("."):
        if isinstance(current, dict) and part in current:
            current = current[part]
        else:
            raise ConfigurationError(f"assertion path not present in action result: {path}")
    return current


def check_assertion(assertion: Assertion, result: dict[str, Any]) -> tuple[bool, str]:
    actual = _get_path(result, assertion.path)
    expected = assertion.value
    op = assertion.operator
    if op == "eq":
        passed = actual == expected
    elif op == "neq":
        passed = actual != expected
    elif op == "lt":
        passed = actual < expected
    elif op == "lte":
        passed = actual <= expected
    elif op == "gt":
        passed = actual > expected
    elif op == "gte":
        passed = actual >= expected
    elif op == "empty":
        passed = actual in (None, "", [], {}, ())
    elif op == "nonempty":
        passed = actual not in (None, "", [], {}, ())
    elif op == "is_true":
        passed = actual is True
    else:
        raise ConfigurationError(f"unsupported assertion operator: {op}")
    return passed, f"{assertion.path} {op} {expected!r}; actual={actual!r}"


def validate_runbook(runbook: Runbook) -> None:
    rank = 0
    for phase in ("preflight", "steps", "postflight"):
        steps = getattr(runbook, phase)
        for step in steps:
            definition = REGISTRY.get(step.action)
            if definition is None:
                raise ConfigurationError(
                    f"unregistered action {step.action!r}; arbitrary commands are not supported"
                )
            if step.timeout_seconds > definition.max_timeout_seconds:
                raise ConfigurationError(
                    f"timeout for {step.action} exceeds its {definition.max_timeout_seconds}s limit"
                )
            if phase in {"preflight", "postflight"} and not definition.read_only:
                raise ConfigurationError(f"{phase} action {step.action} must be read-only")
            validate_argument_keys(step.action, step.arguments)
            for value in _walk_values(step.arguments):
                if isinstance(value, str) and "$param." in value:
                    match = _PARAM_REF.fullmatch(value)
                    if not match or match.group(1) not in runbook.parameters:
                        raise ConfigurationError(
                            f"invalid or unknown parameter reference: {value!r}"
                        )
            rank = max(rank, _RANK[definition.risk])
    if _RANK[runbook.metadata.risk] < rank:
        raise ConfigurationError(
            f"declared runbook risk {runbook.metadata.risk} is lower than action risk"
        )


def _source_hashes(runbook_path: Path, paths: Paths) -> dict[str, str]:
    # Bind plans/approvals to action semantics as well as input configuration. Older
    # plans do not contain this key and therefore require re-planning/re-approval.
    implementation = {
        "version": __version__,
        "remote_dispatcher": hashlib.sha256(REMOTE_SOURCE.encode()).hexdigest(),
        "core_modules": {
            name: hashlib.sha256(Path(__file__).with_name(f"{name}.py").read_bytes()).hexdigest()
            for name in ("actions", "config", "engine", "models", "remote", "ssh")
        },
        "actions": [
            {
                "name": item.name,
                "read_only": item.read_only,
                "required": sorted(item.required_arguments),
                "optional": sorted(item.optional_arguments),
                "risk": item.risk,
                "max_timeout_seconds": item.max_timeout_seconds,
                "arguments_schema": (
                    item.arguments_model.model_json_schema()
                    if item.arguments_model is not None
                    else None
                ),
            }
            for _, item in sorted(REGISTRY.items())
        ],
    }
    return {
        "runbook": file_digest(runbook_path),
        "inventory": file_digest(paths.inventory),
        "policy": file_digest(paths.policy),
        "ssh_profiles": file_digest(paths.ssh_profiles),
        "implementation": hashlib.sha256(canonical_json(implementation).encode()).hexdigest(),
    }


def _plan_hash(document: dict[str, Any]) -> str:
    body = {
        key: value
        for key, value in document.items()
        if key not in {"plan_id", "created_at", "plan_hash"}
    }
    return hashlib.sha256(canonical_json(body).encode()).hexdigest()


class RunbookEngine:
    def __init__(self, paths: Paths) -> None:
        self.paths = paths
        self.store = SQLiteStore(paths.database)

    def plan(self, runbook_path: Path, supplied: dict[str, Any] | None = None) -> PlanDocument:
        runbook_path = runbook_path.expanduser().resolve()
        runbook, _ = load_runbook(runbook_path)
        validate_runbook(runbook)
        inventory, _ = load_inventory(self.paths.inventory)
        policy, _ = load_policy(self.paths.policy)
        profiles, _ = load_ssh_profiles(self.paths.ssh_profiles, resolve_paths=False)
        parameters = validate_parameters(runbook, supplied or {})
        missing_hosts = set(runbook.targets) - set(inventory.hosts)
        if missing_hosts:
            raise ConfigurationError(
                f"runbook targets absent from inventory: {', '.join(sorted(missing_hosts))}"
            )
        for target in runbook.targets:
            host = inventory.hosts[target]
            if host.ssh_profile not in profiles:
                raise ConfigurationError(
                    f"host {target} references missing SSH profile {host.ssh_profile!r}"
                )

        actions: list[PlanAction] = []
        max_rank = _RANK[runbook.metadata.risk]
        phase_steps = [
            ("preflight", runbook.preflight),
            ("steps", runbook.steps),
            ("postflight", runbook.postflight),
        ]
        for phase, steps in phase_steps:
            for step in steps:
                arguments = _expand(step.arguments, parameters)
                verifies = [_expand(item.model_dump(), parameters) for item in step.verify]
                definition = validate_phase_action(phase, step.action, arguments)
                max_rank = max(max_rank, _RANK[definition.risk])
                for target in runbook.targets:
                    host = inventory.hosts[target]
                    host_policy = policy.hosts.get(target)
                    probe_id = arguments.get("endpoint_id")
                    target_probe = (
                        host.probe_targets.get(probe_id) if probe_id is not None else None
                    )
                    probe_protocols = {
                        "network.tcp_connect": {"tcp", "http", "https", "postgresql"},
                        "network.reachability": {"tcp", "http", "https", "postgresql"},
                        "http.readiness": {"http", "https"},
                        "postgresql.protocol_available": {"postgresql"},
                    }
                    probe_configured = probe_id is None or (
                        target_probe is not None
                        and target_probe.protocol in probe_protocols.get(step.action, set())
                        and host_policy is not None
                        and probe_id in host_policy.allowed_probe_targets
                    )
                    allowed = False
                    approval_required = False
                    reason = "host has no explicit policy; default deny"
                    if host_policy:
                        unit = arguments.get("unit")
                        unit_ok = unit is None or unit in host_policy.allowed_units
                        if (
                            definition.read_only
                            and step.action in host_policy.diagnostic_actions
                            and unit_ok
                            and probe_configured
                        ):
                            allowed, reason = True, "explicit diagnostic action allow"
                        elif (
                            not definition.read_only
                            and step.action in host_policy.remediation_actions
                            and unit_ok
                        ):
                            allowed, approval_required = True, True
                            reason = "explicit remediation allow; one-time approval required"
                        elif not unit_ok:
                            reason = f"unit {unit!r} is outside the host policy allowlist"
                        elif not probe_configured:
                            reason = (
                                "probe endpoint is not configured and explicitly policy-allowed"
                            )
                        else:
                            reason = "action is not explicitly allowed by host policy"
                    actions.append(
                        PlanAction(
                            target=target,
                            phase=phase,
                            step_id=step.id,
                            action=step.action,
                            arguments=arguments,
                            timeout_seconds=step.timeout_seconds,
                            read_only=definition.read_only,
                            verify=[Assertion.model_validate(v) for v in verifies],
                            allowed=allowed,
                            approval_required=approval_required,
                            reason=reason,
                        )
                    )
        if _RANK[runbook.metadata.risk] < max_rank:
            raise ConfigurationError("declared runbook risk is lower than the highest action risk")
        if any(not item.allowed for item in actions):
            status = "denied"
        elif any(item.approval_required for item in actions):
            status = "approval_required"
        else:
            status = "ready"
        hashes = _source_hashes(runbook_path, self.paths)
        document = {
            "plan_id": str(uuid.uuid4()),
            "created_at": now(),
            "runbook_id": runbook.metadata.id,
            "runbook_name": runbook.metadata.name,
            "runbook_path": str(runbook_path),
            "parameters": parameters,
            "actions": [item.model_dump() for item in actions],
            "status": status,
            "source_hashes": hashes,
            "risk": runbook.metadata.risk,
        }
        document["plan_hash"] = _plan_hash(document)
        plan = PlanDocument.model_validate(document)
        self.store.create_plan(plan.model_dump())
        return plan

    def approve(self, plan_id: str, actor: str, reason: str) -> str:
        if not actor or len(actor) > 128:
            raise ApprovalError("approval actor must be a non-empty OS user name")
        if len(reason.strip()) < 8 or len(reason) > 1000:
            raise ApprovalError("approval reason must contain 8–1000 characters")
        plan = self.store.get_plan(plan_id)
        parsed = PlanDocument.model_validate(plan)
        self._verify_plan(parsed)
        policy, _ = load_policy(self.paths.policy)
        return self.store.create_approval(
            plan_id, parsed.plan_hash, actor, reason.strip(), policy.approval.ttl_seconds
        )

    def _verify_plan(self, plan: PlanDocument) -> None:
        path = Path(plan.runbook_path)
        current = _source_hashes(path, self.paths)
        if current != plan.source_hashes:
            raise PolicyDenied("runbook or configuration changed since planning; create a new plan")
        if _plan_hash(plan.model_dump()) != plan.plan_hash:
            raise PolicyDenied("stored plan hash is invalid; refusing execution")
        valid, _ = self.store.verify_audit_chain()
        if not valid:
            raise PolicyDenied("audit hash chain is invalid; refusing execution")
        if not self.store.plan_hash_is_audited(plan.plan_id, plan.plan_hash):
            raise PolicyDenied("plan does not match its immutable audit event; refusing execution")

    def execute(self, plan_id: str, diagnostic_only: bool = False) -> tuple[str, str]:
        plan = PlanDocument.model_validate(self.store.get_plan(plan_id))
        self._verify_plan(plan)
        if plan.status == "denied":
            raise PolicyDenied("plan contains denied actions; no steps were executed")
        if diagnostic_only and any(not item.read_only for item in plan.actions):
            raise PolicyDenied("check command accepts read-only runbooks only")
        approval_id = None
        if plan.status == "approval_required":
            approval_id = self.store.consume_approval(plan.plan_id, plan.plan_hash)
        inventory, _ = load_inventory(self.paths.inventory)
        profiles, _ = load_ssh_profiles(self.paths.ssh_profiles, resolve_paths=True)
        adapter = SSHAdapter(profiles)
        execution_id = str(uuid.uuid4())
        started = now()
        self.store.start_execution(execution_id, plan.plan_id, started)
        statuses: list[str] = []
        summary: dict[str, Any] = {
            "plan_id": plan.plan_id,
            "approval_id": approval_id,
            "completed_steps": 0,
        }
        final_status = "succeeded"
        for item in plan.actions:
            action = item.model_dump()
            step_start = now()
            try:
                arguments = dict(item.arguments)
                endpoint_id = arguments.get("endpoint_id")
                if endpoint_id is not None:
                    endpoint = inventory.hosts[item.target].probe_targets.get(endpoint_id)
                    if endpoint is None:
                        raise PolicyDenied("probe endpoint disappeared after planning")
                    arguments["_endpoint"] = endpoint.model_dump()
                result = adapter.execute(
                    inventory.hosts[item.target], item.action, arguments, item.timeout_seconds
                )
                evidence = {
                    "ok": result.ok,
                    "data": result.data,
                    "error": result.error,
                    "duration_seconds": result.duration_seconds,
                }
                if result.uncertain:
                    state = "unknown"
                elif not result.ok:
                    state = "failed"
                else:
                    assertion_results = []
                    for assertion in item.verify:
                        passed, detail = check_assertion(
                            assertion, {"data": result.data, "result": evidence}
                        )
                        assertion_results.append({"passed": passed, "detail": detail})
                    evidence["assertions"] = assertion_results
                    state = (
                        "failed"
                        if any(not check["passed"] for check in assertion_results)
                        else "succeeded"
                    )
            except ExecutionUnknown as exc:
                evidence = {"ok": False, "error": str(exc), "outcome": "unknown", "retry": False}
                state = "unknown"
            except Exception as exc:
                evidence = {"ok": False, "error": f"{type(exc).__name__}: {exc}"}
                state = "failed"
            self.store.record_step(execution_id, action, state, step_start, now(), evidence)
            statuses.append(state)
            summary["completed_steps"] += 1
            if state in {"failed", "unknown"}:
                final_status = state
                break
        summary["step_statuses"] = statuses
        self.store.finish_execution(execution_id, final_status, now(), summary)
        return execution_id, final_status
