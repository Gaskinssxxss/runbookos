from __future__ import annotations

import hashlib
import re
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Protocol

from . import __version__
from .actions import REGISTRY, validate_argument_keys, validate_phase_action
from .application_correlation import correlate_application
from .config import file_digest, load_inventory, load_policy, load_runbook, load_ssh_profiles
from .errors import ApprovalError, ConfigurationError, ExecutionUnknown, PolicyDenied
from .models import Assertion, PlanAction, PlanDocument, RemediationOutcome, Runbook
from .remote import REMOTE_SOURCE
from .ssh import SSHAdapter, SSHResult
from .storage_correlation import correlate_storage
from .store import SQLiteStore, canonical_json, plan_document_hash

_RANK = {"low": 0, "medium": 1, "high": 2}
_PARAM_REF = re.compile(r"^\$param\.([a-z][a-z0-9_]*)$")
_APPLICATION_ACTIONS = {
    "application.health",
    "application.queue_health",
    "application.config_fingerprint",
    "application.deploy_version",
}


def application_source(
    host: Any, host_policy: Any, action: str, application_id: str
) -> tuple[Any, Any, Any] | None:
    if host_policy is None or application_id not in host_policy.allowed_applications:
        return None
    app = host.applications.get(application_id)
    if app is None:
        return None
    if action in {"application.health", "application.queue_health"}:
        endpoint_id = (
            app.health_endpoint_id if action == "application.health" else app.queue_endpoint_id
        )
        if endpoint_id is None or endpoint_id not in host_policy.allowed_probe_targets:
            return None
        return app, host.probe_targets[endpoint_id], None
    storage_id = (
        app.config_storage_id
        if action == "application.config_fingerprint"
        else app.version_storage_id
    )
    if storage_id is None or storage_id not in host_policy.allowed_storage_targets:
        return None
    return app, None, host.storage_targets[storage_id]


class ActionExecutor(Protocol):
    def execute(
        self, host: Any, action: str, arguments: dict[str, Any], timeout_seconds: int
    ) -> SSHResult: ...


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
    mutable = [step for step in runbook.steps if not REGISTRY[step.action].read_only]
    if mutable:
        if len(runbook.targets) != 1:
            raise ConfigurationError("remediation runbooks must target exactly one host")
        if len(mutable) != 1 or len(runbook.steps) != 1:
            raise ConfigurationError(
                "a remediation runbook must contain exactly one registered mutable step"
            )
        if not runbook.preflight or not runbook.postflight:
            raise ConfigurationError(
                "remediation requires read-only preflight and postflight checks"
            )
        for phase in (runbook.preflight, runbook.postflight):
            if any(not step.verify for step in phase):
                raise ConfigurationError(
                    "every remediation preflight and postflight step requires assertions"
                )


def _source_hashes(runbook_path: Path, paths: Paths) -> dict[str, str]:
    # Bind plans/approvals to action semantics as well as input configuration. Older
    # plans do not contain this key and therefore require re-planning/re-approval.
    implementation = {
        "version": __version__,
        "remote_dispatcher": hashlib.sha256(REMOTE_SOURCE.encode()).hexdigest(),
        "core_modules": {
            name: hashlib.sha256(Path(__file__).with_name(f"{name}.py").read_bytes()).hexdigest()
            for name in (
                "actions",
                "cli",
                "config",
                "engine",
                "models",
                "remote",
                "ssh",
                "store",
            )
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
    return plan_document_hash(document)


class RunbookEngine:
    def __init__(self, paths: Paths, executor: ActionExecutor | None = None) -> None:
        self.paths = paths
        self.store = SQLiteStore(paths.database)
        # Executor injection is for isolated tests/embedded callers only. The CLI
        # never accepts an executor from user input and defaults to strict OpenSSH.
        self._executor = executor

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
                        "network.dns_resolve": {"tcp", "http", "https", "postgresql"},
                        "network.listener": {"tcp", "http", "https", "postgresql"},
                        "network.tls_certificate": {"https"},
                    }
                    probe_configured = probe_id is None or (
                        target_probe is not None
                        and target_probe.protocol in probe_protocols.get(step.action, set())
                        and (step.action != "network.listener" or target_probe.local_listener)
                        and (
                            step.action != "network.dns_resolve"
                            or (
                                target_probe.dns_name is not None
                                and target_probe.resolver_address is not None
                            )
                        )
                        and (
                            step.action != "network.tls_certificate"
                            or target_probe.dns_name is not None
                        )
                        and host_policy is not None
                        and probe_id in host_policy.allowed_probe_targets
                    )
                    storage_id = arguments.get("storage_id")
                    storage_configured = storage_id is None or (
                        storage_id in host.storage_targets
                        and host_policy is not None
                        and storage_id in host_policy.allowed_storage_targets
                        and (
                            step.action not in {"filesystem.usage_summary", "filesystem.pressure"}
                            or host.storage_targets[storage_id].kind == "directory"
                        )
                        and (
                            step.action != "filesystem.log_growth"
                            or host.storage_targets[storage_id].kind == "file"
                        )
                        and (
                            step.action != "filesystem.mount_status"
                            or host.storage_targets[storage_id].kind == "mount"
                        )
                    )
                    legacy_storage_path_allowed = (
                        step.action not in {"os.disk", "filesystem.inodes"}
                        or (step.action == "os.disk" and "path" not in arguments)
                        or (
                            host_policy is not None
                            and arguments.get("path") in host_policy.allowed_storage_paths
                        )
                    )
                    application_configured = (
                        step.action not in _APPLICATION_ACTIONS
                        or application_source(
                            host, host_policy, step.action, arguments.get("application_id")
                        )
                        is not None
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
                            and storage_configured
                            and legacy_storage_path_allowed
                            and application_configured
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
                        elif not storage_configured:
                            reason = (
                                "storage target is not configured and explicitly policy-allowed"
                            )
                        elif not legacy_storage_path_allowed:
                            reason = "storage path is outside the host policy allowlist"
                        elif not application_configured:
                            reason = (
                                "application source is not registered and explicitly policy-allowed"
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

    def remediation_preview(self, plan_id: str) -> dict[str, Any]:
        plan = PlanDocument.model_validate(self.store.get_plan(plan_id))
        self._verify_plan(plan)
        mutable = [item for item in plan.actions if not item.read_only]
        if plan.status != "approval_required" or len(mutable) != 1:
            raise PolicyDenied("preview requires an allowed plan with exactly one mutable action")
        action = mutable[0]
        definition = REGISTRY[action.action]
        policy, _ = load_policy(self.paths.policy)
        inventory, _ = load_inventory(self.paths.inventory)
        self._verify_plan(plan)
        host = inventory.hosts[action.target]
        host_policy = policy.hosts.get(action.target)
        return {
            "plan_id": plan.plan_id,
            "plan_hash": plan.plan_hash,
            "target": {
                "alias": action.target,
                "address": host.address,
                "port": host.port,
                "user": host.user,
            },
            "action_id": action.action,
            "parameters": action.arguments,
            "implementation_fingerprint": plan.source_hashes["implementation"],
            "read_only_preconditions": [
                {
                    "step_id": item.step_id,
                    "action_id": item.action,
                    "parameters": item.arguments,
                    "assertions": [assertion.model_dump() for assertion in item.verify],
                    "policy": item.reason,
                }
                for item in plan.actions
                if item.phase == "preflight"
            ],
            "policy": {
                "decision": action.reason,
                "allowed": action.allowed,
                "action_allowed_for_target": bool(
                    host_policy and action.action in host_policy.remediation_actions
                ),
                "unit_allowed_for_target": bool(
                    host_policy and action.arguments.get("unit") in host_policy.allowed_units
                ),
                "arguments_scope_allowed": bool(
                    host_policy
                    and action.action in host_policy.remediation_actions
                    and (
                        action.arguments.get("unit") is None
                        or action.arguments.get("unit") in host_policy.allowed_units
                    )
                    and (
                        action.arguments.get("endpoint_id") is None
                        or action.arguments.get("endpoint_id") in host_policy.allowed_probe_targets
                    )
                ),
                "approval_required": action.approval_required,
            },
            "expected_service_impact": definition.expected_impact,
            "approval": {
                "one_time": True,
                "expires_after_policy_ttl_seconds": policy.approval.ttl_seconds,
            },
            "explicit_execution_confirmation_required": True,
            "postflight_checks": [
                {
                    "step_id": item.step_id,
                    "action_id": item.action,
                    "parameters": item.arguments,
                    "assertions": [assertion.model_dump() for assertion in item.verify],
                }
                for item in plan.actions
                if item.phase == "postflight"
            ],
            "rollback": {
                "available": definition.rollback_available,
                "limitations": definition.rollback,
            },
        }

    def execute(
        self,
        plan_id: str,
        diagnostic_only: bool = False,
        confirm_remediation: bool = False,
        confirming_actor: str | None = None,
    ) -> tuple[str, str]:
        plan = PlanDocument.model_validate(self.store.get_plan(plan_id))
        self._verify_plan(plan)
        if plan.status == "denied":
            raise PolicyDenied("plan contains denied actions; no steps were executed")
        if diagnostic_only and any(not item.read_only for item in plan.actions):
            raise PolicyDenied("check command accepts read-only runbooks only")
        mutable_actions = [item for item in plan.actions if not item.read_only]
        if mutable_actions and (not confirm_remediation or not confirming_actor):
            raise PolicyDenied(
                "remediation requires explicit execution confirmation and a trusted operator identity"
            )
        approval_id = None
        if plan.status == "approval_required":
            approval_id = self.store.consume_approval(plan.plan_id, plan.plan_hash)
        inventory, _ = load_inventory(self.paths.inventory)
        policy, _ = load_policy(self.paths.policy)
        if self._executor is None:
            profiles, _ = load_ssh_profiles(self.paths.ssh_profiles, resolve_paths=True)
            adapter: ActionExecutor = SSHAdapter(profiles)
        else:
            adapter = self._executor
        execution_id = str(uuid.uuid4())
        started = now()
        authorization = None
        if mutable_actions:
            authorization = {
                "approval_id": approval_id,
                "confirmed_by": confirming_actor,
                "confirmation": "explicit CLI --confirm",
            }
        self.store.start_execution(
            execution_id,
            plan.plan_id,
            started,
            authorization,
            RemediationOutcome.NOT_EXECUTED.value if mutable_actions else None,
        )
        statuses: list[str] = []
        summary: dict[str, Any] = {
            "plan_id": plan.plan_id,
            "approval_id": approval_id,
            "completed_steps": 0,
        }
        final_status = "succeeded"
        remediation_outcome = RemediationOutcome.NOT_EXECUTED
        mutation_attempted = False
        mutation_state: str | None = None
        postflight_verified = False
        verified_postflight_failure = False
        for item in plan.actions:
            action = item.model_dump()
            step_start = now()
            is_mutation = not item.read_only
            try:
                arguments = dict(item.arguments)
                if item.action in _APPLICATION_ACTIONS:
                    host = inventory.hosts[item.target]
                    source = application_source(
                        host,
                        policy.hosts.get(item.target),
                        item.action,
                        arguments["application_id"],
                    )
                    if source is None:
                        raise PolicyDenied("application source is no longer policy-allowed")
                    app, endpoint, storage = source
                    arguments["_application"] = app.model_dump()
                    if endpoint is not None:
                        arguments["_endpoint"] = endpoint.model_dump()
                        arguments["_endpoint_id"] = (
                            app.health_endpoint_id
                            if item.action == "application.health"
                            else app.queue_endpoint_id
                        )
                    if storage is not None:
                        arguments["_storage"] = storage.model_dump()
                        arguments["_storage_id"] = (
                            app.config_storage_id
                            if item.action == "application.config_fingerprint"
                            else app.version_storage_id
                        )
                endpoint_id = arguments.get("endpoint_id")
                if endpoint_id is not None:
                    endpoint = inventory.hosts[item.target].probe_targets.get(endpoint_id)
                    if endpoint is None:
                        raise PolicyDenied("probe endpoint disappeared after planning")
                    arguments["_endpoint"] = endpoint.model_dump()
                storage_id = arguments.get("storage_id")
                if item.action in {"os.disk", "filesystem.inodes"} and not (
                    item.action == "os.disk" and "path" not in arguments
                ):
                    host_policy = policy.hosts.get(item.target)
                    if (
                        host_policy is None
                        or arguments.get("path") not in host_policy.allowed_storage_paths
                    ):
                        raise PolicyDenied("storage path is no longer policy-allowed")
                if storage_id is not None:
                    host = inventory.hosts[item.target]
                    storage = host.storage_targets.get(storage_id)
                    host_policy = policy.hosts.get(item.target)
                    if (
                        storage is None
                        or host_policy is None
                        or storage_id not in host_policy.allowed_storage_targets
                    ):
                        raise PolicyDenied(
                            "storage target disappeared or is no longer policy-allowed"
                        )
                    arguments["_storage"] = storage.model_dump()
                if is_mutation:
                    mutation_attempted = True
                    if approval_id is None:
                        raise PolicyDenied("mutable action has no consumed approval")
                    self.store.mark_remediation_dispatch(
                        execution_id,
                        plan.plan_id,
                        item.target,
                        item.action,
                        approval_id,
                    )
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
                if is_mutation and mutation_attempted:
                    mutation_state = state
                if item.phase == "postflight":
                    postflight_verified = state == "succeeded"
                    verified_postflight_failure = state == "failed" and any(
                        check.get("passed") is False for check in evidence.get("assertions", [])
                    )
            except ExecutionUnknown as exc:
                evidence = {"ok": False, "error": str(exc), "outcome": "unknown", "retry": False}
                state = "unknown"
                if is_mutation:
                    mutation_state = "unknown"
            except ConfigurationError as exc:
                evidence = {"ok": False, "error": f"ConfigurationError: {exc}"}
                state = "failed"
                if is_mutation:
                    mutation_attempted = False
                    mutation_state = None
            except Exception as exc:
                evidence = {"ok": False, "error": f"{type(exc).__name__}: {exc}"}
                state = "unknown" if is_mutation else "failed"
                if is_mutation:
                    mutation_state = "unknown"
            self.store.record_step(execution_id, action, state, step_start, now(), evidence)
            statuses.append(state)
            summary["completed_steps"] += 1
            if state in {"failed", "unknown"}:
                final_status = state
                if is_mutation:
                    if mutation_attempted:
                        mutation_state = state
                    if state == "failed" and mutation_attempted:
                        # A definite negative action response is followed by the
                        # registered read-only postflight to establish observed state.
                        continue
                if item.phase == "postflight" and state == "failed":
                    verified_postflight_failure = any(
                        check.get("passed") is False for check in evidence.get("assertions", [])
                    )
                break
        if mutable_actions:
            if not mutation_attempted:
                remediation_outcome = RemediationOutcome.NOT_EXECUTED
            elif mutation_state == "unknown" or final_status == "unknown":
                remediation_outcome = RemediationOutcome.UNKNOWN
            elif verified_postflight_failure or mutation_state == "failed":
                remediation_outcome = RemediationOutcome.VERIFIED_FAILURE
            elif (
                mutation_state == "succeeded"
                and postflight_verified
                and final_status == "succeeded"
            ):
                remediation_outcome = RemediationOutcome.VERIFIED_SUCCESS
            else:
                remediation_outcome = RemediationOutcome.UNKNOWN
            summary["remediation_outcome"] = remediation_outcome.value
        summary["step_statuses"] = statuses
        if any(
            item.action.startswith("filesystem.") or item.action == "os.disk"
            for item in plan.actions
        ):
            summary["storage_correlation"] = correlate_storage(
                self.store.execution(execution_id)["steps"]
            )
        app_summaries = []
        for target in sorted({item.target for item in plan.actions}):
            host = inventory.hosts[target]
            host_policy = policy.hosts.get(target)
            if host_policy is None:
                continue
            for application_id in sorted(
                set(host_policy.allowed_applications) & set(host.applications)
            ):
                app = host.applications[application_id]
                if not any(
                    item.target == target
                    and (
                        item.arguments.get("application_id") == application_id
                        or item.arguments.get("endpoint_id") in app.dependency_endpoint_ids
                        or (
                            app.worker_unit is not None
                            and item.arguments.get("unit") == app.worker_unit
                        )
                    )
                    for item in plan.actions
                ):
                    continue
                app_summaries.append(
                    correlate_application(
                        self.store.execution(execution_id)["steps"],
                        target,
                        application_id,
                        app,
                    )
                )
        if app_summaries:
            summary["application_correlation"] = app_summaries
        self.store.finish_execution(execution_id, final_status, now(), summary)
        return execution_id, final_status
