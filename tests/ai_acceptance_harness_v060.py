"""Test-only v0.6.0 Qwen acceptance helpers.

This module is deliberately outside the RunbookOS package and CLI. It replaces
the investigator's engine factory for the lifetime of one serial harness call
with the real engine backed by a strict synthetic executor. It must never be
used as a production execution adapter.
"""

from __future__ import annotations

import json
import os
import re
import stat
import subprocess
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Callable, Iterator
from unittest.mock import patch

import yaml
from ai_acceptance_config_v060 import PROVIDER_ENDPOINT

from runbookos import ai, engine
from runbookos.ai import IncidentInvestigator, ModelReply, OpenAICompatibleProvider
from runbookos.engine import Paths, RunbookEngine
from runbookos.errors import PolicyDenied, RunbookOSError
from runbookos.ssh import SSHResult
from runbookos.store import SQLiteStore

_LOCAL_FIXTURE = Path(__file__).with_name("scenarios.json")
FIXTURE_PATH = (
    _LOCAL_FIXTURE
    if _LOCAL_FIXTURE.is_file()
    else Path(__file__).resolve().parents[1] / "tests/fixtures/ai_acceptance_v060/scenarios.json"
)
SYNTHETIC_TARGET = "synthetic-acceptance.invalid"
READ_ONLY_ACTIONS = frozenset(
    {
        "systemd.is_active",
        "postgresql.protocol_available",
        "network.routes",
    }
)
MAX_PROVIDER_REQUESTS = 10
RSS_STOP_BYTES = 10 * 1024**3
MEMAVAILABLE_STOP_BYTES = 6 * 1024**3
PRELAUNCH_MEMAVAILABLE_BYTES = 16 * 1024**3


class ResourceMonitorError(RuntimeError):
    """Resource measurements could not be trusted; acceptance must stop."""


class ResourceLimitExceeded(RuntimeError):
    """A configured acceptance resource stop threshold was exceeded."""


def parse_proc_status_rss_bytes(status_text: str) -> int:
    """Parse a positive VmRSS value from Linux procfs status text."""
    matches = re.findall(r"^VmRSS:\s+(\d+)\s+kB\s*$", status_text, flags=re.MULTILINE)
    if len(matches) != 1:
        raise ResourceMonitorError("RSS measurement is missing or ambiguous")
    kib = int(matches[0])
    if kib <= 0:
        raise ResourceMonitorError("RSS measurement is not positive")
    return kib * 1024


def parse_memavailable_bytes(meminfo_text: str) -> int:
    """Parse positive MemAvailable from Linux procfs meminfo text."""
    matches = re.findall(r"^MemAvailable:\s+(\d+)\s+kB\s*$", meminfo_text, flags=re.MULTILINE)
    if len(matches) != 1 or int(matches[0]) <= 0:
        raise ResourceMonitorError("MemAvailable measurement is missing or invalid")
    return int(matches[0]) * 1024


def require_prelaunch_memory(meminfo_text: str) -> int:
    available = parse_memavailable_bytes(meminfo_text)
    if available < PRELAUNCH_MEMAVAILABLE_BYTES:
        raise ResourceLimitExceeded("prelaunch MemAvailable is below 16 GiB")
    return available


def enforce_resource_thresholds(rss_bytes: int, memavailable_bytes: int) -> None:
    if rss_bytes <= 0 or memavailable_bytes <= 0:
        raise ResourceMonitorError("resource measurement is zero or invalid")
    if rss_bytes > RSS_STOP_BYTES:
        raise ResourceLimitExceeded("acceptance model RSS exceeds 10 GiB")
    if memavailable_bytes < MEMAVAILABLE_STOP_BYTES:
        raise ResourceLimitExceeded("host MemAvailable is below 6 GiB")


def _terminate_acceptance_process(process: Any, grace_seconds: float = 3.0) -> None:
    """Stop only the Popen handle owned by this acceptance runner."""
    if process.poll() is not None:
        return
    process.terminate()
    try:
        process.wait(timeout=grace_seconds)
    except (TimeoutError, subprocess.TimeoutExpired):
        process.kill()
        process.wait(timeout=grace_seconds)


def sample_acceptance_server(
    process: Any,
    expected_executable: Path,
    proc_root: Path = Path("/proc"),
    meminfo_path: Path = Path("/proc/meminfo"),
) -> dict[str, int]:
    """Measure the llama-server leader (not the Python runner), failing closed.

    The guard measures the server process's own VmRSS. It does not aggregate
    descendant processes; this boundary is explicit because llama-server is
    launched as the acceptance-owned process and the model/runtime memory is
    resident there. A future runtime that delegates model memory to children
    must extend this monitor before acceptance.
    """
    try:
        if process.poll() is not None:
            raise ResourceMonitorError("acceptance-owned llama-server is not running")
        actual_exe = os.readlink(proc_root / str(process.pid) / "exe")
        if Path(actual_exe).resolve() != expected_executable.resolve():
            raise ResourceMonitorError("acceptance process identity does not match llama-server")
        rss = parse_proc_status_rss_bytes(
            (proc_root / str(process.pid) / "status").read_text(encoding="ascii")
        )
        available = parse_memavailable_bytes(meminfo_path.read_text(encoding="ascii"))
        enforce_resource_thresholds(rss, available)
        return {"rss_bytes": rss, "memavailable_bytes": available}
    except (OSError, UnicodeError, ResourceMonitorError, ResourceLimitExceeded):
        _terminate_acceptance_process(process)
        raise


def _safe_diagnostic_ids(content: str) -> list[str] | None:
    """Extract identifier-shaped IDs only; never retain model text or rationale."""
    try:
        value = json.loads(content)
    except (json.JSONDecodeError, TypeError):
        return None
    ids = value.get("diagnostic_ids") if isinstance(value, dict) else None
    if not isinstance(ids, list) or any(
        not isinstance(item, str) or not re.fullmatch(r"[a-zA-Z0-9_-]{1,64}", item) for item in ids
    ):
        return None
    return ids[:10]


def _reason_category(exc: Exception) -> str:
    """Map controlled exception text to a small non-sensitive category set."""
    message = str(exc).lower()
    categories = (
        ("incident_policy_guard", "instruction to bypass"),
        ("unsupported_diagnostic_id", "unregistered diagnostic id"),
        ("duplicate_diagnostic_id", "contains duplicates"),
        ("diagnostic_selection_limit", "exceeds max_diagnostic_runbooks"),
        ("diagnostic_plan_denied", "policy decision is"),
        ("non_read_only_action", "non-read-only action"),
        ("tool_call_budget", "max_tool_calls"),
        ("execution_time_budget", "execution time budget"),
        ("forged_evidence_reference", "evidence that was not produced"),
        ("unsupported_confident_claim", "confidence <= 0.25"),
    )
    for category, marker in categories:
        if marker in message:
            return category
    if isinstance(exc, PolicyDenied):
        return "other_policy_denied"
    if isinstance(exc, (json.JSONDecodeError,)):
        return "invalid_structured_json"
    if isinstance(exc, RunbookOSError):
        return "invalid_model_response_or_engine_error"
    return "other_error"


class InvestigationTrace:
    """Sanitized per-case telemetry for the test-only acceptance runner."""

    def __init__(self, scenario_id: str):
        self.scenario_id = scenario_id
        self.stage = "incident_validation"
        self.provider_requests = 0
        self.provider_stage = "not_called"
        self.diagnostic_ids_returned: list[str] | None = None
        self.catalog_validation = "not_reached"
        self.plan_policy_validation: list[dict[str, str]] = []
        self.evidence_validation = "not_reached"
        self.exception_type: str | None = None
        self.reason_category: str | None = None
        self.executor_invoked = False
        self.investigation_persisted = False

    def report(self) -> dict[str, Any]:
        return {
            "scenario_id": self.scenario_id,
            "stage": self.stage,
            "provider_requests": self.provider_requests,
            "provider_stage": self.provider_stage,
            "diagnostic_ids_returned": self.diagnostic_ids_returned,
            "catalog_validation": self.catalog_validation,
            "plan_policy_validation": self.plan_policy_validation,
            "evidence_validation": self.evidence_validation,
            "exception_type": self.exception_type,
            "reason_category": self.reason_category,
            "executor_invoked": self.executor_invoked,
            "investigation_persisted": self.investigation_persisted,
        }


class TracedProvider:
    """Observe only call counts and safe diagnostic identifiers, not raw content."""

    def __init__(self, provider: Any, trace: InvestigationTrace):
        self.provider = provider
        self.trace = trace
        self.provider_name = provider.provider_name

    def complete(self, system: str, user: str, max_tokens: int, temperature: float) -> ModelReply:
        try:
            payload = json.loads(user)
        except (json.JSONDecodeError, TypeError):
            payload = {}
        is_selection = isinstance(payload, dict) and "diagnostic_catalog" in payload
        self.trace.provider_stage = "selection" if is_selection else "analysis"
        self.trace.stage = f"provider_{self.trace.provider_stage}"
        count_before = self.provider.request_count
        try:
            reply = self.provider.complete(system, user, max_tokens, temperature)
        finally:
            self.trace.provider_requests += self.provider.request_count - count_before
        if is_selection:
            self.trace.diagnostic_ids_returned = _safe_diagnostic_ids(reply.content)
        return reply


@contextmanager
def trace_investigation(trace: InvestigationTrace) -> Iterator[None]:
    """Temporarily instrument real validation/planning/persistence boundaries."""
    original_parse = ai._parse_selection
    original_decode = ai._decode_model_json
    original_decode_minimal = ai._decode_minimal_assessment_reply
    original_convert_minimal = ai.convert_minimal_reply
    original_restore = ai._restore_evidence_refs
    original_restore_assessment = ai._restore_assessment_refs
    original_sanitize = ai._sanitize_report
    original_plan = RunbookEngine.plan
    original_execute = RunbookEngine.execute
    original_create = SQLiteStore.create_investigation

    def parsed(reply: Any, catalog: Any, limit: int) -> Any:
        trace.stage = "catalog_selection_validation"
        try:
            selected = original_parse(reply, catalog, limit)
        except Exception as exc:
            trace.catalog_validation = "rejected"
            trace.exception_type = type(exc).__name__
            trace.reason_category = _reason_category(exc)
            raise
        trace.catalog_validation = "accepted"
        trace.stage = "diagnostic_plan_policy_validation"
        return selected

    def decoded(content: str, schema: Any) -> Any:
        if schema.__name__ == "DiagnosticSelection":
            trace.stage = "catalog_selection_validation"
        else:
            trace.stage = "analysis_schema_validation"
        try:
            return original_decode(content, schema)
        except Exception as exc:
            trace.exception_type = type(exc).__name__
            trace.reason_category = _reason_category(exc)
            raise

    def restored(analysis: Any, aliases: Any) -> Any:
        trace.stage = "evidence_reference_validation"
        try:
            result = original_restore(analysis, aliases)
        except Exception as exc:
            trace.evidence_validation = "rejected"
            trace.exception_type = type(exc).__name__
            trace.reason_category = _reason_category(exc)
            raise
        trace.evidence_validation = "citation_references_validated"
        return result

    def restored_assessment(analysis: Any, aliases: Any) -> Any:
        trace.stage = "evidence_reference_validation"
        try:
            result = original_restore_assessment(analysis, aliases)
        except Exception as exc:
            trace.evidence_validation = "rejected"
            trace.exception_type = type(exc).__name__
            trace.reason_category = _reason_category(exc)
            raise
        trace.evidence_validation = "citation_references_validated"
        return result

    def decoded_minimal(content: str) -> Any:
        trace.stage = "assessment_schema_validation"
        try:
            return original_decode_minimal(content)
        except Exception as exc:
            trace.exception_type = type(exc).__name__
            trace.reason_category = _reason_category(exc)
            raise

    def converted_minimal(reply: Any, observations: Any, aliases: Any, **kwargs: Any) -> Any:
        trace.stage = "evidence_reference_validation"
        try:
            result = original_convert_minimal(reply, observations, aliases, **kwargs)
        except Exception as exc:
            trace.evidence_validation = "rejected"
            trace.exception_type = type(exc).__name__
            trace.reason_category = _reason_category(exc)
            raise
        trace.evidence_validation = "citation_references_validated"
        return result

    def sanitized(analysis: Any, valid_refs: Any) -> Any:
        trace.stage = "evidence_claim_validation"
        try:
            result = original_sanitize(analysis, valid_refs)
        except Exception as exc:
            trace.evidence_validation = "rejected"
            trace.exception_type = type(exc).__name__
            trace.reason_category = _reason_category(exc)
            raise
        trace.evidence_validation = "reference_and_schema_constraints_passed_semantics_unscored"
        return result

    def planned(instance: RunbookEngine, runbook_path: Path, supplied: Any = None) -> Any:
        runbook_id = runbook_path.stem
        trace.stage = "diagnostic_plan_policy_validation"
        try:
            result = original_plan(instance, runbook_path, supplied)
        except Exception as exc:
            trace.plan_policy_validation.append(
                {
                    "runbook_id": runbook_id,
                    "outcome": "rejected",
                    "reason_category": _reason_category(exc),
                }
            )
            trace.exception_type = type(exc).__name__
            trace.reason_category = _reason_category(exc)
            raise
        outcome = "accepted" if result.status == "ready" else "rejected"
        trace.plan_policy_validation.append({"runbook_id": result.runbook_id, "outcome": outcome})
        return result

    def persisted(instance: SQLiteStore, result: dict[str, Any], **kwargs: Any) -> Any:
        trace.stage = "investigation_persistence"
        value = original_create(instance, result, **kwargs)
        trace.investigation_persisted = True
        failure = result.get("assessment_failure")
        if isinstance(failure, dict):
            trace.exception_type = str(failure.get("error_type", "RunbookOSError"))
            trace.reason_category = str(
                failure.get("reason_category", failure.get("category", "other_error"))
            )
            trace.stage = (
                "catalog_selection_validation"
                if failure.get("stage") == "selection"
                else "assessment_failure_persisted"
            )
        else:
            trace.stage = "completed"
        return value

    def executed(instance: RunbookEngine, *args: Any, **kwargs: Any) -> Any:
        trace.stage = "diagnostic_execution"
        return original_execute(instance, *args, **kwargs)

    with (
        patch.object(ai, "_parse_selection", parsed),
        patch.object(ai, "_decode_model_json", decoded),
        patch.object(ai, "_decode_minimal_assessment_reply", decoded_minimal),
        patch.object(ai, "convert_minimal_reply", converted_minimal),
        patch.object(ai, "_restore_evidence_refs", restored),
        patch.object(ai, "_restore_assessment_refs", restored_assessment),
        patch.object(ai, "_sanitize_report", sanitized),
        patch.object(RunbookEngine, "plan", planned),
        patch.object(RunbookEngine, "execute", executed),
        patch.object(SQLiteStore, "create_investigation", persisted),
    ):
        yield


def load_scenarios() -> list[dict[str, Any]]:
    """Load synthetic test metadata; expected labels are not passed to providers."""
    return json.loads(FIXTURE_PATH.read_text(encoding="utf-8"))


def _write_yaml(path: Path, value: dict[str, Any]) -> None:
    path.write_text(yaml.safe_dump(value, sort_keys=False), encoding="utf-8")
    path.chmod(0o600)


def create_synthetic_tree(root: Path) -> Paths:
    """Create a fresh disposable configuration and SQLite tree; refuse overwrite."""
    root = root.expanduser()
    if root.exists() or root.is_symlink():
        raise FileExistsError(f"acceptance root already exists: {root}")
    root.mkdir(mode=0o700, parents=True)
    config_dir = root / "config"
    runbook_dir = root / "runbooks"
    state_dir = root / "state"
    for directory in (config_dir, runbook_dir, state_dir):
        directory.mkdir(mode=0o700)

    inventory_path = config_dir / "inventory.yml"
    policy_path = config_dir / "policy.yml"
    profiles_path = config_dir / "ssh_profiles.yml"
    database_path = state_dir / "investigation.sqlite3"
    endpoint = {
        "protocol": "postgresql",
        "address": "10.254.254.53",
        "port": 5432,
        "path": None,
    }
    _write_yaml(
        inventory_path,
        {
            "schema_version": 1,
            "hosts": {
                SYNTHETIC_TARGET: {
                    "address": "192.0.2.54",
                    "port": 22,
                    "user": "synthetic-only",
                    "role": "synthetic-test-target",
                    "ssh_profile": "synthetic-no-dispatch",
                    "host_key_alias": "synthetic-only",
                    "probe_targets": {"synthetic_pg": endpoint},
                }
            },
        },
    )
    _write_yaml(
        policy_path,
        {
            "schema_version": 1,
            "default_decision": "deny",
            "approval": {
                "required_for_remediation": True,
                "ttl_seconds": 60,
                "one_time": True,
            },
            "hosts": {
                SYNTHETIC_TARGET: {
                    "diagnostic_actions": sorted(READ_ONLY_ACTIONS),
                    "remediation_actions": [],
                    "allowed_units": ["nginx.service", "runbookos-sample.service"],
                    "allowed_probe_targets": ["synthetic_pg"],
                }
            },
        },
    )
    _write_yaml(
        profiles_path,
        {
            "schema_version": 1,
            "profiles": {
                "synthetic-no-dispatch": {
                    "identity_file": "/NONEXISTENT/TEST-ONLY-NO-SSH-IDENTITY",
                    "known_hosts_file": "/NONEXISTENT/TEST-ONLY-NO-KNOWN-HOSTS",
                    "connect_timeout_seconds": 1,
                    "server_alive_interval_seconds": 1,
                }
            },
        },
    )

    runbooks = {
        "web_health": (
            "web-health.yml",
            "web-health",
            "systemd.is_active",
            {"unit": "nginx.service"},
            "data.active",
        ),
        "application_health": (
            "application-health.yml",
            "application-health",
            "systemd.is_active",
            {"unit": "runbookos-sample.service"},
            "data.active",
        ),
        "database_health": (
            "database-health.yml",
            "database-health",
            "postgresql.protocol_available",
            {"endpoint_id": "synthetic_pg"},
            "data.protocol_available",
        ),
        "network_health": (
            "network-health.yml",
            "network-health",
            "network.routes",
            {},
            "data.routes",
        ),
    }
    catalog: list[dict[str, str]] = []
    for diagnostic_id, (
        filename,
        runbook_id,
        action,
        arguments,
        assertion_path,
    ) in runbooks.items():
        runbook_path = runbook_dir / filename
        verification = (
            {"path": assertion_path, "operator": "is_true", "value": True}
            if assertion_path != "data.routes"
            else {"path": assertion_path, "operator": "nonempty"}
        )
        document = {
            "api_version": "runbookos/v1",
            "kind": "Runbook",
            "metadata": {
                "id": runbook_id,
                "name": f"Synthetic {diagnostic_id}",
                "description": "Synthetic fixture only; not a live host check.",
                "risk": "low",
            },
            "targets": [SYNTHETIC_TARGET],
            "steps": [
                {
                    "id": "synthetic-diagnostic",
                    "action": action,
                    "with": arguments,
                    "timeout_seconds": 5,
                    "verify": [verification],
                }
            ],
        }
        _write_yaml(runbook_path, document)
        catalog.append(
            {
                "id": diagnostic_id,
                "runbook": f"../runbooks/{filename}",
                "description": f"Synthetic registered read-only diagnostic {diagnostic_id}.",
            }
        )

    investigation_path = config_dir / "investigation.yml"
    _write_yaml(
        investigation_path,
        {
            "schema_version": 1,
            "provider": {
                "type": "openai_compatible",
                "base_url": PROVIDER_ENDPOINT,
                "model": "qwen3.5-9b-instruct",
                "api_key_env": "RUNBOOKOS_LLAMA_API_KEY",
                "timeout_seconds": 120,
                "max_tokens": 700,
                "temperature": 0,
            },
            "limits": {
                "max_diagnostic_runbooks": 2,
                "max_tool_calls": 4,
                "execution_budget_seconds": 60,
                "max_incident_chars": 4000,
            },
            "catalog": catalog,
        },
    )
    return Paths(inventory_path, policy_path, profiles_path, database_path)


class SyntheticReadOnlyExecutor:
    """Deterministic in-process responses; no subprocess, socket, or SSH use."""

    def __init__(self, scenario_id: str):
        self.scenario_id = scenario_id
        self.calls: list[dict[str, Any]] = []

    def execute(self, host: Any, action: str, arguments: dict[str, Any], timeout_seconds: int):
        if action not in READ_ONLY_ACTIONS:
            raise PolicyDenied(f"synthetic executor denies action outside allowlist: {action}")
        if host.address != "192.0.2.54" or timeout_seconds > 10:
            raise PolicyDenied(
                f"synthetic executor target or timeout is outside its fixed scope: "
                f"address={host.address!r}, timeout={timeout_seconds}"
            )
        self.calls.append(
            {
                "target": SYNTHETIC_TARGET,
                "action": action,
                "arguments": dict(arguments),
                "timeout": timeout_seconds,
            }
        )
        if action == "systemd.is_active":
            active = self.scenario_id not in {"nginx-unavailable", "fastapi-service-failure"}
            data = {
                "unit": arguments["unit"],
                "active": active,
                "state": "active" if active else "inactive",
            }
        elif action == "postgresql.protocol_available":
            data = {
                "endpoint_id": "synthetic_pg",
                "address": "10.254.254.53",
                "port": 5432,
                "protocol": "postgresql",
                "protocol_available": False,
                "ssl_supported": False,
                "ssl_negotiation_response": None,
                "authentication_attempted": False,
                "database_readiness_verified": False,
                "duration_seconds": 0.001,
            }
        else:
            data = {"routes": []}
        return SSHResult(ok=True, data=data, error=None, uncertain=False, duration_seconds=0.001)


@contextmanager
def fake_executor_only(executor: SyntheticReadOnlyExecutor) -> Iterator[None]:
    """Install the fake executor for this call and make real SSH construction fatal."""
    original_factory = ai.RunbookEngine
    original_ssh_adapter = engine.SSHAdapter
    original_umask = os.umask(0o077)

    def guarded_engine(paths: Paths) -> RunbookEngine:
        return RunbookEngine(paths, executor=executor)

    def forbidden_ssh(*args: Any, **kwargs: Any) -> None:
        raise AssertionError("SSHAdapter must not be constructed by the AI acceptance harness")

    ai.RunbookEngine = guarded_engine
    engine.SSHAdapter = forbidden_ssh  # type: ignore[assignment]
    try:
        yield
    finally:
        ai.RunbookEngine = original_factory
        engine.SSHAdapter = original_ssh_adapter
        os.umask(original_umask)


def create_investigator(paths: Paths, provider: Any) -> IncidentInvestigator:
    config, config_dir = ai.load_investigation_config(paths.inventory.parent / "investigation.yml")
    return IncidentInvestigator(
        paths,
        config,
        config_dir,
        provider,
        allowed_targets={SYNTHETIC_TARGET},
    )


class BoundedProvider:
    """Enforce the acceptance request ceiling without retrying a provider call."""

    def __init__(
        self,
        provider: Any,
        maximum_requests: int = MAX_PROVIDER_REQUESTS,
        request_guard: Callable[[], None] | None = None,
    ):
        self.provider = provider
        self.provider_name = provider.provider_name
        self.maximum_requests = maximum_requests
        self.request_count = 0
        self.request_latencies: list[float] = []
        self.request_guard = request_guard

    def complete(self, system: str, user: str, max_tokens: int, temperature: float) -> ModelReply:
        if self.request_count >= self.maximum_requests:
            raise PolicyDenied("AI acceptance reached its maximum provider request count")
        if self.request_guard is not None:
            self.request_guard()
        self.request_count += 1
        started = time.monotonic()
        try:
            reply = self.provider.complete(system, user, max_tokens, temperature)
        finally:
            self.request_latencies.append(time.monotonic() - started)
        if self.request_guard is not None:
            self.request_guard()
        return reply


def run_five_scenario_acceptance(
    paths: Paths,
    provider: Any,
    request_guard: Callable[[], None] | None = None,
    abort_requested: Callable[[], bool] | None = None,
) -> dict[str, Any]:
    """Run five synthetic cases serially through the real investigator.

    `provider` may be an offline scripted provider or, after separate approval,
    the configured Qwen provider. The engine remains bound to the fake executor.
    No provider call is retried; failures retain sanitized trace metadata only.
    """
    if isinstance(provider, OpenAICompatibleProvider):
        config = provider.config
        if (
            config.base_url != PROVIDER_ENDPOINT
            or config.model != "qwen3.5-9b-instruct"
            or config.timeout_seconds > 120
            or config.max_tokens > 700
            or config.temperature != 0
        ):
            raise PolicyDenied(
                "live acceptance provider configuration is outside the approved bounds"
            )
    elif not str(getattr(provider, "provider_name", "")).startswith("offline-"):
        raise PolicyDenied(
            "test harness accepts only the local Qwen adapter or named offline mocks"
        )

    bounded = BoundedProvider(provider, request_guard=request_guard)
    cases: list[dict[str, Any]] = []
    stopped_early = False
    for scenario in load_scenarios():
        request_count_before = bounded.request_count
        latency_count_before = len(bounded.request_latencies)
        executor = SyntheticReadOnlyExecutor(scenario["id"])
        trace = InvestigationTrace(scenario["id"])
        investigator = create_investigator(paths, TracedProvider(bounded, trace))
        started = time.monotonic()
        try:
            if request_guard is not None:
                request_guard()
            with fake_executor_only(executor), trace_investigation(trace):
                result = investigator.investigate(scenario["incident_text"])
            valid_refs = {item["ref"] for item in result["evidence"]}
            trace.executor_invoked = bool(executor.calls)
            citations = [
                citation
                for hypothesis in result["report"]["hypotheses"]
                for citation in hypothesis["evidence_refs"]
            ]
            cases.append(
                {
                    "scenario_id": scenario["id"],
                    "status": "completed",
                    "selected_diagnostics": result["selected_diagnostics"],
                    "expected_diagnostic_id": scenario["diagnostic_id"],
                    "diagnostic_exact_match": result["selected_diagnostics"]
                    == ([scenario["diagnostic_id"]] if scenario["diagnostic_id"] else []),
                    "evidence_refs": sorted(valid_refs),
                    "evidence_steps": [
                        {key: item[key] for key in ("ref", "execution_id", "action", "status")}
                        for item in result["evidence"]
                    ],
                    "citation_count": len(citations),
                    "citations_valid": all(item in valid_refs for item in citations),
                    "verified_evidence_count": len(result["verified_evidence"]),
                    "model_metadata": result["model_metadata"],
                    "elapsed_seconds": round(time.monotonic() - started, 3),
                    "executor_action_count": len(executor.calls),
                    "provider_request_count": bounded.request_count - request_count_before,
                    "provider_request_latencies_seconds": bounded.request_latencies[
                        latency_count_before:
                    ],
                    **trace.report(),
                    "expected_classification_not_scored": scenario["expected_classification"],
                }
            )
        except Exception as exc:
            guarded_abort = bool(abort_requested and abort_requested())
            if trace.exception_type is None:
                trace.exception_type = type(exc).__name__
                trace.reason_category = (
                    "resource_monitor_abort" if guarded_abort else _reason_category(exc)
                )
            if guarded_abort:
                trace.stage = "resource_monitor_abort"
            trace.executor_invoked = bool(executor.calls)
            cases.append(
                {
                    "scenario_id": scenario["id"],
                    "status": "aborted_by_resource_monitor"
                    if guarded_abort
                    else "rejected_or_failed",
                    "error_type": type(exc).__name__,
                    "elapsed_seconds": round(time.monotonic() - started, 3),
                    "executor_action_count": len(executor.calls),
                    "provider_request_count": bounded.request_count - request_count_before,
                    "provider_request_latencies_seconds": bounded.request_latencies[
                        latency_count_before:
                    ],
                    **trace.report(),
                }
            )
            if guarded_abort:
                stopped_early = True
                break
    return {
        "provider": bounded.provider_name,
        "provider_requests": bounded.request_count,
        "provider_request_latencies_seconds": [
            round(value, 3) for value in bounded.request_latencies
        ],
        "cases": cases,
        "stopped_early": stopped_early,
        "classification_and_root_cause_quality": "not_scored_by_v0.6.0_investigator_schema",
        "automatic_retry": False,
    }


def acceptance_file_inventory(root: Path) -> list[dict[str, Any]]:
    """Return sanitized names/modes for the isolated tree; never reads DB contents."""
    rows = []
    for path in sorted(root.rglob("*")):
        mode = stat.S_IMODE(path.stat().st_mode)
        rows.append(
            {
                "path": str(path.relative_to(root)),
                "kind": "directory" if path.is_dir() else "file",
                "mode": f"{mode:04o}",
                "size_bytes": path.stat().st_size if path.is_file() else None,
            }
        )
    return rows
