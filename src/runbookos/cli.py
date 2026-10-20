from __future__ import annotations

import getpass
import hashlib
import json
import sys
from pathlib import Path
from typing import Any

import typer
import yaml

from . import __version__
from .ai import (
    IncidentInvestigator,
    build_provider,
    load_investigation_config,
)
from .blind_review import export_blind_review, reviewer_agreement
from .config import load_inventory, load_runbook, load_ssh_profiles
from .dashboard import create_auth_file, serve_dashboard
from .engine import Paths, RunbookEngine, validate_runbook
from .errors import RunbookOSError
from .evaluation import (
    ConfiguredScenarioProvider,
    build_dataset,
    load_evaluation_provider_config,
    load_scenarios,
    run_mock_evaluation,
    run_provider_evaluation,
    save_dataset,
)
from .evaluation_v2 import (
    StructuredScenarioProvider,
    build_dataset_v2,
    load_ground_truth,
    load_taxonomy,
    render_report_v2,
    run_mock_evaluation_v2,
    run_provider_evaluation_v2,
    save_dataset_v2,
    summarize_v2,
)
from .incidents import IncidentStore, parse_alert, validate_target
from .store import SQLiteStore
from .tunnel import load_tunnel_config, run_tunnel
from .webhook import serve_from_environment

PROJECT = Path(__file__).resolve().parents[2]
DEFAULTS = (
    PROJECT
    if (PROJECT / "config/inventory.example.yml").is_file()
    else Path(sys.prefix) / "share/runbookos"
)
STATE_DEFAULT = (
    PROJECT / "state"
    if (PROJECT / "config/inventory.example.yml").is_file()
    else Path.home() / ".local/state/runbookos"
)
SCENARIO_DEFAULT = (
    PROJECT / "scenarios"
    if (PROJECT / "scenarios").is_dir()
    else Path(sys.prefix) / "share/runbookos/scenarios"
)
TAXONOMY_DEFAULT = DEFAULTS / "config/diagnostic-taxonomy.v2.example.yml"
GROUND_TRUTH_DEFAULT = SCENARIO_DEFAULT / "metadata/ground-truth-taxonomy-v2.yml"
app = typer.Typer(
    no_args_is_help=True, add_completion=False, help="Safe, auditable Linux runbook execution."
)
scenarios_app = typer.Typer(no_args_is_help=True, help="Manage synthetic incident scenarios.")
app.add_typer(scenarios_app, name="scenarios")
evaluation_app = typer.Typer(no_args_is_help=True, help="Inspect incident evaluation datasets.")
app.add_typer(evaluation_app, name="evaluation")
alerts_app = typer.Typer(no_args_is_help=True, help="Ingest and inspect alert events.")
incidents_app = typer.Typer(no_args_is_help=True, help="Manage human-controlled incidents.")
webhook_app = typer.Typer(no_args_is_help=True, help="Run the optional loopback alert webhook.")
dashboard_app = typer.Typer(no_args_is_help=True, help="Run the optional local operator dashboard.")
app.add_typer(alerts_app, name="alerts")
app.add_typer(incidents_app, name="incidents")
app.add_typer(webhook_app, name="webhook")
app.add_typer(dashboard_app, name="dashboard")


def _path(value: Path) -> Path:
    return value.expanduser().resolve()


@app.callback()
def main(
    ctx: typer.Context,
    inventory: Path = typer.Option(
        DEFAULTS / "config/inventory.example.yml", "--inventory", help="Inventory YAML."
    ),
    policy: Path = typer.Option(
        DEFAULTS / "config/policy.example.yml", "--policy", help="Default-deny policy YAML."
    ),
    ssh_profiles: Path = typer.Option(
        DEFAULTS / "config/ssh_profiles.example.yml",
        "--ssh-profiles",
        help="SSH identity and pinned host key profiles.",
    ),
    database: Path = typer.Option(
        STATE_DEFAULT / "runbookos.sqlite3", "--db", help="Local SQLite execution/audit database."
    ),
) -> None:
    ctx.obj = Paths(
        inventory=_path(inventory),
        policy=_path(policy),
        ssh_profiles=_path(ssh_profiles),
        database=_path(database),
    )


def _engine(ctx: typer.Context) -> RunbookEngine:
    return RunbookEngine(ctx.obj)


def _fail(exc: Exception, code: int = 2) -> None:
    typer.echo(f"ERROR: {exc}", err=True)
    raise typer.Exit(code)


def _json(value: Any) -> None:
    typer.echo(json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False))


@app.command()
def version() -> None:
    """Show the installed RunbookOS version."""
    typer.echo(f"RunbookOS {__version__}")


@app.command()
def validate(
    runbook_file: Path = typer.Argument(..., exists=True, dir_okay=False, readable=True),
) -> None:
    """Validate a versioned YAML runbook and registered actions."""
    try:
        runbook, digest = load_runbook(_path(runbook_file))
        validate_runbook(runbook)
    except Exception as exc:
        _fail(exc)
    typer.echo(
        f"VALID {runbook.metadata.id} (api_version={runbook.api_version}, risk={runbook.metadata.risk})"
    )
    typer.echo(f"sha256 {digest}")


@app.command("inventory")
def inventory_command(
    ctx: typer.Context,
    as_json: bool = typer.Option(False, "--json", help="Print machine-readable inventory."),
) -> None:
    """List configured hosts without exposing SSH key contents."""
    try:
        inv, _ = load_inventory(ctx.obj.inventory)
    except Exception as exc:
        _fail(exc)
    result = {
        name: {
            "address": host.address,
            "port": host.port,
            "user": host.user,
            "role": host.role,
            "ssh_profile": host.ssh_profile,
        }
        for name, host in inv.hosts.items()
    }
    if as_json:
        _json(result)
    else:
        typer.echo("HOST\tADDRESS\tROLE\tSSH PROFILE")
        for name, host in inv.hosts.items():
            typer.echo(f"{name}\t{host.address}:{host.port}\t{host.role}\t{host.ssh_profile}")


def _parameters(items: list[str]) -> dict[str, Any]:
    values: dict[str, Any] = {}
    for item in items:
        if "=" not in item:
            raise RunbookOSError(f"parameter must use name=value syntax: {item!r}")
        name, raw = item.split("=", 1)
        if name in values:
            raise RunbookOSError(f"parameter specified more than once: {name}")
        try:
            values[name] = yaml.safe_load(raw)
        except yaml.YAMLError as exc:
            raise RunbookOSError(f"invalid YAML scalar for parameter {name}: {exc}") from exc
    return values


@app.command()
def plan(
    ctx: typer.Context,
    runbook_file: Path = typer.Argument(..., exists=True, dir_okay=False, readable=True),
    param: list[str] = typer.Option(
        [], "--param", help="Runbook parameter as name=value; repeatable."
    ),
    as_json: bool = typer.Option(False, "--json", help="Print complete plan JSON."),
) -> None:
    """Build and persist a policy-evaluated execution plan without running actions."""
    try:
        result = _engine(ctx).plan(_path(runbook_file), _parameters(param))
    except Exception as exc:
        _fail(exc)
    document = result.model_dump()
    if as_json:
        _json(document)
        return
    typer.echo(
        f"Plan {result.plan_id} [{result.status}] risk={result.risk} runbook={result.runbook_id}"
    )
    typer.echo(f"Plan SHA-256: {result.plan_hash}")
    for action in result.actions:
        decision = "ALLOW" if action.allowed else "DENY"
        if action.approval_required:
            decision = "APPROVAL REQUIRED"
        typer.echo(
            f"{decision:18} {action.target:16} {action.phase:10} {action.action} — {action.reason}"
        )


@app.command()
def run(
    ctx: typer.Context,
    plan_id: str = typer.Argument(..., help="Persisted plan UUID."),
    confirm: bool = typer.Option(
        False,
        "--confirm",
        help="Explicitly confirm execution of an approved remediation plan.",
    ),
) -> None:
    """Execute an approved and unchanged plan; remediation also requires --confirm."""
    try:
        execution_id, status = _engine(ctx).execute(
            plan_id,
            confirm_remediation=confirm,
            confirming_actor=getpass.getuser() if confirm else None,
        )
    except Exception as exc:
        _fail(exc)
    typer.echo(f"Execution {execution_id}: {status}")
    if status == "unknown":
        typer.echo(
            "Remote outcome is uncertain. Do not retry blindly; inspect the target and history first.",
            err=True,
        )
        raise typer.Exit(3)
    if status != "succeeded":
        raise typer.Exit(1)


@app.command("remediation-preview")
def remediation_preview(
    ctx: typer.Context, plan_id: str = typer.Argument(..., help="Persisted remediation plan UUID.")
) -> None:
    """Display trusted impact and verification metadata for a remediation plan."""
    try:
        result = _engine(ctx).remediation_preview(plan_id)
    except Exception as exc:
        _fail(exc)
    _json(result)


@app.command()
def check(
    ctx: typer.Context,
    runbook_file: Path = typer.Argument(..., exists=True, dir_okay=False, readable=True),
    param: list[str] = typer.Option(
        [], "--param", help="Runbook parameter as name=value; repeatable."
    ),
) -> None:
    """Plan and execute a read-only diagnostic runbook."""
    try:
        engine = _engine(ctx)
        plan_doc = engine.plan(_path(runbook_file), _parameters(param))
        if plan_doc.status != "ready":
            raise RunbookOSError(
                f"diagnostic plan is {plan_doc.status}; no action executed (plan {plan_doc.plan_id})"
            )
        execution_id, status = engine.execute(plan_doc.plan_id, diagnostic_only=True)
    except Exception as exc:
        _fail(exc)
    typer.echo(f"Diagnostic execution {execution_id}: {status}")
    if status == "unknown":
        typer.echo("Remote outcome is uncertain; no automatic retry was attempted.", err=True)
        raise typer.Exit(3)
    if status != "succeeded":
        raise typer.Exit(1)


@app.command()
def approve(
    ctx: typer.Context,
    plan_id: str = typer.Argument(...),
    reason: str = typer.Option(..., "--reason", prompt=True),
) -> None:
    """Grant a one-time, time-limited approval to a policy-allowed remediation plan."""
    try:
        approval_id = _engine(ctx).approve(plan_id, getpass.getuser(), reason)
    except Exception as exc:
        _fail(exc)
    typer.echo(f"Approval {approval_id} recorded for plan {plan_id}; one use, policy TTL applies.")


@app.command()
def history(
    ctx: typer.Context,
    execution_id: str | None = typer.Argument(
        None, help="Optional execution UUID for detailed evidence."
    ),
    limit: int = typer.Option(20, min=1, max=200, help="Maximum history rows."),
) -> None:
    """Show execution history or one execution's step evidence."""
    try:
        store = SQLiteStore(ctx.obj.database)
        result = store.execution(execution_id) if execution_id else store.history(limit)
    except Exception as exc:
        _fail(exc)
    _json(result)


@app.command()
def audit(ctx: typer.Context) -> None:
    """Verify the append-only audit event hash chain."""
    try:
        valid, count = SQLiteStore(ctx.obj.database).verify_audit_chain()
    except Exception as exc:
        _fail(exc)
    if valid:
        typer.echo(f"AUDIT OK: {count} hash-chained events")
    else:
        typer.echo(f"AUDIT FAILED after {count} events", err=True)
        raise typer.Exit(1)


@app.command()
def tunnel(
    config_file: Path = typer.Argument(..., exists=True, dir_okay=False, readable=True),
) -> None:
    """Start a foreground, pinned-key SSH tunnel to a remote loopback API."""
    try:
        config = load_tunnel_config(_path(config_file))
        typer.echo(
            f"SSH tunnel active on 127.0.0.1:{config.local_port}; press Ctrl-C to stop.",
            err=True,
        )
        result = run_tunnel(config)
    except KeyboardInterrupt:
        raise typer.Exit(130) from None
    except Exception as exc:
        _fail(exc)
    if result:
        _fail(RunbookOSError(f"SSH tunnel exited with status {result}"), code=result)


@app.command()
def investigate(
    ctx: typer.Context,
    ai_config: Path = typer.Option(
        DEFAULTS / "config/investigation.example.yml",
        "--ai-config",
        help="Optional provider, limits, and diagnostic catalog configuration.",
    ),
    incident_file: Path | None = typer.Option(
        None, "--incident-file", help="Read incident text from a file (not persisted)."
    ),
    incident_stdin: bool = typer.Option(
        False, "--incident-stdin", help="Read incident text from stdin (not persisted)."
    ),
) -> None:
    """Investigate an incident using AI-selected registered read-only runbooks."""
    if bool(incident_file) == incident_stdin:
        _fail(RunbookOSError("choose exactly one of --incident-file or --incident-stdin"))
    try:
        config, config_dir = load_investigation_config(_path(ai_config))
        if incident_file:
            with _path(incident_file).open(encoding="utf-8") as stream:
                incident = stream.read(config.limits.max_incident_chars + 1)
        else:
            incident = sys.stdin.read(config.limits.max_incident_chars + 1)
        result = IncidentInvestigator(
            ctx.obj, config, config_dir, build_provider(config.provider)
        ).investigate(incident)
    except Exception as exc:
        _fail(exc)
    _json(result)


@app.command()
def investigations(
    ctx: typer.Context,
    limit: int = typer.Option(20, min=1, max=200, help="Maximum investigation rows."),
) -> None:
    """List prior investigations without echoing incident descriptions."""
    try:
        rows = SQLiteStore(ctx.obj.database).investigations(limit)
    except Exception as exc:
        _fail(exc)
    _json(
        [
            {
                "investigation_id": row["investigation_id"],
                "status": row["status"],
                "created_at": row["created_at"],
                "incident_sha256": row["incident_sha256"],
                "selected_diagnostics": row["result"].get("selected_diagnostics", []),
                "execution_ids": sorted(
                    {item.get("execution_id") for item in row["result"].get("evidence", [])}
                ),
                "model_metadata": row["result"].get("model_metadata", {}),
            }
            for row in rows
        ]
    )


@alerts_app.command("ingest")
def alerts_ingest(
    ctx: typer.Context,
    source_file: str = typer.Argument("-", help="JSON file path, or - for stdin."),
) -> None:
    """Validate and ingest one bounded JSON alert; ingestion never starts diagnostics."""
    try:
        raw = (
            sys.stdin.buffer.read(64 * 1024 + 1)
            if source_file == "-"
            else _path(Path(source_file)).read_bytes()
        )
        alert = parse_alert(raw)
        validate_target(alert, ctx.obj.inventory)
        _json(IncidentStore(SQLiteStore(ctx.obj.database)).ingest(alert))
    except Exception as exc:
        _fail(exc)


@alerts_app.command("list")
def alerts_list(ctx: typer.Context, limit: int = typer.Option(100, min=1, max=1000)) -> None:
    try:
        _json(IncidentStore(SQLiteStore(ctx.obj.database)).alert_list(limit))
    except Exception as exc:
        _fail(exc)


@incidents_app.command("list")
def incidents_list(
    ctx: typer.Context,
    status: str | None = typer.Option(None),
    limit: int = typer.Option(100, min=1, max=1000),
) -> None:
    try:
        _json(IncidentStore(SQLiteStore(ctx.obj.database)).list(status, limit))
    except Exception as exc:
        _fail(exc)


@incidents_app.command("show")
def incident_show(ctx: typer.Context, incident_id: str) -> None:
    try:
        _json(IncidentStore(SQLiteStore(ctx.obj.database)).show(incident_id))
    except Exception as exc:
        _fail(exc)


def _incident_transition(
    ctx: typer.Context,
    incident_id: str,
    status: str,
    reason: str,
    evidence_status: str | None = None,
) -> None:
    try:
        _json(
            IncidentStore(SQLiteStore(ctx.obj.database)).transition(
                incident_id,
                status,
                getpass.getuser(),
                reason,
                evidence_status=evidence_status,
            )
        )
    except Exception as exc:
        _fail(exc)


@incidents_app.command("acknowledge")
def incident_acknowledge(
    ctx: typer.Context, incident_id: str, reason: str = typer.Option(...)
) -> None:
    _incident_transition(ctx, incident_id, "ACKNOWLEDGED", reason)


@incidents_app.command("resolve")
def incident_resolve(
    ctx: typer.Context,
    incident_id: str,
    reason: str = typer.Option(..., help="Recorded operator resolution reason"),
    evidence_status: str = typer.Option(
        ...,
        "--evidence-status",
        help="verified, not_available, or inconclusive; attestation is recorded in the audit trail",
    ),
) -> None:
    if evidence_status not in {"verified", "not_available", "inconclusive"}:
        _fail(RunbookOSError("--evidence-status must be verified, not_available, or inconclusive"))
    _incident_transition(ctx, incident_id, "RESOLVED", reason, evidence_status)


@incidents_app.command("close")
def incident_close(ctx: typer.Context, incident_id: str, reason: str = typer.Option(...)) -> None:
    _incident_transition(ctx, incident_id, "CLOSED", reason)


@incidents_app.command("investigate")
def incident_investigate(
    ctx: typer.Context,
    incident_id: str,
    runbook_file: Path | None = typer.Option(None, "--runbook", exists=True, dir_okay=False),
    ai_config: Path | None = typer.Option(None, "--ai-config", exists=True, dir_okay=False),
) -> None:
    """Explicitly run one scoped read-only runbook or an explicitly configured AI investigation."""
    if bool(runbook_file) == bool(ai_config):
        _fail(RunbookOSError("choose exactly one of --runbook or --ai-config"))
    try:
        manager = IncidentStore(SQLiteStore(ctx.obj.database))
        incident = manager.show(incident_id)
        if incident["status"] != "ACKNOWLEDGED":
            raise RunbookOSError("incident must be ACKNOWLEDGED before investigation")
        manager.mark_investigating(incident_id, getpass.getuser())
        if ai_config:
            config, config_dir = load_investigation_config(_path(ai_config))
            alert_summary = incident["summary"]
            result = IncidentInvestigator(
                ctx.obj,
                config,
                config_dir,
                build_provider(config.provider),
                allowed_targets={incident["target_alias"]},
            ).investigate(alert_summary)
            evidence = result.get("verified_evidence", [])
            manager.link_investigation(
                incident_id,
                result["investigation_id"],
                sorted({item["execution_id"] for item in evidence}),
                sorted({item["ref"] for item in evidence}),
            )
        else:
            engine = _engine(ctx)
            plan = engine.plan(_path(runbook_file))
            if plan.status != "ready" or not plan.actions:
                raise RunbookOSError("diagnostic plan is not ready")
            if any(action.target != incident["target_alias"] for action in plan.actions):
                raise RunbookOSError("runbook target must exactly match the incident target")
            if any(not action.read_only or not action.allowed for action in plan.actions):
                raise RunbookOSError(
                    "incident investigation accepts only policy-allowed read-only actions"
                )
            if len(plan.actions) > 16:
                raise RunbookOSError(
                    "incident investigation exceeds the 16-action execution budget"
                )
            inventory, _ = load_inventory(ctx.obj.inventory)
            profiles, _ = load_ssh_profiles(ctx.obj.ssh_profiles, resolve_paths=False)
            estimated_seconds = sum(
                action.timeout_seconds
                + profiles[inventory.hosts[action.target].ssh_profile].connect_timeout_seconds
                + profiles[inventory.hosts[action.target].ssh_profile].server_alive_interval_seconds
                + 2
                for action in plan.actions
            )
            if estimated_seconds > 90:
                raise RunbookOSError(
                    "incident investigation exceeds the 90-second execution budget"
                )
            execution_id, status = engine.execute(plan.plan_id, diagnostic_only=True)
            detail = engine.store.execution(execution_id)
            evidence = []
            for step in detail["steps"]:
                if step["status"] == "succeeded":
                    evidence.append(
                        {
                            "ref": f"{execution_id}:{step['step_id']}",
                            "execution_id": execution_id,
                            "target": step["target"],
                            "step_id": step["step_id"],
                            "status": step["status"],
                            "evidence": step["evidence"],
                        }
                    )
            record = {
                "incident_sha256": hashlib.sha256(incident["summary"].encode()).hexdigest(),
                "status": "succeeded" if status == "succeeded" else "partial",
                "selected_diagnostics": [plan.runbook_id],
                "tool_calls": len(plan.actions),
                "evidence": evidence,
                "verified_evidence": evidence,
                "report": {
                    "hypotheses": [],
                    "recommended_next_steps": [],
                    "recommendations_are_executable": False,
                },
                "model_metadata": {"provider": "none", "model": "not_used", "model_calls": 0},
            }
            investigation_id = engine.store.create_investigation(record)
            manager.link_investigation(
                incident_id, investigation_id, [execution_id], [item["ref"] for item in evidence]
            )
            result = {
                "investigation_id": investigation_id,
                "execution_id": execution_id,
                "status": status,
                "evidence_refs": [item["ref"] for item in evidence],
            }
        _json(result)
    except Exception as exc:
        _fail(exc)


@incidents_app.command("timeline")
def incident_timeline(ctx: typer.Context, incident_id: str) -> None:
    try:
        incident = IncidentStore(SQLiteStore(ctx.obj.database)).show(incident_id)
        _json(
            {
                "incident_id": incident_id,
                "events": incident["events"],
                "alerts": incident["alerts"],
                "investigations": incident["investigations"],
            }
        )
    except Exception as exc:
        _fail(exc)


@webhook_app.command("serve")
def webhook_serve(
    ctx: typer.Context,
    auth_config: Path = typer.Option(..., "--auth-config", exists=True, dir_okay=False),
    host: str = typer.Option("127.0.0.1", help="Loopback only."),
    port: int = typer.Option(8765, min=1, max=65535),
) -> None:
    """Run an opt-in foreground webhook using explicit per-source HMAC configuration."""
    try:
        typer.echo(f"Loopback webhook listening on {host}:{port}; Ctrl-C stops it.", err=True)
        serve_from_environment(
            ctx.obj.database, ctx.obj.inventory, _path(auth_config), host=host, port=port
        )
    except KeyboardInterrupt:
        raise typer.Exit(130) from None
    except Exception as exc:
        _fail(exc)


@dashboard_app.command("auth-init")
def dashboard_auth_init(
    operator_id: str = typer.Option(
        ..., "--operator-id", help="Trusted operator identity recorded in audit."
    ),
    auth_file: Path = typer.Option(
        ..., "--auth-file", help="New local verifier file; must not already exist."
    ),
) -> None:
    """Interactively create a protected password verifier for dashboard sessions."""
    try:
        password = typer.prompt("Dashboard password", hide_input=True, confirmation_prompt=True)
        create_auth_file(auth_file, operator_id, password)
        typer.echo(f"Created protected dashboard auth file: {auth_file}")
    except Exception as exc:
        _fail(exc)


@dashboard_app.command("serve")
def dashboard_serve(
    ctx: typer.Context,
    auth_file: Path = typer.Option(..., "--auth-file", exists=True, dir_okay=False),
    host: str = typer.Option("127.0.0.1", help="Loopback only; other values are rejected."),
    port: int = typer.Option(8780, min=1, max=65535),
) -> None:
    """Start the optional foreground dashboard; Ctrl-C stops it."""
    try:
        serve_dashboard(ctx.obj.database, _path(auth_file), host=host, port=port)
    except Exception as exc:
        _fail(exc)


@scenarios_app.command("list")
def scenarios_list(
    scenario_path: Path = typer.Argument(
        SCENARIO_DEFAULT, exists=True, help="Scenario YAML file or directory."
    ),
) -> None:
    """List validated synthetic incident scenarios."""
    try:
        scenarios = load_scenarios(_path(scenario_path))
    except Exception as exc:
        _fail(exc)
    _json(
        [
            {
                "incident_id": item.incident_id,
                "name": item.name,
                "target": item.target,
                "failure_type": item.failure_type,
                "expected_classification": item.expected_classification,
            }
            for item in scenarios
        ]
    )


@scenarios_app.command("validate")
def scenarios_validate(
    scenario_path: Path = typer.Argument(
        SCENARIO_DEFAULT, exists=True, help="Scenario YAML file or directory."
    ),
) -> None:
    """Validate scenario schemas and cross-references."""
    try:
        scenarios = load_scenarios(_path(scenario_path))
    except Exception as exc:
        _fail(exc)
    typer.echo(f"VALID: {len(scenarios)} incident scenarios")


@app.command("evaluate")
def evaluate(
    scenario_path: Path = typer.Option(
        SCENARIO_DEFAULT,
        "--scenarios",
        exists=True,
        help="Scenario YAML file or directory.",
    ),
    provider_mode: str = typer.Option("mock", "--provider", help="mock or configured"),
    provider_config: Path | None = typer.Option(
        None, "--provider-config", help="Provider-only YAML for model evaluation."
    ),
    repeat: int = typer.Option(
        1, "--repeat", min=1, max=20, help="Repeat each scenario for consistency checks."
    ),
    output_dir: Path = typer.Option(Path("evaluation-results"), "--output-dir"),
) -> None:
    """Evaluate diagnosis against synthetic fixtures; does not run SSH or inject faults."""
    try:
        scenarios = load_scenarios(_path(scenario_path))
        if provider_mode == "mock":
            if provider_config is not None:
                raise RunbookOSError("--provider-config is only valid with --provider configured")
            results = run_mock_evaluation(scenarios, repeat=repeat)
        elif provider_mode == "configured":
            if provider_config is None:
                raise RunbookOSError("--provider configured requires --provider-config")
            config = load_evaluation_provider_config(_path(provider_config))
            results = run_provider_evaluation(
                scenarios,
                ConfiguredScenarioProvider(build_provider(config.provider), config.provider.model),
                repeat=repeat,
            )
        else:
            raise RunbookOSError("--provider must be mock or configured")
        dataset = build_dataset(results, provider_mode)
        destination = _path(output_dir)
        json_path = destination / f"{dataset['evaluation_id']}.json"
        report_path = destination / f"{dataset['evaluation_id']}.md"
        save_dataset(dataset, json_path, report_path)
    except Exception as exc:
        _fail(exc)
    typer.echo(f"Evaluation {dataset['evaluation_id']}")
    typer.echo(f"JSON: {json_path}")
    typer.echo(f"Report: {report_path}")
    _json(dataset["summary"])


@app.command("evaluate-v2")
def evaluate_v2(
    scenario_path: Path = typer.Option(
        SCENARIO_DEFAULT, "--scenarios", exists=True, help="Immutable v0.2.2 scenario fixtures."
    ),
    taxonomy_path: Path = typer.Option(
        TAXONOMY_DEFAULT,
        "--taxonomy",
        exists=True,
        help="Versioned classification/root-cause taxonomy.",
    ),
    ground_truth_path: Path = typer.Option(
        GROUND_TRUTH_DEFAULT,
        "--ground-truth",
        exists=True,
        help="Private-to-evaluator labels; never sent to the provider.",
    ),
    provider_mode: str = typer.Option(
        "mock", "--provider", help="mock or configured model provider."
    ),
    provider_config: Path = typer.Option(
        DEFAULTS / "config/evaluation.qwen.example.yml", "--provider-config", exists=True
    ),
    repeat: int = typer.Option(1, "--repeat", min=1, max=20),
    output_dir: Path = typer.Option(Path("evaluation-v2-results"), "--output-dir"),
) -> None:
    """Run taxonomy-v2 evaluation using synthetic fixtures only; never uses SSH."""
    try:
        if provider_mode not in {"mock", "configured"}:
            raise RunbookOSError("--provider must be mock or configured")
        scenarios = load_scenarios(_path(scenario_path))
        taxonomy_file = _path(taxonomy_path)
        taxonomy = load_taxonomy(taxonomy_file)
        truth = load_ground_truth(_path(ground_truth_path), taxonomy)
        if set(truth.scenarios) != {scenario.incident_id for scenario in scenarios}:
            raise RunbookOSError("taxonomy ground truth must match the scenario set exactly")
        if provider_mode == "mock":
            results = run_mock_evaluation_v2(scenarios, truth, taxonomy, repeat=repeat)
        else:
            config = load_evaluation_provider_config(_path(provider_config))
            results = run_provider_evaluation_v2(
                scenarios,
                truth,
                StructuredScenarioProvider(
                    build_provider(config.provider), config.provider.model, taxonomy
                ),
                repeat=repeat,
            )
        dataset = build_dataset_v2(
            results,
            provider_mode,
            hashlib.sha256(taxonomy_file.read_bytes()).hexdigest(),
        )
        json_path, report_path = save_dataset_v2(dataset, _path(output_dir))
    except Exception as exc:
        _fail(exc)
    typer.echo(f"Evaluation {dataset['evaluation_id']}")
    typer.echo(f"JSON: {json_path}")
    typer.echo(f"Report: {report_path}")
    _json(dataset["summary"])


@evaluation_app.command("report")
def evaluation_report(
    dataset_path: Path = typer.Argument(..., exists=True, dir_okay=False, readable=True),
) -> None:
    """Render the Markdown report represented by an evaluation JSON dataset."""
    try:
        from .evaluation import render_report, summarize_results

        dataset = json.loads(_path(dataset_path).read_text(encoding="utf-8"))
        schema_version = dataset.get("schema_version")
        if schema_version not in {1, 2} or not isinstance(dataset.get("results"), list):
            raise RunbookOSError("invalid evaluation dataset")
        if schema_version == 1:
            dataset["summary"] = summarize_results(dataset["results"])
            report = render_report(dataset)
        else:
            dataset["summary"] = summarize_v2(dataset["results"])
            report = render_report_v2(dataset)
    except Exception as exc:
        _fail(exc)
    typer.echo(report)


@evaluation_app.command("export-blind")
def evaluation_export_blind(
    dataset_path: Path = typer.Argument(..., exists=True, dir_okay=False, readable=True),
    output_dir: Path = typer.Option(Path("blind-review-packet"), "--output-dir"),
    scenario_path: Path = typer.Option(
        SCENARIO_DEFAULT, "--scenarios", exists=True, help="Local synthetic fixture directory."
    ),
    seed: int | None = typer.Option(None, "--seed", help="Optional reproducible shuffle seed."),
) -> None:
    """Export two randomized human review sheets and a separate withheld answer key."""
    try:
        paths = export_blind_review(
            _path(dataset_path), _path(scenario_path), _path(output_dir), seed=seed
        )
    except Exception as exc:
        _fail(exc)
    for label, path in paths.items():
        typer.echo(f"{label}: {path}")


@evaluation_app.command("review-agreement")
def evaluation_review_agreement(
    reviewer_1: Path = typer.Argument(..., exists=True, dir_okay=False, readable=True),
    reviewer_2: Path = typer.Argument(..., exists=True, dir_okay=False, readable=True),
) -> None:
    """Compute human reviewer agreement from two completed blind review sheets."""
    try:
        result = reviewer_agreement(_path(reviewer_1), _path(reviewer_2))
    except Exception as exc:
        _fail(exc)
    _json(result)
