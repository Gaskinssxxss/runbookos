from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).parents[1]
sys.path.insert(0, str(ROOT / "scripts"))


def load(name: str):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / f"{name}.py")
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


b04 = load("campaign_batch04")


def test_campaign_has_two_fixed_groups_of_ten_distinct_scenarios():
    assert len(b04.SCENARIOS) == 20
    assert len({item["id"] for item in b04.SCENARIOS}) == 20
    assert sum(item["group"] == "A" for item in b04.SCENARIOS) == 10
    assert sum(item["group"] == "B" for item in b04.SCENARIOS) == 10


@pytest.mark.parametrize("target", ["svc-web-01", "db-01"])
def test_candidate_catalog_contains_alternatives_and_never_includes_oracle(target):
    candidates = b04.candidate_catalog(target)
    assert len(candidates) >= 2
    assert len({(item["action_id"], item["target_ref"]) for item in candidates}) == len(candidates)
    assert all(item.get("purpose") for item in candidates)
    assert not any(
        "oracle" in str(item).casefold() or "expected_actions" in str(item) for item in candidates
    )


def test_candidate_catalog_is_not_narrowed_using_fault_labels():
    catalog = b04.candidate_catalog("svc-web-01")
    for scenario in (item for item in b04.SCENARIOS if item["target"] == "svc-web-01"):
        assert len(catalog) > len(scenario["expected_actions"])
        for expected in scenario["expected_actions"]:
            assert any(item["action_id"] == expected for item in catalog)


def test_oracle_evaluator_is_separate_and_flags_wrong_candidate():
    scenario = next(item for item in b04.SCENARIOS if item["id"] == "B04-02")
    assert b04.action_is_oracle_appropriate(scenario, "config.restore_fixture", "b04-app-config")
    assert not b04.action_is_oracle_appropriate(
        scenario, "config.restore_fixture", "b04-proxy-config"
    )
    assert not b04.action_is_oracle_appropriate(scenario, "systemd.restart", "b04-app-unit")
    assert "expected_actions" not in str(b04.candidate_catalog("svc-web-01"))


def test_disposable_postgres_accepts_only_registered_start_recovery_on_exact_target():
    scenario = next(item for item in b04.SCENARIOS if item["id"] == "B04-05")
    assert b04.action_is_oracle_appropriate(scenario, "postgresql.start_fixture", "b04-postgres")
    assert b04.action_is_oracle_appropriate(scenario, "systemd.start", "b04-postgres-unit")
    assert not b04.action_is_oracle_appropriate(scenario, "systemd.restart", "b04-postgres-unit")


def test_pass_ledger_requires_multiple_candidates_and_exact_executed_action():
    attempt = {
        "run_id": "b04-a1",
        "scenario_id": "B04-01",
        "retry_of": None,
        "result": "AI_DRIVEN_PASS",
        "steps": {
            **{
                name: {"status": "PASS"}
                for name in (
                    "baseline",
                    "fault",
                    "incident",
                    "diagnostics",
                    "assessment",
                    "authorization",
                    "remediation",
                    "postflight",
                    "closure",
                    "audit",
                    "cleanup",
                )
            },
            "proposal": {
                "status": "PASS",
                "candidate_catalog": [
                    {"action_id": "systemd.start"},
                    {"action_id": "config.restore_fixture"},
                ],
                "selected_action_id": "systemd.start",
                "target_ref": "b04-app-unit",
            },
            "remediation": {
                "status": "PASS",
                "action_id": "systemd.start",
                "target_ref": "b04-app-unit",
            },
        },
    }
    b04.validate_ledger([attempt])
    attempt["steps"]["remediation"]["action_id"] = "config.restore_fixture"
    with pytest.raises(ValueError, match="differs"):
        b04.validate_ledger([attempt])


def test_retry_lineage_requires_a_preceding_attempt():
    with pytest.raises(ValueError, match="preceding"):
        b04.validate_ledger([{"run_id": "b04-a2", "retry_of": "missing", "result": "FAIL"}])


def test_live_runbooks_fit_conservative_budget_and_recovery_has_engine_checks(monkeypatch):
    live = load("campaign_batch04_live")
    import yaml

    documents = {}
    template = {"hosts": {"svc-web-01": {}, "db-01": {}}}
    monkeypatch.setattr(live.b03, "remote_read", lambda *a: yaml.safe_dump(template))
    monkeypatch.setattr(
        live.b03, "write_yaml", lambda vm, path, value: documents.__setitem__(path, value)
    )
    monkeypatch.setattr(live, "guest", lambda *a, **k: {})
    live.configure_controller()
    config = documents[live.CONFIG + "/investigation.yml"]
    limits = config["limits"]
    for name in ("core", "dependency", "resource", "db"):
        runbook = documents[live.RUNBOOKS + "/b04-" + name + ".yml"]
        assert len(runbook["steps"]) == (4 if name == "db" else 3)
        if name == "core":
            inspect = [
                step for step in runbook["steps"] if step["action"] == "application.inspect_fixture"
            ]
            assert len(inspect) == 1 and inspect[0]["timeout_seconds"] == 4
        # Actual configured SSH overhead: connect 5, keepalive 5, engine margin 2.
        cost = sum(step["timeout_seconds"] + 12 for step in runbook["steps"])
        assert (
            cost * (1 if name == "db" else limits["max_diagnostic_runbooks"])
            <= limits["execution_budget_seconds"]
        )
        assert (
            len(runbook["steps"]) * (1 if name == "db" else limits["max_diagnostic_runbooks"])
            <= limits["max_tool_calls"]
        )
    for target in ("svc-web-01", "db-01"):
        candidate = b04.candidate_catalog(target)[0]
        recovery = yaml.safe_load(live.recovery_doc("test", target, candidate))
        assert recovery["steps"][0]["action"] == candidate["action_id"]
        assert recovery["steps"][0]["with"] == candidate["arguments"]
        from runbookos.actions import REGISTRY

        assert (
            recovery["steps"][0]["timeout_seconds"]
            <= REGISTRY[candidate["action_id"]].max_timeout_seconds
        )
        assert recovery["preflight"][0]["verify"][0]["value"] is False
        assert recovery["postflight"][0]["verify"][0]["operator"] == "is_true"


@pytest.mark.parametrize(
    "outcome",
    [
        {"resource_watch": {"status": "failed", "failure_category": "resource_threshold_exceeded"}},
        {
            "transport_failure_component": "resource_watch_preflight",
            "transport_failure_category": "FileNotFoundError",
        },
    ],
)
def test_resource_or_identity_failure_aborts_campaign(outcome):
    live = load("campaign_batch04_live")
    with pytest.raises(live.CampaignSafetyAbort):
        live.enforce_transport_guard(outcome)


def test_proposal_timeout_metadata_is_allowlisted_and_bounded():
    live = load("campaign_batch04_live")
    assert live.safe_provider_request_metadata(
        {"request_metadata": {"failure_stage": "proposal", "duration_seconds": 120.125}}
    ) == {"failure_stage": "proposal", "duration_seconds": 120.125}
    for metadata in (
        {"failure_stage": "assessment", "duration_seconds": 120.0},
        {"failure_stage": "proposal", "duration_seconds": float("inf")},
        {"failure_stage": "proposal", "duration_seconds": 10.0, "raw_response": "must not persist"},
        {"failure_stage": "proposal", "duration_seconds": 3600.1},
    ):
        assert live.safe_provider_request_metadata({"request_metadata": metadata}) is None


def test_missing_provider_never_injects_another_fault(monkeypatch):
    live = load("campaign_batch04_live")

    def lost_identity():
        raise live.CampaignSafetyAbort("provider_process_identity_unavailable")

    monkeypatch.setattr(live, "assert_provider_identity", lost_identity)
    monkeypatch.setattr(live, "persist", lambda ledger: None)
    monkeypatch.setattr(live, "reset", lambda scenario: True)
    monkeypatch.setattr(live, "healthy", lambda target: True)
    faults = []
    monkeypatch.setattr(live, "inject", lambda scenario: faults.append(scenario))
    ledger = {"attempts": []}
    attempt = live.run_scenario(b04.SCENARIOS[0], ledger)
    assert attempt["result"] == "FAIL"
    assert attempt["campaign_abort"] is True
    assert attempt["steps"]["cleanup"]["status"] == "PASS"
    assert faults == []
