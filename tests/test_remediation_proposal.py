from __future__ import annotations

import json

import pytest
from pydantic import ValidationError

from runbookos.errors import RunbookOSError
from runbookos.remediation_proposal import (
    PROPOSAL_SYSTEM_PROMPT_V1,
    RegisteredActionCandidate,
    RemediationProposalReplyV1,
    decode_proposal_reply,
    proposal_failure_code,
    proposal_prompt,
    request_remediation_proposal,
    validate_proposal,
)


def candidate(**overrides):
    values = {
        "action_id": "systemd.restart",
        "target_ref": "fixture-web",
        "target_name": "svc-web-01",
        "arguments": {"unit": "runbookos-campaign-b03-api.service"},
        "required_evidence_actions": ("systemd.is_active", "http.readiness"),
        "compatible_categories": ("service_failure",),
    }
    values.update(overrides)
    return RegisteredActionCandidate.model_validate(values)


def reply(**overrides):
    values = {
        "proposal_version": 1,
        "incident_id": "incident-1",
        "investigation_id": "investigation-1",
        "evidence_refs": ["exec-1:http"],
        "suspected_fault_category": "service_failure",
        "uncertainty": 0.25,
        "causal_hypothesis": "The fixture service is unavailable.",
        "candidate_action_id": "systemd.restart",
        "target_ref": "fixture-web",
        "expected_recovery_effect": "The registered service may return to readiness.",
        "rationale": "The cited readiness observation reports an error.",
        "contraindications": ["A restart may interrupt in-flight fixture requests."],
        "abstain": False,
    }
    values.update(overrides)
    return RemediationProposalReplyV1.model_validate(values)


def validate(value=None, **kwargs):
    return validate_proposal(
        value or reply(),
        incident_id="incident-1",
        investigation_id="investigation-1",
        evidence_refs={"exec-1:http", "exec-1:unit"},
        candidates={("systemd.restart", "fixture-web"): candidate()},
        evidence_actions={"exec-1:http": "http.readiness", "exec-1:unit": "systemd.is_active"},
        **kwargs,
    )


def test_registered_proposal_is_advisory_and_returns_trusted_arguments():
    result = validate()
    assert result == {
        "accepted": True,
        "abstained": False,
        "candidate": {
            "action_id": "systemd.restart",
            "target_ref": "fixture-web",
            "target_name": "svc-web-01",
            "arguments": {"unit": "runbookos-campaign-b03-api.service"},
        },
    }


def test_same_registered_action_can_target_distinct_allowlisted_resources():
    primary = candidate()
    backend = candidate(
        target_ref="fixture-backend",
        arguments={"unit": "runbookos-campaign-b03-backend.service"},
    )
    selected = validate_proposal(
        reply(target_ref="fixture-backend"),
        incident_id="incident-1",
        investigation_id="investigation-1",
        evidence_refs={"exec-1:http"},
        candidates={
            (primary.action_id, primary.target_ref): primary,
            (backend.action_id, backend.target_ref): backend,
        },
        evidence_actions={"exec-1:http": "http.readiness"},
    )
    assert selected["candidate"]["target_ref"] == "fixture-backend"
    assert selected["candidate"]["arguments"]["unit"].endswith("backend.service")


def test_valid_abstention_has_no_action():
    value = reply(
        evidence_refs=[],
        suspected_fault_category="unknown",
        candidate_action_id=None,
        target_ref=None,
        abstain=True,
    )
    assert validate(value)["abstained"] is True


@pytest.mark.parametrize(
    "overrides",
    [
        {"candidate_action_id": "shell.exec"},
        {"target_ref": "another-target"},
        {"evidence_refs": ["forged:ref"]},
        {"incident_id": "another-incident"},
        {"investigation_id": "another-investigation"},
        {"abstain": True},
        {"suspected_fault_category": "unknown"},
        {"suspected_fault_category": "healthy"},
        {"evidence_refs": ["exec-1:http", "exec-1:http"]},
    ],
)
def test_invalid_proposal_fails_closed(overrides):
    with pytest.raises((RunbookOSError, ValidationError)):
        validate(reply(**overrides))


def test_required_evidence_action_is_enforced():
    value = reply(evidence_refs=["exec-1:unit"])
    with pytest.raises(RunbookOSError, match="lacks required evidence"):
        validate_proposal(
            value,
            incident_id="incident-1",
            investigation_id="investigation-1",
            evidence_refs={"exec-1:http", "exec-1:unit"},
            candidates={
                ("systemd.restart", "fixture-web"): candidate(
                    required_evidence_actions=("http.readiness",)
                )
            },
            evidence_actions={
                "exec-1:http": "http.readiness",
                "exec-1:unit": "systemd.is_active",
            },
        )


def test_non_abstaining_proposal_requires_evidence():
    with pytest.raises(RunbookOSError, match="requires cited diagnostic evidence"):
        validate(reply(evidence_refs=[]))


def test_action_category_compatibility_is_checked_independently():
    value = reply(suspected_fault_category="resource_pressure")
    with pytest.raises(RunbookOSError, match="incompatible with its category"):
        validate_proposal(
            value,
            incident_id="incident-1",
            investigation_id="investigation-1",
            evidence_refs={"exec-1:http"},
            candidates={
                ("systemd.restart", "fixture-web"): candidate(
                    compatible_categories=("service_failure",)
                )
            },
            evidence_actions={"exec-1:http": "http.readiness"},
        )


def test_model_facing_projection_rejects_gold_and_rationale_fields():
    for forbidden in ("gold", "ground_truth_category", "annotationRationale", "oracle"):
        with pytest.raises(RunbookOSError, match="reserved label metadata"):
            proposal_prompt(
                incident_id="incident-1",
                investigation_id="investigation-1",
                evidence=[
                    {
                        "ref": "exec-1:http",
                        "observed_result": {"status": 503},
                        forbidden: "private expected answer",
                    }
                ],
                candidates=[candidate()],
            )


def test_proposal_prompt_documents_reply_field_types_and_abstention_semantics():
    prompt = PROPOSAL_SYSTEM_PROMPT_V1
    for required in (
        "proposal_version (integer 1)",
        "incident_id (string",
        "investigation_id (string",
        "evidence_refs (array of unique case-local aliases",
        "uncertainty (finite number 0..1)",
        "candidate_action_id (string or null)",
        "target_ref (string or null)",
        "contraindications (array of strings",
        "abstain (boolean)",
        "For abstain=true, use category=unknown",
        "certainty terms such as verified, confirmed, proven",
        "Do not put commands, shell syntax, or secret-like values",
    ):
        assert required in prompt


@pytest.mark.parametrize("uncertainty", [-0.01, 1.01, float("nan"), float("inf"), True])
def test_uncertainty_must_be_finite_unit_interval_number(uncertainty):
    with pytest.raises(ValidationError):
        reply(uncertainty=uncertainty)


@pytest.mark.parametrize(
    "text",
    [
        "systemctl restart api.service",
        "run `sudo rm -rf /`",
        "apply change; restart",
        "The diagnosis is verified.",
        "token=very-secret-value",
    ],
)
def test_command_shaped_text_is_rejected(text):
    with pytest.raises(ValidationError):
        reply(rationale=text)


def test_unknown_registered_action_arguments_are_rejected():
    with pytest.raises(Exception):
        candidate(arguments={"unit": "api.service", "unexpected": "x"})


def test_strict_decoder_rejects_malformed_json_and_extra_fields():
    with pytest.raises(RunbookOSError) as malformed:
        decode_proposal_reply('{"proposal_version":')
    assert proposal_failure_code(malformed.value) == "malformed_json"
    raw = reply().model_dump(mode="json")
    raw["command"] = "systemctl restart anything"
    with pytest.raises(RunbookOSError) as invalid:
        decode_proposal_reply(json.dumps(raw))
    assert proposal_failure_code(invalid.value) == "reply_schema_invalid_unknown_field_extra"


def test_schema_failure_trace_exposes_only_sanitized_field_and_validator_kind():
    raw = reply().model_dump(mode="json")
    raw["suspected_fault_category"] = "private raw model content"
    with pytest.raises(RunbookOSError) as invalid:
        decode_proposal_reply(json.dumps(raw))
    code = proposal_failure_code(invalid.value)
    assert code == "reply_schema_invalid_suspected_fault_category_literal"
    assert "private raw model content" not in str(invalid.value)


@pytest.mark.parametrize(
    ("message", "expected"),
    [
        ("AI remediation proposal references unknown evidence", "forged_evidence_reference"),
        (
            "AI remediation proposal selected an unavailable action",
            "action_not_in_candidate_catalog",
        ),
        ("unclassified internal error", "proposal_contract_rejected"),
    ],
)
def test_proposal_failure_codes_are_sanitized(message, expected):
    assert proposal_failure_code(RunbookOSError(message)) == expected


def test_proposal_timeout_has_a_sanitized_failure_code():
    assert proposal_failure_code(TimeoutError("private provider details")) == "provider_timeout"


def test_wrong_target_and_unknown_evidence_never_return_executable_candidate():
    with pytest.raises(RunbookOSError):
        validate(reply(target_ref="unregistered"))
    with pytest.raises(RunbookOSError):
        validate(reply(evidence_refs=["not-real"]))


def test_duplicate_action_target_candidates_are_rejected_before_provider_call():
    class NoCallProvider:
        calls = 0

        def complete(self, *args, **kwargs):
            self.calls += 1
            raise AssertionError("duplicate candidate must be rejected before inference")

    provider = NoCallProvider()
    item = candidate()
    with pytest.raises(RunbookOSError, match="duplicate candidate identities"):
        request_remediation_proposal(
            provider,
            incident_id="i1",
            investigation_id="x1",
            evidence=[{"ref": "e1"}],
            candidates=[item, item],
        )
    assert provider.calls == 0


def test_request_maps_case_local_alias_back_to_exact_persisted_reference():
    canonical = "execution-12345678:step-http-readiness"
    raw_reply = reply(evidence_refs=["E01"]).model_dump(mode="json")

    class AliasProvider:
        calls = 0
        prompt = ""

        def complete(self, system, user, max_tokens, temperature):
            self.calls += 1
            self.prompt = user
            return type(
                "Response",
                (),
                {
                    "content": json.dumps(raw_reply),
                    "model": "mock",
                    "duration_seconds": 0.01,
                    "token_usage": None,
                },
            )()

    provider = AliasProvider()
    result, metadata = request_remediation_proposal(
        provider,
        incident_id="incident-1",
        investigation_id="investigation-1",
        evidence=[
            {
                "ref": canonical,
                "source_action": "http.readiness",
                "evidence": {
                    "data": {"unit": "runbookos-campaign-b03-api.service", "active": True}
                },
            }
        ],
        candidates=[candidate()],
        evidence_actions={canonical: "http.readiness"},
    )
    assert result.evidence_refs == [canonical]
    assert "E01" in provider.prompt
    assert canonical not in provider.prompt
    assert metadata["evidence_aliases_resolved"] == 1
    assert provider.calls == 1


def test_unknown_case_local_evidence_alias_is_rejected_without_retry():
    raw_reply = reply(evidence_refs=["E99"]).model_dump(mode="json")

    class AliasProvider:
        calls = 0

        def complete(self, *args, **kwargs):
            self.calls += 1
            return type(
                "Response",
                (),
                {
                    "content": json.dumps(raw_reply),
                    "model": "mock",
                    "duration_seconds": 0.01,
                    "token_usage": None,
                },
            )()

    provider = AliasProvider()
    with pytest.raises(RunbookOSError, match="unknown evidence"):
        request_remediation_proposal(
            provider,
            incident_id="incident-1",
            investigation_id="investigation-1",
            evidence=[{"ref": "execution:real"}],
            candidates=[candidate()],
        )
    assert provider.calls == 1


@pytest.mark.parametrize(
    ("text", "suffix"),
    [
        ("The diagnosis is confirmed.", "certainty"),
        ("Start service; inspect result", "command"),
        ("token=private-synthetic-value", "secret"),
    ],
)
def test_text_failure_diagnostics_classify_without_retaining_model_text(text, suffix):
    body = reply().model_dump(mode="json")
    body["rationale"] = text
    with pytest.raises(RunbookOSError) as failure:
        decode_proposal_reply(json.dumps(body))
    assert (
        proposal_failure_code(failure.value)
        == "reply_schema_invalid_rationale_text_policy_" + suffix
    )
    assert text not in str(failure.value)


def test_advisory_service_subject_is_not_a_shell_command():
    proposal = reply(expected_recovery_effect="Service readiness may return after recovery.")
    assert proposal.expected_recovery_effect == "Service readiness may return after recovery."


@pytest.mark.parametrize(
    "text",
    [
        "service nginx restart",
        "service nginx stop",
        "service nginx status",
        "sudo service nginx restart",
    ],
)
def test_service_cli_commands_remain_rejected(text):
    with pytest.raises(ValidationError):
        reply(expected_recovery_effect=text)


def test_semantic_v2_binds_only_trusted_identity_and_preserves_every_semantic_field():
    from runbookos.remediation_proposal import decode_semantic_proposal

    original = reply().model_dump(mode="json")
    wire = {k: v for k, v in original.items() if k not in {"incident_id", "investigation_id"}}
    wire["proposal_version"] = 2
    decoded = decode_semantic_proposal(
        json.dumps(wire), incident_id="trusted-incident", investigation_id="trusted-investigation"
    )
    assert decoded.incident_id == "trusted-incident"
    assert decoded.investigation_id == "trusted-investigation"
    for field in wire:
        if field != "proposal_version":
            assert decoded.model_dump(mode="json")[field] == wire[field]


@pytest.mark.parametrize(
    "mutation",
    [
        {"incident_id": "model-invented"},
        {"command": "service fixture restart"},
        {"uncertainty": "0.2"},
        {"abstain": "false"},
        {"evidence_refs": "E01"},
        {"suspected_fault_category": "unsupported"},
        {"uncertainty": float("nan")},
    ],
)
def test_semantic_v2_never_repairs_invalid_semantics_or_accepts_identity_override(mutation):
    from runbookos.remediation_proposal import decode_semantic_proposal

    body = reply().model_dump(mode="json")
    del body["incident_id"]
    del body["investigation_id"]
    body["proposal_version"] = 2
    body.update(mutation)
    with pytest.raises(RunbookOSError):
        decode_semantic_proposal(json.dumps(body), incident_id="i", investigation_id="x")


def test_semantic_v2_missing_semantic_field_is_not_filled():
    from runbookos.remediation_proposal import decode_semantic_proposal

    body = reply().model_dump(mode="json")
    for field in ("incident_id", "investigation_id", "rationale"):
        del body[field]
    body["proposal_version"] = 2
    with pytest.raises(RunbookOSError):
        decode_semantic_proposal(json.dumps(body), incident_id="i", investigation_id="x")


@pytest.mark.parametrize(
    ("action", "unit", "observations", "result"),
    [
        (
            "systemd.start",
            "app.service",
            [{"evidence": {"data": {"unit": "worker.service", "active": False}}}],
            "unit_state_not_observed",
        ),
        (
            "systemd.start",
            "app.service",
            [{"evidence": {"data": {"unit": "app.service", "active": True}}}],
            "unit_state_incompatible",
        ),
        (
            "systemd.start",
            "app.service",
            [{"evidence": {"data": {"unit": "app.service", "active": False}}}],
            "satisfied",
        ),
        (
            "systemd.restart",
            "app.service",
            [{"evidence": {"data": {"unit": "app.service", "active": True}}}],
            "satisfied",
        ),
        (
            "systemd.start",
            "app.service",
            [
                {"evidence": {"data": {"unit": "app.service", "active": True}}},
                {"evidence": {"data": {"unit": "app.service", "active": False}}},
            ],
            "conflicting_unit_state",
        ),
    ],
)
def test_service_action_requires_exact_observed_unit_and_state(action, unit, observations, result):
    from runbookos.remediation_proposal import unit_state_prerequisite

    item = candidate(action_id=action, arguments={"unit": unit})
    assert unit_state_prerequisite(item, observations) == result


def test_constrained_schema_binds_abstention_and_exact_candidate_pairs_without_oracle():
    from runbookos.remediation_proposal import semantic_proposal_json_schema

    candidates = [
        candidate(),
        candidate(target_ref="other-fixture", arguments={"unit": "other.service"}),
    ]
    schema = semantic_proposal_json_schema(candidates, ["E01", "E02"])
    assert len(schema["anyOf"]) == 3
    abstention, *choices = schema["anyOf"]
    assert abstention["properties"]["abstain"] == {"const": True}
    assert abstention["properties"]["suspected_fault_category"] == {"enum": ["unknown"]}
    assert abstention["properties"]["candidate_action_id"] == {"const": None}
    for branch, item in zip(choices, candidates, strict=True):
        p = branch["properties"]
        assert p["abstain"] == {"const": False}
        assert p["candidate_action_id"] == {"const": item.action_id}
        assert p["target_ref"] == {"const": item.target_ref}
        assert p["evidence_refs"]["items"] == {"enum": ["E01", "E02"]}
        assert p["evidence_refs"]["minItems"] == 1
        assert branch["additionalProperties"] is False
        assert "incident_id" not in p
    assert "oracle" not in json.dumps(schema)


def test_constrained_schema_with_no_evidence_permits_only_abstention():
    from runbookos.remediation_proposal import semantic_proposal_json_schema

    schema = semantic_proposal_json_schema([candidate()], [])
    assert len(schema["anyOf"]) == 1
    assert schema["anyOf"][0]["properties"]["evidence_refs"]["maxItems"] == 0


@pytest.mark.parametrize(
    ("action", "arguments", "data", "state"),
    [
        (
            "config.restore_fixture",
            {"fixture_id": "app_config"},
            {"observations": {"app": {"configuration_valid": True}}},
            "observations_incompatible",
        ),
        (
            "config.restore_fixture",
            {"fixture_id": "app_config"},
            {"observations": {"app": {"configuration_valid": False}}},
            "satisfied",
        ),
        (
            "resource.restore_fixture",
            {"fixture_id": "worker_quota"},
            {"fixture_id": "worker_quota", "quota_below_baseline": False},
            "observations_incompatible",
        ),
        (
            "network.restore_fixture",
            {"fixture_id": "isolated_link"},
            {"endpoint_id": "b04-netns", "connected": False},
            "satisfied",
        ),
        (
            "dns.restore_fixture",
            {"fixture_id": "resolver_config"},
            {"fixture_id": "b04_resolver", "matches_fixture_backend": False},
            "satisfied",
        ),
        (
            "storage.release_fixture",
            {"fixture_id": "bounded_volume"},
            {"path": "/var/lib/runbookos-campaign-b04/volume", "free_bytes": 16777216},
            "observations_incompatible",
        ),
        (
            "dependency.restore_fixture",
            {"fixture_id": "backend_service"},
            {"endpoint_id": "b04-backend", "ready": True},
            "observations_incompatible",
        ),
    ],
)
def test_repair_prerequisites_come_from_observations_not_fault_oracle(
    action, arguments, data, state
):
    from runbookos.remediation_proposal import candidate_observation_prerequisite

    c = candidate(action_id=action, arguments=arguments)
    assert candidate_observation_prerequisite(c, [{"evidence": {"data": data}}]) == state


@pytest.mark.parametrize(
    "observation",
    [
        {"fixture_id": "b04_resolver", "matches_fixture_backend": False},
        {"endpoint_id": "b04-netns", "connected": False},
        {"fixture_id": "worker_quota", "quota_below_baseline": True},
        {"observations": {"proxy": {"configuration_valid": False}}},
        {"path": "/var/lib/runbookos-campaign-b04/volume", "free_bytes": 0},
        {
            "fixture_id": "web_stack",
            "observations": {"app": {"health_code": "isolated-network-OSError"}},
        },
    ],
)
def test_campaign_app_restart_rejected_when_observed_external_fault_is_broken(observation):
    from runbookos.remediation_proposal import candidate_observation_prerequisite

    restart = candidate(
        action_id="systemd.restart",
        arguments={"unit": "runbookos-campaign-b04-app.service"},
    )
    evidence = [
        {"evidence": {"data": {"unit": "runbookos-campaign-b04-app.service", "active": True}}},
        {"evidence": {"data": observation}},
    ]
    assert candidate_observation_prerequisite(restart, evidence) == "observations_incompatible"
    assert candidate_observation_prerequisite(restart, evidence[:1]) == "satisfied"


@pytest.mark.parametrize(
    ("action_id", "arguments", "health_code"),
    [
        ("network.restore_fixture", {"fixture_id": "isolated_link"}, "isolated-network-OSError"),
        ("resource.restore_fixture", {"fixture_id": "worker_quota"}, "worker-resource-pressure"),
    ],
)
def test_fixture_health_codes_support_specific_repair_without_fault_oracle(
    action_id, arguments, health_code
):
    from runbookos.remediation_proposal import candidate_observation_prerequisite

    item = candidate(action_id=action_id, arguments=arguments)
    evidence = [
        {
            "evidence": {
                "data": {
                    "fixture_id": "web_stack",
                    "observations": {"app": {"health_code": health_code}},
                }
            }
        }
    ]
    assert candidate_observation_prerequisite(item, evidence) == "satisfied"


def test_constrained_provider_schema_excludes_only_observation_contradicted_actions():
    class CaptureProvider:
        config = type("Config", (), {"schema_constrained_proposals": True})()
        calls = 0
        schema = None

        def complete_with_schema(self, _system, _user, _tokens, _temperature, schema):
            self.calls += 1
            self.schema = schema
            raise RuntimeError("captured without inference")

    provider = CaptureProvider()
    candidates = [
        candidate(
            action_id="systemd.restart",
            target_ref="app",
            arguments={"unit": "runbookos-campaign-b04-app.service"},
        ),
        candidate(
            action_id="dns.restore_fixture",
            target_ref="dns",
            arguments={"fixture_id": "resolver_config"},
        ),
    ]
    evidence = [
        {
            "ref": "unit",
            "source_action": "systemd.is_active",
            "evidence": {"data": {"unit": "runbookos-campaign-b04-app.service", "active": True}},
        },
        {
            "ref": "dns",
            "source_action": "dns.resolve_fixture",
            "evidence": {"data": {"fixture_id": "b04_resolver", "matches_fixture_backend": False}},
        },
    ]
    with pytest.raises(RuntimeError, match="captured without inference"):
        request_remediation_proposal(
            provider,
            incident_id="i",
            investigation_id="x",
            evidence=evidence,
            candidates=candidates,
        )
    actions = [
        branch["properties"]["candidate_action_id"]["const"] for branch in provider.schema["anyOf"]
    ]
    assert actions == [None, "dns.restore_fixture"]
    assert provider.calls == 1


def test_observed_prerequisites_do_not_filter_model_candidate_catalog():
    candidates = [
        candidate(),
        candidate(
            action_id="config.restore_fixture",
            target_ref="config",
            arguments={"fixture_id": "app_config"},
        ),
    ]
    prompt = json.loads(
        proposal_prompt(
            incident_id="i",
            investigation_id="x",
            evidence=[
                {
                    "ref": "E01",
                    "evidence": {"data": {"observations": {"app": {"configuration_valid": True}}}},
                }
            ],
            candidates=candidates,
        )
    )
    assert len(prompt["registered_action_candidates"]) == 2
    assert {i["target_ref"] for i in prompt["registered_action_candidates"]} == {
        "fixture-web",
        "config",
    }
    config = next(i for i in prompt["registered_action_candidates"] if i["target_ref"] == "config")
    assert config["observed_repair_prerequisite"] == "observations_incompatible"
