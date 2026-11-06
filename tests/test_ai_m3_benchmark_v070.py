from __future__ import annotations

import json
from pathlib import Path

import ai_m3_benchmark_v070 as benchmark_adapter
import pytest
from ai_m3_benchmark_v070 import (
    ASSESSMENT_MAX_COMPLETION_TOKENS,
    ASSESSMENT_SYSTEM_PROMPT,
    DATASET_PATH,
    DIAGNOSTIC_IDS,
    MAX_MODEL_RESPONSE_BYTES,
    MAX_PROVIDER_REQUESTS,
    PILOT_CASE_IDS,
    PILOT_PROVIDER_REQUESTS,
    SELECTION_MAX_COMPLETION_TOKENS,
    SELECTION_SYSTEM_PROMPT,
    RequestBudgetProvider,
    evaluate_pilot_predictions,
    evaluate_predictions,
    generate_predictions,
    load_prediction_submission,
    model_prediction_to_evaluation_input,
    run_benchmark_acceptance,
    run_pilot_acceptance,
    write_prediction_submission,
)

from runbookos import __version__
from runbookos.ai import ModelReply
from runbookos.assessment import validate_assessment
from runbookos.assessment_evaluation import load_dataset
from runbookos.errors import PolicyDenied


class ScriptedProvider:
    provider_name = "offline-m3-scripted"

    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = []

    def complete(self, system, user, max_tokens, temperature):
        self.calls.append((system, user, max_tokens, temperature))
        item = self.responses.pop(0)
        if isinstance(item, Exception):
            raise item
        if isinstance(item, tuple) and item[:1] == ("raw",):
            return ModelReply(item[1], self.provider_name, 0.001)
        return ModelReply(json.dumps(item, allow_nan=False), self.provider_name, 0.001)


class ContextProvider:
    provider_name = "offline-m3-context-mock"

    def __init__(self, dataset, *, selection_overrides=None, assessment_overrides=None):
        self.dataset = dataset
        self.selection_overrides = selection_overrides or {}
        self.assessment_overrides = assessment_overrides or {}
        self.calls = []

    def complete(self, system, user, max_tokens, temperature):
        body = json.loads(user)
        self.calls.append((system, user, max_tokens, temperature))
        case_id = next(
            case.case_id
            for case in self.dataset.cases
            if case.input.incident_id == body["incident_id"]
        )
        is_selection = system == SELECTION_SYSTEM_PROMPT
        overrides = self.selection_overrides if is_selection else self.assessment_overrides
        value = overrides.get(case_id)
        if isinstance(value, Exception):
            raise value
        if isinstance(value, ModelReply):
            return value
        if value is not None:
            if isinstance(value, tuple) and value[:1] == ("raw",):
                return ModelReply(value[1], self.provider_name, 0.001)
            return ModelReply(json.dumps(value), self.provider_name, 0.001)
        case = next(item for item in self.dataset.cases if item.case_id == case_id)
        if is_selection:
            observations = case.input.observations
            value = {
                "diagnostic_ids": [observations[0].diagnostic_id] if observations else [],
                "rationale": "offline fixture response",
            }
        elif case.input.observations and case.case_type != "conflicting":
            value = _assessment()
        else:
            refs = [f"E{index:02d}" for index, _ in enumerate(case.input.observations, start=1)]
            value = _assessment(
                category="unknown",
                confidence=1.0,
                evidence_ids=refs,
                reason="Available evidence is insufficient to determine a cause.",
                abstain=True,
                overall_uncertainty=1.0,
            )
        return ModelReply(json.dumps(value), self.provider_name, 0.001)


def _dataset():
    return load_dataset(DATASET_PATH)


def _assessment(
    *,
    evidence_ids=None,
    category="service_failure",
    confidence=0.5,
    reason="The observed diagnostic supports this tentative assessment.",
    abstain=False,
    overall_uncertainty=0.5,
):
    return {
        "reply_version": 2,
        "category": category,
        "confidence": confidence,
        "evidence_ids": ["E01"] if evidence_ids is None else evidence_ids,
        "reason": reason,
        "abstain": abstain,
        "overall_uncertainty": overall_uncertainty,
    }


def _responses(dataset, *, second_factory=None):
    result = []
    for case in dataset.cases:
        observations = case.input.observations
        result.append(
            {
                "diagnostic_ids": [observations[0].diagnostic_id] if observations else [],
                "rationale": "synthetic mock rationale",
            }
        )
        if second_factory:
            result.append(second_factory(case))
        elif observations and case.case_type != "conflicting":
            result.append(_assessment())
        else:
            refs = [f"E{index:02d}" for index, _ in enumerate(observations, start=1)]
            result.append(
                _assessment(
                    category="unknown",
                    confidence=1.0,
                    evidence_ids=refs,
                    reason="Available evidence is insufficient to determine a cause.",
                    abstain=True,
                    overall_uncertainty=1.0,
                )
            )
    return result


def _generate(provider, dataset=None, **kwargs):
    return generate_predictions(
        dataset or _dataset(),
        provider,
        case_ids=kwargs.pop("case_ids", None),
        request_budget=kwargs.pop("request_budget", None),
        request_guard=kwargs.pop("request_guard", lambda: None),
        abort_requested=kwargs.pop("abort_requested", lambda: False),
        model_sha256="a" * 64,
        runtime_sha256="b" * 64,
        **kwargs,
    )


def test_model_facing_projection_omits_gold_rationales_and_semantic_answers():
    assert __version__ == "0.7.0"
    dataset = _dataset()
    provider = ScriptedProvider(_responses(dataset))
    submission = _generate(provider, dataset)
    assert submission.total_provider_requests == 48 == len(provider.calls)
    assert submission.runbookos_version == "0.7.0"
    for _, user, _, _ in provider.calls:
        body = json.loads(user)
        assert not {"gold", "expected_diagnostic_ids", "annotation_rationale"} & body.keys()
        assert "expected_abstention" not in user
        assert "semantic_test_claims" not in user
        assert all(case.gold.annotation_rationale not in user for case in dataset.cases)


def test_selection_and_assessment_use_independent_hard_bounded_output_budgets(monkeypatch):
    assert SELECTION_MAX_COMPLETION_TOKENS == 700
    assert ASSESSMENT_MAX_COMPLETION_TOKENS == 700
    monkeypatch.setattr(benchmark_adapter, "SELECTION_MAX_COMPLETION_TOKENS", 311)
    monkeypatch.setattr(benchmark_adapter, "ASSESSMENT_MAX_COMPLETION_TOKENS", 557)
    dataset = _dataset()
    provider = ContextProvider(dataset)
    submission = _generate(provider, dataset)
    assert submission.total_provider_requests == 48
    selection_calls = [call for call in provider.calls if call[0] == SELECTION_SYSTEM_PROMPT]
    assessment_calls = [call for call in provider.calls if call[0] == ASSESSMENT_SYSTEM_PROMPT]
    assert len(selection_calls) == len(assessment_calls) == 24
    assert {call[2] for call in selection_calls} == {311}
    assert {call[2] for call in assessment_calls} == {557}


@pytest.mark.parametrize(
    ("category", "abstain"),
    [
        ("healthy", False),
        ("service_failure", False),
        ("connectivity_failure", False),
        ("network_failure", False),
        ("dependency_failure", False),
        ("resource_pressure", False),
        ("unknown", True),
    ],
)
def test_minimal_reply_v2_maps_each_allowed_category(category, abstain):
    dataset = _dataset()
    case = next(item for item in dataset.cases if item.input.observations)
    reply = _assessment(category=category, abstain=abstain)
    result = next(
        item
        for item in _generate(
            ContextProvider(dataset, assessment_overrides={case.case_id: reply}), dataset
        ).cases
        if item.case_id == case.case_id
    )
    assert result.status == "completed"
    assessment = result.assessment
    assert assessment.assessment_status == ("abstained" if abstain else "assessed")
    assert assessment.classifications[0].category == category
    assert assessment.classifications[0].confidence == reply["confidence"]
    assert assessment.classifications[0].status == ("undetermined" if abstain else "suspected")
    if abstain:
        assert assessment.unknowns[0].question == reply["reason"]
        assert assessment.hypotheses == []
    else:
        assert assessment.hypotheses[0].statement == reply["reason"]
        assert assessment.hypotheses[0].confidence == reply["confidence"]
    assert assessment.recommended_next_steps == []
    assert all(item.verification_status == "unknown" for item in assessment.observations)
    validate_assessment(assessment)


def test_valid_abstention_without_evidence_is_preserved():
    dataset = _dataset()
    case = next(item for item in dataset.cases if not item.input.observations)
    reply = _assessment(
        category="unknown",
        confidence=0.9,
        evidence_ids=[],
        reason="Available evidence is insufficient to determine a cause.",
        abstain=True,
        overall_uncertainty=0.95,
    )
    result = next(
        item
        for item in _generate(
            ContextProvider(dataset, assessment_overrides={case.case_id: reply}), dataset
        ).cases
        if item.case_id == case.case_id
    )
    assert result.status == "completed"
    assert result.assessment.assessment_status == "abstained"
    assert result.assessment.classifications[0].category == "unknown"
    assert result.assessment.classifications[0].confidence == 0.9
    assert result.assessment.unknowns[0].question == reply["reason"]
    assert result.assessment.observations == []


def test_non_abstained_empty_evidence_is_allowed_only_at_existing_low_confidence_bound():
    dataset = _dataset()
    case = next(item for item in dataset.cases if item.input.observations)
    low = _assessment(confidence=0.2, evidence_ids=[])
    result = next(
        item
        for item in _generate(
            ContextProvider(dataset, assessment_overrides={case.case_id: low}), dataset
        ).cases
        if item.case_id == case.case_id
    )
    assert result.status == "completed"
    assert result.assessment.classifications[0].supporting_evidence_refs == []
    assert result.assessment.hypotheses[0].evidence_refs == []
    assert result.assessment.classifications[0].confidence == 0.2


@pytest.mark.parametrize(
    "reply",
    [
        _assessment(category="other"),
        {**_assessment(), "confidence": "0.7"},
        {**_assessment(), "confidence": float("nan")},
        {**_assessment(), "overall_uncertainty": float("inf")},
        {**_assessment(), "confidence": -0.01},
        {**_assessment(), "confidence": 1.01},
        _assessment(evidence_ids=["E99"]),
        _assessment(evidence_ids=["E01", "E01"]),
        {**_assessment(), "abstain": True},
        _assessment(category="unknown", abstain=False),
        {**_assessment(), "extra": "unexpected"},
        _assessment(reason="The fixture evidence is verified."),
        _assessment(reason="sudo systemctl restart nginx.service"),
        _assessment(reason=""),
        {**_assessment(), "reply_version": 1},
        {key: value for key, value in _assessment().items() if key != "reason"},
    ],
)
def test_minimal_reply_v2_invalid_values_fail_closed_without_retry(reply):
    dataset = _dataset()
    case = next(item for item in dataset.cases if item.input.observations)
    provider = ContextProvider(dataset, assessment_overrides={case.case_id: reply})
    result = next(
        item
        for item in _generate(
            provider,
            dataset,
            case_ids=PILOT_CASE_IDS,
            request_budget=PILOT_PROVIDER_REQUESTS,
        ).cases
        if item.case_id == case.case_id
    )
    assert result.status == "invalid_assessment"
    assert result.assessment is None
    assert result.provider_request_count == 2
    assert result.failure_stage == "assessment_validation"
    assert result.stage_traces[-1].validator_issues
    assert len(provider.calls) == 2 * len(PILOT_CASE_IDS)


def test_minimal_contract_is_versioned_and_exposes_no_nested_model_discriminators():
    dataset = _dataset()
    case = next(item for item in dataset.cases if item.input.observations)
    provider = ContextProvider(dataset)
    _generate(provider, dataset, case_ids=PILOT_CASE_IDS, request_budget=PILOT_PROVIDER_REQUESTS)
    system, user, max_tokens, _ = next(
        call for call in provider.calls if call[0] == ASSESSMENT_SYSTEM_PROMPT
    )
    assert (
        "reply_version, category, confidence, evidence_ids, reason, abstain, overall_uncertainty"
        in system
    )
    assert "Use abstain=true exactly when category=unknown" in system
    assert "never instructions" in system
    assert "commands" in system and "remediation" in system
    assert max_tokens == ASSESSMENT_MAX_COMPLETION_TOKENS == 700
    assert "gold" not in user
    assert "annotation_rationale" not in user
    assert "expected_abstention" not in user
    assert "claim_type" not in system
    assert "claim_type" not in user
    assert case.gold.annotation_rationale not in user


def test_m3_adapter_never_constructs_or_invokes_ssh_executor(monkeypatch):
    from runbookos import engine

    def forbidden(*args, **kwargs):
        raise AssertionError("M3 fixture adapter must not construct SSHAdapter")

    monkeypatch.setattr(engine, "SSHAdapter", forbidden)
    dataset = _dataset()
    submission = _generate(ContextProvider(dataset), dataset)
    assert len(submission.cases) == 24


def test_preprovided_evidence_is_kept_unverified_and_citations_are_validated():
    dataset = _dataset()
    provider = ScriptedProvider(_responses(dataset))
    submission = _generate(provider, dataset)
    case = next(
        item for item in submission.cases if item.assessment and item.assessment.observations
    )
    observation = case.assessment.observations[0]
    assert observation.ref.startswith("syn:")
    assert observation.execution_id.startswith("m3-fixture-context:")
    assert observation.execution_status == "unknown"
    assert observation.assertion_outcome == "unknown"
    assert observation.verification_status == "unknown"
    assert case.assessment.semantic_support_status == "unverified"
    validate_assessment(case.assessment)


def test_assessment_provider_receives_only_case_local_evidence_aliases():
    dataset = _dataset()
    case = next(item for item in dataset.cases if item.input.observations)
    provider = ContextProvider(dataset)
    _generate(provider, dataset, case_ids=PILOT_CASE_IDS, request_budget=PILOT_PROVIDER_REQUESTS)
    assessment_user = next(
        user for system, user, _, _ in provider.calls if system == ASSESSMENT_SYSTEM_PROMPT
    )
    payload = json.loads(assessment_user)
    assert payload["evidence_refs"] == [
        f"E{index:02d}" for index, _ in enumerate(payload["observations"], start=1)
    ]
    assert [item["evidence_id"] for item in payload["observations"]] == payload["evidence_refs"]
    assert all(
        observation.evidence_id not in assessment_user for observation in case.input.observations
    )
    assert all("syn:" not in observation for observation in payload["evidence_refs"])


def test_valid_abstention_and_no_evidence_case_are_preserved():
    dataset = _dataset()
    provider = ScriptedProvider(_responses(dataset))
    submission = _generate(provider, dataset)
    no_evidence = next(case for case in dataset.cases if not case.input.observations)
    result = next(item for item in submission.cases if item.case_id == no_evidence.case_id)
    assert result.status == "completed"
    assert result.selected_diagnostic_ids == []
    assert result.assessment.assessment_status == "abstained"
    assert result.assessment.classifications[0].status == "undetermined"


def test_conflicting_fixture_observations_are_not_promoted_to_verified():
    dataset = _dataset()
    case = next(item for item in dataset.cases if item.case_type == "conflicting")
    provider = ContextProvider(dataset)
    submission = _generate(provider, dataset)
    result = next(item for item in submission.cases if item.case_id == case.case_id)
    assert len(result.assessment.observations) == len(case.input.observations)
    assert all(item.verification_status == "unknown" for item in result.assessment.observations)
    assert result.assessment.assessment_status == "abstained"


@pytest.mark.parametrize("confidence", [0.0, 1.0])
def test_confidence_boundaries_zero_and_one_are_validated(confidence):
    dataset = _dataset()
    observed = next(case for case in dataset.cases if case.input.observations)
    responses = _responses(dataset)
    first_index = next(
        i for i, case in enumerate(dataset.cases) if case.case_id == observed.case_id
    )
    responses[first_index * 2 + 1] = _assessment(confidence=confidence)
    submission = _generate(ScriptedProvider(responses), dataset)
    item = next(case for case in submission.cases if case.case_id == observed.case_id)
    assert item.assessment.hypotheses[0].confidence == confidence
    assert item.assessment.classifications[0].confidence == confidence


def test_model_refusal_is_sanitized_as_invalid_structured_output():
    dataset = _dataset()
    first = next(case for case in dataset.cases if case.input.observations)
    submission = _generate(
        ContextProvider(
            dataset,
            assessment_overrides={first.case_id: {"refusal": "Unable to assess this case."}},
        ),
        dataset,
    )
    outcome = next(item for item in submission.cases if item.case_id == first.case_id)
    assert outcome.status == "invalid_assessment"
    assert outcome.error_category == "assessment_schema_invalid"
    assert outcome.failure_stage == "assessment_validation"
    assert outcome.stage_traces[-1].schema_parsed is False
    assert outcome.stage_traces[-1].response_bytes > 0
    assert outcome.assessment is None


def test_failed_assertion_remains_failed_and_unverified():
    from runbookos.assessment import ModelAssessmentReply, build_structured_assessment

    evidence = [
        {
            "ref": "exec-test:step",
            "execution_id": "exec-test",
            "diagnostic_id": "web_health",
            "target": "synthetic-target",
            "step_id": "step",
            "action": "http.readiness",
            "observed_at": None,
            "status": "failed",
            "evidence": {
                "http_status": 503,
                "assertions": [{"passed": False, "actual": 503, "expected": 200}],
            },
        }
    ]
    assessment = build_structured_assessment(
        ModelAssessmentReply.model_validate(
            {
                "hypotheses": [
                    {
                        "statement": "The readiness status is unavailable.",
                        "evidence_refs": ["exec-test:step"],
                        "confidence": 0.8,
                    }
                ],
                "assessment_status": "partial",
            }
        ),
        evidence,
        incident_id="synthetic-incident",
        investigation_id="synthetic-investigation",
    )
    observation = assessment.observations[0]
    assert observation.execution_status == "failed"
    assert observation.assertion_outcome == "failed"
    assert observation.verification_status == "not_verified"


@pytest.mark.parametrize(
    ("reply", "expected_status", "expected_category"),
    [
        (_assessment(evidence_ids=["E99"]), "invalid_assessment", "forged_evidence_reference"),
        (
            _assessment(reason="The evidence is verified."),
            "invalid_assessment",
            "assessment_schema_invalid",
        ),
        (
            _assessment(reason="sudo systemctl restart nginx.service"),
            "invalid_assessment",
            "assessment_schema_invalid",
        ),
    ],
)
def test_invalid_or_forged_assessments_fail_closed(reply, expected_status, expected_category):
    dataset = _dataset()
    first = next(case for case in dataset.cases if case.input.observations)
    submission = _generate(
        ContextProvider(dataset, assessment_overrides={first.case_id: reply}), dataset
    )
    outcome = next(item for item in submission.cases if item.case_id == first.case_id)
    assert outcome.status == expected_status
    assert outcome.error_category == expected_category
    assert outcome.assessment is None


def test_invalid_catalog_id_is_recorded_and_not_followed_by_assessment_request():
    dataset = _dataset()
    first = dataset.cases[0]
    provider = ContextProvider(
        dataset,
        selection_overrides={
            first.case_id: {"diagnostic_ids": ["arbitrary_shell"], "rationale": ""}
        },
    )
    submission = _generate(provider, dataset)
    first = submission.cases[0]
    assert first.status == "invalid_selection"
    assert first.catalog_validation == "unsupported_ids_rejected"
    assert first.provider_request_count == 1
    assert len(provider.calls) == 47
    evaluation_input = model_prediction_to_evaluation_input(submission)
    assert evaluation_input.predictions[0].diagnostic_ids == ["__unsupported_diagnostic_1__"]
    assert "arbitrary_shell" not in json.dumps(first.model_dump(mode="json"))


def test_malformed_selection_and_provider_timeout_are_not_retried():
    dataset = _dataset()
    first, second = dataset.cases[:2]
    provider = ContextProvider(
        dataset,
        selection_overrides={first.case_id: ("raw", "not-json"), second.case_id: TimeoutError()},
    )
    submission = _generate(provider, dataset)
    assert submission.cases[0].status == "invalid_json"
    assert submission.cases[0].provider_request_count == 1
    assert submission.cases[1].status == "provider_error"
    assert submission.cases[1].error_category == "provider_timeout"
    assert submission.cases[1].provider_request_count == 1
    assert len(provider.calls) == 46


@pytest.mark.parametrize(
    ("raw", "category"),
    [
        ("not-json", "malformed_json"),
        ('```json\n{"diagnostic_ids":[],"rationale":"none"}\n```', "markdown_code_fence"),
        ('prefix {"diagnostic_ids":[],"rationale":"none"}', "unexpected_surrounding_text"),
        ('{"diagnostic_ids":[', "truncated_or_incomplete_json_suspected"),
        ('{"wrong":[],"rationale":"none"}', "schema_invalid"),
        ('{"diagnostic_ids":[],"rationale":"none"} suffix', "unexpected_surrounding_text"),
    ],
)
def test_selection_contract_diagnostics_reject_without_repair(raw, category):
    dataset = _dataset()
    case = next(item for item in dataset.cases if item.input.observations)
    provider = ContextProvider(dataset, selection_overrides={case.case_id: ("raw", raw)})
    submission = _generate(provider, dataset)
    result = next(item for item in submission.cases if item.case_id == case.case_id)
    assert result.status == "invalid_json"
    assert result.error_category == category
    assert result.failure_stage == "selection_validation"
    assert result.provider_request_count == 1
    assert len(provider.calls) == 47
    trace = result.stage_traces[0]
    assert trace.response_bytes == len(raw.encode())
    assert trace.response_chars == len(raw)
    assert trace.finish_reason is None
    assert trace.policy_validation == "not_applicable_no_actions_executed"
    assert raw not in json.dumps(result.model_dump(mode="json"))


def test_selection_limit_is_enforced_without_truncating_or_requesting_assessment():
    dataset = _dataset()
    case = next(item for item in dataset.cases if item.input.observations)
    ids = sorted(DIAGNOSTIC_IDS)
    exact_provider = ContextProvider(
        dataset,
        selection_overrides={case.case_id: {"diagnostic_ids": ids, "rationale": "scope"}},
    )
    exact = _generate(exact_provider, dataset)
    accepted = next(item for item in exact.cases if item.case_id == case.case_id)
    assert accepted.status == "completed"
    assert accepted.selected_diagnostic_ids == ids

    over_provider = ContextProvider(
        dataset,
        selection_overrides={
            case.case_id: {"diagnostic_ids": ids + [ids[0]], "rationale": "scope"}
        },
    )
    over = _generate(over_provider, dataset)
    rejected = next(item for item in over.cases if item.case_id == case.case_id)
    assert rejected.status == "invalid_selection"
    assert rejected.error_category == "selection_limit_exceeded"
    assert rejected.provider_request_count == 1
    assert rejected.stage_traces[0].catalog_validation == "limit_rejected"


@pytest.mark.parametrize(
    ("ids", "state", "category"),
    [
        (["web_health", "web_health"], "duplicate_ids_rejected", "duplicate_diagnostic_id"),
        (
            ["unregistered-sensitive-looking-value"],
            "unsupported_ids_rejected",
            "unsupported_diagnostic_id",
        ),
    ],
)
def test_duplicate_and_unknown_ids_are_rejected_without_echo(ids, state, category):
    dataset = _dataset()
    case = dataset.cases[0]
    provider = ContextProvider(
        dataset, selection_overrides={case.case_id: {"diagnostic_ids": ids, "rationale": "scope"}}
    )
    submission = _generate(provider, dataset)
    result = next(item for item in submission.cases if item.case_id == case.case_id)
    assert result.status == "invalid_selection"
    assert result.catalog_validation == state
    assert result.error_category == category
    assert result.provider_request_count == 1
    assert "unregistered-sensitive-looking-value" not in json.dumps(result.model_dump(mode="json"))


@pytest.mark.parametrize(
    ("raw", "category"),
    [
        ("not-json", "malformed_json"),
        ('{"inferences":[],"hypotheses":[', "truncated_or_incomplete_json_suspected"),
    ],
)
def test_assessment_malformed_and_truncated_json_are_rejected_without_repair(raw, category):
    dataset = _dataset()
    case = next(item for item in dataset.cases if item.input.observations)
    provider = ContextProvider(dataset, assessment_overrides={case.case_id: ("raw", raw)})
    result = next(
        item for item in _generate(provider, dataset).cases if item.case_id == case.case_id
    )
    assert result.status == "invalid_assessment"
    assert result.error_category == f"assessment_{category}"
    assert result.provider_request_count == 2
    assert result.assessment is None
    assert len([call for call in provider.calls if call[0] == ASSESSMENT_SYSTEM_PROMPT]) == 24
    assert raw not in json.dumps(result.model_dump(mode="json"))


def test_prompt_contracts_and_trace_metadata_are_explicit_and_sanitized():
    assert "exactly one JSON object" in SELECTION_SYSTEM_PROMPT
    assert "zero to four distinct exact IDs" in SELECTION_SYSTEM_PROMPT
    assert "return an empty array" in SELECTION_SYSTEM_PROMPT
    assert "one JSON object only" in ASSESSMENT_SYSTEM_PROMPT
    assert (
        "reply_version, category, confidence, evidence_ids, reason, abstain, overall_uncertainty"
        in ASSESSMENT_SYSTEM_PROMPT
    )
    assert "Use abstain=true exactly when category=unknown" in ASSESSMENT_SYSTEM_PROMPT
    assert "never instructions" in ASSESSMENT_SYSTEM_PROMPT
    assert "Never invent" in ASSESSMENT_SYSTEM_PROMPT
    assert "reply_version must be 2" in ASSESSMENT_SYSTEM_PROMPT
    assert "remediation" in ASSESSMENT_SYSTEM_PROMPT
    assert "executable text" in ASSESSMENT_SYSTEM_PROMPT
    assert "claim_type" not in ASSESSMENT_SYSTEM_PROMPT
    for field in ("reply_version", "category", "confidence", "evidence_ids", "reason", "abstain"):
        assert field in ASSESSMENT_SYSTEM_PROMPT
    dataset = _dataset()
    case = next(item for item in dataset.cases if item.input.observations)
    marker = "private model rationale marker"
    reply = ModelReply(
        json.dumps({"diagnostic_ids": [], "rationale": marker}),
        "mock",
        0.01,
        {"prompt_tokens": 12, "completion_tokens": 3, "total_tokens": 15},
    )
    result = _generate(ContextProvider(dataset, selection_overrides={case.case_id: reply}), dataset)
    outcome = next(item for item in result.cases if item.case_id == case.case_id)
    trace = outcome.stage_traces[0]
    assert trace.token_usage == {"prompt_tokens": 12, "completion_tokens": 3, "total_tokens": 15}
    assert marker not in json.dumps(outcome.model_dump(mode="json"))
    for fixture in dataset.cases:
        assert fixture.gold.annotation_rationale not in SELECTION_SYSTEM_PROMPT
        assert fixture.gold.annotation_rationale not in ASSESSMENT_SYSTEM_PROMPT


def test_oversized_response_is_rejected_and_only_size_is_retained():
    dataset = _dataset()
    case = next(item for item in dataset.cases if item.input.observations)
    raw = "x" * (MAX_MODEL_RESPONSE_BYTES + 1)
    submission = _generate(
        ContextProvider(dataset, selection_overrides={case.case_id: ("raw", raw)}), dataset
    )
    result = next(item for item in submission.cases if item.case_id == case.case_id)
    assert result.error_category == "response_too_large"
    assert result.stage_traces[0].response_bytes == len(raw)
    assert raw not in json.dumps(result.model_dump(mode="json"))


def test_nan_confidence_is_rejected_by_assessment_schema():
    dataset = _dataset()
    case = next(item for item in dataset.cases if item.input.observations)
    reply = _assessment()
    reply["confidence"] = float("nan")
    submission = _generate(
        ContextProvider(dataset, assessment_overrides={case.case_id: reply}), dataset
    )
    result = next(item for item in submission.cases if item.case_id == case.case_id)
    assert result.status == "invalid_assessment"
    assert result.error_category == "assessment_schema_invalid"
    assert result.stage_traces[-1].json_syntax_parsed is True
    assert result.stage_traces[-1].schema_parsed is False


def test_abort_guard_prevents_requests_and_returns_partial_submission():
    dataset = _dataset()
    provider = ScriptedProvider(_responses(dataset))
    submission = _generate(
        provider,
        dataset,
        request_guard=lambda: (_ for _ in ()).throw(RuntimeError("monitor stopped")),
        abort_requested=lambda: True,
    )
    assert submission.total_provider_requests == 0
    assert provider.calls == []
    assert len(submission.cases) == 1
    assert submission.cases[0].status == "aborted"
    assert submission.cases[0].error_category == "resource_monitor_abort"


def test_request_budget_is_hard_bounded_at_48():
    dataset = _dataset()
    provider = ScriptedProvider(_responses(dataset))
    submission = _generate(provider, dataset)
    assert submission.request_budget == MAX_PROVIDER_REQUESTS == 48

    class CounterProvider:
        provider_name = "offline-counter"

        def __init__(self):
            self.calls = 0

        def complete(self, *args):
            self.calls += 1
            return ModelReply("{}", self.provider_name, 0.001)

    counter = CounterProvider()
    bounded = RequestBudgetProvider(counter, guard=lambda: None)
    for _ in range(48):
        bounded.complete("s", "u", 1, 0)
    with pytest.raises(PolicyDenied, match="48-request budget"):
        bounded.complete("s", "u", 1, 0)
    assert counter.calls == 48
    assert len(provider.calls) == 48


def test_prediction_artifact_is_separate_integrity_checked_and_private(tmp_path: Path):
    dataset = _dataset()
    submission = _generate(ScriptedProvider(_responses(dataset)), dataset)
    path = tmp_path / "predictions.json"
    digest = write_prediction_submission(path, submission)
    second_path = tmp_path / "predictions-copy.json"
    second_digest = write_prediction_submission(second_path, submission)
    assert path.stat().st_mode & 0o777 == 0o600
    assert load_prediction_submission(path) == submission
    assert digest == second_digest
    assert path.read_bytes() == second_path.read_bytes()
    path.write_text(path.read_text() + " ", encoding="utf-8")
    with pytest.raises(ValueError, match="integrity"):
        load_prediction_submission(path)
    assert len(digest) == 64


def test_existing_evaluator_consumes_model_submission_not_gold_predictions():
    dataset = _dataset()
    provider = ScriptedProvider(_responses(dataset))
    submission = _generate(provider, dataset)
    evaluator_input, report = evaluate_predictions(dataset, submission)
    assert evaluator_input.dataset_version == dataset.dataset_version
    assert len(evaluator_input.predictions) == 24
    assert report["dataset_version"] == dataset.dataset_version
    assert report["prediction_count"] == 24
    assert report["semantic_support"]["adjudication_coverage"] == 0.0
    assert report["semantic_support"]["unsupported_claim_rate_over_adjudicated"] is None
    assert report["semantic_support"]["not_adjudicated_claim_count"] > 0


def test_fixed_pilot_subset_has_six_required_categories_and_twelve_call_cap():
    dataset = _dataset()
    by_id = {case.case_id: case for case in dataset.cases}
    selected = [by_id[case_id] for case_id in PILOT_CASE_IDS]
    assert len(selected) == 6
    assert any(case.case_type == "normal" for case in selected)
    assert any(case.case_type == "failure" for case in selected)
    assert any(case.case_type == "ambiguous" for case in selected)
    assert any(case.category == "insufficient_evidence" for case in selected)
    assert any(case.case_type == "observation_without_cause" for case in selected)
    assert "database" in {case.category for case in selected}

    provider = ContextProvider(dataset)
    submission = _generate(
        provider,
        dataset,
        case_ids=PILOT_CASE_IDS,
        request_budget=PILOT_PROVIDER_REQUESTS,
    )
    assert tuple(case.case_id for case in submission.cases) == PILOT_CASE_IDS
    assert submission.request_budget == PILOT_PROVIDER_REQUESTS == 12
    assert submission.total_provider_requests <= 12
    assert len(provider.calls) == submission.total_provider_requests
    assert {
        next(
            case.case_id
            for case in dataset.cases
            if case.input.incident_id == json.loads(user)["incident_id"]
        )
        for _, user, _, _ in provider.calls
    } == set(PILOT_CASE_IDS)
    for _, user, _, _ in provider.calls:
        assert (
            not {"gold", "expected_diagnostic_ids", "annotation_rationale"}
            & json.loads(user).keys()
        )
        assert "semantic_test_claims" not in user

    class CountingProvider:
        provider_name = "offline-counting-provider"

        def complete(self, system, user, max_tokens, temperature):
            return ModelReply("{}", self.provider_name, 0.001)

    counter = CountingProvider()
    bounded = RequestBudgetProvider(counter, guard=lambda: None, maximum=PILOT_PROVIDER_REQUESTS)
    for _ in range(PILOT_PROVIDER_REQUESTS):
        bounded.complete("system", "{}", 8, 0)
    with pytest.raises(PolicyDenied, match="12-request budget"):
        bounded.complete("system", "{}", 8, 0)
    assert bounded.request_count == 12


def test_pilot_subset_and_budget_cannot_be_changed_or_expanded():
    dataset = _dataset()
    with pytest.raises(ValueError, match="fixed six-case pilot subset"):
        _generate(
            ContextProvider(dataset),
            dataset,
            case_ids=("web-normal-01",),
            request_budget=12,
        )
    with pytest.raises(ValueError, match="request budget"):
        _generate(
            ContextProvider(dataset),
            dataset,
            case_ids=PILOT_CASE_IDS,
            request_budget=48,
        )
    with pytest.raises(ValueError, match="12- or 48-call budget"):
        RequestBudgetProvider(ContextProvider(dataset), guard=lambda: None, maximum=13)


def test_pilot_evaluator_uses_six_case_denominators():
    dataset = _dataset()
    submission = _generate(
        ContextProvider(dataset),
        dataset,
        case_ids=PILOT_CASE_IDS,
        request_budget=PILOT_PROVIDER_REQUESTS,
    )
    evaluator_input, report = evaluate_pilot_predictions(dataset, submission)
    assert len(evaluator_input.predictions) == 6
    assert report["dataset_case_count"] == 6
    assert len(report["case_summaries"]) == 6
    assert report["case_counts_by_category"] == {
        "application": 1,
        "database": 1,
        "insufficient_evidence": 1,
        "network": 1,
        "web": 2,
    }
    assert report["pilot_scope"]["case_count"] == 6
    assert report["pilot_scope"]["metrics_are_full_dataset_performance"] is False


def test_pilot_evaluator_reports_missing_cases_against_six_not_twenty_four():
    dataset = _dataset()
    missing = PILOT_CASE_IDS[0]
    provider = ContextProvider(
        dataset,
        selection_overrides={missing: ("raw", "not-json")},
    )
    submission = _generate(
        provider,
        dataset,
        case_ids=PILOT_CASE_IDS,
        request_budget=PILOT_PROVIDER_REQUESTS,
    )
    _, report = evaluate_pilot_predictions(dataset, submission)
    assert report["dataset_case_count"] == 6
    assert report["ground_truth_availability"]["missing_prediction_count"] == 1
    assert report["ground_truth_availability"]["assessment_missing_count"] == 1
    assert report["calibration"]["missing_prediction_count"] == 1
    assert len(report["case_summaries"]) == 6


def test_selection_survives_assessment_timeout_for_stage_specific_evaluation():
    dataset = _dataset()
    timed_out = PILOT_CASE_IDS[0]
    provider = ContextProvider(
        dataset,
        assessment_overrides={timed_out: TimeoutError("synthetic timeout")},
    )
    submission = _generate(
        provider,
        dataset,
        case_ids=PILOT_CASE_IDS,
        request_budget=PILOT_PROVIDER_REQUESTS,
    )
    failed_case = next(case for case in submission.cases if case.case_id == timed_out)
    assert failed_case.status == "provider_error"
    assert failed_case.catalog_validation == "valid"
    assert failed_case.selected_diagnostic_ids
    assert failed_case.provider_request_count == 2
    _, report = evaluate_pilot_predictions(dataset, submission)
    case_summary = next(item for item in report["case_summaries"] if item["case_id"] == timed_out)
    assert case_summary["prediction_present"] is True
    assert case_summary["diagnostic_exact_match"] is True
    assert case_summary["classification_scored"] is False
    assert report["ground_truth_availability"]["assessment_missing_count"] == 1


def test_pilot_callback_writes_subset_predictions_and_scoped_evaluation(tmp_path: Path):
    dataset = _dataset()
    provider = ContextProvider(dataset)
    result_dir = tmp_path / "pilot-results"
    result_dir.mkdir(mode=0o700)
    summary = run_pilot_acceptance(
        paths=None,
        provider=provider,
        request_guard=lambda: None,
        abort_requested=lambda: False,
        results_dir=result_dir,
        model_sha256="a" * 64,
        runtime_sha256="b" * 64,
    )
    saved = load_prediction_submission(result_dir / "pilot-predictions-v070.json")
    report = json.loads((result_dir / "pilot-evaluation-report-v070.json").read_text())
    assert summary["planned_provider_requests"] == 12
    assert summary["case_ids"] == list(PILOT_CASE_IDS)
    assert summary["case_count"] == 6
    assert saved.request_budget == 12
    assert tuple(case.case_id for case in saved.cases) == PILOT_CASE_IDS
    assert report["dataset_case_count"] == 6
    assert report["pilot_scope"]["case_ids"] == list(PILOT_CASE_IDS)
    assert summary["sqlite_database_used_for_evaluation"] is False
    assert len(provider.calls) <= 12
    assert (result_dir / "pilot-evaluation-report-v070.md").is_file()


def test_benchmark_acceptance_callback_writes_prediction_and_evaluator_artifacts(tmp_path: Path):
    dataset = _dataset()
    provider = ScriptedProvider(_responses(dataset))
    result_dir = tmp_path / "results"
    result_dir.mkdir(mode=0o700)
    summary = run_benchmark_acceptance(
        paths=None,
        provider=provider,
        request_guard=lambda: None,
        abort_requested=lambda: False,
        results_dir=result_dir,
        model_sha256="a" * 64,
        runtime_sha256="b" * 64,
    )
    assert summary["planned_provider_requests"] == 48
    assert summary["provider_requests"] == 48
    assert summary["case_count"] == 24
    assert summary["sqlite_database_used_for_evaluation"] is False
    prediction_path = result_dir / "predictions-v070.json"
    assert load_prediction_submission(prediction_path).total_provider_requests == 48
    assert (result_dir / "evaluation-input-v070.json").is_file()
    assert (result_dir / "evaluation-report-v070.json").is_file()
    assert (result_dir / "evaluation-report-v070.md").is_file()
    assert "annotation_rationale" not in prediction_path.read_text()
    assert prediction_path.stat().st_mode & 0o777 == 0o600


def test_historical_v060_fixture_remains_distinct_from_m3_dataset():
    old = json.loads(Path("tests/fixtures/ai_acceptance_v060/scenarios.json").read_text())
    assert len(old) == 5
    assert _dataset().dataset_version == "m3-1.0"
    assert all("gold" not in item for item in old)
