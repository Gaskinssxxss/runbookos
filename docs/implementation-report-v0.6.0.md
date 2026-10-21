# RunbookOS v0.6.0 implementation report

## Scope

v0.6.0 links an operator-selected remediation plan to an existing incident and presents that context through CLI review and the read-only dashboard. It reuses the v0.5.0 planner, execution engine, approval records, execution history, and audit chain. No second executor, approval store, or incident database was introduced.

## Implementation

- Additive SQLite schema v4 stores one immutable incident-to-plan association with plan hash, target, registered action ID, actor, and timestamp. Existing rows and audit history remain intact.
- `runbookos incidents associate-plan INCIDENT_ID PLAN_ID` validates the current deterministic plan preview, audit binding, incident/plan existence, registered mutable action, policy allowance, required assertions, and exact target equality. Association is idempotent for the same identity, rejects conflicting associations, and does not issue approval or execute.
- `runbookos incidents remediation-review INCIDENT_ID` displays incident context, linked investigation references, evidence references, associated plans, current preview validity, approvals, and prior outcomes. It records an operator review audit event.
- Incident show and the authenticated dashboard display linked plan metadata, preflight/postflight summaries, approval state, execution outcomes, and an `UNKNOWN` warning. They do not expose raw evidence payloads or add execution/approval routes.
- Successful remediation does not transition an incident. Operators continue to use the existing lifecycle transition and evidence-status requirements.

## Security and compatibility

Plan association validates the persisted plan document against its stored and caller-supplied hash and verifies the immutable `plan.created` audit event. It requires one registered, policy-allowed mutable step on the incident target, with assertion-bearing read-only preflight and postflight. Stale plans are rejected by the existing preview fingerprint checks before CLI association. The execution and approval semantics are unchanged.

The implementation fingerprint includes the RunbookOS version, so v0.5.x plans and approvals become stale after the upgrade. Operators must re-plan and re-approve; historical records remain readable.

The v0.5.0 disposable remediation approval manifest remains `NOT_AUTHORIZED`. No live SSH, mutation, AI inference, VM, hypervisor, homelab, or operational database activity was performed. The pre-existing local edit to that manifest is preserved and is not part of the v0.6.0 implementation change set.

## Verification

Verification on this checkout:

- Full pytest: **144 passed, 11 skipped**. Skips are opt-in live AI/SSH/probe/tunnel tests.
- Coverage: **80.62%**, above the repository's 70% gate.
- Ruff lint: passed. Ruff format check: passed for `src` and `tests`.
- `git diff --check`: passed.
- CLI version and both new command help paths: passed; version is `0.6.0`.
- All seven example runbooks validated, including the reserved disposable remediation example (validation only; no execution).
- PEP 517 wheel and sdist builds: passed using isolated pinned build requirements.
- Fresh wheel and sdist installs: metadata, imported version, and CLI all report `0.6.0`.
- Archive checks confirmed the v0.6.0 docs and association tests are included and no SQLite or private-key files are included.
- Final artifact SHA-256 values are reported with the delivery result; they are not embedded in the source archive to avoid self-referential sdist hashes.

Acceptance is limited to offline tests, packaging, CLI smoke checks, temporary SQLite, and fake executors. No live remediation acceptance is claimed.

## Changed-file manifest

The implementation change set consists of:

- `.github/workflows/validate.yml`
- `MANIFEST.in`
- `README.md`
- `pyproject.toml`
- `src/runbookos/__init__.py`
- `src/runbookos/cli.py`
- `src/runbookos/dashboard.py`
- `src/runbookos/engine.py`
- `src/runbookos/incidents.py`
- `src/runbookos/store.py`
- `tests/test_ai.py`
- `tests/test_cli_integration.py`
- `tests/test_dashboard.py`
- `tests/test_incident_remediation.py`
- `tests/test_incidents.py`
- `docs/implementation-report-v0.6.0.md`
- `docs/workflow-security-v0.6.0.md`

Historical untracked staging evidence and the pre-existing disposable approval manifest edit are intentionally excluded.
