# RunbookOS 0.7.0 readiness review

## Decision

**Overall: `RUNBOOKOS_GITHUB_READY_PRODUCTION_BLOCKED`.** The offline release candidate, operator demo, package builds, and regression checks passed. Real-server acceptance, production deployment and recovery validation, and independently measured diagnostic accuracy remain unverified. This is not a production-readiness claim.

## Repository state

- Branch: `feat/v0.7.0-evidence-aware-assessment`
- HEAD: `d68197c3ac37336e1b9bfa8d66059e5eb8ecd001`
- No files staged; no commit or publication performed.
- Package version: `0.7.0` (`pyproject.toml`, imported package, and CLI agree).
- Working-tree files are listed below. The local disposable-remediation approval manifest remains `NOT_AUTHORIZED` and is excluded from the release candidate.

## Implemented and verified

- The production incident investigator and the M3 test adapter now use one Minimal Semantic Reply v2 contract. The model supplies category, confidence, evidence aliases, reason, abstention, and uncertainty. Python supplies assessment identity, observations, assertion/verification provenance, and stable evidence references. The unchanged `validate_assessment()` remains authoritative.
- Model classifications are stored as `suspected`; abstention is explicit and maps to an undetermined `unknown` classification. A cited reference does not establish semantic support. Evidence is never promoted by the model.
- Invalid/provider-failed attempts persist a sanitized failed investigation and audit result hash without raw prompts, responses, or exception messages. The incident CLI links the attempt and presents an `assessment_failed` projection instead of a diagnosis.
- Diagnostic selection continues through the registered catalog, deterministic planner, default-deny policy, and existing bounded SSH executor. Assessment output has no approval or dispatch interface.
- The existing synthetic operator demo ran end to end: CLI review displayed a synthetic, unexecuted observation with unknown verification and a suspected classification; the authenticated loopback dashboard returned HTTP 200 and displayed the same synthetic provenance. The dashboard was stopped and its temporary SQLite and credential files were removed.
- SQLite schema remains v4. No operational database was accessed.

## Verification evidence

- Full worktree offline regression: **319 passed, 11 skipped**. The skips are opt-in live AI, SSH, probe, and tunnel tests; they are not passing live evidence. The four local Qwen entrypoint checks are kept in an excluded local-only test file.
- Clean candidate archive (committed HEAD plus the proposed changes): **293 passed**, **82.32%** coverage; project CI threshold is 70%. It includes no local-only Qwen runner or its entrypoint tests.
- Ruff lint and format: PASS (`ruff check src tests scripts`; `ruff format --check src tests scripts`).
- `git diff --check`: PASS.
- CLI version/help and seven example runbooks: PASS.
- Wheel and sdist: built with the declared isolated build dependencies. Fresh venv installs of both artifacts reported 0.7.0; CLI version smoke checks passed. Wheel contains the assessment/evaluator modules; sdist includes the offline demo and changelog and excludes local Qwen runners and database artifacts.
- A first non-isolated packaging attempt failed because the current venv lacks setuptools; the declared isolated PEP 517 build then passed. No project source change was needed to address that environment limitation.
- Dependency audit: `pip-audit 2.10.1` found five advisories across the locked pytest/setuptools versions. The lock now pins pytest 9.0.3 and setuptools 84.1.0, and the project test extra accepts pytest 9.x. A second audit of the updated CI lock reported no known vulnerabilities.
- Secret scan: `detect-secrets 1.5.0` ran in a temporary venv against the exact 25-file changed candidate using offline scanning (`--no-verify`). Raw findings: **4**; reviewed findings: **4**; unresolved credential findings: **0**. The findings are (1) an environment-variable-name field, (2–3) synthetic `api_key` fixture values, and (4) a synthetic demo password fixture. No value was printed. Candidate file SHA-256 fingerprints were unchanged across the scan. `gitleaks` is not installed.

## Production-readiness gates

| Gate | Verdict | Evidence / limit |
|---|---|---|
| G1 Reproducible code and dependencies | PASS | Version 0.7.0 wheel/sdist built and freshly installed. |
| G2 Offline regression and integration | PASS | 319 passed, 11 live tests skipped; 82.32% coverage. |
| G3 Security and authorization boundaries | PASS (offline) | Default-deny, fake executor, approval, audit, input validation, and dashboard-auth regressions pass. No external security assessment. |
| G4 Qwen assessment integrated into incident workflow | PASS (offline) | Production investigator uses shared v2 adapter; failure handling is persisted and audited. No new live inference. |
| G5 CLI/dashboard review | PASS (synthetic) | CLI projection and authenticated loopback dashboard show linked synthetic assessment and provenance. |
| G6 Read-only remote diagnostics | PASS (implementation/mock) | Registered read-only actions, pinned-host SSH adapter, bounded execution and policy gates exist; no target was contacted in this task. |
| G7 Authorized disposable-server acceptance | NOT_VERIFIED | No current target-specific lab authorization and credentials were established. No live server access occurred. |
| G8 Remediation authorization and verification | PASS (offline only) | Exact plan-bound approval, one-time expiry/replay protections, bounded dispatch and postflight are covered by tests; no real remediation was executed. |
| G9 Deployment, recovery, monitoring and rollback | NOT_VERIFIED | Operational deployment and recovery were not exercised. Existing documentation does not establish a tested production operations envelope. |
| G10 GitHub publication hygiene and secret scan | PASS (candidate scope) | detect-secrets scanned exact changed files; pip-audit found no issues in the updated CI lock. |

## Proposed release candidate manifest

These 25 changed paths are the proposed product/test/documentation candidate. Nothing is staged.

```text
CHANGELOG.md
MANIFEST.in
pyproject.toml
README.md
requirements-ci-py312.lock
docs/ai-investigation.md
docs/operations.md
docs/operator-demo-v0.7.0.md
docs/production-readiness-review.md
docs/security.md
scripts/operator-demo-v070.py
src/runbookos/ai.py
src/runbookos/assessment.py
src/runbookos/assessment_evaluation.py
src/runbookos/cli.py
src/runbookos/dashboard.py
tests/ai_acceptance_harness_v060.py
tests/ai_m3_benchmark_v070.py
tests/test_ai.py
tests/test_ai_acceptance_harness_v060.py
tests/test_ai_m3_benchmark_v070.py
tests/test_assessment_evaluation.py
tests/test_assessment_review.py
tests/test_m5_integrated_release.py
tests/test_operator_demo_v070.py
```

Excluded worktree material is classified as follows and remains untouched:

- **Unrelated user change:** modified `docs/disposable-remediation-approval-v0.5.0.yml` (`NOT_AUTHORIZED`).
- **Historical staging/acceptance records:** `docs/dashboard-staging-acceptance-report-v0.4.0.md`; `docs/ai-acceptance-approval-v0.6.0.yml`; `docs/ai-acceptance-preparation-v0.6.0.md`; `docs/ai-local-inference-acceptance-v0.6.0.md`; `docs/ai-local-inference-addendum-v0.6.0.md`; `docs/ai-local-inference-rerun-results-v0.6.0.md`; `docs/ai-local-inference-rerun-v0.6.0.md`; `docs/ai-local-rerun-readiness-v0.6.0.md`.
- **Historical Qwen pilot/benchmark artifacts:** `docs/qwen-minimal-assessment-contract.md`; `docs/qwen-minimal-assessment-live-pilot.md`; `docs/qwen-minimal-assessment-m3-evaluation.md`; `docs/v0.7.0-qwen-benchmark-readiness.md`; `docs/v0.7.0-qwen-m3-assessment-contract-compliance.md`; `docs/v0.7.0-qwen-m3-assessment-output-optimization.md`; `docs/v0.7.0-qwen-m3-benchmark-results.json`; `docs/v0.7.0-qwen-m3-benchmark-results.md`; `docs/v0.7.0-qwen-m3-output-contract-analysis.md`; `docs/v0.7.0-qwen-m3-output-pilot.md`; `docs/v0.7.0-qwen-m3-output-pilot-2.md`; `docs/v0.7.0-qwen-m3-output-pilot-3.md`.
- **Local-only inference orchestration and tests:** `scripts/ai-local-acceptance-v060.py`; `scripts/qwen-m3-benchmark-v070.py`; `tests/test_ai_local_orchestrator_v060.py`; `tests/test_qwen_m3_local_entrypoint.py`. The last is an untracked local-only guard-test file created to keep the runner checks out of the portable evaluator suite.
- **Ignored local state/artifacts:** `.runbookos-staging-v032/`, `config/*homelab.example.yml`, `reports/`, `dist/`, pre-existing temporary databases/logs, model/API-key material, and private tunnel files. The validation refreshed ignored `.coverage`, `build/`, and `src/runbookos.egg-info/`; these directories were retained.

These exclusions are not part of the proposed GitHub candidate. Preserve them in the working tree; do not add them to a release commit without separate review.

## Remaining blockers and next operator actions

1. Before any publication, re-run secret scanning on the exact staged Git index and review any changed finding.
2. Separately authorize one disposable Linux lab target, its identity/host-key pin, least-privilege account, exact read-only diagnostics, network scope, and cleanup. Then perform the incident-to-assessment flow on that target. Keep remediation disabled; any live mutation requires separate approval.
3. Define and validate deployment, backup/restore, monitoring, incident recovery, and rollback procedures in an authorized environment.

The previous synthetic Qwen benchmark results (21/24 accepted; 11/13 answered classifications correct) remain exploratory. They do not establish independent semantic support, real root-cause accuracy, live-server readiness, or production safety.

For an operator who wants to repeat only the offline demonstration:

```sh
.venv/bin/python scripts/operator-demo-v070.py
```

For the next remote acceptance, first record explicit authorization for one disposable target, verified host identity, and exact read-only diagnostic scope. No live target command is supplied here because no target-specific authorization was established.

No commit, push, tag, deployment, live Qwen request, SSH, tunnel, managed-VM access, or remediation was performed in this review.
