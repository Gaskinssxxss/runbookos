# RunbookOS production execution result

## Verdict

**`RUNBOOKOS_PARTIALLY_VALIDATED`**. The existing homelab is operational for the
four scoped read-only service-state checks documented below. Offline integration,
assessment, audit, packaging, and recovery tests pass. RunbookOS 0.7.0 is not
deployed on `ops-01`; no real diagnostic evidence has been assessed by Qwen, and
no live incident-to-assessment workflow or remediation was executed.

## Repository and preserved work

- Branch: `feat/v0.7.0-evidence-aware-assessment`
- HEAD: `d68197c3ac37336e1b9bfa8d66059e5eb8ecd001`
- The index remains empty. No commit, push, tag, or deployment occurred.
- The worktree was already dirty. Prior product, test, benchmark, approval,
  historical-report, and local-runner files were preserved. In particular,
  `docs/disposable-remediation-approval-v0.5.0.yml` remains untouched by this
  execution and remains `NOT_AUTHORIZED`.

### Files changed by this execution

- `src/runbookos/actions.py`
- `src/runbookos/remote.py`
- `tests/test_probes.py`
- `tests/test_incidents.py`
- `docs/diagnostic-actions-v0.2.3.md`
- `docs/operations.md`
- `MANIFEST.in`
- `docs/runbookos-production-execution-result.md` (this report)

The source changes add two default-deny read-only diagnostics: bounded,
redacted `systemd.journal_tail` and metadata-only `network.resolver_config`.
Tests enforce argument validation, output and timeout bounds, common-secret
redaction, and policy opt-in. A disposable schema-v4 backup/restore regression
now checks incident/investigation linkage, assessment preservation, SQLite
integrity, foreign keys, and the audit chain. Operations documentation was
corrected to schema v4 and documents backup limitations.

The source distribution now excludes three approval records. The old private-IP
documentation examples were changed to RFC 5737 TEST-NET placeholders.
Homelab
operational reports and local Qwen runner files are not included by the
manifest. No approval record was edited by this packaging change.

### Pre-existing dirty state retained

Other modified files retained from prior work: `README.md`,
`docs/ai-investigation.md`, `docs/disposable-remediation-approval-v0.5.0.yml`,
`docs/security.md`, `pyproject.toml`, `requirements-ci-py312.lock`,
`src/runbookos/ai.py`, `src/runbookos/assessment.py`,
`src/runbookos/assessment_evaluation.py`, `src/runbookos/cli.py`,
`src/runbookos/dashboard.py`, `tests/ai_acceptance_harness_v060.py`,
`tests/test_ai.py`, `tests/test_ai_acceptance_harness_v060.py`,
`tests/test_assessment_evaluation.py`, `tests/test_assessment_review.py`,
`tests/test_m5_integrated_release.py`.

Pre-existing untracked local/history files retained: `CHANGELOG.md`,
`docs/ai-acceptance-approval-v0.6.0.yml`, `docs/ai-acceptance-preparation-v0.6.0.md`,
`docs/ai-local-inference-acceptance-v0.6.0.md`,
`docs/ai-local-inference-addendum-v0.6.0.md`,
`docs/ai-local-inference-rerun-results-v0.6.0.md`,
`docs/ai-local-inference-rerun-v0.6.0.md`,
`docs/ai-local-rerun-readiness-v0.6.0.md`,
`docs/dashboard-staging-acceptance-report-v0.4.0.md`,
`docs/homelab-operational-acceptance.md`, `docs/operator-demo-v0.7.0.md`,
`docs/production-readiness-review.md`, `docs/qwen-minimal-assessment-contract.md`,
`docs/qwen-minimal-assessment-live-pilot.md`,
`docs/qwen-minimal-assessment-m3-evaluation.md`,
`docs/runbookos-final-acceptance.md`, `docs/v0.7.0-qwen-benchmark-readiness.md`,
`docs/v0.7.0-qwen-m3-assessment-contract-compliance.md`,
`docs/v0.7.0-qwen-m3-assessment-output-optimization.md`,
`docs/v0.7.0-qwen-m3-benchmark-results.json`,
`docs/v0.7.0-qwen-m3-benchmark-results.md`,
`docs/v0.7.0-qwen-m3-output-contract-analysis.md`,
`docs/v0.7.0-qwen-m3-output-pilot-2.md`,
`docs/v0.7.0-qwen-m3-output-pilot-3.md`,
`docs/v0.7.0-qwen-m3-output-pilot.md`,
`scripts/ai-local-acceptance-v060.py`, `scripts/operator-demo-v070.py`,
`scripts/qwen-m3-benchmark-v070.py`, `tests/ai_m3_benchmark_v070.py`,
`tests/test_ai_local_orchestrator_v060.py`,
`tests/test_ai_m3_benchmark_v070.py`,
`tests/test_operator_demo_v070.py`, and
`tests/test_qwen_m3_local_entrypoint.py`.

## Homelab verification

Current observed topology remains the five existing system-libvirt guests:
`ops-01`, `svc-web-01`, `svc-app-01`, `db-01`, and `net-01`; all were reported
running in the preceding read-only inventory. `net-01` is the routed gateway
for service/database networks. It was not modified. An unrelated VM was not
touched. The detailed locally retained evidence is in
`docs/homelab-operational-acceptance.md`; that environment-specific report is
not part of the package manifest.

RunbookOS on `ops-01` remains isolated v0.6.0. The development source is v0.7.0.
The controller's current default-deny policy authorized only
`systemd.is_active` for each managed role. Through the installed RunbookOS CLI,
four read-only checks succeeded: Nginx unit active, sample application unit
active, PostgreSQL unit active, and nftables unit active. These results establish
unit state only; they do not establish HTTP, application, PostgreSQL-protocol,
DNS, or end-user health. Audit verification passed at 32 events; SQLite
integrity was `ok` with no foreign-key violations. No incident was fabricated.

The new journal and resolver actions are registered but remain policy-denied
unless an operator explicitly enables them for a target. No new guest action
was run. Journal data can contain sensitive text; redaction covers common
patterns only and is not exhaustive.

## AI and incident workflow

The v0.7.0 source has the Minimal Semantic Reply v2 provider path, evidence-alias
validation, deterministic conversion to the unchanged assessment validator,
sanitized failure persistence, and read-only CLI/dashboard projections. The
prior offline operator demo used explicitly synthetic evidence and was not a
real diagnosis.

No Qwen process or inference was started in this execution. The installed
controller is still v0.6.0, and no v0.7.0 deployment artifact was installed on
the guest. The ops-to-host inference route/listener arrangement was not
revalidated or activated. Therefore real evidence → Qwen → persisted assessment
→ operator review is **NOT_VERIFIED**. The historical 21/24 synthetic M3 result
is not production accuracy or semantic-support evidence.

No service, database, firewall, route, VM, or credential was changed. No
remediation was proposed for execution or performed. AI remains advisory.

## Verification performed

- `.venv/bin/pytest -q`: **324 passed, 11 skipped**. Skips are opt-in live SSH,
  probe, AI, and tunnel tests.
- `.venv/bin/ruff check .`: passed.
- Ruff formatting on the four changed Python files: passed.
- Repository-wide `ruff format --check .`: reports one formatting issue in the
  pre-existing untracked `docs/dashboard-staging-acceptance-v0.4.0.md` embedded
  Python example. That historical report was not rewritten.
- `git diff --check`: passed.
- Wheel and sdist build: passed with the locked setuptools/wheel versions.
- Fresh isolated wheel and sdist installs: passed; imports, `runbookos version`,
  and CLI help worked and reported 0.7.0.
- Package inspection confirmed the three approval manifests, local homelab
  reports, and local Qwen-only runner/tests are absent from wheel/sdist.
- `pip-audit` against `requirements-ci-py312.lock`: no known vulnerabilities.
- `detect-secrets` 1.5.0 against the built sdist: five raw findings, reviewed
  as runtime-generated auth material or synthetic test/config values; zero
  unresolved real-secret findings. No suppression was added. The findings are
  in `scripts/staging-v032.py`, `tests/ai_acceptance_harness_v060.py`,
  `tests/test_assessment_review.py`, `tests/test_m5_integrated_release.py`, and
  `tests/test_operator_demo_v070.py`.
- SQLite backup/restore and audit regression passed on disposable test state.
- The existing offline synthetic operator demo and integration tests remain
  covered by the full suite; no new AI benchmark was run.

Build artifact fingerprints from this verification:

```text
127b060e5303d8b5a7ab2ededc4ceb721044524d0ab23ee390e4379705e85602  runbookos-0.7.0.tar.gz
d4e826548d6dd31bd9ba0878470ec529eafe61ab766c596c4135eb4b42a453f1  runbookos-0.7.0-py3-none-any.whl
```

These are local verification artifacts, not release signatures. Temporary build,
scanner, and installation environments were removed. No repository staging or
commit occurred.

## Acceptance matrix

| Requirement | Result | Evidence / limitation |
|---|---|---|
| Five-VM topology and identity | PASS (observed) | Existing guests identified; detailed local report retained. |
| Controller placement/version | PASS (observed) | `ops-01` has v0.6.0; v0.7.0 not deployed. |
| Registered read-only diagnostics | PASS (narrow scope) | Four role-specific systemd unit checks succeeded through RunbookOS. |
| HTTP/app/DB-protocol/DNS health | NOT_VERIFIED | Current deployed policy/action scope did not include those checks. |
| Evidence provenance and audit | PASS (read-only checks) | Four execution records; chain and SQLite checks passed. |
| Qwen on real evidence | NOT_VERIFIED | No inference; controller/runtime topology not enabled. |
| Persisted real incident assessment and CLI/dashboard review | NOT_VERIFIED | No actual incident/investigation rows; only synthetic demo evidence. |
| Assessment validation and failure handling | PASS (offline) | Existing v2 and assessment regressions passed. |
| Policy/approval and remediation controls | PASS (offline controls only) | No real remediation executed; live behavior not verified. |
| Backup/restore | PASS (disposable schema-v4 test) | Operational controller backup/recovery not exercised. |
| Portable package and install | PASS | Final wheel/sdist built; both artifacts were freshly installed and smoke-tested. |
| Dependency and secret review | PASS (scoped to lock/sdist) | No known advisories; five reviewed scanner findings, zero unresolved. |
| Full formatting gate | BLOCKED (unrelated file) | One pre-existing untracked Markdown code block needs formatting if the owner wants repository-wide Ruff formatting clean. |
| Deployment, monitoring, recovery, rollback | NOT_VERIFIED | No guest deployment or controlled operational recovery exercise. |

## Release boundary and next action

The package excludes approval records and local homelab/Qwen runner artifacts.
`docs/diagnostic-actions-v0.2.3.md` contains private-address examples required
by existing diagnostic documentation; treat those as examples, not as live
inventory. Operational acceptance reports and the local approval manifest must
remain outside a public release.

Do not deploy by copying a wheel into the running controller yet. The exact
guest installation command depends on an approved artifact transfer mechanism,
service identity, runtime configuration, and database/rollback plan, none of
which has been authorized for ops-01. The smallest next operator action is to
approve a target-specific deployment change for `ops-01`, naming the reviewed
wheel SHA-256 above, isolated venv/prefix and database paths, service account,
configuration source, backup destination, and rollback procedure. After that,
approve a separate read-only live acceptance scope for HTTP/app/DB/network
diagnostics and local Qwen connectivity. Remediation still requires its own
explicit approval.

No exact deployment/rollback shell command is issued here because doing so
would assume guest paths, transfer access, service manager, and ownership that
have not been verified or authorized. Operational deployment and remediation
remain **NOT AUTHORIZED**.
