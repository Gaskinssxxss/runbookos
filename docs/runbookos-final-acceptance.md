# RunbookOS final acceptance

## Decision

**`RUNBOOKOS_PARTIALLY_VALIDATED`**. The existing five-VM homelab is present and
running, and four current, policy-allowed read-only diagnostics succeeded
through the installed RunbookOS controller. The full incident-to-real-evidence
AI workflow, deployment/recovery, and live remediation have not been validated.
This is not a production-readiness claim.

## Repository and release boundary

- Repository: `/home/morphious/united/runbookos`
- Branch: `feat/v0.7.0-evidence-aware-assessment`
- HEAD: `d68197c3ac37336e1b9bfa8d66059e5eb8ecd001`
- Package source version: 0.7.0.
- Index: empty; no files staged. No commit, push, tag, or deployment occurred.
- Existing worktree modifications and historical acceptance artifacts were
  preserved.

The current local candidate manifest remains the 25 paths recorded in
`docs/production-readiness-review.md`. The two homelab acceptance reports are
environment-specific local evidence and are **excluded** from public-release
staging. The modified disposable-remediation manifest remains
`NOT_AUTHORIZED`. The prior release review's secret scan covered its exact
25-file candidate (4 raw findings, 4 reviewed synthetic/config findings, 0
unresolved credentials); no candidate file was changed in this acceptance.
There are no staged contents to scan. Any future candidate/index change needs a
fresh scan of the exact staged bytes.

### Proposed release manifest (not staged)

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

After operator review of the current candidate, these are the explicit
staging commands; they have **not** been run:

```sh
git add -- CHANGELOG.md MANIFEST.in pyproject.toml README.md requirements-ci-py312.lock \
  docs/ai-investigation.md docs/operations.md docs/operator-demo-v0.7.0.md \
  docs/production-readiness-review.md docs/security.md scripts/operator-demo-v070.py \
  src/runbookos/ai.py src/runbookos/assessment.py src/runbookos/assessment_evaluation.py \
  src/runbookos/cli.py src/runbookos/dashboard.py tests/ai_acceptance_harness_v060.py \
  tests/ai_m3_benchmark_v070.py tests/test_ai.py tests/test_ai_acceptance_harness_v060.py \
  tests/test_ai_m3_benchmark_v070.py tests/test_assessment_evaluation.py \
  tests/test_assessment_review.py tests/test_m5_integrated_release.py \
  tests/test_operator_demo_v070.py
```

The list excludes both operational reports, local inference runners/results,
historical acceptance/staging records, credentials/databases, and unrelated
working-tree changes. Recheck the report and scan the exact staged index before
any future commit.

## Integrated operational evidence

`docs/homelab-operational-acceptance.md` records the observed topology and
current evidence. In brief:

- All five intended guests are registered in `qemu:///system` and running;
  `qemu:///session` has no domains. An unrelated shut-off VM was not touched.
- Guest identities, NIC mappings, routes, net-01 forwarding/firewall behavior,
  controller inventory, strict host-key pins, and target key fingerprints were
  inspected read-only.
- The controller runs isolated RunbookOS 0.6.0. The v0.7.0 source checkout is
  not deployed there.
- The exact existing policy allowed only one read-only `systemd.is_active`
  action per target. Nginx, the sample application unit, PostgreSQL, and
  nftables each returned `active=true` through the RunbookOS CLI. Four new
  execution/evidence records and their audit events are persisted in the
  isolated schema-v4 acceptance DB.
- The full audit chain verified at 32 events; SQLite integrity passed and
  foreign-key violations were zero. No incidents or investigations exist in
  that DB, so no incident was fabricated.
- No service health probes beyond the registered unit-state action were
  attempted. No model inference, SSH outside RunbookOS, remediation, VM change,
  route/firewall change, or deployment occurred.

Historical synthetic Qwen M3 benchmark evidence remains exploratory. The
reported 21/24 accepted assessments and 11/13 answered-case classification
accuracy are not evidence of real incident accuracy or semantic support.

## Offline software evidence

The latest documented offline release review reported 319 passed and 11
skipped, 82.32% coverage, Ruff and whitespace checks passing, clean-candidate
tests at 293 passed, and wheel/sdist fresh-install checks passing. The 11 skips
are live/opt-in tests, not passes. Dependency audit of the updated CI lock
reported no known advisories. These are repository-level results; this task
made no product-code changes.

## Readiness gates

| Gate | Status | Evidence / limitation |
|---|---|---|
| G1 Reproducible code and dependencies | PASS | Existing v0.7.0 build/install and lock audit evidence; no package changes here. |
| G2 Offline regression/integration | PASS | Existing review: 319 passed, 11 skipped. |
| G3 Security/authorization boundaries | PASS (scoped) | Default-deny, exact read-only action policy, pinned SSH, and audit verified; no broad security assessment. |
| G4 Qwen on real diagnostic evidence | NOT_VERIFIED | No operational-evidence inference was authorized/performed; installed controller is v0.6.0. |
| G5 Real incident through persisted assessment and operator review | NOT_VERIFIED | No active incident; DB has zero incident/investigation rows. Synthetic review passed separately. |
| G6 Policy, authorization, audit invariants | PASS (read-only scope) | Four registered actions succeeded without approval/remediation; hash chain and SQLite checks passed. |
| G7 Remediation/postflight safety | PASS (offline only) | Existing mocked tests only; live remediation was not authorized or run. |
| G8 Deployment and recovery exercised | NOT_VERIFIED | v0.7.0 was not deployed to ops-01; no snapshot/backup restore test. |
| G9 Portable package | PASS | Existing wheel/sdist and fresh-install review. |
| G10 Release security/secret hygiene | PASS (prior candidate scope) | detect-secrets v1.5.0 candidate scan reviewed; no current staged index. New local reports are excluded. |
| G11 No known critical/high dependency issue | PASS (known lock scope) | Updated CI lock audit clean; not an independent system-wide audit. |
| G12 Required regression tests | PASS (offline evidence) | Existing full suite result; live tests remain skipped/unverified. |

## Remaining blockers and exact next actions

1. The installed controller is v0.6.0, while the current repository source is
   v0.7.0 and uncommitted. Deployment requires a separately reviewed,
   operator-approved installation plan and backup/rollback procedure.
2. The only authorized target checks in the installed policy are unit-state
   checks. HTTP, application dependency, PostgreSQL protocol, and broader
   network checks require reviewed registered actions and explicit policy
   scope; none should be added ad hoc.
3. There is no active incident. Do not manufacture one to claim incident-to-AI
   acceptance. A real incident or a separately authorized synthetic incident
   path is needed before inference can be tested end to end.
4. The isolated controller has no AI-provider configuration file, and the
   physical-host loopback listener on port 8080 could not be identified. It was
   not contacted; port 18080 was free. No model server was started and no
   operational evidence was sent to Qwen.
5. No libvirt snapshots or managed-save recovery points were found, and an
   external backup/restore procedure was not verified. No rollback or
   production deployment was exercised.
6. The supplied sudo credential was not used or copied into files or command
   arguments. If it is a real credential, rotate it because it was entered in
   chat.

No software defect required a repository code change during this acceptance.
The operational evidence report records the actual IDs and observations; this
consolidated report intentionally omits private addresses, public-key
fingerprints, and host storage paths. Do not publish the local evidence report
without a separate privacy review.
