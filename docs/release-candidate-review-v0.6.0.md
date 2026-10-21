# RunbookOS v0.6.0 — Local Release Candidate Review

## Scope and baseline

Reviewed source baseline: `b88c22a4d1dadd6af20fdc82f8dc43d7ffc8abb3` on `feat/v0.6.0-incident-remediation-workflow`. This review prepares a local, reproducible v0.6.0 demo and checks packaging from the committed source. It is not a production-readiness statement.

The pre-existing local edit to `docs/disposable-remediation-approval-v0.5.0.yml`, historical untracked `docs/dashboard-staging-acceptance-report-v0.4.0.md`, and synthetic acceptance database are preserved and excluded from the changed-file allowlist. The full synthetic acceptance report has its machine-local SQLite path redacted; its synthetic identifiers and claims remain labeled as synthetic. The separate historical v0.3.2 Alertmanager PASS is explicitly distinguished from the v0.6.0 provider-equivalent test.

## Demo safety review

`scripts/demo-v060.py` creates new temporary configuration and SQLite state, uses target `192.0.2.42` only, asserts that address in `FakeExecutor`, and exposes no user-supplied target or executor input. It starts only ephemeral loopback webhook/dashboard listeners. Generated webhook key material is environment-backed within the child process; dashboard verifier and database are temporary. The code uses the existing engine, plan, policy, approval, confirmation, postflight, incident lifecycle, and audit mechanisms. Fake execution is not added to production CLI dispatch. No SSH, AI, real mutation, external listener, or persistent service is invoked.

## Verification results

This section records the actual verification performed for the current candidate. Replace no result with a historical result:

- Branch / HEAD: `feat/v0.6.0-incident-remediation-workflow` / `b88c22a4d1dadd6af20fdc82f8dc43d7ffc8abb3`; no source-code or test changes from the baseline.
- Working tree: only the prior local disposable-remediation manifest edit, preserved historical report, synthetic acceptance report, and the five files in the allowlist below are present. Nothing was staged.
- Build source: clean `git archive` of HEAD in a new temporary directory; candidate `MANIFEST.in`, demo script, and three report/doc files were overlaid. All `src/runbookos` files remained identical to HEAD.
- Tool environment: new CPython 3.12 venv with `requirements-ci-py312.lock`; PEP 517 build used isolated environments with the pinned `setuptools==80.10.2` and `wheel==0.48.0` requirements.
- Clean committed-source pytest: **143 passed**, coverage **80.62%**.
- Full local checkout pytest with all live opt-in environment variables explicitly unset: **144 passed, 11 skipped** (four live-test modules skipped); coverage **76.37%** when measuring the installed clean-source package. A first coverage invocation used the default source mapping and returned a duplicate-path 55.25% result; rerunning with the explicit clean-source path yielded the passing 76.37% result. No test failed.
- Ruff lint: passed. Ruff format check: passed; 40 files already formatted.
- CLI smoke: installed wheel and sdist each report version `0.6.0` via package metadata, import, and CLI. `--help` passed.
- Example runbooks: all **7** validated.
- Demo harness: **PASS** from both the installed wheel environment and extracted sdist, using temporary state only; both runs confirmed 3 incidents, 3 executions, 1 investigation, 4 nonce records, 46 valid audit events, SQLite `integrity_check=ok`, clean foreign keys, stopped loopback processes, and removed verifier.
- PEP 517 wheel and sdist: both built successfully. Fresh separate venv installs of each artifact passed metadata/import/CLI parity.
- Artifact contents: wheel contains runtime package/entry points and no SQLite, private key, or homelab files. Sdist contains the demo and listed documentation; no SQLite, private-key, or `.runbookos-staging-v032` content.
- SHA-256 was verified for both built artifacts. Hashes are reported with the delivery result rather than embedded in the sdist, avoiding a self-referential archive digest.
- `git diff --check` and trailing-whitespace/final-newline checks on every allowlisted file: passed.
- Secret scan: `detect-secrets` 1.5.0 scanned the exact staged Git-index blobs for all five allowlisted files and reported **0 findings**. Candidate content was also manually checked; generated HMAC material and the dashboard password exist only at runtime and are not logged or written to repository files.

The separate prior full workflow acceptance remains **PASS** in `docs/full-workflow-acceptance-v0.6.0.md`; its report records 144 passed, 11 skipped, and 80.62% from that earlier run. Current fresh results above are reported independently.

## Changed-file allowlist for this preparation

Only these files are in scope for the current uncommitted demo/review work:

- `MANIFEST.in`
- `scripts/demo-v060.py`
- `docs/full-workflow-acceptance-v0.6.0.md`
- `docs/operator-demo-v0.6.0.md`
- `docs/release-candidate-review-v0.6.0.md`

No Git staging, commit, push, tag, merge, publication, or deployment is authorized by this task. Existing unrelated local files remain excluded.

## Verdict

Final offline integration verdict: previously **PASS**. Reproducible operator demo: **PASS** using the fake executor and synthetic data. Release-candidate verification: **PASS** for offline checks and artifacts; this does not imply deployment readiness. Historical real Alertmanager v0.3.2 acceptance: **PASS**, separately. Real SSH remediation: **NOT RUN**. Live AI inference: **NOT RUN**. Natural monitoring rule: **NOT RUN**. Operational deployment: **NOT AUTHORIZED**.

## AI acceptance and current release-candidate addendum

This addendum records the current checkout review at HEAD
`c080a37c24a6d3ae09356e68d7c5cc249db6e69f`. The preceding sections describe
the earlier dashboard/demo review and remain historical; they are not evidence
of the checks below.

### AI acceptance result

The bounded synthetic Qwen rerun in
`docs/ai-diagnostic-selection-rerun-results-v0.6.0.md` completed all five
scenarios: four exact catalog selections and one valid empty-selection
abstention. There were zero catalog/selection-policy rejections and 10 serial
model requests without retries. All emitted citations referenced available
diagnostic evidence. The four diagnostic step assertions were `failed`, with
zero verified evidence; citation validity is not a claim of verified service
health. Semantic causal support and structured classification/root-cause
accuracy were not scored. ResourceWatch, SQLite integrity, audit verification,
and acceptance process cleanup passed as documented in that report. The prior
partial AI reports remain unchanged.

### Verification in this checkout

- Full offline pytest: **190 passed, 11 skipped**. Skips are opt-in live AI,
  live homelab, live probe, and live tunnel tests. No tests initiated live
  infrastructure access.
- Ruff lint (`ruff check .`): passed.
- Ruff format check on AI source, tests, harness, and orchestrator: passed.
- Ruff format check over the entire checkout: one formatting failure in the
  unrelated, untracked historical
  `docs/dashboard-staging-acceptance-v0.4.0.md`. That file was not changed.
- `git diff --check`: passed.
- The `detect-secrets` executable is unavailable in this environment. A
  limited manual pattern review found no private-key block or credential value
  in the inspected AI acceptance files. It did identify machine-local paths in
  some acceptance artifacts, listed below. This is not equivalent to a full
  automated secret scan.

### Proposed AI acceptance commit manifest

This is a proposal only. Nothing is staged. These exact files belong to the
prompt correction and portable synthetic acceptance work:

- `src/runbookos/ai.py`
- `tests/test_ai.py`
- `tests/ai_acceptance_config_v060.py`
- `tests/ai_acceptance_harness_v060.py`
- `tests/fixtures/ai_acceptance_v060/scenarios.json`
- `tests/test_ai_acceptance_harness_v060.py`
- `docs/diagnostic-selection-analysis-v0.6.0.md`
- `docs/ai-diagnostic-selection-rerun-v0.6.0.md`
- `docs/ai-diagnostic-selection-rerun-results-v0.6.0.md`
- `docs/release-candidate-review-v0.6.0.md`

The local live orchestrator and its tests are relevant acceptance tooling but
are held out of this proposed product manifest until their machine-specific
artifact paths are removed or the files are clearly maintained as local-only:

- `scripts/ai-local-acceptance-v060.py` — embeds local model, runtime, and
  API-key file paths.
- `tests/test_ai_local_orchestrator_v060.py` — tests the held-out orchestrator.

Also excluded from the proposed manifest:

- `docs/ai-acceptance-approval-v0.6.0.yml` and
  `docs/ai-acceptance-preparation-v0.6.0.md` — contain host-specific paths and
  operational acceptance details; the approval manifest remains
  `NOT_AUTHORIZED`.
- `docs/ai-local-inference-acceptance-v0.6.0.md`,
  `docs/ai-local-inference-addendum-v0.6.0.md`,
  `docs/ai-local-inference-rerun-v0.6.0.md`,
  `docs/ai-local-inference-rerun-results-v0.6.0.md`, and
  `docs/ai-local-rerun-readiness-v0.6.0.md` — preserve as historical/local
  acceptance records unless separately sanitized and reviewed.
- `docs/disposable-remediation-approval-v0.5.0.yml` — unrelated pre-existing
  local modification; preserve and exclude.
- `docs/dashboard-staging-acceptance-report-v0.4.0.md` — unrelated historical
  untracked report; preserve and exclude.
- `.runbookos-staging-v032/`, SQLite databases, logs, credentials, model
  artifacts, and temporary acceptance state — not part of the manifest.

The local runner has no observed secret value, but its fixed absolute
workstation paths make it inappropriate for an unreviewed public commit. The synthetic SQLite
and JSON summary remain outside the repository. No Git staging, commit, push,
or release was performed.

### Integration boundary and limitations

- Offline regression tests passed; live Qwen results apply only to the stated
  synthetic scenarios and do not establish model accuracy on production
  incidents.
- Historical read-only SSH diagnostic acceptance is separate. No new SSH
  checks were run in this review.
- Real service-health verification remains outstanding; the four synthetic
  diagnostic assertions failed and verified-evidence count was zero.
- Real remediation was neither executed nor authorized.
- Operational deployment remains **NOT AUTHORIZED**.

Current recommendation: **READY_FOR_COMMIT_REVIEW** for the exact proposed
manifest above, subject to review of the held-out local runner and its
machine-specific paths. This is not a production-readiness verdict.
