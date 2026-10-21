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
