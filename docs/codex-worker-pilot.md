# Guarded Codex worker pilot (Issue #2)

This pilot is **disabled**. It has no `issues` trigger, scheduled workflow, GitHub Action, Codex invocation, or paid API configuration. `python scripts/codex_issue_worker.py --self-check` reports the fixed limits. Offline tests exercise the branch and draft-PR transaction with a fake publisher. They do not claim a real Codex run or a GitHub PR created by the worker.

## Trust and permission flow

1. A maintainer manually dispatches an issue. The worker accepts only `workflow_dispatch`, a current open issue, the exact `codex-worker-approved` label, and an actor whose GitHub permission is `write`, `maintain`, or `admin`. Issue title and body are untrusted task data, never authorization. The GitHub API must supply actor permission and issue metadata; a future entry point must not accept these values from issue text or caller flags.
2. One issue maps to `codex/issue-N`. Existing PRs block duplicate dispatch. The workspace must be empty; the pilot sandbox clones the repository and creates exactly one branch.
3. Untrusted code runs without operational secrets. The offline container profile has no network, capabilities, or privileged user; a read-only root filesystem; bounded CPU, memory, processes, and time; and a workspace-only bind mount. No Docker socket or host home is mounted. The publisher runs outside this sandbox.
4. Changed paths are checked before publication. Acceptance fixtures, taxonomy ground truth, CI workflows, `AGENTS.md`, packaging metadata, and secret-shaped files are protected. The publisher must confirm that the PR head matches the issue branch and that the PR is draft. CI evidence and original failures must be linked in the PR body before review; a green retry must not erase an earlier failure.

## Threat model and limits

Public issue text can contain prompt injection, commands, malicious patches, or false test results. The trusted dispatch and path checks prevent it from granting authority. A malicious test can attempt secret theft or host access; the offline sandbox has no secrets or network. A compromised publisher could push an unwanted branch; its credential must be short-lived and scoped to this repository and PR creation. The existing interactive `gh` credential is broader and is **not** supplied to the sandbox or activated for worker automation.

Fixed ceiling: one concurrent job, 20 minutes total, at most three revision rounds, and **$0 paid API spend**. These are caps, not spending authorization. CI and original test failures must be captured as immutable run links or safe summaries. Timeout, failed CI, invalid authorization, protected-file edits, or missing draft confirmation stop the worker and require manual maintainer review. To kill an active job, cancel its GitHub run and remove the approval label; no automatic retry is allowed. A future live runner needs an atomic repository-wide concurrency lock and immutable dispatch record before activation.

Codex CLI login, GitHub Actions minutes, and OpenAI API billing are separate entitlements. A ChatGPT subscription does not authorize paid automation. Networked Codex execution and short-lived scoped publisher credentials are deliberately unimplemented until maintainers approve design, entitlement, and spending limits. The present Docker profile is suitable for offline tests only; adding model egress requires separate review.

## Offline proof and remaining gate

`tests/test_codex_issue_worker.py` verifies trusted dispatch, hostile issue text, duplicate PR rejection, protected paths, manual stop, bounded runtime, container flags, and a single branch/draft-PR transaction against a local Git repository and fake publisher. No homelab access or live operations occur.

Before enabling real automation, maintainers must review this threat model, approve exact entitlement and spending, provide a scoped short-lived token mechanism, enforce an atomic concurrency/idempotency lock, and approve the network boundary for Codex. Until then, the worker stays disabled and any draft PR for this change is a manual implementation review artifact.
