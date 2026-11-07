# PR reviewer pilot — manual preflight, not autonomous AI

Linked work item: #1. Status: **review candidate only**, no paid AI service is enabled.

## Purpose

This phase creates a deterministic, read-only GitHub PR metadata preflight using Python standard-library API calls. This is deliberately **not** semantic AI review and cannot approve PRs or replace a human. It lays the groundwork for a future separately credentialed AI reviewer after a security and cost review.

## How to operate once merged

From GitHub Actions on `main`, choose **PR Review Preflight (manual, no AI)** -> **Run workflow** -> enter a PR number. The job checks out only trusted `main` and **never** PR-supplied code. It reads PR metadata, changed-file filenames and patches, and check-run conclusions using the short-lived read-only `GITHUB_TOKEN`. Its Markdown report appears in the job output and job summary. Failures exit nonzero, pending/missing CI is `UNKNOWN` or `PENDING_OR_UNKNOWN`, never PASS.

- No `pull_request`, `pull_request_target`, `issue_comment`, `schedule`, or `issues` trigger is enabled.
- No OpenAI API, Codex API, model call, credential provision, automated comment, PR modification, issue update, branch push, or merge.
- No self-hosted runner, KVM, SSH, local model, or homelab networking dependency.

## Limitations

- `PASS` means only that the GitHub check-runs inspected have success-like conclusions. It does not mean secure code, sufficient test coverage, approved issue scope, or independently verified acceptance criteria.
- The GitHub API may return missing, incomplete, pending, or expired evidence; all such cases must be treated conservatively.
- Certain suspicious additions are flagged, but heuristics are not a complete threat model. Human review of full diff is still mandatory.
- Read-only does not prevent malicious user text from appearing in metadata; all PR content is treated as untrusted data, displayed only in bounded/escaped form, and never interpreted as instructions.
- The preflight may reveal filename metadata in GitHub Actions logs; repository owners should manage log access accordingly.
- Existing `validate.yml` remains the authoritative offline tests/build; this workflow does not execute tests.
- Workflow dispatch requires the workflow file to exist on the default branch.

## Proposed next phase (requires a new reviewed PR)

Build an isolated, model-powered reviewer with constrained JSON schema output and no automatic write actions. Pin dependencies, measure token usage and expenses, enforce request/output budgets, sanitize inputs, verify exact head SHA and authoritative CI logs, document least-privilege permissions, and test prompt injection plus retry loops. The maintainer must explicitly authorize credentials and spending. A subsequent phase could add automatic events and bounded feedback, but never auto-merge or live remediation.

## Rollback

Disable this workflow in GitHub Actions or revert the workflow and script commit; it does not mutate application state.
