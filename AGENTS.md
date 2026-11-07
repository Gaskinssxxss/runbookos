# Agent engineering instructions for RunbookOS

These are repository-wide instructions for Codex and other coding agents. Human operators remain responsible for authorizing risk-bearing operations.

## Mission and sources of truth
- Implement only the scope of a tracked GitHub Issue or an explicitly authorized maintainer request.
- Read the issue, linked design/acceptance documents, relevant source, and tests before editing.
- Treat GitHub Issues as the task queue, pull requests as review artifacts, and CI as automated evidence. Do not treat an AI-written summary as proof of a test run.
- If issue requirements conflict with security invariants in this file, stop and report the conflict.

## Security invariants (non-negotiable)
- AI output is advisory. Never grant models arbitrary shell execution, policy edits, approvals, or direct remediation dispatch.
- Preserve registered actions, default-deny host policy, exact plan/hash binding, human approval, one-time approval consumption, and independent postflight verification.
- Do not execute live remediation, fault injection, VM lifecycle operations, SSH changes, or changes to KVM/libvirt, production, networking, secrets, or credentials without separate target-scoped operator authorization.
- Do not run untrusted pull-request code on a self-hosted runner with access to the lab. This public repository is for offline checks only unless a security-reviewed, segregated environment is established.
- Never commit secrets, private SSH keys, operational SQLite databases, raw sensitive evidence, host-specific credentials, or private campaign ledgers. Redact reports.
- Do not auto-merge to main; leave main untouched unless a maintainer explicitly approves the merge.

## Per-issue workflow
1. Read and restate scope, constraints, acceptance criteria, and risks; identify baseline commit.
2. Create a dedicated feature branch; do not modify main directly.
3. Make the smallest safe change. Keep public interfaces and SQLite schema backward compatible unless the issue explicitly authorizes migration.
4. Add tests that distinguish successful behavior from regressions; preserve original failures, timeouts, and attempt counts.
5. Run relevant tests first, then offline full suite, lint, and build when environment supports them. Report exact commands, counts, skips, and limitations.
6. Create a PR linking the issue with a concise summary, changed files, test evidence, known risks, and rollback notes.
7. Apply reviewer feedback within issue scope, up to three bounded repair rounds. Escalate unresolved failures rather than weakening tests or claiming success.
8. Do not change acceptance criteria, expected outcomes, ground-truth fixtures, or fault oracles to make implementation pass without explicitly proposed and reviewed justification.

## Pull request evidence contract
Include sections:
- Linked issue and baseline SHA
- Scope and invariants
- Implementation summary
- Exact test commands and PASS/FAIL/SKIP counts
- Evidence locations (CI run links and sanitized logs; never raw secrets)
- Known limitations and unverified claims
- Risk, rollback plan, and human-approval requirements

## Agent collaboration
- A coding agent may generate code and propose a PR.
- A separate reviewer must review PR diff and acceptance evidence; self-review is not independent validation.
- Review comments are advisory until addressed, dismissed with rationale, or escalated.
- Avoid autonomous infinite loops: maximum three revision rounds per PR; no auto-merge and no automatic lab mutation.
- Automation credentials and spending limits must be configured by repository administrators outside the repository.
