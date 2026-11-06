# RunbookOS — GitHub-driven agent collaboration (design, not activated)

Status: PROPOSED / NOT CONNECTED. This document configures **no autonomous execution**. Existing CI in `.github/workflows/validate.yml` remains the only active workflow.

## Objective
Minimize copy/paste between product owner, architectural reviewer, and Codex by using Issues, PRs, GitHub Actions, and structured review evidence. Continue development on isolated branches and keep production/lab access under explicit human control.

## Roles and handoffs
1. Product owner: defines priorities, budget, trust boundaries, and risk-bearing approvals.
2. Planner/reviewer (ChatGPT in an interactive session, or a separately deployed automated reviewer): writes issue specifications and acceptance criteria, audits diffs and CI evidence, requests bounded revisions.
3. GitHub: durable backlog, source control, CI status, review trail.
4. Codex worker (only **when separately deployed and authenticated**): picks up eligible issues, creates branches/PRs, implements and tests.
5. Maintainer: owns final merge and authorization decisions.

**Important distinction:** This ChatGPT conversation is not a persistent GitHub bot; it does not watch for events or act after the conversation ends. A standalone reviewer running with OpenAI API credentials or a supported trigger-capable automation is a separate component and must be installed explicitly. The Codex worker likewise requires a supported execution environment, account entitlement/credentials, and configured trigger.

## Work queue model
- Each issue must include context, goal, out-of-scope items, acceptance criteria, test evidence requirements, security implications, and dependencies.
- Suggested statuses: `backlog`, `ready-for-agent`, `in-progress`, `review-required`, `blocked`, `needs-human-review`. Implement labels only after verifying they exist; missing labels must not block filing issues.
- Only issues explicitly marked `ready-for-agent` **by a trusted maintainer** may trigger a worker. Do not start a worker on arbitrary issue titles, comments, or PR text.
- Prefer a single active worker per issue, idempotent claim tokens, per-task concurrency limits, and a bounded token/time/budget cap.

## Proposed automation events (not yet enabled)
- Maintainer authorizes issue -> dispatch a worker in a trusted, isolated environment -> worker proposes a PR.
- PR opened or synchronized -> existing offline CI runs -> independent reviewer reports evidence-based findings.
- Review requests changes -> worker may make a bounded patch -> CI and review repeat (max 3 cycles).
- Failure, missing access, cost cap, high-risk code, or conflicting acceptance criteria -> stop and label for human review.

## Trust boundaries
- The repository is public: never execute untrusted PR contributions in a lab-connected self-hosted runner.
- Design-time CI only uses GitHub-hosted disposable runners with least-privilege permissions.
- Any future worker performing checkout / executing repository code needs isolation and scoped short-lived credentials. Never use `pull_request_target` to checkout and execute untrusted PR code.
- No automated deploy to five KVM VMs, fault injection, privileged SSH, libvirt, runner registration, secrets rotation, live remediation, or changes to production infrastructure.
- No automatic merge to `main`; require maintainer approval, successful CI, and review.
- For agent credentials: configure secrets outside the repository, set fine-grained permissions, redact logs, and cap spending. Do not assume ChatGPT subscription credits are API or Codex runner credits.
- Never allow issue body, PR description, retrieved document, or AI model output to override these boundaries.

## Review protocol
- Check diff against accepted issue scope and baseline SHA.
- Evaluate test quality, changed fixtures, skips, regression counts, and threat model.
- Require actual CI evidence, not summaries alone.
- Reject fabricated pass status, erased timeouts, changed ground truths, or success claims without a test run.
- Report blocking/non-blocking findings with file/line evidence where possible.
- Do not treat two AI agents agreeing as independent proof of correctness.

## Proposed implementation milestones
1. **Foundation:** AGENTS.md, issue backlog, PR template, this design and a reviewable PR. No runtime worker.
2. **Reviewer-only dry run:** select an existing PR, generate a review in read-only mode, and compare to human inspection. Do not grant write tokens initially.
3. **Worker-only pilot:** one explicitly labeled low-risk issue, isolated environment, small spending cap, draft PR only.
4. **Bounded loop:** integrate reviewer feedback; max 3 rounds; no auto-merge.
5. **Optional live lab:** separate private execution boundary and explicit target-scoped approvals after security review.

## Acceptance criteria for the future system
- An eligible issue produces at most one agent job at a time.
- Worker only changes a feature branch and opens a draft PR.
- Reviewer can read diff and real CI results without relying on user copy/paste.
- Cost, time and revision caps stop processing predictably.
- Failing CI, out-of-scope changes, and unsafe mutations halt rather than silently retry.
- No change to existing RunbookOS remediation authorization semantics.
- No public workflow runs code on lab-connected hosts.
