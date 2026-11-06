# RunbookOS v0.6.0 Local Qwen Rerun Readiness

Status: **offline orchestration verified; live inference NOT RUN**.

This report covers the test-only local acceptance runner and its offline tests.
It does not supersede or rewrite the earlier partial live acceptance report. No
llama-server was started, no inference request was sent, and no network or SSH
operation was performed for this work. The AI acceptance authorization manifest
remains `NOT_AUTHORIZED`.

## Orchestrator

The entry point is `scripts/ai-local-acceptance-v060.py`. Importing it has no
process, network, or filesystem side effects. `--dry-run` invokes only the
offline pytest suites for the AI acceptance harness and orchestrator. The
separate `--live` mode also requires an interactive confirmation phrase, but
that phrase is only an accidental-execution guard; it does not replace the
separate operator authorization required before any live run.

Before a live run, the entry point verifies the fixed model and llama-server
paths and SHA-256 values, exact RunbookOS source version `0.6.0`, a free
`127.0.0.1:8080`, pre-launch `MemAvailable` of at least 16 GiB, and the
owner-only API-key file. Server arguments are fixed in code. The server binds
only to loopback, uses one parallel slot and four threads, and receives no API
key in its environment or arguments. The provider receives the key through the
configured environment variable. The report does not include the secret.

The existing `IncidentInvestigator`, catalog validation, planner/policy
checks, response parser, citation validation, SQLite store, and audit chain are
reused. `tests/ai_acceptance_harness_v060.py` retains the strict synthetic
read-only executor and makes construction of the real `SSHAdapter` fail. The
allowed target is the synthetic fixture target only. Production CLI and
execution code are unchanged.

## Resource guard integration

`ResourceWatch` in the script samples the acceptance-owned llama-server PID
before readiness checks and continues polling every 0.5 seconds while provider
HTTP requests block. It checks executable identity, nonzero parseable `VmRSS`,
and host `MemAvailable`. It aborts on RSS above 10 GiB, available memory below
6 GiB, invalid measurements, identity mismatch, or server exit. The request
wrapper checks the abort state immediately before and after every provider
call; the five-case harness stops after a monitor abort and does not retry.
The polling interval gives a nominal detection delay of 0.5 seconds, plus
scheduler/procfs delay. This is a userspace guard, not a hard memory limit.

The measurement boundary is the main llama-server PID. Descendant RSS is not
aggregated. Only the `Popen` handle created by this acceptance process is
terminated. A request already blocked when a threshold is detected is not
retried; stopping the local server causes that request to fail or return, and
the post-call guard prevents subsequent requests.

On completion or failure, the runner stops its monitor and owned server,
restores the prior provider environment value, removes generated synthetic
configuration/runbooks, and retains a fresh synthetic SQLite database and
sanitized summary under a uniquely created mode-0700 temporary acceptance
directory. The summary records partial results, request counts, per-scenario
stages, resource samples, SQLite integrity, foreign-key status, and audit-chain
verification. It contains neither prompts nor full model responses.

## Offline verification

The focused AI acceptance harness, orchestrator integration, and existing AI
tests passed: **45 passed**. The dedicated `--dry-run` entry point passed its
offline harness/orchestrator suites: **33 passed**. The full offline suite
passed: **177 passed, 11 opt-in live tests skipped**. Ruff lint and formatting
checks passed. The tests use fake process handles, synthetic
procfs, mocked providers, and temporary SQLite. They cover import and dry-run
side-effect boundaries, wrong checksums, port conflict, pre-launch memory,
invalid initial RSS, monitoring during blocked provider calls, RSS and memory
threshold aborts, server exit, process identity, timeout/no retry, request
limits, fake executor isolation, partial-result persistence, SQLite integrity,
and audit verification.

The manifest and five fixture IDs were parsed and cross-checked; the
authorization status was verified as `NOT_AUTHORIZED`. Whitespace and
production-source-diff checks passed. These results establish offline wiring
and failure handling only. They do not establish that the installed
model/runtime artifacts are currently present, that the provider can
authenticate, or that live inference succeeds.

## Changed-file allowlist

Files changed for this orchestrator task:

- `scripts/ai-local-acceptance-v060.py`
- `tests/ai_acceptance_harness_v060.py`
- `tests/test_ai_local_orchestrator_v060.py`
- `docs/ai-local-rerun-readiness-v0.6.0.md`

No files were staged or committed. Historical acceptance material and unrelated
working-tree changes were preserved.

## Remaining live gates

Before a future live run, the operator must separately authorize the local
model process and inference scope. The runner will then require the exact
artifact hashes, free loopback port, protected key file, resource thresholds,
and successful initial identity/RSS sample. Live SSH, tunnel use, managed VM
access, remediation, and operational deployment remain out of scope and
prohibited for this harness.
