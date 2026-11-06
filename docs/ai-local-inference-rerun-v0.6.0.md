# RunbookOS v0.6.0 Local Qwen Rerun Readiness

**Preflight: PASS. Status: READY_FOR_LIVE_RERUN. Live inference: NOT RUN.**

This report records the corrected runtime path and fresh preflight. It does not
alter the original partial live acceptance report or claim that inference
succeeded.

## Preflight results

- Repository HEAD: `c080a37c24a6d3ae09356e68d7c5cc249db6e69f`.
- Source version: `0.6.0`.
- Model: expected SHA-256 matched.
- Runtime: `/home/morphious/.local/src/llama.cpp/build/bin/llama-server` is a
  regular executable, not a symlink; expected SHA-256 matched.
- Runtime ownership and path protection: file and lower directories are owned
  by the current account. The executable and build directories are group
  writable by the account's primary group, whose only listed member is the
  current account. The parent `/home/morphious/.local` is mode `0700`, blocking
  traversal by other users. No untrusted writer was identified from these
  ownership and mode checks.
- API-key file: regular file owned by the current account, mode `0600`. Its
  value was not read or displayed.
- Available memory: `19.93 GiB`, above the 16 GiB launch minimum.
- `127.0.0.1:8080`: available in the final bind check.
- Tunnel acceptance manifest: remains `NOT_AUTHORIZED`.

The prior preflight report identified the symlinked launcher path as a blocker.
The test-only orchestrator now points directly at the canonical executable;
the symlink itself remains rejected by the artifact verifier. Both pinned
artifact checks passed against the configured model and canonical runtime.

## Offline verification

- Targeted harness, orchestrator, and existing AI tests: **47 passed**.
- Ruff lint and format checks for the changed Python files: **passed**.
- Orchestrator tests verify symlink rejection and canonical regular executable
  acceptance without launching either artifact.
- Existing fake-executor, SSH construction guard, resource monitor, and
  request-limit tests remain in force.

## Live execution

No llama-server process was started. No inference requests were made. No
acceptance SQLite database or result file was created. The API-key value was
not read by the orchestrator. No SSH, tunnel, managed VM, network, or
infrastructure activity occurred. The loopback preflight socket was closed
immediately.

The live runner is ready for a separately authorized rerun. That future run
must still pass its own fresh artifact, memory, listener, key-file, initial RSS,
process-identity, and authenticated-readiness checks. A successful preflight
does not establish provider connectivity or model quality.
