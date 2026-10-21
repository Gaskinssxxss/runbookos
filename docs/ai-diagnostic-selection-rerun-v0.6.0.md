# RunbookOS v0.6.0 — Corrected Selection Rerun Readiness

**Live rerun: NOT RUN. Preflight: BLOCKED.** The required fresh operator
approval was not established, and port `127.0.0.1:8080` is already occupied.
The existing listener was not stopped or contacted. This report preserves the
prior live result and records only read-only preflight plus offline tests.

## Preflight observations

- Repository HEAD: `c080a37c24a6d3ae09356e68d7c5cc249db6e69f`.
- Imported RunbookOS source: repository `src/runbookos`, version `0.6.0`.
- Revised selection prompt: present in the imported source. It includes the
  configured maximum, minimum distinct set, empty-selection abstention, and
  no-invented-ID/evidence instructions.
- `src/runbookos/ai.py` working-tree SHA-256:
  `d0a531dd697001ff4bbc55cb4cb74951823713959878ec67f4a12fc4ee3e511d`.
- Source diff is limited to the reviewed model-facing selection prompt change;
  deterministic selection validation is unchanged.
- Model and canonical llama-server checksums match the pinned values.
- Protected API-key file is a regular file owned by the current account with
  mode `0600`; its value was not read or displayed.
- MemAvailable at inspection: `19.53 GiB`, above the 16 GiB launch minimum.
- `127.0.0.1:8080`: **occupied**. Listener inspection showed a loopback LISTEN
  socket but did not identify its owning process. No attempt was made to
  connect to or stop it.
- The orchestrator imports the repository source and requires v0.6.0. Its live
  path wires `ResourceWatch.check` before and after provider calls; offline
  tests exercise monitoring during blocked calls.
- No acceptance database was created during this preflight. A live run would
  create a new unique synthetic tree and SQLite database; existing acceptance
  state is not reused.

## Comparison baseline

The prior live rerun was **PARTIAL**: seven provider requests; Nginx and
insufficient-evidence selections exceeded the two-diagnostic limit; FastAPI
was rejected at selection validation with the exact IDs not safely retained.
PostgreSQL and network investigations completed, with valid citations to
diagnostic steps whose assertions were failed and whose verified-evidence
count was zero. No new model behavior was observed in this task.

## Offline verification

Focused AI, acceptance-harness, and orchestrator tests: **56 passed**.
`git diff --check`: passed. No live inference, SSH, tunnel, managed VM access,
or remediation occurred.

## Stop condition and next gate

The rerun is not ready to launch while the port is occupied. Have the operator
identify and safely clear the existing loopback listener if appropriate, then
repeat the full preflight. A separate explicit approval for the stated local
Qwen scope is still required before running `--live`; neither approval nor a
free port authorizes stopping an unidentified process. The tunnel approval
manifest remains `NOT_AUTHORIZED`.
