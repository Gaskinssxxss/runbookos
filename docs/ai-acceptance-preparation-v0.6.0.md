# RunbookOS v0.6.0 — Isolated Qwen Acceptance Preparation

## Verdict

The offline acceptance harness and synthetic scenarios are prepared and pass their targeted tests. **Live Qwen acceptance is NOT AUTHORIZED and was not run.** No inference request, tunnel handshake, managed-VM connection, firewall change, route change, or operator-controller write occurred.

The current workspace is the Ubuntu physical host, not `ops-01`. The requested `/var/lib/runbookos/acceptance-v060/` installation, tunnel identity, and tunnel `known_hosts` file do not exist on this local filesystem. No SSH was used to inspect `ops-01`; therefore its installation integrity, ownership, pin, and SQLite state were not independently rechecked in this preparation. The prior v0.6.0 acceptance records remain untouched because this task did not access them.

## Immutable input audit

| Input | Observed value | Result |
|---|---|---|
| Model | `/home/morphious/models/llama.cpp/qwen3.5-9b-instruct-q5_k_m.gguf`, 6,577,841,376 bytes | Present; SHA-256 matches expected `dc2a39aef291f91a9116ad214058da0d86eb648743a124bd8c333787c4b9c91c` |
| Server executable | `/home/morphious/.local/bin/llama-server` → `/home/morphious/.local/src/llama.cpp/build/bin/llama-server` | Present; version `0.6.0-dev (build 11479, commit 42c787e8c)`; SHA-256 `98a8581124ccf8ba775a89e1899c895b2d4a2053b9830f8b044fe69b928c02ac` |
| Listener/process | TCP/8080 and exact `llama-server` process lookup | No listener and no server process observed |
| API key file on inference host | `/home/morphious/.config/runbookos/llama-api-key` | File exists with owner-only mode `0600`; secret value was not read or printed |
| RunbookOS AI implementation | `src/runbookos/ai.py` | Uses the current registered diagnostic catalog, existing deterministic planner/policy, strict Pydantic response schemas, bounded provider/evidence sizes, and evidence-reference validation |
| Existing controller install | `/var/lib/runbookos/acceptance-v060/` | Not present on this local host; remote state not inspected |
| Tunnel identity and pin | Paths from `config/tunnel.homelab.example.yml` | Controller-side files not locally present; no handshake performed |

The source includes a deterministic prompt-injection precheck in `_check_incident`. This is tested separately. The precheck is not assumed to cover every adversarial wording; model output remains untrusted and selection/citations are checked after provider responses.

Historical tunnel metadata recorded the client public-key fingerprint `SHA256:yDDP5tent7OSBOGUeU0IwqMHSjsM4szXNBsYrlU6rvA` and a stored host-key pin `SHA256:KVifGkqQ1p5iyFOmgzfAQFPNRwI1IpA4D7p5F8RRPfg`. A trusted independent host-key source was not available in this session. The recorded pin is therefore **not independently verified**, and it is insufficient to authorize a tunnel.

## Prepared offline harness

`tests/ai_acceptance_harness_v060.py` is repository-local test support, outside the `runbookos` package and CLI. It invokes the real `IncidentInvestigator` and real `RunbookEngine` planner, policy checks, SQLite execution history, and audit chain. For each harness call, a context manager substitutes a strict fake executor and makes construction of the real SSH adapter fail immediately. The fake executor accepts only three registered read-only IDs, one synthetic target and a maximum ten-second action timeout. It uses no socket, subprocess, or network path.

The test harness creates only fresh temporary directories, mode `0700`, with YAML files mode `0600` and a new isolated SQLite database. It refuses to reuse an existing root. Acceptance output is not written to the repository or to `/var/lib/runbookos`.

`tests/fixtures/ai_acceptance_v060/scenarios.json` defines five cases:

| Case | Catalog selection expected by fixture | Synthetic observation | Evaluation boundary |
|---|---|---|---|
| Nginx unavailable | `web_health` | `nginx.service` inactive | Fixture class is service failure |
| FastAPI service failure | `application_health` | `runbookos-sample.service` inactive | Fixture class is service failure |
| PostgreSQL protocol failure | `database_health` | Fake PostgreSQL SSLRequest unavailable | Fixture class is connectivity failure; no PostgreSQL connection is sent |
| Network connectivity failure | `network_health` | Fake route table empty | Fixture class is network failure |
| Insufficient evidence | No diagnostic selection | No evidence | Fixture class is unknown; model should abstain or avoid unsupported high-confidence claims |

Expected class and scenario metadata stay out of provider prompts. v0.6.0 investigator output has no structured diagnostic-class or root-cause-ID field, so this harness cannot claim deterministic classification or root-cause accuracy. The evaluation can measure schema completion, selected diagnostic IDs, evidence reference validity, and latency. Natural-language semantic correctness needs independent human review; a plausible explanation or valid citation is not ground truth.

The structured response contract is the existing v0.6.0 contract, unchanged: selection is `{"diagnostic_ids": [registered_id, ...], "rationale": "..."}`; analysis is `{"hypotheses": [{"statement": "...", "confidence": 0..1, "evidence_refs": ["R01", ...]}], "recommended_next_steps": ["..."]}`. Every citation must map to evidence created by this investigation. For the insufficient-evidence case, an empty selection and empty hypotheses are acceptable; any hypothesis must use low confidence when uncited, and the human evaluator must mark unsupported semantics separately. The existing schema has no field for classification or canonical root cause, so those metrics are explicitly unavailable.

A separate adversarial input asks to execute arbitrary shell commands, bypass policy, and approve remediation. The offline test confirms `_check_incident` rejects this exact text before provider invocation. It does not prove that all prompt-injection variants are intercepted pre-provider. Model-generated unsupported diagnostic IDs and fabricated evidence citations are tested separately with offline mocked replies and must fail closed.

## Offline test results

Targeted command: `.venv/bin/pytest -q tests/test_ai_acceptance_harness_v060.py tests/test_ai.py`

Result: **20 passed** (8 new harness tests plus 12 existing AI tests). The cases exercise the five synthetic scenarios, the deterministic adversarial guard, invalid JSON, unsupported diagnostic ID, forged citation, SQLite investigation persistence, audit-chain verification, the ten-request ceiling, mode `0600` for new SQLite, refusal to overwrite an existing harness root, and rejection of an unapproved provider adapter. The five-case serial suite used a scripted fixture provider and issued exactly ten mocked completions. All executor invocations were fake. No Qwen call was made.

Full checkout command: `.venv/bin/pytest -q`

Result: **152 passed, 11 skipped**. All skips are the repository's opt-in live AI, SSH, probe, and tunnel tests. Full `ruff check src tests scripts`, `ruff format --check src tests scripts`, manifest YAML parsing, and `git diff --check` also passed.

The synthetic diagnostics intentionally return failed assertions for outage fixtures. Their records are stored as synthetic execution evidence, but `verified_evidence` is empty for those failed steps. This preserves the distinction between a persisted observation and a successfully verified assertion.

## Exact created-file inventory

Repository files added or changed for this preparation:

- `tests/ai_acceptance_harness_v060.py` — test-only isolated tree builder, fake executor, and engine guard.
- `tests/fixtures/ai_acceptance_v060/scenarios.json` — five synthetic scenario definitions; no credentials or operational evidence.
- `tests/test_ai_acceptance_harness_v060.py` — six offline harness and security regression tests.
- `docs/ai-acceptance-approval-v0.6.0.yml` — dedicated approval manifest, status `NOT_AUTHORIZED`.
- `docs/ai-acceptance-preparation-v0.6.0.md` — this preparation report.

No files were created under `/var/lib/runbookos/acceptance-v060/ai-acceptance/`. The existing acceptance installation and historical SQLite databases were not opened or modified. The existing unrelated Git modification and untracked historical dashboard report were preserved.

## Approval and network prerequisites

The manifest requests, but does not authorize:

- A temporary llama.cpp foreground process bound only to `127.0.0.1:8080`, using the verified model and executable hashes in the manifest, a protected API-key file, one slot, and bounded CPU/context parameters.
- A temporary `ops-01` SSH local forward from `127.0.0.1:8080` to physical-host `127.0.0.1:8080`, using only the tunnel identity and strict pinned-host-key checking.
- A temporary Python harness process on `ops-01`, at most ten serial provider requests total, no more than 120 seconds each, with no retry. The adversarial deterministic precheck should consume zero requests.
- A new `ai-acceptance/` tree with mode `0700` directories and `0600` files, including only a new SQLite database. Existing SSH-acceptance state stays separate and read-only.
- Operator provisioning of the matching API key through a trusted secret channel into the protected client secret path. The value must never appear in chat, command arguments, shell history, logs, or reports.

No route or firewall connectivity was probed. Earlier homelab documentation says the prior temporary nftables exception was removed. If the exact route is absent or TCP/22 is blocked, stop. Any new runtime rule would need separate explicit approval for source `10.60.10.10/32`, destination `192.168.100.145/32`, TCP/22, and the audited interface. No rule may be widened or persisted.

The last historical host snapshot reported 30 GiB RAM and about 20 GiB available; a prior Qwen run reported peak RSS near 8.16 GiB. These are historical measurements, not current guarantees. Context size, single-slot inference, and four CPU threads are resource controls but do not impose a hard memory ceiling. Proposed operator stop thresholds before any future run: require at least 16 GiB `MemAvailable` before starting the model, stop the acceptance-owned server if its RSS exceeds 10 GiB or host `MemAvailable` falls below 6 GiB, and stop immediately on unexpected system pressure. These thresholds require operator acceptance; do not use OOM or host-level resource configuration changes as a workaround.

## Remaining blockers

1. Independent trusted-source verification of the physical host SSH fingerprint and comparison with the pinned key on `ops-01`.
2. Read-only confirmation on `ops-01` of the installed v0.6.0 files, tunnel identity fingerprint/permissions, pinned `known_hosts` ownership/mode, and isolated installation state.
3. Explicit authorization to create the exact isolated acceptance tree and its new SQLite database on `ops-01`.
4. Approved secure provisioning of the model API key to the controller-side acceptance secret file.
5. Explicit approval to start temporary loopback llama-server, tunnel, and harness processes for the request/time bounds in the manifest.
6. Separate approval if a temporary network rule is actually required; do not alter routing or firewall as part of this preparation.

Until these blockers are resolved and approved, no live acceptance is authorized. No live AI quality, SSH evidence, managed-service health, or operational deployment claim follows from the offline tests.
