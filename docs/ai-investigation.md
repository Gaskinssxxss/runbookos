# AI-assisted investigation

## Flow and guardrails

`runbookos investigate` performs these steps:

1. Read an incident from a file or stdin. The incident is length-limited and checked for common direct attempts to bypass safety controls.
2. Ask the configured provider to select IDs from the local diagnostic catalog. Unknown, duplicate, or over-limit IDs are rejected.
3. Resolve each ID to a local runbook and pass it through the ordinary RunbookOS planner. The investigation stops before SSH unless every action is registered, read-only, explicitly policy-allowed, within `max_tool_calls`, and within `execution_budget_seconds`.
4. Execute via the existing key-only, pinned-host-key SSH adapter. Existing engine execution IDs, step results, assertions, and audit records remain authoritative.
5. Send bounded, redacted evidence to the provider for analysis. Hypotheses must cite exact execution/step references. Citations not produced by this investigation are rejected.
6. Build `verified_evidence` directly from successful engine steps. Model-generated hypotheses carry confidence values; next steps are human-review-only text and are never executable.
7. Store investigation metadata and evidence references in SQLite. The raw incident is not persisted; its SHA-256 is retained. Provider and configured model names, latencies, diagnosis, and evidence are retained, and an audit event records the investigation result hash.

The provider receives the incident and selected diagnostic evidence. Do not send regulated data, credentials, private keys, or secrets. Evidence is size-limited and recursively redacted for common secret fields. Model output, incident text, logs, and SSH results remain untrusted. The structural capability boundary is the primary defense: the model can select catalog IDs only and is never passed a shell or remediation tool.

## Configuration

`config/investigation.example.yml` is a portable one-host example. The config supports:

- `provider.type: openai_compatible` with a `base_url`, model identifier, request timeout (1–450 seconds), token ceiling, and optional API key environment variable;
- `limits.max_diagnostic_runbooks` (1–8), `max_tool_calls` (1–64), `execution_budget_seconds` (1–600), and incident character limit;
- an explicit catalog of unique IDs, descriptions, and local runbook paths.

HTTP endpoints are accepted only on loopback. A non-loopback provider URL must use HTTPS. API keys are read from the named environment variable and never included in request history or persisted provider metadata.

## Local llama.cpp

For local development, start llama.cpp bound only to loopback. Set `MODEL` to a model path already approved for that host:

```sh
llama-server --model "$MODEL" \
  --host 127.0.0.1 --port 8080 \
  --alias qwen3.5-9b-instruct \
  --ctx-size 12288 --parallel 1 --threads 4 \
  --reasoning off --reasoning-format none --reasoning-budget 0 \
  --api-key-file "$HOME/.config/runbookos/llama-api-key" \
  --no-webui
```

Provision the API key file outside the repository with owner-only permissions and provide the same secret to RunbookOS through `RUNBOOKOS_LLAMA_API_KEY` using the host's protected secret mechanism. Then use `config/investigation.example.yml`, which targets the OpenAI-compatible `/v1/chat/completions` endpoint. The adapter asks for JSON in its prompt and validates it locally against strict Pydantic schemas; it intentionally does not send `response_format=json_object` because the audited llama.cpp build failed to initialize its grammar sampler for that mode with this Qwen GGUF. A bounded JSON delimiter closure is permitted only when the model omitted final closing braces/brackets; missing string data or schema violations are rejected. The listener stays on loopback and requires an API key. Do not bind to `0.0.0.0` or publish the endpoint.

The optional controller-side SSH tunnel is foreground-only and never starts automatically. Provide a separate tunnel-only key and a host-key pin independently verified through a trusted administrative channel. Keep both files outside source control and owner-only. The built-in `runbookos tunnel CONFIG.yml` command uses `ssh -F /dev/null`, `BatchMode`, `IdentitiesOnly`, public-key-only authentication, `StrictHostKeyChecking=yes`, a dedicated `UserKnownHostsFile`, and a single local forward from `127.0.0.1:<local_port>` to exactly `127.0.0.1:8080`. The target host and port are schema-fixed; the local listener is always `127.0.0.1`. It does not create accounts, install keys, alter `sshd`, or persist a service.

The host-side tunnel account should be dedicated and non-sudo. Restrict its `authorized_keys` entry to port forwarding and `permitopen="127.0.0.1:8080"`, and disable shell/TTY/agent/X11 access. The host firewall should remain default-deny; if a narrow network path is required, review and approve that separately. The API itself still requires a llama.cpp API key, supplied only through `RUNBOOKOS_LLAMA_API_KEY` to RunbookOS and a protected key file to llama.cpp. Neither is stored in YAML, SQLite, or audit events.

Live integration should be treated as environment-specific acceptance. Do not assume a previous tunnel or firewall exception is still present; any new live test requires a fresh review of identity, host-key pin, network scope, and cleanup plan.

## CLI examples

Incident text can be supplied through stdin to avoid putting it in shell history or process arguments:

```sh
runbookos --inventory config/inventory.yml \
  --policy config/policy.yml \
  --ssh-profiles config/ssh_profiles.yml \
  --db state/runbookos.sqlite3 \
  investigate --ai-config config/investigation.yml --incident-stdin < incident.txt
```

Use an inventory, default-deny policy, and SSH profiles created for the target environment. Run as a dedicated non-sudo controller identity. `--incident-file FILE` is another input option; the file content is not stored.

List prior investigations without incident text:

```sh
runbookos investigations --limit 20
runbookos audit
runbookos history EXECUTION_UUID
```

`runbookos investigations` shows the investigation ID, status, incident hash, selected diagnostic IDs, execution references, and provider metadata. Detailed evidence is available through ordinary execution history, which preserves engine step-level evidence.

## Limits

- v0.2.0 uses two serial model requests per investigation and no streaming. Each request has a bounded timeout and response size.
- The total diagnostic action count, runbook count, per-action timeouts, and aggregate estimated SSH budget are checked before a runbook executes. There is no autonomous retry.
- Prompt-injection heuristics reject common direct override/exfiltration instructions. They are not a semantic detector; safety relies on the fixed catalog, typed schemas, policy checks, and absence of arbitrary model tools.
- An LLM can still make incorrect hypotheses. Only successful RunbookOS evidence is marked verified. Recommendations need operator review.
- Investigation completion records are stored in SQLite. The current schema is user_version 3; migrations are additive and retain prior plan, approval, execution, investigation, and audit rows.
