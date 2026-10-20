# Incident simulation and diagnostic evaluation (v0.2.4)

## Scope and separation

The `scenarios/` directory contains six versioned YAML fixtures: healthy baseline, Nginx failure, FastAPI failure, PostgreSQL connectivity failure, disk pressure, and missing network route. Each fixture declares its incident and target, failure type, ground truth, expected classification/root cause, expected diagnostic IDs, expected evidence references, and recovery criteria. Cross references and duplicate IDs are checked before a scenario is accepted.

This framework does not mutate or execute against infrastructure. Its evidence is synthetic and tagged `synthetic_fixture`. It does not invoke SSH, `RunbookEngine.execute`, systemd, database, firewall, or any fault injector. Existing `runbookos investigate` and runbook schemas remain unchanged. Fixture evidence is mapped to a small, fixed diagnostic catalog; provider selection determines which synthetic evidence is supplied for analysis. The evidence records remain fixtures, not output from a live engine execution.

## Commands

```sh
runbookos scenarios list
runbookos scenarios validate
runbookos evaluate --provider mock --repeat 3 --output-dir evaluation-results
runbookos evaluation report evaluation-results/<evaluation-id>.json
runbookos evaluate-v2 --provider mock --repeat 3 --output-dir evaluation-v2-results
```

The `mock` provider is a scripted fixture response. Its expected 100% score confirms schema, metric, persistence, and report plumbing; it is not evidence of model accuracy. It works offline. Results use unique evaluation IDs, preserve evidence references and provider/model metadata, and write JSON plus Markdown.

To opt in to a real model provider against synthetic evidence, provide a separate provider config (for local Qwen, the existing OpenAI-compatible loopback/tunnel config can be reused while the temporary provider endpoint is available):

```sh
runbookos evaluate --provider configured \
  --provider-config config/evaluation.qwen.example.yml \
  --repeat 3 --output-dir evaluation-results
```

This example targets a llama.cpp loopback endpoint, uses a 450-second per-request bound for CPU inference, and makes two bounded requests per scenario: diagnostic selection from the fixture catalog, then classification/root cause/evidence citation from synthetic evidence. Start the model endpoint and provide `RUNBOOKOS_LLAMA_API_KEY` through a local protected secret mechanism first. It does not connect to SSH targets. Token usage is recorded only if the provider returns the standard integer usage fields.

`evaluate-v2 --provider configured` uses `config/diagnostic-taxonomy.v2.example.yml` and evaluator-only expected IDs in `scenarios/metadata/ground-truth-taxonomy-v2.yml`. It never sends expected IDs to the provider. Its prompts/output schema differ from v1, so score changes alone are not evidence of capability improvement. See [taxonomy v2 and blind review rubric](diagnostic-taxonomy-v2.md).

## Metrics and interpretation

- **Diagnostic classification accuracy**: exact normalized match of predicted versus expected incident class.
- **Root-cause identification accuracy**: exact normalized match to the scenario's canonical root-cause label. This strict metric does not award semantic similarity.
- **Diagnostic selection accuracy**: exact set match between selected and expected catalog IDs.
- **Evidence citation validity**: citations are unique references present in that fixture's evidence set. This measures reference integrity only; it does not establish that the diagnosis is correct.
- **Evidence precision/recall**: overlap against expected evidence references. These are separate from citation validity and diagnosis metrics.
- **False-positive/false-negative rate**: incident-vs-healthy classification rates over negative and positive scenario populations.
- **Completion rate, end-to-end latency, token usage (if available), and safety-policy violation count** are included in the JSON dataset and Markdown report.
- The report includes a confusion matrix with raw counts and one-vs-rest per-class precision/recall. Binary false-positive/false-negative rates treat any non-`healthy` classification as an incident; they do not replace the multi-class metrics.

Confidence is retained if the provider supplies it, but marked uncalibrated and excluded from accuracy. Model-generated probabilities are not verified likelihoods. `repeat` runs each fixture multiple times and records per-trial predictions; this allows consistency analysis without asserting statistical significance from a small scenario set.

## Fault injection boundary

Controlled fault injection is **not implemented or enabled in v0.2.3**. There is no disposable environment in this repository, and no production engine action is registered for failure injection. No five-VM homelab fault was created. A future isolated injector must require an explicit disposable-target identity, separate credentials, an explicit operator approval token, a bounded scenario allowlist, and a verified recovery step; it must reject homelab inventory aliases before execution. Until then, use fixtures only.

## Limitations

The scenario set is small and hand-authored. Fixture evidence is intentionally simple and does not capture timing, noisy logs, correlated failures, or partial network partitions. Provider-mode evaluation exercises the provider and evaluator, not the SSH diagnostic executor. Live Qwen results on these fixtures must not be described as accuracy on real incidents. No calibration, confidence interval, or semantic root-cause scorer is included.

The registered catalog includes bounded TCP reachability, fixed-path HTTP(S) readiness with verified TLS, and PostgreSQL SSL negotiation availability checks. These actions require endpoint aliases in both inventory and a separate per-host policy list. They are unit tested with mocked transports; no live action was run against the homelab in v0.2.3. PostgreSQL protocol negotiation does not prove authenticated database readiness. Network route evidence is not equivalent to end-to-end reachability.
