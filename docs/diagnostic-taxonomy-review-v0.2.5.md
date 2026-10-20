# Diagnostic taxonomy review — v0.2.5

## Classification perspective

Classification is made from an explicitly named perspective. v0.2.4 did not encode that perspective in each scenario, which left the PostgreSQL example ambiguous.

| Class | Perspective and minimum evidence |
|---|---|
| `service_failure` | The checked target component itself is inactive, failed, or cannot provide its local service. A systemd inactive result is direct target-service evidence. |
| `dependency_failure` | A caller component is confirmed operational, while a distinct downstream dependency is unavailable and the observed incident is the caller's impact. Evidence must identify both caller and dependency; an error report alone does not prove the caller is healthy. |
| `connectivity_failure` | A source-to-target endpoint/protocol probe fails, but available evidence does not localize it to the target service or a known network path. |
| `network_failure` | Route, interface, gateway, or path evidence identifies the network layer as the failure source. |
| `unknown` | The evidence does not justify choosing one of the above perspectives/classes, or material evidence conflicts. |

The preferred classification perspective is the incident's impacted service. When a scenario is framed as a failure of a particular target host/service, report its local service state as `service_failure`. Use `dependency_failure` only when the caller/dependency relationship is explicit and caller health has independent evidence. Prefer `unknown` when the perspective or required evidence is absent.

## PostgreSQL fixture finding

The historical `postgresql-connectivity-failure` fixture targets the example database host, names PostgreSQL as the service, and supplies evidence that `postgresql.service` is inactive. Its v0.2.4 expected class is `dependency_failure` because the incident text is phrased as an application reporting its database dependency unavailable. However, the fixture does not include an independent application-health check proving the caller is operational. Under the target-service perspective, `service_failure` is also defensible; under a strict caller-impact rubric, the expected evidence is insufficient to prove `dependency_failure`.

Do **not** change the v0.2.4 label, any historical dataset, or its score. The three Qwen `service_failure` predictions are retained as benchmark errors against the frozen v2 expected label and are also a taxonomy/fixture ambiguity to resolve prospectively. Do not reinterpret the observed model output as a reason to relabel the fixture.

Before a future taxonomy version is benchmarked, add an explicit per-scenario `classification_perspective` field and at least one deterministic scenario where (a) the caller is independently healthy, (b) a distinct dependency is down, and (c) evidence links the incident impact to that dependency. Preserve the existing scenario as a versioned legacy case or label it `unknown` only in a newly versioned, independently reviewed truth map. Never mutate the v2.4 ground truth in place.

## Diagnostic selection audit

The preserved v0.2.4 Qwen set-selection results are unchanged: 12/18 exact sets (66.67%), mean precision 83.33%, recall 100%, six unnecessary diagnostics, and zero missed required checks. All six unnecessary selections came from Nginx and FastAPI cases: one additional diagnostic in each of their three trials. This indicates a precision/minimality issue, not missing coverage. The v0.2.5 reviewer should judge explanation evidence separately from whether extra diagnostics were reasonable; no selection labels were altered.

## Compatibility and evaluation policy

The v0.2.5 evaluator continues to use the frozen v2 taxonomy and ground truth for compatibility. The change only tightens evidence-reference handling. A future taxonomy v3 is deferred until its perspective field, class boundaries, fixture evidence, and migration map can be reviewed without looking at new model scores.
