# RunbookOS v0.6.0 Diagnostic Selection Analysis

## Finding

The latest sanitized local Qwen rerun records `diagnostic_selection_limit` at
`catalog_selection_validation` for `nginx-unavailable`,
`fastapi-service-failure`, and `insufficient-evidence`. The acceptance
configuration sets `max_diagnostic_runbooks: 2`.

The deterministic validator applies this order: strict JSON/schema decode,
duplicate-ID rejection, empty-list abstention, configured count limit, then
catalog membership. Therefore the recorded count-limit reason means the
duplicate check did not trigger; catalog-membership validation was not reached
for these selections.

| Scenario | Recorded selection | Count | Duplicate check | Catalog membership |
|---|---|---:|---|---|
| `nginx-unavailable` | `web_health`, `application_health`, `network_health` | 3 | No duplicate reported; all IDs distinct | All three are catalog IDs; selection rejected earlier for count |
| `fastapi-service-failure` | Exact IDs were not safely retained | Exact count unavailable; count-limit rejection proves it exceeded 2 | Duplicate check did not trigger; exact list was not retained for independent enumeration | Not verified; membership check was not reached |
| `insufficient-evidence` | `web_health`, `application_health`, `database_health`, `network_health` | 4 | No duplicate reported; all IDs distinct | All four are catalog IDs; selection rejected earlier for count |

No unrecorded model output was reconstructed. The recorded fixture incident
texts are ordinary symptom descriptions, without instruction-like or
conflicting content. The gap was in the selection prompt: it said to choose
catalog IDs, but did not state the configured maximum, ask for a minimum
sufficient set, or explicitly instruct abstention with an empty list. It did
already treat incident text as untrusted and prohibit command, remediation,
policy, credential, or access requests.

## Correction

The selection system prompt now states the effective configured maximum, asks
for the smallest distinct diagnostic set justified by symptoms, explicitly
permits an empty selection when none is justified, and forbids duplicate or
invented IDs and claims of evidence before diagnostics run. It reiterates the
untrusted status of incident text and prohibits command or remediation
requests.

The schema, count limit, duplicate and catalog checks, policy, diagnostic
catalog, fixtures, executor, and approval boundaries were not relaxed or
changed. Failed diagnostic assertions remain failed and are not counted as
verified evidence.

## Offline verification

Tests cover exact-limit acceptance, count-limit rejection, duplicates,
unsupported IDs, one-item selection, empty abstention, executor non-invocation
on rejected selections, the Nginx/FastAPI fixture mappings, and the
insufficient-evidence fixture. The prompt-contract test checks that the
configured limit and abstention/minimum-set instructions reach the provider.
These tests use deterministic mocks; they do not establish that Qwen will obey
the revised prompt.

- Focused AI and acceptance harness tests: **38 passed**.
- Full offline suite: **188 passed, 11 opt-in live tests skipped**.
- Ruff lint and format: **passed**.
- `git diff --check`: **passed**.

No live inference, SSH, tunnel, VM access, or remediation was performed. The
tunnel acceptance manifest remains `NOT_AUTHORIZED`.

## Remaining uncertainty

The exact FastAPI diagnostic ID list and count were not retained in the
sanitized result. The deterministic failure category establishes only that
the selected list exceeded the configured maximum and that duplicate
rejection did not occur first. Catalog membership for that list is unknown.
The revised instruction requires a future separately authorized live rerun to
measure whether Qwen selection behavior changes; no accuracy improvement is
claimed here.
