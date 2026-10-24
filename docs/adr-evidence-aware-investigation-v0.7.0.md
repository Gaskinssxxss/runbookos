# ADR: Evidence-aware structured investigation

- Status: accepted for v0.7.0 M1/M2 implementation
- Baseline: `03e05a53b75888019d2be69193a932b795e37d65`

## Context

`IncidentInvestigator` already selects only registered diagnostics, executes them
through `RunbookEngine`, validates short evidence aliases, and stores a JSON
result through `SQLiteStore.create_investigation`. The stored evidence has a
stable `execution_id:step_id` reference and action status. Step evidence also
contains assertion results, and step rows retain `finished_at`. The current AI
analysis schema contains hypotheses and recommendations only. The investigations
table is schema v4 and stores the result as JSON; its audit event hashes the
canonical result. Incident-to-investigation links are stored separately.

The CLI has both standalone and incident-bound investigation paths. The
dashboard reads linked investigation references, not full evidence. No
dashboard changes are in scope for M1/M2. Existing v0.6.0 AI fixtures include
legacy analysis replies, which must continue to parse.

## Decision

1. Add a versioned Pydantic assessment and provenance-bearing evidence
   observation types in a separate `assessment` module.
2. Build direct observations only from the engine's persisted step results.
   Keep their assertion outcome and existing succeeded/failed/unknown status;
   never promote a failed assertion.
3. Ask the provider for typed inferences, hypotheses, classifications,
   uncertainty, unknowns, and advisory recommendations. Continue accepting the
   v0.6.0 hypotheses/recommendations response as a legacy input and represent
   its missing classification as partial/abstained rather than fabricating one.
4. Validate all model evidence references against the current investigation's
   evidence set. Require verified evidence for a `supported` classification.
   Record semantic support as `unverified`; valid references alone do not prove
   a claim.
5. Persist the assessment additively inside the existing `result_json`. Do not
   migrate SQLite or rewrite historical investigation/audit rows. Keep the
   existing `IncidentInvestigator.investigate` call compatible by adding only
   optional identity input and additive output fields.
6. Keep AI recommendations advisory and reject explicit executable command or
   remediation-shaped output. The model receives no new execution authority.

## Consequences

Existing v0.6.0 records remain readable and unchanged. New results include a
versioned `assessment` beside the legacy `report`; the audit result hash covers
both. Opening a v0.6.0 database requires no migration. Citation validity is
deterministic; semantic support still requires independent review.

## Security and compatibility invariants

- Diagnostic selection, catalog checks, policy, planner, and executor remain
  unchanged.
- No live provider or infrastructure access is required for tests.
- Invalid schemas, unsupported classes, forged refs, and inconsistent
  verification claims fail closed.
- The legacy report and response parser remain available for v0.6.0 callers.
