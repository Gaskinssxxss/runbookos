# Runbook schema v1

Runbooks are YAML documents with `api_version: runbookos/v1` and `kind: Runbook`. Unknown fields are rejected. See `examples/runbooks/` for complete examples.

```yaml
api_version: runbookos/v1
kind: Runbook
metadata:
  id: web-server-health
  name: Web server health
  description: Read-only Nginx and capacity checks.
  risk: low
targets: [example-web-01]
parameters:
  max_used_percent:
    type: integer
    required: false
    default: 85
    minimum: 1
    maximum: 99
preflight:
  - id: no-failed-units
    action: systemd.failed_units
    verify: [{path: data.units, operator: empty}]
steps:
  - id: nginx-is-active
    action: systemd.is_active
    with: {unit: nginx.service}
    verify: [{path: data.active, operator: is_true}]
  - id: disk-limit
    action: os.disk
    with: {path: /}
    verify: [{path: data.percent, operator: lte, value: "$param.max_used_percent"}]
postflight: []
```

## Field constraints

- `metadata.id` is a stable lowercase ID; `risk` is `low`, `medium`, or `high`. A declared risk cannot be lower than an action's registered risk.
- `targets` are unique inventory aliases. There are no CIDR scans or implicit target selectors.
- Parameters support only `string`, `integer`, and `boolean`, with required/default, choices, integer bounds, or a regular expression. Secret-like parameter names are refused. `$param.name` references must occupy a whole YAML scalar; no template language or string interpolation is evaluated.
- Every step has a unique ID, registered `action`, action-specific `with` fields, timeout (1–300 seconds), and optional typed `verify` assertions.
- Verification operators are `eq`, `neq`, `lt`, `lte`, `gt`, `gte`, `empty`, `nonempty`, and `is_true`. Paths are restricted to result fields such as `data.active`.
- `preflight` and `postflight` cannot contain a mutating action. Failed preflight prevents steps from running; postflight only runs after successful earlier phases.

## Versioning

v0.1 supports only `runbookos/v1`. Breaking schema changes require a new API version and explicit migration. Plans bind source hashes, including the package version and fingerprint of action schemas/permissions, engine, remote dispatcher, and SSH adapter. Changing a runbook, inventory, policy, SSH profile, or relevant implementation code invalidates the plan and any approval bound to it.
