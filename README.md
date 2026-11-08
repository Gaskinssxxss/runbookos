# RunbookOS v0.7.0 — Evidence-Aware Incident Review

Development branch: `feat/v0.7.0-evidence-aware-assessment`, based on the v0.6.0 incident-to-remediation workflow. v0.7.0 adds structured evidence-aware assessment, independent offline evaluation, and read-only CLI/dashboard review while retaining existing human approval and execution boundaries.

RunbookOS is a lightweight Python CLI for validating, planning, running, and auditing Linux operational runbooks, with optional AI-assisted incident investigation and human-controlled alert-to-incident workflow. It uses versioned YAML/JSON, Pydantic, Typer, SQLite, OpenSSH, and a replaceable provider interface with one OpenAI-compatible HTTP implementation. The optional webhook is disabled unless started manually and binds only to loopback. There is no autonomous remediation loop.

## Safety model

- Actions are selected from the built-in registry. YAML cannot provide a shell command or Python code.
- Policy is default-deny and grants diagnostics per host. Changing actions need a separate remediation allow and an explicit, one-use, expiring approval tied to the plan hash.
- The SSH adapter uses public-key authentication only, pinned `known_hosts`, `StrictHostKeyChecking=yes`, `-F /dev/null`, no agent forwarding, no proxy, no password prompt, no sudo, and no retry.
- A lost SSH connection, client timeout, or malformed remote response after dispatch is recorded as `unknown`. The engine stops the run and does not retry.
- SQLite state is created with owner-only permissions. Audit events form a SHA-256 hash chain. This is tamper-evident, not a signed or remote immutable audit log.
- The optional investigator can select only IDs in a local diagnostic catalog. Each selected runbook is re-planned through the normal registry and default-deny policy, then executed as read-only through the normal SSH engine. Minimal Semantic Reply v2 lets the model return a constrained classification, confidence, issued evidence aliases, short explanation, uncertainty, or abstention. Python supplies identity and provenance, and the existing assessment validator remains authoritative. Model output cannot provide commands, change policy, mark evidence verified, approve, or invoke remediation.
- AI is disabled unless `runbookos investigate` is explicitly invoked. Incident text is not persisted; investigation history stores its SHA-256, model metadata, findings, evidence references, and recommendations. Treat the configured model provider as a recipient of the incident and bounded diagnostic evidence.
- Alert ingestion creates or correlates incident records but never starts diagnostics. Operators must acknowledge and explicitly request an investigation. Alert text and metadata remain untrusted data.
- The optional HMAC webhook is foreground-only, loopback-bound, size/concurrency/rate limited, and uses timestamped nonces. It is not a remote or production listener.

## v0.3.2 integrated staging

The Alertmanager adapter remains in RunbookOS. Since generic Alertmanager webhook delivery does not produce the RunbookOS per-source HMAC headers, v0.3.2 adds a separate loopback signing bridge. The bridge requires a staging Basic credential from the configured sender, signs the exact payload with a fresh nonce, and acknowledges only after RunbookOS returns a durable ingestion receipt. It has no incident lifecycle, SSH, AI, or remediation endpoint.

For a disposable local staging area (separate venv/config/secrets/SQLite), use:

```sh
python3 scripts/staging-v032.py init
python3 scripts/staging-v032.py start
python3 scripts/staging-v032.py status
python3 scripts/staging-v032.py stop
```

Generated state is retained under the ignored `.runbookos-staging-v032/` directory. The launcher binds only `127.0.0.1`, refuses to overwrite existing staging data, and does not install a service. See [`docs/staging-acceptance-v0.3.2.md`](docs/staging-acceptance-v0.3.2.md) and [`docs/approval-manifest-v0.3.2.yml`](docs/approval-manifest-v0.3.2.yml). The separate real Alertmanager synthetic acceptance is summarized in [`docs/alertmanager-acceptance-summary-v0.3.2.md`](docs/alertmanager-acceptance-summary-v0.3.2.md); fixture tests do not imply live SSH, Qwen inference, or operational deployment.

## v0.4.1 operator dashboard patch

The optional dashboard is disabled until explicitly started. It reuses the incident store and lifecycle transitions, binds only to `127.0.0.1`, requires an authenticated operator session, and applies CSRF checks to lifecycle POSTs. It supports incident filtering/detail, alert correlation, timeline with status transitions, bounded queue summaries and source, linked investigation/evidence-reference overview, audit-chain status, acknowledgment, resolution, and closure. Investigation execution remains an explicit CLI operation. The dashboard does not execute SSH, AI, runbooks, or remediation. See [`docs/dashboard-patch-v0.4.1.md`](docs/dashboard-patch-v0.4.1.md).

Initialize a local password verifier and start the foreground listener:

```sh
runbookos dashboard auth-init --operator-id alice --auth-file ~/.config/runbookos/dashboard-auth.json
runbookos --db ~/.local/state/runbookos/runbookos.sqlite3 dashboard serve \
  --auth-file ~/.config/runbookos/dashboard-auth.json --port 8780
```

Open `http://127.0.0.1:8780/`. The auth verifier must be a regular file owned by the current account with no group/other permissions. Sessions are memory-only and end on process restart. The listener is plain HTTP on loopback; do not expose it through a network proxy. See [`docs/dashboard-security-v0.4.0.md`](docs/dashboard-security-v0.4.0.md).

## v0.5.0 approved remediation

`systemd.restart` remains disabled by default in shipped policies. A remediation runbook must target one host, contain exactly one registered mutable step, and include assertion-bearing read-only preflight and postflight checks. Review a persisted plan using `runbookos remediation-preview PLAN_ID`, approve it with `runbookos approve`, then separately execute using `runbookos run PLAN_ID --confirm`. The CLI records the local OS operator identity for the explicit confirmation. Approval is one-time, expiring, and bound to the immutable plan and current implementation/configuration fingerprints.

Execution results carry `VERIFIED_SUCCESS`, `VERIFIED_FAILURE`, `UNKNOWN`, or `NOT_EXECUTED`. An uncertain SSH result is never retried, and no automatic rollback is attempted. The dashboard, alerts, and AI cannot invoke remediation. See [`docs/remediation-security-v0.5.0.md`](docs/remediation-security-v0.5.0.md) and the reserved-target example [`examples/runbooks/disposable-systemd-restart.yml`](examples/runbooks/disposable-systemd-restart.yml). The example target is intentionally absent from the shipped inventory and policy.

## v0.6.0 incident-to-remediation review

An operator can associate an existing, current, single-target remediation plan with an incident using `runbookos incidents associate-plan INCIDENT_ID PLAN_ID`. Association records the immutable plan hash, target, registered action, and OS-derived actor; it is not approval and cannot execute the plan. `runbookos incidents remediation-review INCIDENT_ID` presents incident context, linked investigations and evidence references, a revalidated deterministic plan preview, approval state, and previous outcomes. `UNKNOWN` outcomes are called out for independent investigation. Execution remains an explicit CLI action using the existing v0.5.0 approval and confirmation flow. The dashboard only displays associated plan, approval, and outcome context; it has no approval or execution control. Successful remediation never changes incident lifecycle state automatically.

The incident-plan association uses an additive SQLite migration. Historical plans, executions, audit events, benchmark data, and the v0.5.0 disposable-target manifest are retained. That manifest remains `NOT_AUTHORIZED`; this release is offline-validated and does not claim live remediation acceptance.

## v0.7.0 evidence-aware assessment and review

Investigations can persist a versioned `StructuredAssessment` separating direct diagnostic observations from model inferences, hypotheses, classifications, unknowns, and advisory next steps. Deterministic validation checks schema, taxonomy, evidence references, claim constraints, and assertion/verification provenance. Citations establish reference integrity only; semantic support remains unverified unless independently adjudicated. Model-reported confidence is uncalibrated.

The production incident investigation now uses the same Minimal Semantic Reply v2 contract as the offline M3 adapter. Successful assessments are persisted and displayed read-only; provider or contract failures are stored as sanitized failed investigations without raw prompts or model responses. The existing operator workflow does not execute remediation from an assessment.

The M3 evaluator is a separate offline component with a 24-case synthetic held-out dataset. Evaluator reference predictions test metric behavior but are not Qwen outputs. The checked-in M3 evaluation report contains no model predictions; Qwen performance on the held-out cases is **NOT MEASURED**. `runbookos incidents show ID` adds a read-only assessment projection, and the authenticated loopback dashboard displays linked investigations separately. Legacy investigations remain readable with assessment `NOT AVAILABLE`. Neither view starts diagnostics, AI, SSH, approval, or remediation. See the [M1/M2 completion](docs/v0.7.0-m1-m2-completion.md), [M3 evaluation report](docs/v0.7.0-m3-evaluation-report.md), and [M4 completion](docs/v0.7.0-m4-completion.md).

## Install

Requirements: Python 3.11+, OpenSSH client (`ssh`, `ssh-keygen`), and Linux targets with Python 3. Ubuntu 24.04 works with its system Python.

```sh
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -e '.[dev]'
runbookos version
```

The default inventory uses reserved documentation addresses from `192.0.2.0/24` and cannot connect to real services. It contains generic web, application, database, and gateway aliases for planning examples. Copy the example inventory/policy and edit them for a trusted environment. The dependency-readiness example remains denied until an operator adds exact probe endpoints and policy allows. Keep private keys outside the repository and set strict permissions (`0600`). Configure a pinned host key in a dedicated `known_hosts` file after verifying its fingerprint over a trusted channel; RunbookOS never learns or accepts host keys automatically.

The read-only Network/DNS/TLS example (`examples/runbooks/network-dns-tls-review.yml`) also requires a private inventory `probe_targets.service_health` entry with fixed `protocol: https`, private IPv4 `address`, `port`, fixed `path`, `dns_name`, and private IPv4 `resolver_address`. The matching host policy must allow both the action IDs and `allowed_probe_targets: [service_health]`. The shipped inventory deliberately omits an executable endpoint. DNS compares A records with the configured address; TLS connects to that address and verifies the configured name with the system trust store. Neither result alone establishes an incident root cause.

```sh
export RUNBOOKOS_SSH_KEY="$HOME/.ssh/runbookos-readonly"
export RUNBOOKOS_KNOWN_HOSTS="$HOME/.ssh/runbookos_known_hosts"
runbookos inventory
runbookos validate examples/runbooks/web-server-health.yml
runbookos --inventory config/inventory.yml --policy config/policy.yml \
  --ssh-profiles config/ssh_profiles.yml plan examples/runbooks/web-server-health.yml
```

`plan` persists and prints an ID without connecting to a target. `check` creates a plan and runs it only if all actions are read-only and policy-allowed. For a policy-allowed remediation, inspect the exact plan, then explicitly approve and run it:

```sh
runbookos approve PLAN_UUID --reason "Change ticket and maintenance window"
runbookos run PLAN_UUID
```

Approvals expire based on policy (15 minutes by default), apply only to the immutable plan hash, and are consumed once. The approval actor is the local OS username. RunbookOS does not provide multi-person approval, MFA, external identity, or a cryptographically signed audit trail.

## CLI

All config locations can be overridden before the command using `--inventory`, `--policy`, `--ssh-profiles`, and `--db`.

| Command | Purpose |
|---|---|
| `runbookos validate FILE` | Validate version, fields, phase safety, and registered actions |
| `runbookos inventory` | List target aliases, addresses, roles, and SSH profiles |
| `runbookos plan FILE [--param name=value]` | Resolve targets and show allow/deny/approval decisions; no SSH |
| `runbookos check FILE` | Run a read-only diagnostic after policy checks |
| `runbookos approve PLAN_UUID --reason TEXT` | Record human approval for allowed remediation |
| `runbookos run PLAN_UUID` | Run a ready plan or an approved remediation plan |
| `runbookos history [EXECUTION_UUID]` | View execution summaries and step evidence |
| `runbookos investigate --incident-file FILE` | Select and run bounded read-only diagnostics, then produce a cited investigation |
| `runbookos investigate --incident-stdin` | Same workflow with incident text read from stdin |
| `runbookos investigations` | List investigation history without incident descriptions |
| `runbookos scenarios list` | List validated synthetic incident scenarios |
| `runbookos scenarios validate` | Validate scenario schemas and fixture references |
| `runbookos evaluate --provider mock --repeat 3` | Run an offline scripted fixture benchmark |
| `runbookos evaluate --provider configured --provider-config CONFIG.yml` | Opt-in model evaluation over synthetic evidence |
| `runbookos evaluate-v2 --provider mock --repeat 3` | Offline taxonomy-v2 evaluator harness |
| `runbookos evaluate-v2 --provider configured --provider-config CONFIG.yml` | Structured Qwen/provider benchmark over synthetic evidence |
| `runbookos evaluation report DATASET.json` | Render the Markdown report for a saved dataset |
| `runbookos audit` | Verify the local audit hash chain |
| `runbookos tunnel CONFIG.yml` | Start an explicit foreground SSH tunnel bound to controller loopback |
| `runbookos alerts ingest FILE|-` | Validate and ingest one bounded JSON alert; stdin is supported |
| `runbookos alerts list` | List stored alerts without full metadata payloads |
| `runbookos incidents list/show/timeline` | Inspect incident state, sources, actions, evidence linkage, and timeline |
| `runbookos incidents acknowledge ID --reason TEXT` | Acknowledge a new incident explicitly |
| `runbookos incidents investigate ID --runbook FILE` | Run one exact-target policy-allowed read-only runbook |
| `runbookos incidents investigate ID --ai-config FILE` | Explicitly run target-filtered AI diagnosis through the existing engine |
| `runbookos incidents resolve ID --reason TEXT --evidence-status STATUS` | Resolve with linked evidence or explicit operator attestation (`verified`, `not_available`, `inconclusive`) |
| `runbookos incidents close ID --reason TEXT` | Close a resolved incident |
| `runbookos webhook serve --auth-config FILE` | Optional foreground, per-source HMAC webhook on `127.0.0.1`; secrets come from named environment variables |

Runbooks contain `preflight`, `steps`, and `postflight`; checks in preflight/postflight must use read-only actions. A failed preflight stops the plan. The first failed or uncertain action stops subsequent steps. Postflight runs only if earlier actions succeeded.

See [alert and incident workflow docs](docs/alert-incident-workflow-v0.3.0.md), [per-source authentication and rotation](docs/webhook-authentication-v0.3.1.md), [staging/recovery procedures](docs/deployment-recovery-v0.3.1.md), and the [security model](docs/security.md).

## Action registry in v0.2.3

Read-only actions include `systemd.is_active`, `systemd.failed_units`, `os.uptime`, `os.memory`, `os.disk`, `network.interfaces`, `network.routes`, `network.tcp_connect`, `network.reachability`, `http.readiness`, and `postgresql.protocol_available`. **`network.reachability` currently means TCP-based reachability to one configured endpoint; it does not perform ICMP, route tracing, or path diagnosis.** Network probes accept only an inventory endpoint ID with an additional per-host policy allow; endpoint addresses must be private IPv4 literals. `systemd.restart` remains the only registered mutating action. It is denied by the shipped policies, requires a per-host remediation policy allow and explicit approval, and runs as the configured SSH user without sudo. If the operating system denies it, RunbookOS will not expand privileges.

## Configuration

- `config/inventory.example.yml`: target endpoints, SSH user, role, and SSH profile alias.
- `config/policy.example.yml`: default-deny diagnostic/remediation and unit allowlists.
- `config/ssh_profiles.example.yml`: identity path, host key store, and bounded connection timeouts; paths can use exact `${ENV:NAME}` references.
- `examples/runbooks/`: web, application, database, and gateway read-only examples.

AI configuration is in `config/investigation.example.yml`; the provider example points to loopback `http://127.0.0.1:8080/v1`. The tunnel command disables user SSH config, password authentication, agent forwarding, shell, TTY, and all unspecified forwards. The host's `llama-server` must bind to loopback and require an API key. No model is installed on the controller. Lab-specific inventory, tunnel configuration, and provisioning artifacts are not shipped in release packages.

See [architecture](docs/architecture.md), [AI investigation](docs/ai-investigation.md), [runbook schema](docs/runbook-schema.md), [security model](docs/security.md), and [operations](docs/operations.md).

## Offline operator demo

The demo creates a fresh temporary SQLite database, inserts a clearly labeled synthetic incident and assessment through the existing constructors, displays the incident through the CLI, and starts the existing authenticated dashboard on loopback. It performs no provider request, diagnostic, SSH connection, or remediation. Run it from a terminal and use Ctrl-C to stop the owned dashboard and remove temporary state:

```sh
.venv/bin/python scripts/operator-demo-v070.py
```

The script asks for a temporary dashboard password without echoing it, prints the incident ID and loopback URL, and cleans up its temporary database and credentials after shutdown. See [`docs/operator-demo-v0.7.0.md`](docs/operator-demo-v0.7.0.md).

Incident fixtures and metric definitions are documented in [incident simulation and evaluation](docs/incident-evaluation.md). The offline scripted provider is only a harness check; fixture results are not evidence of AI accuracy on real incidents. `config/evaluation.qwen.example.yml` shows the optional local provider config. Bounded probe target setup and signal interpretation are documented in [diagnostic actions](docs/diagnostic-actions-v0.2.3.md). Fault injection is not implemented, and no homelab service is modified by `evaluate`.

The host tunnel provisioning, public-key export, and rollback scripts in the development checkout are **LAB-ONLY** and are not part of normal installation or release artifacts. The operator-provisioning guide and detailed lab acceptance evidence are retained in the development repository, not the portable release documentation. For v0.2.5, all four explicitly approved probes succeeded: PostgreSQL TCP connectivity, PostgreSQL SSLRequest protocol availability, HTTP `/healthz` readiness, and TCP/80 reachability. Temporary self-SSH access used for web probes was rolled back after acceptance.

## Test and build

```sh
pytest -q
pytest --cov=runbookos --cov-report=term-missing
python -m build
```

The default SSH integration tests use a local fake `ssh` binary and temporary ED25519 keys; they do not connect to a live host. Homelab live suites are opt-in through environment variables and are not part of unattended CI or the portable release package.
