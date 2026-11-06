# RunbookOS functional acceptance

**Verdict: `RUNBOOKOS_FUNCTIONAL_ACCEPTANCE_INCOMPLETE`**

The existing controller has an isolated v0.7.0 installation and has executed
real, policy-allowed, read-only diagnostics against all four managed nodes.
That is useful operational evidence, but the mandatory Qwen, HTTP/protocol,
incident-assessment, fault-injection, remediation, and operational recovery
cases did not all pass. No failed or skipped case is counted as a pass.

## Execution identity and scope

- Repository: `/home/morphious/united/runbookos`
- Branch / HEAD: `feat/v0.7.0-evidence-aware-assessment` /
  `d68197c3ac37336e1b9bfa8d66059e5eb8ecd001`
- Hypervisor scopes: five existing RunbookOS guests are running in
  `qemu:///system`; `qemu:///session` has no guests. The unrelated shut-off VM
  was left alone.
- Controller: `ops-01`. Existing isolated v0.6.0 remains installed at
  `/var/lib/runbookos/acceptance-v060/`; its CLI still reports 0.6.0 and its
  SQLite database remains schema 4, integrity `ok`, 32 audit events, mode 0600.
- Isolated v0.7.0 installation: `/var/lib/runbookos/acceptance-v070/`, owned by
  `runbookos`, private root/config/state directories mode 0700, config/database
  files mode 0600. It was installed from a checksum-verified wheelhouse, without
  network access from the guest. CLI reports 0.7.0.
- Installed RunbookOS wheel SHA-256:
  `b278b093fc88d539fb3dba4438c8891af791129dc348f75cc449b0851ad836dc`.
- v0.7.0 uses a new schema-v4 SQLite DB; the v0.6.0 DB was not copied or opened
  for writes. No service unit was installed or started.
- The Git index is empty. No commit or publication occurred. Existing unrelated
  worktree files and historical acceptance evidence remain in place.

## Actual homelab execution

The v0.7.0 RunbookOS engine ran plans using the copied, previously verified
inventory, strict SSH profiles, pinned host keys, and a v0.7.0-only default-deny
policy. The policy enabled only registered read-only actions for these exact
aliases and left every remediation list empty. All plans were serial and
target-scoped. No SSH command was supplied by AI, no service was changed, and no
diagnostic was retried after a failure.

| Target | Real observations executed through v0.7.0 | Result |
|---|---|---|
| `svc-web-01` | Nginx unit state; failed-unit list; uptime, memory, root-disk, interfaces and routes | Core run succeeded; Nginx unit active. Bounded journal attempt failed closed (`command_failed`). |
| `svc-app-01` | Sample application unit state; failed-unit list; uptime, memory, root-disk, interfaces and routes | Core run succeeded; application unit active. Bounded journal attempt failed closed (`command_failed`). |
| `db-01` | PostgreSQL unit state; failed-unit list; uptime, memory, root-disk, interfaces and routes | Core run succeeded; PostgreSQL unit active. Bounded journal attempt failed closed (`command_failed`). |
| `net-01` | nftables unit state; failed-unit list; uptime, memory, root-disk, interfaces, routes and resolver configuration metadata | All eight steps succeeded; nftables unit active. Resolver metadata is not a DNS resolution test. |

The journal failures do not expose underlying stderr, so the exact cause is
**unknown** (for example, journal permissions or a command failure). I removed
`systemd.journal_tail` from the isolated v0.7.0 policy after observing this
failure. I did not add the controller account to privileged groups or otherwise
expand guest privileges. HTTP readiness, application API/dependency health,
PostgreSQL protocol/authentication, and TCP listener checks remain unverified:
the verified inventory had no endpoint IDs or probe targets, and I did not guess
ports or paths.

Across the isolated v0.7.0 DB there are 11 plans, 11 executions (8 succeeded,
3 failed), 42 step results (39 succeeded, 3 failed), zero approvals, zero
remediation plans, zero incident rows, and zero investigation rows. The three
failed journal results remain failed. SQLite reports schema 4, integrity `ok`,
zero foreign-key violations. `runbookos audit` verifies the 75-event hash chain.
No incident was fabricated to make this acceptance look complete.

## Functional acceptance matrix

`PASS` denotes observed evidence in the stated environment. `NOT_VERIFIED`
denotes work not performed. `BLOCKED` denotes a concrete missing prerequisite or
authorization. Mock tests are called out explicitly and do not count as live
execution.

| Requirement | Environment / evidence | Result |
|---|---|---|
| Five VM identities and topology | Read-only system-libvirt and guest identity review; all five intended VMs running; net gateway relationships recorded in local homelab evidence | PASS |
| v0.7.0 controller runtime | Isolated venv on `ops-01`; package hash verified; CLI version/help passed | PASS (isolated install only) |
| Preserve v0.6.0 rollback option | Old CLI still 0.6.0; old DB still schema 4 / 32 audit events / integrity `ok`; separate prefix and DB | PASS (preservation); service rollback untested because no controller service was installed |
| Inventory and role mapping | Existing inventory copied unchanged into v0.7 config; plans matched exact role aliases | PASS |
| SSH identity and pinned host keys | Existing pinned profile used by real RunbookOS executions; previously observed target key matches retained | PASS (the exercised hosts/actions only) |
| Read-only service state | Real `systemd.is_active` on all four targets; all true | PASS |
| Additional host state | Real `systemd.failed_units`, uptime, memory, disk, interfaces/routes on all four targets | PASS for recorded executions |
| Nginx HTTP readiness / failure behavior | No verified HTTP endpoint ID/path; no outage injected | NOT_VERIFIED |
| Application API and DB dependency | No verified API endpoint or dependency probe; no failure injected | NOT_VERIFIED |
| PostgreSQL protocol, auth failure, exhaustion, storage and restore | No protocol target configured; no disposable DB/service instance designated | BLOCKED |
| Network DNS query / packet-delivery cases | Resolver configuration and route metadata read; no DNS query, TCP probe, packet capture, or isolated topology test | NOT_VERIFIED |
| Journal inspection | Three actual bounded attempts failed with sanitized `command_failed`; no privilege expansion; removed from v0.7 policy | FAIL (diagnostic unavailable under current least privilege) |
| Real evidence provenance and audit | 39 successful and 3 failed step records persisted in new DB; 75-event chain verified | PASS for those records |
| Incident intake linked to real evidence | No active/reportable incident; zero incident/investigation rows; no false outage created | NOT_VERIFIED |
| Real Qwen assessment on collected evidence | Host model/runtime hashes match recorded values; API-key file mode 0600; host memory was about 18.4 GiB and 18080 was free at inspection. No server started and no secret transferred. The controller-to-host provider path requires an approved tunnel or network path; the prior TCP/22 attempt timed out. | BLOCKED |
| Assessment schema, aliases, abstention and invalid-output handling | Offline v2 contract/validator regression suite | PASS (mock/offline only) |
| Persisted assessment and CLI/dashboard consistency | Offline synthetic integration/demo tests; live v0.7 DB has no incident to display | PASS (synthetic only); live NOT_VERIFIED |
| Dashboard authentication/session behavior | Existing authenticated dashboard tests | PASS (offline only); live controller dashboard not started |
| Default-deny and action binding | Real plans were checked before execution; only explicitly allowed read-only actions ran; no mutable action or approval row | PASS (observed read-only scope) |
| Remediation proposal, approval, replay/expiry, execution and postflight | Existing isolated/mock regression tests; no real remediation or disposable workload authorized by identity | PASS (offline controls only); live NOT_VERIFIED |
| No unauthorized mutation | No service, database workload, firewall, route, VM, account, key, or infrastructure mutation; no model-generated action | PASS for this execution |
| SQLite backup/restore | Disposable schema-v4 test preserves incident/investigation/assessment/audit state and integrity | PASS (disposable test only); ops recovery NOT_VERIFIED |
| Startup, supervision, crash recovery and rollback | CLI smoke passed; no system service or rollback drill installed | NOT_VERIFIED |
| Wheel/sdist, fresh install, portability | Both artifacts built and installed in temporary environments; import, version and help passed; package excludes approval files and local Qwen runner | PASS |
| Dependency audit | `pip-audit` against current lock: no known vulnerabilities | PASS (tool/database snapshot) |
| Secret scan | `detect-secrets` 1.5.0 on sdist: five raw findings reviewed as runtime-generated or synthetic; zero unresolved real-secret findings | PASS (reviewed artifact scope) |
| Full offline tests | `.venv/bin/pytest -q`: 324 passed, 11 opt-in live tests skipped | PASS offline; skips are not live passes |
| Ruff and whitespace | Ruff lint and changed-Python format passed; `git diff --check` passed. Full-tree formatter reports one pre-existing untracked Markdown code example. | PASS scoped; repo-wide format gate NOT_VERIFIED |

## Failure ledger and blockers

1. **Provider path not authorized/available from controller.** The local model
   is configured to bind loopback on the physical host. Connecting `ops-01` requires a
   tunnel or an approved network path and secure API-key provisioning. No tunnel
   was started and no key was transferred. Until that exact path is authorized,
   live Qwen acceptance cannot run through the controller.
2. **Probe endpoints are missing from verified inventory.** HTTP, TCP, and
   PostgreSQL protocol checks need exact per-target address/port/path entries
   and matching policy allowances. No endpoint was inferred from convention.
3. **System journal permission is insufficient.** Three attempts failed; raw
   stderr is intentionally not persisted. Do not grant broad journal privileges
   until an operator approves the exact data/permission scope.
4. **No expendable workload or recovery channel is designated.** No fault
   injection, service stop/restart, database stress, network fault, remediation,
   rollback, or operational backup/restore was performed. `net-01` was not
   modified.
5. **No real incident was active.** The real evidence is from healthy read-only
   checks, not a fault incident; no incident or diagnosis was fabricated.
6. **Controller operation is an isolated CLI install, not a supervised service.**
   Startup supervision, restart behavior, deployment rollback, and production
   configuration remain unverified.

These are mandatory gaps; the platform does not meet 100% functional acceptance.

## Reproduction and next authorized operations

The installed v0.7.0 health/audit command on `ops-01` is:

```sh
sudo -u runbookos /var/lib/runbookos/acceptance-v070/venv/bin/runbookos \
  --inventory /var/lib/runbookos/acceptance-v070/config/inventory.yml \
  --policy /var/lib/runbookos/acceptance-v070/config/policy.yml \
  --ssh-profiles /var/lib/runbookos/acceptance-v070/config/ssh_profiles.yml \
  --db /var/lib/runbookos/acceptance-v070/state/runbookos.sqlite3 audit
```

An operator must separately approve the exact tunnel source/destination, pinned
host identity, forwarding endpoint, API-key provisioning path, and live
inference budget before configuring Qwen. Separate target-specific approval is
required to add probe endpoint IDs, inspect system journals, or inject faults.
Remediation needs an explicitly expendable target and a distinct action/parameter
approval. No approval manifest was changed, and the repository was not staged
or committed.
