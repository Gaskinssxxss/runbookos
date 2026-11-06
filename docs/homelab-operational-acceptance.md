# Homelab operational acceptance (local record)

Observation date: 2026-10-27, Asia/Makassar. This is a local operational record,
not a portable example or a production-readiness claim. Internal IP addresses,
host-key fingerprints, disk paths, and UUIDs are intentionally omitted.

## Hypervisor and topology

Read-only libvirt inspection of `qemu:///system` found the five intended
`runbookos-*` domains running, persistent, and configured for autostart.
`qemu:///session` contained no domains. A separate `portfolio-demo-01` domain
was shut off and was not inspected or changed. The five disks are qcow2 files
with seed ISOs under the active `runbookos` directory storage pool. No libvirt
snapshots or managed-save images were listed. A separate backup/restore path
was not verified.

Guest identities and addresses were read through the existing QEMU Guest Agent
and matched each domain's configured NIC MAC and the acceptance inventory:

| VM | Guest interface / role | Current state |
|---|---|---|
| `ops-01` | `mgmt0`, controller | Running |
| `svc-web-01` | `svcs0`, web | Running |
| `svc-app-01` | `svcs0`, application | Running |
| `db-01` | `db0`, database | Running |
| `net-01` | `wan0`, `mgmt0`, `svcs0`, `db0`, gateway | Running |

The `rbo-mgmt`, `rbo-services`, and `rbo-db` libvirt networks are active,
persistent L2 networks. Their bridges have no configured host IP/DHCP service.
The controller's default route uses `net-01`; web/application/database guests
use their corresponding `net-01` interface as their default gateway. `net-01`
has IPv4 forwarding enabled and a default-drop nftables forward chain with
explicit narrow rules for controller SSH to managed nodes, the registered
application-to-database protocol path, and selected outbound DNS/web traffic.
Outbound traffic from the lab networks is masqueraded through `wan0` to the
libvirt NAT network. Losing `net-01` would remove the controller's routed path
to all three managed-node segments. No route, bridge, or firewall setting was
changed.

The physical host has the system libvirt scope and the active storage pools.
VM images are therefore host-level libvirt storage, not files inside this Git
repository. The exact host paths and domain UUIDs are retained only in local
libvirt metadata.

## Controller and identity

The controller guest hostname matched `runbookos-ops-01`. It has a separate
RunbookOS 0.6.0 acceptance virtual environment at
`/var/lib/runbookos/acceptance-v060/`; the CLI reports `RunbookOS 0.6.0`.
Its inventory, default-deny policy, SSH profile, four target runbooks, and
schema-v4 acceptance database are under that owner-only acceptance tree. The
controller account is `runbookos`; the isolated root/config/state directories
are mode 0700 and the database is mode 0600. Its SSH private identity is mode
0600 and was not read. The pinned known_hosts file is mode 0600.

For each managed target, the ED25519 host public-key fingerprint read from the
guest through QGA matched the corresponding entry in the controller's pinned
known_hosts file. No key was accepted or replaced. RunbookOS's SSH dispatcher
uses strict host-key checking, identity-only authentication, and bounded
timeouts. Successful diagnostics below also confirm authentication using the
configured `runbookos` target account. No account, key, or privilege was
changed.

The current repository checkout is v0.7.0 source on the expected feature
branch, but it has uncommitted changes. It is not the installed controller
release. No deployment of that checkout to `ops-01` was performed. The host's
repository virtual environment reports v0.7.0; that is not a controller
service deployment.

## RunbookOS read-only diagnostic acceptance

Before connecting, the four inventory aliases, role mappings, runbooks, and
policy were read through RunbookOS/config parsing. Policy uses
`default_decision: deny`, permits only `systemd.is_active` for these targets,
and grants no remediation actions. Each validated runbook has one action with
a 10-second action timeout and an exact unit parameter. The following commands
were executed serially by the RunbookOS 0.6.0 CLI on `ops-01`, as the
`runbookos` OS account, using the isolated acceptance files:

```sh
runbookos --inventory "$ACCEPTANCE_ROOT/config/inventory.yml" \
  --policy "$ACCEPTANCE_ROOT/config/policy.yml" \
  --ssh-profiles "$ACCEPTANCE_ROOT/config/ssh_profiles.yml" \
  --db "$ACCEPTANCE_ROOT/state/acceptance.sqlite3" \
  check "$ACCEPTANCE_ROOT/config/runbooks/check-svc-web-01.yml"

runbookos --inventory "$ACCEPTANCE_ROOT/config/inventory.yml" \
  --policy "$ACCEPTANCE_ROOT/config/policy.yml" \
  --ssh-profiles "$ACCEPTANCE_ROOT/config/ssh_profiles.yml" \
  --db "$ACCEPTANCE_ROOT/state/acceptance.sqlite3" \
  check "$ACCEPTANCE_ROOT/config/runbooks/check-svc-app-01.yml"

runbookos --inventory "$ACCEPTANCE_ROOT/config/inventory.yml" \
  --policy "$ACCEPTANCE_ROOT/config/policy.yml" \
  --ssh-profiles "$ACCEPTANCE_ROOT/config/ssh_profiles.yml" \
  --db "$ACCEPTANCE_ROOT/state/acceptance.sqlite3" \
  check "$ACCEPTANCE_ROOT/config/runbooks/check-db-01.yml"

runbookos --inventory "$ACCEPTANCE_ROOT/config/inventory.yml" \
  --policy "$ACCEPTANCE_ROOT/config/policy.yml" \
  --ssh-profiles "$ACCEPTANCE_ROOT/config/ssh_profiles.yml" \
  --db "$ACCEPTANCE_ROOT/state/acceptance.sqlite3" \
  check "$ACCEPTANCE_ROOT/config/runbooks/check-net-01.yml"
```

`ACCEPTANCE_ROOT` refers only to the existing isolated controller directory;
the commands above do not use the production/default database. Actual execution
IDs and evidence were retained in that database:

| Target | Registered action | Observation | Execution ID |
|---|---|---|---|
| `svc-web-01` | `systemd.is_active` / `nginx.service` | active = true | `42f798bf-dbf5-4074-91f1-8fca20c293bb` |
| `svc-app-01` | `systemd.is_active` / `runbookos-sample.service` | active = true | `fb2c177a-3bfa-46b1-a530-2358f0eb2b16` |
| `db-01` | `systemd.is_active` / `postgresql.service` | active = true | `f775a546-c695-45c2-9efd-9bb519d935ab` |
| `net-01` | `systemd.is_active` / `nftables.service` | active = true | `c922ab85-e9d1-4be3-9f4a-04ca221e4b3f` |

These are current service-manager observations only. They do not establish HTTP
application health, API dependency health, authenticated PostgreSQL readiness,
general network reachability, or production incident cause. The configured
policy does not currently permit broader actions, so none were attempted.

## Persistence and safety

- Existing acceptance DB: schema v4; read-only SQLite `integrity_check` was
  `ok`, `foreign_key_check` returned zero violations.
- RunbookOS audit command: `AUDIT OK: 32 hash-chained events` after the four
  current checks. The DB contains eight total plans/executions: four earlier
  acceptance executions and these four new ones. Historical rows were not
  rewritten; new runbook executions appended evidence and audit events.
- The acceptance DB has no incidents or investigations. No outage was
  fabricated, and no AI assessment was run against these operational
  observations.
- All four commands completed successfully; no retry was made. All selected
  services were active. No remediation, approval, restart, service/config
  mutation, VM lifecycle operation, or network change occurred.
- A loopback listener was observed on port 8080; its owner was not established
  and it was not contacted. The isolated controller configuration contains no
  AI provider file. Port 18080 was free at inspection. No model server was
  started and no inference request was sent.

## Verdict

The five-VM inventory, guest identity, system-libvirt location, routed topology,
strict SSH pins, and four registered read-only service checks are verified for
this observation. End-to-end real-evidence Qwen assessment, application-level
health checks, deployment of v0.7.0 to the controller, backup/restore, and live
remediation remain unverified or unauthorized. Keep this environment-specific
record out of public release artifacts unless separately sanitized and
approved.
