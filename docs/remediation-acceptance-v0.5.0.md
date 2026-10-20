# RunbookOS v0.5.0 remediation acceptance walkthrough

This is an offline/operator workflow description. The shipped example target is absent from the default inventory and policy, so planning it against defaults must be denied until an operator prepares a separate disposable-only configuration.

```sh
runbookos --inventory disposable-inventory.yml \
  --policy disposable-policy.yml \
  --ssh-profiles disposable-ssh.yml \
  --db ./disposable-acceptance.sqlite3 \
  plan examples/runbooks/disposable-systemd-restart.yml

runbookos --inventory disposable-inventory.yml \
  --policy disposable-policy.yml \
  --ssh-profiles disposable-ssh.yml \
  --db ./disposable-acceptance.sqlite3 \
  remediation-preview PLAN_ID

runbookos --inventory disposable-inventory.yml \
  --policy disposable-policy.yml \
  --ssh-profiles disposable-ssh.yml \
  --db ./disposable-acceptance.sqlite3 \
  approve PLAN_ID --reason 'Reviewed disposable service restart'

runbookos --inventory disposable-inventory.yml \
  --policy disposable-policy.yml \
  --ssh-profiles disposable-ssh.yml \
  --db ./disposable-acceptance.sqlite3 \
  run PLAN_ID --confirm
```

Before the final command, the operator must review the exact target, policy decision, action parameters, impact, preconditions, postflight checks, rollback statement, plan hash, and approval expiry. The engine rechecks all source/configuration/implementation fingerprints and audit integrity. A failed preflight prevents dispatch. Unknown mutable execution is never retried. Inspect `history EXECUTION_ID` and verify `audit` afterward.

Do not substitute any of the five operational homelab VMs. Live acceptance requires separate explicit authorization and a target-specific manifest approval. No VM provisioning or privilege changes are authorized by this document.
