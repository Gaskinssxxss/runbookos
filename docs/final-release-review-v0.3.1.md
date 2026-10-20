# RunbookOS v0.3.1 — Final Release Review

**Review date:** 2026-10-20
**Scope:** Offline source hardening, packaging, release hygiene, and an initial-commit candidate review. No source was staged or published. No homelab VM, SSH identity, firewall, route, service, operational SQLite database, or live probe was touched.

## Executive decision

**Recommendation: safe for an initial Git commit only when selected from the explicit allowlist in [`release-staging-manifest-v0.3.1.md`](release-staging-manifest-v0.3.1.md).** This is a source-baseline recommendation, not deployment or production approval. Do not stage the whole workspace: it contains ignored local reports and lab-only material that must remain out of a public baseline.

No files were staged. No commit, tag, remote, push, or publication was created. The working branch is `main`, and the repository has no commits yet, so there is no prior Git diff to review.

## Conformance findings closed

The closeout below updates the earlier evidence snapshot in [`architecture-conformance-audit-v0.3.1.md`](architecture-conformance-audit-v0.3.1.md):

| Finding | Implemented change and evidence | Result |
|---|---|---|
| SSH output could grow without bound before validation | `src/runbookos/ssh.py` reads stdout/stderr incrementally with caps of 256 KiB and 16 KiB. Overflow and timeout terminate the SSH process group with bounded cleanup. Invalid, truncated, or uncertain remote results become `ExecutionUnknown`; no retry is performed. | Covered by fake-SSH output flood, process termination, timeout, malformed JSON, and partial response tests. |
| `known_hosts` integrity was not validated | SSH adapter rejects a final-path symlink, non-regular file, untrusted owner, and group/world-writable permissions. Legitimate read-only modes such as 0644 remain accepted. | Filesystem regression tests cover accepted 0644 and rejected unsafe mode, symlink, and owner. |
| Approval could survive action implementation semantic drift | Plan source identity includes package/action/core/dispatcher implementation fingerprints. A changed implementation invalidates the saved plan before consuming approval. | Regression test confirms stale approved plan is denied; operator must plan and approve again. |
| Incident resolution did not declare evidence status | Resolve requires explicit `--evidence-status`: `verified`, `not_available`, or `inconclusive`. Verified resolution requires linked verified evidence; other statuses are recorded as operator attestations with reason and are not represented as evidence verification. | Tests cover evidence-linked resolution, explicit attestation, and rejection of a forged verified claim. |
| Documentation/action semantics and homelab scope were unclear | README records all four approved v0.2.5 probes as succeeded and states `network.reachability` is TCP-based, not ICMP or route tracing. Existing public action IDs are retained. Tunnel provisioning scripts are marked LAB-ONLY; rollback guidance remains preserved locally. | Text/configuration review; no infrastructure scripts were run. |
| Public package candidate mixed portable and lab-specific files | Generic example aliases and documentation ranges are used in portable examples. Packaging uses explicit safe configuration/documentation inclusion and excludes homelab config, private acceptance data, SQLite state, reports, and lab-only scripts/tests. | Wheel/sdist inventory and staging allowlist reviewed. |
| Fresh package version parity and CI dependency/action pinning were missing | Added Python 3.12 CI/tooling constraints and pinned CI actions to immutable commit SHAs. Fresh wheel and sdist environments report consistent package metadata, imported version, and CLI version `0.3.1`. | Fresh-install checks passed. The repository-local `.venv` remains stale and was not altered. |

Historical benchmark datasets were preserved. No report, state database, or prior audit evidence was deleted or overwritten.

## Verification results

### Tests and code quality

- Current full workspace: **107 passed, 11 skipped**. Skips are opt-in live homelab/probe/AI/tunnel tests; they were not run.
- Sanitized clean source candidate: **106 passed, 0 skipped**. Live-only tests are excluded from the public candidate.
- Extracted sdist: **106 passed**.
- `ruff check` and `ruff format --check`: passed on source/tests.
- CLI smoke: `runbookos --help`, `runbookos version`, and `runbookos incidents resolve --help` passed in fresh package environments.
- `git diff --check` and candidate trailing-whitespace checks: passed. Because all candidate files are untracked, `git diff --check` alone does not inspect their contents; the clean candidate whitespace check covers them.
- No remote CI workflow was executed. The above are local checks.

The test results are offline. They do not assert current VM health or prove live homelab integration in this release review.

### Fresh install and version parity

Fresh Python 3.12 environments were used for both built artifacts:

| Install source | Package metadata | Imported `runbookos.__version__` | CLI | Result |
|---|---:|---:|---:|---|
| Wheel | 0.3.1 | 0.3.1 from installed site-packages | 0.3.1 | Pass |
| Extracted sdist | 0.3.1 | Installed source | 0.3.1 | Pass; sdist tests pass |

The pre-existing repository `.venv` still reports installed distribution metadata version **0.1.0** while its editable import and CLI resolve to source version **0.3.1**. This stale environment was deliberately left untouched. It is ignored and excluded from artifacts. Do not use it to identify the installed version on any homelab VM; no current remote installed-version check was performed.

### Build artifacts and integrity

Artifacts were built from the sanitized candidate copy, not from operational state:

| Artifact | Size | Contents | SHA-256 |
|---|---:|---|---|
| `runbookos-0.3.1-py3-none-any.whl` | 90,809 bytes | 50 members, including 21 Python modules; no homelab configuration | `48bc5d92e11806212f9ce1ca0d2c4a421ed43a24053ff8ae03386455037e4921` |
| `runbookos-0.3.1.tar.gz` | 121,958 bytes | 93 members, including 11 test Python files and 12 portable docs; no homelab paths, reports, SQLite, or authorized_keys | `2a38fbe86a50de0b040b279235eecf9604fe171a6758a368fbd3354579efe69e` |

Artifact hashes are integrity identifiers for these local builds, not signatures or provenance attestations. A signed artifact and trusted build provenance remain open release-process work.

### Secret and candidate scan

The explicit portable candidate was scanned with `detect-secrets 1.5.0`; final scanner output contained **zero findings**. Initial heuristic hits were reviewed: environment-variable names and a deliberately invalid URL in tests were false positives, while a hex-like example alert fingerprint was replaced with a visibly synthetic value. Intentional test/config identifiers carry narrowly scoped scanner allowlist comments. A manual check of the same candidate found no private-key blocks, real SSH tunnel fingerprint, lab host addresses, controller-specific filesystem paths, or operational SQLite/raw live evidence. Synthetic test secrets and addresses remain non-operational fixtures.

The scan is a point-in-time review of allowlisted candidate files, not a guarantee that future additions are safe. Re-run it against the exact operator-selected staging set before the first commit. Ignore rules cover environments, keys, certificates, `known_hosts`, `authorized_keys`, secret overlays, SQLite and WAL/SHM, backups, reports, generated artifacts, homelab configuration, and lab tunnel scripts.

## Initial Git staging manifest

The proposed candidate comprises **80 files** after this review document is included; validate the current manifest before staging. Exact paths are listed in [`release-staging-manifest-v0.3.1.md`](release-staging-manifest-v0.3.1.md). Candidate groups are:

- Root metadata, license, packaging metadata, and CI lock/configuration.
- Pinned CI workflow.
- `src/runbookos/**/*.py` runtime source.
- Generic `config/*.example.yml` and `*.example.json` configurations.
- Generic alert/runbook examples and synthetic incident scenarios.
- Portable product, security, deployment, and release documentation.
- Unit, security, integration, CLI, and fake-SSH tests.

The manifest excludes lab-specific config, tunnel provisioning/export/rollback scripts and operator rollback material, opt-in live homelab tests, private endpoint approval records, local reports/evidence, raw model benchmark outputs, SQLite databases, credentials/keys, caches, build output, and virtual environments. The four successful v0.2.5 probe results are summarized in portable README/report text; sensitive operational detail stays local.

`LICENSE`, README, security documentation, generic configuration examples, and portable test suite are present. There is no `SECURITY.md` disclosure policy file; security practices are documented in `docs/security.md`. Add a separate disclosure contact/policy only when maintainers provide an address and response process—do not invent one for the release.

## Supply-chain and remaining findings

- CI actions are pinned to full commit SHAs. These pins correspond to checkout v4.2.2 and setup-python v5.6.0; local CI validation uses the pinned Python 3.12 tooling lock. The lock is intentionally scoped to the CI/tooling environment rather than a universal cross-platform runtime lock.
- CI checks wheel/sdist contents and reports hashes. No signed provenance/SBOM is generated, and remote CI execution was not observed.
- The HMAC webhook has offline authentication/replay/rotation tests but no real monitoring sender has been accepted in this milestone.
- Live SSH, AI, and probe tests remain skipped; no homelab deployment or production service operation is verified here.
- SQLite audit chaining is tamper-evident against accidental edits but not independently signed or protected from a privileged database owner.
- Local OS account is the operator authorization boundary; product RBAC and multi-party approval are not implemented.
- The old local `.venv` metadata mismatch remains as described above.

The CI action references were checked against the upstream release commits: [actions/checkout v4.2.2](https://github.com/actions/checkout/releases/tag/v4.2.2) and [actions/setup-python v5.6.0](https://github.com/actions/setup-python/releases/tag/v5.6.0).

## Final release recommendation

**Safe for initial Git commit: YES, from the exact allowlist only, after a maintainer rechecks current `git status`, reruns secret scan, and reviews the staged diff.** Do not use `git add .` or stage ignored local material. This recommendation does not authorize staging or publication and does not mean production-ready.

**Deployment readiness: NOT ESTABLISHED.** A separate authorized staging deployment must validate account ownership, secret injection, actual monitoring sender identity and network path, service supervision, backup/restore, audit retention, rollback, and post-deployment health. No such deployment was attempted here.
