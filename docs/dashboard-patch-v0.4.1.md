# RunbookOS v0.4.1 — Dashboard usability and reliability patch

## Scope

This patch addresses the specific dashboard staging findings without changing incident state semantics or adding execution capabilities.

- The incident queue now shows source and a 240-character bounded summary alongside the existing severity, status, target, service, and updated timestamp fields. Source values are derived from linked alerts; old rows without alert links show `unknown`.
- Timeline rows show `from_status → to_status` when transition details exist. Older, malformed, or non-object event details render `—` placeholders.
- All queue and timeline values continue through HTML escaping. The dashboard still omits evidence payloads and does not render raw model output.
- The loopback HTTP server enables address reuse for restart after a clean close. It does not enable port sharing or change the fixed bind address. A conflicting live listener continues to cause a bind error; the dashboard neither kills that process nor silently selects another port.
- Request handler threads are joined on server close. Client sockets have a 10-second timeout, bounding orderly shutdown; process restart discards in-memory sessions.

## Packaging

The prior `setuptools.build_meta` failure occurred when the caller environment lacked the build backend and was built without PEP 517 isolation. This is a build environment issue, not evidence of a source packaging defect. v0.4.1 pins the already-reviewed CI build tools (`setuptools==80.10.2`, `wheel==0.48.0`) as build requirements. These do not add runtime dependencies. Release verification uses a fresh isolated PEP 517 environment and installs both wheel and sdist into fresh virtual environments.

Package metadata, imported `runbookos.__version__`, CLI version output, CI assertions, and README now identify v0.4.1. Historical v0.4.0 reports and configuration file names remain unchanged as historical records.

## Verification record

Verification ran in the working copy. No homelab VM, SSH identity, operational SQLite database, preserved staging process, firewall, route, or service was part of this patch validation.

- Full pytest: **117 passed, 11 opt-in live tests skipped**.
- Coverage: **80.12%**, exceeding the 70% project threshold.
- Ruff: lint passed; format check passed (37 files already formatted).
- CLI smoke: fresh wheel `runbookos version` and `dashboard --help` passed.
- Isolated PEP 517 build: wheel and sdist succeeded with pinned setuptools/wheel.
- Fresh installation: wheel and sdist installed into separate virtual environments; metadata, import version, and CLI version all reported **0.4.1**.
- Artifact contents: dashboard module, patch documentation, and dashboard tests included where applicable; no SQLite or staging directory included.
- Artifact SHA-256:
  - `runbookos-0.4.1-py3-none-any.whl`: `dbc45eae2f3029a49191fe1ea7e622057cb2b8a444985e20274ca62e04551fd6`
  - `runbookos-0.4.1.tar.gz`: `14e91e06ffeba22b7c78ac133a8fb0877919014468630fdc926519f1f813291e`
- `git diff --check`: passed.

## Changed-file manifest

Expected source changes for this patch:

- `.github/workflows/validate.yml`
- `MANIFEST.in`
- `README.md`
- `docs/dashboard-patch-v0.4.1.md`
- `pyproject.toml`
- `src/runbookos/__init__.py`
- `src/runbookos/dashboard.py`
- `src/runbookos/incidents.py`
- `tests/test_dashboard.py`

No commit, push, tag, or staging deployment is performed by this patch.

## Remaining limitations

- The dashboard remains plain HTTP bound to IPv4 loopback; access through a network proxy is unsupported and must not be enabled casually.
- Graceful shutdown may wait for an in-flight request until its socket timeout (up to 10 seconds).
- Live homelab, SSH, AI inference, and preserved staging acceptance were intentionally not exercised.
- Address reuse only solves restart after the prior listener closes. It does not override an occupied port.

## Readiness recommendation

**Local release/commit readiness: ready for operator review.** All requested local checks passed. This is not production readiness or live operational acceptance. No Git commit or push is included.
