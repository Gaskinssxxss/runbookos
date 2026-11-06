# RunbookOS v0.7.0 Operator Demo

This offline demo exercises the existing incident ingestion, investigation storage,
assessment projection, `incidents show` CLI, and authenticated loopback dashboard.
It creates a fresh SQLite database and dashboard password verifier in a temporary
owner-only directory. `Ctrl-C` stops the dashboard and removes those temporary files.

Run from the repository root:

```bash
.venv/bin/python scripts/operator-demo-v070.py
```

Enter and confirm a temporary dashboard password when prompted. The demo prints
the synthetic incident and investigation IDs, observation provenance, assessment
status, uncertainty, and audit result. It then prints a loopback URL. Open that
URL, sign in with the password entered above, and select the incident from the
queue. The incident detail page shows the same linked assessment as the CLI.
Press `Ctrl-C` in the terminal to stop the dashboard and clean up.

The scenario is a deterministic synthetic fixture, not an AI-generated result.
Its inactive-service value is fixture data; no diagnostic was executed. The
observation, assertion, and verification states remain `unknown` / `not_present` /
`unknown`. The `service_failure` classification is `suspected`, confidence is a
fixture value, and semantic support remains unverified. The assessment is advisory
only and creates neither an approval nor an execution.

The SQLite database and password verifier are isolated from operational state.
The dashboard binds only to `127.0.0.1`; its password is entered with hidden input
and only a protected verifier is written. The script uses a dynamically assigned
ephemeral loopback port and stops only the dashboard child process it started.
