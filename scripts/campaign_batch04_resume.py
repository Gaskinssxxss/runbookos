"""Resume Batch 04 after session loss without overlapping an orphaned provider call."""

from __future__ import annotations

import datetime as dt
import json
import subprocess
import sys
import time

import campaign_batch04_live as campaign


def active_controller_calls() -> list[dict]:
    code = """import pathlib,json
rows=[]
for p in pathlib.Path('/proc').glob('[0-9]*/cmdline'):
 try:
  a=p.read_bytes().split(b'\\0')
  if b'runbookos' in a and any(v in a for v in (b'investigate',b'propose-remediation')):
   rows.append({'pid':int(p.parent.name)})
 except OSError:pass
print(json.dumps(rows))
"""
    return json.loads(campaign.guest(campaign.b03.OPS, "/usr/bin/python3", ["-c", code])["stdout"])


def main() -> int:
    # Never mutate fixtures while a disconnected controller request still runs.
    deadline = time.monotonic() + 310
    while active_controller_calls():
        if time.monotonic() >= deadline:
            raise SystemExit("controller call still active; resume aborted")
        time.sleep(1)
    import fcntl

    with (campaign.LOCAL / "runner.lock").open("a+") as lock:
        fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        ledger = json.loads(campaign.LEDGER.read_text())
        for attempt in ledger["attempts"]:
            if attempt["result"] != "IN_PROGRESS":
                continue
            scenario = next(s for s in campaign.spec.SCENARIOS if s["id"] == attempt["scenario_id"])
            attempt.update(
                result="FAIL",
                failure_stage="runner_interruption",
                failure_code="session_restart_before_terminal_checkpoint",
                completed_at=dt.datetime.now(dt.timezone.utc).isoformat(),
            )
            restored = campaign.reset(scenario)
            attempt["steps"]["cleanup"] = {
                "status": "PASS" if restored else "FAIL",
                "baseline_restored": restored,
            }
            campaign.persist(ledger)
            if not restored:
                raise SystemExit("interrupted fixture baseline not restored")
    return subprocess.run(
        [sys.executable, str(campaign.ROOT / "scripts/campaign_batch04_live.py"), "--group", "all"],
        cwd=campaign.ROOT,
        check=False,
    ).returncode


if __name__ == "__main__":
    raise SystemExit(main())
