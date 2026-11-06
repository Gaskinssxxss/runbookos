from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
spec = importlib.util.spec_from_file_location(
    "b04_resume_test", ROOT / "scripts/campaign_batch04_resume.py"
)
resume = importlib.util.module_from_spec(spec)
spec.loader.exec_module(resume)


def test_resume_waits_for_controller_call_before_touching_fixtures(monkeypatch):
    monkeypatch.setattr(resume, "active_controller_calls", lambda: [{"pid": 123}])
    clock = iter([0, 311])
    monkeypatch.setattr(resume.time, "monotonic", lambda: next(clock))
    changes = []
    monkeypatch.setattr(resume.campaign, "reset", lambda scenario: changes.append(scenario))
    monkeypatch.setattr(resume.subprocess, "run", lambda *a, **k: changes.append("started"))
    with pytest.raises(SystemExit, match="controller call still active"):
        resume.main()
    assert changes == []


def test_resume_preserves_history_and_records_failed_baseline_without_launch(tmp_path, monkeypatch):
    ledger = {
        "attempts": [
            {
                "scenario_id": "B04-01",
                "run_id": "prior",
                "result": "AI_DRIVEN_PASS",
                "steps": {"audit": {"status": "PASS"}},
            },
            {
                "scenario_id": "B04-02",
                "run_id": "interrupted",
                "result": "IN_PROGRESS",
                "steps": {},
            },
        ]
    }
    path = tmp_path / "ledger.json"
    path.write_text(json.dumps(ledger))
    monkeypatch.setattr(resume.campaign, "LOCAL", tmp_path)
    monkeypatch.setattr(resume.campaign, "LEDGER", path)
    monkeypatch.setattr(resume, "active_controller_calls", lambda: [])
    monkeypatch.setattr(resume.campaign, "reset", lambda scenario: False)
    saved = []
    monkeypatch.setattr(
        resume.campaign, "persist", lambda value: saved.append(json.loads(json.dumps(value)))
    )
    called = []
    monkeypatch.setattr(resume.subprocess, "run", lambda *a, **k: called.append(True))
    with pytest.raises(SystemExit, match="baseline not restored"):
        resume.main()
    assert saved[-1]["attempts"][0] == ledger["attempts"][0]
    assert saved[-1]["attempts"][1]["result"] == "FAIL"
    assert saved[-1]["attempts"][1]["steps"]["cleanup"]["status"] == "FAIL"
    assert not called
