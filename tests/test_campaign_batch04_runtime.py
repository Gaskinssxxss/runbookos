from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parents[1] / "scripts"))
import campaign_batch04_runtime as runtime


def test_stop_never_signals_a_process_with_wrong_executable(tmp_path, monkeypatch):
    identity = tmp_path / "identity.json"
    identity.write_text(json.dumps({"pid": 12345, "start_ticks": "original"}))
    monkeypatch.setattr(runtime, "IDENTITY", identity)
    monkeypatch.setattr(sys, "argv", ["runtime", "stop"])
    monkeypatch.setattr(runtime.os, "readlink", lambda path: "/usr/bin/unrelated")
    calls = []
    monkeypatch.setattr(runtime.os, "kill", lambda *args: calls.append(args))
    with pytest.raises(SystemExit, match="executable mismatch"):
        runtime.main()
    assert calls == []


def test_stop_rejects_reused_pid_before_signalling(tmp_path, monkeypatch):
    identity = tmp_path / "identity.json"
    identity.write_text(json.dumps({"pid": 12345, "start_ticks": "original"}))
    monkeypatch.setattr(runtime, "IDENTITY", identity)
    monkeypatch.setattr(sys, "argv", ["runtime", "stop"])
    monkeypatch.setattr(runtime.os, "readlink", lambda path: str(runtime.RUNTIME))
    monkeypatch.setattr(runtime, "start_ticks", lambda pid: "different-start")
    calls = []
    monkeypatch.setattr(runtime.os, "kill", lambda *args: calls.append(args))
    with pytest.raises(SystemExit, match="start identity mismatch"):
        runtime.main()
    assert calls == []


def test_occupied_port_aborts_without_starting_any_process(monkeypatch):
    class Occupied:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

        def connect_ex(self, address):
            assert address == ("127.0.0.1", 18080)
            return 0

    monkeypatch.setattr(sys, "argv", ["runtime", "start"])
    monkeypatch.setattr(runtime.socket, "socket", Occupied)
    calls = []
    monkeypatch.setattr(runtime.subprocess, "Popen", lambda *a, **k: calls.append(a))
    with pytest.raises(SystemExit, match="port occupied"):
        runtime.main()
    assert calls == []
