"""Local-machine entrypoint checks; intentionally excluded from source distributions."""

from __future__ import annotations

import importlib.util
import socket
import subprocess
import sys
from pathlib import Path

import pytest


def _entrypoint():
    path = Path("scripts/qwen-m3-benchmark-v070.py").resolve()
    spec = importlib.util.spec_from_file_location("qwen_m3_local_entrypoint_test", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_local_benchmark_entrypoint_import_is_inert(monkeypatch):
    path = Path("scripts/qwen-m3-benchmark-v070.py").resolve()
    spec = importlib.util.spec_from_file_location("qwen_m3_local_inert_test", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)

    def forbidden(*args, **kwargs):
        raise AssertionError("import must not start a process or open a socket")

    monkeypatch.setattr(subprocess, "Popen", forbidden)
    monkeypatch.setattr(socket, "socket", forbidden)
    spec.loader.exec_module(module)
    assert callable(module.main)


def test_local_benchmark_dry_run_never_dispatches_live_mode(monkeypatch):
    module = _entrypoint()
    calls = []

    class OfflinePytest:
        @staticmethod
        def main(args):
            calls.extend(args)
            return 0

    monkeypatch.setitem(sys.modules, "pytest", OfflinePytest)
    assert module.main(["--dry-run"]) == 0
    assert "--live" not in calls
    assert any(str(item).endswith("test_ai_m3_benchmark_v070.py") for item in calls)


def test_local_live_benchmark_requires_interactive_confirmation():
    module = _entrypoint()
    with pytest.raises(SystemExit) as error:
        module.main(["--live"])
    assert error.value.code == 2


def test_local_pilot_requires_its_own_confirmation():
    module = _entrypoint()
    with pytest.raises(SystemExit) as error:
        module.main(["--pilot-live", "--confirm-live", "--output-parent", "."])
    assert error.value.code == 2
