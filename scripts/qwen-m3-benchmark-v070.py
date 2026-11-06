#!/usr/bin/env python3
"""Test-only local Qwen M3 benchmark entry point.

``--dry-run`` runs offline tests only. ``--live`` and ``--pilot-live`` require
separate operator approval and start only the fixed local acceptance lifecycle.
The pilot is locked to six reviewed case IDs and a twelve-request budget.
Importing this file never starts a process or sends a request.
"""

from __future__ import annotations

import argparse
import importlib.util
import os
import stat
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TESTS = ROOT / "tests"
if str(ROOT / "src") not in sys.path:
    sys.path.insert(0, str(ROOT / "src"))
if str(TESTS) not in sys.path:
    sys.path.insert(0, str(TESTS))


def _load_file(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError("local acceptance module could not be loaded")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def _validate_output_parent(path: Path) -> Path:
    try:
        info = path.lstat()
    except OSError as exc:
        raise ValueError("output parent must already exist") from exc
    if (
        stat.S_ISLNK(info.st_mode)
        or not stat.S_ISDIR(info.st_mode)
        or info.st_uid != os.geteuid()
        or stat.S_IMODE(info.st_mode) & 0o077
    ):
        raise ValueError("output parent must be a real owner-controlled directory with mode 0700")
    return path


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    modes = parser.add_mutually_exclusive_group(required=True)
    modes.add_argument("--dry-run", action="store_true", help="run offline regression tests")
    modes.add_argument("--live", action="store_true", help="run after separate approval only")
    modes.add_argument(
        "--pilot-live",
        action="store_true",
        help="run the fixed six-case pilot after separate approval",
    )
    parser.add_argument("--confirm-live", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--confirm-pilot-live", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--output-parent", type=Path)
    args = parser.parse_args(argv)
    if args.dry_run:
        import pytest

        return int(
            pytest.main(
                [
                    "-q",
                    str(TESTS / "test_ai_acceptance_harness_v060.py"),
                    str(TESTS / "test_ai.py"),
                    str(TESTS / "test_assessment.py"),
                    str(TESTS / "test_assessment_evaluation.py"),
                    str(TESTS / "test_ai_m3_benchmark_v070.py"),
                    str(TESTS / "test_ai_local_orchestrator_v060.py"),
                ]
            )
        )
    pilot = args.pilot_live
    if pilot and (not args.confirm_pilot_live or not sys.stdin.isatty()):
        parser.error("--pilot-live requires --confirm-pilot-live and an interactive terminal")
    if args.live and (not args.confirm_live or not sys.stdin.isatty()):
        parser.error("--live requires --confirm-live and an interactive terminal")
    if args.output_parent is None:
        parser.error("--live requires a pre-created protected --output-parent directory")
    try:
        output_parent = _validate_output_parent(args.output_parent.expanduser())
    except ValueError as exc:
        parser.error(str(exc))
    if pilot:
        print(
            "LIVE QWEN M3 PILOT: six fixed synthetic cases, at most 12 serial provider "
            "requests. No SSH, network targets, or remediation."
        )
        confirmation_phrase = "RUN SIX-CASE QWEN M3 PILOT"
    else:
        print(
            "LIVE QWEN M3 BENCHMARK: local model process and 24 synthetic cases only. "
            "No SSH, network targets, or remediation."
        )
        confirmation_phrase = "RUN LOCAL QWEN M3 BENCHMARK"
    confirmation = input(f"Type {confirmation_phrase} to continue: ")
    if confirmation != confirmation_phrase:
        print("Cancelled before starting any process.")
        return 2
    orchestrator = _load_file(
        "runbookos_ai_local_orchestrator_v060",
        ROOT / "scripts/ai-local-acceptance-v060.py",
    )
    adapter = _load_file("runbookos_ai_m3_benchmark_v070", TESTS / "ai_m3_benchmark_v070.py")
    acceptance_runner = adapter.run_pilot_acceptance if pilot else adapter.run_benchmark_acceptance
    result = orchestrator.run_live_acceptance(
        output_parent=output_parent,
        acceptance_runner=acceptance_runner,
    )
    print(f"acceptance_status={result.get('status')}")
    print(f"provider_requests={result.get('provider_requests', 0)}")
    print(f"dataset_cases={result.get('case_count', 0)}")
    if pilot:
        print("pilot_case_ids=" + ",".join(result.get("case_ids", [])))
    print(f"resource_monitor={result.get('resource_monitor', {}).get('status', 'not_started')}")
    return 0 if result.get("status") == "completed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
