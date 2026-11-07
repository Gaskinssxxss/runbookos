"""Guarded, opt-in issue worker. No scheduled or issue-triggered entry point exists.

The offline pilot uses an injected sandbox command. Codex execution requires a
separately reviewed credential and egress design; this module never loads one.
"""

from __future__ import annotations

import argparse
import fcntl
import json
import os
import subprocess
import sys
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

REPO = "Gaskinssxxss/runbookos"
AUTH_LABEL = "codex-worker-approved"
MAX_ROUNDS = 3
MAX_SECONDS = 1200
MAX_CONCURRENT = 1
MAX_PAID_USD = 0
SANDBOX_IMAGE = "alpine@sha256:a8560b36e8b8210634f77d9f7f9efd7ffa463e380b75e2e74aff4511df3ef88c"
PROTECTED = ("tests/fixtures/", "scenarios/metadata/", ".github/workflows/")


class WorkerRejected(Exception):
    """A dispatch or result failed a mandatory guard."""


@dataclass(frozen=True)
class Issue:
    number: int
    title: str
    body: str
    state: str
    labels: frozenset[str]
    author_association: str


@dataclass(frozen=True)
class DraftPR:
    url: str
    head: str
    draft: bool


def authorize(issue: Issue, *, event: str, actor_permission: str) -> None:
    """Treat issue text as untrusted data; only API metadata grants authority."""
    if event != "workflow_dispatch":
        raise WorkerRejected("trusted manual dispatch required")
    if actor_permission not in {"admin", "maintain", "write"}:
        raise WorkerRejected("maintainer permission required")
    if issue.state != "open" or AUTH_LABEL not in issue.labels:
        raise WorkerRejected("open issue and maintainer approval label required")
    if issue.number < 1 or issue.author_association not in {
        "OWNER",
        "MEMBER",
        "COLLABORATOR",
        "CONTRIBUTOR",
        "NONE",
        "FIRST_TIME_CONTRIBUTOR",
    }:
        raise WorkerRejected("invalid issue metadata")


def branch_for(issue_number: int) -> str:
    if issue_number < 1:
        raise WorkerRejected("invalid issue number")
    return f"codex/issue-{issue_number}"


def validate_diff(paths: list[str]) -> None:
    if not paths:
        raise WorkerRejected("worker produced no changes")
    for path in paths:
        if (
            path.startswith("/")
            or ".." in Path(path).parts
            or any(ord(char) < 32 for char in path)
            or any(path.startswith(p) for p in PROTECTED)
        ):
            raise WorkerRejected(f"protected or invalid path: {path}")
        if path in {"AGENTS.md", "pyproject.toml"} or path.endswith(
            (".key", ".pem", ".token", ".env")
        ):
            raise WorkerRejected(f"protected or sensitive path: {path}")


def validate_tracked_changes(paths: list[str]) -> None:
    if any(path.startswith(("tests/", "docs/")) for path in paths):
        raise WorkerRejected("existing tests or acceptance documentation changed")


def run_bounded(command: list[str], cwd: Path, *, seconds: int = MAX_SECONDS) -> tuple[int, str]:
    if not 0 < seconds <= MAX_SECONDS:
        raise WorkerRejected("runtime limit exceeded")
    try:
        result = subprocess.run(
            command,
            cwd=cwd,
            capture_output=True,
            text=True,
            timeout=seconds,
            env={"PATH": "/usr/bin:/bin", "HOME": str(cwd)},
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise WorkerRejected("worker timed out; manual review required") from exc
    # Never persist arbitrary subprocess output: tests may emit secrets.
    return result.returncode, "PASS" if result.returncode == 0 else "FAIL"


def offline_container(workspace: Path, command: list[str], *, seconds: int = MAX_SECONDS) -> None:
    """Execute offline test code with no host secrets, network, or publisher token.

    This does not run Codex: model egress/entitlement remains disabled.
    """
    if not workspace.is_dir() or workspace.is_symlink():
        raise WorkerRejected("invalid workspace")
    if not command or not 0 < seconds <= MAX_SECONDS:
        raise WorkerRejected("invalid command or runtime")
    if os.getuid() == 0:
        raise WorkerRejected("root-owned sandbox workspace is prohibited")
    name = f"runbookos-codex-pilot-{uuid.uuid4().hex}"
    container = [
        "docker",
        "run",
        "--rm",
        "--name",
        name,
        "--network",
        "none",
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges",
        "--read-only",
        "--pids-limit",
        "128",
        "--memory",
        "2g",
        "--cpus",
        "1",
        "--user",
        f"{os.getuid()}:{os.getgid()}",
        "--mount",
        f"type=bind,src={workspace.resolve()},dst=/workspace",
        "--workdir",
        "/workspace",
        "--tmpfs",
        "/tmp:rw,noexec,nosuid,size=64m",
        SANDBOX_IMAGE,
        *command,
    ]
    try:
        status, _ = run_bounded(container, workspace, seconds=seconds)
    except WorkerRejected:
        # A timed-out Docker client can leave its owned container running.
        subprocess.run(["docker", "rm", "-f", name], capture_output=True, timeout=10, check=False)
        raise
    if status:
        raise WorkerRejected("sandbox command failed; inspect isolated CI result")


def pilot(
    issue: Issue,
    *,
    event: str,
    actor_permission: str,
    workspace: Path,
    sandbox: Callable[[Path, Issue], None],
    publish: Callable[[str, str], DraftPR],
    existing_pr: Callable[[str], str | None],
    stop: Callable[[], bool],
) -> str:
    """One branch/PR transaction with a caller-supplied isolated sandbox.

    Publisher credentials stay with the caller, never inside the sandbox.
    """
    authorize(issue, event=event, actor_permission=actor_permission)
    workspace.parent.mkdir(parents=True, exist_ok=True)
    lock_path = workspace.parent / f".codex-worker-issue-{issue.number}.lock"
    with lock_path.open("w") as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise WorkerRejected("issue dispatch already running") from exc
        return _pilot_locked(issue, workspace, sandbox, publish, existing_pr, stop)


def _pilot_locked(
    issue: Issue,
    workspace: Path,
    sandbox: Callable[[Path, Issue], None],
    publish: Callable[[str, str], DraftPR],
    existing_pr: Callable[[str], str | None],
    stop: Callable[[], bool],
) -> str:
    branch = branch_for(issue.number)
    if stop():
        raise WorkerRejected("manual stop requested")
    if existing_pr(branch):
        raise WorkerRejected("existing PR: idempotent dispatch rejected")
    if workspace.exists() and any(workspace.iterdir()):
        raise WorkerRejected("workspace must be empty")
    workspace.mkdir(parents=True, exist_ok=True)
    started = time.monotonic()
    sandbox(workspace, issue)
    if stop() or time.monotonic() - started > MAX_SECONDS:
        raise WorkerRejected("stopped or runtime limit exceeded")
    changed_raw = subprocess.run(
        ["git", "diff", "--name-only", "-z", "HEAD"],
        cwd=workspace,
        capture_output=True,
        check=True,
    ).stdout
    untracked_raw = subprocess.run(
        ["git", "ls-files", "--others", "--exclude-standard", "-z"],
        cwd=workspace,
        capture_output=True,
        check=True,
    ).stdout
    changed = (
        changed_raw.decode("utf-8", "surrogateescape").rstrip("\0").split("\0")
        if changed_raw
        else []
    )
    untracked = (
        untracked_raw.decode("utf-8", "surrogateescape").rstrip("\0").split("\0")
        if untracked_raw
        else []
    )
    validate_tracked_changes(changed)
    validate_diff(changed + untracked)
    if existing_pr(branch):
        raise WorkerRejected("PR appeared during run")
    pr = publish(branch, f"Closes #{issue.number}")
    if pr.head != branch or not pr.draft:
        raise WorkerRejected("publisher did not confirm issue branch and draft PR")
    return pr.url


def main() -> int:
    parser = argparse.ArgumentParser(description="Offline guarded Codex worker pilot")
    parser.add_argument("--self-check", action="store_true")
    args = parser.parse_args()
    if args.self_check:
        print(
            json.dumps(
                {
                    "status": "DISABLED",
                    "repo": REPO,
                    "max_rounds": MAX_ROUNDS,
                    "max_seconds": MAX_SECONDS,
                    "max_concurrent": MAX_CONCURRENT,
                    "max_paid_usd": MAX_PAID_USD,
                }
            )
        )
        return 0
    parser.error("live dispatch is disabled pending maintainer credential and spending review")
    return 2


if __name__ == "__main__":
    sys.exit(main())
