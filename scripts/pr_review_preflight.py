#!/usr/bin/env python3
"""Read-only, deterministic GitHub PR preflight reviewer.

This is NOT an AI reviewer. PR contents are untrusted data and are never executed.
No API writes, model calls, shell execution, PR checkout, or approval decisions.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

API_ROOT = "https://api.github.com"
MAX_FILES = 300
MAX_PAGES = 3
RISK_PATHS = (
    "src/runbookos/engine.py",
    "src/runbookos/ssh.py",
    "src/runbookos/remote.py",
    "src/runbookos/store.py",
    "src/runbookos/actions.py",
    "src/runbookos/remediation_proposal.py",
    "src/runbookos/incidents.py",
    ".github/workflows/",
    "AGENTS.md",
)
CI_PASS = frozenset({"success", "neutral", "skipped"})
CI_BAD = frozenset({"failure", "timed_out", "cancelled", "action_required", "startup_failure"})
REPO_PATTERN = re.compile(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+\Z")
MAX_OUTPUT = 16000


def api_get(path: str, token: str) -> object:
    if not path.startswith("/repos/") or "://" in path or ".." in path:
        raise ValueError("Unsupported GitHub API path")
    request = Request(
        API_ROOT + path,
        headers={
            "Authorization": "Bearer " + token,
            "Accept": "application/vnd.github+json",
            "User-Agent": "RunbookOS-read-only-reviewer",
            "X-GitHub-Api-Version": "2022-11-28",
        },
        method="GET",
    )
    with urlopen(request, timeout=12) as response:
        return json.load(response)


def collect(repo: str, number: int, token: str) -> dict:
    if not REPO_PATTERN.fullmatch(repo):
        raise ValueError("Invalid repository identifier")
    if not 1 <= number <= 1000000000:
        raise ValueError("Invalid PR number")
    path = "/repos/" + repo
    pr = api_get(f"{path}/pulls/{number}", token)
    if not isinstance(pr, dict) or not isinstance(pr.get("head"), dict):
        raise ValueError("Malformed pull request data")
    files: list[dict] = []
    for page in range(1, MAX_PAGES + 1):
        batch = api_get(f"{path}/pulls/{number}/files?per_page=100&page={page}", token)
        if not isinstance(batch, list):
            raise ValueError("Malformed changed-file data")
        files.extend(batch)
        if len(files) > MAX_FILES:
            raise ValueError("File count limit exceeded")
        if len(batch) < 100:
            break
    if pr.get("changed_files", len(files)) > len(files):
        raise ValueError("Incomplete file listing; refusing to claim review")
    sha = pr["head"].get("sha", "")
    if not re.fullmatch(r"[a-fA-F0-9]{40}", sha):
        raise ValueError("Invalid PR head SHA")
    checks = api_get(f"{path}/commits/{sha}/check-runs?per_page=100", token)
    if not isinstance(checks, dict):
        raise ValueError("Malformed check-runs data")
    if checks.get("total_count", 0) > len(checks.get("check_runs", [])):
        raise ValueError("Truncated CI checks; refusing to claim review")
    return {"pr": pr, "files": files, "checks": checks["check_runs"]}


def safe_text(value: object, limit: int = 120) -> str:
    text = str(value if value is not None else "")[:limit]
    return text.replace("\r", " ").replace("\n", " ").replace("|", "\\|").replace("]", "\\]")


def review(payload: dict) -> dict:
    files, checks = payload["files"], payload["checks"]
    findings: list[dict] = []
    ci_status = "UNKNOWN"
    if not checks:
        findings.append({"severity": "WARNING", "subject": "CI", "detail": "No checks found; CI status unknown."})
    else:
        bad = [c for c in checks if c.get("conclusion") in CI_BAD]
        pending = [c for c in checks if c.get("status") != "completed"]
        unknown = [c for c in checks if c.get("status") == "completed" and c.get("conclusion") not in CI_PASS | CI_BAD]
        if bad:
            ci_status = "FAIL"
            findings.append({"severity": "BLOCKER", "subject": "CI", "detail": f"{len(bad)} check(s) failed, cancelled, or require attention."})
        elif pending or unknown:
            ci_status = "PENDING_OR_UNKNOWN"
            findings.append({"severity": "WARNING", "subject": "CI", "detail": f"{len(pending)} pending and {len(unknown)} unknown check(s)."})
        else:
            ci_status = "PASS"
    if not files:
        findings.append({"severity": "WARNING", "subject": "Diff", "detail": "PR has no changed files."})
    for f in files:
        name = f.get("filename", "")
        if not isinstance(name, str):
            name = "unknown"
        if any(name == risk or name.startswith(risk) for risk in RISK_PATHS):
            findings.append({"severity": "WARNING", "subject": name, "detail": "Security-sensitive file changed; manual diff and invariant review required."})
        if f.get("patch") is None:
            findings.append({"severity": "WARNING", "subject": name, "detail": "Patch unavailable; content not reviewed."})
        patch = str(f.get("patch") or "")
        added = "\n".join(line[1:] for line in patch.splitlines() if line.startswith("+") and not line.startswith("+++"))
        if re.search(r"(?im)^\s*(?:assert\s+True\s*$|pytest\.skip\(|@pytest\.mark\.skip\b)", added):
            findings.append({"severity": "WARNING", "subject": name, "detail": "Added test bypass or unconditional assertion pattern; inspect manually."})
    findings.append({"severity": "INFO", "subject": "Limitations", "detail": "Deterministic metadata checks only. No AI reasoning, semantic security audit, or independent test execution."})
    return {"ci_status": ci_status, "findings": findings, "files_count": len(files), "checks_count": len(checks)}


def render(payload: dict, report: dict) -> str:
    pr = payload["pr"]
    lines = [
        "# RunbookOS PR preflight (read-only)",
        "",
        f"- PR: #{safe_text(pr.get('number'))} — {safe_text(pr.get('title'))}",
        f"- Head SHA: `{safe_text(pr.get('head', {}).get('sha'))}`",
        f"- CI evidence: **{report['ci_status']}** ({report['checks_count']} checks inspected)",
        f"- Changed files: {report['files_count']}",
        "- Automation state: **manual preflight only; NOT an independent AI approval**",
        "",
        "| Severity | Subject | Finding |",
        "| --- | --- | --- |",
    ]
    for item in report["findings"][:100]:
        lines.append(f"| {safe_text(item['severity'])} | {safe_text(item['subject'])} | {safe_text(item['detail'], 250)} |")
    lines.extend(["", "This report does not authorize merge, remediation, or live infrastructure changes.", ""])
    return "\n".join(lines)[:MAX_OUTPUT]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo", required=True)
    parser.add_argument("--pr", required=True, type=int)
    args = parser.parse_args()
    token = os.environ.get("GITHUB_TOKEN", "")
    if not token:
        print("GITHUB_TOKEN missing: refusing unauthenticated review", file=sys.stderr)
        return 2
    try:
        payload = collect(args.repo, args.pr, token)
        result = review(payload)
        report = render(payload, result)
    except (ValueError, HTTPError, URLError, OSError, KeyError, TypeError) as exc:
        print(f"Preflight incomplete: {type(exc).__name__}; no PASS claim", file=sys.stderr)
        return 2
    print(report)
    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        with open(summary, "a", encoding="utf-8") as stream:
            stream.write(report)
    return 1 if result["ci_status"] == "FAIL" else 0


if __name__ == "__main__":
    raise SystemExit(main())
