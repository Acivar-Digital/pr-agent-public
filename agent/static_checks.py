from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path
from typing import Any

from agent.security import build_safe_linter_env

# Stage 1 invariant: ONLY pure static, zero-code-execution tools may run on VPS.
# pytest and mypy MUST run in GitHub Actions, never on the VPS host.
FORBIDDEN_VPS_TOOLS: frozenset[str] = frozenset({"pytest", "mypy", "python", "python3"})


def _run_tool(
    cmd: list[str], cwd: Path, timeout_seconds: int
) -> subprocess.CompletedProcess[str]:
    if not cmd or Path(cmd[0]).name in FORBIDDEN_VPS_TOOLS:
        raise ValueError(
            f"Tool '{cmd[0] if cmd else ''}' is forbidden on VPS in Stage 1"
        )
    return subprocess.run(
        cmd,
        cwd=str(cwd),
        env=build_safe_linter_env(),
        capture_output=True,
        text=True,
        timeout=timeout_seconds,
        check=False,
    )


def _parse_ruff(stdout: str) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for item in json.loads(stdout)[:50]:
        findings.append(
            {
                "tool": "ruff",
                "file": item.get("filename", ""),
                "line": (item.get("location") or {}).get("row", 0),
                "code": item.get("code", ""),
                "message": item.get("message", ""),
            }
        )
    return findings


def _run_ruff(
    worktree: Path, py_files: list[str], timeout_seconds: int
) -> tuple[list[dict[str, Any]], list[str]]:
    findings: list[dict[str, Any]] = []
    warnings: list[str] = []
    if not py_files:
        return findings, warnings
    if not shutil.which("ruff"):
        warnings.append("ruff not installed on VPS")
        return findings, warnings
    try:
        proc = _run_tool(
            [
                "ruff",
                "check",
                "--isolated",
                "--no-cache",
                "--output-format",
                "json",
                *py_files,
            ],
            cwd=worktree,
            timeout_seconds=timeout_seconds,
        )
        if proc.stdout.strip():
            findings.extend(_parse_ruff(proc.stdout))
    except (subprocess.TimeoutExpired, json.JSONDecodeError) as exc:
        warnings.append(f"ruff check skipped: {exc}")
    return findings, warnings


def _parse_bandit(stdout: str) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    data = json.loads(stdout)
    for item in (data.get("results") or [])[:50]:
        findings.append(
            {
                "tool": "bandit",
                "file": item.get("filename", ""),
                "line": item.get("line_number", 0),
                "code": item.get("test_id", ""),
                "message": item.get("issue_text", ""),
            }
        )
    return findings


def _run_bandit(
    worktree: Path, py_files: list[str], timeout_seconds: int
) -> tuple[list[dict[str, Any]], list[str]]:
    findings: list[dict[str, Any]] = []
    warnings: list[str] = []
    if not py_files:
        return findings, warnings
    if not shutil.which("bandit"):
        warnings.append("bandit not installed on VPS")
        return findings, warnings
    try:
        proc = _run_tool(
            ["bandit", "-q", "-f", "json", *py_files],
            cwd=worktree,
            timeout_seconds=timeout_seconds,
        )
        if proc.stdout.strip():
            findings.extend(_parse_bandit(proc.stdout))
    except (subprocess.TimeoutExpired, json.JSONDecodeError) as exc:
        warnings.append(f"bandit check skipped: {exc}")
    return findings, warnings


def _parse_gitleaks(stdout: str) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for item in json.loads(stdout)[:20]:
        findings.append(
            {
                "tool": "gitleaks",
                "file": item.get("File", ""),
                "line": item.get("StartLine", 0),
                "code": item.get("RuleID", "secret"),
                "message": "Potential secret detected (value redacted)",
            }
        )
    return findings


def _run_gitleaks(
    worktree: Path, timeout_seconds: int
) -> tuple[list[dict[str, Any]], list[str]]:
    findings: list[dict[str, Any]] = []
    warnings: list[str] = []
    if not shutil.which("gitleaks"):
        return findings, warnings
    try:
        proc = _run_tool(
            [
                "gitleaks",
                "detect",
                "--no-git",
                "--source",
                str(worktree),
                "--report-format",
                "json",
                "--report-path",
                "-",
            ],
            cwd=worktree,
            timeout_seconds=timeout_seconds,
        )
        if proc.stdout.strip():
            findings.extend(_parse_gitleaks(proc.stdout))
    except (subprocess.TimeoutExpired, json.JSONDecodeError) as exc:
        warnings.append(f"gitleaks check skipped: {exc}")
    return findings, warnings


def run_safe_static_checks(
    worktree: Path,
    changed_files: list[str],
    timeout_seconds: int = 30,
) -> tuple[list[dict[str, Any]], list[str]]:
    """Run isolated static checks on changed files. Returns (findings, warnings)."""
    findings: list[dict[str, Any]] = []
    warnings: list[str] = []
    py_files = [
        f for f in changed_files if f.endswith(".py") and (worktree / f).is_file()
    ]

    # 1. ruff (isolated: ignores repo pyproject.toml / ruff.toml)
    ruff_findings, ruff_warnings = _run_ruff(worktree, py_files, timeout_seconds)
    findings.extend(ruff_findings)
    warnings.extend(ruff_warnings)

    # 2. bandit (pure AST SAST)
    bandit_findings, bandit_warnings = _run_bandit(worktree, py_files, timeout_seconds)
    findings.extend(bandit_findings)
    warnings.extend(bandit_warnings)

    # 3. gitleaks (secret scanning on worktree without git hooks)
    gitleaks_findings, gitleaks_warnings = _run_gitleaks(worktree, timeout_seconds)
    findings.extend(gitleaks_findings)
    warnings.extend(gitleaks_warnings)

    return findings, warnings
