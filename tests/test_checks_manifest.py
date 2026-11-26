"""Tests for the .vps-checks.toml manifest runner (PRA-7ol / #26)."""

from __future__ import annotations

import subprocess
import sys
import time
from pathlib import Path
from typing import Any

import pytest

from src.orchestrator.guardrails.checks_manifest import (
    MAX_OUTPUT_BYTES,
    CheckCommand,
    ManifestError,
    load_manifest_from_main,
    parse_manifest,
    run_check,
    run_checks_from_main,
)
from src.orchestrator.middleware.audit import AuditLogger

VALID = """
[[checks]]
name = "ruff"
argv = ["uv", "run", "ruff", "check", "."]
timeout_seconds = 60
"""


def _git(repo: Path, *args: str) -> None:
    subprocess.run(
        ["git", "-C", str(repo), *args],
        check=True,
        capture_output=True,
        text=True,
    )


def _init_repo(tmp_path: Path, manifest_text: str | None) -> Path:
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init", "-q", "-b", "main")
    _git(repo, "config", "user.email", "test@example.com")
    _git(repo, "config", "user.name", "Test")
    if manifest_text is not None:
        (repo / ".vps-checks.toml").write_text(manifest_text, encoding="utf-8")
        _git(repo, "add", ".vps-checks.toml")
    else:
        (repo / "README.md").write_text("x", encoding="utf-8")
        _git(repo, "add", "README.md")
    _git(repo, "commit", "-q", "-m", "init")
    return repo


def _pid_alive(pid: int) -> bool:
    """True only if /proc/<pid> exists and is not a zombie (Linux test host)."""
    stat_path = Path(f"/proc/{pid}/stat")
    if not stat_path.exists():
        return False
    stat = stat_path.read_text(encoding="utf-8")
    state = stat.rsplit(") ", 1)[1].split()[0]
    return state != "Z"


def _wait_pid_gone(pid: int, timeout: float) -> None:
    """Spin until ``pid`` is no longer alive or ``timeout`` seconds elapse."""
    deadline = time.monotonic() + timeout
    while _pid_alive(pid) and time.monotonic() < deadline:
        time.sleep(0.05)


def _assert_valid_ruff_command(cmd: CheckCommand) -> None:
    assert cmd.name == "ruff"
    assert cmd.argv == ("uv", "run", "ruff", "check", ".")
    assert cmd.timeout_seconds == 60


def _assert_verdict_preserved(verdict: dict[str, Any] | None) -> None:
    assert verdict is not None
    assert verdict["checks_passed"] == 1
    assert verdict["security_verdict"] == "APPROVED"


def _assert_checks_verdict(verdict: dict[str, Any] | None, expected: int) -> None:
    assert verdict is not None
    assert verdict["checks_passed"] == expected


def test_parse_manifest_valid() -> None:
    manifest = parse_manifest(VALID)
    assert len(manifest.commands) == 1
    _assert_valid_ruff_command(manifest.commands[0])
    assert bool(manifest) is True


def test_parse_manifest_missing_checks() -> None:
    with pytest.raises(ManifestError):
        parse_manifest('title = "no checks"\n')


def test_parse_manifest_empty_checks() -> None:
    with pytest.raises(ManifestError):
        parse_manifest("checks = []\n")


def test_parse_manifest_invalid_toml() -> None:
    with pytest.raises(ManifestError):
        parse_manifest("[[checks]\nname = broken")


def test_parse_manifest_bad_argv() -> None:
    with pytest.raises(ManifestError):
        parse_manifest('[[checks]]\nname = "x"\nargv = []\n')


def test_parse_manifest_bad_timeout() -> None:
    with pytest.raises(ManifestError):
        parse_manifest('[[checks]]\nname = "x"\nargv = ["true"]\ntimeout_seconds = 0\n')


def test_load_from_main_ignores_worktree(tmp_path: Path) -> None:
    repo = _init_repo(tmp_path, VALID)
    # Overwrite the working tree with a malicious manifest (uncommitted).
    (repo / ".vps-checks.toml").write_text(
        '[[checks]]\nname = "evil"\nargv = ["sh", "-c", "touch /tmp/pwned"]\n',
        encoding="utf-8",
    )
    manifest = load_manifest_from_main(repo, "main")
    assert manifest.commands[0].name == "ruff"


def test_load_missing_manifest_fails(tmp_path: Path) -> None:
    repo = _init_repo(tmp_path, None)
    with pytest.raises(ManifestError):
        load_manifest_from_main(repo, "main")


def test_load_ref_rejects_option_injection(tmp_path: Path) -> None:
    repo = _init_repo(tmp_path, VALID)
    with pytest.raises(ManifestError):
        load_manifest_from_main(repo, "-evil")


def test_run_check_pass_and_fail(tmp_path: Path) -> None:
    ok = run_check(
        CheckCommand("ok", (sys.executable, "-c", "raise SystemExit(0)"), 30),
        tmp_path,
    )
    assert ok.passed is True
    bad = run_check(
        CheckCommand("bad", (sys.executable, "-c", "raise SystemExit(3)"), 30),
        tmp_path,
    )
    assert bad.passed is False
    assert bad.returncode == 3


def test_run_check_missing_binary(tmp_path: Path) -> None:
    result = run_check(
        CheckCommand("nope", ("pr-agent-no-such-binary-xyz",), 5),
        tmp_path,
    )
    assert result.returncode == 127
    assert result.passed is False


def test_run_check_output_capped(tmp_path: Path) -> None:
    script = "import sys; sys.stdout.write('x' * 200000)"
    result = run_check(
        CheckCommand("flood", (sys.executable, "-c", script), 30),
        tmp_path,
    )
    assert result.passed is True
    assert len(result.stdout) <= MAX_OUTPUT_BYTES


def test_run_check_timeout_kills_group(tmp_path: Path) -> None:
    pidfile = tmp_path / "grandchild.pid"
    script = (
        "import subprocess, sys, time\n"
        "p = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(30)'])\n"
        f"open({str(pidfile)!r}, 'w').write(str(p.pid))\n"
        "time.sleep(30)\n"
    )
    result = run_check(
        CheckCommand("slow", (sys.executable, "-c", script), 1),
        tmp_path,
    )
    assert result.timed_out is True
    assert result.passed is False
    grandchild = int(pidfile.read_text(encoding="utf-8"))
    _wait_pid_gone(grandchild, 5.0)
    assert not _pid_alive(grandchild)


def test_run_check_env_is_minimal(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("GITHUB_TOKEN", "super-secret")
    result = run_check(
        CheckCommand(
            "env",
            (
                sys.executable,
                "-c",
                "import os; print(os.environ.get('GITHUB_TOKEN'))",
            ),
            30,
        ),
        tmp_path,
    )
    assert result.stdout.strip() == "None"


def test_record_verdict_non_clobber(tmp_path: Path) -> None:
    # Security first, then checks: the checks writer must preserve security.
    a1 = AuditLogger(tmp_path / "a1.db")
    a1.record_security_verdict("org/repo", "main", "sha1", "APPROVED")
    a1.record_checks_verdict("org/repo", "main", "sha1", True)
    _assert_verdict_preserved(a1.get_verification_verdict("org/repo", "main", "sha1"))
    # Checks first, then security: the security writer must preserve checks.
    a2 = AuditLogger(tmp_path / "a2.db")
    a2.record_checks_verdict("org/repo", "main", "sha1", True)
    a2.record_security_verdict("org/repo", "main", "sha1", "APPROVED")
    _assert_verdict_preserved(a2.get_verification_verdict("org/repo", "main", "sha1"))


def test_run_checks_from_main_records(tmp_path: Path) -> None:
    exe = sys.executable
    manifest = (
        f'[[checks]]\nname = "ok"\nargv = ["{exe}", "-c", "raise SystemExit(0)"]\n'
    )
    repo = _init_repo(tmp_path, manifest)
    audit = AuditLogger(tmp_path / "audit.db")
    passed, results, error = run_checks_from_main(
        repo,
        repo,
        repo="org/repo",
        branch="agent/x",
        head_commit_sha="sha2",
        audit=audit,
    )
    assert error is None
    assert passed is True
    assert results[0].name == "ok"
    _assert_checks_verdict(
        audit.get_verification_verdict("org/repo", "agent/x", "sha2"), 1
    )


def test_run_checks_from_main_fails_closed(tmp_path: Path) -> None:
    repo = _init_repo(tmp_path, None)
    audit = AuditLogger(tmp_path / "audit.db")
    passed, results, error = run_checks_from_main(
        repo,
        repo,
        repo="org/repo",
        branch="b",
        head_commit_sha="sha3",
        audit=audit,
    )
    assert passed is False
    assert results == []
    assert error is not None
    _assert_checks_verdict(audit.get_verification_verdict("org/repo", "b", "sha3"), 0)


def test_run_checks_from_main_empty_manifest_fails_closed(tmp_path: Path) -> None:
    repo = _init_repo(tmp_path, "checks = []\n")
    audit = AuditLogger(tmp_path / "audit.db")
    passed, results, error = run_checks_from_main(
        repo,
        repo,
        repo="org/repo",
        branch="b",
        head_commit_sha="sha4",
        audit=audit,
    )
    assert passed is False
    assert results == []
    assert error is not None
    _assert_checks_verdict(audit.get_verification_verdict("org/repo", "b", "sha4"), 0)
