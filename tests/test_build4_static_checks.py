"""Build 4/5: Isolated VPS-safe static checks (ruff + bandit + gitleaks)."""

from __future__ import annotations

import json
import subprocess

import pytest

from agent.pr_worker import PRTaskReport
from agent.static_checks import _run_tool, run_safe_static_checks


# --------------------------------------------------------------------------- #
# Test 1: Subprocess env has ZERO secrets + ruff uses --isolated --no-cache
# --------------------------------------------------------------------------- #
def test_env_passed_to_subprocess_has_zero_secrets(tmp_path, monkeypatch):
    for key in ("GITHUB_TOKEN", "MCP_SECRET_PATH", "GITHUB_WEBHOOK_SECRET"):
        monkeypatch.setenv(key, "supersecret-value")

    (tmp_path / "a.py").write_text("x = 1\n", encoding="utf-8")
    captured_env = {}
    captured_argv = []

    def _fake_run(cmd, **kwargs):
        captured_argv.append(cmd)
        captured_env.update(kwargs.get("env") or {})
        proc = subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")
        return proc

    monkeypatch.setattr("shutil.which", lambda name: f"/usr/bin/{name}")
    monkeypatch.setattr("subprocess.run", _fake_run)

    run_safe_static_checks(tmp_path, ["a.py"])

    assert not (
        set(captured_env) & {"GITHUB_TOKEN", "MCP_SECRET_PATH", "GITHUB_WEBHOOK_SECRET"}
    ), f"Secrets leaked into subprocess env: {captured_env}"
    ruff_argv = captured_argv[0]
    assert "--isolated" in ruff_argv
    assert "--no-cache" in ruff_argv


# --------------------------------------------------------------------------- #
# Test 2: Forbidden tools (pytest, mypy) are blocked
# --------------------------------------------------------------------------- #
def test_forbidden_tools_blocked(tmp_path):
    with pytest.raises(ValueError, match="forbidden on VPS"):
        _run_tool(["pytest"], tmp_path, 5)
    with pytest.raises(ValueError, match="forbidden on VPS"):
        _run_tool(["mypy", "a.py"], tmp_path, 5)
    with pytest.raises(ValueError, match="forbidden on VPS"):
        _run_tool(["python"], tmp_path, 5)
    with pytest.raises(ValueError, match="forbidden on VPS"):
        _run_tool(["python3"], tmp_path, 5)


# --------------------------------------------------------------------------- #
# Test 3: gitleaks redacts secret values in findings
# --------------------------------------------------------------------------- #
def test_gitleaks_redacts_secret_value(tmp_path, monkeypatch):
    (tmp_path / "a.py").write_text("token = 'SUPER_SECRET_123'\n", encoding="utf-8")

    gitleaks_json = json.dumps(
        [
            {
                "File": "a.py",
                "StartLine": 3,
                "RuleID": "generic-api-key",
                "Secret": "SUPER_SECRET_123",
            }
        ]
    )

    def _fake_run(cmd, **kwargs):
        if "gitleaks" in str(cmd[0]):
            return subprocess.CompletedProcess(cmd, 0, stdout=gitleaks_json, stderr="")
        return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

    monkeypatch.setattr("shutil.which", lambda name: f"/usr/bin/{name}")
    monkeypatch.setattr("subprocess.run", _fake_run)

    findings, _ = run_safe_static_checks(tmp_path, ["a.py"])

    all_text = json.dumps(findings)
    assert "SUPER_SECRET_123" not in all_text, (
        f"Secret value leaked in findings: {all_text}"
    )
    # gitleaks findings should still be present
    gitleaks_findings = [f for f in findings if f["tool"] == "gitleaks"]
    assert len(gitleaks_findings) >= 1


# --------------------------------------------------------------------------- #
# Test 4: Timeout degrades to warning, does not crash
# --------------------------------------------------------------------------- #
def test_timeout_degrades_to_warning(tmp_path, monkeypatch):
    (tmp_path / "a.py").write_text("x = 1\n", encoding="utf-8")

    def _fake_run(cmd, **kwargs):
        raise subprocess.TimeoutExpired(cmd, 1)

    monkeypatch.setattr("shutil.which", lambda name: f"/usr/bin/{name}")
    monkeypatch.setattr("subprocess.run", _fake_run)

    findings, warnings = run_safe_static_checks(tmp_path, ["a.py"])

    assert findings == []
    assert len(warnings) >= 1
    assert any("skipped" in w for w in warnings)


# --------------------------------------------------------------------------- #
# Test 5: PRTaskReport includes static_findings
# --------------------------------------------------------------------------- #
def test_pr_task_report_includes_static_findings():
    report = PRTaskReport(
        repo="test/repo",
        persona="developer",
        branch="test-branch",
        status="completed",
        summary="Test summary",
        static_findings=[{"tool": "ruff", "code": "F401"}],
    )
    dumped = report.model_dump()
    assert dumped["static_findings"] == [{"tool": "ruff", "code": "F401"}]
    # Ensure default_factory works
    report2 = PRTaskReport(
        repo="test/repo",
        persona="developer",
        branch="test-branch",
        status="completed",
        summary="No findings",
    )
    assert report2.model_dump()["static_findings"] == []
