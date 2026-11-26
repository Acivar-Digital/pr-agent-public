"""Wiring tests for the #25-#28 capstone (checks repo, verdict gate, proxy lifecycle)."""

from __future__ import annotations

import asyncio
import subprocess
import sys
from pathlib import Path
from typing import Any, cast

import pytest

from agent.personas import AgentPersona
from agent.pr_worker import PRTaskReport
from agent.verdict import _security_verdict
from src.orchestrator.guardrails.checks_manifest import run_checks_from_main
from src.orchestrator.middleware.audit import AuditLogger
from src.orchestrator.tools.gated_pr import (
    APPROVED_VERDICT,
    handle_security_review_completion,
    open_draft_pr,
)

REPO = "acme/widgets"
BRANCH = "feature/x"
SHA = "abc123"


def _git(repo: Path, *args: str) -> None:
    subprocess.run(
        ["git", "-C", str(repo), *args], check=True, capture_output=True, text=True
    )


def _make_repo(root: Path, manifest: str | None) -> Path:
    """Create a clone with `origin/main` carrying `manifest` (or a seed file)."""
    remote = root / "remote.git"
    subprocess.run(
        ["git", "init", "--bare", str(remote)], check=True, capture_output=True
    )
    work = root / "work"
    subprocess.run(
        ["git", "clone", str(remote), str(work)], check=True, capture_output=True
    )
    _git(work, "config", "user.email", "test@example.com")
    _git(work, "config", "user.name", "Test")
    if manifest is not None:
        (work / ".vps-checks.toml").write_text(manifest, encoding="utf-8")
    else:
        (work / "seed.txt").write_text("seed\n", encoding="utf-8")
    _git(work, "add", "-A")
    _git(work, "commit", "-m", "init")
    _git(work, "push", "-u", "origin", "HEAD:main")
    return work


def _manifest(script: str) -> str:
    return f'[[checks]]\nname = "ok"\nargv = ["{sys.executable}", "-c", "{script}"]\n'


def _assert_checks_passed(passed: bool, results: list[Any], error: str | None) -> None:
    assert error is None
    assert passed is True
    assert [r.name for r in results] == ["ok"]


def test_checks_manifest_comes_from_target_repo(tmp_path: Path) -> None:
    """repo_root must be the target worktree, not the sample-repo install dir."""
    work = _make_repo(tmp_path, _manifest("raise SystemExit(0)"))
    audit = AuditLogger(tmp_path / "audit.db")
    audit.init_db()

    passed, results, error = run_checks_from_main(
        work,
        work,
        repo=REPO,
        branch=BRANCH,
        head_commit_sha=SHA,
        audit=audit,
        ref="origin/main",
    )

    _assert_checks_passed(passed, results, error)
    verdict = audit.get_verification_verdict(REPO, BRANCH, SHA)
    assert verdict is not None
    assert verdict["checks_passed"] == 1


def test_checks_do_not_block_the_event_loop(tmp_path: Path) -> None:
    """A slow check must not freeze the loop: the ticker keeps running."""
    work = _make_repo(tmp_path, _manifest("import time; time.sleep(0.5)"))
    audit = AuditLogger(tmp_path / "audit.db")
    audit.init_db()
    ticks = 0

    async def scenario() -> None:
        nonlocal ticks
        stop = False

        async def ticker() -> None:
            nonlocal ticks
            while not stop:
                ticks += 1
                await asyncio.sleep(0.02)

        task = asyncio.create_task(ticker())
        await asyncio.to_thread(
            run_checks_from_main,
            work,
            work,
            repo=REPO,
            branch=BRANCH,
            head_commit_sha=SHA,
            audit=audit,
            ref="origin/main",
        )
        stop = True
        await task

    asyncio.run(scenario())
    assert ticks > 5


def _report(**overrides: Any) -> PRTaskReport:
    base: dict[str, Any] = {
        "repo": REPO,
        "persona": "security-reviewer",
        "branch": BRANCH,
        "status": "completed",
        "summary": "LGTM",
    }
    base.update(overrides)
    return PRTaskReport(**base)


@pytest.mark.parametrize(
    ("overrides", "expected"),
    [
        ({"summary": "APPROVED"}, "APPROVED"),
        ({"summary": "LGTM, ship it"}, "APPROVED"),
        ({"summary": "NO-GO: critical RCE"}, "CHANGES_REQUESTED"),
        ({"summary": "Approved", "warnings": ["coverage low"]}, "CHANGES_REQUESTED"),
        (
            {"summary": "Approved", "static_findings": [{"rule": "x"}]},
            "CHANGES_REQUESTED",
        ),
        ({"summary": "Looks fine overall"}, "CHANGES_REQUESTED"),
        ({"status": "needs_human_review", "summary": "APPROVED"}, "CHANGES_REQUESTED"),
    ],
)
def test_security_verdict_is_explicit_and_fail_closed(
    overrides: dict[str, Any], expected: str
) -> None:
    assert _security_verdict(_report(**overrides)) == expected


def test_gate_requires_matching_branch_and_sha(tmp_path: Path) -> None:
    """Checks + security verdict on (branch, sha) let the gate open; otherwise block."""
    work = _make_repo(tmp_path, _manifest("raise SystemExit(0)"))
    audit = AuditLogger(tmp_path / "audit.db")
    audit.init_db()
    opened: list[dict[str, Any]] = []

    async def opener(**kwargs: Any) -> None:
        opened.append(kwargs)

    async def scenario() -> tuple[bool, bool]:
        run_checks_from_main(
            work,
            work,
            repo=REPO,
            branch=BRANCH,
            head_commit_sha=SHA,
            audit=audit,
            ref="origin/main",
        )
        handle_security_review_completion(
            audit,
            repo=REPO,
            branch=BRANCH,
            head_commit_sha=SHA,
            verdict=APPROVED_VERDICT,
        )
        allowed = await open_draft_pr(
            repo=REPO,
            branch=BRANCH,
            head_commit_sha=SHA,
            diff_text=(
                "diff --git a/src/a.py b/src/a.py\n--- a/src/a.py\n+++ b/src/a.py\n"
                "@@ -0,0 +1 @@\n+x = 1\n"
            ),
            audit=audit,
            pr_opener=opener,
        )
        blocked = await open_draft_pr(
            repo=REPO,
            branch=BRANCH,
            head_commit_sha="different-sha",
            diff_text="",
            audit=audit,
            pr_opener=opener,
        )
        return allowed.proceed, blocked.proceed

    allowed, blocked = asyncio.run(scenario())
    assert allowed is True
    assert blocked is False
    assert len(opened) == 1


def test_lifespan_closes_proxy_and_shared_audit(tmp_path: Path) -> None:
    """Run in a subprocess: the MCP session manager is single-use per process."""
    script = f"""
import os
os.environ["JOB_DB_PATH"] = {str(tmp_path / "jobs.db")!r}
os.environ["AUDIT_DB_PATH"] = {str(tmp_path / "audit.db")!r}
os.environ["GITHUB_PROXY_UPSTREAM_URL"] = "http://upstream.invalid/mcp"

from fastapi.testclient import TestClient
import server.app as m

closed = []

class P:
    def __init__(self, **kwargs):
        pass

    def register_on(self, server):
        return None

    async def close(self):
        closed.append(True)

m.GitHubProxy = P

with TestClient(m.app):
    pass

assert closed == [True], closed
"""
    result = subprocess.run(
        [sys.executable, "-c", script], capture_output=True, text=True, check=False
    )
    assert result.returncode == 0, result.stderr


def test_job_coroutine_records_verdict_on_head_branch(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import agent.job_store as js

    monkeypatch.setenv("JOB_DB_PATH", str(tmp_path / "jobs.db"))
    js.init_db()
    captured: dict[str, object] = {}

    async def fake_exec(**_kwargs: Any) -> PRTaskReport:
        return _report(summary="APPROVED", head_commit_sha="sha1")

    def fake_record(
        _audit: object,
        *,
        repo: str,
        branch: str,
        head_commit_sha: str,
        verdict: str,
        timestamp: str | None = None,
    ) -> None:
        captured.update(
            repo=repo,
            branch=branch,
            head_commit_sha=head_commit_sha,
            verdict=verdict,
        )

    async def fake_notify(_message: str) -> None:
        return None

    monkeypatch.setattr(js, "execute_pr_task", fake_exec)
    monkeypatch.setattr(js, "handle_security_review_completion", fake_record)
    monkeypatch.setattr(js, "_send_push_notification", fake_notify)

    asyncio.run(
        js._run_job_coroutine(
            job_id="j1",
            repo=REPO,
            persona_name="security-reviewer",
            command="review",
            base_branch="main",
            target_branch="agent/security-reviewer/j1",
            pr_number=None,
            allow_writes=False,
            conversation_id=None,
            head_commit_sha="sha1",
            head_branch="feature/x",
        )
    )

    assert captured["branch"] == "feature/x"
    assert captured["head_commit_sha"] == "sha1"
    assert captured["verdict"] == "APPROVED"


class _FakeProc:
    def __init__(self, payload: bytes) -> None:
        self.stdout = asyncio.StreamReader()
        self.stdout.feed_data(payload)
        self.stdout.feed_eof()
        self.stderr = asyncio.StreamReader()
        self.stderr.feed_eof()
        self.returncode = 0

    async def wait(self) -> int:
        return 0

    def kill(self) -> None:
        return None


def test_execute_pr_task_runs_checks_then_review_then_gate(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import agent.pr_worker as pw
    from src.orchestrator.tools.gated_pr import GateResult

    order: list[str] = []
    persona = AgentPersona(name="backend-dev", instructions="write code")

    async def fake_prepare(**_kwargs: Any) -> Path:
        return tmp_path

    async def fake_commit(**_kwargs: Any) -> tuple[list[str], list[str]]:
        order.append("commit")
        return (["a.py"], ["sha1"])

    async def fake_git(*_args: Any, **_kwargs: Any) -> str:
        return ""

    def fake_checks(*_args: Any, **_kwargs: Any) -> tuple[bool, list[Any], None]:
        order.append("checks")
        return (True, [], None)

    async def fake_review(**_kwargs: Any) -> PRTaskReport:
        order.append("review")
        return _report(summary="APPROVED", head_commit_sha="sha1")

    async def fake_gate(
        *, pr_opener: Any, opener_kwargs: dict[str, Any] | None = None, **_k: Any
    ) -> GateResult:
        order.append("gate")
        await pr_opener(**(opener_kwargs or {}))
        return GateResult(proceed=True, reason="ok", strikes=0)

    async def fake_open(**_kwargs: Any) -> tuple[str, int]:
        return ("https://example/pr/1", 1)

    async def fake_subprocess(*_args: Any, **_kwargs: Any) -> _FakeProc:
        return _FakeProc(b'{"status":"completed","summary":"ok","warnings":[]}')

    monkeypatch.setattr(pw, "prepare_worktree", fake_prepare)
    monkeypatch.setattr(pw, "commit_and_push", fake_commit)
    monkeypatch.setattr(pw, "_run_git", fake_git)
    monkeypatch.setattr(pw, "run_checks_from_main", fake_checks)
    monkeypatch.setattr(pw, "_run_inline_security_review", fake_review)
    monkeypatch.setattr(pw, "open_draft_pr", fake_gate)
    monkeypatch.setattr(pw, "open_pr", fake_open)
    monkeypatch.setattr(pw, "run_safe_static_checks", lambda *_a, **_k: ([], []))
    monkeypatch.setattr(pw, "_persist_model_record", lambda *_a, **_k: "rec")
    monkeypatch.setattr(pw, "_persist_job_log", lambda *_a, **_k: "log")
    monkeypatch.setattr(pw, "cleanup_worktree", fake_cleanup)
    monkeypatch.setattr(asyncio, "create_subprocess_exec", fake_subprocess)

    report = asyncio.run(
        pw.execute_pr_task(
            job_id="j1",
            repo=REPO,
            task="change",
            persona=persona,
            base_branch="main",
            target_branch="agent/backend-dev/j1",
        )
    )

    assert order == ["commit", "checks", "review", "gate"]
    assert report.pr_url == "https://example/pr/1"


async def fake_cleanup(_repo: str, _worktree_dir: Path) -> None:
    return None


def test_proxy_registers_exactly_the_allowlisted_tools() -> None:
    from mcp.server.mcpserver import MCPServer

    from src.orchestrator.upstream.github_proxy import (
        UPSTREAM_TOOL_ALLOWLIST,
        GitHubProxy,
    )

    proxy = GitHubProxy(
        client_factory=cast(Any, lambda: None), allowed_repos=["acme/widgets"]
    )
    server = MCPServer(name="proxy-test")
    proxy.register_on(server)

    names = {tool.name for tool in asyncio.run(server.list_tools())}
    assert names == set(UPSTREAM_TOOL_ALLOWLIST)
    assert len(names) == 4


def test_repo_intel_tools_are_registered() -> None:
    import server.app as m

    names = {tool.name for tool in asyncio.run(m.gemini_mcp.list_tools())}
    assert {"search_code", "get_repo_map"} <= names


def _patch_auto_worker(
    monkeypatch: pytest.MonkeyPatch,
    order: list[str],
    tmp_path: Path,
    *,
    checks_passed: bool,
) -> None:
    import agent.pr_worker as pw
    from src.orchestrator.tools.gated_pr import GateResult

    async def fake_prepare(**_kwargs: Any) -> Path:
        return tmp_path

    async def fake_commit(**_kwargs: Any) -> tuple[list[str], list[str]]:
        order.append("commit")
        return (["a.py"], ["sha1"])

    async def fake_git(*_args: Any, **_kwargs: Any) -> str:
        return ""

    def fake_checks(*_args: Any, **_kwargs: Any) -> tuple[bool, list[Any], None]:
        order.append("checks")
        return (checks_passed, [], None)

    async def fake_review(**_kwargs: Any) -> PRTaskReport:
        order.append("review")
        return _report(summary="APPROVED", head_commit_sha="sha1")

    async def fake_gate(
        *, pr_opener: Any, opener_kwargs: dict[str, Any] | None = None, **_k: Any
    ) -> GateResult:
        order.append("gate")
        await pr_opener(**(opener_kwargs or {}))
        return GateResult(proceed=True, reason="ok", strikes=0)

    async def fake_open(**_kwargs: Any) -> tuple[str, int]:
        return ("https://example/pr/1", 1)

    async def fake_subprocess(*_args: Any, **_kwargs: Any) -> _FakeProc:
        return _FakeProc(b'{"status":"completed","summary":"ok","warnings":[]}')

    async def fake_cleanup(_repo: str, _worktree_dir: Path) -> None:
        return None

    monkeypatch.setattr(pw, "prepare_worktree", fake_prepare)
    monkeypatch.setattr(pw, "commit_and_push", fake_commit)
    monkeypatch.setattr(pw, "_run_git", fake_git)
    monkeypatch.setattr(pw, "run_checks_from_main", fake_checks)
    monkeypatch.setattr(pw, "_run_inline_security_review", fake_review)
    monkeypatch.setattr(pw, "open_draft_pr", fake_gate)
    monkeypatch.setattr(pw, "open_pr", fake_open)
    monkeypatch.setattr(pw, "run_safe_static_checks", lambda *_a, **_k: ([], []))
    monkeypatch.setattr(pw, "_persist_model_record", lambda *_a, **_k: "rec")
    monkeypatch.setattr(pw, "_persist_job_log", lambda *_a, **_k: "log")
    monkeypatch.setattr(pw, "cleanup_worktree", fake_cleanup)
    monkeypatch.setattr(asyncio, "create_subprocess_exec", fake_subprocess)


def test_failed_checks_skip_the_inline_llm_review(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A non-zero ruff/ty exit must fail closed before any 600s review call."""
    import agent.pr_worker as pw

    order: list[str] = []
    _patch_auto_worker(monkeypatch, order, tmp_path, checks_passed=False)

    asyncio.run(
        pw.execute_pr_task(
            job_id="j1",
            repo=REPO,
            task="change",
            persona=AgentPersona(name="backend-dev", instructions="write code"),
            base_branch="main",
            target_branch="agent/backend-dev/j1",
        )
    )

    assert order == ["commit", "checks", "gate"]
    assert "review" not in order


def test_usage_preserves_nested_cost_dict() -> None:
    """`scout` (omp) returns usage["cost"] as a nested dict, not an int."""
    report = PRTaskReport(
        repo=REPO,
        persona="scout",
        branch="agent/scout/j1",
        status="completed",
        summary="ok",
        usage={"input_tokens": 10, "cost": {"usd": 0.25}},
    )

    assert report.usage["cost"] == {"usd": 0.25}
