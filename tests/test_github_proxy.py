"""Tests for the pinned upstream GitHub MCP proxy (Ticket PRA-5rt / #25).

Covers: exact 4-tool read-only allowlist, strict owner/repo RBAC (proxy ceiling
AND caller grant, admin cannot bypass the ceiling), indirect identifier
rejection, owner/repo smuggling + path-traversal rejection, non-allowlisted tool
rejection, upstream timeout, append-only audit logging (success and denial),
outbound secret redaction, and disabled incoming header forwarding.
"""

from __future__ import annotations

import asyncio
import sqlite3
from pathlib import Path
from typing import Any

import pytest
from fastmcp import FastMCP
from fastmcp.server.providers.proxy import ProxyClient

import src.orchestrator.upstream.github_proxy as gp
from src.orchestrator.auth import CallerIdentity
from src.orchestrator.middleware.audit import AuditLogger
from src.orchestrator.upstream.github_proxy import (
    UPSTREAM_TOOL_ALLOWLIST,
    GitHubProxy,
    build_github_proxy_server,
)

SECRET = "ghp_SECRETTOKEN1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZ"


def _upstream() -> FastMCP:
    upstream = FastMCP("up")

    @upstream.tool
    async def list_pull_requests(owner: str, repo: str) -> dict[str, Any]:
        """List pull requests."""
        return {"pulls": [], "token": SECRET}

    @upstream.tool
    async def get_pull_request(
        owner: str, repo: str, pull_number: int
    ) -> dict[str, Any]:
        """Get a pull request."""
        return {"number": pull_number, "token": SECRET}

    @upstream.tool
    async def list_issues(owner: str, repo: str) -> dict[str, Any]:
        """List issues."""
        return {"issues": [], "token": SECRET}

    @upstream.tool
    async def get_issue(owner: str, repo: str, issue_number: int) -> dict[str, Any]:
        """Get an issue."""
        return {"number": issue_number, "token": SECRET}

    @upstream.tool
    async def merge_pull_request(
        owner: str, repo: str, pull_number: int
    ) -> dict[str, Any]:
        """Forbidden write tool."""
        return {"merged": True}

    return upstream


def _proxy(upstream: FastMCP, **kwargs: Any) -> GitHubProxy:
    return GitHubProxy(
        client_factory=lambda: ProxyClient(upstream, forward_incoming_headers=False),
        allowed_repos=["org/a"],
        **kwargs,
    )


def test_exposes_exactly_four_read_tools() -> None:
    server = build_github_proxy_server(
        upstream_transport=_upstream(), allowed_repos=["org/a"]
    )
    names = {t.name for t in asyncio.run(server.list_tools())}
    assert names == set(UPSTREAM_TOOL_ALLOWLIST)
    assert len(names) == 4
    assert "merge_pull_request" not in names


def test_rbac_allows_authorized_repo() -> None:
    proxy = _proxy(_upstream())
    caller = CallerIdentity("c", ["org/a"])
    result = asyncio.run(
        proxy.call_tool(
            "get_pull_request",
            {"owner": "org", "repo": "a", "pull_number": 1},
            caller,
        )
    )
    assert result is not None


def test_rbac_denies_unauthorized_repo() -> None:
    proxy = _proxy(_upstream())
    caller = CallerIdentity("c", ["org/a"])
    with pytest.raises(PermissionError):
        asyncio.run(
            proxy.call_tool(
                "get_pull_request",
                {"owner": "org", "repo": "b", "pull_number": 1},
                caller,
            )
        )


def test_admin_caller_still_blocked_by_proxy_ceiling() -> None:
    proxy = _proxy(_upstream())  # proxy ceiling is org/a
    admin = CallerIdentity("admin", ["*"], role="admin")
    with pytest.raises(PermissionError):
        asyncio.run(
            proxy.call_tool(
                "get_pull_request",
                {"owner": "org", "repo": "b", "pull_number": 1},
                admin,
            )
        )


def test_owner_repo_smuggling_rejected() -> None:
    proxy = _proxy(_upstream())
    caller = CallerIdentity("c", ["org/a"])
    with pytest.raises(PermissionError):
        asyncio.run(
            proxy.call_tool(
                "get_pull_request",
                {"owner": "victim-org", "repo": "org/a", "pull_number": 1},
                caller,
            )
        )


def test_path_traversal_rejected() -> None:
    proxy = _proxy(_upstream())
    caller = CallerIdentity("c", ["org/a"])
    with pytest.raises(PermissionError):
        asyncio.run(
            proxy.call_tool(
                "get_pull_request",
                {"owner": "..", "repo": "a", "pull_number": 1},
                caller,
            )
        )
    with pytest.raises(PermissionError):
        asyncio.run(
            proxy.call_tool("get_pull_request", {"repo": "../../etc/passwd"}, caller)
        )


def test_indirect_identifier_rejected() -> None:
    proxy = _proxy(_upstream())
    caller = CallerIdentity("c", ["org/a"])
    with pytest.raises(PermissionError):
        asyncio.run(
            proxy.call_tool(
                "get_issue",
                {"owner": "org", "repo": "a", "job_id": "x"},
                caller,
            )
        )


def test_tool_not_in_allowlist_rejected() -> None:
    proxy = _proxy(_upstream())
    caller = CallerIdentity("c", ["org/a"])
    with pytest.raises(PermissionError):
        asyncio.run(
            proxy.call_tool("merge_pull_request", {"owner": "org", "repo": "a"}, caller)
        )


def test_upstream_timeout_propagates() -> None:
    upstream = FastMCP("slow")

    @upstream.tool
    async def get_issue(owner: str, repo: str, issue_number: int) -> dict[str, Any]:
        """Slow tool."""
        await asyncio.sleep(5)
        return {"number": issue_number}

    proxy = GitHubProxy(
        client_factory=lambda: ProxyClient(upstream, forward_incoming_headers=False),
        allowed_repos=["org/a"],
        timeout_seconds=1,
    )
    caller = CallerIdentity("c", ["org/a"])
    with pytest.raises(TimeoutError):
        asyncio.run(
            proxy.call_tool(
                "get_issue", {"owner": "org", "repo": "a", "issue_number": 1}, caller
            )
        )


def test_audit_event_recorded(tmp_path: Path) -> None:
    audit = AuditLogger(tmp_path / "a.db")
    proxy = _proxy(_upstream(), audit=audit)
    caller = CallerIdentity("c", ["org/a"])

    async def _run() -> None:
        await proxy.call_tool(
            "get_issue", {"owner": "org", "repo": "a", "issue_number": 1}, caller
        )
        await audit.close()

    asyncio.run(_run())

    assert audit.verify_chain() is True
    conn = sqlite3.connect(tmp_path / "a.db")
    try:
        count = conn.execute("SELECT COUNT(*) FROM audit_log").fetchone()[0]
    finally:
        conn.close()
    assert count >= 1


def test_denial_is_audited(tmp_path: Path) -> None:
    audit = AuditLogger(tmp_path / "a.db")
    proxy = _proxy(_upstream(), audit=audit)
    caller = CallerIdentity("c", ["org/a"])

    async def _run() -> None:
        with pytest.raises(PermissionError):
            await proxy.call_tool(
                "get_pull_request",
                {"owner": "org", "repo": "b", "pull_number": 1},
                caller,
            )
        await audit.close()

    asyncio.run(_run())

    conn = sqlite3.connect(tmp_path / "a.db")
    try:
        count = conn.execute("SELECT COUNT(*) FROM audit_log").fetchone()[0]
    finally:
        conn.close()
    assert count >= 1


def test_secret_redacted_from_result() -> None:
    proxy = _proxy(_upstream())
    caller = CallerIdentity("c", ["org/a"])
    result = asyncio.run(
        proxy.call_tool(
            "get_issue", {"owner": "org", "repo": "a", "issue_number": 1}, caller
        )
    )
    text = result.content[0].text
    assert SECRET not in text
    assert "[REDACTED" in text


def test_forward_incoming_headers_disabled(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: dict[str, Any] = {}
    real_client = gp.ProxyClient

    def spy(transport: Any, **kwargs: Any) -> Any:
        captured.update(kwargs)
        return real_client(transport, **kwargs)

    monkeypatch.setattr(gp, "ProxyClient", spy)

    server = build_github_proxy_server(
        upstream_transport=_upstream(), allowed_repos=["org/a"]
    )
    assert {t.name for t in asyncio.run(server.list_tools())} == set(
        UPSTREAM_TOOL_ALLOWLIST
    )

    # The client factory is lazy: invoke a tool so the ProxyClient is built.
    from src.orchestrator.auth import (
        reset_current_caller_identity,
        set_current_caller_identity,
    )

    token = set_current_caller_identity(CallerIdentity("c", ["org/a"]))
    try:
        asyncio.run(
            server.call_tool(
                "get_issue", {"owner": "org", "repo": "a", "issue_number": 1}
            )
        )
    finally:
        reset_current_caller_identity(token)

    assert captured.get("forward_incoming_headers") is False

    client = real_client(_upstream(), forward_incoming_headers=False)
    options = client._transport_options
    assert options is not None
    assert options.forward_incoming_headers is False
