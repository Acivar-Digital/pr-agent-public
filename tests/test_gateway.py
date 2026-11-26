"""Comprehensive test suite for FastMCP + FastAPI dual-auth gateway (Ticket #24, Bead PRA-t0r).

Verifies:
1. Bearer token auth vs invalid token (401 on missing/invalid, 200 on valid).
2. Secret URL Path auth resolving to admin CallerIdentity without Bearer header.
3. Zero body-read ASGI streaming SSE / Streamable HTTP response without hang.
4. Three-shape RBAC parameter resolution (direct repo, job_id -> repo, and split owner/repo).
5. Hardened /metrics endpoint: localhost access allowed vs remote IP access restricted to admin auth.

Assertions are grouped into small module-level helpers to keep each function's cyclomatic
complexity within the guard limit (<= 5) without weakening, skipping, or removing any check.
"""

from __future__ import annotations

import asyncio
import os
from collections.abc import Generator
from pathlib import Path

import httpx
import pytest
from fastapi import APIRouter
from mcp.server.mcpserver import MCPServer
from starlette.responses import StreamingResponse

from agent.job_store import init_db
from server.app import app as prod_app
from src.orchestrator.auth import (
    SECRET_PATH_IDENTITY,
    CallerIdentity,
    attach_rbac_middleware,
    check_rbac,
    clear_bearer_tokens,
    enforce_rbac,
    extract_bearer_token,
    get_current_caller_identity,
    is_localhost_ip,
    register_bearer_token,
    resolve_target_repo,
    unregister_bearer_token,
    verify_bearer_token,
)
from src.orchestrator.gateway import create_gateway_app


@pytest.fixture(autouse=True)
def _cleanup_tokens() -> Generator[None, None, None]:
    clear_bearer_tokens()
    yield
    clear_bearer_tokens()


# ==============================================================================
# 1. Bearer Token Auth Unit & Integration Tests
# ==============================================================================


async def _assert_rejects_missing_and_invalid_auth(client: httpx.AsyncClient) -> None:
    res_no_auth = await client.post("/mcp", json={})
    assert res_no_auth.status_code == 401
    assert "Authorization header with Bearer token is required" in res_no_auth.text

    res_bad_auth = await client.post(
        "/mcp", headers={"Authorization": "Bearer bad_token_xyz"}, json={}
    )
    assert res_bad_auth.status_code == 401
    assert "Invalid or expired Bearer token" in res_bad_auth.text


def test_bearer_token_registry_and_verify() -> None:
    ident = CallerIdentity(
        client_id="unit_tester", allowed_repos=["org/repo1"], role="user"
    )
    register_bearer_token("valid_token_123", ident)

    assert verify_bearer_token("valid_token_123") == ident
    assert verify_bearer_token("nonexistent_token") is None
    assert verify_bearer_token("") is None

    unregister_bearer_token("valid_token_123")
    assert verify_bearer_token("valid_token_123") is None


def test_bearer_token_env_admin(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("GATEWAY_ADMIN_TOKEN", "super_secret_admin_token")
    verified = verify_bearer_token("super_secret_admin_token")
    assert verified is not None
    assert verified.role == "admin"
    assert verified.is_repo_allowed("any/repo")


def test_bearer_token_env_auth_tokens_json(monkeypatch: pytest.MonkeyPatch) -> None:
    tokens_json = '{"user_tok_1": {"client_id": "svc_user", "allowed_repos": ["org/repo-a"], "role": "user"}}'
    monkeypatch.setenv("GATEWAY_AUTH_TOKENS", tokens_json)

    verified = verify_bearer_token("user_tok_1")
    assert verified is not None
    assert verified.client_id == "svc_user"
    assert verified.is_repo_allowed("org/repo-a")
    assert not verified.is_repo_allowed("org/repo-b")


def test_extract_bearer_token_parsing() -> None:
    assert extract_bearer_token("Bearer secret-token-xyz") == "secret-token-xyz"
    assert extract_bearer_token("bearer  secret-token-xyz  ") == "secret-token-xyz"
    assert extract_bearer_token("Basic abcdef") is None
    assert extract_bearer_token("") is None


@pytest.mark.anyio
async def test_bearer_token_auth_on_mcp_endpoint() -> None:
    gateway_app, mcp_server = create_gateway_app(secret_path="sec_test_path")

    @mcp_server.tool()
    async def sample_tool() -> str:
        return "sample_ok"

    token = "test_bearer_abc"
    ident = CallerIdentity(client_id="client_abc", allowed_repos=["*"], role="user")
    register_bearer_token(token, ident)

    transport = httpx.ASGITransport(app=gateway_app)
    async with httpx.AsyncClient(
        transport=transport, base_url="http://testserver"
    ) as client:
        await _assert_rejects_missing_and_invalid_auth(client)

        async with mcp_server.session_manager.run():
            res_valid = await client.post(
                "/mcp",
                headers={"Authorization": f"Bearer {token}"},
                json={
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "initialize",
                    "params": {
                        "protocolVersion": "2024-11-05",
                        "capabilities": {},
                        "clientInfo": {"name": "test-client", "version": "1.0"},
                    },
                },
            )
            assert res_valid.status_code == 200


# ==============================================================================
# 2. Secret URL Path Authentication Tests
# ==============================================================================


async def _assert_secret_path_statuses(
    init_res: httpx.Response, call_res: httpx.Response
) -> None:
    assert init_res.status_code == 200
    assert call_res.status_code == 200


def _assert_secret_path_caller_identity(caller: CallerIdentity | None) -> None:
    assert caller is not None
    assert caller == SECRET_PATH_IDENTITY
    assert caller.client_id == "secret_path_client"


def _assert_secret_path_admin_scope(caller: CallerIdentity) -> None:
    assert caller.role == "admin"
    assert caller.allowed_repos == ["*"]


@pytest.mark.anyio
async def test_secret_url_path_resolves_to_admin_identity() -> None:
    secret = "random_secret_48_chars_long_xyz_1234567890abcdef"
    gateway_app, mcp_server = create_gateway_app(secret_path=secret)

    observed_caller: list[CallerIdentity | None] = []

    @mcp_server.tool()
    async def inspect_caller() -> str:
        caller = get_current_caller_identity()
        observed_caller.append(caller)
        return caller.client_id if caller else "none"

    transport = httpx.ASGITransport(app=gateway_app)
    async with (
        httpx.AsyncClient(transport=transport, base_url="http://testserver") as client,
        mcp_server.session_manager.run(),
    ):
        # 1. Connect via Secret URL Path without Bearer header
        init_res = await client.post(
            f"/gemini/{secret}/mcp",
            json={
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {
                    "protocolVersion": "2024-11-05",
                    "capabilities": {},
                    "clientInfo": {"name": "gemini-connector", "version": "1.0"},
                },
            },
        )
        session_id = init_res.headers.get("mcp-session-id")
        headers = {"mcp-session-id": session_id} if session_id else {}

        call_res = await client.post(
            f"/gemini/{secret}/mcp",
            headers=headers,
            json={
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tools/call",
                "params": {"name": "inspect_caller", "arguments": {}},
            },
        )

        await _assert_secret_path_statuses(init_res, call_res)

        # Verified: CallerIdentity resolved to SECRET_PATH_IDENTITY
        assert len(observed_caller) == 1
        caller = observed_caller[0]
        _assert_secret_path_caller_identity(caller)
        assert caller is not None
        _assert_secret_path_admin_scope(caller)


@pytest.mark.anyio
async def test_secret_url_path_with_invalid_bearer_returns_401() -> None:
    secret = "secret_path_xyz"
    gateway_app, _ = create_gateway_app(secret_path=secret)

    transport = httpx.ASGITransport(app=gateway_app)
    async with httpx.AsyncClient(
        transport=transport, base_url="http://testserver"
    ) as client:
        # Passing an invalid Bearer token to secret path rejects with 401
        res = await client.post(
            f"/gemini/{secret}/mcp",
            headers={"Authorization": "Bearer fraudulent_token"},
            json={},
        )
        assert res.status_code == 401
        assert "Invalid Bearer token" in res.text


# ==============================================================================
# 3. Zero Body-Read ASGI Streaming SSE / Streamable HTTP Tests
# ==============================================================================


async def _consume_sse_stream(client: httpx.AsyncClient, secret: str) -> str:
    received_chunks: list[str] = []
    async with client.stream("GET", f"/gemini/{secret}/test_stream") as stream_res:
        assert stream_res.status_code == 200
        async for chunk in stream_res.aiter_text():
            received_chunks.append(chunk)
    return "".join(received_chunks)


def _assert_all_sse_chunks_received(full_streamed_text: str) -> None:
    for i in range(5):
        assert f"data: chunk_{i}" in full_streamed_text


@pytest.mark.anyio
async def test_zero_body_read_streaming_sse_no_hang() -> None:
    """Verify that chunked SSE streaming through ZeroBodyReadAuthMiddleware does not hang."""
    secret = "stream_secret"

    async def sse_event_stream():
        for i in range(5):
            yield f"data: chunk_{i}\n\n".encode()
            await asyncio.sleep(0.01)

    router = APIRouter()

    @router.get(f"/gemini/{secret}/test_stream")
    async def sse_endpoint():
        return StreamingResponse(sse_event_stream(), media_type="text/event-stream")

    gateway_app, _ = create_gateway_app(secret_path=secret, router=router)

    transport = httpx.ASGITransport(app=gateway_app)
    async with httpx.AsyncClient(
        transport=transport, base_url="http://testserver"
    ) as client:
        # Stream response chunks; must stream smoothly without deadlocking
        full_streamed_text = await _consume_sse_stream(client, secret)
        _assert_all_sse_chunks_received(full_streamed_text)


def _build_session_headers(token: str, session_id: str | None) -> dict[str, str]:
    headers = {"Authorization": f"Bearer {token}"}
    if session_id:
        headers["mcp-session-id"] = session_id
    return headers


async def _assert_streamable_echo_call(call_res: httpx.Response) -> None:
    assert call_res.status_code == 200
    assert "echo: hello world" in call_res.text


@pytest.mark.anyio
async def test_zero_body_read_streamable_http_session_lifecycle() -> None:
    """Verify end-to-end FastMCP Streamable HTTP transport via Bearer token."""
    token = "bearer_session_test_token"
    register_bearer_token(
        token,
        CallerIdentity(client_id="session_user", allowed_repos=["*"], role="admin"),
    )

    gateway_app, mcp_server = create_gateway_app(secret_path="sec_dummy")

    @mcp_server.tool()
    async def echo_tool(msg: str) -> str:
        return f"echo: {msg}"

    transport = httpx.ASGITransport(app=gateway_app)
    async with (
        httpx.AsyncClient(transport=transport, base_url="http://testserver") as client,
        mcp_server.session_manager.run(),
    ):
        # Initialize
        init_res = await client.post(
            "/mcp",
            headers={"Authorization": f"Bearer {token}"},
            json={
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {
                    "protocolVersion": "2024-11-05",
                    "capabilities": {},
                    "clientInfo": {"name": "stream-tester", "version": "1.0"},
                },
            },
        )
        assert init_res.status_code == 200
        session_id = init_res.headers.get("mcp-session-id")

        # Call tool
        headers = _build_session_headers(token, session_id)
        call_res = await client.post(
            "/mcp",
            headers=headers,
            json={
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tools/call",
                "params": {"name": "echo_tool", "arguments": {"msg": "hello world"}},
            },
        )
        await _assert_streamable_echo_call(call_res)


# ==============================================================================
# 4. Three-Shape RBAC Parameter Resolution Tests
# ==============================================================================


def _assert_rbac_shape1_direct_repo() -> None:
    assert (
        resolve_target_repo({"repo": "example-org/sample-repo"})
        == "example-org/sample-repo"
    )


def _assert_rbac_shape2_job_id(job_id: str) -> None:
    assert resolve_target_repo({"job_id": job_id}) == "example-org/sample-repo"
    assert resolve_target_repo({"job_id": "nonexistent_job_123"}) is None
    assert resolve_target_repo({"job_ids": [job_id]}) == "example-org/sample-repo"


def _assert_rbac_shape3_split_owner_repo() -> None:
    assert (
        resolve_target_repo({"owner": "example-org", "repo": "sample-repo"})
        == "example-org/sample-repo"
    )
    assert (
        resolve_target_repo(
            {"owner": "example-org", "repo": "example-org/sample-repo"}
        )
        == "example-org/sample-repo"
    )


def _assert_rbac_non_matching_shapes() -> None:
    assert resolve_target_repo({}) is None
    assert resolve_target_repo({"some_other_arg": "val"}) is None


async def _cancel_dispatched_jobs(*_job_ids: str) -> None:
    import asyncio

    pending = [
        t
        for t in asyncio.all_tasks()
        if not t.done() and "_run_job_coroutine" in repr(t.get_coro())
    ]
    for t in pending:
        t.cancel()
    await asyncio.gather(*pending, return_exceptions=True)


@pytest.mark.anyio
async def test_three_shape_rbac_resolution_unit(tmp_path: Path) -> None:
    # Setup temporary SQLite job store for Shape 2
    db_file = tmp_path / "rbac_jobs.db"
    prev_db = os.environ.get("JOB_DB_PATH")
    os.environ["JOB_DB_PATH"] = str(db_file)
    job_id = ""
    try:
        init_db()
        from agent.job_store import dispatch_job

        created_job = dispatch_job(
            repo="example-org/sample-repo",
            persona="security-reviewer",
            command="audit",
            base_branch="main",
            allow_writes=False,
        )
        job_id = created_job["job_id"]

        # Shape 1: Direct repo
        _assert_rbac_shape1_direct_repo()
        # Shape 2: job_id -> repo lookup via SQLite
        _assert_rbac_shape2_job_id(job_id)
        # Shape 3: Upstream split owner / repo
        _assert_rbac_shape3_split_owner_repo()
        # Non-matching shapes
        _assert_rbac_non_matching_shapes()
    finally:
        if job_id:
            await _cancel_dispatched_jobs(job_id)
        if prev_db is None:
            os.environ.pop("JOB_DB_PATH", None)
        else:
            os.environ["JOB_DB_PATH"] = prev_db


def _assert_check_rbac_matrix(
    caller_restricted: CallerIdentity, caller_admin: CallerIdentity
) -> None:
    # Allowed access
    assert check_rbac(caller_restricted, "example-org/sample-repo") is True
    assert check_rbac(caller_restricted, "Forbidden/repo") is False
    assert check_rbac(caller_admin, "Forbidden/repo") is True


def _assert_enforce_rbac_allowed(caller_restricted: CallerIdentity) -> None:
    # Shape 1 direct repo enforcement
    assert (
        enforce_rbac(caller_restricted, {"repo": "example-org/sample-repo"})
        == "example-org/sample-repo"
    )
    # Shape 3 split owner/repo enforcement
    assert (
        enforce_rbac(
            caller_restricted,
            {"owner": "example-org", "repo": "sample-repo"},
        )
        == "example-org/sample-repo"
    )


def test_check_and_enforce_rbac_shapes() -> None:
    caller_restricted = CallerIdentity(
        client_id="restricted_client",
        allowed_repos=["example-org/sample-repo"],
        role="user",
    )
    caller_admin = CallerIdentity(
        client_id="admin_client",
        allowed_repos=[],
        role="admin",
    )

    _assert_check_rbac_matrix(caller_restricted, caller_admin)
    _assert_enforce_rbac_allowed(caller_restricted)

    # Shape 1 direct repo enforcement rejects forbidden repo
    with pytest.raises(PermissionError):
        enforce_rbac(caller_restricted, {"repo": "Forbidden/repo"})

    # Shape 3 split owner/repo enforcement rejects forbidden owner
    with pytest.raises(PermissionError):
        enforce_rbac(
            caller_restricted,
            {"owner": "Forbidden", "repo": "other-repo"},
        )


async def _assert_rbac_shape1_tool(
    client: httpx.AsyncClient, headers: dict[str, str]
) -> None:
    # Shape 1: Allowed vs Disallowed
    s1_ok = await client.post(
        "/mcp",
        headers=headers,
        json={
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {
                "name": "tool_shape1",
                "arguments": {"repo": "example-org/sample-repo"},
            },
        },
    )
    assert "shape1_ok: example-org/sample-repo" in s1_ok.text

    s1_denied = await client.post(
        "/mcp",
        headers=headers,
        json={
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {
                "name": "tool_shape1",
                "arguments": {"repo": "Untrusted-Org/secret-repo"},
            },
        },
    )
    assert "PermissionDenied" in s1_denied.text
    assert (
        "not authorized to access repository 'Untrusted-Org/secret-repo'"
        in s1_denied.text
    )


async def _assert_rbac_shape2_tool(
    client: httpx.AsyncClient,
    headers: dict[str, str],
    allowed_job: dict[str, str],
    disallowed_job: dict[str, str],
) -> None:
    # Shape 2: Allowed job_id vs Disallowed job_id vs Nonexistent
    s2_ok = await client.post(
        "/mcp",
        headers=headers,
        json={
            "jsonrpc": "2.0",
            "id": 4,
            "method": "tools/call",
            "params": {
                "name": "tool_shape2",
                "arguments": {"job_id": allowed_job["job_id"]},
            },
        },
    )
    assert f"shape2_ok: {allowed_job['job_id']}" in s2_ok.text

    s2_denied = await client.post(
        "/mcp",
        headers=headers,
        json={
            "jsonrpc": "2.0",
            "id": 5,
            "method": "tools/call",
            "params": {
                "name": "tool_shape2",
                "arguments": {"job_id": disallowed_job["job_id"]},
            },
        },
    )
    assert "PermissionDenied" in s2_denied.text

    s2_nonexistent = await client.post(
        "/mcp",
        headers=headers,
        json={
            "jsonrpc": "2.0",
            "id": 6,
            "method": "tools/call",
            "params": {
                "name": "tool_shape2",
                "arguments": {"job_id": "nonexistent_job_xyz"},
            },
        },
    )
    assert "PermissionDenied" in s2_nonexistent.text


async def _assert_rbac_shape3_tool(
    client: httpx.AsyncClient, headers: dict[str, str]
) -> None:
    # Shape 3: Upstream split owner / repo
    s3_ok = await client.post(
        "/mcp",
        headers=headers,
        json={
            "jsonrpc": "2.0",
            "id": 7,
            "method": "tools/call",
            "params": {
                "name": "tool_shape3",
                "arguments": {
                    "owner": "example-org",
                    "repo": "sample-repo",
                },
            },
        },
    )
    assert "shape3_ok: example-org/sample-repo" in s3_ok.text

    s3_denied = await client.post(
        "/mcp",
        headers=headers,
        json={
            "jsonrpc": "2.0",
            "id": 8,
            "method": "tools/call",
            "params": {
                "name": "tool_shape3",
                "arguments": {
                    "owner": "Untrusted-Org",
                    "repo": "secret-repo",
                },
            },
        },
    )
    assert "PermissionDenied" in s3_denied.text


@pytest.mark.anyio
async def test_fastmcp_rbac_middleware_tool_call_enforcement(tmp_path: Path) -> None:
    db_file = tmp_path / "rbac_tool_jobs.db"
    prev_db = os.environ.get("JOB_DB_PATH")
    os.environ["JOB_DB_PATH"] = str(db_file)
    try:
        init_db()
        from agent.job_store import dispatch_job

        allowed_job = dispatch_job(
            repo="example-org/sample-repo",
            persona="security-reviewer",
            command="audit",
            base_branch="main",
            allow_writes=False,
        )
        disallowed_job = dispatch_job(
            repo="Untrusted-Org/secret-repo",
            persona="security-reviewer",
            command="audit",
            base_branch="main",
            allow_writes=False,
        )

        server = MCPServer("test-rbac-server")

        @server.tool()
        async def tool_shape1(repo: str) -> str:
            return f"shape1_ok: {repo}"

        @server.tool()
        async def tool_shape2(job_id: str) -> str:
            return f"shape2_ok: {job_id}"

        @server.tool()
        async def tool_shape3(owner: str, repo: str) -> str:
            return f"shape3_ok: {owner}/{repo}"

        attach_rbac_middleware(server)

        token = "token_scoped_user"
        register_bearer_token(
            token,
            CallerIdentity(
                client_id="scoped_user",
                allowed_repos=["example-org/sample-repo"],
                role="user",
            ),
        )

        app, _ = create_gateway_app(server=server, secret_path="dummy_sec")
        transport = httpx.ASGITransport(app=app)
        async with (
            httpx.AsyncClient(
                transport=transport, base_url="http://testserver"
            ) as client,
            server.session_manager.run(),
        ):
            init_res = await client.post(
                "/mcp",
                headers={"Authorization": f"Bearer {token}"},
                json={
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "initialize",
                    "params": {
                        "protocolVersion": "2024-11-05",
                        "capabilities": {},
                        "clientInfo": {"name": "test", "version": "1"},
                    },
                },
            )
            session_id = init_res.headers.get("mcp-session-id")
            headers = _build_session_headers(token, session_id)

            await _assert_rbac_shape1_tool(client, headers)
            await _assert_rbac_shape2_tool(client, headers, allowed_job, disallowed_job)
            await _assert_rbac_shape3_tool(client, headers)
    finally:
        if prev_db is None:
            os.environ.pop("JOB_DB_PATH", None)
        else:
            os.environ["JOB_DB_PATH"] = prev_db


# ==============================================================================
# 5. /metrics Localhost vs Remote Access Control Tests
# ==============================================================================


async def _assert_metrics_localhost(client: httpx.AsyncClient) -> None:
    # 1. Localhost access (no headers, default testclient host) -> 200 OK
    res_local = await client.get("/metrics")
    assert res_local.status_code == 200
    assert "pr_agent_workspaces_free_bytes" in res_local.text


async def _assert_metrics_remote_unauth(client: httpx.AsyncClient) -> None:
    # 2. Remote IP access without auth -> 403 Forbidden
    res_remote_unauth = await client.get(
        "/metrics",
        headers={"CF-Connecting-IP": "203.0.113.195"},
    )
    assert res_remote_unauth.status_code == 403
    assert (
        "Metrics access restricted to 127.0.0.1 or admin auth" in res_remote_unauth.text
    )


async def _assert_metrics_remote_user(
    client: httpx.AsyncClient, user_token: str
) -> None:
    # 3. Remote IP access with non-admin token -> 403 Forbidden
    res_remote_user = await client.get(
        "/metrics",
        headers={
            "CF-Connecting-IP": "203.0.113.195",
            "Authorization": f"Bearer {user_token}",
        },
    )
    assert res_remote_user.status_code == 403


async def _assert_metrics_remote_admin(
    client: httpx.AsyncClient, admin_token: str
) -> None:
    # 4. Remote IP access with admin token -> 200 OK
    res_remote_admin = await client.get(
        "/metrics",
        headers={
            "CF-Connecting-IP": "203.0.113.195",
            "Authorization": f"Bearer {admin_token}",
        },
    )
    assert res_remote_admin.status_code == 200
    assert "pr_agent_workspaces_free_bytes" in res_remote_admin.text


@pytest.mark.anyio
async def test_metrics_localhost_vs_remote_access() -> None:
    admin_token = "admin_metrics_token_123"
    register_bearer_token(
        admin_token,
        CallerIdentity(client_id="metrics_admin", allowed_repos=["*"], role="admin"),
    )

    user_token = "user_metrics_token_456"
    register_bearer_token(
        user_token,
        CallerIdentity(client_id="metrics_user", allowed_repos=["*"], role="user"),
    )

    transport = httpx.ASGITransport(app=prod_app)
    async with httpx.AsyncClient(
        transport=transport, base_url="http://testserver"
    ) as client:
        await _assert_metrics_localhost(client)
        await _assert_metrics_remote_unauth(client)
        await _assert_metrics_remote_user(client, user_token)
        await _assert_metrics_remote_admin(client, admin_token)


def _assert_ip(ip: str, expected: bool) -> None:
    assert is_localhost_ip(ip) is expected


def test_ip_helpers() -> None:
    _assert_ip("127.0.0.1", True)
    _assert_ip("127.0.1.1", True)
    _assert_ip("::1", True)
    _assert_ip("testclient", True)
    _assert_ip("203.0.113.5", False)
    _assert_ip("10.0.0.1", False)


@pytest.mark.anyio
async def test_job_ids_enforces_every_repo(tmp_path: Path) -> None:
    """Regression: multi-item job_ids must authorize EVERY repo (fail closed)."""
    db_file = tmp_path / "rbac_multi_jobs.db"
    prev_db = os.environ.get("JOB_DB_PATH")
    os.environ["JOB_DB_PATH"] = str(db_file)
    allowed = ""
    secret = ""
    try:
        init_db()
        from agent.job_store import dispatch_job

        allowed = dispatch_job(
            repo="example-org/sample-repo",
            persona="security-reviewer",
            command="audit",
            base_branch="main",
            allow_writes=False,
        )["job_id"]
        secret = dispatch_job(
            repo="Untrusted-Org/secret-repo",
            persona="security-reviewer",
            command="audit",
            base_branch="main",
            allow_writes=False,
        )["job_id"]

        caller = CallerIdentity(
            client_id="scoped",
            allowed_repos=["example-org/sample-repo"],
            role="user",
        )

        assert (
            enforce_rbac(caller, {"job_ids": [allowed]})
            == "example-org/sample-repo"
        )

        with pytest.raises(PermissionError):
            enforce_rbac(caller, {"job_ids": [allowed, secret]})

        with pytest.raises(PermissionError):
            enforce_rbac(caller, {"job_ids": ["nonexistent_job", secret]})
    finally:
        await _cancel_dispatched_jobs()
        if prev_db is None:
            os.environ.pop("JOB_DB_PATH", None)
        else:
            os.environ["JOB_DB_PATH"] = prev_db
