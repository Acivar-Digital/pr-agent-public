"""FastMCP + FastAPI dual-auth MCP Gateway constructor.

Provides `create_gateway_app` and `get_gateway_mcp_server` to instantiate the
FastAPI gateway server with FastMCP Streamable HTTP transports, dual authentication
(Secret URL Path and Bearer token), and zero body-read ASGI protection.
"""

from __future__ import annotations

import os

from fastapi import APIRouter, FastAPI
from mcp.server.mcpserver import MCPServer
from mcp.server.transport_security import TransportSecuritySettings

from src.orchestrator.auth import (
    ZeroBodyReadAuthMiddleware,
    attach_rbac_middleware,
)
from src.orchestrator.middleware.redactor import attach_secret_scrubber_middleware


def _build_mcp_server(server: MCPServer | None, instructions: str | None) -> MCPServer:
    """Return the provided server, or construct the default FastMCP server."""
    return server or MCPServer(
        name="vps-github-swarm-orchestrator",
        instructions=instructions or "VPS FastMCP Swarm Gateway",
    )


def create_gateway_app(
    server: MCPServer | None = None,
    secret_path: str | None = None,
    instructions: str | None = None,
    router: APIRouter | None = None,
) -> tuple[FastAPI, MCPServer]:
    """Create a FastAPI gateway application with an attached FastMCP server.

    Mounts Streamable HTTP at /gemini/{secret_path}/mcp and /mcp with zero
    body-read dual authentication and repo-scoped RBAC.
    """
    mcp_secret = (
        secret_path
        if secret_path is not None
        else os.environ.get("MCP_SECRET_PATH", "")
    ).strip("/")

    mcp_server = _build_mcp_server(server, instructions)

    attach_secret_scrubber_middleware(mcp_server)
    attach_rbac_middleware(mcp_server)

    app = FastAPI(title="VPS FastMCP Dual-Auth Gateway")
    if router is not None:
        app.include_router(router)

    streamable_app = mcp_server.streamable_http_app(
        streamable_http_path="/mcp",
        stateless_http=True,
        transport_security=TransportSecuritySettings(
            enable_dns_rebinding_protection=False
        ),
    )

    if mcp_secret:
        app.mount(f"/gemini/{mcp_secret}", streamable_app)
    app.mount("", streamable_app)

    app.add_middleware(ZeroBodyReadAuthMiddleware, secret_path=mcp_secret)

    return app, mcp_server
