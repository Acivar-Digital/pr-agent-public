from __future__ import annotations

import logging
import types
from typing import cast

import pytest
from fastapi import Request
from fastapi.testclient import TestClient


@pytest.fixture(scope="module")
def obs_client(tmp_path_factory):
    # Per-test TestClient entry re-runs the app lifespan, whose MCP
    # StreamableHTTPSessionManager.run() can only be called once per process.
    # Use a module-scoped client with proper teardown instead.
    import os

    tmp = tmp_path_factory.mktemp("obs4_")
    prev_db = os.environ.get("JOB_DB_PATH")
    prev_ws = os.environ.get("WORKSPACES_DIR")
    os.environ["JOB_DB_PATH"] = str(tmp / "test.db")
    os.environ["WORKSPACES_DIR"] = str(tmp / "ws")

    from agent.job_store import init_db

    init_db()

    from server.app import app

    try:
        with TestClient(app) as client:
            yield client
    finally:
        if prev_db is None:
            os.environ.pop("JOB_DB_PATH", None)
        else:
            os.environ["JOB_DB_PATH"] = prev_db
        if prev_ws is None:
            os.environ.pop("WORKSPACES_DIR", None)
        else:
            os.environ["WORKSPACES_DIR"] = prev_ws


def test_extract_client_ip_prefers_cf_connecting_ip() -> None:
    from server.app import extract_client_ip

    stub = types.SimpleNamespace(
        headers={
            "cf-connecting-ip": "203.0.113.5",
            "x-forwarded-for": "198.51.100.2, 10.0.0.1",
        },
        client=types.SimpleNamespace(host="127.0.0.1"),
    )
    assert extract_client_ip(cast(Request, stub)) == "203.0.113.5"


def test_extract_client_ip_falls_back_to_xff() -> None:
    from server.app import extract_client_ip

    stub = types.SimpleNamespace(
        headers={"x-forwarded-for": "198.51.100.7, 10.0.0.1"},
        client=types.SimpleNamespace(host="127.0.0.1"),
    )
    assert extract_client_ip(cast(Request, stub)) == "198.51.100.7"


def test_extract_client_ip_falls_back_to_client_host() -> None:
    from server.app import extract_client_ip

    stub = types.SimpleNamespace(
        headers={},
        client=types.SimpleNamespace(host="127.0.0.1"),
    )
    assert extract_client_ip(cast(Request, stub)) == "127.0.0.1"


def test_middleware_logs_real_ip_and_scrubs_mcp_secret(obs_client, caplog) -> None:
    caplog.set_level(logging.INFO, logger="server.app")
    resp = obs_client.get(
        "/gemini/secret_token_abcdefghijklmnopqrstuvwxyz",
        headers={"CF-Connecting-IP": "203.0.113.9"},
    )
    assert "X-Request-ID" in resp.headers
    log_text = caplog.text
    assert "ip=203.0.113.9" in log_text
    assert "secret_token_abcdefghijklmnopqrstuvwxyz" not in log_text
    assert "/gemini/[REDACTED]" in log_text


def test_health_and_metrics_routes_mounted(obs_client) -> None:
    health = obs_client.get("/health")
    assert health.status_code == 200

    metrics = obs_client.get("/metrics")
    assert metrics.status_code == 200
    assert "pr_agent_workspaces_free_bytes" in metrics.text


def test_list_open_prs_uses_read_headers() -> None:
    from pathlib import Path

    src = Path("server/app.py").read_text(encoding="utf-8")
    start = src.index("async def list_open_prs")
    end = src.index("@gemini_mcp.tool()", start)
    span = src[start:end]
    assert "_gh_read_headers" in span
    assert "_gh_headers" not in span
