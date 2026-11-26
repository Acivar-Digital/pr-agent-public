"""Unit and integration tests for Outbound Secret Scrubber FastMCP Middleware."""

from __future__ import annotations

from typing import Any, cast

import httpx
import pytest
from mcp.server.context import CallNext, ServerRequestContext
from mcp.server.mcpserver import MCPServer
from mcp.server.transport_security import TransportSecuritySettings
from pydantic import BaseModel, ConfigDict

from src.orchestrator.middleware.redactor import (
    MAX_PAYLOAD_BYTES,
    REDACTED_API_KEY,
    REDACTED_AWS_KEY,
    REDACTED_GITHUB_TOKEN,
    REDACTED_JWT,
    REDACTED_PRIVATE_KEY,
    REDACTED_SECRET,
    SecretRedactor,
    SecretScrubberMiddleware,
    attach_secret_scrubber_middleware,
    scrub_secrets,
)


class SampleModel(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str
    secret_value: str
    nested_list: list[str]


def _assert_all(checks: list[tuple[bool, str]]) -> None:
    for ok, message in checks:
        assert ok, message


def test_redact_private_keys() -> None:
    redactor = SecretRedactor()

    rsa_key = (
        "-----BEGIN RSA PRIVATE KEY-----\n"
        "MIIEowIBAAKCAQEA0Yxyz123...\n"
        "-----END RSA PRIVATE KEY-----"
    )
    ec_key = (
        "-----BEGIN EC PRIVATE KEY-----\n"
        "MHcCAQEEIAbc123...\n"
        "-----END EC PRIVATE KEY-----"
    )

    text = f"Config before:\n{rsa_key}\nand EC:\n{ec_key}\nDone."
    redacted, counts = redactor.redact_text(text)

    assert REDACTED_PRIVATE_KEY in redacted
    assert "BEGIN RSA PRIVATE KEY" not in redacted
    assert "BEGIN EC PRIVATE KEY" not in redacted
    assert counts.get("private_key") == 2


def test_redact_github_tokens() -> None:
    redactor = SecretRedactor()

    classic_pat = "ghp_123456789012345678901234567890123456"
    oauth_token = "gho_abcdefghijklmnopqrstuvwxyz0123456789"
    fine_grained = "github_pat_11AAAAAAA01234567890123456789012345678901234567890123456789012345678901234"

    text = f"Tokens: {classic_pat}, {oauth_token}, and {fine_grained}."
    redacted, counts = redactor.redact_text(text)

    _assert_all(
        [
            (classic_pat not in redacted, "classic PAT leaked"),
            (oauth_token not in redacted, "oauth token leaked"),
            (fine_grained not in redacted, "fine-grained token leaked"),
            (redacted.count(REDACTED_GITHUB_TOKEN) == 3, "redaction marker count"),
            (counts.get("github_token") == 3, "github_token count"),
        ]
    )


def test_redact_aws_keys() -> None:
    redactor = SecretRedactor()

    standard_key = "AKIAIOSFODNN7EXAMPLE"
    temp_key = "ASIAIOSFODNN7EXAMPLE"

    text = f"AWS: {standard_key} and temporary: {temp_key}."
    redacted, counts = redactor.redact_text(text)

    assert standard_key not in redacted
    assert temp_key not in redacted
    assert redacted.count(REDACTED_AWS_KEY) == 2
    assert counts.get("aws_key") == 2


def test_redact_api_keys() -> None:
    redactor = SecretRedactor()

    openai_key = "sk-proj-abc123xyz4567890abc123xyz4567890"
    anthropic_key = "sk-ant-api03-abcdef1234567890abcdef1234567890"

    text = f"OpenAI: {openai_key}, Anthropic: {anthropic_key}."
    redacted, counts = redactor.redact_text(text)

    assert openai_key not in redacted
    assert anthropic_key not in redacted
    assert redacted.count(REDACTED_API_KEY) == 2
    assert counts.get("api_key") == 2


def test_redact_jwt() -> None:
    redactor = SecretRedactor()

    jwt_token = (
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
        "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ."
        "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
    )

    text = f"Bearer {jwt_token} auth"
    redacted, counts = redactor.redact_text(text)

    assert jwt_token not in redacted
    assert REDACTED_JWT in redacted
    assert counts.get("jwt") == 1


def test_redact_env_secrets() -> None:
    redactor = SecretRedactor()

    env_content = (
        "PORT=8080\n"
        "DEBUG=true\n"
        "API_KEY=my_super_secret_key_123\n"
        'DATABASE_PASSWORD="db_pass_456"\n'
        "AWS_SECRET_ACCESS_KEY='secret_aws_val'\n"
        "+MY_SECRET=diff_added_val\n"
        "-OLD_TOKEN=diff_removed_val\n"
    )

    redacted, counts = redactor.redact_text(env_content)

    _assert_all(
        [
            ("PORT=8080" in redacted, "PORT preserved"),
            ("DEBUG=true" in redacted, "DEBUG preserved"),
            (f"API_KEY={REDACTED_SECRET}" in redacted, "API_KEY redacted"),
            (
                f'DATABASE_PASSWORD="{REDACTED_SECRET}"' in redacted,
                "DATABASE_PASSWORD redacted",
            ),
            (
                f"AWS_SECRET_ACCESS_KEY='{REDACTED_SECRET}'" in redacted,
                "AWS_SECRET_ACCESS_KEY redacted",
            ),
            (f"+MY_SECRET={REDACTED_SECRET}" in redacted, "+MY_SECRET redacted"),
            (f"-OLD_TOKEN={REDACTED_SECRET}" in redacted, "-OLD_TOKEN redacted"),
            (counts.get("env_secret") == 5, "env_secret count"),
        ]
    )


def test_zero_false_positives_code_diff() -> None:
    redactor = SecretRedactor()

    diff_content = """
diff --git a/server/auth.py b/server/auth.py
index a4626b0..dae964af 100644
--- a/server/auth.py
+++ b/server/auth.py
@@ -10,6 +10,14 @@ def verify_login(token: str, password: str = "") -> bool:
     port = 8080
     line_no = 42
     commit_sha = "dae964af309c5fd3a17240eb9183c4be6dd7e2ce"
+    user_token = request.headers.get("Authorization")
+    user_password = form.get("password")
+    if not user_token or not user_password:
+        return False
+    return check_credentials(token=user_token, password=user_password, port=port)
"""

    redacted, counts = redactor.redact_text(diff_content)

    assert counts == {}
    assert redacted == diff_content


def test_truncate_before_scrub() -> None:
    redactor = SecretRedactor()

    head = "sk-proj-supersecretkey1234567890abc\n"
    large_body = "A" * (MAX_PAYLOAD_BYTES + 1000)
    payload = head + large_body

    redacted, counts = redactor.redact_text(payload)

    _assert_all(
        [
            ("[TRUNCATED]" in redacted, "truncation marker present"),
            (REDACTED_API_KEY in redacted, "api key redacted"),
            (counts.get("truncated") == 1, "truncated count"),
            (counts.get("api_key") == 1, "api_key count"),
            (
                len(redacted.encode("utf-8"))
                <= MAX_PAYLOAD_BYTES + len("\n[TRUNCATED]") + 50,
                "payload size bounded",
            ),
        ]
    )


def test_recursive_payload_scrubbing() -> None:
    redactor = SecretRedactor()

    payload = {
        "repo": "example-org/sample-repo",
        "nested": {
            "token": "ghp_123456789012345678901234567890123456",
            "items": [
                "plain_text",
                "sk-proj-123456789012345678901234",
            ],
            "tuple_items": (
                "AKIAIOSFODNN7EXAMPLE",
                "clean_tuple_item",
            ),
        },
        "count": 42,
    }

    redacted, counts = redactor.redact_payload(payload)

    _assert_all(
        [
            (
                redacted["nested"]["token"] == REDACTED_GITHUB_TOKEN,
                "nested token redacted",
            ),
            (
                redacted["nested"]["items"][1] == REDACTED_API_KEY,
                "nested item redacted",
            ),
            (
                isinstance(redacted["nested"]["tuple_items"], tuple),
                "tuple type preserved",
            ),
            (
                redacted["nested"]["tuple_items"][0] == REDACTED_AWS_KEY,
                "tuple item redacted",
            ),
            (redacted["count"] == 42, "count preserved"),
            (counts["github_token"] == 1, "github_token count"),
            (counts["api_key"] == 1, "api_key count"),
            (counts["aws_key"] == 1, "aws_key count"),
        ]
    )


def test_pydantic_model_scrubbing() -> None:
    model = SampleModel(
        name="test_agent",
        secret_value="ghp_123456789012345678901234567890123456",
        nested_list=["clean", "AKIAIOSFODNN7EXAMPLE"],
    )

    redacted_model, counts = scrub_secrets(model)

    _assert_all(
        [
            (isinstance(redacted_model, SampleModel), "model type preserved"),
            (
                redacted_model.secret_value == REDACTED_GITHUB_TOKEN,
                "secret_value redacted",
            ),
            (
                redacted_model.nested_list[1] == REDACTED_AWS_KEY,
                "nested_list item redacted",
            ),
            (counts["github_token"] == 1, "github_token count"),
            (counts["aws_key"] == 1, "aws_key count"),
        ]
    )


@pytest.mark.anyio
async def test_async_redact_non_blocking() -> None:
    redactor = SecretRedactor()
    text = "Secret: ghp_123456789012345678901234567890123456"

    redacted, counts = await redactor.redact_async(text)
    assert REDACTED_GITHUB_TOKEN in redacted
    assert counts["github_token"] == 1


@pytest.mark.anyio
async def test_fastmcp_middleware_wire_interception() -> None:
    server = MCPServer("test-secure-server")

    @server.tool()
    async def get_pr_diff() -> str:
        return (
            "diff --git a/.env b/.env\n"
            "+API_KEY=supersecret12345\n"
            "+GITHUB_TOKEN=ghp_123456789012345678901234567890123456\n"
        )

    attach_secret_scrubber_middleware(server)

    app = server.streamable_http_app(
        streamable_http_path="/mcp",
        transport_security=TransportSecuritySettings(
            enable_dns_rebinding_protection=False
        ),
    )

    async with server.session_manager.run():
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(
            transport=transport, base_url="http://test"
        ) as client:
            init_res = await client.post(
                "/mcp",
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
            session_id = init_res.headers.get("mcp-session-id")
            headers = {"mcp-session-id": session_id} if session_id else {}

            tool_res = await client.post(
                "/mcp",
                headers=headers,
                json={
                    "jsonrpc": "2.0",
                    "id": 2,
                    "method": "tools/call",
                    "params": {"name": "get_pr_diff", "arguments": {}},
                },
            )
            body = tool_res.text

            _assert_all(
                [
                    (init_res.status_code == 200, "init status"),
                    (tool_res.status_code == 200, "tool status"),
                    ("ghp_" not in body, "github token leaked"),
                    ("supersecret12345" not in body, "api key leaked"),
                    (REDACTED_GITHUB_TOKEN in body, "github redaction marker"),
                    (REDACTED_SECRET in body, "secret redaction marker"),
                ]
            )


class FailingRedactor(SecretRedactor):
    def redact_payload(self, payload: Any) -> tuple[Any, dict[str, int]]:
        raise RuntimeError("Simulated crash inside redactor")


@pytest.mark.anyio
async def test_middleware_fail_closed_on_error() -> None:
    middleware = SecretScrubberMiddleware(redactor=FailingRedactor())

    class MockContext:
        method = "tools/call"

    async def mock_call_next(ctx: ServerRequestContext[Any, Any]) -> dict[str, Any]:
        return {"content": [{"type": "text", "text": "secret"}], "isError": False}

    typed_ctx = cast(ServerRequestContext[Any, Any], MockContext())
    typed_call_next = cast(CallNext, mock_call_next)

    res = await middleware(typed_ctx, typed_call_next)
    assert isinstance(res, dict)
    assert res.get("isError") is True
    assert "[ERROR: Secret scrubbing failed]" in res["content"][0]["text"]


def test_redact_json_quoted_secret() -> None:
    redactor = SecretRedactor()

    token = "ghp_123456789012345678901234567890123456"
    text = f'{{"token": "{token}", "user": "bob"}}'

    redacted, _counts = redactor.redact_text(text)

    assert token not in redacted
    assert "[REDACTED" in redacted
    assert '"user": "bob"' in redacted
    assert '"token"' in redacted


def test_redact_json_password() -> None:
    redactor = SecretRedactor()

    text = '{"password": "hunter2"}'

    redacted, _counts = redactor.redact_text(text)

    assert "hunter2" not in redacted
    assert '"password"' in redacted
    assert REDACTED_SECRET in redacted


def test_json_secret_count() -> None:
    redactor = SecretRedactor()

    text = '{"password": "hunter2", "api_key": "abc123", "user": "bob"}'

    redacted, counts = redactor.redact_text(text)

    assert counts.get("json_secret") == 2
    assert "hunter2" not in redacted
    assert "abc123" not in redacted
    assert '"user": "bob"' in redacted
