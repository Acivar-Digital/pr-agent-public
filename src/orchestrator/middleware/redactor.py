"""Outbound secret scrubber FastMCP middleware.

Provides deterministic, high-precision regex-based secret scrubbing for outbound
MCP tool results, prompts, and resources. Guarantees:
- Pure regex matching (zero heavy NLP/spaCy/Presidio dependencies).
- Fail-closed execution without blocking the asyncio event loop (executed in asyncio.to_thread).
- Truncate-before-scrub for payloads > 512 KB with [TRUNCATED] marker to prevent regex DoS.
- Zero false positives on code diffs, commit SHAs, line numbers, port numbers,
  or standard variable names like token/password.
"""

from __future__ import annotations

import asyncio
import re
from typing import Any, cast

import structlog
from mcp.server.context import CallNext, HandlerResult, ServerRequestContext
from mcp.server.mcpserver import MCPServer
from pydantic import BaseModel

logger = structlog.get_logger(__name__)

# Payload cap: 512 KB
MAX_PAYLOAD_BYTES = 512 * 1024
TRUNCATION_MARKER = "\n[TRUNCATED]"

# Redaction placeholders
REDACTED_PRIVATE_KEY = "[REDACTED_PRIVATE_KEY]"
REDACTED_GITHUB_TOKEN = "[REDACTED_GITHUB_TOKEN]"
REDACTED_AWS_KEY = "[REDACTED_AWS_KEY]"
REDACTED_API_KEY = "[REDACTED_API_KEY]"
REDACTED_JWT = "[REDACTED_JWT]"
REDACTED_SECRET = "[REDACTED_SECRET]"

# High-precision deterministic compiled regexes
PATTERNS: list[tuple[str, re.Pattern[str], str]] = [
    # 1. Private key blocks (RSA, EC, DSA, OPENSSH, or generic)
    (
        "private_key",
        re.compile(
            r"-----BEGIN (?:[A-Z0-9_-]+ )?PRIVATE KEY-----[\s\S]*?-----END (?:[A-Z0-9_-]+ )?PRIVATE KEY-----"
        ),
        REDACTED_PRIVATE_KEY,
    ),
    # 2. GitHub PATs and tokens: classic ghp_, oauth gho_, fine-grained github_pat_, user/server/refresh tokens
    (
        "github_token",
        re.compile(
            r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,}\b|\bgithub_pat_[A-Za-z0-9_]{50,}\b"
        ),
        REDACTED_GITHUB_TOKEN,
    ),
    # 3. AWS Access Keys: standard AKIA or temporary ASIA prefix + 16 alphanumeric uppercase chars
    (
        "aws_key",
        re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
        REDACTED_AWS_KEY,
    ),
    # 4. OpenAI / Anthropic / generic sk- API keys (20+ chars)
    (
        "api_key",
        re.compile(r"\b(?:sk-proj-|sk-ant-|sk-)[A-Za-z0-9_-]{20,}\b"),
        REDACTED_API_KEY,
    ),
    # 5. JWT tokens: three base64url segments starting with header 'eyJ'
    (
        "jwt",
        re.compile(
            r"\beyJ[A-Za-z0-9_=-]{10,}\.[A-Za-z0-9_=-]{10,}(?:\.[A-Za-z0-9_.+/=-]*)?\b"
        ),
        REDACTED_JWT,
    ),
    # 5b. Generic Bearer tokens (after specific JWT/API-key rules so [REDACTED_JWT] is preserved)
    (
        "bearer_token",
        re.compile(r"\bBearer\s+(?!\[REDACTED_)[A-Za-z0-9._-]{16,}\b"),
        "Bearer " + REDACTED_SECRET,
    ),
    # 6. JSON/quoted secret fields: "token": "..." / 'password': '...' / bare token values.
    # The key must be a recognized secret name (case-insensitive); only the VALUE is
    # redacted so the key, its quotes and the colon survive. Values already redacted by
    # the specific rules above are skipped via the (?!\[REDACTED_) lookahead, and the
    # value may not start with whitespace so `\s*` cannot backtrack past that guard.
    (
        "json_secret",
        re.compile(
            r"(?i)(([\"'])(?:client[_-]?secret|private[_-]?key|access[_-]?key|api[_-]?key"
            r"|passwd|password|token|secret|credential|auth)\2\s*:\s*)"
            r"([\"']?)(?!\[REDACTED_)(?![\"'])([^\s][^\n]*?)\3(?=\s*(?:[,}\]]|$))"
        ),
        r"\1\3" + REDACTED_SECRET + r"\3",
    ),
    # 7. Strict .env secret assignments: scoped strictly to secret-named uppercase keys (*_KEY=, *_TOKEN=, *_SECRET=, *_PASSWORD=)
    # Skips values already redacted by higher-precedence specific rules (via negative lookahead (?!\[REDACTED_))
    # Excludes plain lower-case code variables, function args, commit SHAs, line numbers, and ports.
    (
        "env_secret",
        re.compile(
            r"(^[+-]?\s*[A-Z0-9_]+_(?:KEY|TOKEN|SECRET|PASSWORD)\s*=\s*)(['\"]?)(?!\[REDACTED_)(.+?)\2\s*$",
            re.MULTILINE,
        ),
        r"\1\2" + REDACTED_SECRET + r"\2",
    ),
]


class SecretRedactor:
    """Synchronous and asynchronous secret redactor using deterministic high-precision regexes."""

    def __init__(self, max_payload_bytes: int = MAX_PAYLOAD_BYTES) -> None:
        self.max_payload_bytes = max_payload_bytes

    def _apply_patterns(self, text: str) -> tuple[str, dict[str, int]]:
        """Apply every compiled redaction pattern, returning redacted text and per-pattern counts."""
        counts: dict[str, int] = {}
        result = text
        for name, pattern, repl in PATTERNS:
            result, matches = pattern.subn(repl, result)
            if matches > 0:
                counts[name] = counts.get(name, 0) + matches
        return result, counts

    def _truncate(self, text: str) -> tuple[str, bool]:
        """Truncate text exceeding max_payload_bytes with [TRUNCATED] before scanning."""
        if len(text.encode("utf-8", errors="replace")) <= self.max_payload_bytes:
            return text, False
        # Slices up to max_payload_bytes characters
        return text[: self.max_payload_bytes] + TRUNCATION_MARKER, True

    def redact_text(self, text: str) -> tuple[str, dict[str, int]]:
        """Redact secrets from a single text string.

        Safely truncates text exceeding max_payload_bytes with [TRUNCATED] before scanning.
        Returns a tuple of (redacted_text, redaction_counts).
        """
        if not text:
            return text, {}

        # Truncate-before-scrub to prevent regex DoS
        text, truncated = self._truncate(text)

        result, pattern_counts = self._apply_patterns(text)

        counts: dict[str, int] = {}
        if truncated:
            counts["truncated"] = 1
        for name, count in pattern_counts.items():
            counts[name] = counts.get(name, 0) + count

        return result, counts

    def _redact_dict(self, payload: dict[Any, Any]) -> tuple[Any, dict[str, int]]:
        """Recursively redact a mapping's keys and values, merging per-key counts."""
        new_dict: dict[Any, Any] = {}
        total_counts: dict[str, int] = {}
        for k, v in payload.items():
            new_k, k_counts = self.redact_text(k) if isinstance(k, str) else (k, {})
            new_v, v_counts = self.redact_payload(v)
            new_dict[new_k] = new_v
            for name, count in (*k_counts.items(), *v_counts.items()):
                total_counts[name] = total_counts.get(name, 0) + count
        return new_dict, total_counts

    def _redact_sequence(
        self, payload: list[Any] | tuple[Any, ...]
    ) -> tuple[Any, dict[str, int]]:
        """Recursively redact a list/tuple's items, preserving the container type."""
        new_items: list[Any] = []
        total_counts: dict[str, int] = {}
        for item in payload:
            new_item, counts = self.redact_payload(item)
            new_items.append(new_item)
            for name, count in counts.items():
                total_counts[name] = total_counts.get(name, 0) + count
        res_container = tuple(new_items) if isinstance(payload, tuple) else new_items
        return res_container, total_counts

    def redact_payload(self, payload: Any) -> tuple[Any, dict[str, int]]:
        """Recursively redact secrets across arbitrary payloads (str, dict, list, tuple, BaseModel)."""
        if isinstance(payload, str):
            return self.redact_text(payload)

        if isinstance(payload, dict):
            return self._redact_dict(payload)

        if isinstance(payload, (list, tuple)):
            return self._redact_sequence(payload)

        if isinstance(payload, BaseModel):
            dumped = payload.model_dump()
            redacted_dumped, counts = self.redact_payload(dumped)
            return type(payload).model_validate(redacted_dumped), counts

        return payload, {}

    async def redact_async(self, payload: Any) -> tuple[Any, dict[str, int]]:
        """Offload payload redaction to asyncio.to_thread to keep the event loop non-blocking."""
        return await asyncio.to_thread(self.redact_payload, payload)


# Global default redactor instance
_DEFAULT_REDACTOR = SecretRedactor()


def scrub_secrets(payload: Any) -> tuple[Any, dict[str, int]]:
    """Convenience helper to redact secrets from a payload using the default redactor."""
    return _DEFAULT_REDACTOR.redact_payload(payload)


class SecretScrubberMiddleware:
    """Universal FastMCP server output middleware for scrubbing secrets from all tool outputs."""

    def __init__(self, redactor: SecretRedactor | None = None) -> None:
        self.redactor = redactor or _DEFAULT_REDACTOR

    async def _scrub(
        self, ctx: ServerRequestContext[Any, Any], result: Any
    ) -> HandlerResult:
        """Redact secrets from an outbound result, logging any redactions."""
        redacted_result, counts = await self.redactor.redact_async(result)
        if counts:
            logger.info(
                "Outbound secrets redacted by FastMCP middleware",
                method=ctx.method,
                counts=counts,
            )
        return cast(HandlerResult, redacted_result)

    def _fail_closed(
        self, ctx: ServerRequestContext[Any, Any], result: Any, exc: Exception
    ) -> HandlerResult | None:
        """Return a scrub-failure error result, or None when the caller must re-raise."""
        logger.error(
            "Error during outbound secret scrubbing; failing closed",
            error=str(exc),
            method=ctx.method,
        )
        # Fail-closed behavior: never leak raw result on failure
        if isinstance(result, dict) and "isError" in result:
            return {
                "content": [
                    {"type": "text", "text": "[ERROR: Secret scrubbing failed]"}
                ],
                "isError": True,
            }
        return None

    async def __call__(
        self,
        ctx: ServerRequestContext[Any, Any],
        call_next: CallNext,
    ) -> HandlerResult:
        result = await call_next(ctx)

        # Intercept outbound tool calls, prompt responses, and resource reads
        if ctx.method not in ("tools/call", "resources/read", "prompts/get"):
            return result

        try:
            return await self._scrub(ctx, result)
        except Exception as e:
            fail_closed = self._fail_closed(ctx, result, e)
            if fail_closed is not None:
                return fail_closed
            raise


def attach_secret_scrubber_middleware(
    server: MCPServer, redactor: SecretRedactor | None = None
) -> SecretScrubberMiddleware:
    """Attach the universal outbound secret scrubber middleware to an MCPServer instance."""
    middleware = SecretScrubberMiddleware(redactor)
    server.middleware.append(middleware)
    return middleware
