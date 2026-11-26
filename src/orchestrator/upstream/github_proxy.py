"""Pinned upstream GitHub MCP proxy.

Exposes exactly four read-only GitHub tools (``list_pull_requests``,
``get_pull_request``, ``list_issues``, ``get_issue``) and proxies them to an
upstream MCP server through a long-lived :class:`ProxyClient`. Every call is
fail-closed:

1. Tool must be in :data:`UPSTREAM_TOOL_ALLOWLIST` (no write/mutation tools).
2. Indirect identifiers (``job_id``/``job_ids``/``id``/``ids``) are rejected;
   only direct ``owner``/``repo`` addressing is accepted.
3. ``owner``/``repo`` segments are strictly validated (no smuggling/traversal).
4. The target repository must be inside the proxy's ``allowed_repos`` ceiling
   **and** authorized by the caller identity (both, case-insensitive).
5. The full connect + call lifecycle is bounded by a timeout (15s default).
6. The result is redacted before it leaves the process (fail closed).
7. The call — and every denial — is recorded in the append-only audit log.
"""

from __future__ import annotations

import asyncio
import copy
import dataclasses
import re
import time
from collections.abc import Callable, Iterable, Mapping
from contextlib import suppress
from typing import Any

from fastmcp import FastMCP
from fastmcp.server.providers.proxy import ProxyClient

from src.orchestrator.auth import CallerIdentity, get_current_caller_identity
from src.orchestrator.middleware.audit import AuditLogger
from src.orchestrator.middleware.redactor import SecretRedactor

UPSTREAM_TOOL_ALLOWLIST: frozenset[str] = frozenset(
    {
        "list_pull_requests",
        "get_pull_request",
        "list_issues",
        "get_issue",
    }
)

DEFAULT_TIMEOUT_SECONDS = 15

INDIRECT_IDENTIFIER_KEYS: frozenset[str] = frozenset({"job_id", "job_ids", "id", "ids"})

# A single GitHub owner/repo path segment: no slashes, no traversal.
_SEGMENT_RE = re.compile(r"^[A-Za-z0-9._-]+$")


def _jsonable(obj: Any) -> Any:
    """Best-effort conversion of arbitrary result objects to JSON-safe data."""
    if obj is None or isinstance(obj, (bool, int, float, str)):
        return obj
    if isinstance(obj, dict):
        return {str(k): _jsonable(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [_jsonable(v) for v in obj]
    return str(obj)


def _with_text(block: Any, text: str) -> Any:
    """Return a copy of a content block with its ``text`` replaced."""
    model_copy = getattr(block, "model_copy", None)
    if callable(model_copy):
        return model_copy(update={"text": text})
    new_block = copy.copy(block)
    try:
        new_block.text = text
    except (AttributeError, ValueError):
        return block
    return new_block


def _valid_segment(value: str) -> bool:
    return bool(_SEGMENT_RE.match(value)) and value not in {".", ".."}


def _valid_slug_parts(parts: list[str]) -> bool:
    return len(parts) == 2 and all(_valid_segment(p) for p in parts)


def _merge_counts(total: dict[str, int], counts: Mapping[str, int]) -> None:
    for name, count in counts.items():
        total[name] = total.get(name, 0) + count


class GitHubProxy:
    """Read-only, RBAC-enforced, redacting proxy in front of an upstream MCP server."""

    def __init__(
        self,
        *,
        client_factory: Callable[[], ProxyClient],
        allowed_repos: Iterable[str],
        audit: AuditLogger | None = None,
        redactor: SecretRedactor | None = None,
        timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS,
    ) -> None:
        self.client_factory = client_factory
        self.allowed_repos = frozenset(allowed_repos)
        self.audit = audit
        self.redactor = redactor
        self.timeout_seconds = timeout_seconds
        self.server: FastMCP | None = None
        self._client: ProxyClient | None = None
        self._client_lock = asyncio.Lock()

    def tool_names(self) -> frozenset[str]:
        """Return the exact set of tool names this proxy exposes."""
        return UPSTREAM_TOOL_ALLOWLIST

    def _repo_allowed(self, repo: str) -> bool:
        """Enforce the proxy's own ``allowed_repos`` ceiling (fail closed if empty)."""
        allowed = {r.strip().lower() for r in self.allowed_repos}
        if not allowed:
            return False
        return repo.strip().lower() in allowed

    def _resolve_repo(self, arguments: Mapping[str, Any]) -> str:
        """Resolve a strict ``owner/repo`` slug; reject smuggling and traversal."""
        owner, repo = self._extract_owner_repo(arguments)
        if not repo:
            raise PermissionError(
                "Repository could not be resolved: direct 'repo' or 'owner' + 'repo' required"
            )
        if "/" in repo:
            return self._resolve_slug(owner, repo)
        if owner:
            return self._resolve_pair(owner, repo)
        return self._reject_bare_repo(repo)

    @staticmethod
    def _extract_owner_repo(arguments: Mapping[str, Any]) -> tuple[str, str]:
        owner = str(arguments.get("owner") or "").strip()
        repo = str(arguments.get("repo") or "").strip()
        return owner, repo

    @staticmethod
    def _resolve_slug(owner: str, repo: str) -> str:
        parts = repo.split("/")
        if not _valid_slug_parts(parts):
            raise PermissionError(f"Invalid repository slug: {repo!r}")
        slug_owner, slug_repo = parts
        if owner and owner.lower() != slug_owner.lower():
            raise PermissionError("Argument 'owner' disagrees with the repository slug")
        return f"{slug_owner}/{slug_repo}"

    @staticmethod
    def _resolve_pair(owner: str, repo: str) -> str:
        if not _valid_segment(owner) or not _valid_segment(repo):
            raise PermissionError("Invalid 'owner' or 'repo' segment")
        return f"{owner}/{repo}"

    @staticmethod
    def _reject_bare_repo(repo: str) -> str:
        # A bare repo name is not a valid GitHub slug; require owner + repo.
        if not _valid_segment(repo):
            raise PermissionError(f"Invalid repository segment: {repo!r}")
        raise PermissionError(
            "Repository could not be resolved: 'owner' + 'repo' required"
        )

    def _redact_result(self, result: Any) -> tuple[Any, dict[str, int]]:
        """Redact a tool result, reconstructing the object or failing closed."""
        redactor = self.redactor or SecretRedactor()
        redacted, counts = redactor.redact_payload(result)
        if redacted is not result:
            return redacted, counts

        # The redactor cannot introspect this result type: scrub its text blocks
        # (and any structured payloads) explicitly. Never return raw text.
        total: dict[str, int] = {}
        new_content = self._redact_content(redactor, result, total)
        new_data = self._redact_field(
            redactor, getattr(result, "data", None), total, (str, dict, list, tuple)
        )
        new_structured = self._redact_field(
            redactor, getattr(result, "structured_content", None), total, (dict,)
        )
        return self._reconstruct(result, new_content, new_data, new_structured, total)

    @staticmethod
    def _redact_content(
        redactor: SecretRedactor, result: Any, total: dict[str, int]
    ) -> list[Any]:
        new_content: list[Any] = []
        for block in getattr(result, "content", []) or []:
            text = getattr(block, "text", None)
            if isinstance(text, str):
                new_text, block_counts = redactor.redact_text(text)
                _merge_counts(total, block_counts)
                if new_text != text:
                    block = _with_text(block, new_text)
            new_content.append(block)
        return new_content

    @staticmethod
    def _redact_field(
        redactor: SecretRedactor,
        value: Any,
        total: dict[str, int],
        types: tuple[type, ...],
    ) -> Any:
        if isinstance(value, types):
            new_value, counts = redactor.redact_payload(value)
            _merge_counts(total, counts)
            return new_value
        return value

    @staticmethod
    def _reconstruct(
        result: Any,
        new_content: list[Any],
        new_data: Any,
        new_structured: Any,
        total: dict[str, int],
    ) -> tuple[Any, dict[str, int]]:
        if dataclasses.is_dataclass(result) and not isinstance(result, type):
            return (
                dataclasses.replace(
                    result,
                    content=new_content,
                    data=new_data,
                    structured_content=new_structured,
                ),
                total,
            )

        model_copy = getattr(result, "model_copy", None)
        if callable(model_copy):
            with suppress(Exception):
                return model_copy(
                    update={
                        "content": new_content,
                        "data": new_data,
                        "structured_content": new_structured,
                    }
                ), total

        # Unknown result type: fail closed with a redacted plain projection.
        return (
            {
                "content": [getattr(block, "text", None) for block in new_content],
                "data": _jsonable(new_data),
                "structured_content": _jsonable(new_structured),
                "is_error": bool(getattr(result, "is_error", False)),
            },
            total,
        )

    @staticmethod
    def _audit_payload(result: Any) -> dict[str, Any]:
        """Project a redacted result onto a JSON-safe audit payload."""
        content = getattr(result, "content", None)
        texts = [
            getattr(block, "text", None)
            for block in (content or [])
            if isinstance(getattr(block, "text", None), str)
        ]
        return {
            "content": texts,
            "data": _jsonable(getattr(result, "data", None)),
            "structured_content": _jsonable(
                getattr(result, "structured_content", None)
            ),
            "is_error": bool(getattr(result, "is_error", False)),
        }

    async def _ensure_client(self) -> ProxyClient:
        """Return a long-lived upstream client, connecting once (bounded by caller)."""
        async with self._client_lock:
            if self._client is None:
                client = self.client_factory()
                await client.__aenter__()
                self._client = client
            return self._client

    async def _reset_client(self) -> None:
        """Drop the cached client so the next call reconnects (after a failure)."""
        async with self._client_lock:
            client = self._client
            self._client = None
        if client is not None:
            with suppress(Exception):
                await client.__aexit__(None, None, None)

    async def close(self) -> None:
        """Tear down the long-lived upstream client."""
        await self._reset_client()

    async def _audit_denial(
        self,
        name: str,
        repo: str,
        caller_identity: CallerIdentity | None,
        reason: str,
        duration_ms: int,
    ) -> None:
        if not self.audit:
            return
        with suppress(Exception):
            await self.audit.log_event(
                tool=name,
                repo=repo or "<unresolved>",
                caller_identity=caller_identity.client_id
                if caller_identity
                else "anonymous",
                duration_ms=duration_ms,
                payload={"denied": True, "reason": reason},
            )

    async def call_tool(
        self,
        name: str,
        arguments: Mapping[str, Any],
        caller_identity: CallerIdentity | None,
    ) -> Any:
        """Proxy a single allow-listed read tool call, fail-closed."""
        started = time.monotonic()
        repo = ""
        try:
            repo = self._authorize(name, arguments, caller_identity)

            async def _connect_and_call() -> Any:
                client = await self._ensure_client()
                return await client.call_tool(name, dict(arguments))

            result = await asyncio.wait_for(_connect_and_call(), self.timeout_seconds)
        except (PermissionError, TimeoutError) as exc:
            await self._handle_failure(name, repo, caller_identity, exc, started)
            raise

        return await self._finalize(name, repo, caller_identity, result, started)

    def _authorize(
        self,
        name: str,
        arguments: Mapping[str, Any],
        caller_identity: CallerIdentity | None,
    ) -> str:
        self._require_allowlisted(name)
        self._require_direct_addressing(arguments)
        repo = self._resolve_repo(arguments)
        self._require_repo_access(repo, caller_identity)
        return repo

    @staticmethod
    def _require_allowlisted(name: str) -> None:
        if name not in UPSTREAM_TOOL_ALLOWLIST:
            raise PermissionError(f"Tool '{name}' is not in the upstream allowlist")

    @staticmethod
    def _require_direct_addressing(arguments: Mapping[str, Any]) -> None:
        if any(key in arguments for key in INDIRECT_IDENTIFIER_KEYS):
            raise PermissionError(
                "Indirect identifiers are not accepted; use direct 'owner'/'repo'"
            )

    def _require_repo_access(
        self, repo: str, caller_identity: CallerIdentity | None
    ) -> None:
        # Enforce BOTH the proxy ceiling and the caller's grant.
        if not self._repo_allowed(repo):
            raise PermissionError(
                f"Repository '{repo}' is outside the proxy allowed_repos ceiling"
            )
        if caller_identity is None or not caller_identity.is_repo_allowed(repo):
            raise PermissionError(
                f"Caller is not authorized to access repository '{repo}'"
            )

    async def _handle_failure(
        self,
        name: str,
        repo: str,
        caller_identity: CallerIdentity | None,
        exc: Exception,
        started: float,
    ) -> None:
        await self._audit_denial(
            name,
            repo,
            caller_identity,
            str(exc) or type(exc).__name__,
            int((time.monotonic() - started) * 1000),
        )
        if isinstance(exc, TimeoutError):
            await self._reset_client()

    async def _finalize(
        self,
        name: str,
        repo: str,
        caller_identity: CallerIdentity | None,
        result: Any,
        started: float,
    ) -> Any:
        duration_ms = int((time.monotonic() - started) * 1000)
        redacted, counts = self._redact_result(result)
        if self.audit:
            await self.audit.log_event(
                tool=name,
                repo=repo,
                caller_identity=caller_identity.client_id
                if caller_identity
                else "anonymous",
                duration_ms=duration_ms,
                payload=self._audit_payload(redacted),
                redaction_counts=counts,
            )
        return redacted

    def _make_proxy_tool(self, tool_name: str) -> Callable[..., Any]:
        async def proxy_tool(
            owner: str | None = None,
            repo: str | None = None,
            pull_number: int | None = None,
            issue_number: int | None = None,
        ) -> Any:
            """Read-only proxied GitHub tool (RBAC + redaction enforced)."""
            caller = get_current_caller_identity()
            arguments = {
                "owner": owner,
                "repo": repo,
                "pull_number": pull_number,
                "issue_number": issue_number,
            }
            return await self.call_tool(
                tool_name,
                {k: v for k, v in arguments.items() if v is not None},
                caller,
            )

        proxy_tool.__name__ = tool_name
        proxy_tool.__doc__ = f"Proxied read-only upstream tool '{tool_name}'."
        return proxy_tool

    def register_on(self, server: Any) -> None:
        """Register exactly the four allow-listed read-only tools on ``server``."""
        for tool_name in UPSTREAM_TOOL_ALLOWLIST:
            server.tool(name=tool_name)(self._make_proxy_tool(tool_name))

    def build_server(self) -> FastMCP:
        """Build a FastMCP server exposing exactly the four allow-listed tools."""
        server = FastMCP(name="vps-github-proxy")
        self.register_on(server)

        try:
            asyncio.get_running_loop()
        except RuntimeError:
            registered = asyncio.run(server.list_tools())
            assert {t.name for t in registered} == UPSTREAM_TOOL_ALLOWLIST

        self.server = server
        return server


def build_github_proxy_server(
    *,
    upstream_transport: Any,
    allowed_repos: Iterable[str] | None = None,
    audit: AuditLogger | None = None,
    redactor: SecretRedactor | None = None,
    timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS,
) -> FastMCP:
    """Build the pinned GitHub proxy server from an upstream MCP transport."""
    if allowed_repos is not None:
        repos: set[str] = set(allowed_repos)
    else:
        from agent.security import get_allowed_repositories

        repos = get_allowed_repositories()

    proxy = GitHubProxy(
        client_factory=lambda: ProxyClient(
            upstream_transport, forward_incoming_headers=False
        ),
        allowed_repos=repos,
        audit=audit,
        redactor=redactor,
        timeout_seconds=timeout_seconds,
    )
    return proxy.build_server()
