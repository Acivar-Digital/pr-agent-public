"""FastMCP and FastAPI authentication, identity, and RBAC authorization module.

Provides:
- CallerIdentity dataclass and SECRET_PATH_IDENTITY for secret URL path clients.
- In-memory and environment-backed Bearer token registry and verification.
- ContextVar-based request-scoped caller identity tracking.
- Three-Shape RBAC parameter resolution (direct repo, job_id -> repo, and split owner/repo).
- FastMCP tool-call RBAC middleware.
- Zero Body-Read ASGI Middleware enforcing dual auth and endpoint hardening without
  reading request bodies (preventing deadlocks on chunked SSE / Streamable HTTP transports).
"""

from __future__ import annotations

import contextvars
import hmac
import json
import os
import re
import threading
from dataclasses import dataclass
from typing import Any

import structlog
from mcp.server.context import CallNext, HandlerResult, ServerRequestContext
from mcp.server.mcpserver import MCPServer
from starlette.datastructures import Headers
from starlette.responses import Response
from starlette.types import ASGIApp, Receive, Scope, Send

# FastMCP version binding (MCPServer in mcp>=1.8.0 / 2.x)
FastMCP = MCPServer

logger = structlog.get_logger(__name__)

LOCAL_HOSTS = frozenset({"127.0.0.1", "::1", "localhost", "testclient"})


@dataclass(frozen=True)
class CallerIdentity:
    """Represents an authenticated caller and its repository access permissions."""

    client_id: str
    allowed_repos: list[str]
    role: str = "user"

    def is_repo_allowed(self, repo: str) -> bool:
        """Check whether the caller is authorized to access the specified repo."""
        if self.role == "admin":
            return True
        if "*" in self.allowed_repos:
            return True
        normalized = repo.strip().lower()
        return normalized in {r.strip().lower() for r in self.allowed_repos}


# Standard secret path identity
SECRET_PATH_IDENTITY = CallerIdentity(
    client_id="secret_path_client",
    allowed_repos=["*"],
    role="admin",
)

# In-memory token registry for Bearer tokens
_TOKEN_REGISTRY: dict[str, CallerIdentity] = {}
_REGISTRY_LOCK = threading.Lock()

# Request-scoped caller identity context variable
_current_caller_identity: contextvars.ContextVar[CallerIdentity | None] = (
    contextvars.ContextVar("current_caller_identity", default=None)
)


def get_current_caller_identity() -> CallerIdentity | None:
    """Retrieve the current request's CallerIdentity from context."""
    return _current_caller_identity.get()


def set_current_caller_identity(
    identity: CallerIdentity | None,
) -> contextvars.Token[CallerIdentity | None]:
    """Set the current request's CallerIdentity in context."""
    return _current_caller_identity.set(identity)


def reset_current_caller_identity(
    token: contextvars.Token[CallerIdentity | None],
) -> None:
    """Reset the CallerIdentity contextvar to its previous value."""
    _current_caller_identity.reset(token)


def register_bearer_token(token: str, identity: CallerIdentity) -> None:
    """Register a Bearer token with its corresponding CallerIdentity."""
    with _REGISTRY_LOCK:
        _TOKEN_REGISTRY[token.strip()] = identity


def unregister_bearer_token(token: str) -> None:
    """Remove a registered Bearer token."""
    with _REGISTRY_LOCK:
        _TOKEN_REGISTRY.pop(token.strip(), None)


def clear_bearer_tokens() -> None:
    """Clear all registered in-memory Bearer tokens."""
    with _REGISTRY_LOCK:
        _TOKEN_REGISTRY.clear()


def _lookup_registry_token(cleaned: str) -> CallerIdentity | None:
    """Return the in-memory registry identity for a token, or None."""
    with _REGISTRY_LOCK:
        return _TOKEN_REGISTRY.get(cleaned)


def _lookup_env_admin_token(cleaned: str) -> CallerIdentity | None:
    """Return the admin identity when the token matches GATEWAY_ADMIN_TOKEN."""
    env_admin = os.environ.get("GATEWAY_ADMIN_TOKEN", "").strip()
    if env_admin and hmac.compare_digest(cleaned, env_admin):
        return CallerIdentity(
            client_id="env_admin",
            allowed_repos=["*"],
            role="admin",
        )
    return None


def _match_token_entry(
    cleaned: str, tokens_data: dict[str, Any]
) -> CallerIdentity | None:
    """Return the identity whose token matches an entry in the parsed token map."""
    for known_token, entry in tokens_data.items():
        if hmac.compare_digest(cleaned, str(known_token)):
            return CallerIdentity(
                client_id=str(entry.get("client_id", "token_client")),
                allowed_repos=list(entry.get("allowed_repos", [])),
                role=str(entry.get("role", "user")),
            )
    return None


def _lookup_env_token(cleaned: str) -> CallerIdentity | None:
    """Return the identity for a token defined in GATEWAY_AUTH_TOKENS, or None."""
    raw = os.environ.get("GATEWAY_AUTH_TOKENS", "").strip()
    if not raw:
        return None
    identity: CallerIdentity | None = None
    try:
        tokens_data = json.loads(raw)
        if isinstance(tokens_data, dict):
            identity = _match_token_entry(cleaned, tokens_data)
    except (
        json.JSONDecodeError,
        KeyError,
        TypeError,
        ValueError,
        AttributeError,
    ) as e:
        logger.warning("Failed to parse GATEWAY_AUTH_TOKENS", error=str(e))
    return identity


def verify_bearer_token(token: str) -> CallerIdentity | None:
    """Verify a Bearer token against in-memory registry and environment variables."""
    if not token:
        return None
    cleaned = token.strip()
    for lookup in (_lookup_registry_token, _lookup_env_admin_token, _lookup_env_token):
        identity = lookup(cleaned)
        if identity is not None:
            return identity
    return None


def _lookup_job_repo(job_id: str) -> str | None:
    """Look up the repo for a single job_id via SQLite; None if unresolved."""
    try:
        from agent.job_store import get_job

        job = get_job(job_id)
        if job and "repo" in job and job["repo"]:
            return str(job["repo"]).strip()
    except (OSError, RuntimeError, ValueError) as e:
        logger.warning(
            "Failed to lookup job_id for RBAC resolution",
            job_id=job_id,
            error=str(e),
        )
    return None


def _clean_str(value: Any) -> str:
    """Coerce a value to a stripped string, treating falsy as empty."""
    return str(value or "").strip()


def _join_owner_repo(owner: str, repo_val: str) -> str:
    """Combine owner and repo into 'owner/repo' unless repo already qualified."""
    return repo_val if "/" in repo_val else f"{owner}/{repo_val}"


def _resolve_owner_repo(args: dict[str, Any]) -> tuple[list[str], bool] | None:
    """Shape 3: separate owner and repo fields; None when not applicable."""
    if "owner" not in args or "repo" not in args:
        return None
    owner = _clean_str(args.get("owner"))
    repo_val = _clean_str(args.get("repo"))
    if not (owner and repo_val):
        return None
    return [_join_owner_repo(owner, repo_val)], False


def _resolve_direct_repo(args: dict[str, Any]) -> tuple[list[str], bool] | None:
    """Shape 1: direct 'repo' argument; None when not applicable."""
    if "repo" not in args or not isinstance(args["repo"], str):
        return None
    repo_val = args["repo"].strip()
    if not repo_val:
        return None
    return [repo_val], False


def _resolve_job_id(args: dict[str, Any]) -> tuple[list[str], bool] | None:
    """Shape 2: single job_id -> repo lookup; None when not applicable."""
    if "job_id" not in args or not isinstance(args["job_id"], str):
        return None
    job_id = args["job_id"].strip()
    if not job_id:
        return None
    repo = _lookup_job_repo(job_id)
    if repo:
        return [repo], False
    return [], True


def _collect_job_repos(job_ids: Any) -> tuple[list[str], bool]:
    """Resolve every job_id to a repo, deduplicating and flagging unresolved ids."""
    repos: list[str] = []
    unresolved = False
    for raw_jid in job_ids:
        repo = _lookup_job_repo(str(raw_jid).strip())
        if not repo:
            unresolved = True
        elif repo not in repos:
            repos.append(repo)
    return repos, unresolved


def _resolve_job_ids(args: dict[str, Any]) -> tuple[list[str], bool] | None:
    """Shape 2b: job_ids list -> repos; None when not applicable."""
    job_ids = args.get("job_ids")
    if not isinstance(job_ids, (list, tuple)) or not job_ids:
        return None
    return _collect_job_repos(job_ids)


def resolve_target_repos(args: dict[str, Any]) -> tuple[list[str], bool]:
    """Resolve EVERY repository referenced by args across the 3 parameter shapes.

    Returns (repos, has_unresolved). ``has_unresolved`` is True when a job_id /
    job_ids entry could not be resolved to a repo, so callers must fail closed.
    """
    if not isinstance(args, dict):
        return [], False

    resolvers = (
        _resolve_owner_repo,
        _resolve_direct_repo,
        _resolve_job_id,
        _resolve_job_ids,
    )
    for resolver in resolvers:
        result = resolver(args)
        if result is not None:
            return result

    return [], False


def resolve_target_repo(args: dict[str, Any]) -> str | None:
    """Resolve the first target repository across the 3 parameter shapes.

    Shape 1: Direct 'repo' argument (e.g. 'owner/repo').
    Shape 2: 'job_id -> repo' lookup via SQLite (agent.job_store.get_job(job_id)).
    Shape 3: Upstream tools with separate 'owner' and 'repo' arguments (f"{owner}/{repo}").
    """
    repos, _ = resolve_target_repos(args)
    return repos[0] if repos else None


def check_rbac(caller: CallerIdentity | None, repo: str | None) -> bool:
    """Check whether a caller has access to the target repository."""
    if caller is None:
        return False
    if repo is None:
        return True
    return caller.is_repo_allowed(repo)


def _is_privileged(caller: CallerIdentity) -> bool:
    """Return True when the caller has admin role or wildcard repo access."""
    return caller.role == "admin" or "*" in caller.allowed_repos


def _first_denied_repo(caller: CallerIdentity, repos: list[str]) -> str | None:
    """Return the first repo the caller may not access, or None if all allowed."""
    for repo in repos:
        if not caller.is_repo_allowed(repo):
            return repo
    return None


def _first_repo(repos: list[str]) -> str | None:
    """Return the first repo in the list, or None when empty."""
    return repos[0] if repos else None


def enforce_rbac(caller: CallerIdentity | None, args: dict[str, Any]) -> str | None:
    """Enforce RBAC rules against args, raising PermissionError on violation."""
    if caller is None:
        raise PermissionError("Unauthenticated caller cannot access resources")

    repos, unresolved = resolve_target_repos(args)

    if unresolved and not _is_privileged(caller):
        raise PermissionError(
            f"Job reference in args not found or unauthorized for caller '{caller.client_id}'"
        )

    denied = _first_denied_repo(caller, repos)
    if denied is not None:
        raise PermissionError(
            f"Caller '{caller.client_id}' is not authorized to access repository '{denied}'"
        )

    return _first_repo(repos)


def _extract_call_params(ctx: ServerRequestContext[Any, Any]) -> tuple[Any, str]:
    """Extract (arguments, tool_name) from a tool-call request context."""
    raw = ctx.params
    params = raw if isinstance(raw, dict) else {}
    return params.get("arguments", {}), params.get("name", "unknown")


def _caller_client_id(caller: CallerIdentity | None) -> str:
    """Return the caller's client_id, or 'anonymous' when unauthenticated."""
    return caller.client_id if caller else "anonymous"


def _evaluate_rbac_denial(caller: CallerIdentity | None, args: dict[str, Any]) -> str:
    """Return the denial reason for a tool call, or '' when access is allowed."""
    repos, unresolved = resolve_target_repos(args)
    if caller is None:
        return "unauthenticated caller"
    if unresolved and not _is_privileged(caller):
        return "job reference not found or unauthorized"
    denied_repo = _first_denied_repo(caller, repos)
    if denied_repo is not None:
        return f"repository '{denied_repo}'"
    return ""


class RBACMiddleware:
    """FastMCP tool-call middleware enforcing repo-scoped RBAC."""

    async def __call__(
        self,
        ctx: ServerRequestContext[Any, Any],
        call_next: CallNext,
    ) -> HandlerResult:
        if ctx.method == "tools/call":
            caller = get_current_caller_identity()
            args, tool_name = _extract_call_params(ctx)
            if isinstance(args, dict):
                reason = _evaluate_rbac_denial(caller, args)
                if reason:
                    client_id = _caller_client_id(caller)
                    logger.warning(
                        "RBAC permission denied for tool call",
                        client_id=client_id,
                        tool=tool_name,
                        reason=reason,
                    )
                    return {
                        "content": [
                            {
                                "type": "text",
                                "text": (
                                    f"PermissionDenied: caller '{client_id}' is not authorized "
                                    f"to access {reason}"
                                ),
                            }
                        ],
                        "isError": True,
                    }

        return await call_next(ctx)


def attach_rbac_middleware(server: MCPServer) -> RBACMiddleware:
    """Attach the universal RBAC middleware to an MCPServer instance."""
    middleware = RBACMiddleware()
    server.middleware.append(middleware)
    return middleware


def _header_value(headers: Headers, name: str) -> str:
    """Return a stripped header value, or '' when absent."""
    return (headers.get(name) or "").strip()


def _scope_client_host(scope: Scope) -> str | None:
    """Return the direct connection host from the ASGI scope, or None."""
    client = scope.get("client")
    if client and len(client) > 0 and client[0]:
        return str(client[0])
    return None


def extract_client_ip_from_scope(scope: Scope) -> str:
    """Extract real caller IP from ASGI scope without reading request body."""
    headers = Headers(scope=scope)
    cf_ip = _header_value(headers, "cf-connecting-ip")
    if cf_ip:
        return cf_ip
    xff = _header_value(headers, "x-forwarded-for")
    if xff:
        return xff.split(",")[0].strip()
    return _scope_client_host(scope) or "unknown"


def is_localhost_ip(ip: str) -> bool:
    """Check if the IP corresponds to local access (127.0.0.1, ::1, testclient)."""
    cleaned = ip.strip()
    return cleaned in LOCAL_HOSTS or cleaned.startswith("127.")


def extract_bearer_token(auth_header: str) -> str | None:
    """Extract token string from 'Authorization: Bearer <token>' header."""
    if not auth_header:
        return None
    match = re.match(r"^Bearer\s+(.+)$", auth_header.strip(), re.IGNORECASE)
    if match:
        return match.group(1).strip()
    return None


def _direct_client_host(scope: Scope) -> str:
    """Return the direct connection host for /metrics, defaulting to 'unknown'."""
    client_tuple = scope.get("client")
    if client_tuple and len(client_tuple) > 0:
        return str(client_tuple[0])
    return "unknown"


def _identity_from_header(auth_header: str) -> CallerIdentity | None:
    """Resolve a CallerIdentity from an Authorization header, or None."""
    if not auth_header:
        return None
    token = extract_bearer_token(auth_header)
    return verify_bearer_token(token) if token else None


def _metrics_identity(identity: CallerIdentity | None) -> CallerIdentity:
    """Return the identity to use for a /metrics request."""
    return (
        identity
        if identity
        else CallerIdentity(
            client_id="localhost_metrics",
            allowed_repos=["*"],
            role="admin",
        )
    )


def _is_path(path: str, base: str) -> bool:
    """Return True when path equals base or is nested under it."""
    return path == base or path.startswith(f"{base}/")


class ZeroBodyReadAuthMiddleware:
    """Zero Body-Read ASGI Middleware.

    Enforces dual-authentication and endpoint hardening:
    - Secret URL Path (/gemini/{MCP_SECRET_PATH}/mcp): authenticates without Bearer
      header as admin CallerIdentity(client_id='secret_path_client', allowed_repos=['*'], role='admin').
      If Bearer header is passed, verifies Bearer token.
    - Direct /mcp endpoint: requires valid Bearer token, returns 401 on missing/invalid token.
    - Hardened /metrics: locked to 127.0.0.1 or admin Bearer auth, returns 403 otherwise.
    - NEVER calls receive() or reads request body in middleware, avoiding deadlocks
      on chunked SSE / Streamable HTTP transports.
    """

    def __init__(self, app: ASGIApp, secret_path: str | None = None) -> None:
        self.app = app
        self.secret_path = secret_path

    def _is_secret_path(self, path: str) -> bool:
        """Return True when path targets the configured secret Gemini endpoint."""
        configured_secret = (
            self.secret_path
            if self.secret_path is not None
            else os.environ.get("MCP_SECRET_PATH", "")
        ).strip("/")
        return bool(
            configured_secret and _is_path(path, f"/gemini/{configured_secret}")
        )

    async def _run_with_identity(
        self,
        identity: CallerIdentity | None,
        scope: Scope,
        receive: Receive,
        send: Send,
    ) -> None:
        """Run the downstream app with the given identity bound to the context."""
        ctx_token = set_current_caller_identity(identity)
        try:
            await self.app(scope, receive, send)
        finally:
            reset_current_caller_identity(ctx_token)

    async def _send_json(
        self,
        payload: dict[str, str],
        status_code: int,
        scope: Scope,
        receive: Receive,
        send: Send,
    ) -> None:
        """Send a JSON error response without reading the request body."""
        resp = Response(
            content=json.dumps(payload),
            status_code=status_code,
            media_type="application/json",
        )
        await resp(scope, receive, send)

    async def _handle_secret_path(
        self, scope: Scope, receive: Receive, send: Send
    ) -> None:
        """Authenticate the secret URL path, then run the app."""
        auth_header = Headers(scope=scope).get("authorization", "")
        identity: CallerIdentity | None
        if auth_header:
            identity = _identity_from_header(auth_header)
            if identity is None:
                await self._send_json(
                    {"error": "Unauthorized", "detail": "Invalid Bearer token"},
                    401,
                    scope,
                    receive,
                    send,
                )
                return
        else:
            identity = SECRET_PATH_IDENTITY

        await self._run_with_identity(identity, scope, receive, send)

    async def _handle_metrics(self, scope: Scope, receive: Receive, send: Send) -> None:
        """Enforce /metrics hardening, then run the app."""
        client_ip = extract_client_ip_from_scope(scope)
        client_host = _direct_client_host(scope)
        is_local = is_localhost_ip(client_ip) and is_localhost_ip(client_host)
        identity = _identity_from_header(Headers(scope=scope).get("authorization", ""))
        is_admin = identity is not None and identity.role == "admin"

        if not is_local and not is_admin:
            logger.warning(
                "Forbidden /metrics access attempt from remote without admin auth",
                client_ip=client_ip,
                client_host=client_host,
            )
            await self._send_json(
                {
                    "error": "Forbidden",
                    "detail": "Metrics access restricted to 127.0.0.1 or admin auth",
                },
                403,
                scope,
                receive,
                send,
            )
            return

        await self._run_with_identity(_metrics_identity(identity), scope, receive, send)

    async def _handle_direct_mcp(
        self, scope: Scope, receive: Receive, send: Send
    ) -> None:
        """Require a valid Bearer token for the direct /mcp endpoint."""
        auth_header = Headers(scope=scope).get("authorization", "")
        if not auth_header:
            await self._send_json(
                {
                    "error": "Unauthorized",
                    "detail": "Authorization header with Bearer token is required",
                },
                401,
                scope,
                receive,
                send,
            )
            return

        identity = _identity_from_header(auth_header)
        if identity is None:
            await self._send_json(
                {
                    "error": "Unauthorized",
                    "detail": "Invalid or expired Bearer token",
                },
                401,
                scope,
                receive,
                send,
            )
            return

        await self._run_with_identity(identity, scope, receive, send)

    async def _handle_standard(
        self, scope: Scope, receive: Receive, send: Send
    ) -> None:
        """Run standard endpoints (e.g. /health, /webhook/github)."""
        identity = _identity_from_header(Headers(scope=scope).get("authorization", ""))
        await self._run_with_identity(identity, scope, receive, send)

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        path = scope.get("path", "")
        if self._is_secret_path(path):
            await self._handle_secret_path(scope, receive, send)
        elif _is_path(path, "/metrics"):
            await self._handle_metrics(scope, receive, send)
        elif _is_path(path, "/mcp"):
            await self._handle_direct_mcp(scope, receive, send)
        else:
            await self._handle_standard(scope, receive, send)
