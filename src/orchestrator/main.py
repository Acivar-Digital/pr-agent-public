"""Main entrypoint and application module for orchestrator gateway."""

from __future__ import annotations

from src.orchestrator.auth import (
    SECRET_PATH_IDENTITY,
    CallerIdentity,
    ZeroBodyReadAuthMiddleware,
    attach_rbac_middleware,
    check_rbac,
    clear_bearer_tokens,
    enforce_rbac,
    get_current_caller_identity,
    register_bearer_token,
    resolve_target_repo,
    unregister_bearer_token,
    verify_bearer_token,
)
from src.orchestrator.gateway import create_gateway_app

__all__ = [
    "SECRET_PATH_IDENTITY",
    "CallerIdentity",
    "ZeroBodyReadAuthMiddleware",
    "attach_rbac_middleware",
    "check_rbac",
    "clear_bearer_tokens",
    "create_gateway_app",
    "enforce_rbac",
    "get_current_caller_identity",
    "register_bearer_token",
    "resolve_target_repo",
    "unregister_bearer_token",
    "verify_bearer_token",
]
