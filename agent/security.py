from __future__ import annotations

import os
import posixpath
import re
from fnmatch import fnmatch
from pathlib import Path
from typing import Any

from agent.workspace import validate_repo_slug

_ANSI_ESCAPE_RE = re.compile(r"\x1b\[[0-9;]*[a-zA-Z]")

MAX_WEBHOOK_BYTES: int = 1_048_576  # 1 MB
MAX_CONCURRENT_JOBS: int = int(os.environ.get("MAX_CONCURRENT_JOBS", "3"))
JOB_TIMEOUT_SECONDS: int = int(os.environ.get("JOB_TIMEOUT_SECONDS", "600"))
REPLAY_TTL_SECONDS: int = int(
    os.environ.get("WEBHOOK_REPLAY_TTL_SECONDS", "300")
)  # 5 min
READ_ONLY_PERSONAS: frozenset[str] = frozenset(
    {
        "security-reviewer",
        "scout",
        "performance-engineer",
        "db-migration-reviewer",
    }
)
TRUSTED_ASSOCIATIONS: frozenset[str] = frozenset({"OWNER", "MEMBER", "COLLABORATOR"})

PROTECTED_PATH_PATTERNS: tuple[str, ...] = (
    ".github/workflows/*",
    ".github/workflows/**",
    ".agents/personas/*",
    ".agents/personas/**",
    ".vps-checks.toml",
    ".mcp-checks.yaml",
)

SECRET_ENV_KEYS: frozenset[str] = frozenset(
    {
        "GITHUB_TOKEN",
        "GITHUB_READ_TOKEN",
        "GITHUB_WEBHOOK_SECRET",
        "MCP_SECRET_PATH",
        "CLOUDFLARED_TOKEN",
        "DATABASE_URL",
    }
)


def get_allowed_repositories() -> set[str]:
    raw = os.environ.get("ALLOWED_REPOSITORIES", "").strip()
    if not raw:
        return set()
    return {item.strip().lower() for item in raw.split(",") if item.strip()}


def enforce_repo_allowlist(repo: str) -> str:
    """Validate slug format and enforce ALLOWED_REPOSITORIES when configured."""
    validate_repo_slug(repo)
    allowed = get_allowed_repositories()
    if allowed and repo.strip().lower() not in allowed:
        raise ValueError(f"Repository '{repo}' is not in ALLOWED_REPOSITORIES")
    return repo.strip()


def build_safe_git_env() -> dict[str, str]:
    """Strict minimal environment for _run_git (no host secrets, no system gitconfig)."""
    return {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_CONFIG_NOSYSTEM": "1",
    }


def build_safe_agy_env() -> dict[str, str]:
    """Secret-stripped allowlist for agy -p (preserves HOME/PATH without host secrets)."""
    return {
        k: v
        for k, v in os.environ.items()
        if k not in SECRET_ENV_KEYS
        and not k.endswith("_SECRET")
        and not k.endswith("_TOKEN")
    }


def is_protected_path(path: str) -> bool:
    """Return True if path targets protected CI/CD workflows, checks manifests, or personas."""
    norm = posixpath.normpath(path.replace("\\", "/")).lstrip("/").lower()
    if norm == ".." or norm.startswith("../"):
        return True
    return any(fnmatch(norm, pat.lower()) for pat in PROTECTED_PATH_PATTERNS)


def assert_no_protected_paths(paths: list[str]) -> None:
    blocked = [p for p in paths if is_protected_path(p)]
    if blocked:
        raise PermissionError(f"Protected paths cannot be modified: {blocked}")


def _get_full_name(pr_payload: dict[str, Any], key: str) -> str:
    """Get full_name from head or base dict, returning '' if missing."""
    return ((pr_payload.get(key) or {}).get("repo") or {}).get("full_name", "")


def is_trusted_internal_pr(pr_payload: dict[str, Any]) -> bool:
    """True only when PR is same-repo (not a fork) AND author is OWNER/MEMBER/COLLABORATOR."""
    head_full = _get_full_name(pr_payload, "head").strip().lower()
    base_full = _get_full_name(pr_payload, "base").strip().lower()
    if not head_full or not base_full or head_full != base_full:
        return False
    assoc = (pr_payload.get("author_association") or "").strip().upper()
    return assoc in TRUSTED_ASSOCIATIONS


def resolve_allow_writes(
    persona: str,
    requested_allow_writes: bool | None,
    *,
    from_webhook: bool = False,
    pr_payload: dict[str, Any] | None = None,
) -> bool:
    """Default-deny write governance: webhooks and reviewers are unconditionally read-only."""
    if from_webhook:
        return False
    if persona.strip().lower() in READ_ONLY_PERSONAS:
        return False
    if pr_payload is not None and not is_trusted_internal_pr(pr_payload):
        return False
    return bool(requested_allow_writes)


def wrap_untrusted(
    text: str,
    label: str = "untrusted_pr_context",
    max_chars: int = 100_000,
) -> str:
    """Strip ANSI escapes, cap length, escape closing XML tag, and wrap."""
    cleaned = _ANSI_ESCAPE_RE.sub("", text or "")
    if len(cleaned) > max_chars:
        cleaned = cleaned[:max_chars] + "\n... [truncated]"
    closing_re = re.compile(rf"</\s*{re.escape(label)}\s*>", re.IGNORECASE)
    cleaned = closing_re.sub(f"&lt;/{label}&gt;", cleaned)
    return f"<{label}>\n{cleaned}\n</{label}>"


def get_github_read_token() -> str:
    """Prefer dedicated read-only GITHUB_READ_TOKEN; fallback to GITHUB_TOKEN."""
    token = (
        os.environ.get("GITHUB_READ_TOKEN") or os.environ.get("GITHUB_TOKEN") or ""
    ).strip()
    if not token:
        raise RuntimeError("GITHUB_READ_TOKEN or GITHUB_TOKEN must be set")
    return token


def build_safe_linter_env() -> dict[str, str]:
    """Minimal secret-free environment for isolated static analysis subprocesses."""
    empty_home = Path("/tmp/pr_agent_empty_home")
    empty_home.mkdir(parents=True, exist_ok=True)
    return {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "HOME": str(empty_home),
        "NO_COLOR": "1",
    }
