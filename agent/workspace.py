from __future__ import annotations

import asyncio
import base64
import logging
import os
import re
import uuid
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager, suppress
from pathlib import Path
from typing import Literal

import httpx
from pydantic import BaseModel, ConfigDict, Field

logger = logging.getLogger(__name__)

DEFAULT_WORKSPACES_DIR = Path(__file__).resolve().parent.parent / "workspaces"
_REPO_RE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")

_CTRL_RE = re.compile(r"[\x00-\x1f\x7f]+")
_REF_RE = re.compile(r"^[A-Za-z0-9._/-]+$")
_REPO_LOCKS: dict[str, asyncio.Lock] = {}


def _repo_lock(slug: str) -> asyncio.Lock:
    return _REPO_LOCKS.setdefault(slug, asyncio.Lock())


def _sanitize_title(title: str) -> str:
    cleaned = _CTRL_RE.sub(" ", title).strip()
    return cleaned or "Automated PR update"


def _remote_url(slug: str) -> str:
    template = os.getenv("AGENT_GIT_REMOTE_TEMPLATE", "https://github.com/{slug}.git")
    url = template.format(slug=slug).strip()
    if not url or url.startswith("-") or _CTRL_RE.search(url):
        raise ValueError("unsafe git remote URL from AGENT_GIT_REMOTE_TEMPLATE")
    return url


class InlineReviewComment(BaseModel):
    model_config = ConfigDict(extra="forbid")
    path: str = Field(min_length=1, max_length=500)
    line: int = Field(ge=1)
    body: str = Field(min_length=1, max_length=4_000)


class SubmitPRReviewRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    repo: str
    pr_number: int = Field(ge=1)
    head_sha: str = Field(min_length=7, max_length=64)
    event: Literal["COMMENT", "REQUEST_CHANGES"]
    summary: str = Field(min_length=1, max_length=16_000)
    comments: list[InlineReviewComment] = Field(default_factory=list, max_length=20)


async def submit_pr_review_api(req: SubmitPRReviewRequest) -> dict:
    """Submit a PR review via GitHub REST API. Returns review_id, html_url, state."""
    slug = validate_repo_slug(req.repo)
    token = _require_github_token()
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    body = {
        "commit_id": req.head_sha,
        "body": req.summary,
        "event": req.event,
        "comments": [
            {"path": c.path, "line": c.line, "side": "RIGHT", "body": c.body}
            for c in req.comments
        ],
    }
    async with httpx.AsyncClient(timeout=20) as client:
        resp = await client.post(
            f"https://api.github.com/repos/{slug}/pulls/{req.pr_number}/reviews",
            headers=headers,
            json=body,
        )
        resp.raise_for_status()
        data = resp.json()
        return {
            "review_id": data.get("id"),
            "html_url": data.get("html_url"),
            "state": data.get("state"),
        }


def validate_repo_slug(repo: str) -> str:
    """Ensure repo is a safe 'owner/name' slug with no path traversal."""
    cleaned = repo.strip()
    if not _REPO_RE.match(cleaned) or ".." in cleaned:
        raise ValueError(f"Invalid GitHub repo slug: {repo!r}")
    return cleaned


def get_workspaces_dir() -> Path:
    return Path(os.getenv("WORKSPACES_DIR", str(DEFAULT_WORKSPACES_DIR)))


def get_external_index_dir(repo: str) -> Path:
    """Return a repo index directory strictly outside git worktrees."""
    validate_repo_slug(repo)
    safe_name = repo.replace("/", "__")
    index_dir = (get_workspaces_dir().parent / "indexes" / safe_name).resolve()
    worktrees_dir = (get_workspaces_dir() / "worktrees").resolve()
    if worktrees_dir in index_dir.parents or index_dir == worktrees_dir:
        raise ValueError("Index directory must never be inside worktrees/")
    index_dir.mkdir(parents=True, exist_ok=True)
    return index_dir


def _require_github_token() -> str:
    token = os.getenv("GITHUB_TOKEN", "").strip()
    if not token:
        raise RuntimeError("GITHUB_TOKEN is not configured in environment.")
    return token


def _git_auth_args(token: str) -> list[str]:
    """Pass GitHub PAT via transient extraheader so .git/config never stores secrets."""
    b64 = base64.b64encode(f"x-access-token:{token}".encode()).decode("ascii")
    return ["-c", f"http.https://github.com/.extraheader=AUTHORIZATION: basic {b64}"]


async def _run_git(
    args: list[str], cwd: Path | None = None, auth_token: str | None = None
) -> str:
    from agent.security import build_safe_git_env

    cmd = ["git", "-c", "core.hooksPath=/dev/null"]
    if auth_token:
        cmd.extend(_git_auth_args(auth_token))
    cmd.extend(args)

    env = build_safe_git_env()

    proc = await asyncio.create_subprocess_exec(
        *cmd,
        cwd=str(cwd) if cwd else None,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        env=env,
    )
    stdout, stderr = await proc.communicate()
    if proc.returncode != 0:
        from src.orchestrator.middleware.redactor import SecretRedactor

        redactor = SecretRedactor()
        safe_args = [a for a in args if "extraheader" not in a.lower()]
        safe_cmd = redactor.redact_text(" ".join(safe_args))[0]
        err = redactor.redact_text(stderr.decode("utf-8", errors="replace").strip())[0]
        raise RuntimeError(f"git {safe_cmd} failed ({proc.returncode}): {err}")
    return stdout.decode("utf-8", errors="replace").strip()


def _base_repo_dir(repo: str) -> Path:
    slug = validate_repo_slug(repo)
    return get_workspaces_dir() / slug.replace("/", "__")


async def prepare_worktree(
    repo: str,
    base_branch: str,
    target_branch: str,
    job_id: str,
) -> Path:
    """
    Clone or fetch `repo` into the local workspace cache and create an isolated
    `git worktree` checked out on `target_branch`.
    """
    slug = validate_repo_slug(repo)
    token = _require_github_token()
    workspaces = get_workspaces_dir()
    workspaces.mkdir(parents=True, exist_ok=True)

    base_dir = _base_repo_dir(slug)
    worktree_dir = workspaces / "worktrees" / job_id
    remote_url = _remote_url(slug)

    # Serialize per-repo git setup only (never across the LLM run).
    async with _repo_lock(slug):
        if not (base_dir / ".git").exists():
            await _run_git(["clone", remote_url, str(base_dir)], auth_token=token)
        else:
            await _run_git(
                ["fetch", "origin", "--prune"], cwd=base_dir, auth_token=token
            )

        await _run_git(["worktree", "prune"], cwd=base_dir)

        worktree_dir.parent.mkdir(parents=True, exist_ok=True)
        if worktree_dir.exists():
            await _run_git(
                ["worktree", "remove", "--force", str(worktree_dir)], cwd=base_dir
            )

        await _run_git(
            [
                "worktree",
                "add",
                "-B",
                target_branch,
                str(worktree_dir),
                f"origin/{base_branch}",
            ],
            cwd=base_dir,
        )
    return worktree_dir


def _validate_ref(ref: str) -> None:
    if not ref or ref.startswith("-") or not _REF_RE.match(ref):
        raise ValueError(f"invalid ref: {ref!r}")


async def _ensure_base_repo(slug: str, ref: str, token: str) -> Path:
    """Clone or fetch the cached base repo and prune stale worktrees."""
    base_dir = _base_repo_dir(slug)
    async with _repo_lock(slug):
        base_dir.parent.mkdir(parents=True, exist_ok=True)
        if not (base_dir / ".git").exists():
            await _run_git(
                ["clone", _remote_url(slug), str(base_dir)], auth_token=token
            )
        else:
            await _run_git(["fetch", "origin", ref], cwd=base_dir, auth_token=token)
        await _run_git(["worktree", "prune"], cwd=base_dir)
    return base_dir


@asynccontextmanager
async def read_only_worktree(repo: str, ref: str = "main") -> AsyncGenerator[Path]:
    """Yield a detached worktree at ``origin/<ref>`` and remove it on exit."""
    slug = validate_repo_slug(repo)
    _validate_ref(ref)
    token = _require_github_token()
    base_dir = await _ensure_base_repo(slug, ref, token)

    worktrees = get_workspaces_dir() / "worktrees"
    worktrees.mkdir(parents=True, exist_ok=True)
    wt = worktrees / f"ro-{slug.replace('/', '-')}-{uuid.uuid4().hex[:8]}"
    await _run_git(
        ["worktree", "add", "--detach", str(wt), f"origin/{ref}"], cwd=base_dir
    )
    try:
        yield wt
    finally:
        with suppress(Exception):
            await _run_git(["worktree", "remove", "--force", str(wt)], cwd=base_dir)


async def cleanup_worktree(repo: str, worktree_dir: Path) -> None:
    """Remove a temporary job worktree cleanly."""
    base_dir = _base_repo_dir(repo)
    if not (base_dir.exists() and worktree_dir.exists()):
        return
    async with _repo_lock(repo):
        try:
            await _run_git(
                ["worktree", "remove", "--force", str(worktree_dir)], cwd=base_dir
            )
        except (RuntimeError, OSError) as exc:
            logger.warning("Failed to remove worktree %s: %s", worktree_dir, exc)


def _check_agent_branch(target_branch: str) -> None:
    if target_branch in {"main", "master"} or not target_branch.startswith("agent/"):
        raise ValueError(
            f"Refusing to push protected/non-agent branch: {target_branch}"
        )


async def _commit_staged_changes(worktree_dir: Path, safe_title: str) -> None:
    from agent.security import assert_no_protected_paths

    status = await _run_git(["status", "--porcelain"], cwd=worktree_dir)
    if not status:
        return
    await _run_git(["add", "-A"], cwd=worktree_dir)
    changed = await _run_git(["diff", "--cached", "--name-only"], cwd=worktree_dir)
    assert_no_protected_paths([f for f in changed.splitlines() if f.strip()])
    await _run_git(
        [
            "-c",
            "user.name=VPS PR-Agent",
            "-c",
            "user.email=pr-agent@local.lan",
            "commit",
            "-m",
            safe_title[:72],
        ],
        cwd=worktree_dir,
    )


async def _commits_ahead(worktree_dir: Path, base_branch: str) -> int:
    ahead_raw = await _run_git(
        ["rev-list", "--count", f"origin/{base_branch}..HEAD"], cwd=worktree_dir
    )
    return int(ahead_raw or "0")


async def _changed_files_and_shas(
    worktree_dir: Path, base_branch: str
) -> tuple[list[str], list[str]]:
    shas_raw = await _run_git(
        ["rev-list", f"origin/{base_branch}..HEAD"], cwd=worktree_dir
    )
    commit_shas = [s for s in shas_raw.splitlines() if s.strip()]

    files_raw = await _run_git(
        ["diff", "--name-only", f"origin/{base_branch}..HEAD"], cwd=worktree_dir
    )
    files_touched = [f for f in files_raw.splitlines() if f.strip()]
    return files_touched, commit_shas


async def commit_and_push(
    worktree_dir: Path,
    repo: str,
    target_branch: str,
    base_branch: str,
    title: str,
) -> tuple[list[str], list[str]]:
    """Commit uncommitted changes and push `target_branch` (never main/master).

    Returns ``(files_touched, commit_shas)``. Opening a PR is a separate,
    gated step so verification runs against the exact pushed commit.
    """
    _check_agent_branch(target_branch)
    validate_repo_slug(repo)
    token = _require_github_token()
    safe_title = _sanitize_title(title)

    await _commit_staged_changes(worktree_dir, safe_title)

    if await _commits_ahead(worktree_dir, base_branch) == 0:
        return [], []

    files_touched, commit_shas = await _changed_files_and_shas(
        worktree_dir, base_branch
    )

    await _run_git(
        ["push", "-u", "origin", target_branch],
        cwd=worktree_dir,
        auth_token=token,
    )

    return files_touched, commit_shas


async def open_pr(
    repo: str,
    target_branch: str,
    base_branch: str,
    title: str,
    body: str,
    pr_number: int | None = None,
) -> tuple[str | None, int | None]:
    """Open (or fetch) a PR for `target_branch`. Returns ``(pr_url, pr_number)``."""
    slug = validate_repo_slug(repo)
    token = _require_github_token()
    safe_title = _sanitize_title(title)
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    pr_url: str | None = None
    created_pr_num = pr_number
    async with httpx.AsyncClient(timeout=20) as client:
        if created_pr_num is None:
            resp = await client.post(
                f"https://api.github.com/repos/{slug}/pulls",
                headers=headers,
                json={
                    "title": safe_title[:120],
                    "head": target_branch,
                    "base": base_branch,
                    "body": body,
                },
            )
            if resp.status_code in {200, 201}:
                data = resp.json()
                pr_url = data.get("html_url")
                created_pr_num = data.get("number")
        else:
            resp = await client.get(
                f"https://api.github.com/repos/{slug}/pulls/{created_pr_num}",
                headers=headers,
            )
            if resp.status_code == 200:
                pr_url = resp.json().get("html_url")
    return pr_url, created_pr_num


async def post_pr_comment(repo: str, pr_number: int, body: str) -> str | None:
    """Post a review comment on an existing PR via GitHub REST API."""
    slug = validate_repo_slug(repo)
    token = _require_github_token()
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    async with httpx.AsyncClient(timeout=20) as client:
        resp = await client.post(
            f"https://api.github.com/repos/{slug}/issues/{pr_number}/comments",
            headers=headers,
            json={"body": body},
        )
        if resp.status_code in {200, 201}:
            return resp.json().get("html_url")
    return None
