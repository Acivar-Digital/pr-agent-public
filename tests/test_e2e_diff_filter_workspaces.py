from __future__ import annotations

import asyncio
import subprocess
from pathlib import Path

import pytest

from agent.diff_filter import filter_and_truncate_diff
from agent.workspace import (
    _remote_url,
    _sanitize_title,
    cleanup_worktree,
    prepare_worktree,
)


def _git(args: list[str], cwd: Path) -> None:
    subprocess.run(["git", *args], cwd=cwd, check=True, capture_output=True)


def _init_remote(tmp_path: Path) -> Path:
    remote = tmp_path / "remote.git"
    _git(["init", "--bare", str(remote)], tmp_path)
    seed = tmp_path / "seed"
    _git(["init", str(seed)], tmp_path)
    (seed / "a.txt").write_text("hi\n", encoding="utf-8")
    _git(["add", "-A"], seed)
    _git(
        ["-c", "user.email=a@b.c", "-c", "user.name=t", "commit", "-m", "init"],
        seed,
    )
    _git(["branch", "-M", "main"], seed)
    _git(["remote", "add", "origin", str(remote)], seed)
    _git(["push", "origin", "main"], seed)
    return remote


def test_diff_filter_e2e_caps_and_skips() -> None:
    diff = "diff --git a/uv.lock b/uv.lock\n+noise\n" + "".join(
        f"diff --git a/f{i}.py b/f{i}.py\n+{'x' * 400}\n" for i in range(3)
    )
    out = filter_and_truncate_diff(diff, max_lines_per_file=5, max_total_chars=2000)
    assert "uv.lock" not in out.split("[Skipped")[0]
    assert "Skipped noisy/lock files" in out
    assert len(out) <= 2200


def test_worktree_lifecycle_e2e(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    remote = _init_remote(tmp_path)
    monkeypatch.setenv("WORKSPACES_DIR", str(tmp_path / "ws"))
    monkeypatch.setenv("GITHUB_TOKEN", "x")
    monkeypatch.setenv("AGENT_GIT_REMOTE_TEMPLATE", f"file://{remote}")

    wt = asyncio.run(prepare_worktree("local/remote", "main", "agent/e2e", "job1"))
    assert (wt / "a.txt").exists()

    asyncio.run(cleanup_worktree("local/remote", wt))
    assert not wt.exists()


def test_remote_template_rejects_option_injection(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("AGENT_GIT_REMOTE_TEMPLATE", "--upload-pack=evil")
    with pytest.raises(ValueError):
        _remote_url("local/remote")


def test_default_remote_template(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("AGENT_GIT_REMOTE_TEMPLATE", raising=False)
    assert _remote_url("o/r") == "https://github.com/o/r.git"


def test_sanitize_title_strips_control_chars() -> None:
    assert _sanitize_title("fix\n\nbad\x00title") == "fix bad title"
