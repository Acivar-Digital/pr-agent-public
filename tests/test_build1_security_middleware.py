from __future__ import annotations

from pathlib import Path

import pytest

from agent.security import (
    SECRET_ENV_KEYS,
    build_safe_linter_env,
    enforce_repo_allowlist,
    get_github_read_token,
)


def test_enforce_repo_allowlist_blocks_unlisted(monkeypatch):
    monkeypatch.setenv("ALLOWED_REPOSITORIES", "example-org/sample-repo")
    assert (
        enforce_repo_allowlist("example-org/sample-repo")
        == "example-org/sample-repo"
    )
    with pytest.raises(ValueError):
        enforce_repo_allowlist("evil/repo")


def test_get_github_read_token_prefers_read_token(monkeypatch):
    monkeypatch.setenv("GITHUB_READ_TOKEN", "read_tok")
    monkeypatch.setenv("GITHUB_TOKEN", "write_tok")
    assert get_github_read_token() == "read_tok"
    monkeypatch.delenv("GITHUB_READ_TOKEN", raising=False)
    assert get_github_read_token() == "write_tok"


def test_build_safe_linter_env_strips_all_secrets(monkeypatch):
    for key in SECRET_ENV_KEYS:
        monkeypatch.setenv(key, "supersecret")
    safe_env = build_safe_linter_env()
    for key in SECRET_ENV_KEYS:
        assert key not in safe_env


def test_app_source_wires_instructions_and_allowlist():
    src = Path("server/app.py").read_text()
    assert "MCP_INSTRUCTIONS" in src
    assert "instructions=" in src
    assert src.count("enforce_repo_allowlist(") >= 4
