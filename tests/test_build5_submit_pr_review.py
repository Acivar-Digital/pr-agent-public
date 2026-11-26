"""Build 5/5: Guarded submit_pr_review with APPROVE blocked, SQLite dedup, audit logging."""

from __future__ import annotations

import asyncio
import logging
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from pydantic import ValidationError

from agent.job_store import init_db
from agent.workspace import InlineReviewComment, SubmitPRReviewRequest
from server.app import submit_pr_review


def _make_review_response(review_id: int = 42, state: str = "COMMENTED") -> dict:
    return {
        "id": review_id,
        "html_url": f"https://github.com/test/repo/pull/1#pullrequestreview-{review_id}",
        "state": state,
    }


def _make_mock_client(response_json: dict, call_counter: list[dict]) -> MagicMock:
    """Create a mock AsyncClient that records calls and returns canned JSON."""
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.raise_for_status = MagicMock()
    mock_resp.json.return_value = response_json

    async def fake_post(url, **kwargs):
        call_counter.append(
            {
                "url": url,
                "json": kwargs.get("json"),
                "headers": kwargs.get("headers", {}),
            }
        )
        return mock_resp

    mock_client = MagicMock()
    mock_client.post = fake_post
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=False)
    return mock_client


def test_approve_event_structurally_rejected():
    """APPROVE must be structurally impossible via Pydantic Literal."""
    with pytest.raises(ValidationError):
        SubmitPRReviewRequest(
            repo="test/repo",
            pr_number=1,
            head_sha="abc123def",
            event="APPROVE",  # ty: ignore[invalid-argument-type]
            summary="This should fail",
        )


def test_max_20_inline_comments_enforced():
    """Pydantic must reject more than 20 inline comments."""
    comments = [
        InlineReviewComment(path=f"file{i}.py", line=1, body="comment")
        for i in range(21)
    ]
    with pytest.raises(ValidationError):
        SubmitPRReviewRequest(
            repo="test/repo",
            pr_number=1,
            head_sha="abc123def",
            event="COMMENT",
            summary="Too many comments",
            comments=comments,
        )


def test_duplicate_review_blocked_without_second_post(tmp_path, monkeypatch):
    """Second submission with same (repo, pr_number, head_sha, event) is blocked."""
    db_path = tmp_path / "test.db"
    monkeypatch.setenv("JOB_DB_PATH", str(db_path))
    init_db()

    monkeypatch.setenv("GITHUB_TOKEN", "test_token")
    monkeypatch.setenv("ALLOWED_REPOSITORIES", "test/repo")

    call_counter: list[dict] = []
    mock_client = _make_mock_client(_make_review_response(), call_counter)

    with patch("agent.workspace.httpx.AsyncClient", return_value=mock_client):
        result1 = asyncio.run(
            submit_pr_review(
                repo="test/repo",
                pr_number=1,
                head_sha="abc123def",
                event="COMMENT",
                summary="First review",
            )
        )
        assert result1["status"] == "submitted"

        result2 = asyncio.run(
            submit_pr_review(
                repo="test/repo",
                pr_number=1,
                head_sha="abc123def",
                event="COMMENT",
                summary="Duplicate review",
            )
        )
        assert result2["status"] == "duplicate_ignored"

    assert len(call_counter) == 1, "HTTP should be called exactly once for duplicate"


def test_unlisted_repo_blocked_before_http(monkeypatch):
    """Repo not in ALLOWED_REPOSITORIES must raise before any HTTP call."""
    monkeypatch.setenv("GITHUB_TOKEN", "test_token")
    monkeypatch.setenv("ALLOWED_REPOSITORIES", "example-org/sample-repo")

    with patch("agent.workspace.httpx.AsyncClient") as mock_cls:
        mock_cls.side_effect = AssertionError("HTTP must not be called")
        with pytest.raises(ValueError, match="not in ALLOWED_REPOSITORIES"):
            asyncio.run(
                submit_pr_review(
                    repo="evil/repo",
                    pr_number=1,
                    head_sha="abc123def",
                    event="COMMENT",
                    summary="Blocked",
                )
            )


def _assert_review_result(result: dict) -> None:
    """Assert the submit_pr_review return payload."""
    assert result["status"] == "submitted"
    assert result["review_id"] == 99
    assert result["state"] == "REQUEST_CHANGES"


def _assert_review_request(call_counter: list[dict]) -> None:
    """Assert exactly one HTTP POST hit the expected reviews endpoint."""
    assert len(call_counter) == 1
    call = call_counter[0]
    assert "/pulls/5/reviews" in call["url"]
    assert call["json"]["event"] == "REQUEST_CHANGES"


def _assert_inline_comment(call_counter: list[dict]) -> None:
    """Assert the single inline comment is posted on the RIGHT side at line 42."""
    comment = call_counter[0]["json"]["comments"][0]
    assert comment["side"] == "RIGHT"
    assert comment["path"] == "src/main.py"
    assert comment["line"] == 42


def _assert_audit_entry(caplog: pytest.LogCaptureFixture) -> None:
    """Assert the audit log records the submission for the repo."""
    assert "AUDIT submit_pr_review" in caplog.text
    assert "test/repo" in caplog.text


def test_valid_request_changes_posts_and_logs_audit(tmp_path, monkeypatch, caplog):
    """Valid REQUEST_CHANGES with 1 inline comment posts correctly and logs audit."""
    db_path = tmp_path / "test.db"
    monkeypatch.setenv("JOB_DB_PATH", str(db_path))
    init_db()

    monkeypatch.setenv("GITHUB_TOKEN", "test_token")
    monkeypatch.setenv("ALLOWED_REPOSITORIES", "test/repo")

    call_counter: list[dict] = []
    mock_client = _make_mock_client(
        _make_review_response(review_id=99, state="REQUEST_CHANGES"), call_counter
    )

    caplog.set_level(logging.INFO)

    with patch("agent.workspace.httpx.AsyncClient", return_value=mock_client):
        result = asyncio.run(
            submit_pr_review(
                repo="test/repo",
                pr_number=5,
                head_sha="xyz789abc",
                event="REQUEST_CHANGES",
                summary="Changes requested",
                comments=[{"path": "src/main.py", "line": 42, "body": "Fix this"}],
            )
        )

    _assert_review_result(result)
    _assert_review_request(call_counter)
    _assert_inline_comment(call_counter)
    _assert_audit_entry(caplog)
