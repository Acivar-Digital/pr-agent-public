"""Tests for gated draft-PR opener (strike breaker + verdict gate + injected opener)."""

from __future__ import annotations

import asyncio
import tempfile
from pathlib import Path

import pytest

from src.orchestrator.middleware.audit import AuditLogger
from src.orchestrator.tools.gated_pr import (
    APPROVED_VERDICT,
    STRIKE_LIMIT,
    GateResult,
    handle_security_review_completion,
    open_draft_pr,
)

REPO = "acme/widgets"
BRANCH = "feature/x"
SHA = "abc123"


def _diff(paths: list[str], *, loc: int = 1) -> str:
    chunks: list[str] = []
    for path in paths:
        lines = "".join(f"+line {i}\n" for i in range(loc))
        chunks.append(
            f"diff --git a/{path} b/{path}\n"
            f"--- a/{path}\n"
            f"+++ b/{path}\n"
            f"@@ -0,0 +1,{loc} @@\n"
            f"{lines}"
        )
    return "".join(chunks)


def _make_audit(tmp: Path) -> AuditLogger:
    audit = AuditLogger(tmp / "audit.db")
    audit.init_db()
    return audit


def _seed_approved(audit: AuditLogger) -> None:
    audit.record_checks_verdict(REPO, BRANCH, SHA, checks_passed=True)
    handle_security_review_completion(
        audit, repo=REPO, branch=BRANCH, head_commit_sha=SHA, verdict=APPROVED_VERDICT
    )


def test_strike_limit_reached_refuses_without_opening() -> None:
    async def scenario() -> tuple[GateResult, int]:
        with tempfile.TemporaryDirectory() as d:
            audit = _make_audit(Path(d))
            audit.record_strike(REPO, BRANCH, strikes=STRIKE_LIMIT)
            calls = 0

            async def opener(**kwargs: object) -> None:
                nonlocal calls
                calls += 1

            result = await open_draft_pr(
                repo=REPO,
                branch=BRANCH,
                head_commit_sha=SHA,
                diff_text=_diff(["src/a.py"]),
                audit=audit,
                pr_opener=opener,
            )
            return result, calls

    result, calls = asyncio.run(scenario())
    assert result.proceed is False
    assert "circuit breaker" in result.reason
    assert result.strikes == STRIKE_LIMIT
    assert calls == 0


def test_over_limit_refuses_and_increments_strike() -> None:
    async def scenario() -> tuple[GateResult, int]:
        with tempfile.TemporaryDirectory() as d:
            audit = _make_audit(Path(d))
            _seed_approved(audit)
            calls = 0

            async def opener(**kwargs: object) -> None:
                nonlocal calls
                calls += 1

            result = await open_draft_pr(
                repo=REPO,
                branch=BRANCH,
                head_commit_sha=SHA,
                diff_text=_diff([f"src/f{i}.py" for i in range(11)]),
                audit=audit,
                pr_opener=opener,
            )
            assert calls == 0
            return result, audit.get_strikes(REPO, BRANCH)

    result, strikes = asyncio.run(scenario())
    assert result.proceed is False
    assert "blast radius exceeded" in result.reason
    assert result.strikes == 1
    assert strikes == 1


def test_missing_verdict_refuses() -> None:
    async def scenario() -> GateResult:
        with tempfile.TemporaryDirectory() as d:
            audit = _make_audit(Path(d))

            async def opener(**kwargs: object) -> None:
                raise AssertionError("pr_opener must not be called")

            return await open_draft_pr(
                repo=REPO,
                branch=BRANCH,
                head_commit_sha=SHA,
                diff_text=_diff(["src/a.py"]),
                audit=audit,
                pr_opener=opener,
            )

    result = asyncio.run(scenario())
    assert result.proceed is False
    assert result.reason == "verification not approved"


def test_denied_verdict_refuses() -> None:
    async def scenario() -> GateResult:
        with tempfile.TemporaryDirectory() as d:
            audit = _make_audit(Path(d))
            audit.record_checks_verdict(REPO, BRANCH, SHA, checks_passed=True)
            handle_security_review_completion(
                audit,
                repo=REPO,
                branch=BRANCH,
                head_commit_sha=SHA,
                verdict="CHANGES_REQUESTED",
            )

            async def opener(**kwargs: object) -> None:
                raise AssertionError("pr_opener must not be called")

            return await open_draft_pr(
                repo=REPO,
                branch=BRANCH,
                head_commit_sha=SHA,
                diff_text=_diff(["src/a.py"]),
                audit=audit,
                pr_opener=opener,
            )

    result = asyncio.run(scenario())
    assert result.proceed is False
    assert result.reason == "verification not approved"


def test_approved_within_limits_calls_opener_once() -> None:
    async def scenario() -> tuple[GateResult, int]:
        with tempfile.TemporaryDirectory() as d:
            audit = _make_audit(Path(d))
            _seed_approved(audit)
            calls = 0
            seen: dict[str, object] = {}

            async def opener(**kwargs: object) -> None:
                nonlocal calls
                calls += 1
                seen.update(kwargs)

            result = await open_draft_pr(
                repo=REPO,
                branch=BRANCH,
                head_commit_sha=SHA,
                diff_text=_diff(["src/a.py"]),
                audit=audit,
                pr_opener=opener,
                opener_kwargs={"title": "feat: x", "draft": True},
            )
            assert seen == {"title": "feat: x", "draft": True}
            return result, calls

    result, calls = asyncio.run(scenario())
    assert result.proceed is True
    assert result.reason == "ok"
    assert result.strikes == 0
    assert calls == 1


def test_handle_security_review_completion_writes_verdict() -> None:
    with tempfile.TemporaryDirectory() as d:
        audit = _make_audit(Path(d))
        handle_security_review_completion(
            audit,
            repo=REPO,
            branch=BRANCH,
            head_commit_sha=SHA,
            verdict=APPROVED_VERDICT,
        )
        row = audit.get_verification_verdict(REPO, BRANCH, SHA)
        assert row is not None
        assert row["security_verdict"] == APPROVED_VERDICT


# ---------------------------------------------------------------------------
# Review regressions (#37)
# ---------------------------------------------------------------------------


def test_strike_count_is_authoritative() -> None:
    # The returned count must come from record_strike, not a stale pre-read + 1.
    class StubAudit:
        def get_strikes(self, repo: str, branch: str) -> int:
            return 0

        def record_strike(self, repo: str, branch: str) -> int:
            return 7  # authoritative post-mutation count

        def get_verification_verdict(self, *a: object) -> None:
            return None

    async def scenario() -> GateResult:
        async def opener(**kwargs: object) -> None:
            raise AssertionError("pr_opener must not be called")

        return await open_draft_pr(
            repo=REPO,
            branch=BRANCH,
            head_commit_sha=SHA,
            diff_text=_diff([f"src/f{i}.py" for i in range(11)]),
            audit=StubAudit(),
            pr_opener=opener,
        )

    result = asyncio.run(scenario())
    assert result.proceed is False
    assert result.strikes == 7


def test_unparseable_diff_records_strike(monkeypatch: pytest.MonkeyPatch) -> None:
    from unidiff.errors import UnidiffParseError

    from src.orchestrator.guardrails import blast_radius as br

    def boom(_: str) -> object:
        raise UnidiffParseError("bad diff")

    monkeypatch.setattr(br, "PatchSet", boom)

    async def scenario() -> tuple[GateResult, int]:
        with tempfile.TemporaryDirectory() as d:
            audit = _make_audit(Path(d))
            _seed_approved(audit)

            async def opener(**kwargs: object) -> None:
                raise AssertionError("pr_opener must not be called")

            result = await open_draft_pr(
                repo=REPO,
                branch=BRANCH,
                head_commit_sha=SHA,
                diff_text="garbage",
                audit=audit,
                pr_opener=opener,
            )
            return result, audit.get_strikes(REPO, BRANCH)

    result, strikes = asyncio.run(scenario())
    assert result.proceed is False
    assert "blast radius exceeded" in result.reason
    assert strikes == 1
