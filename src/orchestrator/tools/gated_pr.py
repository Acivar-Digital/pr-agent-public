"""Gated draft-PR opener: 3-strike circuit breaker + verification verdict gate."""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Any

from src.orchestrator.guardrails.blast_radius import evaluate_blast_radius

STRIKE_LIMIT: int = 3
APPROVED_VERDICT: str = "APPROVED"


@dataclass(frozen=True)
class GateResult:
    proceed: bool
    reason: str
    strikes: int


def handle_security_review_completion(
    audit: Any,
    *,
    repo: str,
    branch: str,
    head_commit_sha: str,
    verdict: str,
    timestamp: str | None = None,
) -> None:
    """Record a security reviewer verdict onto the audit trail (non-clobbering upsert)."""
    audit.record_security_verdict(
        repo,
        branch,
        head_commit_sha,
        verdict,
        timestamp=timestamp,
    )


def _check_blast_radius(
    repo: str,
    branch: str,
    diff_text: str,
    audit: Any,
) -> GateResult | None:
    """Return a blocking GateResult when the diff fails blast-radius limits."""
    report = evaluate_blast_radius(diff_text)
    if report.blocked:
        strikes = audit.record_strike(repo, branch)
        return GateResult(
            proceed=False,
            reason=f"blocked paths: {', '.join(report.blocked)}",
            strikes=strikes,
        )
    if not report.within_limits:
        strikes = audit.record_strike(repo, branch)
        return GateResult(
            proceed=False,
            reason=f"blast radius exceeded: {', '.join(report.reasons)}",
            strikes=strikes,
        )
    return None


def _check_verdict(
    repo: str,
    branch: str,
    head_commit_sha: str,
    audit: Any,
) -> GateResult | None:
    """Return a blocking GateResult when no approved verification verdict exists."""
    verdict_row = audit.get_verification_verdict(repo, branch, head_commit_sha)
    approved = bool(
        verdict_row
        and verdict_row["checks_passed"]
        and verdict_row["security_verdict"] == APPROVED_VERDICT
    )
    if not approved:
        strikes = audit.record_strike(repo, branch)
        return GateResult(
            proceed=False,
            reason="verification not approved",
            strikes=strikes,
        )
    return None


async def open_draft_pr(
    *,
    repo: str,
    branch: str,
    head_commit_sha: str,
    diff_text: str,
    audit: Any,
    pr_opener: Callable[..., Awaitable[Any]],
    opener_kwargs: dict[str, Any] | None = None,
) -> GateResult:
    """Open a draft PR only if the strike budget, blast radius, and verdict all pass.

    Fail-closed: any unmet condition records a strike and refuses to call pr_opener.
    The returned ``strikes`` is always the authoritative post-mutation count.
    """
    strikes = audit.get_strikes(repo, branch)
    if strikes >= STRIKE_LIMIT:
        return GateResult(
            proceed=False,
            reason=f"circuit breaker: {strikes} strikes",
            strikes=strikes,
        )

    blast_failure = _check_blast_radius(repo, branch, diff_text, audit)
    if blast_failure is not None:
        return blast_failure

    verdict_failure = _check_verdict(repo, branch, head_commit_sha, audit)
    if verdict_failure is not None:
        return verdict_failure

    await pr_opener(**(opener_kwargs or {}))
    return GateResult(proceed=True, reason="ok", strikes=strikes)
