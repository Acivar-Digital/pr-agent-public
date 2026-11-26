"""Security-reviewer verdict derivation (fail-closed).

A reviewer job's ``status`` is ``completed`` even when it found critical
vulnerabilities, so status alone must never mean approval. Approval requires an
explicit token in the summary, no warnings, and no static findings.
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from agent.pr_worker import PRTaskReport

_APPROVAL_RE = re.compile(r"\b(APPROVED|LGTM|SHIP\s+IT)\b")
_REJECTION_RE = re.compile(r"\b(NO-GO|CHANGES_REQUESTED|REJECTED|BLOCK(?:ED)?)\b")

APPROVED = "APPROVED"
CHANGES_REQUESTED = "CHANGES_REQUESTED"


def _summary_verdict(summary: str) -> str:
    """Token check on the reviewer summary; ambiguous is CHANGES_REQUESTED."""
    text = (summary or "").upper()
    if _REJECTION_RE.search(text):
        return CHANGES_REQUESTED
    if _APPROVAL_RE.search(text):
        return APPROVED
    return CHANGES_REQUESTED


def _security_verdict(report: PRTaskReport) -> str:
    """Explicit, fail-closed approval: anything ambiguous is CHANGES_REQUESTED."""
    if report.status != "completed":
        return CHANGES_REQUESTED
    if report.warnings or report.static_findings:
        return CHANGES_REQUESTED
    return _summary_verdict(report.summary)
