"""Scanner for type-checking suppression comments.

This repo uses `ty`, so legacy `type: ignore` and `pyright: ignore` comments
are disallowed.
"""

from __future__ import annotations

import io
import re
import tokenize
from typing import Final

from guard.rules.base import DiagnosticFinding

RULE_ID: Final[str] = "NO_TYPE_IGNORE"

WHY_EXPLANATION: Final[str] = (
    "Suppressing type checking with legacy ignore comments bypasses "
    "the repo's `ty` typechecker and masks type mismatches."
)

HOW_EXPLANATION: Final[str] = (
    "1. Remove the suppression comment and fix the underlying type signature.\n"
    "2. If a genuine cross-checker edge case requires suppression, use a targeted ty-ignore rule."
)

TYPE_IGNORE_RE: Final[re.Pattern[str]] = re.compile(r"#\s*" r"type\s*:\s*ignore\b", re.IGNORECASE)
PYRIGHT_IGNORE_RE: Final[re.Pattern[str]] = re.compile(r"#\s*" r"pyright\s*:\s*ignore\b", re.IGNORECASE)


def _find_ignore_match(text: str) -> re.Match[str] | None:
    return PYRIGHT_IGNORE_RE.search(text) or TYPE_IGNORE_RE.search(text)


def _make_finding(
    file_path: str,
    line_num: int,
    comment_text: str,
    code_snippet: str | None = None,
) -> DiagnosticFinding:
    stripped = comment_text.strip()
    snippet = code_snippet.strip() if code_snippet else stripped
    return DiagnosticFinding(
        file_path=file_path,
        line=line_num,
        rule_id=RULE_ID,
        symbol=stripped,
        what=f"Found disallowed type suppression comment '{stripped}' on line {line_num}.",
        why=WHY_EXPLANATION,
        how=HOW_EXPLANATION,
        code_snippet=snippet,
    )


def _scan_via_tokens(source_text: str, file_path: str) -> list[DiagnosticFinding]:
    findings: list[DiagnosticFinding] = []
    reader = io.StringIO(source_text).readline
    for token in tokenize.generate_tokens(reader):
        if token.type == tokenize.COMMENT and _find_ignore_match(token.string):
            findings.append(_make_finding(file_path, token.start[0], token.string, token.line))
    return findings


def _scan_via_lines(source_text: str, file_path: str) -> list[DiagnosticFinding]:
    findings: list[DiagnosticFinding] = []
    for idx, line in enumerate(source_text.splitlines(), start=1):
        match = _find_ignore_match(line)
        if match:
            findings.append(_make_finding(file_path, idx, line[match.start() :].strip(), line))
    return findings


def scan_no_type_ignore(source_text: str, file_path: str) -> list[DiagnosticFinding]:
    """Scan Python source for disallowed type-ignore comments."""
    try:
        findings = _scan_via_tokens(source_text, file_path)
    except (tokenize.TokenError, IndentationError, SyntaxError):
        findings = _scan_via_lines(source_text, file_path)
    findings.sort(key=lambda f: f.line)
    return findings
