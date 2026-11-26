"""Token/line scanner for LLM code-truncation placeholder comments."""

from __future__ import annotations

import io
import re
import tokenize
from typing import Final

from guard.rules.base import DiagnosticFinding

RULE_ID: Final[str] = "INCOMPLETE_CODE"

WHY_PLACEHOLDER: Final[str] = (
    "Truncation artifacts corrupt code structure, introduce syntax errors, and indicate incomplete edits."
)

HOW_PLACEHOLDER: Final[str] = (
    "1. Write the complete function or block in full.\n"
    "2. Remove placeholder comments such as '# ... existing code ...' or '[truncated]'."
)

PLACEHOLDER_PATTERNS: Final[tuple[re.Pattern[str], ...]] = (
    re.compile(r"#\s*\.\.\.\s*existing code", re.IGNORECASE),
    re.compile(r"#\s*\.\.\.\s*rest of code", re.IGNORECASE),
    re.compile(r"#\s*\.\.\.\s*remaining code", re.IGNORECASE),
    re.compile(r"#\s*\.\.\.\s*previous code", re.IGNORECASE),
    re.compile(r"#\s*\[\s*truncated\s*\]", re.IGNORECASE),
    re.compile(r"#\s*\.\.\.\s*snip", re.IGNORECASE),
    re.compile(r"^\s*#\s*\.\.\.\s*$", re.IGNORECASE),
    re.compile(r"^\s*#\s*\.\.\.\s*(code|logic|functions|classes|lines|imports)\s*$", re.IGNORECASE),
)


def _is_placeholder_comment(text: str) -> bool:
    return any(pat.search(text) for pat in PLACEHOLDER_PATTERNS)


def _make_finding(file_path: str, line: int, text: str, snippet: str) -> DiagnosticFinding:
    return DiagnosticFinding(
        file_path=file_path,
        line=line,
        rule_id=RULE_ID,
        symbol=text.strip(),
        what="Code truncation artifact or placeholder comment detected.",
        why=WHY_PLACEHOLDER,
        how=HOW_PLACEHOLDER,
        code_snippet=snippet.strip() or text.strip(),
    )


def _scan_tokens(source_text: str, file_path: str) -> list[DiagnosticFinding]:
    findings: list[DiagnosticFinding] = []
    reader = io.StringIO(source_text).readline
    for token in tokenize.generate_tokens(reader):
        if token.type == tokenize.COMMENT and _is_placeholder_comment(token.string):
            findings.append(_make_finding(file_path, token.start[0], token.string, token.line))
    return findings


def _scan_lines(source_text: str, file_path: str) -> list[DiagnosticFinding]:
    findings: list[DiagnosticFinding] = []
    for idx, line in enumerate(source_text.splitlines(), start=1):
        if _is_placeholder_comment(line):
            findings.append(_make_finding(file_path, idx, line, line))
    return findings


def scan_truncation(source_text: str, file_path: str) -> list[DiagnosticFinding]:
    """Scan Python source for LLM truncation placeholder comments."""
    try:
        findings = _scan_tokens(source_text, file_path)
    except (tokenize.TokenError, IndentationError, SyntaxError):
        findings = _scan_lines(source_text, file_path)
    findings.sort(key=lambda f: f.line)
    return findings
