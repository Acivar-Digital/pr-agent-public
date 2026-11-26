"""Base diagnostic model and tripartite (What / Why / How) formatter."""

from __future__ import annotations

import ast

from pydantic import BaseModel, ConfigDict


def parse_ast_safe(source_text: str, file_path: str) -> ast.AST | None:
    """Parse Python source into an AST, returning None on syntax/null-byte/recursion errors."""
    tree: ast.AST | None = None
    try:
        tree = ast.parse(source_text, filename=file_path)
    except (SyntaxError, ValueError, RecursionError):
        tree = None
    return tree


def _format_header(file_path: str, line: int, rule_id: str, symbol: str) -> str:
    if not symbol:
        return f"{file_path}:{line}: [{rule_id}]"
    return f"{file_path}:{line}: [{rule_id}] {symbol}"


def _format_snippet(snippet: str | None) -> list[str]:
    if not snippet:
        return []
    clean = snippet.strip()
    if not clean:
        return []
    lines = ["  • CODE:"]
    for row in clean.splitlines():
        lines.append(f"    {row}")
    return lines


class DiagnosticFinding(BaseModel):
    """Structured diagnostic finding with tripartite (What, Why, How) guidance."""

    model_config = ConfigDict(extra="forbid")

    file_path: str
    line: int = 1
    rule_id: str
    symbol: str = ""
    what: str
    why: str
    how: str
    code_snippet: str | None = None

    def format_diagnostic(self) -> str:
        """Format finding as a multiline What/Why/How diagnostic string."""
        lines = [
            _format_header(self.file_path, self.line, self.rule_id, self.symbol),
            f"  • WHAT: {self.what}",
            f"  • WHY:  {self.why}",
            f"  • HOW:  {self.how}",
        ]
        lines.extend(_format_snippet(self.code_snippet))
        return "\n".join(lines)

    @property
    def message(self) -> str:
        """Alias for what."""
        return self.what
