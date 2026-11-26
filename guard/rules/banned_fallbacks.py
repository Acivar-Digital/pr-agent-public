"""AST scanner for silent fallback returns inside except blocks."""

from __future__ import annotations

import ast
from typing import Final

from guard.rules.base import DiagnosticFinding, parse_ast_safe

RULE_ID: Final[str] = "BANNED_FALLBACK"

WHY_GUIDANCE: Final[str] = (
    "Catching exceptions and returning silent empty defaults (None, '', 0, False, [], {}) "
    "masks failures and corrupts downstream decisions."
)

HOW_GUIDANCE: Final[str] = (
    "1. Let the exception propagate, or raise an explicit domain error.\n"
    "2. If a fallback is truly intentional at an API boundary, log the failure with context."
)


def _is_empty_container_call(val: ast.Call) -> bool:
    if not isinstance(val.func, ast.Name) or val.func.id not in {"dict", "list", "set", "tuple"}:
        return False
    return not val.args and not val.keywords


def _is_empty_container(val: ast.expr | None) -> bool:
    if isinstance(val, ast.Dict):
        return len(val.keys) == 0
    if isinstance(val, (ast.List, ast.Tuple, ast.Set)):
        return len(val.elts) == 0
    if isinstance(val, ast.Call):
        return _is_empty_container_call(val)
    return False


def _is_banned_fallback_value(val: ast.expr | None) -> bool:
    if val is None:
        return True
    if isinstance(val, ast.Constant) and val.value in (None, "", 0, False):
        return True
    return _is_empty_container(val)


def _iter_handler_returns(handler: ast.ExceptHandler) -> list[ast.Return]:
    returns: list[ast.Return] = []
    stack: list[ast.AST] = list(handler.body)
    while stack:
        current = stack.pop()
        if isinstance(current, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        if isinstance(current, ast.Return):
            returns.append(current)
            continue
        stack.extend(ast.iter_child_nodes(current))
    return returns


def _scan_handler(handler: ast.ExceptHandler, file_path: str) -> list[DiagnosticFinding]:
    findings: list[DiagnosticFinding] = []
    for ret in _iter_handler_returns(handler):
        if _is_banned_fallback_value(ret.value):
            snippet = ast.unparse(ret)
            findings.append(
                DiagnosticFinding(
                    file_path=file_path,
                    line=ret.lineno,
                    rule_id=RULE_ID,
                    symbol=snippet,
                    what=f"Exception handler returns silent fallback `{snippet}`.",
                    why=WHY_GUIDANCE,
                    how=HOW_GUIDANCE,
                    code_snippet=snippet,
                )
            )
    return findings


def scan_banned_fallbacks(source_text: str, file_path: str) -> list[DiagnosticFinding]:
    """Scan Python source for except handlers returning silent empty/falsy fallbacks."""
    tree = parse_ast_safe(source_text, file_path)
    if tree is None:
        return []

    findings: list[DiagnosticFinding] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.ExceptHandler):
            findings.extend(_scan_handler(node, file_path))
    findings.sort(key=lambda f: f.line)
    return findings
