"""Pure-AST Cyclomatic Complexity (CC <= 5) and Nesting Depth (depth <= 3) gatekeeper."""

from __future__ import annotations

import ast
from typing import Final

from guard.rules.base import DiagnosticFinding, parse_ast_safe

DEFAULT_MAX_CC: Final[int] = 5
DEFAULT_MAX_DEPTH: Final[int] = 3

WHY_GUIDANCE: Final[str] = (
    "High cyclomatic complexity and deep nesting multiply edge cases and make code harder to verify."
)

HOW_GUIDANCE: Final[str] = (
    "1. Apply guard clauses / early returns.\n"
    "2. Extract nested loops or branch blocks into small helper functions.\n"
    "3. Use mapping/dispatch tables instead of deep if/elif ladders."
)

NESTING_NODE_TYPES: Final[tuple[type[ast.AST], ...]] = (
    ast.For,
    ast.AsyncFor,
    ast.While,
    ast.If,
    ast.IfExp,
    ast.With,
    ast.AsyncWith,
    ast.Try,
    ast.TryStar,
    ast.Match,
    ast.ListComp,
    ast.DictComp,
    ast.SetComp,
    ast.GeneratorExp,
)

CC_BRANCH_NODES: Final[tuple[type[ast.AST], ...]] = (
    ast.If,
    ast.IfExp,
    ast.For,
    ast.AsyncFor,
    ast.While,
    ast.ExceptHandler,
    ast.With,
    ast.AsyncWith,
    ast.Assert,
)


def _walk_nesting(node: ast.AST, depth: int, is_root: bool, max_ref: list[int]) -> None:
    if not is_root and isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
        return
    current = depth + 1 if isinstance(node, NESTING_NODE_TYPES) else depth
    max_ref[0] = max(max_ref[0], current)
    for child in ast.iter_child_nodes(node):
        _walk_nesting(child, current, False, max_ref)


def _max_nesting_depth(func_node: ast.FunctionDef | ast.AsyncFunctionDef) -> int:
    ref = [0]
    _walk_nesting(func_node, 0, True, ref)
    return ref[0]


def _node_cc_increment(node: ast.AST) -> int:
    if isinstance(node, CC_BRANCH_NODES):
        return 1
    if isinstance(node, ast.BoolOp):
        return max(0, len(node.values) - 1)
    if isinstance(node, ast.Match):
        return max(0, len(node.cases) - 1)
    if isinstance(node, ast.comprehension):
        return len(node.ifs)
    return 0


def _cyclomatic_complexity(func_node: ast.FunctionDef | ast.AsyncFunctionDef) -> int:
    score = 1
    stack: list[ast.AST] = list(func_node.body)
    while stack:
        node = stack.pop()
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            continue
        score += _node_cc_increment(node)
        stack.extend(ast.iter_child_nodes(node))
    return score


def _check_function(
    node: ast.FunctionDef | ast.AsyncFunctionDef,
    file_path: str,
    lines: list[str],
    max_cc: int,
    max_depth: int,
) -> list[DiagnosticFinding]:
    findings: list[DiagnosticFinding] = []
    snippet = lines[node.lineno - 1].strip() if 1 <= node.lineno <= len(lines) else f"def {node.name}(...):"
    depth = _max_nesting_depth(node)
    if depth > max_depth:
        findings.append(
            DiagnosticFinding(
                file_path=file_path,
                line=node.lineno,
                rule_id="NESTED_DEPTH",
                symbol=node.name,
                what=f"Function '{node.name}' has nesting depth {depth} (limit <= {max_depth}).",
                why=WHY_GUIDANCE,
                how=HOW_GUIDANCE,
                code_snippet=snippet,
            )
        )
    cc = _cyclomatic_complexity(node)
    if cc > max_cc:
        findings.append(
            DiagnosticFinding(
                file_path=file_path,
                line=node.lineno,
                rule_id="CYCLOMATIC_COMPLEXITY",
                symbol=node.name,
                what=f"Function '{node.name}' has cyclomatic complexity {cc} (limit <= {max_cc}).",
                why=WHY_GUIDANCE,
                how=HOW_GUIDANCE,
                code_snippet=snippet,
            )
        )
    return findings


def scan_cc_nested(
    source_text: str,
    file_path: str,
    max_cc: int = DEFAULT_MAX_CC,
    max_depth: int = DEFAULT_MAX_DEPTH,
) -> list[DiagnosticFinding]:
    """Scan Python functions for nesting depth > max_depth or McCabe CC > max_cc."""
    tree = parse_ast_safe(source_text, file_path)
    if tree is None:
        return []

    findings: list[DiagnosticFinding] = []
    lines = source_text.splitlines()
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            findings.extend(_check_function(node, file_path, lines, max_cc, max_depth))
    findings.sort(key=lambda f: f.line)
    return findings
