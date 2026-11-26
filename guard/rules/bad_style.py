"""AST scanner for anti-slop style violations.

Checks:
1. BARE_EXCEPT: Bare `except:` clauses.
2. SWALLOWED_EXCEPTION: Broad `except Exception:` / `except BaseException:` with only `pass` or `...`.
3. MUTABLE_DEFAULT: Mutable default arguments (`[]`, `{}`, `set()`, `list()`, `dict()`).
4. UNSAFE_OPEN: `open()` calls outside `with` / `async with` context managers.
"""

from __future__ import annotations

import ast
from typing import Final

from guard.rules.base import DiagnosticFinding, parse_ast_safe

RULE_ID: Final[str] = "BAD_STYLE"


def _is_broad_exception(handler_type: ast.expr) -> bool:
    if isinstance(handler_type, ast.Name):
        return handler_type.id in ("Exception", "BaseException")
    if isinstance(handler_type, ast.Tuple):
        return any(isinstance(elt, ast.Name) and elt.id in ("Exception", "BaseException") for elt in handler_type.elts)
    return False


def _is_swallowed_body(body: list[ast.stmt]) -> bool:
    if len(body) != 1:
        return len(body) == 0
    stmt = body[0]
    if isinstance(stmt, ast.Pass):
        return True
    return isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Constant) and stmt.value.value is Ellipsis


def _is_mutable_default(node: ast.expr) -> bool:
    if isinstance(node, (ast.List, ast.Dict, ast.Set)):
        return True
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
        return node.func.id in ("list", "dict", "set")
    return False


def _check_defaults(node: ast.FunctionDef | ast.AsyncFunctionDef, file_path: str) -> list[DiagnosticFinding]:
    findings: list[DiagnosticFinding] = []
    defaults = [*node.args.defaults, *(d for d in node.args.kw_defaults if d is not None)]
    for default in defaults:
        if _is_mutable_default(default):
            findings.append(
                DiagnosticFinding(
                    file_path=file_path,
                    line=default.lineno,
                    rule_id=RULE_ID,
                    symbol="MUTABLE_DEFAULT",
                    what=f"Mutable default argument in function '{node.name}'.",
                    why="Mutable defaults retain state across calls, causing shared-state bugs.",
                    how="Use `None` as the default and initialize the collection inside the function body.",
                    code_snippet=ast.unparse(default),
                )
            )
    return findings


def _check_except_handler(node: ast.ExceptHandler, file_path: str) -> DiagnosticFinding | None:
    if node.type is None:
        return DiagnosticFinding(
            file_path=file_path,
            line=node.lineno,
            rule_id=RULE_ID,
            symbol="BARE_EXCEPT",
            what="Bare `except:` clause catches SystemExit and KeyboardInterrupt.",
            why="Bare except hides fatal signals and masks unexpected failures.",
            how="Catch specific exceptions (e.g. `except ValueError as err:`) and log or re-raise.",
            code_snippet="except:",
        )
    if _is_broad_exception(node.type) and _is_swallowed_body(node.body):
        return DiagnosticFinding(
            file_path=file_path,
            line=node.lineno,
            rule_id=RULE_ID,
            symbol="SWALLOWED_EXCEPTION",
            what=f"Broad exception '{ast.unparse(node.type)}' swallowed with pass/ellipsis.",
            why="Silently swallowing broad exceptions hides bugs and corrupts downstream state.",
            how="Catch specific exceptions and log with context or re-raise.",
            code_snippet=f"except {ast.unparse(node.type)}:",
        )
    return None


def _collect_with_open_ids(node: ast.With | ast.AsyncWith, safe_ids: set[int]) -> None:
    for item in node.items:
        if isinstance(item.context_expr, ast.Call):
            safe_ids.add(id(item.context_expr))


def _collect_safe_open_ids(tree: ast.AST) -> set[int]:
    safe_ids: set[int] = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.With, ast.AsyncWith)):
            _collect_with_open_ids(node, safe_ids)
    return safe_ids


def _is_unsafe_open_call(node: ast.AST, safe_ids: set[int]) -> bool:
    return (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "open"
        and id(node) not in safe_ids
    )


def _check_unsafe_opens(tree: ast.AST, file_path: str) -> list[DiagnosticFinding]:
    safe_ids = _collect_safe_open_ids(tree)
    findings: list[DiagnosticFinding] = []
    for node in ast.walk(tree):
        if _is_unsafe_open_call(node, safe_ids) and isinstance(node, ast.Call):
            findings.append(
                DiagnosticFinding(
                    file_path=file_path,
                    line=node.lineno,
                    rule_id=RULE_ID,
                    symbol="UNSAFE_OPEN",
                    what="open() called outside a `with` / `async with` context manager.",
                    why="Leaks file descriptors on exceptions or unclosed handles.",
                    how="Use `with open(...) as f:` or `Path(...).read_text(encoding='utf-8')`.",
                    code_snippet=ast.unparse(node),
                )
            )
    return findings


def _inspect_node(node: ast.AST, file_path: str) -> list[DiagnosticFinding]:
    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
        return _check_defaults(node, file_path)
    if isinstance(node, ast.ExceptHandler):
        finding = _check_except_handler(node, file_path)
        return [finding] if finding is not None else []
    return []


def scan_bad_style(source_text: str, file_path: str) -> list[DiagnosticFinding]:
    """Scan Python source for bare except, swallowed exceptions, mutable defaults, and unsafe open()."""
    tree = parse_ast_safe(source_text, file_path)
    if tree is None:
        return []

    findings: list[DiagnosticFinding] = []
    for node in ast.walk(tree):
        findings.extend(_inspect_node(node, file_path))
    findings.extend(_check_unsafe_opens(tree, file_path))
    findings.sort(key=lambda f: f.line)
    return findings
