"""AST scanner for synchronous blocking calls inside async functions."""

from __future__ import annotations

import ast
from typing import Final

from guard.rules.base import DiagnosticFinding, parse_ast_safe

RULE_ID: Final[str] = "ASYNC_BLOCKING"

WHY_EXPLANATION: Final[str] = (
    "Synchronous blocking calls (time.sleep, requests, subprocess) freeze the asyncio "
    "event loop and block concurrent FastAPI/MCP requests and background job workers."
)

HOW_EXPLANATION: Final[str] = (
    "1. Replace time.sleep(n) with await asyncio.sleep(n).\n"
    "2. Replace requests with httpx.AsyncClient.\n"
    "3. Replace subprocess.* with asyncio.create_subprocess_exec or await asyncio.to_thread(...)."
)

BLOCKING_CALLS: Final[frozenset[str]] = frozenset(
    {
        "time.sleep",
        "requests.get",
        "requests.post",
        "requests.put",
        "requests.delete",
        "requests.patch",
        "requests.request",
        "requests.head",
        "requests.options",
        "urllib.request.urlopen",
        "subprocess.run",
        "subprocess.Popen",
        "subprocess.call",
        "subprocess.check_output",
        "subprocess.check_call",
        "os.system",
        "os.popen",
    }
)


def _get_call_name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        value_name = _get_call_name(node.value)
        return f"{value_name}.{node.attr}" if value_name else node.attr
    return ""


def _record_import(node: ast.Import, aliases: dict[str, str]) -> None:
    for alias in node.names:
        aliases[alias.asname or alias.name] = alias.name


def _record_import_from(node: ast.ImportFrom, aliases: dict[str, str]) -> None:
    module = node.module or ""
    for alias in node.names:
        name = alias.asname or alias.name
        aliases[name] = f"{module}.{alias.name}" if module else alias.name


def _collect_import_aliases(tree: ast.AST) -> dict[str, str]:
    aliases: dict[str, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            _record_import(node, aliases)
        elif isinstance(node, ast.ImportFrom):
            _record_import_from(node, aliases)
    return aliases


def _resolve_to_target(call_name: str, aliases: dict[str, str]) -> str:
    if not call_name:
        return ""
    if call_name in aliases:
        return aliases[call_name]
    parts = call_name.split(".", 1)
    if len(parts) == 2 and parts[0] in aliases:
        return f"{aliases[parts[0]]}.{parts[1]}"
    return call_name


class _AsyncBlockingVisitor(ast.NodeVisitor):
    def __init__(self, file_path: str, aliases: dict[str, str]) -> None:
        self.file_path = file_path
        self.aliases = aliases
        self.findings: list[DiagnosticFinding] = []
        self._async_func_stack: list[str] = []

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._async_func_stack.append(node.name)
        self.generic_visit(node)
        self._async_func_stack.pop()

    def visit_Call(self, node: ast.Call) -> None:
        self._inspect_call(node)
        self.generic_visit(node)

    def _inspect_call(self, node: ast.Call) -> None:
        if not self._async_func_stack:
            return
        call_name = _get_call_name(node.func)
        resolved = _resolve_to_target(call_name, self.aliases)
        if resolved not in BLOCKING_CALLS and call_name not in BLOCKING_CALLS:
            return
        self.findings.append(
            DiagnosticFinding(
                file_path=self.file_path,
                line=node.lineno,
                rule_id=RULE_ID,
                symbol=call_name,
                what=f"Synchronous blocking call '{call_name}' inside async function '{self._async_func_stack[-1]}'.",
                why=WHY_EXPLANATION,
                how=HOW_EXPLANATION,
                code_snippet=ast.unparse(node),
            )
        )


def scan_async_blocking(source_text: str, file_path: str) -> list[DiagnosticFinding]:
    """Scan Python source for synchronous blocking calls inside async functions."""
    tree = parse_ast_safe(source_text, file_path)
    if tree is None:
        return []
    visitor = _AsyncBlockingVisitor(file_path, _collect_import_aliases(tree))
    visitor.visit(tree)
    visitor.findings.sort(key=lambda f: f.line)
    return visitor.findings
