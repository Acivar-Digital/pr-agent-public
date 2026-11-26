"""AST scanner enforcing `model_config = ConfigDict(extra='forbid')` on Pydantic BaseModel classes."""

from __future__ import annotations

import ast
from typing import Final

from guard.rules.base import DiagnosticFinding, parse_ast_safe

RULE_ID: Final[str] = "STRICT_SCHEMA"

WHY_GUIDANCE: Final[str] = (
    "Without `extra='forbid'`, Pydantic silently ignores unexpected fields, hiding schema drift and typos."
)

HOW_GUIDANCE: Final[str] = "Add `model_config = ConfigDict(extra='forbid')` inside the BaseModel class body."


def _is_basemodel_base(base: ast.expr) -> bool:
    if isinstance(base, ast.Name):
        return base.id == "BaseModel"
    return isinstance(base, ast.Attribute) and base.attr == "BaseModel"


def _is_basemodel_subclass(node: ast.ClassDef) -> bool:
    return any(_is_basemodel_base(base) for base in node.bases)


def _kw_is_extra_forbid(kw: ast.keyword) -> bool:
    return kw.arg == "extra" and isinstance(kw.value, ast.Constant) and kw.value.value == "forbid"


def _stmt_sets_extra_forbid(stmt: ast.stmt) -> bool:
    if not isinstance(stmt, ast.Assign) or not isinstance(stmt.value, ast.Call):
        return False
    if not any(isinstance(t, ast.Name) and t.id == "model_config" for t in stmt.targets):
        return False
    return any(_kw_is_extra_forbid(kw) for kw in stmt.value.keywords)


def _has_extra_forbid(node: ast.ClassDef) -> bool:
    return any(_stmt_sets_extra_forbid(stmt) for stmt in node.body)


def _is_loose_basemodel(node: ast.AST) -> bool:
    return isinstance(node, ast.ClassDef) and _is_basemodel_subclass(node) and not _has_extra_forbid(node)


def scan_strict_schema(source_text: str, file_path: str) -> list[DiagnosticFinding]:
    """Scan Python source for Pydantic BaseModel classes missing extra='forbid'."""
    tree = parse_ast_safe(source_text, file_path)
    if tree is None:
        return []

    findings: list[DiagnosticFinding] = []
    for node in ast.walk(tree):
        if _is_loose_basemodel(node) and isinstance(node, ast.ClassDef):
            findings.append(
                DiagnosticFinding(
                    file_path=file_path,
                    line=node.lineno,
                    rule_id=RULE_ID,
                    symbol=node.name,
                    what=f"Pydantic model '{node.name}' is missing `model_config = ConfigDict(extra='forbid')`.",
                    why=WHY_GUIDANCE,
                    how=HOW_GUIDANCE,
                    code_snippet=f"class {node.name}(BaseModel):",
                )
            )
    findings.sort(key=lambda f: f.line)
    return findings
