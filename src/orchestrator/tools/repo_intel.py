"""Scoped repository intelligence: local code search and repo maps (Ticket #28).

Two primitives, both fail-closed and bounded:

- ``search_code_local`` runs the ``rg`` binary with an argv list (``shell=False``)
  and a ``--`` separator before the pattern, so user queries can never be
  interpreted as flags. ``rg`` runs with ``cwd=root`` and a *relative* target so
  results are worktree-relative (never absolute host paths); ``SKIP_DIRS`` are
  excluded both as ``--glob '!dir/**'`` (so ``rg`` never scans them) and by a
  post-filter. A ``timeout`` bounds a slow regex.
- ``get_repo_map`` produces a compact, token-bounded map of a worktree: a stdlib
  ``ast`` outline for Python files and a plain tree line for everything else.
  Symlinks and any file resolving outside the worktree are skipped.

Path arguments are resolved with :func:`_safe_path`, which refuses anything that
escapes the worktree (``../../etc/passwd`` -> ``ValueError``).
"""

from __future__ import annotations

import ast
import os
import subprocess
from collections.abc import Iterator
from pathlib import Path

SKIP_DIRS = {
    ".git",
    ".venv",
    "node_modules",
    "__pycache__",
    ".mypy_cache",
    ".pytest_cache",
    "dist",
    "build",
}

MAX_MATCHES = 30
MAX_TOKENS = 2000

_RG_TIMEOUT_SECONDS = 15
_CHARS_PER_TOKEN = 4
_TRUNCATION_MARKER = "\n... [truncated]"


def _safe_path(worktree: Path, rel: str) -> Path:
    """Resolve ``worktree/rel`` and refuse anything outside the worktree."""
    root = Path(worktree).resolve()
    candidate = (root / rel).resolve()
    if not candidate.is_relative_to(root):
        raise ValueError(f"path escapes worktree: {rel!r}")
    return candidate


def _rel(path: Path, root: Path) -> str:
    try:
        return str(path.relative_to(root))
    except ValueError:
        return str(path)


def _under_skip_dir(path: str) -> bool:
    return any(part in SKIP_DIRS for part in Path(path).parts)


def _parse_rg_line(line: str) -> dict[str, object] | None:
    # rg --no-heading --with-filename emits ``file:line:text``.
    parts = line.split(":", 2)
    if len(parts) != 3:
        return None
    file, line_no, text = parts
    if not line_no.isdigit():
        return None
    line_int = int(line_no)
    return {"file": file, "line": line_int, "text": text}


def _build_rg_argv(query: str, rel_target: str, max_matches: int) -> list[str]:
    argv = [
        "rg",
        "--line-number",
        "--no-heading",
        "--with-filename",
        "--color",
        "never",
        "--max-count",
        str(max_matches),
    ]
    for skip in sorted(SKIP_DIRS):
        argv += ["--glob", f"!{skip}/**"]
    argv += ["--", query, rel_target]
    return argv


def _parse_rg_result(line: str) -> dict[str, object] | None:
    if not line:
        return None
    parsed = _parse_rg_line(line)
    if parsed is None:
        return None
    if _under_skip_dir(str(parsed["file"])):
        return None
    return parsed


def _collect_rg_results(stdout: str, max_matches: int) -> list[dict[str, object]]:
    results: list[dict[str, object]] = []
    for line in stdout.splitlines():
        parsed = _parse_rg_result(line)
        if parsed is None:
            continue
        results.append(parsed)
        if len(results) >= max_matches:
            break
    return results


def search_code_local(
    worktree: Path,
    query: str,
    *,
    max_matches: int = MAX_MATCHES,
    path: str | None = None,
) -> list[dict[str, object]]:
    """Search ``worktree`` for ``query`` with ``rg``; return ``{file,line,text}`` dicts."""
    max_matches = max(1, max_matches)
    root = Path(worktree).resolve()
    base = root if path is None else _safe_path(root, path)
    rel_target = _rel(base, root)

    argv = _build_rg_argv(query, rel_target, max_matches)

    try:
        proc = subprocess.run(
            argv,
            cwd=str(root),
            capture_output=True,
            text=True,
            shell=False,
            check=False,
            timeout=_RG_TIMEOUT_SECONDS,
        )
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError("rg timed out") from exc
    if proc.returncode not in (0, 1):
        raise RuntimeError(f"rg failed (exit {proc.returncode}): {proc.stderr.strip()}")

    return _collect_rg_results(proc.stdout, max_matches)


def _outline_class(node: ast.ClassDef) -> list[str]:
    lines = [f"  class {node.name} (line {node.lineno})"]
    for sub in node.body:
        if isinstance(sub, (ast.FunctionDef, ast.AsyncFunctionDef)):
            lines.append(f"    def {sub.name} (line {sub.lineno})")
    return lines


def _outline_body_node(node: ast.stmt) -> list[str]:
    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
        return [f"  def {node.name} (line {node.lineno})"]
    if isinstance(node, ast.ClassDef):
        return _outline_class(node)
    return []


def _py_outline(path: Path, rel: str) -> list[str]:
    try:
        tree = ast.parse(path.read_text(encoding="utf-8"))
    except (OSError, SyntaxError, ValueError):
        return [rel]
    lines = [rel]
    for node in tree.body:
        lines.extend(_outline_body_node(node))
    return lines


def _cap_tokens(text: str, max_tokens: int) -> str:
    max_chars = max_tokens * _CHARS_PER_TOKEN
    if len(text) <= max_chars:
        return text
    keep = max(max_chars - len(_TRUNCATION_MARKER), 0)
    return text[:keep] + _TRUNCATION_MARKER


def _map_file(fp: Path, root: Path) -> Iterator[str]:
    rel = _rel(fp, root)
    if fp.suffix == ".py":
        yield from _py_outline(fp, rel)
    else:
        yield rel


def _should_skip_file(fp: Path, root: Path) -> bool:
    if fp.is_symlink():
        return True
    try:
        return not fp.resolve().is_relative_to(root)
    except OSError:
        return True


def _iter_dir(target: Path, root: Path) -> Iterator[str]:
    for cur, dirs, files in os.walk(target):
        dirs[:] = sorted(d for d in dirs if d not in SKIP_DIRS)
        for name in sorted(files):
            fp = Path(cur) / name
            if _should_skip_file(fp, root):
                continue
            yield from _map_file(fp, root)


def _iter_map(target: Path, root: Path) -> Iterator[str]:
    """Yield map lines, skipping symlinks and anything resolving outside ``root``."""
    if target.is_file():
        yield from _map_file(target, root)
        return
    yield from _iter_dir(target, root)


def get_repo_map(
    worktree: Path,
    *,
    path: str | None = None,
    max_tokens: int = MAX_TOKENS,
) -> str:
    """Return a token-bounded map of ``worktree`` (or a sub-path)."""
    max_tokens = max(1, max_tokens)
    root = Path(worktree).resolve()
    target = root if path is None else _safe_path(root, path)

    budget = max_tokens * _CHARS_PER_TOKEN
    lines: list[str] = []
    total = 0
    for chunk in _iter_map(target, root):
        lines.append(chunk)
        total += len(chunk) + 1
        if total > budget:
            break

    return _cap_tokens("\n".join(lines), max_tokens)
