from __future__ import annotations

import fnmatch
import re

_DIFF_FILE_RE = re.compile(r"^\+\+\+ b/(.+)$")
_HUNK_CONTEXT_RE = re.compile(r"^@@ -\d+(?:,\d+)? \+\d+(?:,\d+)? @@\s*(.+)?$")
_PY_DEF_RE = re.compile(r"^[+-]\s*(?:async\s+def|def|class)\s+([A-Za-z_][A-Za-z0-9_]*)")

IGNORED_PATTERNS = (
    "package-lock.json",
    "yarn.lock",
    "pnpm-lock.yaml",
    "uv.lock",
    "poetry.lock",
    "Cargo.lock",
    "go.sum",
    "*.min.js",
    "*.min.css",
    "*.map",
    "*.svg",
    "*.png",
    "*.jpg",
    "*.woff2",
)


def is_ignored_file(path: str) -> bool:
    """Return True if path matches noisy lockfile or binary/minified patterns."""
    filename = path.rsplit("/", 1)[-1]
    return any(
        fnmatch.fnmatch(path, pat) or fnmatch.fnmatch(filename, pat)
        for pat in IGNORED_PATTERNS
    )


def _line_symbols(line: str) -> list[str]:
    """Collect hunk-context and py-def symbol names appearing on a single diff line."""
    symbols: list[str] = []
    m_hunk = _HUNK_CONTEXT_RE.match(line)
    if m_hunk and m_hunk.group(1):
        symbols.append(m_hunk.group(1).strip())
    m_def = _PY_DEF_RE.match(line)
    if m_def:
        symbols.append(m_def.group(1))
    return symbols


def _append_symbol(
    results: list[dict[str, str]],
    seen: set[tuple[str, str]],
    file_path: str,
    symbol: str,
) -> None:
    """Append a file/symbol entry once, preserving first-seen order."""
    key = (file_path, symbol)
    if key in seen:
        return
    seen.add(key)
    results.append({"file": file_path, "symbol": symbol})


def _scan_line(
    line: str,
    current_file: str,
    results: list[dict[str, str]],
    seen: set[tuple[str, str]],
) -> str:
    """Update current_file from a header line, else collect symbols for the line."""
    m_file = _DIFF_FILE_RE.match(line)
    if m_file:
        return m_file.group(1)
    if not current_file or is_ignored_file(current_file):
        return current_file
    for symbol in _line_symbols(line):
        _append_symbol(results, seen, current_file, symbol)
    return current_file


def extract_changed_symbols(
    raw_diff: str, max_symbols: int = 50
) -> list[dict[str, str]]:
    """Passively extract changed function/class symbol names from unified diff."""
    results: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()
    current_file = ""
    for line in (raw_diff or "").splitlines():
        current_file = _scan_line(line, current_file, results, seen)
        if len(results) >= max_symbols:
            break
    return results


def _build_header(symbols: list[dict[str, str]]) -> str:
    """Render the '## Changed Symbols' header block, or empty when no symbols."""
    if not symbols:
        return ""
    sym_lines = "\n".join(f"- {s['file']}: {s['symbol']}" for s in symbols)
    return f"## Changed Symbols\n{sym_lines}\n\n"


def _chunk_file_path(chunk: str) -> str:
    """Derive the file path from a 'diff --git' chunk's first line."""
    first_line = chunk.splitlines()[0]
    parts = first_line.split(" b/")
    return parts[-1].strip() if len(parts) > 1 else first_line


def _render_chunk(chunk: str, file_path: str, max_lines_per_file: int) -> str:
    """Re-emit a chunk with a 'diff --git' prefix, truncating over-long files."""
    lines = chunk.splitlines()
    if len(lines) > max_lines_per_file:
        lines = lines[:max_lines_per_file] + [
            f"... [truncated {len(lines) - max_lines_per_file} lines in {file_path}]"
        ]
    return "diff --git " + "\n".join(lines)


def _collect_chunk(
    chunk: str,
    max_lines_per_file: int,
    kept: list[str],
    skipped_files: list[str],
) -> None:
    """Route a chunk to kept output or the skipped-files list, dropping blanks."""
    if not chunk.strip():
        return
    file_path = _chunk_file_path(chunk)
    if is_ignored_file(file_path):
        skipped_files.append(file_path)
        return
    kept.append(_render_chunk(chunk, file_path, max_lines_per_file))


def _truncate_result(result: str, max_total_chars: int) -> str:
    """Cap the assembled diff to max_total_chars, appending a truncation marker."""
    if len(result) > max_total_chars:
        return (
            result[:max_total_chars]
            + f"\n\n... [diff truncated at {max_total_chars} chars]"
        )
    return result


def filter_and_truncate_diff(
    raw_diff: str,
    max_lines_per_file: int = 250,
    max_total_chars: int = 28_000,
) -> str:
    """Strip lockfiles/binary noise and cap diff size to prevent context dilution."""
    header = _build_header(extract_changed_symbols(raw_diff))
    kept: list[str] = []
    skipped_files: list[str] = []
    for chunk in raw_diff.split("diff --git "):
        _collect_chunk(chunk, max_lines_per_file, kept, skipped_files)
    body = "\n\n".join(kept)
    if skipped_files:
        body += f"\n\n[Skipped noisy/lock files: {', '.join(skipped_files)}]"
    result = header + body
    return _truncate_result(result, max_total_chars)
