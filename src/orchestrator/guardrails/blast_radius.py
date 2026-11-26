"""Blast-radius guard: cap files/LoC and block protected paths before opening a PR."""

from __future__ import annotations

import posixpath
from dataclasses import dataclass
from fnmatch import fnmatch
from pathlib import PurePosixPath

from unidiff import PatchSet
from unidiff.errors import UnidiffParseError

from agent.security import PROTECTED_PATH_PATTERNS

MAX_FILES: int = 10
MAX_LOC: int = 400

BLOCKED_GLOBS: tuple[str, ...] = PROTECTED_PATH_PATTERNS

LOCKFILE_NAMES: frozenset[str] = frozenset(
    {
        "uv.lock",
        "package-lock.json",
        "yarn.lock",
        "pnpm-lock.yaml",
        "poetry.lock",
        "Cargo.lock",
        "go.sum",
        "composer.lock",
        "Gemfile.lock",
    }
)


@dataclass(frozen=True)
class BlastRadiusReport:
    files: tuple[str, ...]
    total_loc: int
    blocked: tuple[str, ...]
    within_limits: bool
    reasons: tuple[str, ...]


def _normalize(path: str) -> str:
    """Collapse ``./``, ``..``, backslashes, and case before matching."""
    return posixpath.normpath(path.replace("\\", "/")).lstrip("/").lower()


def is_blocked(path: str) -> bool:
    """Return True if path matches any blocked glob (protected CI/persona paths included)."""
    norm = _normalize(path)
    if norm == ".." or norm.startswith("../"):
        return True
    return any(fnmatch(norm, glob.lower()) for glob in BLOCKED_GLOBS)


def is_lockfile(path: str) -> bool:
    """Return True if the path's basename is a known lockfile."""
    return PurePosixPath(path).name in LOCKFILE_NAMES


def _strip_prefix(path: str) -> str:
    if path.startswith(("a/", "b/")):
        return path[2:]
    return path


def _clean_side(raw: str) -> str:
    """Strip quotes and diff prefix from one patch side, dropping empty/``/dev/null`` sides."""
    cleaned = raw.strip('"')
    if not cleaned or cleaned == "/dev/null":
        return ""
    return _strip_prefix(cleaned)


def _patched_paths(pf: object) -> tuple[str, ...]:
    """Return both sides of a patch (source ``a/`` and target ``b/``), skipping ``/dev/null``.

    Checking both sides closes the rename/delete bypass: a protected file moved
    or removed still surfaces via ``source_file`` even when ``path`` is benign.
    """
    source = getattr(pf, "source_file", "") or ""
    target = getattr(pf, "path", "") or ""
    return tuple(filter(None, (_clean_side(source), _clean_side(target))))


def _target_path(pf: object) -> str:
    """Return the post-image path of a patch file, or ``""`` for a deletion."""
    target = getattr(pf, "path", "") or ""
    return "" if target == "/dev/null" else _strip_prefix(target)


def _blocked_paths(patch: PatchSet) -> tuple[str, ...]:
    """Collect every blocked path across both sides of all patched files."""
    all_paths = [p for pf in patch for p in _patched_paths(pf)]
    return tuple(dict.fromkeys(p for p in all_paths if is_blocked(p)))


def _count_files_loc(patch: PatchSet) -> tuple[tuple[str, ...], int]:
    """Return the non-lockfile patched paths and the total added+removed LoC."""
    files_list: list[str] = []
    total_loc = 0
    for pf in patch:
        path = _target_path(pf)
        if path and is_lockfile(path):
            continue
        if path:
            files_list.append(path)
        total_loc += pf.added + pf.removed
    return tuple(files_list), total_loc


def _build_reasons(
    blocked: tuple[str, ...], files: tuple[str, ...], total_loc: int
) -> tuple[str, ...]:
    """Assemble human-readable limit/block reasons for a report."""
    reasons: list[str] = []
    if blocked:
        reasons.append(f"blocked paths: {', '.join(blocked)}")
    if len(files) > MAX_FILES:
        reasons.append(f"file count {len(files)} exceeds limit {MAX_FILES}")
    if total_loc > MAX_LOC:
        reasons.append(f"LoC {total_loc} exceeds limit {MAX_LOC}")
    return tuple(reasons)


def _unparseable_report() -> BlastRadiusReport:
    """Fail-closed report for a diff that cannot be parsed."""
    return BlastRadiusReport(
        files=(),
        total_loc=0,
        blocked=(),
        within_limits=False,
        reasons=("unparseable diff",),
    )


def evaluate_blast_radius(diff_text: str) -> BlastRadiusReport:
    """Evaluate a unified diff against file/LoC caps and protected-path blocks.

    Blocked paths are computed over ALL patched files first (protected/blocked
    checks precede lockfile exclusion). Lockfiles are then excluded from the
    file count and LoC total. An unparseable diff fails closed.
    """
    try:
        patch = PatchSet(diff_text)
    except UnidiffParseError:
        return _unparseable_report()

    blocked = _blocked_paths(patch)
    files, total_loc = _count_files_loc(patch)
    within_limits = not blocked and len(files) <= MAX_FILES and total_loc <= MAX_LOC

    return BlastRadiusReport(
        files=files,
        total_loc=total_loc,
        blocked=blocked,
        within_limits=within_limits,
        reasons=_build_reasons(blocked, files, total_loc),
    )
