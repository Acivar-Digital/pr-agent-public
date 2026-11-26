"""Central guardrail pipeline orchestrator and CLI for future Python changes."""

from __future__ import annotations

import argparse
import subprocess
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Final

from pydantic import BaseModel, ConfigDict, Field

from guard.rules.async_blocking import scan_async_blocking
from guard.rules.bad_style import scan_bad_style
from guard.rules.banned_fallbacks import scan_banned_fallbacks
from guard.rules.base import DiagnosticFinding
from guard.rules.cc_nested import scan_cc_nested
from guard.rules.no_type_ignore import scan_no_type_ignore
from guard.rules.strict_schema import scan_strict_schema
from guard.rules.truncation import scan_truncation
from guard.wrappers.ruff import run_ruff_check
from guard.wrappers.ty import run_ty

IGNORED_DIR_PARTS: Final[frozenset[str]] = frozenset(
    {"__pycache__", ".venv", ".git", ".checkpoints", "node_modules", ".tox", ".pytest_cache"}
)

RuleScanner = Callable[[str, str], list[DiagnosticFinding]]

AST_RULES: Final[tuple[RuleScanner, ...]] = (
    scan_truncation,
    scan_no_type_ignore,
    scan_bad_style,
    scan_async_blocking,
    scan_banned_fallbacks,
    scan_cc_nested,
    scan_strict_schema,
)


class GuardResult(BaseModel):
    """Validation outcome for a single Python file."""

    model_config = ConfigDict(extra="forbid")

    file_path: str
    success: bool
    findings: list[DiagnosticFinding] = Field(default_factory=list)
    external_errors: list[str] = Field(default_factory=list)


class GuardReport(BaseModel):
    """Aggregated validation report across one or more Python files."""

    model_config = ConfigDict(extra="forbid")

    checked_files: int
    passed_files: int
    failed_files: int
    results: list[GuardResult] = Field(default_factory=list)

    @property
    def success(self) -> bool:
        """Return True if all checked files passed."""
        return self.failed_files == 0


def _is_valid_py_file(path: Path) -> bool:
    return path.suffix == ".py" and not any(part in IGNORED_DIR_PARTS for part in path.parts)


def _expand_path(path: Path) -> list[Path]:
    if path.is_dir():
        return [p for p in sorted(path.rglob("*.py")) if _is_valid_py_file(p)]
    if path.is_file() and _is_valid_py_file(path):
        return [path]
    return []


def _collect_python_files(paths: list[Path]) -> list[Path]:
    collected: list[Path] = []
    seen: set[Path] = set()
    for path in paths:
        for py_file in _expand_path(path):
            if py_file not in seen:
                seen.add(py_file)
                collected.append(py_file)
    return collected


def _run_external_checks(target: Path, project_root: Path | None) -> list[str]:
    errors: list[str] = []
    ruff_res = run_ruff_check(target, project_root=project_root)
    if not ruff_res.success:
        errors.append(ruff_res.message)
    ty_res = run_ty(target, project_root=project_root)
    if not ty_res.success:
        errors.append(ty_res.message)
    return errors


def _read_utf8_source(target: Path) -> tuple[str | None, str]:
    if not target.is_file():
        return None, f"File not found: {target}"
    source: str | None = None
    error = "Unreadable file"
    try:
        source = target.read_text(encoding="utf-8")
    except UnicodeDecodeError as exc:
        error = f"Invalid UTF-8 encoding: {exc}"
    return source, error


def validate_file(
    file_path: Path | str,
    *,
    run_external: bool = True,
    project_root: Path | None = None,
) -> GuardResult:
    """Run all AST/token anti-slop rules and optional ruff/ty checks on one file."""
    target = Path(file_path)
    source, read_error = _read_utf8_source(target)
    if source is None:
        return GuardResult(
            file_path=str(target),
            success=False,
            external_errors=[read_error],
        )
    findings: list[DiagnosticFinding] = []
    for scanner in AST_RULES:
        findings.extend(scanner(source, str(target)))

    external_errors = _run_external_checks(target, project_root) if run_external else []
    ok = not findings and not external_errors
    return GuardResult(
        file_path=str(target),
        success=ok,
        findings=findings,
        external_errors=external_errors,
    )


def validate_paths(
    paths: list[Path | str],
    *,
    run_external: bool = True,
    project_root: Path | None = None,
) -> GuardReport:
    """Validate all Python files under the given paths."""
    files = _collect_python_files([Path(p) for p in paths])
    results = [validate_file(f, run_external=run_external, project_root=project_root) for f in files]
    passed = sum(1 for r in results if r.success)
    return GuardReport(
        checked_files=len(results),
        passed_files=passed,
        failed_files=len(results) - passed,
        results=results,
    )


def _git_lines(args: list[str], cwd: Path) -> list[str]:
    proc = subprocess.run(
        ["git", *args],
        capture_output=True,
        cwd=str(cwd),
        text=True,
        encoding="utf-8",
        check=False,
    )
    if proc.returncode != 0:
        return []
    return [line.strip() for line in proc.stdout.splitlines() if line.strip()]


def get_changed_python_files(
    *,
    staged: bool = False,
    base_ref: str | None = None,
    project_root: Path | None = None,
) -> list[Path]:
    """Discover changed Python files for pre-commit (--staged), PR (--base), or working tree."""
    root = project_root or Path.cwd()
    if staged:
        raw = _git_lines(["diff", "--cached", "--name-only", "--diff-filter=ACMR"], root)
    elif base_ref:
        raw = _git_lines(["diff", "--name-only", "--diff-filter=ACMR", f"{base_ref}...HEAD"], root)
    else:
        tracked = _git_lines(["diff", "--name-only", "--diff-filter=ACMR", "HEAD"], root)
        untracked = _git_lines(["ls-files", "--others", "--exclude-standard"], root)
        raw = [*tracked, *untracked]

    return _collect_python_files([root / rel for rel in raw])


def _print_result_errors(res: GuardResult) -> None:
    for finding in res.findings:
        print(finding.format_diagnostic(), file=sys.stderr)
    for err in res.external_errors:
        print(err, file=sys.stderr)


def _print_report(report: GuardReport) -> None:
    for res in report.results:
        if not res.success:
            _print_result_errors(res)
    status = "PASS" if report.success else "FAIL"
    print(f"guard: {status} ({report.passed_files}/{report.checked_files} files passed)")


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="AST quality gatekeeper for Python changes")
    parser.add_argument("paths", nargs="*", help="Files or directories to check")
    parser.add_argument("--staged", action="store_true", help="Check staged Python files")
    parser.add_argument("--changed", action="store_true", help="Check modified/untracked Python files")
    parser.add_argument("--base", dest="base_ref", default=None, help="Check Python files changed vs git base ref")
    parser.add_argument("--no-external", action="store_true", help="Skip ruff and ty subprocess checks")
    return parser


def _resolve_targets(args: argparse.Namespace) -> list[Path | str]:
    if args.staged:
        return list(get_changed_python_files(staged=True))
    if args.base_ref:
        return list(get_changed_python_files(base_ref=args.base_ref))
    if args.changed:
        return list(get_changed_python_files())
    return list(args.paths)


def main(argv: list[str] | None = None) -> int:
    """CLI entrypoint for `uv run python -m guard`."""
    parser = _build_parser()
    args = parser.parse_args(argv if argv is not None else sys.argv[1:])
    targets = _resolve_targets(args)
    if not targets:
        print("guard: PASS (0 Python files to check)")
        return 0
    report = validate_paths(targets, run_external=not args.no_external)
    _print_report(report)
    return 0 if report.success else 1


if __name__ == "__main__":
    raise SystemExit(main())
