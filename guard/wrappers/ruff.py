"""Ruff linter wrapper for guard."""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

from pydantic import BaseModel, ConfigDict


class RuffLintResult(BaseModel):
    """Result of running `ruff check` on a target path."""

    model_config = ConfigDict(extra="forbid")

    file_path: str
    success: bool
    return_code: int
    stdout: str
    stderr: str
    message: str


def _ruff_base_cmd(project_root: Path) -> list[str]:
    venv_ruff = project_root / ".venv" / "bin" / "ruff"
    if venv_ruff.is_file():
        return [str(venv_ruff)]
    if shutil.which("uv") is not None:
        return ["uv", "run", "-q", "ruff"]
    return ["ruff"]


def _execute_ruff(target: Path, root: Path, timeout: int) -> RuffLintResult:
    cmd = [*_ruff_base_cmd(root), "check", str(target)]
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            cwd=str(root),
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
            check=False,
        )
    except (subprocess.SubprocessError, OSError) as exc:
        return RuffLintResult(
            file_path=str(target),
            success=False,
            return_code=1,
            stdout="",
            stderr=str(exc),
            message=f"Ruff execution error: {exc}",
        )
    ok = proc.returncode == 0
    msg = "Ruff check passed cleanly." if ok else f"Ruff check failed:\n{proc.stdout or proc.stderr}"
    return RuffLintResult(
        file_path=str(target),
        success=ok,
        return_code=proc.returncode,
        stdout=proc.stdout,
        stderr=proc.stderr,
        message=msg,
    )


def run_ruff_check(path: Path | str, *, project_root: Path | None = None, timeout: int = 30) -> RuffLintResult:
    """Run `ruff check` on a file or directory."""
    target = Path(path)
    if not target.exists():
        return RuffLintResult(
            file_path=str(target),
            success=False,
            return_code=1,
            stdout="",
            stderr=f"File not found: {target}",
            message=f"File not found: {target}",
        )
    return _execute_ruff(target, project_root or Path.cwd(), timeout)
