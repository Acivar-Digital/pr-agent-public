"""ty typechecker wrapper for guard."""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

from pydantic import BaseModel, ConfigDict


class TyResult(BaseModel):
    """Result of running `ty check` on a target path."""

    model_config = ConfigDict(extra="forbid")

    file_path: str
    success: bool
    return_code: int
    message: str


def _ty_cmd(target: Path, project_root: Path) -> list[str]:
    args = ["check", "--output-format", "concise", "--color", "never", "--no-progress", str(target)]
    venv_ty = project_root / ".venv" / "bin" / "ty"
    if venv_ty.is_file():
        return [str(venv_ty), *args]
    if shutil.which("ty") is not None:
        return ["ty", *args]
    if shutil.which("uv") is not None:
        return ["uv", "run", "-q", "ty", *args]
    return ["ty", *args]


def _execute_ty(target: Path, root: Path, timeout: int) -> TyResult:
    cmd = _ty_cmd(target, root)
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
        return TyResult(file_path=str(target), success=False, return_code=1, message=f"ty execution error: {exc}")

    ok = proc.returncode == 0
    combined = "\n".join(part for part in (proc.stdout, proc.stderr) if part).strip()
    msg = "ty typecheck passed (0 errors)." if ok else f"ty check failed:\n{combined or 'non-zero exit code'}"
    return TyResult(file_path=str(target), success=ok, return_code=proc.returncode, message=msg)


def run_ty(path: Path | str, *, project_root: Path | None = None, timeout: int = 60) -> TyResult:
    """Run `ty check` on a file or directory."""
    target = Path(path)
    if not target.exists():
        return TyResult(file_path=str(target), success=False, return_code=1, message=f"File not found: {target}")
    return _execute_ty(target, project_root or Path.cwd(), timeout)
