"""Repo-level verification manifest runner (``.vps-checks.toml``).

The manifest is loaded STRICTLY from ``main`` (never the untrusted PR head) so a
pull request cannot inject arbitrary check commands. Each command runs with
``shell=False``, a minimal secret-free and offline environment, and process-group
isolation (``start_new_session=True`` + ``os.killpg`` on timeout). A missing,
empty, or invalid manifest fails closed. Results are written to
``verification_verdicts`` without clobbering an existing security verdict.
"""

from __future__ import annotations

import os
import signal
import subprocess
import tempfile
import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

from agent.security import build_safe_git_env, build_safe_linter_env

if TYPE_CHECKING:
    from src.orchestrator.middleware.audit import AuditLogger

MANIFEST_FILENAME = ".vps-checks.toml"
DEFAULT_TIMEOUT_SECONDS = 120
MAX_TIMEOUT_SECONDS = 900
_GIT_SHOW_TIMEOUT_SECONDS = 30
_KILL_GRACE_SECONDS = 5
MAX_OUTPUT_BYTES = 64 * 1024


class ManifestError(ValueError):
    """Raised when ``.vps-checks.toml`` is missing, empty, or invalid."""


@dataclass(frozen=True)
class CheckCommand:
    """A single verification command from the manifest."""

    name: str
    argv: tuple[str, ...]
    timeout_seconds: int


@dataclass(frozen=True)
class ChecksManifest:
    """Parsed ``.vps-checks.toml``."""

    commands: tuple[CheckCommand, ...]

    def __bool__(self) -> bool:
        return bool(self.commands)


@dataclass(frozen=True)
class CheckResult:
    """Outcome of one check command."""

    name: str
    returncode: int
    stdout: str
    stderr: str
    timed_out: bool = False

    @property
    def passed(self) -> bool:
        return self.returncode == 0 and not self.timed_out


def _require_nonempty_str(value: object, message: str) -> str:
    """Return ``value`` stripped, or raise ``ManifestError`` if it is not a
    non-empty string."""
    if not isinstance(value, str) or not value.strip():
        raise ManifestError(message)
    return value.strip()


def _is_valid_argv(argv: object) -> bool:
    """True when ``argv`` is a non-empty list of non-empty strings."""
    return (
        isinstance(argv, list)
        and bool(argv)
        and all(isinstance(part, str) and part for part in argv)
    )


def _parse_argv(index: int, entry: dict) -> tuple[str, ...]:
    """Extract and validate ``checks[index].argv`` as a tuple of strings."""
    argv = entry.get("argv")
    if not _is_valid_argv(argv) or not isinstance(argv, list):
        raise ManifestError(
            f"checks[{index}].argv must be a non-empty array of non-empty strings"
        )
    return tuple(argv)


def _parse_timeout(index: int, entry: dict) -> int:
    """Extract and validate ``checks[index].timeout_seconds`` (clamped)."""
    timeout = entry.get("timeout_seconds", DEFAULT_TIMEOUT_SECONDS)
    if isinstance(timeout, bool) or not isinstance(timeout, int) or timeout <= 0:
        raise ManifestError(
            f"checks[{index}].timeout_seconds must be a positive integer"
        )
    return min(timeout, MAX_TIMEOUT_SECONDS)


def _parse_check_entry(index: int, entry: object) -> CheckCommand:
    """Validate one ``[[checks]]`` table into a :class:`CheckCommand`."""
    if not isinstance(entry, dict):
        raise ManifestError(f"checks[{index}] must be a table")
    name = _require_nonempty_str(
        entry.get("name"), f"checks[{index}].name must be a non-empty string"
    )
    return CheckCommand(
        name=name,
        argv=_parse_argv(index, entry),
        timeout_seconds=_parse_timeout(index, entry),
    )


def _extract_raw_checks(data: dict[str, object]) -> list[object]:
    """Return the raw ``checks`` array, failing closed when absent/empty."""
    raw_checks = data.get("checks")
    if raw_checks is None:
        raise ManifestError("manifest has no [[checks]] entries")
    if not isinstance(raw_checks, list):
        raise ManifestError("'checks' must be an array of tables")
    if not raw_checks:
        raise ManifestError("manifest 'checks' array is empty (fail closed)")
    return raw_checks


def parse_manifest(text: str) -> ChecksManifest:
    """Parse and validate manifest text; raise ManifestError on any problem."""
    try:
        data = tomllib.loads(text)
    except tomllib.TOMLDecodeError as exc:
        raise ManifestError(f"invalid TOML: {exc}") from exc

    raw_checks = _extract_raw_checks(data)
    commands = tuple(
        _parse_check_entry(index, entry) for index, entry in enumerate(raw_checks)
    )
    return ChecksManifest(commands=commands)


def _validate_ref(ref: str) -> None:
    """Reject refs that are empty or could be parsed as a git option."""
    if not isinstance(ref, str) or not ref or ref.startswith("-"):
        raise ManifestError(f"invalid git ref: {ref!r}")


def load_manifest_from_main(repo_root: Path, ref: str = "main") -> ChecksManifest:
    """Load ``.vps-checks.toml`` from ``ref`` (main) via ``git show``.

    Reading from ``ref`` guarantees the manifest is the trusted, merged version
    and never the untrusted PR head's working tree. ``ref`` is validated to
    reject option injection (leading ``-``).
    """
    _validate_ref(ref)
    try:
        proc = subprocess.run(
            ["git", "-C", str(repo_root), "show", f"{ref}:{MANIFEST_FILENAME}"],
            capture_output=True,
            text=True,
            check=False,
            env=build_safe_git_env(),
            timeout=_GIT_SHOW_TIMEOUT_SECONDS,
        )
    except subprocess.TimeoutExpired as exc:
        raise ManifestError(f"git show timed out for ref {ref!r}") from exc
    if proc.returncode != 0:
        raise ManifestError(
            f"{MANIFEST_FILENAME} not found on {ref} "
            f"(git show exited {proc.returncode})"
        )
    return parse_manifest(proc.stdout)


def _kill_process_group(proc: subprocess.Popen[bytes]) -> None:
    """SIGKILL the whole process group so grandchildren cannot outlive the check."""
    try:
        os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
    except (ProcessLookupError, PermissionError):
        try:
            proc.kill()
        except ProcessLookupError:
            pass


def _build_check_env() -> dict[str, str]:
    """Minimal, secret-free, offline env: no host secrets, no uv network/sync."""
    return {
        **build_safe_linter_env(),
        "TY_UV": "1",
        "UV_OFFLINE": "1",
        "UV_NO_SYNC": "1",
        "UV_FROZEN": "1",
    }


def _wait_with_timeout(proc: subprocess.Popen[bytes], timeout: int) -> bool:
    """Wait up to ``timeout`` seconds; on expiry kill the group. Returns timed_out."""
    try:
        proc.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        _kill_process_group(proc)
        try:
            proc.wait(timeout=_KILL_GRACE_SECONDS)
        except subprocess.TimeoutExpired:
            pass
        return True
    return False


def _resolve_returncode(proc: subprocess.Popen[bytes], timed_out: bool) -> int:
    """Map a still-running process to 124 (timeout) or 1, else its returncode."""
    if proc.returncode is None:
        return 124 if timed_out else 1
    return proc.returncode


def run_check(command: CheckCommand, cwd: Path) -> CheckResult:
    """Run one check with a minimal offline env and process-group isolation.

    stdout/stderr are captured to temp files and read back capped at
    ``MAX_OUTPUT_BYTES`` so a runaway check cannot OOM the worker.
    """
    env = _build_check_env()
    with tempfile.TemporaryFile() as out_f, tempfile.TemporaryFile() as err_f:
        try:
            proc: subprocess.Popen[bytes] = subprocess.Popen(
                list(command.argv),
                cwd=str(cwd),
                env=env,
                shell=False,
                start_new_session=True,
                stdout=out_f,
                stderr=err_f,
            )
        except OSError as exc:
            return CheckResult(
                name=command.name, returncode=127, stdout="", stderr=str(exc)
            )
        timed_out = _wait_with_timeout(proc, command.timeout_seconds)
        out_f.seek(0)
        err_f.seek(0)
        stdout = out_f.read(MAX_OUTPUT_BYTES).decode("utf-8", errors="replace")
        stderr = err_f.read(MAX_OUTPUT_BYTES).decode("utf-8", errors="replace")

    return CheckResult(
        name=command.name,
        returncode=_resolve_returncode(proc, timed_out),
        stdout=stdout,
        stderr=stderr,
        timed_out=timed_out,
    )


def run_manifest(manifest: ChecksManifest, cwd: Path) -> list[CheckResult]:
    """Run every command in the manifest, in order."""
    return [run_check(command, cwd) for command in manifest.commands]


def run_checks_from_main(
    repo_root: Path,
    worktree: Path,
    *,
    repo: str,
    branch: str,
    head_commit_sha: str,
    audit: AuditLogger,
    ref: str = "main",
) -> tuple[bool, list[CheckResult], str | None]:
    """Load from main, run in ``worktree``, record a non-clobbering verdict.

    Fails closed: a missing/empty/invalid manifest records ``checks_passed=False``
    and returns the error. Returns ``(passed, results, error)``.
    """
    try:
        manifest = load_manifest_from_main(repo_root, ref)
    except ManifestError as exc:
        audit.record_checks_verdict(repo, branch, head_commit_sha, False)
        return False, [], str(exc)

    results = run_manifest(manifest, worktree)
    passed = bool(results) and all(result.passed for result in results)
    audit.record_checks_verdict(repo, branch, head_commit_sha, passed)
    return passed, results, None
