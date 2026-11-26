from __future__ import annotations

import asyncio
import contextlib
import json
import logging
import os
import re
import signal
import time
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal, cast

from pydantic import BaseModel, ConfigDict, Field

from agent.audit_shared import get_audit_logger
from agent.personas import AgentPersona, load_persona
from agent.security import JOB_TIMEOUT_SECONDS, build_safe_agy_env, wrap_untrusted
from agent.static_checks import run_safe_static_checks
from agent.verdict import APPROVED, _security_verdict
from agent.workspace import (
    _run_git,
    cleanup_worktree,
    commit_and_push,
    open_pr,
    post_pr_comment,
    prepare_worktree,
)
from src.orchestrator.guardrails.blast_radius import evaluate_blast_radius
from src.orchestrator.guardrails.checks_manifest import run_checks_from_main
from src.orchestrator.tools.gated_pr import (
    handle_security_review_completion,
    open_draft_pr,
)

logger = logging.getLogger(__name__)


class _WorkerJSONOutput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    status: str = Field(description="completed | needs_human_review | failed")
    summary: str = Field(
        description="Concise 3-5 bullet summary of findings or changes"
    )
    warnings: list[str] = Field(default_factory=list)


class PRTaskReport(BaseModel):
    model_config = ConfigDict(extra="forbid")

    repo: str
    persona: str
    branch: str
    pr_number: int | None = None
    status: str = Field(description="completed | needs_human_review | failed")
    summary: str = Field(
        description="Concise 3-5 bullet summary of findings or changes"
    )
    failure_point: str | None = Field(
        default=None,
        description="Pinpointed phase and failure cause if status is failed",
    )
    files_touched: list[str] = Field(default_factory=list)
    commit_shas: list[str] = Field(default_factory=list)
    pr_url: str | None = None
    head_commit_sha: str | None = None
    conversation_id: str | None = None
    log_file: str | None = None
    warnings: list[str] = Field(default_factory=list)
    static_findings: list[dict[str, Any]] = Field(default_factory=list)
    duration_ms: int = 0
    phase_timings_ms: dict[str, int] = Field(default_factory=dict)
    model: str | None = None
    finish_reason: str | None = None
    usage: dict[str, Any] = Field(default_factory=dict)
    num_turns: int = 0
    failure_class: Literal["harness", "model", "provider", "none"] = "none"
    timed_out: bool = False
    model_record: str | None = None
    scrubbed: bool = False


@dataclass
class _RunOutcome:
    """Captured result of a single runner subprocess execution."""

    returncode: int | None
    raw_out: str
    raw_err: str
    agy_ms: int
    timed_out: bool
    log_path: str
    model_record: str | None


def _get_logs_dir() -> Path:
    db_path = os.getenv("JOB_DB_PATH", "").strip()
    if db_path:
        return Path(db_path).parent / "logs"
    return Path(__file__).resolve().parent.parent / "data" / "logs"


def _persist_job_log(
    job_id: str, returncode: int | None, raw_out: str, raw_err: str
) -> str:
    """Persist scrubbed agy stdout/stderr to data/logs/<job_id>.log for post-mortem audit."""
    from src.orchestrator.middleware.redactor import SecretRedactor

    redactor = SecretRedactor()
    red_out, _ = redactor.redact_text(raw_out)
    red_err, _ = redactor.redact_text(raw_err)
    logs_dir = _get_logs_dir()
    logs_dir.mkdir(parents=True, exist_ok=True)
    log_path = logs_dir / f"{job_id}.log"
    content = (
        f"=== job_id: {job_id} | returncode: {returncode} ===\n"
        f"--- STDOUT ---\n{red_out}\n"
        f"--- STDERR ---\n{red_err}\n"
    )
    log_path.write_text(content, encoding="utf-8")
    os.chmod(log_path, 0o600)
    return str(log_path)


def _mark_alive(job_id: str) -> None:
    """Record a liveness heartbeat for job_id from the first instant of execution."""
    _JOB_HEARTBEAT[job_id] = time.time()


def _kill_process_group(proc: asyncio.subprocess.Process) -> None:
    """Kill the subprocess AND any children it spawned (whole process group)."""
    try:
        os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
    except (ProcessLookupError, PermissionError):
        with contextlib.suppress(ProcessLookupError):
            proc.kill()


_JOB_ID_RE = re.compile(r"^[A-Za-z0-9_-]{1,64}$")
_MODEL_RECORD_MAX_BYTES = 200_000
_PROVIDER_ERR_RE = re.compile(
    r"rate.?limit|429|50\d|quota|unauthorized|forbidden|auth", re.IGNORECASE
)

# Liveness map: job_id -> wall-clock timestamp of the last heartbeat tick.
# Defined here (not in job_store) because job_store imports pr_worker; defining
# it there would be a circular import.
_JOB_HEARTBEAT: dict[str, float] = {}
# Tracks jobs whose subprocess is currently live (owned by the hard wait_for
# timeout, not the 90s stale reaper). Set/cleared around the subprocess block.
_JOB_SUBPROC_ACTIVE: dict[str, bool] = {}


def _looks_like_provider_error(text: str) -> bool:
    """Best-effort: does this stderr/stdout look like a provider (429/5xx/auth) fault?"""
    return bool(_PROVIDER_ERR_RE.search(text or ""))


def _persist_model_record(
    job_id: str,
    model_meta: dict[str, Any],
    raw_out: str,
    scrub: bool = True,
) -> str:
    """Persist the model I/O envelope to data/logs/<job_id>.model.json (mode 0600)."""
    if not _JOB_ID_RE.match(job_id):
        raise ValueError(f"unsafe job_id for model record: {job_id!r}")
    logs_dir = _get_logs_dir()
    logs_dir.mkdir(parents=True, exist_ok=True)
    path = logs_dir / f"{job_id}.model.json"
    raw = raw_out[:_MODEL_RECORD_MAX_BYTES]
    if scrub:
        from src.orchestrator.middleware.redactor import SecretRedactor

        raw, _ = SecretRedactor().redact_text(raw)
    payload = {**model_meta, "job_id": job_id, "raw_stdout": raw}
    path.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")
    os.chmod(path, 0o600)
    return str(path)


BASE_GUARDRAILS = """
Global Safety & Engineering Rules:
1. Never push directly to `main` or `master`. Work only inside the current isolated worktree.
2. Inspect only files relevant to the order. Ignore lockfiles and generated artifacts.
3. Read target files before editing so you preserve style, types, and formatting.
4. Keep changes minimal, atomic, and verified by tests where available.
5. Return a concise, factual summary matching the requested JSON schema.
"""


def _agy_meta_from_envelope(
    parsed: dict[str, Any], model: str | None
) -> tuple[str | None, dict[str, Any]]:
    meta: dict[str, Any] = {
        "model": model,
        "finish_reason": None,
        "usage": {},
        "num_turns": 0,
        "duration_seconds": 0.0,
    }
    conversation_id = parsed.get("conversation_id") or parsed.get("session_id")
    u = parsed.get("usage")
    meta["usage"] = u if isinstance(u, dict) else {}
    try:
        meta["num_turns"] = int(parsed.get("num_turns", 0))
    except (TypeError, ValueError):
        meta["num_turns"] = 0
    try:
        meta["duration_seconds"] = float(parsed.get("duration_seconds", 0))
    except (TypeError, ValueError):
        meta["duration_seconds"] = 0.0
    return conversation_id, meta


def _select_agy_candidate(parsed: dict[str, Any]) -> Any:
    if "structured_output" in parsed and isinstance(parsed["structured_output"], dict):
        return parsed["structured_output"]
    if "result" in parsed:
        return parsed["result"]
    return parsed


def _finalize_agy_candidate(
    candidate: Any, conversation_id: str | None, meta: dict[str, Any]
) -> tuple[_WorkerJSONOutput, str | None, dict[str, Any]]:
    if isinstance(candidate, dict) and {"status", "summary"}.issubset(candidate.keys()):
        return _WorkerJSONOutput.model_validate(candidate), conversation_id, meta
    return (
        _WorkerJSONOutput(
            status="completed",
            summary=json.dumps(candidate, ensure_ascii=False)[:2000],
            warnings=[
                "Unexpected agy JSON envelope shape; raw payload captured in summary"
            ],
        ),
        conversation_id,
        meta,
    )


def _parse_agy_string_candidate(
    candidate_str: str, conversation_id: str | None, meta: dict[str, Any]
) -> tuple[_WorkerJSONOutput, str | None, dict[str, Any]]:
    try:
        candidate = json.loads(candidate_str)
    except json.JSONDecodeError:
        return (
            _WorkerJSONOutput(
                status="completed",
                summary=candidate_str[:2000],
                warnings=["agy output was plain text rather than structured JSON"],
            ),
            conversation_id,
            meta,
        )
    return _finalize_agy_candidate(candidate, conversation_id, meta)


def _parse_agy_output(
    raw_stdout: str, model: str | None = None
) -> tuple[_WorkerJSONOutput, str | None, dict[str, Any]]:
    """Parse `agy -p --output-format json` stdout into report + conversation_id + meta."""
    meta: dict[str, Any] = {
        "model": model,
        "finish_reason": None,
        "usage": {},
        "num_turns": 0,
        "duration_seconds": 0.0,
    }
    text = raw_stdout.strip()
    if not text:
        return (
            _WorkerJSONOutput(status="failed", summary="Empty output from agy CLI"),
            None,
            meta,
        )

    conversation_id: str | None = None
    candidate: Any = text
    try:
        parsed = json.loads(text)
    except json.JSONDecodeError:
        logger.debug("agy stdout was not valid JSON; parsing leniently")
        parsed = None
    if isinstance(parsed, dict):
        conversation_id, meta = _agy_meta_from_envelope(parsed, model)
        candidate = _select_agy_candidate(parsed)
    if isinstance(candidate, str):
        return _parse_agy_string_candidate(candidate, conversation_id, meta)
    return _finalize_agy_candidate(candidate, conversation_id, meta)


def _collect_omp_text(msg: dict[str, Any], text_chunks: list[str]) -> None:
    for c in msg.get("content", []):
        if isinstance(c, dict) and c.get("type") == "text":
            text_chunks.append(c.get("text", ""))


def _apply_omp_turn_end(
    evt: dict[str, Any], meta: dict[str, Any], text_chunks: list[str]
) -> None:
    meta["num_turns"] += 1
    msg = evt.get("message", {})
    u = evt.get("usage") or msg.get("usage")
    if isinstance(u, dict):
        meta["usage"] = u
    _collect_omp_text(msg, text_chunks)


def _apply_omp_event(
    evt: dict[str, Any], meta: dict[str, Any], text_chunks: list[str]
) -> str | None:
    if evt.get("type") == "session" and "id" in evt:
        return evt["id"]
    if evt.get("type") == "turn_end":
        _apply_omp_turn_end(evt, meta, text_chunks)
    return None


def _omp_summary(text_chunks: list[str], raw_stdout: str) -> str:
    return "\n".join(text_chunks).strip() or raw_stdout.strip()[:2000]


def _omp_result(
    text_chunks: list[str],
    raw_stdout: str,
    session_id: str | None,
    meta: dict[str, Any],
) -> tuple[_WorkerJSONOutput, str | None, dict[str, Any]]:
    summary = _omp_summary(text_chunks, raw_stdout)
    status = "completed" if summary else "failed"
    warnings = [] if summary else ["omp returned empty text response"]
    return (
        _WorkerJSONOutput(status=status, summary=summary, warnings=warnings),
        session_id,
        meta,
    )


def _parse_omp_output(
    raw_stdout: str, model: str | None = None
) -> tuple[_WorkerJSONOutput, str | None, dict[str, Any]]:
    """Parse NDJSON lines from `omp --mode json` into report + session_id + meta."""
    meta: dict[str, Any] = {
        "model": model,
        "finish_reason": None,
        "usage": {},
        "num_turns": 0,
        "duration_seconds": 0.0,
    }
    text_chunks: list[str] = []
    session_id: str | None = None
    for raw_line in raw_stdout.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        try:
            evt = json.loads(line)
        except json.JSONDecodeError:
            logger.debug("skipping malformed stream line")
            continue
        sid = _apply_omp_event(evt, meta, text_chunks)
        if sid is not None:
            session_id = sid

    return _omp_result(text_chunks, raw_stdout, session_id, meta)


async def _run_inline_security_review(
    *,
    job_id: str,
    repo: str,
    base_branch: str,
    target_branch: str,
    head_sha: str,
    verdict_branch: str,
) -> PRTaskReport:
    """Read-only reviewer pass over the just-pushed commit.

    Runs on a dedicated review branch cut from the agent branch, so the reviewer
    sees exactly the committed diff. The outer job's heartbeat is refreshed while
    this runs so the stale-job reaper cannot reap a job mid-review.
    """
    timeout = int(os.getenv("INLINE_REVIEW_TIMEOUT_SECONDS", "600"))
    persona = await load_persona(
        repo=repo, persona_name="security-reviewer", ref=base_branch
    )
    review_job_id = f"{job_id}-review"
    stop = asyncio.Event()

    async def _keepalive() -> None:
        while not stop.is_set():
            _mark_alive(job_id)
            with contextlib.suppress(TimeoutError):
                await asyncio.wait_for(stop.wait(), timeout=5)

    keeper = asyncio.create_task(_keepalive())
    try:
        return await asyncio.wait_for(
            execute_pr_task(
                job_id=review_job_id,
                repo=repo,
                task=(
                    f"Read-only security review of `git diff origin/{base_branch}..HEAD` "
                    f"on branch `{target_branch}` (commit {head_sha}). Do not modify files. "
                    "Report critical vulnerabilities and secret leakage, and end with an "
                    "explicit APPROVED or NO-GO verdict."
                ),
                persona=persona,
                base_branch=target_branch,
                target_branch=f"agent/security-reviewer/{review_job_id}",
                allow_writes=False,
                head_commit_sha=head_sha,
                head_branch=verdict_branch,
            ),
            timeout=timeout,
        )
    except TimeoutError:
        return PRTaskReport(
            repo=repo,
            persona="security-reviewer",
            branch=verdict_branch,
            status="needs_human_review",
            summary=f"inline security review timed out after {timeout}s",
            warnings=[f"inline review timeout: {timeout}s"],
        )
    finally:
        stop.set()
        keeper.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await keeper


def _notify(on_progress: Callable[[str], None] | None, message: str) -> None:
    if on_progress:
        on_progress(message)


def _build_mode_and_instruction(
    effective_writes: bool, persona: AgentPersona, target_branch: str
) -> tuple[str, str]:
    mode = "auto" if (effective_writes and persona.allow_writes) else "plan"
    mode_instruction = (
        f"Read/Write enabled in isolated worktree (branch `{target_branch}`). "
        "Edit files and run tests locally; Python will handle git push and PR creation."
        if mode == "auto"
        else "Read-only review mode: DO NOT modify files. Analyze the codebase/PR and report findings."
    )
    return mode, mode_instruction


def _build_prompt(
    persona: AgentPersona,
    repo: str,
    target_branch: str,
    pr_number: int | None,
    mode_instruction: str,
    task: str,
) -> str:
    return (
        f"{BASE_GUARDRAILS}\n---\n{persona.instructions}\n---\n"
        f"Repository: {repo}\n"
        f"Persona: {persona.name} (source: {persona.source})\n"
        f"Assigned Branch: {target_branch}\n"
        f"PR Number: {pr_number if pr_number is not None else 'N/A'}\n"
        f"Mode: {mode_instruction}\n\n"
        f"Orchestrator Command:\n{wrap_untrusted(task)}"
    )


def _build_runner_cmd(
    runner: str,
    persona: AgentPersona,
    prompt: str,
    mode: str,
    conversation_id: str | None,
    agy_bin: str,
) -> list[str]:
    if runner == "omp":
        omp_bin = os.getenv("OMP_BIN", "/home/linuxbrew/.linuxbrew/bin/omp")
        cmd = [omp_bin, "-p", prompt, "--no-session", "--mode", "json"]
        if persona.model:
            cmd.extend(["--model", persona.model])
        return cmd
    cmd = [
        agy_bin,
        "-p",
        prompt,
        "--output-format",
        "json",
        "--json-schema",
        json.dumps(_WorkerJSONOutput.model_json_schema()),
        "--mode",
        mode,
    ]
    if persona.model:
        cmd.extend(["--model", persona.model])
    if conversation_id:
        cmd.extend(["--conversation", conversation_id])
    return cmd


def _maybe_note(
    on_progress: Callable[[str], None] | None,
    last_note: float,
    heartbeat_sec: int,
    started_at: float,
    runner: str,
) -> float:
    if on_progress and time.monotonic() - last_note >= heartbeat_sec:
        on_progress(
            f"{runner} still running ({int(time.monotonic() - started_at)}s elapsed)"
        )
        return time.monotonic()
    return last_note


async def _pump(
    stream: asyncio.StreamReader | None,
    buf: bytearray,
    job_id: str,
    on_progress: Callable[[str], None] | None,
    runner: str,
    heartbeat_sec: int,
    started_at: float,
) -> None:
    if stream is None:
        return
    last_note = time.monotonic()
    while True:
        chunk = await stream.read(8192)
        if not chunk:
            break
        buf.extend(chunk)
        _JOB_HEARTBEAT[job_id] = time.time()  # real subprocess activity
        last_note = _maybe_note(
            on_progress, last_note, heartbeat_sec, started_at, runner
        )


async def _kill_and_reap(proc: asyncio.subprocess.Process) -> None:
    _kill_process_group(proc)
    with contextlib.suppress(ProcessLookupError):
        await proc.wait()


async def _drain_pumps(
    out_pump: asyncio.Task[None], err_pump: asyncio.Task[None]
) -> None:
    for res in await asyncio.gather(out_pump, err_pump, return_exceptions=True):
        if isinstance(res, Exception):
            logger.warning("worker output pump failed: %s", res)


async def _spawn_and_wait(
    *,
    cmd: list[str],
    worktree_dir: Path,
    job_id: str,
    timeout_sec: int,
    on_progress: Callable[[str], None] | None,
    runner: str,
    model: str | None,
) -> _RunOutcome:
    proc = await asyncio.create_subprocess_exec(
        *cmd,
        cwd=str(worktree_dir),
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        env=build_safe_agy_env(),
        start_new_session=True,
    )
    heartbeat_sec = max(5, int(os.getenv("AGY_HEARTBEAT_SECONDS", "30")))
    started_at = time.monotonic()
    _JOB_SUBPROC_ACTIVE[job_id] = True
    stdout_buf = bytearray()
    stderr_buf = bytearray()
    out_pump = asyncio.create_task(
        _pump(
            proc.stdout,
            stdout_buf,
            job_id,
            on_progress,
            runner,
            heartbeat_sec,
            started_at,
        )
    )
    err_pump = asyncio.create_task(
        _pump(
            proc.stderr,
            stderr_buf,
            job_id,
            on_progress,
            runner,
            heartbeat_sec,
            started_at,
        )
    )
    agy_start = time.monotonic()
    timed_out = False
    try:
        await asyncio.wait_for(proc.wait(), timeout=timeout_sec)
        agy_ms = int((time.monotonic() - agy_start) * 1000)
    except TimeoutError:
        timed_out = True
        agy_ms = int((time.monotonic() - agy_start) * 1000)
        await _kill_and_reap(proc)
    except asyncio.CancelledError:
        await _kill_and_reap(proc)
        raise
    finally:
        _JOB_SUBPROC_ACTIVE.pop(job_id, None)
        await _drain_pumps(out_pump, err_pump)

    raw_out = bytes(stdout_buf).decode("utf-8", errors="replace")
    raw_err_full = bytes(stderr_buf).decode("utf-8", errors="replace")
    if timed_out:
        log_path = _persist_job_log(job_id, None, raw_out, raw_err_full)
        model_meta = {
            "model": model,
            "finish_reason": None,
            "usage": {},
            "num_turns": 0,
            "duration_seconds": timeout_sec,
            "returncode": None,
            "timed_out": True,
            "failure_class": "harness",
        }
        rec = _persist_model_record(job_id, model_meta, "", scrub=True)
        return _RunOutcome(None, raw_out, raw_err_full, agy_ms, True, log_path, rec)

    raw_err = raw_err_full.strip()
    log_path = _persist_job_log(job_id, proc.returncode, raw_out, raw_err)
    return _RunOutcome(proc.returncode, raw_out, raw_err, agy_ms, False, log_path, None)


def _timeout_report(
    outcome: _RunOutcome,
    *,
    repo: str,
    persona: str,
    target_branch: str,
    pr_number: int | None,
    task_start: float,
    timeout_sec: int,
    runner: str,
    phase_timings_ms: dict[str, int],
) -> PRTaskReport:
    return PRTaskReport(
        repo=repo,
        persona=persona,
        branch=target_branch,
        pr_number=pr_number,
        status="failed",
        summary=f"{runner} worker timed out after {timeout_sec}s",
        failure_point=f"timeout: exceeded {timeout_sec}s execution limit",
        log_file=outcome.log_path,
        failure_class="harness",
        timed_out=True,
        model_record=outcome.model_record,
        scrubbed=True,
        duration_ms=int((time.monotonic() - task_start) * 1000),
        phase_timings_ms=phase_timings_ms,
    )


def _failure_report(
    outcome: _RunOutcome,
    *,
    job_id: str,
    repo: str,
    persona: str,
    target_branch: str,
    pr_number: int | None,
    task_start: float,
    runner: str,
    model: str | None,
    phase_timings_ms: dict[str, int],
) -> PRTaskReport:
    fail_detail = outcome.raw_err or outcome.raw_out[:500]
    failure_point = (
        f"runner_{runner}_execution (exit {outcome.returncode}): {fail_detail[:300]}"
    )
    fc = (
        "provider"
        if _looks_like_provider_error(outcome.raw_err or outcome.raw_out)
        else "harness"
    )
    model_meta = {
        "model": model,
        "finish_reason": None,
        "usage": {},
        "num_turns": 0,
        "duration_seconds": 0.0,
        "returncode": outcome.returncode,
        "timed_out": False,
        "failure_class": fc,
    }
    rec = _persist_model_record(job_id, model_meta, outcome.raw_out, scrub=True)
    return PRTaskReport(
        repo=repo,
        persona=persona,
        branch=target_branch,
        pr_number=pr_number,
        status="failed",
        summary=f"{runner} exited with code {outcome.returncode}: {fail_detail}",
        failure_point=failure_point,
        log_file=outcome.log_path,
        failure_class=fc,
        model_record=rec,
        scrubbed=True,
        duration_ms=int((time.monotonic() - task_start) * 1000),
        phase_timings_ms=phase_timings_ms,
    )


def _parse_runner_output(
    runner: str, raw_out: str, model: str | None
) -> tuple[_WorkerJSONOutput, str | None, dict[str, Any]]:
    if runner == "omp":
        return _parse_omp_output(raw_out, model=model)
    return _parse_agy_output(raw_out, model=model)


def _blast_blocked(blast: Any) -> bool:
    return bool(blast.blocked) or not blast.within_limits


async def _run_verification(
    *,
    worktree_dir: Path,
    repo: str,
    base_branch: str,
    verdict_branch: str,
    head_sha: str,
    audit: Any,
    diff_text: str,
    parsed: _WorkerJSONOutput,
) -> bool:
    blast = evaluate_blast_radius(diff_text)
    if _blast_blocked(blast):
        parsed.warnings.append(
            "blast radius rejected: " + ", ".join(blast.blocked or blast.reasons)
        )
        return False
    checks_passed, _, checks_err = await asyncio.to_thread(
        run_checks_from_main,
        worktree_dir,
        worktree_dir,
        repo=repo,
        branch=verdict_branch,
        head_commit_sha=head_sha,
        audit=audit,
        ref=f"origin/{base_branch}",
    )
    if checks_err:
        parsed.warnings.append(f"verification: {checks_err}")
    return checks_passed and checks_err is None


async def _run_security_review(
    *,
    job_id: str,
    repo: str,
    base_branch: str,
    target_branch: str,
    head_sha: str,
    verdict_branch: str,
    audit: Any,
    on_progress: Callable[[str], None] | None,
    parsed: _WorkerJSONOutput,
) -> None:
    _notify(on_progress, "Running inline security review")
    review = await _run_inline_security_review(
        job_id=job_id,
        repo=repo,
        base_branch=base_branch,
        target_branch=target_branch,
        head_sha=head_sha,
        verdict_branch=verdict_branch,
    )
    verdict = _security_verdict(review)
    handle_security_review_completion(
        audit,
        repo=repo,
        branch=verdict_branch,
        head_commit_sha=head_sha,
        verdict=verdict,
    )
    if verdict != APPROVED:
        parsed.warnings.append(
            f"security review did not approve: {review.summary[:200]}"
        )


async def _open_gated_pr(
    *,
    repo: str,
    persona: AgentPersona,
    job_id: str,
    task: str,
    base_branch: str,
    target_branch: str,
    verdict_branch: str,
    head_sha: str,
    diff_text: str,
    audit: Any,
    pr_number: int | None,
    parsed: _WorkerJSONOutput,
) -> tuple[str | None, int | None]:
    holder: dict[str, tuple[str | None, int | None]] = {}

    async def _opener(**kwargs: Any) -> None:
        holder["result"] = await open_pr(**kwargs)

    gate = await open_draft_pr(
        repo=repo,
        branch=verdict_branch,
        head_commit_sha=head_sha,
        diff_text=diff_text,
        audit=audit,
        pr_opener=_opener,
        opener_kwargs={
            "repo": repo,
            "target_branch": target_branch,
            "base_branch": base_branch,
            "title": f"[{persona.name}] {task.splitlines()[0][:72]}",
            "body": (
                f"Automated PR by `{persona.name}` (`{job_id}`).\n\n{parsed.summary}"
            ),
            "pr_number": pr_number,
        },
    )
    if gate.proceed and "result" in holder:
        return holder["result"]
    parsed.warnings.append(f"gate blocked PR: {gate.reason}")
    if parsed.status == "completed":
        parsed.status = "needs_human_review"
    return None, pr_number


async def _run_auto_mode(
    *,
    parsed: _WorkerJSONOutput,
    repo: str,
    persona: AgentPersona,
    job_id: str,
    task: str,
    base_branch: str,
    target_branch: str,
    pr_number: int | None,
    head_branch: str | None,
    audit: Any,
    on_progress: Callable[[str], None] | None,
    worktree_dir: Path,
    head_sha: str | None,
) -> tuple[list[str], list[str], str | None, int | None, str | None]:
    _notify(on_progress, "Committing changes and running verification")
    files_touched, commit_shas = await commit_and_push(
        worktree_dir=worktree_dir,
        repo=repo,
        target_branch=target_branch,
        base_branch=base_branch,
        title=f"[{persona.name}] {task.splitlines()[0][:72]}",
    )
    head_sha = commit_shas[0] if commit_shas else None
    if not head_sha:
        parsed.warnings.append("no commit produced; PR not opened")
        return files_touched, commit_shas, None, pr_number, head_sha
    verdict_branch = head_branch or target_branch
    diff_text = await _run_git(
        ["diff", f"origin/{base_branch}..HEAD"], cwd=worktree_dir
    )
    checks_ok = await _run_verification(
        worktree_dir=worktree_dir,
        repo=repo,
        base_branch=base_branch,
        verdict_branch=verdict_branch,
        head_sha=head_sha,
        audit=audit,
        diff_text=diff_text,
        parsed=parsed,
    )
    if checks_ok:
        await _run_security_review(
            job_id=job_id,
            repo=repo,
            base_branch=base_branch,
            target_branch=target_branch,
            head_sha=head_sha,
            verdict_branch=verdict_branch,
            audit=audit,
            on_progress=on_progress,
            parsed=parsed,
        )
    pr_url, out_pr_num = await _open_gated_pr(
        repo=repo,
        persona=persona,
        job_id=job_id,
        task=task,
        base_branch=base_branch,
        target_branch=target_branch,
        verdict_branch=verdict_branch,
        head_sha=head_sha,
        diff_text=diff_text,
        audit=audit,
        pr_number=pr_number,
        parsed=parsed,
    )
    return files_touched, commit_shas, pr_url, out_pr_num, head_sha


async def _post_review_comment(
    *,
    repo: str,
    pr_number: int,
    persona: AgentPersona,
    on_progress: Callable[[str], None] | None,
    summary: str,
) -> str | None:
    _notify(on_progress, f"Posting review comment to PR #{pr_number}")
    return await post_pr_comment(
        repo=repo,
        pr_number=pr_number,
        body=f"### Automated Review (`{persona.name}`)\n\n{summary}",
    )


async def _do_static_checks(
    worktree_dir: Path,
    files_touched: list[str],
    job_id: str,
    phase_timings_ms: dict[str, int],
) -> tuple[list[dict[str, Any]], list[str]]:
    # Run isolated static checks on changed files (VPS-safe: ruff/bandit/gitleaks only).
    _mark_alive(job_id)
    static_checks_start = time.monotonic()
    static_findings, check_warnings = run_safe_static_checks(
        worktree_dir, files_touched
    )
    phase_timings_ms["static_checks_ms"] = int(
        (time.monotonic() - static_checks_start) * 1000
    )
    return static_findings, check_warnings


def _success_report(
    *,
    repo: str,
    persona: str,
    target_branch: str,
    out_pr_num: int | None,
    parsed: _WorkerJSONOutput,
    files_touched: list[str],
    commit_shas: list[str],
    pr_url: str | None,
    head_sha: str | None,
    new_conv_id: str | None,
    log_path: str,
    model_meta: dict[str, Any],
    static_findings: list[dict[str, Any]],
    rec: str,
    task_start: float,
    phase_timings_ms: dict[str, int],
) -> PRTaskReport:
    out_model = cast("str | None", model_meta.get("model"))
    out_finish = cast("str | None", model_meta.get("finish_reason"))
    out_usage = cast("dict[str, Any]", model_meta.get("usage") or {})
    out_turns = int(model_meta.get("num_turns", 0) or 0)
    return PRTaskReport(
        repo=repo,
        persona=persona,
        branch=target_branch,
        pr_number=out_pr_num,
        status=parsed.status,
        summary=parsed.summary,
        files_touched=files_touched,
        commit_shas=commit_shas,
        pr_url=pr_url,
        head_commit_sha=head_sha,
        conversation_id=new_conv_id,
        log_file=log_path,
        warnings=parsed.warnings,
        static_findings=static_findings,
        model=out_model,
        finish_reason=out_finish,
        usage=out_usage,
        num_turns=out_turns,
        failure_class="none",
        model_record=rec,
        scrubbed=True,
        duration_ms=int((time.monotonic() - task_start) * 1000),
        phase_timings_ms=phase_timings_ms,
    )


async def _finalize_success(
    *,
    parsed: _WorkerJSONOutput,
    new_conv_id: str | None,
    model_meta: dict[str, Any],
    repo: str,
    persona: AgentPersona,
    job_id: str,
    task: str,
    base_branch: str,
    target_branch: str,
    pr_number: int | None,
    head_branch: str | None,
    mode: str,
    effective_writes: bool,
    audit: Any,
    on_progress: Callable[[str], None] | None,
    worktree_dir: Path,
    head_sha: str | None,
    raw_out: str,
    log_path: str,
    task_start: float,
    phase_timings_ms: dict[str, int],
) -> PRTaskReport:
    files_touched: list[str] = []
    commit_shas: list[str] = []
    pr_url: str | None = None
    out_pr_num = pr_number
    if mode == "auto":
        files_touched, commit_shas, pr_url, out_pr_num, head_sha = await _run_auto_mode(
            parsed=parsed,
            repo=repo,
            persona=persona,
            job_id=job_id,
            task=task,
            base_branch=base_branch,
            target_branch=target_branch,
            pr_number=pr_number,
            head_branch=head_branch,
            audit=audit,
            on_progress=on_progress,
            worktree_dir=worktree_dir,
            head_sha=head_sha,
        )
    elif effective_writes and pr_number is not None:
        pr_url = await _post_review_comment(
            repo=repo,
            pr_number=pr_number,
            persona=persona,
            on_progress=on_progress,
            summary=parsed.summary,
        )
    static_findings, check_warnings = await _do_static_checks(
        worktree_dir, files_touched, job_id, phase_timings_ms
    )
    parsed.warnings.extend(check_warnings)

    final_meta = {
        **model_meta,
        "returncode": 0,
        "timed_out": False,
        "failure_class": "none",
    }
    rec = _persist_model_record(job_id, final_meta, raw_out, scrub=True)
    return _success_report(
        repo=repo,
        persona=persona.name,
        target_branch=target_branch,
        out_pr_num=out_pr_num,
        parsed=parsed,
        files_touched=files_touched,
        commit_shas=commit_shas,
        pr_url=pr_url,
        head_sha=head_sha,
        new_conv_id=new_conv_id,
        log_path=log_path,
        model_meta=final_meta,
        static_findings=static_findings,
        rec=rec,
        task_start=task_start,
        phase_timings_ms=phase_timings_ms,
    )


async def execute_pr_task(
    job_id: str,
    repo: str,
    task: str,
    persona: AgentPersona,
    base_branch: str,
    target_branch: str,
    pr_number: int | None = None,
    allow_writes: bool | None = None,
    conversation_id: str | None = None,
    head_commit_sha: str | None = None,
    head_branch: str | None = None,
    on_progress: Callable[[str], None] | None = None,
) -> PRTaskReport:
    """Run an isolated `agy -p` worker in a dedicated git worktree and push results if enabled."""
    task_start = time.monotonic()
    _mark_alive(job_id)
    git_ms = 0
    agy_ms = 0
    static_checks_ms = 0
    effective_writes = persona.allow_writes if allow_writes is None else allow_writes
    audit = get_audit_logger()
    head_sha: str | None = head_commit_sha
    agy_bin = os.getenv("AGY_BIN", "/home/linuxbrew/.linuxbrew/bin/agy")
    timeout_sec = int(os.getenv("AGY_TIMEOUT_SECONDS", str(JOB_TIMEOUT_SECONDS)))

    _notify(on_progress, f"Preparing isolated worktree for {repo} ({target_branch})")

    worktree_dir: Path | None = None
    try:
        git_start = time.monotonic()
        worktree_dir = await prepare_worktree(
            repo=repo,
            base_branch=base_branch,
            target_branch=target_branch,
            job_id=job_id,
        )
        git_ms = int((time.monotonic() - git_start) * 1000)

        mode, mode_instruction = _build_mode_and_instruction(
            effective_writes, persona, target_branch
        )
        prompt = _build_prompt(
            persona, repo, target_branch, pr_number, mode_instruction, task
        )
        runner = getattr(persona, "runner", "agy").lower()
        cmd = _build_runner_cmd(runner, persona, prompt, mode, conversation_id, agy_bin)

        _notify(on_progress, f"Running {runner} ({persona.name}, mode={mode})")

        outcome = await _spawn_and_wait(
            cmd=cmd,
            worktree_dir=worktree_dir,
            job_id=job_id,
            timeout_sec=timeout_sec,
            on_progress=on_progress,
            runner=runner,
            model=persona.model,
        )
        agy_ms = outcome.agy_ms
        phase_timings_ms = {
            "git_ms": git_ms,
            "agy_ms": agy_ms,
            "static_checks_ms": static_checks_ms,
        }
        if outcome.timed_out:
            return _timeout_report(
                outcome,
                repo=repo,
                persona=persona.name,
                target_branch=target_branch,
                pr_number=pr_number,
                task_start=task_start,
                timeout_sec=timeout_sec,
                runner=runner,
                phase_timings_ms=phase_timings_ms,
            )
        if outcome.returncode != 0:
            return _failure_report(
                outcome,
                job_id=job_id,
                repo=repo,
                persona=persona.name,
                target_branch=target_branch,
                pr_number=pr_number,
                task_start=task_start,
                runner=runner,
                model=persona.model,
                phase_timings_ms=phase_timings_ms,
            )

        parsed, new_conv_id, model_meta = _parse_runner_output(
            runner, outcome.raw_out, persona.model
        )
        return await _finalize_success(
            parsed=parsed,
            new_conv_id=new_conv_id,
            model_meta=model_meta,
            repo=repo,
            persona=persona,
            job_id=job_id,
            task=task,
            base_branch=base_branch,
            target_branch=target_branch,
            pr_number=pr_number,
            head_branch=head_branch,
            mode=mode,
            effective_writes=effective_writes,
            audit=audit,
            on_progress=on_progress,
            worktree_dir=worktree_dir,
            head_sha=head_sha,
            raw_out=outcome.raw_out,
            log_path=outcome.log_path,
            task_start=task_start,
            phase_timings_ms=phase_timings_ms,
        )
    finally:
        if worktree_dir is not None:
            await cleanup_worktree(repo, worktree_dir)
