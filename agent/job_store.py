from __future__ import annotations

import asyncio
import json
import logging
import os
import secrets
import sqlite3
import time
from pathlib import Path
from typing import Any

import httpx

logger = logging.getLogger(__name__)

from agent.audit_shared import get_audit_logger
from agent.personas import load_persona
from agent.pr_worker import (
    _JOB_HEARTBEAT,
    _JOB_SUBPROC_ACTIVE,
    PRTaskReport,
    execute_pr_task,
)
from agent.security import MAX_CONCURRENT_JOBS, REPLAY_TTL_SECONDS
from agent.verdict import _security_verdict
from src.orchestrator.middleware.redactor import SecretRedactor
from src.orchestrator.tools.gated_pr import handle_security_review_completion

DEFAULT_DB_PATH = Path(__file__).resolve().parent.parent / "data" / "jobs.db"
_JOB_EVENTS: dict[str, asyncio.Event] = {}
_RUNNING_TASKS: dict[str, asyncio.Task] = {}
_JOB_SEMAPHORE = asyncio.Semaphore(MAX_CONCURRENT_JOBS)


def _get_db_path() -> Path:
    return Path(os.getenv("JOB_DB_PATH", str(DEFAULT_DB_PATH)))


def _conn() -> sqlite3.Connection:
    db_path = _get_db_path()
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    with _conn() as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS jobs (
                job_id TEXT PRIMARY KEY,
                repo TEXT NOT NULL,
                persona TEXT NOT NULL,
                branch TEXT NOT NULL,
                pr_number INTEGER,
                command TEXT NOT NULL,
                status TEXT NOT NULL,
                progress_json TEXT NOT NULL,
                result_json TEXT,
                error TEXT,
                conversation_id TEXT,
                created_at REAL NOT NULL,
                updated_at REAL NOT NULL
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS webhook_deliveries (
                delivery_id TEXT PRIMARY KEY,
                received_at REAL NOT NULL
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS submitted_reviews (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                repo TEXT NOT NULL,
                pr_number INTEGER NOT NULL,
                head_sha TEXT NOT NULL,
                event TEXT NOT NULL,
                comment_count INTEGER NOT NULL,
                created_at REAL NOT NULL,
                UNIQUE(repo, pr_number, head_sha, event)
            )
            """
        )


def register_webhook_delivery(
    delivery_id: str, ttl_seconds: int = REPLAY_TTL_SECONDS
) -> bool:
    """Atomically register a webhook delivery id; returns False if it is a replay within the TTL."""
    now = time.time()
    with _conn() as conn:
        conn.execute(
            "DELETE FROM webhook_deliveries WHERE received_at < ?",
            (now - ttl_seconds,),
        )
        existing = conn.execute(
            "SELECT 1 FROM webhook_deliveries WHERE delivery_id = ?", (delivery_id,)
        ).fetchone()
        if existing:
            return False
        conn.execute(
            "INSERT INTO webhook_deliveries (delivery_id, received_at) VALUES (?, ?)",
            (delivery_id, now),
        )
    return True


def has_submitted_review(repo: str, pr_number: int, head_sha: str, event: str) -> bool:
    with _conn() as conn:
        row = conn.execute(
            "SELECT 1 FROM submitted_reviews WHERE repo=? AND pr_number=? AND head_sha=? AND event=?",
            (repo, pr_number, head_sha, event),
        ).fetchone()
        return row is not None


def record_submitted_review(
    repo: str, pr_number: int, head_sha: str, event: str, comment_count: int
) -> None:
    with _conn() as conn:
        conn.execute(
            "INSERT OR IGNORE INTO submitted_reviews (repo, pr_number, head_sha, event, comment_count, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (repo, pr_number, head_sha, event, comment_count, time.time()),
        )


def _append_progress(job_id: str, message: str, status: str | None = None) -> None:
    message, _ = SecretRedactor().redact_text(message)
    now = time.time()
    with _conn() as conn:
        row = conn.execute(
            "SELECT progress_json, status FROM jobs WHERE job_id = ?", (job_id,)
        ).fetchone()
        if not row:
            return
        logs = json.loads(row["progress_json"])
        logs.append({"ts": int(now), "msg": message})
        new_status = status or row["status"]
        conn.execute(
            "UPDATE jobs SET status = ?, progress_json = ?, updated_at = ? WHERE job_id = ?",
            (new_status, json.dumps(logs[-25:]), now, job_id),
        )


def _redact_completion(
    result: dict | None, error: str | None
) -> tuple[dict | None, str | None]:
    if result is not None:
        result, _ = SecretRedactor().redact_payload(result)
    if error is not None:
        error, _ = SecretRedactor().redact_text(error)
    return result, error


def _complete_job(
    job_id: str,
    status: str,
    result: dict | None = None,
    error: str | None = None,
    conversation_id: str | None = None,
) -> None:
    now = time.time()
    result, error = _redact_completion(result, error)
    with _conn() as conn:
        conn.execute(
            """
            UPDATE jobs
            SET status = ?, result_json = ?, error = ?, conversation_id = COALESCE(?, conversation_id), updated_at = ?
            WHERE job_id = ? AND status = 'running'
            """,
            (
                status,
                json.dumps(result) if result else None,
                error,
                conversation_id,
                now,
                job_id,
            ),
        )
    _JOB_HEARTBEAT.pop(job_id, None)
    ev = _JOB_EVENTS.get(job_id)
    if ev:
        ev.set()


def _is_stale_row(row: sqlite3.Row, now: float, threshold_sec: int) -> bool:
    job_id = row["job_id"]
    if _JOB_SUBPROC_ACTIVE.get(job_id):
        # A live subprocess is owned by the hard wait_for timeout,
        # not the 90s reaper.
        return False
    task = _RUNNING_TASKS.get(job_id)
    last = _JOB_HEARTBEAT.get(job_id, float(row["created_at"]))
    return now - last > threshold_sec or (task is not None and task.done())


def detect_stale_jobs(threshold_sec: int | None = None) -> list[dict[str, Any]]:
    """Return running jobs whose liveness heartbeat is older than the threshold.

    Liveness is tracked in ``_JOB_HEARTBEAT`` (owned by ``agent.pr_worker``),
    refreshed only by the worker heartbeat task — never by ``updated_at``,
    which the 30s heartbeat keeps fresh even while the subprocess is blocked.
    Falls back to ``created_at`` when no heartbeat has been recorded yet.
    """
    if threshold_sec is None:
        threshold_sec = int(os.getenv("STALE_JOB_THRESHOLD_SECONDS", "90"))
    now = time.time()
    stale: list[dict[str, Any]] = []
    conn = _conn()
    try:
        rows = conn.execute(
            "SELECT job_id, repo, persona, created_at FROM jobs WHERE status='running'"
        ).fetchall()
        for r in rows:
            if _is_stale_row(r, now, threshold_sec):
                stale.append(dict(r))
    finally:
        conn.close()
    return stale


def _fail_stale_job(s: dict[str, Any]) -> None:
    job_id = s["job_id"]
    age = int(time.time() - _JOB_HEARTBEAT.get(job_id, float(s["created_at"])))
    _append_progress(job_id, f"stale: no heartbeat for {age}s", status="failed")
    _complete_job(
        job_id,
        status="failed",
        result={
            "status": "failed",
            "summary": f"stale: no heartbeat for {age}s",
            "failure_point": "stale",
            "failure_class": "harness",
        },
        error=f"stale: no heartbeat for {age}s",
    )
    _JOB_EVENTS.pop(job_id, None)
    task = _RUNNING_TASKS.pop(job_id, None)
    if task is not None and not task.done():
        task.cancel()
    _JOB_HEARTBEAT.pop(job_id, None)


async def _stale_reaper_loop(stop: asyncio.Event) -> None:
    """Periodically fail stale running jobs and clean up their in-memory state."""
    while not stop.is_set():
        try:
            for s in detect_stale_jobs():
                _fail_stale_job(s)
        except Exception:  # reaper must never die
            logger.exception("stale reaper iteration failed")
        await asyncio.sleep(30)


async def _send_push_notification(text: str) -> None:
    webhook_url = os.getenv("NOTIFY_WEBHOOK_URL", "").strip()
    if not webhook_url:
        return
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            await client.post(webhook_url, json={"content": text, "text": text})
    except httpx.HTTPError as exc:
        logger.warning("Push notification failed: %s", exc)


def _maybe_handle_security_review(
    persona_name: str,
    repo: str,
    report: PRTaskReport,
    head_branch: str | None,
) -> None:
    if persona_name == "security-reviewer" and report.head_commit_sha and head_branch:
        handle_security_review_completion(
            get_audit_logger(),
            repo=repo,
            branch=head_branch,
            head_commit_sha=report.head_commit_sha,
            verdict=_security_verdict(report),
        )


async def _notify_completion(
    job_id: str, persona_name: str, repo: str, report: PRTaskReport
) -> None:
    await _send_push_notification(
        f"[Swarm {job_id}] {persona_name} finished on `{repo}` ({report.status}). "
        f"PR: {report.pr_url or 'N/A'}"
    )


async def _run_job_coroutine(
    job_id: str,
    repo: str,
    persona_name: str,
    command: str,
    base_branch: str,
    target_branch: str,
    pr_number: int | None,
    allow_writes: bool | None,
    conversation_id: str | None,
    head_commit_sha: str | None,
    head_branch: str | None,
) -> None:
    try:
        async with _JOB_SEMAPHORE:
            _append_progress(
                job_id, f"Loading persona '{persona_name}'", status="running"
            )
            _JOB_HEARTBEAT[job_id] = time.time()
            persona = await load_persona(
                repo=repo, persona_name=persona_name, ref=base_branch
            )

            report = await execute_pr_task(
                job_id=job_id,
                repo=repo,
                task=command,
                persona=persona,
                base_branch=base_branch,
                target_branch=target_branch,
                pr_number=pr_number,
                allow_writes=allow_writes,
                conversation_id=conversation_id,
                head_commit_sha=head_commit_sha,
                head_branch=head_branch,
                on_progress=lambda msg: _append_progress(job_id, msg),
            )
            result_dict = report.model_dump()
            _complete_job(
                job_id,
                status=report.status,
                result=result_dict,
                conversation_id=report.conversation_id,
            )
            _maybe_handle_security_review(persona_name, repo, report, head_branch)
            await _notify_completion(job_id, persona.name, repo, report)
    except Exception as exc:  # noqa: BLE001 - top-level worker boundary must record any failure
        _append_progress(job_id, f"Error: {exc}", status="failed")
        _complete_job(
            job_id,
            status="failed",
            result={
                "status": "failed",
                "summary": f"Worker crashed: {exc}",
                "failure_point": f"harness: {type(exc).__name__}",
                "failure_class": "harness",
            },
            error=str(exc),
        )
        await _send_push_notification(f"[Swarm {job_id}] FAILED on `{repo}`: {exc}")
    finally:
        _RUNNING_TASKS.pop(job_id, None)
        _JOB_HEARTBEAT.pop(job_id, None)


MAX_CONSECUTIVE_FAILURES: int = 3


def check_circuit_breaker(
    repo: str, safe_persona: str, pr_number: int | None
) -> tuple[bool, str | None]:
    """Check if the last N consecutive jobs for (repo, persona, pr_number) all failed."""
    with _conn() as conn:
        rows = conn.execute(
            """
            SELECT status, error FROM jobs
            WHERE repo = ? AND persona = ? AND (pr_number = ? OR (pr_number IS NULL AND ? IS NULL))
            ORDER BY created_at DESC LIMIT ?
            """,
            (repo, safe_persona, pr_number, pr_number, MAX_CONSECUTIVE_FAILURES),
        ).fetchall()
        if len(rows) == MAX_CONSECUTIVE_FAILURES and all(
            r["status"] == "failed" for r in rows
        ):
            last_err = rows[0]["error"] or "Consecutive task failure"
            return True, (
                f"Circuit breaker tripped: {MAX_CONSECUTIVE_FAILURES} consecutive failures for persona "
                f"'{safe_persona}' on {repo}. Last failure: {last_err}. "
                "Automated retries locked to prevent runaway tool loops. "
                "Inspect failure logs or invoke 'scout' to diagnose root cause."
            )
    return False, None


def dispatch_job(
    repo: str,
    persona: str,
    command: str,
    base_branch: str = "main",
    pr_number: int | None = None,
    allow_writes: bool | None = None,
    conversation_id: str | None = None,
    head_commit_sha: str | None = None,
    head_branch: str | None = None,
) -> dict[str, Any]:
    """Queue and immediately launch an isolated background `agy -p` worker."""
    safe_persona = persona.removesuffix(".md").replace("/", "-")
    is_tripped, trip_reason = check_circuit_breaker(repo, safe_persona, pr_number)
    if is_tripped:
        return {
            "job_id": None,
            "status": "circuit_breaker_tripped",
            "repo": repo,
            "persona": safe_persona,
            "error": trip_reason,
            "failure_point": f"circuit_breaker: {MAX_CONSECUTIVE_FAILURES} consecutive failures",
        }

    job_id = f"job_{secrets.token_hex(4)}"
    target_branch = f"agent/{safe_persona}/{job_id}"
    now = time.time()

    stored_command, _ = SecretRedactor().redact_text(command)
    with _conn() as conn:
        conn.execute(
            """
            INSERT INTO jobs (job_id, repo, persona, branch, pr_number, command, status, progress_json, conversation_id, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                job_id,
                repo,
                safe_persona,
                target_branch,
                pr_number,
                stored_command,
                "queued",
                json.dumps([{"ts": int(now), "msg": "Job queued"}]),
                conversation_id,
                now,
                now,
            ),
        )

    _JOB_EVENTS[job_id] = asyncio.Event()
    task = asyncio.create_task(
        _run_job_coroutine(
            job_id=job_id,
            repo=repo,
            persona_name=safe_persona,
            command=command,
            base_branch=base_branch,
            target_branch=target_branch,
            pr_number=pr_number,
            allow_writes=allow_writes,
            conversation_id=conversation_id,
            head_commit_sha=head_commit_sha,
            head_branch=head_branch,
        )
    )
    _RUNNING_TASKS[job_id] = task

    return {
        "job_id": job_id,
        "status": "queued",
        "repo": repo,
        "persona": safe_persona,
        "assigned_branch": target_branch,
    }


def get_job(job_id: str) -> dict[str, Any] | None:
    with _conn() as conn:
        row = conn.execute("SELECT * FROM jobs WHERE job_id = ?", (job_id,)).fetchone()
        if not row:
            return None
        return {
            "job_id": row["job_id"],
            "repo": row["repo"],
            "persona": row["persona"],
            "branch": row["branch"],
            "pr_number": row["pr_number"],
            "status": row["status"],
            "conversation_id": row["conversation_id"],
            "progress": json.loads(row["progress_json"])[-5:],
            "result": json.loads(row["result_json"]) if row["result_json"] else None,
            "error": row["error"],
            "elapsed_seconds": round(row["updated_at"] - row["created_at"], 1),
        }


def _pending_job_ids(
    snapshots: list[dict[str, Any] | None], terminal: set[str]
) -> list[str]:
    return [
        s["job_id"] for s in snapshots if s is not None and s["status"] not in terminal
    ]


def _build_waiters(pending_ids: list[str]) -> list[asyncio.Task]:
    return [
        asyncio.create_task(_JOB_EVENTS[jid].wait())
        for jid in pending_ids
        if jid in _JOB_EVENTS
    ]


async def _cancel_pending(waiters: list[asyncio.Task], remaining: float) -> None:
    _done, pending = await asyncio.wait(
        waiters, timeout=min(5.0, remaining), return_when=asyncio.FIRST_COMPLETED
    )
    for task in pending:
        task.cancel()


async def wait_for_jobs(
    job_ids: list[str], timeout_seconds: int = 45
) -> dict[str, Any]:
    """
    Long-poll up to `timeout_seconds` (capped at 55s to stay safely under Cloudflare's 100s limit).
    Returns immediately once all requested jobs reach a terminal state.
    """
    capped_timeout = max(1, min(timeout_seconds, 55))
    terminal = {"completed", "needs_human_review", "failed"}
    deadline = time.monotonic() + capped_timeout

    while True:
        snapshots = [get_job(jid) for jid in job_ids]
        pending_ids = _pending_job_ids(snapshots, terminal)
        if not pending_ids:
            return {"all_done": True, "jobs": snapshots}
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return {"all_done": False, "pending": pending_ids, "jobs": snapshots}
        waiters = _build_waiters(pending_ids)
        if not waiters:
            await asyncio.sleep(min(2.0, remaining))
            continue
        await _cancel_pending(waiters, remaining)
