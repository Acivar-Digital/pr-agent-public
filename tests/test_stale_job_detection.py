from __future__ import annotations

import asyncio
import json
import time

import pytest

from agent.job_store import (
    _RUNNING_TASKS,
    _complete_job,
    _conn,
    detect_stale_jobs,
    init_db,
)


def _insert_running_job(job_id: str, created_at: float) -> None:
    with _conn() as conn:
        conn.execute(
            """
            INSERT INTO jobs (
                job_id, repo, persona, branch, pr_number, command,
                status, progress_json, conversation_id, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                job_id,
                "acme/widget",
                "scout",
                f"agent/scout/{job_id}",
                None,
                "do the thing",
                "running",
                json.dumps([{"ts": int(created_at), "msg": "Job queued"}]),
                None,
                created_at,
                created_at,
            ),
        )


@pytest.fixture()
def _tmp_db(tmp_path, monkeypatch):
    monkeypatch.setenv("JOB_DB_PATH", str(tmp_path / "test.db"))
    init_db()
    # Isolate the liveness maps from other tests.
    from agent.pr_worker import _JOB_HEARTBEAT, _JOB_SUBPROC_ACTIVE

    _JOB_HEARTBEAT.clear()
    _RUNNING_TASKS.clear()
    _JOB_SUBPROC_ACTIVE.clear()
    yield
    _JOB_HEARTBEAT.clear()
    _RUNNING_TASKS.clear()
    _JOB_SUBPROC_ACTIVE.clear()


def test_detect_stale_jobs_flags_dead_heartbeat(_tmp_db):
    job_id = "job_deadbeef"
    _insert_running_job(job_id, created_at=time.time() - 3600)

    stale = detect_stale_jobs(threshold_sec=1)

    assert [s["job_id"] for s in stale] == [job_id]


def test_detect_stale_jobs_ignores_fresh_heartbeat(_tmp_db):
    from agent.pr_worker import _JOB_HEARTBEAT

    job_id = "job_f00dcafe"
    _insert_running_job(job_id, created_at=time.time() - 3600)
    _JOB_HEARTBEAT[job_id] = time.time()

    stale = detect_stale_jobs(threshold_sec=1)

    assert stale == []


def test_detect_stale_jobs_uses_env_threshold(_tmp_db, monkeypatch):
    job_id = "job_envbound"
    # created_at sits 5s in the past; a 10s threshold must NOT flag it,
    # a 1s threshold MUST flag it.
    _insert_running_job(job_id, created_at=time.time() - 5)

    monkeypatch.setenv("STALE_JOB_THRESHOLD_SECONDS", "10")
    assert detect_stale_jobs() == []

    monkeypatch.setenv("STALE_JOB_THRESHOLD_SECONDS", "1")
    assert [s["job_id"] for s in detect_stale_jobs()] == [job_id]


def test_detect_stale_jobs_reaps_done_task(_tmp_db):
    """A job whose coroutine finished but whose DB row is still 'running' is stale."""
    from agent.pr_worker import _JOB_HEARTBEAT

    async def _finish() -> asyncio.Task:
        task = asyncio.create_task(asyncio.sleep(0))
        await task
        return task

    job_id = "job_doneyet"
    # Fresh heartbeat and fresh created_at: only the done-task signal can flag it.
    _insert_running_job(job_id, created_at=time.time())
    _JOB_HEARTBEAT[job_id] = time.time()
    _RUNNING_TASKS[job_id] = asyncio.run(_finish())

    stale = detect_stale_jobs(threshold_sec=60)

    assert [s["job_id"] for s in stale] == [job_id]


def test_detect_stale_jobs_ignores_live_task(_tmp_db):
    """A pending task with a fresh heartbeat is not stale."""
    from agent.pr_worker import _JOB_HEARTBEAT

    job_id = "job_livetask"
    _insert_running_job(job_id, created_at=time.time())
    _JOB_HEARTBEAT[job_id] = time.time()
    # A real, still-pending task: asyncio.run() would cancel it on exit, and a
    # cancelled task is done, so drive the loop by hand instead.
    loop = asyncio.new_event_loop()
    task = loop.create_task(asyncio.sleep(3600))
    _RUNNING_TASKS[job_id] = task
    try:
        assert detect_stale_jobs(threshold_sec=60) == []
    finally:
        task.cancel()
        loop.run_until_complete(asyncio.gather(task, return_exceptions=True))
        loop.close()


def test_detect_stale_jobs_skips_active_subprocess(_tmp_db):
    """A job with a live subprocess is owned by the hard timeout, not the 90s reaper."""
    from agent.pr_worker import _JOB_SUBPROC_ACTIVE

    job_id = "job_activepump"
    # Fresh created_at and NO heartbeat would normally flag it as stale.
    _insert_running_job(job_id, created_at=time.time())
    _JOB_SUBPROC_ACTIVE[job_id] = True

    assert detect_stale_jobs(threshold_sec=1) == []


def test_complete_job_guard_no_clobber(_tmp_db):
    """A late worker completing a row the reaper already failed must not clobber it."""
    job_id = "job_lateclob"
    _insert_running_job(job_id, created_at=time.time())

    # Reaper marks the row failed.
    _complete_job(
        job_id, status="failed", result={"status": "failed", "summary": "stale"}
    )
    # Late worker tries to complete it.
    _complete_job(job_id, status="completed", result={"x": 1})

    with _conn() as conn:
        row = conn.execute(
            "SELECT status, result_json FROM jobs WHERE job_id = ?", (job_id,)
        ).fetchone()
    assert row["status"] == "failed"
    assert row["result_json"] is None or json.loads(row["result_json"]) == {
        "status": "failed",
        "summary": "stale",
    }


def test_complete_job_scrubs_error(_tmp_db):
    job_id = "job_leakerr"
    _insert_running_job(job_id, created_at=time.time())
    token = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij"

    _complete_job(job_id, "failed", error=f"leak {token}")

    with _conn() as conn:
        row = conn.execute(
            "SELECT error FROM jobs WHERE job_id = ?", (job_id,)
        ).fetchone()
    assert row is not None
    assert token not in row["error"]


def test_complete_job_scrubs_result(_tmp_db):
    job_id = "job_leakres"
    _insert_running_job(job_id, created_at=time.time())
    token = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij"

    _complete_job(job_id, "failed", result={"summary": f"leak {token}"})

    with _conn() as conn:
        row = conn.execute(
            "SELECT result_json FROM jobs WHERE job_id = ?", (job_id,)
        ).fetchone()
    assert row is not None
    assert token not in row["result_json"]


def test_append_progress_scrubs_message(_tmp_db):
    from agent.job_store import _append_progress

    job_id = "job_leakprog"
    _insert_running_job(job_id, created_at=time.time())
    token = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij"

    _append_progress(job_id, f"leak {token}")

    with _conn() as conn:
        row = conn.execute(
            "SELECT progress_json FROM jobs WHERE job_id = ?", (job_id,)
        ).fetchone()
    assert row is not None
    assert token not in row["progress_json"]
