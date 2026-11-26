"""Ticket: Model-I/O capture, failure classification, and model-record persistence."""

from __future__ import annotations

import json
import os
import stat
from pathlib import Path

import pytest

from agent import pr_worker
from agent.pr_worker import (
    PRTaskReport,
    _parse_agy_output,
    _parse_omp_output,
    _persist_job_log,
    _persist_model_record,
)


def test_pr_task_report_has_model_io_defaults() -> None:
    report = PRTaskReport(
        repo="test/repo",
        persona="developer",
        branch="test-branch",
        status="completed",
        summary="Test summary",
    )
    defaults = (
        ("failure_class", "none"),
        ("timed_out", False),
        ("usage", {}),
        ("model", None),
        ("finish_reason", None),
        ("num_turns", 0),
        ("model_record", None),
        ("scrubbed", False),
    )
    for attr, expected in defaults:
        assert getattr(report, attr) == expected, attr


def test_parse_agy_extracts_usage() -> None:
    envelope = {
        "conversation_id": "conv-123",
        "usage": {"input_tokens": 100, "output_tokens": 20},
        "num_turns": 3,
        "duration_seconds": 12.5,
        "structured_output": {
            "status": "completed",
            "summary": "all good",
        },
    }
    parsed, conv, meta = _parse_agy_output(json.dumps(envelope), model="scout")
    actual = {
        "status": parsed.status,
        "conv": conv,
        "model": meta["model"],
        "usage": meta["usage"],
        "num_turns": meta["num_turns"],
        "duration_seconds": meta["duration_seconds"],
    }
    expected = {
        "status": "completed",
        "conv": "conv-123",
        "model": "scout",
        "usage": {"input_tokens": 100, "output_tokens": 20},
        "num_turns": 3,
        "duration_seconds": 12.5,
    }
    for key, want in expected.items():
        assert actual[key] == want, key


def test_parse_omp_counts_turns() -> None:
    lines = [
        json.dumps({"type": "session", "id": "sess-1"}),
        json.dumps(
            {
                "type": "turn_end",
                "usage": {"input_tokens": 5, "output_tokens": 7},
                "message": {"content": [{"type": "text", "text": "hello"}]},
            }
        ),
        json.dumps(
            {
                "type": "turn_end",
                "message": {"content": [{"type": "text", "text": "world"}]},
            }
        ),
    ]
    parsed, session_id, meta = _parse_omp_output("\n".join(lines), model="omp-x")
    actual = {
        "num_turns": meta["num_turns"],
        "usage": meta["usage"],
        "model": meta["model"],
        "session_id": session_id,
    }
    expected = {
        "num_turns": 2,
        "usage": {"input_tokens": 5, "output_tokens": 7},
        "model": "omp-x",
        "session_id": "sess-1",
    }
    for key, want in expected.items():
        assert actual[key] == want, key
    assert "hello" in parsed.summary


def test_parse_agy_coerces_bad_types() -> None:
    envelope = {
        "usage": "not-a-dict",
        "num_turns": "x",
        "duration_seconds": "bad",
        "structured_output": {"status": "completed", "summary": "ok"},
    }
    _parsed, _conv, meta = _parse_agy_output(json.dumps(envelope), model=None)
    assert meta["usage"] == {}
    assert meta["num_turns"] == 0
    assert meta["duration_seconds"] == 0.0


def test_persist_model_record_rejects_unsafe_job_id() -> None:
    with pytest.raises(ValueError):
        _persist_model_record("../etc", {"model": None}, "", scrub=True)


def test_persist_model_record_writes_0600(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("JOB_DB_PATH", str(tmp_path / "jobs.db"))
    path = _persist_model_record(
        "job_abc123", {"model": "m", "usage": {}}, "raw secret ghp_xxx", scrub=True
    )
    p = Path(path)
    assert p.exists()
    mode = stat.S_IMODE(os.stat(p).st_mode)
    assert mode == 0o600
    data = json.loads(p.read_text(encoding="utf-8"))
    assert data.get("job_id") == "job_abc123"
    assert "raw_stdout" in data


def test_persist_job_log_scrubs_secret(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("JOB_DB_PATH", str(tmp_path / "jobs.db"))
    token = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij"
    path = _persist_job_log("job_x", 1, f"token {token}", "")
    content = Path(path).read_text(encoding="utf-8")
    assert token not in content
    assert "[REDACTED" in content


def test_heartbeat_initialised_at_start(monkeypatch) -> None:
    monkeypatch.setattr(pr_worker, "_JOB_HEARTBEAT", {})
    pr_worker._mark_alive("job_hb")
    assert "job_hb" in pr_worker._JOB_HEARTBEAT


def test_persist_job_log_chmod_0600(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("JOB_DB_PATH", str(tmp_path / "jobs.db"))
    path = _persist_job_log("job_chmod", 0, "out", "err")
    p = Path(path)
    assert stat.S_IMODE(p.stat().st_mode) == 0o600


def test_dispatch_job_scrubs_command(tmp_path: Path, monkeypatch) -> None:
    from agent import job_store

    monkeypatch.setenv("JOB_DB_PATH", str(tmp_path / "jobs.db"))
    job_store.init_db()
    job_store._RUNNING_TASKS.clear()
    token = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij"

    async def _noop(*_a, **_k):
        return None

    monkeypatch.setattr(job_store, "_run_job_coroutine", _noop)

    async def _drive():
        return job_store.dispatch_job(
            repo="acme/widget",
            persona="scout",
            command=f"please use token {token}",
        )

    import asyncio

    result = asyncio.run(_drive())
    job_id = result["job_id"]
    with job_store._conn() as conn:
        row = conn.execute(
            "SELECT command FROM jobs WHERE job_id = ?", (job_id,)
        ).fetchone()
    assert row is not None
    assert token not in row["command"]
    job_store._RUNNING_TASKS.clear()
