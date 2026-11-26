"""Ticket #19: Worker phase timing breakdown on PRTaskReport."""

from __future__ import annotations

import inspect
from pathlib import Path

from agent.pr_worker import PRTaskReport, execute_pr_task


def test_pr_task_report_has_timing_defaults() -> None:
    report = PRTaskReport(
        repo="test/repo",
        persona="developer",
        branch="test-branch",
        status="completed",
        summary="Test summary",
    )
    assert report.duration_ms == 0
    assert report.phase_timings_ms == {}


def test_pr_task_report_accepts_phase_timings() -> None:
    report = PRTaskReport(
        repo="test/repo",
        persona="developer",
        branch="test-branch",
        status="completed",
        summary="Test summary",
        duration_ms=1234,
        phase_timings_ms={"git_ms": 100, "agy_ms": 1000, "static_checks_ms": 134},
    )
    dumped = report.model_dump()
    assert dumped["duration_ms"] == 1234
    assert dumped["phase_timings_ms"] == {
        "git_ms": 100,
        "agy_ms": 1000,
        "static_checks_ms": 134,
    }


def _assert_body_records_phase_timings(body: str) -> None:
    assert "git_ms" in body
    assert "agy_ms" in body
    assert "static_checks_ms" in body


def test_pr_worker_source_records_phase_timings() -> None:
    source = inspect.getsource(execute_pr_task)
    assert "phase_timings_ms" in source
    assert "time.monotonic()" in source
    # Confirm the phase captures live inside the function body region.
    file_text = Path(execute_pr_task.__code__.co_filename).read_text(encoding="utf-8")
    start = file_text.index("async def execute_pr_task")
    _assert_body_records_phase_timings(file_text[start:])
