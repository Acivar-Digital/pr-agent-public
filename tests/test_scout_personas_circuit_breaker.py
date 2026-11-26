from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from agent.job_store import _conn, check_circuit_breaker, dispatch_job, init_db
from agent.personas import AgentPersona, discover_personas, load_persona
from agent.pr_worker import PRTaskReport, _parse_omp_output


def _assert_expected_personas(names: set[str]) -> None:
    assert "scout" in names
    assert "security-reviewer" in names


def _assert_persona_identity(p: dict[str, Any]) -> None:
    assert p.get("name")
    assert p.get("role")
    assert p.get("description")


def _assert_persona_routing(p: dict[str, Any]) -> None:
    assert p.get("when_to_use")
    assert p.get("mode") in ("plan", "auto")


def _assert_scout_metadata(scout_meta: dict[str, Any]) -> None:
    assert scout_meta["mode"] == "plan"
    assert "Fast Codebase & PR Scout" in scout_meta["role"]


def _assert_omp_persona(persona: AgentPersona) -> None:
    assert persona.runner == "omp"
    assert persona.model == "lr-fse-scout/scout"
    assert persona.allow_writes is False


def _assert_security_persona(sec_persona: AgentPersona) -> None:
    assert sec_persona.runner == "agy"
    assert sec_persona.model is None  # 'default' resolved to fallback default_model
    assert sec_persona.allow_writes is False


@pytest.mark.anyio
async def test_scout_persona_metadata_and_runner():
    init_db()
    personas = await discover_personas(repo="example-org/sample-repo")
    names = {p["name"] for p in personas}
    _assert_expected_personas(names)

    # Verify all 4 personas declare complete capability metadata
    for p in personas:
        _assert_persona_identity(p)
        _assert_persona_routing(p)

    scout_meta = next(p for p in personas if p["name"] == "scout")
    _assert_scout_metadata(scout_meta)

    persona = await load_persona(
        repo="example-org/sample-repo", persona_name="scout"
    )
    _assert_omp_persona(persona)

    sec_persona = await load_persona(
        repo="example-org/sample-repo", persona_name="security-reviewer"
    )
    _assert_security_persona(sec_persona)


def test_omp_output_parsing():
    sample_ndjson = (
        '{"type":"session","id":"test_session_123"}\n'
        '{"type":"turn_end","message":{"role":"assistant","content":[{"type":"text","text":"Line 1"},{"type":"text","text":"Line 2"}]}}\n'
    )
    parsed, session_id, _meta = _parse_omp_output(sample_ndjson)
    assert parsed.status == "completed"
    assert parsed.summary == "Line 1\nLine 2"
    assert session_id == "test_session_123"


def test_pr_task_report_failure_point():
    report = PRTaskReport(
        repo="test/repo",
        persona="scout",
        branch="agent/scout/job_1",
        status="failed",
        summary="Execution error",
        failure_point="runner_omp_execution (exit 1): 400 invalid model",
    )
    assert report.failure_point == "runner_omp_execution (exit 1): 400 invalid model"


def _seed_failed_jobs(repo: str, persona: str) -> None:
    with _conn() as conn:
        for i in range(3):
            conn.execute(
                """
                INSERT INTO jobs (job_id, repo, persona, branch, pr_number, command, status, progress_json, error, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    f"cb_job_{i}",
                    repo,
                    persona,
                    f"agent/{persona}/cb_{i}",
                    None,
                    "failing task",
                    "failed",
                    "[]",
                    f"Fatal error {i}",
                    1000.0 + i,
                    1000.0 + i,
                ),
            )


def _assert_circuit_tripped(tripped: bool, reason: str | None) -> None:
    assert tripped is True
    assert "Circuit breaker tripped: 3 consecutive failures" in (reason or "")


def _assert_dispatch_blocked(dispatch_res: dict[str, object]) -> None:
    assert dispatch_res["status"] == "circuit_breaker_tripped"
    assert dispatch_res["job_id"] is None


def test_circuit_breaker_tripping(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("JOB_DB_PATH", str(tmp_path / "test_jobs.db"))
    init_db()
    test_repo = "test-owner/test-circuit-repo"
    test_persona = "flaky-agent"

    # Initially not tripped
    tripped, _ = check_circuit_breaker(test_repo, test_persona, None)
    assert tripped is False

    # Simulate 3 consecutive failed jobs in DB
    _seed_failed_jobs(test_repo, test_persona)

    tripped, reason = check_circuit_breaker(test_repo, test_persona, None)
    _assert_circuit_tripped(tripped, reason)

    # dispatch_job should return circuit_breaker_tripped without queueing
    dispatch_res = dispatch_job(
        repo=test_repo, persona=test_persona, command="retry attempt"
    )
    _assert_dispatch_blocked(dispatch_res)
