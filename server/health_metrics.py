from __future__ import annotations

import logging
import shutil
import sqlite3
from threading import Lock

from fastapi import APIRouter
from fastapi.responses import JSONResponse, PlainTextResponse

from agent.job_store import _conn, detect_stale_jobs
from agent.workspace import get_workspaces_dir

logger = logging.getLogger(__name__)

router = APIRouter()

_COUNTER_LOCK = Lock()
_WEBHOOK_REJECTIONS: dict[str, int] = {}


def inc_webhook_rejection(reason: str) -> None:
    with _COUNTER_LOCK:
        _WEBHOOK_REJECTIONS[reason] = _WEBHOOK_REJECTIONS.get(reason, 0) + 1


def _get_job_counts() -> dict[str, int]:
    counts: dict[str, int] = {}
    with _conn() as conn:
        for row in conn.execute(
            "SELECT status, COUNT(*) AS cnt FROM jobs GROUP BY status"
        ).fetchall():
            counts[str(row["status"])] = int(row["cnt"])
    return counts


@router.get("/health")
def health_check() -> JSONResponse:
    """Check SQLite connectivity and workspace disk headroom."""
    db_ok = True
    job_counts: dict[str, int] = {}
    try:
        job_counts = _get_job_counts()
    except (sqlite3.Error, OSError) as exc:
        logger.warning("health_check: job count query failed: %s", exc)
        db_ok = False

    ws_dir = get_workspaces_dir()
    ws_dir.mkdir(parents=True, exist_ok=True)
    disk = shutil.disk_usage(ws_dir)
    free_mb = round(disk.free / (1024 * 1024), 1)

    status_code = 200 if (db_ok and free_mb >= 256.0) else 503
    return JSONResponse(
        status_code=status_code,
        content={
            "status": "ok" if status_code == 200 else "degraded",
            "db_ok": db_ok,
            "workspaces_free_mb": free_mb,
            "jobs": job_counts,
        },
    )


def _job_count_lines() -> list[str]:
    lines: list[str] = []
    try:
        counts = _get_job_counts()
    except (sqlite3.Error, OSError) as exc:
        logger.warning("prometheus_metrics: job count query failed: %s", exc)
        return lines
    lines.append("# HELP pr_agent_jobs_total Total jobs by status")
    lines.append("# TYPE pr_agent_jobs_total gauge")
    for status, cnt in sorted(counts.items()):
        lines.append(f'pr_agent_jobs_total{{status="{status}"}} {cnt}')
    return lines


def _workspace_free_lines() -> list[str]:
    lines: list[str] = []
    try:
        ws_dir = get_workspaces_dir()
        ws_dir.mkdir(parents=True, exist_ok=True)
        free_bytes = shutil.disk_usage(ws_dir).free
    except OSError as exc:
        logger.warning("prometheus_metrics: disk usage failed: %s", exc)
        return lines
    lines.append(
        "# HELP pr_agent_workspaces_free_bytes Free disk bytes in workspaces dir"
    )
    lines.append("# TYPE pr_agent_workspaces_free_bytes gauge")
    lines.append(f"pr_agent_workspaces_free_bytes {free_bytes}")
    return lines


def _webhook_rejection_lines() -> list[str]:
    lines = [
        "# HELP pr_agent_webhook_rejections_total Rejected webhooks by reason",
        "# TYPE pr_agent_webhook_rejections_total counter",
    ]
    with _COUNTER_LOCK:
        for reason, cnt in sorted(_WEBHOOK_REJECTIONS.items()):
            lines.append(
                f'pr_agent_webhook_rejections_total{{reason="{reason}"}} {cnt}'
            )
    return lines


def _stale_job_lines() -> list[str]:
    lines: list[str] = []
    try:
        stale = detect_stale_jobs()
    except (sqlite3.Error, OSError) as exc:
        logger.warning("prometheus_metrics: stale job query failed: %s", exc)
        return lines
    lines.append("# HELP pr_agent_stale_jobs Running jobs with no recent heartbeat")
    lines.append("# TYPE pr_agent_stale_jobs gauge")
    lines.append(f"pr_agent_stale_jobs {len(stale)}")
    return lines


@router.get("/metrics", response_class=PlainTextResponse)
def prometheus_metrics() -> PlainTextResponse:
    """Expose Prometheus text-format metrics without external dependencies."""
    lines: list[str] = []
    lines.extend(_job_count_lines())
    lines.extend(_workspace_free_lines())
    lines.extend(_webhook_rejection_lines())
    lines.extend(_stale_job_lines())
    return PlainTextResponse(
        "\n".join(lines) + "\n", media_type="text/plain; version=0.0.4"
    )
