"""Process-wide AuditLogger instance.

A single logger is shared by the worker, the job store, and the server so the
background writer task, its executor, and its SQLite connection are created
once and closed once (on lifespan shutdown) instead of leaking per job.
"""

from __future__ import annotations

from src.orchestrator.middleware.audit import AuditLogger

_logger: AuditLogger | None = None


def get_audit_logger() -> AuditLogger:
    """Return the shared logger, creating it on first use."""
    global _logger
    if _logger is None:
        _logger = AuditLogger()
    return _logger


async def close_audit_logger() -> None:
    """Close the shared logger if it was created."""
    global _logger
    if _logger is not None:
        await _logger.close()
        _logger = None
