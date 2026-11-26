from __future__ import annotations

import logging
import re
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import IO, Any, cast

import logfire
from opentelemetry.sdk.trace.export import (
    BatchSpanProcessor,
    ConsoleSpanExporter,
    SimpleSpanProcessor,
)

_SECRET_PATH_RE = re.compile(r"(/gemini/)[^/?\s\"']+")
_BEARER_RE = re.compile(r"(Bearer\s+)[A-Za-z0-9._\-]+", re.IGNORECASE)
_GH_PAT_RE = re.compile(r"(gh[pousr]_[A-Za-z0-9_]+|github_pat_[A-Za-z0-9_]+)")
# Query-string tokens, e.g. ?access_token=… or ?token=…
_QUERY_TOKEN_RE = re.compile(
    r"([?&](?:access_|refresh_|id_)?token=)[^&\s\"']+", re.IGNORECASE
)
# Bare JWTs: three base64url segments separated by dots (header.payload.signature)
_JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b")
# key=value secret attributes: password=, secret=, token= (optionally quoted)
_KV_SECRET_RE = re.compile(
    r"\b(password|secret|token)(\s*[=:]\s*)(?:\"[^\"]*\"|'[^']*'|[^\s&\"']+)",
    re.IGNORECASE,
)


def scrub_telemetry_text(text: str) -> str:
    """Redact MCP secret paths, Bearer tokens, GitHub PATs, query-string tokens,
    bare JWTs, and password/secret/token key=value attributes from telemetry."""
    out = _SECRET_PATH_RE.sub(r"\1[REDACTED]", text)
    out = _BEARER_RE.sub(r"\1[REDACTED]", out)
    out = _GH_PAT_RE.sub("[REDACTED_GH_TOKEN]", out)
    out = _QUERY_TOKEN_RE.sub(r"\1[REDACTED]", out)
    out = _JWT_RE.sub("[REDACTED]", out)
    out = _KV_SECRET_RE.sub(r"\1\2[REDACTED]", out)
    return out


class RotatingJSONLStream:
    """File-like stream backed by RotatingFileHandler (bounded disk usage)."""

    def __init__(
        self, log_path: Path, max_bytes: int = 10_485_760, backup_count: int = 5
    ) -> None:
        log_path.parent.mkdir(parents=True, exist_ok=True)
        self._handler = RotatingFileHandler(
            filename=str(log_path),
            maxBytes=max_bytes,
            backupCount=backup_count,
            encoding="utf-8",
        )

    def write(self, data: str) -> int:
        if not data:
            return 0
        record = logging.LogRecord(
            name="telemetry",
            level=logging.INFO,
            pathname="",
            lineno=0,
            msg=data.rstrip("\n"),
            args=(),
            exc_info=None,
        )
        self._handler.emit(record)
        return len(data)

    def flush(self) -> None:
        self._handler.flush()

    def close(self) -> None:
        self._handler.close()


def format_scrubbed_span(span: Any) -> str:
    return scrub_telemetry_text(span.to_json(indent=None)) + "\n"


_CONFIGURED = False


def configure_telemetry(
    app: Any | None = None,
    *,
    log_path: Path = Path("data/logs/traces.jsonl"),
    use_simple_processor: bool = False,
) -> RotatingJSONLStream:
    """Configure local-only Logfire writing scrubbed JSONL spans to rotating disk.

    Idempotent: only the first call configures logfire and instruments FastAPI/httpx.
    Subsequent calls return a fresh stream bound to the same exporter but do NOT
    re-run logfire.configure or re-instrument (avoids "already instrumented" errors
    and leaked file handles on repeated TestClient/lifespan entry).
    """
    global _CONFIGURED
    stream = RotatingJSONLStream(log_path=log_path)
    exporter = ConsoleSpanExporter(
        out=cast(IO[str], stream), formatter=format_scrubbed_span
    )
    processor = (
        SimpleSpanProcessor(exporter)
        if use_simple_processor
        else BatchSpanProcessor(exporter)
    )

    if not _CONFIGURED:
        logfire.configure(
            send_to_logfire=False,
            console=False,
            # Disable logfire's built-in scrubber; redaction is handled by
            # format_scrubbed_span/scrub_telemetry_text to produce our [REDACTED] markers.
            scrubbing=False,
            additional_span_processors=[processor],
        )
        if app is not None:
            logfire.instrument_fastapi(app)
        logfire.instrument_httpx()
        _CONFIGURED = True
    return stream
