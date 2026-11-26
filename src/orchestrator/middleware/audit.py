from __future__ import annotations

import asyncio
import hashlib
import json
import os
import sqlite3
import threading
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path
from types import TracebackType
from typing import Any, Self

import structlog

logger = structlog.get_logger(__name__)

GENESIS_HASH: str = "0" * 64
DEFAULT_AUDIT_DB_PATH = Path("data/audit.db")


def _get_default_audit_db_path() -> Path:
    return Path(os.getenv("AUDIT_DB_PATH", str(DEFAULT_AUDIT_DB_PATH)))


def canonical_json(data: Any) -> str:
    """Serialize data to a deterministic, compact JSON string with sorted keys."""
    return json.dumps(data, separators=(",", ":"), sort_keys=True)


def compute_payload_hash(payload: Any) -> str:
    """Compute SHA-256 hash of arbitrary payload data."""
    if isinstance(payload, bytes):
        raw = payload
    elif isinstance(payload, str):
        raw = payload.encode("utf-8")
    else:
        raw = canonical_json(payload).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def compute_entry_hash(
    prev_hash: str,
    timestamp: str,
    tool: str,
    repo: str,
    caller_identity: str,
    payload_hash: str,
    duration_ms: int,
    redaction_counts: Any,
) -> str:
    """Compute SHA-256 hash across canonical JSON array of all 8 audit fields.

    entry_hash = SHA256(canonical_json([
        prev_hash, timestamp, tool, repo, caller_identity, payload_hash, duration_ms, redaction_counts
    ]))
    """
    normalized_counts = redaction_counts
    if isinstance(redaction_counts, str):
        try:
            normalized_counts = json.loads(redaction_counts)
        except (json.JSONDecodeError, TypeError):
            normalized_counts = redaction_counts
    elif redaction_counts is None:
        normalized_counts = {}

    array = [
        prev_hash,
        timestamp,
        tool,
        repo,
        caller_identity,
        payload_hash,
        duration_ms,
        normalized_counts,
    ]
    serialized = canonical_json(array)
    return hashlib.sha256(serialized.encode("utf-8")).hexdigest()


def configure_sqlite_connection(conn: sqlite3.Connection) -> None:
    """Apply performance, concurrency, and WAL mode pragmas."""
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA synchronous=NORMAL;")
    conn.execute("PRAGMA busy_timeout=30000;")


def get_connection(db_path: Path | str | None = None) -> sqlite3.Connection:
    """Open a new SQLite connection with WAL mode and row factory."""
    path = Path(db_path) if db_path is not None else _get_default_audit_db_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path, timeout=30.0)
    conn.row_factory = sqlite3.Row
    configure_sqlite_connection(conn)
    return conn


def init_db(db_path: Path | str | None = None) -> None:
    """Initialize the 3 shared tables: audit_log, verification_verdicts, and strike_counts."""
    conn = get_connection(db_path)
    try:
        with conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS audit_log (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    tool TEXT NOT NULL,
                    repo TEXT NOT NULL,
                    caller_identity TEXT NOT NULL,
                    payload_hash TEXT NOT NULL,
                    prev_hash TEXT NOT NULL,
                    entry_hash TEXT NOT NULL,
                    duration_ms INTEGER NOT NULL,
                    redaction_counts TEXT NOT NULL
                );
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS verification_verdicts (
                    repo TEXT NOT NULL,
                    branch TEXT NOT NULL,
                    head_commit_sha TEXT NOT NULL,
                    checks_passed INTEGER NOT NULL,
                    security_verdict TEXT NOT NULL,
                    timestamp TEXT NOT NULL,
                    PRIMARY KEY(repo, branch, head_commit_sha)
                );
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS strike_counts (
                    repo TEXT NOT NULL,
                    branch TEXT NOT NULL,
                    strikes INTEGER NOT NULL,
                    last_failure_timestamp TEXT NOT NULL,
                    PRIMARY KEY(repo, branch)
                );
                """
            )
    finally:
        conn.close()


@dataclass(frozen=True)
class AuditEntry:
    id: int
    timestamp: str
    tool: str
    repo: str
    caller_identity: str
    payload_hash: str
    prev_hash: str
    entry_hash: str
    duration_ms: int
    redaction_counts: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class AuditLogger:
    """Thread-safe and async-safe audit logger with WAL mode and dedicated writer."""

    def __init__(self, db_path: Path | str | None = None) -> None:
        self.db_path = (
            Path(db_path) if db_path is not None else _get_default_audit_db_path()
        )
        self._queue: (
            asyncio.Queue[tuple[dict[str, Any], asyncio.Future[AuditEntry]] | None]
            | None
        ) = None
        self._writer_task: asyncio.Task[None] | None = None
        self._executor: ThreadPoolExecutor | None = None
        self._conn: sqlite3.Connection | None = None
        self._last_entry_hash: str | None = None
        self._sync_lock = threading.Lock()
        self._loop: asyncio.AbstractEventLoop | None = None
        self._closed: bool = False

    def init_db(self) -> None:
        init_db(self.db_path)

    def _ensure_writer_started(self) -> None:
        if self._closed:
            raise RuntimeError("AuditLogger is closed")
        loop = asyncio.get_running_loop()
        if (
            self._writer_task is not None
            and not self._writer_task.done()
            and self._loop is loop
        ):
            return
        self._start_writer(loop)

    def _start_writer(self, loop: asyncio.AbstractEventLoop) -> None:
        self.init_db()
        self._loop = loop
        self._queue = asyncio.Queue()
        if self._executor is None:
            self._executor = ThreadPoolExecutor(
                max_workers=1, thread_name_prefix="audit_db_writer"
            )
        self._writer_task = loop.create_task(self._writer_loop())

    async def _writer_loop(self) -> None:
        assert self._queue is not None
        assert self._executor is not None
        loop = asyncio.get_running_loop()

        def _init_thread_conn() -> tuple[sqlite3.Connection, str]:
            conn = get_connection(self.db_path)
            cursor = conn.execute(
                "SELECT entry_hash FROM audit_log ORDER BY id DESC LIMIT 1;"
            )
            row = cursor.fetchone()
            last_hash = row["entry_hash"] if row else GENESIS_HASH
            return conn, last_hash

        # Initialize connection strictly in background worker thread
        self._conn, self._last_entry_hash = await loop.run_in_executor(
            self._executor, _init_thread_conn
        )

        try:
            await self._drain_queue(loop)
        finally:
            await self._close_writer_conn(loop)

    async def _drain_queue(self, loop: asyncio.AbstractEventLoop) -> None:
        assert self._queue is not None
        assert self._executor is not None
        while True:
            item = await self._queue.get()
            if item is None:
                self._queue.task_done()
                break
            await self._process_queue_item(loop, item)

    async def _process_queue_item(
        self,
        loop: asyncio.AbstractEventLoop,
        item: tuple[dict[str, Any], asyncio.Future[AuditEntry]],
    ) -> None:
        assert self._queue is not None
        assert self._executor is not None
        event_data, fut = item
        try:
            # Execute synchronous SQLite I/O off the asyncio event loop
            entry = await loop.run_in_executor(
                self._executor, self._write_entry_sync, event_data, self._conn
            )
            self._resolve_future(fut, result=entry)
        except (sqlite3.Error, OSError, ValueError, RuntimeError) as exc:
            logger.error("Audit log write error", error=str(exc))
            self._resolve_future(fut, error=exc)
        finally:
            self._queue.task_done()

    @staticmethod
    def _resolve_future(
        fut: asyncio.Future[AuditEntry],
        *,
        result: AuditEntry | None = None,
        error: BaseException | None = None,
    ) -> None:
        if fut.done():
            return
        if error is not None:
            fut.set_exception(error)
        elif result is not None:
            fut.set_result(result)

    async def _close_writer_conn(self, loop: asyncio.AbstractEventLoop) -> None:
        if not self._conn:
            return
        assert self._executor is not None
        conn_to_close = self._conn
        self._conn = None
        await loop.run_in_executor(self._executor, conn_to_close.close)

    def _write_entry_sync(
        self,
        event_data: dict[str, Any],
        conn: sqlite3.Connection | None = None,
    ) -> AuditEntry:
        target_conn, should_close = self._resolve_write_conn(conn)
        try:
            with self._sync_lock:
                return self._write_entry_locked(target_conn, event_data)
        finally:
            if should_close and target_conn is not None:
                target_conn.close()

    def _resolve_write_conn(
        self, conn: sqlite3.Connection | None
    ) -> tuple[sqlite3.Connection, bool]:
        if conn is not None:
            return conn, False
        return get_connection(self.db_path), True

    def _write_entry_locked(
        self, target_conn: sqlite3.Connection, event_data: dict[str, Any]
    ) -> AuditEntry:
        if self._last_entry_hash is None:
            self._last_entry_hash = self._load_last_entry_hash(target_conn)

        prev_hash = self._last_entry_hash
        timestamp = event_data.get("timestamp") or datetime.now(UTC).isoformat()
        tool = event_data["tool"]
        repo = event_data["repo"]
        caller_identity = event_data["caller_identity"]
        payload_hash = event_data["payload_hash"]
        duration_ms = int(event_data["duration_ms"])
        redaction_counts = event_data.get("redaction_counts", {})

        entry_hash = compute_entry_hash(
            prev_hash=prev_hash,
            timestamp=timestamp,
            tool=tool,
            repo=repo,
            caller_identity=caller_identity,
            payload_hash=payload_hash,
            duration_ms=duration_ms,
            redaction_counts=redaction_counts,
        )

        stored_redaction = (
            canonical_json(redaction_counts)
            if isinstance(redaction_counts, (dict, list))
            else str(redaction_counts)
        )

        entry_id = self._insert_entry(
            target_conn,
            (
                timestamp,
                tool,
                repo,
                caller_identity,
                payload_hash,
                prev_hash,
                entry_hash,
                duration_ms,
                stored_redaction,
            ),
        )

        self._last_entry_hash = entry_hash

        return AuditEntry(
            id=entry_id,
            timestamp=timestamp,
            tool=tool,
            repo=repo,
            caller_identity=caller_identity,
            payload_hash=payload_hash,
            prev_hash=prev_hash,
            entry_hash=entry_hash,
            duration_ms=duration_ms,
            redaction_counts=stored_redaction,
        )

    def _load_last_entry_hash(self, target_conn: sqlite3.Connection) -> str:
        cursor = target_conn.execute(
            "SELECT entry_hash FROM audit_log ORDER BY id DESC LIMIT 1;"
        )
        row = cursor.fetchone()
        return row["entry_hash"] if row else GENESIS_HASH

    def _insert_entry(
        self, target_conn: sqlite3.Connection, row: tuple[Any, ...]
    ) -> int:
        with target_conn:
            cursor = target_conn.execute(
                """
                INSERT INTO audit_log (
                    timestamp, tool, repo, caller_identity,
                    payload_hash, prev_hash, entry_hash, duration_ms, redaction_counts
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);
                """,
                row,
            )
            entry_id = cursor.lastrowid
            if entry_id is None:
                raise RuntimeError(
                    "Failed to retrieve lastrowid after audit log insert"
                )
        return entry_id

    @staticmethod
    def _resolve_payload_hash(payload_hash: str | None, payload: Any) -> str:
        if payload_hash is not None:
            return payload_hash
        if payload is None:
            raise ValueError("Either payload_hash or payload must be provided")
        return compute_payload_hash(payload)

    async def log_event(
        self,
        tool: str,
        repo: str,
        caller_identity: str,
        duration_ms: int,
        payload_hash: str | None = None,
        payload: Any = None,
        redaction_counts: Any = None,
        timestamp: str | None = None,
    ) -> AuditEntry:
        """Asynchronously record an audit event through the dedicated writer queue."""
        payload_hash = self._resolve_payload_hash(payload_hash, payload)

        self._ensure_writer_started()
        assert self._queue is not None
        assert self._loop is not None

        fut: asyncio.Future[AuditEntry] = self._loop.create_future()
        event_data: dict[str, Any] = {
            "tool": tool,
            "repo": repo,
            "caller_identity": caller_identity,
            "payload_hash": payload_hash,
            "duration_ms": duration_ms,
            "redaction_counts": redaction_counts
            if redaction_counts is not None
            else {},
            "timestamp": timestamp,
        }

        await self._queue.put((event_data, fut))
        return await fut

    def log_sync(
        self,
        tool: str,
        repo: str,
        caller_identity: str,
        duration_ms: int,
        payload_hash: str | None = None,
        payload: Any = None,
        redaction_counts: Any = None,
        timestamp: str | None = None,
    ) -> AuditEntry:
        """Synchronously record an audit event."""
        if payload_hash is None:
            if payload is None:
                raise ValueError("Either payload_hash or payload must be provided")
            payload_hash = compute_payload_hash(payload)

        self.init_db()
        event_data: dict[str, Any] = {
            "tool": tool,
            "repo": repo,
            "caller_identity": caller_identity,
            "payload_hash": payload_hash,
            "duration_ms": duration_ms,
            "redaction_counts": redaction_counts
            if redaction_counts is not None
            else {},
            "timestamp": timestamp,
        }
        return self._write_entry_sync(event_data)

    def record_verification_verdict(
        self,
        repo: str,
        branch: str,
        head_commit_sha: str,
        checks_passed: bool | int | None = None,
        security_verdict: str | None = None,
        timestamp: str | None = None,
    ) -> None:
        """Record or update a verification verdict in verification_verdicts without clobbering.

        Independent verdicts from the checks runner and security-reviewer are merged
        using COALESCE so whichever arrives second does not wipe out the first verdict.
        """
        self.init_db()
        ts = timestamp or datetime.now(UTC).isoformat()
        passed_val = (1 if checks_passed else 0) if checks_passed is not None else None
        conn = get_connection(self.db_path)
        try:
            with conn:
                conn.execute(
                    """
                    INSERT INTO verification_verdicts (
                        repo, branch, head_commit_sha, checks_passed, security_verdict, timestamp
                    ) VALUES (
                        ?, ?, ?,
                        COALESCE(?, 0),
                        COALESCE(?, 'PENDING'),
                        ?
                    )
                    ON CONFLICT(repo, branch, head_commit_sha) DO UPDATE SET
                        checks_passed = CASE
                            WHEN ? IS NOT NULL THEN excluded.checks_passed
                            ELSE verification_verdicts.checks_passed
                        END,
                        security_verdict = CASE
                            WHEN ? IS NOT NULL THEN excluded.security_verdict
                            ELSE verification_verdicts.security_verdict
                        END,
                        timestamp = excluded.timestamp;
                    """,
                    (
                        repo,
                        branch,
                        head_commit_sha,
                        passed_val,
                        security_verdict,
                        ts,
                        passed_val,
                        security_verdict,
                    ),
                )
        finally:
            conn.close()

    def record_checks_verdict(
        self,
        repo: str,
        branch: str,
        head_commit_sha: str,
        checks_passed: bool | int,
        timestamp: str | None = None,
    ) -> None:
        """Record checks runner verdict without touching security_verdict."""
        self.record_verification_verdict(
            repo=repo,
            branch=branch,
            head_commit_sha=head_commit_sha,
            checks_passed=checks_passed,
            security_verdict=None,
            timestamp=timestamp,
        )

    def record_security_verdict(
        self,
        repo: str,
        branch: str,
        head_commit_sha: str,
        security_verdict: str,
        timestamp: str | None = None,
    ) -> None:
        """Record security reviewer verdict without touching checks_passed."""
        self.record_verification_verdict(
            repo=repo,
            branch=branch,
            head_commit_sha=head_commit_sha,
            checks_passed=None,
            security_verdict=security_verdict,
            timestamp=timestamp,
        )

    def get_verification_verdict(
        self,
        repo: str,
        branch: str,
        head_commit_sha: str,
    ) -> dict[str, Any] | None:
        """Retrieve verification verdict for a given repo, branch, and commit."""
        self.init_db()
        conn = get_connection(self.db_path)
        try:
            cursor = conn.execute(
                """
                SELECT repo, branch, head_commit_sha, checks_passed, security_verdict, timestamp
                FROM verification_verdicts
                WHERE repo = ? AND branch = ? AND head_commit_sha = ?
                """,
                (repo, branch, head_commit_sha),
            )
            row = cursor.fetchone()
            if not row:
                return None
            return {
                "repo": row["repo"],
                "branch": row["branch"],
                "head_commit_sha": row["head_commit_sha"],
                "checks_passed": bool(row["checks_passed"]),
                "security_verdict": row["security_verdict"],
                "timestamp": row["timestamp"],
            }
        finally:
            conn.close()

    def record_strike(
        self,
        repo: str,
        branch: str,
        strikes: int | None = None,
        timestamp: str | None = None,
    ) -> int:
        """Increment or set strike count for a given repo and branch atomically.

        Uses composite PRIMARY KEY(repo, branch) with atomic UPSERT to prevent
        cross-repo collisions on common branch names (e.g. 'main', 'fix/auth') and
        eliminate read-then-write race conditions.
        """
        self.init_db()
        ts = timestamp or datetime.now(UTC).isoformat()
        conn = get_connection(self.db_path)
        try:
            with conn:
                if strikes is None:
                    return self._increment_strike(conn, repo, branch, ts)
                return self._set_strike(conn, repo, branch, strikes, ts)
        finally:
            conn.close()

    def _increment_strike(
        self, conn: sqlite3.Connection, repo: str, branch: str, ts: str
    ) -> int:
        cursor = conn.execute(
            """
            INSERT INTO strike_counts (repo, branch, strikes, last_failure_timestamp)
            VALUES (?, ?, 1, ?)
            ON CONFLICT(repo, branch) DO UPDATE SET
                strikes = strike_counts.strikes + 1,
                last_failure_timestamp = excluded.last_failure_timestamp
            RETURNING strikes;
            """,
            (repo, branch, ts),
        )
        row = cursor.fetchone()
        return int(row[0]) if row else 1

    def _set_strike(
        self, conn: sqlite3.Connection, repo: str, branch: str, strikes: int, ts: str
    ) -> int:
        cursor = conn.execute(
            """
            INSERT INTO strike_counts (repo, branch, strikes, last_failure_timestamp)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(repo, branch) DO UPDATE SET
                strikes = excluded.strikes,
                last_failure_timestamp = excluded.last_failure_timestamp
            RETURNING strikes;
            """,
            (repo, branch, strikes, ts),
        )
        row = cursor.fetchone()
        return int(row[0]) if row else strikes

    def get_strikes(self, repo: str, branch: str) -> int:
        """Get the strike count for a repo and branch."""
        self.init_db()
        conn = get_connection(self.db_path)
        try:
            cursor = conn.execute(
                "SELECT strikes FROM strike_counts WHERE repo = ? AND branch = ?",
                (repo, branch),
            )
            row = cursor.fetchone()
            return int(row["strikes"]) if row else 0
        finally:
            conn.close()

    def reset_strikes(self, repo: str, branch: str) -> None:
        """Reset the strike count for a repo and branch."""
        self.init_db()
        conn = get_connection(self.db_path)
        try:
            with conn:
                conn.execute(
                    "DELETE FROM strike_counts WHERE repo = ? AND branch = ?",
                    (repo, branch),
                )
        finally:
            conn.close()

    def verify_chain(self) -> bool:
        """Verify unbroken cryptographic linkage of the audit log."""
        return verify_audit_chain(self.db_path)

    def export_jsonl(self, output_path: Path | str) -> int:
        """Export audit log entries to JSONL."""
        return export_jsonl(output_path, self.db_path)

    async def close(self) -> None:
        """Gracefully shut down background writer."""
        self._closed = True
        await self._shutdown_writer()
        if self._executor is not None:
            self._executor.shutdown(wait=True)
            self._executor = None

    async def _shutdown_writer(self) -> None:
        if self._writer_task and not self._writer_task.done():
            if self._queue is not None:
                await self._queue.put(None)
                await self._writer_task
            return
        if self._conn:
            self._conn.close()
            self._conn = None

    async def __aenter__(self) -> Self:
        self._ensure_writer_started()
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> None:
        await self.close()


def _verify_chain_row(row: sqlite3.Row, expected_prev_hash: str) -> bool:
    row_id = row["id"]
    timestamp = row["timestamp"]
    tool = row["tool"]
    repo = row["repo"]
    caller_identity = row["caller_identity"]
    payload_hash = row["payload_hash"]
    prev_hash = row["prev_hash"]
    entry_hash = row["entry_hash"]
    duration_ms = row["duration_ms"]
    redaction_counts = row["redaction_counts"]

    if prev_hash != expected_prev_hash:
        logger.error(
            "Audit chain broken: prev_hash mismatch",
            row_id=row_id,
            expected=expected_prev_hash,
            actual=prev_hash,
        )
        return False

    computed_hash = compute_entry_hash(
        prev_hash=prev_hash,
        timestamp=timestamp,
        tool=tool,
        repo=repo,
        caller_identity=caller_identity,
        payload_hash=payload_hash,
        duration_ms=duration_ms,
        redaction_counts=redaction_counts,
    )

    if computed_hash != entry_hash:
        logger.error(
            "Audit chain broken: entry_hash mismatch",
            row_id=row_id,
            expected=computed_hash,
            actual=entry_hash,
        )
        return False

    return True


def verify_audit_chain(db_path: Path | str | None = None) -> bool:
    """Traverse audit_log sequentially and validate unbroken cryptographic linkage.

    Iterates directly over the cursor without buffering all rows into RAM.
    Returns True if entire chain is cryptographically intact and unbroken.
    Returns False if any entry_hash, prev_hash, or field mismatch is detected.
    """
    path = Path(db_path) if db_path is not None else _get_default_audit_db_path()
    if not path.exists():
        return True

    conn = get_connection(path)
    try:
        cursor = conn.execute("SELECT * FROM audit_log ORDER BY id ASC")
        expected_prev_hash = GENESIS_HASH

        for row in cursor:
            if not _verify_chain_row(row, expected_prev_hash):
                return False
            expected_prev_hash = row["entry_hash"]

        return True
    finally:
        conn.close()


def _decode_export_row(row: sqlite3.Row) -> dict[str, Any]:
    row_dict = dict(row)
    if isinstance(row_dict.get("redaction_counts"), str):
        try:
            row_dict["redaction_counts"] = json.loads(row_dict["redaction_counts"])
        except (json.JSONDecodeError, TypeError):
            logger.debug("Non-JSON redaction_counts preserved as string")
    return row_dict


def export_jsonl(output_path: Path | str, db_path: Path | str | None = None) -> int:
    """Stream audit entries out to a JSONL file on demand.

    SQLite remains the single source of truth; no live dual-writing.
    Returns number of exported records.
    """
    out = Path(output_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    conn = get_connection(db_path)
    count = 0
    try:
        cursor = conn.execute("SELECT * FROM audit_log ORDER BY id ASC")
        with open(out, "w", encoding="utf-8") as f:
            for row in cursor:
                f.write(canonical_json(_decode_export_row(row)) + "\n")
                count += 1
        return count
    finally:
        conn.close()
