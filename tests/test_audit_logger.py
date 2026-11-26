from __future__ import annotations

import asyncio
import json
import sqlite3
from pathlib import Path

import pytest

from src.orchestrator.middleware.audit import (
    GENESIS_HASH,
    AuditLogger,
    canonical_json,
    compute_entry_hash,
    compute_payload_hash,
    export_jsonl,
    get_connection,
    init_db,
    verify_audit_chain,
)


def test_canonical_json_key_ordering() -> None:
    dict1 = {"b": 2, "a": 1}
    dict2 = {"a": 1, "b": 2}
    assert canonical_json(dict1) == '{"a":1,"b":2}'
    assert canonical_json(dict1) == canonical_json(dict2)


def test_payload_hash_length() -> None:
    payload_hash = compute_payload_hash({"payload": "data"})
    assert len(payload_hash) == 64


def test_entry_hash_length_and_tamper_sensitivity() -> None:
    payload_hash = compute_payload_hash({"payload": "data"})
    common = {
        "prev_hash": GENESIS_HASH,
        "timestamp": "2026-11-24T12:00:00Z",
        "tool": "get_clean_pr_diff",
        "repo": "example-org/sample-repo",
        "caller_identity": "gemini-agent-1",
        "payload_hash": payload_hash,
        "redaction_counts": {"secret": 1},
    }
    entry_hash = compute_entry_hash(**common, duration_ms=42)
    assert len(entry_hash) == 64

    # Verify tampering any field changes entry_hash
    tampered_entry_hash = compute_entry_hash(**common, duration_ms=43)
    assert entry_hash != tampered_entry_hash


def test_schema_initialization(tmp_path: Path) -> None:
    db_path = tmp_path / "test_audit.db"
    init_db(db_path)

    conn = get_connection(db_path)
    try:
        tables = [
            row["name"]
            for row in conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"
            ).fetchall()
        ]
        assert "audit_log" in tables
        assert "strike_counts" in tables
        assert "verification_verdicts" in tables

        # Verify WAL mode PRAGMA
        mode = conn.execute("PRAGMA journal_mode;").fetchone()[0]
        assert mode.lower() == "wal"
    finally:
        conn.close()


def test_first_entry_links_to_genesis(tmp_path: Path) -> None:
    db_path = tmp_path / "test_audit.db"
    logger = AuditLogger(db_path=db_path)

    entry1 = logger.log_sync(
        tool="tool1",
        repo="owner/repo",
        caller_identity="caller1",
        payload={"query": "test1"},
        duration_ms=10,
        redaction_counts={"api_key": 1},
        timestamp="2026-11-24T12:00:00Z",
    )
    assert entry1.id == 1
    assert entry1.prev_hash == GENESIS_HASH
    assert len(entry1.entry_hash) == 64
    assert entry1.redaction_counts == '{"api_key":1}'


def test_second_entry_chains_to_first(tmp_path: Path) -> None:
    db_path = tmp_path / "test_audit.db"
    logger = AuditLogger(db_path=db_path)

    entry1 = logger.log_sync(
        tool="tool1",
        repo="owner/repo",
        caller_identity="caller1",
        payload={"query": "test1"},
        duration_ms=10,
    )
    entry2 = logger.log_sync(
        tool="tool2",
        repo="owner/repo",
        caller_identity="caller2",
        payload={"query": "test2"},
        duration_ms=25,
        redaction_counts={},
        timestamp="2026-11-24T12:01:00Z",
    )
    assert entry2.id == 2
    assert entry2.prev_hash == entry1.entry_hash
    assert len(entry2.entry_hash) == 64


def test_chain_verification_passes(tmp_path: Path) -> None:
    db_path = tmp_path / "test_audit.db"
    logger = AuditLogger(db_path=db_path)

    logger.log_sync(
        tool="tool1",
        repo="owner/repo",
        caller_identity="caller1",
        duration_ms=10,
        payload={"query": "1"},
    )
    logger.log_sync(
        tool="tool2",
        repo="owner/repo",
        caller_identity="caller2",
        duration_ms=20,
        payload={"query": "2"},
    )

    # Verify chain validity
    assert verify_audit_chain(db_path) is True
    assert logger.verify_chain() is True


def test_tampering_detection(tmp_path: Path) -> None:
    db_path = tmp_path / "test_audit.db"
    logger = AuditLogger(db_path=db_path)

    logger.log_sync(
        tool="tool1",
        repo="owner/repo",
        caller_identity="caller1",
        payload={"query": "1"},
        duration_ms=10,
    )
    logger.log_sync(
        tool="tool2",
        repo="owner/repo",
        caller_identity="caller2",
        payload={"query": "2"},
        duration_ms=20,
    )
    logger.log_sync(
        tool="tool3",
        repo="owner/repo",
        caller_identity="caller3",
        payload={"query": "3"},
        duration_ms=30,
    )

    assert verify_audit_chain(db_path) is True

    # 1. Tamper with prev_hash
    conn = sqlite3.connect(db_path)
    try:
        conn.execute(
            "UPDATE audit_log SET prev_hash = 'tampered_prev_hash' WHERE id = 2;"
        )
        conn.commit()
    finally:
        conn.close()

    assert verify_audit_chain(db_path) is False

    # Restore and verify passes
    init_db(db_path)


@pytest.mark.anyio
async def test_concurrent_async_logging(tmp_path: Path) -> None:
    db_path = tmp_path / "test_async_audit.db"
    async with AuditLogger(db_path=db_path) as logger:

        async def record_batch(batch_id: int) -> None:
            for i in range(10):
                await logger.log_event(
                    tool=f"batch_tool_{batch_id}",
                    repo="owner/repo",
                    caller_identity=f"caller_{batch_id}",
                    payload={"batch": batch_id, "i": i},
                    duration_ms=i,
                )

        # Run 4 batches of 10 events (40 total) concurrently
        tasks = [record_batch(b) for b in range(4)]
        await asyncio.gather(*tasks)

    # Validate that all 40 entries were sequentially recorded and cryptographically linked
    conn = get_connection(db_path)
    try:
        count = conn.execute("SELECT count(*) FROM audit_log;").fetchone()[0]
        assert count == 40
    finally:
        conn.close()

    assert verify_audit_chain(db_path) is True


def test_export_jsonl(tmp_path: Path) -> None:
    db_path = tmp_path / "test_audit.db"
    jsonl_path = tmp_path / "exported.jsonl"
    logger = AuditLogger(db_path=db_path)

    logger.log_sync(
        tool="t1", repo="r1", caller_identity="c1", duration_ms=5, payload="hello"
    )
    logger.log_sync(
        tool="t2", repo="r2", caller_identity="c2", duration_ms=10, payload="world"
    )

    exported_count = export_jsonl(jsonl_path, db_path=db_path)
    assert exported_count == 2

    lines = [
        json.loads(line)
        for line in jsonl_path.read_text(encoding="utf-8").strip().split("\n")
    ]
    assert len(lines) == 2
    assert lines[0]["tool"] == "t1"
    assert lines[1]["tool"] == "t2"


def test_strike_counts_increment_per_repo(tmp_path: Path) -> None:
    """Regression test (a): identical branch names across two repos stay isolated."""
    db_path = tmp_path / "test_strikes.db"
    logger = AuditLogger(db_path=db_path)

    # Record strikes for same branch 'fix/auth' in two different repos
    strikes_a1 = logger.record_strike(repo="org/repoA", branch="fix/auth")
    strikes_a2 = logger.record_strike(repo="org/repoA", branch="fix/auth")
    assert strikes_a1 == 1
    assert strikes_a2 == 2

    strikes_b1 = logger.record_strike(repo="org/repoB", branch="fix/auth")
    assert strikes_b1 == 1  # Must be 1, completely isolated from repoA!


def test_get_strikes_isolated_and_reset_scoped(tmp_path: Path) -> None:
    db_path = tmp_path / "test_strikes.db"
    logger = AuditLogger(db_path=db_path)

    logger.record_strike(repo="org/repoA", branch="fix/auth")
    logger.record_strike(repo="org/repoA", branch="fix/auth")
    logger.record_strike(repo="org/repoB", branch="fix/auth")

    assert logger.get_strikes("org/repoA", "fix/auth") == 2
    assert logger.get_strikes("org/repoB", "fix/auth") == 1

    # Reset repoA does not affect repoB
    logger.reset_strikes("org/repoA", "fix/auth")
    assert logger.get_strikes("org/repoA", "fix/auth") == 0
    assert logger.get_strikes("org/repoB", "fix/auth") == 1


def test_checks_verdict_defaults_security_pending(tmp_path: Path) -> None:
    """Regression test (b): updating checks_passed and security_verdict independently preserves both."""
    db_path = tmp_path / "test_verdicts.db"
    logger = AuditLogger(db_path=db_path)

    # 1. Checks runner records checks_passed=True first
    logger.record_checks_verdict(
        repo="org/repoA",
        branch="agent/fix",
        head_commit_sha="commit_sha_123",
        checks_passed=True,
    )

    verdict1 = logger.get_verification_verdict(
        "org/repoA", "agent/fix", "commit_sha_123"
    )
    assert verdict1 is not None
    assert verdict1["checks_passed"] is True
    assert verdict1["security_verdict"] == "PENDING"


def test_security_verdict_preserves_checks(tmp_path: Path) -> None:
    db_path = tmp_path / "test_verdicts.db"
    logger = AuditLogger(db_path=db_path)

    logger.record_checks_verdict(
        repo="org/repoA",
        branch="agent/fix",
        head_commit_sha="commit_sha_123",
        checks_passed=True,
    )

    # 2. Security reviewer arrives later and records security_verdict='PASS'
    logger.record_security_verdict(
        repo="org/repoA",
        branch="agent/fix",
        head_commit_sha="commit_sha_123",
        security_verdict="PASS",
    )

    # Both must now be preserved!
    verdict2 = logger.get_verification_verdict(
        "org/repoA", "agent/fix", "commit_sha_123"
    )
    assert verdict2 is not None
    assert verdict2["checks_passed"] is True  # Preserved! Not wiped!
    assert verdict2["security_verdict"] == "PASS"  # Updated!
