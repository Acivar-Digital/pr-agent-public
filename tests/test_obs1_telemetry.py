from __future__ import annotations

import json
from pathlib import Path

import logfire

from agent.telemetry import (
    RotatingJSONLStream,
    configure_telemetry,
    scrub_telemetry_text,
)


def _assert_valid_jsonl(contents: str) -> None:
    assert contents.strip()
    for line in contents.splitlines():
        if line.strip():
            json.loads(line)


def _assert_rotated_backups(rotated: list[Path]) -> None:
    for suffix in (".1", ".2"):
        assert any(p.name.endswith(suffix) for p in rotated)


def test_scrub_telemetry_text_redacts_all_secrets() -> None:
    text = (
        "url=/gemini/super_secret_token_1234567890 "
        "Authorization: Bearer abc.def.ghi "
        "ghp_1234567890abcdef"
    )
    out = scrub_telemetry_text(text)

    forbidden = [
        "super_secret_token_1234567890",
        "abc.def.ghi",
        "ghp_1234567890abcdef",
    ]
    required = ["[REDACTED]", "[REDACTED_GH_TOKEN]"]
    for needle in forbidden:
        assert needle not in out
    for needle in required:
        assert needle in out


def test_rotating_jsonl_stream_rotates_and_bounds_disk(tmp_path: Path) -> None:
    log_path = tmp_path / "traces.jsonl"
    stream = RotatingJSONLStream(log_path, max_bytes=200, backup_count=2)

    for i in range(20):
        stream.write(f'{{"line": {i}, "padding": "xxxxxxxxxxxxxxxxxxxxxxxxxxx"}}\n')
    stream.flush()
    stream.close()

    assert log_path.exists()
    rotated = list(tmp_path.glob("traces.jsonl.*"))
    _assert_rotated_backups(rotated)
    assert len(list(tmp_path.glob("traces.jsonl*"))) <= 3


def test_configure_telemetry_writes_scrubbed_jsonl(tmp_path: Path) -> None:
    stream = configure_telemetry(
        log_path=tmp_path / "traces.jsonl", use_simple_processor=True
    )
    try:
        with logfire.span("test_op", url="/gemini/my_secret_path_123456789012"):
            pass
        stream.flush()
    finally:
        stream.close()

    contents = (tmp_path / "traces.jsonl").read_text(encoding="utf-8")
    _assert_valid_jsonl(contents)
    assert "my_secret_path_123456789012" not in contents
    assert "/gemini/[REDACTED]" in contents


def test_scrub_telemetry_text_redacts_query_string_token() -> None:
    out = scrub_telemetry_text(
        "https://api.example.com/data?access_token=SUPERSECRET123"
    )
    assert "SUPERSECRET123" not in out
    assert "access_token=[REDACTED]" in out


def test_scrub_telemetry_text_redacts_jwt() -> None:
    jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dBjftJeZ4CVPmB92K27uhbUJU1p1r_wW1gFWFOEjXk"
    out = scrub_telemetry_text(f"Authorization: {jwt}")
    assert jwt not in out
    assert "[REDACTED]" in out


def test_scrub_telemetry_text_redacts_password_kv() -> None:
    out = scrub_telemetry_text("db password=hunter2 user=admin")
    assert "hunter2" not in out
    assert "password=[REDACTED]" in out


def test_pyproject_declares_logfire() -> None:
    text = Path("pyproject.toml").read_text(encoding="utf-8")
    assert "logfire" in text
