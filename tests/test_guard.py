"""Tests for the guard AST quality gatekeeper."""

from __future__ import annotations

from pathlib import Path

from guard.guardrail import (
    get_changed_python_files,
    main,
    validate_file,
    validate_paths,
)
from guard.rules.async_blocking import scan_async_blocking
from guard.rules.bad_style import scan_bad_style
from guard.rules.banned_fallbacks import scan_banned_fallbacks
from guard.rules.cc_nested import scan_cc_nested
from guard.rules.no_type_ignore import scan_no_type_ignore
from guard.rules.strict_schema import scan_strict_schema
from guard.rules.truncation import scan_truncation


def test_bad_style_catches_bare_except_swallowed_mutable_and_open() -> None:
    src = """
def bad(items=[]):
    f = open("foo.txt")
    try:
        return items
    except:
        pass
"""
    findings = scan_bad_style(src, "sample.py")
    symbols = {f.symbol for f in findings}
    assert "MUTABLE_DEFAULT" in symbols
    assert "UNSAFE_OPEN" in symbols
    assert "BARE_EXCEPT" in symbols


def test_bad_style_catches_swallowed_broad_exception() -> None:
    src = """
def swallow() -> None:
    try:
        x = 1
    except Exception:
        pass
"""
    findings = scan_bad_style(src, "sample.py")
    assert any(f.symbol == "SWALLOWED_EXCEPTION" for f in findings)


def test_async_blocking_catches_sync_calls_in_async_def() -> None:
    src = """
import time
import subprocess

async def handler() -> None:
    time.sleep(1)
    subprocess.run(["ls"])
"""
    findings = scan_async_blocking(src, "sample.py")
    assert len(findings) == 2
    assert {f.symbol for f in findings} == {"time.sleep", "subprocess.run"}


def test_banned_fallbacks_catches_silent_returns() -> None:
    src = """
def calc() -> dict[str, int]:
    try:
        return {"a": 1}
    except ValueError:
        return {}
"""
    findings = scan_banned_fallbacks(src, "sample.py")
    assert len(findings) == 1
    assert findings[0].rule_id == "BANNED_FALLBACK"


def test_cc_nested_enforces_depth_and_complexity() -> None:
    src = """
def complex_fn(a: int, b: int, c: int, d: int) -> int:
    if a:
        if b:
            if c:
                if d:
                    return 1
    if a and b and c and d:
        return 2
    return 0
"""
    findings = scan_cc_nested(src, "sample.py")
    rule_ids = {f.rule_id for f in findings}
    assert "NESTED_DEPTH" in rule_ids
    assert "CYCLOMATIC_COMPLEXITY" in rule_ids


def test_no_type_ignore_blocks_legacy_ignores_but_allows_ty_ignore() -> None:
    legacy = "x = 1  # " + "type: ignore\n"
    pyright = "y = 2  # " + "pyright: ignore\n"
    ty_ok = "z = 3  # " + "ty: ignore[invalid-assignment]\n"
    assert len(scan_no_type_ignore(legacy, "sample.py")) == 1
    assert len(scan_no_type_ignore(pyright, "sample.py")) == 1
    assert len(scan_no_type_ignore(ty_ok, "sample.py")) == 0


def test_truncation_catches_placeholder_comments() -> None:
    src = "# ... existing code ...\nx = 1\n"
    findings = scan_truncation(src, "sample.py")
    assert len(findings) == 1
    assert findings[0].rule_id == "INCOMPLETE_CODE"


def test_strict_schema_requires_extra_forbid() -> None:
    bad_src = """
from pydantic import BaseModel

class Loose(BaseModel):
    name: str
"""
    good_src = """
from pydantic import BaseModel, ConfigDict

class Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str
"""
    assert len(scan_strict_schema(bad_src, "sample.py")) == 1
    assert len(scan_strict_schema(good_src, "sample.py")) == 0


def test_validate_file_and_cli_no_external(tmp_path: Path) -> None:
    good = tmp_path / "good.py"
    good.write_text("def add(a: int, b: int) -> int:\n    return a + b\n", encoding="utf-8")
    bad = tmp_path / "bad.py"
    bad.write_text("def oops(x=[]):\n    return x\n", encoding="utf-8")

    assert validate_file(good, run_external=False).success is True
    assert validate_file(bad, run_external=False).success is False
    assert main(["--no-external", str(good)]) == 0
    assert main(["--no-external", str(bad)]) == 1


def test_guard_validates_itself_cleanly() -> None:
    report = validate_paths(["guard"], run_external=False)
    assert report.checked_files >= 10
    assert report.success, [r.findings for r in report.results if not r.success]


def test_get_changed_python_files_returns_paths() -> None:
    files = get_changed_python_files()
    assert all(p.suffix == ".py" for p in files)
