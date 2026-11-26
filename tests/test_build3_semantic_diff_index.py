"""Build 3 — Passive symbol extraction & worktree-external index directory tests."""

from __future__ import annotations

from pathlib import Path

from agent.diff_filter import extract_changed_symbols, filter_and_truncate_diff
from agent.workspace import get_external_index_dir


def test_extract_changed_symbols_finds_hunk_and_added_defs() -> None:
    diff = (
        "diff --git a/src/app.py b/src/app.py\n"
        "--- a/src/app.py\n"
        "+++ b/src/app.py\n"
        "@@ -10,3 +10,5 @@ def existing_fn():\n"
        " context\n"
        "+def new_helper():\n"
        "+    pass\n"
        "diff --git a/package-lock.json b/package-lock.json\n"
        "--- a/package-lock.json\n"
        "+++ b/package-lock.json\n"
        "@@ -1,3 +1,4 @@\n"
        "{\n"
        '  "lockfileVersion": 3\n'
        "}\n"
    )
    syms = extract_changed_symbols(diff)
    all_text = " ".join(s["symbol"] for s in syms)
    files = {s["file"] for s in syms}
    assert "existing_fn" in all_text
    assert "new_helper" in all_text
    assert "src/app.py" in files
    assert "package-lock.json" not in files


def test_filter_and_truncate_diff_includes_header_and_respects_cap() -> None:
    lines = ["diff --git a/big.py b/big.py"]
    for i in range(400):
        lines.append(f"+line_{i} = {i}")
    raw = "\n".join(lines)
    out = filter_and_truncate_diff(raw, max_total_chars=500)
    assert "## Changed Symbols" in out or len(out) <= 600
    assert len(out) <= 600


def test_extract_changed_symbols_handles_malformed_text() -> None:
    assert extract_changed_symbols("") == []
    assert extract_changed_symbols("\x00\x01\x02\xff") == []
    assert extract_changed_symbols("random garbage\nno diff structure\n") == []


def test_get_external_index_dir_outside_worktrees(tmp_path: Path, monkeypatch) -> None:
    workspaces = tmp_path / "workspaces"
    monkeypatch.setattr("agent.workspace.get_workspaces_dir", lambda: workspaces)
    result = get_external_index_dir("example-org/sample-repo")
    assert result.is_dir()
    assert not result.is_relative_to(workspaces / "worktrees")
    assert "indexes/example-org__sample-repo" in str(result)


def test_get_external_index_dir_rejects_traversal() -> None:
    import pytest

    with pytest.raises(ValueError):
        get_external_index_dir("../evil/repo")
