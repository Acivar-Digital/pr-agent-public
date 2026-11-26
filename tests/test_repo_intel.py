"""Tests for scoped repository intelligence (Ticket #28).

Covers: path-traversal refusal, SKIP_DIRS exclusion, non-Python plain tree,
result/token caps, the ``--`` argv separator passed to ``rg``, worktree-relative
results (no host-path leak), skip globs + timeout, symlink escape, and clamps.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from src.orchestrator.tools.repo_intel import (
    MAX_TOKENS,
    SKIP_DIRS,
    _safe_path,
    get_repo_map,
    search_code_local,
)


def _make_worktree(tmp_path: Path) -> Path:
    (tmp_path / "pkg").mkdir()
    (tmp_path / "pkg" / "mod.py").write_text(
        "class Alpha:\n"
        "    def method(self):\n"
        "        return 1\n"
        "\n"
        "def helper():\n"
        "    return 2\n",
        encoding="utf-8",
    )
    (tmp_path / "README.md").write_text("# hello\n", encoding="utf-8")
    return tmp_path


# ---------------------------------------------------------------------------
# Path traversal
# ---------------------------------------------------------------------------


def test_safe_path_blocks_traversal(tmp_path: Path) -> None:
    _make_worktree(tmp_path)
    with pytest.raises(ValueError):
        _safe_path(tmp_path, "../../etc/passwd")


def test_search_and_map_block_traversal(tmp_path: Path) -> None:
    _make_worktree(tmp_path)
    with pytest.raises(ValueError):
        search_code_local(tmp_path, "needle", path="../../etc/passwd")
    with pytest.raises(ValueError):
        get_repo_map(tmp_path, path="../../etc")


# ---------------------------------------------------------------------------
# SKIP_DIRS exclusion
# ---------------------------------------------------------------------------


def test_search_skips_venv_and_node_modules(tmp_path: Path) -> None:
    _make_worktree(tmp_path)
    (tmp_path / ".venv").mkdir()
    (tmp_path / ".venv" / "hidden.py").write_text("needle = 1\n", encoding="utf-8")
    (tmp_path / "node_modules").mkdir()
    (tmp_path / "node_modules" / "dep.js").write_text(
        "const needle = 2;\n", encoding="utf-8"
    )
    (tmp_path / "pkg" / "mod.py").write_text("needle = 3\n", encoding="utf-8")

    results = search_code_local(tmp_path, "needle")
    files = {str(r["file"]) for r in results}
    assert any("mod.py" in f for f in files)
    assert not any(".venv" in f for f in files)
    assert not any("node_modules" in f for f in files)


def _assert_skips_absent(map_text: str) -> None:
    for skipped in SKIP_DIRS:
        assert skipped not in map_text


def test_repo_map_skips_dirs(tmp_path: Path) -> None:
    _make_worktree(tmp_path)
    (tmp_path / ".venv").mkdir()
    (tmp_path / ".venv" / "lib.py").write_text("x = 1\n", encoding="utf-8")
    (tmp_path / "node_modules").mkdir()
    (tmp_path / "node_modules" / "e.js").write_text("1\n", encoding="utf-8")

    map_text = get_repo_map(tmp_path)
    assert "mod.py" in map_text
    _assert_skips_absent(map_text)
    assert ".venv" not in map_text
    assert "node_modules" not in map_text


# ---------------------------------------------------------------------------
# Non-Python plain tree
# ---------------------------------------------------------------------------


def test_non_python_file_is_plain_tree(tmp_path: Path) -> None:
    _make_worktree(tmp_path)
    map_text = get_repo_map(tmp_path, path="README.md")
    assert "README.md" in map_text
    # No ast outline markers for a non-Python target.
    assert "def " not in map_text
    assert "class " not in map_text


def test_non_python_file_in_tree_is_plain_line(tmp_path: Path) -> None:
    _make_worktree(tmp_path)
    map_text = get_repo_map(tmp_path)
    assert "README.md" in map_text
    # README contributes a single plain line, no outline.
    readme_lines = [ln for ln in map_text.splitlines() if ln.strip() == "README.md"]
    assert readme_lines == ["README.md"]


# ---------------------------------------------------------------------------
# Caps
# ---------------------------------------------------------------------------


def test_max_matches_cap(tmp_path: Path) -> None:
    _make_worktree(tmp_path)
    for i in range(10):
        (tmp_path / f"f{i}.py").write_text(f"hit = {i}\n", encoding="utf-8")

    results = search_code_local(tmp_path, "hit", max_matches=3)
    assert len(results) <= 3


def test_repo_map_token_cap(tmp_path: Path) -> None:
    _make_worktree(tmp_path)
    for i in range(50):
        (tmp_path / f"big{i}.py").write_text(
            f"class C{i}:\n    def m(self):\n        return {i}\n", encoding="utf-8"
        )

    small = get_repo_map(tmp_path, max_tokens=10)
    assert "[truncated]" in small
    assert len(small) <= 10 * 4

    full = get_repo_map(tmp_path, max_tokens=MAX_TOKENS)
    assert "[truncated]" not in full


def test_clamps_nonpositive_bounds(tmp_path: Path) -> None:
    root = _make_worktree(tmp_path)
    (root / "pkg" / "mod.py").write_text("hit = 1\n", encoding="utf-8")
    # max_matches=0 clamps to 1 (still returns, never zero-cap everything).
    assert len(search_code_local(root, "hit", max_matches=0)) <= 1
    # max_tokens=0 clamps to 1 (returns a string, never crashes).
    assert isinstance(get_repo_map(root, max_tokens=0), str)


# ---------------------------------------------------------------------------
# rg argv separator, globs, timeout
# ---------------------------------------------------------------------------


def test_rg_invoked_with_double_dash(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _make_worktree(tmp_path)
    captured: dict[str, list[str]] = {}

    def fake_run(
        argv: list[str], *args: object, **kwargs: object
    ) -> subprocess.CompletedProcess[str]:
        captured["argv"] = list(argv)
        return subprocess.CompletedProcess(argv, 0, stdout="", stderr="")

    monkeypatch.setattr(subprocess, "run", fake_run)

    search_code_local(tmp_path, "some_query")
    argv = captured["argv"]
    assert "--" in argv
    assert argv.index("--") < argv.index("some_query")
    # shell string is never used.
    assert "shell" not in argv


def test_flag_like_query_cannot_be_a_flag(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = _make_worktree(tmp_path)
    captured: dict[str, list[str]] = {}

    def fake_run(
        argv: list[str], *args: object, **kwargs: object
    ) -> subprocess.CompletedProcess[str]:
        captured["argv"] = list(argv)
        return subprocess.CompletedProcess(argv, 0, stdout="", stderr="")

    monkeypatch.setattr(subprocess, "run", fake_run)

    search_code_local(root, "--pre=sh")
    argv = captured["argv"]
    # The flag-like query lands after ``--`` so rg treats it as a pattern.
    assert argv.index("--") < argv.index("--pre=sh")


def test_rg_gets_skip_globs_timeout_and_cwd(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = _make_worktree(tmp_path)
    argv_box: dict[str, list[str]] = {}
    kwargs_box: dict[str, object] = {}

    def fake_run(
        argv: list[str], *args: object, **kwargs: object
    ) -> subprocess.CompletedProcess[str]:
        argv_box["argv"] = list(argv)
        kwargs_box.update(kwargs)
        return subprocess.CompletedProcess(argv, 0, stdout="", stderr="")

    monkeypatch.setattr(subprocess, "run", fake_run)

    search_code_local(root, "x")
    argv = argv_box["argv"]
    assert "--glob" in argv
    assert "!build/**" in argv
    assert kwargs_box.get("timeout")  # a slow regex is bounded
    assert kwargs_box.get("cwd") == str(root)  # relative results, no host leak


# ---------------------------------------------------------------------------
# No host-path leak + symlink escape
# ---------------------------------------------------------------------------


def test_search_returns_relative_paths(tmp_path: Path) -> None:
    root = _make_worktree(tmp_path)
    (root / "pkg" / "mod.py").write_text("needle = 1\n", encoding="utf-8")
    results = search_code_local(root, "needle")
    assert results
    for r in results:
        f = str(r["file"])
        assert not Path(f).is_absolute()
        assert str(tmp_path) not in f


def test_symlink_escape_is_skipped(tmp_path: Path) -> None:
    root = _make_worktree(tmp_path)
    outside = tmp_path.parent / "outside_secret.py"
    outside.write_text("secret = 1\n", encoding="utf-8")
    link = root / "link.py"
    try:
        link.symlink_to(outside)
    except (OSError, NotImplementedError):
        pytest.skip("symlinks unsupported on this platform")

    map_text = get_repo_map(root)
    assert "outside_secret" not in map_text
    assert "link.py" not in map_text
