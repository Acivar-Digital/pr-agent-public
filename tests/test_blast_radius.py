"""Tests for blast-radius guard (file/LoC caps + protected-path blocking)."""

from __future__ import annotations

import pytest

from src.orchestrator.guardrails.blast_radius import (
    MAX_FILES,
    MAX_LOC,
    BlastRadiusReport,
    evaluate_blast_radius,
    is_blocked,
    is_lockfile,
)


def _diff_for_paths(paths: list[str], *, loc_per_file: int = 1) -> str:
    """Build a unified diff touching each path with `loc_per_file` added lines."""
    chunks: list[str] = []
    for path in paths:
        lines = "".join(f"+line {i}\n" for i in range(loc_per_file))
        chunks.append(
            f"diff --git a/{path} b/{path}\n"
            f"--- a/{path}\n"
            f"+++ b/{path}\n"
            f"@@ -0,0 +1,{loc_per_file} @@\n"
            f"{lines}"
        )
    return "".join(chunks)


def _assert_under_limit(report: BlastRadiusReport) -> None:
    assert report.within_limits is True
    assert report.blocked == ()
    assert report.reasons == ()
    assert report.total_loc == 30


def test_under_limit_passes() -> None:
    diff = _diff_for_paths([f"src/file{i}.py" for i in range(3)], loc_per_file=10)
    report = evaluate_blast_radius(diff)
    _assert_under_limit(report)
    assert len(report.files) == 3


def test_too_many_files_fails() -> None:
    paths = [f"src/file{i}.py" for i in range(MAX_FILES + 1)]
    report = evaluate_blast_radius(_diff_for_paths(paths))
    assert report.within_limits is False
    assert any("file count" in r for r in report.reasons)


def test_too_many_loc_fails() -> None:
    report = evaluate_blast_radius(
        _diff_for_paths(["src/big.py"], loc_per_file=MAX_LOC + 1)
    )
    assert report.within_limits is False
    assert report.total_loc == MAX_LOC + 1
    assert any("LoC" in r for r in report.reasons)


def _assert_lockfile_excluded(report: BlastRadiusReport) -> None:
    # A huge lockfile change must not trip the LoC cap; only the real file counts.
    assert report.files == ("src/small.py",)
    # Only small.py's lines are counted; the lockfile is excluded entirely.
    assert report.total_loc == MAX_LOC + 50
    assert report.within_limits is False  # small.py alone still exceeds the cap


def _assert_small_lockfile_ok(report: BlastRadiusReport) -> None:
    # A small lockfile alongside a small real file stays within limits.
    assert report.files == ("src/small.py",)
    assert report.total_loc == 5
    assert report.within_limits is True


def test_lockfile_loc_excluded_from_cap() -> None:
    paths = ["uv.lock", "src/small.py"]
    diff = _diff_for_paths(paths, loc_per_file=MAX_LOC + 50)
    report = evaluate_blast_radius(diff)
    _assert_lockfile_excluded(report)

    small = _diff_for_paths(["uv.lock", "src/small.py"], loc_per_file=5)
    report2 = evaluate_blast_radius(small)
    _assert_small_lockfile_ok(report2)


def test_blocked_workflow_path_under_limits() -> None:
    report = evaluate_blast_radius(_diff_for_paths([".github/workflows/ci.yml"]))
    assert report.within_limits is False
    assert report.blocked == (".github/workflows/ci.yml",)
    assert any("blocked paths" in r for r in report.reasons)


def test_blocked_computed_before_lockfile_exclusion() -> None:
    # .github/** path is blocked and must be reported even though it is small.
    diff = _diff_for_paths([".github/workflows/x.yml", "uv.lock"], loc_per_file=1)
    report = evaluate_blast_radius(diff)
    assert ".github/workflows/x.yml" in report.blocked
    assert report.within_limits is False


def test_is_blocked_and_is_lockfile_helpers() -> None:
    assert is_blocked(".github/workflows/ci.yml") is True
    assert is_blocked("src/app.py") is False
    assert is_lockfile("uv.lock") is True
    assert is_lockfile("src/app.py") is False


# ---------------------------------------------------------------------------
# Review regressions (#37)
# ---------------------------------------------------------------------------


def test_vps_checks_toml_is_blocked() -> None:
    # .vps-checks.toml (PR #34) must be a protected path, not the obsolete yaml.
    assert is_blocked(".vps-checks.toml") is True
    report = evaluate_blast_radius(_diff_for_paths([".vps-checks.toml"]))
    assert report.within_limits is False
    assert report.blocked == (".vps-checks.toml",)


def test_leading_dot_slash_is_normalized() -> None:
    # ``./.github/...`` must not slip past the glob match.
    assert is_blocked("./.github/workflows/ci.yml") is True


def test_rename_of_protected_path_is_blocked() -> None:
    # git mv .github/workflows/ci.yml tmp/x.yml — the source side is protected.
    diff = (
        "diff --git a/.github/workflows/ci.yml b/tmp/x.yml\n"
        "similarity index 100%\n"
        "rename from .github/workflows/ci.yml\n"
        "rename to tmp/x.yml\n"
    )
    report = evaluate_blast_radius(diff)
    assert ".github/workflows/ci.yml" in report.blocked
    assert report.within_limits is False


def test_delete_of_protected_path_is_blocked() -> None:
    # Deleting a protected file: target is /dev/null, source is protected.
    diff = (
        "diff --git a/.github/workflows/ci.yml b/.github/workflows/ci.yml\n"
        "deleted file mode 100644\n"
        "--- a/.github/workflows/ci.yml\n"
        "+++ /dev/null\n"
        "@@ -1,1 +0,0 @@\n"
        "-old\n"
    )
    report = evaluate_blast_radius(diff)
    assert ".github/workflows/ci.yml" in report.blocked
    assert report.within_limits is False


def test_unparseable_diff_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    from unidiff.errors import UnidiffParseError

    from src.orchestrator.guardrails import blast_radius as br

    def boom(_: str) -> object:
        raise UnidiffParseError("bad diff")

    monkeypatch.setattr(br, "PatchSet", boom)
    report = br.evaluate_blast_radius("not a real diff")
    assert report.within_limits is False
    assert report.reasons == ("unparseable diff",)
    assert report.blocked == ()
