"""G3 #3 — persona frontmatter schema validation and domain specialists."""

from __future__ import annotations

import asyncio
import base64

import pytest
from pydantic import ValidationError

from agent import personas
from agent.personas import (
    PersonaFrontmatter,
    _parse_markdown_persona,
    discover_personas,
    load_persona,
)
from agent.security import READ_ONLY_PERSONAS, resolve_allow_writes

BROKEN_YAML = "---\nname: 'unclosed\n---\nbody\n"


def _md(frontmatter: str, body: str = "Instructions here.") -> str:
    return f"---\n{frontmatter}---\n{body}\n"


def _assert_valid_frontmatter_parsed(persona: personas.AgentPersona) -> None:
    assert (
        persona.name,
        persona.runner,
        persona.model,
        persona.allow_writes,
        persona.branch_prefix,
        persona.instructions,
    ) == (
        "reviewer",
        "omp",
        "lr-fse-scout/scout",
        False,
        "agent/review",
        "Instructions here.",
    )


def _assert_specialist_is_read_only(name: str) -> None:
    persona = _parse_markdown_persona(
        (personas.DEFAULT_PERSONAS_DIR / f"{name}.md").read_text("utf-8"),
        name,
        source="vps",
    )
    assert persona.allow_writes is False
    assert all((persona.role, persona.description, persona.when_to_use))
    assert persona.branch_prefix is not None
    assert persona.branch_prefix.startswith("agent/")


def test_valid_frontmatter_is_parsed() -> None:
    persona = _parse_markdown_persona(
        _md(
            "name: reviewer\n"
            "role: Reviewer\n"
            "runner: omp\n"
            "model: lr-fse-scout/scout\n"
            "allow_writes: false\n"
            "branch_prefix: agent/review\n"
        ),
        "fallback",
        source="test",
    )
    _assert_valid_frontmatter_parsed(persona)


def test_missing_frontmatter_uses_safe_defaults() -> None:
    persona = _parse_markdown_persona("Just a body.", "fallback", source="test")
    assert persona.name == "fallback"
    assert persona.runner == "agy"
    assert persona.allow_writes is True
    assert persona.branch_prefix == "agent/fallback"


def test_empty_name_falls_back_to_filename() -> None:
    persona = _parse_markdown_persona(_md("name: ''"), "fallback", source="test")
    assert persona.name == "fallback"


def test_unknown_runner_is_rejected() -> None:
    with pytest.raises(ValueError, match="invalid persona frontmatter"):
        _parse_markdown_persona(_md("runner: turbo"), "fallback", source="test")


def test_wrong_type_is_rejected_not_coerced() -> None:
    """`allow_writes: "yes"` must fail closed, never coerce to True."""
    with pytest.raises(ValueError, match="invalid persona frontmatter"):
        _parse_markdown_persona(_md('allow_writes: "yes"'), "fallback", source="test")


def test_non_mapping_frontmatter_is_rejected() -> None:
    with pytest.raises(ValueError, match="must be a mapping"):
        _parse_markdown_persona("---\n- a\n- b\n---\nbody\n", "f", source="test")


def test_broken_yaml_syntax_is_rejected_as_value_error() -> None:
    """yaml.YAMLError is not a ValueError; discovery must still survive it."""
    with pytest.raises(ValueError, match="invalid persona frontmatter YAML"):
        _parse_markdown_persona(BROKEN_YAML, "f", source="test")


def test_model_default_resolves_to_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AGY_MODEL", "env-model")
    persona = _parse_markdown_persona(_md("model: default"), "f", source="test")
    assert persona.model == "env-model"


def test_schema_rejects_wrong_field_type_directly() -> None:
    with pytest.raises(ValidationError):
        PersonaFrontmatter.model_validate({"allow_writes": "yes"})


@pytest.mark.anyio
async def test_repo_override_wins_over_local(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """AC3: `.agents/personas/<name>.md` in the target repo overrides the VPS copy."""
    monkeypatch.setenv("GITHUB_TOKEN", "ghp_test")
    payload = base64.b64encode(
        _md("name: repo-persona\nallow_writes: false").encode()
    ).decode()

    class _Resp:
        status_code = 200

        def json(self) -> dict:
            return {"content": payload}

    class _Client:
        def __init__(self, *args, **kwargs) -> None:
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *args) -> bool:
            return False

        async def get(self, *args, **kwargs):
            return _Resp()

    monkeypatch.setattr(personas.httpx, "AsyncClient", _Client)
    persona = await load_persona(
        repo="example-org/sample-repo", persona_name="scout"
    )
    assert persona.name == "repo-persona"
    assert persona.source == "github:example-org/sample-repo"


def test_discover_skips_invalid_local_persona(
    tmp_path, monkeypatch: pytest.MonkeyPatch
) -> None:
    (tmp_path / "good.md").write_text(
        _md("name: good\nrole: Good\ndescription: d\nwhen_to_use: w"), "utf-8"
    )
    (tmp_path / "bad.md").write_text(_md("runner: turbo"), "utf-8")
    (tmp_path / "bad-yaml.md").write_text(BROKEN_YAML, "utf-8")
    monkeypatch.setenv("PERSONAS_DIR", str(tmp_path))
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)

    found = asyncio.run(discover_personas(repo="example-org/sample-repo"))
    assert {p["name"] for p in found} == {"good"}


def test_domain_specialists_are_read_only() -> None:
    for name in ("scout", "security-reviewer"):
        _assert_specialist_is_read_only(name)


def test_specialists_cannot_be_escalated_to_write_mode() -> None:
    assert {"performance-engineer", "db-migration-reviewer"} <= READ_ONLY_PERSONAS
    for name in ("performance-engineer", "db-migration-reviewer"):
        assert resolve_allow_writes(name, True) is False
        assert resolve_allow_writes(name, False) is False
