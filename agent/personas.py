from __future__ import annotations

import base64
import logging
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

import httpx
import yaml
from pydantic import BaseModel, ConfigDict, ValidationError

logger = logging.getLogger(__name__)

DEFAULT_PERSONAS_DIR = Path(__file__).resolve().parent.parent / "personas"


def get_personas_dir() -> Path:
    return Path(os.getenv("PERSONAS_DIR", str(DEFAULT_PERSONAS_DIR)))


def _gh_headers() -> dict[str, str]:
    token = os.getenv("GITHUB_TOKEN", "").strip()
    headers = {"Accept": "application/vnd.github+json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return headers


@dataclass
class AgentPersona:
    name: str
    instructions: str
    runner: str = "agy"
    model: str | None = None
    allow_writes: bool = True
    branch_prefix: str = "agent/task"
    source: str = "vps"
    role: str = ""
    description: str = ""
    when_to_use: str = ""


class PersonaFrontmatter(BaseModel):
    """Schema for a persona's YAML frontmatter.

    Strict: a wrong type (e.g. ``allow_writes: "yes"``) fails closed instead of
    being silently coerced, so a typo can never widen a persona's permissions.
    """

    model_config = ConfigDict(extra="forbid", strict=True)

    name: str | None = None
    runner: Literal["agy", "omp"] = "agy"
    model: str | None = None
    allow_writes: bool = True
    branch_prefix: str | None = None
    role: str = ""
    description: str = ""
    when_to_use: str = ""


def _extract_frontmatter_block(raw_md: str) -> tuple[str | None, str]:
    """Split leading ``---`` YAML frontmatter from the body.

    Returns ``(block, body)`` where ``block`` is the raw YAML text (or ``None``
    when the document has no well-formed frontmatter) and ``body`` is the
    remaining instructions with surrounding whitespace stripped.
    """
    body = raw_md.strip()
    if not body.startswith("---"):
        return None, body
    parts = body.split("---", 2)
    if len(parts) != 3:
        return None, body
    return parts[1], parts[2].strip()


def _parse_frontmatter_meta(block: str, source: str) -> dict:
    """Parse a YAML frontmatter block into a mapping, failing closed on drift."""
    try:
        raw_meta = yaml.safe_load(block)
    except yaml.YAMLError as exc:
        raise ValueError(f"invalid persona frontmatter YAML ({source}): {exc}") from exc
    if not raw_meta:
        return {}
    if isinstance(raw_meta, dict):
        return raw_meta
    raise ValueError(f"persona frontmatter must be a mapping ({source})")


def _resolve_model(raw_model: str | None) -> str | None:
    """Resolve a persona's model field against the ``AGY_MODEL`` default."""
    default_model = os.getenv("AGY_MODEL", "").strip() or None
    if isinstance(raw_model, str) and raw_model.strip().lower() in (
        "default",
        "none",
        "",
    ):
        return default_model
    return raw_model or default_model


def _build_persona(
    fields: PersonaFrontmatter, fallback_name: str, body: str, source: str
) -> AgentPersona:
    return AgentPersona(
        name=fields.name or fallback_name,
        instructions=body,
        runner=fields.runner,
        model=_resolve_model(fields.model),
        allow_writes=fields.allow_writes,
        branch_prefix=fields.branch_prefix or f"agent/{fallback_name}",
        source=source,
        role=fields.role,
        description=fields.description,
        when_to_use=fields.when_to_use,
    )


def _parse_markdown_persona(
    raw_md: str, fallback_name: str, source: str
) -> AgentPersona:
    block, body = _extract_frontmatter_block(raw_md)
    meta = _parse_frontmatter_meta(block, source) if block is not None else {}
    try:
        fields = PersonaFrontmatter.model_validate(meta)
    except ValidationError as exc:
        raise ValueError(f"invalid persona frontmatter ({source}): {exc}") from exc
    return _build_persona(fields, fallback_name, body, source)


async def load_persona(repo: str, persona_name: str, ref: str = "main") -> AgentPersona:
    """
    1. Checks `.agents/personas/{persona_name}.md` inside the target GitHub repo.
    2. Falls back to local VPS `personas/{persona_name}.md`.
    """
    clean_name = persona_name.removesuffix(".md").strip()
    headers = _gh_headers()

    if "Authorization" in headers:
        url = f"https://api.github.com/repos/{repo}/contents/.agents/personas/{clean_name}.md"
        async with httpx.AsyncClient(timeout=15) as client:
            resp = await client.get(url, params={"ref": ref}, headers=headers)
            if resp.status_code == 200:
                content_b64 = resp.json().get("content", "")
                raw_md = base64.b64decode(content_b64).decode("utf-8")
                return _parse_markdown_persona(
                    raw_md, clean_name, source=f"github:{repo}"
                )

    local_dir = get_personas_dir()
    local_path = local_dir / f"{clean_name}.md"
    if local_path.exists():
        return _parse_markdown_persona(
            local_path.read_text("utf-8"), clean_name, source="vps"
        )

    raise FileNotFoundError(
        f"Persona '{clean_name}' not found in {repo}/.agents/personas/ or {local_dir}"
    )


def _persona_summary(persona: AgentPersona, source: str) -> dict:
    return {
        "name": persona.name,
        "role": persona.role,
        "description": persona.description,
        "when_to_use": persona.when_to_use,
        "mode": "auto" if persona.allow_writes else "plan",
        "source": source,
    }


def _collect_local_personas(found: dict[str, dict], local_dir: Path) -> None:
    if not local_dir.exists():
        return
    for path in sorted(local_dir.glob("*.md")):
        try:
            persona = _parse_markdown_persona(
                path.read_text("utf-8"), path.stem, source="vps"
            )
        except ValueError as exc:
            logger.warning("skipping invalid persona %s: %s", path, exc)
            continue
        found[path.stem] = _persona_summary(persona, "vps")


async def _fetch_github_persona_items(repo: str, ref: str) -> list | None:
    headers = _gh_headers()
    if "Authorization" not in headers:
        return None
    url = f"https://api.github.com/repos/{repo}/contents/.agents/personas"
    async with httpx.AsyncClient(timeout=15) as client:
        resp = await client.get(url, params={"ref": ref}, headers=headers)
        if resp.status_code != 200:
            return None
        items = resp.json()
        if not isinstance(items, list):
            return None
        return items


async def _add_github_persona(
    found: dict[str, dict], repo: str, ref: str, item: dict
) -> None:
    stem = item["name"].removesuffix(".md")
    try:
        persona = await load_persona(repo=repo, persona_name=stem, ref=ref)
        found[stem] = _persona_summary(persona, f"github:{repo}")
    except Exception:  # noqa: BLE001
        found[stem] = {"name": stem, "source": f"github:{repo}"}


async def _collect_github_personas(found: dict[str, dict], repo: str, ref: str) -> None:
    items = await _fetch_github_persona_items(repo, ref)
    if items is None:
        return
    for item in items:
        if item.get("name", "").endswith(".md"):
            await _add_github_persona(found, repo, ref, item)


async def discover_personas(repo: str, ref: str = "main") -> list[dict]:
    """List available personas from both the VPS fallback directory and the GitHub repo with rich capability metadata."""
    found: dict[str, dict] = {}
    _collect_local_personas(found, get_personas_dir())
    await _collect_github_personas(found, repo, ref)
    return list(found.values())
