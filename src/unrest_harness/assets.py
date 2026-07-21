from __future__ import annotations

from pathlib import Path
from typing import Any, Literal

import yaml
from jinja2 import Environment, StrictUndefined

from .config import HarnessConfig
from .models import LoadedMarkdownAsset


def iter_skill_directories(skill_root: Path) -> list[Path]:
    if not skill_root.exists():
        return []
    return [
        path
        for path in sorted(skill_root.iterdir())
        if path.is_dir() and (path / "SKILL.md").exists()
    ]


def parse_frontmatter(raw_text: str) -> tuple[dict[str, Any], str]:
    if not raw_text.startswith("---\n"):
        return {}, raw_text
    parts = raw_text.split("\n---\n", 1)
    if len(parts) != 2:
        return {}, raw_text
    frontmatter_raw = parts[0][4:]
    body = parts[1]
    data = yaml.safe_load(frontmatter_raw) or {}
    if not isinstance(data, dict):
        data = {}
    return data, body


class AssetLoader:
    def __init__(self, config: HarnessConfig):
        self.config = config
        self._jinja = Environment(
            undefined=StrictUndefined, autoescape=False, keep_trailing_newline=True
        )

    def load_skill(
        self, skill_name: str, project_id: str | None = None
    ) -> LoadedMarkdownAsset:
        for source, base_dir in self._iter_skill_dirs(project_id):
            skill_path = base_dir / skill_name / "SKILL.md"
            if skill_path.exists():
                raw = skill_path.read_text(encoding="utf-8")
                frontmatter, body = parse_frontmatter(raw)
                return LoadedMarkdownAsset(
                    name=frontmatter.get("name", skill_name),
                    description=frontmatter.get("description"),
                    source=source,
                    path=str(skill_path),
                    rawText=raw,
                    body=body,
                    frontmatter=frontmatter,
                )
        raise FileNotFoundError(f"Skill not found: {skill_name}")

    def list_skills(
        self, project_id: str | None = None
    ) -> list[LoadedMarkdownAsset]:
        seen: set[str] = set()
        results: list[LoadedMarkdownAsset] = []
        for source, base_dir in self._iter_skill_dirs(project_id):
            for skill_root in iter_skill_directories(base_dir):
                skill_path = skill_root / "SKILL.md"
                raw = skill_path.read_text(encoding="utf-8")
                frontmatter, body = parse_frontmatter(raw)
                skill_name = frontmatter.get("name", skill_root.name)
                if skill_name in seen:
                    continue
                seen.add(skill_name)
                results.append(
                    LoadedMarkdownAsset(
                        name=skill_name,
                        description=frontmatter.get("description"),
                        source=source,
                        path=str(skill_path),
                        rawText=raw,
                        body=body,
                        frontmatter=frontmatter,
                    )
                )
        return results

    def load_prompt_file(self, session_type: str, relative_path: str) -> str:
        """Read a bundled prompt file under `bundled/prompts/<session_type>/`."""
        path = self.config.bundled_dir / "prompts" / session_type / relative_path
        if not path.exists():
            raise FileNotFoundError(f"Prompt file not found: {path}")
        return path.read_text(encoding="utf-8")

    def render_prompt_template(
        self,
        session_type: str,
        template_name: str,
        variables: dict[str, Any],
    ) -> str:
        template_source = self.load_prompt_file(session_type, template_name)
        template = self._jinja.from_string(template_source)
        return template.render(**variables)

    def bundled_skills_dir(self) -> Path:
        return self.config.bundled_dir / "skills"

    def bundled_agents_dir(self, provider_name: str) -> Path:
        """Per-provider subagents directory (`bundled/providers/<name>/agents/`)."""
        return self.config.bundled_dir / "providers" / provider_name / "agents"

    def _iter_skill_dirs(
        self, project_id: str | None
    ) -> list[tuple[Literal["project", "personal", "bundled"], Path]]:
        dirs = self.config.skill_dirs(project_id)
        all_labels: list[Literal["project", "personal", "bundled"]] = [
            "project", "personal", "bundled",
        ]
        labels = all_labels if project_id is not None else all_labels[1:]
        return list(zip(labels, dirs))
