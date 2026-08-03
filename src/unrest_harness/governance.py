"""Strict Batch 0 change-governance models and deterministic checks.

This module defines repository governance. It does not implement release
promotion, deployment, or rollback execution.
"""
from __future__ import annotations

import fnmatch
import hashlib
import html
import json
import os
import re
import shlex
import subprocess
import unicodedata
from dataclasses import dataclass
from html.parser import HTMLParser
from pathlib import Path, PurePosixPath
from typing import Any, Literal, Self

import yaml
from markdown_it import MarkdownIt
from markdown_it.token import Token
from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator

POLICY_ID = "GOV-PROTECTED-SURFACES-001"
POLICY_SCHEMA_VERSION = 1
REQUIRED_ACCOUNTABLE_ROLES = ("release-maintainer", "security-maintainer")
FORBIDDEN_APPROVER_KINDS = ("agent", "provider")
REQUIRED_SURFACE_IDS = (
    "capability-policy",
    "coordinator-semantics",
    "evaluation-holdouts",
    "governance-self-protection",
    "promotion-policy",
    "rollback-controls",
    "storage-migrations",
)
REQUIRED_EVALUATION_TIERS: dict[str, frozenset[str]] = {
    "capability-policy": frozenset(
        {"full-repository", "installed-wheel", "real-cli-mcp-acp", "security"}
    ),
    "coordinator-semantics": frozenset(
        {"concurrency", "full-repository", "real-cli-mcp-acp"}
    ),
    "evaluation-holdouts": frozenset(
        {"full-repository", "private-holdout", "security"}
    ),
    "governance-self-protection": frozenset({"full-repository", "security"}),
    "promotion-policy": frozenset(
        {"full-repository", "real-cli-mcp-acp", "security"}
    ),
    "rollback-controls": frozenset(
        {"full-repository", "real-cli-mcp-acp", "security"}
    ),
    "storage-migrations": frozenset(
        {"full-repository", "installed-wheel", "real-cli-mcp-acp"}
    ),
}
REQUIRED_PROTECTED_COMPONENT_PATHS: dict[str, tuple[str, ...]] = {
    "COMP-GOVERNANCE": (
        ".github/PULL_REQUEST_TEMPLATE.md",
        "docs/architecture/change-governance.md",
        "docs/templates/adr.md",
        "policy/protected-surfaces.yaml",
        "schemas/protected-surfaces.schema.json",
        "src/unrest_harness/governance.py",
    ),
    "COMP-REPOSITORY-CONTRACT": (
        ".github/workflows/ci.yml",
        "AGENTS.md",
        "CONTRIBUTING.md",
        "README.md",
        "docs/architecture/annotation-policy.json",
        "docs/architecture/component-map.json",
        "docs/architecture/evidence-policy.json",
        "docs/architecture/historical-record-policy.json",
        "docs/architecture/repository-contract.md",
        "docs/architecture/template-heading-policy.json",
        "pyproject.toml",
        "src/unrest_harness/repository_contract.py",
        "uv.lock",
    ),
}
REQUIRED_SELF_PROTECTION: dict[str, tuple[str, str, str]] = {
    "annotation-policy": (
        "governance-self-protection",
        "path",
        "docs/architecture/annotation-policy.json",
    ),
    "architecture-component-map": (
        "governance-self-protection",
        "path",
        "docs/architecture/component-map.json",
    ),
    "change-governance-document": (
        "governance-self-protection",
        "path",
        "docs/architecture/change-governance.md",
    ),
    "continuous-integration": (
        "governance-self-protection",
        "path",
        ".github/workflows/ci.yml",
    ),
    "contribution-guidance": (
        "governance-self-protection",
        "path",
        "CONTRIBUTING.md",
    ),
    "contract-validator": (
        "governance-self-protection",
        "path",
        "src/unrest_harness/governance.py",
    ),
    "dependency-lock": (
        "governance-self-protection",
        "path",
        "uv.lock",
    ),
    "evaluation-holdouts": (
        "evaluation-holdouts",
        "path-prefix",
        "evals/holdouts/",
    ),
    "evaluation-oracles": (
        "evaluation-holdouts",
        "path-prefix",
        "evals/baseline/",
    ),
    "evidence-policy": (
        "governance-self-protection",
        "path",
        "docs/architecture/evidence-policy.json",
    ),
    "governance-adr-template": (
        "governance-self-protection",
        "path",
        "docs/templates/adr.md",
    ),
    "governance-component-catalog": (
        "governance-self-protection",
        "component",
        "COMP-GOVERNANCE",
    ),
    "historical-record-policy": (
        "governance-self-protection",
        "path",
        "docs/architecture/historical-record-policy.json",
    ),
    "policy-schema": (
        "governance-self-protection",
        "path",
        "schemas/protected-surfaces.schema.json",
    ),
    "promotion-controls": (
        "governance-self-protection",
        "path",
        "policy/protected-surfaces.yaml",
    ),
    "protected-surface-policy": (
        "governance-self-protection",
        "path",
        "policy/protected-surfaces.yaml",
    ),
    "project-guidance": (
        "governance-self-protection",
        "path",
        "AGENTS.md",
    ),
    "project-metadata": (
        "governance-self-protection",
        "path",
        "pyproject.toml",
    ),
    "project-readme": (
        "governance-self-protection",
        "path",
        "README.md",
    ),
    "pull-request-template": (
        "governance-self-protection",
        "path",
        ".github/PULL_REQUEST_TEMPLATE.md",
    ),
    "repository-contract-component-catalog": (
        "governance-self-protection",
        "component",
        "COMP-REPOSITORY-CONTRACT",
    ),
    "repository-contract-document": (
        "governance-self-protection",
        "path",
        "docs/architecture/repository-contract.md",
    ),
    "repository-contract-validator": (
        "governance-self-protection",
        "path",
        "src/unrest_harness/repository_contract.py",
    ),
    "rollback-controls": (
        "governance-self-protection",
        "path",
        "policy/protected-surfaces.yaml",
    ),
    "template-heading-policy": (
        "governance-self-protection",
        "path",
        "docs/architecture/template-heading-policy.json",
    ),
}

EvaluationTier = Literal[
    "concurrency",
    "full-repository",
    "installed-wheel",
    "live-provider",
    "private-holdout",
    "real-cli-mcp-acp",
    "security",
]
SelectorKind = Literal["component", "path", "path-prefix"]


@dataclass(frozen=True, order=True)
class GovernanceDiagnostic:
    """A stable machine-readable failure with human context."""

    code: str
    location: str
    message: str

    def render(self) -> str:
        return f"{self.code}:{self.location}: {self.message}"


class GovernanceValidationError(ValueError):
    """Raised when governance input fails with stable diagnostics."""

    def __init__(self, diagnostics: list[GovernanceDiagnostic]) -> None:
        self.diagnostics = tuple(sorted(diagnostics))
        super().__init__("\n".join(item.render() for item in self.diagnostics))


@dataclass(frozen=True)
class CommonMarkHeading:
    """One operative CommonMark heading, independent of source syntax."""

    level: int
    text: str
    aliases: tuple[str, ...] = ()


@dataclass(frozen=True)
class DocumentAttribute:
    """One decoded HTML or Markdown attribute."""

    name: str
    value: str
    source: Literal["html", "markdown"]


@dataclass(frozen=True)
class DocumentElement:
    """One parsed HTML element, including closing-only structural markers."""

    tag: str
    attributes: tuple[DocumentAttribute, ...]
    closing: bool = False


@dataclass(frozen=True)
class CommonMarkBlock:
    """Visible Markdown block with its logical section and field context."""

    text: str
    heading_path: tuple[CommonMarkHeading, ...]
    field_name: str | None
    field_value: str | None


@dataclass(frozen=True)
class CommonMarkSurface:
    """Structural Markdown content used by repository and governance checks."""

    headings: tuple[CommonMarkHeading, ...]
    top_level_headings: tuple[CommonMarkHeading, ...]
    blocks: tuple[CommonMarkBlock, ...]
    attributes: tuple[DocumentAttribute, ...]
    elements: tuple[DocumentElement, ...]
    visible_blocks: tuple[str, ...]
    visible_lines: tuple[str, ...]
    operative_lines: tuple[str, ...]
    html_blocks: tuple[str, ...]
    html_inlines: tuple[str, ...]
    html_tokens: tuple[str, ...]
    fences: tuple[tuple[str, str], ...]
    top_level_html_blocks: tuple[str, ...]
    top_level_html_inlines: tuple[str, ...]
    top_level_html_tokens: tuple[str, ...]
    top_level_fences: tuple[tuple[str, str], ...]


_COMMONMARK = MarkdownIt("commonmark")


def normalize_document_text(text: str) -> str:
    """Apply the compatibility/security normalization used by document rules."""

    compatible = unicodedata.normalize("NFKC", html.unescape(text))
    return "".join(
        character
        for character in compatible
        if unicodedata.category(character) != "Cf"
    )


def normalized_document_tokens(text: str) -> tuple[str, ...]:
    """Return punctuation-independent normalized word tokens."""

    return tuple(
        re.findall(r"[a-z0-9]+", normalize_document_text(text).casefold())
    )


class _DocumentHTMLParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.elements: list[DocumentElement] = []

    def _append(
        self,
        tag: str,
        attributes: list[tuple[str, str | None]],
    ) -> None:
        self.elements.append(
            DocumentElement(
                tag=normalize_document_text(tag).casefold(),
                attributes=tuple(
                    DocumentAttribute(
                        name=normalize_document_text(name).casefold(),
                        value=normalize_document_text(value or ""),
                        source="html",
                    )
                    for name, value in attributes
                ),
            )
        )

    def handle_starttag(
        self,
        tag: str,
        attrs: list[tuple[str, str | None]],
    ) -> None:
        self._append(tag, attrs)

    def handle_startendtag(
        self,
        tag: str,
        attrs: list[tuple[str, str | None]],
    ) -> None:
        self._append(tag, attrs)

    def handle_endtag(self, tag: str) -> None:
        self.elements.append(
            DocumentElement(
                tag=normalize_document_text(tag).casefold(),
                attributes=(),
                closing=True,
            )
        )


def _parse_html_elements(text: str) -> tuple[DocumentElement, ...]:
    parser = _DocumentHTMLParser()
    try:
        parser.feed(text)
        parser.close()
    except (AssertionError, ValueError):
        return ()
    return tuple(parser.elements)


def _markdown_attribute_list(
    text: str,
) -> tuple[str, tuple[DocumentAttribute, ...]]:
    """Split one trailing Pandoc/Kramdown-style attribute list when valid."""

    compatible = normalize_document_text(text).rstrip()
    if not compatible.endswith("}"):
        return compatible, ()
    opening = compatible.rfind("{")
    if opening < 0:
        return compatible, ()
    payload = compatible[opening + 1 : -1].strip()
    if not payload:
        return compatible, ()
    lexer = shlex.shlex(payload, posix=True)
    lexer.whitespace_split = True
    lexer.commenters = ""
    try:
        parts = tuple(lexer)
    except ValueError:
        return compatible, ()
    attributes: list[DocumentAttribute] = []
    classes: list[str] = []
    for part in parts:
        if re.fullmatch(r"#[^\s{}]+", part):
            attributes.append(
                DocumentAttribute("id", html.unescape(part[1:]), "markdown")
            )
        elif re.fullmatch(r"\.[^\s{}]+", part):
            classes.append(html.unescape(part[1:]))
        elif (
            match := re.fullmatch(
                r"(?P<name>[A-Za-z_:][A-Za-z0-9_.:-]*)=(?P<value>\S+)",
                part,
            )
        ) is not None:
            attributes.append(
                DocumentAttribute(
                    normalize_document_text(match.group("name")).casefold(),
                    html.unescape(match.group("value")),
                    "markdown",
                )
            )
        else:
            return compatible, ()
    if classes:
        attributes.append(DocumentAttribute("class", " ".join(classes), "markdown"))
    return compatible[:opening].rstrip(), tuple(attributes)


def _field_parts(text: str) -> tuple[str | None, str | None]:
    match = re.match(r"^(?P<name>[^:\n]{1,80})\s*:\s*(?P<value>.*)$", text)
    if match is None:
        return None, None
    return match.group("name").strip(), match.group("value").strip()


def _heading_from_inline(inline: Token, level: int) -> CommonMarkHeading:
    raw_text = re.sub(r"\s+", " ", _inline_visible_text(inline)).strip()
    text, markdown_attributes = _markdown_attribute_list(raw_text)
    html_elements = tuple(
        element
        for child in inline.children or ()
        if child.type == "html_inline"
        for element in _parse_html_elements(child.content)
    )
    aliases = {
        attribute.value
        for attribute in (
            *markdown_attributes,
            *(
                attribute
                for element in html_elements
                for attribute in element.attributes
            ),
        )
        if attribute.name in {"id", "name"} and attribute.value
    }
    return CommonMarkHeading(level, text, tuple(sorted(aliases)))


def _inline_visible_text(token: Token) -> str:
    if not token.children:
        return token.content
    visible: list[str] = []
    for child in token.children:
        if child.type in {"html_inline", "html_block"}:
            continue
        if child.type in {"softbreak", "hardbreak"}:
            visible.append("\n")
        elif child.children:
            visible.append(_inline_visible_text(child))
        elif child.type in {"text", "code_inline"}:
            visible.append(child.content)
    return "".join(visible)


def parse_commonmark(text: str) -> CommonMarkSurface:
    """Parse operative Markdown using the CommonMark reference token semantics."""

    tokens = _COMMONMARK.parse(text)
    headings: list[CommonMarkHeading] = []
    top_level_headings: list[CommonMarkHeading] = []
    blocks: list[CommonMarkBlock] = []
    attributes: list[DocumentAttribute] = []
    elements: list[DocumentElement] = []
    visible_blocks: list[str] = []
    visible_lines: list[str] = []
    operative_lines: list[str] = []
    html_blocks: list[str] = []
    html_inlines: list[str] = []
    fences: list[tuple[str, str]] = []
    top_level_html_blocks: list[str] = []
    top_level_html_inlines: list[str] = []
    top_level_fences: list[tuple[str, str]] = []
    containers: list[str] = []
    heading_path: list[CommonMarkHeading] = []
    heading_by_inline_index: dict[int, CommonMarkHeading] = {}
    for index, token in enumerate(tokens):
        if token.type != "heading_open" or index + 1 >= len(tokens):
            continue
        inline = tokens[index + 1]
        if inline.type != "inline":
            continue
        heading_by_inline_index[index + 1] = _heading_from_inline(
            inline,
            int(token.tag.removeprefix("h")),
        )
    for index, token in enumerate(tokens):
        if token.nesting == -1:
            closing = token.type.removesuffix("_close")
            if containers and containers[-1] == closing:
                containers.pop()
        semantic_containers = tuple(
            container
            for container in containers
            if container not in {"heading", "paragraph"}
        )
        if token.type == "fence":
            fence = (token.info.strip(), token.content)
            fences.append(fence)
            if not semantic_containers:
                top_level_fences.append(fence)
        elif token.type == "html_block":
            html_blocks.append(token.content)
            parsed_elements = _parse_html_elements(token.content)
            elements.extend(parsed_elements)
            attributes.extend(
                attribute
                for element in parsed_elements
                for attribute in element.attributes
            )
            if not semantic_containers:
                top_level_html_blocks.append(token.content)
        elif token.type == "html_inline":
            html_inlines.append(token.content)
            if not semantic_containers:
                top_level_html_inlines.append(token.content)
        if token.type == "inline":
            for child in token.children or []:
                if child.type == "html_inline":
                    html_inlines.append(child.content)
                    parsed_elements = _parse_html_elements(child.content)
                    elements.extend(parsed_elements)
                    attributes.extend(
                        attribute
                        for element in parsed_elements
                        for attribute in element.attributes
                    )
                    if not semantic_containers:
                        top_level_html_inlines.append(child.content)
            visible = _inline_visible_text(token)
            normalized_block = re.sub(r"\s+", " ", visible).strip()
            rendered_block, markdown_attributes = _markdown_attribute_list(
                normalized_block
            )
            attributes.extend(markdown_attributes)
            if normalized_block:
                visible_blocks.append(normalized_block)
            normalized_lines = [
                normalized
                for line in visible.splitlines()
                if (normalized := re.sub(r"\s+", " ", line).strip())
            ]
            visible_lines.extend(normalized_lines)
            if not semantic_containers or semantic_containers == (
                "bullet_list",
                "list_item",
            ):
                operative_lines.extend(normalized_lines)
            if (
                rendered_block
                and (heading := heading_by_inline_index.get(index)) is None
            ):
                field_name, field_value = _field_parts(rendered_block)
                blocks.append(
                    CommonMarkBlock(
                        text=rendered_block,
                        heading_path=tuple(heading_path),
                        field_name=field_name,
                        field_value=field_value,
                    )
                )
            elif heading is not None:
                del heading_path[heading.level - 1 :]
                heading_path.append(heading)
        if token.type == "heading_open" and index + 1 < len(tokens):
            heading = heading_by_inline_index.get(index + 1)
            if heading is not None:
                headings.append(heading)
                if not semantic_containers:
                    top_level_headings.append(heading)
        if token.nesting == 1:
            containers.append(token.type.removesuffix("_open"))
    return CommonMarkSurface(
        headings=tuple(headings),
        top_level_headings=tuple(top_level_headings),
        blocks=tuple(blocks),
        attributes=tuple(attributes),
        elements=tuple(elements),
        visible_blocks=tuple(visible_blocks),
        visible_lines=tuple(visible_lines),
        operative_lines=tuple(operative_lines),
        html_blocks=tuple(html_blocks),
        html_inlines=tuple(html_inlines),
        html_tokens=tuple((*html_blocks, *html_inlines)),
        fences=tuple(fences),
        top_level_html_blocks=tuple(top_level_html_blocks),
        top_level_html_inlines=tuple(top_level_html_inlines),
        top_level_html_tokens=tuple(
            (*top_level_html_blocks, *top_level_html_inlines)
        ),
        top_level_fences=tuple(top_level_fences),
    )


class _StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


class AccountableRole(_StrictModel):
    id: str = Field(pattern=r"^[a-z][a-z0-9-]+$")
    kind: Literal["human", "team"]


class ProtectedSelector(_StrictModel):
    kind: SelectorKind
    value: str = Field(min_length=1)

    @model_validator(mode="after")
    def validate_selector(self) -> Self:
        if self.kind == "component":
            if re.fullmatch(r"COMP-[A-Z0-9-]+", self.value) is None:
                raise ValueError(
                    "GOV-POLICY-SELECTOR-INVALID: component IDs must use COMP-*"
                )
            return self

        if "\\" in self.value:
            raise ValueError(
                "GOV-POLICY-PATH-INVALID: selectors must use repository-relative POSIX paths"
            )
        candidate = PurePosixPath(self.value)
        if (
            candidate.is_absolute()
            or any(part in {"", ".", ".."} for part in candidate.parts)
            or any(character in self.value for character in "*?[")
        ):
            raise ValueError(
                "GOV-POLICY-PATH-INVALID: selectors cannot escape or use glob syntax"
            )
        if self.kind == "path" and self.value.endswith("/"):
            raise ValueError(
                "GOV-POLICY-PATH-INVALID: exact path selectors cannot end with '/'"
            )
        if self.kind == "path-prefix" and not self.value.endswith("/"):
            raise ValueError(
                "GOV-POLICY-PATH-INVALID: path-prefix selectors must end with '/'"
            )
        return self


class EvaluationRequirement(_StrictModel):
    selection: Literal["strongest-applicable"]
    tiers: list[EvaluationTier] = Field(min_length=1)

    @model_validator(mode="after")
    def validate_tiers(self) -> Self:
        if self.tiers != sorted(set(self.tiers)):
            raise ValueError(
                "GOV-POLICY-ORDER-INVALID: evaluation tiers must be sorted and unique"
            )
        return self


class ProtectedSurface(_StrictModel):
    id: str = Field(pattern=r"^[a-z][a-z0-9-]+$")
    selectors: list[ProtectedSelector] = Field(min_length=1)
    reviewer_roles: list[str] = Field(min_length=1)
    rollback_plan_required: Literal[True]
    evaluation: EvaluationRequirement

    @model_validator(mode="after")
    def validate_order(self) -> Self:
        selector_order = [(selector.kind, selector.value) for selector in self.selectors]
        if selector_order != sorted(set(selector_order)):
            raise ValueError(
                "GOV-POLICY-ORDER-INVALID: selectors must be sorted and unique"
            )
        if self.reviewer_roles != sorted(set(self.reviewer_roles)):
            raise ValueError(
                "GOV-POLICY-ORDER-INVALID: reviewer roles must be sorted and unique"
            )
        return self


class SelfProtectionControl(_StrictModel):
    id: str = Field(pattern=r"^[a-z][a-z0-9-]+$")
    category_id: str = Field(pattern=r"^[a-z][a-z0-9-]+$")
    selector: ProtectedSelector


class ProtectedSurfacePolicy(_StrictModel):
    schema_version: Literal[1]
    policy_id: Literal["GOV-PROTECTED-SURFACES-001"]
    accountable_roles: list[AccountableRole] = Field(min_length=1)
    forbidden_approver_kinds: list[Literal["agent", "provider"]] = Field(min_length=1)
    protected_surfaces: list[ProtectedSurface] = Field(min_length=1)
    self_protection: list[SelfProtectionControl] = Field(min_length=1)

    @model_validator(mode="after")
    def validate_contract(self) -> Self:
        role_ids = [role.id for role in self.accountable_roles]
        if role_ids != list(REQUIRED_ACCOUNTABLE_ROLES):
            raise ValueError(
                "GOV-POLICY-REVIEWERS-INCOMPLETE: release-maintainer and "
                "security-maintainer are required"
            )
        if any(role.kind not in {"human", "team"} for role in self.accountable_roles):
            raise ValueError(
                "GOV-POLICY-APPROVER-KIND-FORBIDDEN: accountable roles must be human or team"
            )
        if self.forbidden_approver_kinds != list(FORBIDDEN_APPROVER_KINDS):
            raise ValueError(
                "GOV-POLICY-FORBIDDEN-KINDS-INCOMPLETE: agent and provider must be forbidden"
            )

        surface_ids = [surface.id for surface in self.protected_surfaces]
        if surface_ids != list(REQUIRED_SURFACE_IDS):
            raise ValueError(
                "GOV-POLICY-CATEGORIES-INCOMPLETE: required protected categories are missing"
            )
        for surface in self.protected_surfaces:
            if surface.reviewer_roles != list(REQUIRED_ACCOUNTABLE_ROLES):
                raise ValueError(
                    f"GOV-POLICY-REVIEWERS-INCOMPLETE: {surface.id} must require "
                    "both accountable roles"
                )
            missing_tiers = REQUIRED_EVALUATION_TIERS[surface.id] - set(
                surface.evaluation.tiers
            )
            if missing_tiers:
                raise ValueError(
                    f"GOV-POLICY-EVALUATION-WEAKENED: {surface.id} omits "
                    f"{','.join(sorted(missing_tiers))}"
                )

        control_ids = [control.id for control in self.self_protection]
        if control_ids != sorted(REQUIRED_SELF_PROTECTION):
            raise ValueError(
                "GOV-POLICY-SELF-PROTECTION-INCOMPLETE: required controls are missing"
            )
        surfaces = {surface.id: surface for surface in self.protected_surfaces}
        for control in self.self_protection:
            expected = REQUIRED_SELF_PROTECTION[control.id]
            actual = (
                control.category_id,
                control.selector.kind,
                control.selector.value,
            )
            if actual != expected:
                raise ValueError(
                    f"GOV-POLICY-SELF-PROTECTION-WEAKENED: {control.id} target changed"
                )
            category = surfaces[control.category_id]
            if control.selector not in category.selectors:
                raise ValueError(
                    f"GOV-POLICY-SELF-PROTECTION-UNRESOLVED: {control.id} "
                    "is not selected by its category"
                )

        self._validate_selector_ambiguity()
        return self

    def _validate_selector_ambiguity(self) -> None:
        indexed = [
            (surface.id, selector)
            for surface in self.protected_surfaces
            for selector in surface.selectors
        ]
        for index, (left_category, left) in enumerate(indexed):
            for right_category, right in indexed[index + 1 :]:
                if left_category == right_category:
                    continue
                if _selectors_overlap(left, right):
                    raise ValueError(
                        "GOV-POLICY-SELECTOR-AMBIGUOUS: "
                        f"{left_category}:{left.kind}:{left.value} overlaps "
                        f"{right_category}:{right.kind}:{right.value}"
                    )


SchemaEvidenceMode = Literal["compatibility", "migration", "recovery", "rollback"]
SchemaEvidenceResult = Literal[
    "old-fixtures-readable",
    "unsupported-version-rejected",
    "migration-complete",
    "recovery-complete",
    "rollback-complete",
]


class SchemaFixture(_StrictModel):
    path: str = Field(min_length=1)
    version: int = Field(ge=0)
    sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    @model_validator(mode="after")
    def validate_path(self) -> Self:
        try:
            _normalize_repo_path(self.path)
        except GovernanceValidationError as error:
            raise ValueError(
                "GOV-SCHEMA-FIXTURE-PATH-INVALID: fixture path must be "
                "repository-relative"
            ) from error
        return self


class SchemaEvidenceRecord(_StrictModel):
    mode: SchemaEvidenceMode
    fixture_path: str = Field(min_length=1)
    fixture_version: int = Field(ge=0)
    fixture_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    exact_check: str = Field(min_length=1)
    observed_result: SchemaEvidenceResult
    exit_code: Literal[0]
    status: Literal["passed"]
    artifact_path: str = Field(min_length=1)
    artifact_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    @model_validator(mode="after")
    def validate_record(self) -> Self:
        for field, value in (
            ("fixture_path", self.fixture_path),
            ("artifact_path", self.artifact_path),
        ):
            try:
                _normalize_repo_path(value)
            except GovernanceValidationError as error:
                raise ValueError(
                    f"GOV-SCHEMA-EVIDENCE-PATH-INVALID: {field} must be "
                    "repository-relative"
                ) from error
        if "\n" in self.exact_check:
            raise ValueError(
                "GOV-SCHEMA-EVIDENCE-CHECK-INVALID: exact_check must be a "
                "concrete one-line command"
            )
        try:
            command = shlex.split(self.exact_check)
        except ValueError as error:
            raise ValueError(
                "GOV-SCHEMA-EVIDENCE-CHECK-INVALID: exact_check is not shell-parseable"
            ) from error
        if (
            len(command) < 2
            or re.fullmatch(r"[A-Za-z0-9_./-]+", command[0]) is None
        ):
            raise ValueError(
                "GOV-SCHEMA-EVIDENCE-CHECK-INVALID: exact_check must name an "
                "executable and arguments"
            )
        return self


class SchemaFixtures(_StrictModel):
    previous: list[SchemaFixture] = Field(min_length=1)
    current: list[SchemaFixture] = Field(min_length=1)

    @model_validator(mode="after")
    def validate_fixtures(self) -> Self:
        for values in (self.previous, self.current):
            paths = [fixture.path for fixture in values]
            if paths != sorted(set(paths)):
                raise ValueError(
                    "GOV-SCHEMA-FIXTURES-INVALID: fixture records must be sorted "
                    "and unique by path"
                )
        return self


SchemaProofBehavior = Literal[
    "old-fixtures-readable",
    "unsupported-version-rejected",
]


class SchemaCompatibilityProof(_StrictModel):
    behavior: SchemaProofBehavior
    records: list[SchemaEvidenceRecord] = Field(min_length=1)


class SchemaEvolutionPacket(_StrictModel):
    """Typed evidence packet required for every governed schema change."""

    packet_version: Literal[1]
    change_id: str = Field(pattern=r"^[A-Z][A-Z0-9-]+$")
    schema_id: str = Field(pattern=r"^[A-Z][A-Z0-9-]+$")
    from_version: int = Field(ge=0)
    to_version: int = Field(gt=0)
    compatibility: Literal["backward-compatible", "hard-cut"]
    reason_code: str = Field(pattern=r"^[A-Z][A-Z0-9-]+$")
    reader_strategy: Literal["explicit-version"]
    fixtures: SchemaFixtures
    compatibility_proof: SchemaCompatibilityProof
    migration: SchemaEvidenceRecord
    recovery: SchemaEvidenceRecord
    rollback: SchemaEvidenceRecord

    @model_validator(mode="after")
    def validate_semantics(self) -> Self:
        if self.to_version <= self.from_version:
            raise ValueError(
                "GOV-SCHEMA-VERSION-NOT-INCREMENTED: to_version must exceed from_version"
            )
        previous_paths = {fixture.path for fixture in self.fixtures.previous}
        current_paths = {fixture.path for fixture in self.fixtures.current}
        previous_hashes = {fixture.sha256 for fixture in self.fixtures.previous}
        current_hashes = {fixture.sha256 for fixture in self.fixtures.current}
        if previous_paths & current_paths or previous_hashes & current_hashes:
            raise ValueError(
                "GOV-SCHEMA-FIXTURES-OVERLAP: previous and current fixtures must "
                "have distinct paths and content hashes"
            )
        if any(
            fixture.version != self.from_version
            for fixture in self.fixtures.previous
        ) or any(
            fixture.version != self.to_version for fixture in self.fixtures.current
        ):
            raise ValueError(
                "GOV-SCHEMA-FIXTURE-VERSION-MISMATCH: fixture versions must match "
                "the declared from/to versions"
            )
        expected_reason_prefix = {
            "backward-compatible": "SCHEMA-BACKWARD-COMPATIBLE",
            "hard-cut": "SCHEMA-HARD-CUT",
        }[self.compatibility]
        if not self.reason_code.startswith(expected_reason_prefix):
            raise ValueError(
                "GOV-SCHEMA-REASON-CONTRADICTORY: reason code does not match "
                "the compatibility mode"
            )
        expected_behavior: SchemaProofBehavior = (
            "old-fixtures-readable"
            if self.compatibility == "backward-compatible"
            else "unsupported-version-rejected"
        )
        if self.compatibility_proof.behavior != expected_behavior:
            raise ValueError(
                "GOV-SCHEMA-PROOF-MODE-MISMATCH: compatibility proof does not "
                "match the declared mode"
            )
        previous_by_path = {fixture.path: fixture for fixture in self.fixtures.previous}
        proof_paths: list[str] = []
        for record in self.compatibility_proof.records:
            fixture = previous_by_path.get(record.fixture_path)
            if fixture is None:
                raise ValueError(
                    "GOV-SCHEMA-PROOF-FIXTURE-UNKNOWN: compatibility proof must "
                    "reference declared previous-version fixtures"
                )
            if (
                record.mode != "compatibility"
                or record.observed_result != expected_behavior
            ):
                raise ValueError(
                    "GOV-SCHEMA-PROOF-MODE-MISMATCH: compatibility evidence mode "
                    "and observed result must match the declared behavior"
                )
            if (
                record.fixture_version != fixture.version
                or record.fixture_sha256 != fixture.sha256
            ):
                raise ValueError(
                    "GOV-SCHEMA-PROOF-FIXTURE-MISMATCH: compatibility evidence "
                    "must name the declared fixture version and hash"
                )
            proof_paths.append(record.fixture_path)
        if proof_paths != sorted(previous_paths):
            raise ValueError(
                "GOV-SCHEMA-PROOF-COVERAGE-INCOMPLETE: every previous-version "
                "fixture requires one sorted evidence record"
            )

        expected_records = (
            (self.migration, "migration", "migration-complete", current_paths),
            (self.recovery, "recovery", "recovery-complete", previous_paths),
            (self.rollback, "rollback", "rollback-complete", previous_paths),
        )
        for record, mode, result, paths in expected_records:
            if (
                record.mode != mode
                or record.observed_result != result
                or record.fixture_path not in paths
            ):
                raise ValueError(
                    "GOV-SCHEMA-EVIDENCE-MODE-MISMATCH: migration, recovery, and "
                    "rollback records must prove their named operation"
                )
            fixture = {
                item.path: item
                for item in (*self.fixtures.previous, *self.fixtures.current)
            }[record.fixture_path]
            if (
                record.fixture_version != fixture.version
                or record.fixture_sha256 != fixture.sha256
            ):
                raise ValueError(
                    "GOV-SCHEMA-EVIDENCE-FIXTURE-MISMATCH: operation evidence "
                    "must name the declared fixture version and hash"
                )
        evidence_records = [
            *self.compatibility_proof.records,
            self.migration,
            self.recovery,
            self.rollback,
        ]
        artifacts = [
            (record.artifact_path, record.artifact_sha256)
            for record in evidence_records
        ]
        if len(artifacts) != len(set(artifacts)):
            raise ValueError(
                "GOV-SCHEMA-EVIDENCE-REUSED: each proof operation requires a "
                "distinct artifact path/hash"
            )
        return self


class _UniqueKeyLoader(yaml.SafeLoader):
    pass


def _construct_unique_mapping(
    loader: _UniqueKeyLoader,
    node: yaml.MappingNode,
    deep: bool = False,
) -> dict[Any, Any]:
    mapping: dict[Any, Any] = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        if key in mapping:
            raise GovernanceValidationError(
                [
                    GovernanceDiagnostic(
                        "GOV-POLICY-YAML-DUPLICATE-KEY",
                        str(key),
                        "mapping keys must be unique",
                    )
                ]
            )
        mapping[key] = loader.construct_object(value_node, deep=deep)
    return mapping


_UniqueKeyLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,
    _construct_unique_mapping,
)


def _selectors_overlap(left: ProtectedSelector, right: ProtectedSelector) -> bool:
    if left.kind == "component" or right.kind == "component":
        return left.kind == right.kind and left.value == right.value
    if left.kind == "path" and right.kind == "path":
        return left.value == right.value
    if left.kind == "path-prefix" and right.kind == "path-prefix":
        return left.value.startswith(right.value) or right.value.startswith(left.value)
    exact = left if left.kind == "path" else right
    prefix = right if right.kind == "path-prefix" else left
    return exact.value.startswith(prefix.value)


def _diagnostics_from_validation(
    error: ValidationError,
    *,
    prefix: str,
) -> list[GovernanceDiagnostic]:
    diagnostics: list[GovernanceDiagnostic] = []
    for item in error.errors():
        location = ".".join(str(part) for part in item["loc"]) or "<root>"
        error_type = item["type"]
        if error_type == "missing":
            code = f"{prefix}-FIELD-MISSING"
        elif error_type == "extra_forbidden":
            code = f"{prefix}-FIELD-UNKNOWN"
        elif error_type.endswith("_type"):
            code = f"{prefix}-TYPE-INVALID"
        elif error_type in {"literal_error", "string_pattern_mismatch"}:
            code = f"{prefix}-VALUE-UNSUPPORTED"
        else:
            context_error = item.get("ctx", {}).get("error")
            detail = str(context_error) if context_error is not None else ""
            code = detail.partition(":")[0] if detail.startswith("GOV-") else f"{prefix}-VALUE-INVALID"
        diagnostics.append(GovernanceDiagnostic(code, location, item["msg"]))
    return diagnostics


def validate_policy_data(data: Any) -> ProtectedSurfacePolicy:
    try:
        return ProtectedSurfacePolicy.model_validate(data)
    except ValidationError as error:
        raise GovernanceValidationError(
            _diagnostics_from_validation(error, prefix="GOV-POLICY")
        ) from error


def load_protected_surface_policy(path: Path) -> ProtectedSurfacePolicy:
    try:
        data = yaml.load(path.read_text(encoding="utf-8"), Loader=_UniqueKeyLoader)
    except GovernanceValidationError:
        raise
    except (OSError, yaml.YAMLError) as error:
        raise GovernanceValidationError(
            [
                GovernanceDiagnostic(
                    "GOV-POLICY-YAML-INVALID",
                    path.as_posix(),
                    str(error),
                )
            ]
        ) from error
    return validate_policy_data(data)


def _schema_evidence_records(
    packet: SchemaEvolutionPacket,
) -> tuple[tuple[str, SchemaEvidenceRecord], ...]:
    records = [
        (f"compatibility_proof.records.{index}", record)
        for index, record in enumerate(packet.compatibility_proof.records)
    ]
    records.extend(
        (
            ("migration", packet.migration),
            ("recovery", packet.recovery),
            ("rollback", packet.rollback),
        )
    )
    return tuple(records)


def _is_allowed_schema_path(value: str, prefix: str) -> bool:
    candidate = PurePosixPath(value)
    allowed = PurePosixPath(prefix)
    return candidate != allowed and allowed in candidate.parents


def _resolve_schema_evidence_file(
    root: Path,
    relative: str,
    *,
    allowed_prefix: str,
    location: str,
    missing_code: str,
    diagnostics: list[GovernanceDiagnostic],
) -> Path | None:
    try:
        normalized = _normalize_repo_path(relative)
    except GovernanceValidationError:
        diagnostics.append(
            GovernanceDiagnostic(
                "GOV-SCHEMA-EVIDENCE-PATH-INVALID",
                location,
                f"path must use normalized repository-relative {allowed_prefix}/ syntax",
            )
        )
        return None
    if not _is_allowed_schema_path(normalized, allowed_prefix):
        diagnostics.append(
            GovernanceDiagnostic(
                "GOV-SCHEMA-EVIDENCE-PATH-INVALID",
                location,
                f"path must be beneath {allowed_prefix}/",
            )
        )
        return None

    cursor = root
    for part in PurePosixPath(normalized).parts:
        try:
            entries = {entry.name: entry for entry in os.scandir(cursor)}
        except OSError:
            entries = {}
        entry = entries.get(part)
        if entry is None or entry.is_symlink():
            diagnostics.append(
                GovernanceDiagnostic(
                    missing_code,
                    location,
                    f"{relative!r} is not a regular repository file",
                )
            )
            return None
        cursor /= part
    if not cursor.is_file():
        diagnostics.append(
            GovernanceDiagnostic(
                missing_code,
                location,
                f"{relative!r} is not a regular repository file",
            )
        )
        return None
    try:
        cursor.resolve(strict=True).relative_to(root)
    except (OSError, ValueError):
        diagnostics.append(
            GovernanceDiagnostic(
                missing_code,
                location,
                f"{relative!r} is not a regular repository file",
            )
        )
        return None
    return cursor


def _sha256_path(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _schema_shell_check_is_safe(
    root: Path,
    script: Path,
    *,
    required_path: str,
) -> bool:
    try:
        lines = script.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeError):
        return False
    checked_paths: set[str] = set()
    for raw_line in lines:
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if re.fullmatch(r"set -[eu]+", line):
            continue
        if any(character in line for character in ";&|><`$(){}"):
            return False
        try:
            command = shlex.split(line)
        except ValueError:
            return False
        if (
            len(command) == 3
            and command[0] == "test"
            and command[1] in {"-f", "-r", "-s"}
        ):
            relative = command[2]
        elif (
            len(command) == 4
            and command[0] == "["
            and command[1] in {"-f", "-r", "-s"}
            and command[3] == "]"
        ):
            relative = command[2]
        elif command == ["exit", "0"] and checked_paths:
            continue
        else:
            return False
        try:
            normalized = _normalize_repo_path(relative)
            (root / normalized).resolve(strict=False).relative_to(root)
        except (GovernanceValidationError, ValueError):
            return False
        checked_paths.add(normalized)
    return required_path in checked_paths


def _safe_schema_check_argv(
    root: Path,
    record: SchemaEvidenceRecord,
    *,
    location: str,
    diagnostics: list[GovernanceDiagnostic],
) -> tuple[str, ...] | None:
    if any(character in record.exact_check for character in "\r\n;&|><`$"):
        diagnostics.append(
            GovernanceDiagnostic(
                "GOV-SCHEMA-EVIDENCE-CHECK-INVALID",
                f"{location}.exact_check",
                "declared check contains unsupported shell syntax",
            )
        )
        return None
    try:
        command = shlex.split(record.exact_check)
    except ValueError:
        command = []

    artifact = PurePosixPath(record.artifact_path)
    if (
        len(command) == 2
        and command[0] in {"sh", "/bin/sh"}
        and command[1].endswith(".sh")
    ):
        script_relative = command[1]
        script = _resolve_schema_evidence_file(
            root,
            script_relative,
            allowed_prefix="evidence",
            location=f"{location}.exact_check",
            missing_code="GOV-SCHEMA-EVIDENCE-CHECK-MISSING",
            diagnostics=diagnostics,
        )
        script_path = PurePosixPath(script_relative)
        if (
            script_path.parent != artifact.parent
            or script_path.stem != artifact.stem
        ):
            diagnostics.append(
                GovernanceDiagnostic(
                    "GOV-SCHEMA-EVIDENCE-CHECK-UNBOUND",
                    f"{location}.exact_check",
                    "check script and recorded artifact must share a path stem",
                )
            )
            return None
        if script is not None and not _schema_shell_check_is_safe(
            root,
            script,
            required_path=record.artifact_path,
        ):
            diagnostics.append(
                GovernanceDiagnostic(
                    "GOV-SCHEMA-EVIDENCE-CHECK-UNSAFE",
                    f"{location}.exact_check",
                    "repository check script contains non-read-only operations",
                )
            )
            return None
        return ("/bin/sh", str(script)) if script is not None else None

    pytest_prefixes = (
        ("uv", "run", "pytest"),
        ("uv", "run", "python", "-m", "pytest"),
        ("python", "-m", "pytest"),
        ("python3", "-m", "pytest"),
    )
    prefix = next(
        (
            candidate
            for candidate in pytest_prefixes
            if tuple(command[: len(candidate)]) == candidate
        ),
        None,
    )
    if prefix is not None:
        arguments = command[len(prefix) :]
        targets = [
            argument
            for argument in arguments
            if not argument.startswith("-") and argument != "no:cacheprovider"
        ]
        allowed_options = {"-q", "--quiet", "-x", "-p", "no:cacheprovider"}
        if len(targets) == 1 and all(
            argument in allowed_options or argument == targets[0]
            for argument in arguments
        ):
            target_path, _, node = targets[0].partition("::")
            test_file = _resolve_schema_evidence_file(
                root,
                target_path,
                allowed_prefix="tests",
                location=f"{location}.exact_check",
                missing_code="GOV-SCHEMA-EVIDENCE-CHECK-MISSING",
                diagnostics=diagnostics,
            )
            if (
                test_file is not None
                and (
                    test_file.suffix != ".py"
                    or not node
                    or artifact.stem not in node
                )
            ):
                diagnostics.append(
                    GovernanceDiagnostic(
                        "GOV-SCHEMA-EVIDENCE-CHECK-UNBOUND",
                        f"{location}.exact_check",
                        "pytest node and recorded artifact must share an identifier",
                    )
                )
                return None
            if test_file is not None:
                return (
                    command[0],
                    *command[1 : len(prefix)],
                    "-p",
                    "no:cacheprovider",
                    *(
                        argument
                        for argument in arguments
                        if argument not in {"-p", "no:cacheprovider"}
                    ),
                )
        diagnostics.append(
            GovernanceDiagnostic(
                "GOV-SCHEMA-EVIDENCE-CHECK-INVALID",
                f"{location}.exact_check",
                "pytest checks require one repository test node and safe options",
            )
        )
        return None

    diagnostics.append(
        GovernanceDiagnostic(
            "GOV-SCHEMA-EVIDENCE-CHECK-INVALID",
            f"{location}.exact_check",
            "declared check must use an allowed repository script or pytest node",
        )
    )
    return None


def _schema_provenance_diagnostics(
    packet: SchemaEvolutionPacket,
    root: Path,
) -> list[GovernanceDiagnostic]:
    diagnostics: list[GovernanceDiagnostic] = []
    fixture_paths: dict[str, str] = {}
    fixture_hashes: dict[str, str] = {}
    observed_files: list[tuple[Path, str, str, str]] = []
    for group_name, group in (
        ("previous", packet.fixtures.previous),
        ("current", packet.fixtures.current),
    ):
        for index, fixture in enumerate(group):
            location = f"fixtures.{group_name}.{index}"
            prior_hash = fixture_paths.setdefault(fixture.path, fixture.sha256)
            prior_path = fixture_hashes.setdefault(fixture.sha256, fixture.path)
            if prior_hash != fixture.sha256 or prior_path != fixture.path:
                diagnostics.append(
                    GovernanceDiagnostic(
                        "GOV-SCHEMA-FIXTURE-RELATIONSHIP-CONFLICT",
                        location,
                        "fixture paths and content hashes must have one consistent mapping",
                    )
                )
            path = _resolve_schema_evidence_file(
                root,
                fixture.path,
                allowed_prefix="tests/fixtures",
                location=f"{location}.path",
                missing_code="GOV-SCHEMA-FIXTURE-FILE-MISSING",
                diagnostics=diagnostics,
            )
            if path is not None:
                observed_files.append(
                    (
                        path,
                        fixture.sha256,
                        location,
                        "GOV-SCHEMA-FIXTURE-HASH-MISMATCH",
                    )
                )

    artifact_paths: dict[str, str] = {}
    artifact_hashes: dict[str, str] = {}
    exact_checks: set[str] = set()
    runnable: list[tuple[str, tuple[str, ...]]] = []
    for location, record in _schema_evidence_records(packet):
        prior_hash = artifact_paths.setdefault(
            record.artifact_path, record.artifact_sha256
        )
        prior_path = artifact_hashes.setdefault(
            record.artifact_sha256, record.artifact_path
        )
        if prior_hash != record.artifact_sha256 or prior_path != record.artifact_path:
            diagnostics.append(
                GovernanceDiagnostic(
                    "GOV-SCHEMA-EVIDENCE-RELATIONSHIP-CONFLICT",
                    location,
                    "artifact paths and content hashes must have one consistent mapping",
                )
            )
        if record.exact_check in exact_checks:
            diagnostics.append(
                GovernanceDiagnostic(
                    "GOV-SCHEMA-EVIDENCE-CHECK-REUSED",
                    f"{location}.exact_check",
                    "each proof operation requires a distinct declared check",
                )
            )
        exact_checks.add(record.exact_check)
        artifact = _resolve_schema_evidence_file(
            root,
            record.artifact_path,
            allowed_prefix="evidence",
            location=f"{location}.artifact_path",
            missing_code="GOV-SCHEMA-EVIDENCE-FILE-MISSING",
            diagnostics=diagnostics,
        )
        if artifact is not None:
            observed_files.append(
                (
                    artifact,
                    record.artifact_sha256,
                    location,
                    "GOV-SCHEMA-EVIDENCE-HASH-MISMATCH",
                )
            )
        argv = _safe_schema_check_argv(
            root,
            record,
            location=location,
            diagnostics=diagnostics,
        )
        if argv is not None:
            runnable.append((location, argv))

    for path, expected, location, code in observed_files:
        try:
            actual = _sha256_path(path)
        except OSError:
            actual = ""
        if actual != expected:
            diagnostics.append(
                GovernanceDiagnostic(
                    code,
                    location,
                    "declared SHA-256 does not match repository file bytes",
                )
            )
    if diagnostics:
        return diagnostics

    check_environment = {
        key: value
        for key in ("LANG", "LC_ALL", "PATH", "TMPDIR")
        if (value := os.environ.get(key)) is not None
    }
    check_environment["PYTHONDONTWRITEBYTECODE"] = "1"
    for location, argv in runnable:
        try:
            result = subprocess.run(
                argv,
                cwd=root,
                env=check_environment,
                check=False,
                capture_output=True,
                timeout=30,
            )
        except (OSError, subprocess.TimeoutExpired):
            diagnostics.append(
                GovernanceDiagnostic(
                    "GOV-SCHEMA-EVIDENCE-CHECK-FAILED",
                    f"{location}.exact_check",
                    "declared check could not complete",
                )
            )
            continue
        if result.returncode != 0:
            diagnostics.append(
                GovernanceDiagnostic(
                    "GOV-SCHEMA-EVIDENCE-CHECK-FAILED",
                    f"{location}.exact_check",
                    f"declared check exited {result.returncode}, expected 0",
                )
            )

    for path, expected, location, code in observed_files:
        try:
            actual = _sha256_path(path)
        except OSError:
            actual = ""
        if actual != expected:
            diagnostics.append(
                GovernanceDiagnostic(
                    code,
                    location,
                    "repository evidence changed while its check executed",
                )
            )
    return diagnostics


def validate_schema_change_data(
    data: Any,
    *,
    repository_root: Path | None = None,
) -> SchemaEvolutionPacket:
    try:
        packet = SchemaEvolutionPacket.model_validate(data)
    except ValidationError as error:
        raise GovernanceValidationError(
            _diagnostics_from_validation(error, prefix="GOV-SCHEMA")
        ) from error
    try:
        root = (repository_root or Path.cwd()).resolve(strict=True)
    except OSError as error:
        raise GovernanceValidationError(
            [
                GovernanceDiagnostic(
                    "GOV-SCHEMA-EVIDENCE-ROOT-INVALID",
                    ".",
                    type(error).__name__,
                )
            ]
        ) from error
    diagnostics = _schema_provenance_diagnostics(packet, root)
    if diagnostics:
        raise GovernanceValidationError(diagnostics)
    return packet


def load_component_paths(path: Path) -> dict[str, tuple[str, ...]]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        components = data["components"]
        return {
            component["id"]: tuple(component["paths"])
            for component in components
        }
    except (OSError, json.JSONDecodeError, KeyError, TypeError) as error:
        raise GovernanceValidationError(
            [
                GovernanceDiagnostic(
                    "GOV-COMPONENT-MAP-INVALID",
                    path.as_posix(),
                    str(error),
                )
            ]
        ) from error


def validate_policy_components(
    policy: ProtectedSurfacePolicy,
    component_paths: dict[str, tuple[str, ...]],
) -> None:
    diagnostics = [
        GovernanceDiagnostic(
            "GOV-POLICY-COMPONENT-UNKNOWN",
            f"{surface.id}.{selector.value}",
            "component selector does not resolve in the canonical component map",
        )
        for surface in policy.protected_surfaces
        for selector in surface.selectors
        if selector.kind == "component" and selector.value not in component_paths
    ]
    diagnostics.extend(
        GovernanceDiagnostic(
            "GOV-COMPONENT-PROTECTED-CATALOG-MISMATCH",
            component_id,
            "protected component paths must match the authoritative catalog",
        )
        for component_id, expected_paths in REQUIRED_PROTECTED_COMPONENT_PATHS.items()
        if component_paths.get(component_id) != expected_paths
    )
    if diagnostics:
        raise GovernanceValidationError(diagnostics)


def _normalize_repo_path(value: str) -> str:
    if not value or value != value.strip() or "\\" in value or "//" in value:
        raise GovernanceValidationError(
            [
                GovernanceDiagnostic(
                    "GOV-PATH-INVALID",
                    value,
                    "changed paths must use repository-relative POSIX syntax",
                )
            ]
        )
    path = PurePosixPath(value)
    if (
        path.is_absolute()
        or any(part in {"", ".", ".."} for part in path.parts)
        or path.as_posix() != value
    ):
        raise GovernanceValidationError(
            [
                GovernanceDiagnostic(
                    "GOV-PATH-INVALID",
                    value,
                    "changed path escapes the repository or is empty",
                )
            ]
        )
    return path.as_posix()


EVIDENCE_POLICY_PATH = "docs/architecture/evidence-policy.json"


@dataclass(frozen=True)
class EvidenceRecordValidation:
    """Validated state of one cataloged evidence record."""

    mode: str
    passing: bool
    record_type: str


def _evidence_diagnostic(
    code: str,
    location: str,
    message: str,
) -> GovernanceValidationError:
    return GovernanceValidationError(
        [GovernanceDiagnostic(code, location, message)]
    )


def _regular_repository_file(
    root: Path,
    relative: str,
    *,
    location: str,
    missing_code: str,
) -> Path:
    try:
        normalized = _normalize_repo_path(relative)
    except GovernanceValidationError as error:
        raise _evidence_diagnostic(
            "GOV-EVIDENCE-PATH-INVALID",
            location,
            "reference must be a normalized repository-relative path",
        ) from error
    cursor = root
    for part in PurePosixPath(normalized).parts:
        try:
            entries = {entry.name: entry for entry in os.scandir(cursor)}
        except OSError:
            entries = {}
        entry = entries.get(part)
        if entry is None or entry.is_symlink():
            raise _evidence_diagnostic(
                missing_code,
                location,
                f"{relative!r} is not a regular repository file",
            )
        cursor /= part
    try:
        resolved = cursor.resolve(strict=True)
        resolved.relative_to(root)
    except (OSError, ValueError) as error:
        raise _evidence_diagnostic(
            missing_code,
            location,
            f"{relative!r} is not a regular repository file",
        ) from error
    if not resolved.is_file():
        raise _evidence_diagnostic(
            missing_code,
            location,
            f"{relative!r} is not a regular repository file",
        )
    return resolved


def _load_evidence_policy(root: Path) -> dict[str, Any]:
    path = _regular_repository_file(
        root,
        EVIDENCE_POLICY_PATH,
        location=EVIDENCE_POLICY_PATH,
        missing_code="GOV-EVIDENCE-POLICY-MISSING",
    )
    try:
        policy = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise _evidence_diagnostic(
            "GOV-EVIDENCE-POLICY-INVALID",
            EVIDENCE_POLICY_PATH,
            type(error).__name__,
        ) from error
    if (
        not isinstance(policy, dict)
        or policy.get("schema_version") != 1
        or not isinstance(policy.get("positive_record"), dict)
        or not isinstance(policy.get("non_passing_record"), dict)
    ):
        raise _evidence_diagnostic(
            "GOV-EVIDENCE-POLICY-INVALID",
            EVIDENCE_POLICY_PATH,
            "catalog does not match the version-1 evidence contract",
        )
    return policy


def validate_evidence_record_reference(
    reference: str,
    *,
    repository_root: Path,
    expected_mode: str,
) -> EvidenceRecordValidation:
    """Validate one typed record without inferring evidence from free prose."""

    try:
        root = repository_root.resolve(strict=True)
    except OSError as error:
        raise _evidence_diagnostic(
            "GOV-EVIDENCE-ROOT-INVALID",
            ".",
            type(error).__name__,
        ) from error
    policy = _load_evidence_policy(root)
    positive = policy["positive_record"]
    non_passing = policy["non_passing_record"]
    record_prefix = positive.get("record_prefix")
    if (
        not isinstance(record_prefix, str)
        or not reference.startswith(record_prefix)
        or not reference.endswith(".json")
    ):
        raise _evidence_diagnostic(
            "GOV-EVIDENCE-REFERENCE-INVALID",
            reference,
            "expected a cataloged JSON evidence-record path",
        )
    path = _regular_repository_file(
        root,
        reference,
        location=reference,
        missing_code="GOV-EVIDENCE-RECORD-MISSING",
    )
    try:
        record = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise _evidence_diagnostic(
            "GOV-EVIDENCE-RECORD-INVALID",
            reference,
            type(error).__name__,
        ) from error
    if not isinstance(record, dict):
        raise _evidence_diagnostic(
            "GOV-EVIDENCE-RECORD-INVALID",
            reference,
            "evidence record must be a JSON object",
        )

    record_type = record.get("record_type")
    mode = record.get("mode")
    if not isinstance(mode, str) or mode != expected_mode:
        raise _evidence_diagnostic(
            "GOV-EVIDENCE-MODE-MISMATCH",
            reference,
            f"expected mode {expected_mode!r}",
        )
    allowed_results = positive.get("observed_results")
    if not isinstance(allowed_results, dict) or mode not in allowed_results:
        raise _evidence_diagnostic(
            "GOV-EVIDENCE-MODE-UNSUPPORTED",
            reference,
            f"mode {mode!r} is not cataloged",
        )

    non_passing_types = non_passing.get("allowed_record_types")
    if isinstance(non_passing_types, list) and record_type in non_passing_types:
        required = non_passing.get("required_fields")
        if (
            not isinstance(required, list)
            or set(record) != set(required)
            or record.get("schema_version") != 1
            or record.get("status") != non_passing.get("status")
            or not isinstance(record.get("summary"), str)
            or not record["summary"].strip()
        ):
            raise _evidence_diagnostic(
                "GOV-EVIDENCE-NONPASSING-INVALID",
                reference,
                "typed history/limitation record has invalid fields",
            )
        return EvidenceRecordValidation(mode, False, str(record_type))

    required = positive.get("required_fields")
    if (
        record_type != "evidence"
        or not isinstance(required, list)
        or set(record) != set(required)
        or record.get("schema_version") != positive.get("schema_version")
        or record.get("status") != positive.get("status")
    ):
        raise _evidence_diagnostic(
            "GOV-EVIDENCE-RECORD-INVALID",
            reference,
            "positive record fields do not match the catalog",
        )
    observed_result = record.get("observed_result")
    mode_results = allowed_results[mode]
    if (
        not isinstance(mode_results, list)
        or observed_result not in mode_results
    ):
        raise _evidence_diagnostic(
            "GOV-EVIDENCE-RESULT-INVALID",
            reference,
            f"observed result is not enumerated for mode {mode!r}",
        )
    if record.get("exit_code") != positive.get("successful_exit_code"):
        raise _evidence_diagnostic(
            "GOV-EVIDENCE-EXECUTION-NONPASSING",
            reference,
            "positive evidence requires declared successful execution",
        )

    artifact_path = record.get("artifact_path")
    artifact_sha256 = record.get("artifact_sha256")
    artifact_prefix = positive.get("artifact_prefix")
    if (
        not isinstance(artifact_path, str)
        or not isinstance(artifact_prefix, str)
        or not artifact_path.startswith(artifact_prefix)
        or not isinstance(artifact_sha256, str)
        or re.fullmatch(r"[0-9a-f]{64}", artifact_sha256) is None
    ):
        raise _evidence_diagnostic(
            "GOV-EVIDENCE-ARTIFACT-INVALID",
            reference,
            "artifact path and SHA-256 must match the catalog",
        )
    artifact = _regular_repository_file(
        root,
        artifact_path,
        location=f"{reference}#artifact_path",
        missing_code="GOV-EVIDENCE-ARTIFACT-MISSING",
    )
    before_hash = _sha256_path(artifact)
    if before_hash != artifact_sha256:
        raise _evidence_diagnostic(
            "GOV-EVIDENCE-ARTIFACT-HASH-MISMATCH",
            reference,
            "declared artifact SHA-256 does not match repository bytes",
        )

    exact_check = record.get("exact_check")
    permitted_checks = positive.get("permitted_checks")
    expected_checks = {
        item["command"].replace("{artifact_path}", artifact_path)
        for item in permitted_checks
        if isinstance(item, dict)
        and isinstance(item.get("command"), str)
    } if isinstance(permitted_checks, list) else set()
    if not isinstance(exact_check, str) or exact_check not in expected_checks:
        raise _evidence_diagnostic(
            "GOV-EVIDENCE-CHECK-INVALID",
            reference,
            "exact_check is not a permitted check bound to artifact_path",
        )
    argv = tuple(shlex.split(exact_check))
    check_environment = {
        key: value
        for key in ("LANG", "LC_ALL", "PATH", "TMPDIR")
        if (value := os.environ.get(key)) is not None
    }
    try:
        result = subprocess.run(
            argv,
            cwd=root,
            env=check_environment,
            check=False,
            capture_output=True,
            timeout=30,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise _evidence_diagnostic(
            "GOV-EVIDENCE-CHECK-FAILED",
            reference,
            "permitted check could not complete",
        ) from error
    if result.returncode != positive.get("successful_exit_code"):
        raise _evidence_diagnostic(
            "GOV-EVIDENCE-CHECK-FAILED",
            reference,
            f"permitted check exited {result.returncode}",
        )
    if _sha256_path(artifact) != before_hash:
        raise _evidence_diagnostic(
            "GOV-EVIDENCE-ARTIFACT-CHANGED",
            reference,
            "bound artifact changed while its check executed",
        )
    return EvidenceRecordValidation(mode, True, "evidence")


def validate_schema_change_reference(
    reference: str,
    *,
    repository_root: Path,
) -> SchemaEvolutionPacket:
    """Resolve and validate the typed schema-evolution packet named by a trailer."""

    root = repository_root.resolve(strict=True)
    if (
        not reference.startswith("evidence/")
        or PurePosixPath(reference).suffix not in {".json", ".yaml", ".yml"}
    ):
        raise _evidence_diagnostic(
            "GOV-SCHEMA-REFERENCE-INVALID",
            reference,
            "expected an evidence/ JSON or YAML schema-evolution packet",
        )
    path = _regular_repository_file(
        root,
        reference,
        location=reference,
        missing_code="GOV-SCHEMA-PACKET-MISSING",
    )
    try:
        data = yaml.load(path.read_text(encoding="utf-8"), Loader=_UniqueKeyLoader)
    except GovernanceValidationError:
        raise
    except (OSError, UnicodeError, yaml.YAMLError) as error:
        raise _evidence_diagnostic(
            "GOV-SCHEMA-PACKET-INVALID",
            reference,
            type(error).__name__,
        ) from error
    return validate_schema_change_data(data, repository_root=root)


def _component_matches(
    path: str,
    component_id: str,
    component_paths: dict[str, tuple[str, ...]],
) -> bool:
    return any(
        fnmatch.fnmatchcase(path, pattern) or PurePosixPath(path).match(pattern)
        for pattern in component_paths[component_id]
    )


def resolve_path_category(
    policy: ProtectedSurfacePolicy,
    component_paths: dict[str, tuple[str, ...]],
    changed_path: str,
) -> str | None:
    path = _normalize_repo_path(changed_path)
    matches: set[str] = set()
    for surface in policy.protected_surfaces:
        for selector in surface.selectors:
            if selector.kind == "path" and path == selector.value:
                matches.add(surface.id)
            elif selector.kind == "path-prefix" and path.startswith(selector.value):
                matches.add(surface.id)
            elif selector.kind == "component" and _component_matches(
                path, selector.value, component_paths
            ):
                matches.add(surface.id)
    if len(matches) > 1:
        raise GovernanceValidationError(
            [
                GovernanceDiagnostic(
                    "GOV-POLICY-PATH-AMBIGUOUS",
                    path,
                    f"matches categories {','.join(sorted(matches))}",
                )
            ]
        )
    return next(iter(matches), None)


def governance_report(
    policy: ProtectedSurfacePolicy,
    component_paths: dict[str, tuple[str, ...]],
    paths: tuple[str, ...],
) -> dict[str, Any]:
    validate_policy_components(policy, component_paths)
    resolved = {
        path: category
        for path in sorted(set(paths))
        if (category := resolve_path_category(policy, component_paths, path)) is not None
    }
    return {
        "accountable_roles": [role.model_dump(mode="json") for role in policy.accountable_roles],
        "path_categories": resolved,
        "policy_id": policy.policy_id,
        "protected_surfaces": {
            surface.id: {
                "evaluation": surface.evaluation.model_dump(mode="json"),
                "reviewer_roles": surface.reviewer_roles,
                "rollback_plan_required": surface.rollback_plan_required,
            }
            for surface in policy.protected_surfaces
        },
        "schema_version": policy.schema_version,
        "self_protection": {
            control.id: {
                "category_id": control.category_id,
                "selector": control.selector.model_dump(mode="json"),
            }
            for control in policy.self_protection
        },
    }


COMMIT_TYPES = (
    "build",
    "chore",
    "ci",
    "docs",
    "feat",
    "fix",
    "perf",
    "refactor",
    "revert",
    "test",
)
COMMIT_TRAILERS = (
    "Task-ID",
    "Contract-Targets",
    "Decision-IDs",
    "Protected-Surfaces",
    "Human-Reviewers",
    "Evaluation-Evidence",
    "Schema-Change",
    "Rollback-Plan",
)
_SUBJECT_RE = re.compile(
    r"^(?P<type>[a-z]+)(?:\((?P<scope>[a-z0-9][a-z0-9-]*)\))?"
    r"(?P<breaking>!)?: (?P<summary>\S.*)$"
)
_TRAILER_RE = re.compile(r"^(?P<key>[A-Za-z][A-Za-z0-9-]*): (?P<value>\S.*)$")


@dataclass(frozen=True)
class CommitCheckResult:
    protected_surfaces: tuple[str, ...]
    trailers: dict[str, str]


def _csv_value(value: str, *, code: str, location: str) -> tuple[str, ...]:
    if value == "none":
        return ()
    values = tuple(part.strip() for part in value.split(","))
    if (
        any(not part for part in values)
        or tuple(sorted(set(values))) != values
    ):
        raise GovernanceValidationError(
            [
                GovernanceDiagnostic(
                    code,
                    location,
                    "comma-separated values must be sorted, unique, and non-empty",
                )
            ]
        )
    return values


def check_commit_message(
    message: str,
    *,
    changed_paths: tuple[str, ...],
    policy: ProtectedSurfacePolicy,
    component_paths: dict[str, tuple[str, ...]],
    repository_root: Path | None = None,
) -> CommitCheckResult:
    diagnostics: list[GovernanceDiagnostic] = []
    normalized = message.rstrip("\n")
    blocks = re.split(r"\n[ \t]*\n", normalized)
    subject = blocks[0].splitlines()[0] if blocks and blocks[0] else ""
    subject_match = _SUBJECT_RE.fullmatch(subject)
    if subject_match is None:
        diagnostics.append(
            GovernanceDiagnostic(
                "GOV-COMMIT-SUBJECT-FORMAT",
                "subject",
                "expected type(scope): imperative summary",
            )
        )
    else:
        commit_type = subject_match.group("type")
        summary = subject_match.group("summary")
        if commit_type not in COMMIT_TYPES:
            diagnostics.append(
                GovernanceDiagnostic(
                    "GOV-COMMIT-SUBJECT-TYPE",
                    "subject",
                    f"unsupported type {commit_type!r}",
                )
            )
        if summary[0].isupper() or summary.endswith("."):
            diagnostics.append(
                GovernanceDiagnostic(
                    "GOV-COMMIT-SUBJECT-SUMMARY",
                    "subject",
                    "summary must start lowercase and omit a trailing period",
                )
            )
    if len(subject) > 72:
        diagnostics.append(
            GovernanceDiagnostic(
                "GOV-COMMIT-SUBJECT-LENGTH",
                "subject",
                "subject exceeds 72 characters",
            )
        )

    trailer_lines = blocks[-1].splitlines() if len(blocks) > 1 else []
    parsed: list[tuple[str, str]] = []
    for index, line in enumerate(trailer_lines, start=1):
        match = _TRAILER_RE.fullmatch(line)
        if match is None:
            diagnostics.append(
                GovernanceDiagnostic(
                    "GOV-COMMIT-TRAILER-FORMAT",
                    f"trailers.{index}",
                    "expected Key: non-empty value",
                )
            )
            continue
        parsed.append((match.group("key"), match.group("value")))

    trailer_keys = [key for key, _value in parsed]
    for key in COMMIT_TRAILERS:
        count = trailer_keys.count(key)
        if count == 0:
            diagnostics.append(
                GovernanceDiagnostic(
                    "GOV-COMMIT-TRAILER-MISSING",
                    key,
                    "required trailer is absent",
                )
            )
        elif count > 1:
            diagnostics.append(
                GovernanceDiagnostic(
                    "GOV-COMMIT-TRAILER-DUPLICATE",
                    key,
                    "required trailer appears more than once",
                )
            )
    for key in sorted(set(trailer_keys) - set(COMMIT_TRAILERS)):
        diagnostics.append(
            GovernanceDiagnostic(
                "GOV-COMMIT-TRAILER-UNKNOWN",
                key,
                "unknown governance trailer",
            )
        )
    if trailer_keys != list(COMMIT_TRAILERS):
        diagnostics.append(
            GovernanceDiagnostic(
                "GOV-COMMIT-TRAILER-ORDER",
                "trailers",
                "trailers must appear once in the documented order",
            )
        )
    if diagnostics:
        raise GovernanceValidationError(diagnostics)

    trailers = dict(parsed)
    if re.fullmatch(r"[A-Za-z][A-Za-z0-9_-]*", trailers["Task-ID"]) is None:
        diagnostics.append(
            GovernanceDiagnostic(
                "GOV-COMMIT-TASK-ID-INVALID",
                "Task-ID",
                "expected one stable task ID",
            )
        )
    contract_targets = _csv_value(
        trailers["Contract-Targets"],
        code="GOV-COMMIT-CONTRACT-TARGETS-INVALID",
        location="Contract-Targets",
    )
    if any(re.fullmatch(r"VAL-[A-Z0-9-]+", value) is None for value in contract_targets):
        diagnostics.append(
            GovernanceDiagnostic(
                "GOV-COMMIT-CONTRACT-TARGETS-INVALID",
                "Contract-Targets",
                "expected VAL-* IDs or none",
            )
        )
    decision_ids = _csv_value(
        trailers["Decision-IDs"],
        code="GOV-COMMIT-DECISION-IDS-INVALID",
        location="Decision-IDs",
    )
    if any(re.fullmatch(r"ADR-[0-9]{4}", value) is None for value in decision_ids):
        diagnostics.append(
            GovernanceDiagnostic(
                "GOV-COMMIT-DECISION-IDS-INVALID",
                "Decision-IDs",
                "expected ADR-NNNN IDs or none",
            )
        )

    expected_surfaces = tuple(
        sorted(
            {
                category
                for path in changed_paths
                if (
                    category := resolve_path_category(policy, component_paths, path)
                )
                is not None
            }
        )
    )
    declared_surfaces = _csv_value(
        trailers["Protected-Surfaces"],
        code="GOV-COMMIT-PROTECTED-SURFACES-INVALID",
        location="Protected-Surfaces",
    )
    if declared_surfaces != expected_surfaces:
        diagnostics.append(
            GovernanceDiagnostic(
                "GOV-COMMIT-PROTECTED-SURFACES-MISMATCH",
                "Protected-Surfaces",
                f"expected {','.join(expected_surfaces) if expected_surfaces else 'none'}",
            )
        )

    reviewer_roles = _csv_value(
        trailers["Human-Reviewers"],
        code="GOV-COMMIT-HUMAN-REVIEWERS-INVALID",
        location="Human-Reviewers",
    )
    forbidden_tokens = {
        token
        for token in reviewer_roles
        if any(kind in token.casefold() for kind in FORBIDDEN_APPROVER_KINDS)
    }
    if forbidden_tokens:
        diagnostics.append(
            GovernanceDiagnostic(
                "GOV-COMMIT-APPROVER-KIND-FORBIDDEN",
                "Human-Reviewers",
                "agents and providers cannot satisfy accountable review",
            )
        )
    if expected_surfaces and reviewer_roles != REQUIRED_ACCOUNTABLE_ROLES:
        diagnostics.append(
            GovernanceDiagnostic(
                "GOV-COMMIT-PROTECTED-REVIEWERS",
                "Human-Reviewers",
                "protected changes require release-maintainer and security-maintainer",
            )
        )
    resolved_root: Path | None = None
    if repository_root is not None:
        try:
            resolved_root = repository_root.resolve(strict=True)
        except OSError:
            resolved_root = None
    if expected_surfaces:
        evaluation_passing = False
        if resolved_root is not None:
            try:
                evaluation = validate_evidence_record_reference(
                    trailers["Evaluation-Evidence"],
                    repository_root=resolved_root,
                    expected_mode="evaluation",
                )
                evaluation_passing = evaluation.passing
            except GovernanceValidationError as error:
                diagnostics.extend(error.diagnostics)
        if not evaluation_passing:
            diagnostics.append(
                GovernanceDiagnostic(
                    "GOV-COMMIT-PROTECTED-EVALUATION",
                    "Evaluation-Evidence",
                    "protected changes require a passing positive evidence record",
                )
            )

        rollback_valid = False
        if resolved_root is not None and trailers["Rollback-Plan"] != "none":
            try:
                _regular_repository_file(
                    resolved_root,
                    trailers["Rollback-Plan"],
                    location="Rollback-Plan",
                    missing_code="GOV-COMMIT-ROLLBACK-ARTIFACT-MISSING",
                )
                rollback_valid = True
            except GovernanceValidationError as error:
                diagnostics.extend(error.diagnostics)
        if not rollback_valid:
            diagnostics.append(
                GovernanceDiagnostic(
                    "GOV-COMMIT-PROTECTED-ROLLBACK",
                    "Rollback-Plan",
                    "protected changes require an existing rollback-plan artifact",
                )
            )
    schema_changed = any(
        _normalize_repo_path(path).startswith("schemas/") for path in changed_paths
    )
    if schema_changed:
        schema_valid = False
        if resolved_root is not None:
            try:
                validate_schema_change_reference(
                    trailers["Schema-Change"],
                    repository_root=resolved_root,
                )
                schema_valid = True
            except (GovernanceValidationError, OSError) as error:
                if isinstance(error, GovernanceValidationError):
                    diagnostics.extend(error.diagnostics)
        if not schema_valid:
            diagnostics.append(
                GovernanceDiagnostic(
                    "GOV-COMMIT-SCHEMA-PACKET-MISSING",
                    "Schema-Change",
                    "schema changes require a passing versioned evolution packet",
                )
            )
    if diagnostics:
        raise GovernanceValidationError(diagnostics)
    return CommitCheckResult(expected_surfaces, trailers)


WORKFLOW_TEMPLATE_FIELDS: dict[str, tuple[str, ...]] = {
    "adr": (
        "compatibility-schema",
        "contract-targets",
        "decision-id",
        "evaluation-evidence",
        "human-reviewers",
        "protected-surfaces",
        "rollback",
        "scope",
        "task-ids",
    ),
    "pull-request": (
        "compatibility-schema",
        "contract-targets",
        "decision-ids",
        "evaluation-evidence",
        "human-reviewers",
        "protected-surfaces",
        "rollback",
        "scope",
        "task-ids",
        "trailers",
    ),
}
WORKFLOW_TEMPLATE_CONTENT: dict[str, dict[str, tuple[str, ...]]] = {
    "adr": {
        "compatibility-schema": (
            "- Compatibility/hard cut:",
            "- Schema/migration impact:",
        ),
        "contract-targets": ("contract_targets:",),
        "decision-id": ("id: ADR-NNNN",),
        "evaluation-evidence": ("- Evaluation evidence:",),
        "human-reviewers": ("- Required reviewers:", "- Review evidence:"),
        "protected-surfaces": ("- Protected categories:",),
        "rollback": (
            "## Rollback",
            "- Trigger:",
            "- Procedure:",
            "- Data recovery:",
            "- Verification:",
        ),
        "scope": ("## Scope", "- In scope:", "- Out of scope:"),
        "task-ids": ("task_ids:",),
    },
    "pull-request": {
        "compatibility-schema": (
            "## Compatibility and schema impact",
            "- Compatibility mode:",
            "- Schema versions:",
            "- Stable reason code:",
            "- Fixtures:",
            "- Migration and recovery evidence:",
        ),
        "contract-targets": ("- Contract targets:",),
        "decision-ids": ("- Decision IDs:",),
        "evaluation-evidence": (
            "## Evaluation evidence",
            "- Strongest-applicable tiers:",
            "- Commands/artifacts:",
            "- Non-applicable tiers and stable reasons:",
        ),
        "human-reviewers": (
            "- Required human/team reviewers:",
            "- Approval evidence:",
        ),
        "protected-surfaces": (
            "## Protected surfaces and accountable review",
            "- Protected categories:",
            "- Resolved changed paths:",
        ),
        "rollback": (
            "## Rollback",
            "- Trigger:",
            "- Procedure:",
            "- Data recovery:",
            "- Verification:",
        ),
        "scope": (
            "## Scope and stable IDs",
            "- Summary:",
            "- In scope:",
            "- Out of scope:",
            "- Base SHA:",
        ),
        "task-ids": ("- Task IDs:",),
        "trailers": (
            "## Required commit trailers",
            "Task-ID:",
            "Contract-Targets:",
            "Decision-IDs:",
            "Protected-Surfaces:",
            "Human-Reviewers:",
            "Evaluation-Evidence:",
            "Schema-Change:",
            "Rollback-Plan:",
        ),
    },
}
_WORKFLOW_MARKER_LINE_RE = re.compile(
    r"[ \t]*<!-- GOV-FIELD:([a-z-]+) -->[ \t]*",
)


def _workflow_markdown_surface(
    text: str,
) -> tuple[CommonMarkSurface, tuple[str, ...]]:
    surface = parse_commonmark(text)
    markers = tuple(
        match.group(1)
        for token in surface.top_level_html_blocks
        if (match := _WORKFLOW_MARKER_LINE_RE.fullmatch(token.strip())) is not None
    )
    return surface, markers


def _visible_markdown_lines(text: str) -> tuple[str, ...]:
    surface, _markers = _workflow_markdown_surface(text)
    return surface.operative_lines


def _has_workflow_content(surface: CommonMarkSurface, required_line: str) -> bool:
    if required_line.startswith("#"):
        match = re.fullmatch(r"(#{1,6})[ \t]+(.+)", required_line)
        assert match is not None
        level = len(match.group(1))
        text = match.group(2)
        return CommonMarkHeading(level, text) in surface.top_level_headings
    normalized = required_line.removeprefix("- ").strip()
    return any(
        line.removeprefix("- ").strip().startswith(normalized)
        for line in surface.operative_lines
    )


def validate_workflow_template(kind: str, text: str) -> None:
    required = WORKFLOW_TEMPLATE_FIELDS[kind]
    surface, markers = _workflow_markdown_surface(text)
    diagnostics: list[GovernanceDiagnostic] = []
    for field in required:
        count = markers.count(field)
        if count == 0:
            diagnostics.append(
                GovernanceDiagnostic(
                    "GOV-TEMPLATE-FIELD-MISSING",
                    f"{kind}.{field}",
                    "required workflow field marker is absent",
                )
            )
        elif count > 1:
            diagnostics.append(
                GovernanceDiagnostic(
                    "GOV-TEMPLATE-FIELD-DUPLICATE",
                    f"{kind}.{field}",
                    "workflow field marker appears more than once",
                )
            )
        missing_content = [
            required_line
            for required_line in WORKFLOW_TEMPLATE_CONTENT[kind][field]
            if not _has_workflow_content(surface, required_line)
        ]
        if missing_content:
            diagnostics.append(
                GovernanceDiagnostic(
                    "GOV-TEMPLATE-FIELD-MISSING",
                    f"{kind}.{field}",
                    "required workflow field content is absent: "
                    + ", ".join(missing_content),
                )
            )
    for field in sorted(set(markers) - set(required)):
        diagnostics.append(
            GovernanceDiagnostic(
                "GOV-TEMPLATE-FIELD-UNKNOWN",
                f"{kind}.{field}",
                "unknown workflow field marker",
            )
        )
    if diagnostics:
        raise GovernanceValidationError(diagnostics)


def render_policy_json_schema() -> str:
    schema = ProtectedSurfacePolicy.model_json_schema()
    schema["$id"] = "https://unrest.dev/schemas/protected-surfaces-v1.schema.json"
    schema["$schema"] = "https://json-schema.org/draft/2020-12/schema"
    return json.dumps(schema, indent=2, sort_keys=True) + "\n"
