"""Deterministic, read-only validation of the checked-in repository contract."""
from __future__ import annotations

import ast
import glob
import io
import json
import os
import re
import shlex
import subprocess
import tempfile
import tomllib
import tokenize
from collections import Counter
from dataclasses import dataclass
from html.parser import HTMLParser
from itertools import product
from pathlib import Path, PurePosixPath
from typing import Any, Literal

import yaml
from jsonschema import Draft202012Validator
from jsonschema.exceptions import SchemaError

from .assets import parse_frontmatter
from .baseline import GENERATED_FILENAMES, generate_baseline
from .capability_policy import (
    CapabilityPolicy,
    CapabilityPolicyError,
    CapabilitySecurityModel,
    CapabilitySinkCatalog,
    load_capability_policy,
    load_capability_security_model,
    load_capability_sink_catalog,
    validate_capability_model_anchors,
    validate_capability_sink_anchors,
)
from .governance import (
    GovernanceValidationError,
    load_component_paths,
    load_protected_surface_policy,
    normalize_document_text,
    normalized_document_tokens,
    parse_commonmark,
    render_policy_json_schema,
    resolve_path_category,
    validate_evidence_record_reference,
    validate_policy_components,
    validate_workflow_template,
)

CANONICAL_COMMAND = "uv run unrest check-repository"
ARCHITECTURE_DIR = "docs/architecture"
ANNOTATION_POLICY_PATH = f"{ARCHITECTURE_DIR}/annotation-policy.json"


def visible_guidance_paths(root: Path) -> set[str]:
    """Enumerate repository guidance while excluding generated/tool trees."""
    found: set[str] = set()
    for directory, dirnames, filenames in os.walk(root):
        relative = Path(directory).relative_to(root)
        dirnames[:] = [
            name
            for name in dirnames
            if not name.startswith(".")
            and name not in {"__pycache__", "build", "dist"}
        ]
        if "AGENTS.md" in filenames and not any(
            part.startswith(".") for part in relative.parts
        ):
            found.add((relative / "AGENTS.md").as_posix())
    return found
COMPONENT_MAP_PATH = f"{ARCHITECTURE_DIR}/component-map.json"
EVIDENCE_POLICY_PATH = f"{ARCHITECTURE_DIR}/evidence-policy.json"
HISTORICAL_POLICY_PATH = f"{ARCHITECTURE_DIR}/historical-record-policy.json"
ID_REGISTRY_PATH = f"{ARCHITECTURE_DIR}/id-registry.json"
NORMATIVE_POLICY_PATH = f"{ARCHITECTURE_DIR}/normative-documents.json"
REMOVAL_REGISTRY_PATH = f"{ARCHITECTURE_DIR}/removal-registry.json"
TEMPLATE_HEADING_POLICY_PATH = f"{ARCHITECTURE_DIR}/template-heading-policy.json"
CAPABILITY_MODEL_PATH = (
    "src/unrest_harness/bundled/policies/capability-security-model.v1.json"
)
CAPABILITY_SINKS_PATH = "src/unrest_harness/bundled/policies/capability-sinks.v1.json"
CAPABILITY_ROLE_POLICY_PATH = (
    "src/unrest_harness/bundled/policies/role-capabilities.v1.json"
)
CAPABILITY_MODEL_SCHEMA_PATH = "schemas/capability-security-model.schema.json"
CAPABILITY_SINKS_SCHEMA_PATH = "schemas/capability-sinks.schema.json"
CAPABILITY_ROLE_POLICY_SCHEMA_PATH = "schemas/role-capabilities.schema.json"
POLICY_PATH = "policy/protected-surfaces.yaml"
POLICY_SCHEMA_PATH = "schemas/protected-surfaces.schema.json"
CI_PATH = ".github/workflows/ci.yml"
BASELINE_PATH = "evals/baseline"
FULL_SOURCE_SUITE_COMMAND = "env -u CODEX_PATH uv run pytest -q"
COMPATIBILITY_TEST_COMMAND = (
    "uv run pytest -q tests/test_assets.py tests/test_config.py tests/test_models.py"
)
COMPATIBILITY_IMPORT_COMMAND = (
    'uv run python -c "import unrest_harness; from unrest_harness.config import '
    'HarnessConfig; HarnessConfig.discover()"'
)
DISTRIBUTION_CHECK_COMMAND = "uv run python tools/check_distribution.py dist"

HISTORICAL_ACTIVE_ROLE_LOCATORS = (
    {
        "collection_field": "documents",
        "id": "canonical-template",
        "record_filter": {
            "field": "path",
            "prefix": "docs/templates/",
        },
        "registry_path": NORMATIVE_POLICY_PATH,
        "value_field": "id",
    },
    {
        "collection_field": "ids",
        "id": "compatibility-rule",
        "record_filter": {
            "equals": "compatibility",
            "field": "kind",
        },
        "registry_path": ID_REGISTRY_PATH,
        "value_field": "id",
    },
    {
        "collection_field": "components",
        "id": "component-invariant",
        "registry_path": COMPONENT_MAP_PATH,
        "value_list_field": "invariants",
    },
    {
        "collection_field": "ids",
        "id": "invariant-rule",
        "record_filter": {
            "equals": "invariant",
            "field": "kind",
        },
        "registry_path": ID_REGISTRY_PATH,
        "value_field": "id",
    },
    {
        "collection_field": "ids",
        "id": "security-rule",
        "record_filter": {
            "equals": "security",
            "field": "kind",
        },
        "registry_path": ID_REGISTRY_PATH,
        "value_field": "id",
    },
)
HISTORICAL_ACTIVE_ROLE_IDS = tuple(
    role["id"] for role in HISTORICAL_ACTIVE_ROLE_LOCATORS
)
HISTORICAL_AUTHORIZATION_CONTRACT = {
    "active_role_field": "active_role",
    "current_contract_field": "current_contract_id",
    "current_contract_registry": ID_REGISTRY_PATH,
    "historical_reference_field": "historical_reference",
}
ID_KIND_ACTIVE_ROLES = {
    "compatibility": "compatibility-rule",
    "invariant": "invariant-rule",
    "security": "security-rule",
}

CANONICAL_JSON_PATHS = (
    ANNOTATION_POLICY_PATH,
    COMPONENT_MAP_PATH,
    EVIDENCE_POLICY_PATH,
    HISTORICAL_POLICY_PATH,
    ID_REGISTRY_PATH,
    NORMATIVE_POLICY_PATH,
    REMOVAL_REGISTRY_PATH,
    TEMPLATE_HEADING_POLICY_PATH,
    CAPABILITY_MODEL_PATH,
    CAPABILITY_ROLE_POLICY_PATH,
    CAPABILITY_SINKS_PATH,
)
EXPECTED_GUIDANCE = (
    "AGENTS.md",
    "evals/AGENTS.md",
    "src/unrest_harness/AGENTS.md",
    "src/unrest_harness/bundled/AGENTS.md",
    "tests/AGENTS.md",
)
EXPECTED_GUIDANCE_CHAINS = {
    "README.md": ("AGENTS.md",),
    "evals/baseline/manifest.yaml": ("AGENTS.md", "evals/AGENTS.md"),
    "src/unrest_harness/bundled/skills/agent-browser/SKILL.md": (
        "AGENTS.md",
        "src/unrest_harness/AGENTS.md",
        "src/unrest_harness/bundled/AGENTS.md",
    ),
    "src/unrest_harness/storage.py": (
        "AGENTS.md",
        "src/unrest_harness/AGENTS.md",
    ),
    "tests/test_storage.py": ("AGENTS.md", "tests/AGENTS.md"),
}
TEMPLATE_YAML_FIELDS = {
    "TPL-CLOSEOUT-001": (
        ("task_id:", ("task_id",)),
        ("status:", ("status",)),
        ("base_sha:", ("base_sha",)),
        ("result_sha:", ("result_sha",)),
        ("scope_completed:", ("scope_completed",)),
        ("files_changed:", ("files_changed",)),
        ("public_or_persisted_changes:", ("public_or_persisted_changes",)),
        ("invariants_and_decisions:", ("invariants_and_decisions",)),
        ("contract_targets:", ("contract_targets",)),
        ("verification:", ("verification",)),
        ("evaluation_or_evidence:", ("evaluation_or_evidence",)),
        ("risks_or_unknowns:", ("risks_or_unknowns",)),
        ("rollback:", ("rollback",)),
        ("follow_ons:", ("follow_ons",)),
        ("required:", ("follow_ons", "required")),
        ("optional:", ("follow_ons", "optional")),
    ),
}
SUPPORTED_METASCHEMAS = {
    "https://json-schema.org/draft/2020-12/schema": Draft202012Validator,
}
CHECK_FAMILIES = (
    "annotations",
    "capability-security",
    "canonical-json",
    "ci",
    "component-map",
    "frontmatter",
    "generated-output",
    "guidance",
    "markdown-and-source-references",
    "protected-policy",
    "schemas",
    "stable-ids",
    "templates",
)

EnumerationOrder = Literal["forward", "reverse"]


@dataclass(frozen=True, order=True)
class RepositoryDiagnostic:
    """A stable reason code tied to one repository-relative location."""

    code: str
    path: str
    message: str

    def render(self) -> str:
        return f"{self.code}:{self.path}: {self.message}"


class RepositoryContractError(ValueError):
    """Raised when one or more repository-contract checks fail."""

    def __init__(self, diagnostics: list[RepositoryDiagnostic]) -> None:
        self.diagnostics = tuple(sorted(set(diagnostics)))
        super().__init__("\n".join(item.render() for item in self.diagnostics))


@dataclass(frozen=True)
class RepositoryContractReport:
    """Deterministic success report for the canonical command."""

    checked_families: tuple[str, ...]
    generated_outputs: tuple[str, ...]

    def as_dict(self) -> dict[str, Any]:
        return {
            "checked_families": list(self.checked_families),
            "command": CANONICAL_COMMAND,
            "generated_outputs": list(self.generated_outputs),
            "repository": ".",
            "schema_version": 1,
            "status": "ok",
        }

    def render(self) -> str:
        return json.dumps(self.as_dict(), indent=2, sort_keys=True) + "\n"


class _DuplicateJSONKey(ValueError):
    pass


class _DuplicateYAMLKey(ValueError):
    def __init__(self, key: str) -> None:
        self.key = key
        super().__init__(key)


class _TemplateYAMLLoader(yaml.BaseLoader):
    pass


def _construct_template_mapping(
    loader: _TemplateYAMLLoader,
    node: yaml.MappingNode,
    deep: bool = False,
) -> dict[Any, Any]:
    mapping: dict[Any, Any] = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        if key in mapping:
            raise _DuplicateYAMLKey(str(key))
        mapping[key] = loader.construct_object(value_node, deep=deep)
    return mapping


_TemplateYAMLLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,
    _construct_template_mapping,
)


def _compatible_text(text: str) -> str:
    return normalize_document_text(text)


def _logical_heading_text(text: str) -> str:
    """Normalize only the rendered visible label of an operative heading."""

    normalized = _compatible_text(text)
    return re.sub(r"\s+", " ", normalized).strip().casefold()


def _logical_heading_key(level: int, text: str) -> str:
    return f"{'#' * level} {_logical_heading_text(text)}"


def _markdown_headings(text: str) -> tuple[str, ...]:
    """Return visible identities for operative top-level Markdown headings."""

    return tuple(
        _logical_heading_key(heading.level, heading.text)
        for heading in parse_commonmark(text).top_level_headings
        if heading.text
    )


def _required_heading_key(level: int, visible_label: str) -> str:
    return _logical_heading_key(level, visible_label)


def _markdown_yaml_mappings(
    text: str,
) -> tuple[list[dict[str, Any]], tuple[str, ...]]:
    """Parse mapping-valued YAML fences from Markdown template bodies."""

    mappings: list[dict[str, Any]] = []
    duplicate_keys: list[str] = []
    for info, payload in parse_commonmark(text).top_level_fences:
        if info.casefold() not in {"yaml", "yml"}:
            continue
        try:
            value = yaml.load(payload, Loader=_TemplateYAMLLoader)
        except _DuplicateYAMLKey as error:
            duplicate_keys.append(error.key)
            value = None
        except yaml.YAMLError:
            value = None
        if isinstance(value, dict):
            mappings.append(value)
    return mappings, tuple(sorted(duplicate_keys))


def _mapping_has_path(mapping: dict[str, Any], path: tuple[str, ...]) -> bool:
    current: Any = mapping
    for part in path:
        if not isinstance(current, dict) or part not in current:
            return False
        current = current[part]
    return True


def _mapping_values_at_path(value: Any, path: tuple[str, ...]) -> tuple[Any, ...]:
    if not path:
        return (value,)
    part, *remaining = path
    if part == "*":
        if isinstance(value, list):
            children = value
        elif isinstance(value, dict):
            children = list(value.values())
        else:
            return ()
        return tuple(
            item
            for child in children
            for item in _mapping_values_at_path(child, tuple(remaining))
        )
    if not isinstance(value, dict) or part not in value:
        return ()
    return _mapping_values_at_path(value[part], tuple(remaining))


_BANNED_CONTENT_FIELDS = {
    "identity_attribution_grammar",
    "normalization",
    "out_of_scope_containers",
    "supported_containers",
}
_SOURCE_REFERENCE_GRAMMAR = re.compile(
    r"^(?P<path>(?:docs|specs)/"
    r"(?:[A-Za-z0-9][A-Za-z0-9._-]*/)*"
    r"[A-Za-z0-9][A-Za-z0-9._-]*\.md)"
    r"(?:#(?P<anchor>[A-Za-z0-9_][A-Za-z0-9_-]*))?$"
)
_SOURCE_REFERENCE_CANDIDATE = re.compile(
    r"(?<![A-Za-z0-9_./\\-])"
    r"(?P<reference>"
    r"[A-Za-z0-9_./\\-]*(?:docs|specs)"
    r"[A-Za-z0-9_./\\-]*\.md"
    r"[A-Za-z0-9_-]*(?:\.[A-Za-z0-9_-]+)*"
    r"(?:[ \t]*#[^\s)\]}>\"'`]*)?"
    r")"
    r"(?![A-Za-z0-9_/#\\-])",
    re.IGNORECASE,
)
_EXTERNAL_REFERENCE = re.compile(
    r"(?:https?://|mailto:)[^\s)\]}>\"'`]+",
    re.IGNORECASE,
)


def _contains_phrase(
    tokens: tuple[str, ...],
    phrase: tuple[str, ...],
) -> bool:
    return bool(phrase) and any(
        tokens[index : index + len(phrase)] == phrase
        for index in range(len(tokens) - len(phrase) + 1)
    )


class _SupportedHTMLLabelParser(HTMLParser):
    """Collect visible labels only from cataloged HTML elements."""

    def __init__(self, supported_tags: set[str]) -> None:
        super().__init__(convert_charrefs=True)
        self.supported_tags = supported_tags
        self.stack: list[str] = []
        self.labels: list[str] = []

    def handle_starttag(
        self,
        tag: str,
        attrs: list[tuple[str, str | None]],
    ) -> None:
        del attrs
        self.stack.append(normalize_document_text(tag).casefold())

    def handle_startendtag(
        self,
        tag: str,
        attrs: list[tuple[str, str | None]],
    ) -> None:
        del tag, attrs

    def handle_endtag(self, tag: str) -> None:
        normalized = normalize_document_text(tag).casefold()
        if normalized in self.stack:
            index = len(self.stack) - 1 - self.stack[::-1].index(normalized)
            del self.stack[index:]

    def handle_data(self, data: str) -> None:
        if self.stack and self.stack[-1] in self.supported_tags:
            normalized = re.sub(r"\s+", " ", data).strip()
            if normalized:
                self.labels.append(normalized)


def _attribute_name_matches(name: str, supported: set[str]) -> bool:
    return name in supported or ("data-*" in supported and name.startswith("data-"))


def _identity_private_marker_categories(
    text: str,
    policy: dict[str, Any],
) -> tuple[str, ...]:
    """Apply the cataloged open identity-slot grammar to supported containers."""

    grammar = policy.get("identity_attribution_grammar")
    containers = policy.get("supported_containers")
    if not isinstance(grammar, dict) or not isinstance(containers, list):
        return ()
    identity_slot = grammar.get("identity_slot")
    concepts = grammar.get("private_reasoning_concepts")
    if (
        not isinstance(identity_slot, dict)
        or not isinstance(concepts, list)
        or not all(isinstance(concept, str) for concept in concepts)
    ):
        return ()
    minimum = identity_slot.get("minimum_tokens")
    maximum = identity_slot.get("maximum_tokens")
    if not isinstance(minimum, int) or not isinstance(maximum, int):
        return ()
    concept_tokens = tuple(
        normalized_document_tokens(concept)
        for concept in concepts
    )
    by_id = {
        container["id"]: container
        for container in containers
        if isinstance(container, dict) and isinstance(container.get("id"), str)
    }

    def has_concept(tokens: tuple[str, ...]) -> bool:
        return any(_contains_phrase(tokens, concept) for concept in concept_tokens)

    def is_identity(tokens: tuple[str, ...]) -> bool:
        return minimum <= len(tokens) <= maximum

    def visible_label_matches(candidate: str) -> bool:
        compatible = normalize_document_text(candidate)
        match = re.fullmatch(
            r"\s*(?P<label>[^:\n]{1,160}?)\s*:\s*(?P<body>\S.*)",
            compatible,
        )
        if match is None:
            return False
        label_tokens = normalized_document_tokens(match.group("label"))
        if label_tokens[-1:] == ("says",):
            label_tokens = label_tokens[:-1]
        return is_identity(label_tokens) and has_concept(
            normalized_document_tokens(match.group("body"))
        )

    def compound_matches(candidate: str) -> bool:
        tokens = normalized_document_tokens(candidate)
        for concept in concept_tokens:
            for index in range(len(tokens) - len(concept) + 1):
                if tokens[index : index + len(concept)] != concept:
                    continue
                identity = (*tokens[:index], *tokens[index + len(concept) :])
                if is_identity(identity):
                    return True
        return False

    surface = parse_commonmark(text)
    if "markdown-visible-label" in by_id and any(
        visible_label_matches(line) for line in surface.visible_lines
    ):
        return ("identity-attributed-private-reasoning",)

    html_visible = by_id.get("html-visible-label")
    if isinstance(html_visible, dict):
        tags = html_visible.get("tags")
        if isinstance(tags, list) and all(isinstance(tag, str) for tag in tags):
            for token in surface.html_tokens:
                parser = _SupportedHTMLLabelParser(set(tags))
                try:
                    parser.feed(token)
                    parser.close()
                except (AssertionError, ValueError):
                    continue
                if any(visible_label_matches(label) for label in parser.labels):
                    return ("identity-attributed-private-reasoning",)

    attribute_containers = {
        source: by_id.get(f"{source}-attribute-value")
        for source in ("html", "markdown")
    }
    for attribute in surface.attributes:
        container = attribute_containers.get(attribute.source)
        names = container.get("names") if isinstance(container, dict) else None
        if (
            isinstance(names, list)
            and all(isinstance(name, str) for name in names)
            and _attribute_name_matches(attribute.name, set(names))
            and compound_matches(attribute.value)
        ):
            return ("identity-attributed-private-reasoning",)

    tag_container = by_id.get("html-private-concept-tag")
    if isinstance(tag_container, dict):
        identity_names = tag_container.get("identity_attribute_names")
        allowed_identity_names = (
            set(identity_names)
            if isinstance(identity_names, list)
            and all(isinstance(name, str) for name in identity_names)
            else set()
        )
        for element in surface.elements:
            tag_tokens = normalized_document_tokens(element.tag)
            if tag_container.get("compound_tag_name") is True and compound_matches(
                element.tag
            ):
                return ("identity-attributed-private-reasoning",)
            if not any(tag_tokens == concept for concept in concept_tokens):
                continue
            if any(
                attribute.name in allowed_identity_names
                and is_identity(normalized_document_tokens(attribute.value))
                for attribute in element.attributes
            ):
                return ("identity-attributed-private-reasoning",)
    return ()


def _ci_condition_is_always(value: Any) -> bool:
    if value is None or value is True:
        return True
    if not isinstance(value, str):
        return False
    normalized = re.sub(r"\s+", " ", value.strip().casefold())
    return normalized in {
        "true",
        "${{ true }}",
        "always()",
        "${{ always() }}",
    }


def _ci_continue_on_error_is_disabled(value: Any) -> bool:
    if value is None or value is False:
        return True
    if not isinstance(value, str):
        return False
    normalized = re.sub(r"\s+", " ", value.strip().casefold())
    return normalized in {"false", "${{ false }}"}


def _matrix_combinations(matrix: dict[str, Any]) -> list[dict[str, Any]] | None:
    dimensions = {
        key: value
        for key, value in matrix.items()
        if key not in {"exclude", "include"}
    }
    if not dimensions or any(
        not isinstance(values, list) or not values
        for values in dimensions.values()
    ):
        return None
    if any(
        isinstance(value, str) and "${{" in value
        for values in dimensions.values()
        for value in values
    ):
        return None

    dimension_names = tuple(dimensions)
    combinations: list[dict[str, Any]] = [
        dict(zip(dimension_names, values, strict=True))
        for values in product(*(dimensions[name] for name in dimension_names))
    ]
    includes = matrix.get("include", [])
    if not isinstance(includes, list) or any(
        not isinstance(entry, dict) for entry in includes
    ):
        return None
    if any(
        isinstance(value, str) and "${{" in value
        for entry in includes
        if isinstance(entry, dict)
        for value in entry.values()
    ):
        return None
    combinations.extend(entry for entry in includes if isinstance(entry, dict))

    excludes = matrix.get("exclude", [])
    if not isinstance(excludes, list) or any(
        not isinstance(entry, dict) for entry in excludes
    ):
        return None
    if any(
        isinstance(value, str) and "${{" in value
        for entry in excludes
        if isinstance(entry, dict)
        for value in entry.values()
    ):
        return None
    active = [
        combination
        for combination in combinations
        if not any(
            all(combination.get(key) == value for key, value in exclusion.items())
            for exclusion in excludes
        )
    ]
    return active


def _python_matrix_dimensions(
    matrix: dict[str, Any],
    steps: list[Any],
    declared_versions: tuple[str, ...],
) -> tuple[str, ...]:
    referenced: set[str] = set()
    for step in steps:
        if not isinstance(step, dict):
            continue
        with_values = step.get("with")
        python_version = (
            with_values.get("python-version")
            if isinstance(with_values, dict)
            else None
        )
        if isinstance(python_version, str):
            referenced.update(
                re.findall(r"\bmatrix\.([A-Za-z0-9_-]+)\b", python_version)
            )
    dimensions: list[str] = []
    for key, values in matrix.items():
        if key in {"exclude", "include"} or not isinstance(values, list):
            continue
        literal_values = {value for value in values if isinstance(value, str)}
        if literal_values & set(declared_versions) and (
            "python" in key.casefold() or key in referenced
        ):
            dimensions.append(key)
    return tuple(sorted(dimensions))


def _effective_matrix_versions(
    matrix: dict[str, Any],
    dimension: str,
) -> tuple[str, ...] | None:
    combinations = _matrix_combinations(matrix)
    if combinations is None:
        return None
    return tuple(
        sorted(
            {
                version
                for combination in combinations
                if isinstance(version := combination.get(dimension), str)
            }
        )
    )


def _shell_command_sequence(
    run: str,
) -> tuple[tuple[tuple[str, ...], str | None], ...]:
    source = run.replace("\\\n", " ").replace("\n", " ; ")
    lexer = shlex.shlex(source, posix=True, punctuation_chars=";&|")
    lexer.whitespace_split = True
    lexer.commenters = "#"
    try:
        tokens = tuple(lexer)
    except ValueError:
        return ()
    commands: list[tuple[tuple[str, ...], str | None]] = []
    current: list[str] = []
    pending_operator: str | None = None
    for token in tokens:
        if token and set(token) <= {";", "&", "|"}:
            if current:
                commands.append((tuple(current), pending_operator))
                current = []
            pending_operator = token
            continue
        if not current and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*=.*", token):
            continue
        current.append(token)
    if current:
        commands.append((tuple(current), pending_operator))
    return tuple(commands)


def _unwrap_uv_run(command: tuple[str, ...]) -> tuple[str, ...]:
    if not command or PurePosixPath(command[0]).name != "uv":
        return command
    try:
        run_index = command.index("run", 1)
    except ValueError:
        return command
    inner = command[run_index + 1 :]
    command_names = {
        "coverage",
        "nox",
        "pytest",
        "python",
        "python3",
        "tox",
    }
    for index, token in enumerate(inner):
        if PurePosixPath(token).name in command_names:
            return inner[index:]
    return inner


def _strip_command_prefixes(command: tuple[str, ...]) -> tuple[str, ...]:
    current = command
    while current:
        base = PurePosixPath(current[0]).name
        if base == "command":
            current = current[1:]
            continue
        if base == "env":
            current = current[1:]
            while current:
                if current[0] in {"-u", "--unset"} and len(current) >= 2:
                    current = current[2:]
                    continue
                if current[0] == "--":
                    current = current[1:]
                    break
                if current[0].startswith("-") or re.fullmatch(
                    r"[A-Za-z_][A-Za-z0-9_]*=.*",
                    current[0],
                ):
                    current = current[1:]
                    continue
                break
            continue
        break
    return current


def _command_has_sequence(command: tuple[str, ...], sequence: tuple[str, ...]) -> bool:
    return any(
        command[index : index + len(sequence)] == sequence
        for index in range(len(command) - len(sequence) + 1)
    )


_SHELL_BOOLEAN_SHORT_OPTIONS = {
    "bash": frozenset("abefhiklmnprstuvxBCDEHPT"),
    "dash": frozenset("abefilmnprstuvxCIEV"),
    "sh": frozenset("abefilmnprstuvxCIEV"),
    "zsh": frozenset("dfilrstvx"),
}
_BASH_LONG_OPTIONS_WITH_OPERANDS = frozenset({"--init-file", "--rcfile"})
_BASH_BOOLEAN_LONG_OPTIONS = frozenset(
    {
        "--debug",
        "--debugger",
        "--login",
        "--noediting",
        "--noprofile",
        "--norc",
        "--posix",
        "--protected",
        "--restricted",
        "--verbose",
    }
)


def _shell_command_string(command: tuple[str, ...]) -> str | None:
    if not command:
        return None
    shell = PurePosixPath(command[0]).name
    boolean_short_options = _SHELL_BOOLEAN_SHORT_OPTIONS.get(shell)
    if boolean_short_options is None:
        return None
    option_operand_flags = frozenset({"o", "O"} if shell == "bash" else {"o"})
    index = 1
    while index < len(command):
        token = command[index]
        if token in {"--", "-"} or not token.startswith(("-", "+")):
            return None

        if token.startswith("--"):
            if shell != "bash":
                return None
            option, separator, operand = token.partition("=")
            if option in _BASH_LONG_OPTIONS_WITH_OPERANDS:
                if separator:
                    if not operand:
                        return None
                    index += 1
                else:
                    if index + 1 >= len(command):
                        return None
                    index += 2
                continue
            if separator or option not in _BASH_BOOLEAN_LONG_OPTIONS:
                return None
            index += 1
            continue

        short_options = token[1:]
        if not short_options or any(
            option not in boolean_short_options
            and option not in option_operand_flags
            and option != "c"
            for option in short_options
        ):
            return None
        command_string_enabled = token.startswith("-") and "c" in short_options
        if command_string_enabled and short_options.count("c") != 1:
            return None
        operand_count = sum(
            option in option_operand_flags for option in short_options
        )
        command_index = index + operand_count + 1
        if command_string_enabled:
            return command[command_index] if command_index < len(command) else None
        index = command_index
    return None


def _ci_python_surface_kinds(step: dict[str, Any]) -> frozenset[str]:
    run = step.get("run")
    if not isinstance(run, str):
        return frozenset()
    kinds: set[str] = set()
    for command, _operator in _shell_command_sequence(run):
        command = _strip_command_prefixes(command)
        if not command:
            continue
        base = PurePosixPath(command[0]).name
        command_string = _shell_command_string(command)
        if command_string is not None:
            kinds.update(_ci_python_surface_kinds({"run": command_string}))
            continue
        if base == "uv":
            subcommands = {
                token
                for token in command[1:]
                if token in {"build", "publish", "run"}
            }
            if "build" in subcommands:
                kinds.add("build")
            if "publish" in subcommands:
                kinds.add("publish")
        if (
            _command_has_sequence(command, ("-m", "build"))
            or (
                base in {"pip", "pip3"}
                and len(command) > 1
                and command[1] == "wheel"
            )
            or _command_has_sequence(command, ("-m", "pip", "wheel"))
            or (
                base in {"flit", "hatch", "pdm", "poetry"}
                and "build" in command[1:]
            )
        ):
            kinds.add("build")
        if (
            (base == "twine" and "upload" in command[1:])
            or _command_has_sequence(command, ("-m", "twine", "upload"))
            or (
                base in {"flit", "pdm", "poetry"}
                and "publish" in command[1:]
            )
        ):
            kinds.add("publish")

        test_command = _unwrap_uv_run(command)
        if not test_command:
            continue
        test_base = PurePosixPath(test_command[0]).name
        if (
            test_base in {"pytest", "tox", "nox"}
            or _command_has_sequence(test_command, ("-m", "pytest"))
            or (
                (
                    test_base == "coverage"
                    or _command_has_sequence(test_command, ("-m", "coverage"))
                )
                and _command_has_sequence(test_command, ("-m", "pytest"))
            )
        ):
            kinds.add("test")
    return frozenset(kinds)


_PYTEST_OPTIONS_WITH_VALUE = frozenset(
    {
        "-c",
        "-k",
        "-m",
        "--basetemp",
        "--capture",
        "--color",
        "--confcutdir",
        "--deselect",
        "--ignore",
        "--ignore-glob",
        "--import-mode",
        "--junit-prefix",
        "--junitxml",
        "--maxfail",
        "--rootdir",
        "--show-capture",
        "--tb",
    }
)
_PYTEST_NARROWING_OPTIONS = frozenset(
    {"-k", "-m", "--deselect", "--ignore", "--ignore-glob"}
)


def _ci_pytest_invocations(run: str) -> tuple[tuple[str, ...], ...]:
    invocations: list[tuple[str, ...]] = []
    for command, _operator in _shell_command_sequence(run):
        command = _strip_command_prefixes(command)
        if not command:
            continue
        command_string = _shell_command_string(command)
        if command_string is not None:
            invocations.extend(_ci_pytest_invocations(command_string))
            continue
        test_command = _unwrap_uv_run(command)
        if not test_command:
            continue
        test_base = PurePosixPath(test_command[0]).name
        if test_base in {"pytest", "py.test"}:
            invocations.append(test_command[1:])
            continue
        pytest_markers = tuple(
            index
            for index in range(len(test_command) - 1)
            if test_command[index : index + 2] == ("-m", "pytest")
        )
        if pytest_markers:
            invocations.append(test_command[pytest_markers[-1] + 2 :])
    return tuple(invocations)


def _ci_is_full_source_suite(arguments: tuple[str, ...]) -> bool:
    selectors: list[str] = []
    narrowed = False
    index = 0
    while index < len(arguments):
        token = arguments[index]
        if token == "--":
            selectors.extend(arguments[index + 1 :])
            break
        option, separator, _value = token.partition("=")
        if option in _PYTEST_NARROWING_OPTIONS:
            narrowed = True
        if token.startswith("-"):
            if not separator and option in _PYTEST_OPTIONS_WITH_VALUE:
                index += 2
                continue
            index += 1
            continue
        selectors.append(token)
        index += 1
    normalized_selector = (
        str(PurePosixPath(selectors[0])) if len(selectors) == 1 else None
    )
    return not narrowed and (not selectors or normalized_selector in {".", "tests"})


def _static_command_exit_code(command: tuple[str, ...]) -> int | None:
    command = _strip_command_prefixes(command)
    if not command:
        return 0
    base = PurePosixPath(command[0]).name
    if base == "true":
        return 0
    if base == "false":
        return 1
    if base in {"echo", "printf"}:
        return 0
    if base in {"exit", "return"} and len(command) >= 2:
        try:
            return int(command[1], 10)
        except ValueError:
            return None
    if base in {"bash", "dash", "sh", "zsh"} and len(command) == 3 and command[1] == "-c":
        return _static_run_exit_code(command[2])
    if (
        base.startswith("python")
        and len(command) >= 3
        and command[1] == "-c"
        and (
            match := re.search(
                r"(?:sys\.exit|raise\s+SystemExit)\s*\(\s*([0-9]+)\s*\)",
                command[2],
            )
        )
        is not None
    ):
        return int(match.group(1))
    return None


def _static_run_exit_code(run: str) -> int | None:
    sequence = _shell_command_sequence(run)
    if not sequence:
        return 0
    status: int | None = None
    for command, operator in sequence:
        command_status = _static_command_exit_code(command)
        if status is None and operator is None:
            status = command_status
        elif operator in {None, ";", "&"}:
            status = command_status
        elif operator == "&&":
            if status == 0:
                status = command_status
            elif status is None and command_status not in {None, 0}:
                status = command_status
        elif operator == "||":
            if status not in {None, 0}:
                status = command_status
            elif status is None:
                status = None
        else:
            status = None
        if (
            PurePosixPath(command[0]).name in {"exit", "return"}
            and command_status is not None
        ):
            return command_status
    return status


def _ci_needs(job: dict[str, Any]) -> tuple[str, ...] | None:
    needs = job.get("needs")
    if needs is None:
        return ()
    if isinstance(needs, str):
        return (needs,)
    if isinstance(needs, list) and all(isinstance(value, str) for value in needs):
        return tuple(needs)
    return None


def _ci_job_is_guaranteed_reachable(
    job_id: str,
    jobs: dict[str, Any],
    *,
    visiting: frozenset[str] = frozenset(),
) -> bool:
    if job_id in visiting:
        return False
    job = jobs.get(job_id)
    if not isinstance(job, dict):
        return False
    if not _ci_condition_is_always(job.get("if")):
        return False
    if not _ci_continue_on_error_is_disabled(job.get("continue-on-error")):
        return False
    needs = _ci_needs(job)
    if needs is None or any(
        not _ci_job_is_guaranteed_reachable(
            dependency,
            jobs,
            visiting=visiting | {job_id},
        )
        for dependency in needs
    ):
        return False
    steps = job.get("steps")
    if not isinstance(steps, list):
        return False
    for step in steps:
        if not isinstance(step, dict):
            continue
        if not _ci_condition_is_always(step.get("if")):
            return False
        if not _ci_continue_on_error_is_disabled(step.get("continue-on-error")):
            return False
        run = step.get("run")
        if (
            isinstance(run, str)
            and (
                (exit_code := _static_run_exit_code(run)) is not None
                and exit_code != 0
            )
        ):
            return False
    return True


class _RepositoryValidator:
    def __init__(self, root: Path, *, enumeration_order: EnumerationOrder) -> None:
        self.root = root.resolve()
        self.reverse = enumeration_order == "reverse"
        self.diagnostics: list[RepositoryDiagnostic] = []
        self._json_cache: dict[str, Any] = {}
        self._normative_documents: list[tuple[str, str, dict[str, Any], str]] = []
        self._normative_role_aliases: dict[tuple[str, str], str] = {}
        self._accepted_decisions: set[str] = set()
        self._global_ids: dict[str, set[str]] = {}
        self._historical_authorized_links_cache: set[tuple[str, str]] | None = None

    def run(self) -> RepositoryContractReport:
        self._check_guidance()
        self._load_accepted_decisions()
        self._check_normative_documents()
        self._check_stable_ids()
        self._check_annotations()
        self._check_component_map()
        self._check_capability_security()
        self._check_templates()
        self._check_historical_active_roles()
        self._check_evidence_policy()
        self._check_protected_policy()
        self._check_schemas()
        self._check_generated_outputs()
        self._check_ci()
        self._check_global_id_uniqueness()
        if self.diagnostics:
            raise RepositoryContractError(self.diagnostics)
        return RepositoryContractReport(
            checked_families=tuple(sorted(CHECK_FAMILIES)),
            generated_outputs=tuple(
                sorted(
                    [
                        *(f"{BASELINE_PATH}/{name}" for name in GENERATED_FILENAMES),
                        POLICY_SCHEMA_PATH,
                    ]
                )
            ),
        )

    def _ordered(self, values: list[str] | set[str] | tuple[str, ...]) -> list[str]:
        return sorted(values, reverse=self.reverse)

    def _add(self, code: str, path: str, message: str) -> None:
        self.diagnostics.append(RepositoryDiagnostic(code, path, message))

    def _read_text(self, relative_path: str) -> str | None:
        path = self.root / relative_path
        try:
            return path.read_text(encoding="utf-8")
        except (OSError, UnicodeError) as error:
            message = (
                error.strerror
                if isinstance(error, OSError) and error.strerror
                else type(error).__name__
            )
            self._add("REPO-FILE-UNREADABLE", relative_path, message)
            return None

    def _historical_authorized_links(self) -> set[tuple[str, str]]:
        if self._historical_authorized_links_cache is not None:
            return self._historical_authorized_links_cache
        self._historical_authorized_links_cache = set()
        catalog = self._load_json(HISTORICAL_POLICY_PATH)
        manifest_text = self._read_text(f"{BASELINE_PATH}/manifest.yaml")
        id_registry = self._load_json(ID_REGISTRY_PATH)
        if (
            not isinstance(catalog, dict)
            or not isinstance(id_registry, dict)
            or manifest_text is None
            or set(catalog)
            != {
                "active_roles",
                "authorizations",
                "authorization_contract",
                "historical_classifications",
                "historical_records",
                "schema_version",
                "source_manifest",
            }
            or catalog.get("schema_version") != 1
            or catalog.get("source_manifest") != f"{BASELINE_PATH}/manifest.yaml"
            or catalog.get("authorization_contract")
            != HISTORICAL_AUTHORIZATION_CONTRACT
        ):
            return self._historical_authorized_links_cache
        try:
            manifest = yaml.safe_load(manifest_text)
        except yaml.YAMLError:
            return self._historical_authorized_links_cache
        fixtures = manifest.get("fixtures") if isinstance(manifest, dict) else None
        if not isinstance(fixtures, list):
            return self._historical_authorized_links_cache
        expected_records = sorted(
            (
                {
                    "classification": fixture["classification"],
                    "id": fixture["fixture_id"],
                }
                for fixture in fixtures
                if isinstance(fixture, dict)
                and isinstance(fixture.get("fixture_id"), str)
                and fixture.get("classification")
                in {"known_defect", "observed_legacy"}
            ),
            key=lambda item: item["id"],
        )
        expected_classifications = sorted(
            {item["classification"] for item in expected_records}
        )
        active_roles = catalog.get("active_roles")
        authorizations = catalog.get("authorizations")
        if (
            catalog.get("historical_records") != expected_records
            or catalog.get("historical_classifications")
            != expected_classifications
            or active_roles != list(HISTORICAL_ACTIVE_ROLE_LOCATORS)
            or not isinstance(authorizations, list)
        ):
            return self._historical_authorized_links_cache
        forbidden = {
            *expected_classifications,
            *(item["id"] for item in expected_records),
        }
        id_entries = id_registry.get("ids")
        if not isinstance(id_entries, list):
            return self._historical_authorized_links_cache
        current_contract_ids = {
            entry["id"]
            for entry in id_entries
            if isinstance(entry, dict)
            and isinstance(entry.get("id"), str)
            and entry["id"] not in forbidden
            and re.fullmatch(
                r"[A-Z][A-Z0-9]*(?:-[A-Z0-9]+)+",
                entry["id"],
            )
            is not None
        }
        for authorization in authorizations:
            if not isinstance(authorization, dict) or set(authorization) != {
                "active_role",
                "current_contract_id",
                "historical_reference",
            }:
                continue
            active_role = authorization.get("active_role")
            current_contract = authorization.get("current_contract_id")
            historical_reference = authorization.get("historical_reference")
            if (
                active_role in HISTORICAL_ACTIVE_ROLE_IDS
                and current_contract in current_contract_ids
                and historical_reference in forbidden
            ):
                self._historical_authorized_links_cache.add(
                    (str(active_role), str(historical_reference))
                )
        return self._historical_authorized_links_cache

    def _historical_role_is_authorized(
        self,
        active_role: str,
        historical_reference: str,
    ) -> bool:
        return (
            active_role,
            historical_reference,
        ) in self._historical_authorized_links()

    def _effective_normative_policy_id(self, entry: dict[str, Any]) -> Any:
        declared_id = entry.get("id")
        path = entry.get("path")
        if not isinstance(declared_id, str) or not isinstance(path, str):
            return declared_id
        return self._normative_role_aliases.get(
            (declared_id, path),
            declared_id,
        )

    def _load_json(self, relative_path: str) -> Any | None:
        if relative_path in self._json_cache:
            return self._json_cache[relative_path]
        text = self._read_text(relative_path)
        if text is None:
            return None

        def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
            result: dict[str, Any] = {}
            for key, value in pairs:
                if key in result:
                    raise _DuplicateJSONKey(key)
                result[key] = value
            return result

        try:
            value = json.loads(text, object_pairs_hook=unique_object)
        except _DuplicateJSONKey as error:
            self._add(
                "REPO-JSON-DUPLICATE-KEY",
                relative_path,
                f"key {error.args[0]!r} appears more than once",
            )
            return None
        except json.JSONDecodeError as error:
            self._add(
                "REPO-JSON-INVALID",
                relative_path,
                f"line {error.lineno}, column {error.colno}: {error.msg}",
            )
            return None
        self._json_cache[relative_path] = value
        return value

    def _load_accepted_decisions(self) -> None:
        path = "docs/decisions/index.md"
        text = self._read_text(path)
        if text is None:
            return
        section = text.partition("## Accepted decisions")[2].partition("\n## ")[0]
        self._accepted_decisions = set(re.findall(r"\bADR-[0-9]{4}\b", section))

    def _tracked_paths(self) -> set[str]:
        process = subprocess.run(
            ["git", "-C", str(self.root), "ls-files", "-z"],
            check=False,
            capture_output=True,
        )
        if process.returncode != 0:
            self._add(
                "REPO-GIT-INDEX-UNAVAILABLE",
                ".",
                f"git ls-files failed with exit code {process.returncode}",
            )
            return set()
        return {
            raw.decode("utf-8")
            for raw in process.stdout.split(b"\0")
            if raw
        }

    def _visible_guidance_paths(self) -> set[str]:
        return visible_guidance_paths(self.root)

    def _guidance_chain(self, target_path: str) -> tuple[str, ...]:
        target = self.root / target_path
        directories = [self.root]
        cursor = self.root
        for part in target.parent.relative_to(self.root).parts:
            cursor /= part
            directories.append(cursor)
        chain: list[str] = []
        for directory in directories:
            candidate = directory / "AGENTS.md"
            if not os.path.lexists(candidate):
                continue
            relative = candidate.relative_to(self.root).as_posix()
            if candidate.is_symlink():
                self._add(
                    "REPO-GUIDANCE-SYMLINK",
                    relative,
                    "guidance must be a repository-owned regular file",
                )
                continue
            if not candidate.is_file():
                self._add(
                    "REPO-GUIDANCE-NOT-REGULAR",
                    relative,
                    "guidance must be a regular file",
                )
                continue
            chain.append(relative)
        return tuple(chain)

    def _check_guidance(self) -> None:
        tracked = self._tracked_paths()
        expected = set(EXPECTED_GUIDANCE)
        found = self._visible_guidance_paths()
        for path in self._ordered(expected - found):
            self._add("REPO-GUIDANCE-MISSING", path, "required guidance file is absent")
        for path in self._ordered(found - expected):
            self._add(
                "REPO-GUIDANCE-UNDECLARED",
                path,
                "guidance boundary is not part of the canonical hierarchy",
            )
        for path in self._ordered(expected):
            candidate = self.root / path
            if os.path.lexists(candidate) and candidate.is_symlink():
                self._add(
                    "REPO-GUIDANCE-SYMLINK",
                    path,
                    "guidance must be a repository-owned regular file",
                )
            elif os.path.lexists(candidate) and not candidate.is_file():
                self._add(
                    "REPO-GUIDANCE-NOT-REGULAR",
                    path,
                    "guidance must be a regular file",
                )
            if path not in tracked:
                self._add(
                    "REPO-GUIDANCE-UNTRACKED",
                    path,
                    "guidance must be owned by the Git index",
                )
        for target, expected_chain in EXPECTED_GUIDANCE_CHAINS.items():
            if not (self.root / target).is_file():
                self._add(
                    "REPO-GUIDANCE-TARGET-MISSING",
                    target,
                    "canonical hierarchy target is absent",
                )
                continue
            actual = self._guidance_chain(target)
            if actual != expected_chain:
                self._add(
                    "REPO-GUIDANCE-HIERARCHY",
                    target,
                    f"expected {list(expected_chain)!r}, found {list(actual)!r}",
                )
        claude = self._read_text("CLAUDE.md")
        if claude is not None and claude.splitlines() != [
            "# Claude repository guidance",
            "",
            "@AGENTS.md",
        ]:
            self._add(
                "REPO-GUIDANCE-CLAUDE-INDIRECTION",
                "CLAUDE.md",
                "Claude guidance must remain a thin @AGENTS.md indirection",
            )

    @staticmethod
    def _valid_repo_path(value: str) -> bool:
        if (
            not value
            or value != value.strip()
            or "\\" in value
            or "//" in value
        ):
            return False
        candidate = PurePosixPath(value)
        return (
            not candidate.is_absolute()
            and candidate.as_posix() == value
            and all(part not in {"", ".", ".."} for part in candidate.parts)
        )

    def _matching_paths(self, pattern: str) -> list[Path]:
        if not self._valid_repo_path(pattern):
            return []
        return sorted(
            (
                Path(match)
                for match in glob.glob(str(self.root / pattern), recursive=True)
                if Path(match).exists()
            ),
            reverse=self.reverse,
        )

    def _check_normative_documents(self) -> None:
        policy = self._load_json(NORMATIVE_POLICY_PATH)
        if not isinstance(policy, dict):
            if policy is not None:
                self._add(
                    "REPO-NORMATIVE-POLICY-TYPE",
                    NORMATIVE_POLICY_PATH,
                    "top level must be an object",
                )
            return
        if set(policy) != {"documents", "frontmatter_policy", "schema_version"}:
            self._add(
                "REPO-NORMATIVE-POLICY-FIELDS",
                NORMATIVE_POLICY_PATH,
                "top-level fields must match the version-1 contract",
            )
        if policy.get("schema_version") != 1:
            self._add(
                "REPO-NORMATIVE-POLICY-VERSION",
                NORMATIVE_POLICY_PATH,
                "only schema_version 1 is supported",
            )
        documents = policy.get("documents")
        rules = policy.get("frontmatter_policy")
        if not isinstance(documents, list) or not isinstance(rules, dict):
            self._add(
                "REPO-NORMATIVE-POLICY-SHAPE",
                NORMATIVE_POLICY_PATH,
                "documents and frontmatter_policy must be present",
            )
            return
        required_rule_fields = {
            "allow_unknown_fields",
            "required_fields",
            "supported_schema_versions",
            "supported_statuses",
        }
        if set(rules) != required_rule_fields:
            self._add(
                "REPO-FRONTMATTER-POLICY-FIELDS",
                NORMATIVE_POLICY_PATH,
                "frontmatter policy fields must match the version-1 contract",
            )
            return
        required_fields = rules.get("required_fields")
        status_values = rules.get("supported_statuses")
        version_values = rules.get("supported_schema_versions")
        allow_unknown = rules.get("allow_unknown_fields")
        if (
            not isinstance(required_fields, list)
            or not all(isinstance(item, str) for item in required_fields)
            or not isinstance(status_values, list)
            or not all(isinstance(item, str) for item in status_values)
            or not isinstance(version_values, list)
            or not all(isinstance(item, int) for item in version_values)
            or not isinstance(allow_unknown, bool)
        ):
            self._add(
                "REPO-FRONTMATTER-POLICY-TYPE",
                NORMATIVE_POLICY_PATH,
                "frontmatter policy values have invalid types",
            )
            return
        if allow_unknown:
            self._add(
                "REPO-FRONTMATTER-POLICY-NOT-STRICT",
                NORMATIVE_POLICY_PATH,
                "unknown frontmatter fields must be rejected",
            )
        required = set(required_fields)
        supported_statuses = set(status_values)
        supported_versions = set(version_values)
        seen_ids: set[str] = set()
        seen_paths: set[str] = set()
        indices = list(range(len(documents)))
        if self.reverse:
            indices.reverse()
        for numeric_index in indices:
            index = str(numeric_index)
            raw = documents[numeric_index]
            location = f"{NORMATIVE_POLICY_PATH}#documents[{index}]"
            if not isinstance(raw, dict) or set(raw) != {"id", "path"}:
                self._add(
                    "REPO-NORMATIVE-ENTRY-FIELDS",
                    location,
                    "each entry requires only id and path",
                )
                continue
            declared_id = raw.get("id")
            path = raw.get("path")
            if not isinstance(declared_id, str) or not isinstance(path, str):
                self._add(
                    "REPO-NORMATIVE-ENTRY-TYPE",
                    location,
                    "id and path must be strings",
                )
                continue
            if declared_id in seen_ids:
                self._add(
                    "REPO-CANONICAL-ID-DUPLICATE",
                    NORMATIVE_POLICY_PATH,
                    f"normative ID {declared_id!r} appears more than once",
                )
            if path in seen_paths:
                self._add(
                    "REPO-CANONICAL-PATH-DUPLICATE",
                    NORMATIVE_POLICY_PATH,
                    f"canonical path {path!r} appears more than once",
                )
            seen_ids.add(declared_id)
            seen_paths.add(path)
            if not self._valid_repo_path(path):
                self._add(
                    "REPO-NORMATIVE-PATH-INVALID",
                    location,
                    f"{path!r} is not repository-relative",
                )
                continue
            text = self._read_text(path)
            if text is None:
                continue
            frontmatter_parts = text.split("---", 2)
            if len(frontmatter_parts) >= 3:
                keys = re.findall(
                    r"^([A-Za-z_][A-Za-z0-9_-]*):",
                    frontmatter_parts[1],
                    re.MULTILINE,
                )
                for key in sorted({item for item in keys if keys.count(item) > 1}):
                    self._add(
                        "REPO-FRONTMATTER-KEY-DUPLICATE",
                        path,
                        f"frontmatter key {key!r} appears more than once",
                    )
            try:
                metadata, body = parse_frontmatter(text)
            except (TypeError, ValueError, yaml.YAMLError) as error:
                self._add("REPO-FRONTMATTER-INVALID", path, str(error))
                continue
            if not isinstance(metadata, dict):
                self._add(
                    "REPO-FRONTMATTER-INVALID",
                    path,
                    "frontmatter must be a mapping",
                )
                continue
            fields = set(metadata)
            for field in sorted(required - fields):
                self._add(
                    "REPO-FRONTMATTER-FIELD-MISSING",
                    path,
                    f"required field {field!r} is absent",
                )
            if allow_unknown is False:
                for field in sorted(fields - required):
                    self._add(
                        "REPO-FRONTMATTER-FIELD-UNKNOWN",
                        path,
                        f"field {field!r} is not permitted",
                    )
            actual_id = metadata.get("id")
            if actual_id != declared_id:
                if (
                    isinstance(actual_id, str)
                    and self._historical_role_is_authorized(
                        "canonical-template",
                        declared_id,
                    )
                ):
                    self._normative_role_aliases[(declared_id, path)] = actual_id
                else:
                    self._add(
                        "REPO-FRONTMATTER-ID-MISMATCH",
                        path,
                        f"expected {declared_id!r}, found {actual_id!r}",
                    )
            status = metadata.get("status")
            if not isinstance(status, str) or status not in supported_statuses:
                self._add(
                    "REPO-FRONTMATTER-STATUS-UNSUPPORTED",
                    path,
                    f"unsupported status {status!r}",
                )
            schema_version = metadata.get("schema_version")
            if (
                not isinstance(schema_version, int)
                or isinstance(schema_version, bool)
                or schema_version not in supported_versions
            ):
                self._add(
                    "REPO-FRONTMATTER-VERSION-UNSUPPORTED",
                    path,
                    f"unsupported schema version {schema_version!r}",
                )
            for field in ("applies_to", "verified_by"):
                values = metadata.get(field)
                if not isinstance(values, list) or not values:
                    self._add(
                        "REPO-FRONTMATTER-PATH-LIST-INVALID",
                        path,
                        f"{field} must be a non-empty list",
                    )
                    continue
                for value in values:
                    if not isinstance(value, str) or not self._valid_repo_path(value):
                        self._add(
                            "REPO-FRONTMATTER-PATH-INVALID",
                            path,
                            f"{field} contains non-repository path {value!r}",
                        )
                    elif not self._matching_paths(value):
                        self._add(
                            "REPO-FRONTMATTER-PATH-UNRESOLVED",
                            path,
                            f"{field} path {value!r} resolves to nothing",
                        )
            related = metadata.get("related_decisions")
            if not isinstance(related, list):
                self._add(
                    "REPO-FRONTMATTER-DECISIONS-INVALID",
                    path,
                    "related_decisions must be a list",
                )
            else:
                for decision_id in related:
                    if (
                        not isinstance(decision_id, str)
                        or decision_id not in self._accepted_decisions
                    ):
                        self._add(
                            "REPO-FRONTMATTER-DECISION-UNKNOWN",
                            path,
                            f"decision {decision_id!r} is not accepted",
                        )
            if isinstance(actual_id, str):
                self._record_global_id(actual_id, path)
            self._normative_documents.append((declared_id, path, metadata, body))
            if (declared_id, path) in self._normative_role_aliases:
                self._normative_documents[-1] = (
                    self._normative_role_aliases[(declared_id, path)],
                    path,
                    metadata,
                    body,
                )
            self._check_markdown_links(path, text)
        declared_order = [
            self._effective_normative_policy_id(entry)
            for entry in documents
            if isinstance(entry, dict) and isinstance(entry.get("id"), str)
        ]
        if declared_order != sorted(declared_order):
            self._add(
                "REPO-NORMATIVE-ORDER",
                NORMATIVE_POLICY_PATH,
                "document entries must be sorted by ID",
            )
        self._check_architecture_reachability(seen_paths)
        self._check_source_references()

    def _heading_anchors(self, relative_path: str) -> set[str]:
        text = self._read_text(relative_path)
        if text is None:
            return set()
        anchors: set[str] = set()
        counts: dict[str, int] = {}
        for heading in parse_commonmark(text).headings:
            normalized = re.sub(
                r"[^\w\s-]",
                "",
                _compatible_text(heading.text).casefold(),
            )
            base = re.sub(r"[\s-]+", "-", normalized).strip("-")
            count = counts.get(base, 0)
            counts[base] = count + 1
            anchors.add(base if count == 0 else f"{base}-{count}")
            anchors.update(heading.aliases)
        return anchors

    def _repo_path_has_exact_case(self, relative_path: str) -> bool:
        if not self._valid_repo_path(relative_path):
            return False
        cursor = self.root
        for part in PurePosixPath(relative_path).parts:
            try:
                names = {entry.name for entry in os.scandir(cursor)}
            except OSError:
                return False
            if part not in names:
                return False
            cursor /= part
        return True

    def _resolve_reference(
        self,
        *,
        source_path: str,
        relative: str,
        anchor: str,
        missing_code: str,
        anchor_code: str,
    ) -> str | None:
        source = self.root / source_path
        target = source.parent if not relative else source.parent / relative
        try:
            lexical_target = Path(os.path.normpath(target))
            lexical_path = lexical_target.relative_to(self.root).as_posix()
        except ValueError:
            self._add(
                "REPO-REFERENCE-PATH-ESCAPE",
                source_path,
                f"target {relative!r} escapes the repository",
            )
            return None
        if not self._repo_path_has_exact_case(lexical_path):
            self._add(missing_code, source_path, f"target {relative!r} does not exist")
            return None
        try:
            resolved = target.resolve(strict=True)
            target_path = resolved.relative_to(self.root).as_posix()
        except FileNotFoundError:
            self._add(missing_code, source_path, f"target {relative!r} does not exist")
            return None
        except ValueError:
            self._add(
                "REPO-REFERENCE-PATH-ESCAPE",
                source_path,
                f"target {relative!r} escapes the repository",
            )
            return None
        if anchor and anchor not in self._heading_anchors(target_path):
            self._add(
                anchor_code,
                source_path,
                f"anchor {anchor!r} does not resolve in {target_path}",
            )
        return target_path

    def _check_markdown_links(self, path: str, text: str) -> set[str]:
        destinations: set[str] = set()
        for raw in re.findall(r"\[[^\]]+\]\(([^)]+)\)", text):
            destination = raw.strip().split(maxsplit=1)[0].strip("<>")
            if destination.startswith(("http://", "https://", "mailto:")):
                continue
            relative, _, anchor = destination.partition("#")
            target = self._resolve_reference(
                source_path=path,
                relative=relative,
                anchor=anchor,
                missing_code="REPO-MARKDOWN-TARGET-MISSING",
                anchor_code="REPO-MARKDOWN-ANCHOR-MISSING",
            )
            if target is not None:
                destinations.add(target)
        return destinations

    def _check_architecture_reachability(self, canonical_paths: set[str]) -> None:
        index_path = f"{ARCHITECTURE_DIR}/index.md"
        text = self._read_text(index_path)
        if text is None:
            return
        destinations = self._check_markdown_links(index_path, text)
        for path in self._ordered(canonical_paths - {index_path}):
            if path not in destinations:
                self._add(
                    "REPO-CANONICAL-NOT-INDEXED",
                    path,
                    "canonical normative document is not linked from the architecture index",
                )

    def _check_source_references(self) -> None:
        paths = [
            path
            for base in (self.root / "src", self.root / "tests")
            for path in base.rglob("*.py")
            if path.is_file()
        ]
        for source in sorted(paths, reverse=self.reverse):
            source_path = source.relative_to(self.root).as_posix()
            text = self._read_text(source_path)
            if text is None:
                continue
            reference_texts: list[str] = []
            try:
                tokens = tokenize.generate_tokens(io.StringIO(text).readline)
                reference_texts.extend(
                    token.string
                    for token in tokens
                    if token.type == tokenize.COMMENT
                )
            except tokenize.TokenError as error:
                self._add("REPO-SOURCE-TOKENIZE", source_path, str(error))
                continue
            try:
                tree = ast.parse(text)
            except SyntaxError as error:
                self._add(
                    "REPO-SOURCE-PARSE",
                    source_path,
                    f"line {error.lineno}: {error.msg}",
                )
                continue
            for node in ast.walk(tree):
                if isinstance(
                    node,
                    (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef),
                ):
                    docstring = ast.get_docstring(node, clean=False)
                    if docstring is not None:
                        reference_texts.append(docstring)
            for reference_text in reference_texts:
                scrubbed = _EXTERNAL_REFERENCE.sub(
                    lambda match: " " * len(match.group(0)),
                    reference_text,
                )
                for candidate in _SOURCE_REFERENCE_CANDIDATE.finditer(scrubbed):
                    raw_reference = candidate.group("reference").rstrip(".,;:")
                    match = _SOURCE_REFERENCE_GRAMMAR.fullmatch(raw_reference)
                    if match is None:
                        raw_path, separator, _raw_anchor = raw_reference.partition("#")
                        code = (
                            "REPO-SOURCE-ANCHOR-MISSING"
                            if separator
                            and _SOURCE_REFERENCE_GRAMMAR.fullmatch(raw_path) is not None
                            else "REPO-SOURCE-REFERENCE-INVALID"
                        )
                        message = (
                            (
                                f"empty anchor does not resolve in {raw_path}"
                                if not _raw_anchor
                                else f"anchor {_raw_anchor!r} does not resolve in {raw_path}"
                            )
                            if code == "REPO-SOURCE-ANCHOR-MISSING"
                            else (
                                f"reference {raw_reference!r} does not match "
                                "the exact grammar"
                            )
                        )
                        self._add(
                            code,
                            source_path,
                            message,
                        )
                        continue
                    target_path = match.group("path")
                    anchor = match.group("anchor") or ""
                    self._resolve_reference(
                        source_path=source_path,
                        relative=os.path.relpath(
                            self.root / target_path,
                            start=(self.root / source_path).parent,
                        ),
                        anchor=anchor,
                        missing_code="REPO-SOURCE-REFERENCE-MISSING",
                        anchor_code="REPO-SOURCE-ANCHOR-MISSING",
                    )

    def _record_global_id(self, record_id: str, canonical_path: str) -> None:
        self._global_ids.setdefault(record_id, set()).add(canonical_path)

    def _check_stable_ids(self) -> None:
        registry = self._load_json(ID_REGISTRY_PATH)
        if not isinstance(registry, dict):
            return
        if set(registry) != {"ids", "kinds", "schema_version"}:
            self._add(
                "REPO-ID-REGISTRY-FIELDS",
                ID_REGISTRY_PATH,
                "top-level fields must match the version-1 contract",
            )
        if registry.get("schema_version") != 1:
            self._add(
                "REPO-ID-REGISTRY-VERSION",
                ID_REGISTRY_PATH,
                "only schema_version 1 is supported",
            )
        kinds = registry.get("kinds")
        entries = registry.get("ids")
        if not isinstance(kinds, list) or not isinstance(entries, list):
            self._add(
                "REPO-ID-REGISTRY-SHAPE",
                ID_REGISTRY_PATH,
                "kinds and ids must be lists",
            )
            return
        if not all(isinstance(kind, str) for kind in kinds):
            self._add(
                "REPO-ID-KIND-TYPE",
                ID_REGISTRY_PATH,
                "registered kinds must be strings",
            )
            return
        if kinds != sorted(set(kinds)):
            self._add(
                "REPO-ID-KIND-ORDER",
                ID_REGISTRY_PATH,
                "kinds must be sorted and unique",
            )
        seen: set[str] = set()
        order: list[str] = []
        for index, entry in enumerate(entries):
            location = f"{ID_REGISTRY_PATH}#ids[{index}]"
            if not isinstance(entry, dict) or set(entry) != {
                "id",
                "kind",
                "source",
                "statement",
            }:
                self._add(
                    "REPO-ID-RECORD-FIELDS",
                    location,
                    "ID records require id, kind, source, and statement",
                )
                continue
            record_id = entry.get("id")
            kind = entry.get("kind")
            source = entry.get("source")
            statement = entry.get("statement")
            if (
                not isinstance(record_id, str)
                or not isinstance(kind, str)
                or not isinstance(source, str)
                or not isinstance(statement, str)
            ):
                self._add(
                    "REPO-ID-RECORD-TYPE",
                    location,
                    "ID record values must be strings",
                )
                continue
            order.append(record_id)
            active_role = ID_KIND_ACTIVE_ROLES.get(kind)
            if (
                re.fullmatch(
                    r"[A-Z][A-Z0-9]*(?:-[A-Z0-9]+)+",
                    record_id,
                )
                is None
                and (
                    active_role is None
                    or not self._historical_role_is_authorized(
                        active_role,
                        record_id,
                    )
                )
            ):
                self._add(
                    "REPO-ID-FORMAT",
                    location,
                    f"{record_id!r} is not a stable ID",
                )
            if record_id in seen:
                self._add(
                    "REPO-ID-DUPLICATE",
                    ID_REGISTRY_PATH,
                    f"ID {record_id!r} appears more than once",
                )
            seen.add(record_id)
            if kind not in kinds:
                self._add(
                    "REPO-ID-KIND-UNKNOWN",
                    location,
                    f"kind {kind!r} is not registered",
                )
            if not self._valid_repo_path(source):
                self._add(
                    "REPO-ID-SOURCE-INVALID",
                    location,
                    f"source {source!r} is not repository-relative",
                )
                continue
            source_text = self._read_text(source)
            if source_text is not None and record_id not in source_text:
                self._add(
                    "REPO-ID-SOURCE-UNRESOLVED",
                    source,
                    f"canonical source does not contain {record_id}",
                )
            self._record_global_id(record_id, source)
        if order != sorted(order):
            self._add(
                "REPO-ID-ORDER",
                ID_REGISTRY_PATH,
                "ID records must be sorted by ID",
            )

    def _check_annotations(self) -> None:
        annotation_policy = self._load_json(ANNOTATION_POLICY_PATH)
        id_registry = self._load_json(ID_REGISTRY_PATH)
        removal_registry = self._load_json(REMOVAL_REGISTRY_PATH)
        if (
            not isinstance(annotation_policy, dict)
            or not isinstance(id_registry, dict)
            or not isinstance(removal_registry, dict)
        ):
            return
        if set(annotation_policy) != {"annotations", "banned_content", "schema_version"}:
            self._add(
                "REPO-ANNOTATION-POLICY-FIELDS",
                ANNOTATION_POLICY_PATH,
                "top-level fields must match the version-1 contract",
            )
        if annotation_policy.get("schema_version") != 1:
            self._add(
                "REPO-ANNOTATION-POLICY-VERSION",
                ANNOTATION_POLICY_PATH,
                "only schema_version 1 is supported",
            )
        if set(removal_registry) != {
            "issue_id_pattern",
            "issues",
            "removal_condition_pattern",
            "removal_conditions",
            "schema_version",
        }:
            self._add(
                "REPO-REMOVAL-REGISTRY-FIELDS",
                REMOVAL_REGISTRY_PATH,
                "top-level fields must match the version-1 contract",
            )
        if removal_registry.get("schema_version") != 1:
            self._add(
                "REPO-REMOVAL-REGISTRY-VERSION",
                REMOVAL_REGISTRY_PATH,
                "only schema_version 1 is supported",
            )
        annotations = annotation_policy.get("annotations")
        banned_content = annotation_policy.get("banned_content")
        grammar = (
            banned_content.get("identity_attribution_grammar")
            if isinstance(banned_content, dict)
            else None
        )
        containers = (
            banned_content.get("supported_containers")
            if isinstance(banned_content, dict)
            else None
        )
        identity_slot = (
            grammar.get("identity_slot") if isinstance(grammar, dict) else None
        )
        container_ids = [
            entry.get("id")
            for entry in containers
            if isinstance(entry, dict)
        ] if isinstance(containers, list) else []
        if (
            not isinstance(annotations, list)
            or not isinstance(banned_content, dict)
            or set(banned_content) != _BANNED_CONTENT_FIELDS
            or not isinstance(grammar, dict)
            or set(grammar)
            != {
                "identity_slot",
                "known_identity_examples",
                "private_reasoning_concepts",
                "visible_label_forms",
            }
            or not isinstance(identity_slot, dict)
            or identity_slot
            != {
                "kind": "open-token-sequence",
                "maximum_tokens": 6,
                "minimum_tokens": 1,
            }
            or any(
                not isinstance(grammar.get(field), list)
                or not all(
                    isinstance(value, str) and value.strip()
                    for value in grammar[field]
                )
                or grammar[field] != sorted(set(grammar[field]))
                for field in (
                    "known_identity_examples",
                    "private_reasoning_concepts",
                    "visible_label_forms",
                )
            )
            or any(
                not isinstance(banned_content.get(field), list)
                or not all(
                    isinstance(value, str) and value.strip()
                    for value in banned_content[field]
                )
                or banned_content[field] != sorted(set(banned_content[field]))
                for field in ("normalization", "out_of_scope_containers")
            )
            or container_ids
            != [
                "html-attribute-value",
                "html-private-concept-tag",
                "html-visible-label",
                "markdown-attribute-value",
                "markdown-visible-label",
            ]
        ):
            self._add(
                "REPO-ANNOTATION-POLICY-SHAPE",
                ANNOTATION_POLICY_PATH,
                "annotations and normalized banned-content categories are invalid",
            )
            return
        typed_banned_content: dict[str, Any] = banned_content
        expected_references = {
            "COMPAT": "id-registry.json#kind=compatibility",
            "INVARIANT": "id-registry.json#kind=invariant",
            "SECURITY": "id-registry.json#kind=security",
            "TODO": "removal-registry.json#issues+removal_conditions",
            "WHY": "../decisions/index.md#accepted-decisions",
        }
        references: dict[str, str] = {}
        annotation_order: list[str] = []
        for index, entry in enumerate(annotations):
            location = f"{ANNOTATION_POLICY_PATH}#annotations[{index}]"
            if not isinstance(entry, dict) or set(entry) != {
                "kind",
                "reference",
                "syntax",
            }:
                self._add(
                    "REPO-ANNOTATION-RECORD-FIELDS",
                    location,
                    "annotation records require kind, reference, and syntax",
                )
                continue
            kind = entry.get("kind")
            reference = entry.get("reference")
            syntax = entry.get("syntax")
            if (
                not isinstance(kind, str)
                or not isinstance(reference, str)
                or not isinstance(syntax, str)
            ):
                self._add(
                    "REPO-ANNOTATION-RECORD-TYPE",
                    location,
                    "annotation record values must be strings",
                )
                continue
            if kind in references:
                self._add(
                    "REPO-ANNOTATION-KIND-DUPLICATE",
                    ANNOTATION_POLICY_PATH,
                    f"annotation kind {kind!r} appears more than once",
                )
            references[kind] = reference
            annotation_order.append(kind)
        if annotation_order != sorted(annotation_order):
            self._add(
                "REPO-ANNOTATION-ORDER",
                ANNOTATION_POLICY_PATH,
                "annotation records must be sorted by kind",
            )
        if references != expected_references:
            self._add(
                "REPO-ANNOTATION-POLICY-REFERENCES",
                ANNOTATION_POLICY_PATH,
                "annotation kinds must resolve through the canonical registries",
            )
        id_kinds: dict[str, str] = {
            entry["id"]: entry["kind"]
            for entry in id_registry.get("ids", [])
            if isinstance(entry, dict)
            and isinstance(entry.get("id"), str)
            and isinstance(entry.get("kind"), str)
        }
        issues: set[str] = {
            entry["id"]
            for entry in removal_registry.get("issues", [])
            if isinstance(entry, dict) and isinstance(entry.get("id"), str)
        }
        conditions: set[str] = {
            entry["id"]
            for entry in removal_registry.get("removal_conditions", [])
            if isinstance(entry, dict) and isinstance(entry.get("id"), str)
        }
        for field in ("issues", "removal_conditions"):
            entries = removal_registry.get(field)
            if not isinstance(entries, list):
                self._add(
                    "REPO-REMOVAL-REGISTRY-SHAPE",
                    REMOVAL_REGISTRY_PATH,
                    f"{field} must be a list",
                )
                continue
            ids = [
                entry["id"]
                for entry in entries
                if isinstance(entry, dict) and isinstance(entry.get("id"), str)
            ]
            if ids != sorted(set(ids)):
                self._add(
                    "REPO-REMOVAL-REGISTRY-ORDER",
                    REMOVAL_REGISTRY_PATH,
                    f"{field} must be sorted and unique",
                )
        simple_re = re.compile(
            r"^(COMPAT|INVARIANT|SECURITY|WHY)\[([^\]]+)\]:\s+\S.*$"
        )
        todo_re = re.compile(
            r"^TODO\[(#[1-9][0-9]*); remove-after=([a-z0-9][a-z0-9-]*)\]:\s+\S.*$"
        )
        structured_re = re.compile(r"^([A-Z][A-Z0-9_-]*)\[")
        approved = set(expected_references)
        kind_mapping = {
            "COMPAT": "compatibility",
            "INVARIANT": "invariant",
            "SECURITY": "security",
        }
        paths = [
            path
            for base in (self.root / "src", self.root / "tests")
            for path in base.rglob("*.py")
            if path.is_file()
        ]
        for path in sorted(paths, reverse=self.reverse):
            relative = path.relative_to(self.root).as_posix()
            text = self._read_text(relative)
            if text is None:
                continue
            try:
                tokens = tokenize.generate_tokens(io.StringIO(text).readline)
                comments = [token.string for token in tokens if token.type == tokenize.COMMENT]
            except tokenize.TokenError as error:
                self._add("REPO-SOURCE-TOKENIZE", relative, str(error))
                continue
            for raw in comments:
                comment = raw.removeprefix("#").strip()
                structured = structured_re.match(comment)
                if structured and structured.group(1) not in approved:
                    self._add(
                        "REPO-ANNOTATION-KIND-UNKNOWN",
                        relative,
                        f"annotation kind {structured.group(1)!r} is not approved",
                    )
                    continue
                if comment.startswith("TODO"):
                    match = todo_re.fullmatch(comment)
                    if match is None:
                        self._add(
                            "REPO-ANNOTATION-MALFORMED",
                            relative,
                            "TODO annotation does not match the approved syntax",
                        )
                        continue
                    issue, condition = match.groups()
                    if issue not in issues:
                        self._add(
                            "REPO-ANNOTATION-ISSUE-UNKNOWN",
                            relative,
                            f"issue {issue!r} is not registered",
                        )
                    if condition not in conditions:
                        self._add(
                            "REPO-ANNOTATION-REMOVAL-UNKNOWN",
                            relative,
                            f"removal condition {condition!r} is not registered",
                        )
                    continue
                if comment.startswith(("COMPAT", "INVARIANT", "SECURITY", "WHY")):
                    match = simple_re.fullmatch(comment)
                    if match is None:
                        self._add(
                            "REPO-ANNOTATION-MALFORMED",
                            relative,
                            "structured annotation does not match the approved syntax",
                        )
                        continue
                    kind, record_id = match.groups()
                    if kind == "WHY":
                        if record_id not in self._accepted_decisions:
                            self._add(
                                "REPO-ANNOTATION-DECISION-UNKNOWN",
                                relative,
                                f"decision {record_id!r} is not accepted",
                            )
                    elif id_kinds.get(record_id) != kind_mapping[kind]:
                        self._add(
                            "REPO-ANNOTATION-ID-UNKNOWN",
                            relative,
                            f"{kind} record {record_id!r} does not resolve",
                        )
        for _document_id, normative_path, _metadata, _body in self._normative_documents:
            text = self._read_text(normative_path)
            if text is None:
                continue
            for category in _identity_private_marker_categories(
                text,
                typed_banned_content,
            ):
                self._add(
                    "REPO-NORMATIVE-BANNED-MARKER",
                    normative_path,
                    f"document contains banned {category} content",
                )

    def _check_component_map(self) -> None:
        component_map = self._load_json(COMPONENT_MAP_PATH)
        id_registry = self._load_json(ID_REGISTRY_PATH)
        if not isinstance(component_map, dict) or not isinstance(id_registry, dict):
            return
        if set(component_map) != {"components", "schema_version"}:
            self._add(
                "REPO-COMPONENT-MAP-FIELDS",
                COMPONENT_MAP_PATH,
                "top-level fields must match the version-1 contract",
            )
        if component_map.get("schema_version") != 1:
            self._add(
                "REPO-COMPONENT-MAP-VERSION",
                COMPONENT_MAP_PATH,
                "only schema_version 1 is supported",
            )
        components = component_map.get("components")
        if not isinstance(components, list):
            self._add(
                "REPO-COMPONENT-MAP-SHAPE",
                COMPONENT_MAP_PATH,
                "components must be a list",
            )
            return
        registered_ids = {
            entry["id"]
            for entry in id_registry.get("ids", [])
            if isinstance(entry, dict) and isinstance(entry.get("id"), str)
        }
        expected_fields = {
            "decisions",
            "id",
            "invariants",
            "paths",
            "specifications",
            "tests",
        }
        seen: set[str] = set()
        order: list[str] = []
        for index, component in enumerate(components):
            location = f"{COMPONENT_MAP_PATH}#components[{index}]"
            if not isinstance(component, dict):
                self._add(
                    "REPO-COMPONENT-RECORD-TYPE",
                    location,
                    "component must be an object",
                )
                continue
            component_id = component.get("id")
            if set(component) != expected_fields:
                self._add(
                    "REPO-COMPONENT-RECORD-FIELDS",
                    location,
                    "component fields must match the version-1 contract",
                )
            if not isinstance(component_id, str):
                self._add(
                    "REPO-COMPONENT-ID-INVALID",
                    location,
                    "component ID must be a string",
                )
                continue
            order.append(component_id)
            if component_id in seen:
                self._add(
                    "REPO-COMPONENT-ID-DUPLICATE",
                    COMPONENT_MAP_PATH,
                    f"component {component_id!r} appears more than once",
                )
            seen.add(component_id)
            self._record_global_id(component_id, COMPONENT_MAP_PATH)
            string_lists: dict[str, list[str]] = {}
            for field in ("paths", "specifications", "tests", "invariants", "decisions"):
                values = component.get(field)
                if not isinstance(values, list):
                    self._add(
                        "REPO-COMPONENT-LIST-INVALID",
                        location,
                        f"{field} must be a list",
                    )
                    string_lists[field] = []
                    continue
                if not all(isinstance(value, str) for value in values):
                    self._add(
                        "REPO-COMPONENT-LIST-TYPE",
                        location,
                        f"{field} entries must be strings",
                    )
                    string_lists[field] = []
                    continue
                string_lists[field] = values
                if values != sorted(set(values)):
                    self._add(
                        "REPO-COMPONENT-LIST-ORDER",
                        location,
                        f"{field} must be sorted and unique",
                    )
            for pattern in string_lists["paths"]:
                if not isinstance(pattern, str) or not self._valid_repo_path(pattern):
                    self._add(
                        "REPO-COMPONENT-PATH-INVALID",
                        location,
                        f"path pattern {pattern!r} is not repository-relative",
                    )
                elif not self._matching_paths(pattern):
                    self._add(
                        "REPO-COMPONENT-PATH-UNRESOLVED",
                        location,
                        f"path pattern {pattern!r} resolves to nothing",
                    )
            for field in ("specifications", "tests"):
                for edge in string_lists[field]:
                    if not self._valid_repo_path(edge):
                        self._add(
                            "REPO-COMPONENT-EDGE-INVALID",
                            location,
                            f"{field} edge {edge!r} is not repository-relative",
                        )
                        continue
                    candidate = self.root / edge
                    if candidate.is_symlink() or not candidate.is_file():
                        self._add(
                            "REPO-COMPONENT-EDGE-UNRESOLVED",
                            location,
                            f"{field} edge {edge!r} is missing or not regular",
                        )
            for invariant in string_lists["invariants"]:
                if (
                    invariant not in registered_ids
                    and not self._historical_role_is_authorized(
                        "component-invariant",
                        invariant,
                    )
                ):
                    self._add(
                        "REPO-COMPONENT-INVARIANT-UNKNOWN",
                        location,
                        f"invariant {invariant!r} is not registered",
                    )
            for decision in string_lists["decisions"]:
                if decision not in self._accepted_decisions:
                    self._add(
                        "REPO-COMPONENT-DECISION-UNKNOWN",
                        location,
                        f"decision {decision!r} is not accepted",
                    )
        if order != sorted(order):
            self._add(
                "REPO-COMPONENT-ORDER",
                COMPONENT_MAP_PATH,
                "components must be sorted by ID",
            )

    def _check_historical_active_roles(self) -> None:
        catalog = self._load_json(HISTORICAL_POLICY_PATH)
        manifest_text = self._read_text(f"{BASELINE_PATH}/manifest.yaml")
        if not isinstance(catalog, dict) or manifest_text is None:
            return
        if set(catalog) != {
            "active_roles",
            "authorizations",
            "authorization_contract",
            "historical_classifications",
            "historical_records",
            "schema_version",
            "source_manifest",
        } or catalog.get("schema_version") != 1:
            self._add(
                "REPO-HISTORICAL-CATALOG-SHAPE",
                HISTORICAL_POLICY_PATH,
                "catalog must match the version-1 historical-record contract",
            )
            return
        if catalog.get("source_manifest") != f"{BASELINE_PATH}/manifest.yaml":
            self._add(
                "REPO-HISTORICAL-CATALOG-SOURCE",
                HISTORICAL_POLICY_PATH,
                "source_manifest must name the candidate baseline manifest",
            )
        try:
            manifest = yaml.safe_load(manifest_text)
        except yaml.YAMLError as error:
            self._add(
                "REPO-HISTORICAL-MANIFEST-INVALID",
                f"{BASELINE_PATH}/manifest.yaml",
                str(error),
            )
            return
        fixtures = manifest.get("fixtures") if isinstance(manifest, dict) else None
        if not isinstance(fixtures, list):
            return
        expected_records = sorted(
            (
                {
                    "classification": fixture["classification"],
                    "id": fixture["fixture_id"],
                }
                for fixture in fixtures
                if isinstance(fixture, dict)
                and isinstance(fixture.get("fixture_id"), str)
                and fixture.get("classification") in {"known_defect", "observed_legacy"}
            ),
            key=lambda item: item["id"],
        )
        expected_classifications = sorted(
            {item["classification"] for item in expected_records}
        )
        if (
            catalog.get("historical_records") != expected_records
            or catalog.get("historical_classifications") != expected_classifications
        ):
            self._add(
                "REPO-HISTORICAL-CATALOG-DRIFT",
                HISTORICAL_POLICY_PATH,
                "historical IDs/classifications must exactly match the candidate manifest",
            )

        active_roles = catalog.get("active_roles")
        authorizations = catalog.get("authorizations")
        authorization_contract = catalog.get("authorization_contract")
        if (
            not isinstance(active_roles, list)
            or not isinstance(authorizations, list)
            or not isinstance(authorization_contract, dict)
        ):
            self._add(
                "REPO-HISTORICAL-CATALOG-SHAPE",
                HISTORICAL_POLICY_PATH,
                "active roles and authorizations must be finite lists",
            )
            return
        if active_roles != list(HISTORICAL_ACTIVE_ROLE_LOCATORS):
            self._add(
                "REPO-HISTORICAL-ACTIVE-ROLE-INVALID",
                HISTORICAL_POLICY_PATH,
                "active role locators must exactly match the version-1 contract",
            )

        forbidden = {
            *expected_classifications,
            *(item["id"] for item in expected_records),
        }
        id_registry = self._load_json(ID_REGISTRY_PATH)
        current_contract_ids = {
            entry["id"]
            for entry in id_registry.get("ids", [])
            if isinstance(id_registry, dict)
            and isinstance(entry, dict)
            and isinstance(entry.get("id"), str)
            and entry["id"] not in forbidden
        } if isinstance(id_registry, dict) else set()
        allowed_links = self._historical_authorized_links()
        authorization_order: list[tuple[str, str, str]] = []
        if authorization_contract != HISTORICAL_AUTHORIZATION_CONTRACT:
            self._add(
                "REPO-HISTORICAL-AUTHORIZATION-INVALID",
                f"{HISTORICAL_POLICY_PATH}#authorization_contract",
                "authorization contract fields must match the version-1 contract",
            )
        for index, authorization in enumerate(authorizations):
            location = f"{HISTORICAL_POLICY_PATH}#authorizations[{index}]"
            if not isinstance(authorization, dict) or set(authorization) != {
                "active_role",
                "current_contract_id",
                "historical_reference",
            }:
                self._add(
                    "REPO-HISTORICAL-AUTHORIZATION-INVALID",
                    location,
                    "authorization fields must match the catalog contract",
                )
                continue
            active_role = authorization.get("active_role")
            current_contract = authorization.get("current_contract_id")
            historical_reference = authorization.get("historical_reference")
            if (
                active_role not in HISTORICAL_ACTIVE_ROLE_IDS
                or current_contract not in current_contract_ids
                or historical_reference not in forbidden
            ):
                self._add(
                    "REPO-HISTORICAL-AUTHORIZATION-INVALID",
                    location,
                    "authorization must bind one historical reference and separate current contract",
                )
                continue
            authorization_order.append(
                (str(active_role), str(historical_reference), str(current_contract))
            )
        if authorization_order != sorted(set(authorization_order)):
            self._add(
                "REPO-HISTORICAL-AUTHORIZATION-ORDER",
                HISTORICAL_POLICY_PATH,
                "authorizations must be sorted and unique",
            )

        for role in HISTORICAL_ACTIVE_ROLE_LOCATORS:
            role_id = role.get("id")
            registry_path = role.get("registry_path")
            collection_field = role.get("collection_field")
            if not all(
                isinstance(value, str)
                for value in (role_id, registry_path, collection_field)
            ):
                self._add(
                    "REPO-HISTORICAL-ACTIVE-ROLE-INVALID",
                    HISTORICAL_POLICY_PATH,
                    "active role locator is incomplete",
                )
                continue
            assert isinstance(role_id, str)
            assert isinstance(registry_path, str)
            assert isinstance(collection_field, str)
            registry = self._load_json(registry_path)
            records = (
                registry.get(collection_field) if isinstance(registry, dict) else None
            )
            if not isinstance(records, list):
                self._add(
                    "REPO-HISTORICAL-ACTIVE-ROLE-INVALID",
                    HISTORICAL_POLICY_PATH,
                    f"{role_id} registry collection does not resolve",
                )
                continue
            record_filter = role.get("record_filter")
            for index, record in enumerate(records):
                if not isinstance(record, dict):
                    continue
                if isinstance(record_filter, dict):
                    field = record_filter.get("field")
                    if "equals" in record_filter and record.get(field) != record_filter["equals"]:
                        continue
                    if "prefix" in record_filter and (
                        not isinstance(record.get(field), str)
                        or not record[field].startswith(record_filter["prefix"])
                    ):
                        continue
                values: list[tuple[str, str]] = []
                value_field = role.get("value_field")
                value_list_field = role.get("value_list_field")
                if isinstance(value_field, str) and isinstance(record.get(value_field), str):
                    values.append((value_field, record[value_field]))
                if isinstance(value_list_field, str) and isinstance(
                    record.get(value_list_field), list
                ):
                    values.extend(
                        (f"{value_list_field}[{value_index}]", value)
                        for value_index, value in enumerate(record[value_list_field])
                        if isinstance(value, str)
                    )
                for field_location, value in values:
                    if (
                        value in forbidden
                        and (role_id, value) not in allowed_links
                    ):
                        self._add(
                            "REPO-BASELINE-NONNORMATIVE-PROMOTED",
                            f"{registry_path}#{collection_field}[{index}].{field_location}",
                            f"historical reference {value!r} occupies active role {role_id!r}",
                        )

    def _check_templates(self) -> None:
        policy = self._load_json(NORMATIVE_POLICY_PATH)
        heading_policy = self._load_json(TEMPLATE_HEADING_POLICY_PATH)
        if (
            not isinstance(policy, dict)
            or not isinstance(policy.get("documents"), list)
            or not isinstance(heading_policy, dict)
        ):
            return
        if set(heading_policy) != {
            "canonical_templates",
            "excluded_identity_sources",
            "non_operative_containers",
            "normalization",
            "operative_syntaxes",
            "schema_version",
        } or heading_policy.get("schema_version") != 1:
            self._add(
                "REPO-TEMPLATE-HEADING-CATALOG-SHAPE",
                TEMPLATE_HEADING_POLICY_PATH,
                "catalog must match the version-1 template-heading contract",
            )
            return
        template_records = heading_policy.get("canonical_templates")
        if not isinstance(template_records, list):
            return
        template_by_id = {
            record["document_id"]: record
            for record in template_records
            if isinstance(record, dict)
            and isinstance(record.get("document_id"), str)
        }
        if list(template_by_id) != sorted(template_by_id) or set(template_by_id) != {
            "TPL-ADR-001",
            "TPL-PLAN-001",
            "TPL-TASK-001",
        }:
            self._add(
                "REPO-TEMPLATE-HEADING-CATALOG-SHAPE",
                TEMPLATE_HEADING_POLICY_PATH,
                "canonical template heading records are incomplete or unordered",
            )
        entries = policy["documents"]
        for template_id in sorted((*template_by_id, *TEMPLATE_YAML_FIELDS)):
            matching = [
                entry
                for entry in entries
                if isinstance(entry, dict)
                and self._effective_normative_policy_id(entry) == template_id
            ]
            if len(matching) != 1:
                self._add(
                    "REPO-TEMPLATE-CANONICAL-COUNT",
                    NORMATIVE_POLICY_PATH,
                    f"{template_id} has {len(matching)} canonical entries",
                )
                continue
            path = matching[0].get("path")
            if not isinstance(path, str):
                continue
            heading_record = template_by_id.get(template_id)
            if (
                heading_record is not None
                and heading_record.get("path") != path
            ):
                self._add(
                    "REPO-TEMPLATE-HEADING-CATALOG-DRIFT",
                    TEMPLATE_HEADING_POLICY_PATH,
                    f"{template_id} path does not match normative-documents.json",
                )
            document = next(
                (
                    item
                    for item in self._normative_documents
                    if item[0] == template_id and item[1] == path
                ),
                None,
            )
            if document is None:
                continue
            body = document[3]
            if heading_record is not None:
                required_headings = heading_record.get("required_headings")
                if not isinstance(required_headings, list):
                    continue
                heading_counts = Counter(_markdown_headings(body))
                missing_fields = [
                    f"{'#' * field['level']} {field['visible_label']}"
                    for field in required_headings
                    if isinstance(field, dict)
                    and isinstance(field.get("level"), int)
                    and isinstance(field.get("visible_label"), str)
                    and heading_counts[
                        _required_heading_key(
                            field["level"],
                            field["visible_label"],
                        )
                    ]
                    == 0
                ]
                duplicate_fields = [
                    f"{'#' * field['level']} {field['visible_label']}"
                    for field in required_headings
                    if isinstance(field, dict)
                    and isinstance(field.get("level"), int)
                    and isinstance(field.get("visible_label"), str)
                    and heading_counts[
                        _required_heading_key(
                            field["level"],
                            field["visible_label"],
                        )
                    ]
                    > 1
                ]
                duplicate_keys: tuple[str, ...] = ()
            else:
                mappings, duplicate_keys = _markdown_yaml_mappings(body)
                field_counts = {
                    display: sum(
                        _mapping_has_path(mapping, field_path)
                        for mapping in mappings
                    )

                    for display, field_path in TEMPLATE_YAML_FIELDS[template_id]
                }
                missing_fields = [
                    display
                    for display, count in field_counts.items()
                    if count == 0
                ]
                duplicate_fields = [
                    display
                    for display, count in field_counts.items()
                    if count > 1
                ]
            for field in missing_fields:
                self._add(
                    "REPO-TEMPLATE-FIELD-MISSING",
                    path,
                    f"required field {field!r} is absent",
                )
            for field in duplicate_fields:
                self._add(
                    "REPO-TEMPLATE-FIELD-DUPLICATE",
                    path,
                    f"required field {field!r} appears more than once",
                )
            for key in duplicate_keys:
                self._add(
                    "REPO-TEMPLATE-YAML-KEY-DUPLICATE",
                    path,
                    f"YAML key {key!r} appears more than once",
                )
        for kind, path in (
            ("adr", "docs/templates/adr.md"),
            ("pull-request", ".github/PULL_REQUEST_TEMPLATE.md"),
        ):
            text = self._read_text(path)
            if text is None:
                continue
            try:
                validate_workflow_template(kind, text)
            except GovernanceValidationError as error:
                for diagnostic in error.diagnostics:
                    self._add(
                        diagnostic.code,
                        f"{path}#{diagnostic.location}",
                        diagnostic.message,
                    )

    def _check_capability_security(self) -> None:
        bundled = self.root / "src/unrest_harness/bundled"
        loaded_assets: dict[
            str,
            CapabilityPolicy | CapabilitySecurityModel | CapabilitySinkCatalog,
        ] = {}
        asset_specs = (
            (
                CAPABILITY_ROLE_POLICY_PATH,
                CAPABILITY_ROLE_POLICY_SCHEMA_PATH,
                load_capability_policy,
            ),
            (
                CAPABILITY_MODEL_PATH,
                CAPABILITY_MODEL_SCHEMA_PATH,
                load_capability_security_model,
            ),
            (
                CAPABILITY_SINKS_PATH,
                CAPABILITY_SINKS_SCHEMA_PATH,
                load_capability_sink_catalog,
            ),
        )
        for document_path, _, loader in asset_specs:
            try:
                loaded_assets[document_path] = loader(bundled)
            except CapabilityPolicyError:
                self._add(
                    "REPO-CAPABILITY-ASSET-INVALID",
                    document_path,
                    "version-1 capability asset is missing or invalid",
                )
        for document_path, schema_path, _ in asset_specs:
            document = self._load_json(document_path)
            schema = self._load_json(schema_path)
            if not isinstance(document, dict) or not isinstance(schema, dict):
                continue
            errors = sorted(
                Draft202012Validator(schema).iter_errors(document),
                key=lambda error: tuple(str(item) for item in error.absolute_path),
            )
            for error in errors:
                location = "/".join(str(item) for item in error.absolute_path)
                self._add(
                    "REPO-CAPABILITY-ASSET-SCHEMA",
                    f"{document_path}#{location}" if location else document_path,
                    "version-1 capability asset does not match its strict schema",
                )
        model = loaded_assets.get(CAPABILITY_MODEL_PATH)
        catalog = loaded_assets.get(CAPABILITY_SINKS_PATH)
        if not isinstance(model, CapabilitySecurityModel) or not isinstance(
            catalog,
            CapabilitySinkCatalog,
        ):
            return
        if model.sink_catalog != Path(CAPABILITY_SINKS_PATH).name:
            self._add(
                "REPO-CAPABILITY-SINK-CATALOG",
                CAPABILITY_MODEL_PATH,
                "security model does not bind the canonical sink catalog",
            )
        for error in validate_capability_model_anchors(self.root, model):
            field_name, _, reason = error.partition(": ")
            self._add(
                "REPO-CAPABILITY-MODEL-ANCHOR",
                f"{CAPABILITY_MODEL_PATH}#{field_name}",
                reason or "model implementation binding is invalid",
            )
        for error in validate_capability_sink_anchors(self.root, catalog):
            sink_id, _, reason = error.partition(": ")
            self._add(
                "REPO-CAPABILITY-SINK-CATALOG",
                f"{CAPABILITY_SINKS_PATH}#{sink_id}",
                reason or "sink implementation binding is invalid",
            )

    def _check_evidence_policy(self) -> None:
        policy = self._load_json(EVIDENCE_POLICY_PATH)
        normative = self._load_json(NORMATIVE_POLICY_PATH)
        if not isinstance(policy, dict) or not isinstance(normative, dict):
            return
        if set(policy) != {
            "canonical_template_fields",
            "commit_trailers",
            "non_passing_record",
            "positive_record",
            "schema_evolution_records",
            "schema_version",
        } or policy.get("schema_version") != 1:
            self._add(
                "REPO-EVIDENCE-CATALOG-SHAPE",
                EVIDENCE_POLICY_PATH,
                "catalog must match the version-1 protected-evidence contract",
            )
            return
        trailers = policy.get("commit_trailers")
        schema_records = policy.get("schema_evolution_records")
        positive = policy.get("positive_record")
        non_passing = policy.get("non_passing_record")
        fields = policy.get("canonical_template_fields")
        if (
            not isinstance(trailers, list)
            or [item.get("name") for item in trailers if isinstance(item, dict)]
            != ["Evaluation-Evidence", "Rollback-Plan", "Schema-Change"]
            or not isinstance(schema_records, list)
            or [item.get("id") for item in schema_records if isinstance(item, dict)]
            != ["compatibility", "migration", "recovery", "rollback"]
            or not isinstance(positive, dict)
            or set(positive.get("required_fields", []))
            != {
                "artifact_path",
                "artifact_sha256",
                "exact_check",
                "exit_code",
                "mode",
                "observed_result",
                "record_type",
                "schema_version",
                "status",
            }
            or not isinstance(non_passing, dict)
            or set(non_passing.get("allowed_record_types", []))
            != {"history", "limitation"}
            or not isinstance(fields, list)
        ):
            self._add(
                "REPO-EVIDENCE-CATALOG-SHAPE",
                EVIDENCE_POLICY_PATH,
                "protected locations or positive tuple are incomplete",
            )
            return
        declared_documents = {
            self._effective_normative_policy_id(entry): entry["path"]
            for entry in normative.get("documents", [])
            if isinstance(entry, dict)
            and isinstance(entry.get("id"), str)
            and isinstance(entry.get("path"), str)
        }
        for field in fields:
            if not isinstance(field, dict):
                continue
            document_id = field.get("document_id")
            path = field.get("path")
            if (
                not isinstance(document_id, str)
                or not isinstance(path, str)
                or declared_documents.get(document_id) != path
            ):
                self._add(
                    "REPO-EVIDENCE-CATALOG-LOCATION",
                    EVIDENCE_POLICY_PATH,
                    "canonical evidence field does not resolve through normative-documents.json",
                )
                continue
            document = next(
                (
                    item
                    for item in self._normative_documents
                    if item[0] == document_id and item[1] == path
                ),
                None,
            )
            if document is None:
                continue
            values: tuple[Any, ...] = ()
            if isinstance(field.get("field"), str) and isinstance(
                field.get("heading"), str
            ):
                expected_field = _logical_heading_text(field["field"])
                expected_heading = _logical_heading_text(field["heading"])
                values = tuple(
                    block.field_value
                    for block in parse_commonmark(document[3]).blocks
                    if block.field_name is not None
                    and block.field_value is not None
                    and _logical_heading_text(block.field_name) == expected_field
                    and block.heading_path
                    and _logical_heading_text(block.heading_path[-1].text)
                    == expected_heading
                )
            elif isinstance(field.get("yaml_path"), str):
                mappings, _duplicates = _markdown_yaml_mappings(document[3])
                path_parts = tuple(field["yaml_path"].split("."))
                values = tuple(
                    value
                    for mapping in mappings
                    for value in _mapping_values_at_path(mapping, path_parts)
                )
            if not values:
                self._add(
                    "REPO-EVIDENCE-FIELD-MISSING",
                    path,
                    f"cataloged evidence field {field.get('id')!r} is absent",
                )
                continue
            for value in values:
                if isinstance(value, str) and re.fullmatch(r"<[^<>]+>", value):
                    continue
                if not isinstance(value, str):
                    self._add(
                        "REPO-EVIDENCE-RECORD-INVALID",
                        path,
                        f"cataloged evidence field {field.get('id')!r} is not a record reference",
                    )
                    continue
                try:
                    validation = validate_evidence_record_reference(
                        value,
                        repository_root=self.root,
                        expected_mode=(
                            "rollback"
                            if field.get("id") == "closeout-rollback-verification"
                            else "evaluation"
                        ),
                    )
                except GovernanceValidationError as error:
                    for diagnostic in error.diagnostics:
                        self._add(
                            "REPO-EVIDENCE-RECORD-INVALID",
                            path,
                            f"{field.get('id')}: {diagnostic.code}",
                        )
                    continue
                if not validation.passing:
                    self._add(
                        "REPO-EVIDENCE-NONPASSING",
                        path,
                        f"cataloged evidence field {field.get('id')!r} is explicitly non-passing",
                    )

    def _check_protected_policy(self) -> None:
        if not (self.root / POLICY_PATH).is_file():
            self._add(
                "REPO-PROTECTED-POLICY-MISSING",
                POLICY_PATH,
                "protected-surface policy is absent",
            )
            return
        try:
            policy = load_protected_surface_policy(self.root / POLICY_PATH)
        except GovernanceValidationError as error:
            for diagnostic in error.diagnostics:
                diagnostic_base = (
                    COMPONENT_MAP_PATH
                    if diagnostic.code.startswith("GOV-COMPONENT-")
                    else POLICY_PATH
                )
                self._add(
                    diagnostic.code,
                    self._governance_location(
                        diagnostic_base,
                        diagnostic.location,
                    ),
                    diagnostic.message,
                )
            return
        try:
            components = load_component_paths(self.root / COMPONENT_MAP_PATH)
            validate_policy_components(policy, components)
        except GovernanceValidationError as error:
            for diagnostic in error.diagnostics:
                diagnostic_base = (
                    COMPONENT_MAP_PATH
                    if diagnostic.code.startswith("GOV-COMPONENT-")
                    else POLICY_PATH
                )
                self._add(
                    diagnostic.code,
                    self._governance_location(
                        diagnostic_base,
                        diagnostic.location,
                    ),
                    diagnostic.message,
                )
        else:
            candidate_paths = {
                path.relative_to(self.root).as_posix()
                for patterns in components.values()
                for pattern in patterns
                for path in self._matching_paths(pattern)
                if path.is_file()
            }
            candidate_paths.update(
                selector.value
                for surface in policy.protected_surfaces
                for selector in surface.selectors
                if selector.kind == "path"
            )
            for candidate in self._ordered(candidate_paths):
                try:
                    resolve_path_category(policy, components, candidate)
                except GovernanceValidationError as error:
                    for diagnostic in error.diagnostics:
                        self._add(
                            diagnostic.code,
                            f"{COMPONENT_MAP_PATH}#{diagnostic.location}",
                            diagnostic.message,
                        )
        self._record_global_id(policy.policy_id, POLICY_PATH)

    def _governance_location(self, base: str, location: str) -> str:
        candidate = Path(location)
        if candidate.is_absolute():
            try:
                relative = candidate.resolve().relative_to(self.root).as_posix()
            except ValueError:
                relative = "<external>"
            return base if relative == base else f"{base}#{relative}"
        return f"{base}#{location}"

    def _check_schemas(self) -> None:
        schema_root = self.root / "schemas"
        paths = [
            path
            for path in schema_root.rglob("*.schema.json")
            if path.is_file()
        ]
        if not paths:
            self._add(
                "REPO-SCHEMA-MISSING",
                "schemas",
                "at least one checked-in JSON Schema is required",
            )
            return
        for path in sorted(paths, reverse=self.reverse):
            relative = path.relative_to(self.root).as_posix()
            schema = self._load_json(relative)
            if not isinstance(schema, dict):
                self._add(
                    "REPO-SCHEMA-TYPE",
                    relative,
                    "JSON Schema must be an object",
                )
                continue
            metaschema = schema.get("$schema")
            validator = (
                SUPPORTED_METASCHEMAS.get(metaschema)
                if isinstance(metaschema, str)
                else None
            )
            if validator is None:
                self._add(
                    "REPO-SCHEMA-METASCHEMA-UNSUPPORTED",
                    relative,
                    f"unsupported or missing $schema {metaschema!r}",
                )
                continue
            try:
                validator.check_schema(schema)
            except SchemaError as error:
                location = "/".join(str(part) for part in error.absolute_path) or "<root>"
                self._add(
                    "REPO-SCHEMA-INVALID",
                    f"{relative}#{location}",
                    error.message,
                )

    @staticmethod
    def _canonicalize(value: Any) -> Any:
        if isinstance(value, dict):
            return {
                key: _RepositoryValidator._canonicalize(value[key])
                for key in sorted(value)
            }
        if isinstance(value, list):
            normalized = [_RepositoryValidator._canonicalize(item) for item in value]
            if all(isinstance(item, dict) and "id" in item for item in normalized):
                return sorted(normalized, key=lambda item: str(item["id"]))
            if all(isinstance(item, dict) and "kind" in item for item in normalized):
                return sorted(normalized, key=lambda item: str(item["kind"]))
            if all(isinstance(item, (str, int)) for item in normalized):
                return sorted(normalized, key=str)
            return normalized
        return value

    @classmethod
    def _canonical_json(cls, value: Any) -> str:
        return json.dumps(cls._canonicalize(value), indent=2, sort_keys=True) + "\n"

    def _check_generated_outputs(self) -> None:
        for relative in CANONICAL_JSON_PATHS:
            value = self._load_json(relative)
            text = self._read_text(relative)
            if value is None or text is None:
                continue
            expected = self._canonical_json(value)
            if (
                relative == NORMATIVE_POLICY_PATH
                and isinstance(value, dict)
                and isinstance(value.get("documents"), list)
                and self._normative_role_aliases
            ):
                normalized = self._canonicalize(value)
                assert isinstance(normalized, dict)
                normalized["documents"] = sorted(
                    (
                        self._canonicalize(entry)
                        for entry in value["documents"]
                    ),
                    key=lambda entry: str(
                        self._effective_normative_policy_id(entry)
                        if isinstance(entry, dict)
                        else entry
                    ),
                )
                expected = json.dumps(normalized, indent=2, sort_keys=True) + "\n"
            if text != expected:
                self._add(
                    "REPO-CANONICAL-JSON-DRIFT",
                    relative,
                    "file is not canonical sorted UTF-8 JSON",
                )
        policy_schema = self._read_text(POLICY_SCHEMA_PATH)
        if policy_schema is not None and policy_schema != render_policy_json_schema():
            self._add(
                "REPO-GENERATED-SCHEMA-DRIFT",
                POLICY_SCHEMA_PATH,
                "checked-in schema differs from the strict model",
            )
        with tempfile.TemporaryDirectory(prefix="unrest-repository-contract-") as raw:
            temporary = Path(raw)
            forward = temporary / "forward"
            reverse = temporary / "reverse"
            generate_baseline(forward, input_order="forward")
            generate_baseline(reverse, input_order="reverse")
            for name in GENERATED_FILENAMES:
                forward_path = forward / name
                reverse_path = reverse / name
                checked_in = self.root / BASELINE_PATH / name
                relative = f"{BASELINE_PATH}/{name}"
                if forward_path.read_bytes() != reverse_path.read_bytes():
                    self._add(
                        "REPO-GENERATED-NONDETERMINISTIC",
                        relative,
                        "forward and reverse producer enumeration differ",
                    )
                if not checked_in.is_file():
                    self._add(
                        "REPO-GENERATED-OUTPUT-MISSING",
                        relative,
                        "checked-in generated output is absent",
                    )
                elif checked_in.read_bytes() != forward_path.read_bytes():
                    self._add(
                        "REPO-GENERATED-OUTPUT-DRIFT",
                        relative,
                        "checked-in generated output differs from fresh generation",
                    )
            output_root = self.root / BASELINE_PATH
            if output_root.is_dir():
                actual = {
                    path.relative_to(output_root).as_posix()
                    for path in output_root.rglob("*")
                    if path.is_file()
                }
                for name in self._ordered(actual - set(GENERATED_FILENAMES)):
                    self._add(
                        "REPO-GENERATED-OUTPUT-UNDECLARED",
                        f"{BASELINE_PATH}/{name}",
                        "generated directory contains an undeclared file",
                    )

    def _declared_python_versions(self) -> tuple[str, ...] | None:
        text = self._read_text("pyproject.toml")
        if text is None:
            return None
        try:
            pyproject = tomllib.loads(text)
        except tomllib.TOMLDecodeError as error:
            self._add(
                "REPO-CI-PYPROJECT-INVALID",
                "pyproject.toml",
                str(error),
            )
            return None
        project = pyproject.get("project") if isinstance(pyproject, dict) else None
        classifiers = project.get("classifiers") if isinstance(project, dict) else None
        if not isinstance(classifiers, list):
            self._add(
                "REPO-CI-SUPPORTED-VERSIONS-MISSING",
                "pyproject.toml#project.classifiers",
                "supported Python version classifiers are absent",
            )
            return None
        versions = tuple(
            match.group(1)
            for classifier in classifiers
            if isinstance(classifier, str)
            and (
                match := re.fullmatch(
                    r"Programming Language :: Python :: ([0-9]+\.[0-9]+)",
                    classifier,
                )
            )
            is not None
        )
        expected_order = tuple(
            sorted(set(versions), key=lambda value: tuple(map(int, value.split("."))))
        )
        if not versions or versions != expected_order:
            self._add(
                "REPO-CI-SUPPORTED-VERSIONS-INVALID",
                "pyproject.toml#project.classifiers",
                "supported Python version classifiers must be sorted and unique",
            )
            return None
        return versions

    def _check_ci(self) -> None:
        text = self._read_text(CI_PATH)
        if text is None:
            return
        declared_versions = self._declared_python_versions()
        try:
            workflow = yaml.load(text, Loader=yaml.BaseLoader)
        except yaml.YAMLError as error:
            self._add("REPO-CI-YAML-INVALID", CI_PATH, str(error))
            return
        if not isinstance(workflow, dict) or not isinstance(workflow.get("jobs"), dict):
            self._add("REPO-CI-JOBS-MISSING", CI_PATH, "workflow jobs mapping is absent")
            return
        jobs = workflow["jobs"]
        covered_versions: set[str] = set()
        full_suite_locations: list[str] = []
        workflow_test_runs: list[str] = []
        primary_jobs = 0
        compatibility_jobs = 0
        for job_id, job in jobs.items():
            if not isinstance(job, dict):
                continue
            steps = job.get("steps")
            if not isinstance(steps, list):
                continue
            location = f"{CI_PATH}#jobs.{job_id}"
            for index, step in enumerate(steps):
                if not isinstance(step, dict) or not isinstance(step.get("run"), str):
                    continue
                full_suite_locations.extend(
                    f"{location}.steps.{index}"
                    for arguments in _ci_pytest_invocations(step["run"])
                    if _ci_is_full_source_suite(arguments)
                )
            workflow_test_runs.extend(
                step["run"].strip()
                for step in steps
                if isinstance(step, dict)
                and isinstance(step.get("run"), str)
                and "test" in _ci_python_surface_kinds(step)
            )
            setup_versions: list[str] = []
            matrix = None
            dimension = None
            for step in steps:
                if not isinstance(step, dict) or not isinstance(step.get("uses"), str):
                    continue
                if not step["uses"].startswith("astral-sh/setup-uv@"):
                    continue
                with_values = step.get("with")
                version = (
                    with_values.get("python-version")
                    if isinstance(with_values, dict)
                    else None
                )
                if not isinstance(version, str):
                    continue
                references = re.findall(r"\bmatrix\.([A-Za-z0-9_-]+)\b", version)
                if references:
                    strategy = job.get("strategy")
                    matrix = strategy.get("matrix") if isinstance(strategy, dict) else None
                    if not isinstance(matrix, dict) or len(references) != 1:
                        self._add(
                            "REPO-CI-MATRIX-INVALID",
                            location,
                            "setup-uv Python matrix reference must resolve to one static dimension",
                        )
                        continue
                    dimension = references[0]
                    effective = _effective_matrix_versions(matrix, dimension)
                    if effective is None:
                        self._add(
                            "REPO-CI-MATRIX-INVALID",
                            location,
                            "Python matrix dimensions, include, and exclude must be explicit lists",
                        )
                        continue
                    setup_versions.extend(effective)
                else:
                    setup_versions.append(version)

            if not setup_versions:
                continue
            versions = tuple(sorted(set(setup_versions)))
            if declared_versions is not None and not set(versions) <= set(declared_versions):
                self._add(
                    "REPO-CI-PYTHON-VERSIONS-MISMATCH",
                    location,
                    "Python job versions must be drawn from declared support: "
                    + ", ".join(declared_versions),
                )
            covered_versions.update(
                version
                for version in versions
                if declared_versions is not None and version in declared_versions
            )
            surface_steps = [
                (index, step, kinds)
                for index, step in enumerate(steps)
                if isinstance(step, dict)
                and (kinds := _ci_python_surface_kinds(step))
            ]

            if not _ci_condition_is_always(job.get("if")):
                self._add(
                    "REPO-CI-JOB-CONDITIONAL",
                    location,
                    "Python test/build job must run unconditionally",
                )
            if not _ci_continue_on_error_is_disabled(job.get("continue-on-error")):
                self._add(
                    "REPO-CI-JOB-CONTINUE-ON-ERROR",
                    location,
                    "Python test/build job failures must remain enforcing",
                )
            needs = _ci_needs(job)
            if needs is None:
                self._add(
                    "REPO-CI-NEEDS-INVALID",
                    location,
                    "Python test/build job needs must be a job ID or list of job IDs",
                )
            elif any(
                not _ci_job_is_guaranteed_reachable(dependency, jobs)
                for dependency in needs
            ):
                self._add(
                    "REPO-CI-NEEDS-UNREACHABLE",
                    location,
                    "Python test/build job is blocked by a missing, conditional, "
                    "soft-failed, failing, or unreachable dependency",
                )

            runs = [
                step.get("run", "").strip()
                for step in steps
                if isinstance(step, dict) and isinstance(step.get("run"), str)
            ]
            full_indexes = [
                index
                for index, step in enumerate(steps)
                if isinstance(step, dict)
                and isinstance(step.get("run"), str)
                and step["run"].strip() == FULL_SOURCE_SUITE_COMMAND
            ]
            named_contract_steps = [
                step
                for step in steps
                if isinstance(step, dict) and step.get("name") == "Repository contract"
            ]
            exact_indexes = [
                index
                for index, step in enumerate(steps)
                if isinstance(step, dict)
                and isinstance(step.get("run"), str)
                and step["run"].strip() == CANONICAL_COMMAND
            ]
            for _index, step, kinds in surface_steps:
                if not _ci_condition_is_always(step.get("if")):
                    for kind in sorted(kinds):
                        self._add(
                            "REPO-CI-PYTHON-STEP-CONDITIONAL",
                            location,
                            f"Python {kind} step must run unconditionally",
                        )
                if not _ci_continue_on_error_is_disabled(
                    step.get("continue-on-error")
                ):
                    for kind in sorted(kinds):
                        self._add(
                            "REPO-CI-PYTHON-STEP-CONTINUE-ON-ERROR",
                            location,
                            f"Python {kind} step failures must remain enforcing",
                        )
            if len(exact_indexes) != 1:
                code = (
                    "REPO-CI-COMMAND-SUBSTITUTED"
                    if named_contract_steps
                    or any("check-repository" in command for command in runs)
                    else "REPO-CI-COMMAND-MISSING"
                )
                self._add(
                    code,
                    location,
                    f"expected exactly one {CANONICAL_COMMAND!r} step",
                )
                continue
            contract_step = steps[exact_indexes[0]]
            if (
                isinstance(contract_step, dict)
                and not _ci_condition_is_always(contract_step.get("if"))
            ):
                self._add(
                    "REPO-CI-COMMAND-CONDITIONAL",
                    location,
                    "repository contract step must run in every effective matrix lane",
                )
            if (
                isinstance(contract_step, dict)
                and not _ci_continue_on_error_is_disabled(
                    contract_step.get("continue-on-error")
                )
            ):
                self._add(
                    "REPO-CI-COMMAND-CONTINUE-ON-ERROR",
                    location,
                    "repository contract step failures must remain enforcing",
                )
            build_indexes = [
                index
                for index, _step, kinds in surface_steps
                if kinds & {"build", "publish"}
            ]
            test_indexes = [
                index
                for index, _step, kinds in surface_steps
                if "test" in kinds
            ]
            if build_indexes and exact_indexes[0] >= min(build_indexes):
                self._add(
                    "REPO-CI-COMMAND-ORDER",
                    location,
                    "repository contract must run before build, package, or publish",
                )
            installed_check_steps = [
                (index, step)
                for index, step in enumerate(steps)
                if isinstance(step, dict)
                and isinstance(step.get("run"), str)
                and "-m unrest_harness.installed_wheel_check" in step["run"]
            ]

            if declared_versions is None:
                continue
            primary_version = declared_versions[-1]
            compatibility_versions = declared_versions[:-1]
            if versions == compatibility_versions:
                compatibility_jobs += 1
                if dimension is None or not isinstance(matrix, dict):
                    self._add(
                        "REPO-CI-COMPATIBILITY-MATRIX-MISSING",
                        location,
                        "compatibility checks must use one explicit Python matrix",
                    )
                elif tuple(matrix.get(dimension, ())) != compatibility_versions:
                    self._add(
                        "REPO-CI-PYTHON-VERSIONS-MISMATCH",
                        location,
                        "compatibility matrix must exactly cover "
                        + ", ".join(compatibility_versions),
                    )
                required_commands = {
                    COMPATIBILITY_IMPORT_COMMAND,
                    COMPATIBILITY_TEST_COMMAND,
                    "uv run unrest --help\nuv run unrest-server --help\nuv run python -m unrest_harness --help",
                }
                missing = sorted(required_commands - set(runs))
                if missing:
                    self._add(
                        "REPO-CI-COMPATIBILITY-CHECK-MISSING",
                        location,
                        "compatibility lanes must run import, focused contract, and CLI checks",
                    )
                if full_indexes or build_indexes or installed_check_steps:
                    self._add(
                        "REPO-CI-COMPATIBILITY-TOO-BROAD",
                        location,
                        "compatibility lanes cannot run the full suite, build, or wheel lifecycle",
                    )
            elif versions == (primary_version,):
                primary_jobs += 1
                if len(full_indexes) != 1:
                    self._add(
                        "REPO-CI-FULL-SUITE-MISSING",
                        location,
                        f"Python {primary_version} must run exactly one full source suite",
                    )
                else:
                    full_step = steps[full_indexes[0]]
                    if isinstance(full_step, dict) and not _ci_condition_is_always(
                        full_step.get("if")
                    ):
                        self._add(
                            "REPO-CI-PYTHON-STEP-CONDITIONAL",
                            location,
                            "Python test step must run unconditionally",
                        )
                    if isinstance(full_step, dict) and not _ci_continue_on_error_is_disabled(
                        full_step.get("continue-on-error")
                    ):
                        self._add(
                            "REPO-CI-PYTHON-STEP-CONTINUE-ON-ERROR",
                            location,
                            "Python test step failures must remain enforcing",
                        )
                if len(build_indexes) != 1:
                    self._add(
                        "REPO-CI-BUILD-COUNT",
                        location,
                        "primary job must build exactly once",
                    )
                if len(installed_check_steps) != 1:
                    self._add(
                        "REPO-CI-INSTALLED-MISSION-MISSING",
                        location,
                        "expected exactly one installed-wheel lifecycle mission",
                    )
                else:
                    check_index, check_step = installed_check_steps[0]
                    if build_indexes and check_index <= max(build_indexes):
                        self._add(
                            "REPO-CI-INSTALLED-MISSION-ORDER",
                            location,
                            "installed-wheel lifecycle mission must run after build",
                        )
                    if not _ci_condition_is_always(check_step.get("if")):
                        self._add(
                            "REPO-CI-INSTALLED-MISSION-CONDITIONAL",
                            location,
                            "installed-wheel lifecycle mission must run unconditionally",
                        )
                    if not _ci_continue_on_error_is_disabled(
                        check_step.get("continue-on-error")
                    ):
                        self._add(
                            "REPO-CI-INSTALLED-MISSION-CONTINUE-ON-ERROR",
                            location,
                            "installed-wheel lifecycle mission failures must remain enforcing",
                        )
                distribution_indexes = [
                    index
                    for index, step in enumerate(steps)
                    if isinstance(step, dict)
                    and isinstance(step.get("run"), str)
                    and step["run"].strip() == DISTRIBUTION_CHECK_COMMAND
                ]
                if len(distribution_indexes) != 1:
                    self._add(
                        "REPO-CI-DISTRIBUTION-CHECK-MISSING",
                        location,
                        "primary job must run exactly one focused distribution archive check",
                    )
                elif build_indexes and distribution_indexes[0] <= max(build_indexes):
                    self._add(
                        "REPO-CI-DISTRIBUTION-CHECK-ORDER",
                        location,
                        "distribution archive check must run after build",
                    )
                post_build_tests = [
                    index
                    for index in test_indexes
                    if build_indexes and index > max(build_indexes)
                ]
                if post_build_tests:
                    self._add(
                        "REPO-CI-POST-BUILD-PYTEST",
                        location,
                        "post-build verification must use focused archive and installed-wheel checks",
                    )
            else:
                self._add(
                    "REPO-CI-TIER-INVALID",
                    location,
                    "Python jobs must be the exact compatibility matrix or sole primary lane",
                )

        if compatibility_jobs != 1:
            self._add(
                "REPO-CI-COMPATIBILITY-MATRIX-MISSING",
                CI_PATH,
                "expected exactly one Python 3.11/3.12 compatibility matrix",
            )
        if primary_jobs != 1:
            self._add(
                "REPO-CI-PRIMARY-JOB-MISSING",
                CI_PATH,
                "expected exactly one Python 3.13 primary job",
            )
        if len(full_suite_locations) != 1:
            self._add(
                "REPO-CI-FULL-SUITE-COUNT",
                CI_PATH,
                "workflow must contain exactly one full source-suite invocation",
            )
        if sorted(workflow_test_runs) != sorted(
            (COMPATIBILITY_TEST_COMMAND, FULL_SOURCE_SUITE_COMMAND)
        ):
            self._add(
                "REPO-CI-TEST-SURFACES-INVALID",
                CI_PATH,
                "workflow must contain only the fixed compatibility tests and "
                "one full source-suite invocation",
            )
        if (
            declared_versions is not None
            and covered_versions != set(declared_versions)
        ):
            self._add(
                "REPO-CI-PYTHON-COVERAGE-MISSING",
                CI_PATH,
                "effective workflow Python coverage must exactly match declared support: "
                + ", ".join(declared_versions),
            )

    def _check_global_id_uniqueness(self) -> None:
        for record_id, paths in sorted(self._global_ids.items()):
            if len(paths) > 1:
                self._add(
                    "REPO-GLOBAL-ID-CANONICAL-CONFLICT",
                    ID_REGISTRY_PATH,
                    f"{record_id} has canonical sources {','.join(sorted(paths))}",
                )


def find_repository_root(start: Path) -> Path:
    """Return the Git toplevel for ``start`` without changing repository state."""
    process = subprocess.run(
        ["git", "-C", str(start), "rev-parse", "--show-toplevel"],
        check=False,
        capture_output=True,
        text=True,
    )
    if process.returncode != 0:
        raise RepositoryContractError(
            [
                RepositoryDiagnostic(
                    "REPO-GIT-ROOT-UNAVAILABLE",
                    ".",
                    f"git rev-parse failed with exit code {process.returncode}",
                )
            ]
        )
    return Path(process.stdout.strip())


def check_repository(
    root: Path,
    *,
    enumeration_order: EnumerationOrder = "forward",
) -> RepositoryContractReport:
    """Validate the repository without writing beneath ``root``."""
    if enumeration_order not in {"forward", "reverse"}:
        raise ValueError(f"unsupported enumeration order {enumeration_order!r}")
    return _RepositoryValidator(root, enumeration_order=enumeration_order).run()
