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
from itertools import product
from pathlib import Path, PurePosixPath
from typing import Any, Literal

import yaml
from jsonschema import Draft202012Validator
from jsonschema.exceptions import SchemaError

from .assets import parse_frontmatter
from .baseline import GENERATED_FILENAMES, generate_baseline
from .governance import (
    GovernanceValidationError,
    load_component_paths,
    load_protected_surface_policy,
    parse_commonmark,
    render_policy_json_schema,
    resolve_path_category,
    validate_policy_components,
    validate_workflow_template,
)

CANONICAL_COMMAND = "uv run unrest check-repository"
ARCHITECTURE_DIR = "docs/architecture"
ANNOTATION_POLICY_PATH = f"{ARCHITECTURE_DIR}/annotation-policy.json"
COMPONENT_MAP_PATH = f"{ARCHITECTURE_DIR}/component-map.json"
ID_REGISTRY_PATH = f"{ARCHITECTURE_DIR}/id-registry.json"
NORMATIVE_POLICY_PATH = f"{ARCHITECTURE_DIR}/normative-documents.json"
REMOVAL_REGISTRY_PATH = f"{ARCHITECTURE_DIR}/removal-registry.json"
POLICY_PATH = "policy/protected-surfaces.yaml"
POLICY_SCHEMA_PATH = "schemas/protected-surfaces.schema.json"
CI_PATH = ".github/workflows/ci.yml"
BASELINE_PATH = "evals/baseline"

CANONICAL_JSON_PATHS = (
    ANNOTATION_POLICY_PATH,
    COMPONENT_MAP_PATH,
    ID_REGISTRY_PATH,
    NORMATIVE_POLICY_PATH,
    REMOVAL_REGISTRY_PATH,
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
TEMPLATE_HEADINGS = {
    "TPL-ADR-001": (
        "## Record metadata",
        "## Scope",
        "## Context",
        "## Decision",
        "## Alternatives considered",
        "## Consequences",
        "## Protected-surface review",
        "## Rollback",
        "## Implementation and verification",
        "## References",
    ),
    "TPL-PLAN-001": (
        "## Plan identity",
        "## Objective and success criteria",
        "## Current behavior and evidence",
        "## Scope and non-goals",
        "## Surface and file map",
        "## Invariants, compatibility, and security",
        "## Dependency and execution order",
        "## Implementation steps",
        "## Rollback",
        "## Verification and evidence",
        "## Risks, decisions, and follow-ons",
    ),
    "TPL-TASK-001": (
        "## Task identity",
        "## Objective",
        "## Read first",
        "## Current behavior and evidence",
        "## Scope",
        "## Invariants and risks",
        "## Implementation requirements",
        "## Verification and evidence",
        "## Handoff requirements",
    ),
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
TEMPLATE_IDS = tuple(sorted((*TEMPLATE_HEADINGS, *TEMPLATE_YAML_FIELDS)))
SUPPORTED_METASCHEMAS = {
    "https://json-schema.org/draft/2020-12/schema": Draft202012Validator,
}
CHECK_FAMILIES = (
    "annotations",
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


def _markdown_headings(text: str) -> tuple[str, ...]:
    """Return operative ATX or setext headings from the CommonMark token stream."""

    return tuple(
        f"{'#' * heading.level} {heading.text}"
        for heading in parse_commonmark(text).top_level_headings
    )


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


_BANNED_CONTENT_FIELDS = {
    "agent_identity_labels",
    "attribution_context_terms",
    "hidden_reasoning_phrases",
    "hidden_reasoning_tags",
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
_PRIVATE_TAG_ROOTS = (
    "analysis",
    "monologue",
    "reason",
    "scratch",
    "thought",
    "think",
)


def _banned_content_categories(
    text: str,
    policy: dict[str, list[str]],
) -> tuple[str, ...]:
    """Classify rendered labels and structural reasoning tags without banning prose."""

    categories: list[str] = []
    surface = parse_commonmark(text)
    labels = policy["agent_identity_labels"]
    label_pattern = "|".join(
        re.escape(label)
        for label in sorted(labels, key=lambda value: (-len(value), value))
    )
    identity_re = re.compile(
        rf"^(?:{label_pattern})(?:[ \t]+says)?[ \t]*:",
        re.IGNORECASE,
    )
    attribution_re = re.compile(
        r"^(?P<label>[A-Za-z][A-Za-z0-9]*(?:[ \t]+"
        r"[A-Za-z][A-Za-z0-9]*){0,2})(?:[ \t]+says)?[ \t]*:"
        r"(?P<body>.*)$",
    )
    context_terms = tuple(
        re.sub(r"[-_\s]+", " ", term.casefold()).strip()
        for term in policy["attribution_context_terms"]
    )
    identity_found = False
    for line in surface.visible_lines:
        if label_pattern and identity_re.search(line):
            identity_found = True
            break
        match = attribution_re.match(line)
        if match is None:
            continue
        normalized_body = re.sub(
            r"[-_\s]+", " ", match.group("body").casefold()
        ).strip()
        if any(
            re.search(rf"\b{re.escape(term)}\b", normalized_body)
            for term in context_terms
            if term
        ):
            identity_found = True
            break
    if identity_found:
        categories.append("agent-identity")

    tags = policy["hidden_reasoning_tags"]
    configured = {tag.casefold() for tag in tags}
    html_tag_re = re.compile(
        r"</?[ \t]*(?P<tag>[a-z][a-z0-9_-]*)"
        r"(?:[ \t]+[^<>]*?)?[ \t]*/?>",
        re.IGNORECASE,
    )
    tag_tokens = (*surface.html_tokens, *surface.visible_lines)
    if any(
        (
            (normalized_tag := match.group("tag").casefold()) in configured
            or any(root in normalized_tag for root in _PRIVATE_TAG_ROOTS)
        )
        for token in tag_tokens
        for match in html_tag_re.finditer(token)
    ):
        categories.append("hidden-reasoning-tag")

    normalized_phrases = tuple(
        re.sub(r"[-_\s]+", " ", phrase.casefold()).strip()
        for phrase in policy["hidden_reasoning_phrases"]
    )
    normalized_lines = tuple(
        re.sub(r"[-_\s]+", " ", line.casefold()).strip()
        for line in surface.visible_lines
    )
    if any(
        line.startswith(f"{phrase}:") or line.startswith(f"{phrase} notes:")
        for phrase in normalized_phrases
        if phrase
        for line in normalized_lines
    ) or any(
        (
            match := attribution_re.match(line)
        ) is not None
        and any(
            root in re.sub(r"[-_\s]+", " ", match.group("label").casefold())
            for root in _PRIVATE_TAG_ROOTS
        )
        for line in surface.visible_lines
    ):
        categories.append("hidden-reasoning-phrase")
    return tuple(categories)


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
            while current and (
                current[0].startswith("-")
                or re.fullmatch(
                    r"[A-Za-z_][A-Za-z0-9_]*=.*",
                    current[0],
                )
            ):
                current = current[1:]
            continue
        break
    return current


def _command_has_sequence(command: tuple[str, ...], sequence: tuple[str, ...]) -> bool:
    return any(
        command[index : index + len(sequence)] == sequence
        for index in range(len(command) - len(sequence) + 1)
    )


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
        if (
            base in {"bash", "dash", "sh", "zsh"}
            and len(command) == 3
            and command[1] == "-c"
        ):
            kinds.update(_ci_python_surface_kinds({"run": command[2]}))
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
        self._accepted_decisions: set[str] = set()
        self._global_ids: dict[str, set[str]] = {}
        self._non_normative_baseline_ids: set[str] = set()
        self._non_normative_classifications: set[str] = set()

    def run(self) -> RepositoryContractReport:
        self._check_guidance()
        self._load_baseline_non_normative()
        self._load_accepted_decisions()
        self._check_normative_documents()
        self._check_stable_ids()
        self._check_annotations()
        self._check_component_map()
        self._check_templates()
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

    def _load_baseline_non_normative(self) -> None:
        text = self._read_text(f"{BASELINE_PATH}/manifest.yaml")
        if text is None:
            return
        try:
            manifest = yaml.safe_load(text)
        except yaml.YAMLError:
            return
        fixtures = manifest.get("fixtures") if isinstance(manifest, dict) else None
        if not isinstance(fixtures, list):
            return
        for fixture in fixtures:
            if not isinstance(fixture, dict):
                continue
            fixture_id = fixture.get("fixture_id")
            classification = fixture.get("classification")
            if (
                isinstance(fixture_id, str)
                and isinstance(classification, str)
                and classification != "intended"
            ):
                self._non_normative_baseline_ids.add(fixture_id)
                self._non_normative_classifications.add(classification)

    def _check_normative_baseline_claims(self, path: str, body: str) -> None:
        protected_tokens = (
            self._non_normative_baseline_ids | self._non_normative_classifications
        )
        safe_context = re.compile(
            r"\b(?:characterization|historical|non-normative)\b|"
            r"\b(?:does not|do not|is not|are not|not an?|never)\b|"
            r"\b(?:classified|retained only as)\b",
            re.IGNORECASE,
        )
        promotion_context = re.compile(
            r"\b(?:authoritative|canonical|governing|intended|normative|required)\b"
            r".{0,60}\b(?:behavior|contract|invariant|oracle|promise|rule|"
            r"semantics?|source of truth)\b|"
            r"\b(?:is|are|becomes?|defines?|represents?|serves as)\b.{0,60}"
            r"\b(?:authoritative|canonical|governing|intended|normative|required|"
            r"invariant|oracle)\b|"
            r"\b(?:must|should)\b.{0,40}\b(?:follow|match|preserve|reproduce|"
            r"retain)\b|"
            r"\b(?:not merely|not only|no longer|rather than)\b|"
            r"\b(?:but|however|instead|now)\b.{0,40}"
            r"\b(?:authoritative|behavior|canonical|invariant|normative|preserve)\b",
            re.IGNORECASE,
        )
        for block in parse_commonmark(body).visible_blocks:
            offsets = [
                offset
                for token in protected_tokens
                if (offset := block.find(token)) >= 0
            ]
            if not offsets:
                continue
            first_offset = min(offsets)
            clause_start = max(
                block.rfind(delimiter, 0, first_offset)
                for delimiter in (".", ";", "\n")
            )
            clause_ends = [
                offset
                for delimiter in (".", "\n")
                if (offset := block.find(delimiter, first_offset)) >= 0
            ]
            clause_end = min(clause_ends, default=len(block))
            relevant_block = block[clause_start + 1 : clause_end]
            explicitly_non_normative = safe_context.search(relevant_block) is not None
            promotion_text = re.sub(
                r"\b(?:is|are|was|were)\s+not\s+(?:an?\s+)?"
                r"(?:normative|canonical|intended|required|invariant)\b",
                "",
                re.sub(
                    r"\bnon-normative\b",
                    "",
                    relevant_block,
                    flags=re.IGNORECASE,
                ),
                flags=re.IGNORECASE,
            )
            promoted = promotion_context.search(promotion_text) is not None
            if promoted or not explicitly_non_normative:
                self._add(
                    "REPO-BASELINE-NONNORMATIVE-PROMOTED",
                    path,
                    "baseline defect/legacy classification is used without "
                    "an explicit non-normative characterization",
                )

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
        found: set[str] = set()
        for directory, dirnames, filenames in os.walk(self.root):
            relative = Path(directory).relative_to(self.root)
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
        declared_order: list[str] = [
            entry["id"]
            for entry in documents
            if isinstance(entry, dict) and isinstance(entry.get("id"), str)
        ]
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
            self._check_normative_baseline_claims(path, body)
            self._check_markdown_links(path, text)
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
            normalized = re.sub(r"[^\w\s-]", "", heading.text.casefold())
            base = re.sub(r"[\s-]+", "-", normalized).strip("-")
            count = counts.get(base, 0)
            counts[base] = count + 1
            anchors.add(base if count == 0 else f"{base}-{count}")
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
            if re.fullmatch(r"[A-Z][A-Z0-9]*(?:-[A-Z0-9]+)+", record_id) is None:
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
            if (
                record_id in self._non_normative_baseline_ids
                or any(
                    classification in statement
                    for classification in self._non_normative_classifications
                )
            ):
                self._add(
                    "REPO-BASELINE-NONNORMATIVE-ID",
                    location,
                    "baseline defect/legacy records cannot become stable invariants",
                )
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
        if (
            not isinstance(annotations, list)
            or not isinstance(banned_content, dict)
            or set(banned_content) != _BANNED_CONTENT_FIELDS
            or any(
                not isinstance(values, list)
                or not all(isinstance(value, str) and value.strip() for value in values)
                or values != sorted(set(values))
                for values in banned_content.values()
            )
        ):
            self._add(
                "REPO-ANNOTATION-POLICY-SHAPE",
                ANNOTATION_POLICY_PATH,
                "annotations and normalized banned-content categories are invalid",
            )
            return
        typed_banned_content = {
            field: values
            for field, values in banned_content.items()
            if isinstance(field, str) and isinstance(values, list)
        }
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
                for category in _banned_content_categories(
                    comment,
                    typed_banned_content,
                ):
                    self._add(
                        "REPO-ANNOTATION-BANNED-MARKER",
                        relative,
                        f"comment contains banned {category} content",
                    )
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
            for category in _banned_content_categories(
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
                if invariant in self._non_normative_baseline_ids:
                    self._add(
                        "REPO-COMPONENT-NONNORMATIVE-INVARIANT",
                        location,
                        f"baseline record {invariant!r} is non-normative",
                    )
                if invariant not in registered_ids:
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

    def _check_templates(self) -> None:
        policy = self._load_json(NORMATIVE_POLICY_PATH)
        if not isinstance(policy, dict) or not isinstance(policy.get("documents"), list):
            return
        entries = policy["documents"]
        for template_id in TEMPLATE_IDS:
            matching = [
                entry
                for entry in entries
                if isinstance(entry, dict) and entry.get("id") == template_id
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
            if template_id in TEMPLATE_HEADINGS:
                heading_counts = Counter(_markdown_headings(body))
                missing_fields = [
                    field
                    for field in TEMPLATE_HEADINGS[template_id]
                    if heading_counts[field] == 0
                ]
                duplicate_fields = [
                    field
                    for field in TEMPLATE_HEADINGS[template_id]
                    if heading_counts[field] > 1
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
                self._add(
                    diagnostic.code,
                    self._governance_location(POLICY_PATH, diagnostic.location),
                    diagnostic.message,
                )
            return
        try:
            components = load_component_paths(self.root / COMPONENT_MAP_PATH)
            validate_policy_components(policy, components)
        except GovernanceValidationError as error:
            for diagnostic in error.diagnostics:
                self._add(
                    diagnostic.code,
                    self._governance_location(POLICY_PATH, diagnostic.location),
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
            if text != self._canonical_json(value):
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
        python_jobs = 0
        python_matrix_jobs = 0
        covered_versions: set[str] = set()
        for job_id, job in jobs.items():
            if not isinstance(job, dict):
                continue
            steps = job.get("steps")
            if not isinstance(steps, list):
                continue
            surface_steps = [
                (index, step, kinds)
                for index, step in enumerate(steps)
                if isinstance(step, dict)
                and (kinds := _ci_python_surface_kinds(step))
            ]
            if not surface_steps:
                continue

            python_jobs += 1
            location = f"{CI_PATH}#jobs.{job_id}"
            strategy = job.get("strategy")
            matrix = strategy.get("matrix") if isinstance(strategy, dict) else None
            if isinstance(matrix, dict) and declared_versions is not None:
                dimensions = _python_matrix_dimensions(
                    matrix,
                    steps,
                    declared_versions,
                )
                if len(dimensions) != 1:
                    self._add(
                        "REPO-CI-PYTHON-DIMENSION-INVALID",
                        location,
                        "Python test/build matrices require exactly one explicit "
                        "Python-version dimension",
                    )
                else:
                    python_matrix_jobs += 1
                    dimension = dimensions[0]
                    versions = matrix.get(dimension)
                    if not isinstance(versions, list) or tuple(versions) != declared_versions:
                        self._add(
                            "REPO-CI-PYTHON-VERSIONS-MISMATCH",
                            location,
                            "Python matrix versions must exactly match declared support: "
                            + ", ".join(declared_versions),
                        )
                    effective_versions = _effective_matrix_versions(matrix, dimension)
                    if effective_versions is None:
                        self._add(
                            "REPO-CI-MATRIX-INVALID",
                            location,
                            "Python matrix dimensions, include, and exclude must "
                            "be explicit lists",
                        )
                    else:
                        covered_versions.update(
                            version
                            for version in effective_versions
                            if version in declared_versions
                        )
                        if set(effective_versions) != set(declared_versions):
                            self._add(
                                "REPO-CI-PYTHON-COVERAGE-MISSING",
                                location,
                                "effective Python matrix versions must exactly match "
                                "declared support: "
                                + ", ".join(declared_versions),
                            )
            elif matrix is not None:
                self._add(
                    "REPO-CI-MATRIX-INVALID",
                    location,
                    "Python matrix must be a static mapping",
                )

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
            if build_indexes and exact_indexes[0] >= min(build_indexes):
                self._add(
                    "REPO-CI-COMMAND-ORDER",
                    location,
                    "repository contract must run before build, package, or publish",
                )
        if python_jobs == 0 or python_matrix_jobs == 0:
            self._add(
                "REPO-CI-PYTHON-MATRIX-MISSING",
                CI_PATH,
                "no supported Python matrix lane was found",
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
