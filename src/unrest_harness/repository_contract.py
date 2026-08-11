"""Finite, read-only validation for the Lean Core source repository."""

from __future__ import annotations

import ast
from dataclasses import dataclass
import fnmatch
import json
import posixpath
from pathlib import Path, PurePosixPath
import re
import shlex
import subprocess
from typing import Any, Literal

import yaml

from .capability_policy import SAFE_PROFILE, load_capability_policy


EnumerationOrder = Literal["forward", "reverse"]

_REQUIRED_FILES = (
    ".github/workflows/ci.yml",
    "AGENTS.md",
    "README.md",
    "docs/architecture/component-map.json",
    "docs/architecture/index.md",
    "docs/decisions/index.md",
    "docs/v5/07-runtime-architecture.md",
    "docs/v5/08-mcp-surface.md",
    "pyproject.toml",
    "specs/memory_v2/PRODUCT.md",
    "specs/task_list/PRODUCT.md",
    "src/unrest_harness/bundled/policies/role-capabilities.v1.json",
    "uv.lock",
)
_REQUIRED_MARKDOWN = tuple(path for path in _REQUIRED_FILES if path.endswith(".md"))
_MARKDOWN_LINK = re.compile(r"(?<!!)\[[^\]]*\]\(([^)]+)\)")
_FRONTMATTER_PATH_FIELDS = frozenset({"applies_to", "verified_by"})
_DIAGNOSTIC_CODES = frozenset(
    {
        "LEAN-REPO-MISSING",
        "LEAN-REPO-REFERENCE",
        "LEAN-REPO-COMPONENT",
        "LEAN-REPO-POLICY",
        "LEAN-REPO-CI",
    }
)
_CONSTANT_EXPRESSION_TOKEN = re.compile(r"\s*(\&\&|\|\||[!()]|true\b|false\b)", re.I)
_DEAD_SHELL_IF = re.compile(r"^\s*if\s+false\s*;\s*then\s*(?:#.*)?$", re.I)
_SHELL_FI = re.compile(r"^\s*fi\s*(?:#.*)?$", re.I)
_INLINE_DEAD_SHELL_IF = re.compile(
    r"^\s*if\s+false\s*;\s*then(?:\s+.*?)?\s*;\s*fi\s*(?:#.*)?$", re.I
)


@dataclass(frozen=True, order=True)
class RepositoryDiagnostic:
    code: str
    path: str

    def render(self) -> str:
        return f"{self.code} {self.path}"


class RepositoryContractError(ValueError):
    """Raised with bounded, path-only Lean repository diagnostics."""

    def __init__(self, diagnostics: tuple[RepositoryDiagnostic, ...]) -> None:
        self.diagnostics = tuple(sorted(set(diagnostics)))
        super().__init__("\n".join(item.render() for item in self.diagnostics))


@dataclass(frozen=True)
class RepositoryContractReport:
    checked_files: int
    checked_references: int
    checked_components: int

    def render(self) -> str:
        return (
            "Lean repository contract passed "
            f"({self.checked_files} files, {self.checked_references} references, "
            f"{self.checked_components} components)\n"
        )


def _safe_relative_path(value: str) -> bool:
    path = PurePosixPath(value)
    return not path.is_absolute() and ".." not in path.parts and value not in {"", "."}


def _matches(root: Path, pattern: str) -> tuple[str, ...]:
    if not _safe_relative_path(pattern):
        return ()
    if not any(character in pattern for character in "*?["):
        return (pattern,) if (root / pattern).is_file() else ()
    return tuple(
        path.relative_to(root).as_posix()
        for path in sorted(root.glob(pattern))
        if path.is_file()
    )


def _frontmatter_paths(text: str) -> tuple[str, ...]:
    if not text.startswith("---\n"):
        return ()
    end = text.find("\n---\n", 4)
    if end < 0:
        return ()
    value = yaml.safe_load(text[4:end])
    if not isinstance(value, dict):
        return ()
    paths: list[str] = []
    for field in sorted(_FRONTMATTER_PATH_FIELDS):
        entries = value.get(field, ())
        if isinstance(entries, list):
            paths.extend(entry for entry in entries if isinstance(entry, str))
    return tuple(paths)


def _markdown_paths(path: str, text: str) -> tuple[str, ...]:
    references: list[str] = []
    parent = PurePosixPath(path).parent
    for match in _MARKDOWN_LINK.finditer(text):
        raw = match.group(1).strip().split(maxsplit=1)[0].strip("<>")
        if not raw or raw.startswith(("#", "http://", "https://", "mailto:")):
            continue
        target = raw.split("#", 1)[0]
        references.append(posixpath.normpath((parent / target).as_posix()))
    references.extend(_frontmatter_paths(text))
    return tuple(references)


def _load_json_object(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError("expected object")
    return value


def _check_components(
    root: Path, diagnostics: list[RepositoryDiagnostic]
) -> tuple[int, int]:
    component_path = "docs/architecture/component-map.json"
    try:
        document = _load_json_object(root / component_path)
        components = document["components"]
        if not isinstance(components, list):
            raise ValueError("components must be a list")
    except (OSError, UnicodeError, json.JSONDecodeError, KeyError, ValueError):
        diagnostics.append(RepositoryDiagnostic("LEAN-REPO-COMPONENT", component_path))
        return (0, 0)

    ids = tuple(
        item["id"]
        for item in components
        if isinstance(item, dict) and isinstance(item.get("id"), str)
    )
    if len(ids) != len(components) or ids != tuple(sorted(set(ids))):
        diagnostics.append(RepositoryDiagnostic("LEAN-REPO-COMPONENT", component_path))

    references = 0
    ownership_patterns: list[str] = []
    for item in components:
        if not isinstance(item, dict) or not isinstance(item.get("id"), str):
            continue
        component_id = item["id"]
        for field in ("paths", "specifications", "tests"):
            entries = item.get(field)
            if not isinstance(entries, list) or not all(
                isinstance(entry, str) for entry in entries
            ):
                diagnostics.append(
                    RepositoryDiagnostic("LEAN-REPO-COMPONENT", component_id)
                )
                continue
            for entry in entries:
                references += 1
                if not _matches(root, entry):
                    diagnostics.append(
                        RepositoryDiagnostic("LEAN-REPO-COMPONENT", component_id)
                    )
                if field == "paths":
                    ownership_patterns.append(entry)

    for source in sorted((root / "src/unrest_harness").rglob("*.py")):
        relative = source.relative_to(root).as_posix()
        if not any(fnmatch.fnmatchcase(relative, pattern) for pattern in ownership_patterns):
            diagnostics.append(RepositoryDiagnostic("LEAN-REPO-COMPONENT", relative))
    return (len(components), references)


def _check_policy(root: Path, diagnostics: list[RepositoryDiagnostic]) -> None:
    policy_path = "src/unrest_harness/bundled/policies/role-capabilities.v1.json"
    try:
        policy = load_capability_policy(root / "src/unrest_harness/bundled")
        for role_name in ("orchestrator", "worker", "validator", "terminal_reviewer"):
            safe_role = policy.role(SAFE_PROFILE, role_name)  # type: ignore[arg-type]
            unsafe_role = policy.role(  # type: ignore[arg-type]
                "unsafe-development-unrestricted", role_name
            )
            if not safe_role.environment.credentials or "*" in safe_role.environment.credentials:
                raise ValueError("safe known-credential inventory must be finite")
            if safe_role.environment.inherit_all:
                raise ValueError("safe profile may not inherit ambient environment")
            if unsafe_role.environment.inherit_all and unsafe_role.environment.forward != ("*",):
                raise ValueError("unsafe wildcard forwarding is malformed")
    except (OSError, UnicodeError, ValueError):
        diagnostics.append(RepositoryDiagnostic("LEAN-REPO-POLICY", policy_path))


class _ConstantExpressionParser:
    def __init__(self, tokens: tuple[str, ...]) -> None:
        self._tokens = tokens
        self._index = 0

    def parse(self) -> bool | None:
        value = self._parse_or()
        if value is None or self._index != len(self._tokens):
            return None
        return value

    def _take(self, token: str) -> bool:
        if self._index < len(self._tokens) and self._tokens[self._index] == token:
            self._index += 1
            return True
        return False

    def _parse_or(self) -> bool | None:
        value = self._parse_and()
        if value is None:
            return None
        while self._take("||"):
            right = self._parse_and()
            if right is None:
                return None
            value = value or right
        return value

    def _parse_and(self) -> bool | None:
        value = self._parse_unary()
        if value is None:
            return None
        while self._take("&&"):
            right = self._parse_unary()
            if right is None:
                return None
            value = value and right
        return value

    def _parse_unary(self) -> bool | None:
        if self._take("!"):
            value = self._parse_unary()
            return None if value is None else not value
        if self._take("("):
            value = self._parse_or()
            if value is None or not self._take(")"):
                return None
            return value
        if self._take("true"):
            return True
        if self._take("false"):
            return False
        return None


def _constant_boolean_expression(value: str) -> bool | None:
    expression = value.strip()
    if expression.startswith("${{") and expression.endswith("}}"):
        expression = expression[3:-2].strip()
    if not expression:
        return None
    tokens: list[str] = []
    position = 0
    while position < len(expression):
        match = _CONSTANT_EXPRESSION_TOKEN.match(expression, position)
        if match is None:
            return None
        tokens.append(match.group(1).lower())
        position = match.end()
    return _ConstantExpressionParser(tuple(tokens)).parse()


def _enabled_workflow_record(value: dict[str, Any]) -> bool:
    condition = value.get("if")
    if condition is False or (
        isinstance(condition, str) and _constant_boolean_expression(condition) is False
    ):
        return False
    continue_on_error = value.get("continue-on-error")
    return continue_on_error is not True and not (
        isinstance(continue_on_error, str)
        and continue_on_error.strip().lower() in {"true", "${{ true }}"}
    )


def _executable_shell_lines(run: str) -> tuple[str, ...]:
    lines = run.splitlines()
    dead_ranges: list[tuple[int, int]] = []
    start: int | None = None
    for index, line in enumerate(lines):
        if start is None and _DEAD_SHELL_IF.fullmatch(line):
            start = index
        elif start is not None and _SHELL_FI.fullmatch(line):
            dead_ranges.append((start, index))
            start = None
        elif start is not None and re.match(r"^\s*(?:if|elif|else)\b", line, re.I):
            return tuple(lines)
    if start is not None:
        return tuple(lines)
    return tuple(
        line
        for index, line in enumerate(lines)
        if not _INLINE_DEAD_SHELL_IF.fullmatch(line)
        and not any(first <= index <= last for first, last in dead_ranges)
    )


def _run_commands(job: dict[str, Any]) -> tuple[tuple[str, ...], ...]:
    if not _enabled_workflow_record(job):
        return ()
    steps = job.get("steps")
    if not isinstance(steps, list):
        return ()
    commands: list[tuple[str, ...]] = []
    for step in steps:
        if not isinstance(step, dict) or not _enabled_workflow_record(step):
            continue
        run = step.get("run")
        if not isinstance(run, str):
            continue
        for line in _executable_shell_lines(run):
            try:
                tokens = tuple(shlex.split(line, comments=True, posix=True))
            except ValueError:
                continue
            if tokens:
                commands.append(tokens)
    return tuple(commands)


def _uses_setup_python(step: dict[str, Any], version: str) -> bool:
    uses = step.get("uses")
    settings = step.get("with")
    return (
        isinstance(uses, str)
        and uses.startswith("astral-sh/setup-uv@")
        and isinstance(settings, dict)
        and str(settings.get("python-version")) == version
    )


def _has_setup_python(job: dict[str, Any], version: str) -> bool:
    steps = job.get("steps")
    return isinstance(steps, list) and any(
        isinstance(step, dict)
        and _enabled_workflow_record(step)
        and _uses_setup_python(step, version)
        for step in steps
    )


def _has_compatibility_lanes(job: dict[str, Any]) -> bool:
    strategy = job.get("strategy")
    matrix = strategy.get("matrix") if isinstance(strategy, dict) else None
    versions = matrix.get("python-version") if isinstance(matrix, dict) else None
    return (
        isinstance(versions, list)
        and {"3.11", "3.12"}.issubset(str(version) for version in versions)
        and _has_setup_python(job, "${{ matrix.python-version }}")
    )


def _has_exact_command(commands: tuple[tuple[str, ...], ...], expected: tuple[str, ...]) -> bool:
    return expected in commands


def _has_package_import(commands: tuple[tuple[str, ...], ...]) -> bool:
    for command in commands:
        if len(command) != 5 or command[:4] != ("uv", "run", "python", "-c"):
            continue
        try:
            tree = ast.parse(command[4])
        except SyntaxError:
            continue
        if any(
            (
                isinstance(node, ast.Import)
                and any(alias.name == "unrest_harness" for alias in node.names)
            )
            or (isinstance(node, ast.ImportFrom) and node.module == "unrest_harness")
            for node in ast.walk(tree)
        ):
            return True
    return False


def _without_env_prefix(command: tuple[str, ...]) -> tuple[str, ...]:
    if not command or command[0] != "env":
        return command
    index = 1
    while index < len(command):
        token = command[index]
        if token == "-u" and index + 1 < len(command):
            index += 2
        elif token.startswith("-") or ("=" in token and not token.startswith("/")):
            index += 1
        else:
            break
    return command[index:]


def _has_installed_lifecycle(commands: tuple[tuple[str, ...], ...]) -> bool:
    lifecycle = any(
        len(unwrapped := _without_env_prefix(command)) == 3
        and unwrapped[0].endswith("/python")
        and unwrapped[1:] == ("-m", "unrest_harness.installed_wheel_check")
        for command in commands
    )
    return all(
        (
            _has_exact_command(commands, ("uv", "venv", "--clear", ".wheel-venv")),
            _has_exact_command(
                commands,
                (
                    "uv",
                    "pip",
                    "install",
                    "--python",
                    ".wheel-venv/bin/python",
                    "dist/*.whl",
                ),
            ),
            _has_exact_command(commands, ("cd", "$(mktemp -d)")),
            lifecycle,
        )
    )


def _compatibility_job_is_complete(job: dict[str, Any]) -> bool:
    commands = _run_commands(job)
    required = (
        ("uv", "run", "unrest", "--help"),
        ("uv", "run", "unrest-server", "--help"),
        ("uv", "run", "python", "-m", "unrest_harness", "--help"),
        ("uv", "run", "unrest", "check-repository"),
    )
    return (
        _has_compatibility_lanes(job)
        and _has_package_import(commands)
        and all(_has_exact_command(commands, command) for command in required)
    )


def _primary_job_is_complete(job: dict[str, Any]) -> bool:
    commands = _run_commands(job)
    required = (
        ("uv", "run", "ruff", "check", "."),
        ("uv", "run", "mypy", "src"),
        ("env", "-u", "CODEX_PATH", "uv", "run", "pytest", "-q"),
        ("uv", "run", "unrest", "check-repository"),
        ("uv", "build"),
        ("uv", "run", "python", "tools/check_distribution.py", "dist"),
    )
    return (
        _has_setup_python(job, "3.13")
        and all(_has_exact_command(commands, command) for command in required)
        and _has_installed_lifecycle(commands)
    )


def _check_ci(root: Path, diagnostics: list[RepositoryDiagnostic]) -> None:
    ci_path = ".github/workflows/ci.yml"
    try:
        document = yaml.safe_load((root / ci_path).read_text(encoding="utf-8"))
        if not isinstance(document, dict):
            raise ValueError("workflow must be an object")
    except (OSError, UnicodeError, yaml.YAMLError, ValueError):
        diagnostics.append(RepositoryDiagnostic("LEAN-REPO-CI", ci_path))
        return

    jobs = document.get("jobs")
    if not isinstance(jobs, dict) or not all(
        isinstance(job_id, str) and isinstance(job, dict)
        for job_id, job in jobs.items()
    ):
        diagnostics.append(RepositoryDiagnostic("LEAN-REPO-CI", ci_path))
        return
    workflow_jobs = tuple(job for job in jobs.values() if isinstance(job, dict))
    if not any(_compatibility_job_is_complete(job) for job in workflow_jobs) or not any(
        _primary_job_is_complete(job) for job in workflow_jobs
    ):
        diagnostics.append(RepositoryDiagnostic("LEAN-REPO-CI", ci_path))


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
            (RepositoryDiagnostic("LEAN-REPO-MISSING", "."),)
        )
    return Path(process.stdout.strip())


def check_repository(
    root: Path,
    *,
    enumeration_order: EnumerationOrder = "forward",
) -> RepositoryContractReport:
    """Validate only the finite Lean repository catalog without writing files."""
    if enumeration_order not in {"forward", "reverse"}:
        raise ValueError(f"unsupported enumeration order {enumeration_order!r}")
    diagnostics: list[RepositoryDiagnostic] = []
    required = sorted(_REQUIRED_FILES, reverse=enumeration_order == "reverse")
    for relative in required:
        if not (root / relative).is_file():
            diagnostics.append(RepositoryDiagnostic("LEAN-REPO-MISSING", relative))

    reference_count = 0
    for relative in sorted(_REQUIRED_MARKDOWN, reverse=enumeration_order == "reverse"):
        path = root / relative
        if not path.is_file():
            continue
        try:
            references = _markdown_paths(relative, path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, yaml.YAMLError):
            diagnostics.append(RepositoryDiagnostic("LEAN-REPO-REFERENCE", relative))
            continue
        for reference in references:
            reference_count += 1
            if not _matches(root, reference):
                diagnostics.append(RepositoryDiagnostic("LEAN-REPO-REFERENCE", reference))

    component_count, component_references = _check_components(root, diagnostics)
    reference_count += component_references
    _check_policy(root, diagnostics)
    _check_ci(root, diagnostics)
    if diagnostics:
        assert all(item.code in _DIAGNOSTIC_CODES for item in diagnostics)
        raise RepositoryContractError(tuple(diagnostics))
    return RepositoryContractReport(
        checked_files=len(_REQUIRED_FILES),
        checked_references=reference_count,
        checked_components=component_count,
    )
