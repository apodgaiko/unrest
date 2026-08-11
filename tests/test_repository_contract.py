"""Focused tests for the finite Lean repository checker."""

from __future__ import annotations

import ast
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

import pytest
from click.testing import CliRunner

from unrest_harness.cli import cli
from unrest_harness.repository_contract import (
    RepositoryContractError,
    check_repository,
)


ROOT = Path(__file__).resolve().parents[1]
REMOVED_MODULES = (
    "unrest_harness.baseline",
    "unrest_harness.governance",
    "unrest_harness.repository_contract",
)


def _copy_repository(tmp_path: Path) -> Path:
    target = tmp_path / "repository"
    shutil.copytree(
        ROOT,
        target,
        ignore=shutil.ignore_patterns(
            ".git",
            ".mypy_cache",
            ".pytest_cache",
            ".ruff_cache",
            ".validation",
            ".venv",
            "dist",
            "validator-regressions",
            "__pycache__",
        ),
    )
    return target


@pytest.fixture(scope="module")
def repository_copy(tmp_path_factory: pytest.TempPathFactory) -> Path:
    return _copy_repository(tmp_path_factory.mktemp("repository-contract"))


def _write_json(path: Path, value: object) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _error(root: Path) -> RepositoryContractError:
    with pytest.raises(RepositoryContractError) as caught:
        check_repository(root)
    return caught.value


def _run_repository_cli(root: Path) -> subprocess.CompletedProcess[str]:
    subprocess.run(["git", "init", "--quiet"], cwd=root, check=True)
    environment = os.environ.copy()
    environment["PYTHONPATH"] = str(root / "src")
    return subprocess.run(
        [str(Path(sys.executable).with_name("unrest")), "check-repository"],
        cwd=root,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )


def test_current_repository_passes_deterministically_without_writes() -> None:
    before = subprocess.run(
        ["git", "status", "--short"], cwd=ROOT, check=True, capture_output=True, text=True
    ).stdout
    forward = check_repository(ROOT, enumeration_order="forward").render()
    reverse = check_repository(ROOT, enumeration_order="reverse").render()
    after = subprocess.run(
        ["git", "status", "--short"], cwd=ROOT, check=True, capture_output=True, text=True
    ).stdout
    assert forward == reverse
    assert forward.startswith("Lean repository contract passed")
    assert before == after


def test_component_ownership_is_complete() -> None:
    report = check_repository(ROOT)
    component_map = json.loads(
        (ROOT / "docs/architecture/component-map.json").read_text(encoding="utf-8")
    )
    assert report.checked_components == len(component_map["components"])


@pytest.mark.parametrize(
    ("family", "code", "locator"),
    (
        ("required", "LEAN-REPO-MISSING", "README.md"),
        ("reference", "LEAN-REPO-REFERENCE", "missing-reference.md"),
        ("component", "LEAN-REPO-COMPONENT", "COMP-ACP"),
        (
            "policy-version",
            "LEAN-REPO-POLICY",
            "src/unrest_harness/bundled/policies/role-capabilities.v1.json",
        ),
        (
            "policy-credentials",
            "LEAN-REPO-POLICY",
            "src/unrest_harness/bundled/policies/role-capabilities.v1.json",
        ),
        (
            "policy-wildcard",
            "LEAN-REPO-POLICY",
            "src/unrest_harness/bundled/policies/role-capabilities.v1.json",
        ),
        (
            "policy-duplicate",
            "LEAN-REPO-POLICY",
            "src/unrest_harness/bundled/policies/role-capabilities.v1.json",
        ),
        ("ci", "LEAN-REPO-CI", ".github/workflows/ci.yml"),
    ),
)
def test_each_rule_family_emits_its_bounded_code(
    repository_copy: Path, family: str, code: str, locator: str
) -> None:
    repository = repository_copy
    mutated_path = repository / (
        "README.md"
        if family in {"required", "reference"}
        else "docs/architecture/component-map.json"
        if family == "component"
        else locator
    )
    original = mutated_path.read_bytes()
    try:
        if family == "required":
            mutated_path.unlink()
        elif family == "reference":
            mutated_path.write_text(
                mutated_path.read_text(encoding="utf-8")
                + "\n[missing](missing-reference.md)\n",
                encoding="utf-8",
            )
        elif family == "component":
            document = json.loads(mutated_path.read_text(encoding="utf-8"))
            component = next(
                item for item in document["components"] if item["id"] == "COMP-ACP"
            )
            component["paths"].append("src/unrest_harness/not-present.py")
            _write_json(mutated_path, document)
        elif family.startswith("policy-"):
            if family == "policy-duplicate":
                mutated_path.write_text(
                    mutated_path.read_text(encoding="utf-8").replace(
                        '"safe": {', '"safe": {},\n    "safe": {', 1
                    ),
                    encoding="utf-8",
                )
            else:
                document = json.loads(mutated_path.read_text(encoding="utf-8"))
                if family == "policy-version":
                    document["schema_version"] = 2
                elif family == "policy-credentials":
                    document["profiles"]["safe"]["worker"]["environment"][
                        "credentials"
                    ] = ["*"]
                else:
                    document["profiles"]["unsafe-development-unrestricted"]["worker"][
                        "environment"
                    ]["forward"] = ["PATH"]
                _write_json(mutated_path, document)
        else:
            mutated_path.write_text(
                mutated_path.read_text(encoding="utf-8").replace(
                    "uv run mypy src", "uv run mypy package"
                ),
                encoding="utf-8",
            )

        error = _error(repository)
        assert any(item.code == code and item.path == locator for item in error.diagnostics)
        assert all(item.code.startswith("LEAN-REPO-") for item in error.diagnostics)
        assert all("\n" not in item.path and len(item.path) < 180 for item in error.diagnostics)
    finally:
        mutated_path.write_bytes(original)


@pytest.mark.parametrize(
    ("family", "old", "new"),
    (
        ("python-3.11", '["3.11", "3.12"]', '["3.10", "3.12"]'),
        ("python-3.12", '["3.11", "3.12"]', '["3.11", "3.10"]'),
        ("python-3.13", 'python-version: "3.13"', 'python-version: "3.10"'),
        (
            "package-import",
            'run: uv run python -c "import unrest_harness; from unrest_harness.config import HarnessConfig; HarnessConfig.discover()"',
            'run: uv run python -c "print(\'import unrest_harness\')"',
        ),
        ("unrest-help", "uv run unrest --help", "uv run unrest help"),
        (
            "server-help",
            "uv run unrest-server --help",
            "uv run unrest-server --version",
        ),
        (
            "module-help",
            "uv run python -m unrest_harness --help",
            "uv run python -m unrest_harness --version",
        ),
        (
            "repository-check",
            "run: uv run unrest check-repository",
            "run: uv run python -c \"print('uv run unrest check-repository')\"",
        ),
        ("ruff", "run: uv run ruff check .", "run: uv run ruff check src"),
        ("mypy", "run: uv run mypy src", "run: uv run mypy tests"),
        (
            "source-suite",
            "run: env -u CODEX_PATH uv run pytest -q",
            "run: env -u CODEX_PATH uv run pytest -q tests/test_assets.py",
        ),
        ("build", "run: uv build", "run: uv build --wheel"),
        (
            "distribution-check",
            "run: uv run python tools/check_distribution.py dist",
            "run: uv run python tools/check_distribution.py other-dist",
        ),
        (
            "wheel-environment",
            "uv venv --clear .wheel-venv",
            "uv venv --clear .other-venv",
        ),
        (
            "wheel-install",
            "uv pip install --python .wheel-venv/bin/python dist/*.whl",
            "uv pip install --python .wheel-venv/bin/python dist/*.tar.gz",
        ),
        ("unrelated-cwd", 'cd "$(mktemp -d)"', "cd /tmp"),
        (
            "installed-lifecycle",
            "-m unrest_harness.installed_wheel_check",
            "-m unrest_harness --help",
        ),
    ),
)
def test_ci_required_executable_and_lane_families_are_candidate_bound(
    tmp_path: Path, family: str, old: str, new: str
) -> None:
    repository = _copy_repository(tmp_path)
    path = repository / ".github/workflows/ci.yml"
    text = path.read_text(encoding="utf-8")
    assert old in text, f"candidate no longer contains the {family} binding"
    path.write_text(text.replace(old, new), encoding="utf-8")

    error = _error(repository)
    assert [(item.code, item.path) for item in error.diagnostics] == [
        ("LEAN-REPO-CI", ".github/workflows/ci.yml")
    ]


@pytest.mark.parametrize(
    "replacement",
    (
        "        # uv run mypy src\n"
        "        run: uv run python -c \"print('mypy omitted')\"",
        "        env:\n"
        "          REQUIRED_COMMAND: uv run mypy src\n"
        "        run: uv run python -c \"print('mypy omitted')\"",
        "        run: echo uv run mypy src",
        "        run: printf '%s\\n' 'uv run mypy src'",
        "        run: uv run python -c \"print('uv run mypy src')\"",
        "        if: ${{ false }}\n        run: uv run mypy src",
        "        continue-on-error: true\n        run: uv run mypy src",
    ),
)
def test_ci_text_spoofs_and_disabled_commands_do_not_satisfy_duty(
    tmp_path: Path, replacement: str
) -> None:
    repository = _copy_repository(tmp_path)
    path = repository / ".github/workflows/ci.yml"
    text = path.read_text(encoding="utf-8")
    target = "        run: uv run mypy src"
    assert text.count(target) == 1
    path.write_text(text.replace(target, replacement), encoding="utf-8")

    error = _error(repository)
    assert [(item.code, item.path) for item in error.diagnostics] == [
        ("LEAN-REPO-CI", ".github/workflows/ci.yml")
    ]


@pytest.mark.parametrize(
    "condition",
    (
        "${{ false && true }}",
        "${{ !true }}",
        "${{ !(false || true) }}",
        "${{ (true && false) || false }}",
        "false || (false && true)",
    ),
)
@pytest.mark.parametrize("control", ("step", "job"))
def test_ci_constant_dead_guards_fail_through_candidate_cli(
    tmp_path: Path, condition: str, control: str
) -> None:
    repository = _copy_repository(tmp_path)
    path = repository / ".github/workflows/ci.yml"
    text = path.read_text(encoding="utf-8")
    if control == "step":
        old = "      - name: Type-check (mypy)\n        run: uv run mypy src"
        new = f"      - name: Type-check (mypy)\n        if: {condition}\n        run: uv run mypy src"
    else:
        old = "  primary:\n    name: primary source and package gate (py3.13)"
        new = f"  primary:\n    if: {condition}\n    name: primary source and package gate (py3.13)"
    assert text.count(old) == 1
    path.write_text(text.replace(old, new), encoding="utf-8")

    result = _run_repository_cli(repository)

    assert result.returncode == 1
    assert "LEAN-REPO-CI .github/workflows/ci.yml" in result.stderr


@pytest.mark.parametrize(
    "replacement",
    (
        "        run: |\n"
        "          if false; then\n"
        "            uv run mypy src\n"
        "          fi",
        "        run: |\n"
        "          if   false ; then\n"
        "            uv run mypy src\n"
        "          fi",
        "        run: if false; then uv run mypy src; fi",
    ),
)
def test_ci_literal_dead_shell_branches_fail_through_candidate_cli(
    tmp_path: Path, replacement: str
) -> None:
    repository = _copy_repository(tmp_path)
    path = repository / ".github/workflows/ci.yml"
    text = path.read_text(encoding="utf-8")
    target = "        run: uv run mypy src"
    assert text.count(target) == 1
    path.write_text(text.replace(target, replacement), encoding="utf-8")

    result = _run_repository_cli(repository)

    assert result.returncode == 1
    assert "LEAN-REPO-CI .github/workflows/ci.yml" in result.stderr


@pytest.mark.parametrize(
    "condition",
    (
        "${{ true && !false }}",
        "${{ false || true }}",
        "${{ github.ref == 'refs/heads/main' }}",
        "${{ false && github.ref }}",
    ),
)
def test_ci_live_or_dynamic_guards_remain_accepted_through_candidate_cli(
    tmp_path: Path, condition: str
) -> None:
    repository = _copy_repository(tmp_path)
    path = repository / ".github/workflows/ci.yml"
    text = path.read_text(encoding="utf-8")
    old = "      - name: Type-check (mypy)\n        run: uv run mypy src"
    new = f"      - name: Type-check (mypy)\n        if: {condition}\n        run: uv run mypy src"
    assert text.count(old) == 1
    path.write_text(text.replace(old, new), encoding="utf-8")

    result = _run_repository_cli(repository)

    assert result.returncode == 0, result.stdout + result.stderr
    assert result.stdout.startswith("Lean repository contract passed")


@pytest.mark.parametrize(
    "replacement",
    (
        "        run: |\n"
        "          if test -n \"$RUN_CHECKS\"; then\n"
        "            uv run mypy src\n"
        "          fi",
        "        run: |\n"
        "          if false; then\n"
        "            echo skipped\n"
        "          else\n"
        "            uv run mypy src\n"
        "          fi",
    ),
)
def test_ci_dynamic_or_alternate_shell_branches_remain_accepted(
    tmp_path: Path, replacement: str
) -> None:
    repository = _copy_repository(tmp_path)
    path = repository / ".github/workflows/ci.yml"
    text = path.read_text(encoding="utf-8")
    target = "        run: uv run mypy src"
    assert text.count(target) == 1
    path.write_text(text.replace(target, replacement), encoding="utf-8")

    result = _run_repository_cli(repository)

    assert result.returncode == 0, result.stdout + result.stderr
    assert result.stdout.startswith("Lean repository contract passed")


def test_ci_duty_allows_an_additional_compatibility_lane(tmp_path: Path) -> None:
    repository = _copy_repository(tmp_path)
    path = repository / ".github/workflows/ci.yml"
    text = path.read_text(encoding="utf-8")
    path.write_text(
        text.replace('["3.11", "3.12"]', '["3.11", "3.12", "3.13"]'),
        encoding="utf-8",
    )

    check_repository(repository)


def test_withdrawn_commands_are_unknown_and_absent_from_help() -> None:
    runner = CliRunner()
    help_result = runner.invoke(cli, ["--help"])
    assert help_result.exit_code == 0
    for command in ("check-governance", "check-commit"):
        assert command not in help_result.output
        result = runner.invoke(cli, [command])
        assert result.exit_code == 2
        assert f"No such command '{command}'" in result.output


def _import_probe(arguments: tuple[str, ...], blocked: tuple[str, ...]) -> dict[str, object]:
    script = r'''
import importlib.abc
import json
import sys

blocked = tuple(json.loads(sys.argv[1]))
arguments = json.loads(sys.argv[2])
class Trap(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path=None, target=None):
        if any(fullname == name or fullname.startswith(name + ".") for name in blocked):
            raise RuntimeError("TRAPPED_IMPORT:" + fullname)
        return None
sys.meta_path.insert(0, Trap())
error = None
try:
    from unrest_harness.cli import cli
    cli.main(args=arguments, prog_name="unrest", standalone_mode=False)
except BaseException as exc:
    error = f"{type(exc).__name__}:{exc}"
print(json.dumps({"error": error, "modules": sorted(sys.modules)}, sort_keys=True))
'''
    result = subprocess.run(
        [sys.executable, "-c", script, json.dumps(blocked), json.dumps(arguments)],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
        timeout=20,
    )
    return json.loads(result.stdout.splitlines()[-1])


@pytest.mark.parametrize(
    "arguments", (("--help",), ("init", "--help"), ("list-projects",))
)
def test_ordinary_cli_entrypoints_do_not_import_repository_modules(
    arguments: tuple[str, ...],
) -> None:
    observation = _import_probe(arguments, REMOVED_MODULES)
    assert observation["error"] is None


def test_repository_command_is_the_lazy_positive_control() -> None:
    observation = _import_probe(("check-repository",), ())
    assert observation["error"] is None
    assert "unrest_harness.repository_contract" in observation["modules"]


def test_mcp_help_does_not_import_repository_modules() -> None:
    script = r'''
import importlib.abc
import json
import runpy
import sys
blocked = tuple(json.loads(sys.argv[1]))
class Trap(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path=None, target=None):
        if any(fullname == name or fullname.startswith(name + ".") for name in blocked):
            raise RuntimeError("TRAPPED_IMPORT:" + fullname)
        return None
sys.meta_path.insert(0, Trap())
sys.argv = ["unrest-server", "--help"]
try:
    runpy.run_module("unrest_harness.server", run_name="__main__")
except SystemExit as exc:
    if exc.code not in (None, 0):
        raise
'''
    result = subprocess.run(
        [sys.executable, "-c", script, json.dumps(REMOVED_MODULES)],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
        timeout=20,
    )
    assert result.returncode == 0, result.stdout + result.stderr


def test_real_entrypoint_import_boundary() -> None:
    for arguments in (("--help",), ("init", "--help"), ("list-projects",)):
        assert _import_probe(arguments, REMOVED_MODULES)["error"] is None
    test_mcp_help_does_not_import_repository_modules()
    test_repository_command_is_the_lazy_positive_control()


def test_removed_repository_surfaces_have_no_maintained_source() -> None:
    forbidden_paths = (
        "src/unrest_harness/baseline.py",
        "src/unrest_harness/governance.py",
        "evals/baseline",
        "policy/protected-surfaces.yaml",
        "tests/test_baseline.py",
        "tests/test_governance.py",
    )
    assert not [path for path in forbidden_paths if (ROOT / path).exists()]
    cli_source = (ROOT / "src/unrest_harness/cli.py").read_text(encoding="utf-8")
    assert "check-governance" not in cli_source
    assert "check-commit" not in cli_source


def test_governance_responsibility_inventory_is_absent() -> None:
    test_removed_repository_surfaces_have_no_maintained_source()
    forbidden = (
        ROOT / "policy/protected-surfaces.yaml",
        ROOT / "docs/architecture/change-governance.md",
        ROOT / "tests/fixtures/governance",
    )
    assert not [path.relative_to(ROOT).as_posix() for path in forbidden if path.exists()]


def test_root_schemas_and_obsolete_direct_dependencies_are_absent() -> None:
    assert not (ROOT / "schemas").exists()
    project = (ROOT / "pyproject.toml").read_text(encoding="utf-8").lower()
    for dependency in ("jsonschema", "types-jsonschema", "markdown-it-py"):
        assert dependency not in project
    source_imports = []
    for path in sorted((*ROOT.glob("src/**/*.py"), *ROOT.glob("tests/**/*.py"))):
        if "tests/contracts" in path.as_posix():
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"))
        imported = {
            alias.name
            for node in ast.walk(tree)
            if isinstance(node, ast.Import)
            for alias in node.names
        }
        imported.update(
            node.module or "" for node in ast.walk(tree) if isinstance(node, ast.ImportFrom)
        )
        if any(name == "jsonschema" or name.startswith("jsonschema.") for name in imported):
            source_imports.append(path.relative_to(ROOT).as_posix())
        elif any(name == "markdown_it" or name.startswith("markdown_it.") for name in imported):
            source_imports.append(path.relative_to(ROOT).as_posix())
    assert source_imports == []


def test_root_raw_evidence_is_absent() -> None:
    assert not (ROOT / "evidence").exists()
