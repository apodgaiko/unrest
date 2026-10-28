"""Shared runner for the pre-change Lean Core contract manifests."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tarfile
import zipfile

import pytest


from tests.reference_outcomes import ReferenceOutcomes, ReferenceSelection


@dataclass(frozen=True)
class CandidateProcess:
    """One fresh process tied to the interpreter running the candidate tests."""

    returncode: int
    output: str


@dataclass(frozen=True)
class BuiltDistribution:
    """Actual archives and isolated interpreter built from this checkout."""

    directory: Path
    wheel: Path
    sdist: Path
    wheel_sha256: str
    sdist_sha256: str
    wheel_members: tuple[str, ...]
    sdist_members: tuple[str, ...]
    checker_output: str
    installed_python: Path
    installed_site: Path
    dependency_site: Path


_CREDENTIAL_NAME = re.compile(
    r"(?:API[_-]?KEY|TOKEN|PASSWORD|CREDENTIAL|PRIVATE[_-]?KEY|ACCESS[_-]?KEY)",
    re.IGNORECASE,
)


def run_candidate_process(
    arguments: tuple[str, ...],
    *,
    repository_root: Path,
    cwd: Path | None = None,
    env: dict[str, str] | None = None,
    timeout_seconds: float = 30,
) -> CandidateProcess:
    """Execute a fresh candidate Python process without credential-shaped input."""
    child_env = {
        key: value
        for key, value in os.environ.items()
        if not _CREDENTIAL_NAME.search(key)
    }
    child_env.pop("PYTHONPATH", None)
    if env:
        child_env.update(env)
    completed = subprocess.run(
        [sys.executable, *arguments],
        cwd=cwd or repository_root,
        env=child_env,
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        timeout=timeout_seconds,
    )
    return CandidateProcess(completed.returncode, completed.stdout)


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _run_checked(
    command: list[str],
    *,
    cwd: Path,
    env: dict[str, str],
    timeout_seconds: float = 60,
) -> str:
    completed = subprocess.run(
        command,
        cwd=cwd,
        env=env,
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        timeout=timeout_seconds,
    )
    if completed.returncode != 0:
        raise AssertionError(
            f"candidate command failed ({completed.returncode}): {' '.join(command)}\n"
            f"{completed.stdout}"
        )
    return completed.stdout


def pytest_configure(config: pytest.Config) -> None:
    config.pluginmanager.register(ReferenceOutcomes(), "contract-reference-outcomes")


@pytest.fixture(scope="module")
def lean_reference_run(request: pytest.FixtureRequest) -> ReferenceSelection:
    """Bind the complete manifest to actual source tests in this session."""
    nodes = frozenset(row[2] for row in request.module.SCENARIOS)
    assert nodes and any(not node.startswith("local::") for node in nodes)
    binder = request.config.pluginmanager.get_plugin("contract-reference-outcomes")
    return ReferenceSelection(nodes, binder)


@pytest.fixture(scope="session")
def repository_root() -> Path:
    return Path(__file__).resolve().parents[2]


@pytest.fixture(scope="session")
def built_distribution(
    tmp_path_factory: pytest.TempPathFactory,
    repository_root: Path,
) -> BuiltDistribution:
    """Build, validate, and install the exact checkout into temporary storage."""
    root = tmp_path_factory.mktemp("candidate-distribution")
    dist = root / "archives"
    dist.mkdir()
    uv = shutil.which("uv")
    if uv is None:
        raise AssertionError("uv executable is required for candidate archive proof")
    child_env = {
        key: value
        for key, value in os.environ.items()
        if not _CREDENTIAL_NAME.search(key)
    }
    child_env.pop("PYTHONPATH", None)
    child_env.setdefault("UV_CACHE_DIR", "/tmp/unrest-worker-uv-cache")
    child_env.setdefault("UV_OFFLINE", "1")
    _run_checked(
        [uv, "build", "--out-dir", str(dist)],
        cwd=repository_root,
        env=child_env,
    )
    checker_output = _run_checked(
        [sys.executable, "tools/check_distribution.py", str(dist)],
        cwd=repository_root,
        env=child_env,
    )
    wheels = tuple(sorted(dist.glob("*.whl")))
    sdists = tuple(sorted(dist.glob("*.tar.gz")))
    if len(wheels) != 1 or len(sdists) != 1:
        raise AssertionError(
            f"actual build produced wheel={wheels!r}, sdist={sdists!r}"
        )
    wheel = wheels[0]
    sdist = sdists[0]
    with zipfile.ZipFile(wheel) as archive:
        wheel_members = tuple(sorted(archive.namelist()))
    with tarfile.open(sdist, "r:gz") as archive:
        sdist_members = tuple(sorted(archive.getnames()))

    environment = root / "installed-site"
    _run_checked(
        [
            uv,
            "pip",
            "install",
            "--target",
            str(environment),
            "--no-deps",
            "--force-reinstall",
            str(wheel),
        ],
        cwd=root,
        env=child_env,
    )
    dependency_sites = tuple(
        Path(entry).resolve()
        for entry in sys.path
        if entry and Path(entry).name == "site-packages" and Path(entry).is_dir()
    )
    if len(dependency_sites) != 1:
        raise AssertionError(f"cannot isolate candidate dependency site: {dependency_sites}")
    dependency_site = dependency_sites[0]
    bootstrap = (
        "import sys; "
        f"sys.path[:0] = [{str(environment)!r}, {str(dependency_site)!r}]; "
    )
    provenance = _run_checked(
        [
            sys.executable,
            "-S",
            "-c",
            (
                bootstrap
                + "import json, pathlib, unrest_harness; "
                "print(json.dumps({'module': unrest_harness.__file__, "
                "'cwd': str(pathlib.Path.cwd())}, sort_keys=True))"
            ),
        ],
        cwd=root,
        env=child_env,
    )
    module_path = Path(json.loads(provenance)["module"]).resolve()
    if repository_root.resolve() in module_path.parents:
        raise AssertionError(f"installed import resolved to source checkout: {module_path}")
    if environment.resolve() not in module_path.parents:
        raise AssertionError(f"installed import escaped isolated environment: {module_path}")
    return BuiltDistribution(
        directory=root,
        wheel=wheel,
        sdist=sdist,
        wheel_sha256=_sha256(wheel),
        sdist_sha256=_sha256(sdist),
        wheel_members=wheel_members,
        sdist_members=sdist_members,
        checker_output=checker_output,
        installed_python=Path(sys.executable),
        installed_site=environment,
        dependency_site=dependency_site,
    )
