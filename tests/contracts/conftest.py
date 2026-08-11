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
import tempfile
import tarfile
import xml.etree.ElementTree as ET
import zipfile

import pytest


@dataclass(frozen=True)
class ReferenceRun:
    nodes: frozenset[str]
    returncode: int
    output: str


class ReferenceRunError(AssertionError):
    """The selected reference surface did not execute completely and cleanly."""


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


_SUMMARY_FAILURE = re.compile(
    r"\b(?:skipped|deselected|xfailed|xpassed|failed|errors?)\b",
    re.IGNORECASE,
)
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


def run_reference_nodes(
    nodes: tuple[str, ...],
    *,
    repository_root: Path,
    timeout_seconds: float = 120,
) -> ReferenceRun:
    """Run selected nodes and reject every incomplete pytest outcome.

    Pytest's process exit status is deliberately insufficient here: a selection
    containing only skips exits zero.  JUnit data supplies execution counts and
    per-node outcomes; the terminal summary supplies deselection detection.
    """
    if not nodes:
        raise ReferenceRunError("reference selection is empty")
    if any(re.search(r"(?:^|[_-])(smoke|live)(?:[_-]|$)", node) for node in nodes):
        raise ReferenceRunError("live-provider and smoke nodes are forbidden")

    child_env = {
        key: value
        for key, value in os.environ.items()
        if not _CREDENTIAL_NAME.search(key)
    }
    with tempfile.TemporaryDirectory(prefix="unrest-contract-run-") as raw_dir:
        report_path = Path(raw_dir) / "pytest.xml"
        command = [
            sys.executable,
            "-m",
            "pytest",
            "-q",
            "-ra",
            "-p",
            "no:cacheprovider",
            f"--junitxml={report_path}",
            *nodes,
        ]
        try:
            completed = subprocess.run(
                command,
                cwd=repository_root,
                env=child_env,
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                timeout=timeout_seconds,
            )
        except subprocess.TimeoutExpired as exc:
            raise ReferenceRunError(
                f"reference selection timed out after {timeout_seconds:g}s"
            ) from exc

        output = completed.stdout
        if not report_path.is_file():
            raise ReferenceRunError(
                f"pytest produced no execution report (exit {completed.returncode})\n{output}"
            )
        try:
            root = ET.parse(report_path).getroot()
        except ET.ParseError as exc:
            raise ReferenceRunError("pytest execution report is malformed") from exc

        cases = root.findall(".//testcase")
        skipped = root.findall(".//skipped")
        failures = root.findall(".//failure")
        errors = root.findall(".//error")
        if not cases:
            raise ReferenceRunError(f"pytest executed zero tests\n{output}")
        if skipped:
            raise ReferenceRunError(f"pytest skipped {len(skipped)} selected tests\n{output}")
        if failures or errors or completed.returncode != 0:
            raise ReferenceRunError(
                "pytest selection failed "
                f"(exit {completed.returncode}, failures={len(failures)}, "
                f"errors={len(errors)})\n{output}"
            )
        if _SUMMARY_FAILURE.search(output):
            raise ReferenceRunError(f"pytest selection was incomplete\n{output}")

    return ReferenceRun(frozenset(nodes), completed.returncode, output)


@pytest.fixture(scope="session", autouse=True)
def _runner_integrity_regressions(tmp_path_factory: pytest.TempPathFactory) -> None:
    """Every aggregate fake-pass route is rejected in the current process."""
    probe_dir = tmp_path_factory.mktemp("runner-regressions")
    probe = probe_dir / "test_runner_outcomes.py"
    probe.write_text(
        "import os\n"
        "import time\n"
        "import pytest\n\n"
        "def test_passes():\n"
        "    assert 'CONTRACT_TEST_API_KEY' not in os.environ\n\n"
        "def test_skips():\n"
        "    pytest.skip('synthetic missing setup')\n\n"
        "def test_fails():\n"
        "    raise AssertionError('synthetic failure')\n\n"
        "def test_waits():\n"
        "    time.sleep(1)\n",
        encoding="utf-8",
    )
    with pytest.raises(ReferenceRunError, match="skipped 1 selected tests"):
        run_reference_nodes(
            (f"{probe}::test_skips",),
            repository_root=probe_dir,
            timeout_seconds=10,
        )
    with pytest.raises(ReferenceRunError, match="reference selection is empty"):
        run_reference_nodes((), repository_root=probe_dir)
    with pytest.raises(ReferenceRunError, match="live-provider and smoke"):
        run_reference_nodes(("test_live_provider",), repository_root=probe_dir)
    with pytest.raises(ReferenceRunError, match="executed zero tests|incomplete"):
        run_reference_nodes(
            (f"{probe}::test_passes", "-k", "not test_passes"),
            repository_root=probe_dir,
        )
    with pytest.raises(ReferenceRunError, match="failed"):
        run_reference_nodes(
            (f"{probe}::test_fails",),
            repository_root=probe_dir,
        )
    with pytest.raises(ReferenceRunError, match="timed out"):
        run_reference_nodes(
            (f"{probe}::test_waits",),
            repository_root=probe_dir,
            timeout_seconds=0.05,
        )
    credential_name = "CONTRACT_TEST_API_KEY"
    previous = os.environ.get(credential_name)
    os.environ[credential_name] = "runner-probe-value"
    try:
        clean = run_reference_nodes(
            (f"{probe}::test_passes",),
            repository_root=probe_dir,
        )
    finally:
        if previous is None:
            os.environ.pop(credential_name, None)
        else:
            os.environ[credential_name] = previous
    assert clean.returncode == 0


@pytest.fixture(scope="module")
def lean_reference_run(request: pytest.FixtureRequest) -> ReferenceRun:
    """Run the manifest's reference nodes once, without cache or live providers."""
    scenarios = request.module.SCENARIOS
    nodes = tuple(dict.fromkeys(scenario[2] for scenario in scenarios))
    external_nodes = tuple(node for node in nodes if not node.startswith("local::"))
    assert nodes, "Lean contract manifest must not have an empty scenario family"
    assert all("test_smoke_" not in node for node in nodes), (
        "Lean contract manifests must not require live-provider smoke tests"
    )

    repository_root = Path(__file__).resolve().parents[2]
    assert external_nodes, "manifest must select at least one executable reference node"
    executed = run_reference_nodes(
        external_nodes,
        repository_root=repository_root,
    )
    return ReferenceRun(frozenset(nodes), executed.returncode, executed.output)


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
