"""Executable source-distribution restart-oracle regressions."""

from __future__ import annotations

import copy
import importlib.util
import io
import os
from pathlib import Path, PurePosixPath
import shutil
import subprocess
import sys
import tarfile

import pytest


ROOT = Path(__file__).resolve().parents[1]
CHECKER_SPEC = importlib.util.spec_from_file_location(
    "check_distribution", ROOT / "tools/check_distribution.py"
)
assert CHECKER_SPEC is not None and CHECKER_SPEC.loader is not None
checker = importlib.util.module_from_spec(CHECKER_SPEC)
CHECKER_SPEC.loader.exec_module(checker)


@pytest.fixture(scope="module")
def built_distribution(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """Build the candidate archives once in test-owned temporary storage."""
    dist = tmp_path_factory.mktemp("sdist-executable-proof") / "dist"
    environment = os.environ.copy()
    environment.pop("PYTHONPATH", None)
    environment.pop("CODEX_PATH", None)
    environment.setdefault("UV_CACHE_DIR", "/tmp/unrest-worker-uv-cache")
    result = subprocess.run(
        ["uv", "build", "--out-dir", str(dist)],
        cwd=ROOT,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    return dist


def _run_checker(dist: Path, *, environment: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "tools/check_distribution.py", str(dist)],
        cwd=ROOT,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
        timeout=180,
    )


def _rewrite_sdist(source: Path, target: Path, member_path: str, *, omit: bool) -> None:
    with tarfile.open(source, "r:gz") as archive, tarfile.open(target, "w:gz") as rewritten:
        for member in archive.getmembers():
            relative = PurePosixPath(member.name)
            matches = len(relative.parts) > 1 and PurePosixPath(*relative.parts[1:]).as_posix() == member_path
            if matches and omit:
                continue
            replacement = copy.copy(member)
            if matches and member.isfile():
                extracted = archive.extractfile(member)
                assert extracted is not None
                payload = extracted.read() + b"\nmutation"
                replacement.size = len(payload)
                rewritten.addfile(replacement, io.BytesIO(payload))
            elif member.isfile():
                extracted = archive.extractfile(member)
                assert extracted is not None
                rewritten.addfile(replacement, extracted)
            else:
                rewritten.addfile(replacement)


def _mutated_distribution(
    tmp_path: Path, built_distribution: Path, member: str, *, omit: bool
) -> Path:
    target = tmp_path / ("omitted" if omit else "changed")
    target.mkdir()
    wheel = next(built_distribution.glob("*.whl"))
    sdist = next(built_distribution.glob("*.tar.gz"))
    shutil.copy2(wheel, target / wheel.name)
    _rewrite_sdist(sdist, target / sdist.name, member, omit=omit)
    return target


def test_checker_builds_and_executes_14_cases_with_extracted_provenance(
    built_distribution: Path,
) -> None:
    environment = os.environ.copy()
    environment["PYTHONPATH"] = str(ROOT / "src")
    result = _run_checker(built_distribution, environment=environment)

    assert result.returncode == 0, result.stdout + result.stderr
    assert "extracted restart oracle" in result.stdout
    assert "'cases': 14" in result.stdout
    assert str(ROOT.resolve()) not in result.stdout


@pytest.mark.parametrize("member", sorted(checker.SDIST_RESTART_ORACLE_FILES))
@pytest.mark.parametrize("omit", (True, False), ids=("omitted", "changed"))
def test_checker_rejects_each_missing_or_changed_oracle_member(
    tmp_path: Path,
    built_distribution: Path,
    member: str,
    omit: bool,
) -> None:
    dist = _mutated_distribution(tmp_path, built_distribution, member, omit=omit)
    result = _run_checker(dist)

    assert result.returncode != 0
    diagnostic = result.stdout + result.stderr
    assert "sdist restart oracle inventory mismatch" in diagnostic
    category = "missing" if omit else "changed"
    other = "changed" if omit else "missing"
    assert f"{category}=['{member}']" in diagnostic
    assert f"{other}=[]" in diagnostic


def test_extracted_oracle_cannot_borrow_an_omitted_fixture(
    tmp_path: Path, built_distribution: Path
) -> None:
    extracted = checker._extract_sdist_safely(next(built_distribution.glob("*.tar.gz")), tmp_path)
    (extracted / "tests/fixtures/persistence_schema_v1/corpus.json").unlink()

    with pytest.raises(RuntimeError, match="extracted sdist restart oracle failed"):
        checker._run_extracted_restart_oracle(extracted, checkout_root=ROOT)


def test_extracted_oracle_cannot_import_from_forced_checkout_path(
    tmp_path: Path,
    built_distribution: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    extracted = checker._extract_sdist_safely(next(built_distribution.glob("*.tar.gz")), tmp_path)
    shutil.move(extracted / "src/unrest_harness", extracted / "removed-unrest-harness")
    monkeypatch.setenv("PYTHONPATH", str(ROOT / "src"))

    with pytest.raises(RuntimeError, match="extracted sdist restart oracle failed"):
        checker._run_extracted_restart_oracle(extracted, checkout_root=ROOT)


def test_safe_extraction_rejects_traversal_member(tmp_path: Path) -> None:
    archive_path = tmp_path / "unsafe.tar.gz"
    with tarfile.open(archive_path, "w:gz") as archive:
        member = tarfile.TarInfo("package/../outside")
        member.size = 1
        archive.addfile(member, io.BytesIO(b"x"))

    with pytest.raises(RuntimeError, match="unsafe member"):
        checker._extract_sdist_safely(archive_path, tmp_path / "extract")
