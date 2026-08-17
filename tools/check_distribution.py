"""Verify wheel/sdist package membership, metadata, and content hashes."""
from __future__ import annotations

import argparse
import base64
import csv
import hashlib
import io
import json
import os
import re
import subprocess
import sys
import tarfile
import tempfile
import tomllib
import zipfile
from pathlib import Path, PurePosixPath

PACKAGE = "unrest_harness"
CONSOLE_SCRIPTS = {
    "unrest": "unrest_harness.cli:cli",
    "unrest-server": "unrest_harness.server:main",
}
SDIST_RESTART_ORACLE_FILES = frozenset(
    {
        "tests/test_persistence_schema_v1.py",
        "tests/fixtures/persistence_schema_v1/corpus.json",
        "tests/fixtures/persistence_schema_v1/manifest.json",
        "tests/fixtures/persistence_schema_v1/generation-transcript.json",
        "tests/fixtures/persistence_schema_v1/legacy-work-handoff.json",
        "tests/fixtures/persistence_schema_v1/legacy-validation-handoff.json",
        "tools/generate_legacy_handoff_fixtures.py",
    }
)
_PROVENANCE_PREFIX = "SDIST_RESTART_PROVENANCE="
_RESTART_TEST = "tests/test_persistence_schema_v1.py"
_PYTEST_PROBE = r'''
import json
import pathlib
import sys

checkout = pathlib.Path(sys.argv[1]).resolve()
import pytest
import pydantic
import unrest_harness
from unrest_harness import config, controller, dispatcher, models

sys.path[:] = [
    entry for entry in sys.path
    if checkout not in pathlib.Path(entry or ".").resolve().parents
    and pathlib.Path(entry or ".").resolve() != checkout
]

class ProvenancePlugin:
    def pytest_sessionfinish(self, session, exitstatus):
        test_files = sorted({str(pathlib.Path(item.path).resolve()) for item in session.items})
        print("SDIST_RESTART_PROVENANCE=" + json.dumps({
            "cwd": str(pathlib.Path.cwd().resolve()),
            "module": str(pathlib.Path(unrest_harness.__file__).resolve()),
            "source_path": str(next(
                pathlib.Path(entry or ".").resolve()
                for entry in sys.path
                if pathlib.Path(entry or ".").resolve() == pathlib.Path.cwd().resolve() / "src"
            )),
            "sys_path": [str(pathlib.Path(entry or ".").resolve()) for entry in sys.path],
            "test_files": test_files,
            "nodeids": [item.nodeid for item in session.items],
        }, sort_keys=True))

raise SystemExit(pytest.main(["-q", "tests/test_persistence_schema_v1.py"], plugins=[ProvenancePlugin()]))
'''


def _source_package(root: Path) -> dict[str, bytes]:
    package_root = root / "src" / PACKAGE
    files: dict[str, bytes] = {}
    for path in sorted(package_root.rglob("*")):
        relative = path.relative_to(package_root)
        if not path.is_file() or "__pycache__" in relative.parts or path.suffix == ".pyc":
            continue
        if relative.parts == ("AGENTS.md",):
            continue
        files[f"{PACKAGE}/{relative.as_posix()}"] = path.read_bytes()
    return files


def _safe_members(names: list[str], *, archive: str) -> None:
    if len(names) != len(set(names)):
        raise RuntimeError(f"{archive} contains duplicate members")
    for name in names:
        path = PurePosixPath(name)
        if path.is_absolute() or ".." in path.parts:
            raise RuntimeError(f"{archive} contains unsafe member {name!r}")


def _wheel_payload(path: Path) -> tuple[dict[str, bytes], str, str, str]:
    with zipfile.ZipFile(path) as archive:
        names = archive.namelist()
        _safe_members(names, archive=path.name)
        package = {
            name: archive.read(name)
            for name in names
            if name.startswith(f"{PACKAGE}/") and not name.endswith("/")
        }
        metadata_names = [name for name in names if name.endswith(".dist-info/METADATA")]
        entry_names = [name for name in names if name.endswith(".dist-info/entry_points.txt")]
        record_names = [name for name in names if name.endswith(".dist-info/RECORD")]
        if len(metadata_names) != 1 or len(entry_names) != 1 or len(record_names) != 1:
            raise RuntimeError("wheel must contain one METADATA, entry_points.txt, and RECORD")
        metadata = archive.read(metadata_names[0]).decode("utf-8")
        entry_points = archive.read(entry_names[0]).decode("utf-8")
        record = archive.read(record_names[0]).decode("utf-8")
        for name, digest, size in csv.reader(io.StringIO(record)):
            if name == record_names[0]:
                if digest or size:
                    raise RuntimeError("wheel RECORD must leave its own digest and size empty")
                continue
            payload = archive.read(name)
            expected = "sha256=" + base64.urlsafe_b64encode(
                hashlib.sha256(payload).digest()
            ).rstrip(b"=").decode("ascii")
            if digest != expected or size != str(len(payload)):
                raise RuntimeError(f"wheel RECORD mismatch for {name}")
    return package, metadata, entry_points, record


def _sdist_payload(path: Path) -> tuple[dict[str, bytes], dict[str, bytes]]:
    with tarfile.open(path, "r:gz") as archive:
        members = archive.getmembers()
        names = [member.name for member in members]
        _safe_members(names, archive=path.name)
        roots = {PurePosixPath(name).parts[0] for name in names if name}
        if len(roots) != 1:
            raise RuntimeError("sdist must contain exactly one top-level directory")
        root = next(iter(roots))
        prefix = f"{root}/src/{PACKAGE}/"
        package: dict[str, bytes] = {}
        source_files: dict[str, bytes] = {}
        for member in members:
            if not member.isfile():
                continue
            extracted = archive.extractfile(member)
            if extracted is None:
                raise RuntimeError(f"cannot read sdist member {member.name}")
            payload = extracted.read()
            relative = member.name.removeprefix(f"{root}/")
            source_files[relative] = payload
            if member.name.startswith(prefix):
                package[f"{PACKAGE}/{member.name.removeprefix(prefix)}"] = payload
        return package, source_files


def _extract_sdist_safely(path: Path, destination: Path) -> Path:
    """Extract a single-root sdist without links or path traversal."""
    with tarfile.open(path, "r:gz") as archive:
        members = archive.getmembers()
        names = [member.name for member in members]
        _safe_members(names, archive=path.name)
        roots = {PurePosixPath(name).parts[0] for name in names if name}
        if len(roots) != 1:
            raise RuntimeError("sdist must contain exactly one top-level directory")
        root = destination / next(iter(roots))
        for member in members:
            relative = PurePosixPath(member.name)
            target = destination.joinpath(*relative.parts)
            if member.isdir():
                target.mkdir(parents=True, exist_ok=True)
                continue
            if not member.isfile():
                raise RuntimeError(f"sdist contains unsupported member {member.name!r}")
            target.parent.mkdir(parents=True, exist_ok=True)
            extracted = archive.extractfile(member)
            if extracted is None:
                raise RuntimeError(f"cannot read sdist member {member.name}")
            target.write_bytes(extracted.read())
    return root


def _inside(path: Path, directory: Path) -> bool:
    return path == directory or directory in path.parents


def _run_extracted_restart_oracle(
    extracted_root: Path,
    *,
    checkout_root: Path,
    candidate_python: Path = Path(sys.executable),
) -> dict[str, object]:
    environment = os.environ.copy()
    for name in tuple(environment):
        if name == "PYTHONPATH" or name == "CODEX_PATH" or name.endswith("_API_KEY"):
            environment.pop(name, None)
    environment["PYTHONPATH"] = "src"
    environment["PYTEST_DISABLE_PLUGIN_AUTOLOAD"] = "1"
    process = subprocess.run(
        [str(candidate_python), "-c", _PYTEST_PROBE, str(checkout_root.resolve())],
        cwd=extracted_root,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
        timeout=120,
    )
    marker_lines = [
        line.split(_PROVENANCE_PREFIX, 1)[1]
        for line in process.stdout.splitlines()
        if _PROVENANCE_PREFIX in line
    ]
    if process.returncode != 0 or len(marker_lines) != 1:
        detail = (process.stdout + process.stderr)[-4000:]
        raise RuntimeError(
            f"extracted sdist restart oracle failed with exit {process.returncode}: {detail}"
        )
    provenance = json.loads(marker_lines[0])
    nodeids = provenance.get("nodeids")
    if not isinstance(nodeids, list) or len(nodeids) != 14:
        raise RuntimeError(f"extracted sdist restart oracle collected {len(nodeids or [])}, expected 14")
    normalized_output = process.stdout.replace("\r\n", "\n")
    if re.search(r"\b14 passed\b", normalized_output) is None:
        raise RuntimeError("extracted sdist restart oracle did not report exactly 14 passed")
    if " skipped" in normalized_output or " deselected" in normalized_output:
        raise RuntimeError("extracted sdist restart oracle skipped or deselected cases")

    extraction = extracted_root.resolve()
    checkout = checkout_root.resolve()
    module = Path(str(provenance["module"])).resolve()
    cwd = Path(str(provenance["cwd"])).resolve()
    source_path = Path(str(provenance["source_path"])).resolve()
    test_files = [Path(str(value)).resolve() for value in provenance.get("test_files", [])]
    effective_paths = [Path(str(value)).resolve() for value in provenance.get("sys_path", [])]
    expected_test = (extraction / _RESTART_TEST).resolve()
    if module != (extraction / "src" / PACKAGE / "__init__.py").resolve():
        raise RuntimeError(f"extracted sdist imported unexpected package module {module}")
    if cwd != extraction or source_path != (extraction / "src").resolve():
        raise RuntimeError(
            f"extracted sdist provenance mismatch: cwd={cwd}, source_path={source_path}"
        )
    if test_files != [expected_test]:
        raise RuntimeError(f"extracted sdist collected unexpected test modules {test_files}")
    provenance_paths = [module, cwd, source_path, *test_files]
    if not all(_inside(path, extraction) for path in provenance_paths):
        raise RuntimeError("extracted sdist provenance escaped extraction root")
    if any(_inside(path, checkout) for path in effective_paths):
        raise RuntimeError("extracted sdist sys.path leaked the source checkout")
    return {
        "cases": 14,
        "cwd": str(cwd),
        "module": str(module),
        "source_path": str(source_path),
        "test": str(expected_test),
    }


def _check_extracted_restart_oracle(root: Path, sdist: Path) -> dict[str, object]:
    with tempfile.TemporaryDirectory(prefix="unrest-sdist-check-") as temporary:
        extracted_root = _extract_sdist_safely(sdist, Path(temporary))
        return _run_extracted_restart_oracle(extracted_root, checkout_root=root)


def check_distribution(root: Path, dist: Path) -> dict[str, object]:
    wheels = sorted(dist.glob("*.whl"))
    sdists = sorted(dist.glob("*.tar.gz"))
    if len(wheels) != 1 or len(sdists) != 1:
        raise RuntimeError("distribution directory must contain exactly one wheel and one sdist")

    source = _source_package(root)
    project = tomllib.loads((root / "pyproject.toml").read_text(encoding="utf-8"))["project"]
    version = project["version"]
    expected_wheel = f"unrest_harness-{version}-py3-none-any.whl"
    expected_sdist = f"unrest_harness-{version}.tar.gz"
    if wheels[0].name != expected_wheel or sdists[0].name != expected_sdist:
        raise RuntimeError(
            "distribution filenames do not match project version: "
            f"expected={[expected_wheel, expected_sdist]}, "
            f"actual={[wheels[0].name, sdists[0].name]}"
        )
    wheel, metadata, entry_points, _record = _wheel_payload(wheels[0])
    sdist, sdist_source_files = _sdist_payload(sdists[0])
    if wheel != source:
        missing = sorted(source.keys() - wheel.keys())
        extra = sorted(wheel.keys() - source.keys())
        changed = sorted(name for name in source.keys() & wheel.keys() if source[name] != wheel[name])
        raise RuntimeError(
            f"wheel/source package mismatch: missing={missing}, extra={extra}, changed={changed}"
        )
    if sdist != source:
        missing = sorted(source.keys() - sdist.keys())
        extra = sorted(sdist.keys() - source.keys())
        changed = sorted(name for name in source.keys() & sdist.keys() if source[name] != sdist[name])
        raise RuntimeError(
            f"sdist/source package mismatch: missing={missing}, extra={extra}, changed={changed}"
        )
    missing_oracle_files = sorted(SDIST_RESTART_ORACLE_FILES - sdist_source_files.keys())
    changed_oracle_files = sorted(
        name
        for name in SDIST_RESTART_ORACLE_FILES & sdist_source_files.keys()
        if sdist_source_files[name] != (root / name).read_bytes()
    )
    if missing_oracle_files or changed_oracle_files:
        raise RuntimeError(
            "sdist restart oracle inventory mismatch: "
            f"missing={missing_oracle_files}, changed={changed_oracle_files}"
        )
    if "Requires-Python: >=3.11\n" not in metadata.replace("\r\n", "\n"):
        raise RuntimeError("wheel metadata does not preserve Requires-Python >=3.11")
    if f"Version: {version}\n" not in metadata.replace("\r\n", "\n"):
        raise RuntimeError("wheel metadata version does not match project version")
    normalized_entries = {
        name.strip(): value.strip()
        for line in entry_points.splitlines()
        if "=" in line
        for name, value in [line.split("=", 1)]
    }
    if normalized_entries != CONSOLE_SCRIPTS:
        raise RuntimeError(f"wheel console scripts mismatch: {normalized_entries}")
    required_assets = {
        f"{PACKAGE}/py.typed",
        f"{PACKAGE}/bundled/policies/role-capabilities.v1.json",
    }
    if not required_assets <= wheel.keys():
        raise RuntimeError("wheel is missing typed marker or runtime policy asset")
    restart_oracle = _check_extracted_restart_oracle(root, sdists[0])
    return {
        "package_files": len(source),
        "restart_oracle": restart_oracle,
        "sdist": sdists[0].name,
        "wheel": wheels[0].name,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("dist", type=Path)
    arguments = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    result = check_distribution(root, arguments.dist.resolve())
    print(
        f"distribution archives verified: {result['package_files']} package files; "
        f"{result['wheel']}; {result['sdist']}; "
        f"extracted restart oracle: {result['restart_oracle']}"
    )


if __name__ == "__main__":
    main()
