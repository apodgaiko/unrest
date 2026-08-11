"""Verify wheel/sdist package membership, metadata, and content hashes."""
from __future__ import annotations

import argparse
import base64
import csv
import hashlib
import io
import tarfile
import zipfile
from pathlib import Path, PurePosixPath

PACKAGE = "unrest_harness"
CONSOLE_SCRIPTS = {
    "unrest": "unrest_harness.cli:cli",
    "unrest-server": "unrest_harness.server:main",
}
SDIST_RESTART_ORACLE_FILES = {
    "tests/test_persistence_schema_v1.py",
    "tests/fixtures/persistence_schema_v1/corpus.json",
    "tests/fixtures/persistence_schema_v1/manifest.json",
}


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


def check_distribution(root: Path, dist: Path) -> dict[str, object]:
    wheels = sorted(dist.glob("*.whl"))
    sdists = sorted(dist.glob("*.tar.gz"))
    if len(wheels) != 1 or len(sdists) != 1:
        raise RuntimeError("distribution directory must contain exactly one wheel and one sdist")

    source = _source_package(root)
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
    return {
        "package_files": len(source),
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
        f"{result['wheel']}; {result['sdist']}"
    )


if __name__ == "__main__":
    main()
