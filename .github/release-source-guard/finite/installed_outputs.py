"""Exact UV 0.11.0 Unix target outputs; inspection is not producer settlement."""

from __future__ import annotations

import base64
import configparser
import csv
import hashlib
import io
import json
from pathlib import Path
import stat
import zipfile

from operation_activation import identity, verify_caches


class EntryConfig(configparser.ConfigParser):
    def optionxform(self, optionstr: str) -> str:
        return optionstr


def generated_cache(wheel: Path) -> dict:
    ctime = wheel.stat().st_ctime_ns
    return {
        "timestamp": {
            "secs_since_epoch": ctime // 1_000_000_000,
            "nanos_since_epoch": ctime % 1_000_000_000,
        },
        "commit": None,
        "tags": None,
        "env": {},
        "directories": {},
    }


def console_source(module: str, function: str, executable: str) -> bytes:
    if " " in executable or len(executable) > 125 or not Path(executable).is_absolute():
        raise RuntimeError("unsupported_target_shebang")
    imported = function.split(".")[0]
    return (
        f"#!{executable}\n# -*- coding: utf-8 -*-\nimport sys\nfrom {module} import {imported}\n"
        'if __name__ == "__main__":\n'
        '    if sys.argv[0].endswith("-script.pyw"):\n        sys.argv[0] = sys.argv[0][:-11]\n'
        '    elif sys.argv[0].endswith(".exe"):\n        sys.argv[0] = sys.argv[0][:-4]\n'
        f"    sys.exit({function}())\n"
    ).encode()


def inspect_install(
    wheel: Path, site: Path, executable: str, expected_entries: dict[str, str], cache_writers=None
) -> dict:
    with zipfile.ZipFile(wheel) as archive:
        names = archive.namelist()
        if len(names) != len(set(names)):
            raise RuntimeError("installed_duplicate_wheel_member")
        payload = {n: archive.read(n) for n in names if not n.endswith("/")}
    if any(".data/" in n or Path(n).is_absolute() or ".." in Path(n).parts for n in payload):
        raise RuntimeError("installed_unregistered_relocation")
    records = [n for n in payload if n.endswith(".dist-info/RECORD") and len(Path(n).parts) == 2]
    if len(records) != 1:
        raise RuntimeError("installed_top_level_distribution_cardinality")
    record = records[0]
    dist = str(Path(record).parent)
    parser = EntryConfig(interpolation=None)
    if dist + "/entry_points.txt" in payload:
        parser.read_string(payload[dist + "/entry_points.txt"].decode())
    entries = dict(parser.items("console_scripts")) if parser.has_section("console_scripts") else {}
    if entries != expected_entries or set(parser.sections()) - {"console_scripts"}:
        raise RuntimeError("installed_entry_point_contract")
    scripts = {}
    for name, entry in entries.items():
        if Path(name).name != name or entry.count(":") != 1:
            raise RuntimeError("installed_entry_point_shape")
        module, function = entry.split(":")
        if not all(p.isidentifier() for p in module.split(".") + function.split(".")):
            raise RuntimeError("installed_entry_point_identifiers")
        scripts["bin/" + name] = console_source(module, function, executable)
    generated = {
        dist + "/INSTALLER": b"uv",
        dist + "/REQUESTED": b"",
        dist + "/uv_cache.json": json.dumps(generated_cache(wheel), separators=(",", ":")).encode(),
        dist + "/direct_url.json": json.dumps(
            {"url": wheel.as_uri(), "archive_info": {}}, separators=(",", ":")
        ).encode(),
        **scripts,
    }
    expected = {**payload, **generated, ".lock": b""}
    observed = {}
    for path in sorted(site.rglob("*")):
        mode = path.lstat().st_mode
        if stat.S_ISDIR(mode):
            continue
        if not stat.S_ISREG(mode):
            raise RuntimeError("installed_special_member")
        if path.suffix == ".pyc":
            continue
        relative = path.relative_to(site).as_posix()
        observed[relative] = path.read_bytes()
        if relative in scripts and mode & 0o111 != 0o111:
            raise RuntimeError("installed_console_mode")
    if set(observed) != set(expected):
        raise RuntimeError(
            "installed_generated_membership:" + ",".join(sorted(set(observed) ^ set(expected)))
        )
    for name, body in expected.items():
        if name == record:
            continue
        if name == dist + "/direct_url.json":
            if json.loads(observed[name]) != json.loads(body):
                raise RuntimeError("installed_direct_url_lineage")
            expected[name] = observed[name]
        elif observed[name] != body:
            raise RuntimeError("installed_generated_or_member_drift:" + name)
    rows = list(csv.reader(io.StringIO(observed[record].decode())))
    by_name = {}
    for row in rows:
        if len(row) != 3 or row[0] in by_name:
            raise RuntimeError("installed_RECORD_shape_or_duplicate")
        by_name[row[0]] = row[1:]
    if set(by_name) != set(expected) - {".lock"} or by_name[record] != ["", ""]:
        raise RuntimeError("installed_RECORD_membership")
    if [r[0] for r in rows] != sorted(by_name):
        raise RuntimeError("installed_RECORD_order")
    for name in sorted(set(expected) - {record, ".lock"}):
        body = expected[name]
        digest = (
            "sha256="
            + base64.urlsafe_b64encode(hashlib.sha256(body).digest()).rstrip(b"=").decode()
        )
        if by_name[name] != [digest, str(len(body))]:
            raise RuntimeError("installed_RECORD_generated_hash_or_size")
    caches = verify_caches(site)
    writers = [] if cache_writers is None else cache_writers
    complete = not caches
    if caches and writers:
        by_cache = {v["cache"]: v for v in writers}
        if len(by_cache) != len(writers) or set(by_cache) != {v["cache"]["path"] for v in caches}:
            raise RuntimeError("installed_cache_writer_membership")
        for cache in caches:
            writer = by_cache[cache["cache"]["path"]]
            if (
                writer["cache_sha256"] != cache["cache"]["sha256"]
                or writer["source"] != cache["source"]["path"]
                or writer["source_sha256"] != cache["source"]["sha256"]
            ):
                raise RuntimeError("installed_cache_writer_source_drift")
        complete = True
    return {
        "wheel": identity(wheel),
        "site": str(site),
        "members": [identity(site / n) for n in sorted(payload) if n != record],
        "generated": [identity(site / n) for n in sorted(generated)],
        "entrypoints": [identity(site / n) for n in sorted(scripts)],
        "record": identity(site / record),
        "source_correspondent_caches": caches,
        "complete_generated_file_mapping": complete,
        "cache_writer_provenance": "actual writer records; caller authenticates admission/wait"
        if caches and complete
        else "unobserved"
        if caches
        else "no caches",
        "producer_settlement": False,
        "original_source_coverage": False,
    }
