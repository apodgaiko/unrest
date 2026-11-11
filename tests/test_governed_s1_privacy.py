"""Governed S1 buckets, strict JSON, write-once, platform probe, boundaries (VAL-50..55)."""
from __future__ import annotations

import ast
import errno
import hashlib
import json
import logging
import os
import stat
from pathlib import Path

import pytest

from tests.governed_s1_support import (
    abandon_request,
    governed_dir,
    governed_project,
    request,
    work_plan,
)
from unrest_harness import governed_records as gr
from unrest_harness.controller import ToolError
from unrest_harness.coordinator import MissionCoordinator

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src" / "unrest_harness"
SECRET_TEXT = "Criterion text with marker PRIVATE-CRITERION-TEXT.\n"


def _all_files(root: Path) -> dict[str, bytes]:
    return {str(p.relative_to(root)): p.read_bytes() for p in sorted(root.rglob("*"))
            if p.is_file() and not p.is_symlink()}


# VAL-50 ----------------------------------------------------------------------


def test_val50_buckets(tmp_path, caplog):
    caplog.set_level(logging.DEBUG)
    controller, project_id, mid = governed_project(
        tmp_path, criteria={"VAL-A": SECRET_TEXT})
    receipt = controller.submit_governed_plan(project_id, mid, work_plan(["VAL-A"]), request())
    MissionCoordinator(controller.store, project_id, controller.dispatcher,
                       controller.terminal_reviewer, governed_delivery_route=True).step()
    g = governed_dir(controller.store, project_id, mid)
    files = _all_files(g)
    digest = hashlib.sha256(SECRET_TEXT.encode()).hexdigest()
    key = request()["idempotency_key"]
    manifests = [name for name in files if name.endswith("manifest.json")]
    (manifest_name,) = manifests
    manifest = json.loads(files[manifest_name])
    assert [row["content_sha256"] for row in manifest["criteria"]] == [digest]
    p_bucket = {n: b for n, b in files.items() if "/criteria/" in n or "/post-images/" in n}
    assert any(SECRET_TEXT.encode() == b for b in p_bucket.values())
    e_bucket = {n: b for n, b in files.items()
                if n.endswith(("intent.json", "commit.json", "opened.json", "closed.json",
                               "outcome.json")) or "/submissions/" in n}
    assert e_bucket
    outputs = [
        gr.canonical_bytes(receipt),
        *(gr.canonical_bytes(controller.inspect_governed(project_id, mid, section))
          for section in ("summary", "criteria", "task_gate", "executions")),
    ]
    with pytest.raises(ToolError) as caught:
        controller.submit_governed_plan(project_id, mid, work_plan(["VAL-A"], prefix="z"),
                                        request())
    error_payload = json.dumps({"code": caught.value.code, "message": caught.value.message,
                                "details": [str(d) for d in caught.value.details or []]})
    forbidden = (b"PRIVATE-CRITERION-TEXT", digest.encode(), key.encode())
    for name, data in e_bucket.items():
        assert not any(token in data for token in forbidden), name
    for data in outputs + [error_payload.encode(), caplog.text.encode()]:
        assert not any(token in data for token in forbidden)
    summary = controller.inspect_governed(project_id, mid)["governed_inspection"]
    assert set(summary) == {
        "schema", "project_id", "mission_id", "section", "admission_status", "status_reason",
        "executions_status", "executions_reason", "dispatch_gate", "admission_id",
        "abandon_id", "orphan_admission_ids", "temp_residue_count", "counts",
        "committed_is_historical", "concurrent_owner", "observation", "route_coverage",
        "trust_boundary", "not_claimed"}
    assert set(receipt["governed_admission"]) == {
        "schema", "project_id", "mission_id", "admission_id", "status", "replayed",
        "revision", "render_version", "criteria", "timed_assessment_eligible",
        "committed_is_historical", "terminal_review", "not_claimed"}
    abandon = controller.abandon_governance(project_id, mid, abandon_request())
    assert set(abandon["governed_abandon"]) == {
        "schema", "project_id", "mission_id", "abandon_id", "status", "replayed",
        "admission_phase", "not_claimed"}
    assert key.encode() not in gr.canonical_bytes(abandon)


# VAL-51 ----------------------------------------------------------------------

RECORD = {"schema": "unrest.governed-admission-commit.v1", "project_id": "p",
          "mission_id": "mission-001", "admission_id": "a" * 32,
          "product_publication_order": list(gr.PRODUCT_PUBLICATION_ORDER),
          "readback": "exact_bytes_equal_v1"}


@pytest.mark.parametrize("variant", ["duplicate", "extra", "float", "nan", "bool_int",
                                     "whitespace", "oversize", "schema", "utf8", "bigint",
                                     "nesting"])
def test_val51_strict_json_invalid_record(tmp_path, variant):
    good = gr.canonical_bytes(RECORD)
    data = {
        "duplicate": good.replace(b'{"admission_id"', b'{"admission_id":"x","admission_id"'),
        "extra": gr.canonical_bytes({**RECORD, "x": 1}),
        "float": good.replace(b'"readback"', b'"f":1.5,"readback"'),
        "nan": good.replace(b'"readback"', b'"f":NaN,"readback"'),
        "bool_int": gr.canonical_bytes({**RECORD, "project_id": True}),
        "whitespace": json.dumps(RECORD, indent=1, sort_keys=True).encode() + b"\n",
        "oversize": good + b" " * (gr.SMALL_RECORD_LIMIT + 1),
        "schema": gr.canonical_bytes({**RECORD, "schema": "other"}),
        "utf8": good.replace(b'"p"', b'"\xff"'),
        "bigint": good.replace(b'"readback"', b'"f":' + b"9" * 5000 + b',"readback"'),
        "nesting": b"[" * 16_000 + b"]" * 16_000,
    }[variant]
    (tmp_path / "commit.json").write_bytes(data)
    fd = os.open(tmp_path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        with pytest.raises(gr.GovernedRecordError) as caught:
            limit = gr.MANIFEST_LIMIT if variant in ("bigint", "nesting") else (
                gr.SMALL_RECORD_LIMIT)
            gr.read_record(fd, "commit.json", limit, gr.COMMIT_SPEC)
    finally:
        os.close(fd)
    assert caught.value.reason in ("invalid_record", "limit_exceeded")
    if variant != "oversize":
        assert caught.value.reason == "invalid_record"


def test_val51_io_mapping(tmp_path, monkeypatch):
    (tmp_path / "x.json").write_bytes(gr.canonical_bytes(RECORD))
    (tmp_path / "link.json").symlink_to(tmp_path / "x.json")
    fd = os.open(tmp_path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        for name, reason in (("link.json", "unexpected_member"),
                             ("missing.json", "member_missing")):
            with pytest.raises(gr.GovernedRecordError) as caught:
                gr.read_record(fd, name, gr.SMALL_RECORD_LIMIT, gr.COMMIT_SPEC)
            assert caught.value.reason == reason
        real_read = os.read
        monkeypatch.setattr(os, "read", lambda *a: (_ for _ in ()).throw(
            OSError(errno.EIO, "eio")))
        with pytest.raises(gr.GovernedRecordError) as caught:
            gr.read_record(fd, "x.json", gr.SMALL_RECORD_LIMIT, gr.COMMIT_SPEC)
        monkeypatch.setattr(os, "read", real_read)
        assert caught.value.reason == "io_unavailable"
    finally:
        os.close(fd)


def test_val51_residue_ignored_then_limit(tmp_path):
    for index in range(64):
        (tmp_path / f".tmp-{index:032x}").write_text("")
    fd = os.open(tmp_path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        members, residue = gr.scan_dir(fd)
        assert not members and residue == 64
        (tmp_path / f".tmp-{64:032x}").write_text("")
        with pytest.raises(gr.GovernedRecordError) as caught:
            gr.scan_dir(fd)
        assert caught.value.reason == "limit_exceeded"
    finally:
        os.close(fd)


# VAL-52 ----------------------------------------------------------------------


def test_val52_write_once(tmp_path):
    fd = os.open(tmp_path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        assert gr.publish(fd, "a.json", b"one\n", 100) == "created"
        assert gr.publish(fd, "a.json", b"one\n", 100) == "reused"
        with pytest.raises(gr.GovernedRecordError) as caught:
            gr.publish(fd, "a.json", b"two\n", 100)
        assert caught.value.reason == "artifact_identity_conflict"
        assert sorted(os.listdir(tmp_path)) == ["a.json"]
    finally:
        os.close(fd)


def test_val52_no_replace_or_rename_on_governed_paths(tmp_path, monkeypatch):
    calls: list[tuple[str, str]] = []
    real_replace, real_rename = os.replace, os.rename

    def spy(kind, real):
        def inner(src, dst, *args, **kwargs):
            parts = Path(os.fspath(dst)).parts
            if "governed" in parts or "identity" in parts:
                calls.append((kind, os.fspath(dst)))
            return real(src, dst, *args, **kwargs)
        return inner

    monkeypatch.setattr(os, "replace", spy("replace", real_replace))
    monkeypatch.setattr(os, "rename", spy("rename", real_rename))
    controller, project_id, mid = governed_project(tmp_path)
    MissionCoordinator(controller.store, project_id, controller.dispatcher,
                       controller.terminal_reviewer, governed_delivery_route=True).step()
    controller.abandon_governance(project_id, mid, abandon_request())
    assert calls == []


# Verbatim V3 §3.5 predicate (closed list).
CAPABILITY_EXPRESSION = """(
    all(hasattr(os, n) for n in ("O_NOFOLLOW", "O_DIRECTORY", "O_CLOEXEC", "O_NONBLOCK", "fsync", "link", "scandir"))
    and os.open in os.supports_dir_fd
    and os.mkdir in os.supports_dir_fd
    and os.stat in os.supports_dir_fd
    and os.unlink in os.supports_dir_fd
    and os.link in os.supports_dir_fd
    and os.link in os.supports_follow_symlinks
    and os.stat in os.supports_follow_symlinks
    and os.scandir in os.supports_fd
)"""  # noqa: E501


def test_val52_capability_predicate_is_exactly_contract_list():
    source = ast.parse((SRC / "governed_records.py").read_text())
    function = next(node for node in source.body if isinstance(node, ast.FunctionDef)
                    and node.name == "_compute_capability")
    (try_node,) = function.body
    assert isinstance(try_node, ast.Try)
    (returned,) = try_node.body
    assert isinstance(returned, ast.Return) and returned.value is not None
    expected = ast.parse(CAPABILITY_EXPRESSION, mode="eval").body
    assert ast.dump(returned.value) == ast.dump(expected)


def test_g2_platform_probe(tmp_path, record_property):
    """Host-only probe (macOS/.venv Python, basetemp filesystem); target FS stay UNKNOWN."""
    record_property("governed_fs_capable", gr.GOVERNED_FS_CAPABLE)
    for name in ("supports_dir_fd", "supports_follow_symlinks", "supports_fd"):
        record_property(f"os.{name}", sorted(f.__name__ for f in getattr(os, name)))
    for flag in ("O_NOFOLLOW", "O_DIRECTORY", "O_NONBLOCK", "O_EXCL", "O_CLOEXEC"):
        record_property(f"os.{flag}", getattr(os, flag, None))
    assert gr.GOVERNED_FS_CAPABLE is True
    root = os.open(tmp_path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.mkdir("d", dir_fd=root)
        fd = os.open("f", os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600,
                     dir_fd=root)
        os.write(fd, b"x")
        os.close(fd)
        os.link("f", "g", src_dir_fd=root, dst_dir_fd=root, follow_symlinks=False)
        with pytest.raises(FileExistsError):
            os.link("f", "g", src_dir_fd=root, dst_dir_fd=root, follow_symlinks=False)
        os.unlink("g", dir_fd=root)
        assert sorted(entry.name for entry in os.scandir(root)) == ["d", "f"]
        os.mkfifo(tmp_path / "fifo")
        fifo = os.open("fifo", os.O_RDONLY | os.O_NONBLOCK, dir_fd=root)
        assert stat.S_ISFIFO(os.fstat(fifo).st_mode)
        os.close(fifo)
        os.symlink(tmp_path / "d", tmp_path / "s")
        with pytest.raises(OSError) as caught:
            os.open("s", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=root)
        assert caught.value.errno in (errno.ELOOP, errno.ENOTDIR)
        record_property("symlink_dir_errno", errno.errorcode[caught.value.errno])
    finally:
        os.close(root)


# VAL-55 ----------------------------------------------------------------------


def test_val55_module_boundaries():
    assert hashlib.sha256((SRC / "cli.py").read_bytes()).hexdigest() == (
        "2ca82d15f3ad4bbc877971bfde90f20bcea8a4a1631641584f7077e785bc0b87")
    for module in ("governed_records.py", "governed_admission.py"):
        tree = ast.parse((SRC / module).read_text())
        imported: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom):
                imported.add(node.module or "")
            elif isinstance(node, ast.Import):
                imported.update(alias.name for alias in node.names)
        for name in imported:
            leaf = name.rsplit(".", 1)[-1]
            assert not leaf.startswith("continuation_"), (module, name)
            assert leaf not in ("run_control", "supervision"), (module, name)
