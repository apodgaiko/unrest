"""Real file/schema/race controls; no execution or release authority is exercised."""
from __future__ import annotations

import copy
import hashlib
import json
import os
from pathlib import Path
import sys

import pytest

sys.path.insert(0, str(Path(__file__).parent))
import content_manifest as content


@pytest.fixture
def source(tmp_path):
    root = tmp_path.resolve() / "source"
    root.mkdir()
    (root / "src").mkdir()
    (root / "src/module.py").write_bytes(b"private body must not escape\n")
    (root / "tool.py").write_bytes(b"different body\n")
    for p in (root / "src/module.py", root / "tool.py"):
        p.chmod(0o644)
    return root


NAMES = ["src/module.py", "tool.py"]


def reference(source):
    value = content.capture(source, NAMES)
    body = content.encode(value)
    return value, body, hashlib.sha256(body).hexdigest()


def test_roundtrip_sorted_content_not_inode_or_run_identity(source, tmp_path, capsys):
    value, body, pin = reference(source)
    assert content.verify(source, body, pin, list(reversed(NAMES))) == value
    other = tmp_path.resolve() / "other"
    other.mkdir()
    (other / "src").mkdir()
    for name in NAMES:
        target = other / name
        target.write_bytes((source / name).read_bytes())
        target.chmod(0o644)
    assert content.capture(other, NAMES) == value
    assert b"private body" not in body
    assert set(value) == {"schema", "files"}
    assert capsys.readouterr() == ("", "")


@pytest.mark.parametrize("path", ["", "/tool.py", "../tool.py", "src/../tool.py",
                                 "src//module.py", "./tool.py", "src/", "a\\b",
                                 "a\x00b", "\ud800", "a/" * 33 + "b", "x" * 4097])
def test_noncanonical_paths_refuse_before_file_access(source, path):
    with pytest.raises(content.Refused):
        content.capture(source, [path])


@pytest.mark.parametrize("paths", [[], ["tool.py", "tool.py"], "tool.py", {"tool.py"}])
def test_inventory_closed(source, paths):
    with pytest.raises(content.Refused):
        content.capture(source, paths)


@pytest.mark.parametrize("mutation", ["body", "mode", "missing", "leaf_link",
                                     "parent_link", "hardlink", "fifo", "setid"])
def test_current_files_and_aliases_refuse(source, mutation):
    _, body, pin = reference(source)
    target = source / "src/module.py"
    if mutation == "body":
        target.write_bytes(b"changed")
    elif mutation == "mode":
        target.chmod(0o600)
    elif mutation == "missing":
        target.unlink()
    elif mutation == "leaf_link":
        target.unlink()
        target.symlink_to(source / "tool.py")
    elif mutation == "parent_link":
        (source / "src").rename(source / "saved")
        (source / "src").symlink_to(source / "saved", target_is_directory=True)
    elif mutation == "hardlink":
        os.link(target, source / "alias")
    elif mutation == "fifo":
        target.unlink()
        os.mkfifo(target)
    else:
        target.chmod(0o4644)
        if not target.lstat().st_mode & 0o4000:
            pytest.skip("filesystem strips setid; actual mutation requires Linux certification")
    with pytest.raises(content.Refused):
        content.verify(source, body, pin, NAMES)


def test_root_alias_refused(source):
    alias = source.parent / "alias"
    alias.symlink_to(source, target_is_directory=True)
    with pytest.raises(content.Refused, match="noncanonical_root"):
        content.capture(alias, NAMES)


def test_setid_mode_refuses_before_open_even_on_nosuid_filesystem(source, monkeypatch):
    original = os.stat

    def observed(path, *args, **kwargs):
        info = original(path, *args, **kwargs)
        if path == "module.py" and kwargs.get("dir_fd") is not None:
            values = list(info)
            values[0] |= 0o4000
            return os.stat_result(values)
        return info

    monkeypatch.setattr(content.os, "stat", observed)
    with pytest.raises(content.Refused, match="nonregular_or_aliased_file"):
        content.capture(source, NAMES)


@pytest.mark.parametrize("mutation", ["schema", "unknown", "order", "path", "mode_bool",
                                     "mode_setid", "size_bool", "size_negative", "hash"])
def test_strict_schema_even_with_matching_external_hash(source, mutation):
    value, _, _ = reference(source)
    changed = copy.deepcopy(value)
    if mutation == "schema":
        changed["schema"] = "unknown"
    elif mutation == "unknown":
        changed["run_id"] = "not-content"
    elif mutation == "order":
        changed["files"].reverse()
    else:
        field, new = {"path": ("path", "tool.py"), "mode_bool": ("mode", True),
                      "mode_setid": ("mode", 0o4644), "size_bool": ("size", False),
                      "size_negative": ("size", -1), "hash": ("sha256", "G" * 64)}[mutation]
        changed["files"][0][field] = new
    body = json.dumps(changed, sort_keys=True, separators=(",", ":")).encode() + b"\n"
    with pytest.raises(content.Refused):
        content.verify(source, body, hashlib.sha256(body).hexdigest(), NAMES)


def test_digest_inventory_duplicates_and_encoding_are_independently_bound(source):
    value, body, pin = reference(source)
    with pytest.raises(content.Refused, match="manifest_reference"):
        content.verify(source, body, "0" * 64, NAMES)
    with pytest.raises(content.Refused):
        content.verify(source, body, pin, ["tool.py"])
    noncanonical = json.dumps(value, indent=2).encode()
    with pytest.raises(content.Refused, match="noncanonical_manifest"):
        content.verify(source, noncanonical, hashlib.sha256(noncanonical).hexdigest(), NAMES)
    duplicate = body.replace(b'{"files":', b'{"schema":"duplicate","files":', 1)
    with pytest.raises(content.Refused, match="duplicate_json_key"):
        content.verify(source, duplicate, hashlib.sha256(duplicate).hexdigest(), NAMES)


@pytest.mark.parametrize("limit", ["MAX_FILE_BYTES", "MAX_TOTAL_BYTES", "MAX_FILES",
                                  "MAX_MANIFEST_BYTES"])
def test_bounds_refuse(source, monkeypatch, limit):
    _, body, pin = reference(source)
    monkeypatch.setattr(content, limit, 1)
    with pytest.raises(content.Refused):
        content.verify(source, body, pin, NAMES)


@pytest.mark.parametrize("replacement", ["leaf", "parent", "root", "ancestor", "inplace"])
def test_replacement_during_read_refuses_and_closes_all_fds(source, monkeypatch, replacement):
    original_read, original_open, original_close = os.read, os.open, os.close
    acquired, closed = [], []
    changed = False

    def opened(*args, **kwargs):
        fd = original_open(*args, **kwargs)
        acquired.append(fd)
        return fd

    def close(fd):
        closed.append(fd)
        return original_close(fd)

    def read(fd, count):
        nonlocal changed
        block = original_read(fd, count)
        if block and not changed:
            changed = True
            if replacement == "leaf":
                target = source / "src/module.py"
                target.rename(source / "src/saved.py")
                target.write_bytes(block)
            elif replacement == "parent":
                (source / "src").rename(source / "saved")
                (source / "src").mkdir()
            elif replacement == "root":
                source.rename(source.with_name("saved"))
                source.mkdir()
            elif replacement == "ancestor":
                parent = source.parent
                saved = parent.with_name(parent.name + "-saved")
                parent.rename(saved)
                parent.symlink_to(saved, target_is_directory=True)
            else:
                (source / "src/module.py").write_bytes(b"different content same inode")
        return block

    monkeypatch.setattr(content.os, "open", opened)
    monkeypatch.setattr(content.os, "close", close)
    monkeypatch.setattr(content.os, "read", read)
    with pytest.raises(content.Refused):
        content.capture(source, NAMES)
    assert changed
    assert sorted(acquired) == sorted(closed)


@pytest.mark.parametrize("boundary", ["leaf", "directory", "root"])
def test_stat_open_replacement_refuses_and_closes_fds(source, monkeypatch, boundary):
    original_open, original_close = os.open, os.close
    acquired, closed = [], []
    changed = False

    def opened(path, *args, **kwargs):
        nonlocal changed
        expected = {"leaf": "module.py", "directory": "src", "root": "source"}[boundary]
        if path == expected and not changed:
            changed = True
            target = {"leaf": source / "src/module.py", "directory": source / "src",
                      "root": source}[boundary]
            target.rename(target.with_name("saved"))
            if boundary == "leaf":
                target.write_bytes(b"different")
            else:
                target.mkdir()
        fd = original_open(path, *args, **kwargs)
        acquired.append(fd)
        return fd

    def close(fd):
        closed.append(fd)
        return original_close(fd)

    monkeypatch.setattr(content.os, "open", opened)
    monkeypatch.setattr(content.os, "close", close)
    with pytest.raises(content.Refused, match="acquisition_race"):
        content.capture(source, NAMES)
    assert changed and sorted(acquired) == sorted(closed)


def test_encoded_unicode_size_bound_is_symmetric(monkeypatch):
    value = {"schema": content.SCHEMA, "files": [
        {"path": "é.py", "mode": 0o644, "size": 0, "sha256": "0" * 64}]}
    body = content.encode(value)
    monkeypatch.setattr(content, "MAX_MANIFEST_BYTES", len(body))
    assert content.encode(value) == body
    monkeypatch.setattr(content, "MAX_MANIFEST_BYTES", len(body) - 1)
    with pytest.raises(content.Refused, match="manifest_byte_bound"):
        content.encode(value)


def test_oversized_json_integer_has_closed_refusal(source):
    body = b'{"schema":"unrest.guard-content.v1","files":' + b"9" * 10000 + b"}"
    with pytest.raises(content.Refused, match="manifest_encoding"):
        content.verify(source, body, hashlib.sha256(body).hexdigest(), NAMES)


@pytest.mark.parametrize("value", [None, {}, {"files": None}, {"files": [None]},
                                  {"files": [{}]}])
def test_direct_encoding_refuses_malformed_objects(value):
    with pytest.raises(content.Refused):
        content.encode(value)


def test_failure_after_nested_open_closes_directory_fds(source, monkeypatch):
    (source / "src/module.py").unlink()
    original_open, original_close = os.open, os.close
    acquired, closed = [], []

    def opened(*args, **kwargs):
        fd = original_open(*args, **kwargs)
        acquired.append(fd)
        return fd

    def close(fd):
        closed.append(fd)
        return original_close(fd)

    monkeypatch.setattr(content.os, "open", opened)
    monkeypatch.setattr(content.os, "close", close)
    with pytest.raises(content.Refused, match="filesystem_acquisition_refused"):
        content.capture(source, NAMES)
    assert acquired and sorted(acquired) == sorted(closed)


def test_native_measurement_has_a_separate_finite_bound(tmp_path):
    executable = tmp_path / 'native'
    data = b'x' * (content.MAX_FILE_BYTES + 1)
    executable.write_bytes(data)
    assert content.native_digest(executable) == hashlib.sha256(data).hexdigest()
    with pytest.raises(content.Refused, match='file_bound'):
        content.capture(tmp_path, ['native'])
    with executable.open('wb') as stream:
        stream.truncate(16 * 1024 * 1024 + 1)
    with pytest.raises(content.Refused, match='file_bound'):
        content.native_digest(executable)
    executable.unlink()
    executable.symlink_to('missing')
    with pytest.raises(content.Refused):
        content.native_digest(executable)
