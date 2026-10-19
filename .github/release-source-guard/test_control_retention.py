"""Physical failure evidence remains complete when preparation never finishes."""

from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
import tarfile

import pytest

spec = importlib.util.spec_from_file_location(
    "control_retention", Path(__file__).with_name("control_retention.py")
)
retention = importlib.util.module_from_spec(spec)
spec.loader.exec_module(retention)


def test_failed_preparation_is_retained_with_named_missing_facts(tmp_path):
    body = b"actual preparation stderr\x00\xff\n"
    (tmp_path / "preparation.log").write_bytes(body)
    (tmp_path / "preparation-status").write_text("73\n")
    archive = tmp_path / "evidence.tar.gz"
    retention.retain(tmp_path, archive)
    with tarfile.open(archive) as saved:
        assert saved.extractfile("preparation.log").read() == body
        assert saved.extractfile("preparation-status").read() == b"73\n"
        index = json.loads(saved.extractfile("control-retention.json").read())
        assert "ownership.log" in index["missing_named_records"]
        assert "source-copy.json" in index["missing_named_records"]
        assert len(index["members"]) == 2


@pytest.mark.parametrize("kind", ["symlink", "hardlink"])
def test_evidence_alias_is_refused(tmp_path, kind):
    outside = tmp_path / "outside"
    outside.write_bytes(b"not owned evidence")
    selected = tmp_path / "preparation.log"
    if kind == "symlink":
        selected.symlink_to(outside)
    else:
        os.link(outside, selected)
    with pytest.raises(RuntimeError, match="carrier refused"):
        retention.retain(tmp_path, tmp_path / "evidence.tar.gz")
    assert not (tmp_path / "evidence.tar.gz").exists()


def test_real_oversized_sparse_carrier_is_refused_before_read(tmp_path):
    with (tmp_path / "preparation.log").open("wb") as file:
        file.truncate(retention.CAP + 1)
    with pytest.raises(RuntimeError, match="carrier refused"):
        retention.retain(tmp_path, tmp_path / "evidence.tar.gz")
    assert not (tmp_path / "evidence.tar.gz").exists()


def test_actual_owned_records_retain_their_complete_bytes(tmp_path):
    root = tmp_path / "retention"
    root.mkdir()
    owned = tmp_path / "owned"
    owned.mkdir()
    body = b"actual kernel record\x00\xff"
    (owned / "kernel.json").write_bytes(body)
    archive = root / "evidence.tar.gz"
    retention.retain(root, archive, owned)
    with tarfile.open(archive) as saved:
        assert saved.extractfile("owned-multiprocess/kernel.json").read() == body
        index = json.loads(saved.extractfile("control-retention.json").read())
        assert index["members"][0]["bytes"] == len(body)


def test_read_access_time_does_not_masquerade_as_a_changed_carrier(tmp_path):
    source = tmp_path / "preparation.log"
    source.write_bytes(b"actual preparation")
    info = source.stat()
    os.utime(source, ns=(0, info.st_mtime_ns))
    retention.retain(tmp_path, tmp_path / "evidence.tar.gz")
    with tarfile.open(tmp_path / "evidence.tar.gz") as saved:
        assert saved.extractfile("preparation.log").read() == b"actual preparation"
