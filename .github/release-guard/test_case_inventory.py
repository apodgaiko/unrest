"""Large discovery stays outside profiles; altered custody or bytes fail closed."""

import copy
import json
import os
import stat
from pathlib import Path

import pytest

import case_inventory as inventory
from content_manifest import Refused


def value():
    return {
        "cases": ["tests/test_many.py::test_case[" + str(i) + "]" for i in range(6000)],
        "skips": [],
        "source": "a" * 64,
        "dependency": "b" * 64,
    }


@pytest.mark.parametrize("mutation", ["duplicate", "bool", "skip", "source", "extra"])
def test_inventory_rejects_invalid_nodes_and_generation(mutation):
    data = value()
    if mutation == "duplicate":
        data["cases"].append(data["cases"][0])
    elif mutation == "bool":
        data["cases"][0] = True
    elif mutation == "skip":
        data["skips"] = ["foreign"]
    elif mutation == "source":
        data["source"] = "unbound"
    else:
        data["extra"] = True
    with pytest.raises(Refused):
        inventory.document(data)


def observer_files(monkeypatch):
    original_stat, fstat = os.stat, os.fstat

    def owner(info):
        if not stat.S_ISREG(info.st_mode):
            return info
        row = list(info)
        row[4] = 20001
        return os.stat_result(row)

    monkeypatch.setattr(os, "chown", lambda *args: None)
    monkeypatch.setattr(os, "stat", lambda *args, **kwargs: owner(original_stat(*args, **kwargs)))
    monkeypatch.setattr(os, "fstat", lambda fd: owner(fstat(fd)))


def test_large_manifest_has_small_profile_reference_and_exact_current_bytes(tmp_path, monkeypatch):
    observer_files(monkeypatch)
    data = value()
    ref = inventory.seal(data, tmp_path)
    assert len(json.dumps(data)) > 65536
    assert len(json.dumps(ref)) < 512
    assert inventory.load(ref, tmp_path, "a" * 64, "b" * 64) == data
    with pytest.raises(Refused, match="generation"):
        inventory.load(ref, tmp_path, "c" * 64, "b" * 64)
    path = Path(ref["path"])
    path.chmod(0o644)
    path.write_bytes(path.read_bytes().replace(b"test_case[0]", b"test_case[X]"))
    path.chmod(0o444)
    with pytest.raises(Refused, match="bytes"):
        inventory.load(ref, tmp_path, "a" * 64, "b" * 64)


@pytest.mark.parametrize("mutation", ["count", "path", "hash", "mode", "link"])
def test_inventory_reference_rejects_aliases_and_wrong_custody(tmp_path, monkeypatch, mutation):
    observer_files(monkeypatch)
    ref = inventory.seal(value(), tmp_path)
    bad = copy.deepcopy(ref)
    if mutation == "count":
        bad["count"] = True
    elif mutation == "path":
        bad["path"] = str(tmp_path / "../foreign")
    elif mutation == "hash":
        bad["sha256"] = "c" * 64
    elif mutation == "mode":
        Path(ref["path"]).chmod(0o644)
    else:
        os.link(ref["path"], tmp_path / "alias")
    with pytest.raises(Refused):
        inventory.reference(bad, tmp_path)


def test_oversized_pytest_parameter_ids_keep_parameters_out_of_control_frames():
    from control_transport import encode, REQUEST_LIMIT
    from source_profile import case_seal

    node = "tests/test_wire.py::test_oversized[" + "x" * 70000 + "]"
    data = {"cases": [node], "skips": [], "source": "a" * 64, "dependency": "b" * 64}
    assert inventory.document(data)["cases"] == [node]
    name = inventory.identity(node)
    assert name != node and len(name) < 80
    assert len(encode({"kind": "case-start", "payload": {"case": name}}, REQUEST_LIMIT)) < 256
    assert case_seal([name])["count"] == 1
    assert inventory.identity(node + "different") != name


def test_only_framework_case_metadata_is_normalized_for_child_environment():
    node = "tests/test_wire.py::test_oversized[" + "x" * 70000 + "]"
    values = {"PYTEST_CURRENT_TEST": node + " (call)", "PARAMETER": "original-byte-sequence"}
    normalized = inventory.environment(values, inventory.identity(node))
    assert normalized is not values
    assert normalized == {
        "PYTEST_CURRENT_TEST": inventory.identity(node) + " (call)",
        "PARAMETER": "original-byte-sequence",
    }
    assert values["PYTEST_CURRENT_TEST"] == node + " (call)"
    assert inventory.environment(values, "foreign-case") is values
    ordinary = {"PYTEST_CURRENT_TEST": "tests/test_small.py::test_case (call)"}
    assert inventory.environment(ordinary, "tests/test_small.py::test_case") is ordinary


def test_product_json_and_hash_mocks_cannot_change_framework_case_identity(monkeypatch):
    node = "tests/test_wire.py::test_large[" + "x" * 70000 + "]"
    expected = inventory.identity(node)

    def forbidden(*args, **kwargs):
        pytest.fail("product serializer mock leaked into framework identity")

    monkeypatch.setattr(inventory.json, "dumps", forbidden)
    monkeypatch.setattr(inventory.hashlib, "sha256", forbidden)
    assert inventory.identity(node) == expected
