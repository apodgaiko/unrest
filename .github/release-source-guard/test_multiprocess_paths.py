"""Actual filesystem bytes match CPython's bytes-valued executable boundary."""

from __future__ import annotations

import hashlib
import importlib.util
import os
from pathlib import Path

import pytest

spec = importlib.util.spec_from_file_location(
    "multiprocess_routes", Path(__file__).with_name("finite") / "multiprocess_routes.py"
)
routes = importlib.util.module_from_spec(spec)
spec.loader.exec_module(routes)


@pytest.mark.parametrize("kind", ["path", "str", "bytes"])
def test_executable_path_representation_preserves_complete_bytes(tmp_path, kind):
    path = tmp_path / "runtime"
    body = b"complete image\x00\xff"
    path.write_bytes(body)
    actual = path if kind == "path" else str(path) if kind == "str" else os.fsencode(path)
    assert routes.digest(actual) == hashlib.sha256(body).hexdigest()


def test_core_ready_cannot_release_parent_before_authenticated_endpoint_setup():
    state = {"pin": "manifest", "guard_sha256": "guard", "endpoint": {"nonce": "nonce"}}
    common = {"token": "child", "owner_pid": 42, "parent_pid": os.getpid(),
              "manifest_sha256": "manifest", "guard_sha256": "guard"}
    core = {**common, "kind": "ready"}
    complete = {**common, "kind": "endpoint_install_complete", "nonce": "nonce",
                "identity": {"pid": 42, "ppid": os.getpid(), "uid": os.getuid()}}
    assert not routes.endpoint_ready([core], state, "child", 42)
    assert not routes.endpoint_ready([complete], state, "child", 42)
    assert routes.endpoint_ready([core, complete], state, "child", 42)
    for field in ("nonce", "token", "owner_pid", "parent_pid", "manifest_sha256", "guard_sha256"):
        assert not routes.endpoint_ready([core, {**complete, field: "drift"}], state, "child", 42)
    for field in ("pid", "ppid", "uid"):
        changed = {**complete, "identity": {**complete["identity"], field: -1}}
        assert not routes.endpoint_ready([core, changed], state, "child", 42)
