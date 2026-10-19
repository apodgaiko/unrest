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
