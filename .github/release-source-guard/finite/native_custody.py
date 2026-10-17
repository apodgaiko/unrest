"""Retained Linux kernel parent/birth observation for admitted native leaves."""

from __future__ import annotations

import importlib.util
import os
from pathlib import Path
from typing import Any


def prepare(platform: dict[str, str]) -> Any:
    if platform != {"system": "Linux", "abi": "proc-stat-start-ticks"}:
        raise RuntimeError("native Linux identity ABI drift")
    spec = importlib.util.spec_from_file_location(
        "linux_identity", Path(__file__).with_name("linux_identity.py")
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.identity


def observe(pid: int, query: Any) -> dict[str, Any]:
    value = query(pid)
    if value["pid"] != pid or value["ppid"] != os.getpid():
        raise RuntimeError("native retained Linux parent mismatch")
    return {
        "native_pid": pid,
        "native_ppid": value["ppid"],
        "native_pgid": value["pgid"],
        "native_sid": value["sid"],
        "native_uid": value["uid"],
        "native_start_ticks": value["start_ticks"],
        "native_boot_id": value["boot_id"],
        "ownership_observation": "Linux proc stat/status retained until actual parent wait",
        "native_child_READY": "not applicable only under approved exact ordinary native leaf disposition",
        "owner_READY_required": True,
    }
