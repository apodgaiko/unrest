"""Linux process birth fields that remain observable until the actual wait."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any


def identity(pid: int) -> dict[str, Any]:
    if type(pid) is not int or pid <= 0:
        raise ValueError("positive owned PID required")
    root = Path("/proc") / str(pid)
    first = (root / "stat").read_text().rpartition(") ")[2].split()
    status = dict(line.split(":", 1) for line in (root / "status").read_text().splitlines())
    value = {
        "pid": pid,
        "ppid": int(first[1]),
        "pgid": int(first[2]),
        "sid": int(first[3]),
        "uid": int(status["Uid"].split()[0]),
        "start_ticks": int(first[19]),
        "clock_ticks_per_second": os.sysconf("SC_CLK_TCK"),
        "boot_id": Path("/proc/sys/kernel/random/boot_id").read_text().strip(),
    }
    second = (root / "stat").read_text().rpartition(") ")[2].split()
    if int(second[19]) != value["start_ticks"]:
        raise RuntimeError("Linux process birth changed during observation")
    return value
