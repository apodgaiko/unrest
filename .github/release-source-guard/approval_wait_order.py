"""Collect a dying original parent before its already adopted terminal child."""

from __future__ import annotations

import hashlib
import os
from pathlib import Path

from approval_exit_observation import snapshot
from approval_orphan_custody import CASES, CLASSES
from finite.approval_unix import PINS


def unique(rows):
    return rows[0] if len(rows) == 1 else None


def defer(authority, trace, pid):
    if pid not in getattr(authority, "_approval_exited", ()):
        return False
    selected = getattr(authority, "bound", {}).get(pid)
    if selected is None or selected["registration"].get("class") not in CLASSES:
        return False
    events = authority.supervisor.events()
    child = unique([r for r in events if r["kind"] == "registered" and r["pid"] == pid])
    saved = authority.supervisor.registered.get(pid)
    if child is None or saved is None or child.get("case") not in CASES:
        return False
    birth = saved["identity"]
    parent = birth["ppid"]
    if (
        child["owner_pid"] != parent
        or child["token"] != saved["token"]
        or child["class"] != selected["registration"]["class"]
        or parent not in trace.active
        or any(
            r["kind"] == "tracer_terminal_wait" and r["pid"] in (parent, pid) for r in trace.records
        )
    ):
        return False
    ready = unique([r for r in events if r["kind"] == "ready" and r["owner_pid"] == pid])
    parent_registration = unique(
        [r for r in events if r["kind"] == "registered" and r["pid"] == parent]
    )
    parent_saved = authority.supervisor.registered.get(parent)
    child_birth = unique(
        [r for r in trace.records if r["kind"] == "kernel_child" and r["child"] == pid]
    )
    child_exit = unique(
        [r for r in trace.records if r["kind"] == "kernel_exit" and r["pid"] == pid]
    )
    parent_exit = unique(
        [r for r in trace.records if r["kind"] == "kernel_exit" and r["pid"] == parent]
    )
    if (
        ready is None
        or ready["token"] != child["token"]
        or parent_registration is None
        or parent_saved is None
        or parent_registration.get("case") != child["case"]
        or child_birth is None
        or child_birth["parent"] != parent
        or child_exit is None
        or parent_exit is None
    ):
        return False
    if (
        ready.get("case") != child["case"]
        or ready.get("class") != child["class"]
        or ready.get("parent_pid") != parent
    ):
        return False
    parent_ready = unique([r for r in events if r["kind"] == "ready" and r["owner_pid"] == parent])
    if (
        parent_ready is None
        or parent_ready["token"] != parent_saved["token"]
        or parent_registration["token"] != parent_saved["token"]
        or parent_ready.get("case") != parent_registration["case"]
        or parent_ready.get("class") != parent_registration["class"]
        or parent_ready.get("parent_pid") != parent_saved["identity"]["ppid"]
    ):
        return False
    for name, pin in PINS.items():
        if (
            authority.supervisor.manifest["product_pins"].get(name) != pin
            or hashlib.sha256(Path("/source", name).read_bytes()).hexdigest() != pin
        ):
            return False
    raw = parent_exit["raw"]
    if type(raw) is not int or not os.WIFSIGNALED(raw):
        return False
    signal = os.WTERMSIG(raw)
    if not (
        signal == 15
        and "[cancel" in child["case"]
        or signal == 9
        and "[crash" in child["case"]
        and parent_registration["class"] == "source-run-worker"
    ):
        return False
    immutable = ("pid", "ppid", "start_ticks", "boot_id", "clock_ticks_per_second")
    if any(child_birth["identity"].get(k) != birth.get(k) for k in immutable) or any(
        trace.identities[parent].get(k) != parent_saved["identity"].get(k) for k in immutable
    ):
        return False
    try:
        current = snapshot(pid)
    except (OSError, ValueError, RuntimeError):
        return False
    # No status is manufactured or consumed here. The ordinary round-robin loop
    # continues serving every other task, under its unchanged overall deadline.
    return (
        current.get("ppid") == os.getpid()
        and all(current.get(k) == value for k, value in birth.items() if k != "ppid")
        and current.get("uids") == [birth["uid"]] * 4
    )
