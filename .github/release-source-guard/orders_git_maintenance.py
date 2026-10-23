"""Stock housekeeping child bound to one original finite-orders commit."""

from __future__ import annotations

import hashlib
from pathlib import Path
import re
import zlib

from finite.orders_git import ENVIRONMENT
from finite.linux_identity import identity
from linux_git import regular
from orders_git_custody import eligible, join_registration

VECTOR = ["/usr/lib/git-core/git", "maintenance", "run", "--auto", "--no-quiet"]
MESSAGES = {
    ("setup", 40): "finite fixture",
    ("campaign", 571): "base",
    ("seal", 197): "sealed candidate",
    ("integrate", 239): "authored lane integration",
}


def metadata(parent, environment, cwd):
    registration = parent["orders_registration"]
    caller = registration["caller_binding"]
    message = MESSAGES.get((caller.get("function"), caller.get("line")))
    arguments = (
        ["commit", "-m", message]
        if caller.get("function") in ("setup", "campaign")
        else ["commit", "--allow-empty", "-m", message]
    )
    if (
        message is None
        or parent["argv"] != ["/usr/bin/git", "--no-replace-objects", *arguments]
        or parent["cwd"] != cwd
        or parent["environment"] != ENVIRONMENT
    ):
        return False
    git = Path(cwd) / ".git"
    if regular(git / "HEAD", 256) != b"ref: refs/heads/main\n":
        return False
    reference = git / "refs/heads/main"
    if reference.resolve() != reference:
        return False
    oid = regular(reference, 64).decode().strip()
    if not re.fullmatch("[0-9a-f]{40}", oid):
        return False
    path = git / "objects" / oid[:2] / oid[2:]
    if path.resolve() != path:
        return False
    decoder = zlib.decompressobj()
    raw = decoder.decompress(regular(path, 16384), 16385)
    header, separator, commit = raw.partition(b"\0")
    if (
        len(raw) > 16384
        or not decoder.eof
        or decoder.unused_data
        or hashlib.sha1(raw).hexdigest() != oid
        or not separator
        or header != b"commit " + str(len(commit)).encode()
        or b"\nauthor Fixture <fixture@example.invalid> 946684800 +0000\n" not in commit
        or b"\ncommitter Fixture <fixture@example.invalid> 946684800 +0000\n" not in commit
        or not commit.endswith(b"\n\n" + message.encode() + b"\n")
    ):
        return False
    return environment == {
        **ENVIRONMENT,
        "PATH": "/usr/lib/git-core:/usr/bin:/bin",
        "GIT_EXEC_PATH": "/usr/lib/git-core",
        "GIT_PREFIX": "",
        "GIT_NO_REPLACE_OBJECTS": "1",
        "GIT_AUTHOR_DATE": "@946684800 +0000",
    }


def resolve(authority, trace, pid, path, vector, environment, cwd):
    if path != VECTOR[0] or vector != VECTOR:
        return False
    parent = trace.identities[pid]["ppid"]
    context = authority.native_context.get(parent)
    original = authority.bound.get(parent)
    if context is None or original is None or parent in authority.maintenance:
        return False
    selected = join_registration(original, authority.supervisor.events())
    if (
        selected is None
        or context.get("orders_registration") != selected["registration"]
        or not eligible(
            selected, context["argv"], context["environment"], context["cwd"], authority.manifest
        )
    ):
        return False
    before = identity(parent)
    if (
        before != authority.contexts[parent]["identity"]
        or Path("/proc/" + str(pid) + "/cwd").resolve() != Path(cwd)
        or hashlib.sha256(Path(path).read_bytes()).hexdigest()
        != authority.manifest["git_maintenance_sha256"]
        or not metadata(context, environment, cwd)
        or identity(parent) != before
    ):
        return False
    authority.maintenance.add(parent)
    authority.contexts[pid] = {"role": "source-git-maintenance", "identity": identity(pid)}
    authority.pipe_records.append(
        {
            "kind": "orders_git_maintenance_child",
            "pid": pid,
            "identity": identity(pid),
            "parent_identity": before,
            "original_commit_token": selected["token"],
            "executable_sha256": authority.manifest["git_maintenance_sha256"],
        }
    )
    return True
