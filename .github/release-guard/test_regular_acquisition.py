"""Shared custody, bounded byte reads and inventory-only streaming measurement."""

import hashlib
import os
import stat

import pytest

import content_manifest as content


def test_regular_bytes_and_streaming_inventory_have_identical_identity_and_digest(tmp_path):
    file = tmp_path / "member"
    raw = bytes(range(256)) * 300
    file.write_bytes(raw)
    file.chmod(0o600)
    body, info, pin = content.read_regular(file, len(raw), uid=os.getuid(), mode=0o600)
    assert body == raw and stat.S_ISREG(info.st_mode)
    assert pin == hashlib.sha256(raw).hexdigest()
    absent, streamed, digest = content.read_regular(
        file, len(raw), uid=os.getuid(), mode=0o600, retain=False
    )
    assert absent is None and content._key(streamed) == content._key(info) and digest == pin


@pytest.mark.parametrize("policy", ("uid", "mode", "minimum", "bound"))
def test_invalid_custody_refuses_before_read(tmp_path, monkeypatch, policy):
    file = tmp_path / "member"
    file.write_bytes(b"x")
    file.chmod(0o600)
    options = {"uid": os.getuid(), "mode": 0o600, "minimum": 0}
    limit = 1
    if policy == "uid":
        options["uid"] += 1
    elif policy == "mode":
        options["mode"] = 0o644
    elif policy == "minimum":
        options["minimum"] = 2
    else:
        limit = 0
    monkeypatch.setattr(
        content.os, "read", lambda *args: pytest.fail("custody must reject before read")
    )
    with pytest.raises(content.Refused):
        content.read_regular(file, limit, **options)


def test_empty_and_sticky_regular_metadata_retain_callers_explicit_policy(tmp_path):
    file = tmp_path / "member"
    file.write_bytes(b"")
    file.chmod(0o1600)
    body, _, _ = content.read_regular(file, 1, uid=os.getuid(), forbidden=0o6022)
    assert body == b""
    with pytest.raises(content.Refused):
        content.read_regular(file, 1, uid=os.getuid())
    with pytest.raises(content.Refused):
        content.read_regular(file, 1, uid=os.getuid(), forbidden=0o6022, minimum=1)
