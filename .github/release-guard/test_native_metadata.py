"""Synthetic metadata graph controls, never native execution certification."""

import hashlib
import io
import os
import tarfile

import pytest

from content_manifest import Refused
import native_metadata as metadata


@pytest.fixture
def graph(tmp_path, monkeypatch):
    bodies = (b"#! /usr/bin/env node\nstock test data", bytes.fromhex("cffaedfe") + b"node data")
    inputs = []
    archives = {}
    members = []
    for index, (name, body) in enumerate(zip(("index.js", "node.data"), bodies, strict=True)):
        stream = io.BytesIO()
        with tarfile.open(fileobj=stream, mode="w:gz") as archive:
            info = tarfile.TarInfo("package/" + name)
            info.size = len(body)
            archive.addfile(info, io.BytesIO(body))
        data = stream.getvalue()
        url = "https://example.invalid/" + name
        inputs.append(
            (
                name,
                url,
                hashlib.sha256(data).hexdigest(),
                "package/" + name,
                hashlib.sha256(body).hexdigest(),
            )
        )
        archives[url] = data
    for name, mode, _, pin in metadata.MEMBERS:
        body = bodies[1 if name == "bin/node" else 0]
        members.append((name, mode, len(body), hashlib.sha256(body).hexdigest()))
    monkeypatch.setattr(metadata, "INPUTS", tuple(inputs))
    monkeypatch.setattr(metadata, "MEMBERS", tuple(members))
    monkeypatch.setattr(metadata, "OWNER", os.getuid())
    monkeypatch.setattr(
        metadata.urllib.request, "urlopen", lambda url, timeout: io.BytesIO(archives[url])
    )
    root = tmp_path / "metadata"
    value = metadata.prepare(root)
    yield root, value
    for path in [root, *root.rglob("*")]:
        if path.is_dir() and not path.is_symlink():
            path.chmod(0o755)


def test_original_metadata_graph_is_readonly_and_descriptor_is_closed(graph):
    root, value = graph
    metadata.validate(value)
    assert metadata.measure(root) == value
    assert not (root / "bin/node").stat().st_mode & 0o111
    assert (root / "bin/codex-acp").resolve() == root / metadata.MEMBERS[1][0]


@pytest.mark.parametrize("mutation", ["body", "mode", "extra", "link", "platform"])
def test_native_metadata_graph_rejects_mutation(graph, mutation):
    root, _ = graph
    if mutation in ("body", "platform"):
        path = root / metadata.MEMBERS[0][0]
        path.chmod(0o644)
        path.write_bytes(b"wrong bytes")
        path.chmod(0o444)
    elif mutation == "mode":
        (root / "bin/node").chmod(0o555)
    elif mutation == "extra":
        root.chmod(0o755)
        (root / "extra").write_text("untrusted")
    else:
        (root / "bin").chmod(0o755)
        link = root / "bin/codex-acp"
        link.unlink()
        link.symlink_to("/foreign")
    with pytest.raises(Refused):
        metadata.measure(root)


@pytest.mark.parametrize("field", ["members", "link", "platform", "execution"])
def test_descriptor_substitution_refuses_before_use(graph, field):
    _, value = graph
    changed = dict(value)
    changed[field] = None
    with pytest.raises(Refused):
        metadata.validate(changed)
