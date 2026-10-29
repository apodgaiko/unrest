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
    assert value==metadata.descriptor()
    assert all(path.stat().st_mode & 0o777==0o555 for path in [root,*root.rglob('*')] if path.is_dir())
    assert (root/'bin/codex-acp').readlink().as_posix()==metadata.LINK[1]
    assert not (root / "bin/node").stat().st_mode & 0o111
    assert (root / "bin/codex-acp").resolve() == root / metadata.MEMBERS[1][0]


@pytest.mark.parametrize('mutation',['archive','member','written','size','alias'])
def test_factory_refuses_changed_bytes_before_exposing_readonly_inputs(graph,monkeypatch,mutation):
    root,_=graph
    target=root.parent/'new-metadata'
    if mutation in ('archive','member'):
        rows=[list(row) for row in metadata.INPUTS]
        rows[0][2 if mutation=='archive' else 4]='0'*64
        monkeypatch.setattr(metadata,'INPUTS',tuple(tuple(row) for row in rows))
    elif mutation=='written':
        monkeypatch.setattr(metadata,'regular',lambda *args,**kwargs:b'changed after write')
    elif mutation=='size':
        rows=[list(row) for row in metadata.MEMBERS]
        rows[1][2]+=1
        monkeypatch.setattr(metadata,'MEMBERS',tuple(tuple(row) for row in rows))
    else:
        target.symlink_to(root)
    try:
        with pytest.raises(Refused):
            metadata.prepare(target)
    finally:
        if target.is_dir() and not target.is_symlink():
            for path in [target,*target.rglob('*')]:
                if path.is_dir() and not path.is_symlink():
                    path.chmod(0o755)
