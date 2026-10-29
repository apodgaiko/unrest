"""Closed metadata/input-envelope controls; no provider or child execution."""

import hashlib
import json
from types import SimpleNamespace

import pytest

from content_manifest import Refused
from native_metadata import descriptor
from input_manifest import read
from source_observer import Observer


@pytest.mark.parametrize(
    "record, mounted", [(True, True), (True, False), (False, True), (False, False)]
)
def test_native_descriptor_and_readonly_generation_must_agree(tmp_path, record, mounted):
    source = {
        "schema": "unrest.guard-content.v1",
        "files": [{"path": "module.py", "sha256": "a" * 64}],
    }
    value = (
        {"schema": "unrest.source-inputs.v1", "source": source, "native_metadata": descriptor()}
        if record
        else source
    )
    raw = json.dumps(value).encode()
    (tmp_path / "source-manifest.json").write_bytes(raw)
    policy = SimpleNamespace(
        directory=tmp_path,
        profile={
            "source_sha256": hashlib.sha256(raw).hexdigest(),
            "mounts": {"/native": [1, 2, 3]} if mounted else {},
        },
    )
    if record == mounted:
        assert read(policy.directory,policy.profile) == {"module.py": "a" * 64}
    else:
        with pytest.raises(Refused):
            read(policy.directory,policy.profile)


def test_metadata_changes_only_root_discovery_path():
    observer = object.__new__(Observer)
    observer.full, observer.outcomes = True, []
    observer.meta = {"owned": "/owned", "runtime_root": "/runtime", "mounts": {"/native": [1, 2, 3]}}
    assert observer.meta_environment()["PATH"] == "/runtime/bin:/runtime/bin:/native/bin:/usr/bin:/bin"
    observer.meta["mounts"] = {}
    assert observer.meta_environment()["PATH"] == "/runtime/bin:/runtime/bin:/usr/bin:/bin"


@pytest.mark.parametrize('mounted', [False, True])
def test_actual_worker_root_environment_matches_observer_before_fork(monkeypatch, tmp_path, mounted):
    import os
    import sys
    import source_host
    metadata = {'owned': str(tmp_path), 'mounts': {'/native': [1, 2, 3]} if mounted else {},
                'cases': {},'selection': [],'runtime_root':str(tmp_path/'runtime'),'checkout':str(tmp_path/'source')}
    observer = object.__new__(Observer)
    observer.full, observer.outcomes = True, []
    observer.meta = metadata
    descriptors = []
    original_pipe = os.pipe
    def pipe():
        pair = original_pipe()
        descriptors.extend(pair)
        return pair
    class BeforeFork(RuntimeError):
        pass
    def fork():
        from full_source import environment
        from uv_cli import child_environment
        actual=sys._getframe(1).f_locals['environment']
        assert actual==environment(metadata)
        assert child_environment(metadata,actual)==observer.meta_environment()
        raise BeforeFork
    monkeypatch.setattr(source_host, 'isolate', lambda value, support: value)
    monkeypatch.setattr(os, 'pipe', pipe)
    monkeypatch.setattr(os, 'fork', fork)
    try:
        with pytest.raises(BeforeFork):
            source_host.worker({'support': '/support', 'entry': {'path': '/entry'}}, metadata, tmp_path)
    finally:
        for descriptor in descriptors:
            os.close(descriptor)
