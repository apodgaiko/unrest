"""Closed metadata/input-envelope controls; no provider or child execution."""


import pytest

from source_observer import Observer


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
