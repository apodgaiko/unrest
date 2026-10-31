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
    monkeypatch.setattr(source_host, 'isolate', lambda value, support, output: value)
    monkeypatch.setattr(os, 'pipe', pipe)
    monkeypatch.setattr(os, 'fork', fork)
    try:
        with pytest.raises(BeforeFork):
            source_host.worker({'support': '/support', 'entry': {'path': '/entry'}}, metadata, tmp_path)
    finally:
        for descriptor in descriptors:
            os.close(descriptor)


@pytest.mark.parametrize('full', (False, True))
def test_jail_mounts_measured_snapshot_at_genuine_editable_path_only_for_full_source(tmp_path, monkeypatch, full):
    import source_host
    import network_scope
    import filesystem_scope
    from types import SimpleNamespace

    metadata = {'checkout': '/private-snapshot/source', 'dependencies': '/deps',
                'runtime_root': '/runtime', 'owned': '/owned'}
    if full:
        metadata['_checkout_destination'] = '/home/runner/work/unrest/unrest'
    monkeypatch.setattr(source_host.ctypes, 'CDLL', lambda *a, **kw: SimpleNamespace(unshare=lambda flags: 0, mount=lambda *args: 0))
    monkeypatch.setattr(source_host.os, 'readlink', lambda path: 'net:before')
    monkeypatch.setattr(network_scope, 'configure', lambda before: 'net:private')
    monkeypatch.setattr(filesystem_scope, 'enter', lambda value, support, output: value)
    result = source_host.isolate(metadata, '/support', tmp_path)
    destination = '/home/runner/work/unrest/unrest' if full else '/private-snapshot/source'
    assert result['checkout'] == destination
    assert result['mounts'] == {'/deps': '/deps', '/runtime': '/runtime', '/support': '/support', destination: '/private-snapshot/source'}
    assert '_checkout_destination' not in result
