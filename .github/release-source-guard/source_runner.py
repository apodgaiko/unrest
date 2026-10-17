"""Run all four unchanged in-process restart parameters under the source guard."""
from __future__ import annotations
import hashlib
import json
import os
from pathlib import Path
import sys
import types

CASE = 'tests/test_server.py::test_completion_refusal_survives_server_restart'
EXPECTED = {CASE + '[' + repair + '-' + role + ']' for repair in ('valid-repair','second-invalid') for role in ('work','validate')}

def load(name, path, pin):
    data = Path(path).read_bytes()
    if hashlib.sha256(data).hexdigest() != pin:
        raise RuntimeError('source support drift')
    module = types.ModuleType(name)
    module.__file__ = str(path)
    sys.modules[name] = module
    exec(compile(data, str(path), 'exec', dont_inherit=True), module.__dict__)
    return module

def main():
    path, pin = sys.argv[1:]
    assert hashlib.sha256(Path(path).read_bytes()).hexdigest() == pin
    manifest = json.loads(Path(path).read_bytes())
    assert manifest['source_case'] == CASE and dict(os.environ) == manifest['root_environment']
    sys.path[:0] = ['/opt/deps/lib/python3.13/site-packages', '/source/src', '/source']
    endpoint = load('endpoint', '/guard/finite/endpoint.py', manifest['endpoint']['sha256'])
    endpoint.early(manifest['endpoint'])
    sys._finite_source_bootstrap_gate = {'active': True}
    guard = load('runtime_guard', manifest['guard'], manifest['guard_sha256'])
    endpoint.attach(guard)
    guard.install(path, pin, case=CASE)
    guard.require_ready('root')
    os.chdir('/source')
    import pytest
    class Plugin:
        def pytest_runtest_setup(self, item):
            assert item.nodeid in EXPECTED
            guard._STATE['case'] = item.nodeid
        def pytest_collection_finish(self, session):
            collected = [item.nodeid for item in session.items]
            Path('/work/collection.json').write_text(json.dumps(collected))
            if not session.testsfailed:
                assert len(collected) == 4 and set(collected) == EXPECTED
        def pytest_runtest_logreport(self, report):
            guard.append({'kind': 'test_outcome', 'nodeid': report.nodeid,
                          'phase': report.when, 'outcome': report.outcome})
    result = int(pytest.main(['-q', '-p', 'no:cacheprovider', '--basetemp=/work/pytest',
                             '--junitxml=/work/source.xml', CASE], plugins=[Plugin()]))
    summary = guard.observe_summary(path)
    Path('/work/summary.json').write_text(json.dumps(summary, sort_keys=True, indent=2))
    if not summary['ready'] or endpoint.STATE['poison']:
        return 2
    return result

if __name__ == '__main__':
    raise SystemExit(main())
