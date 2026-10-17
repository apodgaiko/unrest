"""Run all four unchanged in-process restart parameters under the source guard."""
from __future__ import annotations
import hashlib
import json
import os
from pathlib import Path
import sys
import types
import time

INPROCESS = 'tests/test_server.py::test_completion_refusal_survives_server_restart'
COMPOSED = 'tests/test_server.py::test_composed_restart_stop_replacement_and_cancel_are_distinct'


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
    case = manifest['source_case']
    assert case in {INPROCESS, COMPOSED} and dict(os.environ) == manifest['root_environment']
    expected = ({INPROCESS + '[' + repair + '-' + role + ']'
                 for repair in ('valid-repair','second-invalid') for role in ('work','validate')}
                if case == INPROCESS else {COMPOSED})
    sys.path[:0] = ['/opt/deps/lib/python3.13/site-packages', '/source/src', '/source']
    endpoint = load('endpoint', '/guard/finite/endpoint.py', manifest['endpoint']['sha256'])
    endpoint.early(manifest['endpoint'])
    sys._finite_source_bootstrap_gate = {'active': True}
    guard = load('runtime_guard', manifest['guard'], manifest['guard_sha256'])
    endpoint.attach(guard)
    guard.install(path, pin, case=case)
    guard.require_ready('root')
    os.chdir('/source')
    custodian = None
    if case == COMPOSED:
        custodian = sys.modules['restart_custody'].start_custodian(Path(manifest['owned_root']))
        deadline = time.monotonic() + 8
        while not any(event['kind'] == 'custody_IPC_listener_ready' and event['owner_pid'] == custodian.pid
                      for event in guard.summarize(path)['events']):
            assert custodian.poll() is None and time.monotonic() < deadline
            time.sleep(.01)
    import pytest
    class Plugin:
        def pytest_runtest_setup(self, item):
            assert item.nodeid in expected
            guard._STATE['case'] = item.nodeid
        def pytest_collection_finish(self, session):
            collected = [item.nodeid for item in session.items]
            Path('/work/collection.json').write_text(json.dumps(collected))
            if not session.testsfailed:
                assert len(collected) == len(expected) and set(collected) == expected
        def pytest_runtest_logreport(self, report):
            guard.append({'kind': 'test_outcome', 'nodeid': report.nodeid,
                          'phase': report.when, 'outcome': report.outcome})
    result = 1
    custodian_status = None
    try:
        result = int(pytest.main(['-q', '-p', 'no:cacheprovider', '--basetemp=' + manifest['owned_root'] + '/pytest',
                                 '--junitxml=/work/source.xml', case], plugins=[Plugin()]))
    finally:
        if custodian is not None:
            try:
                endpoint.request('custody_close')
            finally:
                actual_status = custodian.wait(timeout=25)
                guard.append({'kind': 'root_actual_custodian_wait', 'pid': custodian.pid,
                              'numeric_returncode': actual_status, 'source_assertions_completed': result == 0})
                custodian_status = actual_status

    summary = guard.observe_summary(path)
    summary['original_pytest_exit_code'] = result
    summary['actual_custodian_status'] = custodian_status
    Path('/work/summary.json').write_text(json.dumps(summary, sort_keys=True, indent=2))
    if (not summary['ready'] or endpoint.STATE['poison']
            or custodian_status not in (None, 0)):
        return 2
    return result

if __name__ == '__main__':
    raise SystemExit(main())
