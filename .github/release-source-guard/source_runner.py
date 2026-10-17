"""Run all four unchanged in-process restart parameters under the source guard."""
from __future__ import annotations
import hashlib
import json
import os
from pathlib import Path
import sys
import types
import time

CI = 'tests/test_repository_contract.py'
CI_SELECTORS = [CI + '::' + name for name in (
    'test_ci_constant_dead_guards_fail_through_candidate_cli',
    'test_ci_literal_dead_shell_branches_fail_through_candidate_cli',
    'test_ci_live_or_dynamic_guards_remain_accepted_through_candidate_cli')]

INPROCESS = 'tests/test_server.py::test_completion_refusal_survives_server_restart'
BACKEND = 'tests/test_controlled_python_acp.py'
BACKEND_SELECTORS = [BACKEND + '::' + name for name in (
    'test_real_local_boundaries[receipts]',
    'test_lane_selection_survives_correction_rotation[None]',
    'test_programmatic_private_preflight',
    'test_native_pin_refusal_stays_native[launcher]',
    'test_native_pin_refusal_stays_native[runtime]')]
PRODUCER_CONTRACT = 'tests/contracts/test_lean_provider_security.py::test_installed_supported_provider_matrix'
PRODUCER_DISTRIBUTION = 'tests/test_distribution_check.py::test_checker_builds_and_executes_15_cases_with_extracted_provenance'
COMPOSED = 'tests/test_server.py::test_composed_restart_stop_replacement_and_cancel_are_distinct'
STAGE = 'startup'


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
    global STAGE
    STAGE = 'manifest'
    path, pin = sys.argv[1:]
    assert hashlib.sha256(Path(path).read_bytes()).hexdigest() == pin
    manifest = json.loads(Path(path).read_bytes())
    case = manifest['source_case']
    assert case in {CI, INPROCESS, COMPOSED, BACKEND, PRODUCER_CONTRACT, PRODUCER_DISTRIBUTION} and dict(os.environ) == manifest['root_environment']
    expected = ({INPROCESS + '[' + repair + '-' + role + ']'
                 for repair in ('valid-repair','second-invalid') for role in ('work','validate')}
                if case == INPROCESS else set(BACKEND_SELECTORS) if case == BACKEND
                else {PRODUCER_CONTRACT + '[' + provider + ']' for provider in ('claude','codex')}
                if case == PRODUCER_CONTRACT else {case})
    sys.path[:0] = ['/opt/deps/lib/python3.13/site-packages', '/source/src', '/source']
    STAGE = 'guard_load'
    endpoint = load('endpoint', '/guard/finite/endpoint.py', manifest['endpoint']['sha256'])
    endpoint.early(manifest['endpoint'])
    sys._finite_source_bootstrap_gate = {'active': True}
    guard = load('runtime_guard', manifest['guard'], manifest['guard_sha256'])
    endpoint.attach(guard)
    STAGE = 'guard_install'
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
            assert (any(item.nodeid.startswith(selector + '[') for selector in CI_SELECTORS)
                    if case == CI else item.nodeid in expected)
            guard._STATE['case'] = item.nodeid
        def pytest_collection_finish(self, session):
            collected = [item.nodeid for item in session.items]
            Path('/work/collection.json').write_text(json.dumps(collected))
            if not session.testsfailed:
                if case == CI:
                    assert len(collected) == 17 and len(set(collected)) == 17
                    assert all(any(node.startswith(selector + '[') for selector in CI_SELECTORS)
                               for node in collected)
                else:
                    assert len(collected) == len(expected) and set(collected) == expected
        def pytest_runtest_logreport(self, report):
            guard.append({'kind': 'test_outcome', 'nodeid': report.nodeid,
                          'phase': report.when, 'outcome': report.outcome})
    result = 1
    completed_pytest_status = None
    custodian_status = None
    try:
        STAGE = 'pytest'
        result = int(pytest.main(['-q', '-p', 'no:cacheprovider', '--basetemp=' + manifest['owned_root'] + '/pytest',
                                 '--junitxml=/work/source.xml',
                                 *(CI_SELECTORS if case == CI else BACKEND_SELECTORS if case == BACKEND else [case])], plugins=[Plugin()]))
        completed_pytest_status = result
    finally:
        if custodian is not None:
            try:
                endpoint.request('custody_close')
            finally:
                actual_status = custodian.wait(timeout=25)
                guard.append({'kind': 'root_actual_custodian_wait', 'pid': custodian.pid,
                              'numeric_returncode': actual_status, 'source_assertions_completed': result == 0})
                custodian_status = actual_status

    STAGE = 'summary'
    summary = guard.observe_summary(path)
    summary['original_pytest_exit_code'] = result
    summary['actual_custodian_status'] = custodian_status
    Path('/work/summary.json').write_text(json.dumps(summary, sort_keys=True, indent=2))
    if (not summary['ready'] or endpoint.STATE['poison']
            or custodian_status not in (None, 0)):
        return 2
    return result

def entry():
    try:
        return main()
    except BaseException as error:
        frames = []
        trace = error.__traceback__
        pytest_status = None
        while trace is not None:
            frame = trace.tb_frame
            frames.append({'file_sha256': hashlib.sha256(frame.f_code.co_filename.encode()).hexdigest(),
                           'line': trace.tb_lineno})
            if frame.f_code.co_name == 'main' and type(frame.f_locals.get('completed_pytest_status')) is int:
                pytest_status = frame.f_locals['completed_pytest_status']
            trace = trace.tb_next
        kinds = {'AssertionError', 'AttributeError', 'KeyError', 'RuntimeError', 'TypeError', 'ValueError'}
        kind = type(error).__name__
        Path('/work/runner-stage.json').write_text(json.dumps({
            'schema': 'unrest.v046.runner-failure.v1', 'stage': STAGE,
            'error_code': kind if kind in kinds else 'other',
            'frames': frames[-8:], 'original_pytest_exit_code': pytest_status}, sort_keys=True))
        return 125


if __name__ == '__main__':
    raise SystemExit(entry())
