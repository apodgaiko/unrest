"""Pre-body SOURCE setup and a collection observer for the real pytest console."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import sys
import threading
import time
import types


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':')).encode()


def load(name, path, pin):
    data = Path(path).read_bytes()
    if hashlib.sha256(data).hexdigest() != pin:
        raise RuntimeError('primary_source_support_drift')
    module = types.ModuleType(name)
    module.__file__ = path
    sys.modules[name] = module
    exec(compile(data, path, 'exec', dont_inherit=True), module.__dict__)
    return module


def activate(profile, event, arguments):
    path = profile['manifest']
    body = Path(path).read_bytes()
    if hashlib.sha256(body).hexdigest() != profile['manifest_sha256']:
        os._exit(86)
    manifest = json.loads(body)
    if profile['source_role'] == 'source-bootstrap':
        # The observer already consumed the fixture's exact transformed argv,
        # parent identity, source binding and environment. Its pinned -c program
        # is the existing endpoint/bootstrap composition, including -I/-S.
        if event != 'cpython.run_command' or len(arguments) != 1:
            os._exit(86)
        sys._unrest_primary_source_bootstrap_consumed = True
        return
    if (event != 'cpython.run_file' or len(arguments) != 1
            or hashlib.sha256(Path(arguments[0]).read_bytes()).hexdigest()
            != profile['console_source_sha256']):
        os._exit(86)
    endpoint = load('endpoint', '/guard/finite/endpoint.py', manifest['endpoint']['sha256'])
    endpoint.early(manifest['endpoint'])
    sys._finite_source_bootstrap_gate = {'active': True}
    guard = load('runtime_guard', manifest['guard'], manifest['guard_sha256'])
    endpoint.attach(guard)
    guard.install(path, profile['manifest_sha256'])
    guard.require_ready('root')
    import pytest
    import _pytest.config
    original = _pytest.config.get_config
    plugin = Observer(guard, endpoint, manifest, profile)

    def get_config(args=None, plugins=None):
        config = original(args, plugins)
        config.pluginmanager.register(plugin, 'primary-source-observer')
        return config

    _pytest.config.get_config = get_config
    # Collection hooks observe the original list before and after all hooks;
    # neither hook returns replacement items or adds marks/options/selectors.
    plugin.pytest_collection_modifyitems.__func__.pytest_impl = {'wrapper': True, 'tryfirst': True}
    plugin.pytest_configure.__func__.pytest_impl = {'tryfirst': True}
    plugin.pytest_runtest_setup.__func__.pytest_impl = {'tryfirst': True}
    assert pytest.console_main is not None


class Observer:
    def __init__(self, guard, endpoint, manifest, profile):
        self.guard, self.endpoint = guard, endpoint
        self.manifest, self.profile = manifest, profile
        self.before, self.after = [], []
        self.deselected = 0
        self.custodian = None
        self.collection_timer = None
        self.poison_checked = False

    def pytest_configure(self, config):
        expected = ['-q']
        if self.profile['source_mode'].startswith('TEST-'):
            # TEST selection is an explicit different primary script/profile.
            from_primary = self.profile['orig_argv'][2:]
            expected = from_primary
        if list(config.invocation_params.args) != expected:
            self.guard.refuse('primary_source_invocation_drift')
        if config.option.xmlpath is not None:
            self.guard.refuse('primary_source_foreign_junit')
        config.option.xmlpath = '/work/source.xml'
        self.collection_timer = threading.Timer(
            self.profile['source_budget']['collection_seconds'], lambda: os._exit(87))
        self.collection_timer.daemon = True
        self.collection_timer.start()

    def pytest_collection_modifyitems(self, session, config, items):
        self.before = [item.nodeid for item in items]
        yield
        self.after = [item.nodeid for item in items]

    def pytest_collection_finish(self, session):
        self.collection_timer.cancel()
        collected = [item.nodeid for item in session.items]
        Path('/work/collection.json').write_bytes(canonical(collected))
        if self.before != self.after or self.after != collected or self.deselected:
            self.guard.refuse('primary_source_collection_mutated')

    def pytest_deselected(self, items):
        self.deselected += len(items)

    def pytest_runtest_setup(self, item):
        self.guard._STATE['case'] = item.nodeid
        if item.nodeid == 'tests/test_server.py::test_composed_restart_stop_replacement_and_cancel_are_distinct':
            self.custodian = sys.modules['restart_custody'].start_custodian(
                Path(self.manifest['owned_root']))
            deadline = time.monotonic() + 8
            while not any(row['kind'] == 'custody_IPC_listener_ready'
                          and row['owner_pid'] == self.custodian.pid
                          for row in self.guard.summarize(self.profile['manifest'])['events']):
                if self.custodian.poll() is not None or time.monotonic() >= deadline:
                    self.guard.refuse('primary_source_custodian_not_ready')
                time.sleep(.01)

    def pytest_runtest_logreport(self, report):
        self.guard.append({'kind': 'test_outcome', 'nodeid': report.nodeid,
                           'phase': report.when, 'outcome': report.outcome})
        if report.when == 'teardown' and self.custodian is not None:
            self.endpoint.request('custody_close')
            status = self.custodian.wait(timeout=25)
            self.guard.append({'kind': 'root_actual_custodian_wait', 'pid': self.custodian.pid,
                               'numeric_returncode': status})
            self.custodian = None
            if status:
                self.guard.refuse('primary_source_custodian_status')
        if (report.when == 'teardown' and self.profile['source_mode'] == 'TEST-poison'
                and not self.poison_checked):
            self.poison_checked = True
            import subprocess
            try:
                subprocess.run(['/bin/true'], check=False)
            except BaseException:
                pass
            # Continue pytest normally. The observer and custody must refuse
            # despite a caught exception and an otherwise successful test.

    def pytest_sessionfinish(self, session, exitstatus):
        if self.collection_timer is not None:
            self.collection_timer.cancel()
        timer = threading.Timer(self.profile['source_budget']['drain_seconds'], lambda: os._exit(88))
        timer.daemon = True
        timer.start()
        try:
            summary = self.guard.observe_summary(self.profile['manifest'])
            summary['original_pytest_exit_code'] = int(exitstatus)
            Path('/work/summary.json').write_bytes(canonical(summary))
            roots = [row for row in summary['events'] if row['kind'] == 'ready' and row['token'] == 'root']
            if len(roots) != 1:
                self.guard.refuse('primary_source_root_ready_cardinality')
            provenance = {
                'schema': 'unrest.v046.primary-source-provenance.v1',
                'invocation_args': list(session.config.invocation_params.args),
                'collection_before': self.before, 'collection_after': self.after,
                'deselected': self.deselected, 'exitstatus': int(exitstatus),
                'root_ready_sha256': hashlib.sha256(canonical(roots[0])).hexdigest()}
            Path('/work/source-provenance.json').write_bytes(canonical(provenance))
        finally:
            timer.cancel()
