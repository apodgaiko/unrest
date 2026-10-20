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
    receipt = Path('/receipts/primary-startup') / (str(os.getpid()) + '.child-relative.json')
    if receipt.exists():
        import stat
        info = receipt.lstat()
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != 20001
                or stat.S_IMODE(info.st_mode) != 0o444 or info.st_nlink != 1 or info.st_size > 65536):
            os._exit(86)
        context = json.loads(receipt.read_bytes())
        if (type(context) is not dict or set(context) != {
                'schema', 'token', 'identity', 'view', 'constructor', 'prebody_required', 'allowed', 'refusal'}
                or context['schema'] != 'unrest.v047.child-relative-prebody.v1'):
            os._exit(86)
        if context.get('allowed') is not True:
            diagnostic = Path('/work') / ('primary-native-state-' + str(os.getpid()) + '.json')
            observed = json.loads(diagnostic.read_bytes())
            observed['child_relative_prebody_refusal'] = {
                'token': context['token'], 'receipt_sha256': hashlib.sha256(receipt.read_bytes()).hexdigest()}
            diagnostic.write_text(json.dumps(observed, sort_keys=True))
            os._exit(86)
        support = Path('/guard/finite/child_relative_view.py')
        module = load('child_relative_view', str(support),
                      manifest['direct_support']['files'][str(support)])
        birth = context['identity']
        try:
            actual_view = module.view()
        except (OSError, RuntimeError, ValueError, KeyError):
            os._exit(86)
        if (birth['pid'] != profile['pid'] or birth['ppid'] != profile['parent']
                or birth['start_ticks'] != profile['start_ticks']
                or birth['boot_id'] != profile['boot_id'] or not context['prebody_required']
                or birth['uid'] != os.geteuid() or os.getresuid() != (20000, 20000, 20000)
                or os.getresgid() != (20000, 20000, 20000)
                or not module.child_matches(actual_view, context['view'])
                or context['constructor']['token'] != context['token']
                or context['constructor']['original_cwd'] is not None
                or context['constructor']['constructor_cwd'] != '.'
                or context['constructor']['argv_sha256'] != hashlib.sha256(
                    json.dumps(profile['orig_argv']).encode()).hexdigest()):
            os._exit(86)
        diagnostic = Path('/work') / ('primary-native-state-' + str(os.getpid()) + '.json')
        observed = json.loads(diagnostic.read_bytes())
        observed['child_relative_prebody'] = {
            'token': context['token'], 'view': actual_view,
            'receipt_sha256': hashlib.sha256(receipt.read_bytes()).hexdigest()}
        diagnostic.write_text(json.dumps(observed, sort_keys=True))
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
        self.snapshot_rpc_started = {}
        self.snapshot_rpc_counts = {}
        guard._STATE['primary_snapshot_observer'] = self.observe_snapshot_rpc

    def observe_snapshot_rpc(self, frame, event, value):
        if (self.guard._STATE.get('case') != 'tests/test_server.py::test_composed_restart_stop_replacement_and_cancel_are_distinct'
                or frame.f_code.co_filename != '/source/tests/test_server.py'
                or frame.f_code.co_name != '_call_process_mcp'
                or event not in {'call', 'return'}):
            return
        method = frame.f_locals.get('name')
        if method not in {'inspect_run', 'inspect_project'} or self.snapshot_rpc_counts.get(method, 0) >= 2:
            return
        original = frame.f_globals.get('_call_process_mcp')
        module = sys.modules.get(frame.f_globals.get('__name__'))
        if (module is None or vars(module) is not frame.f_globals
                or getattr(original, '__code__', None) is not frame.f_code
                or getattr(original, '__globals__', None) is not frame.f_globals):
            return
        if event == 'call':
            if len(self.snapshot_rpc_started) < 4:
                self.snapshot_rpc_started[id(frame)] = time.monotonic_ns()
            return
        started = self.snapshot_rpc_started.pop(id(frame), None)
        if started is None or type(value) is not dict:
            return
        attempts = value.get('active_attempts')
        if type(attempts) is not list or len(attempts) != 1 or type(attempts[0]) is not dict:
            return
        snapshot = attempts[0]
        if (snapshot.get('role') != 'worker' or snapshot.get('checkpoint_sequence') != 1
                or snapshot.get('phase') not in {'active', 'waiting_at_checkpoint'}
                or type(snapshot.get('elapsed_nanoseconds')) is not int
                or snapshot['elapsed_nanoseconds'] < 0):
            return
        if self.guard.digest('/source/tests/test_server.py') != self.manifest['product_pins']['tests/test_server.py']:
            self.guard.refuse('primary_snapshot_source_drift')
        identity = {k: snapshot.get(k) for k in ('project_id', 'mission_id', 'node_id', 'attempt_id', 'role')}
        self.snapshot_rpc_counts[method] = self.snapshot_rpc_counts.get(method, 0) + 1
        self.guard.append({'kind': 'primary_composed_snapshot_rpc', 'method': method,
                           'start_monotonic_ns': started, 'return_monotonic_ns': time.monotonic_ns(),
                           'elapsed_nanoseconds': snapshot['elapsed_nanoseconds'],
                           'checkpoint_sequence': 1, 'phase': snapshot['phase'],
                           'snapshot_sha256': hashlib.sha256(canonical(snapshot)).hexdigest(),
                           'identity_sha256': hashlib.sha256(canonical(identity)).hexdigest()})

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
        if config.option.basetemp is not None:
            self.guard.refuse('primary_source_foreign_basetemp')
        # The original finite Git/custody predicates require this exact owned
        # pytest subtree, as in the existing focused source runner. This is a
        # filesystem setup option, not an item/mark/selection transformation.
        config.option.basetemp = self.manifest['owned_root'] + '/pytest'
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

    def pytest_assertrepr_compare(self, config, op, left, right):
        case = 'tests/test_server.py::test_composed_restart_stop_replacement_and_cancel_are_distinct'
        if (self.guard._STATE.get('case') != case or op != '=='
                or getattr(self, 'snapshot_diagnostic_emitted', False)
                or type(left) is not list or type(right) is not list
                or len(left) != 1 or len(right) != 1
                or type(left[0]) is not dict or type(right[0]) is not dict):
            return None
        keys = {'attempt_id', 'blocker_code', 'checkpoint_requests', 'checkpoint_sequence',
                'completed_target_ids', 'elapsed_nanoseconds', 'last_effect_sequence',
                'mission_id', 'node_id', 'phase', 'project_id', 'remaining_target_ids',
                'role', 'scope_status', 'supervision_status', 'terminal_review_id'}
        if set(left[0]) != keys or set(right[0]) != keys:
            return None
        differences = sorted(k for k in keys if left[0][k] != right[0][k])
        numeric = {'checkpoint_requests', 'checkpoint_sequence', 'elapsed_nanoseconds',
                   'last_effect_sequence'}
        statuses = {'active', 'waiting_at_checkpoint', 'stopping', 'terminal',
                    'running', 'waiting', 'stop_requested', 'in_scope', 'scope_drift'}
        values = {}
        for key in differences:
            pair = [left[0][key], right[0][key]]
            if key in numeric and all(type(v) is int and v >= 0 for v in pair):
                values[key] = pair
            elif key in {'phase', 'supervision_status', 'scope_status'} and all(
                    type(v) is str and v in statuses for v in pair):
                values[key] = pair
        self.snapshot_diagnostic_emitted = True
        self.guard.append({'kind': 'primary_composed_snapshot_difference',
                           'source_path': 'tests/test_server.py', 'line': 3869,
                           'exception_class': 'AssertionError',
                           'cardinalities': [len(left), len(right)],
                           'differing_keys': differences, 'values': values,
                           'operand_sha256': [hashlib.sha256(canonical(v)).hexdigest()
                                              for v in (left, right)]})
        return None

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
    def pytest_sessionfinish(self, session, exitstatus):
        if self.collection_timer is not None:
            self.collection_timer.cancel()
        timer = threading.Timer(self.profile['source_budget']['drain_seconds'], lambda: os._exit(88))
        timer.daemon = True
        timer.start()
        try:
            if self.profile['source_mode'] == 'TEST-poison':
                import subprocess
                try:
                    subprocess.run(['/bin/true'], check=False)
                except BaseException:
                    pass
                # Preserve the original test's successful return. The capsule
                # must still fail from the caught guard refusal below.
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
