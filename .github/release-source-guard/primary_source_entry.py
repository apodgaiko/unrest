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
    nested_path = Path(guard._STATE['guard']).with_name('owned_nested_pytest.py')
    nested = guard.checked_source(nested_path, guard._STATE['direct_support']['files'][str(nested_path)])['owned']

    _pytest.config.get_config = config_factory(original, plugin, nested, guard)
    # Collection hooks observe the original list before and after all hooks;
    # neither hook returns replacement items or adds marks/options/selectors.
    plugin.pytest_collection_modifyitems.__func__.pytest_impl = {'wrapper': True, 'tryfirst': True}
    plugin.pytest_configure.__func__.pytest_impl = {'tryfirst': True}
    plugin.pytest_runtest_setup.__func__.pytest_impl = {'tryfirst': True}
    plugin.pytest_runtest_call.__func__.pytest_impl = {'tryfirst': True}
    assert pytest.console_main is not None


def config_factory(original, plugin, nested, guard):
    def get_config(args=None, plugins=None):
        config = original(args, plugins)
        # Only authenticated original negative sessions omit the outer observer.
        allowed = nested(guard, args, plugins)
        if type(allowed) is not bool:
            guard.refuse('primary_nested_verdict_type')
        if not allowed:
            config.pluginmanager.register(plugin, 'primary-source-observer')
        return config
    return get_config


class Observer:
    def __init__(self, guard, endpoint, manifest, profile):
        self.guard, self.endpoint = guard, endpoint
        self.manifest, self.profile = manifest, profile
        self.before, self.after = [], []
        self.deselected = 0
        self.custodian = None
        self.collection_timer = None
        self.failure_reports = 0
        self.session = None
        self.snapshot_rpc_started = {}
        self.snapshot_rpc_counts = {}
        self.negative_startup = None
        self.startup_stall_timer = None
        self.startup_stall_token = None
        guard._STATE['primary_snapshot_observer'] = self.observe_snapshot_rpc

    def observe_snapshot_rpc(self, frame, event, value):
        if (self.guard._STATE.get('case') or '').startswith(
                'tests/test_acp_cleanup.py::test_startup_failure_attribution_and_owned_cleanup['):
            if self.negative_startup is None:
                support = Path(self.guard._STATE['guard']).with_name('negative_startup.py')
                self.negative_startup = self.guard.checked_source(
                    support, self.guard._STATE['direct_support']['files'][str(support)])['observe']
            self.negative_startup(self.guard, self.endpoint.STATE, frame, event, value)
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

    def pytest_sessionstart(self, session):
        self.session = session

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

    def pytest_runtest_call(self, item):
        prefix = 'tests/test_acp_cleanup.py::test_startup_failure_attribution_and_owned_cleanup['
        startup = item.nodeid.startswith(prefix)
        cleanup = item.nodeid.startswith(tuple('tests/test_acp_cleanup.py::' + owner + '[' for owner in (
            'test_recorded_transport_failures', 'test_cleanup_faults_and_repeated_cancellation',
            'test_saved_review_observer_compatibility')))
        approval_seconds = None
        if item.nodeid.startswith('tests/test_approval_recovery.py::'):
            support = '/guard/finite/approval_stall_diagnostic.py'
            diagnostic = load('approval_stall_diagnostic', support,
                              self.manifest['direct_support']['files'][support])
            approval_seconds = diagnostic.case_seconds(self.profile, item.nodeid)
        if not startup and not cleanup and approval_seconds is None:
            return
        import asyncio
        loops = [v if isinstance(v, asyncio.AbstractEventLoop)
                 else getattr(v, '_loop', None) if type(v) is asyncio.Runner else None
                 for v in item.funcargs.values()]
        loop = next((v for v in loops if isinstance(v, asyncio.AbstractEventLoop)), None)
        token = object()
        self.startup_stall_token = token
        if approval_seconds is not None:
            def callback(token, case, loop):
                captured = self.retain_stall_snapshot(token, case, loop)
                if (captured and self.startup_stall_token is token
                        and self.guard._STATE.get('case') == case):
                    # Diagnostic TEST only: a failed isolated root, never a pass.
                    os._exit(89)
        else:
            callback = self.finish_startup_stall if startup else self.retain_stall_snapshot
        self.startup_stall_timer = threading.Timer(
            approval_seconds if approval_seconds is not None else 60 if startup else 10,
            lambda: callback(token, item.nodeid, loop))
        self.startup_stall_timer.daemon = True
        self.startup_stall_timer.start()

    def finish_startup_stall(self, token, case, loop):
        captured = self.retain_stall_snapshot(token, case, loop)
        if (captured and self.profile.get('source_mode') == 'SOURCE'
                and self.startup_stall_token is token and self.guard._STATE.get('case') == case):
            # End only this failed isolated root, after its private stack flush.
            # Missing results/waits remain failures; no certificate can issue.
            os._exit(89)

    def retain_stall_snapshot(self, token, case, loop):
        if self.startup_stall_token is not token or self.guard._STATE.get('case') != case:
            return
        try:
            import asyncio
            def location(frame):
                return [frame.f_code.co_filename, frame.f_code.co_name, frame.f_lineno]
            threads = []
            for frame in list(sys._current_frames().values())[:64]:
                stack = []
                while frame is not None and len(stack) < 24:
                    stack.append(location(frame))
                    frame = frame.f_back
                threads.append(stack)
            tasks = []
            if loop is not None:
                for task in list(asyncio.all_tasks(loop))[:64]:
                    coroutine, stack, seen = task.get_coro(), [], set()
                    while coroutine is not None and id(coroutine) not in seen and len(stack) < 24:
                        seen.add(id(coroutine))
                        frame = getattr(coroutine, 'cr_frame', None) or getattr(coroutine, 'gi_frame', None)
                        if frame is not None:
                            stack.append(location(frame))
                        coroutine = (getattr(coroutine, 'cr_await', None)
                                     or getattr(coroutine, 'gi_yieldfrom', None))
                    tasks.append({'done': task.done(), 'cancelling': task.cancelling(), 'stack': stack})
            body = canonical({'case': case, 'threads': threads, 'tasks': tasks})[:65536].decode(
                'utf-8', errors='ignore')
            if self.startup_stall_token is token:
                sys.__stderr__.write('\n[retained task snapshot]\n' + body + '\n')
                sys.__stderr__.flush()
                return True
        except (OSError, AttributeError, RuntimeError, UnicodeError):
            # Private stack diagnostics cannot change a test or its deadline.
            pass

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

    def retain_failure(self, report):
        # The command's stderr is already private encrypted evidence. Emit the
        # original report there now: a later hung test must not erase the first
        # failure by preventing pytest's terminal summary. No body enters events.
        if not report.failed or self.failure_reports >= 12:
            return
        self.failure_reports += 1
        try:
            body = report.longreprtext.encode('utf-8', errors='backslashreplace')
            body = body[:65536].decode('utf-8', errors='ignore')
            stream = sys.__stderr__
            stream.write('\n[retained original pytest failure]\n' + body + '\n')
            stream.flush()
        except (OSError, AttributeError, UnicodeError):
            # A diagnostic write cannot replace the original test result.
            pass

    def pytest_runtest_makereport(self, item, call):
        # Observe only the original oracle's already-failed metadata check.
        case = 'tests/test_experimental_candidate.py::test_literal_manifest_and_independent_oracle'
        if item.nodeid != case or call.when != 'call' or call.excinfo is None:
            return None
        error = call.excinfo.value
        if type(error).__name__ != 'CandidateInputError' or str(error) != 'unsupported_git_metadata':
            return None
        try:
            traceback = error.__traceback__
            for _ in range(128):
                if traceback is None:
                    break
                frame = traceback.tb_frame
                source = Path('/source/src/unrest_harness/experimental_candidate.py')
                if frame.f_code.co_filename == str(source) and frame.f_code.co_name == 'metadata':
                    name = frame.f_locals.get('name')
                    body = source.read_bytes()
                    compiled = compile(body, str(source), 'exec', dont_inherit=True)
                    owner_code = next(v for v in compiled.co_consts
                                      if type(v) is types.CodeType and v.co_name == '_Observation')
                    method_code = next(v for v in owner_code.co_consts
                                       if type(v) is types.CodeType and v.co_name == 'metadata')
                    owner = frame.f_globals.get('_Observation')
                    method = getattr(owner, 'metadata', None)
                    if (type(name) is str and len(name) <= 256
                            and all(part and part not in {'.', '..'}
                                    and all(c.isascii() and (c.isalnum() or c in '._-') for c in part)
                                    for part in name.split('/'))
                            and isinstance(method, types.FunctionType)
                            and method.__code__ is frame.f_code and method.__globals__ is frame.f_globals
                            and frame.f_code == method_code
                            and hashlib.sha256(body).hexdigest()
                            == self.manifest['product_pins']['src/unrest_harness/experimental_candidate.py']):
                        self.guard.append({'kind': 'candidate_metadata_refusal_entry', 'entry': name,
                                           'error_code': 'unsupported_git_metadata'})
                    break
                traceback = traceback.tb_next
        except (OSError, AttributeError, KeyError, TypeError, ValueError, RuntimeError, StopIteration):
            # Optional private diagnosis cannot replace the original failure.
            pass
        return None

    def pytest_runtest_logreport(self, report):
        if report.when in {'call', 'teardown'} and self.startup_stall_timer is not None:
            self.startup_stall_token = None
            self.startup_stall_timer.cancel()
            self.startup_stall_timer = None
        self.retain_failure(report)
        self.guard.append({'kind': 'test_outcome', 'nodeid': report.nodeid,
                           'phase': report.when, 'outcome': report.outcome})
        if report.failed and self.session is not None and not self.session.shouldfail:
            # pytest stops after this item's ordinary teardown, never mid-cleanup.
            self.session.shouldfail = 'original source failure retained; corrected full candidate required'
        if report.when == 'teardown' and self.custodian is not None:
            self.endpoint.request('custody_close')
            status = self.custodian.wait(timeout=25)
            self.guard.append({'kind': 'root_actual_custodian_wait', 'pid': self.custodian.pid,
                               'numeric_returncode': status})
            self.custodian = None
            if status:
                self.guard.refuse('primary_source_custodian_status')
    def pytest_sessionfinish(self, session, exitstatus):
        self.startup_stall_token = None
        if self.startup_stall_timer is not None:
            self.startup_stall_timer.cancel()
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
