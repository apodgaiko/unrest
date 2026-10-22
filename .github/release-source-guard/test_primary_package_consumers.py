"""Package-only native domains and the exact original scripts stay closed."""
from __future__ import annotations

import ast
import hashlib
import json
from pathlib import Path
from types import ModuleType, SimpleNamespace

import pytest
import yaml

from primary_custody import INSTALLED, CHECKSUM, WHEEL, SDIST

ROOT = Path(__file__).parent


def shell():
    class Base:
        def refuse(self, code):
            self.denials.append(code)
            return False
        def resolve(self, *args):
            raise AssertionError('unknown execution reached original authority')
    path = ROOT / 'primary_package_shell.py'
    nodes = [n for n in ast.parse(path.read_bytes()).body if isinstance(n, (ast.FunctionDef, ast.ClassDef))]
    module = ModuleType('controlled_shell')
    module.__dict__.update(Authority=Base, INSTALLED=INSTALLED, CHECKSUM=CHECKSUM,
                           WHEEL=WHEEL, SDIST=SDIST, Path=Path, hashlib=hashlib, json=json,
                           PREFIX='/source/.wheel-venv', UNSET=('ANTHROPIC_API_KEY',))
    module.LIFECYCLE = ['env', '-u', 'ANTHROPIC_API_KEY', '/source/.wheel-venv/bin/python',
                        '-m', 'unrest_harness.installed_wheel_check']
    exec(compile(ast.Module(body=nodes, type_ignores=[]), str(path), 'exec'), module.__dict__)
    return module


@pytest.mark.parametrize('duty', [INSTALLED, CHECKSUM])
def test_workflow_runs_literal_original_package_script(duty):
    registry = json.loads((ROOT / 'ci_commands.json').read_text())
    workflow_path = (ROOT.parent / 'metadata/source-readiness-workflow.yml' if ROOT.name == 'guard'
                     else ROOT.parent / 'workflows/v046-source-readiness.yml')
    workflow = yaml.safe_load(workflow_path.read_text())
    steps = workflow['jobs']['compartment-controls']['steps']
    matches = [row for row in steps if row.get('run') == registry[duty]]
    assert len(matches) == 1
    assert matches[0]['shell'] == 'python3 .github/release-source-guard/ci_shell.py --package-test {0}'


@pytest.mark.parametrize('field', ['foreign-key', 'cwd', 'underscore', 'unsupported', 'credential'])
def test_shell_environment_cannot_add_credentials_or_redirect_execution(field):
    module = shell()
    original = {'PATH': '/fixed', 'HOME': '/owned'}
    actual = {**original, 'PWD': '/source/dist', '_': '/usr/bin/sha256sum', 'SHLVL': '1'}
    assert module.environment_matches(actual, original, '/source/dist', '/usr/bin/sha256sum')
    if field == 'foreign-key':
        actual['FOREIGN'] = '1'
    elif field == 'cwd':
        actual['PWD'] = '/foreign'
    elif field == 'underscore':
        actual['_'] = '/foreign'
    elif field == 'unsupported':
        actual['UNREST_CAPABILITY_PROFILE'] = 'unsupported'
    else:
        actual['OPENAI_API_KEY'] = 'canary'
    assert not module.environment_matches(actual, original, '/source/dist', '/usr/bin/sha256sum')


@pytest.mark.parametrize('vector', [['python', '-c', 'pass'], ['uv', 'venv', '--clear', '.wheel-venv'],
                                  ['claude'], ['codex'], ['sha256sum', 'foreign'], ['env', 'python']])
def test_completed_or_unknown_shell_path_never_falls_back_to_generic_native_admission(vector):
    module = shell()
    owner = module.PackageShellAuthority.__new__(module.PackageShellAuthority)
    owner.contexts, owner.denials = {}, []
    owner.pending_env = None
    owner.operation_index = 2
    owner.operations = module.operations(CHECKSUM)
    trace = SimpleNamespace(identities={12: {'ppid': 7}})
    assert owner.resolve(trace, 12, '/foreign', vector, {}, '/source/dist') is False
    assert owner.denials == ['package_shell_unknown_exec']


@pytest.mark.parametrize('name', ['cohort3_plan.py', 'cohort_plan.py'])
def test_actual_original_cohort_selector_reproduces_none_case_and_accepts_bound_package_case(name):
    path = ROOT / 'finite' / name
    node = next(n for n in ast.parse(path.read_bytes()).body if isinstance(n, ast.FunctionDef) and n.name == 'select')
    namespace = {'Path': Path, 'Any': object}
    exec(compile(ast.Module(body=[node], type_ignores=[]), str(path), 'exec'), namespace)
    with pytest.raises(AttributeError):
        namespace['select']([], None, None, {'checkout': '/source', 'case': None}, None, None)
    assert namespace['select']([], None, None, {'checkout': '/source', 'case': 'PRIMARY-package-TEST'}, None, None) is None


def test_package_archive_entry_binds_case_without_changing_original_guard():
    tree = ast.parse((ROOT / 'primary_package_entry.py').read_bytes())
    call = next(n for n in ast.walk(tree) if isinstance(n, ast.Call) and ast.unparse(n.func) == 'guard.install')
    assert {keyword.arg: ast.unparse(keyword.value) for keyword in call.keywords} == {
        'command_class': "'source-checker'", 'case': "manifest['source_case']"}
    assert hashlib.sha256((ROOT / 'finite/runtime_guard.py').read_bytes()).hexdigest() == '68abd1e8ca8b2fed37a2fd2298dc39c1e8d822fa3c4065ceb53bc6a54e0684eb'


def test_installed_public_metadata_contains_hashes_instead_of_private_fixture_ids(monkeypatch):
    import checkpoint_issuer
    import primary_package_probe as probe
    from primary_custody import canonical
    from test_primary_custody import records
    from test_checkpoint_issuer import archives
    data = records(INSTALLED, archives())
    kernel = json.loads(data['kernel-source.json'])
    kernel['primary_plan'].update(package_mode='TEST')
    kernel.update(guard_poison=False, receipt_ledger_poison=[],
                  native_source_records=[{'kind': 'primary_package_installed_corruption',
                                          'corrupt_state_refused': True, 'original_bytes_restored': True}])
    data['kernel-source.json'] = canonical(kernel)
    proof = {'result': {'attempts': 2, 'terminal_reviews': 1, 'restart_resume': True, 'state': 'done',
                        'mission_id': 'private-fixture-mission-canary', 'project_id': 'private-fixture-project-canary'}}
    data['package-proof.json'] = canonical(proof)
    monkeypatch.setattr(checkpoint_issuer, 'observed_return', lambda *a: None)
    result = probe.check_installed(data)
    assert 'private-fixture-' not in json.dumps(result)
    assert result['original_return_sha256'] == hashlib.sha256(canonical(proof)).hexdigest()


@pytest.mark.parametrize('change', ['exact', 'foreign-path', 'foreign-cwd', 'foreign-parent',
                                  'foreign-image', 'foreign-program', 'foreign-environment'])
def test_relative_installed_uv_query_retains_actual_argv(monkeypatch, change):
    module = shell()
    module.PYTHON = '/usr/local/bin/python-primary-audit'
    module.digest = lambda path: 'a' * 64
    module.command_environment = lambda actual, initial, source: actual == initial
    module.query_package = lambda body, common: None if body == 'exact-query' else (_ for _ in ()).throw(ValueError())
    module.identity = lambda pid: {'pid': pid, 'ppid': 7}
    class Image:
        def resolve(self):
            return Path('/foreign' if change == 'foreign-image' else module.PYTHON)
    module.Path = lambda name: Image() if name == '/source/.wheel-venv/bin/python' else Path(name)
    owner = module.PackageShellAuthority.__new__(module.PackageShellAuthority)
    owner.operations = module.operations(INSTALLED)
    owner.operation_index = 2
    owner.pending_env = None
    birth = {'pid': 12, 'ppid': 7}
    owner.contexts = {12: {'role': 'uv', 'command': owner.operations[1], 'python_calls': 0, 'identity': birth}}
    owner.environment, owner.denials = {'PATH': '/fixed'}, []
    observed = []
    owner.profile = lambda *args, **kwargs: observed.append(args) or True
    trace = SimpleNamespace(identities={15: {'ppid': 12}})
    vector = ['.wheel-venv/bin/python', '-I', '-B', '-c', 'exact-query']
    cwd, environment = '/source', owner.environment
    if change == 'foreign-path':
        vector[0] = 'foreign/bin/python'
    elif change == 'foreign-cwd':
        cwd = '/foreign'
    elif change == 'foreign-parent':
        owner.contexts[12]['identity'] = {'pid': 99}
    elif change == 'foreign-program':
        vector[-1] = 'foreign-query'
    elif change == 'foreign-environment':
        environment = {'PATH': '/foreign'}
    if change == 'foreign-path':
        with pytest.raises(AssertionError, match='unknown execution|unknown execution reached|unknown'):
            owner.resolve(trace, 15, vector[0], vector, environment, cwd)
    else:
        assert owner.resolve(trace, 15, vector[0], vector, environment, cwd) is (change == 'exact')
    if change == 'exact':
        assert observed[0][2] is vector
        assert observed[0][2][0] == '.wheel-venv/bin/python'
    else:
        assert not observed


@pytest.mark.parametrize('change', ['exact', 'foreign-parent', 'wrong-image', 'executed-parent',
                                  'foreign-birth', 'capability', 'wrong-cwd', 'stale-script', 'incomplete'])
def test_final_command_substitution_is_one_current_original_shell_fork(change):
    module = shell()
    birth = {'pid': 104, 'ppid': 7, 'tgid': 104, 'start_ticks': 10, 'boot_id': 'boot',
             'uids': [20000] * 4, 'capabilities': {'CapEff': 0}, 'no_new_privs': 1}
    current = dict(birth)
    module.process_identity = lambda pid: current
    module.identity = lambda pid: {'pid': pid, 'ppid': current['ppid'], 'start_ticks': current['start_ticks'], 'boot_id': current['boot_id']}
    module.digest = lambda path: 'foreign' if (change == 'wrong-image' and path == '/proc/104/exe') or (change == 'stale-script' and path == '/inputs/github-script.sh') else 'a' * 64
    class Cwd:
        def resolve(self):
            return Path('/foreign' if change == 'wrong-cwd' else '/work/owned/tmp/tmp.exact')
    module.Path = lambda path: Cwd()
    owner = module.PackageShellAuthority.__new__(module.PackageShellAuthority)
    owner.plan = {'duty': INSTALLED, 'script_sha256': 'a' * 64}
    owner.operations, owner.operation_index = module.operations(INSTALLED), 9
    owner.contexts, owner.records, owner.root = {}, [], 7
    owner.unrelated = '/work/owned/tmp/tmp.exact'
    def complete(trace):
        if change == 'incomplete':
            raise RuntimeError('package_installed_incomplete')
    owner.source = SimpleNamespace(require_complete=complete)
    rows = [{'kind': 'kernel_child', 'child': 104, 'parent': 7, 'event': 1, 'identity': birth}]
    if change == 'foreign-parent':
        current['ppid'] = 99
    elif change == 'executed-parent':
        rows.append({'kind': 'kernel_exec', 'pid': 104})
    elif change == 'foreign-birth':
        current['start_ticks'] = 99
    elif change == 'capability':
        current['capabilities'] = {'CapEff': 1}
    if change == 'incomplete':
        with pytest.raises(RuntimeError, match='incomplete'):
            owner.substitution_parent(SimpleNamespace(records=rows), 104)
    else:
        assert owner.substitution_parent(SimpleNamespace(records=rows), 104) is (change == 'exact')
    if change == 'exact':
        assert owner.contexts[104]['role'] == 'package-shell-substitution'
        assert owner.records[0]['script_sha256'] == 'a' * 64
    else:
        assert not owner.contexts and not owner.records


@pytest.fixture
def pending_thread():
    import primary_package_trace as module
    birth = {'pid': 72, 'ppid': 7, 'tgid': 12, 'start_ticks': 10, 'boot_id': 'boot',
             'uids': [20000] * 4, 'capabilities': {'CapEff': 0}, 'no_new_privs': 1}
    group = {**birth, 'pid': 12, 'tgid': 12, 'start_ticks': 5}
    owner = SimpleNamespace(root=7, denials=[], operation_index=2,
                           plan={'package_mode': 'TEST', 'duty': INSTALLED},
                           operations=[[], module.COMMAND], contexts={12: {
                               'role': 'uv', 'command': module.COMMAND, 'identity': group}},
                           records=[{'kind': 'primary_package_shell_operation', 'pid': 12,
                                     'operation_index': 1, 'identity': group,
                                     'image_sha256': module.SOURCE_UV_ELF_SHA256}])
    trace = module.PackageInstalledTrace.__new__(module.PackageInstalledTrace)
    trace.package_authority, trace.child = owner, 7
    trace.identities, trace.active, trace.poison = {72: birth, 12: group}, {7, 12, 72}, []
    trace.records = [{'kind': 'kernel_child', 'child': 72, 'parent': 13,
                      'event': 3, 'identity': birth}]
    return module, trace


@pytest.mark.parametrize('change', ['exact', 'leader', 'foreign-group', 'image', 'generation',
                                  'capability', 'poison', 'wrong-phase', 'unobserved', 'duplicate'])
def test_terminal_retirement_never_grants_execution_or_substitutes_a_wait(pending_thread, change):
    import copy
    module, trace = pending_thread
    if change == 'leader':
        trace.identities[72] = {**trace.identities[72], 'tgid': 72}
    elif change == 'foreign-group':
        trace.package_authority.contexts.clear()
    elif change == 'image':
        trace.package_authority.records[0]['image_sha256'] = 'foreign'
    elif change == 'generation':
        trace.identities[12] = {**trace.identities[12], 'start_ticks': 99}
    elif change == 'capability':
        trace.identities[72]['capabilities'] = {'CapEff': 1}
    elif change == 'poison':
        trace.poison.append('original poison')
    elif change == 'wrong-phase':
        trace.package_authority.operation_index = 3
    elif change == 'unobserved':
        trace.records.clear()
    elif change == 'duplicate':
        trace.records.append({'kind': 'primary_package_thread_exit_pending', 'pid': 72})
    before = copy.deepcopy(trace.records)
    assert trace.defer_thread_exit(72, 'exit-message') is (change == 'exact')
    if change == 'exact':
        assert trace.active == {7, 12, 72}
        with pytest.raises(RuntimeError, match='actual_terminal_wait_missing'):
            module.verify_retirements(trace.records)
        trace.records.append({'kind': 'failure_cleanup_tracer_wait', 'pid': 72, 'raw': 0})
        with pytest.raises(RuntimeError, match='actual_terminal_wait_missing'):
            module.verify_retirements(trace.records)
        trace.records.append({'kind': 'tracer_terminal_wait', 'pid': 72, 'raw': 0,
                              'identity': trace.identities[72]})
        assert module.verify_retirements(trace.records) == 1
    else:
        assert trace.records == before


@pytest.mark.parametrize('operation', ['exit-message', 'exit-resume'])
@pytest.mark.parametrize('algorithm', ['original', 'package'])
def test_real_owned_loop_collects_terminal_status_after_exit_stop_esrch(pending_thread, monkeypatch, operation, algorithm):
    import ctypes
    import errno
    import os
    import signal
    from linux_trace import DiagnosticTrace
    module, trace = pending_thread
    identities = {**trace.identities, 7: {**trace.identities[12], 'pid': 7, 'tgid': 7, 'ppid': 1}}
    trace.identities, trace.active, trace.records = {}, {7}, []
    trace.seize, trace.selective, trace.timeout = True, True, 180
    trace.on_attached, trace.on_tick = None, None
    trace.pending, trace.newborn = {}, set()
    trace.root_parent_wait, trace.diagnostic_trace = None, DiagnosticTrace()
    def stopped(event):
        return (event << 16) | (signal.SIGTRAP << 8) | 0x7f
    events = [(7, stopped(128)), (7, stopped(1)), (12, stopped(3)),
              (72, stopped(128)), (72, stopped(6)), (72, 0), (12, 0), (7, 0)]
    last = [None]
    def waitpid(pid, flags):
        if pid == -1:
            return min(trace.active), 0
        if events and pid == events[0][0]:
            value = events.pop(0)
            last[0] = value
            return value
        return 0, 0
    injected = []
    def ptrace(request, pid, address=0, data=0):
        if request == 0x4201:
            if pid in {7, 12}:
                ctypes.cast(data, ctypes.POINTER(ctypes.c_ulong))[0] = 12 if pid == 7 else 72
            elif operation == 'exit-message':
                injected.append((request, pid))
                raise ProcessLookupError(errno.ESRCH, 'controlled terminal race')
        if (operation == 'exit-resume' and request == 7 and pid == 72
                and last[0] == (72, stopped(6))):
            injected.append((request, pid))
            raise ProcessLookupError(errno.ESRCH, 'controlled terminal race')
        return 0
    controlled_os = SimpleNamespace(waitpid=waitpid, WNOHANG=os.WNOHANG,
        WIFEXITED=os.WIFEXITED, WIFSIGNALED=os.WIFSIGNALED, WIFSTOPPED=os.WIFSTOPPED,
        WSTOPSIG=os.WSTOPSIG, waitstatus_to_exitcode=os.waitstatus_to_exitcode)
    monkeypatch.setattr(module, 'os', controlled_os)
    monkeypatch.setattr(module, 'ptrace', ptrace)
    monkeypatch.setattr(module, '_observation', SimpleNamespace(process_identity=lambda pid: identities[pid]))
    if algorithm == 'original':
        import types
        from linux_trace import OwnedTrace
        original = types.FunctionType(OwnedTrace.run.__code__, {
            **OwnedTrace.run.__globals__, 'os': controlled_os, 'ptrace': ptrace,
            '_observation': SimpleNamespace(process_identity=lambda pid: identities[pid])})
        with pytest.raises(ProcessLookupError):
            original(trace)
        assert len(injected) == 1
        assert any(row['kind'] == 'failure_cleanup_tracer_wait' for row in trace.records)
        return
    result = trace.run()
    assert len(injected) == 1 and not events and result['root_parent_wait_raw'] == 0
    assert not trace.active and module.verify_retirements(result['records']) == 1
    assert not any(row['kind'] == 'failure_cleanup_tracer_wait' for row in result['records'])
    assert sum(row['kind'] == 'tracer_terminal_wait' and row['pid'] == 72
               and row['raw'] == 0 for row in result['records']) == 1


def test_package_loop_preserves_original_trace_algorithm_outside_terminal_boundary():
    import copy
    from test_startup_phases import restore_before_numeric_wait
    original = restore_before_numeric_wait(ast.parse((ROOT / 'linux_trace.py').read_bytes()))
    package = ast.parse((ROOT / 'primary_package_trace.py').read_bytes())
    def run(tree, name):
        owner = next(n for n in tree.body if isinstance(n, ast.ClassDef) and n.name == name)
        return next(n for n in owner.body if isinstance(n, ast.FunctionDef) and n.name == 'run')
    class StripRepair(ast.NodeTransformer):
        def visit_Try(self, node):
            node = self.generic_visit(node)
            if node.handlers and any(isinstance(n, ast.Attribute) and n.attr == 'defer_thread_exit'
                                     for handler in node.handlers for n in ast.walk(handler)):
                return node.body
            return node
        def visit_Expr(self, node):
            if isinstance(node.value, ast.Call) and ast.unparse(node.value.func) == 'verify_retirements':
                return None
            return node
    restored = StripRepair().visit(copy.deepcopy(run(package, 'PackageInstalledTrace')))
    assert ast.dump(restored, include_attributes=False) == ast.dump(run(original, 'OwnedTrace'), include_attributes=False)
