"""Closed primary setup allocation and unchanged actual trace expiry ownership."""
import copy
import json
import os
from pathlib import Path
import signal
import sys
from types import SimpleNamespace

import pytest

sys.path.insert(0, str(Path(__file__).parent))
import linux_trace as trace
import primary_policy as policy
from primary_source_inputs import test_plan as make_test_plan
from test_primary_source_entry import inputs


def context(tmp_path, monkeypatch, mode='TEST-positive', cases=policy.TEST_SEAM_CASES):
    workflow, source = inputs()
    script = ('env -u CODEX_PATH uv run pytest -q' + ((' ' + ' '.join(cases)) if cases else '')).encode()
    support = Path(__file__).parent
    pins = {str(p.relative_to(support)): policy.sha(p.read_bytes())
            for p in sorted(support.rglob('*'))
            if p.is_file() and p.suffix in {'.py', '.json', '.pem', '.c'}}
    expected = source['definition']
    expected['guard_definition_sha256'] = policy.sha(json.dumps(pins, sort_keys=True).encode())
    identity = {'repository': 'apodgaiko/unrest', 'head_sha': expected['head_sha'],
                'workflow_sha': expected['head_sha'], 'run_id': '1', 'run_attempt': '1',
                'support_sha256': policy.sha(policy.canonical(pins)),
                'artifact_name': 'v046-source-primary-source' + ('-' + mode.removeprefix('TEST-') if mode else '') + '-1-1',
                'workflow_ref': 'apodgaiko/unrest/.github/workflows/v046-source-readiness.yml@refs/heads/codex/source-guard-structured-20261018-root-allocation-01'}
    spec = make_test_plan(script, workflow, mode) if mode else policy.plan(script, workflow, source)
    bodies = {'/inputs/github-script.sh': script, '/source/.github/workflows/ci.yml': workflow.encode(),
              '/inputs/identity.json': policy.canonical(expected), '/inputs/plan.json': policy.canonical(spec),
              '/inputs/transport-identity.json': policy.canonical({'identity': identity, 'invocation_sha256': 'f' * 64}),
              '/source/.git/HEAD': (expected['head_sha'] + '\n').encode()}
    if mode:
        bodies['/inputs/test-mode'] = mode.encode()
    else:
        bodies['/inputs/source-input.json'] = policy.canonical(source)
    for name, body in bodies.items():
        target = tmp_path / name.lstrip('/')
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(body)
    def mapped(name):
        text = str(name)
        return tmp_path / text.lstrip('/') if text.startswith(('/inputs/', '/source/')) else Path(name)
    monkeypatch.setattr(policy, 'Path', mapped)
    allowed = [{'pid': 123, 'path': spec['shell_argv'][0], 'argv': spec['shell_argv']}]
    return spec, allowed, mapped


@pytest.mark.parametrize('mode', ['TEST-positive', 'TEST-poison', None])
def test_exact_fixed_allocations_and_immutable_binding(tmp_path, monkeypatch, mode):
    spec, allowed, _ = context(tmp_path, monkeypatch, mode, policy.TEST_SEAM_CASES if mode else ())
    allocation = policy.primary_root_allocation()
    assert allocation.seconds == spec['timeout_seconds'] == (600 if mode else 7200)
    policy.require_primary_root_allocation(allocation, allocation.seconds, 123, allowed)
    with pytest.raises(AttributeError):
        allocation.seconds = 601
    with pytest.raises(ValueError):
        policy.require_primary_root_allocation(tuple(allocation), allocation.seconds, 123, allowed)
    with pytest.raises(ValueError):
        policy.require_primary_root_allocation(allocation._replace(binding_sha256='0' * 64), allocation.seconds, 123, allowed)


@pytest.mark.parametrize('field', ['plan', 'script', 'mode', 'head', 'support', 'workflow', 'readiness'])
def test_stale_foreign_or_mutated_inputs_refuse(tmp_path, monkeypatch, field):
    spec, allowed, path = context(tmp_path, monkeypatch, None if field == 'readiness' else 'TEST-positive',
                                  () if field == 'readiness' else policy.TEST_SEAM_CASES)
    allocation = policy.primary_root_allocation()
    if field == 'plan':
        spec['timeout_seconds'] = 601
        path('/inputs/plan.json').write_bytes(policy.canonical(spec))
    elif field == 'script':
        path('/inputs/github-script.sh').write_bytes(b'env -u CODEX_PATH uv run pytest -q')
    elif field == 'mode':
        path('/inputs/test-mode').write_text('TEST-poison')
    elif field == 'head':
        path('/source/.git/HEAD').write_text('0' * 40 + '\n')
    elif field == 'support':
        value = json.loads(path('/inputs/transport-identity.json').read_bytes())
        value['identity']['support_sha256'] = '0' * 64
        path('/inputs/transport-identity.json').write_bytes(policy.canonical(value))
    elif field == 'workflow':
        with path('/source/.github/workflows/ci.yml').open('a') as stream:
            stream.write('\n')
    else:
        path('/inputs/source-input.json').unlink()
    with pytest.raises((ValueError, RuntimeError, KeyError, TypeError)):
        policy.require_primary_root_allocation(allocation, allocation.seconds, 123, allowed)


@pytest.mark.parametrize('timeout', [True, False, -1, 0, 181, 601, 600.0, 7201, float('nan'), float('inf'), 10**1000])
def test_no_raw_or_mismatched_budget_override(tmp_path, monkeypatch, timeout):
    _, allowed, _ = context(tmp_path, monkeypatch)
    allocation = policy.primary_root_allocation()
    with pytest.raises(ValueError):
        policy.require_primary_root_allocation(allocation, timeout, 123, allowed)


def test_one_case_and_six_focused_duties_keep_180(tmp_path, monkeypatch):
    spec, _, _ = context(tmp_path, monkeypatch, cases=(policy.TEST_CASE,))
    assert spec['timeout_seconds'] == 180
    with pytest.raises(ValueError):
        policy.primary_root_allocation()
    from ci_commands import REGISTRY
    from test_ci_commands import workflow
    registry = json.loads(REGISTRY.read_bytes())
    for name in policy.FOCUSED:
        script = (registry[name] if '\n' in registry[name].rstrip('\n') else registry[name].removesuffix('\n')).encode()
        assert policy.plan(script, workflow(registry))['timeout_seconds'] == 180
    assert policy.SOURCE_BUDGET == {'root_seconds': 7200, 'collection_seconds': 300, 'drain_seconds': 60}


@pytest.mark.parametrize('change', ['shell', 'command', 'hash', 'tuple', 'allocation', 'foreign'])
def test_plan_and_root_command_boundaries(tmp_path, monkeypatch, change):
    spec, allowed, path = context(tmp_path, monkeypatch)
    allocation = policy.primary_root_allocation()
    if change == 'shell':
        spec['shell_argv'] = ['/bin/bash', '/foreign']
    elif change == 'command':
        spec['commands'][0].append('-x')
    elif change == 'hash':
        spec['script_sha256'] = '0' * 64
    elif change == 'tuple':
        spec['commands'][0][7:] = spec['commands'][0][7:][::-1]
    elif change == 'allocation':
        spec['timeout_seconds'] = 7200
    else:
        allowed = copy.deepcopy(allowed)
        allowed[0]['argv'].append('foreign')
    path('/inputs/plan.json').write_bytes(policy.canonical(spec))
    with pytest.raises(ValueError):
        policy.require_primary_root_allocation(allocation, allocation.seconds, 123, allowed)


def constructor_platform(monkeypatch):
    monkeypatch.setattr(trace.sys, 'platform', 'linux')
    monkeypatch.setattr(trace.os, 'uname', lambda: SimpleNamespace(machine='x86_64'))
    monkeypatch.setattr(trace, 'Path', lambda name: SimpleNamespace(read_text=lambda: f'PPid:\t{os.getpid()}\n'))


@pytest.mark.parametrize('timeout', [181, 600, 601, 7200, True, float('nan'), float('inf'), -1, 10**1000])
def test_generic_constructor_still_refuses_before_proc(monkeypatch, timeout):
    constructor_platform(monkeypatch)
    monkeypatch.setattr(trace, 'Path', lambda name: pytest.fail('refusal must precede proc'))
    with pytest.raises(ValueError, match='bounded owned trace'):
        trace.OwnedTrace(123, [], timeout)


def test_generic_180_constructor_unchanged(monkeypatch):
    constructor_platform(monkeypatch)
    assert trace.OwnedTrace(123, [], 180).timeout == 180


@pytest.mark.parametrize('seconds', [600, 7200])
def test_actual_run_fixed_expiry_kills_drains_and_waits(tmp_path, monkeypatch, seconds):
    spec, allowed, _ = context(tmp_path, monkeypatch, 'TEST-positive' if seconds == 600 else None,
                               policy.TEST_SEAM_CASES if seconds == 600 else ())
    allocation = policy.primary_root_allocation()
    constructor_platform(monkeypatch)
    clock = iter([0, seconds, seconds + .001])
    monkeypatch.setattr(trace.time, 'monotonic', lambda: next(clock))
    monkeypatch.setattr(trace.time, 'sleep', lambda duration: None)
    monkeypatch.setattr(trace._observation, 'process_identity', lambda pid: {'pid': pid})
    calls, waits, ticks = [], [], []
    monkeypatch.setattr(trace, 'ptrace', lambda request, pid, **kw: calls.append((request, pid)))
    responses = iter([(123, (signal.SIGSTOP << 8) | 0x7f), (0, 0), (123, signal.SIGKILL)])
    def wait(pid, flags):
        waits.append((pid, flags))
        return next(responses)
    monkeypatch.setattr(trace.os, 'waitpid', wait)
    owned = trace.OwnedTrace(123, allowed, spec['timeout_seconds'], primary_allocation=allocation,
                             on_tick=lambda current: ticks.append(current.timeout))
    with pytest.raises(TimeoutError, match='owned trace deadline exceeded'):
        owned.run()
    assert ticks == [seconds, seconds]  # Equality retains the original strict expiry boundary.
    assert calls == [(0x4200, 123), (24, 123), (8, 123)]
    assert waits == [(123, 0), (123, os.WNOHANG | 0x40000000), (-1, 0x40000000)]
    assert owned.root_parent_wait == signal.SIGKILL and owned.active == set()
    assert owned.records[-1]['kind'] == 'failure_cleanup_tracer_wait'
    assert owned.records[-1]['root_original_parent'] is True


@pytest.mark.skipif(sys.platform != 'linux', reason='requires owned Linux ptrace child')
@pytest.mark.parametrize('seconds', [600, 7200])
def test_linux_owned_child_fixed_expiry(tmp_path, monkeypatch, seconds):
    _, _, _ = context(tmp_path, monkeypatch, 'TEST-positive' if seconds == 600 else None,
                       policy.TEST_SEAM_CASES if seconds == 600 else ())
    allocation = policy.primary_root_allocation()
    child = os.fork()
    if child == 0:
        trace.trace_me()
        while True:
            signal.pause()
    allowed = [{'pid': child, 'path': allocation.shell_argv[0], 'argv': list(allocation.shell_argv)}]
    clock = iter([0, seconds + .001])
    monkeypatch.setattr(trace.time, 'monotonic', lambda: next(clock))
    owned = trace.OwnedTrace(child, allowed, seconds, primary_allocation=allocation)
    with pytest.raises(TimeoutError):
        owned.run()
    assert owned.root_parent_wait == signal.SIGKILL and not owned.active
    with pytest.raises(ChildProcessError):
        os.waitpid(child, os.WNOHANG)


@pytest.mark.parametrize('field', ['artifact_name', 'head_sha', 'support_sha256'])
def test_wrong_identity_cannot_issue_allocation(tmp_path, monkeypatch, field):
    _, _, path = context(tmp_path, monkeypatch)
    value = json.loads(path('/inputs/transport-identity.json').read_bytes())
    value['identity'][field] = ('v046-source-primary-source-poison-1-1' if field == 'artifact_name'
                                else '0' * (40 if field == 'head_sha' else 64))
    path('/inputs/transport-identity.json').write_bytes(policy.canonical(value))
    with pytest.raises(ValueError):
        policy.primary_root_allocation()


@pytest.mark.parametrize('raw', [True, 600, {'seconds': 600}, (600, 'a' * 64, ('/bin/bash',))])
def test_constructor_raw_descriptor_refusal_precedes_proc(tmp_path, monkeypatch, raw):
    _, allowed, _ = context(tmp_path, monkeypatch)
    constructor_platform(monkeypatch)
    monkeypatch.setattr(trace, 'Path', lambda name: pytest.fail('refusal must precede proc'))
    with pytest.raises(ValueError, match='primary_root_allocation_refused'):
        trace.OwnedTrace(123, allowed, 600, primary_allocation=raw)


@pytest.mark.parametrize('seconds', [True, 600.0, 601, -1, float('nan'), float('inf'), 7200])
def test_supplied_plan_cannot_choose_its_budget(tmp_path, monkeypatch, seconds):
    spec, _, path = context(tmp_path, monkeypatch)
    spec['timeout_seconds'] = seconds
    path('/inputs/plan.json').write_bytes(policy.canonical(spec))
    with pytest.raises(ValueError):
        policy.primary_root_allocation()


@pytest.mark.parametrize('mode', ['SOURCE', 'TEST-foreign', '', 'TEST-positive\n'])
def test_foreign_mode_refuses(tmp_path, monkeypatch, mode):
    _, _, path = context(tmp_path, monkeypatch)
    path('/inputs/test-mode').write_text(mode)
    with pytest.raises(RuntimeError):
        policy.primary_root_allocation()


@pytest.mark.parametrize('suffix', ['01', '02', '03', '04', '01-extra', '', 'foreign'])
def test_new_controller_refs_are_exact(suffix):
    import ast
    tree = ast.parse(Path(__file__).with_name('ci_shell.py').read_bytes())
    gate = next(node for node in ast.walk(tree) if isinstance(node, ast.If)
                and isinstance(node.body[0], ast.Raise)
                and any(isinstance(child, ast.Constant) and child.value == 'primary_test_workflow_identity'
                        for child in ast.walk(node.body[0])))
    environment = {'GITHUB_WORKFLOW': 'v0.4.6 source guard readiness',
                   'GITHUB_REF': 'refs/heads/codex/source-guard-structured-20261018-root-allocation-' + suffix}
    refused = eval(compile(ast.Expression(gate.test), 'actual_controller_ref_gate', 'eval'),
                   {'os': SimpleNamespace(environ=environment)})
    assert refused is (suffix not in {'01', '02', '03'})


# The historical whole-engine oracle keeps its original hash. Normalize only
# the separately pinned, explicitly allocated constructor plus its math import.
LEGACY_CONSTRUCTOR = 'def __init__(self, child: int, allowed: list[dict[str, Any]], timeout: float,\n                 on_tick: Any = None, resolve_exec: Any = None,\n                 seize: bool = False, on_attached: Any = None, selective: bool = False):\n        if sys.platform != "linux" or os.uname().machine != "x86_64":\n            raise RuntimeError("unsupported trace ABI")\n        if child <= 0 or timeout <= 0 or timeout > 180:\n            raise ValueError("bounded owned trace required")\n        if Path(f"/proc/{child}/status").read_text().split("PPid:", 1)[1].split()[0] != str(\n            os.getpid()\n        ):\n            raise RuntimeError("trace root is not a direct child")\n        self.child = child\n        self.allowed = allowed\n        self.timeout = timeout\n        self.on_tick = on_tick\n        self.resolve_exec = resolve_exec\n        self.selective = selective\n        self.seize = seize\n        self.on_attached = on_attached\n        self.root_parent_wait: int | None = None\n        self.records: list[dict[str, Any]] = []\n        self.diagnostic_trace = DiagnosticTrace()\n        self.poison: list[str] = []\n        self.active = {child}\n        self.pending: dict[int, dict[str, Any]] = {}\n        self.denied: set[int] = set()\n        self.newborn: set[int] = set()\n        self.identities: dict[int, dict[str, Any]] = {}'
ALLOCATED_CONSTRUCTOR_AST = '4c731bd5f91fbb41af9e3c77800e60d1db0ad78525acba399c3900d43400a69e'


def restore_primary_allocation(tree):
    import ast
    import hashlib
    cls = next(node for node in tree.body if isinstance(node, ast.ClassDef) and node.name == 'OwnedTrace')
    constructor = next(node for node in cls.body if isinstance(node, ast.FunctionDef) and node.name == '__init__')
    assert hashlib.sha256(ast.dump(constructor, include_attributes=False).encode()).hexdigest() == ALLOCATED_CONSTRUCTOR_AST
    original = ast.parse(LEGACY_CONSTRUCTOR).body[0]
    cls.body[cls.body.index(constructor)] = original
    imports = [node for node in tree.body if isinstance(node, ast.Import)
               and len(node.names) == 1 and node.names[0].name == 'math' and node.names[0].asname is None]
    assert len(imports) == 1
    tree.body.remove(imports[0])
    return tree


def test_legacy_normalization_cannot_hide_constructor_or_execution_changes():
    import ast
    import hashlib
    import test_startup_phases as baseline
    source = Path(__file__).with_name('linux_trace.py').read_text()
    original = baseline.StripTelemetry().visit(baseline.restore_before_numeric_wait(restore_primary_allocation(baseline.restore_environment_name_grammar(ast.parse(source)))))
    assert hashlib.sha256(ast.dump(original, include_attributes=False).encode()).hexdigest() == baseline.BASELINE_AST_SHA256['linux_trace.py']
    for before, after in [('timeout > 180', 'timeout > 181'),
                          ('primary_allocation is None', 'primary_allocation is not None')]:
        assert before in source
        with pytest.raises(AssertionError):
            restore_primary_allocation(ast.parse(source.replace(before, after)))
    changed = source.replace('raise TimeoutError("owned trace deadline exceeded")', 'pass')
    assert changed != source
    tree = baseline.StripTelemetry().visit(baseline.restore_before_numeric_wait(restore_primary_allocation(baseline.restore_environment_name_grammar(ast.parse(changed)))))
    assert hashlib.sha256(ast.dump(tree, include_attributes=False).encode()).hexdigest() != baseline.BASELINE_AST_SHA256['linux_trace.py']
