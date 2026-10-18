"""Local pure preparation controls; these do not establish SOURCE acceptance."""
import ast
import hashlib
import importlib.util
from pathlib import Path
import subprocess
import sys
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).parent
CHECKOUT = ROOT.parent.parent


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


custody = load('preparation_custody', ROOT / 'finite/restart_custody.py')
isolated = load('preparation_isolated', ROOT / 'finite/isolated_refusal.py')


class Refusal(RuntimeError):
    pass


@pytest.fixture
def setup(monkeypatch):
    source = CHECKOUT / 'src/unrest_harness/run_control.py'
    events, derived = [], []

    def original(path):
        derived.append(str(path))
        return isolated.source_code(path)

    # Exercise the existing guard cache implementation, without installing a
    # guard or manufacturing an admission frame/request.
    tree = ast.parse((ROOT / 'finite/runtime_guard.py').read_bytes())
    node = next(n for n in ast.walk(tree)
                if isinstance(n, ast.FunctionDef) and n.name == 'current_source_code')
    namespace = {'Path': Path, 'hashlib': hashlib, 'sys': sys,
                 'original_code_cache': {}, 'original_source_code': original}
    exec(compile(ast.Module(body=[node], type_ignores=[]), '<guard-cache>', 'exec'), namespace)

    def refuse(reason):
        events.append({'kind': 'poison', 'reason': reason})
        raise Refusal(reason)

    def forbidden(*args, **kwargs):
        raise AssertionError('preparation attempted an effect or admission')

    state = {'checkout': str(CHECKOUT), 'class': 'restart-custodian',
             'custody_pending': [], 'custody_retained': [],
             'product_pins': {'src/unrest_harness/run_control.py': custody.sha(source)},
             'isolated_source_code': namespace['current_source_code'],
             'isolated_named': isolated.named}
    guard = SimpleNamespace(_STATE=state, append=events.append, refuse=refuse,
                            GuardRefusal=Refusal, admit=forbidden, require_ready=forbidden)
    monkeypatch.setattr(subprocess, 'Popen', forbidden)
    monkeypatch.setitem(sys.modules, 'runtime_guard', guard)
    monkeypatch.setitem(sys.modules, 'endpoint', SimpleNamespace(
        request=lambda kind: {'closing': True} if kind == 'custody_poll' else forbidden()))
    monkeypatch.setitem(sys.modules, 'custody_ipc', SimpleNamespace(start=forbidden))
    return guard, events, derived, source


def test_prepare_moves_one_real_derivation_before_listener_and_keeps_fresh_reads(setup, monkeypatch):
    guard, events, derived, source = setup
    reads = []
    actual_sha = custody.sha

    def sha(path):
        reads.append(str(path))
        return actual_sha(path)

    monkeypatch.setattr(custody, 'sha', sha)

    def start():
        assert len(derived) == 1
        assert events[-1]['phase'] == 'source_preparation_complete'
        events.append({'kind': 'custody_IPC_listener_ready'})
        return lambda: events.append({'kind': 'IPC_closed'})

    monkeypatch.setattr(sys.modules['custody_ipc'], 'start', start)
    custody.serve()
    assert len(derived) == 1
    # The actual job uses this same accessor; preparation does not replace it.
    first = guard._STATE['isolated_source_code'](source)
    assert guard._STATE['isolated_source_code'](source) is first
    custody.prepare_source(guard)
    assert len(derived) == 1
    assert reads == [str(source)] * 4
    assert guard._STATE['custody_pending'] == guard._STATE['custody_retained'] == []
    assert events[-1]['phase'] == 'source_preparation_complete'
    assert not any(e['kind'] == 'poison' for e in events)


@pytest.mark.parametrize('drift', ['pin', 'code', 'missing', 'resolver-error', 'changed-after-read'])
def test_failure_poisons_before_listener_without_effects(setup, monkeypatch, drift):
    guard, events, _, source = setup
    state = guard._STATE
    if drift == 'pin':
        state['product_pins']['src/unrest_harness/run_control.py'] = '0' * 64
    elif drift == 'code':
        state['isolated_named'] = lambda *args: (lambda: None).__code__
    elif drift == 'missing':
        state['checkout'] = str(source.parent / 'absent')
    elif drift == 'resolver-error':
        def broken(path):
            raise ValueError('not published')
        state['isolated_source_code'] = broken
    else:
        answers = iter([custody.sha(source), '0' * 64])
        monkeypatch.setattr(custody, 'sha', lambda path: next(answers))
    with pytest.raises(Refusal):
        custody.serve()
    assert events[-1]['kind'] == 'poison'
    assert not any(e.get('phase') == 'source_preparation_complete' for e in events)
    assert state['custody_pending'] == state['custody_retained'] == []


def test_preparation_does_not_trust_populated_cache_after_current_byte_drift(setup, monkeypatch):
    guard, events, derived, _ = setup
    custody.prepare_source(guard)
    monkeypatch.setattr(custody, 'sha', lambda path: '0' * 64)
    with pytest.raises(Refusal, match='source_drift'):
        custody.prepare_source(guard)
    assert len(derived) == 1
    assert events[-1]['kind'] == 'poison'
