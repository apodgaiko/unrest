"""Finite support compilation reuse never substitutes for current admission."""
import hashlib
import importlib
import os
from pathlib import Path
import sys
import types

import pytest

ROOT = Path(__file__).parent
sys.path.insert(0, str(ROOT / 'finite'))
routes = importlib.import_module('direct_routes')


def fixture(tmp_path):
    path = tmp_path / 'support.py'
    path.write_text('calls = []\ndef admit(value):\n    calls.append(value)\n    assert value == "original"\n')
    state = {'direct_support': {'files': {str(path): hashlib.sha256(path.read_bytes()).hexdigest()}}}
    return path, state


def test_three_admissions_compile_once_and_keep_fresh_globals(tmp_path, monkeypatch):
    path, state = fixture(tmp_path)
    compiled = []
    original = compile
    def compiling(*args, **kwargs):
        compiled.append((args[1], kwargs))
        return original(*args, **kwargs)
    monkeypatch.setattr(routes, 'compile', compiling, raising=False)
    namespaces = []
    for _ in range(3):
        namespace = {}
        exec(routes.support_code(path, state), namespace)
        namespace['admit']('original')
        namespaces.append(namespace)
    assert compiled == [(str(path), {})]
    assert state['direct_support_pure_metrics']['reads'] == 3
    assert state['direct_support_pure_metrics']['compiles'] == 1
    assert all(n['calls'] == ['original'] for n in namespaces)
    assert len({id(n['admit'].__globals__) for n in namespaces}) == 3
    # A changed live input still reaches the original assertion after warming.
    with pytest.raises(AssertionError):
        namespaces[-1]['admit']('changed')
    other = {'direct_support': state['direct_support']}
    assert routes.support_code(path, other) is not state['direct_support_compiled'][str(path)][1]


@pytest.mark.parametrize('change', ['bytes', 'missing', 'symlink', 'hardlink', 'mode',
                                   'replacement', 'owner', 'pin', 'read-race', 'unregistered'])
def test_populated_compilation_never_hides_current_carrier_drift(tmp_path, monkeypatch, change):
    path, state = fixture(tmp_path)
    routes.support_code(path, state)
    if change == 'bytes':
        info = path.stat()
        path.write_bytes(path.read_bytes().replace(b'original', b'modified'))
        os.utime(path, ns=(info.st_atime_ns, info.st_mtime_ns))
    elif change == 'missing':
        path.unlink()
    elif change in {'symlink', 'hardlink', 'replacement'}:
        original = path.with_suffix('.original')
        path.rename(original)
        if change == 'symlink':
            path.symlink_to(original)
        elif change == 'hardlink':
            os.link(original, path)
        else:
            path.write_bytes(original.read_bytes())
    elif change == 'mode':
        path.chmod(0o600)
    elif change == 'pin':
        state['direct_support']['files'][str(path)] = '0' * 64
    elif change == 'unregistered':
        state['direct_support']['files'].clear()
    else:
        actual = os.fstat
        count = 0
        def changed(fd):
            nonlocal count
            info = actual(fd)
            count += 1
            if change == 'owner' or count > 1:
                values = {k: getattr(info, k) for k in ('st_dev', 'st_ino', 'st_uid', 'st_gid',
                          'st_mode', 'st_nlink', 'st_size', 'st_mtime_ns', 'st_ctime_ns')}
                values['st_uid' if change == 'owner' else 'st_ctime_ns'] += 1
                return types.SimpleNamespace(**values)
            return info
        monkeypatch.setattr(os, 'fstat', changed)
    with pytest.raises((RuntimeError, OSError, KeyError)):
        routes.support_code(path, state)


def test_hit_reopens_nofollow_and_never_mutates_shallow_resolver_state(tmp_path, monkeypatch):
    path, state = fixture(tmp_path)
    first = routes.support_code(path, state)
    actual = os.open
    reads = []
    def opened(pathname, flags, *args, **kwargs):
        if Path(pathname) == path:
            assert flags & os.O_NOFOLLOW
            reads.append(str(pathname))
        return actual(pathname, flags, *args, **kwargs)
    monkeypatch.setattr(os, 'open', opened)
    for _ in range(3):
        # SourceActivation re-resolution uses a shallow copy of this state.
        assert routes.support_code(path, {**state}) is first
    assert reads == [str(path)] * 3


def test_real_finite_support_reuses_code_across_fresh_resolver_namespaces():
    path = ROOT / 'finite/direct_routes.py'
    state = {'direct_support': {'files': {
        str(p): hashlib.sha256(p.read_bytes()).hexdigest()
        for p in (ROOT / 'finite').glob('*.py')}}}
    namespaces = []
    for _ in range(3):
        namespace = {'__file__': str(path)}
        exec(compile(path.read_bytes(), str(path), 'exec'), namespace)
        carrier = ROOT / 'finite/ordinary_routes.py'
        namespaces.append(namespace)
        code = namespace['support_code'](carrier, state)
        output = {}
        exec(code, output)
        assert output['admit'].__code__.co_filename == str(carrier)
    assert len({id(n['support_code'].__globals__) for n in namespaces}) == 3
    assert len(state['direct_support_compiled']) == 1


def test_changed_compiler_context_cannot_reuse_code(tmp_path):
    import __future__
    path, state = fixture(tmp_path)
    routes.support_code(path, state)
    resolver = ROOT / 'finite/direct_routes.py'
    namespace = {'__file__': str(resolver)}
    exec(compile(resolver.read_bytes(), str(resolver), 'exec',
                 flags=__future__.annotations.compiler_flag), namespace)
    with pytest.raises(RuntimeError, match='cached_carrier_drift'):
        namespace['support_code'](path, state)
