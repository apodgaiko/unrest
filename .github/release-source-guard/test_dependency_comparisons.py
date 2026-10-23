"""Complete-byte pure comparison reuse never replaces current custody checks."""
from pathlib import Path
import types

import pytest

from primary_dependency import comparison_functions

ROOT = Path(__file__).parent


def namespace():
    path = ROOT / 'finite/operation_activation.py'
    value = {'__name__': 'comparison_control', '__file__': str(path)}
    exec(compile(path.read_bytes(), str(path), 'exec', dont_inherit=True), value)
    return value


def test_complete_source_bytes_filename_and_options_bind_compilation():
    value, cache = namespace(), {}
    comparison_functions(value, cache)
    derive = value['compile']
    original = derive(b'answer = 1\n', '/same.py', 'exec', dont_inherit=True, optimize=0)
    assert derive(b'answer = 1\n', '/same.py', 'exec', dont_inherit=True, optimize=0) is original
    for body, path, optimize in [(b'answer = 2\n', '/same.py', 0),
                                 (b'answer = 1\n', '/other.py', 0),
                                 (b'answer = 1\n', '/same.py', 1)]:
        assert derive(body, path, 'exec', dont_inherit=True, optimize=optimize) is not original
    assert len(cache['compiled']) == 4
    with pytest.raises(SyntaxError):
        derive(b'broken syntax', '/same.py', 'exec', dont_inherit=True, optimize=0)
    assert len(cache['compiled']) == 4


@pytest.mark.parametrize('change', ['filename', 'lines', 'exception-table', 'code', 'constant'])
def test_full_marshaled_code_identity_preserves_original_comparison(change):
    value, cache = namespace(), {}
    original_identity = namespace()['code_identity']
    comparison_functions(value, cache)
    code = compile('def inner():\n try:\n  return 1\n except Exception:\n  return 2\n', '/same.py', 'exec')
    inner = next(item for item in code.co_consts if type(item) is types.CodeType)
    change_code = {'filename': {'co_filename': '/other.py'},
                   'lines': {'co_linetable': b''},
                   'exception-table': {'co_exceptiontable': b''},
                   'code': {'co_code': bytes(len(inner.co_code))},
                   'constant': {'co_consts': (None, 3, 2)}}[change]
    other = inner.replace(**change_code)
    expected = original_identity(inner) == original_identity(other)
    assert (value['code_identity'](inner) == value['code_identity'](other)) is expected
    assert not expected
    assert type(value['code_identity'](inner)) is tuple
    assert len(cache['identities']) == 2


def test_journal_dependency_reuses_only_pure_state_after_current_support_checks(tmp_path):
    import ast
    import hashlib
    module = ast.parse((ROOT / 'primary_operation_journal.py').read_bytes())
    cls = next(item for item in module.body if isinstance(item, ast.ClassDef))
    dependency = tmp_path / 'dependency.py'
    outputs = tmp_path / 'outputs.py'
    outputs.write_bytes(b'output support')
    dependency.write_text('def verify(site, support, *, comparisons):\n'
                          ' comparisons["visits"] = comparisons.get("visits", 0) + 1\n'
                          ' return {"kind": "consumed", "visits": comparisons["visits"]}\n')
    def path(name):
        return {'/guard/primary_dependency.py': dependency,
                '/guard/producer_outputs.py': outputs}[name]
    globals_ = {'_PrimaryOperations': object, 'Path': path, 'hashlib': hashlib}
    exec(compile(ast.Module(body=[cls], type_ignores=[]), str(ROOT / 'primary_operation_journal.py'), 'exec'), globals_)
    value = globals_['Operations']()
    value.spec = {'primary_dependency_support': {
        'path': '/guard/primary_dependency.py', 'sha256': hashlib.sha256(dependency.read_bytes()).hexdigest(),
        'outputs_sha256': hashlib.sha256(outputs.read_bytes()).hexdigest()}, 'primary_dependency': {}}
    events = []
    value.emit = events.append
    def refuse(reason):
        raise RuntimeError(reason)
    value.refuse = refuse
    for _ in range(2):
        value.dependency('/source/.venv/lib/python3.13/site-packages')
    assert [event['visits'] for event in events] == [1, 2]
    dependency.write_bytes(dependency.read_bytes() + b'# changed\n')
    with pytest.raises(RuntimeError, match='primary_dependency_support_drift'):
        value.dependency('/source/.venv/lib/python3.13/site-packages')
    assert len(events) == 2 and value._dependency_comparisons == {'visits': 2}


def reference_freeze(value):
    if type(value) is dict:
        return ('dict', tuple((key, reference_freeze(item)) for key, item in sorted(value.items())))
    if type(value) in (list, tuple):
        return (type(value).__name__, tuple(reference_freeze(item) for item in value))
    return value


@pytest.mark.parametrize('optimize', [0, 1, 2])
def test_direct_projection_is_exact_original_value_for_nested_code_and_constants(optimize):
    value, cache = namespace(), {}
    original = namespace()['code_identity']
    comparison_functions(value, cache)
    program = '''"module docs"
VALUES = (None, True, False, 1, -0.0, 2j, b"bytes", "text", ..., (1, "nested"))
def outer(arg, /, *args, named=1, **kwargs):
    captured = named
    def inner(value):
        assert value
        try:
            return captured, {value for value in ("a", "b") if value in {"a", "b"}}
        except Exception:
            raise
    return inner
async def iterate(source):
    async for item in source:
        yield item
'''
    root = compile(program, '/exact.py', 'exec', dont_inherit=True, optimize=optimize)
    pending = [root]
    while pending:
        code = pending.pop()
        assert value['code_identity'](code) == reference_freeze(original(code))
        pending.extend(item for item in code.co_consts if type(item) is types.CodeType)


@pytest.mark.parametrize('field, replacement', [
    ('co_argcount', 0), ('co_posonlyargcount', 0), ('co_kwonlyargcount', 0),
    ('co_stacksize', 100), ('co_flags', 0), ('co_filename', '/foreign.py'),
    ('co_name', 'foreign'), ('co_qualname', 'foreign.qualified'), ('co_firstlineno', 100),
    ('co_names', ('foreign',)), ('co_varnames', ('foreign', 'named')),
    ('co_freevars', ('foreign',)), ('co_cellvars', ('foreign',)),
    ('co_linetable', b''), ('co_exceptiontable', b''), ('co_consts', (None, 42)),
])
def test_every_original_projected_field_keeps_the_original_comparison(field, replacement):
    value, cache = namespace(), {}
    original = namespace()['code_identity']
    comparison_functions(value, cache)
    module = compile('def call(arg, /, *, named):\n try:\n  return target(arg, named)\n except Exception:\n  raise\n',
                     '/same.py', 'exec')
    code = next(item for item in module.co_consts if type(item) is types.CodeType)
    changes = {field: replacement}
    if field == 'co_argcount':
        changes['co_posonlyargcount'] = 0  # Keep the mutated CodeType internally valid.
    changed = code.replace(**changes)
    assert value['code_identity'](changed) == reference_freeze(original(changed))
    assert ((value['code_identity'](code) == value['code_identity'](changed))
            is (original(code) == original(changed)))


@pytest.mark.parametrize('field, replacement', [
    ('co_argcount', 0), ('co_posonlyargcount', 0), ('co_kwonlyargcount', 0),
    ('co_stacksize', 100), ('co_flags', 0), ('co_filename', '/foreign.py'),
    ('co_name', 'foreign'), ('co_qualname', 'foreign.qualified'), ('co_firstlineno', 100),
    ('co_names', ('foreign',)), ('co_varnames', ('foreign', 'named')),
    ('co_freevars', ('foreign',)), ('co_cellvars', ('foreign',)),
    ('co_linetable', b''), ('co_exceptiontable', b''), ('co_consts', (None, 42)),
])
def test_sealed_reference_preserves_every_original_nested_code_field(field, replacement):
    import primary_dependency as dependency
    body = b'def call(arg, /, *, named):\n try:\n  return target(arg, named)\n except Exception:\n  raise\n'
    path = str(dependency.SITE / 'data.py')
    original = namespace()['code_identity']
    references = dependency.compiled_references({'data.py': body})
    value = namespace()
    comparison_functions(value, {}, references)
    expected = value['compile'](body, path, 'exec', dont_inherit=True, optimize=0)
    assert not isinstance(expected, types.CodeType)
    with pytest.raises(TypeError):
        exec(expected, {})
    actual = compile(body, path, 'exec', dont_inherit=True, optimize=0)
    assert value['code_identity'](actual) == value['code_identity'](expected)
    inner = next(item for item in actual.co_consts if type(item) is types.CodeType)
    changes = {field: replacement}
    if field == 'co_argcount':
        changes['co_posonlyargcount'] = 0
    changed_inner = inner.replace(**changes)
    changed = actual.replace(co_consts=tuple(changed_inner if item is inner else item for item in actual.co_consts))
    assert ((value['code_identity'](changed) == value['code_identity'](expected))
            is (original(changed) == original(actual)))
    assert original(changed) != original(actual)


def test_reference_reuses_only_matching_complete_current_bytes_and_compilation_options(monkeypatch):
    import primary_dependency as dependency
    body = b'answer = 1\n'
    path = str(dependency.SITE / 'data.py')
    references = dependency.compiled_references({'data.py': body, 'unused.py': b'broken syntax!'})
    assert set(references) == {'data.py'}
    calls = []
    actual_compile = compile
    def counted(*args, **kwargs):
        calls.append((args, kwargs))
        return actual_compile(*args, **kwargs)
    monkeypatch.setattr(dependency, 'compile', counted, raising=False)
    value = namespace()
    comparison_functions(value, {}, references)
    value['compile'](body, path, 'exec', dont_inherit=True, optimize=0)
    assert not calls
    for current, filename, inherit, optimize in [(b'answer = 2\n', path, True, 0),
            (body, str(dependency.SITE / 'other.py'), True, 0),
            (body, '/foreign/data.py', True, 0), (body, path, False, 0),
            (body, path, True, 1), (body, path, True, 2)]:
        assert isinstance(value['compile'](current, filename, 'exec',
                          dont_inherit=inherit, optimize=optimize), types.CodeType)
    assert len(calls) == 6


def test_same_pure_cache_cannot_carry_a_reference_verdict_across_modes_or_changes():
    import primary_dependency as dependency
    body = b'answer = 1\n'
    path = str(dependency.SITE / 'data.py')
    refs = dependency.compiled_references({'data.py': body})
    changed = {'data.py': {**refs['data.py'], 'identity_sha256': 'a' * 64}}
    cache = {}
    actual = compile(body, path, 'exec', dont_inherit=True, optimize=0)
    for references in (None, refs, None, changed, {}, refs, None):
        value = namespace()
        comparison_functions(value, cache, references)
        expected = value['compile'](body, path, 'exec', dont_inherit=True, optimize=0)
        same = value['code_identity'](actual) == value['code_identity'](expected)
        assert same is (references is not changed)
        assert (type(value['code_identity'](actual)) is tuple) is (references is None)
    assert all(type(code) is types.CodeType for code in cache['compiled'].values())
