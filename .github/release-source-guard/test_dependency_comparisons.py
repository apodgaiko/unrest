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
