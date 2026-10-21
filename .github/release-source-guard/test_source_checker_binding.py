"""Observe original helper frames without launching an original test or process."""
import ast
import importlib
from pathlib import Path
import subprocess
import sys
import types

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(Path(__file__).parent / 'finite'))


def operations_module():
    path = Path(__file__).with_name('finite') / 'source_operations.py'
    tree = ast.parse(path.read_bytes())
    for node in tree.body:
        if isinstance(node, ast.Assign) and any(isinstance(t, ast.Name) and t.id == 'ROOT' for t in node.targets):
            node.value = ast.Call(func=ast.Name(id='Path', ctx=ast.Load()), args=[ast.Constant(str(ROOT))], keywords=[])
    module = types.ModuleType('checker_binding_control')
    exec(compile(ast.fix_missing_locations(tree), str(path), 'exec'), module.__dict__)
    specialized = ast.parse(path.parents[1].joinpath('primary_operation_journal.py').read_bytes())
    cls = next(n for n in specialized.body if isinstance(n, ast.ClassDef))
    module.__dict__['_PrimaryOperations'] = module.Operations
    exec(compile(ast.Module(body=[cls], type_ignores=[]), str(path.parents[1] / 'primary_operation_journal.py'), 'exec'), module.__dict__)
    return module


def test_original_checker_helper_binds_real_frame_without_os_launch(tmp_path, monkeypatch):
    module = operations_module()
    pytest.register_assert_rewrite('tests.contracts.conftest')
    original = importlib.import_module('tests.contracts.conftest')
    owner = module.Operations({'operation_spec': {}}, lambda r: None,
                              lambda reason: (_ for _ in ()).throw(RuntimeError(reason)), lambda t: None)
    record = {'token': 'owned-control-build'}
    owner.require = lambda path, kind: record
    owner.inputs = lambda: {'control': 'not-a-launch-proof'}
    owner.activation = lambda record: None
    owner.reference = lambda record: {'control': 'not-a-launch-proof'}
    dist = tmp_path / 'dist'
    vector = [sys.executable, 'tools/check_distribution.py', str(dist)]
    results = []
    def no_launch(command, **kwargs):
        results.append(owner.consumer(command, kwargs['cwd'], kwargs['env']))
        return subprocess.CompletedProcess(command, 0, 'observed-only')
    monkeypatch.setattr(original.subprocess, 'run', no_launch)
    assert original._run_checked(vector, cwd=ROOT, env={}) == 'observed-only'
    assert results[0]['class'] == 'source-checker'
    assert results[0]['source_binding']['function'] == '_run_checked'


@pytest.mark.parametrize('tail', [b'', b'{"kind":', b'{"word":"\xe2\x82', b'{"kind":"uncommitted"}'])
def test_live_uncommitted_journal_tail_never_supplies_settlement(tmp_path, tail):
    import json
    module = operations_module()
    events = tmp_path / 'events'
    events.mkdir()
    parent = {'kind': 'operation_settled', 'token': 'owned', 'owner_pid': 17}
    (events / '17.jsonl').write_bytes(json.dumps(parent).encode() + b'\n')
    child = events / '18.jsonl'
    child.write_bytes(tail)
    owner = module.Operations({'operation_spec': {}, 'events': str(events)}, lambda r: None,
                              lambda r: (_ for _ in ()).throw(RuntimeError(r)), lambda t: None)
    assert owner.rows() == [parent]
    assert owner.reference(parent)['record_sha256'] == module.hashed(parent)
    child.write_bytes(b'{"kind":"committed"}\n')
    assert owner.rows() == [parent, {'kind': 'committed'}]


@pytest.mark.parametrize('data,error', [(b'not-json\n', ValueError), (b'\xff\n', UnicodeDecodeError), (b'\n', ValueError)])
def test_committed_invalid_journal_record_still_refuses(tmp_path, data, error):
    module = operations_module()
    (tmp_path / '17.jsonl').write_bytes(data)
    owner = module.Operations({'operation_spec': {}, 'events': str(tmp_path)}, lambda r: None,
                              lambda r: None, lambda t: None)
    with pytest.raises(error):
        owner.rows()


@pytest.mark.parametrize('error', [OSError(28, 'private detail'), RuntimeError('private detail'), KeyError('private detail'), ValueError('private detail'), TypeError('private detail')])
def test_binding_diagnostic_retains_same_original_error_and_excludes_body(error):
    import json
    module = operations_module()
    rows = []
    owner = module.Operations({'operation_spec': {}}, rows.append, lambda r: None, lambda t: None)
    def failing(*args):
        raise error
    module._PrimaryOperations.admit = failing
    with pytest.raises(type(error)) as caught:
        owner.admit([], None, None)
    assert caught.value is error
    assert len(rows) == 1 and rows[0]['kind'] == 'operation_binding_failure'
    assert rows[0]['error_class'] == type(error).__name__
    assert 'private detail' not in json.dumps(rows)
    assert len(rows[0]['frames']) <= 8


def test_primary_specialization_pins_and_preserves_original_constructor_domain():
    import hashlib
    support = Path(__file__).parent
    wrapper = ast.parse((support / 'primary_operation_journal.py').read_bytes())
    check = next(n for n in wrapper.body if isinstance(n, ast.If))
    digest = next(n.value for n in ast.walk(check.test)
                  if isinstance(n, ast.Constant) and isinstance(n.value, str) and len(n.value) == 64)
    assert hashlib.sha256((support / 'primary_operations.py').read_bytes()).hexdigest() == digest
    cls = next(n for n in wrapper.body if isinstance(n, ast.ClassDef))
    assert [n.name for n in cls.body if isinstance(n, ast.FunctionDef)] == ['dependency', 'rows', 'admit']
    dependency = next(n for n in cls.body if isinstance(n, ast.FunctionDef) and n.name == 'dependency')
    assert hashlib.sha256(ast.dump(dependency, include_attributes=False).encode()).hexdigest() == '1af30a5615d7d797916b8194491f1eecacba337b1354725579f810bcccf46842'
    assert cls.bases[0].id == '_PrimaryOperations'
    original = ast.parse((support / 'primary_operations.py').read_bytes())
    assert len([n for n in original.body if isinstance(n, ast.ClassDef)]) == 1
    authority = (support / 'primary_dependency_authority.py').read_text()
    assert "original.update(path='/guard/primary_operation_journal.py'" in authority
    source = (support / 'finite/child_relative.py').read_text()
    assert "operations_source = Path('/guard/primary_operations.py')" in source
    assert "guard.digest(operations_source) != '" + digest + "'" in source
