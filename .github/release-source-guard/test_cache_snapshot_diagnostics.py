"""Closed diagnostics cannot change original cache refusal or assertion operands."""
import ast
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).parent


def module(name):
    spec = importlib.util.spec_from_file_location(name, ROOT / (name + '.py'))
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


def test_escape_diagnostic_retains_original_strict_refusal(tmp_path):
    closure = module('dependency_closure')
    root = tmp_path / 'cache'
    root.mkdir()
    target = tmp_path / 'external'
    target.write_bytes(b'private content')
    (root / 'link').symlink_to(target)
    with pytest.raises(RuntimeError, match='dependency symlink escapes its finite runtime closure'):
        closure.inventory(root)


def test_inventory_inverse_is_exact_original_program():
    tree = ast.parse((ROOT / 'dependency_closure.py').read_text())
    function = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == 'inventory')
    function.args.kwonlyargs = []
    function.args.kw_defaults = []
    class Strip(ast.NodeTransformer):
        def visit_If(self, node):
            if ast.unparse(node.test) == 'on_escape is not None':
                assert len(node.body) == 1 and ast.unparse(node.body[0]) == 'on_escape(root, path, resolved, info)'
                return None
            return self.generic_visit(node)
    actual = ast.dump(Strip().visit(function), include_attributes=False)
    assert hashlib.sha256(actual.encode()).hexdigest() == ORIGINAL_INVENTORY


ORIGINAL_INVENTORY = 'c6ea0fd53aa32d5a4ae28da86b45aff2b8506a38a1f0640bcb0cd55a8f10f20a'


@pytest.mark.parametrize('old,new', [
    ('not resolved.is_relative_to(root)', 'False'),
    ('resolved != Path("/usr/local/bin/python3.13")', 'False'),
    ('path.resolve(strict=True)', 'path.resolve()'),
])
def test_inverse_rejects_weakened_original(tmp_path, old, new):
    source = (ROOT / 'dependency_closure.py').read_text()
    original = ast.parse(source)
    altered = ast.parse(source.replace(old, new))
    assert ast.dump(original, include_attributes=False) != ast.dump(altered, include_attributes=False)


def snapshot():
    return dict(attempt_id='private-attempt', blocker_code=None, checkpoint_requests=0,
                checkpoint_sequence=1, completed_target_ids=[], elapsed_nanoseconds=0,
                last_effect_sequence=0, mission_id='private-mission', node_id='private-node',
                phase='waiting_at_checkpoint', project_id='private-project',
                remaining_target_ids=['private-target'], role='worker', scope_status='in_scope',
                supervision_status='waiting', terminal_review_id=None)


def test_snapshot_diagnostic_closed_and_operands_unchanged():
    entry = module('primary_source_entry')
    rows = []
    case = 'tests/test_server.py::test_composed_restart_stop_replacement_and_cancel_are_distinct'
    guard = SimpleNamespace(_STATE={'case': case}, append=rows.append)
    observer = entry.Observer(guard, None, {}, {})
    left, right = [snapshot()], [snapshot()]
    left[0]['elapsed_nanoseconds'] = 30000000000
    left[0]['project_id'] = 'different-private-project'
    before = copy.deepcopy((left, right))
    for _ in range(3):
        assert observer.pytest_assertrepr_compare(None, '==', left, right) is None
    assert (left, right) == before and len(rows) == 1
    row = rows[0]
    assert row['differing_keys'] == ['elapsed_nanoseconds', 'project_id']
    assert row['values'] == {'elapsed_nanoseconds': [30000000000, 0]}
    assert row['cardinalities'] == [1, 1]
    assert 'private' not in json.dumps(row)


@pytest.mark.parametrize('change', ['case', 'op', 'shape', 'keys'])
def test_unrelated_comparisons_are_not_observed(change):
    entry = module('primary_source_entry')
    rows = []
    guard = SimpleNamespace(_STATE={'case': 'tests/test_server.py::test_composed_restart_stop_replacement_and_cancel_are_distinct'}, append=rows.append)
    observer = entry.Observer(guard, None, {}, {})
    left, right, op = [snapshot()], [snapshot()], '=='
    if change == 'case':
        guard._STATE['case'] = 'unrelated'
    elif change == 'op':
        op = '!='
    elif change == 'shape':
        left = []
    elif change == 'keys':
        left[0]['foreign'] = 'private'
    assert observer.pytest_assertrepr_compare(None, op, left, right) is None
    assert rows == []


def test_exact_current_cache_snapshot_refs_are_finite():
    tree = ast.parse((ROOT / 'ci_shell.py').read_text())
    sets = [node for node in ast.walk(tree) if isinstance(node, ast.SetComp)
            and 'cache-snapshot-' in ast.unparse(node)]
    assert len(sets) == 1
    values = eval(compile(ast.Expression(sets[0]), '<closed ref set>', 'eval'), {})
    prefix = 'refs/heads/codex/source-guard-structured-20261018-cache-snapshot-'
    assert values == {prefix + f'{n:02}' for n in range(1, 7)}
    assert prefix + '07' not in values and prefix + '02-extra' not in values


@pytest.fixture
def runtime_fixture(tmp_path, monkeypatch):
    from test_producer_startup import load_function
    import os
    import stat
    activation_spec = importlib.util.spec_from_file_location('runtime_activation', ROOT / 'finite/operation_activation.py')
    activation = importlib.util.module_from_spec(activation_spec)
    activation_spec.loader.exec_module(activation)
    root = tmp_path / 'cache/builds-v0/exact-runtime'
    (root / 'bin').mkdir(parents=True)
    site = root / 'lib/python3.13/site-packages'
    site.mkdir(parents=True)
    (site / 'backend.py').write_bytes(b'pinned original backend')
    (root / 'pyvenv.cfg').write_bytes(b'known generated config')
    base = tmp_path / 'interpreter'
    base.write_bytes(b'byte-pinned interpreter')
    (root / 'bin/python').symlink_to(base)
    (root / 'bin/python3').symlink_to('python')
    # The production owner is fixed UID20000; map only that host fixture fact.
    original_lstat = Path.lstat
    class Info:
        def __init__(self, value):
            self.value = value
        def __getattr__(self, key):
            return 20000 if key == 'st_uid' else getattr(self.value, key)
        def __eq__(self, other):
            return self.value == other.value
    monkeypatch.setattr(Path, 'lstat', lambda path: Info(original_lstat(path)))
    namespace = {'Path': Path, 'os': os, 'stat': stat, 'hashlib': hashlib,
                 'load': lambda *args: activation,
                 'digest': lambda path: hashlib.sha256(Path(path).read_bytes()).hexdigest()}
    declare = load_function('runtime_members', 'producer_profile.py', namespace)
    inventory = load_function('primary_inventory', 'producer_profile.py', namespace)
    spec = {'base': str(base)}
    selected = {'prefix': str(root), 'python_link': str(root / 'bin/python')}
    output = declare(spec, selected)
    return root, base, spec, selected, output, declare, inventory


def test_current_declared_runtime_is_separate_from_dependency_domain(runtime_fixture):
    root, base, spec, selected, output, declare, inventory = runtime_fixture
    cache = root.parent.parent
    closure = module('dependency_closure')
    with pytest.raises(RuntimeError, match='dependency symlink escapes'):
        closure.inventory(cache)
    rows = inventory(cache, {str(root): output})
    assert rows['builds-v0/exact-runtime/bin/python']['resolved_sha256'] == hashlib.sha256(base.read_bytes()).hexdigest()
    assert output['members']['bin/python']['target_identity']['sha256'] == hashlib.sha256(base.read_bytes()).hexdigest()


@pytest.mark.parametrize('change', ['unregistered', 'wrong_target', 'target_bytes', 'replacement', 'mode', 'foreign_link'])
def test_runtime_external_link_refuses_drift(runtime_fixture, change):
    root, base, spec, selected, output, declare, inventory = runtime_fixture
    outputs = {str(root): output}
    if change == 'unregistered':
        outputs = {}
    elif change == 'wrong_target':
        foreign = base.with_name('foreign')
        foreign.write_bytes(base.read_bytes())
        (root / 'bin/python').unlink()
        (root / 'bin/python').symlink_to(foreign)
    elif change == 'target_bytes':
        base.write_bytes(b'foreign interpreter')
    elif change == 'replacement':
        (root / 'bin/python').unlink()
        (root / 'bin/python').symlink_to(base)
    elif change == 'mode':
        output['members']['bin/python']['identity'][2] ^= 0o100
    elif change == 'foreign_link':
        (root.parent / 'foreign').symlink_to(base)
    with pytest.raises(RuntimeError):
        inventory(root.parent.parent, outputs)


@pytest.mark.parametrize('name,kind', [('unknown', 'file'), ('bin/unknown', 'symlink'), ('other', 'directory')])
def test_original_runtime_declaration_rejects_unknown_member(runtime_fixture, name, kind):
    root, base, spec, selected, output, declare, inventory = runtime_fixture
    path = root / name
    if kind == 'file':
        path.write_bytes(b'unknown writer')
    elif kind == 'directory':
        path.mkdir()
    else:
        path.symlink_to(base)
    rows = []
    with pytest.raises(RuntimeError):
        declare(spec, selected, rows.append)
    assert len(rows) == 1 and rows[0]['member_type'] == kind
    assert rows[0]['member_sha256'] == hashlib.sha256(name.encode()).hexdigest()
    assert 'unknown writer' not in json.dumps(rows)


@pytest.mark.parametrize('change', ['none', 'missing_helper', 'duplicate_helper', 'missing_ready',
                                    'duplicate_ready', 'stale_parent', 'stale_build',
                                    'wrong_owner', 'wrong_mode', 'wrong_spec_pin',
                                    'foreign_cache', 'foreign_image', 'foreign_argv', 'foreign_output'])
def test_runtime_consumption_requires_current_original_operation(tmp_path, monkeypatch, change):
    import os
    import stat
    from test_producer_startup import load_function
    headers = tmp_path / 'headers'
    headers.mkdir()
    build = {'pid': 10, 'owner_pid': 20, 'token': 'current-build'}
    admission = {'kind': 'operation_admission', 'owner_pid': 20, 'token': build['token']}
    def hashed(value):
        return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
    spec = {'output': '/known-output', 'cache': '/work/cache', 'base_identity': {'sha256': 'image'}}
    rows = [admission]
    children = {}
    names = ['get_requires_for_build_sdist', 'build_sdist', 'get_requires_for_build_wheel', 'build_wheel']
    for index, helper in enumerate(names):
        pid = 100 + index
        argv = ['/work/cache/builds-v0/runtime/bin/python', '-c', 'exact original helper']
        child = {'parent_operation': dict(build, record_sha256=hashed(admission)),
                 'cache': spec['cache'], 'base_identity': spec['base_identity'], 'output': spec['output'],
                 'primary_runtime_output': {'root': '/work/cache/builds-v0/runtime', 'members': {}}}
        header = {'pid': pid, 'ppid': 10, 'token': 'child-' + str(pid), 'role': 'isolated-uv-helper',
                  'spec': 'spec-' + str(pid), 'spec_sha256': 'pin-' + str(pid),
                  'manifest_sha256': 'manifest-' + str(pid), 'orig_argv': argv}
        rows.extend([{'kind': 'isolated_original_dispatch', 'owner_pid': pid, 'parent_pid': 10,
                      'helper': helper, 'orig_argv_sha256': hashlib.sha256(json.dumps(argv).encode()).hexdigest()},
                     {'kind': 'ready', 'owner_pid': pid, 'token': header['token'],
                      'manifest_sha256': header['manifest_sha256']}])
        children[header['spec']] = (header['spec_sha256'], child)
        if index == 0:
            if change == 'stale_parent':
                header['ppid'] = 11
            elif change == 'stale_build':
                child['parent_operation']['token'] = 'old-build'
            elif change == 'wrong_spec_pin':
                header['spec_sha256'] = 'foreign-pin'
            elif change == 'foreign_cache':
                child['cache'] = '/foreign'
            elif change == 'foreign_image':
                child['base_identity'] = {'sha256': 'foreign'}
            elif change == 'foreign_argv':
                header['orig_argv'] = ['/foreign', '-c', 'foreign']
            elif change == 'foreign_output':
                child['output'] = '/foreign-output'
        (headers / (str(pid) + '.json')).write_text(json.dumps(header))
        (headers / (str(pid) + '.json')).chmod(0o444)
    if change == 'missing_helper':
        rows = [row for row in rows if row.get('helper') != names[0]]
    elif change == 'duplicate_helper':
        rows.append(rows[1])
    elif change == 'missing_ready':
        rows = [row for row in rows if not (row['kind'] == 'ready' and row['owner_pid'] == 100)]
    elif change == 'duplicate_ready':
        rows.append(rows[2])
    elif change == 'wrong_mode':
        (headers / '100.json').chmod(0o644)
    original = Path.lstat
    class Info:
        def __init__(self, value):
            self.value = value
        def __getattr__(self, key):
            return (20000 if change == 'wrong_owner' else 20001) if key == 'st_uid' else getattr(self.value, key)
    monkeypatch.setattr(Path, 'lstat', lambda path: Info(original(path)))
    def mapped(path):
        return headers if str(path) == '/receipts/native-startup' else Path(path)
    def protected(path, pin):
        expected, value = children[path]
        if pin != expected:
            raise RuntimeError('controlled protected spec pin drift')
        return value
    def require(output, operation):
        assert output == spec['output'] and operation == 'source-build'
        return build
    function = load_function('original_runtime_outputs', 'producer_profile.py', {
        'Path': mapped, 'os': os, 'stat': stat, 'hashlib': hashlib, 'json': json,
        'load': lambda *args: SimpleNamespace(require=require), 'events': lambda spec: rows,
        'hashed': hashed, 'protected_json': protected})
    if change == 'none':
        assert set(function(spec)) == {'/work/cache/builds-v0/runtime'}
    else:
        with pytest.raises(RuntimeError):
            function(spec)
