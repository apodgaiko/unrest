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
    root = tmp_path / 'cache/builds-v0/.tmp-exact-runtime'
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
    namespace['check_response_binding'] = load_function('check_response_binding', 'producer_profile.py', {
        'hashlib': hashlib, 'hashed': lambda value: hashlib.sha256(json.dumps(value,sort_keys=True,separators=(',', ':')).encode()).hexdigest()})
    namespace['response_member'] = load_function('response_member', 'producer_profile.py', namespace)
    namespace['runtime_metadata'] = load_function('runtime_metadata', 'producer_profile.py', {
        'Path': Path, 'hashlib': hashlib, 'public_inputs': SimpleNamespace(UV_EMBEDDED={})})
    declare = load_function('runtime_members', 'producer_profile.py', namespace)
    inventory = load_function('primary_inventory', 'producer_profile.py', namespace)
    spec = {'base': str(base), 'virtualenv_source': str(tmp_path / '_virtualenv.py')}
    metadata = {'.gitignore': b'*', 'CACHEDIR.TAG': b'Signature: 8a477f597d28d172789f06886806bc55'}
    for name, body in metadata.items():
        (root / name).write_bytes(body)
    spec['base_identity'] = activation.identity(base)
    original_stat = Path.stat
    class BaseInfo:
        def __init__(self, value):
            self.value = value
        def __getattr__(self, key):
            return 0 if key == 'st_uid' else getattr(self.value, key)
    def owned_base_stat(path, *args, **kwargs):
        info = original_stat(path, *args, **kwargs)
        return BaseInfo(info) if path == base else info
    monkeypatch.setattr(Path, 'stat', owned_base_stat)
    import zipfile
    wheel = tmp_path / 'backend.whl'
    with zipfile.ZipFile(wheel, 'w') as archive:
        archive.writestr('backend.py', b'pinned original backend')
    spec['wheel'] = str(wheel)
    selected = {'prefix': str(root), 'python_link': str(root / 'bin/python'),
                'generated': [], 'caches': []}
    output = declare(spec, selected)
    return root, base, spec, selected, output, declare, inventory


def test_current_declared_runtime_is_separate_from_dependency_domain(runtime_fixture):
    root, base, spec, selected, output, declare, inventory = runtime_fixture
    cache = root.parent.parent
    closure = module('dependency_closure')
    with pytest.raises(RuntimeError, match='dependency symlink escapes'):
        closure.inventory(cache)
    rows = inventory(cache, {str(root): output})
    assert rows['builds-v0/.tmp-exact-runtime/bin/python']['resolved_sha256'] == hashlib.sha256(base.read_bytes()).hexdigest()
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
                                    'foreign_cache', 'foreign_image', 'foreign_argv', 'foreign_output', 'source_output_drift'])
def test_runtime_consumption_requires_current_original_operation(tmp_path, monkeypatch, change):
    import os
    import stat
    from test_producer_startup import load_function
    headers = tmp_path / 'headers'
    headers.mkdir()
    runtime = tmp_path / 'declared-runtime'
    runtime.mkdir()
    operations_spec = importlib.util.spec_from_file_location('actual_source_operations', ROOT / 'finite/source_operations.py')
    operations_module = importlib.util.module_from_spec(operations_spec)
    operation_tree = ast.parse((ROOT / 'finite/source_operations.py').read_bytes())
    original_class = ast.dump(next(n for n in operation_tree.body
                                  if isinstance(n, ast.ClassDef) and n.name == 'Operations'),
                              include_attributes=False)
    # Import-time source registrations need the compartment's /source mount.
    # They do not participate in require; retain the entire actual owner class
    # and its real filesystem identity checks, without running that startup scan.
    for node in operation_tree.body:
        if isinstance(node, ast.Assign) and any(isinstance(t, ast.Name) and t.id == 'REGISTRATIONS' for t in node.targets):
            node.value = ast.List(elts=[], ctx=ast.Load())
    assert ast.dump(next(n for n in operation_tree.body
                         if isinstance(n, ast.ClassDef) and n.name == 'Operations'),
                    include_attributes=False) == original_class
    exec(compile(ast.fix_missing_locations(operation_tree), str(ROOT / 'finite/source_operations.py'), 'exec'),
         operations_module.__dict__)
    output = tmp_path / 'build-output'
    output.mkdir()
    build = {'pid': 10, 'owner_pid': 20, 'token': 'current-build', 'settled': True,
             'output_identity': {'tree': operations_module.tree_identity(output)}}
    def refuse(code):
        raise RuntimeError(code)
    owner = operations_module.Operations({'operation_spec': {}}, lambda row: None, refuse, lambda token: None)
    owner.settled[(str(output), 'source-build')] = build
    admission = {'kind': 'operation_admission', 'owner_pid': 20, 'token': build['token']}
    def hashed(value):
        return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
    spec = {'output': str(output), 'cache': '/work/cache', 'base_identity': {'sha256': 'image'}}
    rows = [admission]
    children = {}
    names = ['get_requires_for_build_sdist', 'build_sdist', 'get_requires_for_build_wheel', 'build_wheel']
    for index, helper in enumerate(names):
        pid = 100 + index
        argv = [str(runtime / 'bin/python'), '-c', 'exact original helper']
        child = {'parent_operation': dict(build, record_sha256=hashed(admission)),
                 'cache': spec['cache'], 'base_identity': spec['base_identity'], 'output': spec['output'],
                 'primary_runtime_output': {'root': str(runtime), 'root_identity': [1, 2, 0o40700, 20000], 'members': {}}}
        header = {'pid': pid, 'ppid': 10, 'start_ticks': pid * 100, 'boot_id': 'current-boot', 'token': 'child-' + str(pid), 'role': 'isolated-uv-helper',
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
    if change == 'source_output_drift':
        (output / 'foreign').write_bytes(b'unknown output')
    function = load_function('original_runtime_outputs', 'producer_profile.py', {
        'Path': mapped, 'os': os, 'stat': stat, 'hashlib': hashlib, 'json': json,
        'events': lambda spec: rows,
        'hashed': hashed, 'protected_json': protected,
        'read_response': lambda pid: {'profile_sha256': hashlib.sha256((headers / (str(pid) + '.json')).read_bytes()).hexdigest(),
            'child_start_ticks': pid * 100, 'child_boot_sha256': hashlib.sha256(b'current-boot').hexdigest(), 'pid': pid,
            'helper': names[pid - 100], 'member': names[pid - 100] + '.txt'},
        'response_member': lambda *args: {'type': 'file'}, 'load': lambda *args: None,
        'check_response_binding': lambda *args: None})
    if change == 'none':
        assert set(function(spec, owner)) == {str(runtime)}
    else:
        with pytest.raises(RuntimeError):
            function(spec, owner)


@pytest.mark.parametrize('change', ['none', 'bytes', 'symlink', 'unrenderable'])
def test_uv_template_rendering_is_byte_pinned(tmp_path, change):
    from test_producer_startup import load_function
    upstream = tmp_path / 'upstream'
    template = upstream / 'virtualenv/activator/activate.nu'
    template.parent.mkdir(parents=True)
    body = b'{{ VIRTUAL_ENV_DIR }};{{ BIN_NAME }};{{ VIRTUAL_PROMPT }};{{ PATH_SEP }};{{ RELATIVE_SITE_PACKAGES }}\r\n'
    template.write_bytes(body)
    binding = {'size': len(body), 'sha256': hashlib.sha256(body).hexdigest()}
    root = tmp_path / ('invalid\nroot' if change == 'unrenderable' else 'declared-runtime')
    if change == 'bytes':
        template.write_bytes(body + b'foreign')
    elif change == 'symlink':
        original = tmp_path / 'outside-template'
        original.write_bytes(body)
        template.unlink()
        template.symlink_to(original)
    function = load_function('runtime_metadata', 'producer_profile.py', {
        'Path': Path, 'hashlib': hashlib,
        'public_inputs': SimpleNamespace(UV_EMBEDDED={'virtualenv/activator/activate.nu': binding})})
    if change == 'none':
        result = function({'virtualenv_source': str(upstream / '_virtualenv.py')}, root)
        assert result == {'.gitignore': b'*',
                          'CACHEDIR.TAG': b'Signature: 8a477f597d28d172789f06886806bc55',
                          'bin/activate.nu': ("'" + str(root) + "';bin;;:;../lib/python3.13/site-packages\r\n").encode()}
    else:
        with pytest.raises(RuntimeError):
            function({'virtualenv_source': str(upstream / '_virtualenv.py')}, root)


@pytest.mark.parametrize('change', ['bytes', 'missing'])
def test_runtime_metadata_requires_exact_original_files(runtime_fixture, change):
    root, base, spec, selected, output, declare, inventory = runtime_fixture
    path = root / '.gitignore'
    if change == 'bytes':
        path.write_bytes(b'foreign')
    else:
        path.unlink()
    with pytest.raises(RuntimeError):
        declare(spec, selected)


def test_runtime_declaration_refuses_symlink_swap_during_read(runtime_fixture, monkeypatch):
    import os
    root, base, spec, selected, output, declare, inventory = runtime_fixture
    foreign = base.with_name('foreign-interpreter')
    foreign.write_bytes(base.read_bytes())
    original = os.readlink
    calls = [0]
    def swap(path, *args, **kwargs):
        result = original(path, *args, **kwargs)
        if Path(path) == root / 'bin/python':
            calls[0] += 1
            if calls[0] == 2:
                (root / 'bin/python').unlink()
                (root / 'bin/python').symlink_to(foreign)
        return result
    monkeypatch.setattr(os, 'readlink', swap)
    with pytest.raises(RuntimeError):
        declare(spec, selected)


def test_runtime_declaration_rejects_extra_empty_site_directory(runtime_fixture):
    root, base, spec, selected, output, declare, inventory = runtime_fixture
    (root / 'lib/python3.13/site-packages/unknown-empty').mkdir()
    with pytest.raises(RuntimeError):
        declare(spec, selected)


@pytest.mark.parametrize('change', ['none', 'operation', 'parent', 'parent_birth', 'wait',
                                    'path', 'bytes', 'replacement', 'member', 'owner'])
def test_response_consumption_requires_prior_wait_and_exact_current_file(runtime_fixture, change):
    from test_producer_startup import load_function
    root, base, spec, selected, output, declare, inventory = runtime_fixture
    path = root / 'get_requires_for_build_sdist.txt'
    path.write_bytes(b'[]')
    identity_spec = importlib.util.spec_from_file_location('response_test_identity', ROOT / 'finite/operation_activation.py')
    identity_module = importlib.util.module_from_spec(identity_spec)
    identity_spec.loader.exec_module(identity_module)
    file = identity_module.identity(path)
    spec['parent_operation'] = {'pid': 10, 'token': 'current-operation', 'identity': {'start_ticks': 100}}
    receipt = {'member': path.name, 'member_sha256': hashlib.sha256(str(path).encode()).hexdigest(),
               'runtime_root_sha256': hashlib.sha256(str(root).encode()).hexdigest(),
               'operation_sha256': hashlib.sha256(b'current-operation').hexdigest(), 'parent': 10,
               'parent_identity_sha256': hashlib.sha256(json.dumps({'start_ticks':100},sort_keys=True,separators=(',', ':')).encode()).hexdigest(), 'parent_wait_raw': 0,
               'file_identity': file['identity'], 'sha256': file['sha256'], 'uid': 20000, 'nlink': 1}
    if change == 'operation':
        receipt['operation_sha256'] = hashlib.sha256(b'stale-operation').hexdigest()
    elif change == 'parent':
        receipt['parent'] = 11
    elif change == 'parent_birth':
        receipt['parent_identity_sha256'] = hashlib.sha256(b'foreign-birth').hexdigest()
    elif change == 'wait':
        receipt['parent_wait_raw'] = 256
    elif change == 'path':
        receipt['member_sha256'] = hashlib.sha256(b'foreign-path').hexdigest()
    elif change == 'bytes':
        path.write_bytes(b'foreign')
    elif change == 'replacement':
        path.unlink()
        path.write_bytes(b'[]')
    elif change == 'member':
        receipt['member'] = 'unknown.txt'
    elif change == 'owner':
        receipt['uid'] = 20001
    function = load_function('response_member', 'producer_profile.py', {'hashlib': hashlib,
        'hashed': lambda value: hashlib.sha256(json.dumps(value,sort_keys=True,separators=(',', ':')).encode()).hexdigest(),
        'check_response_binding': load_function('check_response_binding', 'producer_profile.py', {
            'hashlib': hashlib, 'hashed': lambda value: hashlib.sha256(json.dumps(value,sort_keys=True,separators=(',', ':')).encode()).hexdigest()})})
    if change == 'none':
        result = function(receipt, spec, root, identity_module)
        assert result['file'] == file and result['uid'] == 20000
    else:
        with pytest.raises(RuntimeError):
            function(receipt, spec, root, identity_module)


def test_runtime_accepts_response_only_after_original_producer_receipt(runtime_fixture):
    root, base, spec, selected, output, declare, inventory = runtime_fixture
    path = root / 'get_requires_for_build_sdist.txt'
    path.write_bytes(b'[]')
    rows = []
    with pytest.raises(RuntimeError):
        declare(spec, selected, rows.append)
    assert rows[0]['member_sha256'] == hashlib.sha256(path.name.encode()).hexdigest()


def test_new_response_observer_preserves_original_exit_poison():
    tree = ast.parse((ROOT / 'linux_producers.py').read_bytes())
    function = next(n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef) and n.name == 'tick')
    class Strip(ast.NodeTransformer):
        def visit_Expr(self, node):
            if ast.unparse(node) in {'self.completed_response(event, trace)', 'self.completed_cache(event, trace)'}:
                return None
            return self.generic_visit(node)
    restored = Strip().visit(function)
    assert hashlib.sha256(ast.dump(restored, include_attributes=False).encode()).hexdigest() == '84bad09261eee236b6ecd3200544c51a27c4c34a929c87b20074ce5ad4092b2c'


@pytest.mark.parametrize('change', ['none', 'wait', 'parent', 'body', 'ready', 'call', 'path'])
def test_original_response_capture_uses_original_renderer_and_real_file(runtime_fixture, change):
    import stat
    from test_producer_startup import load_function
    root, base, spec, selected, output, declare, inventory = runtime_fixture
    identity_spec = importlib.util.spec_from_file_location('capture_response_identity', ROOT / 'finite/operation_activation.py')
    identity_module = importlib.util.module_from_spec(identity_spec)
    identity_spec.loader.exec_module(identity_module)
    helper = 'get_requires_for_build_sdist'
    request = root / (helper + '.txt')
    request.write_bytes(b'[]')
    spec.update(cache=str(root.parent.parent), full_build=True, root=str(root),
                primary_runtime_output={'root': str(root)},
                parent_operation={'pid': 10, 'token': 'current-operation', 'identity': {'start_ticks': 100}})
    prefix = ('import sys\n\nif sys.path[0] == "":\n    sys.path.pop(0)\n\n'
              'sys.path = [] + sys.path\n\nimport setuptools.build_meta as backend\n')
    script = (prefix + '\nimport json\n\nget_requires_for_build = getattr(backend, "get_requires_for_build_sdist", None)\n'
              'if get_requires_for_build:\n    requires = get_requires_for_build({})\nelse:\n    requires = []\n\n'
              f'with open("{request}", "w") as fp:\n    json.dump(requires, fp)\n')
    renderer = load_function('helper_class', 'finite/isolated_activation.py', {'Path': Path, 'ast': ast})
    child = {'helper': helper, 'pid': 11, 'parent': 10, 'token': 'child',
             'identity': {'start_ticks': 110, 'boot_id': 'current-boot'}, 'profile_sha256': 'a' * 64}
    header = {'orig_argv': [str(root / 'bin/python'), '-c', script], 'manifest_sha256': 'b' * 64}
    wait = {'raw': 0, 'parent_tgid': 10}
    rows = [{'kind': 'isolated_actual_backend_call', 'owner_pid': 11, 'parent_pid': 10, 'helper': helper},
            {'kind': 'ready', 'owner_pid': 11, 'token': 'child', 'manifest_sha256': 'b' * 64}]
    file = identity_module.identity(request)
    produced = {'kind': 'isolated_original_response_output', 'owner_pid': 11, 'parent_pid': 10,
                 'helper': helper, 'profile_sha256': child['profile_sha256'],
                 'member_sha256': hashlib.sha256(str(request).encode()).hexdigest(),
                 'file_identity': file['identity'], 'sha256': hashlib.sha256(b'[]').hexdigest(),
                 'uid': 20000, 'nlink': 1}
    if change == 'wait':
        wait['raw'] = 256
    elif change == 'parent':
        wait['parent_tgid'] = 12
    elif change == 'body':
        request.write_bytes(b'foreign')
    elif change == 'ready':
        rows.pop()
    elif change == 'call':
        rows.pop(0)
    elif change == 'path':
        header['orig_argv'][-1] = script.replace(str(request), str(root.parent / (helper + '.txt')))
    namespace = {'Path': Path, 'ast': ast, 'stat': stat, 'hashlib': hashlib,
                 'hashed': lambda value: hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':')).encode()).hexdigest(),
                 'events': lambda spec: rows,
                 'load': lambda name, path: identity_module if path.endswith('operation_activation.py') else SimpleNamespace(helper_class=renderer)}
    function = load_function('response_receipt', 'producer_profile.py', namespace)
    if change == 'none':
        receipt = function(spec, header, child, wait, produced)
        assert receipt['sha256'] == hashlib.sha256(b'[]').hexdigest()
        assert receipt['parent_wait_raw'] == 0 and receipt['uid'] == 20000
        assert not any('current-operation' in str(value) for value in receipt.values())
    else:
        with pytest.raises(RuntimeError):
            function(spec, header, child, wait, produced)


@pytest.mark.parametrize('change', ['none', 'extra_fields', 'foreign_pid', 'token', 'birth', 'parent', 'duplicate', 'role', 'profile', 'primary'])
def test_live_response_observer_cannot_be_minted(tmp_path, monkeypatch, change):
    from test_producer_startup import module as producers
    value = object.__new__(producers.NativeProducers)
    profile = tmp_path / '11.json'
    profile.write_text(json.dumps({'spec': 'sealed', 'spec_sha256': 'pinned'}))
    child = {'pid': 11, 'parent': 10, 'role': 'isolated-uv-helper', 'helper': 'build_sdist',
             'identity': {'pid': 11, 'start_ticks': 110}, 'token': 'child-token',
             'profile_sha256': hashlib.sha256(profile.read_bytes()).hexdigest()}
    parent = {'pid': 10, 'start_ticks': 100}
    value.common, value.children = {'primary_producer': {}}, {11: child}
    # A real PRIMARY descriptor is nonempty; ordinary absence cannot select it.
    value.common['primary_producer'] = {'entry': 'pinned'}
    value.response_staged, value.records = {}, []
    value.kernel = SimpleNamespace(identity=lambda pid: child['identity'] if pid == 11 else parent)
    value.interface = SimpleNamespace(
        protected_json=lambda *args: {'parent_operation': {'identity': parent}},
        original_response_output=lambda *args, **kwargs: {'profile_sha256': child['profile_sha256'],
            'member_sha256': 'a' * 64, 'sha256': 'b' * 64})
    monkeypatch.setattr(producers, 'Path', lambda path: tmp_path if str(path) == '/receipts/native-startup' else Path(path))
    request = dict(id='request', kind='source_response_output', nonce='nonce', pid=11,
                   token='child-token', identity=child['identity'])
    if change == 'extra_fields':
        request['inventory'] = {'attacker': 'claimed output'}
    elif change == 'foreign_pid':
        request['pid'] = 12
    elif change == 'token':
        request['token'] = 'stale'
    elif change == 'birth':
        value.kernel = SimpleNamespace(identity=lambda pid: {'pid': 11, 'start_ticks': 111})
    elif change == 'parent':
        value.interface.protected_json = lambda *args: {'parent_operation': {'identity': {'pid': 10, 'start_ticks': 101}}}
    elif change == 'duplicate':
        value.response_staged[11] = {}
    elif change == 'role':
        child['role'] = 'isolated-uv-query'
    elif change == 'profile':
        child['profile_sha256'] = '0' * 64
    elif change == 'primary':
        value.common = {}
    if change == 'none':
        assert value.stage_response(request)['source_response_observed'] is True
        assert value.records[0]['live_kernel_peer'] is True and 11 in value.response_staged
        with pytest.raises(RuntimeError):
            value.stage_response(request)
    else:
        with pytest.raises(RuntimeError):
            value.stage_response(request)
        assert value.records == []


def test_untrusted_response_journal_is_not_output_authority(runtime_fixture):
    # No producer-written journal record can replace the observer's staged object.
    tree = ast.parse((ROOT / 'producer_profile.py').read_text())
    function = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == 'response_receipt')
    conditions = [ast.unparse(n.test) for n in ast.walk(function) if isinstance(n, ast.If)]
    assert any(condition.startswith('produced is None or ') for condition in conditions)
    assert not any(isinstance(n, ast.Constant) and n.value == 'isolated_original_response_output' for n in ast.walk(function))


def test_live_return_hook_inverse_retains_original_native_program():
    tree = ast.parse((ROOT / 'finite/native_producer.py').read_text())
    profile = next(n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef) and n.name == 'profile_body')
    branch = profile.body[1]
    assert hashlib.sha256(ast.dump(branch, include_attributes=False).encode()).hexdigest() == '6393b13c5d5e992f40ac5c4560c9b2790a8cec51541261c4267771f59701c91b'
    profile.body.pop(1)
    assert hashlib.sha256(ast.dump(tree, include_attributes=False).encode()).hexdigest() == '4d59cdc83b63cdffb205f2524640286d217a6fc6183fe4b0b77691a1c70b854b'


@pytest.mark.parametrize('change', ['none', 'poison', 'denial', 'foreign_parent', 'parent_birth',
    'missing_query', 'duplicate_query', 'wait', 'missing_wait', 'stale_child', 'stale_profile',
    'wrong_mode', 'wrong_owner', 'wrong_helper', 'foreign_writer'])
def test_bootstrap_cache_requires_original_live_operation(tmp_path, monkeypatch, change):
    import stat
    from test_producer_startup import load_function
    profiles = tmp_path / 'profiles'
    profiles.mkdir()
    parent = {'pid': 10, 'start_ticks': 100}
    contexts = {10: {'role': 'uv', 'command': ['uv', 'run', 'pytest'], 'identity': parent}}
    records, waits = [], []
    headers = {}
    for pid, role, helper in [(11, 'query', 'query'), (12, 'editable_backend', 'get_requires_for_build_editable'),
                              (13, 'editable_backend', 'build_editable')]:
        child = {'pid': pid, 'ppid': 10, 'start_ticks': pid * 10, 'boot_id': 'current'}
        contexts[pid] = {'role': role, 'identity': child}
        header = dict(pid=pid, parent=10, start_ticks=pid * 10, boot_id='current',
                      orig_argv=[str(tmp_path / 'cache/runtime/bin/python'), '-c', helper])
        headers[pid] = header
        body = json.dumps(header).encode()
        (profiles / (str(pid) + '.json')).write_bytes(body)
        records.append(dict(kind='primary_native_preinit', pid=pid, parent=10, role=role,
                            identity=child, profile_sha256=hashlib.sha256(body).hexdigest()))
        waits.append(dict(kind='original_parent_wait4', child=pid, parent_tgid=10, raw=0))
    primary = SimpleNamespace(root=1, contexts=contexts, records=records, denials=[])
    trace = SimpleNamespace(poison=False, records=waits, active={1, 10, 20}, identities={
        1: {'tgid': 1}, 10: {'tgid': 10}, 20: {'tgid': 20, 'ppid': 10}})
    uid, mode = 20001, stat.S_IFREG | 0o444
    if change == 'poison':
        trace.poison = True
    elif change == 'denial':
        primary.denials.append('refused')
    elif change == 'foreign_parent':
        contexts[10]['role'] = 'foreign'
    elif change == 'parent_birth':
        contexts[10]['identity'] = {'pid': 10, 'start_ticks': 101}
    elif change == 'missing_query':
        contexts.pop(11)
    elif change == 'duplicate_query':
        contexts[14] = contexts[11]
    elif change == 'wait':
        waits[0]['raw'] = 256
    elif change == 'missing_wait':
        waits.pop()
    elif change == 'stale_child':
        contexts[11]['identity'] = {**contexts[11]['identity'], 'start_ticks': 111}
    elif change == 'stale_profile':
        (profiles / '11.json').write_bytes(b'{}')
    elif change == 'wrong_mode':
        mode = stat.S_IFREG | 0o644
    elif change == 'wrong_owner':
        uid = 20000
    elif change == 'wrong_helper':
        headers[12]['orig_argv'][-1] = 'foreign'
        body = json.dumps(headers[12]).encode()
        (profiles / '12.json').write_bytes(body)
        records[1]['profile_sha256'] = hashlib.sha256(body).hexdigest()
    elif change == 'foreign_writer':
        trace.active.add(30)
        trace.identities[30] = {'tgid': 30}
    real_lstat = Path.lstat
    monkeypatch.setattr(Path, 'lstat', lambda path: SimpleNamespace(st_mode=mode, st_uid=uid, st_nlink=1)
                        if path.parent == profiles else real_lstat(path))
    function = load_function('bootstrap_cache', 'producer_profile.py', {
        'Path': lambda path: profiles if str(path) == '/receipts/primary-startup' else Path(path),
        'stat': stat, 'hashlib': hashlib, 'json': json,
        'identities': SimpleNamespace(identity=lambda pid: parent),
        'load': lambda *args: SimpleNamespace(backend_request=lambda value: value),
        'hashed': lambda value: hashlib.sha256(json.dumps(value, sort_keys=True).encode()).hexdigest(),
        'cache_view': lambda *args: ({'sealed': {'type': 'file', 'sha256': 'pinned'}}, {})})
    if change == 'none':
        result = function({'cache': str(tmp_path / 'cache')}, trace, 20, primary)
        assert len(result['producers']) == 3 and len(result['external_links']) == 3
        assert result['source_checkpoint_ready'] is False and result['selected_carrier'] is None
    else:
        with pytest.raises(RuntimeError):
            function({'cache': str(tmp_path / 'cache')}, trace, 20, primary)


def test_bootstrap_cache_join_preserves_original_primary_admission():
    tree = ast.parse((ROOT / 'primary_authority.py').read_text())
    calls = [n for n in ast.walk(tree) if isinstance(n, ast.Call) and ast.unparse(n.func) == 'self.source.start']
    assert len(calls) == 1
    call = calls[0]
    assert [ast.unparse(n) for n in call.keywords] == ['trace=trace', 'primary=self']
    call.keywords = []
    assert hashlib.sha256(ast.dump(tree, include_attributes=False).encode()).hexdigest() == '779b322196c778dae817d5987556e0a9d9befc0faad7ae17540a65d9d4399f1c'
