"""Closed native-producer diagnostics preserve the original refusal program."""
import ast
import hashlib
import importlib.util
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).parent
spec = importlib.util.spec_from_file_location('startup_producers', ROOT / 'linux_producers.py')
assert spec is not None and spec.loader is not None
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
ORIGINAL_RESOLVE = 'ea4f0caa50410102a19484d98bd759be780bdb5254ca684bbc7182528e2eb362'


class Inverse(ast.NodeTransformer):
    def visit_If(self, node):
        if ast.unparse(node.test) == "role == 'isolated-uv-helper' and 'primary_producer' in spec":
            assert hashlib.sha256(ast.dump(node, include_attributes=False).encode()).hexdigest() == '7117e6bfe90deac2a50e6a7bc1dacff5078b50b3ffbd7b415014e26b203c9d59'
            return None
        return self.generic_visit(node)

    def visit_Call(self, node):
        self.generic_visit(node)
        if isinstance(node.func, ast.Attribute) and node.func.attr == 'producer_check':
            assert len(node.args) == 3 and not node.keywords
            return node.args[2]
        return node

    def visit_Expr(self, node):
        if (isinstance(node.value, ast.Call) and isinstance(node.value.func, ast.Attribute)
                and node.value.func.attr == 'producer_check'):
            return None
        return self.generic_visit(node)


def inverse_pin(source):
    node = next(n for n in ast.walk(ast.parse(source))
                if isinstance(n, ast.FunctionDef) and n.name == 'resolve_child')
    return hashlib.sha256(ast.dump(Inverse().visit(node), include_attributes=False).encode()).hexdigest()


def test_diagnostic_inverse_preserves_original_resolve():
    assert inverse_pin((ROOT / 'linux_producers.py').read_text()) == ORIGINAL_RESOLVE


@pytest.mark.parametrize('old,new', [
    ("self.kernel.identity(parent) != context['identity']", 'False'),
    ("len(context['children']) >= 8", "len(context['children']) >= 9"),
    ('path != vector[0]', 'False'),
    ("Path(path).resolve() != Path(self.common['base'])", 'False'),
    ("digest(path) != self.common['base_identity']['sha256']", 'False'),
    ('environment != expected_environment', 'False'),
    ("identity['ppid'] != parent", 'False'),
    ("identity['uid'] != 20000", 'False'),
    ("context['seen_requests'].add(key)", 'pass'),
    ('return False', 'return True'),
])
def test_diagnostic_inverse_detects_admission_mutation(old, new):
    source = (ROOT / 'linux_producers.py').read_text()
    assert old in source
    assert inverse_pin(source.replace(old, new)) != ORIGINAL_RESOLVE


def producer():
    value = object.__new__(module.NativeProducers)
    value.records = []
    value.producer_diagnostic_keys = set()
    return value


def test_fixed_schema_and_global_bound():
    value = producer()
    for pid in range(1000):
        assert value.producer_check(pid, 'parent_identity', False) is False
    assert len(value.records) == len(value.producer_diagnostic_keys) == 128
    assert all(set(row) == {'kind', 'pid', 'stage', 'value'} for row in value.records)
    assert value.records[0] == {'kind': 'native_producer_predicate', 'pid': 0,
                                'stage': 'parent_identity', 'value': False}
    value.producer_check(0, 'parent_identity', True)
    assert len(value.records) == 128


@pytest.mark.parametrize('failure', ['duplicate_child', 'parent_identity', 'child_limit',
                                     'argv_path', 'realpath', 'image_bytes'])
def test_early_first_refusal_and_short_circuit(monkeypatch, failure):
    value = producer()
    context = {'identity': {'birth': 1}, 'children': list(range(8)) if failure == 'child_limit' else []}
    value.uv = {10: context}
    value.children = {11: {}} if failure == 'duplicate_child' else {}
    calls = []
    def identity(pid):
        calls.append(('identity', pid))
        return {'birth': 2 if failure == 'parent_identity' else 1}
    value.kernel = SimpleNamespace(identity=identity)
    value.common = {'base': '/base', 'base_identity': {'sha256': 'expected'}}
    class Path:
        def __init__(self, path):
            self.path = path
        def resolve(self):
            calls.append(('resolve', self.path))
            return Path('/foreign' if failure == 'realpath' else '/base')
        def __eq__(self, other):
            return self.path == other.path
    monkeypatch.setattr(module, 'Path', Path)
    def digest(path):
        calls.append(('digest', path))
        return 'foreign'
    monkeypatch.setattr(module, 'digest', digest)
    vector = ['/foreign' if failure == 'argv_path' else '/python']
    assert value.resolve_child(11, 10, '/python', vector, {}, '/') is False
    rows = value.records
    assert rows[-1]['stage'] == failure and rows[-1]['value'] is True
    assert all(row['value'] is False for row in rows[:-1])
    if failure != 'image_bytes':
        assert not any(call[0] == 'digest' for call in calls)
    if failure in {'duplicate_child', 'parent_identity', 'child_limit', 'argv_path'}:
        assert not any(call[0] == 'resolve' for call in calls)
    if failure == 'duplicate_child':
        assert calls == []


def test_original_exception_is_not_replaced():
    value = producer()
    value.uv = {10: {'identity': {}, 'children': []}}
    value.children = {}
    def broken(pid):
        raise FileNotFoundError('controlled identity loss')
    value.kernel = SimpleNamespace(identity=broken)
    with pytest.raises(FileNotFoundError, match='controlled identity loss'):
        value.resolve_child(11, 10, '/python', ['/python'], {}, '/')
    assert [row['stage'] for row in value.records] == ['duplicate_child']


def load_function(name, filename, namespace):
    node = next(n for n in ast.parse((ROOT / filename).read_text()).body
                if isinstance(n, ast.FunctionDef) and n.name == name)
    exec(compile(ast.Module(body=[node], type_ignores=[]), filename, 'exec'), namespace)
    return namespace[name]


@pytest.mark.parametrize('change', ['none', 'base', 'cache', 'entry', 'bootstrap', 'consumer', 'bytes'])
def test_primary_producer_consumer_has_one_exact_context(change):
    setup = {'entry': {'path': '/usr/local/bin/python-primary-audit', 'sha256': 'entry'},
             'bootstrap': {'path': '/guard/primary_entry.py', 'sha256': 'bootstrap'},
             'consumer': {'path': '/guard/native_entry.py', 'sha256': 'consumer'}}
    spec = {'primary_producer': setup, 'base': '/usr/local/bin/python-primary-audit',
            'base_identity': dict(setup['entry']), 'cache': '/work/cache',
            'parent_operation': {'pid': 10, 'identity': {'birth': 1}, 'operation': 'source-build'}}
    if change == 'base':
        spec['base'] = '/usr/local/bin/python-source-audit'
    elif change == 'cache':
        spec['cache'] = '/work/producer-cache'
    elif change in {'entry', 'bootstrap', 'consumer'}:
        setup[change] = {**setup[change], 'path': '/foreign'}
    class ReachedOriginalChecks(Exception):
        pass
    def digest(path):
        if path == '/opt/source-bootstrap/bin/uv':
            return 'uv'
        if path == '/usr/local/bin/python-source-audit':
            return 'entry'
        return 'foreign' if change == 'bytes' else next(
            item['sha256'] for item in setup.values() if item['path'] == path)
    consume = load_function('consume', 'producer_profile.py', {
        'protected_json': lambda *args: spec,
        'os': SimpleNamespace(getppid=lambda: 10),
        'identities': SimpleNamespace(identity=lambda pid: {'birth': 1}),
        'digest': digest,
        'public_inputs': SimpleNamespace(SOURCE_UV_ELF_SHA256='uv'),
        'sys': SimpleNamespace(executable='/selected/python'),
        'time': SimpleNamespace(monotonic=lambda: (_ for _ in ()).throw(ReachedOriginalChecks())),
    })
    spec['cwd'] = '/source'
    consume.__globals__['os'].getcwd = lambda: '/source'
    profile = {'spec': 'protected', 'spec_sha256': 'protected',
               'cwd': '/source', 'orig_argv': ['/selected/python']}
    if change == 'none':
        with pytest.raises(ReachedOriginalChecks):
            consume(profile)
    else:
        with pytest.raises(RuntimeError, match='producer setup consumption drift|parent/runtime binding drift'):
            consume(profile)



@pytest.mark.parametrize('change', ['none', 'image_path', 'image_bytes', 'realpath',
                                     'consumer_path', 'consumer_bytes', 'header', 'symlink'])
def test_primary_native_producer_branch_requires_exact_image_header_and_consumer(change):
    called = []
    data = b"CALLED.append('consumed')"
    image = b'exact image'
    header_bytes = b'exact protected native header'
    def sha(body):
        return hashlib.sha256(body).hexdigest()
    profile = {'source_role': 'source-producer-child',
               'producer_image': {'path': '/usr/local/bin/python-primary-audit', 'sha256': sha(image)},
               'producer_consumer': {'path': '/guard/native_entry.py', 'sha256': sha(data)},
               'native_profile_sha256': sha(header_bytes)}
    if change == 'image_path':
        profile['producer_image']['path'] = '/foreign'
    if change == 'consumer_path':
        profile['producer_consumer']['path'] = '/foreign'
    class Path:
        def __init__(self, path):
            self.path = path
        def __truediv__(self, suffix):
            return Path(self.path + '/' + suffix)
        def __str__(self):
            return self.path
        def __eq__(self, other):
            return self.path == other.path
        def resolve(self):
            return Path('/foreign' if change == 'realpath' else '/usr/local/bin/python-primary-audit')
        def is_symlink(self):
            return change == 'symlink'
        def read_bytes(self):
            if self.path == '/guard/native_entry.py':
                return b'foreign' if change == 'consumer_bytes' else data
            if self.path == '/proc/self/exe':
                return b'foreign' if change == 'image_bytes' else image
            return b'foreign' if change == 'header' else header_bytes
    class Exit(Exception):
        pass
    def exit(code):
        assert code == 86
        raise Exit
    import types
    original_module = types.ModuleType
    def fresh_module(name):
        module = original_module(name)
        module.CALLED = called
        return module
    monkey = pytest.MonkeyPatch()
    monkey.setattr(types, 'ModuleType', fresh_module)
    main = next(n for n in ast.parse((ROOT / 'primary_entry.py').read_text()).body
                if isinstance(n, ast.FunctionDef) and n.name == 'main')
    branch = next(n for n in main.body if isinstance(n, ast.If)
                  and "'source-producer-child'" in ast.unparse(n.test))
    function = ast.FunctionDef(name='branch', args=ast.arguments(
        posonlyargs=[], args=[], kwonlyargs=[], kw_defaults=[], defaults=[]),
        body=[branch], decorator_list=[])
    namespace = {'profile': profile, 'Path': Path, 'hashlib': hashlib, 'str': str,
                 'os': SimpleNamespace(getpid=lambda: 11, _exit=exit),
                 'sys': SimpleNamespace(executable='/selected/bin/python', modules={}),
                 'event': 'cpython.run_command', 'arguments': ('exact command',)}
    exec(compile(ast.fix_missing_locations(ast.Module(body=[function], type_ignores=[])),
                 '<native branch>', 'exec'), namespace)
    try:
        if change == 'none':
            namespace['branch']()
            assert called == ['consumed']
        else:
            with pytest.raises(Exit):
                namespace['branch']()
            assert called == []
    finally:
        monkey.undo()


def test_primary_native_producer_preserves_full_original_fd_census():
    tree = ast.parse((ROOT / 'primary_entry.py').read_text())
    main = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == 'main')
    index = next(i for i, n in enumerate(main.body) if isinstance(n, ast.If)
                 and "'source-producer-child'" in ast.unparse(n.test))
    previous = main.body[index - 1]
    assert isinstance(previous, ast.If)
    assert ast.unparse(previous.test) == 'actual_descriptors != expected_descriptors'
    assert ast.unparse(previous.body[0]) == 'os._exit(86)'


# Preserve the original whole-authority oracle while separately pinning the
# dedicated producer-header integration and its only resolve call site.
PRIMARY_PRODUCER_PROFILE_AST = '9c33d1b8016d083799b251bc3021a46315880abb11f484a2ea17885c01fd6dee'


def restore_producer_profile(tree):
    cls = next(n for n in tree.body if isinstance(n, ast.ClassDef) and n.name == 'SourceAuthority')
    method = next(n for n in cls.body if isinstance(n, ast.FunctionDef) and n.name == 'producer_profile')
    assert hashlib.sha256(ast.dump(method, include_attributes=False).encode()).hexdigest() == PRIMARY_PRODUCER_PROFILE_AST
    cls.body.remove(method)
    expected = ast.dump(ast.parse('self.producer_profile(pid, parent, vector, environment, cwd)').body[0],
                        include_attributes=False)
    class Remove(ast.NodeTransformer):
        removed = 0
        def visit_Expr(self, node):
            if ast.dump(node, include_attributes=False) == expected:
                self.removed += 1
                return None
            return self.generic_visit(node)
    inverse = Remove()
    inverse.visit(tree)
    assert inverse.removed == 1
    return tree


@pytest.mark.parametrize('before,after', [
    ("actual != item['identity']", 'False'),
    ("actual['ppid'] != parent", 'False'),
    ("self.common['base'] != PYTHON", 'False'),
    ("sha(native_path) != item['profile_sha256']", 'False'),
    ("native['environment'] != environment", 'False'),
    ("'source_role': 'source-producer-child'", "'source_role': 'source-root'"),
    ('self.producer_profile(pid, parent, vector, environment, cwd)', 'pass'),
])
def test_header_integration_inverse_rejects_mutation(before, after):
    source = (ROOT / 'primary_source_authority.py').read_text()
    assert before in source
    with pytest.raises(AssertionError):
        restore_producer_profile(ast.parse(source.replace(before, after)))


PRIMARY_CACHE_BRANCH_AST = '6a80bae6754714e7af88928d900ef9b5bbed452e201d6978a5611eb7fb10fab6'


def restore_primary_cache(tree):
    method = next(n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef) and n.name == 'cache_tree')
    # Remove only the closed diagnostic sink, leaving the original authority
    # prefix's separately pinned expression program intact.
    for node in ast.walk(method):
        if (isinstance(node, ast.Call) and isinstance(node.func, ast.Subscript)
                and ast.unparse(node.func) == "namespace['primary_cache_tree']"):
            assert ast.unparse(node) == "namespace['primary_cache_tree'](self.spec, self.emit, self.state['operations'])"
            node.args = node.args[:1]
    prefix = ast.Module(body=method.body[:2], type_ignores=[])
    assert hashlib.sha256(ast.dump(prefix, include_attributes=False).encode()).hexdigest() == PRIMARY_CACHE_BRANCH_AST
    method.body = method.body[2:]
    return tree


@pytest.mark.parametrize('old,new', [
    ("primary is not None", 'True'),
    ("support['path'] != '/guard/producer_profile.py'", 'False'),
    ("hashlib.sha256(body).hexdigest() != support['sha256']", 'False'),
    ("self.refuse(str(error))", 'pass'),
])
def test_cache_branch_inverse_rejects_weakening(old, new):
    source = (ROOT / 'finite/source_activation.py').read_text()
    assert old in source
    with pytest.raises(AssertionError):
        restore_primary_cache(ast.parse(source.replace(old, new)))


@pytest.mark.parametrize('change', [
    'none', 'cache_context', 'base_context', 'seed_bytes', 'seed_mode',
    'seed_input_bytes', 'seed_input_mode', 'seed_input_missing', 'seed_input_link',
    'backend_payload', 'extra_writer', 'extra_link', 'extra_empty_directory', 'source_minted_inventory',
    'interpreter_record', 'bad_interpreter_record',
])
def test_primary_cache_exact_seed_backend_and_finite_additions(tmp_path, change, monkeypatch):
    import shutil
    import zipfile
    closure_spec = importlib.util.spec_from_file_location('cache_closure', ROOT / 'dependency_closure.py')
    closure = importlib.util.module_from_spec(closure_spec)
    closure_spec.loader.exec_module(closure)
    identity_spec = importlib.util.spec_from_file_location('cache_identity', ROOT / 'finite/operation_activation.py')
    activation = importlib.util.module_from_spec(identity_spec)
    identity_spec.loader.exec_module(activation)
    seed, current = tmp_path / 'seed', tmp_path / 'cache'
    backend = seed / 'archive-v0/backend'
    backend.mkdir(parents=True)
    (backend / 'backend.py').write_bytes(b'original selected backend')
    other = seed / 'archive-v0/dependency'
    other.mkdir()
    (other / 'dependency.py').write_bytes(b'original dependency')
    for package, target in [('setuptools/84.0.0-py3-none-any', backend),
                            ('dependency/1.0-py3-none-any', other)]:
        link = seed / 'wheels-v6/index/exact-publisher' / package
        link.parent.mkdir(parents=True, exist_ok=True)
        link.symlink_to(target)
    shutil.copytree(seed, current, symlinks=True)
    for path in current.rglob('*'):
        if path.is_symlink():
            target = path.resolve().relative_to(seed)
            path.unlink()
            path.symlink_to(current / target)
    wheel = tmp_path / 'selected.whl'
    with zipfile.ZipFile(wheel, 'w') as archive:
        archive.writestr('backend.py', b'original selected backend')
    spec = {'primary_producer': {'cache_seed_inventory': closure.inventory(seed)},
            'cache': '/work/cache', 'base': '/usr/local/bin/python-primary-audit', 'wheel': str(wheel)}
    original_path = Path
    def mapped(path):
        return {'/opt/primary-cache': seed, '/work/cache': current}.get(str(path), original_path(path))
    cache_tree = load_function('primary_cache_tree', 'producer_profile.py', {
        'Path': mapped, 'os': __import__('os'), 'hashlib': hashlib, 'load': lambda name, path: closure if path.endswith('dependency_closure.py') else activation,
        'original_runtime_outputs': lambda spec, operations: {},
        'primary_inventory': load_function('primary_inventory', 'producer_profile.py', {
            'stat': __import__('stat'), 'os': __import__('os'), 'load': lambda *args: activation,
            'digest': lambda path: hashlib.sha256(path.read_bytes()).hexdigest()})})
    original_lstat = Path.lstat
    class OwnedInfo:
        def __init__(self, value):
            self.value = value
        def __getattr__(self, key):
            return 20000 if key == 'st_uid' else getattr(self.value, key)
        def __eq__(self, other):
            return self.value == other.value
    monkeypatch.setattr(Path, 'lstat', lambda path: OwnedInfo(original_lstat(path)))
    if change == 'cache_context':
        spec['cache'] = '/work/foreign'
    elif change == 'base_context':
        spec['base'] = '/usr/local/bin/python-source-audit'
    elif change == 'seed_bytes':
        (other / 'dependency.py').write_bytes(b'altered readonly origin')
    elif change == 'seed_mode':
        (other / 'dependency.py').chmod(0o777)
    elif change == 'seed_input_bytes':
        (current / 'archive-v0/dependency/dependency.py').write_bytes(b'foreign')
    elif change == 'seed_input_mode':
        (current / 'archive-v0/dependency/dependency.py').chmod(0o777)
    elif change == 'seed_input_missing':
        (current / 'archive-v0/dependency/dependency.py').unlink()
    elif change == 'seed_input_link':
        link = current / 'wheels-v6/index/exact-publisher/dependency/1.0-py3-none-any'
        link.unlink()
        link.symlink_to(current / 'archive-v0/backend')
    elif change == 'backend_payload':
        with zipfile.ZipFile(wheel, 'w') as archive:
            archive.writestr('backend.py', b'foreign selected backend')
    elif change == 'extra_empty_directory':
        (current / 'unknown-empty-directory').mkdir()
    elif change == 'extra_writer':
        (current / 'foreign.py').write_bytes(b'unrelated writable cache writer')
    elif change == 'extra_link':
        (current / 'foreign').symlink_to(current / 'archive-v0/dependency')
    elif change == 'source_minted_inventory':
        (current / 'foreign.py').write_bytes(b'cannot mint observer input')
        spec['primary_producer']['cache_seed_inventory'] = closure.inventory(current)
    elif change in {'interpreter_record', 'bad_interpreter_record'}:
        record = current / 'interpreter-v4/exact/key.msgpack'
        record.parent.mkdir(parents=True)
        record.with_suffix('.py' if change == 'bad_interpreter_record' else '.msgpack').write_bytes(b'original finite UV record')
    if change in {'none', 'interpreter_record'}:
        rows = cache_tree(spec)
        assert rows and all(set(row) in ({'path', 'target', 'inode'}, {'path', 'directory'},
                                        set(activation.identity(current / 'archive-v0/backend/backend.py')))
                            for row in rows)
        assert len([row for row in rows if 'target' in row]) == 2
    else:
        with pytest.raises(RuntimeError):
            cache_tree(spec)
