"""Fresh filesystem capture compared with the preceding direct implementations."""
import ast
import hashlib
import json
import os
from pathlib import Path
import stat
import types

import pytest

ROOT = Path(__file__).parent
# Public predecessor implementations, not derivations of the replacement.
REFERENCE = {
    'operation_activation.py': r'''def identity(path):
    path = Path(path)
    before = path.lstat()
    if not stat.S_ISREG(before.st_mode):
        raise RuntimeError('activation_nonregular_input')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        opened = os.fstat(fd)
        with os.fdopen(fd, 'rb', closefd=False) as stream:
            digest = hashlib.file_digest(stream, 'sha256').hexdigest()
        after = os.fstat(fd)
    finally:
        os.close(fd)
    def key(info):
        return (info.st_dev, info.st_ino, info.st_mode, info.st_size,
                info.st_mtime_ns, info.st_ctime_ns)
    if key(before) != key(opened) or key(after) != key(before) or key(after) != key(path.lstat()):
        raise RuntimeError('activation_input_read_race')
    return {'path': str(path), 'identity': list(key(after)), 'sha256': digest}

def tree(root):
    root = Path(root)
    result = []
    for path in [root, *sorted(root.rglob('*'))]:
        info = path.lstat()
        if stat.S_ISDIR(info.st_mode):
            result.append({'path': str(path), 'directory': [info.st_dev, info.st_ino, info.st_mode]})
        else:
            result.append(identity(path))
    return result''',
    'source_operations.py': r'''def identity(path):
    path = Path(path)
    before = path.lstat()
    if not stat.S_ISREG(before.st_mode):
        raise RuntimeError("operation input is not a regular file")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        opened = os.fstat(fd)
        if (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino):
            raise RuntimeError("operation input replaced before read")
        with os.fdopen(fd, "rb", closefd=False) as stream:
            digest = hashlib.file_digest(stream, "sha256").hexdigest()
        after = os.fstat(fd)
    finally:
        os.close(fd)

    def key(s):
        return (s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns, s.st_mode)

    if key(before) != key(after) or key(after) != key(path.lstat()):
        raise RuntimeError("operation input changed during capture")
    return {
        "path": str(path),
        "device": before.st_dev,
        "inode": before.st_ino,
        "size": before.st_size,
        "mode": before.st_mode,
        "mtime_ns": before.st_mtime_ns,
        "ctime_ns": before.st_ctime_ns,
        "sha256": digest,
    }

def root_identity(root):
    path = Path(root)
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode) or path.resolve() != path:
        raise RuntimeError("operation root is not a direct directory")
    return {"root": str(path), "device": info.st_dev, "inode": info.st_ino, "mode": info.st_mode}

def tree_identity(root):
    result = root_identity(root)
    files = []
    directories = []
    for path in sorted(Path(root).rglob("*")):
        if path.is_symlink():
            raise RuntimeError("operation tree contains a symlink")
        if path.is_file():
            files.append(identity(path))
        elif path.is_dir():
            directories.append(root_identity(path))
        else:
            raise RuntimeError("operation tree contains a special file")
    if root_identity(root) != result:
        raise RuntimeError("operation root replaced during capture")
    return {**result, "files": files, "directories": directories}''',
}
REFERENCE_SHA256 = {'operation_activation.py': '990957b12f36bf1798accb954fde72434a4abdb67b80d62f1bd10515eac348ae', 'source_operations.py': '966fb6363b02dbe034c5640450832845d1b3bd2d0769e78f24867fa08009557c'}


def load(name, original=False):
    body = REFERENCE[name] if original else (ROOT / 'finite' / name).read_text()
    assert hashlib.sha256(REFERENCE[name].encode()).hexdigest() == REFERENCE_SHA256[name]
    names = {'identity', 'tree', 'root_identity', 'tree_identity'}
    nodes = [n for n in ast.parse(body).body if isinstance(n, ast.FunctionDef) and n.name in names]
    namespace = {'Path': Path, 'os': os, 'stat': stat, 'hashlib': hashlib}
    exec(compile(ast.Module(body=nodes, type_ignores=[]), str(ROOT / 'finite' / name), 'exec'), namespace)
    return namespace


@pytest.fixture(params=['operation_activation.py', 'source_operations.py'])
def implementations(request):
    name = request.param
    a, b = load(name, True), load(name)
    key = 'tree' if name == 'operation_activation.py' else 'tree_identity'
    return a, b, key


def fixture(root):
    root.mkdir()
    for name in ['é', 'a-z', 'a', 'a.b', 'Ω', 'a0']:
        folder = root / name
        folder.mkdir()
        (folder / 'payload').write_bytes(b'original')
    (root / 'empty').touch()
    return root


def outcome(function, root):
    try:
        return ('value', function(root))
    except (OSError, RuntimeError) as error:
        return ('refusal', type(error).__name__, str(error))


def test_complete_vectors_and_serialization(implementations, tmp_path):
    a, b, key = implementations
    root = fixture(tmp_path / 'tree')
    expected, observed = a[key](root), b[key](root)
    assert observed == expected
    assert json.dumps(observed, sort_keys=True) == json.dumps(expected, sort_keys=True)
    assert a[key](str(root)) == b[key](str(root))
    assert a['identity'](root / 'a/payload') == b['identity'](root / 'a/payload')


@pytest.mark.parametrize('change', ['bytes', 'same-size', 'mode', 'owner', 'timestamp',
                                   'inode', 'path-replacement', 'directory-replacement',
                                   'missing', 'additional', 'symlink', 'directory-symlink', 'fifo'])
def test_every_capture_observes_post_first_invocation_mutation(implementations, tmp_path, change):
    a, b, key = implementations
    root = fixture(tmp_path / 'tree')
    before = b[key](root)
    assert before == a[key](root)
    path = root / 'a/payload'
    if change in {'bytes', 'same-size'}:
        path.write_bytes(b'modified' if change == 'same-size' else b'longer changed payload')
    elif change == 'mode':
        path.chmod(0o400)
    elif change == 'owner':
        os.chown(path, -1, os.getgid())
    elif change == 'timestamp':
        info = path.stat()
        os.utime(path, ns=(info.st_atime_ns, info.st_mtime_ns + 1000000000))
    elif change in {'inode', 'path-replacement'}:
        body = path.read_bytes()
        path.rename(tmp_path / 'old-file')
        path.write_bytes(body)
    elif change == 'directory-replacement':
        root.rename(tmp_path / 'old-tree')
        fixture(root)
    elif change == 'missing':
        path.unlink()
    elif change == 'additional':
        (root / 'new').write_bytes(b'new')
    elif change == 'symlink':
        path.unlink()
        path.symlink_to(root / 'empty')
    elif change == 'directory-symlink':
        (root / 'link').symlink_to(root / 'a', target_is_directory=True)
    else:
        os.mkfifo(root / 'fifo')
    expected, observed = outcome(a[key], root), outcome(b[key], root)
    assert observed == expected
    assert observed != ('value', before)


@pytest.mark.parametrize('when', ['opened', 'after', 'path'])
def test_read_races_match_direct_original(implementations, tmp_path, monkeypatch, when):
    a, b, _ = implementations
    root = fixture(tmp_path / 'tree')
    path = root / 'a/payload'
    real_fstat, real_stat = os.fstat, os.stat
    def capture(fn):
        calls = 0
        def fstat(fd):
            nonlocal calls
            calls += 1
            info = real_fstat(fd)
            if (when == 'opened' and calls == 1) or (when == 'after' and calls == 2):
                fields = {k: getattr(info, k) for k in ('st_dev', 'st_ino', 'st_size', 'st_mode', 'st_mtime_ns', 'st_ctime_ns')}
                fields['st_ino' if when == 'opened' else 'st_ctime_ns'] += 1
                return types.SimpleNamespace(**fields)
            return info
        path_stats = 0
        def stat_path(p, *args, **kwargs):
            nonlocal path_stats
            info = real_stat(p, *args, **kwargs)
            path_stats += 1
            if when == 'path' and path_stats == 2:
                fields = {k: getattr(info, k) for k in ('st_dev', 'st_ino', 'st_size', 'st_mode', 'st_mtime_ns', 'st_ctime_ns')}
                fields['st_ino'] += 1
                return types.SimpleNamespace(**fields)
            return info
        with monkeypatch.context() as patch:
            patch.setattr(os, 'fstat', fstat)
            patch.setattr(os, 'stat', stat_path)
            return outcome(fn, path)
    assert capture(a['identity']) == capture(b['identity'])
    assert capture(b['identity'])[0] == 'refusal'


def test_fresh_syscall_sequence_is_identical(implementations, tmp_path, monkeypatch):
    a, b, key = implementations
    root = fixture(tmp_path / 'tree')
    actual = {name: getattr(os, name) for name in ('stat', 'fstat', 'open', 'fdopen', 'close')}
    def exercise(function):
        rows = []
        def wrapper(name):
            def called(*args, **kwargs):
                values = list(args)
                if values and isinstance(values[0], Path):
                    values[0] = str(values[0])
                rows.append((name, values, kwargs))
                return actual[name](*args, **kwargs)
            return called
        with monkeypatch.context() as patch:
            for name in actual:
                patch.setattr(os, name, wrapper(name))
            result = function(root)
        return result, rows
    expected, calls = exercise(a[key])
    observed, current = exercise(b[key])
    assert observed == expected
    assert current == calls
    opens = [r for r in current if r[0] == 'open']
    assert len(opens) == 7
    assert all(row[1][1] & os.O_NOFOLLOW for row in opens)
    assert len([r for r in current if r[0] == 'fstat']) == 14


def test_operations_inputs_stays_fresh_on_each_call(tmp_path):
    body = ast.parse((ROOT / 'finite/source_operations.py').read_bytes())
    owner = next(n for n in body.body if isinstance(n, ast.ClassDef) and n.name == 'Operations')
    method = next(n for n in owner.body if isinstance(n, ast.FunctionDef) and n.name == 'inputs')
    namespace = load('source_operations.py')
    namespace.update({'_diagnostic_mark': lambda *args: None,
                      'hashed': lambda value: hashlib.sha256(json.dumps(value, sort_keys=True).encode()).hexdigest()})
    exec(compile(ast.Module(body=[method], type_ignores=[]), str(ROOT / 'finite/source_operations.py'), 'exec'), namespace)
    root = fixture(tmp_path / 'tree')
    def refuse(reason):
        raise RuntimeError(reason)
    self = types.SimpleNamespace(spec={'files': [], 'trees': [namespace['tree_identity'](root)]}, refuse=refuse)
    namespace['inputs'](self)
    (root / 'a/payload').write_bytes(b'modified')
    with pytest.raises(RuntimeError, match='source_operation_dependency_site_drift'):
        namespace['inputs'](self)


@pytest.mark.parametrize('change', ['missing-root', 'root-symlink', 'root-file'])
def test_root_refusals_match_direct_original(implementations, tmp_path, change):
    a, b, key = implementations
    root = fixture(tmp_path / 'tree')
    root.rename(tmp_path / 'old')
    if change == 'root-symlink':
        root.symlink_to(tmp_path / 'old', target_is_directory=True)
    elif change == 'root-file':
        root.write_bytes(b'file')
    assert outcome(a[key], root) == outcome(b[key], root)


def test_shared_startup_runs_both_checks_again_after_first_call(tmp_path):
    tree = ast.parse((ROOT / 'finite/source_activation.py').read_bytes())
    owner = next(n for n in tree.body if isinstance(n, ast.ClassDef) and n.name == 'SourceActivation')
    method = next(n for n in owner.body if isinstance(n, ast.FunctionDef) and n.name == 'shared')
    namespace = load('operation_activation.py')
    namespace['_diagnostic_mark'] = lambda *args: None
    exec(compile(ast.Module(body=[method], type_ignores=[]), str(ROOT / 'finite/source_activation.py'), 'exec'), namespace)
    root = fixture(tmp_path / 'tree')
    link = tmp_path / 'python'
    link.symlink_to(root / 'empty')
    calls = []
    operations = types.SimpleNamespace(inputs=lambda: calls.append('inputs'))
    def refuse(reason):
        raise RuntimeError(reason)
    self = types.SimpleNamespace(
        state={'token': 'test', 'operations': operations}, ready=lambda token: calls.append('ready'), refuse=refuse,
        spec={'shared_files': [], 'shared_trees': {str(root): namespace['tree'](root)},
              'shared_absent': [], 'shared_python_link': {'path': str(link),
              'target': str(root / 'empty'), 'inode': link.lstat().st_ino}})
    namespace['shared'](self)
    namespace['shared'](self)
    assert calls == ['ready', 'inputs', 'ready', 'inputs']
    (root / 'a/payload').write_bytes(b'modified')
    with pytest.raises(RuntimeError, match='source_shared_startup_membership_drift'):
        namespace['shared'](self)
    assert calls == ['ready', 'inputs', 'ready', 'inputs', 'ready']
