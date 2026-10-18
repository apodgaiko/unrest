"""Finite public UV renderer and protected original-source profile consumption."""
from __future__ import annotations

import ast
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import stat
import sys
import time

ROOT = Path('/receipts/producers')


def load(name, path):
    specification = importlib.util.spec_from_file_location(name, path)
    assert specification is not None and specification.loader is not None
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


public_inputs = load('producer_inputs', '/guard/producer_inputs.py')
identities = load('linux_identity', '/guard/finite/linux_identity.py')


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def hashed(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def protected_json(path, pin):
    path = Path(path)
    if path.parent != ROOT or path.is_symlink():
        raise RuntimeError('producer profile root refused')
    info = path.stat()
    body = path.read_bytes()
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != 20001
            or stat.S_IMODE(info.st_mode) != 0o444 or info.st_nlink != 1
            or hashlib.sha256(body).hexdigest() != pin):
        raise RuntimeError('producer profile custody or byte drift')
    return json.loads(body)


def events(spec):
    return [json.loads(line) for path in sorted(Path(spec['events']).glob('*.jsonl'))
            for line in path.read_text().splitlines()]


def query_package(script, spec):
    try:
        nodes = ast.parse(script).body
        assignment = nodes[1]
        if (not isinstance(assignment, ast.Assign)
                or not isinstance(assignment.value, ast.BinOp)
                or not isinstance(assignment.value.left, ast.List)
                or len(assignment.value.left.elts) != 1
                or not isinstance(assignment.value.left.elts[0], ast.Constant)):
            raise RuntimeError('query renderer shape drift')
        directory = assignment.value.left.elts[0].value
        if not isinstance(directory, str):
            raise RuntimeError('query renderer directory type drift')
    except (SyntaxError, AttributeError, IndexError, TypeError):
        raise RuntimeError('query renderer shape drift') from None
    path = Path(directory)
    if (path.parent != Path(spec['cache']) or not path.name.startswith('.tmp')
            or path.resolve() != path or path.is_symlink()):
        raise RuntimeError('query package is outside its finite UV cache')
    expected = ('import sys; sys.path = ["' + directory + '"] + sys.path; '
                'from python.get_interpreter_info import main; main()')
    if script != expected:
        raise RuntimeError('query literal renderer drift')
    wanted = {name: item['sha256'] for name, item in public_inputs.UV_EMBEDDED.items()
              if name.startswith('python/')}
    paths = list(path.rglob('*'))
    if any(item.is_symlink() for item in paths):
        raise RuntimeError('query package symlink refused')
    actual = {item.relative_to(path).as_posix(): digest(item)
              for item in paths if item.is_file()}
    if actual != wanted:
        raise RuntimeError('query generated package or cache drift')
    return {'path': str(path), 'members': actual,
            'script_sha256': hashlib.sha256(script.encode()).hexdigest()}


def consume(profile):
    spec = protected_json(profile['spec'], profile['spec_sha256'])
    parent = spec['parent_operation']
    primary = spec.get('primary_producer')
    base = '/usr/local/bin/python-primary-audit' if primary is not None else '/usr/local/bin/python-source-audit'
    if primary is not None:
        if (primary['entry'] != spec['base_identity']
                or primary['entry']['path'] != base
                or spec['cache'] != '/work/cache'
                or primary['bootstrap']['path'] != '/guard/primary_entry.py'
                or primary['consumer']['path'] != '/guard/native_entry.py'
                or any(digest(primary[key]['path']) != primary[key]['sha256']
                       for key in ('entry', 'bootstrap', 'consumer'))):
            raise RuntimeError('primary producer setup consumption drift')
    if (parent['pid'] != os.getppid() or parent['identity'] != identities.identity(os.getppid())
            or parent['operation'] not in ('source-build', 'source-install')
            or digest('/opt/source-bootstrap/bin/uv') != public_inputs.SOURCE_UV_ELF_SHA256
            or digest(spec['base']) != spec['base_identity']['sha256']
            or spec['base'] != base
            or os.getcwd() != profile['cwd'] or sys.executable != profile['orig_argv'][0]):
        raise RuntimeError('native original UV parent/runtime binding drift')
    deadline = time.monotonic() + 4
    while True:
        rows = events(spec)
        retained = [row for row in rows if row['kind'] == 'operation_retained'
                    and row['owner_pid'] == parent['owner_pid'] and row['pid'] == parent['pid']
                    and row['launch_token'] == parent['launch_token'] and row['token'] == parent['token']]
        if retained or time.monotonic() >= deadline:
            break
        if identities.identity(os.getppid()) != parent['identity']:
            raise RuntimeError('native original parent changed before retention')
        time.sleep(.001)
    admissions = [row for row in rows if row['kind'] == 'operation_admission'
                  and row['owner_pid'] == parent['owner_pid'] and row['token'] == parent['token']]
    if (len(retained) != 1 or len(admissions) != 1
            or hashed(admissions[0]) != parent['record_sha256']):
        raise RuntimeError('native actual source operation consumption missing or changed')
    if profile['role'] == 'isolated-uv-query':
        if sys.orig_argv[1:4] != ['-I', '-B', '-c'] or len(sys.orig_argv) != 5:
            raise RuntimeError('native original isolated query flags drift')
        if sys.executable != spec['query_python']:
            raise RuntimeError('native selected query interpreter drift')
        query_package(sys.orig_argv[-1], spec)
    elif sys.orig_argv[1:-1] != ['-c']:
        raise RuntimeError('native original backend flags drift')
    return spec


def primary_cache_tree(spec, emit=None):
    """Validate the primary's whole native seed plus original finite UV additions.

    Extra dependency wheels have immutable image provenance. A writable member
    that was not in that seed still needs the original finite cache predicates;
    observing it here cannot turn it into an authorized input.
    """
    primary = spec['primary_producer']
    if spec['cache'] != '/work/cache' or spec['base'] != '/usr/local/bin/python-primary-audit':
        raise RuntimeError('source_primary_cache_context_drift')
    closure = load('primary_cache_closure', '/guard/dependency_closure.py')
    seed = Path('/opt/primary-cache')
    expected = closure.inventory(seed)
    if expected != primary['cache_seed_inventory']:
        raise RuntimeError('source_primary_cache_seed_drift')
    root = Path(spec['cache'])
    def escape(root, path, resolved, info):
        if emit is None:
            return
        name = path.relative_to(root).as_posix()
        emit({'kind': 'primary_cache_first_escape',
              'input_role': 'immutable_seed' if name in expected else 'uv_runtime_addition',
              'member_sha256': hashlib.sha256(name.encode()).hexdigest(),
              'target_sha256': hashlib.sha256(str(resolved).encode()).hexdigest(),
              'contained': resolved.is_relative_to(root),
              'target_is_file': resolved.is_file(), 'target_is_directory': resolved.is_dir(),
              'link_mode': stat.S_IMODE(info.st_mode), 'link_uid': info.st_uid,
              'target_uid': resolved.stat().st_uid,
              'target_matches_runtime': resolved == Path(spec['base']),
              'target_bytes_match_runtime': resolved.is_file()
                  and digest(resolved) == spec['base_identity']['sha256'],
              'declared_seed': name in expected})
    current = closure.inventory(root, on_escape=escape)
    for name, item in expected.items():
        wanted = dict(item)
        if item['type'] == 'symlink':
            target = (seed / name).resolve(strict=True)
            if not target.is_relative_to(seed) or not target.is_dir():
                raise RuntimeError('source_primary_cache_seed_link')
            wanted['target'] = str(root / target.relative_to(seed))
        if current.get(name) != wanted:
            raise RuntimeError('source_primary_cache_input_drift')
    links = [root / name for name, item in current.items() if item['type'] == 'symlink'
             and len(Path(name).parts) == 5
             and Path(name).parts[:2] == ('wheels-v6', 'index')
             and Path(name).parts[3:] == ('setuptools', '84.0.0-py3-none-any')]
    if len(links) != 1:
        raise RuntimeError('source_cache_link_cardinality')
    link = links[0]
    target = link.resolve()
    if target.parent != root / 'archive-v0' or target.is_symlink():
        raise RuntimeError('source_cache_unknown_link')
    import zipfile
    with zipfile.ZipFile(spec['wheel']) as archive:
        payload = {n: archive.read(n) for n in archive.namelist() if not n.endswith('/')}
    actual = {p.relative_to(target).as_posix(): p.read_bytes()
              for p in target.rglob('*') if p.is_file()}
    if actual != payload:
        raise RuntimeError('source_cache_selected_wheel_drift')
    fixed = {'.gitignore': b'*', '.lock': b'',
             'CACHEDIR.TAG': b'Signature: 8a477f597d28d172789f06886806bc55',
             'sdists-v9/.git': b'', 'sdists-v9/.gitignore': b''}
    # Re-evaluate every complete file byte and every link on each consumption.
    # Only original UV interpreter records/metadata may extend the sealed seed.
    for name, item in current.items():
        if name in expected or item['type'] == 'directory':
            continue
        if item['type'] != 'file':
            raise RuntimeError('source_primary_cache_unbound_link')
        path = root / name
        parts = Path(name).parts
        permitted = (len(parts) == 3 and parts[0] == 'interpreter-v4'
                     and path.suffix == '.msgpack') or name == str(link.relative_to(root)) + '.rev'
        if name in fixed:
            if path.read_bytes() != fixed[name]:
                raise RuntimeError('source_cache_metadata_drift')
        elif not permitted:
            raise RuntimeError('source_primary_cache_unbound_member')
    rows = []
    activation = load('primary_cache_identity', '/guard/finite/operation_activation.py')
    for path in sorted(root.rglob('*')):
        if path.is_symlink():
            rows.append({'path': str(path), 'target': str(path.resolve()), 'inode': path.lstat().st_ino})
        elif path.is_dir():
            info = path.lstat()
            rows.append({'path': str(path), 'directory': [info.st_dev, info.st_ino, info.st_mode]})
        else:
            # Use the original inode/ctime/full-byte file identity shape, so
            # build-to-install comparison retains its original failure model.
            rows.append(activation.identity(path))
    return rows
