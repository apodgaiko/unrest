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
    if (parent['pid'] != os.getppid() or parent['identity'] != identities.identity(os.getppid())
            or parent['operation'] not in ('source-build', 'source-install')
            or digest('/opt/source-bootstrap/bin/uv') != public_inputs.SOURCE_UV_ELF_SHA256
            or digest(spec['base']) != spec['base_identity']['sha256']
            or spec['base'] != '/usr/local/bin/python-source-audit'
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
