"""Recognize only the two original in-process negative resource-lifetime sessions."""
from __future__ import annotations

import ast
import hashlib
import inspect
import os
from pathlib import Path
import stat
import sys
import types

SOURCE = 'tests/test_session_resource_ownership.py'
OWNER = 'test_actual_pytest_failure_finalizes_exact_factory'
CASES = frozenset(SOURCE + '::' + OWNER + '[' + phase + ']' for phase in ('setup', 'body'))


def active_frames():
    frame = inspect.currentframe().f_back
    result = []
    while frame is not None:
        result.append(frame)
        frame = frame.f_back
    return result


def literal(body):
    tree = ast.parse(body)
    function = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == OWNER)
    writes = [n for n in ast.walk(function) if isinstance(n, ast.Call)
              and isinstance(n.func, ast.Attribute) and isinstance(n.func.value, ast.Name)
              and n.func.value.id == 'source' and n.func.attr == 'write_text']
    if len(writes) != 1 or len(writes[0].args) != 1 or writes[0].keywords:
        raise ValueError('nested_source_shape')
    replacement = writes[0].args[0]
    if (not isinstance(replacement, ast.Call) or not isinstance(replacement.func, ast.Attribute)
            or replacement.func.attr != 'replace' or not isinstance(replacement.func.value, ast.Constant)
            or type(replacement.func.value.value) is not str
            or len(replacement.args) != 2 or ast.unparse(replacement.args[0]) != "'PHASE'"
            or ast.unparse(replacement.args[1]) != 'repr(phase)'
            or replacement.keywords):
        raise ValueError('nested_source_shape')
    return replacement.func.value.value


def owned(guard, args, plugins):
    state = guard._STATE
    if state.get('case') not in CASES:
        return False
    if (plugins is not None or state.get('class') != 'pytest-root'
            or state.get('token') != 'root' or state.get('checkout') != '/source'):
        guard.refuse('primary_nested_owner_scope')
    source = Path(state['checkout']) / SOURCE
    body = source.read_bytes()
    pin = hashlib.sha256(body).hexdigest()
    if pin != state['product_pins'].get(SOURCE):
        guard.refuse('primary_nested_source_drift')
    code = state['isolated_named'](state['isolated_source_code'](source), OWNER)
    frames = active_frames()
    try:
        owners = {id(f): f for f in frames if f.f_code == code
                  and f.f_code.co_filename == str(source)}
        if len(owners) != 1:
            guard.refuse('primary_nested_live_owner')
        frame = next(iter(owners.values()))
        module = sys.modules.get(frame.f_globals.get('__name__'))
        function = getattr(module, OWNER, None)
        local = frame.f_locals
        phase = local.get('phase')
        if (module is None or vars(module) is not frame.f_globals
                or not isinstance(function, types.FunctionType)
                or function.__globals__ is not frame.f_globals or function.__code__ is not frame.f_code
                or frame.f_lineno != 267 or phase not in ('setup', 'body')
                or state['case'] != SOURCE + '::' + OWNER + '[' + phase + ']'):
            guard.refuse('primary_nested_original_identity')
        temporary, target, root = local['tmp_path'], local['source'], local['root']
        expected = ['-c', str(root / 'pyproject.toml'), '-q', str(target)]
        observer = local.get('observer')
        if (type(args) not in (list, tuple) or list(args) != expected or root != Path('/source')
                or target != temporary / ('test_owned_failure_' + phase + '.py')
                or target.resolve() != target or not target.parent.resolve().is_relative_to(Path(state['owned_root']))
                or os.getcwd() != str(root) or type(observer) is not types.ModuleType
                or observer.__name__ != '_session_ownership_observer'
                or sys.modules.get(observer.__name__) is not observer
                or type(observer.owners) is not list or observer.owners):
            guard.refuse('primary_nested_invocation_binding')
        before = target.lstat()
        generated = target.read_bytes()
        after = target.lstat()
        fields = ('st_dev', 'st_ino', 'st_mode', 'st_uid', 'st_gid', 'st_nlink',
                  'st_size', 'st_mtime_ns', 'st_ctime_ns')
        if (not stat.S_ISREG(before.st_mode) or before.st_uid != os.geteuid() or before.st_nlink != 1
                or generated != literal(body).replace('PHASE', repr(phase)).encode()
                or any(getattr(after, key) != getattr(before, key) for key in fields)):
            guard.refuse('primary_nested_generated_source')
        guard.append({'kind': 'primary_owned_nested_pytest', 'phase': phase,
                      'source_sha256': hashlib.sha256(generated).hexdigest(),
                      'source_binding': {'path': str(source), 'line': 267, 'sha256': pin}})
        return True
    finally:
        frames.clear()
