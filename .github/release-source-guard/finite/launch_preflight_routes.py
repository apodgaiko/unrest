"""Closed original LaunchPlan fixtures, preserving actual PATH search and argv0."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import stat
import sys

SOURCE = 'tests/test_launch_preflight.py'
PIN = '0bca9124dea59dc4f516eeb2a7bfe7042dd58a258a3e54b86004ef447760303a'
ALIAS_PATH = '/work/owned/pytest/test_real_spawn_preserves_exac0/adapter'
ALIAS_OWNER = 'test_real_spawn_preserves_exact_plan_fields'
ALIAS_CLASS = 'source-cohort2:' + SOURCE + ':293'
NATIVE_CLASS = 'source-launch-preflight:native'
CODE = ("import json,os,sys,pathlib;"
        "pathlib.Path(sys.argv[1]).write_text(json.dumps({"
        "'argv':sys.argv[2:],'cwd':os.getcwd(),'path':os.environ.get('PATH'),"
        "'marker':os.environ.get('MARKER')}))")
SITES = {
    'test_relative_and_empty_path_entries_use_launch_cwd[tools]': 136,
    'test_relative_and_empty_path_entries_use_launch_cwd[]': 136,
    'test_real_direct_launch_preserves_original_argv0[relative]': 211,
    'test_real_direct_launch_preserves_original_argv0[absolute]': 211,
    'test_real_bare_launch_uses_later_valid_path_candidate': 243,
    ALIAS_OWNER: 293,
    'test_direct_plan_copies_mutable_inputs_before_real_spawn': 352,
    'test_plan_preserves_legal_empty_environment_name_and_equals_value': 536,
    'test_real_invalid_format_is_distinct_safe_startup_failure': 582,
}


def specification(case, directory):
    if not case.startswith(SOURCE + '::'):
        return None
    name = case.removeprefix(SOURCE + '::')
    if name not in SITES:
        return None
    d = Path(directory)
    if not d.is_absolute() or '..' in d.parts:
        return None
    adapter = d / 'adapter'
    body = b'#!/bin/sh\nexit 0\n'
    kind, launcher, paths = 'script', adapter, [str(adapter)]
    if name.startswith('test_relative_and_empty'):
        entry = 'tools' if name.endswith('[tools]') else ''
        launcher = d / entry / 'adapter'
        argv, env, paths = ['adapter'], {'PATH': entry}, [str(Path(entry) / 'adapter')]
    elif name.startswith('test_real_direct_launch'):
        argv0 = './adapter' if name.endswith('[relative]') else str(adapter)
        argv, env, paths = [argv0, str(d / 'argv0.txt')], {'PATH': str(d / 'decoy')}, [argv0]
        body = b'#!/bin/sh\nprintf "%s" "$0" > "$1"\n'
    elif name == 'test_real_bare_launch_uses_later_valid_path_candidate':
        launcher = d / 'selected/adapter'
        argv = ['adapter', str(d / 'selected.txt')]
        env = {'PATH': str(d / 'blocked') + ':' + str(d / 'selected')}
        paths = [str(d / 'blocked/adapter'), str(launcher)]
        body = b'#!/bin/sh\nprintf selected > "$1"\n'
    elif name == ALIAS_OWNER:
        kind, body = 'python-alias', None
        argv, env = ['adapter', '-c', CODE, str(d / 'capture.json'), 'quoted argument'], {'PATH': str(d), 'MARKER': 'exact'}
    elif name == 'test_direct_plan_copies_mutable_inputs_before_real_spawn':
        launcher = d / 'selected/adapter'
        argv, env, paths = ['adapter', str(d / 'selected.txt')], {'PATH': str(d / 'selected'), 'MARKER': 'before'}, [str(launcher)]
        body = b'#!/bin/sh\nprintf "selected" > "$1"\n'
    elif name == 'test_plan_preserves_legal_empty_environment_name_and_equals_value':
        kind, launcher, body = 'native-true', Path('/usr/bin/true'), None
        argv, env, paths = ['/usr/bin/true'], {'': 'empty-name', 'VALUE': 'before=after'}, ['/usr/bin/true']
    else:
        kind, launcher = 'invalid-format', d / 'invalid-format'
        argv, env, paths = ['./invalid-format'], {}, ['./invalid-format']
        body = b'this is executable but has no executable format\n'
    return {'owner': name.split('[')[0], 'line': SITES[name], 'kind': kind,
            'launcher': launcher, 'body': body, 'argv': argv, 'environment': env, 'paths': paths}


def fixture(spec, runtime, *, owner_uid=None):
    launcher, body = spec['launcher'], spec['body']
    before = launcher.lstat()
    def stable(info):
        # Reading exact bytes may update atime; it cannot change custody.
        return tuple(getattr(info, name) for name in (
            'st_dev', 'st_ino', 'st_mode', 'st_nlink', 'st_uid', 'st_gid',
            'st_size', 'st_mtime_ns', 'st_ctime_ns'))
    if spec['kind'] == 'python-alias':
        return (stat.S_ISLNK(before.st_mode) and launcher.resolve() == Path(runtime['realpath'])
                and hashlib.sha256(launcher.read_bytes()).hexdigest() == runtime['sha256']
                and stable(launcher.lstat()) == stable(before))
    if body is None:
        return spec['kind'] == 'native-true' and launcher == Path('/usr/bin/true')
    return (stat.S_ISREG(before.st_mode) and before.st_mode & 0o777 == 0o700
            and before.st_nlink == 1 and before.st_uid == (os.getuid() if owner_uid is None else owner_uid)
            and launcher.read_bytes() == body and stable(launcher.lstat()) == stable(before))


def select(argv, cwd, env, state, append, refuse):
    case = state.get('case', '')
    if state.get('class', '').startswith('reference:'):
        path = Path(state['guard']).with_name('execution_owner.py')
        case = sys.modules['runtime_guard'].checked_source(path, state['direct_support']['files'][str(path)])['current'](state, refuse)
    spec = specification(case, cwd) if cwd is not None else None
    if spec is None:
        return None
    from_path = Path(state['checkout']) / SOURCE
    product = Path(state['checkout']) / 'src/unrest_harness/acp_runner.py'
    root = Path(state['owned_root']) / 'pytest'
    directory = Path(cwd)
    if (state['product_pins'].get(SOURCE) != PIN or not directory.is_relative_to(root) or directory.resolve() != directory
            or argv != spec['argv'] or dict(env) != spec['environment']
            or not fixture(spec, state['runtime'])
            or spec['kind'] == 'python-alias' and str(spec['launcher']) != ALIAS_PATH):
        refuse('launch_preflight_fixture_drift')
    helper = Path(state['guard']).with_name('fallback_binding.py')
    frames = sys.modules['runtime_guard'].checked_source(helper, state['direct_support']['files'][str(helper)])['active_frames']()
    try:
        for source in (from_path, product):
            if hashlib.sha256(source.read_bytes()).hexdigest() != state['product_pins'][str(source.relative_to(state['checkout']))]:
                refuse('launch_preflight_source_drift')
        owners = {id(f): f for f in frames if f.f_code.co_filename == str(from_path) and f.f_code.co_name == spec['owner']}
        calls = {id(f): f for f in frames if f.f_code.co_filename == str(product) and f.f_code.co_name == 'spawn_launch'}
        if len(owners) != 1 or len(calls) != 1:
            refuse('launch_preflight_owner_missing')
        owner, call = next(iter(owners.values())), next(iter(calls.values()))
        for f, source in ((owner, from_path), (call, product)):
            module = sys.modules.get(f.f_globals.get('__name__'))
            expected = state['isolated_named'](state['isolated_source_code'](source), f.f_code.co_name)
            if module is None or vars(module) is not f.f_globals or f.f_code != expected:
                refuse('launch_preflight_owner_code_drift')
        plan = call.f_locals['plan']
        if (owner.f_lineno != spec['line'] or owner.f_locals['tmp_path'] != directory
                or owner.f_locals['plan'] is not plan or tuple(argv) != plan.argv
                or plan.cwd != str(cwd) or plan.environment is not env
                or plan.path != env.get('PATH') or call.f_lineno != 409
                or call.f_locals['limit'] != 64 * 1024
                or any(call.f_locals[k] != -1 for k in ('stdin', 'stdout', 'stderr'))):
            refuse('launch_preflight_plan_drift')
        binding = {'path': str(from_path), 'line': spec['line'], 'sha256': state['product_pins'][SOURCE]}
        name = ALIAS_CLASS if spec['kind'] == 'python-alias' else NATIVE_CLASS
        append({'kind': 'launch_preflight_original_plan', 'class': name, 'source_binding': binding,
                'case': case, 'argv_sha256': hashlib.sha256(json.dumps(argv).encode()).hexdigest(),
                'cwd': str(cwd), 'environment_sha256': hashlib.sha256(json.dumps(dict(env), sort_keys=True).encode()).hexdigest()})
        return {'class': name, 'python': spec['kind'] == 'python-alias', 'source_binding': binding}, argv
    finally:
        frames.clear()
