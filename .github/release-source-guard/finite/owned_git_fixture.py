"""Suppress incidental maintenance only in the exact owned inventory fixture repo."""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
import stat
import sys
import types

SOURCE = 'tests/test_acp_runner.py'
PIN = 'b6f1c200a94c1107d6059baae0eb646dd5a113cc304d7062b29aec8263dd52d0'
OWNER = 'test_real_mcp_inventory_fd_redacts_before_crash_and_restart'
CASE = SOURCE + '::' + OWNER + '[worker]'
COMMAND = ['git', 'commit', '--allow-empty', '--quiet', '-m', 'base']
SUFFIX = b'[maintenance]\n\tauto = false\n[gc]\n\tauto = 0\n'


def key(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
            info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def configure(frame, argv, directory, environment, state, append, refuse):
    source = Path(state['checkout']) / SOURCE
    if (state.get('case') != CASE or state.get('class') != 'pytest-root'
            or state.get('token') != 'root' or state.get('checkout') != '/source'
            or argv != COMMAND):
        refuse('owned_git_fixture_context')
    if (state['product_pins'].get(SOURCE) != PIN
            or hashlib.sha256(source.read_bytes()).hexdigest() != PIN):
        refuse('owned_git_fixture_source')
    code = state['isolated_named'](state['isolated_source_code'](source), OWNER)
    module = sys.modules.get(frame.f_globals.get('__name__'))
    function = getattr(module, OWNER, None)
    local = frame.f_locals
    previous = local.get('git_process')
    root = Path(state['owned_root']).resolve()
    directory = Path(directory)
    if (frame.f_code != code or frame.f_code.co_filename != str(source) or frame.f_lineno != 214
            or module is None or vars(module) is not frame.f_globals
            or not isinstance(function, types.FunctionType) or function.__code__ is not frame.f_code
            or function.__globals__ is not frame.f_globals or local.get('mode') != 'worker'
            or local.get('git_args') != tuple(COMMAND[1:])
            or type(environment) is not dict or environment != local.get('git_environment')
            or environment.get('GIT_CONFIG_GLOBAL') != os.devnull
            or environment.get('GIT_CONFIG_NOSYSTEM') != '1'
            or directory != local.get('workspace') or directory.resolve(strict=True) != directory
            or not directory.is_relative_to(root) or directory == root
            or previous is None or type(previous.pid) is not int or previous.pid <= 0
            or type(previous.returncode) is not int or previous.returncode != 0):
        refuse('owned_git_fixture_binding')
    git = directory / '.git'
    if git.is_symlink() or not git.is_dir() or git.resolve(strict=True) != git:
        refuse('owned_git_fixture_repository')
    target = git / 'config'
    before = target.lstat()
    if (not stat.S_ISREG(before.st_mode) or before.st_uid != os.getuid()
            or before.st_nlink != 1 or not 0 < before.st_size <= 65536):
        refuse('owned_git_fixture_config_custody')
    descriptor = os.open(target, os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        if key(os.fstat(descriptor)) != key(before):
            refuse('owned_git_fixture_config_open_race')
        body = b''
        while len(body) <= before.st_size:
            chunk = os.read(descriptor, before.st_size + 1 - len(body))
            if not chunk:
                break
            body += chunk
        if len(body) != before.st_size or key(target.lstat()) != key(before):
            refuse('owned_git_fixture_config_read_race')
        records = state.setdefault('owned_git_fixture_configs', {})
        binding = (state['case'], previous.pid)
        prior = records.get(str(target))
        if prior is not None:
            if prior != (binding, hashlib.sha256(body).hexdigest(), key(before)[:6]):
                refuse('owned_git_fixture_config_drift')
            return
        if not body.endswith(b'\n') or b'[maintenance]' in body or b'[gc]' in body:
            refuse('owned_git_fixture_unknown_config')
        expected = body + SUFFIX
        os.lseek(descriptor, 0, os.SEEK_END)
        tail = memoryview(SUFFIX)
        while tail:
            written = os.write(descriptor, tail)
            if written <= 0:
                raise OSError('owned fixture config write incomplete')
            tail = tail[written:]
        os.fsync(descriptor)
        after = os.fstat(descriptor)
        if (key(after)[:6] != key(before)[:6] or key(target.lstat()) != key(after)
                or target.read_bytes() != expected):
            refuse('owned_git_fixture_config_write_race')
        digest = hashlib.sha256(expected).hexdigest()
        records[str(target)] = (binding, digest, key(after)[:6])
        append({'kind': 'source_owned_git_maintenance_configuration', 'case': state['case'],
                'init_pid': previous.pid, 'before_sha256': hashlib.sha256(body).hexdigest(),
                'after_sha256': digest, 'mode_preserved': True,
                'argv_environment_unchanged': True, 'native_launch_permission_added': False})
    finally:
        os.close(descriptor)
