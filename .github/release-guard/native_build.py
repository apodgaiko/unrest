"""Build the closed native control against the actual CI CPython 3.13 ABI."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import shlex
import shutil
import stat
import subprocess
import sys
import sysconfig


def pin(path: Path) -> dict:
    return {'path': str(path), 'sha256': hashlib.sha256(path.read_bytes()).hexdigest()}


def main():
    if (os.environ.get('GITHUB_ACTIONS') != 'true' or sys.platform != 'linux'
            or sys.version_info[:2] != (3, 13) or os.uname().machine != 'x86_64'):
        raise RuntimeError('native control build requires its Linux CI lane')
    original_support = Path(__file__).resolve().parent
    run_id, attempt = int(os.environ['GITHUB_RUN_ID']), int(os.environ['GITHUB_RUN_ATTEMPT'])
    parent = Path('/tmp') / f'unrest-native-control-{run_id}-{attempt}'
    parent.mkdir(mode=0o755)
    root = parent / 'guard-native-control'
    root.mkdir(mode=0o755)
    support = root / 'support'
    support.mkdir(mode=0o755)
    for member in sorted(original_support.iterdir()):
        if member.suffix in ('.py', '.c', '.pem') and not member.name.startswith('test_'):
            if member.is_symlink() or not member.is_file() or member.stat().st_size > 4 * 1024 * 1024:
                raise RuntimeError('native support input refused')
            shutil.copyfile(member, support / member.name)
            (support / member.name).chmod(0o644)
    compiler = Path('/usr/bin/cc').resolve(strict=True)
    original = Path(sys.base_prefix).resolve(strict=True)
    runtime = root / 'runtime'
    # uv's managed installation can have a private ancestor. Copy only this
    # interpreter tree; never relax permissions on the shared host installation.
    members = sorted(original.rglob('*'))
    if len(members) > 20000:
        raise RuntimeError('native runtime inventory bound')
    for member in members:
        target = member.resolve(strict=True)
        mode = member.stat().st_mode
        if (not target.is_relative_to(original) or stat.S_IMODE(mode) & 0o6000
                or not (stat.S_ISREG(mode) or stat.S_ISDIR(mode))
                or member.is_symlink() and target.is_dir()):
            raise RuntimeError('native runtime input custody refused')
    if sum(member.stat().st_size for member in members if member.is_file()) > 512 * 1024 * 1024:
        raise RuntimeError('native runtime byte bound')
    shutil.copytree(original, runtime, symlinks=False)
    for member in [runtime, *sorted(runtime.rglob('*'))]:
        member.chmod(0o755 if member.is_dir() or member.stat().st_mode & 0o111 else 0o644)
    entry = runtime / 'bin/python-unrest-guard-control'
    if entry.exists() or entry.is_symlink():
        raise RuntimeError('native control output already exists')
    profiles = root / 'profiles'
    bootstrap = support / 'native_entry.py'
    library = runtime / Path(sysconfig.get_config_var('LIBDIR')).relative_to(original) / 'libpython3.13.so.1.0'
    if sysconfig.get_config_var('SOABI') != 'cpython-313-x86_64-linux-gnu':
        raise RuntimeError('native control ABI refused')
    argv = [str(compiler), '-O2', '-Wall', '-Wextra', '-Werror',
            '-I' + str(runtime / Path(sysconfig.get_path('include')).relative_to(original)), '-L' + str(library.parent),
            '-DGUARD_BOOTSTRAP=' + json.dumps(repr(str(bootstrap))),
            '-DGUARD_PROFILES=' + json.dumps(repr(str(profiles))),
            '-DGUARD_BOOTSTRAP_SHA256=' + json.dumps(pin(bootstrap)['sha256']),
            str(support / 'native_entry.c'), '-Wl,-rpath,' + str(library.parent),
            '-lpython3.13', *shlex.split(sysconfig.get_config_var('LIBS') or ''),
            *shlex.split(sysconfig.get_config_var('SYSLIBS') or ''), '-o', str(entry)]
    subprocess.run(argv, check=True)
    entry.chmod(0o755)
    bad_entry = entry.with_name(entry.name + '-badpin')
    if bad_entry.exists() or bad_entry.is_symlink():
        raise RuntimeError('negative native control output already exists')
    bad_argv = [('-DGUARD_BOOTSTRAP_SHA256=' + json.dumps('0' * 64))
                if value.startswith('-DGUARD_BOOTSTRAP_SHA256=') else value for value in argv]
    bad_argv[-1] = str(bad_entry)
    subprocess.run(bad_argv, check=True)
    bad_entry.chmod(0o755)
    record = {'schema': 'unrest.native-control-build.v1', 'entry': pin(entry),
              'negative_entry': pin(bad_entry), 'bootstrap': pin(bootstrap), 'source': pin(support / 'native_entry.c'),
              'library': pin(library), 'compiler': pin(compiler),
              'recipient': pin(support / 'evidence-recipient.pem'), 'profiles': str(profiles),
              'support': str(support), 'soabi': sysconfig.get_config_var('SOABI'),
              'runtime': pin(runtime / Path(sys.executable).resolve().relative_to(original)), 'compiler_argv': argv,
              'head': os.environ['GITHUB_SHA'], 'run': int(os.environ['GITHUB_RUN_ID']),
              'attempt': int(os.environ['GITHUB_RUN_ATTEMPT'])}
    target = root / 'binding.json'
    target.write_text(json.dumps(record, sort_keys=True) + '\n')
    target.chmod(0o444)


if __name__ == '__main__':
    main()
