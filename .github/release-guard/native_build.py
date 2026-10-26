"""Build the closed native control against the actual CI CPython 3.13 ABI."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import shlex
import subprocess
import sys
import sysconfig


def pin(path: Path) -> dict:
    return {'path': str(path), 'sha256': hashlib.sha256(path.read_bytes()).hexdigest()}


def main():
    if (os.environ.get('GITHUB_ACTIONS') != 'true' or sys.platform != 'linux'
            or sys.version_info[:2] != (3, 13) or os.uname().machine != 'x86_64'):
        raise RuntimeError('native control build requires its Linux CI lane')
    support = Path(__file__).resolve().parent
    root = Path(os.environ['RUNNER_TEMP']).resolve() / 'guard-native-control'
    root.mkdir(mode=0o755)
    compiler = Path('/usr/bin/cc').resolve(strict=True)
    entry = Path(sys.base_prefix) / 'bin/python-unrest-guard-control'
    if entry.exists() or entry.is_symlink():
        raise RuntimeError('native control output already exists')
    profiles = root / 'profiles'
    bootstrap = support / 'native_entry.py'
    library = Path(sysconfig.get_config_var('LIBDIR')) / 'libpython3.13.so.1.0'
    if sysconfig.get_config_var('SOABI') != 'cpython-313-x86_64-linux-gnu':
        raise RuntimeError('native control ABI refused')
    argv = [str(compiler), '-O2', '-Wall', '-Wextra', '-Werror',
            '-I' + sysconfig.get_path('include'), '-L' + str(library.parent),
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
              'runtime': pin(Path(sys.executable).resolve()), 'compiler_argv': argv,
              'head': os.environ['GITHUB_SHA'], 'run': int(os.environ['GITHUB_RUN_ID']),
              'attempt': int(os.environ['GITHUB_RUN_ATTEMPT'])}
    target = root / 'binding.json'
    target.write_text(json.dumps(record, sort_keys=True) + '\n')
    target.chmod(0o444)


if __name__ == '__main__':
    main()
