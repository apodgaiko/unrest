"""Consume an observer-owned PID/birth-bound producer startup profile."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import stat
import sys
import types


def activate(event: str, arguments: tuple) -> None:
    directory = Path('/receipts/native-startup')
    parent = directory.stat()
    if parent.st_uid != 20001 or stat.S_IMODE(parent.st_mode) != 0o755:
        raise RuntimeError('native profile directory custody drift')
    path = directory / (str(os.getpid()) + '.json')
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        info = os.fstat(descriptor)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != 20001
                or stat.S_IMODE(info.st_mode) != 0o444 or info.st_nlink != 1):
            raise RuntimeError('native startup profile custody drift')
        with os.fdopen(descriptor, 'rb', closefd=False) as stream:
            body = stream.read(65537)
        if len(body) > 65536 or os.fstat(descriptor) != info:
            raise RuntimeError('native startup profile size or identity drift')
    finally:
        os.close(descriptor)
    profile = json.loads(body)
    proc = Path('/proc/self/stat').read_text()
    start = int(proc[proc.rfind(')') + 2:].split()[19])
    if (profile['pid'] != os.getpid() or profile['ppid'] != os.getppid()
            or profile['start_ticks'] != start
            or profile['boot_id'] != Path('/proc/sys/kernel/random/boot_id').read_text().strip()
            or profile['event'] != event or profile['orig_argv'] != sys.orig_argv
            or profile['environment'] != dict(os.environ) or profile['cwd'] != os.getcwd()
            or profile['flags'] != [sys.flags.isolated, sys.flags.no_site, sys.flags.dont_write_bytecode]
            or event != 'cpython.run_command' or len(arguments) != 1
            or hashlib.sha256(arguments[0].encode()).hexdigest() != profile['command_sha256']
            or profile['role'] not in {'isolated-uv-query', 'isolated-uv-helper'}):
        raise RuntimeError('native source startup identity drift')
    support = Path('/guard/finite/native_producer.py')
    data = support.read_bytes()
    if hashlib.sha256(data).hexdigest() != profile['activation_sha256']:
        raise RuntimeError('native producer activation source drift')
    module = types.ModuleType('native_producer')
    module.__file__ = str(support)
    sys.modules['native_producer'] = module
    exec(compile(data, str(support), 'exec', dont_inherit=True), module.__dict__)
    module.activate(profile, arguments[0])


activate(globals()['ENTRY_EVENT'], globals()['ENTRY_ARGUMENTS'])
