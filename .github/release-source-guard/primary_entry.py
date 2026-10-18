"""Native pre-body consumption for one primary-script-derived Python operation."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import stat
import sys


def main(event, arguments):
    path = Path('/receipts/primary-startup') / (str(os.getpid()) + '.json')
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        info = os.fstat(descriptor)
        if (info.st_uid != 20001 or stat.S_IMODE(info.st_mode) != 0o444
                or not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > 65536):
            os._exit(86)
        body = os.read(descriptor, 65537)
    finally:
        os.close(descriptor)
    profile = json.loads(body)
    raw = Path('/proc/self/stat').read_text()
    if (profile['pid'] != os.getpid() or profile['parent'] != os.getppid()
            or profile['start_ticks'] != int(raw[raw.rfind(')') + 2:].split()[19])
            or profile['boot_id'] != Path('/proc/sys/kernel/random/boot_id').read_text().strip()
            or profile['environment'] != dict(os.environ) or profile['cwd'] != os.getcwd()
            or profile['orig_argv'] != sys.orig_argv or profile['event'] != event
            or profile['flags'] != [sys.flags.isolated, sys.flags.no_site, sys.flags.dont_write_bytecode]
            or len(arguments) != 1
            or hashlib.sha256(str(arguments[0]).encode()).hexdigest() != profile['body_sha256']):
        os._exit(86)
    # Source cannot inherit a credential, controller socket or unrelated file.
    for descriptor in range(3, 128):
        try:
            os.fstat(descriptor)
        except OSError:
            continue
        os._exit(86)
    denied = {'subprocess.Popen', 'os.exec', 'os.posix_spawn', 'os.system', 'os.fork',
              'os.forkpty', 'socket.connect', 'socket.bind'}
    used_git = [False]
    def audit(name, args):
        if name == 'subprocess.Popen' and profile['repository'] and not used_git[0]:
            executable, argv, cwd, environment = args
            frame = sys._getframe(1)
            while frame is not None and frame.f_code.co_name != 'find_repository_root':
                frame = frame.f_back
            source = Path('/source/src/unrest_harness/repository_contract.py')
            if (frame is not None and frame.f_code.co_filename == str(source)
                    and hashlib.sha256(source.read_bytes()).hexdigest() == profile['repository_source_sha256']
                    and executable == 'git' and argv == ['git', '-C', '/source', 'rev-parse', '--show-toplevel']
                    and cwd is None and environment is None):
                module = sys.modules.get('unrest_harness.repository_contract')
                if (module is not None and frame.f_globals is vars(module)
                        and frame.f_code is module.find_repository_root.__code__):
                    used_git[0] = True
                    return
        if name in denied:
            os._exit(86)
    sys.addaudithook(audit)
    sys._unrest_finite_source_audit = True


main(globals()['ENTRY_EVENT'], globals()['ENTRY_ARGUMENTS'])
