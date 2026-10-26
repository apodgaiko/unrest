"""Consume one actual-birth-bound native control profile before body dispatch.

Only closed diagnostic programs are admitted here. This consumer does not
activate a product route or certify source execution. Product startup requires
its separate source-intent, endpoint and custody integration.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import socket
import stat
import sys
import time

BODY_READY = False
BODIES = {
    'positive': 'print("NATIVE_BODY_OK", flush=True)',
    'caught-process': 'import subprocess\ntry: subprocess.run(["/usr/bin/true"])\nexcept RuntimeError: print("REFUSAL_CAUGHT", flush=True)',
    'caught-network': 'import socket\ns=socket.socket()\ntry: s.bind(("127.0.0.1",0))\nexcept RuntimeError: print("REFUSAL_CAUGHT", flush=True)\nfinally: s.close()',
}


def unique(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError('native duplicate field')
        value[key] = item
    return value


def key(info):
    return tuple(getattr(info, name) for name in (
        'st_dev', 'st_ino', 'st_mode', 'st_uid', 'st_gid', 'st_nlink',
        'st_size', 'st_mtime_ns', 'st_ctime_ns'))


def consume(directory: str, event: str, arguments: tuple) -> None:
    global BODY_READY
    root = Path(directory)
    parent = root.lstat()
    if (root.resolve() != root or parent.st_uid != 20001
            or not stat.S_ISDIR(parent.st_mode) or stat.S_IMODE(parent.st_mode) != 0o755):
        raise ValueError('native profile directory')
    file = root / (str(os.getpid()) + '.json')
    descriptor = os.open(file, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        before = os.fstat(descriptor)
        if (not stat.S_ISREG(before.st_mode) or before.st_uid != 20001
                or stat.S_IMODE(before.st_mode) != 0o444 or before.st_nlink != 1 or before.st_size > 65536):
            raise ValueError('native profile file')
        body = os.read(descriptor, 65537)
        if key(before) != key(os.fstat(descriptor)) or key(before) != key(file.lstat()) or len(body) != before.st_size:
            raise ValueError('native profile acquisition')
    finally:
        os.close(descriptor)
    profile = json.loads(body, object_pairs_hook=unique)
    fields = {'schema', 'case', 'identity', 'observer', 'argv', 'environment', 'cwd', 'flags',
              'native', 'native_sha256', 'entry_sha256', 'nonce', 'token', 'seal', 'generation', 'mount_namespace'}
    if type(profile) is not dict or set(profile) != fields or profile['schema'] != 'unrest.native-control.v1':
        raise ValueError('native profile schema')
    sys.path.insert(0, str(Path(__file__).parent))
    from control_transport import Frame, RESPONSE_LIMIT, peer, verify_reply
    from linux_observation import process_identity
    from process_ledger import Birth, canonical

    actual = process_identity(os.getpid())
    claimed = canonical(profile['identity'])
    if claimed != profile['identity']:
        raise ValueError('native profile identity schema')
    if (type(profile['argv']) is not list or any(type(value) is not str for value in profile['argv'])
            or type(profile['environment']) is not dict
            or any(type(key) is not str or type(value) is not str for key, value in profile['environment'].items())
            or type(profile['flags']) is not list or any(type(value) is not int for value in profile['flags'])):
        raise ValueError('native profile primitive records')
    for name in os.listdir('/proc/self/fd'):
        descriptor = int(name)
        if descriptor > 2:
            try:
                os.fstat(descriptor)
            except OSError:
                continue
            raise ValueError('native ambient descriptor inherited')
    case = profile['case']
    if (type(case) is not str or case not in BODIES or event != 'cpython.run_command'
            or type(arguments) is not tuple or len(arguments) != 1 or type(arguments[0]) is not str
            or arguments[0] != BODIES[case] + '\n' or actual['uids'] != [20000] * 4
            or actual['gids'] != [20000] * 4 or any(actual['capabilities'].values())
            or actual['no_new_privs'] != 1 or actual['seccomp'] != 2
            or canonical(actual) != claimed
            or os.readlink('/proc/self/ns/mnt') != profile['mount_namespace']
            or profile['argv'] != sys.orig_argv or profile['environment'] != dict(os.environ)
            or profile['cwd'] != os.getcwd() or profile['flags'] != [1, 1, 0]
            or [sys.flags.isolated, sys.flags.no_site, sys.flags.dont_write_bytecode] != [1, 1, 0]
            or profile['argv'] != [profile['native'], '-I', '-S', '-c', BODIES[case]]
            or sys.executable != profile['native'] or type(profile['generation']) is not int or profile['generation'] != 1
            or hashlib.sha256(Path(sys.executable).read_bytes()).hexdigest() != profile['native_sha256']
            or hashlib.sha256(Path(__file__).read_bytes()).hexdigest() != profile['entry_sha256']):
        diagnostic = {
            'environment_matches': profile['environment'] == dict(os.environ),
            'locale_coercion_only': dict(os.environ) == {**profile['environment'], 'LC_CTYPE': 'C.UTF-8'},
            'flags': [sys.flags.isolated, sys.flags.no_site, sys.flags.dont_write_bytecode],
            'argv_matches': profile['argv'] == sys.orig_argv,
            'identity_matches': canonical(actual) == claimed,
            'executable_matches': sys.executable == profile['native'],
            'body_matches': type(case) is str and case in BODIES and arguments == (BODIES[case] + '\n',),
        }
        raise ValueError('native actual execution binding: ' + json.dumps(diagnostic, sort_keys=True))
    for name, size in (('nonce', 64), ('token', 32), ('seal', 64)):
        value = profile[name]
        if type(value) is not str or len(value) != size or any(char not in '0123456789abcdef' for char in value):
            raise ValueError('native profile token')
    observer = Birth.read(profile['observer'])
    if observer.uid != 20001 or observer.pid != os.getppid():
        raise ValueError('native observer parent')
    for kind, payload in (
            ('core-ready', {'pins': [['entry', profile['entry_sha256']], ['native', profile['native_sha256']]]}),
            ('body-ready', {'seal': profile['seal']})):
        request = {'pid': os.getpid(), 'nonce': profile['nonce'], 'token': profile['token'],
                   'generation': 1, 'id': os.urandom(16).hex(), 'kind': kind, 'payload': payload}
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as stream:
            stream.settimeout(4)
            stream.connect(str(root / 'control.sock'))
            peer(stream, observer, 20001)
            frame = Frame(stream, RESPONSE_LIMIT, [])
            frame.answer(request)
            while not frame.send():
                time.sleep(.0001)
            response = None
            while response is None:
                response = frame.read()
                time.sleep(.0001)
            peer(stream, observer, 20001)
            if verify_reply(response, request) != {'ok': True}:
                raise ValueError('native readiness refused')
    sys.path.pop(0)
    sys.dont_write_bytecode = True
    BODY_READY = True


if __name__ == '_release_native_entry':
    consume(globals()['PROFILE_DIRECTORY'], globals()['ENTRY_EVENT'], globals()['ENTRY_ARGUMENTS'])
