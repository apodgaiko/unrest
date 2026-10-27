"""Synthetic native diagnostic consumer; disconnected from production source admission."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import sys

if __name__ == '_release_native_entry':
    sys.path.insert(0, str(Path(__file__).parents[1] / 'support'))
from native_entry import acquire

BODY_READY = False
BODIES = {
    'positive': 'print("NATIVE_BODY_OK", flush=True)',
    'caught-process': 'import subprocess\ntry: subprocess.run(["/usr/bin/true"])\nexcept RuntimeError: print("REFUSAL_CAUGHT", flush=True)',
    'caught-network': 'import socket\ns=socket.socket()\ntry: s.bind(("127.0.0.1",0))\nexcept RuntimeError: print("REFUSAL_CAUGHT", flush=True)\nfinally: s.close()',
}


def consume(directory, event, arguments):
    global BODY_READY
    root, profile = acquire(directory)
    fields = {'schema', 'case', 'identity', 'observer', 'argv', 'environment', 'cwd', 'flags',
              'native', 'native_sha256', 'entry_sha256', 'nonce', 'token', 'seal', 'generation', 'mount_namespace'}
    if type(profile) is not dict or set(profile) != fields or profile['schema'] != 'unrest.native-control.v1':
        raise ValueError('native profile schema')
    sys.path.insert(0, str(Path(__file__).parent))
    from bootstrap_wire import Client
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
            or actual['no_new_privs'] != 1 or actual['seccomp'] != 2 or sys.flags.utf8_mode != 1
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
    client = Client(root, profile, frozenset({'core-ready', 'body-ready'}))
    for kind, payload in (
            ('core-ready', {'pins': [['entry', profile['entry_sha256']], ['native', profile['native_sha256']]]}),
            ('body-ready', {'seal': profile['seal']})):
        if client.request(kind, payload) != {'ok': True}:
            raise ValueError('native readiness refused')
    sys.path.pop(0)
    sys.dont_write_bytecode = True
    BODY_READY = True



if __name__ == '_release_native_entry':
    consume(globals()['PROFILE_DIRECTORY'], globals()['ENTRY_EVENT'], globals()['ENTRY_ARGUMENTS'])
