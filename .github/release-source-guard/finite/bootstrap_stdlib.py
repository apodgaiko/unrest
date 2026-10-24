"""Two-stage seal for the original half-second sleep/runpy fixture only."""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
import types

CASE = 'tests/test_experimental_bootstrap.py::test_startup_subtracts_from_actual_inference_timeout'
SOURCE = 'tests/test_experimental_bootstrap.py'
PIN = 'c81fc04a81ef3aa657c16a69627c4c6b80ba1012f9255d2a05b15557934a7383'
BODY = 'import runpy,sys,time; p=sys.argv.pop(1); time.sleep(0.5); runpy.run_path(p,run_name="__main__")'
BACKEND_PIN = 'be7847ba715816b3f0cfdc9c29087b8751a998d160f616a5c08210c6ca404f53'


def inline_eligible(state, endpoint, payload):
    if (type(payload) is not dict or state.get('class') != 'source-canonical-stdlib-backend'
            or state.get('case') != CASE or state.get('phase') != 'READY'
            or payload.get('class') != state['class'] or payload.get('case') != CASE
            or payload.get('token') != state.get('token') or not state.get('token')
            or endpoint.get('token') != state['token'] or endpoint.get('identity', {}).get('pid') != os.getpid()
            or payload.get('mode') != 'inline' or payload.get('target') != BODY
            or payload.get('isolated') is not True or payload.get('path0') != ''
            or payload.get('source_binding') != {'path': str(Path(state['checkout']) / SOURCE), 'line': 38, 'sha256': PIN}):
        return False
    argv, arguments = payload.get('orig_argv'), payload.get('sys_argv')
    if (type(argv) is not list or len(argv) < 6 or any(type(x) is not str for x in argv)
            or argv[0] not in state['runtime']['paths'] or argv[1:4] != ['-I', '-S', '-c']
            or argv[4] != BODY or type(arguments) is not list or arguments != ['-c', *argv[5:]]
            or argv[-1] != 'app-server'):
        return False
    target = Path(argv[5])
    source = Path(state['checkout']) / SOURCE
    return (target.is_absolute() and '..' not in target.parts and target.name == 'fake-app-server'
            and target.is_relative_to(Path(state['owned_root'])) and not target.is_symlink()
            and target.resolve(strict=True) == target and hashlib.sha256(target.read_bytes()).hexdigest() == BACKEND_PIN
            and state['product_pins'].get(SOURCE) == PIN and hashlib.sha256(source.read_bytes()).hexdigest() == PIN)


def wrapper_dispatch(executed, frame, guard, payload, dispatched):
    """Authorize one exact compiled wrapper in the unchanged guard child frame."""
    namespace = frame.f_locals.get('namespace')
    return (dispatched is False and type(executed) is types.CodeType
            and executed == compile(BODY, '<string>', 'exec', dont_inherit=True)
            and frame.f_code is guard.child.__code__ and frame.f_globals is vars(guard)
            and frame.f_locals.get('payload') is payload and frame.f_locals.get('code') is executed
            and guard._STATE.get('payload_code') is executed
            and type(namespace) is dict and guard._STATE.get('payload_globals') is namespace
            and namespace.get('__builtins__') is guard.child.__builtins__
            and namespace == {'__name__': '__main__', '__package__': None, '__spec__': None,
                              '__builtins__': namespace.get('__builtins__')})
