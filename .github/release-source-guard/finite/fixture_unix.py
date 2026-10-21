"""Only the original two unsafe-lock socket carriers may perform a bind."""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
import re
import socket
import stat
import sys

SOURCE = 'tests/test_supervision_paths.py'
PIN = 'dba9e0a17ad4698c5699c4aa4b87aa3cbde88482391c64ac042144d743bdec16'
CASES = frozenset(SOURCE + '::test_static_carrier_refuses_without_outside_effects[socket-' + value + ']'
                  for value in ('False', 'True'))


def address_owned(address, owned_root, uid):
    alias = Path('/private/tmp')
    if (type(address) is not str or '\0' in address or not alias.is_symlink()
            or os.readlink(alias) != str(Path(owned_root) / 'tmp')
            or not os.statvfs(alias.parent).f_flag & os.ST_RDONLY):
        return False
    path = Path(address)
    parent = path.parent
    if (path.name != 's' or parent.parent != alias
            or re.fullmatch(r'tmp[a-z0-9_]{8}', parent.name) is None
            or parent.resolve() != Path(owned_root) / 'tmp' / parent.name):
        return False
    info = parent.lstat()
    return stat.S_ISDIR(info.st_mode) and info.st_uid == uid and stat.S_IMODE(info.st_mode) == 0o700


def authorize(event, args, state, endpoint, guard):
    if event != 'socket.bind' or state.get('case') not in CASES:
        return False
    stream, address = args[:2]
    if (state['product_pins'].get(SOURCE) != PIN or stream.family != socket.AF_UNIX
            or stream.type != socket.SOCK_STREAM or not address_owned(address, state['owned_root'], os.getuid())):
        endpoint.refuse('fixture_unix_scope_drift')
    helper = Path(state['guard']).with_name('fallback_binding.py')
    frames = guard.checked_source(helper, state['direct_support']['files'][str(helper)])['active_frames']()
    try:
        source = Path(state['checkout']) / SOURCE
        candidates = {id(f): f for f in frames if f.f_code.co_filename == str(source)
                      and f.f_code.co_name == 'test_static_carrier_refuses_without_outside_effects'}
        if len(candidates) != 1:
            endpoint.refuse('fixture_unix_owner_missing')
        frame = next(iter(candidates.values()))
        module = sys.modules.get(frame.f_globals.get('__name__'))
        local = frame.f_locals
        if (module is None or vars(module) is not frame.f_globals
                or hashlib.sha256(source.read_bytes()).hexdigest() != PIN
                or frame.f_code != state['isolated_named'](state['isolated_source_code'](source), frame.f_code.co_name)
                or frame.f_lineno != 57 or local.get('kind') != 'socket'
                or type(local.get('nested')) is not bool or local.get('sock') is not stream
                or str(local.get('socket_path')) != address
                or str(Path(local['short']) / 's') != address
                or not Path(local['lock']).resolve().is_relative_to(Path(state['owned_root']) / 'pytest')):
            endpoint.refuse('fixture_unix_original_owner_drift')
        endpoint.request('fixture_unix_bind', fd=stream.fileno(), address=address, case=state['case'],
                         source_binding={'path': str(source), 'line': 57, 'sha256': PIN})
        return True
    finally:
        frames.clear()
