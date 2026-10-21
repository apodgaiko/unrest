"""Filesystem socket-carrier bind only; never listen, connect or payload rights."""
from __future__ import annotations

import os

from approval_unix_custody import observe
from finite.fixture_unix import SOURCE, PIN, CASES, address_owned
from finite.linux_identity import identity


def handle(supervisor, request, events):
    manifest = supervisor.manifest
    pid, fd = request['pid'], request['fd']
    saved = supervisor.registered[pid]['identity']
    address = request['address']
    if (request.get('case') not in CASES or type(fd) is not int or not 0 <= fd <= 4095
            or manifest['product_pins'].get(SOURCE) != PIN
            or request.get('source_binding') != {'path': '/source/' + SOURCE, 'line': 57, 'sha256': PIN}
            or identity(pid) != saved or saved['uid'] != 20000
            or not address_owned(address, manifest['owned_root'], saved['uid'])
            or os.path.lexists(address)):
        raise RuntimeError('fixture_unix_scope_drift')
    actual = observe(pid, fd)
    if (actual['owner_identity'] != saved or actual['uid'] != saved['uid']
            or actual['local'] != '' or actual['remote'] is not None or actual['listening']
            or identity(pid) != saved or not address_owned(address, manifest['owned_root'], saved['uid'])):
        raise RuntimeError('fixture_unix_kernel_fd_drift')
    return {'fixture_unix_bind': actual, 'listen_connect_payload_authorized': False}
