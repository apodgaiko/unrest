"""Fresh SOURCE process/READY authentication for local self-pipe witnesses."""
from __future__ import annotations

import hashlib
import json
import os
import stat
from pathlib import Path


def prepare(guard, endpoint):
    state = guard._STATE
    if state.get('setup_mode') != 'source':
        return None
    token = state['token']
    guard.require_ready(token)
    reader = Path(guard.__file__).with_name('linux_identity.py')
    pin = state['direct_support']['files'][str(reader)]
    identify = guard.checked_source(reader, pin)['identity']
    saved = dict(endpoint.STATE['identity'])
    ready = json.loads(json.dumps(state['ready_record']))
    journal = Path(state['events']) / (str(os.getpid()) + '.jsonl')
    def journal_key(info):
        return (info.st_dev, info.st_ino, info.st_uid, info.st_gid, info.st_mode, info.st_nlink)
    original = journal.lstat()
    if (not stat.S_ISREG(original.st_mode) or original.st_uid != os.getuid()
            or original.st_nlink != 1 or stat.S_IMODE(original.st_mode) != 0o600):
        guard.refuse('self_pipe_READY_journal_custody')
    saved_journal = journal_key(original)
    ready_pin = hashlib.sha256(json.dumps(ready, sort_keys=True).encode()).hexdigest()

    def authenticate():
        if (state.get('phase') != 'READY' or state.get('token') != token
                or state.get('ready_record') != ready
                or endpoint.STATE.get('token') != token
                or endpoint.STATE.get('identity') != saved):
            return None
        try:
            current = identify(os.getpid())
        except (OSError, RuntimeError, ValueError):
            return None
        if current != saved:
            # Existing observer routes alone may approve exact ppid adoption.
            return None
        # The observer also checks the original ready event on every payload.
        # Stop at that early immutable claim; do not rescan a growing journal.
        try:
            fd = os.open(journal, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
            with os.fdopen(fd) as stream:
                if journal_key(os.fstat(stream.fileno())) != saved_journal:
                    return None
                present = any(json.loads(line) == ready for line in stream)
            if journal_key(journal.lstat()) != saved_journal or not present:
                return None
        except (OSError, ValueError):
            return None
        return {'process_identity': current, 'token': token, 'ready_sha256': ready_pin}

    return authenticate
