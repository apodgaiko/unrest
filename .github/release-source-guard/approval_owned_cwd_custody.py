"""Kernel cwd join before the unchanged native pre-body profile is consumed."""
import hashlib
import json
import os
from pathlib import Path

from finite.approval_owned_cwd import KINDS, directory
from finite.approval_routes import selected_mode
from finite.linux_identity import identity


def check(authority, trace, pid, vector):
    selected = authority.bound.get(pid)
    if selected is None or selected['registration']['class'] not in KINDS:
        return
    registration = selected['registration']
    parent = identity(pid)['ppid']
    owner = authority.supervisor.registered[parent]['identity']
    rows = [row for row in authority.supervisor.events()
            if row['kind'] == 'approval_owned_cwd_constructor'
            and row['owner_pid'] == parent and row['token'] == selected['token']]
    try:
        if len(rows) != 1:
            raise RuntimeError('approval_owned_cwd_cardinality')
        row = rows[0]
        observed = directory(os.readlink(Path('/proc', str(pid), 'cwd')), authority.manifest['owned_root'])
        info = Path('/proc', str(pid), 'cwd').stat()
        source, line, pin, _ = KINDS[registration['class']]
        if (row['class'] != registration['class'] or selected_mode(row.get('case')) is None
                or row['source_binding'] != registration['source_binding']
                or row['source_binding'] != {'path': '/source/' + source, 'line': line, 'sha256': pin}
                or authority.manifest['product_pins'].get(source) != pin
                or hashlib.sha256(Path('/source', source).read_bytes()).hexdigest() != pin
                or row['original_cwd'] is not None or row['constructor_cwd'] != '.'
                or row['argv_sha256'] != selected['transformed_argv_sha256']
                or row['argv_sha256'] != hashlib.sha256(json.dumps(vector).encode()).hexdigest()
                or observed != row['parent_view'] or observed['cwd'] != selected['cwd']
                or (info.st_dev, info.st_ino) != (observed['device'], observed['inode'])
                or identity(parent) != owner
                or any(identity(pid)[key] != trace.identities[pid][key]
                       for key in ('pid', 'ppid', 'start_ticks', 'boot_id'))):
            raise RuntimeError('approval_owned_cwd_kernel_binding')
        authority.pipe_records.append({'kind': 'approval_owned_cwd_preexec', 'pid': pid,
                                       'identity': identity(pid), 'owner_identity': owner,
                                       'view': observed, 'token': selected['token'],
                                       'native_prebody_cwd_check_required': True})
    except BaseException:
        trace.poison.append('approval_owned_cwd_kernel_binding')
        authority.supervisor.poison('approval_owned_cwd_kernel_binding')
        raise
