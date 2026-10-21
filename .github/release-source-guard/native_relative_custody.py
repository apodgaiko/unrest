"""Join the exact original sleep leaf to its existing source and kernel custody."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

from finite.native_relative import CASES, CLASS, PIN, SOURCE, VECTOR, binding
from finite.child_relative_view import view, same_object
from finite.linux_identity import identity


def validate(selected, rows, vector, environment, cwd, path, checkout, facts):
    registration = selected['registration']
    if (selected.get('bootstrap_sha256') is not None
            or registration.get('class') != CLASS or registration.get('case') not in CASES
            or registration.get('source_binding') != binding(checkout)
            or vector != VECTOR or path != VECTOR[0] or cwd != checkout
            or selected.get('cwd') != cwd
            or selected.get('transformed_argv_sha256') != hashlib.sha256(json.dumps(vector).encode()).hexdigest()
            or selected.get('environment_sha256') != hashlib.sha256(json.dumps(environment, sort_keys=True).encode()).hexdigest()
            or len(rows) != 1):
        raise RuntimeError('native_relative_launch_join')
    row = rows[0]
    if (row.get('class') != CLASS or row.get('source_binding') != registration['source_binding']
            or row.get('case') != registration['case']
            or row.get('token') != selected['token'] or row.get('owner_pid') != selected['owner_pid']
            or row.get('original_cwd') is not None or row.get('constructor_cwd') != '.'
            or row.get('argv_sha256') != selected['transformed_argv_sha256']
            or not same_object(row.get('parent_view'), facts)):
        raise RuntimeError('native_relative_stopped_cwd_join')


def resolve(authority, trace, pid, path, vector, environment, cwd):
    selected = authority.bound.get(pid)
    if selected is None or selected.get('registration', {}).get('class') != CLASS:
        return False
    supervisor = authority.supervisor
    try:
        parent = trace.identities[pid]['ppid']
        saved = supervisor.registered[parent]
        if (selected['owner_pid'] != parent or identity(parent) != saved['identity']
                or selected['registration']['token'] != selected['token']
                or selected['registration']['owner_pid'] != parent
                or authority.manifest['product_pins'].get(SOURCE) != PIN):
            raise RuntimeError('native_relative_parent_custody')
        facts = view(process=pid)
        events = supervisor.events()
        rows = [r for r in events if r['kind'] == 'native_relative_constructor'
                and r.get('token') == selected['token'] and r.get('owner_pid') == parent]
        validate(selected, rows, vector, environment, cwd, path, '/source', facts)
        if (authority.manifest['cohort_native_pins'].get(path)
                != hashlib.sha256(Path(path).read_bytes()).hexdigest()
                or facts != view(process=pid)):
            raise RuntimeError('native_relative_image_or_cwd_drift')
        authority.contexts[pid] = {'role': 'source-native', 'identity': identity(pid)}
        authority.pipe_records.append({'kind': 'native_relative_stopped_cwd',
                                       'pid': pid, 'token': selected['token'], 'cwd': facts,
                                       'executable_sha256': authority.manifest['cohort_native_pins'][path]})
        return True
    except BaseException:
        trace.poison.append('native_relative_kernel_custody')
        supervisor.poison('native_relative_kernel_custody')
        raise
