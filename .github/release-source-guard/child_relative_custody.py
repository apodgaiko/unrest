"""Stopped-child enforcement for the finite constructor's exact launch binding."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

from finite.child_relative_view import view, same_object
from finite.linux_identity import identity



def validate(selected, record, actual, vector):
    if record is None:
        raise RuntimeError('child_relative_constructor_cardinality')
    if (record['original_cwd'] is not None or record['constructor_cwd'] != '.'
            or record['class'] != selected['registration']['class']
            or record['argv_sha256'] != selected['transformed_argv_sha256']
            or record['argv_sha256'] != hashlib.sha256(json.dumps(vector).encode()).hexdigest()
            or not same_object(actual, record['parent_view'])
            or record['parent_view']['searchable'] is not True
            or actual['searchable'] is not None or actual['cwd'] != selected['cwd']):
        raise RuntimeError('child_relative_child_cwd_binding')

def check(authority, trace, pid, vector):
    selected = authority.bound.get(pid)
    if selected is None or selected.get('bootstrap_sha256') is None:
        return
    records = [row for row in authority.supervisor.events()
               if row['kind'] == 'child_relative_constructor'
               and row['owner_pid'] == selected['owner_pid'] and row['token'] == selected['token']]
    if not records:
        return
    actual = None
    record = records[0] if len(records) == 1 else None
    refusal = None
    try:
        actual = view(process=pid)
        validate(selected, record, actual, vector)
    except (OSError, RuntimeError, ValueError, KeyError) as error:
        refusal = {'exception_class': type(error).__name__, 'errno': getattr(error, 'errno', None),
                   'facts': getattr(error, 'facts', None)}
        trace.poison.append('primary_source_child_relative_cwd')
        authority.supervisor.poison('primary_source_child_relative_cwd')
    receipt = {'schema': 'unrest.v047.child-relative-prebody.v1', 'token': selected['token'], 'identity': identity(pid), 'view': actual,
               'constructor': record, 'prebody_required': True, 'allowed': refusal is None,
               'refusal': refusal}
    path = Path('/receipts/primary-startup') / (str(pid) + '.child-relative.json')
    try:
        with path.open('x') as stream:
            stream.write(json.dumps(receipt, sort_keys=True))
        path.chmod(0o444)
        authority.pipe_records.append({'kind': 'child_relative_prebody_cwd', **receipt,
                                       'receipt_sha256': hashlib.sha256(path.read_bytes()).hexdigest()})
    except BaseException:
        trace.poison.append('primary_source_child_relative_receipt')
        authority.supervisor.poison('primary_source_child_relative_receipt')
        raise
