"""A current role pipe consumes its unique launch token, not reusable argv."""
from __future__ import annotations

from primary_source_authority import SourceAuthority as OriginalSourceAuthority

CLASSES = frozenset({'source-owned-role:worker', 'source-owned-role:validator',
                     'source-owned-role:terminal-reviewer'})
FIELDS = ('owner_pid', 'token', 'case', 'cwd', 'bootstrap_sha256',
          'transformed_argv_sha256', 'environment_sha256')


def digest(value):
    return type(value) is str and len(value) == 64 and all(c in '0123456789abcdef' for c in value)


def concrete(row):
    return (type(row) is dict and row.get('kind') == 'concrete_owned_role_registration'
            and type(row.get('owner_pid')) is int and type(row.get('parent_pid')) is int
            and type(row.get('case')) is str
            and type(row.get('role')) is str
            and row['role'] in {'worker', 'validator', 'terminal-reviewer'}
            and type(row.get('source_binding')) is dict and digest(row.get('argv_sha256'))
            and type(row.get('pipe_device')) is int and row['pipe_device'] >= 0
            and type(row.get('pipe_inode')) is int and row['pipe_inode'] > 0)


class EventView:
    def __init__(self, supervisor, rows):
        self.supervisor, self.rows = supervisor, rows

    def events(self):
        return self.rows

    def __getattr__(self, name):
        return getattr(self.supervisor, name)


class AuthorityView:
    def __init__(self, authority, rows):
        self.authority = authority
        self.supervisor = EventView(authority.supervisor, rows)

    def __getattr__(self, name):
        return getattr(self.authority, name)


def binding(authority, pid):
    selected = authority.bound[pid]
    admitted = selected['registration']
    token = selected.get('token')
    if (admitted.get('class') not in CLASSES or type(token) is not str or len(token) != 32
            or any(c not in '0123456789abcdef' for c in token)
            or type(selected.get('owner_pid')) is not int or type(admitted.get('case')) is not str
            or any(admitted.get(key) != selected.get(key) for key in ('owner_pid', 'token', 'case'))
            or not all(digest(selected.get(key)) for key in FIELDS[4:])):
        raise RuntimeError('owned_role_token_context')
    rows = authority.supervisor.events()
    if any(type(row) is not dict or 'kind' not in row for row in rows):
        # Preserve the original indexing error on malformed journal values.
        OriginalSourceAuthority.pipe_binding(AuthorityView(authority, rows), pid)
        raise RuntimeError('owned_role_malformed_journal')
    joined = {}
    for kind in ('owned_role_launch_binding', 'actual_launch_binding', 'admitted'):
        found = [(i, row) for i, row in enumerate(rows)
                 if row.get('kind') == kind and row.get('token') == token]
        if len(found) != 1:
            raise RuntimeError('owned_role_token_cardinality')
        joined[kind] = found[0]
    side_index, side = joined['owned_role_launch_binding']
    launch_index, launch = joined['actual_launch_binding']
    admitted_index, record = joined['admitted']
    if (not side_index < launch_index < admitted_index or record != admitted
            or any(side.get(key) != selected.get(key) or launch.get(key) != selected.get(key)
                   for key in FIELDS)
            or any(side.get(key) != admitted.get(key)
                   for key in ('class', 'source_binding', 'argv_sha256'))
            or type(side.get('pipe_device')) is not int or side['pipe_device'] < 0
            or type(side.get('pipe_inode')) is not int or side['pipe_inode'] <= 0):
        raise RuntimeError('owned_role_token_join')
    role = admitted['class'].removeprefix('source-owned-role:')
    projected = []
    for row in rows:
        # Only well-formed historical observations of this same logical argv
        # are excluded. Malformed/current rows retain the original predicate.
        historical = (concrete(row) and row['owner_pid'] == selected['owner_pid']
                      and row['role'] == role and row['source_binding'] == admitted['source_binding']
                      and row['argv_sha256'] == admitted['argv_sha256']
                      and (row['case'] != admitted['case']
                           or (row['pipe_device'], row['pipe_inode']) !=
                           (side['pipe_device'], side['pipe_inode'])))
        if not historical:
            projected.append(row)
    result = OriginalSourceAuthority.pipe_binding(AuthorityView(authority, projected), pid)
    if (result is None or not concrete(result) or result['case'] != admitted['case']
            or result['owner_pid'] != selected['owner_pid']
            or (result['pipe_device'], result['pipe_inode']) !=
            (side['pipe_device'], side['pipe_inode'])):
        raise RuntimeError('owned_role_current_pipe')
    return result
