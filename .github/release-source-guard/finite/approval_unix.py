"""Byte-bound approval API Unix effects; no native backend launch authority."""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
import re
import socket
import stat
import sys

PINS = {
    'tests/test_approval_recovery.py': 'f886178539296b984f19db2814bc53817133b214632146843b6934abb69bb80a',
    'src/unrest_harness/approval_recovery.py': '48a4c68fdff042b49f37cc3edf30e240cdb5ae69aa1da8a6e0280d19ec364ff4',
    'src/unrest_harness/approval_relay.py': 'efaba9521aa12d6fbdb228f05da210a4027675c79830d1a5ca93627faa80da44',
}
TEST = 'tests/test_approval_recovery.py'
OWNERS = frozenset(['test_exact_supported_backend_admission', 'test_credentials_refuse_before_actual_mcp_form', 'test_selection_rechecks_unsafe_display_without_opening_form', 'test_actual_mcp_nonconsent_never_submits', 'test_actual_mcp_accept_single_submit_and_receipt', 'test_expiry_cancel_commit_and_wrong_id_refuse', 'test_actual_acp_owner_native_subprocess_order_and_cleanup', 'test_unmodified_pinned_adapter_owned_relay', 'test_durable_run_owner_and_restart_never_revives', 'test_duplicate_review_does_not_open_or_clobber_first_form', 'test_exact_expiry_boundary_and_fixed_retention', 'test_real_deadline_timer_erases_memory_and_cleans_reader', 'test_pending_inspection_reference_is_read_only', 'test_completion_commits_during_human_response_before_submit', 'test_cleanup_failure_preserves_first_and_exhausts_owned_paths', 'test_host_disconnect_during_form_never_submits'])
SITES = {
    ('socket.bind', 'src/unrest_harness/approval_recovery.py', 'launch_environment'): (215, 'self'),
    ('socket.bind', TEST, 'install_pending'): (321, 'owner'),
    ('socket.connect', TEST, 'install_pending'): (325, 'owner'),
    ('socket.connect', 'src/unrest_harness/approval_recovery.py', 'review_approval'): (621, 'value'),
    ('socket.connect', 'src/unrest_harness/approval_relay.py', 'run'): (124, 'socket_path'),
}


def owned_address(address, root, uid):
    if type(address) is not str or '\0' in address:
        return False
    path = Path(address)
    parent = path.parent
    if (not path.is_absolute() or '..' in path.parts or path.name != 'control'
            or parent.parent != Path(root) / 'tmp'
            or re.fullmatch(r'unrest-approval-(?:test-)?[a-z0-9_]{8}', parent.name) is None
            or parent.resolve() != parent):
        return False
    try:
        info = parent.lstat()
    except OSError:
        return False
    return (stat.S_ISDIR(info.st_mode) and not parent.is_symlink()
            and info.st_uid == uid and stat.S_IMODE(info.st_mode) == 0o700)


def scope(state):
    return (type(state.get('case')) is str and state['case'].startswith(TEST + '::')
            and state['case'].removeprefix(TEST + '::').split('[')[0] in OWNERS
            and all(state['product_pins'].get(name) == pin for name, pin in PINS.items()))


def authorize(event, stream, address, state, endpoint, guard):
    if not scope(state) or not owned_address(address, state['owned_root'], os.getuid()):
        return False
    if stream.family != socket.AF_UNIX or stream.type != socket.SOCK_STREAM:
        return False
    helper = Path(state['guard']).with_name('fallback_binding.py')
    frames = guard.checked_source(helper, state['direct_support']['files'][str(helper)])['active_frames']()
    try:
        selected = []
        for frame in frames:
            try:
                relative = str(Path(frame.f_code.co_filename).relative_to(state['checkout']))
            except ValueError:
                continue
            site = SITES.get((event, relative, frame.f_code.co_name))
            if site is None:
                continue
            line, key = site
            source = Path(state['checkout']) / relative
            module = sys.modules.get(frame.f_globals.get('__name__'))
            code = (state['isolated_source_code'](source) if relative.startswith('tests/')
                    else compile(source.read_bytes(), str(source), 'exec', dont_inherit=True))
            if (module is None or vars(module) is not frame.f_globals
                    or hashlib.sha256(source.read_bytes()).hexdigest() != PINS[relative]
                    or frame.f_code != state['isolated_named'](code, frame.f_code.co_name)
                    or frame.f_lineno != line):
                endpoint.refuse('approval_unix_source_owner_drift')
            owner = frame.f_locals[key]
            expected = (str(owner.root / 'control') if key in {'self', 'owner'}
                        else owner['socket'] if key == 'value' else owner)
            if address != expected:
                endpoint.refuse('approval_unix_original_address_drift')
            selected.append({'path': str(source), 'line': line, 'sha256': PINS[relative]})
        unique = {tuple(sorted(row.items())): row for row in selected}
        if len(unique) != 1:
            endpoint.refuse('approval_unix_source_owner_missing')
        binding = next(iter(unique.values()))
        endpoint.request('approval_unix', operation='bind' if event == 'socket.bind' else 'connect',
                         fd=stream.fileno(), address=address, case=state['case'], source_binding=binding)
        state.setdefault('approval_unix_fds', {})[stream.fileno()] = {
            'address': address, 'binding': binding, 'device': os.fstat(stream.fileno()).st_dev,
            'inode': os.fstat(stream.fileno()).st_ino}
        return True
    finally:
        frames.clear()


def bound(stream, state):
    if stream.family != socket.AF_UNIX or stream.type != socket.SOCK_STREAM:
        return None
    record = state.get('approval_unix_fds', {}).get(stream.fileno())
    if record is not None:
        info = os.fstat(stream.fileno())
        if (info.st_dev, info.st_ino) == (record['device'], record['inode']):
            return record['address']
    for method in ('getsockname', 'getpeername'):
        try:
            address = getattr(stream, method)()
        except OSError:
            continue
        if owned_address(address, state['owned_root'], os.getuid()):
            return address
    return None


def receipt(operation, stream, state, endpoint):
    if not scope(state):
        return False
    address = bound(stream, state)
    if address is None:
        return False
    endpoint.request('approval_unix', operation=operation, fd=stream.fileno(),
                     address=address, case=state['case'])
    info = os.fstat(stream.fileno())
    records = state.setdefault('approval_unix_fds', {})
    previous = records.get(stream.fileno())
    if previous is None or (previous['device'], previous['inode']) != (info.st_dev, info.st_ino):
        records[stream.fileno()] = {'address': address, 'device': info.st_dev, 'inode': info.st_ino}
    return True
