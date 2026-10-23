"""Finite failed-root diagnostics for the exact original approval subset."""
import hashlib
import json

PREFIX = 'tests/test_approval_recovery.py::test_actual_acp_owner_native_subprocess_order_and_cleanup'
DURABLE_PREFIX = 'tests/test_approval_recovery.py::test_durable_run_owner_and_restart_never_revives'
SELECTION_SHA256 = '48732f66ebe09d9be202fb44240144da697a90ce7fc6a45f2de3ab54d7dd0773'
SELECTIONS = frozenset(['48732f66ebe09d9be202fb44240144da697a90ce7fc6a45f2de3ab54d7dd0773', '1bc7f8bc0ff3fe70afbd32bfd97442d411304c365277f2dfb4a2bc1cd12ab007', '11f047606d23b0465040506961c5992456281ca78d4174073650b3ae02d19ac4'])

EXPIRY_CASES = frozenset(('tests/test_approval_recovery.py::test_real_deadline_timer_erases_memory_and_cleans_reader', 'tests/test_approval_recovery.py::test_real_deadline_expires_during_settlement_handshake', 'tests/test_approval_recovery.py::test_expiry_cleanup_closes_owner_after_writer_error[reset]', 'tests/test_approval_recovery.py::test_expiry_cleanup_closes_owner_after_writer_error[other]'))


def case_seconds(profile, case):
    # This is not a source-checkpoint deadline or a pytest timeout override.
    if (profile.get('source_mode') != 'TEST-positive'
            or hashlib.sha256(json.dumps(profile.get('orig_argv', [])[2:]).encode()).hexdigest() not in SELECTIONS
            or case not in profile['orig_argv'][3:]):
        return None
    if case in EXPIRY_CASES:
        return 20
    if case.startswith(PREFIX + '['):
        return 60
    if case.startswith(DURABLE_PREFIX + '['):
        return 120
    return None


REGISTRATION_CASE = 'tests/test_controlled_python_acp.py::test_actual_registration[late-2]'
REGISTRATION_SELECTION_SHA256 = '9d84ea3ef8211e7591a9c2b8cc19afc947e1de7fd9c8d3b5fc1f9cfa31058446'

def registration_seconds(profile, case):
    """Passive stack capture only; never a test deadline or exit watchdog."""
    argv = profile.get('orig_argv')
    if (profile.get('source_mode') != 'TEST-positive'
            or type(argv) is not list or any(type(value) is not str for value in argv)
            or type(case) is not str or case != REGISTRATION_CASE
            or hashlib.sha256(json.dumps(argv[2:]).encode()).hexdigest() != REGISTRATION_SELECTION_SHA256):
        return None
    return 2.0
