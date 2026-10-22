"""Finite failed-root diagnostics for the exact original approval subset."""
from primary_policy import TEST_APPROVAL_CLOSURE_CASES
from finite.approval_routes import PREFIX, DURABLE_PREFIX


def case_seconds(profile, case):
    # This is not a source-checkpoint deadline or a pytest timeout override.
    if (profile.get('source_mode') != 'TEST-positive'
            or profile.get('orig_argv', [])[2:] != ['-q', *TEST_APPROVAL_CLOSURE_CASES]
            or case not in TEST_APPROVAL_CLOSURE_CASES):
        return None
    if case.startswith(PREFIX + '['):
        return 60
    if case.startswith(DURABLE_PREFIX + '['):
        return 120
    return None
