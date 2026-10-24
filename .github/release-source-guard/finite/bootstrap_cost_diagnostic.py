"""Closed TEST-only CPU attribution; never source certification or timing proof."""
CASES = ('tests/test_experimental_bootstrap.py::test_actual_sequential_initialize_and_session_share_cutoff', 'tests/test_experimental_bootstrap.py::test_startup_subtracts_from_actual_inference_timeout')


def selected(profile, case):
    return (profile.get('source_mode') == 'TEST-positive' and case in CASES
            and profile.get('orig_argv', [])[2:] == ['-q', *CASES])
