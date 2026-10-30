"""Historical bootstrap selection used only by guard control tests."""
CASES = tuple('tests/test_experimental_bootstrap.py::' + name for name in (
    'test_actual_sequential_initialize_and_session_share_cutoff',
    'test_startup_subtracts_from_actual_inference_timeout'))
