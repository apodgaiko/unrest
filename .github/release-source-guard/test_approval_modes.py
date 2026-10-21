"""All and only the original nine controlled approval scenarios are admitted."""
import ast
from pathlib import Path

import pytest

from finite import approval_routes as routes


@pytest.mark.parametrize('mode', routes.MODES)
def test_each_original_mode_is_derived_from_its_exact_case(mode):
    assert routes.selected_mode(routes.PREFIX + '[' + mode + ']') == mode
    assert routes.selected_mode(routes.PREFIX + '[' + mode + ']-foreign') is None


@pytest.mark.parametrize('case', [None, '', 'foreign', routes.PREFIX, routes.PREFIX + '[new]',
                                   routes.PREFIX + '[success] extra'])
def test_other_cases_gain_no_controlled_approval_launch(case):
    assert routes.selected_mode(case) is None
    assert routes.select([], None, None, {'case': case}, None, None) is None


def test_original_mode_parameters_and_backend_identity_gates_remain_closed():
    path = Path(routes.__file__)
    source = path.read_text()
    tree = ast.parse(source)
    assert source.count('scenario["mode"] != mode') == 1
    assert source.count('env["CONTROLLED_APPROVAL_MODE"] != mode') == 1
    assert 'backend_path.read_bytes() != backend_body' in source
    assert 'backend.read_bytes() != body' in source
    assert 'sha(backend) != local["backend_digest"]' in source
    assert not any(isinstance(n, ast.Call) and ast.unparse(n.func) in {'subprocess.Popen', 'os.system'}
                   for n in ast.walk(tree))


@pytest.mark.parametrize('boundary, mode', routes.DURABLE_MODES.items())
def test_exact_durable_boundaries_derive_original_modes(boundary, mode):
    from finite.approval_run_owner import boundary as select_boundary
    case = routes.DURABLE_PREFIX + '[' + boundary + ']'
    assert routes.selected_mode(case) == mode
    assert select_boundary(case) == boundary
    assert select_boundary(case + '-foreign') is None


def test_closed_bulk_diagnostic_keeps_existing_budget_and_original_deadlines():
    from primary_policy import TEST_APPROVAL_CLOSURE_CASES, TEST_SEAM_ROOT_SECONDS, root_seconds
    from test_primary_source_entry import inputs, COMMAND
    from primary_source_inputs import test_plan as make_plan
    text, _ = inputs()
    assert len(TEST_APPROVAL_CLOSURE_CASES) == 33
    script = (COMMAND + ' ' + ' '.join(TEST_APPROVAL_CLOSURE_CASES)).encode()
    plan = make_plan(script, text, 'TEST-positive')
    assert plan['timeout_seconds'] == root_seconds(plan) == TEST_SEAM_ROOT_SECONDS == 600
    assert plan['source_checkpoint_ready'] is False
    with pytest.raises(RuntimeError):
        make_plan((COMMAND + ' ' + ' '.join(TEST_APPROVAL_CLOSURE_CASES[:-1])).encode(), text, 'TEST-positive')
