"""One exact non-launching original regression selection, never a release root."""
from content_manifest import Refused
from launch_policy import source_unit,assignment,literal
import ast

CASE='tests/test_v04_speed_runner.py::test_async_task_adapter_then_guard_regression_runs_in_one_process'
NODES=('tests/test_task_adapter.py::test_nominal_bounded_completion_and_handoff',
       'tests/test_v04_speed_runner.py::test_every_available_network_and_command_route_is_guarded_counted_and_restored')
PYTEST_PIN='a150eb186a3b3744cdcb35e7b546e57204ca6e11c65ad8af717e530bbb4470aa'

HERMETIC_TEST='tests/test_environment_isolation.py'
HERMETIC=HERMETIC_TEST+'::test_seeded_pytest_run_is_hermetic_and_restores_parent_environment'
CASES={CASE:NODES,HERMETIC:(HERMETIC_TEST+'::test_autouse_fixture_scrubs_complete_authoritative_inventory',
    HERMETIC_TEST+'::test_autouse_fixture_preserves_unrelated_environment',
    'tests/test_config.py::test_discover_defaults_to_four_parallel_nodes')}
PINS={'tests/test_environment_isolation.py': '3e82797b6dee4e339b1fb53f62fe3ccd9c7445a5d0667b4f7795f671799c473c', 'src/unrest_harness/config.py': '09835fde9cd71844bcff7ce3e4f4427e959a60e0883ba7241b632dd8f04b5ea2', 'tests/test_config.py': '04553ce290a7945bcf68bec8f28ad332efc83a41dcdbd7162dc097de8ffd2d42'}


def hermetic(checkout, environment):
    trees={path:source_unit(checkout,path,pin) for path,pin in PINS.items()}
    tree=trees[HERMETIC_TEST]
    function=next(node for node in tree.body if isinstance(node,ast.FunctionDef) and node.name=='_adversarial_environment')
    names=set(ast.literal_eval(assignment(trees['src/unrest_harness/config.py'],'_CONFIG_ENV')).values())
    names.update(('UNREST_CAPABILITY_PROFILE','UNREST_CAPABILITY_POLICY_VERSION','UNREST_UNSAFE_DEVELOPMENT_UNRESTRICTED'))
    values={name:f'ambient-{index}-{name.lower()}' for index,name in enumerate(sorted(names),1)}
    overrides=[node for node in ast.walk(function) if isinstance(node,ast.Call)
               and isinstance(node.func,ast.Attribute) and node.func.attr=='update']
    values.update(ast.literal_eval(overrides[0].args[0]))
    if set(values)!=names:
        raise Refused('hermetic complete environment inventory')
    return literal(tree,'_PYTEST_RESTORE_PROBE'), {**environment,**values,
        'UNREST_TEST_ISOLATION_UNRELATED_SENTINEL':'outer-unrelated-value'}


def selected(policy):
    from source_root import local_cases
    from source_profile import case_seal
    return local_cases(policy,CASES[policy.case],on_last=lambda:policy.client.request('preselected-finish',case_seal(CASES[policy.case])))


def pytest_configure(config):
    from source_entry import ACTIVE
    if ACTIVE is None or ACTIVE.profile['role']!='pytest-regression' or ACTIVE.case not in CASES:
        raise Refused('preselected pytest native scope')
    config.pluginmanager.register(selected(ACTIVE),'release-preselected-outcomes')
