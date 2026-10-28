"""One exact non-launching original regression selection, never a release root."""
from content_manifest import Refused

CASE='tests/test_v04_speed_runner.py::test_async_task_adapter_then_guard_regression_runs_in_one_process'
NODES=('tests/test_task_adapter.py::test_nominal_bounded_completion_and_handoff',
       'tests/test_v04_speed_runner.py::test_every_available_network_and_command_route_is_guarded_counted_and_restored')
PYTEST_PIN='a150eb186a3b3744cdcb35e7b546e57204ca6e11c65ad8af717e530bbb4470aa'


def selected(policy):
    from source_root import OriginalCases
    class Leaf(OriginalCases):
        def enter(self,case):
            pass

        def leave(self,case,outcome,phases):
            if case==NODES[-1]:
                from source_profile import case_seal
                self.policy.client.request('preselected-finish',case_seal(NODES))
    result=Leaf(policy)
    result.cases=NODES
    return result


def pytest_configure(config):
    from source_entry import ACTIVE
    if ACTIVE is None or ACTIVE.profile['role']!='pytest-regression' or ACTIVE.case!=CASE:
        raise Refused('preselected pytest native scope')
    config.pluginmanager.register(selected(ACTIVE),'release-preselected-outcomes')
