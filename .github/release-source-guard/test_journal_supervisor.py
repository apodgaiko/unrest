"""Parsing composition keeps every authority method and original object identity."""
from pathlib import Path
import sys

import pytest

sys.path.insert(0, str(Path(__file__).parent))
from journal_supervisor import JournalSupervisor
from linux_supervisor import Supervisor
from owned_multiprocess_authority import OwnedMultiprocessCustody


def test_authority_methods_remain_original_with_closed_census_and_list_adapters():
    original_methods = {name: value for name, value in vars(Supervisor).items()
                        if callable(value)}
    assert 'events' in original_methods and len(original_methods) > 10
    for name, method in original_methods.items():
        if name not in {'events', 'refresh', 'handle', 'tick'}:
            assert getattr(JournalSupervisor, name) is method, name
    assert set(vars(JournalSupervisor)) - {
        '__module__', '__doc__', '__firstlineno__', '__static_attributes__',
        'adopt', 'events', 'journal', 'refresh', 'handle', 'tick'} == set()


def test_adoption_preserves_instance_state_and_existing_references():
    original = Supervisor.__new__(Supervisor)
    original.channel = object()
    original.registered = {2: {'token': 'owned'}}
    original.source_response_output = lambda request: request
    references = [original, {'supervisor': original}]
    state, identity = original.__dict__, id(original)
    values = dict(state)
    assert JournalSupervisor.adopt(original) is original
    assert id(original) == identity and original.__dict__ is state
    assert original.__dict__ == values
    assert references[0] is original and references[1]['supervisor'] is original
    assert type(original) is JournalSupervisor
    with pytest.raises(RuntimeError, match='original_type_required'):
        JournalSupervisor.adopt(original)


def test_adoption_rejects_non_original_supervisors():
    class Different(Supervisor):
        pass
    for value in (object(), Different.__new__(Different)):
        with pytest.raises(RuntimeError, match='original_type_required'):
            JournalSupervisor.adopt(value)


def test_existing_authority_composition_preserves_start_call_and_result():
    calls = []
    result = object()
    class Parent:
        def start(self, *args, **kwargs):
            calls.append((args, kwargs))
            self.supervisor = Supervisor.__new__(Supervisor)
            self.original_reference = self.supervisor
            return result
    class Authority(OwnedMultiprocessCustody, Parent):
        pass
    authority = Authority()
    assert authority.start(2, 3, trace='trace', primary='primary') is result
    assert calls == [((2, 3), {'trace': 'trace', 'primary': 'primary'})]
    assert authority.supervisor is authority.original_reference
    assert type(authority.supervisor) is JournalSupervisor
