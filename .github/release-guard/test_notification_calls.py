"""Portable selector negatives; synthetic inputs do not certify original execution."""
from types import SimpleNamespace

import pytest

from content_manifest import Refused
from notification_calls import closure, signal_owner


@pytest.mark.parametrize('value', [None, object(), {}, 1, 'function'])
def test_closure_requires_actual_function_without_descriptor_callbacks(value):
    with pytest.raises(Refused):
        closure(value)


def test_closure_does_not_invoke_custom_code_descriptors():
    class Foreign:
        @property
        def __code__(self):
            pytest.fail('descriptor callback')
    with pytest.raises(Refused):
        closure(Foreign())


@pytest.mark.parametrize('phase,status', [('startup', 'connected'), ('parked', 'disabled'),
                                        ('foreign', 'unknown'), ('before-send', 'foreign')])
def test_signal_phase_must_be_declared_before_any_owner_or_handle_access(phase, status):
    calls = SimpleNamespace(notification=(None,) * 7,
                            policy=SimpleNamespace(case='original['+phase+'-'+status+']'))
    with pytest.raises(Refused, match='selected signal phase'):
        signal_owner(calls)


def test_closure_capture_preserves_actual_cell_identity():
    token = object()
    def body():
        return token
    assert closure(body) == {'token': token}
