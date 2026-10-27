"""The production native consumer cannot select a diagnostic profile or binding."""
from pathlib import Path

import pytest

import native_entry
import source_host
import test_native_profile


@pytest.mark.parametrize('schema', ['unrest.native-control.v1', 'unknown', None])
def test_production_rejects_diagnostic_and_unknown_schema_before_activation(monkeypatch, schema):
    monkeypatch.setattr(native_entry,'acquire',lambda directory:(Path('/profiles'),{'schema':schema}))
    monkeypatch.setattr(native_entry,'BODY_READY',False)
    with pytest.raises(ValueError, match='source profile schema'):
        native_entry.consume('/profiles','cpython.run_command',('pass\n',))
    assert native_entry.BODY_READY is False


def test_test_consumer_has_no_production_schema_fallback(monkeypatch):
    monkeypatch.setattr(test_native_profile,'acquire',lambda directory:(Path('/profiles'),{'schema':'unrest.bootstrap-source.v1'}))
    monkeypatch.setattr(test_native_profile,'BODY_READY',False)
    with pytest.raises(ValueError,match='profile schema'):
        test_native_profile.consume('/profiles','cpython.run_command',('pass\n',))
    assert test_native_profile.BODY_READY is False


@pytest.mark.parametrize('field', [None, 'entry', 'bootstrap', 'both'])
def test_source_driver_accepts_only_fixed_production_paths(field):
    binding={'support':'/generation/support','runtime':{'path':'/generation/runtime/bin/python3.13'},
        'entry':{'path':'/generation/runtime/bin/python-unrest-guard-control'},
        'bootstrap':{'path':'/generation/support/native_entry.py'}}
    if field in ('entry','both'):
        binding['entry']['path']='/generation/runtime/bin/python-unrest-guard-test'
    if field in ('bootstrap','both'):
        binding['bootstrap']['path']='/generation/test-support/test_native_profile.py'
    if field is None:
        source_host.production_binding(binding)
    else:
        with pytest.raises(RuntimeError,match='production native binding'):
            source_host.production_binding(binding)
