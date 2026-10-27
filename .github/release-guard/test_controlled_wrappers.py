"""Original prepared constructor wrappers retain exact original functions."""
import asyncio
from pathlib import Path
import sys

import pytest

from content_manifest import Refused
from controlled_wrappers import verify
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from tests.test_controlled_acp_cancel import methods  # noqa: E402


def test_original_observing_wrapper_keeps_source_and_closure_binding(monkeypatch):
    original = asyncio.create_subprocess_exec
    methods.__wrapped__(monkeypatch)
    verify(asyncio,'create_subprocess_exec',original,Path(__file__).resolve().parents[2])
    with pytest.raises(Refused):
        verify(asyncio,'create_subprocess_exec',lambda:None,Path(__file__).resolve().parents[2])


def test_unprepared_constructor_wrapper_refuses(monkeypatch):
    original = asyncio.create_subprocess_exec
    async def foreign(*args,**kwargs):
        return await original(*args,**kwargs)
    monkeypatch.setattr(asyncio,'create_subprocess_exec',foreign)
    with pytest.raises(Refused):
        verify(asyncio,'create_subprocess_exec',original,Path(__file__).resolve().parents[2])


@pytest.mark.parametrize('field',['qualname','code'])
def test_wrapper_metadata_cannot_execute_comparison_or_hash_callbacks(monkeypatch,field):
    original = asyncio.create_subprocess_exec
    methods.__wrapped__(monkeypatch)
    live = asyncio.create_subprocess_exec
    class Text(str):
        def __hash__(self):
            pytest.fail('metadata hash callback')
        def __eq__(self,other):
            pytest.fail('metadata equality callback')
    if field == 'qualname':
        live.__qualname__ = Text(live.__qualname__)
    else:
        live.__code__ = live.__code__.replace(co_consts=(*live.__code__.co_consts,Text('foreign')))
    with pytest.raises(Refused):
        verify(asyncio,'create_subprocess_exec',original,Path(__file__).resolve().parents[2])


@pytest.mark.parametrize('barrier', [False, True])
def test_original_retirement_wrapper_keeps_product_start_without_launch(monkeypatch, tmp_path, barrier):
    from tests import test_experimental_drain_retirement as tests
    from unrest_harness.experimental_session import _SessionOwner
    original = _SessionOwner.start
    class Stopped(RuntimeError):
        pass
    async def inspect(*args, **kwargs):
        verify(_SessionOwner, 'start', original, Path(__file__).resolve().parents[2])
        with pytest.raises(Refused):
            verify(_SessionOwner, 'start', lambda: None, Path(__file__).resolve().parents[2])
        raise Stopped
    monkeypatch.setattr(tests, 'original_stop', inspect)
    with pytest.raises(Stopped):
        asyncio.run(tests.test_original_stop_and_retired_delivery(tmp_path, monkeypatch, lambda *args: None, barrier))


def test_original_startup_environment_wrapper_retains_original(monkeypatch):
    from tests.test_experimental_startup_diagnostics import controlled_config_home
    from unrest_harness.experimental_session import _SessionOwner
    original = _SessionOwner._environment
    controlled_config_home.__wrapped__(monkeypatch)
    verify(_SessionOwner, '_environment', original, Path(__file__).resolve().parents[2])
    with pytest.raises(Refused):
        verify(_SessionOwner, '_environment', lambda: None, Path(__file__).resolve().parents[2])
