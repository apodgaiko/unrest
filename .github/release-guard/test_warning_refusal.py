"""Original warning caller and retained owner; stopped before any child or signal."""
import asyncio
import asyncio.unix_events
import hashlib
from pathlib import Path
from types import SimpleNamespace

import pytest

from content_manifest import Refused
from controlled_wrappers import instance_environment
from source_calls import Sources
from source_owner import Link, prepare
from source_root import BootstrapCalls


@pytest.mark.parametrize('mutation', [None, 'group', 'pid', 'generation', 'owner', 'config'])
def test_original_warning_signal_and_environment_are_owned(tmp_path, monkeypatch, mutation):
    from tests import test_controlled_acp_warnings as tests
    from unrest_harness import experimental_session as module
    source = Path(tests.__file__)
    unit = prepare(source.read_bytes(), str(source), tests.__name__, 'pytest', hashlib.sha256(source.read_bytes()).hexdigest())
    fn = tests.test_owned_warning_refusal_and_cleanup
    calls = object.__new__(BootstrapCalls)
    calls.test_owner = Sources.owner(unit, tests, fn, fn.__qualname__, (Link(tests, fn.__name__, fn),))
    calls.startup = SimpleNamespace(base=module._SessionOwner, synthetic=module.SyntheticSession)
    calls.session = module
    calls.backend_type = module._Backend
    calls.process_class = asyncio.subprocess.Process
    calls.transport_class = asyncio.unix_events._UnixSubprocessTransport
    marker = object()
    case = 'tests/test_controlled_acp_warnings.py::test_owned_warning_refusal_and_cleanup[malformed]'
    calls.policy = SimpleNamespace(case=case, children={123: {'process': marker}})
    transport = object.__new__(calls.transport_class)
    vars(transport).update(_pid=123, _proc=object() if mutation == 'generation' else marker, _closed=True, _returncode=0)
    process = object.__new__(calls.process_class)
    process._transport = transport
    process.pid = 123
    original_environment = module._SessionOwner._environment
    retained = []
    class Selected(RuntimeError):
        pass
    async def start(owner):
        retained.append(owner)
        config = vars(owner)['provider_config']
        if mutation in ('owner', 'config'):
            live = vars(owner)['_environment']
            cells = dict(zip(live.__code__.co_freevars, live.__closure__, strict=True))
            if mutation == 'owner':
                import types
                cells['environment'].cell_contents = types.MethodType(original_environment, object())
            else:
                cells['config'].cell_contents = object()
        instance_environment(owner, module._SessionOwner, original_environment, config, Path.cwd(), case)
        owner.backends['worker'] = module._Backend(process, None, None)
    async def nothing(*args, **kwargs):
        pass
    def send(sig):
        calls.signal(124 if mutation == 'pid' else 123, int(sig), mutation == 'group')
        raise Selected
    monkeypatch.setattr(module._SessionOwner, 'start', start)
    monkeypatch.setattr(module._SessionOwner, 'initialize_only', nothing)
    monkeypatch.setattr(module._SessionOwner, 'close', nothing)
    monkeypatch.setattr(process, 'send_signal', send)
    try:
        with pytest.raises(Selected if mutation is None else Refused):
            asyncio.run(fn(tmp_path, monkeypatch, 'malformed'))
    finally:
        for owner in retained:
            owner.backends.clear()
