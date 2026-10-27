"""Original teardown caller/handle selection, stopped before any OS signal."""
import hashlib
from pathlib import Path
from types import SimpleNamespace

import pytest

from content_manifest import Refused
from source_calls import Sources
from source_owner import Link,prepare
from source_root import BootstrapCalls


@pytest.mark.parametrize('mutation',[None,'group','pid','generation','backend-key'])
def test_original_teardown_signal_requires_its_exact_owned_backend(tmp_path,monkeypatch,mutation):
    monkeypatch.syspath_prepend(str(Path(__file__).resolve().parents[2]))
    from tests import test_experimental_bridge_shutdown as tests
    from tests.test_experimental_session import session as fixture
    from unrest_harness import experimental_session as module
    import asyncio.unix_events
    owner = fixture.__wrapped__(tmp_path,None)
    source = Path(tests.__file__)
    unit = prepare(source.read_bytes(),str(source),tests.__name__,'pytest',hashlib.sha256(source.read_bytes()).hexdigest())
    fn = tests.test_owned_teardown_completes_after_native_drain_failure
    calls = object.__new__(BootstrapCalls)
    calls.test_owner = Sources.owner(unit,tests,fn,fn.__qualname__,(Link(tests,fn.__name__,fn),))
    calls.startup = SimpleNamespace(base=module._SessionOwner,synthetic=module.SyntheticSession)
    calls.session = module
    calls.backend_type = module._Backend
    calls.process_class = asyncio.subprocess.Process
    calls.transport_class = asyncio.unix_events._UnixSubprocessTransport
    marker = object()
    calls.policy = SimpleNamespace(case='tests/test_experimental_bridge_shutdown.py::'+fn.__name__,children={123:{'process':marker}})
    transport = object.__new__(calls.transport_class)
    vars(transport).update(_pid=123,_proc=object() if mutation == 'generation' else marker,_closed=True,_returncode=0)
    process = object.__new__(calls.process_class)
    process._transport = transport
    process.pid = 123
    async def nothing(*args,**kwargs):
        pass
    writer = SimpleNamespace(drain=nothing)
    owner.backends['worker'] = module._Backend(process,None,SimpleNamespace(writer=writer))
    original_close = owner.close
    monkeypatch.setattr(owner,'start',nothing)
    monkeypatch.setattr(owner,'initialize_only',nothing)
    monkeypatch.setattr(owner,'close',nothing)
    class Selected(RuntimeError):
        pass
    selected = []
    def send(sig):
        if mutation == 'backend-key':
            class Trap:
                def __hash__(self):
                    return hash('worker')
                def __eq__(self,other):
                    pytest.fail('backend lookup equality callback')
            backend = owner.backends.pop('worker')
            owner.backends[Trap()] = backend
        calls.signal(124 if mutation == 'pid' else 123,int(sig),mutation == 'group')
        selected.append(True)
        raise Selected
    monkeypatch.setattr(process,'send_signal',send)
    try:
        with pytest.raises(Selected if mutation is None else Refused):
            asyncio.run(fn(owner,monkeypatch,tmp_path))
        assert selected == ([True] if mutation is None else [])
    finally:
        owner.backends.clear()
        asyncio.run(original_close())
