"""Real running/suspended asyncio stacks; no fixture or process is launched."""
import asyncio
import hashlib
from pathlib import Path
import sys
from types import SimpleNamespace

from finite import cleanup_routes


def test_inflight_discovery_includes_running_and_suspended_owners(monkeypatch):
    root = Path(__file__).parent / 'finite'
    support = root / 'fallback_binding.py'
    body = support.read_bytes()
    pin = hashlib.sha256(body).hexdigest()
    state = {'guard': str(root / 'runtime_guard.py'),
             'direct_support': {'files': {str(support): pin}}}
    calls = []
    def checked(path, expected):
        current = Path(path).read_bytes()
        assert hashlib.sha256(current).hexdigest() == expected == pin
        value = {'__file__': str(path), '__name__': 'inflight_frames_control'}
        exec(compile(current, str(path), 'exec', dont_inherit=True), value)
        calls.append('checked')
        return value
    monkeypatch.setitem(sys.modules, 'runtime_guard', SimpleNamespace(checked_source=checked))
    async def running_leaf():
        suspended_only = cleanup_routes.task_frames()
        combined = cleanup_routes.inflight_frames(state)
        try:
            task_names = {frame.f_code.co_name for frame in suspended_only}
            all_names = {frame.f_code.co_name for frame in combined}
            assert 'running_leaf' not in task_names
            assert {'running_leaf', 'running_producer', 'suspended_owner'} <= all_names
            assert len({id(frame) for frame in combined}) == len(combined)
        finally:
            suspended_only.clear()
            combined.clear()
    async def running_producer():
        await running_leaf()
    async def suspended_owner():
        await asyncio.create_task(running_producer())
    asyncio.run(suspended_owner())
    assert calls == ['checked']
