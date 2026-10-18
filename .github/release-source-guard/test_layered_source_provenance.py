"""Real product coroutine controls for the finite literal/launcher join.

Popen stops before OS launch here; hosted original SOURCE supplies execution.
"""
from __future__ import annotations

import ast
import asyncio
import inspect
from pathlib import Path
import subprocess
import sys
import types

import pytest

from test_source_activation_composition import Consumed, Refusal, setup
from unrest_harness import acp_runner

ROOT = Path(__file__).resolve().parents[2]


@pytest.mark.parametrize('change', [None, 'binding', 'literal', 'trace', 'cwd', 'source-pin',
                                   'plan-vector', 'plan-env', 'plan-type', 'globals', 'code',
                                   'stream', 'limit', 'missing-frame', 'module-function',
                                   'missing-file', 'missing-plan-environment'])
def test_literal_producer_and_real_product_launcher_are_both_required(tmp_path, monkeypatch, change):
    h = setup(tmp_path, monkeypatch)
    producer = ROOT / 'tests/test_server.py'
    node = next(n for n in ast.parse(producer.read_bytes()).body
                if isinstance(n, ast.FunctionDef) and n.name == '_write_composed_acp_adapter')
    literal = next(n.args[0].value for n in ast.walk(node)
                   if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)
                   and n.func.attr == 'write_text')
    script = tmp_path / '.hermetic-acp-adapter.py'
    script.write_text(literal)
    vector = [sys.executable, str(script), str(tmp_path / '.hermetic-acp-trace.jsonl')]
    h.state['checkout'] = str(ROOT)
    h.state['product_pins'] = {'src/unrest_harness/acp_runner.py':
                             h.guard.digest(ROOT / 'src/unrest_harness/acp_runner.py')}
    registration = {'class': 'source-composed-adapter', 'python': True,
                    'source_binding': {'path': str(producer), 'line': 3302,
                                       'sha256': h.guard.digest(producer)}}
    plan = acp_runner.LaunchPlan(tuple(vector), str(tmp_path), {'PATH': '/bin'}, '/bin')
    call = acp_runner.spawn_launch
    if change == 'binding':
        registration['source_binding']['line'] += 1
    elif change == 'literal':
        script.write_text(literal + '\n')
    elif change == 'trace':
        vector[2] += '.foreign'
    elif change == 'cwd':
        vector[1] = str(tmp_path.parent / '.hermetic-acp-adapter.py')
    elif change == 'source-pin':
        h.state['product_pins']['src/unrest_harness/acp_runner.py'] = '0' * 64
    elif change == 'plan-type':
        plan = types.SimpleNamespace(argv=plan.argv, cwd=plan.cwd,
                                     environment=plan.environment, path=plan.path)
    elif change == 'globals':
        call = types.FunctionType(call.__code__, dict(call.__globals__))
    elif change == 'code':
        call = types.FunctionType(call.__code__.replace(co_name='copied'), call.__globals__)
    elif change == 'module-function':
        monkeypatch.setattr(acp_runner, 'spawn_launch', lambda *a: None)

    def consume(handle, args, **kwargs):
        frames = []
        frame = inspect.currentframe()
        while frame:
            frames.append(frame)
            frame = frame.f_back
        env = kwargs['env']
        observed = list(args)
        if change == 'plan-vector':
            object.__setattr__(plan, 'argv', ('changed',))
        elif change == 'plan-env':
            env = dict(env)
        elif change == 'stream':
            kwargs['stdin'] = subprocess.DEVNULL
        elif change == 'missing-file':
            script.unlink()
        elif change == 'missing-plan-environment':
            object.__delattr__(plan, 'environment')
        elif change == 'missing-frame':
            frames = [f for f in frames if f.f_code.co_name != 'spawn_launch']
        try:
            h.activation.composed_adapter_owner(h.guard, {'kwargs': kwargs}, observed,
                                                kwargs['cwd'], env, registration, frames)
        finally:
            frames.clear()
        raise Consumed

    monkeypatch.setattr(subprocess.Popen, '__init__', consume)
    if change == 'limit':
        original = asyncio.create_subprocess_exec
        async def different_limit(*args, **kwargs):
            kwargs['limit'] += 1
            return await original(*args, **kwargs)
        monkeypatch.setattr(asyncio, 'create_subprocess_exec', different_limit)
    # Keep the plan/call vector distinct where the test perturbs the producer.
    if change in {'trace', 'cwd'}:
        plan = acp_runner.LaunchPlan(tuple(vector), str(tmp_path), {'PATH': '/bin'}, '/bin')
    with pytest.raises(Consumed if change is None else Refusal):
        asyncio.run(call(plan, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                         stderr=subprocess.PIPE, limit=65536))
    assert bool(h.poison) is (change is not None)
