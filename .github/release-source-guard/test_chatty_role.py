"""Metadata-only checks of the exact original spy; no child or fixture is executed."""
import asyncio
import asyncio.subprocess
import hashlib
from importlib.machinery import SourceFileLoader
import importlib.util
import os
from pathlib import Path
import sys
import types

import pytest

from finite import chatty_role as helper


def named(code, name):
    if code.co_name == name:
        return code
    for value in code.co_consts:
        if isinstance(value, types.CodeType):
            result = named(value, name)
            if result is not None:
                return result
    return None


@pytest.fixture(params=['worker', 'terminal-reviewer'])
def model(request, tmp_path, monkeypatch):
    root = Path(__file__).resolve().parents[2]
    source, product = root / helper.SOURCE, root / helper.PRODUCT
    code = compile(source.read_bytes(), str(source), 'exec', dont_inherit=True)
    test_module = types.ModuleType('chatty_test_control')
    owner_code = named(code, helper.OWNER)
    owner_function = types.FunctionType(owner_code, vars(test_module))
    setattr(test_module, helper.OWNER, owner_function)
    original = asyncio.subprocess.create_subprocess_exec
    cells = {'secret': 'oversized-child-secret', 'original_spawn': original, 'spawned_argv': []}
    spy_code = named(owner_code, 'spawn_chatty')
    spy = types.FunctionType(spy_code, vars(test_module),
                             closure=tuple(types.CellType(cells[n]) for n in spy_code.co_freevars))
    product_module = types.ModuleType('chatty_product_control')
    loader = SourceFileLoader(product_module.__name__, str(product))
    product_module.__loader__ = loader
    product_module.__spec__ = importlib.util.spec_from_loader(product_module.__name__, loader)
    product_module.SUBPROCESS_STREAM_LIMIT = 8 * 1024 * 1024
    product_code = loader.source_to_code(product.read_bytes(), str(product))
    mode = request.param
    method = '_start_worker_mcp_server' if mode == 'worker' else '_start_terminal_reviewer_mcp'
    workspace = tmp_path / 'owned/workspace'
    workspace.mkdir(parents=True)
    runner = object()
    read_fd, write_fd = os.pipe()
    command = [sys.executable, '-m', 'unrest_harness', '--mode', mode, '--transport',
               'streamable-http', '--host', '127.0.0.1', '--port', '43210',
               '--sensitive-inventory-fd', str(read_fd)]
    environment = {'PATH': os.environ['PATH']}
    if mode == 'worker':
        environment['UNREST_NODE_ASSIGNMENT'] = '{"targets":["VAL-SEC-014"],"task_type":"work"}'
    owner = types.SimpleNamespace(f_code=owner_code, f_globals=vars(test_module), f_locals={
        'mode': mode, 'workspace': workspace, 'runner': runner, 'spawn_chatty': spy,
        'original_spawn': original, 'secret_name': 'ANTHROPIC_API_KEY', 'secret': 'oversized-child-secret'})
    options = {'cwd': str(workspace), 'env': environment, 'pass_fds': (read_fd,),
               'stdout': asyncio.subprocess.PIPE, 'stderr': asyncio.subprocess.PIPE,
               'limit': product_module.SUBPROCESS_STREAM_LIMIT}
    active = types.SimpleNamespace(f_code=spy_code, f_globals=vars(test_module), f_lineno=341,
                                   f_locals={'original_spawn': original, 'args': tuple(command), 'kwargs': options})
    factory = types.SimpleNamespace(f_code=named(product_code, method), f_globals=vars(product_module),
                                    f_locals={'self': runner, 'cmd': command, 'mcp_port': 43210,
                                              'environment': {'PATH': os.environ['PATH']},
                                              'sensitive_inventory': {'ANTHROPIC_API_KEY': 'oversized-child-secret'}})
    frames = [owner, active, factory, owner]
    support = root / '.github/release-source-guard/finite/fallback_binding.py'
    pin = hashlib.sha256(support.read_bytes()).hexdigest()
    state = {'checkout': str(root), 'owned_root': str(tmp_path / 'owned'),
             'guard': str(support.with_name('runtime_guard.py')),
             'case': helper.SOURCE + '::' + helper.OWNER + '[' + mode + ']',
             'product_pins': {helper.SOURCE: helper.PIN, helper.PRODUCT: helper.PRODUCT_PIN},
             'isolated_source_code': lambda path: code, 'isolated_named': named,
             'direct_support': {'files': {str(support): pin}}}
    def checked(path, expected):
        assert Path(path) == support and hashlib.sha256(support.read_bytes()).hexdigest() == expected
        return {'active_frames': lambda: list(frames)}
    monkeypatch.setitem(sys.modules, 'runtime_guard', types.SimpleNamespace(checked_source=checked))
    for module in (test_module, product_module):
        monkeypatch.setitem(sys.modules, module.__name__, module)
    monkeypatch.setattr(asyncio, 'create_subprocess_exec', spy)
    def refuse(reason):
        raise RuntimeError(reason)
    def bind():
        return helper.bind([sys.executable, '-c', helper.BODY], str(workspace), environment,
                           state, mode, factory, read_fd, command, refuse)
    try:
        yield types.SimpleNamespace(bind=bind, source=source, owner=owner, active=active,
                                    factory=factory, state=state, environment=environment, frames=frames)
    finally:
        os.close(read_fd)
        os.close(write_fd)


def test_exact_spy_keeps_original_source_and_truthful_binding(model):
    assert model.bind() == {'path': str(model.source), 'line': 341, 'sha256': helper.PIN}
    assert len(model.frames) == 4


@pytest.mark.parametrize('change', ['case', 'mode', 'source', 'program-secret', 'alias', 'spy-line',
                                   'spy-code', 'args', 'runner', 'factory-code', 'port', 'cwd',
                                   'pipe', 'stdout', 'limit', 'inventory', 'environment'])
def test_changed_or_unbound_fixture_is_not_admitted(model, change):
    m = model
    if change == 'case':
        m.state['case'] = 'foreign'
        assert m.bind() is None
        return
    if change == 'mode':
        m.owner.f_locals['mode'] = 'foreign'
    elif change == 'source':
        m.state['product_pins'][helper.SOURCE] = '0' * 64
    elif change == 'program-secret':
        m.owner.f_locals['secret'] = 'foreign'
    elif change == 'alias':
        m.active.f_locals['original_spawn'] = object()
    elif change == 'spy-line':
        m.active.f_lineno += 1
    elif change == 'spy-code':
        m.active.f_code = compile('pass', str(m.source), 'exec')
    elif change == 'args':
        m.active.f_locals['args'] = ('foreign',)
    elif change == 'runner':
        m.factory.f_locals['self'] = object()
    elif change == 'factory-code':
        m.factory.f_code = compile('pass', '/foreign', 'exec')
    elif change == 'port':
        m.factory.f_locals['mcp_port'] += 1
    elif change in {'cwd', 'pipe', 'stdout', 'limit'}:
        key = {'pipe': 'pass_fds'}.get(change, change)
        m.active.f_locals['kwargs'][key] = 'foreign'
    elif change == 'inventory':
        m.factory.f_locals['sensitive_inventory'] = {}
    else:
        m.factory.f_locals['environment'] = {}
    with pytest.raises(RuntimeError):
        m.bind()
