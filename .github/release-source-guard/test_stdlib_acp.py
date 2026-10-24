"""Real stdlib ACP pipe/socket lifecycle and finite post-admission controls."""
from __future__ import annotations

import asyncio
import hashlib
import json
import os
from pathlib import Path
import sys

import pytest

from finite import mock_backend_setup as setup, stdlib_acp as domain
from test_stdlib_backend import ROOT, RUNNER


@pytest.mark.parametrize('case', sorted(setup.ACP_ISOLATED_CASES))
@pytest.mark.parametrize('change', [None, 'case', 'argv', 'registry', 'caller', 'bytes'])
def test_exact_previously_admitted_acp_translation(tmp_path, monkeypatch, case, change):
    root = tmp_path / 'source'
    fixture = root / setup.ACP
    fixture.parent.mkdir(parents=True)
    fixture.write_bytes((ROOT / setup.ACP).read_bytes())
    cwd = tmp_path / 'owned/worker'
    cwd.mkdir(parents=True)
    original = {'class': 'controlled-acp', 'python': True,
                'source_binding': {'path': str(fixture), 'line': 1, 'sha256': setup.ACP_PIN},
                'files': {str(fixture): setup.ACP_PIN}}
    state = {'case': case, 'commands': [original], 'checkout': str(root),
             'owned_root': str(cwd.parent), 'runtime': {'realpath': str(Path(sys.executable).resolve())}}
    argv = [state['runtime']['realpath'], str(fixture), '--controlled-local-acp-v1']
    registration = dict(original)
    binding = {'source': str(root / setup.SESSION), 'line': 553, 'function': '_open_role_owned'}
    if change == 'case':
        state['case'] += '-foreign'
    if change == 'argv':
        argv.append('--foreign')
    if change == 'registry':
        registration['python'] = False
    if change == 'caller':
        binding['line'] = 554
    if change == 'bytes':
        fixture.write_bytes(fixture.read_bytes() + b'\n')
    def support(actual, name):
        assert actual is state
        if name == 'mock_backend_setup.py':
            return vars(setup)
        assert name == 'fallback_binding.py'
        return {'matches': lambda *args: binding}
    monkeypatch.setattr(domain, 'support', support)
    def refuse(reason): raise RuntimeError(reason)
    if change in {'argv', 'registry', 'caller', 'bytes'}:
        with pytest.raises(RuntimeError, match='stdlib_acp_original_'):
            domain.resolve(registration, argv, cwd, {}, state, refuse)
    else:
        selected = domain.resolve(registration, argv, cwd, {}, state, refuse)
        assert selected == (None if change else ({**original, 'class': domain.CLASS, 'case': case},
                                                [argv[0], '-I', '-S', *argv[1:]]))


@pytest.mark.asyncio
async def test_original_acp_under_sealed_stdlib_domain(tmp_path):
    # This runs the unchanged actual fixture, including asyncio.run, stdin pipe,
    # both authenticated TCP channels, initialize/new/prompt/cancel and close.
    body = RUNNER.replace("payload={'target':str(source/domain.SCRIPT)}",
        "payload={'target':str(source/'tests/fixtures/controlled_python_acp.py')}")
    body = body.replace("state={'guard':", "state={'class':'source-canonical-stdlib-acp','guard':")
    body = body.replace("sys.argv=[payload['target'],'app-server']",
                        "sys.argv=[payload['target'],'--controlled-local-acp-v1']")
    script = tmp_path / 'acp-control.py'
    script.write_text(body)
    authenticated = set()
    errors = []
    methods = []
    prompt = asyncio.Event()
    async def lifetime(reader, writer):
        try:
            assert await reader.readline() == b'lifetime-nonce\n'
            authenticated.add('lifetime')
            assert await reader.read() == b''
        except Exception as error:
            errors.append(error)
        finally:
            writer.close()
            await writer.wait_closed()
    async def backend(reader, writer):
        try:
            assert await reader.readline() == b'bridge-nonce\n'
            authenticated.add('bridge')
            while line := await reader.readline():
                frame = json.loads(line)
                method = frame['method']
                methods.append(method)
                result = {'thread': {'id': 'local-thread'}} if method == 'thread/start' else {}
                writer.write((json.dumps({'id': frame['id'], 'result': result}) + '\n').encode())
                if method == 'turn/start':
                    prompt.set()
                if method == 'turn/interrupt':
                    writer.write((json.dumps({'method':'turn/completed', 'params': {
                        'threadId':'local-thread', 'turn':{'status':'completed','error':None}}})+'\n').encode())
                await writer.drain()
        except Exception as error:
            errors.append(error)
        finally:
            writer.close()
            await writer.wait_closed()
    life = await asyncio.start_server(lifetime, '127.0.0.1', 0)
    back = await asyncio.start_server(backend, '127.0.0.1', 0)
    environment = {**os.environ, 'SYNTHETIC_RELAY': json.dumps([
        back.sockets[0].getsockname()[1], 'bridge-nonce',
        life.sockets[0].getsockname()[1], 'lifetime-nonce'])}
    process = None
    try:
        process = await asyncio.create_subprocess_exec(sys.executable, '-I', '-S', str(script),
            str(ROOT), 'original', cwd=tmp_path, env=environment,
            stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
        async def send(identifier, method, params):
            process.stdin.write((json.dumps({'id':identifier,'method':method,'params':params})+'\n').encode())
            await process.stdin.drain()
        async def receive():
            line = await asyncio.wait_for(process.stdout.readline(), 10)
            if not line:
                raise AssertionError((await process.stderr.read()).decode())
            return json.loads(line)
        await send(1, 'initialize', {})
        assert (await receive())['result']['protocolVersion'] == 1
        await send(2, 'session/new', {'cwd':str(tmp_path),'mcpServers':[]})
        assert (await receive())['result'] == {'sessionId':'local-thread'}
        await send(3, 'session/prompt', {'sessionId':'local-thread','prompt':[{'text':'local'}]})
        await asyncio.wait_for(prompt.wait(), 5)
        await send(4, 'session/cancel', {'sessionId':'local-thread'})
        replies = [await receive(), await receive()]
        assert {r['id'] for r in replies} == {3,4}
        assert next(r for r in replies if r['id']==3)['result'] == {'stopReason':'end_turn'}
        process.stdin.close()
        await process.stdin.wait_closed()
        assert await asyncio.wait_for(process.wait(), 5) == 0, (await process.stderr.read()).decode()
        assert authenticated == {'bridge','lifetime'} and not errors
        assert methods == ['initialize','account/read','model/list','thread/start','turn/start','turn/interrupt']
    finally:
        if process is not None and process.returncode is None:
            process.kill()
            await process.wait()
        for server in (life,back):
            server.close()
            await server.wait_closed()


def test_exact_fixture_and_finite_case_roster():
    assert hashlib.sha256((ROOT / setup.ACP).read_bytes()).hexdigest() == setup.ACP_PIN
    assert len(setup.ACP_ISOLATED_CASES) == 6 and len(setup.REGISTRATION_CASES) == 4
    assert setup.ACP_ISOLATED_CASES - setup.REGISTRATION_CASES - setup.WITNESS_CASES == {
        'tests/test_experimental_startup_diagnostics.py::test_bridge_failure_preserved_through_owned_close[timeout]'}


@pytest.mark.parametrize(('mode', 'expected'), [
    ('path','import_path_drift'), ('exec','unknown_exec'), ('forged','payload_dispatch'),
    ('module','new_module'), ('new-module','new_module'), ('support','support_exec'),
    ('import','unsealed_import'), ('extension-import','unsealed_import'),
])
def test_acp_seal_rejects_foreign_execution(tmp_path, mode, expected):
    import subprocess
    body = RUNNER.replace("payload={'target':str(source/domain.SCRIPT)}",
        "payload={'target':str(source/'tests/fixtures/controlled_python_acp.py')}")
    body = body.replace("state={'guard':", "state={'class':'source-canonical-stdlib-acp','guard':")
    script = tmp_path / 'acp-negative.py'
    script.write_text(body)
    result = subprocess.run([sys.executable,'-I','-S',str(script),str(ROOT),mode],
        cwd=tmp_path,capture_output=True,text=True,timeout=15)
    assert result.returncode != 0
    assert 'stdlib_backend_' + expected in result.stderr


@pytest.mark.parametrize('case', sorted(setup.ACP_ISOLATED_CASES))
def test_acp_setup_exact_case_flags_and_binding(case):
    from test_mock_backend_setup import leaf_context
    state, endpoint, payload = leaf_context('controlled-acp')
    state['class'] = payload['class'] = domain.CLASS
    state['case'] = payload['case'] = case
    payload['orig_argv'][1:1] = ['-I','-S']
    payload['isolated'] = True
    assert setup.eligible(state,endpoint,payload)
    payload['orig_argv'].remove('-S')
    assert not setup.eligible(state,endpoint,payload)
    payload['orig_argv'].insert(2,'-S')
    state['case'] = payload['case'] = case+'-foreign'
    assert not setup.eligible(state,endpoint,payload)


def test_direct_post_admission_call_is_refused(monkeypatch):
    import finite.runtime_guard as guard
    monkeypatch.setitem(sys.modules, 'runtime_guard', guard)
    def refuse(reason): raise RuntimeError(reason)
    with pytest.raises(RuntimeError,match='post_admission_boundary'):
        domain.after_admission({},[],None,{}, {'commands':[]},None,refuse)


def test_registration_backend_additions_preserve_all_prior_rows():
    from finite import backend_postimage_catalog as catalog
    import primary_policy as policy
    assert setup.REGISTRATION_CASES == frozenset(policy.REGISTRATION_POSTIMAGE_CASES) == frozenset(policy.TEST_CONTROLLED_REGISTRATION_CASES)
    prior = {k:v for k,v in catalog.CASES.items() if k not in setup.REGISTRATION_CASES | setup.WITNESS_CASES}
    assert len(prior) == 149
    # Frozen current base manifest, rather than a new count-only acceptance.
    assert hashlib.sha256(json.dumps(prior,sort_keys=True,separators=(',',':')).encode()).hexdigest() == '229faa0b00d864d82d5ad5398c8a4ac1c477117d179fe72bf9235739b692b825'


@pytest.mark.parametrize('change', [None, 'line', 'code', 'argv'])
def test_actual_original_caller_binding_reaches_resolver(tmp_path,monkeypatch,change):
    import types
    from finite import fallback_binding, registry
    from unrest_harness import experimental_session as session
    original = next(row for row in registry.COMMANDS if row['class']=='controlled-acp')
    fixture = ROOT / setup.ACP
    registration = {**original,
        'argv':[str(fixture),'--controlled-local-acp-v1'],
        'source_binding':{**original['source_binding'],'path':str(fixture)},
        'files':{str(fixture):setup.ACP_PIN}}
    home = tmp_path / 'worker'
    home.mkdir()
    environment = {'SYNTHETIC_RELAY':'[1,"a",2,"b"]'}
    argv = [str(Path(sys.executable).resolve()),str(fixture),'--controlled-local-acp-v1']
    state = {'case':sorted(setup.ACP_ISOLATED_CASES)[0], 'commands':[registration],
        'checkout':str(ROOT),'owned_root':str(tmp_path),
        'product_pins':{setup.SESSION:setup.SESSION_PIN},
        'runtime':{'realpath':argv[0]}}
    def named(code,name):
        if code.co_name==name:
            return code
        for child in code.co_consts:
            if type(child) is types.CodeType:
                result=named(child,name)
                if result is not None:
                    return result
        return None
    state['isolated_named']=named
    frame = types.SimpleNamespace(f_code=session._SessionOwner._open_role_owned.__code__,
        f_globals=vars(session),f_lineno=553,
        f_locals={'adapter_argv':tuple(argv),'home':home,'environment':environment})
    if change=='line':
        frame.f_lineno=552
    if change=='code':
        frame.f_code=(lambda:None).__code__
    if change=='argv':
        frame.f_locals['adapter_argv']=(*argv,'foreign')
    monkeypatch.setattr(fallback_binding,'active_frames',lambda:[frame])
    monkeypatch.setitem(sys.modules,'runtime_guard',types.SimpleNamespace(append=lambda e:None))
    monkeypatch.chdir(ROOT)
    def support(actual,name):
        assert actual is state
        return vars(setup) if name=='mock_backend_setup.py' else vars(fallback_binding)
    monkeypatch.setattr(domain,'support',support)
    def refuse(reason):
        raise RuntimeError(reason)
    if change:
        with pytest.raises(RuntimeError,match='original_caller'):
            domain.resolve(registration,argv,home,environment,state,refuse)
    else:
        actual=fallback_binding.matches(registration,argv,home,environment,state)
        assert actual == {'source':str(ROOT/setup.SESSION),'line':553,
                          'function':'_open_role_owned','globals_module':session.__name__}
        result=domain.resolve(registration,argv,home,environment,state,refuse)
        assert result[0]['class']==domain.CLASS and result[1]==[argv[0],'-I','-S',*argv[1:]]
