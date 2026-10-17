"""One-shot startup configuration framing; controlled bytes only."""
import copy
import hashlib
import json

import pytest

from unrest_harness.experimental_lease import LeaseRefused
from unrest_harness.experimental_provider_config import ThreadObservation
from tests.test_experimental_admission_bounds import padded, wire

from tests.controlled_transport import controlled_transport

A = 262144
RESULT = {'config': {}, 'origins': {}, 'layers': [
    {'name': {'type': 'sessionFlags'}, 'config': {}, 'version': 'controlled'}]}


def observer(result=None, verify=lambda: None):
    obs = ThreadObservation()
    result = RESULT if result is None else result
    obs.seal_configuration(hashlib.sha256(json.dumps(result, sort_keys=True).encode()).hexdigest(),
                           '/role', verify)
    return obs


def request(identifier=1, **params):
    return wire({'id': identifier, 'method': 'config/read',
                 'params': {'includeLayers': True, 'cwd': '/role', **params}})


def deliver(obs, raw):
    complete = obs.restrict_backend(raw)
    obs.backend(complete)
    return complete


@pytest.mark.parametrize('length', [65536, 65537, 65538, A])
def test_exact_large_reply_fragmentation_and_original_bytes(length):
    obs = observer()
    obs.adapter(request())
    raw = padded(wire({'id': 1, 'result': RESULT}), length)
    assert deliver(obs, raw[:23]) == b''
    assert deliver(obs, raw[23:-1]) == b''
    assert deliver(obs, raw[-1:]) == raw
    assert obs._config_state == 'spent'
    with pytest.raises(LeaseRefused):
        obs.adapter(request(2))


@pytest.mark.parametrize('length', [A + 1, A + 2])
def test_exception_upper_bound(length):
    obs = observer()
    obs.adapter(request())
    with pytest.raises(LeaseRefused, match='protocol_bound'):
        deliver(obs, padded(wire({'id': 1, 'result': RESULT}), length))
    assert obs._config_state == 'spent'


@pytest.mark.parametrize('identifier', [True, 1.0, None, [], {}])
def test_invalid_request_id(identifier):
    obs = observer()
    with pytest.raises(LeaseRefused):
        obs.adapter(request(identifier))
    assert obs._config_state == 'spent'


@pytest.mark.parametrize('params', [{'includeLayers': False}, {'includeLayers': 1},
                                   {'cwd': '/other'}, {'extra': True}])
def test_exact_request_params(params):
    obs = observer()
    with pytest.raises(LeaseRefused):
        obs.adapter(request(**params))
    assert obs._config_state == 'spent'


@pytest.mark.parametrize('case', ['preseal', 'twice', 'pending-thread', 'post-thread', 'stop'])
def test_lifecycle_no_rearm(case):
    obs = ThreadObservation() if case == 'preseal' else observer()
    if case == 'twice':
        obs.adapter(request())
    elif case == 'pending-thread':
        obs.adapter(request())
        with pytest.raises(LeaseRefused):
            obs.adapter(wire({'id': 2, 'method': 'thread/start', 'params': {}}))
    elif case == 'post-thread':
        obs.adapter(wire({'id': 2, 'method': 'thread/start', 'params': {}}))
    elif case == 'stop':
        obs.stop()
    with pytest.raises(LeaseRefused):
        obs.adapter(request())
    with pytest.raises(LeaseRefused):
        obs.seal_configuration('different', '/role', lambda: None)


def test_small_terminal_consumes_and_duplicate_survives_thread_start():
    obs = observer()
    obs.adapter(request())
    deliver(obs, wire({'id': 1, 'result': RESULT}))
    obs.adapter(wire({'id': 2, 'method': 'thread/start', 'params': {}}))
    with pytest.raises(LeaseRefused, match='id_mismatch'):
        deliver(obs, wire({'id': 1, 'result': RESULT}))


@pytest.mark.parametrize('case', ['error', 'malformed', 'both', 'missing-config', 'missing-origins',
                                  'missing-layers', 'empty-layers', 'wrong-config', 'drift'])
def test_terminal_failures_consume(case):
    obs = observer()
    obs.adapter(request())
    result = copy.deepcopy(RESULT)
    frame = {'id': 1, 'result': result}
    if case in ('error', 'both'):
        frame['error'] = {'code': -1, 'message': 'PRIVATE_CONFIG_ERROR'}
        if case == 'error':
            del frame['result']
    elif case.startswith('missing-'):
        del result[case.removeprefix('missing-')]
    elif case == 'empty-layers':
        result['layers'] = []
    elif case == 'wrong-config':
        result['config'] = []
    elif case == 'drift':
        result['origins']['new'] = {'version': 'different'}
    with pytest.raises(LeaseRefused):
        deliver(obs, b'{broken}\n' if case == 'malformed' else wire(frame))
    assert obs._config_state == 'spent'
    with pytest.raises(LeaseRefused):
        obs.adapter(request(3))


def test_input_verification_and_immutable_copy(tmp_path):
    from tests.test_experimental_provider_config import configuration, effective_fixture
    config = configuration(tmp_path)
    role = tmp_path / 'campaign/role'
    result, requirements, account = effective_fixture(config, role)
    config.verify_effective(result, requirements, account, role)
    obs = ThreadObservation()
    obs.seal_configuration(config.effective_digests[str(role)], str(role), config.inputs.verify)
    config.effective_digests[str(role)] = 'rebaseline'
    obs.adapter(request(cwd=str(role)))
    assert deliver(obs, wire({'id': 1, 'result': result}))
    second = observer(verify=config.inputs.verify)
    second.adapter(request())
    (config.codex_home / 'config.toml').write_text('changed')
    with pytest.raises(LeaseRefused, match='common_inputs_changed'):
        deliver(second, wire({'id': 1, 'result': RESULT}))
    assert second._config_state == 'spent'


def test_strict_id_collisions_capacity_and_completed_reuse():
    obs = observer()
    def ordinary(i):
        return wire({'id': i, 'method': 'skills/list', 'params': {}})
    obs.adapter(ordinary('1'))
    obs.adapter(request(1))
    deliver(obs, wire({'id': '1', 'result': {}}))
    obs.adapter(ordinary('1'))
    with pytest.raises(LeaseRefused, match='id_mismatch'):
        obs.adapter(ordinary(1))
    for duplicate in (False, True):
        obs = observer()
        for i in range(32):
            obs.adapter(ordinary(i))
        assert len(obs._outstanding) == 32
        with pytest.raises(LeaseRefused, match='id_mismatch' if duplicate else 'protocol_bound'):
            obs.adapter(ordinary(31 if duplicate else 32))
    obs = observer()
    for i in range(100):
        obs.adapter(ordinary(i))
        deliver(obs, wire({'id': i, 'result': {}}))
    assert not obs._outstanding


@pytest.mark.parametrize('suffix', ['large-complete', 'large-fragment', 'duplicate', 'notification'])
def test_coalesced_suffix_sees_consumed_state(suffix):
    obs = observer()
    obs.adapter(request())
    tail = (wire({'id': 1, 'result': RESULT}) if suffix == 'duplicate' else
            padded(wire({'method': 'configWarning', 'params': {'summary': 'private'}}), 65538))
    if suffix == 'large-fragment':
        tail = tail[:-1]
    with pytest.raises(LeaseRefused):
        deliver(obs, wire({'id': 1, 'result': RESULT}) + tail)
    assert obs._config_state == 'spent'


@pytest.mark.parametrize('pending', [False, True])
@pytest.mark.parametrize('length', [65537, 65538])
def test_ordinary_runtime_newline_boundary(pending, length):
    obs = observer()
    if pending:
        obs.adapter(request())
    raw = padded(wire({'method': 'configWarning', 'params': {'summary': 'private'}}), length)
    if length == 65537:
        assert deliver(obs, raw) == raw
    else:
        with pytest.raises(LeaseRefused, match='protocol_bound'):
            deliver(obs, raw)


@pytest.mark.parametrize('mode', ['ready', 'drift', 'error', 'eof'])
async def test_pinned_adapter_large_private_and_adapter_replies(tmp_path, monkeypatch, capfd, mode):
    import asyncio
    import contextlib

    from unrest_harness import experimental_session as session
    from tests.test_experimental_startup_diagnostics import ADAPTER, FIXTURE, PROBE, config

    canary = 'PRIVATE_CONFIG_FRAME_CANARY'
    source = FIXTURE.read_text()
    injection = """        if method == 'config/read':
            result['config']['synthetic_padding'] = CANARY * 4096
            sys.stderr.write(CANARY * 20000)
            sys.stderr.flush()
            if not str(request['id']).startswith('unrest-preflight-'):
                if MODE == 'drift':
                    result['layers'][0]['version'] = 'drift'
                elif MODE == 'error':
                    emit({'id': request['id'], 'error': {'code': -1, 'message': CANARY}})
                    continue
                elif MODE == 'eof':
                    return
""".replace('CANARY', repr(canary)).replace('MODE', repr(mode))
    source = source.replace("        emit({'id': request['id'], 'result': result})",
                            injection + "        emit({'id': request['id'], 'result': result})")
    fixture = tmp_path / 'large_backend.py'
    fixture.write_text(source)
    monkeypatch.setattr(session, 'FIXTURE_SHA256', hashlib.sha256(fixture.read_bytes()).hexdigest())
    c = config(tmp_path)
    owners, processes, methods, sizes = [], [], [], []
    environment = session._SessionOwner._environment
    start = session._SessionOwner.start
    spawn = asyncio.create_subprocess_exec
    restrict = ThreadObservation.restrict_backend
    def env(self, home):
        return {**environment(self, home), 'CODEX_HOME': str(c.codex_home)}
    async def owner_start(self):
        owners.append(self)
        return await start(self)
    async def launch(*args, **kwargs):
        process = await spawn(*args, **kwargs)
        processes.append(process)
        if process.stdin is not None:
            original = process.stdin.write
            pending = bytearray()
            def write(raw):
                pending.extend(raw)
                while b'\n' in pending:
                    line, _, rest = pending.partition(b'\n')
                    pending[:] = rest
                    with contextlib.suppress(ValueError):
                        value = json.loads(line)
                        if isinstance(value, dict) and 'method' in value:
                            methods.append(value['method'])
                            assert value['method'] not in ('turn/start', 'session/prompt',
                                                           'thread/resume', 'thread/fork')
                return original(raw)
            process.stdin.write = write
        return process
    def restriction(self, raw):
        complete = restrict(self, raw)
        for line in complete.splitlines():
            if len(line) > 65536:
                sizes.append(len(line))
        return complete
    monkeypatch.setattr(session._SessionOwner, '_environment', env)
    monkeypatch.setattr(session._SessionOwner, 'start', owner_start)
    monkeypatch.setattr(asyncio, 'create_subprocess_exec', launch)
    monkeypatch.setattr(ThreadObservation, 'restrict_backend', restriction)
    result = await PROBE(tmp_path / 'probe', ADAPTER, None, trusted_process=True,
                         fixture=fixture, configuration=c, transport=controlled_transport())
    assert result['outcome'] == ('initialized' if mode == 'ready' else 'attention')
    assert result['owned_reaped'] and all(p.returncode is not None for p in processes)
    assert methods.count('config/read') == 2
    assert not {'turn/start', 'session/prompt', 'thread/resume', 'thread/fork'} & set(methods)
    owner = owners[0]
    assert owner.broker._active is None and owner.stopped
    assert owner.thread_observations['worker']._config_state == 'spent'
    if mode == 'ready':
        assert result['closed'] and result['effective_config_sha256']
        assert sizes and all(65536 < n < A for n in sizes)
        assert 'thread/start' in methods
    else:
        assert 'thread/start' not in methods
    diagnostic = result['owner_diagnostics']['pre_cleanup']['backends']['worker']
    assert diagnostic['stderr_bytes'] == 65536 and diagnostic['stderr_truncated']
    for path in (tmp_path / 'probe').rglob('*'):
        if path.is_file() and path != owner.backend_launcher:
            assert canary.encode() not in path.read_bytes()
    journal = [json.loads(line)['event'] for line in
               (tmp_path / 'probe/initialization-only.jsonl').read_text().splitlines()]
    assert not {'reserve', 'send', 'ack', 'uncertain'} & set(journal)
    assert canary not in json.dumps(result)
    captured = capfd.readouterr()
    assert canary not in captured.out + captured.err


@pytest.mark.parametrize('identifier', [True, 1.0, None, '1', 2])
def test_backend_id_alias_or_mismatch_refuses(identifier):
    obs = observer()
    obs.adapter(request(1))
    with pytest.raises(LeaseRefused):
        deliver(obs, wire({'id': identifier, 'result': RESULT}))
    assert obs._config_state == 'spent'


@pytest.mark.parametrize('ending', ['eof', 'cancel'])
async def test_bridge_retirement_on_eof_and_cancellation(ending):
    import asyncio
    from unrest_harness.experimental_relay import Bridge
    from tests.test_experimental_provider_config import stream_pair, close_streams
    obs = observer()
    obs.adapter(request())
    (reader, peer), (_, writer) = await stream_pair()
    bridge = Bridge(reader, writer, obs.stop)
    task = asyncio.create_task(bridge._pump(reader, writer, obs.backend, obs.restrict_backend))
    try:
        await asyncio.sleep(0)
        if ending == 'eof':
            peer.close()
        else:
            task.cancel()
        await asyncio.gather(task, return_exceptions=True)
        assert obs._config_state == 'spent'
        with pytest.raises(LeaseRefused):
            obs.adapter(request(2))
    finally:
        task.cancel()
        await asyncio.gather(task, return_exceptions=True)
        await close_streams(peer, writer)


@pytest.mark.parametrize('length,limit,expected', [
    (180000, A - 1, None), (A, A - 1, 'aggregate_bound'),
    (A + 1, A - 1, 'reader_limit'), (A + 1, A * 2, 'frame_bound'),
])
async def test_private_config_frame_bound_and_shared_total(tmp_path, length, limit, expected):
    import asyncio
    from unrest_harness.experimental_diagnostics import startup_timeout
    from tests.test_experimental_admission_bounds import Writer
    from tests.test_experimental_provider_config import configuration, effective_fixture
    config = configuration(tmp_path)
    role = tmp_path / 'campaign/role'
    results = effective_fixture(config, role)
    ar, br = asyncio.StreamReader(), asyncio.StreamReader(limit=limit)
    aw, bw = Writer(), Writer()
    ar.feed_data(wire({'id': 1, 'method': 'initialize', 'params': {}}))
    br.feed_data(wire({'id': 1, 'result': {}}))
    for method, result in zip(('config/read', 'configRequirements/read', 'account/read'), results):
        raw = wire({'id': 'unrest-preflight-' + method, 'result': result})
        br.feed_data(padded(raw, length) if method == 'config/read' else raw)
    async with startup_timeout(2, 'owner_launch'):
        if expected:
            with pytest.raises(LeaseRefused, match='provider_configuration_' + expected):
                await config.admit_bridge(ar, aw, br, bw, role)
            assert not aw.frames
        else:
            await config.admit_bridge(ar, aw, br, bw, role)
            assert len(aw.frames) == 1
            assert config.effective_digests[str(role)]
