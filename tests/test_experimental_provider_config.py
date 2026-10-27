"""No real backend launches: pinned config construction and controlled wire checks."""
import hashlib
import json
from pathlib import Path
import shutil
import runpy

import pytest

from unrest_harness.experimental_lease import LeaseRefused
from unrest_harness.experimental_provider_config import CATALOGUE, CATALOGUE_SHA256, ProviderConfig


from tests.controlled_transport import controlled_transport

ORACLE = runpy.run_path(str(Path(__file__).parent / 'fixtures/experimental_session_app_server.py'))

def configuration(tmp_path):
    home = tmp_path / 'subscription'
    home.mkdir()
    names = ['external.with.dots', 'ordinary', 'quote"and\\slash', 'λ😀']
    (home / 'config.toml').write_text('\n'.join(
        '[mcp_servers.' + json.dumps(name, ensure_ascii=False) + ']\n'
        'command="CANARY_PRIVATE"\nenv={UNCHANGED="synthetic"}' for name in names))
    (home / 'AGENTS.md').write_text('COMMON_INSTRUCTION_CANARY')
    (home / 'auth.json').write_text('NEVER_READ_AUTH_BODY')
    (tmp_path / 'campaign').mkdir()
    config = ProviderConfig(codex_home=home, user_home=tmp_path / 'user',
                            cwd=tmp_path / 'campaign', ambient={}, system=tmp_path / 'system')
    return config


def test_actual_startup_overrides_full_catalogue_and_private_role_paths(tmp_path):
    config = configuration(tmp_path)
    first, second = tmp_path / 'campaign/worker', tmp_path / 'campaign/validator'
    argv = config.argv(Path('/frozen/bin/codex'), first)
    assert argv[0] == '/frozen/bin/codex' and argv[-1] == 'app-server'
    assert all(argv[i] == '-c' for i in range(1, len(argv) - 1, 2))
    parsed = ORACLE['cli_layer'](argv[2:-1:2])
    assert parsed == config.thread_config(first)
    assert parsed['sqlite_home'] == str(first / 'sqlite')
    assert parsed['log_dir'] == str(first / 'logs')
    assert config.thread_config(second)['sqlite_home'] != parsed['sqlite_home']
    assert parsed['mcp_servers']['external.with.dots']['enabled'] is False
    assert parsed['features']['context_management'] is False
    assert parsed['features']['external_agent_memory_import'] is False
    assert parsed['history']['persistence'] == 'none'
    assert parsed['skills']['bundled']['enabled'] is False
    raw = CATALOGUE.read_bytes()
    assert hashlib.sha256(raw).hexdigest() == CATALOGUE_SHA256
    models = json.loads(raw)['models']
    assert len(models) > 10 and any(m['slug'] == 'gpt-6-astra' for m in models)
    evidence = json.dumps(config.evidence(first))
    assert config.evidence(first)['global_instruction_selection'] == 'default'
    assert not any(value in evidence for value in ('CANARY', 'NEVER_READ', 'external.with.dots'))
    # The authentication file is excluded from context and is not read by the seal.
    (config.codex_home / 'auth.json').unlink()
    (config.codex_home / 'auth.json').mkdir()
    config.inputs.verify()


@pytest.mark.parametrize('change', ['global-override', 'config', 'skill', 'rule'])
def test_common_context_membership_and_absence_are_sealed(tmp_path, change):
    config = configuration(tmp_path)
    if change == 'global-override':
        (config.codex_home / 'AGENTS.override.md').write_text('changed')
    elif change == 'config':
        (config.codex_home / 'config.toml').write_text('model="changed"')
    else:
        root = config.codex_home / ('skills' if change == 'skill' else 'rules')
        root.mkdir()
        (root / 'new').write_text('changed')
    with pytest.raises(LeaseRefused, match='common_inputs_changed'):
        config.argv(Path('/backend'), tmp_path / 'campaign/role')


@pytest.mark.parametrize('attack', ['coerced-flag', 'server', 'managed', 'layer', 'auth', 'account-change'])
def test_effective_configuration_and_account_negatives(tmp_path, attack):
    config = configuration(tmp_path)
    role = tmp_path / 'campaign/role'
    response = {'config': config.thread_config(role), 'layers': [
        {'name': {'type': 'sessionFlags'}, 'config': {}, 'version': 'controlled'}]}
    requirements = ORACLE['requirements'](response['config'])
    account = {'account': {'type': 'chatgpt', 'id': 'one'}}
    config.verify_effective(response, requirements, account, role)
    if attack == 'coerced-flag':
        response['config']['features']['shell_tool'] = 0
    elif attack == 'server':
        response['config']['mcp_servers']['surprise'] = {'enabled': True}
    elif attack == 'managed':
        requirements['requirements'] = {'unknown': True}
    elif attack == 'layer':
        response['layers'].append({'name': {'type': 'enterpriseManaged'}, 'config': {}})
    elif attack == 'auth':
        account['account']['type'] = 'apiKey'
    else:
        account['account']['id'] = 'different'
    with pytest.raises(LeaseRefused):
        config.verify_effective(response, requirements, account, role)


@pytest.mark.parametrize('inject_context', [False, True])
@pytest.mark.parametrize('with_skills', [False, True])
async def test_startup_and_thread_controls_through_actual_owned_adapter(tmp_path, inject_context, with_skills, monkeypatch):
    from unrest_harness.capability_policy import SAFE_PROFILE, load_capability_policy, resolve_role_capability
    from unrest_harness.experimental_session import _SessionOwner
    from unrest_harness.providers import PROVIDERS
    config = configuration(tmp_path)
    if with_skills:
        skill = config.codex_home / 'skills/example/SKILL.md'
        skill.parent.mkdir(parents=True)
        skill.write_text('synthetic skill')
        config = ProviderConfig(codex_home=config.codex_home, user_home=tmp_path / 'user',
                                cwd=tmp_path / 'campaign', ambient={}, system=tmp_path / 'system')
    candidate = tmp_path / 'candidate'
    candidate.mkdir()
    (candidate / 'a').write_text('base\n')
    policy = resolve_role_capability(PROVIDERS['codex'], role='worker',
        policy=load_capability_policy(Path(__file__).resolve().parents[1] / 'src/unrest_harness/bundled'),
        profile=SAFE_PROFILE, workspace=candidate, project_record=tmp_path)
    owner = _SessionOwner(tmp_path / 'campaign/owner', candidate, ('a',),
        adapter=Path(shutil.which('codex-acp') or '/missing').resolve(),
        fixture=Path(__file__).parent / 'fixtures/experimental_session_app_server.py',
        policy=policy, provider_config=config, transport=controlled_transport())
    original_environment = owner._environment
    def environment(home):
        value = original_environment(home)
        value['CODEX_HOME'] = str(config.codex_home)
        return value
    monkeypatch.setattr(owner, '_environment', environment)
    try:
        await owner.start('P2')
        result = await owner.turn('worker')
        assert result.disposition == 'sealed'
        assert str(owner.root / 'worker') in config.effective_digests
        assert config.account_digest is not None
        assert owner.thread_observations['worker'].session == result.identity.session
        assert owner.thread_observations['worker'].served == {
            'model': 'gpt-6-astra', 'reasoningEffort': 'medium', 'modelProvider': 'openai'}
        assert owner._environment(owner.root / 'worker')['TMPDIR'] == str(owner.root / 'worker/tmp')
        if inject_context:
            (owner.root / 'worker/.agents').mkdir()
            with pytest.raises(LeaseRefused, match='quarantined'):
                await owner.turn('validator')
            assert owner.stopped
            assert 'validator' not in owner.backends
        else:
            failure = await owner.turn('validator', disposition='reproducible_product_defect')
            correction = await owner.turn('worker')
            recheck = await owner.turn('validator')
            assert correction.identity.session == result.identity.session
            assert recheck.identity.session == failure.identity.session
            assert correction.identity.process_generation == result.identity.process_generation
            assert (candidate / 'a').read_text() == 'corrected\n'
            assert recheck.disposition == 'pass'
    finally:
        if inject_context:
            with pytest.raises(LeaseRefused, match='quarantined'):
                await owner.close()
        else:
            await owner.close()
    assert all(backend.process.returncode is not None for backend in owner.backends.values())


@pytest.mark.parametrize('injection', ['.agents/skills', '.AGENTS/skills', '.codex/skills',
                                    '.CODEX/skills', 'config.toml', 'CONFIG.TOML', 'link'])
def test_runtime_context_absence_is_part_of_common_seal(tmp_path, injection):
    config = configuration(tmp_path)
    role = tmp_path / 'campaign/turn-1/worker'
    role.mkdir(parents=True)
    for name in ('sqlite', 'logs', 'tmp'):
        (role / name).mkdir()
        (role / name / 'ordinary').write_text('runtime data')
    config.inputs.verify()
    config.argv(Path('/not-launched'), role)
    if injection == 'link':
        (role / 'linked-context').symlink_to(tmp_path / 'subscription', target_is_directory=True)
    elif injection.casefold() == 'config.toml':
        (role / injection).write_text('model="other"')
    else:
        (role / injection).mkdir(parents=True)
    with pytest.raises(LeaseRefused, match='undeclared_provider_runtime_context'):
        config.inputs.verify()
    with pytest.raises(LeaseRefused, match='undeclared_provider_runtime_context'):
        config.argv(Path('/not-launched'), role)


def test_role_cannot_escape_declared_runtime_context(tmp_path):
    config = configuration(tmp_path)
    with pytest.raises(LeaseRefused, match='outside_declared_runtime'):
        config.argv(Path('/not-launched'), tmp_path / 'elsewhere')


@pytest.mark.parametrize('name', ['AUTH.JSON', 'Auth.Json.Bak', 'Credentials.JSON'])
def test_credential_name_aliases_refuse_before_open(tmp_path, monkeypatch, name):
    import os
    from unrest_harness.experimental_provider_config import CommonInputs
    path = tmp_path / name
    path.write_text('UNREAD_CREDENTIAL_CANARY')
    def forbidden_open(*args, **kwargs):
        raise AssertionError('credential body must not be opened')
    monkeypatch.setattr(os, 'open', forbidden_open)
    with pytest.raises(LeaseRefused, match='authentication_store_not_context'):
        CommonInputs((path,))


@pytest.mark.parametrize('attack', ['missing-effort', 'wrong-model', 'wrong-provider',
                                  'cross-thread', 'resume', 'fork', 'extra-thread', 'account-change'])
def test_observed_thread_and_served_identity_fail_closed(attack):
    from unrest_harness.experimental_provider_config import ThreadObservation
    observer = ThreadObservation()
    start = (json.dumps({'id': 7, 'method': 'thread/start', 'params': {}}) + '\n').encode()
    observer.adapter(start[:10])
    observer.adapter(start[10:])
    result = {'thread': {'id': 'exact'}, 'model': 'gpt-6-astra',
              'reasoningEffort': 'medium', 'modelProvider': 'openai'}
    if attack in ('missing-effort', 'wrong-model', 'wrong-provider'):
        if attack == 'missing-effort':
            del result['reasoningEffort']
        else:
            result['model' if attack == 'wrong-model' else 'modelProvider'] = 'other'
        with pytest.raises(LeaseRefused, match='served_model_mismatch'):
            observer.backend((json.dumps({'id': 7, 'result': result}) + '\n').encode())
        assert observer.served is None
        return
    observer.backend((json.dumps({'id': 7, 'result': result}) + '\n').encode())
    frame = {'method': {'cross-thread': 'turn/start', 'resume': 'thread/resume',
                       'fork': 'thread/fork', 'extra-thread': 'thread/start',
                       'account-change': 'account/updated'}[attack],
             'id': 8, 'params': {'threadId': 'wrong'}}
    with pytest.raises(LeaseRefused):
        (observer.backend if attack == 'account-change' else observer.adapter)(
            (json.dumps(frame) + '\n').encode())


def test_turn_restriction_only_tightens_approval_and_preserves_other_fields():
    from unrest_harness.experimental_provider_config import ThreadObservation
    observer = ThreadObservation()
    other = b'{"id":4,"method":"model/list","params":{}}\n'
    assert observer.restrict_adapter(other) == other
    frame = {'id': 5, 'method': 'turn/start', 'params': {
        'approvalPolicy': 'on-request', 'sandboxPolicy': {'type': 'readOnly', 'networkAccess': False},
        'threadId': 'exact', 'input': [{'type': 'text', 'text': 'PRIVATE_CANARY_λ'}]}}
    raw = (json.dumps(frame) + '\n').encode()
    assert observer.restrict_adapter(raw[:8]) == b''
    actual = json.loads(observer.restrict_adapter(raw[8:]))
    frame['params']['approvalPolicy'] = 'never'
    assert actual == frame
    frame['params']['sandboxPolicy']['type'] = 'dangerFullAccess'
    with pytest.raises(LeaseRefused, match='permissions_changed'):
        observer.restrict_adapter((json.dumps(frame) + '\n').encode())


def test_literal_cli_parser_and_recursive_layers_have_independent_oracle(tmp_path):
    names = ['ordinary', 'with.dots', 'quote"and\\slash', 'λ😀', 'second']
    home = tmp_path / 'home'
    home.mkdir()
    inherited = {'mcp_servers': {name: {'command': 'local-fixture', 'enabled': True,
                                      'env': {'UNCHANGED': 'synthetic'}} for name in names}}
    # JSON strings are valid TOML basic keys for these controlled names.
    (home / 'config.toml').write_text('\n'.join(
        '[mcp_servers.' + json.dumps(name, ensure_ascii=False) + ']\n'
        'command="local-fixture"\nenabled=true\nenv={UNCHANGED="synthetic"}' for name in names))
    config = ProviderConfig(codex_home=home, user_home=tmp_path / 'user',
                            cwd=tmp_path / 'runtime', ambient={}, system=tmp_path / 'system')
    role = tmp_path / 'runtime/worker'
    overrides = config.argv(Path('/unused'), role)[2:-1:2]
    assert sum(item.startswith('mcp_servers=') for item in overrides) == 1
    assert not any(item.startswith('mcp_servers.') for item in overrides)
    cli = ORACLE['cli_layer'](overrides)
    assert cli['mcp_servers'] == {name: {'enabled': False} for name in names}
    assert cli == config.thread_config(role)
    ORACLE['merge'](inherited, cli)
    assert inherited['mcp_servers'] == {name: {'command': 'local-fixture', 'enabled': False,
                                               'env': {'UNCHANGED': 'synthetic'}} for name in names}
    assert ORACLE['cli_layer'](['mcp_servers={a={enabled=false}}',
                                'mcp_servers={b={enabled=false}}']) == {
                                    'mcp_servers': {'b': {'enabled': False}}}
    assert ORACLE['cli_layer'](['mcp_servers."a.b".enabled=false']) == {
        'mcp_servers': {'"a': {'b"': {'enabled': False}}}}
    assert ORACLE['cli_layer']([' x = unquoted=value ', 'a=1', 'a.b=false']) == {
        'x': 'unquoted=value', 'a': {'b': False}}


def effective_fixture(config, role):
    # Independent provider-shaped response: CLI RHS parser, layer merge and
    # typed serialization; no product comparison or parsing helpers.
    flags = ORACLE['cli_layer'](config.argv(Path('/unused'), role)[2:-1:2])
    import tomllib
    inherited = tomllib.loads((config.codex_home / 'config.toml').read_text())
    ORACLE['merge'](inherited, flags)
    return {'config': ORACLE['typed_config'](inherited), 'origins': {}, 'layers': [
        {'name': {'type': 'sessionFlags'}, 'version': 'controlled', 'config': flags},
        {'name': {'type': 'user', 'file': str(config.codex_home / 'config.toml'), 'profile': None},
         'version': 'controlled', 'config': {}}]}, ORACLE['requirements'](flags), {
             'account': {'type': 'chatgpt', 'email': 'controlled@example.invalid', 'planType': 'plus'},
             'requiresOpenaiAuth': False}


@pytest.mark.parametrize('name', ['requirements.toml', 'managed_config.toml'])
@pytest.mark.parametrize('body', ['', 'mcp_servers={unprojected={enabled=true}}'])
def test_unprojected_local_policy_is_not_proven_absent_by_requirements_api(tmp_path, name, body):
    system = tmp_path / 'system'
    system.mkdir()
    (system / name).write_text(body)
    with pytest.raises(LeaseRefused, match='managed_requirements_unresolved'):
        configuration(tmp_path)


@pytest.mark.parametrize('field', sorted(ORACLE['requirements']({'forced_login_method': 'chatgpt'})['requirements']))
@pytest.mark.parametrize('mutation', ['missing', 'unsupported'])
def test_exact_projected_requirements_schema(tmp_path, field, mutation):
    config = configuration(tmp_path)
    role = tmp_path / 'campaign/role'
    effective, requirements, account = effective_fixture(config, role)
    config.verify_effective(effective, requirements, account, role)
    if mutation == 'missing':
        del requirements['requirements'][field]
    else:
        requirements['requirements'][field] = False
    with pytest.raises(LeaseRefused, match='managed_requirements_unresolved'):
        config.verify_effective(effective, requirements, account, role)


async def stream_pair():
    import asyncio
    import socket
    first, second = socket.socketpair()
    return await asyncio.open_connection(sock=first), await asyncio.open_connection(sock=second)


async def close_streams(*writers):
    import asyncio
    for writer in writers:
        writer.close()
    await asyncio.gather(*(writer.wait_closed() for writer in writers), return_exceptions=True)


# Each case traverses the real admission function over actual stream transports.
WIRE_ATTACKS = [
    'bool-id', 'float-id', 'null-id', 'array-id', 'wrong-id', 'string-id', 'both-result-error',
    'method-result', 'missing-result', 'extra-envelope', 'duplicate-id', 'invalid-json',
    'oversize', 'unterminated', 'frame-overflow', 'byte-overflow', 'stall',
    'unknown-notification', 'notification-id', 'notification-params', 'notification-auth',
    'notification-plan', 'unknown-layer', 'wrong-layer-file', 'extra-layer-field',
    'missing-version', 'null-disabled-reason', 'selected-profile', 'mdm', 'enterprise',
    'legacy', 'packaged', 'requirements-null', 'requirements-unknown', 'requirements-value',
    'skills-null', 'skills-missing-nonempty', 'skills-coerced-nonempty', 'coerced-control', 'extra-server',
    'config-response-id', 'config-response-both', 'account-change',
]


@pytest.mark.parametrize('attack', ['none', 'notification-before-initialize', *WIRE_ATTACKS])
async def test_controlled_preflight_wire_accepts_only_supported_startup(tmp_path, attack):
    import asyncio
    import copy
    import time
    config = configuration(tmp_path)
    if attack in ('skills-missing-nonempty', 'skills-coerced-nonempty'):
        skill = config.codex_home / 'skills/a/SKILL.md'
        skill.parent.mkdir(parents=True)
        skill.write_text('synthetic skill')
        config = ProviderConfig(codex_home=config.codex_home, user_home=tmp_path / 'user',
                                cwd=tmp_path / 'campaign', ambient={}, system=tmp_path / 'system')
    role = tmp_path / 'campaign/role'
    effective, requirements, account = effective_fixture(config, role)
    if attack == 'unknown-layer':
        effective['layers'][1]['name']['type'] = 'unknown'
    elif attack == 'wrong-layer-file':
        effective['layers'][1]['name']['file'] = str(tmp_path / 'other')
    elif attack == 'extra-layer-field':
        effective['layers'][0]['name']['file'] = str(config.codex_home / 'config.toml')
    elif attack == 'missing-version':
        del effective['layers'][0]['version']
    elif attack == 'null-disabled-reason':
        effective['layers'][0]['disabledReason'] = None
    elif attack == 'selected-profile':
        effective['layers'][1]['name']['profile'] = 'unresolved'
    elif attack in ('mdm', 'enterprise', 'legacy', 'packaged'):
        effective['layers'][1]['name'] = {
            'mdm': {'type': 'mdm', 'domain': 'test', 'key': 'test'},
            'enterprise': {'type': 'enterpriseManaged', 'id': 'test', 'name': 'test'},
            'legacy': {'type': 'legacyManagedConfigTomlFromFile',
                       'file': str(config.codex_home / 'config.toml')},
            'packaged': {'type': 'packagedDefaults', 'file': str(config.codex_home / 'config.toml')},
        }[attack]
    elif attack == 'requirements-null':
        requirements['requirements'] = None
    elif attack == 'requirements-unknown':
        requirements['requirements']['unknown'] = None
    elif attack == 'requirements-value':
        requirements['requirements']['allowLoginShell'] = 0
    elif attack == 'skills-null':
        effective['config']['skills']['config'] = None
    elif attack == 'skills-missing-nonempty':
        del effective['config']['skills']['config']
    elif attack == 'skills-coerced-nonempty':
        effective['config']['skills']['config'][0]['enabled'] = 0
    elif attack == 'coerced-control':
        effective['config']['features']['shell_tool'] = 0
    elif attack == 'extra-server':
        effective['config']['mcp_servers']['unexpected'] = {'enabled': False}
    elif attack == 'account-change':
        config.account_digest = 'previous-account-digest'
    notification = {'method': 'account/updated', 'params': {'authMode': 'chatgpt', 'planType': 'plus'}}
    if attack == 'unknown-notification':
        notification['method'] = 'unknown'
    elif attack == 'notification-id':
        notification['id'] = 4
    elif attack == 'notification-params':
        notification['params']['extra'] = None
    elif attack == 'notification-auth':
        notification['params']['authMode'] = 'apiKey'
    elif attack == 'notification-plan':
        notification['params']['planType'] = 'unsupported'
    def encoded(frame):
        return (json.dumps(frame, ensure_ascii=False) + '\n').encode()
    (adapter_reader, adapter_writer), (client_reader, client_writer) = await stream_pair()
    (backend_reader, backend_writer), (server_reader, server_writer) = await stream_pair()
    observed = []
    original = b'{"id":1,"method":"initialize","params":{"clientInfo":{"name":"controlled"}}}\n'
    init_response = {'id': 1, 'result': {'userAgent': 'controlled'}}
    reply = copy.deepcopy(init_response)
    if attack in ('bool-id', 'float-id', 'null-id', 'array-id', 'wrong-id', 'string-id'):
        reply['id'] = {'bool-id': True, 'float-id': 1.0, 'null-id': None,
                       'array-id': [], 'wrong-id': 2, 'string-id': '1'}[attack]
    elif attack == 'both-result-error':
        reply['error'] = {'code': -1, 'message': 'synthetic'}
    elif attack == 'method-result':
        reply['method'] = 'unexpected'
    elif attack == 'missing-result':
        del reply['result']
    elif attack == 'extra-envelope':
        reply['unsupported'] = 1

    async def backend():
        assert await server_reader.readline() == original
        observed.append('initialize')
        if attack == 'stall':
            await asyncio.Event().wait()
            return
        if attack == 'duplicate-id':
            server_writer.write(b'{"id":1,"id":1,"result":{}}\n')
        elif attack == 'invalid-json':
            server_writer.write(b'not-json\n')
        elif attack == 'oversize':
            server_writer.write(b' ' * 65537 + b'\n')
        elif attack == 'unterminated':
            server_writer.write(b'{"id":1,"result":{}}')
            server_writer.write_eof()
        else:
            if attack == 'notification-before-initialize':
                server_writer.write(encoded(notification))
            server_writer.write(encoded(reply))
        await server_writer.drain()
        for method, result in [('config/read', effective), ('configRequirements/read', requirements),
                               ('account/read', account)]:
            raw = await server_reader.readline()
            if not raw:
                return
            request = json.loads(raw)
            observed.append(request['method'])
            assert request['method'] == method
            if method == 'config/read':
                if attack == 'byte-overflow':
                    # Valid JSON frames, each below the per-frame bound.
                    result['padding'] = 'x' * 60000
                count = 40 if attack == 'frame-overflow' else 1
                for _ in range(count):
                    server_writer.write(encoded(notification))
            if attack == 'byte-overflow':
                result = {**result, 'padding': 'x' * 60000}
                # Four responses plus a large initialize reply exceed total cap
                # only with another valid, bounded notification frame.
                for _ in range(2):
                    server_writer.write(encoded({'method': 'configWarning', 'params': {
                        'summary': 'x' * 60000}}))
            response = {'id': request['id'], 'result': result}
            if method == 'config/read' and attack == 'config-response-id':
                response['id'] = 'other'
            if method == 'config/read' and attack == 'config-response-both':
                response['error'] = {'code': -1, 'message': 'synthetic'}
            server_writer.write(encoded(response))
            await server_writer.drain()

    from unrest_harness.experimental_relay import Bridge
    from unrest_harness.experimental_diagnostics import startup_timeout
    async def admit(reader, writer):
        async with startup_timeout(.2 if attack == 'stall' else 5, 'owner_launch'):
            await config.admit_bridge(reader, writer, backend_reader, backend_writer, role)
    bridge = Bridge(backend_reader, backend_writer, lambda: None, admit=admit)
    bridge_task = asyncio.create_task(bridge.attach(adapter_reader, adapter_writer))
    task = asyncio.create_task(backend())
    start = time.monotonic()
    try:
        client_writer.write((bridge.nonce + '\n').encode() + original)
        await client_writer.drain()
        if attack in ('none', 'notification-before-initialize'):
            await asyncio.wait_for(bridge.connected.wait(), 5.5)
            wanted = ([encoded(notification)] if attack == 'notification-before-initialize' else [])
            wanted += [encoded(init_response), encoded(notification)]
            assert await client_reader.readexactly(sum(map(len, wanted))) == b''.join(wanted)
            assert observed == ['initialize', 'config/read', 'configRequirements/read', 'account/read']
        else:
            if attack == 'stall':
                await bridge_task  # Bridge handles the bounded timeout by closing.
            else:
                with pytest.raises(LeaseRefused) as refusal:
                    await bridge_task
                if attack in ('frame-overflow', 'byte-overflow', 'oversize'):
                    assert str(refusal.value) == {
                        'frame-overflow': 'provider_configuration_frame_count_bound',
                        'byte-overflow': 'provider_configuration_aggregate_bound',
                        'oversize': 'provider_configuration_reader_limit',
                    }[attack]
            assert not bridge.connected.is_set()
            adapter_writer.close()
            assert await client_reader.read() == b''
            assert 'thread/start' not in observed and 'turn/start' not in observed
        if attack == 'stall':
            assert .2 <= time.monotonic() - start < 2
            assert not config.effective_digests
        else:
            assert time.monotonic() - start < 5.8
    finally:
        task.cancel()
        bridge_task.cancel()
        await asyncio.gather(task, bridge_task, return_exceptions=True)
        await close_streams(adapter_writer, client_writer, backend_writer, server_writer)


@pytest.mark.parametrize('attack', ['bool-id', 'float-id', 'null-id', 'both', 'extra-envelope',
                                  'thread-control', 'thread-list-control', 'broker-control',
                                  'sandbox-int', 'sandbox-float', 'approval-bool'])
async def test_strict_thread_and_permission_boundary_through_relay_pump(attack):
    from unrest_harness.experimental_provider_config import ThreadObservation
    from unrest_harness.experimental_relay import pump
    controls = {'features': {'shell_tool': False}, 'skills': {'config': [{'enabled': False}]}}
    broker = {'url': 'http://127.0.0.1:1/mcp', 'enabled': True}
    observer = ThreadObservation(controls, broker)
    start = {'id': 1, 'method': 'thread/start', 'params': {'config': {
        **controls, 'mcp_servers': {'unrest_turn_broker': broker}}}}
    response = {'id': 1, 'result': {'thread': {'id': 'exact'}, 'model': 'gpt-6-astra',
                                   'reasoningEffort': 'medium', 'modelProvider': 'openai'}}
    def wire(value):
        return (json.dumps(value) + '\n').encode()
    # Deep copy keeps expected controls independent of the hostile wire values.
    start = json.loads(json.dumps(start))
    frame = response
    observe, restrict = observer.backend, None
    if attack in ('thread-control', 'thread-list-control', 'broker-control'):
        frame, observe = start, observer.adapter
        if attack == 'thread-control':
            start['params']['config']['features']['shell_tool'] = 0
        elif attack == 'thread-list-control':
            start['params']['config']['skills']['config'][0]['enabled'] = 0.0
        else:
            start['params']['config']['mcp_servers']['unrest_turn_broker']['enabled'] = 1
    else:
        observer.adapter(wire(start))
        if attack in ('bool-id', 'float-id', 'null-id'):
            frame['id'] = {'bool-id': True, 'float-id': 1.0, 'null-id': None}[attack]
        elif attack == 'both':
            frame['error'] = {'code': -1, 'message': 'synthetic'}
        elif attack == 'extra-envelope':
            frame['extra'] = None
        else:
            observer.backend(wire(response))
            frame = {'id': 2, 'method': 'turn/start', 'params': {'threadId': 'exact',
                'approvalPolicy': True if attack == 'approval-bool' else 'on-request',
                'sandboxPolicy': {'type': 'readOnly', 'networkAccess':
                                  0.0 if attack == 'sandbox-float' else 0}}}
            observe, restrict = observer.adapter, observer.restrict_adapter
    (reader, input_writer), (input_reader, writer) = await stream_pair()
    (output_reader, peer), (_, output_writer) = await stream_pair()
    try:
        writer.write(wire(frame))
        await writer.drain()
        with pytest.raises(LeaseRefused):
            await pump(reader, output_writer, lambda: None, observe, restrict)
        output_writer.close()
        assert await output_reader.read() == b''
        if observe == observer.backend:
            assert observer.session is None
    finally:
        await close_streams(input_writer, writer, peer, output_writer)


def test_never_rewrite_preserves_unrelated_wire_bytes():
    from unrest_harness.experimental_provider_config import ThreadObservation
    raw = (b' { "id": 9, "method": "turn/start", "params": { "approvalPolicy" : "on-request", '
           b'"sandboxPolicy":{"type":"readOnly","networkAccess":false}, '
           b'"input":[{"text":"on-request \\u03bb"}], "threadId":"exact" } }\n')
    expected = raw.replace(b'"approvalPolicy" : "on-request"', b'"approvalPolicy" : "never"')
    observer = ThreadObservation()
    assert observer.restrict_adapter(raw) == expected
    assert observer.restrict_adapter(expected) == expected


@pytest.mark.parametrize('kind', ['system', 'project', 'user'])
async def test_supported_file_layer_shapes_including_absent_files(tmp_path, kind):
    config = configuration(tmp_path)
    role = tmp_path / 'campaign/role'
    effective, requirements, account = effective_fixture(config, role)
    path = sorted(config.layer_files[kind])[-1]
    source = ({'type': kind, 'dotCodexFolder': str(path.parent)} if kind == 'project' else
              {'type': kind, 'file': str(path)})
    if kind == 'user':
        source['profile'] = None
    effective['layers'].append({'name': source, 'version': 'controlled', 'config': {}})
    config.verify_effective(effective, requirements, account, role)
    source['type'] = 'unknown'
    with pytest.raises(LeaseRefused, match='undeclared_configuration_layer'):
        config.verify_effective(effective, requirements, account, role)
