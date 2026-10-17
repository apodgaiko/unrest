"""Runtime authority checks for the initialization helper, without real providers."""
import json
from pathlib import Path
import runpy
import shutil

import pytest

from unrest_harness.experimental_provider_config import ProviderConfig
from unrest_harness.experimental_session import _SessionOwner, _TurnClient

from tests.controlled_transport import controlled_transport

PROBE = runpy.run_path(str(Path(__file__).parents[1] / 'tools/probe_v046_startup.py'))['probe']
FIXTURE = Path(__file__).parent / 'fixtures/experimental_session_app_server.py'


class TruthySelection:
    calls = 0

    def __bool__(self):
        self.calls += 1
        return True


@pytest.mark.parametrize('selection', [
    False, None, 0, 1, 0.0, 1.0, '', 'false', 'true', [], [True], {},
    {'trusted_process': True}, (), (True,), set(), {True}, TruthySelection(),
], ids=[
    'false', 'none', 'zero', 'one', 'float-zero', 'float-one', 'empty-string',
    'string-false', 'string-true', 'empty-list', 'list', 'empty-dict', 'dict',
    'empty-tuple', 'tuple', 'empty-set', 'set', 'truthy-object',
])
@pytest.mark.parametrize('controlled', [False, True])
async def test_nonboolean_optin_refuses_before_setup(tmp_path, monkeypatch, selection, controlled):
    calls = []

    def forbidden(*args, **kwargs):
        calls.append('setup')
        raise AssertionError('invalid selection reached setup')

    for name in ('check_package', 'ProviderConfig', 'PilotLedger', 'require_provider',
                 '_SessionOwner'):
        monkeypatch.setitem(PROBE.__globals__, name, forbidden)
    root = tmp_path / 'probe'
    # Catch even transient directory creation; a caught exception is not a refusal proof.
    monkeypatch.setattr(Path, 'mkdir', forbidden)
    result = await PROBE(root, Path('/unused-adapter'),
                         None if controlled else Path('/unused-package'),
                         trusted_process=selection, fixture=FIXTURE if controlled else None, transport=controlled_transport())
    assert calls == []
    assert not root.exists()
    assert result['outcome'] == 'attention'
    assert 'owner_diagnostics' not in result
    assert result['reservations'] == result['sends'] == 0
    if isinstance(selection, TruthySelection):
        assert selection.calls == 0


@pytest.mark.parametrize('fixture,package', [(None, None), (FIXTURE, Path('/unused-package'))])
async def test_true_still_requires_exactly_one_backend(tmp_path, fixture, package):
    root = tmp_path / 'probe'
    result = await PROBE(root, Path('/unused-adapter'), package,
                         trusted_process=True, fixture=fixture, transport=controlled_transport())
    assert result['outcome'] == 'attention'
    assert not root.exists()


async def test_literal_true_preserves_admission_and_initializes_controlled_owner(tmp_path, monkeypatch):
    root = tmp_path / 'probe'
    configuration = ProviderConfig(codex_home=tmp_path / 'subscription',
        user_home=tmp_path / 'user', cwd=root, ambient={}, system=tmp_path / 'system')
    environment = _SessionOwner._environment
    admission = PROBE.__globals__['require_provider']
    request = _TurnClient.send_request
    selections = []
    methods = []

    def controlled_environment(self, home):
        value = environment(self, home)
        value['CODEX_HOME'] = str(configuration.codex_home)
        return value

    def observed_admission(*args, **kwargs):
        selections.append(kwargs['trusted_process'])
        return admission(*args, **kwargs)

    async def observed_request(self, method, *args, **kwargs):
        methods.append(method)
        return await request(self, method, *args, **kwargs)

    monkeypatch.setattr(_SessionOwner, '_environment', controlled_environment)
    monkeypatch.setattr(_TurnClient, 'send_request', observed_request)
    monkeypatch.setitem(PROBE.__globals__, 'require_provider', observed_admission)
    result = await PROBE(root, Path(shutil.which('codex-acp') or '/missing').resolve(), None,
        trusted_process=True, fixture=FIXTURE, configuration=configuration, transport=controlled_transport())
    assert selections == [True] and selections[0] is True
    assert result['outcome'] == 'initialized', result
    assert result['effective_config_sha256']
    assert result['served_identity'] == {'model': 'gpt-6-astra', 'modelProvider': 'openai',
                                         'reasoningEffort': 'medium'}
    assert result['closed'] and result['owned_reaped']
    assert 'initialize' in methods and 'session/new' in methods
    assert 'session/prompt' not in methods and 'turn/start' not in methods
    events = [json.loads(line)['event'] for line in
              (root / 'initialization-only.jsonl').read_text().splitlines()]
    assert not set(events) & {'reserve', 'send', 'ack', 'uncertain'}
    assert not list(root.rglob('trace.jsonl'))
