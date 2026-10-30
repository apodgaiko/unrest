"""Original collection/configuration parity; no provider or child launch."""
from __future__ import annotations

import ast
import itertools
import json
from pathlib import Path

import pytest

from bootstrap_cases import BOOTSTRAP, CONTROLS, DECLARATIONS, TEST, configuration, wrapper
from types import SimpleNamespace
from content_manifest import Refused
from unrest_harness.experimental_provider_config import ProviderConfig


def test_catalogue_is_exact_original_parametrized_collection(tmp_path):
    checkout = next(p for p in Path(__file__).resolve().parents if (p/'pyproject.toml').is_file())
    tree = ast.parse((checkout / TEST).read_text())
    collected = []
    for function in tree.body:
        if not isinstance(function, (ast.FunctionDef, ast.AsyncFunctionDef)) or not function.name.startswith('test_'):
            continue
        parameters = [ast.literal_eval(item.args[1]) for item in reversed(function.decorator_list)
            if isinstance(item, ast.Call) and isinstance(item.func, ast.Attribute) and item.func.attr == 'parametrize']
        for values in itertools.product(*parameters):
            suffix = '[' + '-'.join(str(value) for value in values) + ']' if values else ''
            collected.append(TEST + '::' + function.name + suffix)
    zero={TEST+'::'+name for name in (
        'test_actual_launch_lifetime_and_interruptions[exhausted]',
        'test_phases_share_one_deadline_across_tasks','test_absolute_ledger_includes_setup_and_cleanup',
        'test_capped_body_free_observation_is_pre_cleanup','test_turn_reservation_does_not_restart_clock_after_bootstrap',
        *(f'test_original_limits_refuse_before_grant_or_send[True-{limit}]' for limit in ('turn','episode','campaign')),
        'test_expiry_during_seal_cannot_publish_grant')}
    assert tuple(case for case in collected if case not in zero)==BOOTSTRAP
    assert len(collected)==27 and len(BOOTSTRAP)==18
    from test_source_integration import backend_request
    from effect_proposals import proposal
    for index,case in enumerate(sorted(zero)):
        host,actor,raw=backend_request(tmp_path/str(index))
        host.case=raw['case']=case
        with pytest.raises(Refused):
            proposal(host,actor,raw)
        assert not host.intents
    assert sum(case.configured for case in DECLARATIONS) == 4
    assert wrapper(BOOTSTRAP[0]).find('time.sleep(32)') >= 0


@pytest.fixture
def fresh(tmp_path):
    checkout = next(p for p in Path(__file__).resolve().parents if (p/'pyproject.toml').is_file())
    probe = tmp_path / 'probe'
    root = probe / 'owner'
    home = root / 'worker'
    home.mkdir(parents=True)
    config = ProviderConfig(codex_home=tmp_path / 'subscription', user_home=tmp_path / 'user',
                            cwd=probe, ambient={}, system=tmp_path / 'system')
    return SimpleNamespace(checkout=checkout), config, root, home


def test_independent_configuration_render_matches_original_product(fresh):
    binding, config, root, home = fresh
    arguments, encoded = configuration(binding.checkout, home)
    assert config.argv(root / 'fake-app-server', home) == [str(root / 'fake-app-server'), *arguments, 'app-server']
    assert encoded == json.dumps(config.thread_config(home), sort_keys=True)
    assert config.overrides(home).keys() == CONTROLS.keys() | {'sqlite_home', 'log_dir', 'model_catalog_json', 'skills.config', 'mcp_servers'}


@pytest.mark.parametrize('field', ['codex_home','skills','servers'])
def test_configuration_render_refuses_foreign_launch_operands(fresh,field):
    binding,config,root,home=fresh
    arguments,encoded=configuration(binding.checkout,home)
    if field=='codex_home':
        config.codex_home=root
        assert config.codex_home != root.parent.parent/'subscription'
    elif field=='skills':
        config.skills.add('foreign')
        assert json.dumps(config.thread_config(home),sort_keys=True)!=encoded
    else:
        config.servers.add('foreign')
        assert config.argv(root/'fake-app-server',home)!=[str(root/'fake-app-server'),*arguments,'app-server']


def test_populated_fixture_renderer_disables_exact_servers_and_skills_without_auth_read(tmp_path,monkeypatch):
    monkeypatch.syspath_prepend(str(next(p for p in Path(__file__).resolve().parents if (p/'pyproject.toml').is_file())))
    from tests.test_experimental_provider_config import configuration as original
    from unittest.mock import patch
    config = original(tmp_path)
    skill = config.codex_home/'skills/example/SKILL.md'
    skill.parent.mkdir(parents=True)
    skill.write_text('synthetic skill')
    config = ProviderConfig(codex_home=config.codex_home,user_home=tmp_path/'user',
        cwd=tmp_path/'campaign',ambient={},system=tmp_path/'system')
    servers = ('external.with.dots','ordinary','quote"and\\slash','λ😀')
    original_read = Path.open
    def read(path,*args,**kwargs):
        assert path.name != 'auth.json','authentication body must never be acquired'
        return original_read(path,*args,**kwargs)
    home = tmp_path/'campaign/owner/worker'
    home.mkdir(parents=True)
    with patch.object(Path,'open',read):
        arguments,encoded = configuration(next(p for p in Path(__file__).resolve().parents if (p/'pyproject.toml').is_file()),home,
            servers=servers,skills=(str(skill),))
        assert config.argv(home/'backend',home) == [str(home/'backend'),*arguments,'app-server']
        assert encoded == json.dumps(config.thread_config(home),sort_keys=True)
    assert encoded.count('mcp_servers') == 1


@pytest.mark.parametrize('case', __import__('test_controlled_catalogue').FRESH)
def test_original_fresh_probe_configuration_binding_and_render(fresh, case):
    from controlled_startup import expected_entry
    binding, config, root, home = fresh
    value, _, _ = expected_entry(case, binding.checkout, home, '/pinned/python', 'a'*64, backend=True,variant=1,backend_pin=__import__('test_controlled_catalogue').backend(case)[0])
    assert value.argv[1:] == tuple(config.argv(root/'fake-app-server', home))
    assert dict(value.environment)['CODEX_HOME'] == str(config.codex_home)
    assert dict(value.environment)['CODEX_CONFIG'] == json.dumps(config.thread_config(home), sort_keys=True)


def test_live_configuration_selection_is_closed_and_callback_free(fresh):
    from controlled_cases import eligible,STARTUP_FAILURE
    from controlled_startup import expected_entry
    class Trap:
        def __hash__(self):
            pytest.fail('case hashing callback')
    assert not eligible(BOOTSTRAP[0]) and eligible(STARTUP_FAILURE)
    assert not eligible('foreign') and not eligible(Trap())
    binding,_,_,home=fresh
    for variant in (True,-1,4,1.5,Trap()):
        with pytest.raises(Refused,match='finite configuration variant'):
            expected_entry(BOOTSTRAP[0],binding.checkout,home,'/native/python','a'*64,backend=True,variant=variant)


@pytest.mark.parametrize('case', __import__('test_controlled_catalogue').POPULATED)
def test_exact_populated_configuration_binds_inputs_without_reading_auth(tmp_path, monkeypatch, case):
    monkeypatch.syspath_prepend(str(next(p for p in Path(__file__).resolve().parents if (p/'pyproject.toml').is_file())))
    from tests.test_experimental_provider_config import configuration as original
    from test_controlled_catalogue import configuration_items
    from controlled_startup import expected_entry
    config = original(tmp_path)
    if case.split('[')[1].startswith('True-'):
        skill = config.codex_home/'skills/example/SKILL.md'
        skill.parent.mkdir(parents=True)
        skill.write_text('synthetic skill')
        config = ProviderConfig(codex_home=config.codex_home,user_home=tmp_path/'user',
            cwd=tmp_path/'campaign',ambient={},system=tmp_path/'system')
    root = tmp_path/'campaign/owner'
    home = root/'worker'
    home.mkdir(parents=True)
    binding = SimpleNamespace(checkout=next(p for p in Path(__file__).resolve().parents if (p/'pyproject.toml').is_file()))
    read = Path.open
    def opening(path,*args,**kwargs):
        assert path.name != 'auth.json'
        return read(path,*args,**kwargs)
    monkeypatch.setattr(Path,'open',opening)
    value,_,_ = expected_entry(case,binding.checkout,home,'/pinned/python','a'*64,backend=True,variant=3 if case.split('[')[1].startswith('True-') else 2,backend_pin=__import__('test_controlled_catalogue').backend(case)[0])
    assert value.argv[1:] == tuple(config.argv(root/'fake-app-server',home))
    assert json.dumps(config.thread_config(home),sort_keys=True) == dict(value.environment)['CODEX_CONFIG']
    assert configuration_items(case,home)[0] == tuple(sorted(config.servers))
