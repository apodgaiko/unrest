"""Original collection/configuration parity; no provider or child launch."""
from __future__ import annotations

import ast
import itertools
import json
from pathlib import Path

import pytest

from bootstrap_cases import BOOTSTRAP, CONTROLS, DECLARATIONS, TEST, configuration, wrapper
from types import SimpleNamespace
from configuration_inputs import check_inputs
from content_manifest import Refused
from unrest_harness.experimental_provider_config import ProviderConfig


def test_catalogue_is_exact_original_parametrized_collection():
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
    assert tuple(collected) == BOOTSTRAP and len(BOOTSTRAP) == 27
    assert sum(case.configured for case in DECLARATIONS) == 5
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
    check_inputs(binding.checkout,home,BOOTSTRAP[0])
    arguments, encoded = configuration(binding.checkout, home)
    assert config.argv(root / 'fake-app-server', home) == [str(root / 'fake-app-server'), *arguments, 'app-server']
    assert encoded == json.dumps(config.thread_config(home), sort_keys=True)
    assert config.overrides(home).keys() == CONTROLS.keys() | {'sqlite_home', 'log_dir', 'model_catalog_json', 'skills.config', 'mcp_servers'}


@pytest.mark.parametrize('relative', ['system/config.toml','subscription/config.toml',
    'subscription/AGENTS.md','subscription/AGENTS.override.md','subscription/rules',
    'system/requirements.toml','system/managed_config.toml','probe/config.toml',
    'probe/.codex/config.toml','probe/.agents/skills','user/.agents/skills'])
def test_configuration_binding_refuses_mutated_or_new_inputs(fresh,relative):
    binding,config,root,home=fresh
    check_inputs(binding.checkout,home,BOOTSTRAP[0])
    target=root.parent.parent/relative
    target.parent.mkdir(parents=True,exist_ok=True)
    target.write_text('foreign')
    with pytest.raises(Refused,match='unexpected input'):
        check_inputs(binding.checkout,home,BOOTSTRAP[0])


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


@pytest.mark.parametrize('case', __import__('controlled_cases').FRESH)
def test_original_fresh_probe_configuration_binding_and_render(fresh, case):
    from controlled_startup import expected_entry
    binding, config, root, home = fresh
    check_inputs(binding.checkout,home,case)
    value, _, _ = expected_entry(case, binding.checkout, home, '/pinned/python', 'a'*64, backend=True)
    assert value.argv[1:] == tuple(config.argv(root/'fake-app-server', home))
    assert dict(value.environment)['CODEX_HOME'] == str(config.codex_home)
    assert dict(value.environment)['CODEX_CONFIG'] == json.dumps(config.thread_config(home), sort_keys=True)


def test_fresh_configuration_case_is_closed_and_callback_free():
    from controlled_cases import configured, STARTUP_FAILURE
    class Trap:
        def __hash__(self):
            pytest.fail('case hashing callback')
    assert configured(BOOTSTRAP[0]) is True and configured(STARTUP_FAILURE) is False
    for case in ('foreign', Trap()):
        with pytest.raises(Refused):
            configured(case)


@pytest.mark.parametrize('case', __import__('controlled_cases').POPULATED)
def test_exact_populated_configuration_binds_inputs_without_reading_auth(tmp_path, monkeypatch, case):
    monkeypatch.syspath_prepend(str(next(p for p in Path(__file__).resolve().parents if (p/'pyproject.toml').is_file())))
    from tests.test_experimental_provider_config import configuration as original
    from controlled_cases import configuration_items
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
    check_inputs(binding.checkout,home,case)
    value,_,_ = expected_entry(case,binding.checkout,home,'/pinned/python','a'*64,backend=True)
    assert value.argv[1:] == tuple(config.argv(root/'fake-app-server',home))
    assert json.dumps(config.thread_config(home),sort_keys=True) == dict(value.environment)['CODEX_CONFIG']
    assert configuration_items(case,home)[0] == tuple(sorted(config.servers))
    (config.codex_home/'config.toml').write_text('mcp_servers={}\n')
    with pytest.raises(Refused):
        check_inputs(binding.checkout,home,case)
