"""Original collection/configuration parity; no provider or child launch."""
from __future__ import annotations

import ast
import itertools
import json
from pathlib import Path

import pytest

from bootstrap_cases import BOOTSTRAP, CONTROLS, DECLARATIONS, TEST, configuration, wrapper
from bootstrap_configuration import Binding
from content_manifest import Refused
from unrest_harness.experimental_provider_config import ProviderConfig


def test_catalogue_is_exact_original_parametrized_collection():
    checkout = Path(__file__).resolve().parents[2]
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
    checkout = Path(__file__).resolve().parents[2]
    probe = tmp_path / 'probe'
    root = probe / 'owner'
    home = root / 'worker'
    home.mkdir(parents=True)
    config = ProviderConfig(codex_home=tmp_path / 'subscription', user_home=tmp_path / 'user',
                            cwd=probe, ambient={}, system=tmp_path / 'system')
    return Binding(checkout), config, root, home


def test_independent_configuration_render_matches_original_product(fresh):
    binding, config, root, home = fresh
    binding.check(config, root, BOOTSTRAP[0])
    arguments, encoded = configuration(binding.checkout, home)
    assert config.argv(root / 'fake-app-server', home) == [str(root / 'fake-app-server'), *arguments, 'app-server']
    assert encoded == json.dumps(config.thread_config(home), sort_keys=True)
    assert config.overrides(home).keys() == CONTROLS.keys() | {'sqlite_home', 'log_dir', 'model_catalog_json', 'skills.config', 'mcp_servers'}


@pytest.mark.parametrize('mutation', ['home', 'skills', 'servers', 'input-root', 'paths', 'method', 'new-input'])
def test_configuration_binding_refuses_mutated_or_new_inputs(fresh, mutation):
    binding, config, root, home = fresh
    if mutation == 'home':
        config.codex_home = root
    elif mutation == 'skills':
        config.skills.add('foreign')
    elif mutation == 'servers':
        config.servers.add('foreign')
    elif mutation == 'input-root':
        config.inputs.runtime_root = root
    elif mutation == 'paths':
        config.inputs.paths += (home / 'extra',)
    elif mutation == 'method':
        config.inputs.verify = lambda: None
    else:
        path = root.parent.parent / 'system/config.toml'
        path.parent.mkdir()
        path.write_text('model = "foreign"\n')
    with pytest.raises(Refused):
        binding.check(config, root, BOOTSTRAP[0])


def test_populated_fixture_renderer_disables_exact_servers_and_skills_without_auth_read(tmp_path,monkeypatch):
    monkeypatch.syspath_prepend(str(Path(__file__).resolve().parents[2]))
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
        arguments,encoded = configuration(Path(__file__).resolve().parents[2],home,
            servers=servers,skills=(str(skill),))
        assert config.argv(home/'backend',home) == [str(home/'backend'),*arguments,'app-server']
        assert encoded == json.dumps(config.thread_config(home),sort_keys=True)
    assert encoded.count('mcp_servers') == 1
