"""Root certification remains attached; exact inner negative scopes stay separate."""
from types import SimpleNamespace

import pytest

from primary_source_entry import config_factory


def test_original_factory_arguments_and_root_observer_are_unchanged():
    calls, attached = [], []
    def original(args, plugins):
        calls.append((args, plugins))
        return SimpleNamespace(pluginmanager=SimpleNamespace(register=lambda *a: attached.append(a)))
    plugin, guard = object(), object()
    args, plugins = ['-q'], None
    factory = config_factory(original, plugin, lambda *a: False, guard)
    config = factory(args, plugins)
    assert calls == [(args, plugins)] and calls[0][0] is args
    assert attached == [(plugin, 'primary-source-observer')]
    assert set(vars(config)) == {'pluginmanager'}


def test_verified_inner_negative_scope_adds_no_observer_options_or_result_mutation():
    plugin = object()
    config = SimpleNamespace(pluginmanager=SimpleNamespace(register=lambda *a: pytest.fail('outer observer added')))
    args = ['-c', '/source/pyproject.toml', '-q', '/owned/test_owned_failure_setup.py']
    seen = []
    def original(actual, plugins):
        assert actual is args and plugins is None
        return config
    def nested(guard, actual, plugins):
        seen.append((guard, actual, plugins))
        return True
    guard = object()
    assert config_factory(original, plugin, nested, guard)(args) is config
    assert seen == [(guard, args, None)] and set(vars(config)) == {'pluginmanager'}


def test_truthy_or_refused_verdict_cannot_remove_the_outer_guard():
    effects = []
    def refuse(reason):
        raise RuntimeError(reason)
    config = SimpleNamespace(pluginmanager=SimpleNamespace(register=lambda *a: effects.append(a)))
    factory = config_factory(lambda *a: config, object(), lambda *a: {'allowed': True},
                             SimpleNamespace(refuse=refuse))
    with pytest.raises(RuntimeError, match='verdict_type'):
        factory(['-q'])
    assert effects == []
