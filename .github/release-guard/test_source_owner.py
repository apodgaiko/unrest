"""Pure source-owner controls: no product command, socket or provider launch."""
from __future__ import annotations

import asyncio
from dataclasses import replace
import hashlib
import importlib.machinery
import sys
import types

from _pytest.assertion.rewrite import AssertionRewritingHook
import pytest

import source_owner as owner
from content_manifest import Refused


BODY = b'''def route(value=7, *, flag=True):
    return check(__import__('sys')._getframe())

def factory(value):
    def nested():
        assert value
        return check(__import__('sys')._getframe())
    return nested

async def outer():
    return await inner()

async def inner():
    return check(__import__('sys')._getframe())

def other():
    def nested():
        return 1
    return nested
'''


@pytest.fixture
def module(request, monkeypatch):
    mode = getattr(request, 'param', 'plain')
    path, name = '/sealed/owner_control.py', 'sealed_owner_control'
    unit = owner.prepare(BODY, path, name, mode, hashlib.sha256(BODY).hexdigest())
    module = types.ModuleType(name)
    if mode == 'beartype-passive':
        from beartype.claw._importlib._clawimpload import BeartypeSourceFileLoader
        loader = BeartypeSourceFileLoader(name, path)
    else:
        loader = (importlib.machinery.SourceFileLoader(name, path) if mode == 'plain'
                  else AssertionRewritingHook(request.config))
    module.__file__, module.__loader__ = path, loader
    module.__spec__ = importlib.machinery.ModuleSpec(name, loader, origin=path)
    monkeypatch.setitem(sys.modules, name, module)
    # Controlled test source only. Enforcement prepare() never executes a unit.
    exec(unit.code('<module>', 1), vars(module))
    return unit, module


def bound(unit, module, name='route', **extra):
    fn = vars(module)[name]
    defaults = {'defaults': (7,), 'keyword_defaults': (('flag', True),)} if name == 'route' else {}
    return owner.Owner(unit, module, fn, fn.__qualname__, fn.__code__.co_firstlineno,
                       (1, 100), (owner.Link(module, name, fn),), **defaults, **extra)


@pytest.mark.parametrize('module', ['plain', 'pytest', 'beartype-passive'], indirect=True)
def test_prepared_owner_matches_actual_loader_code_globals_defaults_and_case(module):
    unit, module = module
    expected = bound(unit, module)

    def check(frame):
        expected.verify(frame)
        owner.verify_chain((expected,), 'case[param=7]', ('case[param=7]',))
        return 'verified'

    module.check = check
    assert module.route() == 'verified'


@pytest.mark.parametrize('mutation', ['code', 'globals', 'function', 'module', 'loader',
                                      'origin', 'spec_loader', 'name', 'file', 'defaults',
                                      'kwdefaults', 'callsite', 'case'])
def test_mutated_owner_refuses(module, monkeypatch, mutation):
    unit, module = module
    expected = bound(unit, module)
    function = module.route

    def check(frame):
        if mutation == 'case':
            owner.verify_chain((expected,), 'case[wrong]', ('case[right]',))
        else:
            expected.verify(frame)

    module.check = check
    if mutation == 'code':
        function.__code__ = function.__code__.replace(co_firstlineno=2)
    if mutation in ('globals', 'function'):
        namespace = dict(vars(module)) if mutation == 'globals' else vars(module)
        copied = types.FunctionType(function.__code__, namespace, 'route', (7,))
        copied.__kwdefaults__ = {'flag': True}
        module.route = copied
    elif mutation == 'module':
        monkeypatch.setitem(sys.modules, unit.module, types.ModuleType(unit.module))
    elif mutation == 'loader':
        module.__loader__ = object()
    elif mutation == 'origin':
        module.__spec__.origin = '/sealed/sibling.py'
    elif mutation == 'spec_loader':
        module.__spec__.loader = object()
    elif mutation == 'name':
        module.__name__ = 'copied_owner'
    elif mutation == 'file':
        module.__file__ = '/sealed/sibling.py'
    elif mutation == 'defaults':
        function.__defaults__ = (True,)
    elif mutation == 'kwdefaults':
        function.__kwdefaults__ = {'flag': 1}
    elif mutation == 'callsite':
        expected = replace(expected, call_lines=(90, 91))
    with pytest.raises(Refused):
        module.route()


@pytest.mark.parametrize('module', ['plain', 'pytest'], indirect=True)
def test_nested_code_qualified_path_and_cell_links(module):
    unit, module = module
    value = object()
    fn = module.factory(value)
    module.selected = fn
    expected = owner.Owner(unit, module, fn, 'factory.<locals>.nested', 5, (5, 7),
                           (owner.Link(module, 'selected', fn),), closure=(value,),
                           cell_anchors=fn.__closure__)
    module.check = lambda frame: expected.verify(frame) or 'verified'
    assert fn() == 'verified'
    assert unit.code('other.<locals>.nested', 17) != unit.code('factory.<locals>.nested', 5)
    fn.__closure__[0].cell_contents = object()
    with pytest.raises(Refused, match='closure changed'):
        fn()


def test_copied_closure_function_does_not_replace_retained_function_anchor(module):
    unit, module = module
    value = object()
    original = module.factory(value)
    module.selected = original
    expected = owner.Owner(unit, module, original, original.__qualname__, 5, (5, 7),
                           (owner.Link(module, 'selected', original),), closure=(value,),
                           cell_anchors=original.__closure__)
    module.check = lambda frame: expected.verify(frame)
    copied = types.FunctionType(original.__code__, vars(module), closure=original.__closure__)
    copied.__qualname__ = original.__qualname__
    module.selected = copied
    with pytest.raises(Refused):
        copied()


def test_actual_async_owner_chain_and_parameter_suffix(module):
    unit, module = module
    inner, outer = bound(unit, module, 'inner'), bound(unit, module, 'outer')

    def check(frame):
        owner.verify_chain((inner, outer), 'async[one]', ('async[one]',))
        return 'verified'

    module.check = check
    assert asyncio.run(module.outer()) == 'verified'
    with pytest.raises(Refused, match='chain changed'):
        asyncio.run(module.inner())


@pytest.mark.parametrize('mode', ['plain', 'pytest', 'beartype-passive'])
def test_prepare_compiles_without_executing_and_unknown_modes_closed(mode):
    body = b"raise AssertionError('source executed during preparation')\n"
    unit = owner.prepare(body, '/sealed/noexec.py', 'noexec', mode, hashlib.sha256(body).hexdigest())
    assert unit.code('<module>', 1)
    with pytest.raises(Refused):
        owner.prepare(body, '/sealed/noexec.py', 'noexec', 'beartype-unprepared', hashlib.sha256(body).hexdigest())
    with pytest.raises(Refused):
        owner.prepare(body, '/sealed/noexec.py', 'noexec', mode, '0' * 64)


def test_missing_namespace_none_is_not_a_link():
    with pytest.raises(Refused, match='missing namespace'):
        owner.Link({}, 'absent', None).check()


def test_ambiguous_qualified_code_is_not_first_name_match(module):
    unit, module = module
    code = unit.code('route', 1)
    with pytest.raises(Refused, match='ambiguous'):
        replace(unit, codes=(code, code)).code('route', 1)


def test_actual_pytest_imported_owner_matches_independent_preparation():
    from pathlib import Path
    module = sys.modules[__name__]
    path = str(Path(__file__).absolute())
    body = Path(path).read_bytes()
    unit = owner.prepare(body, path, __name__, 'pytest', hashlib.sha256(body).hexdigest())
    function = test_actual_pytest_imported_owner_matches_independent_preparation
    expected = owner.Owner(unit, module, function, function.__qualname__,
                           function.__code__.co_firstlineno, (1, 10000),
                           (owner.Link(module, function.__name__, function),))
    expected.verify(sys._getframe())


@pytest.mark.parametrize('empty', [False, True])
def test_actual_executing_closure_is_checked_even_when_retained_cell_unchanged(monkeypatch, empty):
    body = b'''def factory(value):
    def nested():
        check(__import__('sys')._getframe())
        return value
    return nested
'''
    name, path = 'sealed_actual_closure', '/sealed/actual_closure.py'
    unit = owner.prepare(body, path, name, 'plain', hashlib.sha256(body).hexdigest())
    module = types.ModuleType(name)
    module.__file__ = path
    module.__loader__ = importlib.machinery.SourceFileLoader(name, path)
    module.__spec__ = importlib.machinery.ModuleSpec(name, module.__loader__, origin=path)
    monkeypatch.setitem(sys.modules, name, module)
    exec(unit.code('<module>', 1), vars(module))
    value = object()
    original = module.factory(value)
    module.selected = original
    expected = owner.Owner(unit, module, original, original.__qualname__, 2, (2, 4),
                           (owner.Link(module, 'selected', original),), closure=(value,),
                           cell_anchors=original.__closure__)
    module.check = lambda frame: expected.verify(frame)
    cell = types.CellType() if empty else types.CellType(object())
    copied = types.FunctionType(original.__code__, vars(module), closure=(cell,))
    assert module.selected is original and original.__closure__[0].cell_contents is value
    with pytest.raises(Refused, match='closure changed'):
        copied()


def test_identical_function_clone_is_not_claimed_as_distinguishable(module):
    unit, module = module
    expected = bound(unit, module)
    module.check = lambda frame: expected.verify(frame) or 'frame identity only'
    copied = types.FunctionType(module.route.__code__, vars(module), argdefs=(7,))
    copied.__kwdefaults__ = {'flag': True}
    assert module.route is expected.function and copied is not expected.function
    # No launch authority follows. Actual argument/default provenance is separate.
    assert copied() == 'frame identity only'


def test_inspection_refuses_custom_namespace_keys_without_comparison_callbacks():
    class Key:
        armed = False
        def __hash__(self):
            return hash('route')

        def __eq__(self, other):
            pytest.fail('user equality executed during identity inspection')

    namespace = {Key(): object()}
    with pytest.raises(Refused, match='non-string namespace'):
        owner.Link(namespace, 'route', object()).check()


def test_custom_default_objects_never_execute_equality(module):
    class Default:
        def __eq__(self, other):
            pytest.fail('user equality executed during default inspection')

    unit, module = module
    expected = bound(unit, module)
    module.check = lambda frame: expected.verify(frame)
    module.route.__defaults__ = (Default(),)
    with pytest.raises(Refused, match='unsupported source default'):
        module.route()


@pytest.mark.parametrize('mutation', ['qualname', 'keyword_dictionary', 'code_constant'])
def test_live_metadata_callbacks_are_never_invoked(module, mutation):
    class Text(str):
        def __eq__(self, other):
            pytest.fail('qualname equality callback')

        def __ne__(self, other):
            pytest.fail('qualname inequality callback')

    class Dictionary(dict):
        def __bool__(self):
            pytest.fail('keyword dictionary truth callback')

    class Constant:
        def __eq__(self, other):
            pytest.fail('code constant equality callback')

    unit, module = module
    expected = bound(unit, module)
    module.check = lambda frame: expected.verify(frame)
    if mutation == 'qualname':
        module.route.__qualname__ = Text('route')
    elif mutation == 'keyword_dictionary':
        module.route.__kwdefaults__ = Dictionary(flag=True)
    else:
        module.route.__code__ = module.route.__code__.replace(
            co_consts=(*module.route.__code__.co_consts, Constant()))
    with pytest.raises(Refused):
        module.route()



@pytest.mark.parametrize('module', ['beartype-passive'], indirect=True)
@pytest.mark.parametrize('attribute,value', [('_module_conf', object()), ('_module_name', 'other')])
def test_passive_loader_cannot_enable_an_unprepared_transform(module, attribute, value):
    unit, module = module
    expected = bound(unit, module)
    module.check = expected.verify
    setattr(module.__loader__, attribute, value)
    with pytest.raises(Refused, match='beartype compiler'):
        module.route()


@pytest.mark.parametrize('module', ['plain', 'pytest', 'beartype-passive'], indirect=True)
def test_loader_class_reference_is_prepared_before_live_module_mutation(module, monkeypatch):
    unit, module = module
    expected = bound(unit, module)
    retained_type = unit.loader_type
    module.check = lambda frame: expected.verify(frame)
    if unit.mode == 'plain':
        monkeypatch.setattr(importlib.machinery, 'SourceFileLoader', type('Replacement', (), {}))
    elif unit.mode == 'pytest':
        import _pytest.assertion.rewrite as rewrite
        monkeypatch.setattr(rewrite, 'AssertionRewritingHook', type('Replacement', (), {}))
    else:
        import beartype.claw._importlib._clawimpload as claw
        monkeypatch.setattr(claw, 'BeartypeSourceFileLoader', type('Replacement', (), {}))
    assert unit.loader_type is retained_type
    assert module.route() is None



@pytest.mark.parametrize('module', ['beartype-passive'], indirect=True)
def test_passive_loader_metadata_refuses_custom_keys_without_equality_callbacks(module):
    unit, module = module
    expected = bound(unit, module)
    module.check = expected.verify
    class Key:
        armed = False
        def __hash__(self):
            return hash('_module_conf')
        def __eq__(self, other):
            if self.armed:
                raise AssertionError('metadata equality callback executed')
            return False
    values = vars(module.__loader__)
    del values['_module_conf']
    key = Key()
    values[key] = None
    key.armed = True
    with pytest.raises(Refused, match='non-string namespace key'):
        module.route()


def test_actual_passive_loader_matches_independently_prepared_code(tmp_path, monkeypatch):
    from beartype.claw._importlib._clawimpload import BeartypeSourceFileLoader
    import importlib.util

    path = str(tmp_path / 'guard_passive_owner_control.py')
    name = '_guard_passive_owner_control'
    from pathlib import Path
    Path(path).write_bytes(BODY)
    unit = owner.prepare(BODY, path, name, 'beartype-passive', hashlib.sha256(BODY).hexdigest())
    loader = BeartypeSourceFileLoader(name, path)
    spec = importlib.util.spec_from_file_location(name, path, loader=loader)
    assert spec is not None
    module = importlib.util.module_from_spec(spec)
    monkeypatch.setitem(sys.modules, name, module)
    loader.exec_module(module)
    assert loader._module_conf is None and loader._module_name is None
    expected = bound(unit, module)
    module.check = lambda frame: expected.verify(frame)
    assert module.route() is None
