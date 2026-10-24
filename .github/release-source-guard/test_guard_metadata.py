"""Guard bookkeeping keeps fresh bytes, canonical paths and complete evidence."""
from __future__ import annotations

import ast
import hashlib
import importlib.util
from pathlib import Path
import sys
from types import SimpleNamespace

import pytest

SUPPORT = Path(__file__).parent


def load(name):
    spec = importlib.util.spec_from_file_location('metadata_' + name, SUPPORT / 'finite' / (name + '.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def sha(body):
    return hashlib.sha256(body).hexdigest()


def anchor(path, relative):
    body = path.read_bytes()
    node = next(n for n in ast.walk(ast.parse(body)) if isinstance(n, ast.Call))
    return {'path': relative, 'line': node.lineno, 'route': 'subprocess.Popen',
            'source_sha256': sha(body), 'family': 'controlled', 'owner': 'owner',
            'expression_ast_sha256': sha(ast.dump(node, include_attributes=False).encode())}


def frame(path, name='owner', line=1, parent=None, values=None, globals=None):
    return SimpleNamespace(f_code=SimpleNamespace(co_filename=str(path), co_name=name),
                           f_lineno=line, f_back=parent, f_locals=values or {}, f_globals=globals or {})


@pytest.fixture
def anchored(tmp_path, monkeypatch):
    module = load('anchor_probe')
    checkout = tmp_path / 'checkout'
    checkout.mkdir()
    source = checkout / 'input.py'
    source.write_text('launch()\n')
    row = anchor(source, 'input.py')
    state = {'checkout': str(checkout), 'anchor_inventory': [row]}
    active = frame(source)
    monkeypatch.setattr(module, 'inspect', SimpleNamespace(currentframe=lambda: active))
    return module, state, source, row, active


def test_complete_anchor_row_alias_duplicates_and_fresh_retarget(anchored, tmp_path):
    module, state, source, row, active = anchored
    alias = tmp_path / 'alias.py'
    alias.symlink_to(source)
    active.f_code.co_filename = str(alias)
    active.f_back = frame(source)
    expected = {**row, 'observed_source_path': str(source), 'function': 'owner',
                'frame_line': 1, 'observation': 'actual launch stack or active await chain'}
    assert module.observe(state, tmp_path) == [expected]
    other = tmp_path / 'elsewhere.py'
    other.write_bytes(source.read_bytes())
    alias.unlink()
    alias.symlink_to(other)
    active.f_back = None
    assert module.observe(state, tmp_path) == []


def test_sibling_prefix_is_not_a_checkout_member(anchored, tmp_path):
    module, state, source, row, active = anchored
    sibling = tmp_path / 'checkout-extra'
    sibling.mkdir()
    other = sibling / 'input.py'
    other.write_bytes(source.read_bytes())
    active.f_code.co_filename = str(other)
    assert module.observe(state, tmp_path) == []


def test_filesystem_root_keeps_original_relative_path(anchored, tmp_path):
    module, state, source, row, active = anchored
    state['checkout'] = '/'
    row['path'] = str(source).lstrip('/')
    assert module.observe(state, tmp_path)[0]['path'] == row['path']


def test_source_drift_is_checked_after_cached_ast(anchored, tmp_path):
    module, state, source, row, active = anchored
    assert len(module.observe(state, tmp_path)) == 1
    source.write_text('different()\n')
    with pytest.raises(RuntimeError, match='passive_anchor_source_drift'):
        module.observe(state, tmp_path)


def test_wrong_ast_pin_remains_refused(anchored, tmp_path):
    module, state, source, row, active = anchored
    row['expression_ast_sha256'] = '0' * 64
    with pytest.raises(RuntimeError, match='passive_anchor_AST_drift'):
        module.observe(state, tmp_path)


def test_copied_source_fallback_keeps_complete_row(anchored, tmp_path):
    module, state, source, row, active = anchored
    copied = tmp_path / 'copy'
    selected = copied / 'src/unrest_harness/repository_contract.py'
    selected.parent.mkdir(parents=True)
    selected.write_bytes(source.read_bytes())
    row['path'] = 'src/unrest_harness/repository_contract.py'
    state['class'] = 'source-copied-repository-cli'
    active.f_code.co_filename = str(selected)
    assert module.observe(state, copied) == [{
        **row, 'observed_source_path': str(selected), 'function': 'owner',
        'frame_line': 1, 'observation': 'actual launch stack or active await chain'}]


def test_await_chain_anchor_is_not_lost(anchored, tmp_path, monkeypatch):
    import asyncio
    module, state, source, row, active = anchored
    awaited = frame(source)
    active.f_code.co_filename = str(tmp_path / 'unrelated')
    coroutine = SimpleNamespace(cr_frame=awaited, cr_await=None)
    monkeypatch.setattr(asyncio, 'current_task', lambda: SimpleNamespace(get_coro=lambda: coroutine))
    assert len(module.observe(state, tmp_path)) == 1


def test_copied_cli_ignores_only_names_that_cannot_match(tmp_path, monkeypatch):
    module = load('copied_cli')
    active = frame(tmp_path / 'irrelevant.py', 'other')
    monkeypatch.setattr(module, 'inspect', SimpleNamespace(currentframe=lambda: active))
    original = module.Path.resolve
    resolved = []

    def resolve(path, *args, **kwargs):
        resolved.append(str(path))
        return original(path, *args, **kwargs)

    monkeypatch.setattr(module.Path, 'resolve', resolve)
    assert module.translate(['/usr/bin/git'], tmp_path, {}, {'checkout': str(tmp_path)},
                            lambda row: None, pytest.fail) is None
    assert str(tmp_path / 'irrelevant.py') not in resolved


@pytest.mark.parametrize('alias', [False, True])
def test_original_copied_cli_translation_keeps_all_source_checks(tmp_path, monkeypatch, alias):
    module = load('copied_cli')
    checkout, copied, binary = (tmp_path / name for name in ('checkout', 'copy', 'bin'))
    test = checkout / 'tests/test_repository_contract.py'
    test.parent.mkdir(parents=True)
    test.write_text('original test source\n')
    product = copied / 'src/unrest_harness/module.py'
    product.parent.mkdir(parents=True)
    product.write_text('original product bytes\n')
    binary.mkdir()
    python, console = binary / 'python', binary / 'unrest'
    console.write_text('#!' + str(python) + '\noriginal console\n')
    monkeypatch.setattr(module, 'sys', SimpleNamespace(executable=str(python)))
    environment = {**module.os.environ, 'PYTHONPATH': str(copied / 'src')}
    source = test
    if alias:
        source = tmp_path / 'source-alias.py'
        source.symlink_to(test)
    active = frame(source, '_run_repository_cli', values={'root': copied, 'environment': environment})
    monkeypatch.setattr(module, 'inspect', SimpleNamespace(currentframe=lambda: active))
    state = {'checkout': str(checkout), 'owned_root': str(tmp_path),
             'product_pins': {'tests/test_repository_contract.py': sha(test.read_bytes()),
                              'src/unrest_harness/module.py': sha(product.read_bytes())},
             'copied_console_pins': {'unrest': sha(console.read_bytes())}}

    def refuse(code):
        raise RuntimeError(code)

    events = []
    result = module.translate([str(console), 'check-repository'], copied, environment,
                              state, events.append, refuse)
    assert result[0]['class'] == 'source-copied-repository-cli'
    assert result[1] == [str(python), str(console), 'check-repository']
    assert events[0]['source_binding']['path'] == str(test)
    product.write_text('changed product bytes\n')
    with pytest.raises(RuntimeError, match='copied_cli_module_bytes'):
        module.translate([str(console), 'check-repository'], copied, environment,
                         state, events.append, refuse)


def test_static_binding_precomputed_paths_keep_real_owner_code_and_source(tmp_path, monkeypatch):
    module = load('static_binding')
    source = tmp_path / 'src/unrest_harness/acp_runner.py'
    source.parent.mkdir(parents=True)
    source.write_text('\n' * 124 + 'def _run_cmd():\n    launch()\n')
    import types
    owner = types.ModuleType('_metadata_original_owner')
    exec(compile(source.read_bytes(), str(source), 'exec', dont_inherit=True), owner.__dict__)
    function = owner._run_cmd
    monkeypatch.setitem(sys.modules, owner.__name__, owner)
    active = frame(source, '_run_cmd', line=126, globals=owner.__dict__)
    active.f_code = function.__code__
    monkeypatch.setattr(module, 'inspect', SimpleNamespace(currentframe=lambda: active))

    def named(code, name):
        return next(c for c in code.co_consts if isinstance(c, types.CodeType) and c.co_name == name)

    state = {'checkout': str(tmp_path), 'product_pins': {
        'src/unrest_harness/acp_runner.py': sha(source.read_bytes())},
        'isolated_named': named, 'isolated_source_code': lambda path: compile(
            path.read_bytes(), str(path), 'exec', dont_inherit=True)}
    rows = []

    def refuse(code):
        raise RuntimeError(code)

    module.check(state, rows.append, refuse)
    assert rows == [{'kind': 'inactive_source_owner_identity_checked',
                     'path': 'src/unrest_harness/acp_runner.py', 'line': 126,
                     'source_sha256': sha(source.read_bytes()), 'new_launch_authority': False}]
    source.write_text(source.read_text() + '# changed\n')
    with pytest.raises(RuntimeError, match='inactive_source_owner_identity_drift'):
        module.check(state, rows.append, refuse)


def test_anchor_preparation_caches_only_syntax_and_rechecks_inventory(anchored, tmp_path, monkeypatch):
    module, state, source, row, active = anchored
    parse = module.ast.parse
    parses = []
    def counted(body):
        parses.append(body)
        return parse(body)
    monkeypatch.setattr(module.ast, 'parse', counted)
    module.prepare(state, [source])
    assert len(parses) == 1 and 'cohort_passive_ASTs' not in state
    assert len(module.observe(state, tmp_path)) == 1 and len(parses) == 1
    row['expression_ast_sha256'] = '0' * 64
    with pytest.raises(RuntimeError, match='passive_anchor_AST_drift'):
        module.observe(state, tmp_path)
    source.write_text('different()\n')
    with pytest.raises(RuntimeError, match='passive_anchor_source_drift'):
        module.observe(state, tmp_path)


@pytest.mark.parametrize('name', ['anchor_probe', 'fallback_binding'])
def test_optional_syntax_preparation_retains_current_bytes_and_original_errors(tmp_path, name):
    module = load(name)
    source = tmp_path / 'source.py'
    state = {}
    module.prepare(state, [source])
    source.write_text('not valid ?')
    module.prepare(state, [source])
    with pytest.raises(SyntaxError):
        module.syntax(state, source, source.read_bytes())
    source.write_text('first()\n')
    module.prepare(state, [source])
    first = module.syntax(state, source, source.read_bytes())
    assert module.syntax(state, source, source.read_bytes()) is first
    source.write_text('second()\n')
    second = module.syntax(state, source, source.read_bytes())
    assert second is not first
    assert ast.dump(second) == ast.dump(ast.parse(source.read_bytes()))
