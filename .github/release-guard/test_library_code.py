"""Pure compilation controls; readonly mount custody belongs to native entry."""
from __future__ import annotations

import hashlib
import importlib.util
from pathlib import Path
import sys

import pytest

from content_manifest import Refused
from library_code import Computation
import library_code


@pytest.fixture
def domain(tmp_path):
    roots = {key: str(tmp_path / key) for key in ('source', 'dependencies', 'stdlib')}
    for path in roots.values():
        Path(path).mkdir()
    return Computation(roots)


def test_readonly_source_bytes_do_not_authorize_forged_code(domain):
    source = Path(domain.roots['source']) / 'module.py'
    source.write_bytes(b'value = 7\n')
    domain.compilation(source.read_bytes(), str(source), None)
    domain.execution(compile(source.read_bytes(), str(source), 'exec', dont_inherit=True))
    with pytest.raises(Refused, match='forged source filename'):
        domain.compilation(b'value = 8\n', str(source), None)
    with pytest.raises(Refused, match='differs from immutable source'):
        domain.execution(compile(b'value = 8\n', str(source), 'exec', dont_inherit=True))


def test_unknown_generated_body_and_external_import_are_refused(domain, tmp_path):
    with pytest.raises(Refused, match='compiler caller'):
        domain.compilation('value = 7', '<string>', sys._getframe())
    with pytest.raises(Refused, match='without prepared compilation'):
        domain.execution(compile('value = 7', '<string>', 'exec', dont_inherit=True))
    other = tmp_path / 'foreign.py'
    other.write_text('value = 7\n')
    with pytest.raises(Refused, match='outside immutable inputs'):
        domain.compilation(other.read_bytes(), str(other), None)
    with pytest.raises(Refused, match='extension outside immutable inputs'):
        domain.audit('import', ('foreign', str(other)))


def test_source_alias_cannot_enter_immutable_domain(domain, tmp_path):
    other = tmp_path / 'outside.py'
    other.write_text('value = 7\n')
    alias = domain.roots['source'] / 'alias.py'
    alias.symlink_to(other)
    with pytest.raises(Refused, match='outside immutable inputs'):
        domain.body(str(alias))


def test_exact_compiler_code_globals_and_live_link(domain, monkeypatch):
    source = domain.roots['dependencies'] / 'compiler.py'
    body = b'def build(text):\n    return check(text, "<generated>", __import__("sys")._getframe())\n'
    source.write_bytes(body)
    spec = importlib.util.spec_from_file_location('finite_compiler_control', source)
    module = importlib.util.module_from_spec(spec)
    monkeypatch.setitem(sys.modules, module.__name__, module)
    exec(compile(body, str(source), 'exec', dont_inherit=True), vars(module))
    module.check = domain.compilation
    monkeypatch.setattr(library_code, 'PRODUCERS', (('dependencies', 'compiler.py', module.__name__, 'build'),))
    module.build('value = 7')
    domain.execution(compile('value = 7', '<generated>', 'exec', dont_inherit=True))
    with pytest.raises(Refused, match='without prepared compilation'):
        domain.execution(compile('value = 8', '<generated>', 'exec', dont_inherit=True))
    saved = module.build
    module.build = lambda text: text
    with pytest.raises(Refused, match='function replaced'):
        saved('value = 8')


class EqualityTrap:
    def __eq__(self, other):
        pytest.fail('code comparison executed a caller callback')


@pytest.mark.parametrize('field', ('co_consts', 'co_filename'))
def test_code_metadata_is_checked_before_comparison(domain, field):
    code = compile('value = 7', '<string>', 'exec', dont_inherit=True)
    class Text(str):
        def __eq__(self, other):
            pytest.fail('filename comparison executed a caller callback')
    corrupt = code.replace(**{field: (EqualityTrap(),) if field == 'co_consts' else Text('<string>')})
    with pytest.raises(Refused, match='constant|text type'):
        domain.execution(corrupt)


def test_prepared_source_has_no_product_effect_permission(domain):
    source = domain.roots['source'] / 'module.py'
    source.write_text('value = 7\n')
    domain.execution(compile(source.read_bytes(), str(source), 'exec', dont_inherit=True))
    with pytest.raises(Refused, match='unknown computation event'):
        domain.audit('subprocess.Popen', ())
    with pytest.raises(Refused, match='unknown computation event'):
        domain.audit('socket.connect', ())
    assert hashlib.sha256(source.read_bytes()).hexdigest()


def test_colliding_namespace_key_cannot_call_equality(domain, monkeypatch):
    source = domain.roots['dependencies'] / 'compiler.py'
    source.write_text('def build(text):\n    return check(text, "<generated>", __import__("sys")._getframe())\n')
    spec = importlib.util.spec_from_file_location('finite_collision_compiler', source)
    module = importlib.util.module_from_spec(spec)
    monkeypatch.setitem(sys.modules, module.__name__, module)
    exec(compile(source.read_bytes(), str(source), 'exec', dont_inherit=True), vars(module))
    saved = module.build
    module.check = domain.compilation
    del module.build
    class Collision:
        def __hash__(self):
            return hash('build')
        def __eq__(self, other):
            pytest.fail('namespace lookup invoked caller equality')
    vars(module)[Collision()] = saved
    monkeypatch.setattr(library_code, 'PRODUCERS', (('dependencies', 'compiler.py', module.__name__, 'build'),))
    with pytest.raises(Refused, match='non-string namespace key'):
        saved('value = 7')


def test_forwarding_frame_filename_cannot_call_overridden_prefix(domain):
    class Filename(str):
        def startswith(self, *args):
            pytest.fail('forwarding frame invoked caller method')
    def invoke():
        return domain.audit('compile', (b'value = 7', '<string>'))
    invoke.__code__ = invoke.__code__.replace(co_filename=Filename('/foreign.py'))
    with pytest.raises(Refused, match='forwarding frame filename type'):
        invoke()


def test_ast_snapshot_is_callback_free_and_content_exact():
    import ast
    tree = ast.parse('value = 7\n')
    clone = library_code.copy_ast(tree)
    assert clone is not tree and ast.dump(clone, include_attributes=True) == ast.dump(tree, include_attributes=True)
    tree.body[0].value.value = EqualityTrap()
    with pytest.raises(Refused, match='AST primitive type'):
        library_code.copy_ast(tree)
    class Meta(type):
        def __hash__(self):
            pytest.fail('AST type lookup invoked caller hash')
        def __eq__(self, other):
            pytest.fail('AST type lookup invoked caller equality')
    class Foreign(ast.AST, metaclass=Meta):
        pass
    with pytest.raises(Refused, match='AST primitive type'):
        library_code.copy_ast(Foreign())


def test_original_beartype_ast_is_bound_to_source_and_actual_compile_line(domain, monkeypatch):
    import ast
    source = domain.roots['dependencies'] / 'compiler.py'
    source.write_text('\n' * 496 + 'class BeartypeSourceFileLoader:\n'
        ' def source_to_code(self, data, path, module_ast_beartyped, _optimize=-1):\n'
        '  return check(module_ast_beartyped, None, __import__("sys")._getframe())\n')
    spec = importlib.util.spec_from_file_location('finite_ast_compiler', source)
    module = importlib.util.module_from_spec(spec)
    monkeypatch.setitem(sys.modules, module.__name__, module)
    exec(compile(source.read_bytes(), str(source), 'exec', dont_inherit=True), vars(module))
    module.check = domain.compilation
    monkeypatch.setattr(library_code, 'PRODUCERS', (('dependencies', 'compiler.py', module.__name__, 'BeartypeSourceFileLoader.source_to_code'),))
    target = domain.roots['source'] / 'module.py'
    target.write_bytes(b'value = 7\n')
    loader = module.BeartypeSourceFileLoader()
    tree = ast.parse('value = 7\nextra = True\n')
    loader.source_to_code(target.read_bytes(), str(target), tree)
    domain.execution(compile(tree, str(target), 'exec', dont_inherit=True))
    with pytest.raises(Refused, match='immutable source binding'):
        loader.source_to_code(b'value = 8\n', str(target), tree)
    with pytest.raises(Refused, match='immutable source binding'):
        loader.source_to_code(target.read_bytes(), str(target), tree, 1)


def test_prepared_ast_class_cannot_run_new_descriptors(monkeypatch):
    import ast
    tree = ast.parse('value = 7\n')
    def forbidden(*args):
        pytest.fail('AST snapshot invoked a class descriptor')
    monkeypatch.setattr(ast.Constant, 'value', property(forbidden, forbidden), raising=False)
    with pytest.raises(Refused, match='class descriptor changed'):
        library_code.copy_ast(tree)


def test_transformed_outputs_share_generated_count_and_byte_budget(domain, monkeypatch):
    import ast
    from types import SimpleNamespace
    target = domain.roots['source'] / 'module.py'
    target.write_bytes(b'value = 7\n')
    tree = ast.parse('value = 7\nextra = True\n')
    frame = SimpleNamespace(f_lineno=499, f_locals={'data': target.read_bytes(), 'path': str(target),
                                                 'module_ast_beartyped': tree, '_optimize': 0})
    monkeypatch.setattr(domain, 'producer', lambda supplied: 'BeartypeSourceFileLoader.source_to_code')
    domain.generations = 4096
    with pytest.raises(Refused, match='generation bound'):
        domain.transformation(tree, None, frame)
    domain.generations, domain.bytes = 0, 64 * 1024 * 1024
    with pytest.raises(Refused, match='generation bound'):
        domain.transformation(tree, None, frame)
