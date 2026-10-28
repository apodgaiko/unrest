"""Literal policy controls; unused expression syntax is explicitly retired."""
from __future__ import annotations

from dataclasses import replace
import hashlib
from pathlib import Path
import sys

import pytest

sys.path.insert(0, str(Path(__file__).parent))
import launch_policy as policy

CASE, OWNER, IMAGE = "tests/test_example.py::test_launch[work]", "source-owner-v1", "a" * 64


def rule(**changes):
    base = policy.Rule("role", OWNER, (CASE,), "/runtime/python", IMAGE,
                       ("python", "-I", "-S", "-c", "print('finite')"),
                       (("MODE", "controlled"),), "/source", "python-command")
    return replace(base, **changes)


def expected(spec=None, values=None, roots=None):
    return policy.render(spec or rule(), CASE, OWNER, values or {}, roots or {})




def test_literal_render_separates_image_path_and_argv0():
    value = expected()
    assert value.executable == "/runtime/python" and value.argv[0] == "python"
    assert value.payload_sha256 == hashlib.sha256(value.argv[4].encode()).hexdigest()


def test_literal_program_has_no_substitution_or_evaluation():
    body = "path=\"/owned/quote'\\n;not_code\"; role='${role}'"
    value = expected(rule(argv=('python', '-c', body)))
    assert value.argv[2] == body
    assert value.payload_sha256 == hashlib.sha256(body.encode()).hexdigest()
    with pytest.raises(policy.Refused):
        expected(rule(argv=('python', '-c', body)), values={'role': "';forbidden()"})


def test_literal_flags_and_environment_are_not_interpreted():
    value = expected(rule(argv=('python', '-B', '-c', 'pass'),
        environment=(('OPTION', 'role=${role}; $(forbidden)'),)))
    assert value.argv == ('python', '-B', '-c', 'pass')
    assert value.environment == (('OPTION', 'role=${role}; $(forbidden)'),)


@pytest.mark.parametrize("kind,argv,pin", [
    ("python-script", ("python", "-I", "/source/fixture.py"), "b" * 64),
    ("python-module", ("python", "-m", "unrest_harness.server"), "b" * 64),
    ("native", ("git", "status", "--short"), None),
    ("expected-exec-failure", ("bad-format",), None)])
def test_payload_modes_keep_external_content_and_failed_exec_distinct(kind, argv, pin):
    value = expected(rule(payload_kind=kind, argv=argv, payload_sha256=pin))
    assert value.payload_sha256 == (pin or IMAGE)






@pytest.mark.parametrize('field', ('argv', 'environment', 'cwd', 'executable'))
@pytest.mark.parametrize('value', (True, 1, b'value', ('nested',), {'slot': 'value'}, object()))
def test_nonprimitive_fields_and_expression_objects_refuse(field, value):
    change = {'argv': ('python', '-c', value)} if field == 'argv' else (
        {'environment': (('VALUE', value),)} if field == 'environment' else {field: value})
    with pytest.raises(policy.Refused):
        expected(rule(**change))


@pytest.mark.parametrize("changes", [
    {"environment": (("MODE", "controlled"), ("MODE", "controlled"))},
    {"environment": (("BAD=KEY", "x"),)},
    {"cases": (CASE, CASE)}, {"cases": (CASE, [])},
    {"payload_sha256": "b" * 64},
    {"payload_kind": "python-script"},
    {"argv": ("python", "-c", ("pass",))},
    {"argv": ("python", "-m", "invalid/module"), "payload_kind": "python-module",
     "payload_sha256": "b" * 64},
    {"argv": ("python", "relative.py"), "payload_kind": "python-script",
     "payload_sha256": "b" * 64}])
def test_invalid_declarations_never_render(changes):
    with pytest.raises(policy.Refused):
        policy.render(rule(**changes), CASE, OWNER, {}, {})


def test_inline_program_cannot_be_a_context_slot():
    with pytest.raises(policy.Refused, match='unused_context'):
        expected(rule(argv=('python', '-c', object())), values={'code': 'pass'})






def test_external_payload_reference_and_absolute_root():
    with pytest.raises(policy.Refused, match='external_payload_reference'):
        expected(rule(argv=('python', '/source/script.py'), payload_kind='python-script',
                      payload_sha256='not-a-digest'))
    assert expected(rule(cwd='/child')).cwd == '/child'
    assert expected(rule(cwd='/')).cwd == '/'


def test_literal_vector_environment_and_aggregate_bounds(monkeypatch):
    with pytest.raises(policy.Refused):
        expected(rule(argv=('python',) * (policy.MAX_ARGUMENTS + 1)))
    with pytest.raises(policy.Refused):
        expected(rule(environment=(('MODE', 'one'), ('MODE', 'two'))))
    with monkeypatch.context() as context:
        context.setattr(policy, 'MAX_DECLARATION_BYTES', 256)
        with pytest.raises(policy.Refused, match='declaration_bound'):
            expected(rule(environment=(('VALUE', 'x' * 200),)))
    with monkeypatch.context() as context:
        context.setattr(policy, 'MAX_TEXT_BYTES', 100)
        with pytest.raises(policy.Refused, match='text_bound'):
            expected(rule(environment=(('VALUE', 'x' * 101),)))


def test_extra_context_and_all_finite_bounds_refuse(monkeypatch):
    with pytest.raises(policy.Refused, match='unused_context'):
        expected(values={'extra': 'ignored'})
    with pytest.raises(policy.Refused, match='unused_context'):
        expected(roots={'extra': '/owned'})
    for name in ('MAX_ARGUMENTS', 'MAX_TEXT_BYTES', 'MAX_VECTOR_BYTES', 'MAX_FIELDS', 'MAX_DECLARATION_BYTES'):
        with monkeypatch.context() as context:
            context.setattr(policy, name, 1)
            with pytest.raises(policy.Refused):
                expected()
    nested = 'value'
    for _ in range(100):
        nested = (nested,)
    with pytest.raises(policy.Refused):
        expected(rule(environment=(('MODE', nested),)))


@pytest.mark.parametrize('field', ('argv', 'environment', 'cwd', 'executable', 'cases'))
def test_nonliteral_callbacks_never_run(field):
    class Trap(str):
        def __str__(self):
            pytest.fail('coercion executed')
        def __eq__(self, other):
            pytest.fail('equality executed')
        __hash__ = str.__hash__
    value = Trap('value')
    change = {'argv': ('python', '-c', value)} if field == 'argv' else (
        {'environment': (('VALUE', value),)} if field == 'environment' else (
        {'cases': (CASE, value)} if field == 'cases' else {field: value}))
    with pytest.raises(policy.Refused):
        expected(rule(**change))


@pytest.mark.parametrize('cwd', ('relative', '//owned', '/owned//child', '/owned/../other', False, Path('/owned')))
def test_literal_cwd_is_primitive_and_canonical(cwd):
    with pytest.raises(policy.Refused):
        expected(rule(cwd=cwd))


@pytest.mark.parametrize('value', ('bad\0value', '\ud800'))
def test_literal_text_rejects_nul_and_unencodable_values(value):
    with pytest.raises(policy.Refused):
        expected(rule(environment=(('VALUE', value),)))


@pytest.mark.parametrize('context', (False, True, [], (), object(), {'extra': 'value'}))
def test_substitution_context_types_and_nonempty_contexts_are_rejected(context):
    with pytest.raises(policy.Refused):
        policy.render(rule(), CASE, OWNER, context, {})
    with pytest.raises(policy.Refused):
        policy.render(rule(), CASE, OWNER, {}, context)
