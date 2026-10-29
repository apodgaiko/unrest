"""Literal policy controls; unused expression syntax is explicitly retired."""
from __future__ import annotations

import hashlib
from pathlib import Path
import sys

import pytest

sys.path.insert(0, str(Path(__file__).parent))
import launch_policy as policy
from effect_proposals import proposal_operands
from control_transport import encode,REQUEST_LIMIT,unique

CASE, IMAGE = "tests/test_example.py::test_launch[work]", "a" * 64


def rule(**changes):
    return {"case": CASE, "executable": "/runtime/python",
            "executable_sha256": IMAGE, "argv": ("python", "-I", "-S", "-c", "print('finite')"),
            "environment": (("MODE", "controlled"),), "cwd": "/source",
            "payload_kind": "python-command", **changes}



def expected(spec=None):
    return policy.build_expected(**(spec or rule()))


def test_literal_render_separates_image_path_and_argv0():
    value = expected()
    assert value.executable == "/runtime/python" and value.argv[0] == "python"
    assert value.payload_sha256 == hashlib.sha256(value.argv[4].encode()).hexdigest()


def test_literal_program_has_no_substitution_or_evaluation():
    body = "path=\"/owned/quote'\\n;not_code\"; role='${role}'"
    value = expected(rule(argv=('python', '-c', body)))
    assert value.argv[2] == body
    assert value.payload_sha256 == hashlib.sha256(body.encode()).hexdigest()



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
    value = expected(rule(payload_kind=kind, argv=argv, reference=pin))
    assert value.payload_sha256 == (pin or IMAGE)






def raw(**changes):
    return {'case':CASE,'executable':'python','argv':['python','-c','pass'],
            'environment':{'MODE':'controlled'},'cwd':'/source','stdin':None,**changes}


@pytest.mark.parametrize('field', ('argv', 'environment', 'cwd', 'executable'))
@pytest.mark.parametrize('value', (True, 1, b'value', ('nested',), {'slot':'value'}, object()))
def test_actual_proposal_ingress_refuses_nonprimitive_fields(field,value):
    change={'argv':['python','-c',value]} if field=='argv' else (
        {'environment':{'VALUE':value}} if field=='environment' else {field:value})
    with pytest.raises(policy.Refused):
        proposal_operands(raw(**change),CASE)


def test_payload_kind_must_match_the_declared_interpreter_mode():
    with pytest.raises(policy.Refused,match='payload_mode_mismatch'):
        expected(rule(payload_kind='python-script'))


def test_external_payload_reference_and_absolute_root():
    with pytest.raises(policy.Refused, match='external_payload_reference'):
        expected(rule(argv=('python', '/source/script.py'), payload_kind='python-script',
                      reference='not-a-digest'))
    assert expected(rule(cwd='/child')).cwd == '/child'
    assert expected(rule(cwd='/')).cwd == '/'


def test_actual_proposal_and_frame_bounds_are_enforced_once():
    with pytest.raises(policy.Refused):
        proposal_operands(raw(argv=['python']*257),CASE)
    with pytest.raises(policy.Refused):
        proposal_operands(raw(environment={'BAD=KEY':'x'}),CASE)
    with pytest.raises(policy.Refused):
        unique([('MODE','one'),('MODE','two')])
    with pytest.raises(policy.Refused):
        encode(raw(environment={'VALUE':'x'*REQUEST_LIMIT}),REQUEST_LIMIT)
    nested='value'
    for _ in range(100):
        nested=[nested]
    with pytest.raises(policy.Refused):
        proposal_operands(raw(environment={'MODE':nested}),CASE)
    assert proposal_operands(raw(environment={'':'empty-name','VALUE':'before=after'}),CASE)==['python','-c','pass']


@pytest.mark.parametrize('field', ('argv', 'environment', 'cwd', 'executable', 'case'))
def test_nonliteral_callbacks_never_run(field):
    class Trap(str):
        def __str__(self):
            pytest.fail('coercion executed')
        def __eq__(self, other):
            pytest.fail('equality executed')
        __hash__ = str.__hash__
    value = Trap('value')
    change = {'argv': ['python', '-c', value]} if field == 'argv' else (
        {'environment': {'VALUE': value}} if field == 'environment' else (
        {'case': value} if field == 'case' else {field: value}))
    with pytest.raises(policy.Refused):
        proposal_operands(raw(**change),CASE)


@pytest.mark.parametrize('cwd', ('relative', '//owned', '/owned//child', '/owned/../other', False, Path('/owned')))
def test_literal_cwd_is_primitive_and_canonical(cwd):
    with pytest.raises(policy.Refused):
        proposal_operands(raw(cwd=cwd),CASE)


@pytest.mark.parametrize('value', ('bad\0value', '\ud800'))
def test_literal_text_rejects_nul_and_unencodable_values(value):
    with pytest.raises(policy.Refused):
        proposal_operands(raw(environment={'VALUE':value}),CASE)


@pytest.mark.parametrize('extra', ('owner', 'cases', 'values', 'roots'))
def test_retired_context_is_not_a_constructor_input(extra):
    with pytest.raises(TypeError):
        policy.build_expected(**{**rule(), extra: {}})
