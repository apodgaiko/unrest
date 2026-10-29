"""Shared extraction selects authored owners only after verifying complete bytes."""
import ast
import hashlib

import pytest

from content_manifest import Refused
from launch_policy import source_unit,assignment,literal


def write(tmp_path,body):
    path=tmp_path/'original.py'
    path.write_text(body)
    return hashlib.sha256(path.read_bytes()).hexdigest()


def test_exact_qualified_owner_and_literal_are_preserved(tmp_path):
    pin=write(tmp_path,'class Original:\n def scenario(self):\n  script="literal body"\n')
    unit=source_unit(tmp_path,'original.py',pin,('Original','scenario'))
    assert isinstance(unit,ast.FunctionDef)
    assert literal(unit,'script')=='literal body'


@pytest.mark.parametrize('body',[
    'def scenario():\n script="first"\n script="second"\n',
    'def scenario():\n script=f"{unknown}"\n',
    'def scenario():\n script=call()\n',
    'def scenario():\n script=123\n',
    'def scenario():\n other="foreign"\n',
])
def test_unlisted_or_ambiguous_value_is_not_a_literal(body,tmp_path):
    pin=write(tmp_path,body)
    unit=source_unit(tmp_path,'original.py',pin,('scenario',))
    with pytest.raises(Refused):
        literal(unit,'script')


@pytest.mark.parametrize('body',[
    'def scenario(): pass\ndef scenario(): pass\n',
    'class Other:\n def scenario(self): pass\n',
])
def test_ambiguous_or_foreign_owner_is_not_selected(body,tmp_path):
    pin=write(tmp_path,body)
    with pytest.raises(Refused):
        source_unit(tmp_path,'original.py',pin,('scenario',))


def test_drift_is_refused_before_parsing_or_evaluating(tmp_path):
    pin=write(tmp_path,'script="original"\n')
    (tmp_path/'original.py').write_text('this is not valid Python !!!')
    with pytest.raises(Refused,match='source bytes'):
        source_unit(tmp_path,'original.py',pin)


def test_nonliteral_template_is_only_returned_as_an_unevaluated_ast(tmp_path):
    pin=write(tmp_path,'script=f"literal {untrusted!r}"\n')
    unit=source_unit(tmp_path,'original.py',pin)
    assert isinstance(assignment(unit,'script'),ast.JoinedStr)
