"""Shared refusals retain truth testing, original exceptions and sticky effects."""
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from content_manifest import Refused, refuse_if


@pytest.mark.parametrize('invalid',(False,None,0,'',[],{},True,1,'invalid',[1],{'invalid':True}))
def test_preconditions_use_ordinary_truth_without_assert_or_exception_translation(invalid):
    if invalid:
        with pytest.raises(Refused) as error:
            refuse_if(invalid,'original-code')
        assert type(error.value) is Refused and error.value.args==('original-code',)
    else:
        assert refuse_if(invalid,'original-code') is None


@pytest.mark.parametrize('value',(False,True))
def test_a_callback_result_is_truth_tested_once(value):
    seen=[]
    class Truth:
        def __bool__(self):
            seen.append(value)
            return value
    if value:
        with pytest.raises(Refused):
            refuse_if(Truth(),'one-truth-test')
    else:
        refuse_if(Truth(),'one-truth-test')
    assert seen==[value]


def test_truth_callback_exceptions_are_preserved():
    original=RuntimeError('truth failure')
    class Truth:
        def __bool__(self):
            raise original
    with pytest.raises(RuntimeError) as error:
        refuse_if(Truth(),'not-a-refusal')
    assert error.value is original


def test_refusal_keeps_the_active_exception_context():
    original=RuntimeError('active context')
    try:
        raise original
    except RuntimeError:
        with pytest.raises(Refused) as error:
            refuse_if(True,'same-context')
    assert error.value.__context__ is original
    assert error.value.__cause__ is None and not error.value.__suppress_context__


@pytest.mark.parametrize('operator',('==','!='))
@pytest.mark.parametrize('result',(False,True))
def test_single_rich_comparisons_keep_their_evaluation_order(operator,result):
    def evaluate(converted):
        seen=[]
        class Truth:
            def __bool__(self):
                seen.append('truth')
                return result
        class Operand:
            def __eq__(self,other):
                seen.append('compare')
                return Truth()
            __ne__=__eq__
        predicate='left '+operator+' right'
        code=('refuse_if('+predicate+', "same")' if converted else
            'if '+predicate+':\n    raise Refused("same")')
        try:
            exec(code,{'left':Operand(),'right':object(),'refuse_if':refuse_if,'Refused':Refused})
        except Refused as error:
            return seen,error.args
        return seen,None
    assert evaluate(False)==evaluate(True)


def test_optimized_interpreter_keeps_refusals_enabled():
    support=Path(__file__).resolve().parent
    code=f'''import sys
sys.path.insert(0,{str(support)!r})
from content_manifest import Refused,refuse_if
try:
    refuse_if(True,'optimized-refusal')
except Refused:
    raise SystemExit(37)
raise SystemExit(0)
'''
    result=subprocess.run([sys.executable,'-O','-I','-S','-c',code],capture_output=True,timeout=5)
    assert result.returncode==37 and result.stdout==result.stderr==b''


def test_a_caught_shared_refusal_still_poisons_the_real_source_audit():
    from source_entry import Policy
    policy=object.__new__(Policy)
    policy.poison=False
    reports=[]
    policy.client=SimpleNamespace(request=lambda kind,payload:reports.append((kind,payload)))
    policy.popen=lambda arguments:refuse_if(True,'shared-refusal')
    with pytest.raises(Refused,match='shared-refusal'):
        policy.audit('subprocess.Popen',())
    assert policy.poison and reports==[('guard-refusal',{'code':'shared-refusal'})]
