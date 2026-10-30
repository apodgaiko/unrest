"""Readiness grants one exact local probe and never application payload."""
import ast
from pathlib import Path
from types import SimpleNamespace

import pytest

from content_manifest import Refused
from launch_policy import source_unit
import readiness_launch as readiness

ROOT=next(p for p in Path(__file__).resolve().parents if (p/'pyproject.toml').is_file())


@pytest.mark.parametrize('case',readiness.CASES[:4])
@pytest.mark.parametrize('mutation',[None,'body','variant','args','env','cwd','descendant'])
def test_exact_original_readiness_program_and_operands(case,mutation):
    unit=source_unit(ROOT,readiness.TEST,readiness.PIN,(readiness.NAME,'exercise'))
    bodies=[ast.literal_eval(node.value) for node in ast.walk(unit) if isinstance(node,ast.Assign)
            and any(isinstance(target,ast.Name) and target.id=='body' for target in node.targets)]
    body=bodies[0 if case==readiness.CASES[2] else 1 if case==readiness.CASES[0] else 2]
    host=SimpleNamespace(case=case,meta={'checkout':str(ROOT)},
        binding={'entry':{'path':'/native','sha256':'a'*64}},intents={})
    def root_only(actor):
        if actor['role']!='root':
            raise Refused('root only')
    host.root_only=root_only
    host.meta_environment=lambda:{'PATH':'/bin'}
    admitted=[]
    host.admit_launch=lambda *args,**kwargs:admitted.append(args) or {'ticket':1,'token':'bound'}
    raw={'case':case,'executable':'/native','argv':['/native','-c',body],
         'environment':{'PATH':'/bin','PYTEST_VERSION':'9.0.2','PYTEST_CURRENT_TEST':case+' (call)'},
         'cwd':str(ROOT),'stdin':None}
    if mutation=='body':
        raw['argv'][2]='print("different")'
    elif mutation=='variant':
        raw['argv'][2]=bodies[1 if case==readiness.CASES[2] else 0]
    elif mutation=='args':
        raw['argv'].append('foreign')
    elif mutation=='env':
        raw['environment']['EXTRA']='not original'
    elif mutation=='cwd':
        raw['cwd']='/foreign'
    actor={'role':'child' if mutation=='descendant' else 'root'}
    if mutation is None:
        assert readiness.proposal(host,actor,raw)['translated']==['/native','-I','-S','-c',body]
        assert len(admitted)==1
    else:
        with pytest.raises(Refused):
            readiness.proposal(host,actor,raw)
        assert not admitted




@pytest.mark.parametrize('status,signals,expected',[(0,(),True),(-15,(15,),True),(-15,(),False),(23,(),True)])
def test_real_child_terminal_status_and_authorized_cleanup_required(status,signals,expected):
    from source_observer import Observer
    from types import SimpleNamespace
    actor={'birth':1,'role':'fixed-inline','case':readiness.CASES[2],'body_ready':True,'signals':signals,'token':'owned'}
    row={'ticket':1,'birth':1,'role':actor['role'],'case':actor['case'],'consumed':True,'token':'owned'}
    actor['intent']=row
    host=SimpleNamespace(intents={1:row},ledger=SimpleNamespace(process=lambda birth:SimpleNamespace(terminal=(1,0,status))))
    assert Observer.completed_child(host,actor) is expected
    host.ledger=SimpleNamespace(process=lambda birth:SimpleNamespace(terminal=None))
    assert not Observer.completed_child(host,actor)
    host.ledger=SimpleNamespace(process=lambda birth:SimpleNamespace(terminal=(1,0,status)))
    assert not Observer.completed_child(host,{**actor,'body_ready':False})


@pytest.mark.parametrize('case',readiness.INLINE)
@pytest.mark.parametrize('mutation',[None,'body','environment','descendant'])
def test_literal_owned_client_leaves_keep_exact_original_body_and_parent(case,mutation):
    from launch_policy import literal,assignment
    path,pin=readiness.INLINE[case]
    unit=source_unit(ROOT,path,pin,(case.split('::')[1],))
    if path==readiness.SESSION:
        body=literal(unit,'code')
    else:
        call=next(n for n in ast.walk(unit) if isinstance(n,ast.Call) and isinstance(n.func,ast.Attribute) and n.func.attr=='create_subprocess_exec')
        secret=ast.literal_eval(assignment(unit,'secret'))
        pieces=[]
        for part in call.args[2].values:
            if isinstance(part,ast.Constant):
                pieces.append(part.value)
            else:
                assert isinstance(part.value,ast.Name) and part.value.id=='secret'
                pieces.append(secret)
        body=''.join(pieces)
    calls=[]
    host=SimpleNamespace(case=case,meta={'checkout':str(ROOT)},binding={'entry':{'path':'/native','sha256':'a'*64}},
        root_only=lambda actor:None if actor['role']=='root' else (_ for _ in ()).throw(Refused('owner')),
        meta_environment=lambda:{'PATH':'/bin'},admit_launch=lambda *args,**kwargs:calls.append(args) or {'ticket':1})
    raw={'case':case,'argv':['/native','-c',body],'executable':'/native','cwd':str(ROOT),'stdin':None,
         'environment':{'PATH':'/bin','PYTEST_VERSION':'9.0.2','PYTEST_CURRENT_TEST':case+' (call)'}}
    if mutation=='body':
        raw['argv'][2]+='; print("foreign")'
    elif mutation=='environment':
        raw['environment']['EXTRA']='foreign'
    if mutation:
        with pytest.raises(Refused):
            readiness.proposal(host,{'role':'child' if mutation=='descendant' else 'root'},raw)
        assert not calls
    else:
        assert readiness.proposal(host,{'role':'root'},raw)['translated']==['/native','-I','-S','-c',body]
        assert calls[0][2]==('session-inline' if case.endswith('::test_sigterm_ignoring_owned_process_is_killed_and_reaped') else 'fixed-inline')
