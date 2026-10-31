"""Readiness grants one exact local probe and never application payload."""
import ast
from pathlib import Path
from types import SimpleNamespace

import pytest

from content_manifest import Refused
from launch_policy import source_unit
import inline_leaves as readiness

ROOT=next(p for p in Path(__file__).resolve().parents if (p/'pyproject.toml').is_file())


@pytest.mark.parametrize('case',readiness.READINESS_CASES[:4])
@pytest.mark.parametrize('mutation',[None,'body','variant','args','env','cwd','descendant'])
def test_exact_original_readiness_program_and_operands(case,mutation):
    unit=source_unit(ROOT,readiness.READINESS_TEST,readiness.PIN,(readiness.NAME,'exercise'))
    bodies=[ast.literal_eval(node.value) for node in ast.walk(unit) if isinstance(node,ast.Assign)
            and any(isinstance(target,ast.Name) and target.id=='body' for target in node.targets)]
    body=bodies[0 if case==readiness.READINESS_CASES[2] else 1 if case==readiness.READINESS_CASES[0] else 2]
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
        raw['argv'][2]=bodies[1 if case==readiness.READINESS_CASES[2] else 0]
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




@pytest.mark.parametrize('status,signals,expected',[(0,(),True),(-15,(15,),True),(-15,(),False),(-9,(9,),True),(-9,(),False),(23,(),True)])
def test_real_child_terminal_status_and_authorized_cleanup_required(status,signals,expected):
    from source_observer import Observer
    from types import SimpleNamespace
    actor={'birth':1,'role':'fixed-inline','case':readiness.READINESS_CASES[2],'body_ready':True,'signals':signals,'token':'owned'}
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


@pytest.mark.parametrize('case',readiness.LEASES)
@pytest.mark.parametrize('mutation',[None,'body','args','env','cwd','alias','owner','stdin','second'])
def test_lease_child_is_exact_owned_session_with_one_constructor(tmp_path,monkeypatch,mutation,case):
    import hashlib
    import os
    from source_observer import Observer
    unit=ast.parse((ROOT/case.split('::')[0]).read_bytes())
    function=next(node for node in unit.body if isinstance(node,ast.FunctionDef) and node.name==case.split('::')[1].split('[')[0])
    argv=next(node for node in ast.walk(function) if isinstance(node,ast.List) and len(node.elts)==3
              and isinstance(node.elts[1],ast.Constant) and node.elts[1].value=='-c')
    body=ast.literal_eval(argv.elts[2])
    assert hashlib.sha256(body.encode()).hexdigest()==readiness.PROGRAM_PINS[case]
    monkeypatch.setattr(readiness,'OWNER',os.getuid())
    cwd=tmp_path/'pytest'/'lease'
    cwd.mkdir(parents=True)
    host=object.__new__(Observer)
    host.case,host.serial,host.root_birth=case,0,'root-birth'
    host.meta={'checkout':str(ROOT),'owned':str(tmp_path)}
    host.binding={'entry':{'path':'/native','sha256':'a'*64}}
    host.intents,host.fixture_roots={},{}
    host.meta_environment=lambda:{'PATH':'/bin'}
    host.root_only=lambda actor:None if actor['role']=='root' else (_ for _ in ()).throw(Refused('owner'))
    actor={'role':'root','birth':'root-birth'}
    raw={'case':case,'argv':['/native','-c',body],'executable':'/native','cwd':str(cwd),'stdin':None,'environment':{}}
    if mutation=='body':
        raw['argv'][2]+='; print("foreign")'
    elif mutation=='args':
        raw['argv'].append('foreign')
    elif mutation=='env':
        raw['environment']['PATH']='/bin'
    elif mutation=='cwd':
        raw['cwd']=str(tmp_path)
    elif mutation=='alias':
        alias=tmp_path/'pytest'/'alias'
        alias.symlink_to(cwd,target_is_directory=True)
        raw['cwd']=str(alias)
    elif mutation=='owner':
        actor['role']='child'
    elif mutation=='stdin':
        raw['stdin']='foreign'
    if mutation in (None,'second'):
        answer=readiness.proposal(host,actor,raw)
        assert answer['translated']==['/native','-I','-S','-c',body]
        row=host.intents[answer['ticket']]
        assert row['role']=='session-inline' and row['parent']=='root-birth'
        assert row['environment']=={} and row['cwd']==str(cwd)
        if mutation=='second':
            with pytest.raises(Refused,match='independent launch'):
                readiness.proposal(host,actor,raw)
            assert len(host.intents)==1
    else:
        with pytest.raises(Refused):
            readiness.proposal(host,actor,raw)
        assert not host.intents


def test_injected_spawn_failure_has_no_child_declaration():
    case='tests/test_experimental_lease.py::test_close_waits_for_launch_registration[spawn_failure]'
    assert case not in readiness.LEASES and case not in readiness.CASES
    host=SimpleNamespace(case=case,root_only=lambda actor:None)
    with pytest.raises(Refused,match='original leaf'):
        readiness.proposal(host,{'role':'root'},{'stdin':None})
