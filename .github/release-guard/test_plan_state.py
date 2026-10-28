"""Fabricated exec-state controls; actual native execution remains separate."""
from pathlib import Path
from types import SimpleNamespace
import os

import pytest

from content_manifest import Refused
import plan_launch
import plan_observer
from plan_launch import CASES,expected
from test_process_ledger import identity,emit,PINS,SEAL
from process_ledger import Ledger,Birth


@pytest.fixture
def state(tmp_path,monkeypatch):
    monkeypatch.setattr(plan_launch,'OWNER',os.getuid())
    monkeypatch.setattr(plan_launch,'shell',lambda:('/sealed/dash','b'*64))
    root=tmp_path/'pytest/case'
    (root/'blocked/adapter').mkdir(parents=True)
    (root/'selected').mkdir()
    file=root/'selected/adapter'
    file.write_bytes(b'#!/bin/sh\nprintf selected > "$1"\n')
    file.chmod(0o700)
    model=expected(CASES[4],str(root),tmp_path,'/sealed/python','a'*64)
    ledger=Ledger('nonce')
    parent_identity,child_identity=identity(100,99),identity(101,100)
    parent,child=Birth.read(parent_identity),Birth.read(child_identity)
    emit(ledger,'kernel_root',identity=parent_identity)
    ledger.register(parent,'root-token',PINS,SEAL,case=CASES[4],command_class='root')
    emit(ledger,'kernel_child',parent=100,child=101,event=1,identity=child_identity)
    value={'case':CASES[4],'role':'plan-native','parent':parent,'translated':list(model.vector),
           'environment':dict(model.expected.environment),'cwd':str(root),'token':'plan-token',
           'consumed':False,'plan':model,'plan_stage':0,'plan_pending':None,'plan_pid':None,
           'plan_script_key':plan_observer.key(file),'plan_parent_key':plan_observer.key(file.parent)}
    host=SimpleNamespace(case=CASES[4],intents={1:value},ledger=ledger,root_birth=parent,actors={},plan_records=[],
        meta={'owned':str(tmp_path)},binding={'entry':{'path':'/sealed/python','sha256':'a'*64}},
        consume=lambda trace:None,stdio=lambda pid,role:(1,2))
    process=identity(child.pid,parent.pid)
    process['namespaces']={'mnt':'sealed-namespace'}
    monkeypatch.setattr(plan_observer,'process_identity',lambda pid:process)
    original_readlink=os.readlink
    monkeypatch.setattr(os,'readlink',lambda file,*args,**kwargs:'sealed-namespace' if str(file)=='/proc/self/ns/mnt' else original_readlink(file,*args,**kwargs))
    return host,value,child,model


def resolve(host,child,model,path):
    return plan_observer.resolve(host,SimpleNamespace(records=[]),child.pid,path,list(model.vector),dict(model.expected.environment),model.expected.cwd)


def test_failed_candidate_requires_actual_exact_errno_before_selected_path(state):
    host,value,child,model=state
    assert resolve(host,child,model,model.attempts[0])
    assert not value['consumed'] and value['plan_pending']=='blocked'
    plan_observer.consume(host,{'kind':'exec_syscall_return','pid':child.pid,'return':-13})
    assert value['plan_stage']==1 and value['plan_pending'] is None
    assert resolve(host,child,model,model.attempts[1])
    assert value['consumed'] and host.actors[child.pid]['kernel_admitted'] and not host.actors[child.pid]['body_ready']


@pytest.mark.parametrize('event',[{'kind':'exec_syscall_return','return':-2},
                                 {'kind':'exec_syscall_return','return':0},
                                 {'kind':'exec_syscall_return','return':-13,'denied':True},
                                 {'kind':'kernel_exec'}])
def test_unexpected_failed_candidate_outcome_refuses(state,event):
    host,_,child,model=state
    resolve(host,child,model,model.attempts[0])
    with pytest.raises(Refused):
        plan_observer.consume(host,{**event,'pid':child.pid})


def test_repeated_or_early_second_attempt_is_not_a_failed_exec_allowlist(state):
    host,_,child,model=state
    assert not resolve(host,child,model,model.attempts[1])
    resolve(host,child,model,model.attempts[0])
    for path in model.attempts:
        with pytest.raises(Refused):
            resolve(host,child,model,path)


def test_same_body_replacement_does_not_borrow_script_generation(state):
    host,_,child,model=state
    file=Path(model.expected.executable)
    body=file.read_bytes()
    file.unlink()
    file.write_bytes(body)
    file.chmod(0o700)
    with pytest.raises(Refused):
        resolve(host,child,model,model.attempts[0])


def test_extra_candidate_after_real_failure_refuses(state):
    host,_,child,model=state
    resolve(host,child,model,model.attempts[0])
    plan_observer.consume(host,{'kind':'exec_syscall_return','pid':child.pid,'return':-13})
    assert not resolve(host,child,model,model.attempts[0])
    assert not resolve(host,child,model,str(Path(model.expected.cwd)/'decoy/adapter'))


def test_empty_environment_name_is_literal_and_unknown_additions_still_refuse():
    from dataclasses import replace
    from launch_policy import Rule,Observation,render,match
    rule=Rule('empty','owner',('case',),'/usr/bin/true','a'*64,('/usr/bin/true',),
              (('','empty-name'),('VALUE','before=after')),'/owned','native')
    value=render(rule,'case','owner',{}, {})
    observed=Observation(value.executable,value.executable_sha256,value.argv,value.environment,value.cwd,value.payload_kind,value.payload_sha256)
    assert match((value,),observed,'owner','case')==value
    with pytest.raises(Refused):
        match((value,),replace(observed,environment=(*observed.environment,('OTHER','value'))),'owner','case')


def test_constructor_no_session_variant_requires_key_absence():
    from session_calls import constructor_options
    environment=object()
    plan={'cwd':'/owned','argv':('adapter',),'environment':environment}
    values={'program':'adapter','args':(),'kwds':{'cwd':'/owned','env':environment},
            'stdin':-1,'stdout':-1,'stderr':-1,'limit':65536}
    constructor_options(values,plan,65536,session=False)
    values['kwds']['start_new_session']=False
    with pytest.raises(Refused):
        constructor_options(values,plan,65536,session=False)


def test_policy_popen_reaches_exact_selector_for_one_element_plan_vector():
    from source_entry import Policy
    class Reached(RuntimeError):
        pass
    selected=[]
    def select(case,arguments):
        selected.append((case,arguments))
        raise Reached
    policy=object.__new__(Policy)
    policy.profile={'role':'root'}
    policy.case=CASES[0]
    policy.calls=SimpleNamespace(startup=SimpleNamespace(select=select))
    with pytest.raises(Reached):
        policy.popen(('adapter',['adapter'],'/owned',{}))
    assert len(selected)==1 and selected[0][0]==CASES[0]


def test_unknown_one_element_vector_is_sticky_after_exact_selector_refusal():
    from source_entry import Policy
    calls=[]
    def select(case,arguments):
        assert arguments[1]==['foreign']
        raise Refused('synthetic exact selector rejects vector')
    policy=object.__new__(Policy)
    policy.profile={'role':'root'}
    policy.case=CASES[0]
    policy.calls=SimpleNamespace(startup=SimpleNamespace(select=select))
    policy.client=SimpleNamespace(request=lambda kind,payload:calls.append(kind))
    policy.poison=False
    with pytest.raises(Refused):
        policy.audit('subprocess.Popen',('foreign',['foreign'],'/owned',{}))
    assert policy.poison and calls==['guard-refusal']


def test_host_accepts_preflight_selector_before_binding_and_refuses_unknown(tmp_path,monkeypatch):
    import sys
    import source_host
    monkeypatch.setattr(sys,'platform','linux')
    monkeypatch.setattr(os,'getuid',lambda:0)
    monkeypatch.setattr(sys,'path',list(sys.path))
    monkeypatch.setattr(sys,'argv',['source_host.py',str(tmp_path/'absent.json'),'preflight9'])
    with pytest.raises(FileNotFoundError):
        source_host.main()
    monkeypatch.setattr(sys,'argv',['source_host.py',str(tmp_path/'absent.json'),'unknown'])
    with pytest.raises(RuntimeError,match='exact root Linux invocation'):
        source_host.main()
