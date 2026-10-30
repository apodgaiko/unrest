"""Only the exact registered-child regression can TERM its current own session."""
from types import SimpleNamespace

import pytest

from content_manifest import Refused
from process_ledger import Birth
from run_worker_launch import REGISTERED,self_group
from test_process_ledger import identity


@pytest.mark.parametrize('mutation',[None,'case','actor-case','role','ready','session','pgid','sid','child-ready','child-role','float','signal','prior-signal','unbound'])
def test_registered_group_requires_real_current_owner_and_one_ready_child(monkeypatch,mutation):
    actual={**identity(17,16),'pgid':17,'sid':17}
    birth=Birth.read(actual)
    child_birth=Birth.read(identity(18,17))
    row={'ticket':1,'case':REGISTERED,'role':'fixed-inline','birth':birth,'token':'owner','consumed':True,'run_worker':True}
    actor={key:row[key] for key in ('case','role','birth','token')}
    actor.update(intent=row,body_ready=True,signals={15})
    child={'case':REGISTERED,'role':'session-child','birth':child_birth,'body_ready':True}
    process=SimpleNamespace(new_session=True,session_complete=True,parent=None)
    host=SimpleNamespace(case=REGISTERED,intents={1:row},actors={17:actor,18:child},executed=lambda row:True,
        ledger=SimpleNamespace(process=lambda target:process if target==birth else SimpleNamespace(parent=birth)))
    import linux_observation
    import composed_adoption
    calls=[]
    monkeypatch.setattr(linux_observation,'process_identity',lambda pid:actual)
    monkeypatch.setattr(composed_adoption,'record_group',lambda *args:calls.append(args))
    payload={'signal':15}
    if mutation=='case':
        host.case='foreign'
    elif mutation=='actor-case':
        actor['case']='foreign'
    elif mutation=='role':
        actor['role']='root'
    elif mutation=='ready':
        actor['body_ready']=False
    elif mutation=='session':
        process.session_complete=False
    elif mutation in ('pgid','sid'):
        actual[mutation]+=1
    elif mutation=='child-ready':
        child['body_ready']=False
    elif mutation=='child-role':
        child['role']='approval-backend'
    elif mutation=='float':
        payload['signal']=15.0
    elif mutation=='signal':
        payload['signal']=9
    elif mutation=='prior-signal':
        actor['signals'].clear()
    elif mutation=='unbound':
        actor['intent']=dict(row)
    if mutation:
        with pytest.raises(Refused):
            self_group(host,actor,payload)
        assert not calls
    else:
        assert self_group(host,actor,payload)=={'ok':True} and calls==[(host,actor,15)]


@pytest.mark.parametrize('mutation',[None,'case','role','signal','pid','not-group'])
def test_source_group_wrapper_has_no_generic_self_signal_authority(tmp_path,monkeypatch,mutation):
    import os
    import subprocess
    from source_entry import Policy
    calls=[]
    requests=[]
    for obj,name in ((subprocess.Popen,'__init__'),(subprocess,'run'),(os,'kill'),(os,'killpg')):
        monkeypatch.setattr(obj,name,getattr(obj,name))
    monkeypatch.setattr(os,'killpg',lambda pid,sig:calls.append((pid,sig)))
    monkeypatch.setattr(os,'kill',lambda pid,sig:calls.append((pid,sig)))
    def request(kind,payload):
        requests.append((kind,payload))
        return {'ok':True}
    policy=Policy(tmp_path,{'role':'root' if mutation=='role' else 'fixed-inline'},{},SimpleNamespace(request=request))
    policy.case='foreign' if mutation=='case' else REGISTERED
    policy.install_process_hooks()
    pid=os.getpid()+int(mutation=='pid')
    sig=9 if mutation=='signal' else 15
    send=os.kill if mutation=='not-group' else os.killpg
    if mutation:
        with pytest.raises(Refused):
            send(pid,sig)
        assert not calls and policy.poison
    else:
        send(pid,sig)
        assert calls==[(pid,15)] and requests==[('self-group',{'signal':15})]
        assert policy.local.signal is None
