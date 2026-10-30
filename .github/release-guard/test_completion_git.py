"""Finite original Git operands and seed-generation custody; model controls only."""
import os
import re
from pathlib import Path
from types import SimpleNamespace

import pytest

from content_manifest import Refused
import git_policy as git
import completion_roles as roles
from git_policy import HOME_CONFIG
import git_policy as git_observer


@pytest.fixture
def fixture(tmp_path,monkeypatch):
    case=next(iter(roles.CASES))
    base=tmp_path/'pytest'/(re.sub(r'[\W]','_',case.split('::')[1])[:30]+'0')
    workspace=base/'workspace'
    workspace.mkdir(parents=True)
    home=tmp_path/'home'
    home.mkdir()
    (home/'.gitconfig').write_bytes(HOME_CONFIG)
    monkeypatch.setattr(roles,'OWNER',os.getuid())
    monkeypatch.setattr(git_observer,'image',lambda:'a'*64)
    def repository(path,owned):
        root=Path(path)
        assert root.resolve()==root and root.is_relative_to(owned/'pytest')
    monkeypatch.setattr(git,'custody_repository',repository)
    parent=object()
    host=SimpleNamespace(case=case,root_birth=parent,meta={'owned':str(tmp_path)},fixture_roots={},intents={},actors={})
    host.meta_environment=lambda:{'HOME':str(home),'TMPDIR':str(tmp_path/'tmp'),'PATH':'/usr/bin:/bin'}
    host.root_only=lambda actor:None if actor['birth'] is parent else pytest.fail('foreign root')
    host.ledger=SimpleNamespace(process=lambda birth:SimpleNamespace(terminal=(3,0,0)),body_ready=lambda *args:True)
    host.git=SimpleNamespace(commands={},reaped=lambda actor:actor['waited'])
    def admit(actor,value,role,vector,pin,**kwargs):
        ticket=len(host.intents)+1
        host.intents[ticket]={'case':case,'role':role,'parent':actor['birth'],'token':f'token-{ticket}',
            'consumed':False,'pid':None,'environment':dict(value.environment),'cwd':value.cwd}
        return {'ok':True,'ticket':ticket,'token':f'token-{ticket}'}
    host.admit_launch=admit
    actor={'role':'root','birth':parent,'token':'root-token'}
    def raw(argv,environment=None):
        return {'executable':'/usr/bin/git','argv':list(argv),'cwd':str(workspace),'stdin':None,
            'environment':environment or {**host.meta_environment(),'PYTEST_VERSION':'9.0.2','PYTEST_CURRENT_TEST':case+' (call)'}}
    def wait(answer):
        row=host.intents[answer['ticket']]
        row.update(consumed=True,pid=answer['ticket'],birth=object())
        host.actors[row['pid']]={'waited':True,'birth':row['birth']}
    return host,actor,raw,wait,workspace


def prepare(fixture):
    host,actor,raw,wait,workspace=fixture
    first=git.completion_proposal(host,actor,raw(git.COMPLETION_FIXTURE[0]))
    metadata=workspace/'.git'
    (metadata/'refs/heads').mkdir(parents=True)
    (metadata/'HEAD').write_text('ref: refs/heads/main\n')
    (metadata/'refs/heads/main').write_text('1'*40+'\n')
    wait(first)
    second=git.completion_proposal(host,actor,raw(git.COMPLETION_FIXTURE[1]))
    wait(second)
    return host,actor,raw,wait,workspace


def test_fixture_retains_exact_mutation_count_and_metadata_generation(fixture):
    host,actor,raw,wait,workspace=prepare(fixture)
    assert git.completion_ready(host,workspace) is None
    with pytest.raises(Refused,match='root fixture sequence'):
        git.completion_proposal(host,actor,raw(git.COMPLETION_FIXTURE[1]))
    assert len(host.intents)==2


@pytest.mark.parametrize('mutation',['generation','bytes','symlink','hardlink','special-mode','home','argv','env'])
def test_foreign_or_changed_git_inputs_never_become_query_authority(fixture,mutation):
    if mutation in ('argv','env'):
        host,actor,raw,wait,workspace=fixture
        argv=('git','status') if mutation=='argv' else git.COMPLETION_FIXTURE[0]
        with pytest.raises(Refused,match='original launch operands'):
            git.completion_proposal(host,actor,raw(argv,{'PATH':'foreign'} if mutation=='env' else None))
        assert not host.intents
        return
    host,actor,raw,wait,workspace=prepare(fixture)
    assert git.completion_ready(host,workspace) is None
    if mutation=='generation':
        (workspace/'.git').rename(workspace/'.old-git')
        (workspace/'.git').mkdir()
    elif mutation=='bytes':
        (workspace/'.git/refs/heads/main').write_text('2'*40+'\n')
    elif mutation=='symlink':
        (workspace/'.git/foreign').symlink_to(workspace/'.git/HEAD')
    elif mutation=='hardlink':
        os.link(workspace/'.git/HEAD',workspace/'.git/foreign')
    elif mutation=='special-mode':
        (workspace/'.git/HEAD').chmod(0o1644)
    elif mutation=='home':
        (Path(host.meta_environment()['HOME'])/'.gitconfig').write_bytes(b'foreign')
    # Product tests own Git data semantics; these bytes confer no launch right.
    assert git.completion_ready(host,workspace) is None



def test_concurrent_servers_have_independent_queries_and_exact_parent_quota(fixture):
    host,root,raw,wait,workspace=prepare(fixture)
    servers=[]
    for slot in (0,1):
        birth=object()
        token=f'server-{slot}'
        environment={'HOME':str(workspace.parent/'.unrest'),'PATH':'/usr/bin:/bin','SERVER':str(slot),'UNREST_NODE_TYPE':'work'}
        actor={'role':'mcp','case':host.case,'birth':birth,'token':token,'body_ready':True,
               'profile':{'environment':environment}}
        host.intents[3+slot]={'ticket':3+slot,'case':host.case,'role':'mcp','server_slot':slot,'server_kind':'http','parent':host.root_birth,
                            'consumed':True,'birth':birth,'token':token,'pid':30+slot}
        actor['intent']=host.intents[3+slot]
        servers.append(actor)
    first=git.completion_proposal(host,servers[0],raw(('git','rev-parse','HEAD'),servers[0]['profile']['environment']))
    second=git.completion_proposal(host,servers[1],raw(('git','rev-parse','HEAD'),servers[1]['profile']['environment']))
    assert first['ticket']!=second['ticket']
    assert host.intents[first['ticket']]['parent'] is servers[0]['birth']
    assert host.intents[second['ticket']]['parent'] is servers[1]['birth']
    with pytest.raises(Refused,match='query quota'):
        git.completion_proposal(host,servers[0],raw(('git','rev-parse','HEAD'),servers[0]['profile']['environment']))
    wait(first)
    with pytest.raises(Refused,match='query quota'):
        git.completion_proposal(host,servers[0],raw(('git','rev-parse','HEAD'),servers[0]['profile']['environment']))
