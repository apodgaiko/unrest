"""All Git families share the complete kernel-intent binding, never command authority."""
from types import SimpleNamespace

import pytest

import git_observer
from content_manifest import Refused
from git_commands import Command


@pytest.mark.parametrize('mutation',[None,'image','stdin','argv','cwd','environment','deferred'])
def test_shared_issuer_binds_all_operands_before_reserving_an_intent(monkeypatch,mutation):
    monkeypatch.setattr(git_observer,'image',lambda:'a'*64)
    command=Command(('git','rev-parse','HEAD'),'/owned/repository')
    environment={'PATH':'/usr/bin:/bin'}
    host=SimpleNamespace(case='authored-case',intents={},git=SimpleNamespace(commands={}))
    calls=[]
    def admit(actor,expected,role,vector,pin,**options):
        calls.append((actor,expected,role,vector,pin,options))
        if mutation=='deferred':
            return None
        host.intents[7]={}
        return {'ok':True,'ticket':7,'token':'current-child'}
    host.admit_launch=admit
    raw={'executable':'/usr/bin/git','stdin':None,'argv':list(command.argv),
        'cwd':command.cwd,'environment':dict(environment)}
    if mutation=='image':
        raw['executable']='/foreign/git'
    elif mutation=='stdin':
        raw['stdin']='foreign'
    elif mutation=='argv':
        raw['argv'].append('--exec-path=/foreign')
    elif mutation=='cwd':
        raw['cwd']='/foreign'
    elif mutation=='environment':
        raw['environment']['GIT_CONFIG_GLOBAL']='/foreign'
    actor={'birth':'actual-parent'}
    fields={'command':command,'repository':command.cwd,'operation':'completion-head'}
    if mutation not in (None,'deferred'):
        with pytest.raises(Refused):
            git_observer.issue(host,actor,raw,command,environment,maximum=3,fields=fields)
        assert not calls and not host.intents and not host.git.commands
        return
    result=git_observer.issue(host,actor,raw,command,environment,maximum=3,fields=fields)
    assert len(calls)==1
    parent,expected,role,vector,pin,options=calls[0]
    assert parent is actor and expected.case==host.case
    assert expected.executable=='/usr/bin/git' and expected.executable_sha256=='a'*64
    assert expected.argv==command.argv and expected.cwd==command.cwd
    assert dict(expected.environment)==environment and role=='git-command'
    assert vector==['/usr/bin/git','rev-parse','HEAD'] and pin is None and options=={'maximum':3}
    if mutation=='deferred':
        assert result is None and not host.intents and not host.git.commands
    else:
        assert result=={'ok':True,'ticket':7,'token':'current-child','translated':vector}
        assert host.git.commands=={'current-child':host.intents[7]} and host.intents[7]==fields
