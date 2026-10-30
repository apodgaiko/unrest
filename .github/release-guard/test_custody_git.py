"""Finite custody templates and owned repository negatives; no native launch."""
from pathlib import Path

import pytest

from content_manifest import Refused
from test_controlled_catalogue import CASES
from git_policy import custody_command as command, custody_repository as repository, CUSTODY_PREFIX as PREFIX

CASE = next(case for case in CASES if 'test_ack_durability[' in case)


@pytest.mark.parametrize('args',[
    ('init','--initial-branch=main','--object-format=sha1'),('add','.'),
    ('commit','-m','finite fixture'),('rev-parse','HEAD'),('add','--','a'),
    ('diff','--cached','--name-only','a'*40),('commit','--allow-empty','-m','sealed candidate'),
])
def test_closed_original_templates(args):
    result,_ = command(CASE,(*PREFIX,*args),'/owned/pytest/case/cohort/base',Path('/owned'))
    assert result.argv[len(PREFIX):] == args and result.stdin is None


@pytest.mark.parametrize('args',[
    ('fetch','https://example.invalid/private'),('clone','/foreign','.'),('add','--','../private'),
    ('-c','core.hooksPath=/foreign','commit','-m','base'),('diff','--cached','--name-only','HEAD'),
    ('commit','-m','foreign'),('add','--','auth.json'),
])
def test_external_or_unbounded_commands_refuse(args):
    with pytest.raises(Refused):
        command(CASE,(*PREFIX,*args),'/owned/pytest/case/cohort/base',Path('/owned'))


def test_repository_cannot_leave_the_disposable_case(tmp_path):
    root = tmp_path/'foreign'
    root.mkdir()
    with pytest.raises(Refused):
        repository(str(root),tmp_path)
    with pytest.raises(Refused):
        command(CASE,(*PREFIX,'rev-parse','HEAD'),str(root),tmp_path)


_ACTIVE = [None]


def _audit(event,args):
    if event == 'subprocess.Popen' and _ACTIVE[0] is not None:
        _ACTIVE[0](args)
        raise RuntimeError('custody selection stopped before exec')


__import__('sys').addaudithook(_audit)




@pytest.mark.parametrize('replacement',['repository','metadata'])
def test_mutable_repository_data_does_not_supply_new_command_rights(tmp_path,monkeypatch,replacement):
    from types import SimpleNamespace
    root=tmp_path/'pytest/case/repository'
    (root/'.git').mkdir(parents=True)
    original=Path.lstat
    def owned(path,*args,**kwargs):
        info=original(path,*args,**kwargs)
        return SimpleNamespace(st_mode=info.st_mode,st_uid=20000)
    monkeypatch.setattr(Path,'lstat',owned)
    assert repository(str(root),tmp_path) is None
    changed=root if replacement=='repository' else root/'.git'
    changed.rename(changed.with_name('retired'))
    changed.mkdir()
    assert repository(str(root),tmp_path) is None
    with pytest.raises(Refused,match='undeclared template'):
        command(CASE,(*PREFIX,'fetch','https://example.invalid/private'),str(root),tmp_path)


def test_deferred_constructor_does_not_consume_a_git_command(monkeypatch):
    import git_policy as custody_git
    import git_policy as git_observer
    monkeypatch.setattr(git_observer,'image',lambda:'a'*64)
    from types import SimpleNamespace
    cwd = '/owned/pytest/case/cohort/base'
    host = SimpleNamespace(case=CASE,meta={'owned':'/owned'},intents={},root_only=lambda actor:None,
        admit_launch=lambda *args,**kwargs:None,
        git=SimpleNamespace(custody_roots={},commands={}))
    monkeypatch.setattr(custody_git,'custody_repository',lambda *args,**kwargs:(((cwd,1,10,20000),),(1,20,20000)))
    assert custody_git.custody_launch(host,None,*custody_git.custody_command(CASE,tuple([*PREFIX,'rev-parse','HEAD']),cwd,Path('/owned')),
        {'executable':'/usr/bin/git','argv':[*PREFIX,'rev-parse','HEAD'],'cwd':cwd,
         'stdin':None,'environment':custody_git.CUSTODY_ENVIRONMENT}) is None
    assert not host.intents and not host.git.commands
