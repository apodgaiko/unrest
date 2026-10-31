"""Finite custody templates and owned repository negatives; no native launch."""
from pathlib import Path

import pytest

from content_manifest import Refused
from test_controlled_catalogue import CASES
from controlled_owners import IMMUTABLE
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


@pytest.mark.parametrize('case',IMMUTABLE)
@pytest.mark.parametrize('args',[
    ('init','--initial-branch=main','--object-format=sha1'),('add','.'),
    ('commit','-m','base'),('rev-parse','HEAD'),
])
def test_immutable_custody_has_only_four_original_seed_commands(case,args):
    import controlled_cases
    from controlled_pairs import before_spawn
    assert controlled_cases.custody(case) and not controlled_cases.eligible(case)
    result,_=command(case,(*PREFIX,*args),'/owned/pytest/case/candidate',Path('/owned'))
    assert result.argv==(*PREFIX,*args)
    with pytest.raises(Refused):
        before_spawn(case,'/owned/pytest/case/worker','backend',[],{})


@pytest.mark.parametrize('case',IMMUTABLE)
@pytest.mark.parametrize('args',[
    ('fetch','https://example.invalid/private'),('clone','/foreign','.'),('add','--','a'),
    ('commit','-m','finite fixture'),('commit','--allow-empty','-m','sealed candidate'),
    ('init','--initial-branch=foreign','--object-format=sha1'),('config','core.hooksPath','/foreign'),
])
def test_immutable_custody_does_not_inherit_other_fixture_or_remote_commands(case,args):
    with pytest.raises(Refused):
        command(case,(*PREFIX,*args),'/owned/pytest/case/candidate',Path('/owned'))


@pytest.mark.parametrize('case',IMMUTABLE)
@pytest.mark.parametrize('mutation',(None,'owner','cwd','environment','executable','quota'))
def test_immutable_custody_binds_source_root_environment_and_four_launch_ceiling(tmp_path,monkeypatch,case,mutation):
    import os
    from types import SimpleNamespace
    from source_observer import Observer
    import git_policy
    checkout=next(p for p in Path(__file__).resolve().parents if (p/'pyproject.toml').is_file())
    cwd=tmp_path/'pytest'/'case'/'candidate'
    cwd.mkdir(parents=True)
    acquire=git_policy.acquire
    monkeypatch.setattr(git_policy,'acquire',lambda path,owned:acquire(path,owned,os.getuid()))
    monkeypatch.setattr(git_policy,'image',lambda:'a'*64)
    host=object.__new__(Observer)
    host.case,host.serial,host.root_birth=case,0,'root-birth'
    host.meta={'checkout':str(checkout),'owned':str(tmp_path)}
    host.intents={}
    host.git=SimpleNamespace(commands={})
    host.root_only=lambda actor:None if actor['role']=='root' else (_ for _ in ()).throw(Refused('owner'))
    actor={'role':'root','birth':'root-birth'}
    raw={'argv':[*PREFIX,'rev-parse','HEAD'],'executable':'/usr/bin/git','cwd':str(cwd),
         'environment':dict(git_policy.CUSTODY_ENVIRONMENT),'stdin':None}
    if mutation=='owner':
        actor['role']='child'
    elif mutation=='cwd':
        raw['cwd']=str(tmp_path/'pytest'/'case'/'foreign')
    elif mutation=='environment':
        raw['environment']['EXTRA']='foreign'
    elif mutation=='executable':
        raw['executable']='/foreign/git'
    elif mutation=='quota':
        host.intents={i:{'case':case,'role':'git-custody'} for i in range(4)}
    if mutation:
        with pytest.raises(Refused):
            selected=command(case,tuple(raw['argv']),raw['cwd'],tmp_path)
            git_policy.custody_launch(host,actor,*selected,raw)
        assert not host.git.commands
    else:
        selected=command(case,tuple(raw['argv']),raw['cwd'],tmp_path)
        answer=git_policy.custody_launch(host,actor,*selected,raw)
        assert host.intents[answer['ticket']]['role']=='git-custody'
        assert host.intents[answer['ticket']]['translated']==raw['argv']
        assert answer['token'] in host.git.commands


def test_immutable_custody_closed_case_names_match_source_functions():
    import ast
    unit=ast.parse(Path('tests/test_immutable_custody.py').read_bytes())
    assert tuple('tests/test_immutable_custody.py::'+node.name for node in unit.body
                 if isinstance(node,ast.FunctionDef) and node.name.startswith('test_'))==IMMUTABLE
    with pytest.raises(Refused):
        command('tests/test_immutable_custody.py::test_foreign',(*PREFIX,'rev-parse','HEAD'),
                '/owned/pytest/case/candidate',Path('/owned'))
