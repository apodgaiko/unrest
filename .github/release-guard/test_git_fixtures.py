"""Additional fixture rows bind original setup, slots and normal parameters."""
import ast
import os
from pathlib import Path
from types import SimpleNamespace

import pytest

from content_manifest import Refused
from launch_policy import source_unit
from test_git_vectors import build
import git_fixtures as fixtures
import owned_fixture

ROOT=next(p for p in Path(__file__).resolve().parents if (p/'pyproject.toml').is_file())


@pytest.mark.parametrize('file',tuple(file for file,spec in fixtures.MODULES.items() if spec.family!='candidate'))
def test_setup_commands_are_original_pinned_fixture_literals(file):
    name='repository' if file.endswith(('test_project_adapter.py','test_improve_adapter.py')) else '_repository'
    unit=source_unit(ROOT,file,fixtures.PINS[file],(name,))
    calls=[node for node in ast.walk(unit) if isinstance(node,ast.Call) and isinstance(node.func,ast.Name) and node.func.id=='_git']
    commands=tuple(tuple(ast.literal_eval(arg) for arg in call.args[1:]) for call in calls)
    assert commands==fixtures.MODULES[file].commands


def test_selected_fixtures_collect_every_original_parameter_without_bodies(monkeypatch):
    monkeypatch.setenv('PYTEST_DISABLE_PLUGIN_AUTOLOAD','1')
    nodes=[]
    class Collected:
        def pytest_collection_finish(self,session):
            nodes.extend(item.nodeid for item in session.items)
    assert pytest.main(['--collect-only','-q',*fixtures.SLOTS],plugins=[Collected()])==0
    assert tuple(nodes)==tuple(fixtures.SLOTS) and len(nodes)==158
    assert {key:len(value) for key,value in fixtures.GROUPS.items()}=={
        'foundation8':8,'project12':12,'improve20':20,'activation5':5,'candidate113':113}


@pytest.mark.parametrize('mutation',[None,'case','slot','parent','generation'])
def test_additional_repositories_are_bound_to_exact_owned_case_slots(tmp_path,monkeypatch,mutation):
    acquire=owned_fixture.acquire
    monkeypatch.setattr(fixtures,'acquire',lambda path,owned,prefix,owner:acquire(path,owned,prefix,os.getuid()))
    case=next(case for case in fixtures.SLOTS if fixtures.fixture(case).family!='candidate')
    base=tmp_path/'pytest'/(case.split('::')[1][:30]+'0')
    repository=base/'repo'
    repository.mkdir(parents=True)
    host=SimpleNamespace(meta={'checkout':str(ROOT),'owned':str(tmp_path)},fixture_roots={})
    if mutation=='case':
        with pytest.raises(Refused):
            fixtures.fixture('undeclared')
        return
    if mutation=='slot':
        repository=base/'foreign'
        repository.mkdir()
    elif mutation=='parent':
        repository=tmp_path/'outside/repo'
        repository.mkdir(parents=True)
    elif mutation=='generation':
        host.fixture_roots[('git-fixture',case)]=('other',0,0)
    if mutation is None:
        fixtures.root(host,case,str(repository))
        assert host.fixture_roots[('git-fixture',case)][0]==str(base)
    else:
        with pytest.raises(Refused):
            fixtures.root(host,case,str(repository))


@pytest.mark.parametrize('case',tuple(case for case in fixtures.SLOTS if fixtures.fixture(case).family!='candidate'))
def test_each_setup_uses_only_its_authored_commands_and_phase(case):
    spec=fixtures.fixture(case)
    repo='/owned/'+fixtures.SLOTS[case][0]
    for index,operation in enumerate(('init','config-name','config-email','stage-base','commit-base')):
        command=build(operation,repo,repo,{},family=spec.family,fixture=spec)
        assert command.argv==('git',*spec.commands[index])
    assert spec.phase in ('setup','call')


def test_repository_keeps_generation_and_closed_routing_configuration(tmp_path,monkeypatch):
    import git_observer
    from git_observer import Git,HOME_CONFIG

    case=next(case for case in fixtures.SLOTS if fixtures.fixture(case).family!='candidate')
    repository=tmp_path/'pytest/case/repo'
    repository.mkdir(parents=True)
    host=SimpleNamespace(case=case,meta={'owned':str(tmp_path)})
    git=Git(host)
    monkeypatch.setattr(fixtures,'root',lambda *args:None)
    original=Path.lstat
    def lstat(path,*args,**kwargs):
        info=original(path,*args,**kwargs)
        return SimpleNamespace(st_mode=info.st_mode,st_uid=20000,st_dev=info.st_dev,st_ino=info.st_ino)
    monkeypatch.setattr(Path,'lstat',lstat)
    config=[b'[core]\nrepositoryformatversion = 0\nfilemode = true\nbare = false\nlogallrefupdates = true\n']
    monkeypatch.setattr(git_observer,'regular',lambda path,*args,**kwargs:HOME_CONFIG if path.name=='.gitconfig' else config[0])
    git.repository(str(repository),'init','workspaces')
    (repository/'.git').mkdir()
    git.repository(str(repository),'config-name','workspaces')
    assert set(git.repositories[(case,str(repository))])=={'path','identities'}
    metadata=repository/'.git'
    metadata.rmdir()
    with pytest.raises(Refused,match='metadata missing'):
        git.repository(str(repository),'head','workspaces')
    foreign=repository.parent/'foreign-metadata'
    foreign.mkdir()
    metadata.symlink_to(foreign,target_is_directory=True)
    with pytest.raises(Refused,match='metadata directory'):
        git.repository(str(repository),'head','workspaces')
    metadata.unlink()
    metadata.mkdir()
    config[0]+=b'worktree=/outside\n'
    with pytest.raises(Refused,match='routing configuration'):
        git.repository(str(repository),'config-email','workspaces')
