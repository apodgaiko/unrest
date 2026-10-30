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


@pytest.mark.parametrize('file',tuple(file for file,spec in fixtures.MODULES.items() if spec.family not in ('candidate','measurement')))
def test_setup_commands_are_original_pinned_fixture_literals(file):
    name=fixtures.SERVER_INQUIRY.split('::')[1] if file=='tests/test_server.py' else 'repository' if file.endswith(('test_project_adapter.py','test_improve_adapter.py')) else '_repository'
    unit=source_unit(ROOT,file,fixtures.PINS[file],(name,))
    calls=[node for node in ast.walk(unit) if isinstance(node,ast.Call) and isinstance(node.func,ast.Name) and node.func.id==('git' if file=='tests/test_server.py' else '_git')]
    commands=tuple(tuple(ast.literal_eval(arg) for arg in call.args[0 if file=='tests/test_server.py' else 1:]) for call in calls)
    assert (commands[:5] if file=='tests/test_server.py' else commands)==fixtures.MODULES[file].commands


def test_selected_fixtures_collect_every_original_parameter_without_bodies(monkeypatch):
    monkeypatch.setenv('PYTEST_DISABLE_PLUGIN_AUTOLOAD','1')
    nodes=[]
    class Collected:
        def pytest_collection_finish(self,session):
            nodes.extend(item.nodeid for item in session.items)
    assert pytest.main(['--collect-only','-q',*fixtures.SLOTS],plugins=[Collected()])==0
    assert tuple(nodes)==tuple(fixtures.SLOTS) and len(nodes)==170



@pytest.mark.parametrize('mutation',[None,'case','slot','parent','generation'])
def test_additional_repositories_are_bound_to_exact_owned_case_slots(tmp_path,monkeypatch,mutation):
    acquire=owned_fixture.acquire
    monkeypatch.setattr(fixtures,'acquire',lambda path,owned,prefix,owner:acquire(path,owned,prefix,os.getuid()))
    case=next(case for case in fixtures.SLOTS if fixtures.fixture(case).family not in ('candidate','measurement'))
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


@pytest.mark.parametrize('case',tuple(case for case in fixtures.SLOTS if fixtures.fixture(case).family not in ('candidate','measurement')))
def test_each_setup_uses_only_its_authored_commands_and_phase(case):
    spec=fixtures.fixture(case)
    repo='/owned/'+fixtures.SLOTS[case][0]
    for index,operation in enumerate(('init','config-name','config-email','stage-base','commit-base')):
        command=build(operation,repo,repo,{},family=spec.family,fixture=spec)
        assert command.argv==('git',*spec.commands[index])
    assert spec.phase in ('setup','call')


def test_repository_keeps_generation_without_attesting_git_configuration(tmp_path,monkeypatch):
    from git_observer import Git

    case=next(case for case in fixtures.SLOTS if fixtures.fixture(case).family not in ('candidate','measurement'))
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
    (metadata/'config').write_bytes(b'[core]\nworktree=/outside\n')
    assert git.repository(str(repository),'config-email','workspaces')==repository


def test_factored_parameter_axes_preserve_the_complete_ordered_fixture_map():
    import hashlib
    import json
    assert hashlib.sha256(json.dumps([(case,value) for case,value in fixtures.SLOTS.items() if case!=fixtures.SERVER_INQUIRY],separators=(',',':')).encode()).hexdigest()=='294ac85f02c8f2ba7cef463ee297fd2d67b1e88c913e4331ad3fcd55276c13c8'
