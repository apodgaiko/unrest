"""Additional fixture rows bind original setup, slots and normal parameters."""
import ast
import os
from pathlib import Path
from types import SimpleNamespace

import pytest

from content_manifest import Refused
from launch_policy import source_unit
import git_policy as fixtures
import test_git_catalogue as observed
import owned_fixture

ROOT=next(p for p in Path(__file__).resolve().parents if (p/'pyproject.toml').is_file())


@pytest.mark.parametrize('file',tuple(file for file in fixtures.FIXTURE_PINS if file not in (fixtures.CANDIDATE_TEST,fixtures.MEASUREMENT_TEST)))
def test_setup_commands_are_original_pinned_fixture_literals(file):
    name=fixtures.FIXTURE_SERVER_INQUIRY.split('::')[1] if file=='tests/test_server.py' else 'repository' if file.endswith(('test_project_adapter.py','test_improve_adapter.py','test_workspaces.py','test_evolution.py')) else '_repository'
    unit=source_unit(ROOT,file,fixtures.FIXTURE_PINS[file],(name,))
    calls=[node for node in ast.walk(unit) if isinstance(node,ast.Call) and isinstance(node.func,ast.Name) and node.func.id==('git' if file=='tests/test_server.py' else '_git')]
    commands=tuple(tuple(ast.literal_eval(arg) for arg in call.args[0 if file=='tests/test_server.py' else 1:]) for call in calls)
    assert all(row in set().union(*map(set,fixtures.SETUP_FORMS.values())) for row in (commands[:5] if file=='tests/test_server.py' else commands))


def test_selected_fixtures_collect_every_original_parameter_without_bodies(monkeypatch):
    monkeypatch.setenv('PYTEST_DISABLE_PLUGIN_AUTOLOAD','1')
    nodes=[]
    class Collected:
        def pytest_collection_finish(self,session):
            nodes.extend(item.nodeid for item in session.items)
    assert pytest.main(['--collect-only','-q',*observed.FIXTURE_SLOTS],plugins=[Collected()])==0
    assert tuple(nodes)==tuple(observed.FIXTURE_SLOTS) and len(nodes)==170



@pytest.mark.parametrize('mutation',[None,'case','slot','parent','generation','repository-generation','ancestor-generation','alias'])
def test_additional_repositories_are_bound_to_exact_owned_case_slots(tmp_path,monkeypatch,mutation):
    acquire=owned_fixture.acquire
    monkeypatch.setattr(fixtures,'acquire',lambda path,owned,prefix,owner:acquire(path,owned,prefix,os.getuid()))
    original_lstat=Path.lstat
    def lstat(path,*args,**kwargs):
        info=original_lstat(path,*args,**kwargs)
        return SimpleNamespace(st_mode=info.st_mode,st_uid=20000,st_dev=info.st_dev,st_ino=info.st_ino)
    monkeypatch.setattr(Path,'lstat',lstat)
    case=next(iter(observed.FIXTURE_SLOTS))
    base=tmp_path/'pytest'/(case.split('::')[1][:30]+'0')
    repository=base/'repo'
    repository.mkdir(parents=True)
    host=SimpleNamespace(meta={'checkout':str(ROOT),'owned':str(tmp_path)},fixture_roots={})
    if mutation=='case':
        with pytest.raises(Refused):
            fixtures.fixture_root(host,'undeclared',str(repository))
        return
    if mutation=='slot':
        repository=base/'foreign'
        repository.mkdir()
    elif mutation=='parent':
        repository=tmp_path/'outside/repo'
        repository.mkdir(parents=True)
    elif mutation=='generation':
        host.fixture_roots[('git-fixture',case)]=('other',0,0)
    if mutation in ('repository-generation','ancestor-generation'):
        repository=base/'nested/repository'
        repository.mkdir(parents=True)
        fixtures.fixture_root(host,case,str(repository))
        changed=repository if mutation=='repository-generation' else repository.parent
        changed.rename(changed.with_name('old'))
        repository.mkdir(parents=True)
    elif mutation=='alias':
        alias=base/'alias'
        alias.symlink_to(repository,target_is_directory=True)
        repository=alias
    if mutation in (None,'slot'):
        fixtures.fixture_root(host,case,str(repository))
        assert host.fixture_roots[('git-fixture',case)][0]==str(base)
    else:
        with pytest.raises(Refused):
            fixtures.fixture_root(host,case,str(repository))




def test_repository_keeps_generation_without_attesting_git_configuration(tmp_path,monkeypatch):
    from git_policy import Git

    case=next(iter(observed.FIXTURE_SLOTS))
    repository=tmp_path/'pytest/case/repo'
    repository.mkdir(parents=True)
    host=SimpleNamespace(case=case,meta={'owned':str(tmp_path)})
    git=Git(host)
    monkeypatch.setattr(fixtures,'fixture_root',lambda *args:None)
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
    assert hashlib.sha256(json.dumps([(case,value) for case,value in observed.FIXTURE_SLOTS.items() if case!=fixtures.FIXTURE_SERVER_INQUIRY],separators=(',',':')).encode()).hexdigest()=='294ac85f02c8f2ba7cef463ee297fd2d67b1e88c913e4331ad3fcd55276c13c8'


def test_local_git_eligibility_is_module_bounded_and_byte_pinned(tmp_path):
    assert fixtures.local_case('tests/test_workspaces.py::original-active-node')
    assert not fixtures.local_case('tests/foreign.py::node')
    assert not fixtures.local_case('tests/test_workspaces.py')
    assert not fixtures.local_case(None)
    file=tmp_path/'tests/test_workspaces.py'
    file.parent.mkdir()
    file.write_text('changed source')
    host=SimpleNamespace(meta={'checkout':str(tmp_path),'owned':str(tmp_path)},fixture_roots={})
    with pytest.raises(Refused,match='original source bytes'):
        fixtures.fixture_root(host,'tests/test_workspaces.py::original-active-node',str(tmp_path/'pytest/case/repo'))


def test_retired_catalogue_is_only_a_test_oracle():
    import ast
    support=Path(fixtures.__file__).parent
    for path in support.glob('*.py'):
        if path.name.startswith('test_'):
            continue
        tree=ast.parse(path.read_bytes())
        assert all(not (isinstance(node,ast.ImportFrom) and node.module=='test_git_catalogue') for node in ast.walk(tree))
    assert fixtures.CANDIDATE_CANARIES==tuple(tuple(item.split('-',1)) for item in observed.CANDIDATE_CONSUMERS['test_config_canaries_never_called'])
    assert len(fixtures.CANDIDATE_CANARIES)==14
