"""Original candidate cases and exact Git forms; these controls launch no Git."""
from pathlib import Path

import pytest

import candidate_git as candidate
from content_manifest import Refused

ROOT=next(path for path in Path(__file__).resolve().parents if (path/'pyproject.toml').is_file())
REPOSITORY='/owned/pytest/original0/repository'


def test_all_fixture_consumers_are_exact_normal_collected_nodes(monkeypatch):
    monkeypatch.setenv('PYTEST_DISABLE_PLUGIN_AUTOLOAD','1')
    nodes=[]
    class Collected:
        def pytest_collection_finish(self,session):
            nodes.extend(item.nodeid for item in session.items if 'repo' in item.fixturenames)
    assert pytest.main(['--collect-only','-q',candidate.TEST],plugins=[Collected()])==0
    assert tuple(nodes)==candidate.CASES and len(nodes)==113


@pytest.mark.parametrize('case',candidate.CASES)
def test_setup_and_extras_have_closed_original_ordinals(case):
    setup,extras=candidate.declarations(ROOT,case,REPOSITORY)
    assert len(setup)==9
    for index,row in enumerate((*setup,*extras)):
        args=[part if part is not None else 'a'*40 for part in row]
        args=[part.replace('OID','b'*40) for part in args]
        value,environment=candidate.command(ROOT,case,REPOSITORY,index,['/usr/bin/git',*args])
        assert value.argv==('/usr/bin/git',*args)
        assert environment['HOME']==REPOSITORY and environment['GIT_CONFIG_GLOBAL']=='/dev/null'
        with pytest.raises(Refused):
            candidate.command(ROOT,case,REPOSITORY,index,['/usr/bin/git',*args,'--foreign'])
    with pytest.raises(Refused,match='ordinal'):
        candidate.command(ROOT,case,REPOSITORY,len(setup)+len(extras),['/usr/bin/git','status'])


@pytest.mark.parametrize('mutation',['consumer','bytes','executable','oid','option'])
def test_foreign_consumer_source_image_and_dynamic_operands_refuse(tmp_path,mutation):
    case=candidate.TEST+'::test_wrong_ids_types_and_unrelated_history'
    root=ROOT
    argv=['/usr/bin/git','commit-tree','a'*40,'-m','unrelated']
    if mutation=='consumer':
        case=candidate.TEST+'::test_not_an_original_consumer'
    elif mutation=='bytes':
        root=tmp_path
        file=root/candidate.TEST
        file.parent.mkdir()
        file.write_text('foreign')
    elif mutation=='executable':
        argv[0]='/foreign/git'
    elif mutation=='oid':
        argv[2]='--exec=foreign'
    elif mutation=='option':
        argv[3]='--exec-path=/foreign'
    with pytest.raises(Refused):
        candidate.command(root,case,REPOSITORY,11,argv)


def test_canary_authority_ends_at_exact_configuration_write():
    case=candidate.TEST+'::test_config_canaries_never_called[core.hooksPath-CANARY]'
    vector=['/usr/bin/git','config','core.hooksPath',str(Path(REPOSITORY).parent/'canary')]
    candidate.command(ROOT,case,REPOSITORY,9,vector)
    with pytest.raises(Refused,match='ordinal'):
        candidate.command(ROOT,case,REPOSITORY,10,['/usr/bin/git','commit','-m','run hook'])
    with pytest.raises(Refused,match='complete command'):
        candidate.command(ROOT,case,REPOSITORY,9,[*vector[:-1],'/foreign/canary'])


def test_candidate_message_option_does_not_borrow_integration_stdin_authority():
    import threading
    from types import SimpleNamespace
    from source_entry import Policy
    policy=object.__new__(Policy)
    policy.case=candidate.TEST+'::test_wrong_ids_types_and_unrelated_history'
    policy.profile={'role':'root'}
    policy.local=threading.local()
    frames=[]
    vector=['/usr/bin/git','commit-tree','a'*40,'-m','unrelated']
    def request(kind,frame):
        frames.append((kind,frame))
        return {'ok':True,'ticket':1,'token':'token','translated':list(vector),'rule':'candidate:git'}
    policy.client=SimpleNamespace(request=request)
    policy.popen(('/usr/bin/git',vector,REPOSITORY,{}))
    assert frames[0][1]['stdin'] is None
