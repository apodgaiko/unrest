"""Original parameter schedules and repr-only role templates; no launch claim."""
import ast
from pathlib import Path

import pytest

from content_manifest import Refused
import completion_roles as roles

ROOT=next(p for p in Path(__file__).resolve().parents if (p/'pyproject.toml').is_file())


def test_role_catalogue_preserves_all_original_parameter_ids_and_order():
    class Collected:
        def pytest_collection_finish(self,session):
            self.nodes=tuple(item.nodeid for item in session.items)
    plugin=Collected()
    code=pytest.main(['--collect-only','-q',roles.OWNERSHIP,roles.CRASH,roles.SETUP],plugins=[plugin])
    assert code==0 and plugin.nodes==tuple(case for case in roles.CASES if roles.CASES[case][0] in ('ownership','crash','setup'))
    assert sum(row[0] in ('ownership','crash','setup') for row in roles.CASES.values())==28 and sum(len(roles.schedule(case)) for case,row in roles.CASES.items() if row[0] in ('ownership','crash','setup'))==80
    assert sum(kind=='http' for case,row in roles.CASES.items() if row[0] in ('ownership','crash','setup') for kind,_,_ in roles.schedule(case))==52


@pytest.mark.parametrize('case',[case for case,row in roles.CASES.items() if row[0] in ('ownership','crash','setup')])
def test_all_literals_and_environment_bind_closed_role_and_attempt(case,tmp_path):
    parent=tmp_path/'quote\'s-root'
    ambient={'HOME':'/owned/home','PATH':'/usr/bin:/bin','UNREST_FOREIGN':'must be stripped for stdio'}
    family,role,_=roles.CASES[case]
    for ordinal,(kind,attempt,quota) in enumerate(roles.schedule(case)):
        body=roles.program(ROOT,parent,case,ordinal)
        ast.parse(body)
        environment=roles.environment(ROOT,parent,case,ordinal,ambient)
        assert environment['UNREST_NODE_TYPE']==role
        assert environment['UNREST_PROJECT_ID']==family
        assert environment['UNREST_HANDOFF_PATH']==str(roles.attempt(parent,case,ordinal))
        assert Path(environment['UNREST_HANDOFF_PATH']).name==attempt+'__node.json'
        assert ('UNREST_FOREIGN' in environment)==(kind=='http')
        assert quota==0 if role=='validate' else 0<=quota<=2
        if kind=='http':
            assert body=='from unrest_harness.server import main; main()'
            assert environment['PYTHONPATH']==str(ROOT/'src')
        elif family=='crash':
            assert 'os._exit(73)' in body and repr(str(roles.attempt(parent,case,ordinal))) in body
        else:
            assert body.count(repr(str(parent/'workspace/barrier')))==2


def test_no_foreign_case_can_select_a_role_or_descendant_schedule():
    with pytest.raises(Refused):
        roles.schedule('foreign')


def test_source_only_fixture_nodes_match_original_collection():
    class Collected:
        def pytest_collection_finish(self,session):
            self.nodes=tuple(item.nodeid for item in session.items)
    plugin=Collected()
    selectors=tuple(dict.fromkeys(case.split('[')[0] for case in roles.SOURCE))
    assert len(selectors)==5
    assert pytest.main(['--collect-only','-q',*selectors],plugins=[plugin])==0
    assert plugin.nodes==tuple(roles.SOURCE) and len(plugin.nodes)==47
    assert all(roles.schedule(case)==() and case not in roles.HTTP for case in roles.SOURCE)


@pytest.mark.parametrize('key',('HOME','PATH','TMPDIR','PYTHONPATH','PYTHONHOME','LD_PRELOAD','DYLD_INSERT_LIBRARIES',
    'GIT_CONFIG','GIT_CONFIG_COUNT','GIT_DIR','GIT_WORK_TREE','UNREST_FOREIGN','UNREST_WORKER_PROVIDER',
    'UNREST_APPROVAL_RECOVERY','CODEX_CONFIG','ANTHROPIC_API_KEY'))
def test_passive_git_metadata_does_not_admit_execution_or_provider_environment(key):
    from completion_git import application_environment
    baseline={'HOME':'/owned/home','PATH':'/usr/bin:/bin','TMPDIR':'/owned/tmp'}
    with pytest.raises(Refused):
        application_environment(baseline,{**baseline,key:'foreign'})


def test_passive_git_metadata_is_closed_and_fully_retained():
    from completion_git import APP_KEYS,application_environment
    assert APP_KEYS=={'UNREST_HOME','UNREST_PROJECTS_DIR','UNREST_PROJECT_ID','UNREST_MISSION_ID',
        'UNREST_NODE_ID','UNREST_NODE_TYPE','UNREST_HANDOFF_PATH','UNREST_NODE_ASSIGNMENT'}
    baseline={'HOME':'/owned/home','PATH':'/usr/bin:/bin'}
    observed={**baseline,**{key:'inert-'+key for key in APP_KEYS}}
    assert application_environment(baseline,observed)==observed
    with pytest.raises(Refused):
        application_environment(baseline,{'PATH':'/usr/bin:/bin'})


def test_added_http_families_preserve_original_nodes_and_server_topology():
    class Collected:
        def pytest_collection_finish(self,session):
            self.nodes=tuple(item.nodeid for item in session.items)
    selected={**roles.RESTART,**roles.TARGETLESS,**roles.BINDING}
    selectors=tuple(dict.fromkeys(case.split('[')[0] for case in selected))
    plugin=Collected()
    assert pytest.main(['--collect-only','-q',*selectors],plugins=[plugin])==0
    assert plugin.nodes==tuple(selected) and len(selected)==15
    for case,(family,role,scenario) in selected.items():
        parent=Path('/owned/case')
        for slot in range(len(roles.schedule(case))):
            environment=roles.environment(ROOT,parent,case,slot,{'HOME':'/owned/home','PATH':'/usr/bin:/bin'})
            assert roles.program(ROOT,parent,case,slot)=='from unrest_harness.server import main; main()'
            if family=='restart' and slot>0:
                assert roles.mode(case,slot)=='orchestrator'
                assert 'UNREST_HANDOFF_PATH' not in environment
                assert environment['UNREST_WORKER_ACP_COMMAND']=='/bin/true'
            else:
                assert environment['UNREST_NODE_TYPE']==role
                assert roles.mode(case,slot)==('validator' if role=='validate' else 'worker')
                if family=='restart':
                    assert environment['UNREST_PROJECT_ID']==f'real-restart-{role}-{scenario=="repair"}'
                    assert environment['UNREST_WORKER_ACP_COMMAND']=='/owned/case/workspace/.forbidden-child-trap'
                else:
                    assert environment['UNREST_PROJECT_ID']==family
        assert case in roles.HTTP
