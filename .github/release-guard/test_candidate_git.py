"""Original candidate cases and exact Git forms; these controls launch no Git."""
from pathlib import Path

import pytest

import git_policy as candidate
from content_manifest import Refused

ROOT=next(path for path in Path(__file__).resolve().parents if (path/'pyproject.toml').is_file())
REPOSITORY='/owned/pytest/original0/repository'


def test_all_fixture_consumers_are_exact_normal_collected_nodes(monkeypatch):
    monkeypatch.setenv('PYTEST_DISABLE_PLUGIN_AUTOLOAD','1')
    nodes=[]
    class Collected:
        def pytest_collection_finish(self,session):
            nodes.extend(item.nodeid for item in session.items if 'repo' in item.fixturenames)
    assert pytest.main(['--collect-only','-q',candidate.CANDIDATE_TEST],plugins=[Collected()])==0
    assert tuple(nodes)==candidate.CANDIDATE_CASES and len(nodes)==113








def test_candidate_message_option_does_not_borrow_integration_stdin_authority():
    import threading
    from types import SimpleNamespace
    from source_entry import Policy
    policy=object.__new__(Policy)
    policy.case=candidate.CANDIDATE_TEST+'::test_wrong_ids_types_and_unrelated_history'
    policy.profile={'role':'root'}
    policy.local=threading.local()
    frames=[]
    vector=['/usr/bin/git','commit-tree','a'*40,'-m','unrelated']
    def request(kind,frame):
        frames.append((kind,frame))
        return {'ok':True,'ticket':1,'token':'token','translated':list(vector)}
    policy.client=SimpleNamespace(request=request)
    policy.popen(('/usr/bin/git',vector,REPOSITORY,{}))
    assert frames[0][1]['stdin'] is None


def test_all_original_candidate_setup_vectors_remain_closed():
    import ast
    from launch_policy import source_unit
    unit=source_unit(ROOT,candidate.CANDIDATE_TEST,candidate.CANDIDATE_PIN,('repo',))
    rows=[]
    for node in unit.body:
        call=node.value if isinstance(node,(ast.Expr,ast.Assign)) else None
        if isinstance(call,ast.Call) and isinstance(call.func,ast.Name) and call.func.id=='git':
            rows.append(tuple(ast.literal_eval(arg) for arg in call.args[1:]))
    assert len(rows)==9
    for args in rows:
        operations=[]
        for operation in (*candidate.COMMAND_OPERATIONS,'fixture-extra'):
            try:
                candidate.command_match(operation,REPOSITORY,REPOSITORY,['/usr/bin/git',*args],None,{},family='workspaces')
            except Refused:
                continue
            operations.append(operation)
        assert len(operations)==1


@pytest.mark.parametrize('args',[
    ['commit-tree','--exec=foreign','-m','unrelated'],
    ['config','core.hooksPath','/foreign/canary'],
    ['commit','-m','run hook'],['fetch','https://example.invalid'],
    ['update-index','--add','--cacheinfo','120000,--exec=foreign,unsupported'],
])
def test_union_rejects_foreign_commands_options_and_object_ids(args):
    for operation in (*candidate.COMMAND_OPERATIONS,'fixture-extra'):
        with pytest.raises(Refused):
            candidate.command_match(operation,REPOSITORY,REPOSITORY,['/usr/bin/git',*args],None,{},family='workspaces')


def test_closed_canary_write_does_not_add_arbitrary_configuration():
    args=['/usr/bin/git','config','core.hooksPath',str(Path(REPOSITORY).parent/'canary')]
    assert candidate.command_match('fixture-extra',REPOSITORY,REPOSITORY,args,None,{},family='workspaces').argv==tuple(args)
