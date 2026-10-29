"""Provider-free source fixtures cannot acquire other Git or process authority."""
from pathlib import Path
from types import SimpleNamespace
import pytest
from content_manifest import Refused
import measurement_git as measurement

ROOT=Path(__file__).resolve().parents[2]

@pytest.fixture
def host(monkeypatch):
    import git_observer
    monkeypatch.setattr(git_observer,'image',lambda:'a'*64)
    value=SimpleNamespace(case=measurement.CASES[0],meta={'checkout':str(ROOT)},
        binding={'entry':{'path':'/native/python'}},intents={},seen=[])
    value.root_only=lambda actor:None
    value.meta_environment=lambda:{'PATH':'/usr/bin:/bin'}
    def launch(*args):
        value.seen.append(args)
        return {'ticket':1,'token':'child','ok':True}
    value.git=SimpleNamespace(launch=launch)
    return value

def raw(host,args):
    environment={**host.meta_environment(),'PYTEST_VERSION':'9.0.2','PYTEST_CURRENT_TEST':host.case+' (call)'}
    if args==['ls-files','-z','--stage'] and host.case.split('::')[1] in measurement.SYNTHETIC:
        command='/native/python '+str(ROOT/'tests/mock_measurement_acp.py')
        environment.update(UNREST_WORKER_ACP_COMMAND=command,UNREST_VALIDATOR_ACP_COMMAND=command)
    return {'executable':'/usr/bin/git','argv':['git',*args],'stdin':None,'environment':environment,'cwd':'/owned/pytest/test_case0/source'}

@pytest.mark.parametrize('case',measurement.CASES)
def test_every_original_source_fixture_has_exact_commands(host,case):
    host.case=case
    for args in (['init','-q'],['add','.'],['ls-files','-z','--stage']):
        result=measurement.proposal(host,{},raw(host,args))
        assert result['translated']==['/usr/bin/git',*args]
        assert host.seen[-1][1]==('init' if args[0]=='init' else 'measurement-command')

@pytest.mark.parametrize('args',(['add','USER'],['commit','-m','fixture'],['config','user.name','extra'],['ls-files','--others']))
def test_other_commands_refuse_before_any_launch(host,args):
    with pytest.raises(Refused,match='original source Git command'):
        measurement.proposal(host,{},raw(host,args))
    assert not host.seen

def test_provider_or_other_environment_cannot_be_inherited(host):
    request=raw(host,['init','-q'])
    request['environment']['OPENAI_API_KEY']='canary'
    with pytest.raises(Refused,match='original Git environment'):
        measurement.proposal(host,{},request)
    assert not host.seen


def test_original_source_setup_has_only_the_two_declared_git_calls():
    import ast
    from launch_policy import source_unit
    owner=source_unit(ROOT,measurement.TEST,measurement.PIN,('_source',))
    calls=[node for node in ast.walk(owner) if isinstance(node,ast.Call) and isinstance(node.func,ast.Attribute) and node.func.attr=='run']
    assert [ast.literal_eval(call.args[0]) for call in calls]==[['git','init','-q'],['git','add','.']]
