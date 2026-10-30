"""Provider-free source fixtures cannot acquire other Git or process authority."""
from pathlib import Path
from types import SimpleNamespace
import pytest
from content_manifest import Refused
import git_policy as measurement

ROOT=Path(__file__).resolve().parents[2]

@pytest.fixture
def host(monkeypatch):
    import git_policy as git_observer
    monkeypatch.setattr(git_observer,'image',lambda:'a'*64)
    value=SimpleNamespace(case=measurement.MEASUREMENT_CASES[0],meta={'checkout':str(ROOT)},
        binding={'entry':{'path':'/native/python'}},intents={},seen=[])
    value.root_only=lambda actor:None
    value.meta_environment=lambda:{'PATH':'/usr/bin:/bin'}
    from git_policy import Git
    value.git=Git(value)
    value.git.repository=lambda repository,*args:Path(repository)
    value.git.location=lambda *args:None
    def admit(actor,expected,role,vector,pin,**options):
        value.seen.append(expected)
        value.intents[1]={}
        return {'ticket':1,'token':'child','ok':True}
    value.admit_launch=admit
    return value

def raw(host,args):
    environment={**host.meta_environment(),'PYTEST_VERSION':'9.0.2','PYTEST_CURRENT_TEST':host.case+' (call)'}
    if args==['ls-files','-z','--stage'] and host.case.split('::')[1] in measurement.MEASUREMENT_SYNTHETIC:
        command='/native/python '+str(ROOT/'tests/mock_measurement_acp.py')
        environment.update(UNREST_WORKER_ACP_COMMAND=command,UNREST_VALIDATOR_ACP_COMMAND=command)
    return {'executable':'/usr/bin/git','argv':['git',*args],'stdin':None,'environment':environment,'cwd':'/owned/pytest/test_case0/source'}

@pytest.mark.parametrize('case',measurement.MEASUREMENT_CASES)
def test_every_original_source_fixture_has_exact_commands(host,case):
    host.case=case
    for args in (['init','-q'],['add','.'],['ls-files','-z','--stage']):
        result=measurement.measurement_proposal(host,{'role':'root'},raw(host,args))
        assert result['translated']==['/usr/bin/git',*args]
        assert host.intents[1]['operation']==('init' if args[0]=='init' else 'measurement-command')

@pytest.mark.parametrize('args',(['add','USER'],['commit','-m','fixture'],['config','user.name','extra'],['ls-files','--others']))
def test_other_commands_refuse_before_any_launch(host,args):
    with pytest.raises(Refused,match='original source Git command'):
        measurement.measurement_proposal(host,{'role':'root'},raw(host,args))
    assert not host.seen

def test_provider_or_other_environment_cannot_be_inherited(host):
    request=raw(host,['init','-q'])
    request['environment']['OPENAI_API_KEY']='canary'
    with pytest.raises(Refused,match='original launch operands'):
        measurement.measurement_proposal(host,{'role':'root'},request)
    assert not host.seen


def test_original_source_setup_has_only_the_two_declared_git_calls():
    import ast
    from launch_policy import source_unit
    owner=source_unit(ROOT,measurement.MEASUREMENT_TEST,measurement.MEASUREMENT_PIN,('_source',))
    calls=[node for node in ast.walk(owner) if isinstance(node,ast.Call) and isinstance(node.func,ast.Attribute) and node.func.attr=='run']
    assert [ast.literal_eval(call.args[0]) for call in calls]==[['git','init','-q'],['git','add','.']]


@pytest.mark.parametrize('mutation',(None,'repetition','case','run','alias','generation'))
def test_cold_repositories_are_exact_case_repetition_and_directory_generations(tmp_path,monkeypatch,mutation):
    import os
    monkeypatch.setattr(measurement,'MEASUREMENT_OWNER',os.getuid())
    case=next(iter(measurement.MEASUREMENT_REAL))
    base=tmp_path/'pytest/test_case0'
    path=base/'home/measurement-private'/('a'*32)/'cold-roots/rep-11/workspace'
    path.mkdir(parents=True)
    host=SimpleNamespace(case=case,fixture_roots={('git-fixture',case):(str(base),)})
    if mutation=='repetition':
        path=path.parent.parent/'rep-01/workspace'
        path.mkdir(parents=True)
    elif mutation=='case':
        host.case=measurement.MEASUREMENT_CASES[0]
    elif mutation=='run':
        host.fixture_roots['measurement-run',case]='b'*32
    elif mutation=='alias':
        alias=path.parent/'alias'
        alias.symlink_to(path,target_is_directory=True)
        path=alias
    elif mutation=='generation':
        measurement.measurement_cold_root(host,path)
        path.rename(path.with_name('old'))
        path.mkdir()
    if mutation is None:
        measurement.measurement_cold_root(host,path)
        assert host.fixture_roots['measurement-run',case]=='a'*32
        assert host.fixture_roots['measurement-root',case,str(path)][0][0]==str(path)
    else:
        with pytest.raises(Refused):
            measurement.measurement_cold_root(host,path)

@pytest.mark.parametrize('mutation',(None,'exhausted','pending','unreaped','repetition'))
def test_evolution_workers_are_two_fixed_start_operations(host,monkeypatch,mutation):
    import run_worker_launch
    host.case=run_worker_launch.MEASUREMENT_EVOLUTION
    host.fixture_roots={}
    host.ledger=SimpleNamespace(reaped=lambda birth,token:mutation!='unreaped')
    previous={'case':host.case,'run_worker':True,'consumed':mutation!='pending','birth':'first','token':'first'}
    host.intents={} if mutation is None or mutation=='repetition' else {1:previous}
    if mutation=='exhausted':
        host.intents[2]=dict(previous)
    monkeypatch.setattr(measurement,'measurement_cold_root',lambda host,path:None)
    seen=[]
    def admit(*args):
        seen.append(args)
        host.intents[99]={}
        return {'ok':True,'ticket':99}
    monkeypatch.setattr(run_worker_launch,'admit_worker',admit)
    repetition=16 if host.intents else 11
    if mutation=='repetition':
        repetition=1
    request={'cwd':f'/owned/home/cold-roots/rep-{repetition:02d}/harness-home'}
    if mutation is None:
        assert measurement.measurement_worker(host,{},request)=={'ok':True,'ticket':99}
        assert seen[0][4]=='start_project' and seen[0][6:]==(2,)
        assert seen[0][5]['UNREST_APPROVAL_RECOVERY']=='0'
        assert set(seen[0][5])=={'LANG','PATH','PYTHONPATH','UNREST_HOME','UNREST_PROJECTS_DIR','UNREST_APPROVAL_RECOVERY','UNREST_WORKER_ACP_COMMAND','UNREST_VALIDATOR_ACP_COMMAND'}
    else:
        with pytest.raises(Refused):
            measurement.measurement_worker(host,{},request)
        assert not seen
