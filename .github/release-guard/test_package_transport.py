"""Original package commands and complete real-report/exit joins remain distinct."""
import hashlib
import os
from pathlib import Path
from types import SimpleNamespace

import pytest

from content_manifest import Refused
import package_proposals as transport
from package_cases import POSITIVE, NEGATIVE, MUTATIONS, FIRST, LIFECYCLE, DISTRIBUTION, literal, PINS, CONTRACT
from source_observer import Observer
from source_root import local_cases
import source_root
from postbuild_root import CASES
from archive_leaf import finish

ROOT=next(p for p in Path(__file__).resolve().parents if (p/'pyproject.toml').is_file())


def test_original_source_units_and_distribution_selection_are_byte_current():
    for name,pin in PINS.items():
        assert hashlib.sha256((ROOT/name).read_bytes()).hexdigest()==pin
    probe=literal(ROOT,'tools/check_distribution.py',None,'_PYTEST_PROBE')
    assert 'pytest.main(["-q", "tests/test_persistence_schema_v1.py"]' in probe
    assert literal(ROOT,CONTRACT,'_run_installed_lifecycle','script')
    assert literal(ROOT,'tests/contracts/conftest.py',None,'PROVENANCE_BODY')
    assert len(MUTATIONS)==14 and len(NEGATIVE)==2 and POSITIVE not in MUTATIONS


def test_native_catalogue_matches_normal_original_collection(monkeypatch):
    monkeypatch.setenv('PYTEST_DISABLE_PLUGIN_AUTOLOAD','1')
    rows=[]
    class Collector:
        def pytest_collection_finish(self,session):
            rows.extend(item.nodeid for item in session.items)
    result=pytest.main(['--collect-only','-q','-o','addopts=',
        'tests/test_distribution_check.py'],plugins=[Collector()])
    assert result==0 and len(rows)==19
    assert tuple(node for node in rows if node in DISTRIBUTION)==DISTRIBUTION
    assert set(rows)-set(DISTRIBUTION)=={
        'tests/test_distribution_check.py::test_v045_public_assets_and_api_exports_are_in_source_package',
        'tests/test_distribution_check.py::test_safe_extraction_rejects_traversal_member'}


def host(tmp_path,monkeypatch,case):
    monkeypatch.setattr(transport,'SOURCE_UID',os.getuid())
    monkeypatch.setattr(transport,'PREPARED_UID',os.getuid())
    archives=tmp_path/'prepared/archives'
    archives.mkdir(parents=True)
    for name in ('candidate.whl','candidate.tar.gz'):
        (archives/name).write_bytes(name.encode())
    data={'dist':archives,'installed_site':tmp_path/'prepared/installed','dependency_site':tmp_path/'dependencies'}
    calls=[]
    value=SimpleNamespace(case=case,meta={'checkout':str(ROOT),'owned':str(tmp_path)},
        binding={'entry':{'path':'/native/python','sha256':'a'*64}},
        fixture_roots={'<prepared-distribution>':data},intents={},root_only=lambda actor:None,
        meta_environment=lambda:{'HOME':str(tmp_path/'home'),'TMPDIR':str(tmp_path/'tmp'),'PATH':'/usr/bin:/bin'})
    def admit(actor,expected,role,vector,reference):
        calls.append((expected,role,vector))
        value.intents[1]={}
        return {'ok':True,'ticket':1,'token':'owned'}
    value.admit_launch=admit
    return value,data,calls


@pytest.mark.parametrize('case',[POSITIVE,*MUTATIONS])
def test_original_checker_has_exact_path_environment_and_current_data(tmp_path,monkeypatch,case):
    value,data,calls=host(tmp_path,monkeypatch,case)
    dist=data['dist']
    if case in MUTATIONS:
        parent=tmp_path/'pytest'/(case.split('::')[1].split('[')[0][:30]+'0')
        parent.mkdir(parents=True,mode=0o700)
        dist=parent/MUTATIONS[case][0]
        dist.mkdir()
        for name in ('candidate.whl','candidate.tar.gz'):
            (dist/name).write_bytes(name.encode())
    env=transport.environment(value,case,'call')
    if case==POSITIVE:
        env['PYTHONPATH']=str(ROOT/'src')
    raw={'stdin':None,'argv':['/native/python','tools/check_distribution.py',str(dist)],
         'environment':env,'cwd':str(ROOT)}
    result=transport.proposal(value,{'role':'root'},raw)
    assert calls[-1][1]=='archive-checker'
    assert result['translated'][:4]==['/native/python','-I','-S','-c']
    row=value.intents[1]['package_inputs']
    transport.retained_archive(row,case)
    (dist/'candidate.whl').write_bytes(b'changed admitted generation')
    with pytest.raises(Refused,match='generation'):
        transport.retained_archive(row,case)


@pytest.mark.parametrize('case',[FIRST,LIFECYCLE])
def test_installed_bodies_and_arguments_are_original_and_checkout_excluded(tmp_path,monkeypatch,case):
    value,data,calls=host(tmp_path,monkeypatch,case)
    work=tmp_path/'pytest/candidate-distribution0'
    work.mkdir(parents=True,mode=0o700)
    if case==FIRST:
        body=literal(ROOT,'tests/contracts/conftest.py',None,'PROVENANCE_BODY')
        tail=[str(data['installed_site']),str(data['dependency_site'])]
        env=transport.environment(value,case,'setup')
        env.update(UV_CACHE_DIR='/tmp/unrest-worker-uv-cache',UV_OFFLINE='1')
    else:
        body=literal(ROOT,CONTRACT,'_run_installed_lifecycle','script')
        (work/'lifecycle-probe').mkdir()
        tail=[str(work/'lifecycle-probe'),str(ROOT),str(data['installed_site']),str(data['dependency_site'])]
        env=transport.environment(value,case,'call')
    raw={'stdin':None,'argv':['/native/python','-S','-c',body,*tail],'cwd':str(work),'environment':env}
    result=transport.proposal(value,{'role':'root'},raw)
    assert calls[-1][1]=='archive-installed'
    assert result['translated']==['/native/python','-I','-S','-c',body,*tail]
    assert 'restart' in body if case==LIFECYCLE else 'sys.path[:0] = sys.argv[1:3]' in body


def proof(monkeypatch,kind):
    calls=[]
    policy=SimpleNamespace(profile={'cases':[POSITIVE]},case=next(iter(NEGATIVE)) if kind!='normal' else POSITIVE,
        poison=False,client=SimpleNamespace(request=lambda *args:calls.append(args)))
    leaf=local_cases(policy,CASES,normal_outcomes=kind=='missing-corpus')
    monkeypatch.setattr(source_root,'Function',SimpleNamespace)
    items=[SimpleNamespace(nodeid=node) for node in CASES]
    leaf.pytest_collection_finish(SimpleNamespace(items=items))
    return policy,leaf,items,calls


@pytest.mark.parametrize('kind',['normal','missing-corpus'])
def test_every_real_report_phase_is_needed_before_result(monkeypatch,kind):
    policy,leaf,items,calls=proof(monkeypatch,kind)
    for item in items:
        protocol=leaf.pytest_runtest_protocol(item,None)
        next(protocol)
        for phase in ('setup','call','teardown'):
            outcome='failed' if kind=='missing-corpus' and phase=='call' else 'passed'
            leaf.pytest_runtest_logreport(SimpleNamespace(nodeid=item.nodeid,when=phase,outcome=outcome,
                failed=outcome=='failed',longreprtext='actual omitted corpus',sections=[]))
        with pytest.raises(StopIteration):
            next(protocol)
        assert not calls
    code=1 if kind=='missing-corpus' else 0
    assert finish(policy,kind,code,leaf,False,True)==code
    assert calls==[('archive-result',{'kind':kind,'count':15,'failed':15 if code else 0,'exit':code})]
    policy.poison=True
    with pytest.raises(Refused):
        finish(policy,kind,code,leaf,False,True)


@pytest.mark.parametrize('kind',['normal','missing-corpus','missing-package'])
def test_exit_or_missing_reports_cannot_substitute_for_actual_oracle(monkeypatch,kind):
    policy,leaf,_,calls=proof(monkeypatch,kind)
    with pytest.raises(Refused):
        finish(policy,kind,0 if kind=='normal' else 1,leaf,False,False)
    assert not calls


@pytest.mark.parametrize('case',[*MUTATIONS,*NEGATIVE])
def test_negative_parsing_or_leaf_roles_have_no_descendant_authority(case):
    value=SimpleNamespace(case=case,finished=False)
    with pytest.raises(Refused,match='owner'):
        Observer.launch_owner(value,{'role':'archive-checker','case':case,'body_ready':True})


@pytest.mark.parametrize('case',[POSITIVE,*NEGATIVE])
def test_archive_result_requires_its_consumed_actor_actual_exit_and_body(case):
    birth=object()
    actor={'role':'archive-leaf','case':case,'birth':birth,'token':'owned','body_ready':True}
    value=object.__new__(Observer)
    value.case=case
    value.intents={1:{'birth':birth,'token':'owned','case':case,'role':'archive-leaf','consumed':True}}
    value.intents[1].update(ticket=1,role=actor['role'],case=actor['case'])
    actor['intent']=value.intents[1]
    value.ledger=SimpleNamespace(process=lambda birth:SimpleNamespace(terminal=None))
    kind=NEGATIVE.get(case,'normal')
    code=1 if case in NEGATIVE else 0
    result={'kind':kind,'count':0 if kind=='missing-package' else 15,
            'failed':15 if kind=='missing-corpus' else 0,'exit':code}
    assert not value.completed_child(actor)
    assert value.dispatch(actor,{'kind':'archive-result','payload':result})=={'ok':True}
    assert not value.completed_child(actor)
    value.ledger.process=lambda birth:SimpleNamespace(terminal=(1,code<<8,code))
    assert value.completed_child(actor)
    actor['body_ready']=False
    assert not value.completed_child(actor)
    actor['body_ready']=True
    with pytest.raises(Refused):
        value.dispatch(actor,{'kind':'archive-result','payload':result})


@pytest.mark.parametrize('mutation',['role','case','birth','token','consumed','body','boolean','count'])
def test_foreign_or_incomplete_archive_result_cannot_seal(mutation):
    birth=object()
    actor={'role':'archive-leaf','case':POSITIVE,'birth':birth,'token':'owned','body_ready':True}
    value=object.__new__(Observer)
    value.case=POSITIVE
    value.intents={1:{'birth':birth,'token':'owned','case':POSITIVE,'role':'archive-leaf','consumed':True}}
    value.intents[1].update(ticket=1,role=actor['role'],case=actor['case'])
    actor['intent']=value.intents[1]
    result={'kind':'normal','count':15,'failed':0,'exit':0}
    if mutation=='role':
        actor['role']='root'
    elif mutation=='case':
        actor['case']='foreign'
    elif mutation=='birth':
        actor['birth']=object()
    elif mutation=='token':
        actor['token']='foreign'
    elif mutation=='consumed':
        value.intents[1]['consumed']=False
    elif mutation=='body':
        actor['body_ready']=False
    elif mutation=='boolean':
        result['exit']=False
    else:
        result['count']=14
    with pytest.raises(Refused):
        value.dispatch(actor,{'kind':'archive-result','payload':result})
    assert 'archive_result' not in actor



def test_prepared_auxiliary_members_are_bound_but_never_treated_as_archives(tmp_path,monkeypatch):
    value,data,_=host(tmp_path,monkeypatch,POSITIVE)
    (data['dist']/'.gitignore').write_bytes(b'*\n')
    row=transport.archive_inputs(data['dist'],POSITIVE)
    assert [member[0] for member in row[2]]==['.gitignore','candidate.tar.gz','candidate.whl']
    transport.retained_archive(row,POSITIVE)
    (data['dist']/'.gitignore').write_bytes(b'changed')
    with pytest.raises(Refused,match='generation'):
        transport.retained_archive(row,POSITIVE)
    with pytest.raises(Refused,match='two-member'):
        transport.archive_inputs(data['dist'],next(iter(MUTATIONS)))


def test_standalone_archive_seals_root_only_after_all_fifteen_real_reports(monkeypatch):
    from source_profile import case_seal
    policy,leaf,_,calls=proof(monkeypatch,'normal')
    policy.profile.update(role='root',cases=list(CASES))
    leaf.completed=list(CASES)
    leaf.reports={case:{phase:'passed' for phase in ('setup','call','teardown')} for case in CASES}
    assert finish(policy,'normal',0,leaf,False,True)==0
    assert calls==[('root-finish',case_seal(CASES))]
    leaf.reports[CASES[-1]]['teardown']='failed'
    with pytest.raises(Refused):
        finish(policy,'normal',0,leaf,False,True)
    assert len(calls)==1
