"""Fresh inspection inputs bind the original literal and actual owned project."""
import ast
import json
import os
from pathlib import Path
from types import SimpleNamespace

import pytest

from content_manifest import Refused
from fixed_inline import SEQUENCES
import fixed_leaves as inspection

ROOT=next(p for p in Path(__file__).resolve().parents if (p/'pyproject.toml').is_file())


def fixture(tmp_path,monkeypatch,case):
    monkeypatch.setattr(inspection,'OWNER',os.getuid())
    owned=tmp_path/'owned'
    root=owned/'pytest'/(case.split('::')[-1][:30]+'0')
    home=root/('home' if case==inspection.RECOVERY else '.unrest')
    project='20261029T000000Z-original-project'
    record=home/'projects'/project/'.unrest-runtime/project.json'
    record.parent.mkdir(parents=True)
    record.write_text(json.dumps({'id':project,'workspace_dir':str(root/'workspace')}))
    env={'PATH':'/bin:/usr/bin'}
    host=SimpleNamespace(case=case,meta={'checkout':str(ROOT),'owned':str(owned)},fixture_roots={})
    if case in inspection.PROJECTION_CASES:
        from launch_policy import source_unit,literal
        from completion_roles import PINS
        body=literal(source_unit(ROOT,'tests/test_server.py',PINS['tests/test_server.py'],('_fresh_process_project_projection',)),'script')
        argv=['/native/python','-c',body,str(ROOT/'src/unrest_harness/bundled'),str(home),str(home/'projects'),project]
        cwd=str(ROOT)
    elif case==inspection.SEALED or case in inspection.RETIREMENT_CASES:
        argv=['/native/python',str(ROOT/inspection.REPLAY),'gate' if case in inspection.RETIREMENT_CASES else 'sealed-patch',str(home),project,*(('g1',) if case in inspection.RETIREMENT_CASES else ())]
        cwd=str(ROOT)
    elif case==inspection.FRONTIER:
        tree=ast.parse((ROOT/case.split('::')[0]).read_bytes())
        owner=next(node for node in tree.body if isinstance(node,ast.ClassDef) and node.name=='TestCurrentEvidenceFrontier')
        function=next(node for node in owner.body if isinstance(node,ast.FunctionDef) and node.name==case.split('::')[-1])
        program=next(ast.literal_eval(node.value) for node in function.body if isinstance(node,ast.Assign) and isinstance(node.targets[0],ast.Name) and node.targets[0].id=='script')
        argv=['/native/python','-c',program,str(home),project]
        cwd=str(ROOT)
    else:
        argv=['/native/python','-c','from unrest_harness.cli import cli; cli()','inspect-tasks','--project',project]
        cwd=str(root)
    return host,argv,cwd,env,record


@pytest.mark.parametrize('case',inspection.INSPECTION_CASES)
def test_original_byte_and_operand_parity_binds_owned_project_path(tmp_path,monkeypatch,case):
    host,argv,cwd,env,record=fixture(tmp_path,monkeypatch,case)
    value=inspection.expected(host,None,argv,cwd,env,argv[0],'a'*64)
    assert value.argv==tuple(argv) and value.cwd==cwd
    assert len(SEQUENCES[case])==(2 if case in (inspection.FRONTIER,*inspection.RETIREMENT_CASES) else 1)
    expected=env if case!=inspection.RECOVERY else {**env,'UNREST_HOME':str(record.parents[3]),'UNREST_PROJECTS_DIR':str(record.parents[2])}
    assert dict(value.environment)==expected


@pytest.mark.parametrize('case',inspection.INSPECTION_CASES)
@pytest.mark.parametrize('mutation',['id','workspace','missing','alias','generation','pid-path'])
def test_inspection_cannot_borrow_foreign_or_stale_project_input(tmp_path,monkeypatch,case,mutation):
    host,argv,cwd,env,record=fixture(tmp_path,monkeypatch,case)
    inspection.expected(host,None,argv,cwd,env,argv[0],'a'*64)
    if mutation in ('id','workspace'):
        value=json.loads(record.read_bytes())
        value['id' if mutation=='id' else 'workspace_dir']='foreign'
        record.write_text(json.dumps(value))
    elif mutation=='missing':
        record.unlink()
    elif mutation=='alias':
        record.rename(record.with_suffix('.old'))
        record.symlink_to(record.with_suffix('.old'))
    elif mutation=='generation':
        host.fixture_roots[case]=('foreign',1,1)
    else:
        argv[4 if case in inspection.RETIREMENT_CASES else -1]='../foreign'
    if mutation in ('id','workspace','missing'):
        value=inspection.expected(host,None,argv,cwd,env,argv[0],'a'*64)
        assert value.argv==tuple(argv)
    else:
        with pytest.raises((Refused,FileNotFoundError)):
            inspection.expected(host,None,argv,cwd,env,argv[0],'a'*64)


@pytest.mark.parametrize('case',inspection.RETIREMENT_CASES)
@pytest.mark.parametrize('position,value',[(1,'/foreign/replay.py'),(2,'sealed-patch'),(5,'foreign-gate')])
def test_retirement_replay_keeps_exact_program_mode_and_gate(tmp_path,monkeypatch,case,position,value):
    from launch_policy import check_expected
    host,argv,cwd,env,_=fixture(tmp_path,monkeypatch,case)
    argv[position]=value
    expected=inspection.expected(host,None,argv,cwd,env,argv[0],'a'*64)
    with pytest.raises(Refused,match='original launch operands'):
        check_expected({'argv':argv,'environment':env,'cwd':cwd},expected)


@pytest.mark.parametrize('case',inspection.PROJECTION_CASES)
@pytest.mark.parametrize('position,value',[(2,'print("foreign")'),(3,'/foreign/bundled'),(5,'/foreign/projects')])
def test_fresh_projection_keeps_pinned_script_policy_and_projects(tmp_path,monkeypatch,case,position,value):
    from launch_policy import check_expected
    host,argv,cwd,env,_=fixture(tmp_path,monkeypatch,case)
    argv[position]=value
    expected=inspection.expected(host,None,argv,cwd,env,argv[0],'a'*64)
    with pytest.raises(Refused,match='original launch operands'):
        check_expected({'argv':argv,'environment':env,'cwd':cwd},expected)
