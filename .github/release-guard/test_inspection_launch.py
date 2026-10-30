"""Fresh inspection inputs bind the original literal and actual owned project."""
import ast
import json
import os
from pathlib import Path
from types import SimpleNamespace

import pytest

from content_manifest import Refused
from fixed_inline import SEQUENCES
import inspection_launch as inspection

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
    if case==inspection.SEALED:
        argv=['/native/python',str(ROOT/inspection.REPLAY),'sealed-patch',str(home),project]
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


@pytest.mark.parametrize('case',inspection.CASES)
def test_original_byte_and_operand_parity_binds_owned_project_path(tmp_path,monkeypatch,case):
    host,argv,cwd,env,record=fixture(tmp_path,monkeypatch,case)
    value=inspection.expected(host,argv,cwd,env,argv[0],'a'*64)
    assert value.argv==tuple(argv) and value.cwd==cwd
    assert len(SEQUENCES[case])==(2 if case==inspection.FRONTIER else 1)
    expected=env if case!=inspection.RECOVERY else {**env,'UNREST_HOME':str(record.parents[3]),'UNREST_PROJECTS_DIR':str(record.parents[2])}
    assert dict(value.environment)==expected


@pytest.mark.parametrize('case',inspection.CASES)
@pytest.mark.parametrize('mutation',['id','workspace','missing','alias','generation','pid-path'])
def test_inspection_cannot_borrow_foreign_or_stale_project_input(tmp_path,monkeypatch,case,mutation):
    host,argv,cwd,env,record=fixture(tmp_path,monkeypatch,case)
    inspection.expected(host,argv,cwd,env,argv[0],'a'*64)
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
        argv[-1]='../foreign'
    if mutation in ('id','workspace','missing'):
        value=inspection.expected(host,argv,cwd,env,argv[0],'a'*64)
        assert value.argv==tuple(argv)
    else:
        with pytest.raises((Refused,FileNotFoundError)):
            inspection.expected(host,argv,cwd,env,argv[0],'a'*64)
