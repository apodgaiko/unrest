"""Two non-launching original fresh-interpreter project inspections."""
import json
from pathlib import Path

from content_manifest import Refused,read_regular
from owned_fixture import acquire
from control_transport import unique
from launch_policy import build_expected,source_unit,literal

FRONTIER='tests/test_coordinator.py::TestCurrentEvidenceFrontier::test_frontier_reconstructs_byte_identically_in_fresh_interpreters'
RECOVERY='tests/test_stranded_recovery.py::test_real_cli_inspection_after_recovery'
CASES=(FRONTIER,RECOVERY)
PINS={'tests/test_coordinator.py': '8ab30d0ce4bc4a318c3fd5f8fc295fb506e76dab128be6324dc5ab3713a6eeec', 'tests/test_stranded_recovery.py': '07dc29e2387be16906373ef66b02d5e508744a084284486da5d4fb69c71c8f7b'}
OWNER=20000


def expected(host,argv,cwd,environment,native,pin):
    case=host.case
    if case not in CASES or len(argv)!=(5 if case==FRONTIER else 6):
        raise Refused('inspection finite original arguments')
    checkout,owned=Path(host.meta['checkout']),Path(host.meta['owned'])
    path=case.split('::')[0]
    if case==FRONTIER:
        home=Path(argv[3])
        root=home.parent
        script=literal(source_unit(checkout,path,PINS[path],case.split('::')[1:]),'script')
        project_id=argv[4]
        vector=(native,'-c',script,str(root/'.unrest'),project_id)
        expected_cwd=str(checkout)
    else:
        source_unit(checkout,path,PINS[path])
        root=Path(cwd)
        home=root/'home'
        project_id=argv[5]
        environment={**environment,'UNREST_HOME':str(home),'UNREST_PROJECTS_DIR':str(home/'projects')}
        vector=(native,'-c','from unrest_harness.cli import cli; cli()','inspect-tasks','--project',project_id)
        expected_cwd=str(root)
    root,info=acquire(str(root),owned,case.split('::')[-1][:30],OWNER)
    if (home!=root/('.unrest' if case==FRONTIER else 'home') or home.resolve()!=home
            or not project_id or Path(project_id).name!=project_id or project_id in ('.','..')):
        raise Refused('inspection owned original home')
    generation=(str(root),info.st_dev,info.st_ino)
    if host.fixture_roots.setdefault(case,generation)!=generation:
        raise Refused('inspection changed fixture generation')
    record=home/'projects'/project_id/'.unrest-runtime/project.json'
    if record.resolve()!=record:
        raise Refused('inspection aliased project record')
    raw,_,_=read_regular(record,65536,uid=OWNER)
    value=json.loads(raw,object_pairs_hook=unique)
    if type(value) is not dict or value.get('id')!=project_id or value.get('workspace_dir')!=str(root/'workspace'):
        raise Refused('inspection actual original project identity')
    return build_expected('fixed:inspection',case,native,pin,vector,tuple(sorted(environment.items())),expected_cwd,'python-command')
