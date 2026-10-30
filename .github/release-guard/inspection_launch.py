"""Original fresh-process inspections and sealed-patch refusal replay."""
from pathlib import Path

from content_manifest import Refused
from owned_fixture import retain
from launch_policy import build_expected,source_unit,literal

FRONTIER='tests/test_coordinator.py::TestCurrentEvidenceFrontier::test_frontier_reconstructs_byte_identically_in_fresh_interpreters'
RECOVERY='tests/test_stranded_recovery.py::test_real_cli_inspection_after_recovery'
SEALED='tests/test_coordinator.py::TestCurrentEvidenceFrontier::test_invalid_cycle_rejects_before_persistence_and_cleared_gate_stays_sealed'
CASES=(FRONTIER,RECOVERY,SEALED)
REPLAY='tests/fixtures/evidence_frontier_v045/replay.py'
REPLAY_PIN='5296e65bdf9bd8a7896636e71a503f0965a6ebbcfebb49ce0147b44d976fe8a9'
PINS={'tests/test_coordinator.py': '8ab30d0ce4bc4a318c3fd5f8fc295fb506e76dab128be6324dc5ab3713a6eeec', 'tests/test_stranded_recovery.py': '07dc29e2387be16906373ef66b02d5e508744a084284486da5d4fb69c71c8f7b'}
OWNER=20000


def expected(host,argv,cwd,environment,native,pin):
    case=host.case
    if case not in CASES or len(argv)!=(6 if case==RECOVERY else 5):
        raise Refused('inspection finite original arguments')
    checkout=Path(host.meta['checkout'])
    path=case.split('::')[0]
    if case==SEALED:
        source_unit(checkout,path,PINS[path],case.split('::')[1:])
        source_unit(checkout,REPLAY,REPLAY_PIN)
        home=Path(argv[3])
        root=home.parent
        project_id=argv[4]
        vector=(native,str(checkout/REPLAY),'sealed-patch',str(root/'.unrest'),project_id)
        expected_cwd=str(checkout)
    elif case==FRONTIER:
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
    root=retain(host,root,case.split('::')[-1][:30],OWNER)
    if (home!=root/('home' if case==RECOVERY else '.unrest') or home.resolve()!=home
            or not project_id or Path(project_id).name!=project_id or project_id in ('.','..')):
        raise Refused('inspection owned original home')
    record=home/'projects'/project_id/'.unrest-runtime/project.json'
    if record.resolve()!=record:
        raise Refused('inspection aliased project record')
    return build_expected(case,native,pin,vector,tuple(sorted(environment.items())),expected_cwd,'python-script' if case==SEALED else 'python-command',REPLAY_PIN if case==SEALED else None)
