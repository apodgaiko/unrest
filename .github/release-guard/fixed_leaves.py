"""Closed fixed-leaf launches with shared custody context and finalization."""
import hashlib
from pathlib import Path
import stat

from content_manifest import Refused, refuse_if
from owned_fixture import retain
from launch_policy import build_expected,source_unit,literal

OWNER=20000
STORAGE_TEST='tests/test_storage.py'
STORAGE_PREFIX=STORAGE_TEST+'::TestAtomicWriteText::'
FAIL=STORAGE_PREFIX+'test_failure_preserves_target_and_cleans_unique_temp'
DIRECTORY=STORAGE_PREFIX+'test_directory_fsync_failure_accepts_visible_generation'
NESTED=STORAGE_PREFIX+'test_regular_nested_destinations_remain_atomic'
STORAGE_CASES=(*(FAIL+'['+stage+']' for stage in ('write','content_fsync','replace')),DIRECTORY,
    *(NESTED+f'[{existing}-{depth}-{relative}]' for existing in ('fresh','existing')
      for depth in (0,1,3) for relative in ('absolute','relative')))
PROGRAM='import pathlib,sys; sys.stdout.buffer.write(pathlib.Path(sys.argv[1]).read_bytes())'
FRONTIER='tests/test_coordinator.py::TestCurrentEvidenceFrontier::test_frontier_reconstructs_byte_identically_in_fresh_interpreters'
RECOVERY='tests/test_stranded_recovery.py::test_real_cli_inspection_after_recovery'
SEALED='tests/test_coordinator.py::TestCurrentEvidenceFrontier::test_invalid_cycle_rejects_before_persistence_and_cleared_gate_stays_sealed'
INSPECTION_CASES=(FRONTIER,RECOVERY,SEALED)
REPLAY='tests/fixtures/evidence_frontier_v045/replay.py'
REPLAY_PIN='5296e65bdf9bd8a7896636e71a503f0965a6ebbcfebb49ce0147b44d976fe8a9'
INSPECTION_PINS={'tests/test_coordinator.py': '8ab30d0ce4bc4a318c3fd5f8fc295fb506e76dab128be6324dc5ab3713a6eeec', 'tests/test_stranded_recovery.py': '07dc29e2387be16906373ef66b02d5e508744a084284486da5d4fb69c71c8f7b'}
PUBLICATION='tests/test_completion_ownership.py::test_interrupted_publication_and_lock_recovery'
MARKER='tests/test_completion_setup.py::test_consumed_marker_survives_recovery_interruption'
SETUP='tests/test_completion_setup.py::test_process_dies_during_first_setup'
COMPLETION_CASES={**{PUBLICATION+'['+phase+']':('attempt.json',phase) for phase in ('before','after')},
    **{MARKER+'['+kind+'-'+phase+']':('marker.json',phase)
       for kind in ('corrupt','wrong-mode','symlink') for phase in ('temporary','before-replace','after-replace')},
    SETUP:('bucket/.unrest-runtime/attempts/result.json',None)}
COMPLETION_SEQUENCES={case:('crash','retry') if case.startswith(PUBLICATION+'[') else ('crash',) for case in COMPLETION_CASES}
COMPLETION_PINS={'tests/test_completion_ownership.py': '2b67510bdd8f40d584baab65837174b2f5a3935aff343b7d9eaccedf09b5df8b', 'tests/test_completion_setup.py': 'fe1a1c98792d1b30d81d975cb23ad9122ae74678295ef4ed8c5e532a7aa00b6a'}
MEASUREMENT_CASE='tests/test_v046_measurement_helpers.py::test_four_arm_simulation_uses_independent_terminal_counts'
MEASUREMENT_TOOL='tools/measure_v046_flow.py'
MEASUREMENT_FIXTURE='tests/fixtures/v046_measurement/flow-cases.json'
MEASUREMENT_PINS={'tests/test_v046_measurement_helpers.py': '019efe94eda1c806082d4880195e12da4d9529e349bb4ab4e55e7c277b03e736', 'tools/measure_v046_flow.py': '650286242250c0a112021f31a2c152b2d682ba32f12488a2fb280d173e3b96a4', 'tests/fixtures/v046_measurement/flow-cases.json': '8c081b8e5f3b6d11a397c7bf64f55f0a377d021bc0395ef0349d5738e7f4b08b'}


def expected(host,operation,argv,cwd,environment,native,pin):
    case=host.case
    checkout,owned=Path(host.meta['checkout']),Path(host.meta['owned'])
    kind,reference,expected_cwd='python-command',None,cwd
    if case in STORAGE_CASES:
        refuse_if(len(argv)!=4, 'storage finite read declaration')
        target=Path(argv[3])
        actual=Path(cwd)/target
        try:
            root=owned/'pytest'/actual.relative_to(owned/'pytest').parts[0]
        except (ValueError,IndexError):
            raise Refused('storage owned fixture root') from None
        root=retain(host,root, OWNER)
        location=Path(cwd)
        if (actual.resolve()!=actual or location.resolve()!=location
                or location!=checkout and not location.is_relative_to(root)):
            raise Refused('storage canonical owned read path')
        file=actual.stat(follow_symlinks=False)
        if not stat.S_ISREG(file.st_mode) or file.st_uid!=OWNER or file.st_nlink!=1:
            raise Refused('storage owned regular read input')
        vector=(native,'-c',PROGRAM,str(target))
    elif case in INSPECTION_CASES:
        refuse_if(len(argv)!=(6 if case==RECOVERY else 5), 'inspection finite original arguments')
        path=case.split('::')[0]
        if case==SEALED:
            source_unit(checkout,path,INSPECTION_PINS[path],case.split('::')[1:])
            source_unit(checkout,REPLAY,REPLAY_PIN)
            home=Path(argv[3])
            root=home.parent
            project_id=argv[4]
            vector=(native,str(checkout/REPLAY),'sealed-patch',str(root/'.unrest'),project_id)
            expected_cwd=str(checkout)
        elif case==FRONTIER:
            home=Path(argv[3])
            root=home.parent
            script=literal(source_unit(checkout,path,INSPECTION_PINS[path],case.split('::')[1:]),'script')
            project_id=argv[4]
            vector=(native,'-c',script,str(root/'.unrest'),project_id)
            expected_cwd=str(checkout)
        else:
            source_unit(checkout,path,INSPECTION_PINS[path])
            root=Path(cwd)
            home=root/'home'
            project_id=argv[5]
            environment={**environment,'UNREST_HOME':str(home),'UNREST_PROJECTS_DIR':str(home/'projects')}
            vector=(native,'-c','from unrest_harness.cli import cli; cli()','inspect-tasks','--project',project_id)
            expected_cwd=str(root)
        root=retain(host,root, OWNER)
        if (home!=root/('home' if case==RECOVERY else '.unrest') or home.resolve()!=home
                or not project_id or Path(project_id).name!=project_id or project_id in ('.','..')):
            raise Refused('inspection owned original home')
        record=home/'projects'/project_id/'.unrest-runtime/project.json'
        refuse_if(record.resolve()!=record, 'inspection aliased project record')
        kind,reference=('python-script',REPLAY_PIN) if case==SEALED else ('python-command',None)
    elif case in COMPLETION_CASES:
        refuse_if(operation not in COMPLETION_SEQUENCES[case], 'completion exact primitive sequence')
        suffix,phase=COMPLETION_CASES[case]
        refuse_if(len(argv)!=(5 if operation=='crash' and phase is not None else 4), 'completion original argument count')
        path,name=case.split('::')
        name=name.split('[')[0]
        program=literal(source_unit(checkout,path,COMPLETION_PINS[path],(name,)),'retry' if operation=='retry' else 'script')
        root=Path(argv[3]).parents[len(Path(suffix).parts)-1]
        root=retain(host,root, OWNER)
        refuse_if(cwd!=str(checkout), 'completion changed fixture generation or cwd')
        vector=(native,'-c',program,str(root/suffix),*((phase,) if operation=='crash' and phase is not None else ()))
    elif case==MEASUREMENT_CASE:
        refuse_if(len(argv)!=8, 'simulation exact original case')
        for path,digest in MEASUREMENT_PINS.items():
            refuse_if(hashlib.sha256((checkout/path).read_bytes()).hexdigest()!=digest, 'simulation original input bytes')
        root=retain(host,Path(argv[7]).parent, OWNER)
        vector=(native,str(checkout/MEASUREMENT_TOOL),'--case-manifest',str(checkout/MEASUREMENT_FIXTURE),
            '--mode','simulated','--output',str(root/'flow.json'))
        refuse_if(cwd!=str(checkout), 'simulation original working directory')
        kind,reference='python-script',MEASUREMENT_PINS[MEASUREMENT_TOOL]
    else:
        raise Refused('fixed leaf has no declaration')
    return build_expected(case,native,pin,vector,tuple(sorted(environment.items())),expected_cwd,kind,reference)
