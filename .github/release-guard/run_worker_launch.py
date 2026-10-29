"""Two original async error paths reuse the guarded library-module entry."""
from pathlib import Path
import json
import os
import re

from content_manifest import Refused,read_regular,native_digest
from control_transport import unique
from git_fixtures import root as repository_root
from launch_policy import build_expected,admit_expected

CASES={
    'tests/test_foundation_authority.py::test_tool_error_mapping_is_closed_and_private_details_survive_async_run':'submit_plan',
    'tests/test_foundation_authority.py::test_async_project_lock_contention_is_public_busy_with_private_cause':'end_mission',
}


def proposal(host,actor,raw):
    host.root_only(actor)
    case=host.case
    if case not in CASES or any(row['case']==case and row.get('run_worker') for row in host.intents.values()):
        raise Refused('async error worker exact case and count')
    home=Path(raw['cwd'])
    repository_root(host,case,str(home.parent/'repo'))
    if home.name!='.unrest' or home.resolve()!=home:
        raise Refused('async error worker original home')
    argv=raw['argv']
    if len(argv)!=13 or not re.fullmatch('run:[a-f0-9]{64}',argv[6]):
        raise Refused('async error worker bounded run identity')
    run=argv[6]
    record,_,_=read_regular(home/'.unrest/runs'/run[4:]/'request.json',65536,uid=20000,mode=0o600)
    document=json.loads(record,object_pairs_hook=unique)
    if document.get('run_id')!=run or document.get('operation')!=CASES[case] or document.get('generation')!=1:
        raise Refused('async error worker exact retained request')
    native,pin=host.binding['entry']['path'],host.binding['entry']['sha256']
    vector=[native,'-m','unrest_harness.run_worker','--project-root',str(home),'--run-id',run,
            '--executor','unrest_harness.runtime_executor:execute','--custody-root-id','local:unrest-run-control','--generation','1']
    env={'LANG':'C.UTF-8','PATH':os.defpath,'PYTHONPATH':str(Path(host.meta['checkout'])/'src'),
         'UNREST_APPROVAL_RECOVERY':'0','UNREST_HOME':str(home),'UNREST_PROJECTS_DIR':str(home/'projects')}
    expected=build_expected('async:error-worker',case,native,pin,tuple(vector),tuple(sorted(env.items())),str(home),'python-module',native_digest(Path(host.meta['checkout'])/'src/unrest_harness/run_worker.py'))
    return admit_expected(host,actor,raw,expected,'fixed-inline',[native,'-I','-S',*vector[1:]],maximum=1,
                          fields={'run_worker':True,'null_stdio':True})
