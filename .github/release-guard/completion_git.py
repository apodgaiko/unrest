"""Two root fixture mutations and bounded server-owned read-only HEAD queries."""
from pathlib import Path

from completion_roles import CASES,SOURCE,ROOT_QUERIES,DEFECT,schedule,root,actor_slot
from content_manifest import Refused
from custody_git import repository
from git_commands import Command
from git_observer import issue
from composed_cases import CASES as COMPOSED,queries

FIXTURE=(('git','init','-q'),('git','-c','user.name=Test','-c','user.email=test@example.invalid',
    'commit','--allow-empty','-qm','base'))


def fixture(case):
    return (FIXTURE[0],('git','add','product.txt'),
        ('git','-c','user.name=Test','-c','user.email=test@example.invalid','commit','-qm','defective candidate')) if case==DEFECT else FIXTURE


APP_KEYS=frozenset(('UNREST_HOME','UNREST_PROJECTS_DIR','UNREST_PROJECT_ID','UNREST_MISSION_ID',
    'UNREST_NODE_ID','UNREST_NODE_TYPE','UNREST_HANDOFF_PATH','UNREST_NODE_ASSIGNMENT'))


def application_environment(baseline,observed):
    expected={**baseline,**{key:value for key,value in observed.items() if key in APP_KEYS}}
    if observed!=expected:
        raise Refused('Git environment outside closed application metadata')
    return expected


def ready(host,workspace):
    identity=repository(str(workspace),Path(host.meta['owned']),initialize=False)
    if host.fixture_roots.get(('completion-git-root',host.case))!=identity:
        raise Refused('completion fixture repository generation changed')


def proposal(host,actor,raw):
    case=host.case
    if case not in CASES or raw['stdin'] is not None or raw['executable']!='/usr/bin/git':
        raise Refused('completion exact Git proposal')
    parent=root(host,raw['cwd'])
    workspace=parent/'workspace'
    records=[row for row in host.intents.values() if row['case']==case and row['role']=='git-command'
             and row['parent']==actor['birth']]
    base={**host.meta_environment(),'PYTEST_VERSION':'9.0.2','PYTEST_CURRENT_TEST':case+' (call)'}
    commands=fixture(case)
    if actor['role']=='root':
        host.root_only(actor)
        if (len(records)>=len(commands)+ROOT_QUERIES.get(case,0)
                or any(row['case']==case and 'server_slot' in row for row in host.intents.values())):
            raise Refused('completion root fixture sequence')
        is_fixture=len(records)<len(commands)
        if is_fixture:
            vector=commands[len(records)]
            identity=repository(str(workspace),Path(host.meta['owned']),initialize=not records)
            key=('completion-git-root',case)
            previous=host.fixture_roots.setdefault(key,identity)
            if previous[0]!=identity[0] or previous[1] is not None and previous[1]!=identity[1]:
                raise Refused('completion fixture repository generation')
            host.fixture_roots[key]=identity
            environment=base
        else:
            ready(host,workspace)
            vector=('git','rev-parse','HEAD')
            environment=application_environment(base,raw['environment']) if case in SOURCE else base
        command=Command(vector,str(workspace))
    else:
        if case in COMPOSED:
            from composed_runtime import query_quota
            quota=query_quota(host,actor)
        else:
            server=actor_slot(host,actor)
            quota=schedule(case)[server['server_slot']][2]
        if len(records)>=quota:
            raise Refused('completion server-owned Git query quota')
        ready(host,workspace)
        is_fixture=False
        vector=('git','rev-parse','HEAD')
        command=Command(vector,str(workspace))
        environment=dict(actor['profile']['environment'])
    return issue(host,actor,raw,command,environment,
        maximum=len(commands)+ROOT_QUERIES.get(case,0)+(queries(case) if case in COMPOSED else sum(row[2] for row in schedule(case))),
        fields={'command':command,'repository':str(workspace),'operation':'completion-fixture' if is_fixture else 'completion-head',
            'fixture_git':is_fixture})
