"""Original provider-free measurement source fixtures; no benchmark authority."""
from pathlib import Path
import re
import stat
from content_manifest import Refused
from launch_policy import source_unit,build_expected
from git_commands import Command,match as match_command

OWNER=20000
TEST='tests/test_measurement.py'
PIN='d850dcaf77c4b4ebd08efa87089cbc7b59762d5eb8d7fd0b673a9e043bc3e97f'
SYNTHETIC=('test_successful_exact_protocol_publishes_sanitized_recomputable_bundle',
    *(f'test_oracle_cache_and_cost_fail_closed[provider{index}-invalid]' for index in range(3)),
    'test_noise_over_fifteen_percent_is_inconclusive','test_unknown_reported_cost_is_not_collapsed_to_zero',
    'test_publication_rejects_unknown_or_private_fields_and_preserves_existing')
NAMES=(*SYNTHETIC,'test_evolution_cases_use_real_public_state_machine_and_cold_state',
    'test_project_cases_use_real_run_control_and_nested_acp','test_confirmation_and_protocol_drift_do_not_invoke_provider',
    'test_product_digest_excludes_only_results')
CASES=tuple(TEST+'::'+name for name in NAMES)
COLD=('inside','top','head','parent-ref','clean','inventory','verify-base','lease-add','checkout','stage-return','diff-return')
REAL={TEST+'::'+NAMES[-4]:(11,16),TEST+'::'+NAMES[-3]:(1,6)}


def proposal(host,actor,raw):
    from run_worker_launch import MEASUREMENT_PROJECT
    if host.case==MEASUREMENT_PROJECT and actor['role']!='root':
        from measurement_runtime import nested
        return nested(host,actor,raw)
    host.root_only(actor)
    checkout=Path(host.meta['checkout'])
    source_unit(checkout,TEST,PIN)
    argv=raw['argv']
    arguments=tuple(argv[1:])
    source=Path(raw['cwd']).name=='source'
    records=[slot for (case,repository),slot in host.git.repositories.items() if case==host.case
        and (raw['cwd']==repository or raw['cwd'].startswith(repository+'/.unrest-runtime/'))]
    repository=records[0]['path'] if len(records)==1 else raw['cwd']
    if len(records)>1 or raw['executable']!='/usr/bin/git' or argv[0]!='git':
        raise Refused('measurement original source Git command')
    environment={**host.meta_environment(),'PYTEST_VERSION':'9.0.2','PYTEST_CURRENT_TEST':host.case+' (call)'}
    if not source or arguments==('ls-files','-z','--stage') and host.case.split('::')[1] in SYNTHETIC:
        command=host.binding['entry']['path']+' '+str(checkout/'tests/mock_measurement_acp.py')
        environment.update(UNREST_WORKER_ACP_COMMAND=command,UNREST_VALIDATOR_ACP_COMMAND=command)
    operation='init' if arguments==('init','-q') else 'measurement-command'
    if source:
        if raw['stdin'] is not None or arguments not in (('init','-q'),('add','.'),('ls-files','-z','--stage')):
            raise Refused('measurement original source Git command')
        value=Command(tuple(argv),raw['cwd'])
    else:
        cold_root(host,Path(repository))
        if arguments in (('init','-q'),('add','.gitignore','candidate.txt'),
                ('-c','user.name=Unrest Measurement','-c','user.email=measurement@invalid','commit','-q','-m','frozen baseline')):
            if raw['stdin'] is not None or raw['cwd']!=repository:
                raise Refused('measurement cold setup location or input')
            value=Command(tuple(argv),repository)
        else:
            matches={}
            for candidate in COLD:
                try:
                    matches[candidate]=match_command(candidate,repository,raw['cwd'],argv,raw['stdin'],raw['environment'],family='evolution')
                except Refused:
                    pass
            if len(matches)!=1:
                raise Refused('measurement single shared Git operation')
            operation,value=next(iter(matches.items()))
            environment.update(value.additions)
    if raw['environment']!=environment:
        raise Refused('measurement original Git environment')
    from git_observer import image
    expected=build_expected('measurement:git',host.case,'/usr/bin/git',image(),value.argv,
        tuple(sorted(environment.items())),value.cwd,'native')
    answer=host.git.launch(actor,operation,repository,value,expected,['/usr/bin/git',*argv[1:]])
    return None if answer is None else {**answer,'translated':['/usr/bin/git',*argv[1:]],'rule':expected.rule}


def cold_root(host,path):
    if host.case not in REAL:
        raise Refused('measurement cold repository case')
    fixture=host.fixture_roots.get(('git-fixture',host.case))
    if fixture is None:
        raise Refused('measurement source fixture must precede cold roots')
    base=Path(fixture[0])
    try:
        parts=path.relative_to(base).parts
    except ValueError:
        raise Refused('measurement cold fixture escape') from None
    if (len(parts)!=6 or parts[:2]!=('home','measurement-private') or not re.fullmatch('[a-f0-9]{32}',parts[2])
            or parts[3]!='cold-roots' or parts[4] not in tuple(f'rep-{index:02d}' for index in REAL[host.case]) or parts[5]!='workspace'
            or path.resolve()!=path):
        raise Refused('measurement exact cold repetition path')
    identity=[]
    for directory in (path,*(parent for parent in path.parents if parent.is_relative_to(base))):
        info=directory.stat(follow_symlinks=False)
        if not stat.S_ISDIR(info.st_mode) or info.st_uid!=OWNER or info.st_mode&0o6022:
            raise Refused('measurement cold directory custody')
        identity.append((str(directory),info.st_dev,info.st_ino))
    if (host.fixture_roots.setdefault(('measurement-run',host.case),parts[2])!=parts[2]
            or host.fixture_roots.setdefault(('measurement-root',host.case,str(path)),identity)!=identity):
        raise Refused('measurement cold generation changed')


def worker(host,actor,raw):
    import os
    from run_worker_launch import admit_worker,MEASUREMENT_EVOLUTION,MEASUREMENT_PROJECT
    if host.case not in (MEASUREMENT_EVOLUTION,MEASUREMENT_PROJECT):
        raise Refused('measurement worker exact case')
    source_unit(Path(host.meta['checkout']),TEST,PIN)
    records=[row for row in host.intents.values() if row['case']==host.case and row.get('run_worker')]
    from measurement_runtime import PROJECT_STEPS
    steps=((11,'start_project',()),(16,'start_project',())) if host.case==MEASUREMENT_EVOLUTION else PROJECT_STEPS
    if len(records)>=len(steps) or any(not row['consumed'] or not host.ledger.reaped(row['birth'],row['token']) for row in records):
        raise Refused('measurement worker original sequence and waits')
    repetition,operation,nodes=steps[len(records)]
    home=Path(raw['cwd'])
    cold_root(host,home.parent/'workspace')
    if home.name!='harness-home' or home.resolve()!=home or home.parent.name!=f'rep-{repetition:02d}':
        raise Refused('measurement worker original repetition home')
    native=host.binding['entry']['path']
    command=native+' '+str(Path(host.meta['checkout'])/'tests/mock_measurement_acp.py')
    env={'LANG':'C.UTF-8','PATH':os.defpath,'PYTHONPATH':str(Path(host.meta['checkout'])/'src'),
        'UNREST_APPROVAL_RECOVERY':'0','UNREST_HOME':str(home),'UNREST_PROJECTS_DIR':str(home/'projects'),
        'UNREST_WORKER_ACP_COMMAND':command,'UNREST_VALIDATOR_ACP_COMMAND':command}
    answer=admit_worker(host,actor,raw,home,operation,env,len(steps),0)
    if answer is not None:
        host.intents[answer['ticket']]['measurement_nodes']=nodes
    return answer
