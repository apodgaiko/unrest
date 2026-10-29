"""Finite Git forms and bounded operands; native ownership/waits remain separate."""

from content_manifest import Refused
from git_commands import match as match_command,Command,SETUP
from git_sites import CASES,OPERATIONS,OWNED_BODY,SHARED_OPERATIONS
from git_observer import image
from launch_policy import build_expected


def prepare(host,actor,raw):
    case=host.case
    from history_git import CASES as HISTORY_CASES,proposal as history_proposal
    if case in HISTORY_CASES:
        return history_proposal(host,actor,raw)
    from candidate_git import CASES as CANDIDATE_CASES,proposal as candidate_proposal
    if case in CANDIDATE_CASES:
        return candidate_proposal(host,actor,raw)
    if case not in CASES:
        raise Refused('Git proposal undeclared case')
    from git_fixtures import SLOTS,fixture as declared_fixture
    fixture=declared_fixture(case) if case in SLOTS else None
    family=fixture.family if fixture is not None else 'workspaces' if case.startswith('tests/test_workspaces.py::') else 'evolution'
    choices=[slot for (current,repo),slot in host.git.repositories.items() if current==case
             and (raw['cwd']==repo or raw['cwd'].startswith(repo+'/.unrest-runtime/'))]
    if len(choices)>1:
        raise Refused('Git unique repository slot')
    slot=choices[0] if choices else None
    repository=slot['path'] if slot is not None else raw['cwd']
    native,pin=host.binding['entry']['path'],host.binding['entry']['sha256']
    owned=raw['argv']==[native,'-c',OWNED_BODY]
    if owned:
        if case!=CASES[7] or slot is None or raw['stdin'] is not None or raw['cwd']!=repository+'/.unrest-runtime/workspaces/trees/process':
            raise Refused('Git proposal owned process scope')
        operation,command='owned-process',None
        expected=build_expected(
            'workspace:owned', case,
            native, pin,
            tuple(raw['argv']),
            tuple(sorted({**host.meta_environment(),'PYTEST_VERSION':'9.0.2','PYTEST_CURRENT_TEST':case+' (call)'}.items())),
            raw['cwd'], 'python-command',
        )
        vector=[native,'-I','-S','-c',OWNED_BODY]
    else:
        if raw['executable']!='/usr/bin/git':
            raise Refused('Git proposal original executable')
        operations=(*SETUP,*SHARED_OPERATIONS) if fixture is not None else OPERATIONS[family]
        branch='master' if fixture is not None and fixture.init==('init',) and raw['argv'][1:3]==['update-ref','refs/heads/master'] else 'main'
        operations=tuple(dict.fromkeys({'rollback-update':'update-parent','rollback-reset':'reset-parent'}.get(operation,operation) for operation in operations))
        candidates: dict[str,Command] = {}
        for operation in operations:
            try:
                command=match_command(operation,repository,raw['cwd'],raw['argv'],raw['stdin'],raw['environment'],family=family,fixture=fixture,branch=branch)
            except Refused:
                continue
            candidates[operation]=command
        if len(candidates)!=1:
            raise Refused('Git proposal requires one finite operation')
        operation,command=next(iter(candidates.items()))
        phase=(fixture.phase if fixture is not None else 'setup') if operation in SETUP else 'call'
        environment={**host.meta_environment(),'PYTEST_VERSION':'9.0.2','PYTEST_CURRENT_TEST':case+' ('+phase+')',**dict(command.additions)}
        expected=build_expected(
            'git:'+operation, case,
            '/usr/bin/git', image(),
            command.argv,
            tuple(sorted(environment.items())),
            command.cwd, 'native',
        )
        vector=['/usr/bin/git',*command.argv[1:]]
    if raw['environment']!=dict(expected.environment) or raw['cwd']!=expected.cwd:
        raise Refused('Git proposal environment or cwd differs')
    answer=host.git.launch(actor,operation,repository,command,expected,vector)
    if answer is None:
        return None
    return {**answer,'translated':vector,'rule':expected.rule}
