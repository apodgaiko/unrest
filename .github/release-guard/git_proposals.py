"""Finite Git forms and bounded operands; native ownership/waits remain separate."""

from content_manifest import Refused
from git_commands import build,FIELDS,Command
from git_sites import CASES,OPERATIONS,OWNED_BODY,SHARED_OPERATIONS
from git_observer import SETUP,image
from launch_policy import build_expected


def operands(operation,args,raw):
    if not FIELDS[operation]:
        return {}
    match operation,args:
        case ('lease-add', ['worktree','add','--detach','--no-checkout',tree,revision]):
            return {'tree':tree,'revision':revision}
        case (('integration-add'|'rollback-add'), ['worktree','add','--detach',tree,revision]):
            return {'tree':tree,'revision':revision}
        case ('remove-tree',['worktree','remove','--force',tree]):
            return {'tree':tree}
        case ('verify-base',['rev-parse','--verify',revision]) if revision.endswith('^{commit}'):
            return {'revision':revision[:-9]}
        case ('checkout',['checkout','--detach',revision]):
            return {'revision':revision}
        case ('diff-return',['diff','--cached','--binary','--no-ext-diff',revision]):
            return {'revision':revision}
        case ('date',['show','-s','--format=%aI',revision]):
            return {'revision':revision}
        case ('apply',['apply','--index','--binary',patch]):
            return {'patch':patch}
        case (('update-parent'|'rollback-update'),['update-ref',ref,new,old]) if ref in ('refs/heads/main','refs/heads/master'):
            return {'new':new,'old':old}
        case (('reset-parent'|'rollback-reset'),['reset','--hard',revision]):
            return {'revision':revision}
        case ('commit-tree',['commit-tree',tree,'-p',revision]):
            message=raw['stdin']
            if type(message) is not str or len(message)>16384 or not message.startswith('Integrate Unrest workspaces\n\n') or not message.endswith('\n'):
                raise Refused('Git proposal finite commit input')
            leases=tuple(tuple(line.split(' ')) for line in message[len('Integrate Unrest workspaces\n\n'):-1].split('\n'))
            return {'tree_id':tree,'revision':revision,'date':raw['environment'].get('GIT_AUTHOR_DATE'),'leases':leases}
    raise Refused('Git proposal does not match a template')


def prepare(host,actor,raw):
    case=host.case
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
        operation,fields,command='owned-process',{},None
        expected=build_expected(
            'workspace:owned', case,
            native, pin,
            tuple(raw['argv']),
            tuple(sorted({**host.meta_environment(),'PYTEST_VERSION':'9.0.2','PYTEST_CURRENT_TEST':case+' (call)'}.items())),
            raw['cwd'], 'python-command',
        )
        vector=[native,'-I','-S','-c',OWNED_BODY]
    else:
        if raw['executable']!='git':
            raise Refused('Git proposal original executable')
        setup=0 if slot is None else slot['setup']
        operations=(SETUP[setup],) if setup<len(SETUP) else SHARED_OPERATIONS if fixture is not None else OPERATIONS[family]
        candidates: dict[str,tuple[dict,Command]] = {}
        for operation in operations:
            try:
                fields=operands(operation,raw['argv'][1:],raw)
                command=build(operation,repository,raw['cwd'],fields,family=family,fixture=fixture,branch=slot.get('branch','main') if slot is not None else 'main')
            except Refused:
                continue
            if list(command.argv)==raw['argv'] and raw['stdin']==command.stdin:
                candidates.setdefault(operation,(fields,command))
        # These authored labels describe the same scoped OS effect.
        for canonical,rollback in (('update-parent','rollback-update'),('reset-parent','rollback-reset')):
            if canonical in candidates and rollback in candidates:
                strong,weak=candidates[canonical][1],candidates[rollback][1]
                if (strong.argv,strong.cwd,strong.additions,strong.stdin)!=(weak.argv,weak.cwd,weak.additions,weak.stdin):
                    raise Refused('Git overlapping declarations differ')
                del candidates[rollback]
        if len(candidates)!=1:
            raise Refused('Git proposal requires one finite operation')
        operation,(fields,command)=next(iter(candidates.items()))
        phase=(fixture.phase if fixture is not None else 'setup') if setup<len(SETUP) else 'call'
        environment={**host.meta_environment(),'PYTEST_VERSION':'9.0.2','PYTEST_CURRENT_TEST':case+' ('+phase+')',**dict(command.additions)}
        expected=build_expected(
            'git:'+operation, case,
            '/usr/bin/git', image(),
            command.argv,
            tuple(sorted(environment.items())),
            command.cwd, 'native',
        )
        vector=list(command.argv)
    if raw['environment']!=dict(expected.environment) or raw['cwd']!=expected.cwd:
        raise Refused('Git proposal environment or cwd differs')
    answer=host.git.launch(actor,operation,repository,command,expected,vector)
    if answer is None:
        return None
    return {**answer,'translated':vector,'rule':expected.rule}
