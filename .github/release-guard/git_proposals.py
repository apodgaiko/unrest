"""Inverse finite Git templates, retaining kernel-wait and value dependencies."""

from content_manifest import Refused
from git_commands import build,FIELDS,Command
from git_sites import CASES,OPERATIONS,OWNED_BODY
from git_observer import SETUP,image
from launch_policy import build_expected


def integration(host,repository,revision):
    values={(row.location,row.inputs) for row in host.git.values.values
            if row.case==host.case and row.repository==repository and row.kind=='integration-commit' and row.value==revision}
    if len(values)!=1:
        raise Refused('Git proposal lacks unique integration producer')
    location,inputs=next(iter(values))
    return {'new_location':location,'new_inputs':inputs}


def operands(host,operation,args,raw,repository):
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
        case (('update-parent'|'rollback-update'),['update-ref','refs/heads/main',new,old]):
            return {'new':new,'old':old,**(integration(host,repository,new) if operation=='update-parent' else {})}
        case (('reset-parent'|'rollback-reset'),['reset','--hard',revision]):
            return {'revision':revision,**(integration(host,repository,revision) if operation=='reset-parent' else {})}
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
    family='workspaces' if case.startswith('tests/test_workspaces.py::') else 'evolution'
    slot=host.git.repositories.get(case)
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
        operations=(SETUP[setup],) if setup<len(SETUP) else OPERATIONS[family]
        candidates: dict[str,tuple[dict,Command]] = {}
        for operation in operations:
            try:
                fields=operands(host,operation,raw['argv'][1:],raw,repository)
                command=build(operation,repository,raw['cwd'],fields,family=family)
                for location,kind,value,inputs in command.requires:
                    host.git.values.require(case,repository,location,kind,value,inputs)
            except Refused:
                continue
            if list(command.argv)==raw['argv'] and raw['stdin']==command.stdin:
                candidates.setdefault(operation,(fields,command))
        # Promotion/reset labels share argv with rollback. Prefer the complete
        # integration provenance when both prove the same finite OS effect.
        for canonical,rollback in (('update-parent','rollback-update'),('reset-parent','rollback-reset')):
            if canonical in candidates and rollback in candidates:
                strong,weak=candidates[canonical][1],candidates[rollback][1]
                if (strong.argv,strong.cwd,strong.additions,strong.stdin)!=(weak.argv,weak.cwd,weak.additions,weak.stdin):
                    raise Refused('Git overlapping declarations differ')
                del candidates[rollback]
        if len(candidates)!=1:
            raise Refused('Git proposal requires one finite operation')
        operation,(fields,command)=next(iter(candidates.items()))
        phase='setup' if setup<len(SETUP) else 'call'
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
    return {**answer,'translated':vector,'rule':expected.rule,
            'command':None if command is None else {'stdin':command.stdin,'produces':[command.produces[0],command.produces[1],list(command.produces[2])] if command.produces else None}}
