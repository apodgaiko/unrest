"""Two root fixture mutations and bounded server-owned read-only HEAD queries."""
from pathlib import Path

from completion_roles import CASES,schedule,root,actor_slot
from content_manifest import Refused,capture
from custody_git import repository
from git_commands import Command
from git_observer import HOME_CONFIG,image,regular
from git_values import digest
from launch_policy import build_expected

FIXTURE=(('git','init','-q'),('git','-c','user.name=Test','-c','user.email=test@example.invalid',
    'commit','--allow-empty','-qm','base'))


def ready(host,workspace):
    records=[row for row in host.intents.values() if row['case']==host.case and row.get('fixture_git')]
    if (len(records)!=2 or any(not row['consumed'] or not host.git.reaped(host.actors[row['pid']])
            or host.ledger.process(row['birth']).terminal[2]!=0 for row in records)):
        raise Refused('completion fixture before actual Git waits')
    identity=repository(str(workspace),Path(host.meta['owned']),initialize=False)
    if host.fixture_roots.get(('completion-git-root',host.case))!=identity:
        raise Refused('completion fixture repository generation changed')
    metadata=workspace/'.git'
    members=sorted(metadata.rglob('*'))
    if any(path.is_symlink() or not (path.is_file() or path.is_dir()) for path in members):
        raise Refused('completion fixture Git member custody')
    names=[str(path.relative_to(metadata)) for path in members if path.is_file()]
    value={'identity':identity,'files':capture(metadata,names)}
    key=('completion-git',host.case)
    if host.fixture_roots.setdefault(key,value)!=value:
        raise Refused('completion fixture Git metadata changed')
    head=regular(metadata/'HEAD').decode()
    if not head.startswith('ref: ') or not head.endswith('\n'):
        raise Refused('completion fixture symbolic HEAD')
    reference=Path(head[5:-1])
    file=metadata/reference
    if reference.is_absolute() or '..' in reference.parts or reference.parts[:2]!=('refs','heads') or file.resolve()!=file:
        raise Refused('completion fixture HEAD reference')
    raw=regular(file)
    if len(raw)!=41 or not raw.endswith(b'\n'):
        raise Refused('completion fixture HEAD bytes')
    return digest(raw[:-1].decode())


def proposal(host,actor,raw):
    case=host.case
    if case not in CASES or raw['stdin'] is not None or raw['executable']!='git':
        raise Refused('completion exact Git proposal')
    parent=root(host,raw['cwd'])
    workspace=parent/'workspace'
    if regular(Path(host.meta['owned'])/'home/.gitconfig',uid=20001)!=HOME_CONFIG:
        raise Refused('completion sealed Git home configuration')
    records=[row for row in host.intents.values() if row['case']==case and row['role']=='git-command'
             and row['parent']==actor['birth']]
    if any(not row['consumed'] or not host.git.reaped(host.actors[row['pid']]) for row in records):
        raise Refused('completion previous parent-local Git wait')
    base={**host.meta_environment(),'PYTEST_VERSION':'9.0.2','PYTEST_CURRENT_TEST':case+' (call)'}
    if actor['role']=='root':
        host.root_only(actor)
        if len(records)>=2 or any(row['case']==case and 'server_slot' in row for row in host.intents.values()):
            raise Refused('completion root fixture sequence')
        vector=FIXTURE[len(records)]
        identity=repository(str(workspace),Path(host.meta['owned']),initialize=not records)
        key=('completion-git-root',case)
        previous=host.fixture_roots.setdefault(key,identity)
        if previous[0]!=identity[0] or previous[1] is not None and previous[1]!=identity[1]:
            raise Refused('completion fixture repository generation')
        host.fixture_roots[key]=identity
        command=Command(vector,str(workspace))
        environment,head=base,None
    else:
        server=actor_slot(host,actor)
        if len(records)>=schedule(case)[server['server_slot']][2]:
            raise Refused('completion server-owned Git query quota')
        head=ready(host,workspace)
        vector=('git','rev-parse','HEAD')
        command=Command(vector,str(workspace),produces=(str(workspace),'commit',()))
        environment=dict(actor['profile']['environment'])
    expected=build_expected('completion:git',case,'/usr/bin/git',image(),vector,
        tuple(sorted(environment.items())),str(workspace),'native')
    if raw['argv']!=list(vector) or raw['environment']!=dict(expected.environment) or raw['cwd']!=expected.cwd:
        raise Refused('completion original Git operands')
    translated=['/usr/bin/git',*vector[1:]]
    answer=host.admit_launch(actor,expected,'git-command',translated,None,
        maximum=2+sum(row[2] for row in schedule(case)))
    if answer is None:
        return None
    intent=host.intents[answer['ticket']]
    intent.update(command=command,repository=str(workspace),operation='completion-fixture' if head is None else 'completion-head',
        fixture_git=head is None,fixture_head=head,fixture_stdio=head is None)
    host.git.commands[intent['token']]=intent
    return {**answer,'translated':translated,'rule':expected.rule,
        'command':{'stdin':None,'produces':None if command.produces is None else [command.produces[0],command.produces[1],list(command.produces[2])]}}
