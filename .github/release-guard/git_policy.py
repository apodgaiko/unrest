"""Finite Git command families, actual native custody and closed public inputs.

Families retain independent case sets, parent roles, budgets and helper rights.
"""
from __future__ import annotations

import os
import json
import re
import shlex
import subprocess
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
import stat
from launch_policy import source_unit, build_expected, admit_expected
from owned_fixture import acquire, retain
from content_manifest import Refused, native_digest, read_regular, refuse_if
from controlled_cases import eligible as CONTROLLED_CASES
from cohort_cases import CASES as COHORT_CASES, EXTRA as COHORT_EXTRA
from completion_roles import CASES as ROLE_CASES, SOURCE as ROLE_SOURCE, ROOT_QUERIES, DEFECT as ROLE_DEFECT, schedule as role_schedule, root as role_root, actor_slot
from composed_cases import CASES as COMPOSED_CASES, queries as composed_queries


PUBLIC_TAGS = {
    'v0.2.0': '687ad97c3d4622d3a793a3363bc154ba5e6aa9cf',
    'v0.2.1': '2652e657ea69e7ed65b2e5cf19278a45260989c4',
    'v0.3.0': 'c0e7a4faae8863b935c5cd8a0f37a8408860b2e4',
    'v0.3.1': 'fb52910a3d2499375d9283791ba35b31fc620943',
    'v0.4.0': '111396f755a82d8194ee3ad649ba3d0519504158',
    'v0.4.5': 'a77a8be304b736f54acfa6b7181661560aa8433d',
}
PUBLIC_FM000 = '2b17a613b99ef182c9bae18b8171efc17e8fe8d2'
PUBLIC_OID = re.compile(r'[0-9a-f]{40}')


def public_git(repository: Path, *arguments: str, data: bytes | None = None) -> bytes:
    environment = {key: value for key, value in os.environ.items() if not key.startswith('GIT_')}
    environment.update(GIT_CONFIG_NOSYSTEM='1', GIT_CONFIG_SYSTEM=os.devnull,
                       GIT_CONFIG_GLOBAL=os.devnull, GIT_NO_LAZY_FETCH='1', GIT_TERMINAL_PROMPT='0')
    return subprocess.run(['git', '--no-replace-objects', '-c', 'safe.directory=' + str(repository), '-C', str(repository), *arguments],
                          input=data, capture_output=True, check=True, env=environment).stdout


def public_oid(value: bytes) -> str:
    result = value.decode('ascii').strip()
    if PUBLIC_OID.fullmatch(result) is None:
        raise RuntimeError('public_git_object_id')
    return result


def public_prepare(repository: Path, destination: Path, head: str) -> dict[str, object]:
    """Acquire reachable public history from the trusted CI checkout, not .git."""
    if destination.resolve(strict=True) != destination:
        raise RuntimeError('public_git_destination_alias')
    repository, destination = repository.resolve(strict=True), destination.resolve(strict=True)
    if (not destination.is_dir() or destination.is_relative_to(repository)
            or repository.is_relative_to(destination) or (destination / '.git').exists()
            or (destination / '.git').is_symlink()):
        raise RuntimeError('public_git_destination')
    if PUBLIC_OID.fullmatch(head) is None or public_oid(public_git(repository,'rev-parse','--verify','HEAD'))!=head:
        raise RuntimeError('public_git_head_drift')
    commits=public_git(repository,'rev-list',head).decode('ascii').splitlines()
    if (not commits or len(commits)>20000 or PUBLIC_FM000 not in commits
            or any(PUBLIC_OID.fullmatch(item) is None for item in commits)):
        raise RuntimeError('public_git_commit_graph')
    for name,expected in PUBLIC_TAGS.items():
        if public_oid(public_git(repository,'rev-parse','--verify','refs/tags/'+name))!=expected:
            raise RuntimeError('public_git_historical_tag_drift')
    public_git(destination,'init','--template=','--object-format=sha1')
    # Explicit refspecs bring complete reachable public trees, without source
    # config/hooks, alternate directories, unrelated refs or automatic maintenance.
    git_dir=public_git(repository,'rev-parse','--absolute-git-dir').decode().strip()
    upload=shlex.join(['/usr/bin/git','-c','safe.directory='+git_dir,'upload-pack'])
    public_git(destination,'fetch','--upload-pack='+upload,'--no-tags','--no-recurse-submodules','--no-write-fetch-head',
        '--no-auto-maintenance',str(repository),head,*('refs/tags/'+name+':refs/tags/'+name for name in PUBLIC_TAGS))
    (destination/'.git/HEAD').write_text(head+'\n')
    public_git(destination,'read-tree',head)
    if (public_oid(public_git(destination,'rev-parse','--verify','HEAD^{commit}'))!=head
            or any(public_oid(public_git(destination,'rev-parse','--verify','refs/tags/'+name))!=oid for name,oid in PUBLIC_TAGS.items())):
        raise RuntimeError('public_git_acquired_refs')
    return {'head':head,'historical_tags':dict(PUBLIC_TAGS),'commits':len(commits),
            'scope':'trusted public CI HEAD and six pinned tags; complete reachable history'}


def operand_text(value, maximum=4096):
    if type(value) is not str or not value or len(value) > maximum or '\0' in value:
        raise Refused('git value primitive')
    try:
        refuse_if(len(value.encode('utf-8')) > maximum, 'git value text bound')
    except UnicodeError:
        raise Refused('git value text encoding') from None
    return value


def operand_digest(value, length=40):
    if type(value) is not str or len(value) != length or any(c not in '0123456789abcdef' for c in value):
        raise Refused('git value digest')
    return value



# Closed Git commands for the workspace/evolution launch families.
#
# The independent observer validates filesystem custody and process state.
# The matcher interprets no expressions and admits only complete closed argv forms.
# Dynamic data operands remain scoped; the product tests own Git value semantics.




@dataclass(frozen=True)
class Command:
    argv: tuple[str, ...]
    cwd: str
    additions: tuple[tuple[str, str], ...] = ()
    stdin: str | None = None



COMMAND_FIXED = {
    'inside': ('rev-parse', '--is-inside-work-tree'),
    'top': ('rev-parse', '--show-toplevel'),
    'head': ('rev-parse', 'HEAD'),
    'head-tree': ('rev-parse', 'HEAD^{tree}'),
    'parent-ref': ('symbolic-ref', '--quiet', 'HEAD'),
    'clean': ('status', '--porcelain=v1', '--untracked-files=all'),
    'inventory': ('status', '--porcelain=v1', '-z', '--untracked-files=all'),
    'stage-return': ('add', '-A', '--', '.'),
    'write-tree': ('write-tree',),
    'check-index': ('diff', '--cached', '--check'),
    'prune': ('worktree', 'prune'),
}


SETUP_FORMS={
    'init':(('init',),('init','-q'),('init','-b','main'),('init','--initial-branch=main','--object-format=sha1')),
    'config-name':tuple(('config','user.name',name) for name in ('Workspace Test','Evolution Test','Fixture','Schema Validator','Authority Test','Foundation Integration','Project Adapter Test','Improve Adapter Test','ACT-190 Activation')),
    'config-email':tuple(('config','user.email',name) for name in ('workspace@example.test','evolution@example.test','fixture@example.invalid','schema@example.test','authority@example.test','foundation@example.test','project-adapter@example.test','improve@example.test','act190@example.test')),
    'stage-base':tuple(('add',*paths) for paths in (('README.md',),('.',),('README.md','.gitignore'))),
    'commit-base':tuple(('commit','-m',message) for message in ('base','candidate','unsupported','executable')),
    'stage-advance':(('add','advance.txt'),),'commit-advance':(('commit','-m','advance parent'),),
    'stage-child':(('add','child.txt'),),'commit-child':(('commit','-m','child self commit'),),
}


def command_path(value):
    operand_text(value)
    p = PurePosixPath(value)
    if not value.startswith('/') or value.startswith('//') or str(p) != value or '..' in p.parts:
        raise Refused('git command canonical path')
    return p


def command_location(repo, path, *, target=False):
    runtime = repo / '.unrest-runtime'
    if not ((not target and path == repo) or runtime in path.parents):
        raise Refused('git operation location outside runtime')


def command_match(repository,location,argv,stdin,environment):
    """Parse one complete closed vector; labels do not select command rights."""
    refuse_if(type(argv) is not list or not argv or any(type(value) is not str for value in argv) or argv[0] not in ('git','/usr/bin/git'), 'git literal argument vector')
    repo,cwd=command_path(repository),command_path(location)
    command_location(repo,cwd)
    args=tuple(argv[1:])
    forms={**{name:(vector,) for name,vector in COMMAND_FIXED.items()},**SETUP_FORMS}
    operation=next((name for name,vectors in forms.items() if args in vectors),None)
    additions=()
    if operation is None:
        operation='local'
        match args:
            case ('worktree','add','--detach','--no-checkout',tree,revision) | ('worktree','add','--detach',tree,revision):
                operation='lease-add' if len(args)==6 else 'integration-add'
                command_location(repo,command_path(tree),target=True)
                operand_digest(revision)
            case ('worktree','remove','--force',tree):
                operation='remove-tree'
                command_location(repo,command_path(tree),target=True)
            case ('rev-parse','--verify',revision) if revision.endswith('^{commit}'):
                operand_digest(revision[:-9])
            case ('checkout','--detach',revision) | ('diff','--cached','--binary','--no-ext-diff',revision) | ('show','-s','--format=%aI',revision):
                operand_digest(revision)
            case ('reset','--hard',revision):
                operand_digest(revision)
            case ('apply','--index','--binary',patch):
                patch=command_path(patch)
                if patch.parent!=repo/'.unrest/workspaces/patches' or patch.suffix!='.patch':
                    raise Refused('git patch scope')
                operand_digest(patch.stem,64)
            case ('update-ref',reference,new,old):
                refuse_if(reference not in ('refs/heads/main','refs/heads/master'), 'git update reference')
                operand_digest(new)
                operand_digest(old)
            case ('commit-tree',tree,'-p',revision):
                operation='commit-tree'
                operand_digest(tree)
                operand_digest(revision)
                operand_text(stdin,16384)
                additions=tuple(sorted((name,operand_text(environment.get(name))) for name in (
                    'GIT_AUTHOR_NAME','GIT_AUTHOR_EMAIL','GIT_AUTHOR_DATE',
                    'GIT_COMMITTER_NAME','GIT_COMMITTER_EMAIL','GIT_COMMITTER_DATE')))
            case _:
                forms={('rev-parse','HEAD:lane_a.txt'),('config','core.filemode','false'),
                    ('add','lane_a.txt'),('rm','--cached','lane_a.txt'),('add','extra.txt'),
                    ('update-index','--assume-unchanged','lane_a.txt'),('update-index','--skip-worktree','lane_a.txt'),
                    ('add','-N','extra.txt'),('ls-files','-z','--stage'),('add','.gitignore','candidate.txt'),
                    ('-c','user.name=Unrest Measurement','-c','user.email=measurement@invalid','commit','-q','-m','frozen baseline')}
                forms.update(('config',key,value.replace('CANARY',str(repo.parent/'canary'))) for key,value in CANDIDATE_CANARIES)
                if args not in forms:
                    match args:
                        case ('commit-tree',oid,'-m','unrelated'):
                            operand_digest(oid)
                        case ('update-index','--add','--cacheinfo',entry):
                            mode,oid,name=entry.split(',') if entry.count(',')==2 else ('','','')
                            if mode not in ('120000','160000') or name!='unsupported':
                                raise Refused('Git finite cache entry')
                            operand_digest(oid)
                        case _:
                            raise Refused('Git proposal does not match a template')
    if operation!='commit-tree' and stdin is not None:
        raise Refused('git unexpected command input')
    return operation,Command(tuple(argv),str(cwd),additions,stdin)


CANDIDATE_TEST='tests/test_experimental_candidate.py'
CANDIDATE_PIN='6827bd92719ed7e138980b9e4dc3d9e6fdc775444093609fe78c0e806981c39e'
CANDIDATE_CANARIES=(('filter.canary.clean', 'CANARY'),
 ('filter.canary.smudge', 'CANARY'),
 ('diff.canary.textconv', 'CANARY'),
 ('diff.external', 'CANARY'),
 ('core.fsmonitor', 'CANARY'),
 ('core.hooksPath', 'CANARY'),
 ('credential.helper', 'CANARY'),
 ('remote.origin.url', 'ext::CANARY'),
 ('remote.origin.uploadpack', 'CANARY'),
 ('include.path', 'CANARY'),
 ('extensions.partialclone', 'origin'),
 ('remote.origin.promisor', 'true'),
 ('core.sparsecheckout', 'true'),
 ('extensions.objectformat', 'sha256'))

MEASUREMENT_TEST='tests/test_measurement.py'
MEASUREMENT_PIN='d850dcaf77c4b4ebd08efa87089cbc7b59762d5eb8d7fd0b673a9e043bc3e97f'
MEASUREMENT_WORKERS=tuple(MEASUREMENT_TEST+'::'+name for name in ('test_evolution_cases_use_real_public_state_machine_and_cold_state','test_project_cases_use_real_run_control_and_nested_acp'))

def measurement_worker(host,actor,raw):
    from run_worker_launch import admit_worker,MEASUREMENT_EVOLUTION,MEASUREMENT_PROJECT
    refuse_if(host.case not in (MEASUREMENT_EVOLUTION,MEASUREMENT_PROJECT), 'measurement worker exact case')
    source_unit(Path(host.meta['checkout']),MEASUREMENT_TEST,MEASUREMENT_PIN)
    records=[row for row in host.intents.values() if row['case']==host.case and row.get('run_worker')]
    from measurement_runtime import PROJECT_STEPS
    steps=((11,'start_project',()),(16,'start_project',())) if host.case==MEASUREMENT_EVOLUTION else PROJECT_STEPS
    refuse_if(len(records)>=len(steps) or any(not row['consumed'] or not host.ledger.reaped(row['birth'],row['token']) for row in records), 'measurement worker original sequence and waits')
    repetition,operation,nodes=steps[len(records)]
    home=Path(raw['cwd'])
    fixture_root(host,host.case,str(home.parent/'workspace'))
    if home.name!='harness-home' or home.resolve()!=home or home.parent.name!=f'rep-{repetition:02d}':
        raise Refused('measurement worker original repetition home')
    native=host.binding['entry']['path']
    command=native+' '+str(Path(host.meta['checkout'])/'tests/mock_measurement_acp.py')
    env={'LANG':'C.UTF-8','PATH':os.defpath,'PYTHONPATH':str(Path(host.meta['checkout'])/'src'),
        'UNREST_APPROVAL_RECOVERY':'0','UNREST_HOME':str(home),'UNREST_PROJECTS_DIR':str(home/'projects'),
        'UNREST_WORKER_ACP_COMMAND':command,'UNREST_VALIDATOR_ACP_COMMAND':command}
    answer=admit_worker(host,actor,raw,home,operation,env,len(steps))
    if answer is not None:
        host.intents[answer['ticket']]['measurement_roles']=nodes
    return answer


FIXTURE_SERVER_INQUIRY='tests/test_server.py::test_real_run_inquiry_workspace_and_campaign_results_cross_validator'

FIXTURE_PINS={
    'tests/test_workspaces.py':'a578e3070eb68ab4012b40dc41443dc833a92ffbff14aa42c7f39dbc27f56595',
    'tests/test_evolution.py':'778aeac7d73291bbeaaad3cb2ad2905d6a4e93a723a42378daa080222e7c57db',
    'tests/test_server.py':'0550689ff20fb183ea62b47606bd3e66c5fc1222b5d4166e57e74d546afbb286',
    MEASUREMENT_TEST:MEASUREMENT_PIN,
    CANDIDATE_TEST:CANDIDATE_PIN,
    'tests/test_foundation_authority.py':'c8f63d70d4dcc3d74215a9db538632fc9115086d32d42f633235135dcaea2c70',
    'tests/test_foundation_integration.py':'bcbddfff3ffabd8b4374be17fa22b35872bd347d2daa8ca9ee3132f007caa8ef',
    'tests/test_improve_adapter.py':'d3c9c1fa8461db4e30b3d3239bf52746018a56b957f4699ddff7572c10be3290',
    'tests/test_project_adapter.py':'b48d315875eedb9350219fcc3c203c778f329389f32d8f787de0c574390235cf',
    'tests/test_v04_activation.py':'4741feb6a71d9c06be777a08a34e064be0610c1f8b755ebfffef21489621c435',
}
WORKER_REPOSITORIES={'tests/test_foundation_authority.py::test_async_project_lock_contention_is_public_busy_with_private_cause': ('repo',),
 'tests/test_foundation_authority.py::test_tool_error_mapping_is_closed_and_private_details_survive_async_run': ('repo',),
 'tests/test_server.py::test_real_run_inquiry_workspace_and_campaign_results_cross_validator': ('repository',)}

def local_case(case):
    return type(case) is str and '::' in case and case.split('::')[0] in FIXTURE_PINS


def fixture_root(host,case,repository):
    refuse_if(not local_case(case), 'Git exact fixture case')
    file=case.split('::')[0]
    source_unit(Path(host.meta['checkout']),file,FIXTURE_PINS[file])
    acquire(repository,Path(host.meta['owned']))



HISTORY_CROSSWALK='tests/contracts/test_lean_evidence_crosswalk.py'
HISTORY_BINDING='tests/test_release_binding.py'
HISTORY_V021='tests/test_v021_release_records.py'
HISTORY_V045='tests/test_v045_release_records.py'
HISTORY_REPOSITORY='tests/test_repository_contract.py::test_current_repository_passes_deterministically_without_writes'
HISTORY_CLI=HISTORY_V045+'::test_binding_cli_accepts_active_manifest_and_refuses_wrong_digest'
HISTORY_TOOL='tools/release_binding.py'
HISTORY_TOOL_PIN='c40638ed9b7b00e2ca831bd29c909c78672bb91017d21ad13c283143989f43a2'
HISTORY_PUBLISHED='5a3d568aa881c746432b7034597bbb8a1ffe025f'
HISTORY_CATALOG={
    HISTORY_BINDING:('test_binding_uses_only_candidate_regular_files','test_binding_rejects_coherent_fake_digest',
        'test_current_candidate_binding_hashes_exact_current_source','test_v02_carriers_are_byte_identical_to_the_v020_tag',
        'test_v030_carriers_are_byte_identical_to_the_v030_tag','test_v031_carriers_are_byte_identical_to_the_v031_tag',
        'test_v045_manifest_binds_only_its_published_source'),
    HISTORY_V021:('test_fm000_proposal_artifacts_remain_exact_historical_provenance','test_v021_candidate_had_no_forbidden_v03_runtime_surface'),
    HISTORY_V045:('test_v040_release_carriers_remain_exact_tag_bytes',),
    HISTORY_CROSSWALK:('test_v02_source_import_dependency_and_hard_cut_inventories_are_historical',
        'test_v02_package_inventory_is_bound_to_the_v020_tag'),
}
HISTORY_CASES=(*tuple(file+'::'+name for file,names in HISTORY_CATALOG.items() for name in names),HISTORY_CLI,HISTORY_REPOSITORY)
HISTORY_PINS={HISTORY_CROSSWALK:'c1ccd829942713f030fcc928dfff1a0a9cd1e948eb6337e2f8fa65782a048c81','tests/test_repository_contract.py':'1c1fcfee0aefd633452a4515e451a0008cef5e758a47f09fbc1e16e8d988d72c', 'tests/test_release_binding.py': '2db77fb31af6b7e536420a16aaa92fc237404570d0f97df37f374fed788c2d0f', 'tests/test_v021_release_records.py': '7d5f90c969295c019e515133cca6abbb2458882c53b43a7bee3c59ca44a95ee5', 'tests/test_v045_release_records.py': 'be9693d6ad6937f0080f6022d3db602ad8530c0d24f8528b85ebc3ee4c492da4'}


def history_commands(checkout,case):
    file,name=case.split('::')
    source_unit(checkout,file,HISTORY_PINS[file],(name,))
    if file==HISTORY_CROSSWALK:
        source=name==HISTORY_CATALOG[HISTORY_CROSSWALK][0]
        roots=('src/unrest_harness','.') if source else ('src/unrest_harness/bundled','src/unrest_harness')
        commands=[('ls-tree','-r','--name-only','v0.2.0','--',root) for root in roots]
        if source:
            audit=json.loads((checkout/'docs/release/lean-core-v0.2-review-audit.json').read_bytes())
            commands.extend(('show','v0.2.0:'+path) for path in (*audit['source_inventory'],'pyproject.toml'))
        return commands
    if case==HISTORY_REPOSITORY:
        return [('status','--short')]
    if case==HISTORY_CLI or name in HISTORY_CATALOG[HISTORY_BINDING][:3]:
        return [('ls-files','--stage','-z'),('ls-files','--others','--exclude-standard','-z')]
    versions={'test_v02_carriers_are_byte_identical_to_the_v020_tag':('0.2', '0.2.0',('manifest.json','review-audit.json','evidence-crosswalk.json','md','rollback.md')),
        'test_v030_carriers_are_byte_identical_to_the_v030_tag':('0.3.0','0.3.0',('manifest.json','md','rollback.md')),
        'test_v031_carriers_are_byte_identical_to_the_v031_tag':('0.3.1','0.3.1',('manifest.json','burden.json','md','rollback.md'))}
    if name in versions:
        stem,tag,suffixes=versions[name]
        return [('show','v'+tag+':docs/release/lean-core-v'+stem+('.md' if suffix=='md' else '-'+suffix)) for suffix in suffixes]
    if name=='test_v045_manifest_binds_only_its_published_source':
        return [('ls-tree','-r','-z',HISTORY_PUBLISHED),('archive',HISTORY_PUBLISHED),
            *(('show',HISTORY_PUBLISHED+':docs/release/lean-core-v0.4.5'+suffix) for suffix in ('-manifest.json','.md','-rollback.md'))]
    if name==HISTORY_CATALOG[HISTORY_V045][0]:
        return [('show','v0.4.0:'+str(path.relative_to(checkout))) for path in sorted((checkout/'docs/release').glob('lean-core-v0.4.0*'))]
    if name==HISTORY_CATALOG[HISTORY_V021][1]:
        commit='d14054605fdb9890f2c78395f8d08b532dbc5dc7'
        return [('rev-parse','v0.2.1^{commit}'),('diff','--name-only',PUBLIC_FM000,commit)]
    roots=('docs/v03/contracts','tests/fixtures/v03_decisions','docs/decisions')
    paths=sorted(path for root in roots for path in (checkout/root).rglob('*') if path.is_file()
        and (root!='docs/decisions' or path.name.startswith('ADR-030')))
    return [('merge-base','--is-ancestor',PUBLIC_FM000,'HEAD'),*(('ls-tree','-r',PUBLIC_FM000,'--',root) for root in roots),
        *(('rev-parse',PUBLIC_FM000+':'+str(path.relative_to(checkout))) for path in paths)]


def history_proposal(host,actor,raw):
    checkout=Path(host.meta['checkout'])
    if host.case==HISTORY_CLI:
        if raw['argv'][0]==host.binding['entry']['path']:
            return history_cli_proposal(host,actor,raw)
        if actor['role']!='fixed-inline' or actor['case']!=HISTORY_CLI or not actor['body_ready']:
            raise Refused('history original CLI parent')
        records=[value for value in host.intents.values() if value['role']=='fixed-inline'
            and value['case']==HISTORY_CLI and value['token']==actor['token'] and value.get('birth')==actor['birth'] and value['consumed']]
        if len(records)!=1 or raw['cwd']!=records[0]['binding_repository']:
            raise Refused('history original CLI repository')
    else:
        host.root_only(actor)
    if raw['executable']!='/usr/bin/git' or raw['stdin'] is not None or tuple(raw['argv'][1:]) not in history_commands(checkout,host.case):
        raise Refused('history exact readonly command')
    environment={**host.meta_environment(),'PYTEST_VERSION':'9.0.2','PYTEST_CURRENT_TEST':host.case+' (call)'}
    command=Command(tuple(raw['argv']),raw['cwd'] if host.case==HISTORY_CLI else str(checkout))
    return issue(host,actor,raw,command,environment,role='git-custody',maximum=2 if host.case==HISTORY_REPOSITORY else 128)


def history_cli_proposal(host,actor,raw):
    host.root_only(actor)
    checkout=Path(host.meta['checkout'])
    source_unit(checkout,HISTORY_V045,HISTORY_PINS[HISTORY_V045],(HISTORY_CLI.split('::')[1],))
    source_unit(checkout,HISTORY_TOOL,HISTORY_TOOL_PIN)
    argv=raw['argv']
    refuse_if(len(argv)!=7 or raw['stdin'] is not None, 'binding CLI original argument count')
    root=retain(host,Path(argv[4]).parent, 20000)
    repository=root/'repository'
    if repository.resolve()!=repository or (repository/'.git').resolve()!=repository/'.git':
        raise Refused('binding CLI repository alias')
    previous=[value for value in host.intents.values() if value['case']==HISTORY_CLI]
    ordinal=sum(value['role']=='fixed-inline' for value in previous)
    refuse_if(ordinal>=2, 'binding CLI original two invocations')
    native,pin=host.binding['entry']['path'],host.binding['entry']['sha256']
    vector=(native,'-B',str(checkout/HISTORY_TOOL),'--repository',str(repository),'--check-manifest',str(root/('active-manifest.json' if ordinal==0 else 'wrong-manifest.json')))
    environment={**host.meta_environment(),'PYTEST_VERSION':'9.0.2','PYTEST_CURRENT_TEST':HISTORY_CLI+' (call)'}
    expected=build_expected(HISTORY_CLI,native,pin,vector,tuple(sorted(environment.items())),str(checkout),'python-script',HISTORY_TOOL_PIN)
    return admit_expected(host,actor,raw,expected,'fixed-inline',[native,'-I','-S',*vector[2:]],HISTORY_TOOL_PIN,maximum=2,
        fields={'fixed_operation':'check','binding_repository':str(repository)})


OWNED_CASE='tests/test_workspaces.py::test_owned_process_budget_and_restart_cleanup'


SITE_OWNED_BODY = 'import time; time.sleep(60)'



HOME_CONFIG = b'[maintenance]\n\tauto = false\n[gc]\n\tauto = 0\n'


def regular(file, maximum=4096, uid=20000):
    return read_regular(file,maximum,uid=uid,minimum=1,forbidden=0o6022)[0]


def image(file='/usr/bin/git'):
    target = Path(file)
    refuse_if(str(target.resolve(strict=True)) != file, 'git native image alias')
    for member in (target, *target.parents):
        info = member.lstat()
        if info.st_uid != 0 or stat.S_IMODE(info.st_mode) & 0o6022:
            raise Refused('git native image custody')
        if member == target:
            refuse_if(not stat.S_ISREG(info.st_mode) or not info.st_mode & 0o111, 'git native executable')
        elif not stat.S_ISDIR(info.st_mode):
            raise Refused('git native ancestor')
    return native_digest(target)


def issue(host,actor,raw,command,environment,*,role='git-command',maximum=128,fields=None):
    if raw['executable']!='/usr/bin/git' or raw['stdin']!=command.stdin:
        raise Refused('Git exact executable and input')
    expected=build_expected(host.case,'/usr/bin/git',image(),command.argv,
        tuple(sorted(environment.items())),command.cwd,'native')
    vector=['/usr/bin/git',*command.argv[1:]]
    if role=='git-custody' and command.cwd==host.meta.get('checkout'):
        vector[1:1]=['-c','safe.directory='+command.cwd]
    answer=admit_expected(host,actor,raw,expected,role,vector,maximum=maximum,fields=fields)
    if answer is not None and fields is not None:
        host.git.commands[answer['token']]=host.intents[answer['ticket']]
    return answer


class Git:
    def __init__(self, observer):
        self.host = observer
        self.repositories, self.commands = {}, {}
        self.helpers = {}

    def repository(self, repository, operation, family):
        root = Path(repository)
        fixture_root(self.host,self.host.case,repository)
        key=(self.host.case,repository)
        self.repositories.setdefault(key,{'path':repository})
        return root

    def location(self, root, location):
        path = Path(location)
        command_location(root, path)
        if not path.is_dir() or path.lstat().st_uid != 20000 or str(path.resolve(strict=True)) != location:
            raise Refused('git original worktree directory')

    def launch(self, actor, operation, repository, command, raw, environment):
        host = self.host
        host.root_only(actor)
        refuse_if(not local_case(host.case), 'Git finite case')
        root = self.repository(repository, operation, 'workspaces')
        self.location(root, command.cwd)
        if operation in ('lease-add','integration-add','rollback-add','remove-tree'):
            target = Path(command.argv[-1] if operation=='remove-tree' else command.argv[-2])
            command_location(root,target,target=True)
            refuse_if(target.resolve(strict=False) != target, 'git worktree target alias')
        return issue(host,actor,raw,command,environment,
            fields={'command':command,'repository':str(root),'operation':operation})

    def reserve_helper(self, birth, parent):
        host = self.host
        process = host.ledger.process(parent)
        intent = self.commands.get(process.token)
        if (intent is None or not intent['consumed'] or intent['case'] != host.case
                or intent['operation'] not in ('integration-add', 'rollback-add')
                or process.exit is not None or process.terminal is not None):
            raise Refused('git child outside original worktree creation')
        siblings = host.ledger.children.get(parent, ())
        refuse_if(list(siblings) != [birth], 'git single current checkout helper')
        tree = intent['command'].argv[-2]
        root, worktree = Path(intent['repository']), Path(tree)
        self.location(root, tree)
        executable = '/usr/lib/git-core/git'
        pin=intent['executable_sha256']
        refuse_if(image(executable) != pin, 'git helper exact native image')
        environment = {**intent['environment'], 'GIT_DIR': str(worktree / '.git'), 'GIT_WORK_TREE': tree,
            'GIT_EXEC_PATH': '/usr/lib/git-core', 'GIT_PREFIX': '',
            'PATH': '/usr/lib/git-core:' + intent['environment']['PATH']}
        vector = [executable, 'reset', '--hard', '--no-recurse-submodules']
        host.serial += 1
        child = {'ticket':host.serial,'case': host.case, 'role': 'git-helper', 'parent': parent, 'environment': environment,
            'cwd': intent['cwd'], 'translated': vector, 'token': os.urandom(16).hex(), 'consumed': False,
            'pid': None, 'executable': executable, 'executable_sha256': pin, 'inherited': [], 'port': None}
        host.intents[host.serial] = child
        self.helpers[birth] = child

    def native_child_reaped(self,parent,birth,case,pins):
        ledger=self.host.ledger
        child,owner=ledger.process(birth),ledger.process(parent)
        return (child.parent==parent and child.case==owner.case==case
            and child.command_class=='native-git-helper' and owner.command_class in ('native-git-command','native-git-helper')
            and child.pins==owner.pins==pins and child.generation==child.registered_generation==1
            and owner.generation==owner.registered_generation==1 and ledger.reaped(birth,child.life_token)
            and child.terminal[2]==0 and child.parent_wait[3]==0)

    def reaped(self, actor):
        birth = actor['birth']
        if actor['role'] == 'git-helper':
            process = self.host.ledger.process(birth)
            return self.native_child_reaped(process.parent, birth, actor['case'], process.pins)
        return self.host.ledger.reaped(birth, actor['token'])


    def owned_launch(self, actor, raw, repository, expected, vector):
        host = self.host
        if host.case != OWNED_CASE or self.repositories.get((host.case,repository), {}).get('path') != repository:
            raise Refused('workspace owned launch scope')
        cwd = repository + '/.unrest-runtime/workspaces/trees/process'
        self.location(Path(repository), cwd)
        return admit_expected(host,actor,raw,expected,'workspace-owned',vector,expected.payload_sha256)


def workspace_prepare(host,actor,raw):
    case=host.case
    if case in MEASUREMENT_WORKERS and actor['role']!='root':
        from measurement_runtime import nested
        return nested(host,actor,raw)
    if case in HISTORY_CASES:
        return history_proposal(host,actor,raw)
    refuse_if(not local_case(case), 'Git proposal undeclared case')
    choices=[slot for (current,repo),slot in host.git.repositories.items() if current==case
             and (raw['cwd']==repo or raw['cwd'].startswith(repo+'/.unrest-runtime/'))]
    refuse_if(len(choices)>1, 'Git unique repository slot')
    slot=choices[0] if choices else None
    repository=slot['path'] if slot is not None else raw['cwd']
    native,pin=host.binding['entry']['path'],host.binding['entry']['sha256']
    owned=raw['argv']==[native,'-c',SITE_OWNED_BODY]
    if owned:
        if case!=OWNED_CASE or slot is None or raw['stdin'] is not None or raw['cwd']!=repository+'/.unrest-runtime/workspaces/trees/process':
            raise Refused('Git proposal owned process scope')
        expected=build_expected(
            case,
            native, pin,
            tuple(raw['argv']),
            tuple(sorted({**host.meta_environment(),'PYTEST_VERSION':'9.0.2','PYTEST_CURRENT_TEST':case+' (call)'}.items())),
            raw['cwd'], 'python-command',
        )
        vector=[native,'-I','-S','-c',SITE_OWNED_BODY]
        host.root_only(actor)
        return host.git.owned_launch(actor,raw,repository,expected,vector)

    refuse_if(raw['executable']!='/usr/bin/git', 'Git proposal original executable')
    operation,command=command_match(repository,raw['cwd'],raw['argv'],raw['stdin'],raw['environment'])
    phase=raw['environment'].get('PYTEST_CURRENT_TEST')
    if case.split('::')[0]==CANDIDATE_TEST:
        environment={'PATH':'/usr/bin:/bin','HOME':repository,'LC_ALL':'C',
            'GIT_CONFIG_NOSYSTEM':'1','GIT_CONFIG_GLOBAL':'/dev/null','GIT_CONFIG_COUNT':'1',
            'GIT_CONFIG_KEY_0':'maintenance.auto','GIT_CONFIG_VALUE_0':'false',
            'GIT_AUTHOR_DATE':'2000-01-01T00:00:00+0000','GIT_COMMITTER_DATE':'2000-01-01T00:00:00+0000'}
    else:
        refuse_if(phase not in (case+' (setup)',case+' (call)'), 'Git current original case phase')
        environment={**host.meta_environment(),'PYTEST_VERSION':'9.0.2','PYTEST_CURRENT_TEST':phase,**dict(command.additions)}
        if case.split('::')[0]==MEASUREMENT_TEST and 'UNREST_WORKER_ACP_COMMAND' in raw['environment']:
            acp=native+' '+str(Path(host.meta['checkout'])/'tests/mock_measurement_acp.py')
            environment.update(UNREST_WORKER_ACP_COMMAND=acp,UNREST_VALIDATOR_ACP_COMMAND=acp)
    return host.git.launch(actor,operation,repository,command,raw,environment)


# Closed native Git family used by the original controlled custody helper.
#
# Only disposable repositories, fixed templates and the pinned original helper
# are valid. Git data stays inside the private filesystem; it never grants remote,
# external-diff, hook or other native execution authority.



CUSTODY_ENVIRONMENT = {
    'PATH':'/usr/bin:/bin','LC_ALL':'C','GIT_CONFIG_NOSYSTEM':'1',
    'GIT_CONFIG_GLOBAL':'/dev/null','GIT_TERMINAL_PROMPT':'0',
    'GIT_AUTHOR_NAME':'Fixture','GIT_AUTHOR_EMAIL':'fixture@example.invalid',
    'GIT_COMMITTER_NAME':'Fixture','GIT_COMMITTER_EMAIL':'fixture@example.invalid',
    'GIT_AUTHOR_DATE':'2000-01-01T00:00:00+0000','GIT_COMMITTER_DATE':'2000-01-01T00:00:00+0000',
}
CUSTODY_PREFIX = ('/usr/bin/git','--no-replace-objects','-c','maintenance.auto=false','-c','gc.auto=0')
CUSTODY_FIXED = (
    ('init','--initial-branch=main','--object-format=sha1'), ('add','.'),
    ('commit','-m','finite fixture'), ('commit','-m','base'), ('rev-parse','HEAD'),
    ('commit','--allow-empty','-m','sealed candidate'),
    ('commit','--allow-empty','-m','authored lane integration'),
)


def custody_command(case, argv, cwd, owned):
    if type(case) is not str or not (CONTROLLED_CASES(case) or case in COHORT_CASES) or type(argv) is not tuple or any(type(v) is not str for v in argv):
        raise Refused('custody Git finite command primitives')
    if type(cwd) is not str or str(Path(cwd).resolve()) != cwd or not Path(cwd).is_relative_to(owned/'pytest'):
        raise Refused('custody Git owned repository')
    refuse_if(argv[:len(CUSTODY_PREFIX)] != CUSTODY_PREFIX, 'custody Git literal executable and prefix')
    args = argv[len(CUSTODY_PREFIX):]
    if args not in (*CUSTODY_FIXED,*COHORT_EXTRA.get(case,())):
        if args[:2] == ('add','--'):
            refuse_if(args[2:] not in (('a',),('b',),('lane_a.txt',),('lane_b.txt',)), 'custody Git exact authored scope')
        elif len(args) == 4 and args[:3] == ('diff','--cached','--name-only'):
            operand_digest(args[3])
        else:
            raise Refused('custody Git undeclared template')
    kind = 'head' if args == ('rev-parse','HEAD') else 'commit' if args[0] == 'commit' else 'other'
    return Command(argv,cwd),kind


def custody_repository(cwd, owned):
    acquire(cwd,owned)


def custody_launch(host,actor,result,kind,raw):
    from cohort_controller import parent
    parent(host,actor)
    prior = [v for v in host.intents.values() if v['case'] == host.case and v['role'] == 'git-custody']
    from cohort_controller import CASES as CRASH
    maximum=4 if host.case in CRASH else COHORT_CASES[host.case][1] if host.case in COHORT_CASES else 128
    refuse_if(len(prior) >= maximum, 'custody Git finite case command bound')
    custody_repository(result.cwd,Path(host.meta['owned']))
    return issue(host,actor,raw,result,CUSTODY_ENVIRONMENT,role='git-custody',maximum=maximum,
        fields={'command':result,'repository':result.cwd,'operation':'custody-'+kind})


COMPLETION_FIXTURE=(('git','init','-q'),('git','-c','user.name=Test','-c','user.email=test@example.invalid',
    'commit','--allow-empty','-qm','base'))


def completion_fixture(case):
    return (COMPLETION_FIXTURE[0],('git','add','product.txt'),
        ('git','-c','user.name=Test','-c','user.email=test@example.invalid','commit','-qm','defective candidate')) if case==ROLE_DEFECT else COMPLETION_FIXTURE


COMPLETION_APP_KEYS=frozenset(('UNREST_HOME','UNREST_PROJECTS_DIR','UNREST_PROJECT_ID','UNREST_MISSION_ID',
    'UNREST_NODE_ID','UNREST_NODE_TYPE','UNREST_HANDOFF_PATH','UNREST_NODE_ASSIGNMENT'))


def completion_application_environment(baseline,observed):
    expected={**baseline,**{key:value for key,value in observed.items() if key in COMPLETION_APP_KEYS}}
    refuse_if(observed!=expected, 'Git environment outside closed application metadata')
    return expected


def completion_ready(host,workspace):
    custody_repository(str(workspace),Path(host.meta['owned']))


def completion_proposal(host,actor,raw):
    case=host.case
    if case not in ROLE_CASES or raw['stdin'] is not None or raw['executable']!='/usr/bin/git':
        raise Refused('completion exact Git proposal')
    parent=role_root(host,raw['cwd'])
    workspace=parent/'workspace'
    records=[row for row in host.intents.values() if row['case']==case and row['role']=='git-command'
             and row['parent']==actor['birth']]
    base={**host.meta_environment(),'PYTEST_VERSION':'9.0.2','PYTEST_CURRENT_TEST':case+' (call)'}
    commands=completion_fixture(case)
    if actor['role']=='root':
        host.root_only(actor)
        if (len(records)>=len(commands)+ROOT_QUERIES.get(case,0)
                or any(row['case']==case and 'server_slot' in row for row in host.intents.values())):
            raise Refused('completion root fixture sequence')
        is_fixture=len(records)<len(commands)
        if is_fixture:
            vector=commands[len(records)]
            completion_ready(host,workspace)
            environment=base
        else:
            completion_ready(host,workspace)
            vector=('git','rev-parse','HEAD')
            environment=completion_application_environment(base,raw['environment']) if case in ROLE_SOURCE else base
        command=Command(vector,str(workspace))
    else:
        if case in COMPOSED_CASES:
            from composed_runtime import query_quota
            quota=query_quota(host,actor)
        else:
            actor_slot(host,actor)
            quota=max(row[2] for row in role_schedule(case)) if actor['profile']['environment'].get('UNREST_NODE_TYPE')=='work' else 0
        refuse_if(len(records)>=quota, 'completion server-owned Git query quota')
        completion_ready(host,workspace)
        is_fixture=False
        vector=('git','rev-parse','HEAD')
        command=Command(vector,str(workspace))
        environment=dict(actor['profile']['environment'])
    return issue(host,actor,raw,command,environment,
        maximum=len(commands)+ROOT_QUERIES.get(case,0)+(composed_queries(case) if case in COMPOSED_CASES else sum(row[2] for row in role_schedule(case))),
        fields={'command':command,'repository':str(workspace),'operation':'completion-fixture' if is_fixture else 'completion-head',
            'fixture_git':is_fixture})
