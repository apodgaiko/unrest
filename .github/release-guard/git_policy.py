"""Finite Git command families, actual native custody and closed public inputs.

Families retain independent case sets, parent roles, budgets and helper rights.
"""
from __future__ import annotations

import hashlib
import os
import re
import subprocess
from datetime import datetime
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
import ast
import stat
from launch_policy import source_unit, build_expected, admit_expected
from owned_fixture import acquire, retain
from content_manifest import Refused, native_digest, read_regular
from controlled_cases import CASES as CONTROLLED_CASES
from controlled_pairs import limits as pair_limits
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


def public_projection(repository: Path, head: str) -> tuple[dict[str, str], dict[str, str]]:
    if PUBLIC_OID.fullmatch(head) is None or public_oid(public_git(repository, 'rev-parse', '--verify', 'HEAD')) != head:
        raise RuntimeError('public_git_head_drift')
    commits = public_git(repository, 'rev-list', head).decode('ascii').splitlines()
    if not commits or len(commits) > 20000 or any(PUBLIC_OID.fullmatch(item) is None for item in commits):
        raise RuntimeError('public_git_commit_graph')
    objects = dict.fromkeys(commits, 'commit')
    roots = {head, PUBLIC_FM000}
    if PUBLIC_FM000 not in objects:
        raise RuntimeError('public_git_required_ancestor')
    for name, expected in PUBLIC_TAGS.items():
        if public_oid(public_git(repository, 'rev-parse', '--verify', 'refs/tags/' + name)) != expected:
            raise RuntimeError('public_git_historical_tag_drift')
        if public_git(repository, 'cat-file', '-t', expected).strip() != b'tag':
            raise RuntimeError('public_git_historical_tag_type')
        objects[expected] = 'tag'
        commit = public_oid(public_git(repository, 'rev-parse', '--verify', name + '^{commit}'))
        if commit not in objects or objects[commit] != 'commit':
            raise RuntimeError('public_git_historical_ancestry')
        roots.add(commit)
    for commit in sorted(roots):
        tree = public_oid(public_git(repository, 'rev-parse', '--verify', commit + '^{tree}'))
        objects[tree] = 'tree'
        for row in public_git(repository, 'ls-tree', '-r', '-t', '-z', '--full-tree', commit).split(b'\0'):
            if not row:
                continue
            header, _ = row.split(b'\t', 1)
            _, kind, object_id = header.decode('ascii').split(' ')
            if kind not in {'tree', 'blob'} or PUBLIC_OID.fullmatch(object_id) is None:
                raise RuntimeError('public_git_tree_member')
            if objects.setdefault(object_id, kind) != kind:
                raise RuntimeError('public_git_object_type_conflict')
    if len(objects) > 50000:
        raise RuntimeError('public_git_projection_bound')
    return objects, dict(PUBLIC_TAGS)


def public_prepare(repository: Path, destination: Path, head: str) -> dict[str, object]:
    if destination.resolve(strict=True) != destination:
        raise RuntimeError('public_git_destination_alias')
    repository, destination = repository.resolve(strict=True), destination.resolve(strict=True)
    if (not destination.is_dir() or destination.is_relative_to(repository)
            or repository.is_relative_to(destination) or (destination / '.git').exists()
            or (destination / '.git').is_symlink()):
        raise RuntimeError('public_git_destination')
    objects, tags = public_projection(repository, head)
    # Explicit IDs, no revision traversal or delta reuse: no other trees,
    # branches, hooks, runner config, credentials or alternate path is copied.
    pack = public_git(repository, 'pack-objects', '--stdout', '--no-reuse-delta',
               '--no-reuse-object', '--window=0', data=''.join(k + '\n' for k in sorted(objects)).encode())
    if len(pack) > 256 * 1024 * 1024 or not pack.startswith(b'PACK'):
        raise RuntimeError('public_git_pack_bound')
    metadata = destination / '.git'
    packed = metadata / 'objects/pack'
    packed.mkdir(parents=True)
    (metadata / 'refs/tags').mkdir(parents=True)
    (metadata / 'config').write_bytes(b'[core]\nrepositoryformatversion = 0\nbare = false\n')
    (metadata / 'HEAD').write_text(head + '\n')
    name = hashlib.sha1(pack[:-20]).hexdigest()
    if bytes.fromhex(name) != pack[-20:]:
        raise RuntimeError('public_git_pack_checksum')
    path = packed / ('pack-' + name + '.pack')
    path.write_bytes(pack)
    if public_oid(public_git(destination, 'index-pack', '--index-version=2', str(path))) != name:
        raise RuntimeError('public_git_index_identity')
    index = path.with_suffix('.idx')
    observed = {}
    for line in public_git(destination, 'verify-pack', '-v', str(index)).decode('ascii').splitlines():
        fields = line.split()
        if fields and PUBLIC_OID.fullmatch(fields[0]):
            if len(fields) != 5 or fields[0] in observed or fields[1] not in {'commit', 'tree', 'blob', 'tag'}:
                raise RuntimeError('public_git_pack_member')
            observed[fields[0]] = fields[1]
        elif not (line.startswith('non delta: ') or line == str(path) + ': ok'):
            raise RuntimeError('public_git_pack_verification')
    if observed != objects:
        raise RuntimeError('public_git_object_set')
    for name, object_id in tags.items():
        (metadata / 'refs/tags' / name).write_text(object_id + '\n')
    public_git(destination, 'read-tree', head)
    if public_oid(public_git(destination, 'rev-parse', '--verify', 'HEAD^{commit}')) != head:
        raise RuntimeError('public_git_head_consumption')
    public_git(destination, 'merge-base', '--is-ancestor', PUBLIC_FM000, head)
    return {'head': head, 'historical_tags': tags, 'objects': len(objects),
            'pack_sha256': hashlib.sha256(pack).hexdigest(), 'external_deltas': False,
            'scope': 'public HEAD commit graph; HEAD/FM000/six historical trees; exact tag objects'}


def operand_text(value):
    if type(value) is not str or not value or len(value) > 4096 or '\0' in value:
        raise Refused('git value primitive')
    try:
        if len(value.encode('utf-8')) > 4096:
            raise Refused('git value text bound')
    except UnicodeError:
        raise Refused('git value text encoding') from None
    return value


def operand_digest(value, length=40):
    if type(value) is not str or len(value) != length or any(c not in '0123456789abcdef' for c in value):
        raise Refused('git value digest')
    return value


def operand_date_text(value):
    operand_text(value)
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        raise Refused('git value date') from None
    canonical = parsed.isoformat()
    alternatives = (canonical, canonical[:-6] + 'Z') if canonical.endswith('+00:00') else (canonical,)
    if parsed.tzinfo is None or value not in alternatives:
        raise Refused('git value canonical date')
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


COMMAND_SETUP=('init','config-name','config-email','stage-base','commit-base')

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
COMMAND_OPERATIONS = (*COMMAND_FIXED,
    'init', 'config-name', 'config-email', 'stage-base',
    'commit-base', 'stage-advance', 'commit-advance', 'stage-child',
    'commit-child', 'verify-base', 'lease-add', 'integration-add',
    'rollback-add', 'checkout', 'diff-return', 'apply',
    'date', 'commit-tree', 'update-parent', 'reset-parent',
    'rollback-update', 'rollback-reset', 'remove-tree',
)


def command_path(value):
    operand_text(value)
    p = PurePosixPath(value)
    if not value.startswith('/') or value.startswith('//') or str(p) != value or '..' in p.parts:
        raise Refused('git command canonical path')
    return p


def command_location_role(repo, cwd):
    if cwd == repo:
        return 'parent'
    if cwd.parent == repo / '.unrest-runtime/workspaces/trees':
        if cwd.name and all(c in 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-' for c in cwd.name):
            return 'lease'
    for role, parent, prefix in (('integration', repo / '.unrest-runtime/workspaces', 'integration-'),
                                  ('rollback', repo / '.unrest-runtime/evolution', 'rollback-')):
        suffix = cwd.name.removeprefix(prefix)
        if cwd.parent == parent and cwd.name.startswith(prefix) and len(suffix) == 8 and all(c in 'abcdefghijklmnopqrstuvwxyz0123456789_' for c in suffix):
            return role
    raise Refused('git operation location')


COMMAND_ROLES = {**dict.fromkeys(COMMAND_OPERATIONS, ('parent',)),
    'top': ('parent', 'lease'), 'head': ('parent', 'lease'),
    **dict.fromkeys(('inventory', 'stage-return', 'checkout', 'diff-return', 'stage-child', 'commit-child'), ('lease',)),
    **dict.fromkeys(('apply', 'write-tree', 'commit-tree'), ('integration',)),
    'check-index': ('integration', 'rollback')}


def command_match(operation, repository, location, argv, stdin, environment, *, family, fixture=None, branch="main"):
    """Match one closed complete vector; dynamic operands grant no extra forms."""
    if type(family) is not str or family not in ('workspaces','evolution') or type(operation) is not str or operation not in COMMAND_OPERATIONS:
        raise Refused('git closed operation')
    if type(argv) is not list or not argv or any(type(value) is not str for value in argv) or argv[0]!='git':
        raise Refused('git literal argument vector')
    repo,cwd=command_path(repository),command_path(location)
    role=command_location_role(repo,cwd)
    if role=='rollback' and family!='evolution':
        raise Refused('git rollback location family')
    if role not in COMMAND_ROLES[operation]:
        raise Refused('git operation location role')
    args=tuple(argv[1:])
    additions=()
    if operation in COMMAND_FIXED:
        if args!=COMMAND_FIXED[operation]:
            raise Refused('git fixed command')
    elif operation in ('init','config-name','config-email','stage-base','commit-base','stage-advance','commit-advance','stage-child','commit-child'):
        label='Workspace' if family=='workspaces' else 'Evolution'
        expected={'init':('init','-b','main'),'config-name':('config','user.name',label+' Test'),
            'config-email':('config','user.email',family.removesuffix('s')+'@example.test'),
            'stage-base':('add','README.md'),'commit-base':('commit','-m','base'),
            'stage-advance':('add','advance.txt'),'commit-advance':('commit','-m','advance parent'),
            'stage-child':('add','child.txt'),'commit-child':('commit','-m','child self commit')}[operation]
        if fixture is not None and operation in ('init','config-name','config-email','stage-base','commit-base'):
            expected=fixture.commands[('init','config-name','config-email','stage-base','commit-base').index(operation)]
        if (args!=expected or (operation in ('stage-child','commit-child'))!=(cwd!=repo)
                or family=='evolution' and operation in ('stage-child','commit-child','stage-advance','commit-advance')):
            raise Refused('git fixture command or family')
    else:
        match operation,args:
            case ('lease-add',('worktree','add','--detach','--no-checkout',tree,revision)) | (('integration-add'|'rollback-add'),('worktree','add','--detach',tree,revision)):
                tree=command_path(tree)
                target={'lease-add':'lease','integration-add':'integration','rollback-add':'rollback'}[operation]
                if command_location_role(repo,tree)!=target or target=='rollback' and family!='evolution':
                    raise Refused('git add tree scope or rollback family')
                operand_digest(revision)
            case ('remove-tree',('worktree','remove','--force',tree)):
                target=command_location_role(repo,command_path(tree))
                if target not in ('lease','integration','rollback') or target=='rollback' and family!='evolution':
                    raise Refused('git remove tree scope or rollback target family')
            case ('verify-base',('rev-parse','--verify',revision)) if revision.endswith('^{commit}'):
                operand_digest(revision[:-9])
            case ('checkout',('checkout','--detach',revision)) | ('diff-return',('diff','--cached','--binary','--no-ext-diff',revision)) | ('date',('show','-s','--format=%aI',revision)):
                operand_digest(revision)
            case (('reset-parent'|'rollback-reset'),('reset','--hard',revision)):
                operand_digest(revision)
                if operation=='rollback-reset' and family!='evolution':
                    raise Refused('git rollback family')
            case ('apply',('apply','--index','--binary',patch)):
                patch=command_path(patch)
                if patch.parent!=repo/'.unrest/workspaces/patches' or patch.suffix!='.patch':
                    raise Refused('git patch scope')
                operand_digest(patch.stem,64)
            case (('update-parent'|'rollback-update'),('update-ref',reference,new,old)):
                if branch not in ('main','master') or reference!='refs/heads/'+branch or operation=='rollback-update' and family!='evolution':
                    raise Refused('git update reference or rollback family')
                operand_digest(new)
                operand_digest(old)
            case ('commit-tree',('commit-tree',tree,'-p',revision)):
                operand_digest(tree)
                operand_digest(revision)
                date=environment.get('GIT_AUTHOR_DATE')
                operand_date_text(date)
                if type(stdin) is not str or len(stdin)>16384 or not stdin.startswith('Integrate Unrest workspaces\n\n') or not stdin.endswith('\n'):
                    raise Refused('Git finite commit input')
                rows=stdin[len('Integrate Unrest workspaces\n\n'):-1].split('\n')
                import re
                if (not 0<len(rows)<=128 or rows!=sorted(rows) or len(set(row.split(' ')[0] for row in rows))!=len(rows)
                        or any(len(row.split(' ',1)[0])>4096 or re.fullmatch(r'lease:[A-Za-z0-9_-]+ sha256:[a-f0-9]{64}',row) is None for row in rows)):
                    raise Refused('git commit deterministic lease identity')
                additions=tuple(sorted({'GIT_AUTHOR_NAME':'Unrest parent integration authority','GIT_AUTHOR_EMAIL':'unrest@localhost',
                    'GIT_COMMITTER_NAME':'Unrest parent integration authority','GIT_COMMITTER_EMAIL':'unrest@localhost',
                    'GIT_AUTHOR_DATE':date,'GIT_COMMITTER_DATE':date}.items()))
            case _:
                raise Refused('Git proposal does not match a template')
    if operation!='commit-tree' and stdin is not None:
        raise Refused('git unexpected command input')
    return Command(tuple(argv),str(cwd),additions,stdin)


CANDIDATE_TEST='tests/test_experimental_candidate.py'
CANDIDATE_PIN='6827bd92719ed7e138980b9e4dc3d9e6fdc775444093609fe78c0e806981c39e'
CANDIDATE_CONSUMERS={
    'test_literal_manifest_and_independent_oracle':(None,),
    'test_immutable_binding_and_failed_observation':(None,),
    'test_input_changes_refuse':('content', 'delete', 'mode', 'staged', 'index-delete', 'index-add', 'assume', 'skip', 'intent', 'unmerged', 'extra', 'extra-delete', 'untracked', 'ignored'),
    'test_hardlinks_refuse':('tracked/output', 'extra/output', 'tracked/tracked', 'input/outside', 'output/outside'),
    'test_equal_independent_files_and_outputs':(None,),
    'test_noncanonical_declarations':('../escape', '/absolute', './out', 'out/', 'a//b', 'a/../b', '*.txt', '.git', 'a/.GiT/x', '.unrest/x', 'a\\\\b', 'trailing.', '\\xe9', 'a\\n'),
    'test_overlap':('extras0-outputs0', 'extras1-outputs1', 'extras2-outputs2', 'extras3-outputs3', 'extras4-outputs4', 'extras5-outputs5'),
    'test_unsafe_files':('input-symlink', 'output-symlink', 'output-leaf-symlink', 'fifo', 'nested', 'alias', 'missing-output', 'output-file'),
    'test_symlink_ancestor_and_git_indirection':(None,),
    'test_config_canaries_never_called':('filter.canary.clean-CANARY', 'filter.canary.smudge-CANARY', 'diff.canary.textconv-CANARY', 'diff.external-CANARY', 'core.fsmonitor-CANARY', 'core.hooksPath-CANARY', 'credential.helper-CANARY', 'remote.origin.url-ext::CANARY', 'remote.origin.uploadpack-CANARY', 'include.path-CANARY', 'extensions.partialclone-origin', 'remote.origin.promisor-true', 'core.sparsecheckout-true', 'extensions.objectformat-sha256'),
    'test_ambient_overrides_scrubbed':(None,),
    'test_metadata_refusal_before_git':('shallow', 'objects/info/alternates', 'objects/info/http-alternates', 'objects/pack/pack-x.promisor', 'objects/pack/pack-x.pack', 'refs/replace/replaced', 'info/grafts', 'commondir', 'hooks/pre-commit', 'config.worktree'),
    'test_wrong_ids_types_and_unrelated_history':(None,),
    'test_raw_object_integrity':('wrong-content-candidate', 'wrong-content-base', 'wrong-content-tree', 'wrong-content-blob', 'wrong-content-ancestry', 'wrong-type-candidate', 'wrong-type-base', 'wrong-type-tree', 'wrong-type-blob', 'wrong-type-ancestry', 'missing-candidate', 'missing-base', 'missing-tree', 'missing-blob', 'missing-ancestry', 'truncated-candidate', 'truncated-base', 'truncated-tree', 'truncated-blob', 'truncated-ancestry'),
    'test_object_size_count_aggregate_deadlines':(None,),
    'test_observer_leaves_all_repository_bytes_and_modes_unchanged':(None,),
    'test_unsupported_tree_entries':('120000', '160000'),
    'test_manifest_constructor_cannot_retain_mutable_values':(None,),
    'test_index_independent_refusals':('mode', 'checksum', 'version', 'extension', 'missing'),
    'test_nested_bare_repository_refuses':(None,),
    'test_executable_tracked_file_and_nested_extra':(None,),
    'test_declarations_reject_custom_containers':(None,),
    'test_declaration_deadline_starts_before_validation':(None,),
    'test_overlap_loop_checks_deadline':(None,),
    'test_observation_and_verification_create_no_object_read_children':(None,),
}
CANDIDATE_CASES=tuple(CANDIDATE_TEST+'::'+name+('['+parameter+']' if parameter is not None else '') for name,parameters in CANDIDATE_CONSUMERS.items() for parameter in parameters)


def candidate_declarations(checkout,case,repository):
    if case not in CANDIDATE_CASES:
        raise Refused('candidate exact fixture consumer')
    unit=source_unit(checkout,CANDIDATE_TEST,CANDIDATE_PIN,('repo',))
    setup=[]
    for statement in unit.body:
        call=statement.value if isinstance(statement,ast.Expr) else statement.value if isinstance(statement,ast.Assign) else None
        if isinstance(call,ast.Call) and isinstance(call.func,ast.Name) and call.func.id=='git':
            setup.append(tuple(ast.literal_eval(arg) for arg in call.args[1:]))
    if len(setup)!=9 or any(type(arg) is not str for row in setup for arg in row):
        raise Refused('candidate literal fixture setup')
    name=case.split('::',1)[1]
    root=Path(repository)
    extras=[]
    if name=='test_literal_manifest_and_independent_oracle':
        extras=[('rev-parse','HEAD^{tree}')]
    elif name.startswith('test_input_changes_refuse['):
        parameter=name[len('test_input_changes_refuse['):-1]
        extras={'mode':[('config','core.filemode','false')], 'staged':[('add','lane_a.txt')],
            'index-delete':[('rm','--cached','lane_a.txt')], 'index-add':[('add','extra.txt')],
            'assume':[('update-index','--assume-unchanged','lane_a.txt')],
            'skip':[('update-index','--skip-worktree','lane_a.txt')], 'intent':[('add','-N','extra.txt')]}.get(parameter,[])
    elif name.startswith('test_config_canaries_never_called['):
        parameter=name[len('test_config_canaries_never_called['):-1]
        key,value=parameter.split('-',1)
        extras=[('config',key,value.replace('CANARY',str(root.parent/'canary')))]
    elif name=='test_wrong_ids_types_and_unrelated_history':
        extras=[('rev-parse','HEAD^{tree}'),('rev-parse','HEAD:lane_a.txt'),('commit-tree',None,'-m','unrelated')]
    elif name.startswith('test_raw_object_integrity[') and not name.endswith('-ancestry]'):
        extras=[('rev-parse','HEAD^{tree}'),('rev-parse','HEAD:lane_a.txt')]
    elif name.startswith('test_unsupported_tree_entries['):
        mode=name[len('test_unsupported_tree_entries['):-1]
        extras=([('rev-parse','HEAD:lane_a.txt')] if mode=='120000' else [])+[
            ('update-index','--add','--cacheinfo',mode+',OID,unsupported'),('commit','-m','unsupported'),('rev-parse','HEAD')]
    elif name=='test_executable_tracked_file_and_nested_extra':
        extras=[('add','lane_a.txt'),('commit','-m','executable'),('rev-parse','HEAD')]
    return tuple(setup),tuple(extras)


def candidate_command(checkout,case,repository,ordinal,argv):
    setup,extras=candidate_declarations(checkout,case,repository)
    rows=(*setup,*extras)
    if not 0<=ordinal<len(rows) or not argv or argv[0]!='/usr/bin/git':
        raise Refused('candidate fixture finite command ordinal')
    expected=list(rows[ordinal])
    actual=argv[1:]
    if None in expected:
        index=expected.index(None)
        if len(actual)!=len(expected):
            raise Refused('candidate object operand shape')
        operand_digest(actual[index])
        expected[index]=actual[index]
    if expected[-1].endswith(',OID,unsupported'):
        if len(actual)!=len(expected):
            raise Refused('candidate cache entry operand shape')
        parts=actual[-1].split(',')
        if len(parts)!=3 or (parts[0],parts[2])!=(expected[-1].split(',')[0],'unsupported'):
            raise Refused('candidate cache entry scope')
        operand_digest(parts[1])
        expected[-1]=actual[-1]
    if actual!=expected:
        raise Refused('candidate original complete command')
    environment={'PATH':'/usr/bin:/bin','HOME':repository,'LC_ALL':'C',
        'GIT_CONFIG_NOSYSTEM':'1','GIT_CONFIG_GLOBAL':'/dev/null',
        'GIT_CONFIG_COUNT':'1','GIT_CONFIG_KEY_0':'maintenance.auto','GIT_CONFIG_VALUE_0':'false',
        'GIT_AUTHOR_DATE':'2000-01-01T00:00:00+0000','GIT_COMMITTER_DATE':'2000-01-01T00:00:00+0000'}
    return Command(tuple(argv),repository),environment


def candidate_proposal(host,actor,raw):
    records=[row for row in host.intents.values() if row['case']==host.case and row['role']=='git-command']
    repository=raw['cwd']
    value,environment=candidate_command(Path(host.meta['checkout']),host.case,repository,len(records),raw['argv'])
    return host.git.launch(actor,'init' if not records else 'candidate-command',repository,value,raw,environment)


MEASUREMENT_OWNER=20000
MEASUREMENT_TEST='tests/test_measurement.py'
MEASUREMENT_PIN='d850dcaf77c4b4ebd08efa87089cbc7b59762d5eb8d7fd0b673a9e043bc3e97f'
MEASUREMENT_SYNTHETIC=('test_successful_exact_protocol_publishes_sanitized_recomputable_bundle',
    *(f'test_oracle_cache_and_cost_fail_closed[provider{index}-invalid]' for index in range(3)),
    'test_noise_over_fifteen_percent_is_inconclusive','test_unknown_reported_cost_is_not_collapsed_to_zero',
    'test_publication_rejects_unknown_or_private_fields_and_preserves_existing')
MEASUREMENT_NAMES=(*MEASUREMENT_SYNTHETIC,'test_evolution_cases_use_real_public_state_machine_and_cold_state',
    'test_project_cases_use_real_run_control_and_nested_acp','test_confirmation_and_protocol_drift_do_not_invoke_provider',
    'test_product_digest_excludes_only_results')
MEASUREMENT_CASES=tuple(MEASUREMENT_TEST+'::'+name for name in MEASUREMENT_NAMES)
MEASUREMENT_COLD=('inside','top','head','parent-ref','clean','inventory','verify-base','lease-add','checkout','stage-return','diff-return')
MEASUREMENT_REAL={MEASUREMENT_TEST+'::'+MEASUREMENT_NAMES[-4]:(11,16),MEASUREMENT_TEST+'::'+MEASUREMENT_NAMES[-3]:(1,6)}


def measurement_proposal(host,actor,raw):
    from run_worker_launch import MEASUREMENT_PROJECT
    if host.case==MEASUREMENT_PROJECT and actor['role']!='root':
        from measurement_runtime import nested
        return nested(host,actor,raw)
    host.root_only(actor)
    checkout=Path(host.meta['checkout'])
    source_unit(checkout,MEASUREMENT_TEST,MEASUREMENT_PIN)
    argv=raw['argv']
    arguments=tuple(argv[1:])
    source=Path(raw['cwd']).name=='source'
    records=[slot for (case,repository),slot in host.git.repositories.items() if case==host.case
        and (raw['cwd']==repository or raw['cwd'].startswith(repository+'/.unrest-runtime/'))]
    repository=records[0]['path'] if len(records)==1 else raw['cwd']
    if len(records)>1 or raw['executable']!='/usr/bin/git' or argv[0]!='git':
        raise Refused('measurement original source Git command')
    environment={**host.meta_environment(),'PYTEST_VERSION':'9.0.2','PYTEST_CURRENT_TEST':host.case+' (call)'}
    if not source or arguments==('ls-files','-z','--stage') and host.case.split('::')[1] in MEASUREMENT_SYNTHETIC:
        command=host.binding['entry']['path']+' '+str(checkout/'tests/mock_measurement_acp.py')
        environment.update(UNREST_WORKER_ACP_COMMAND=command,UNREST_VALIDATOR_ACP_COMMAND=command)
    operation='init' if arguments==('init','-q') else 'measurement-command'
    if source:
        if raw['stdin'] is not None or arguments not in (('init','-q'),('add','.'),('ls-files','-z','--stage')):
            raise Refused('measurement original source Git command')
        value=Command(tuple(argv),raw['cwd'])
    else:
        measurement_cold_root(host,Path(repository))
        if arguments in (('init','-q'),('add','.gitignore','candidate.txt'),
                ('-c','user.name=Unrest Measurement','-c','user.email=measurement@invalid','commit','-q','-m','frozen baseline')):
            if raw['stdin'] is not None or raw['cwd']!=repository:
                raise Refused('measurement cold setup location or input')
            value=Command(tuple(argv),repository)
        else:
            matches={}
            for candidate in MEASUREMENT_COLD:
                try:
                    matches[candidate]=command_match(candidate,repository,raw['cwd'],argv,raw['stdin'],raw['environment'],family='evolution')
                except Refused:
                    pass
            if len(matches)!=1:
                raise Refused('measurement single shared Git operation')
            operation,value=next(iter(matches.items()))
            environment.update(value.additions)
    return host.git.launch(actor,operation,repository,value,raw,environment)


def measurement_cold_root(host,path):
    if host.case not in MEASUREMENT_REAL:
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
            or parts[3]!='cold-roots' or parts[4] not in tuple(f'rep-{index:02d}' for index in MEASUREMENT_REAL[host.case]) or parts[5]!='workspace'
            or path.resolve()!=path):
        raise Refused('measurement exact cold repetition path')
    identity=[]
    for directory in (path,*(parent for parent in path.parents if parent.is_relative_to(base))):
        info=directory.stat(follow_symlinks=False)
        if not stat.S_ISDIR(info.st_mode) or info.st_uid!=MEASUREMENT_OWNER or info.st_mode&0o6022:
            raise Refused('measurement cold directory custody')
        identity.append((str(directory),info.st_dev,info.st_ino))
    if (host.fixture_roots.setdefault(('measurement-run',host.case),parts[2])!=parts[2]
            or host.fixture_roots.setdefault(('measurement-root',host.case,str(path)),identity)!=identity):
        raise Refused('measurement cold generation changed')


def measurement_worker(host,actor,raw):
    import os
    from run_worker_launch import admit_worker,MEASUREMENT_EVOLUTION,MEASUREMENT_PROJECT
    if host.case not in (MEASUREMENT_EVOLUTION,MEASUREMENT_PROJECT):
        raise Refused('measurement worker exact case')
    source_unit(Path(host.meta['checkout']),MEASUREMENT_TEST,MEASUREMENT_PIN)
    records=[row for row in host.intents.values() if row['case']==host.case and row.get('run_worker')]
    from measurement_runtime import PROJECT_STEPS
    steps=((11,'start_project',()),(16,'start_project',())) if host.case==MEASUREMENT_EVOLUTION else PROJECT_STEPS
    if len(records)>=len(steps) or any(not row['consumed'] or not host.ledger.reaped(row['birth'],row['token']) for row in records):
        raise Refused('measurement worker original sequence and waits')
    repetition,operation,nodes=steps[len(records)]
    home=Path(raw['cwd'])
    measurement_cold_root(host,home.parent/'workspace')
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

@dataclass(frozen=True)
class Fixture:
    family: str
    init: tuple[str,...]
    user: str
    email: str
    stage: tuple[str,...]
    phase: str

    @property
    def commands(self):
        return (self.init,('config','user.name',self.user),('config','user.email',self.email),
                ('add',*self.stage),('commit','-m','base'))


FIXTURE_MODULES={
    'tests/test_server.py':Fixture('workspaces',('init',),'Schema Validator','schema@example.test',('.',),'call'),
    MEASUREMENT_TEST:Fixture('measurement',('init','-q'),'','',('.',),'call'),
    CANDIDATE_TEST:Fixture('candidate',('init','--initial-branch=main','--object-format=sha1'),'Fixture','fixture@example.invalid',('.',),'setup'),
    'tests/test_foundation_authority.py':Fixture('workspaces',('init',),'Authority Test','authority@example.test',('.',),'call'),
    'tests/test_foundation_integration.py':Fixture('workspaces',('init',),'Foundation Integration','foundation@example.test',('.',),'call'),
    'tests/test_project_adapter.py':Fixture('workspaces',('init','-b','main'),'Project Adapter Test','project-adapter@example.test',('README.md','.gitignore'),'setup'),
    'tests/test_improve_adapter.py':Fixture('evolution',('init','-b','main'),'Improve Adapter Test','improve@example.test',('README.md',),'setup'),
    'tests/test_v04_activation.py':Fixture('activation',('init','-b','main'),'ACT-190 Activation','act190@example.test',('README.md',),'call'),
}
FIXTURE_PINS={
    'tests/test_server.py':'0550689ff20fb183ea62b47606bd3e66c5fc1222b5d4166e57e74d546afbb286',
    MEASUREMENT_TEST:MEASUREMENT_PIN,
    CANDIDATE_TEST:CANDIDATE_PIN,
    'tests/test_foundation_authority.py':'c8f63d70d4dcc3d74215a9db538632fc9115086d32d42f633235135dcaea2c70',
    'tests/test_foundation_integration.py':'bcbddfff3ffabd8b4374be17fa22b35872bd347d2daa8ca9ee3132f007caa8ef',
    'tests/test_improve_adapter.py':'d3c9c1fa8461db4e30b3d3239bf52746018a56b957f4699ddff7572c10be3290',
    'tests/test_project_adapter.py':'b48d315875eedb9350219fcc3c203c778f329389f32d8f787de0c574390235cf',
    'tests/test_v04_activation.py':'4741feb6a71d9c06be777a08a34e064be0610c1f8b755ebfffef21489621c435',
}
FIXTURE_SLOTS={
    'tests/test_foundation_authority.py::test_workspace_mutations_replay_exactly_and_collision_precedes_events':('repo',),
    'tests/test_foundation_authority.py::test_integration_requires_retained_exact_grant_and_consumes_it_once':('repo',),
    'tests/test_foundation_authority.py::test_scope_mismatched_retained_grant_fails_before_parent_effect':('repo',),
    'tests/test_foundation_authority.py::test_tool_error_mapping_is_closed_and_private_details_survive_async_run':('repo',),
    'tests/test_foundation_authority.py::test_async_project_lock_contention_is_public_busy_with_private_cause':('repo',),
    'tests/test_foundation_authority.py::test_evolution_provider_and_git_faults_reconcile_without_reexecution':('repo',),
    'tests/test_foundation_integration.py::test_two_disjoint_mutable_tasks_use_distinct_worktrees_and_integrate':('repo',),
    'tests/test_foundation_integration.py::test_scope_escape_withholds_entire_parallel_batch':('repo',),
    'tests/test_project_adapter.py::test_two_isolated_leaves_join_in_deterministic_order_and_serialize':('project',),
    'tests/test_project_adapter.py::test_leaf_failure_blocks_join_and_withholds_integration':('project',),
    'tests/test_project_adapter.py::test_cancellation_stops_after_atomic_leaf_batch':('project',),
    'tests/test_project_adapter.py::test_execution_bound_leaves_join_pending':('project',),
    'tests/test_project_adapter.py::test_invalid_graphs_and_mismatched_runtime_fail_closed':('project',),
    **{'tests/test_project_adapter.py::test_invalid_step_matrix_fails_before_coordinator_step['+value+']':('project',)
       for value in ('0','-1','True','1.5','1','None')},
    'tests/test_project_adapter.py::test_missing_submitted_dag_is_exact_and_never_coordinates':('project',),
    'tests/test_improve_adapter.py::test_nominal_provider_free_open_add_evaluate_review_inspect':('project',),
    'tests/test_improve_adapter.py::test_success_stops_at_reviewed_decision_needed':('project',),
    'tests/test_improve_adapter.py::test_resume_from_persisted_candidate':('project',),
    'tests/test_improve_adapter.py::test_missing_campaign_freeze_is_exact_and_inert':('project',),
    'tests/test_improve_adapter.py::test_missing_lease_and_candidate_are_distinct_and_inert':('project',),
    'tests/test_improve_adapter.py::test_mismatched_freeze_lease_and_candidate_are_exact':('project',),
    'tests/test_improve_adapter.py::test_expired_active_lease_mismatch_is_exact_and_inert':('project',),
    'tests/test_improve_adapter.py::test_resume_preserves_existing_review_outcome':('project',),
    'tests/test_improve_adapter.py::test_serialization_is_canonical_and_resume_stable':('project',),
    'tests/test_improve_adapter.py::test_public_result_preserves_provenance_without_private_content':('project',),
    'tests/test_improve_adapter.py::test_no_later_decision_network_or_external_effect':('project',),
    **{f'tests/test_improve_adapter.py::test_invalid_costs_fail_during_request_construction[{value}-{field}]':('project',)
       for value in ('-1','True','1.5','1') for field in ('candidate_cost_steps','evaluation_cost_steps')},
    'tests/test_improve_adapter.py::test_configured_provider_is_rejected_before_any_campaign_operation':('project',),
    'tests/test_v04_activation.py::test_project_direct_and_api_carriers_preserve_topology_and_state':('repo-direct', 'repo-api'),
    'tests/test_v04_activation.py::test_improvement_direct_and_api_carriers_stop_private_and_provider_free':('improve-parity',),
    'tests/test_v04_activation.py::test_improvement_invalid_and_provider_reject_before_campaign_effect':('improve-invalid', 'improve-provider'),
    'tests/test_v04_activation.py::test_project_click_and_subprocess_stop_without_exact_request':('repo-click', 'repo-subprocess'),
    'tests/test_v04_activation.py::test_improvement_click_and_subprocess_stop_without_exact_request':('improve-click-cli', 'improve-subprocess-cli'),
}
FIXTURE_SLOTS.update(dict.fromkeys(CANDIDATE_CASES,('repository',)))
FIXTURE_SLOTS.update(dict.fromkeys(MEASUREMENT_CASES,('source','workspace')))


def fixture_fixture(case):
    if case not in FIXTURE_SLOTS:
        raise Refused('Git exact additional fixture case')
    value=FIXTURE_MODULES[case.split('::')[0]]
    if value.family=='activation':
        from dataclasses import replace
        value=replace(value,family='evolution' if FIXTURE_SLOTS[case][0].startswith('improve-') else 'workspaces')
    return value


def fixture_root(host,case,repository):
    file=case.split('::')[0]
    source_unit(Path(host.meta['checkout']),file,FIXTURE_PINS[file])
    path=Path(repository)
    if file==MEASUREMENT_TEST and path.name=='workspace':
        return measurement_cold_root(host,path)
    parent,info=acquire(str(path.parent),Path(host.meta['owned']),re.sub(r'[\W]','_',case.split('::')[1])[:30],20000)
    if path.name not in FIXTURE_SLOTS[case] or path.resolve()!=path:
        raise Refused('Git exact additional repository slot')
    generation=(str(parent),info.st_dev,info.st_ino)
    if host.fixture_roots.setdefault(('git-fixture',case),generation)!=generation:
        raise Refused('Git additional pytest generation changed')

FIXTURE_SLOTS[FIXTURE_SERVER_INQUIRY]=('repository',)


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
}
HISTORY_CASES=(*tuple(file+'::'+name for file,names in HISTORY_CATALOG.items() for name in names),HISTORY_CLI,HISTORY_REPOSITORY)
HISTORY_PINS={'tests/test_repository_contract.py':'f6b284b53f2c9f4f307ace30ce17c48fe4c8f33dd9035fcc36ab6edeb0623c44', 'tests/test_release_binding.py': '2db77fb31af6b7e536420a16aaa92fc237404570d0f97df37f374fed788c2d0f', 'tests/test_v021_release_records.py': '7d5f90c969295c019e515133cca6abbb2458882c53b43a7bee3c59ca44a95ee5', 'tests/test_v045_release_records.py': 'be9693d6ad6937f0080f6022d3db602ad8530c0d24f8528b85ebc3ee4c492da4'}


def history_commands(checkout,case):
    file,name=case.split('::')
    source_unit(checkout,file,HISTORY_PINS[file],(name,))
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
    if len(argv)!=7 or raw['stdin'] is not None:
        raise Refused('binding CLI original argument count')
    root=retain(host,Path(argv[4]).parent,HISTORY_CLI.split('::')[1][:30],20000)
    repository=root/'repository'
    if repository.resolve()!=repository or (repository/'.git').resolve()!=repository/'.git':
        raise Refused('binding CLI repository alias')
    previous=[value for value in host.intents.values() if value['case']==HISTORY_CLI]
    ordinal=sum(value['role']=='fixed-inline' for value in previous)
    if ordinal>=2:
        raise Refused('binding CLI original two invocations')
    native,pin=host.binding['entry']['path'],host.binding['entry']['sha256']
    vector=(native,'-B',str(checkout/HISTORY_TOOL),'--repository',str(repository),'--check-manifest',str(root/('active-manifest.json' if ordinal==0 else 'wrong-manifest.json')))
    environment={**host.meta_environment(),'PYTEST_VERSION':'9.0.2','PYTEST_CURRENT_TEST':HISTORY_CLI+' (call)'}
    expected=build_expected(HISTORY_CLI,native,pin,vector,tuple(sorted(environment.items())),str(checkout),'python-script',HISTORY_TOOL_PIN)
    return admit_expected(host,actor,raw,expected,'fixed-inline',[native,'-I','-S',*vector[2:]],HISTORY_TOOL_PIN,maximum=2,
        fields={'fixed_operation':'check','binding_repository':str(repository)})


SITE_CASES = (
    'tests/test_workspaces.py::test_exact_clean_base_scope_and_t1_label_survive_restart',
    'tests/test_workspaces.py::test_two_leases_use_distinct_worktrees_and_scope_escape_fails',
    'tests/test_workspaces.py::test_return_is_identity_bound_append_only_and_parent_is_unchanged',
    'tests/test_workspaces.py::test_disjoint_returns_integrate_in_deterministic_order',
    'tests/test_workspaces.py::test_overlap_stale_and_validation_failure_preserve_parent',
    'tests/test_workspaces.py::test_expiry_orphan_cleanup_and_retry_preserve_evidence',
    'tests/test_workspaces.py::test_child_commit_is_not_parent_authority',
    'tests/test_workspaces.py::test_owned_process_budget_and_restart_cleanup',
    'tests/test_workspaces.py::test_mutated_patch_artifact_and_cleanup_failure_are_retained',
    'tests/test_workspaces.py::test_closed_plan_rejects_nonhuman_and_swapped_mission_proofs',
    'tests/test_workspaces.py::test_integration_transaction_recovers_each_git_boundary[pre_ref]',
    'tests/test_workspaces.py::test_integration_transaction_recovers_each_git_boundary[post_ref]',
    'tests/test_workspaces.py::test_integration_transaction_recovers_each_git_boundary[post_receipt]',
    'tests/test_evolution.py::test_campaign_freeze_is_complete_immutable_and_restartable',
    'tests/test_evolution.py::test_genealogy_retains_failures_retries_and_rejections',
    'tests/test_evolution.py::test_independent_evaluation_review_and_reward_hack_fail_closed',
    'tests/test_evolution.py::test_missing_provider_is_non_improving_and_cannot_promote',
    'tests/test_evolution.py::test_human_promotion_is_exact_atomic_and_idempotent',
    'tests/test_evolution.py::test_post_accept_receipt_failure_reconciles_without_reapply',
    'tests/test_evolution.py::test_exact_human_rollback_and_receipt_recovery',
    'tests/test_evolution.py::test_rollback_transaction_recovers_each_git_boundary[pre_ref]',
    'tests/test_evolution.py::test_rollback_transaction_recovers_each_git_boundary[post_ref]',
    'tests/test_evolution.py::test_rollback_transaction_recovers_each_git_boundary[post_receipt]',
    'tests/test_evolution.py::test_rollback_validation_failure_preserves_current',
)
SITE_WORKSPACE_ONLY=frozenset({'head-tree','stage-advance','commit-advance','stage-child','commit-child'})
SITE_SHARED_OPERATIONS=tuple(sorted(set(COMMAND_OPERATIONS)-SITE_WORKSPACE_ONLY-set(COMMAND_SETUP)))
SITE_OPERATIONS={'workspaces':tuple(sorted(COMMAND_OPERATIONS)),
    'evolution':tuple(sorted(set(COMMAND_OPERATIONS)-SITE_WORKSPACE_ONLY)),
    'candidate':('init','candidate-command'),'measurement':('init','measurement-command',*MEASUREMENT_COLD)}

SITE_OWNED_BODY = 'import time; time.sleep(60)'

SITE_CASES=(*SITE_CASES,*FIXTURE_SLOTS,*HISTORY_CASES)


HOME_CONFIG = b'[maintenance]\n\tauto = false\n[gc]\n\tauto = 0\n'


def regular(file, maximum=4096, uid=20000):
    return read_regular(file,maximum,uid=uid,minimum=1,forbidden=0o6022)[0]


def image(file='/usr/bin/git'):
    target = Path(file)
    if str(target.resolve(strict=True)) != file:
        raise Refused('git native image alias')
    for member in (target, *target.parents):
        info = member.lstat()
        if info.st_uid != 0 or stat.S_IMODE(info.st_mode) & 0o6022:
            raise Refused('git native image custody')
        if member == target:
            if not stat.S_ISREG(info.st_mode) or not info.st_mode & 0o111:
                raise Refused('git native executable')
        elif not stat.S_ISDIR(info.st_mode):
            raise Refused('git native ancestor')
    return native_digest(target)


def issue(host,actor,raw,command,environment,*,role='git-command',maximum=128,fields=None):
    from launch_policy import build_expected,admit_expected
    if raw['executable']!='/usr/bin/git' or raw['stdin']!=command.stdin:
        raise Refused('Git exact executable and input')
    expected=build_expected(host.case,'/usr/bin/git',image(),command.argv,
        tuple(sorted(environment.items())),command.cwd,'native')
    vector=['/usr/bin/git',*command.argv[1:]]
    answer=admit_expected(host,actor,raw,expected,role,vector,maximum=maximum,fields=fields)
    if answer is not None and fields is not None:
        host.git.commands[answer['token']]=host.intents[answer['ticket']]
    return answer


class Git:
    def __init__(self, observer):
        self.host = observer
        self.repositories, self.commands = {}, {}
        self.helpers = {}
        self.custody_roots = {}

    def repository(self, repository, operation, family):
        root = Path(repository)
        owned = Path(self.host.meta['owned'])
        fixture=fixture_fixture(self.host.case) if self.host.case in FIXTURE_SLOTS else None
        if fixture is not None:
            fixture_root(self.host,self.host.case,repository)
        if (((root.name != 'project' or root.parent.parent != owned / 'pytest') if fixture is None else root.name not in FIXTURE_SLOTS[self.host.case])
                or str(root.resolve(strict=True)) != repository):
            raise Refused('git original repository location')
        identities = []
        for directory in (root.parent, root):
            info = directory.lstat()
            if not stat.S_ISDIR(info.st_mode) or info.st_uid != 20000 or stat.S_IMODE(info.st_mode) & 0o6022:
                raise Refused('git repository custody')
            identities.append((info.st_dev, info.st_ino, info.st_uid))
        key=(self.host.case,repository)
        slot = self.repositories.get(key)
        if slot is None:
            if operation != 'init' or (root / '.git').exists():
                raise Refused('git first original fixture operation')
            slot = {'path': repository, 'identities': identities}
            self.repositories[key] = slot
        if slot['path'] != repository or slot['identities'] != identities:
            raise Refused('git repository generation')
        metadata=root/'.git'
        if not metadata.exists() and not metadata.is_symlink():
            if operation!='init':
                raise Refused('git declared metadata missing')
        else:
            info=metadata.lstat()
            if (not stat.S_ISDIR(info.st_mode) or metadata.resolve(strict=True)!=metadata
                    or info.st_uid!=20000 or info.st_mode&0o6022):
                raise Refused('git declared metadata directory')
        return root

    def location(self, root, location):
        path = Path(location)
        command_location_role(root, path)
        if not path.is_dir() or str(path.resolve(strict=True)) != location:
            raise Refused('git original worktree directory')

    def launch(self, actor, operation, repository, command, raw, environment):
        host = self.host
        host.root_only(actor)
        if host.case not in SITE_CASES:
            raise Refused('Git finite case')
        family=fixture_fixture(host.case).family if host.case in FIXTURE_SLOTS else 'workspaces' if host.case.startswith('tests/test_workspaces.py::') else 'evolution'
        if operation not in SITE_OPERATIONS[family]:
            raise Refused('Git finite operation declaration')
        root = self.repository(repository, operation, family)
        self.location(root, command.cwd)
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
        if list(siblings) != [birth]:
            raise Refused('git single current checkout helper')
        tree = intent['command'].argv[-2]
        root, worktree = Path(intent['repository']), Path(tree)
        self.location(root, tree)
        executable = '/usr/lib/git-core/git'
        pin=intent['executable_sha256']
        if image(executable) != pin:
            raise Refused('git helper exact native image')
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


    def owned_launch(self, actor, repository, expected, vector):
        host = self.host
        if host.case != SITE_CASES[7] or self.repositories.get((host.case,repository), {}).get('path') != repository:
            raise Refused('workspace owned launch scope')
        cwd = repository + '/.unrest-runtime/workspaces/trees/process'
        self.location(Path(repository), cwd)
        return host.admit_launch(actor,expected,'workspace-owned',vector,expected.payload_sha256)


def workspace_prepare(host,actor,raw):
    case=host.case
    if case in MEASUREMENT_CASES:
        return measurement_proposal(host,actor,raw)
    if case in HISTORY_CASES:
        return history_proposal(host,actor,raw)
    if case in CANDIDATE_CASES:
        return candidate_proposal(host,actor,raw)
    if case not in SITE_CASES:
        raise Refused('Git proposal undeclared case')
    fixture=fixture_fixture(case) if case in FIXTURE_SLOTS else None
    family=fixture.family if fixture is not None else 'workspaces' if case.startswith('tests/test_workspaces.py::') else 'evolution'
    choices=[slot for (current,repo),slot in host.git.repositories.items() if current==case
             and (raw['cwd']==repo or raw['cwd'].startswith(repo+'/.unrest-runtime/'))]
    if len(choices)>1:
        raise Refused('Git unique repository slot')
    slot=choices[0] if choices else None
    repository=slot['path'] if slot is not None else raw['cwd']
    native,pin=host.binding['entry']['path'],host.binding['entry']['sha256']
    owned=raw['argv']==[native,'-c',SITE_OWNED_BODY]
    if owned:
        if case!=SITE_CASES[7] or slot is None or raw['stdin'] is not None or raw['cwd']!=repository+'/.unrest-runtime/workspaces/trees/process':
            raise Refused('Git proposal owned process scope')
        operation,command='owned-process',None
        expected=build_expected(
            case,
            native, pin,
            tuple(raw['argv']),
            tuple(sorted({**host.meta_environment(),'PYTEST_VERSION':'9.0.2','PYTEST_CURRENT_TEST':case+' (call)'}.items())),
            raw['cwd'], 'python-command',
        )
        vector=[native,'-I','-S','-c',SITE_OWNED_BODY]
        host.root_only(actor)
        if raw['environment']!=dict(expected.environment):
            raise Refused('Git owned process environment differs')
        answer=host.git.owned_launch(actor,repository,expected,vector)
        return None if answer is None else {**answer,'translated':vector}

    else:
        if raw['executable']!='/usr/bin/git':
            raise Refused('Git proposal original executable')
        operations=(*COMMAND_SETUP,*SITE_SHARED_OPERATIONS) if fixture is not None else SITE_OPERATIONS[family]
        branch='master' if fixture is not None and fixture.init==('init',) and raw['argv'][1:3]==['update-ref','refs/heads/master'] else 'main'
        operations=tuple(dict.fromkeys({'rollback-update':'update-parent','rollback-reset':'reset-parent'}.get(operation,operation) for operation in operations))
        candidates: dict[str,Command] = {}
        for operation in operations:
            try:
                command=command_match(operation,repository,raw['cwd'],raw['argv'],raw['stdin'],raw['environment'],family=family,fixture=fixture,branch=branch)
            except Refused:
                continue
            candidates[operation]=command
        if len(candidates)!=1:
            raise Refused('Git proposal requires one finite operation')
        operation,command=next(iter(candidates.items()))
        phase=(fixture.phase if fixture is not None else 'setup') if operation in COMMAND_SETUP else 'call'
        environment={**host.meta_environment(),'PYTEST_VERSION':'9.0.2','PYTEST_CURRENT_TEST':case+' ('+phase+')',**dict(command.additions)}
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
    if type(case) is not str or case not in (*CONTROLLED_CASES,*COHORT_CASES) or type(argv) is not tuple or any(type(v) is not str for v in argv):
        raise Refused('custody Git finite command primitives')
    if type(cwd) is not str or str(Path(cwd).resolve()) != cwd or not Path(cwd).is_relative_to(owned/'pytest'):
        raise Refused('custody Git owned repository')
    if argv[:len(CUSTODY_PREFIX)] != CUSTODY_PREFIX:
        raise Refused('custody Git literal executable and prefix')
    args = argv[len(CUSTODY_PREFIX):]
    if args not in (*CUSTODY_FIXED,*COHORT_EXTRA.get(case,())):
        if args[:2] == ('add','--'):
            if args[2:] not in (('a',),('b',),('lane_a.txt',),('lane_b.txt',)):
                raise Refused('custody Git exact authored scope')
        elif len(args) == 4 and args[:3] == ('diff','--cached','--name-only'):
            operand_digest(args[3])
        else:
            raise Refused('custody Git undeclared template')
    kind = 'head' if args == ('rev-parse','HEAD') else 'commit' if args[0] == 'commit' else 'other'
    return Command(argv,cwd),kind


def custody_repository(cwd, owned, *, initialize):
    root = Path(cwd)
    if str(root.resolve(strict=True)) != cwd or not root.is_relative_to(owned/'pytest'):
        raise Refused('custody Git repository alias')
    identities = []
    base = owned/'pytest'
    for path in (root,*(parent for parent in root.parents if parent.is_relative_to(base))):
        info = path.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != 20000 or info.st_mode & 0o6022:
            raise Refused('custody Git directory custody')
        identities.append((str(path),info.st_dev,info.st_ino,info.st_uid))
    metadata = root/'.git'
    if initialize:
        if metadata.exists() or metadata.is_symlink():
            raise Refused('custody Git repeated initialization')
        return tuple(identities),None
    info = metadata.lstat()
    if (not stat.S_ISDIR(info.st_mode) or metadata.resolve(strict=True) != metadata
            or info.st_uid != 20000 or info.st_mode & 0o6022):
        raise Refused('custody Git metadata generation')
    metadata_identity = info.st_dev,info.st_ino,info.st_uid
    return tuple(identities),metadata_identity


def custody_launch(host,actor,result,kind,raw):
    from cohort_controller import parent
    parent(host,actor)
    prior = [v for v in host.intents.values() if v['case'] == host.case and v['role'] == 'git-custody']
    from cohort_controller import CASES as CRASH
    maximum=4 if host.case in CRASH else COHORT_CASES[host.case][1] if host.case in COHORT_CASES else 12+8*pair_limits(host.case)[0]
    if len(prior) >= maximum:
        raise Refused('custody Git finite case command bound')
    identity = custody_repository(result.cwd,Path(host.meta['owned']),initialize=result.argv[len(CUSTODY_PREFIX)] == 'init')
    key = host.case,result.cwd
    previous = host.git.custody_roots.get(key)
    if previous is not None and (previous[0] != identity[0] or previous[1] is not None and previous[1] != identity[1]):
        raise Refused('custody Git replaced repository generation')
    host.git.custody_roots[key] = identity
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
    if observed!=expected:
        raise Refused('Git environment outside closed application metadata')
    return expected


def completion_ready(host,workspace):
    identity=custody_repository(str(workspace),Path(host.meta['owned']),initialize=False)
    if host.fixture_roots.get(('completion-git-root',host.case))!=identity:
        raise Refused('completion fixture repository generation changed')


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
            identity=custody_repository(str(workspace),Path(host.meta['owned']),initialize=not records)
            key=('completion-git-root',case)
            previous=host.fixture_roots.setdefault(key,identity)
            if previous[0]!=identity[0] or previous[1] is not None and previous[1]!=identity[1]:
                raise Refused('completion fixture repository generation')
            host.fixture_roots[key]=identity
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
            server=actor_slot(host,actor)
            quota=role_schedule(case)[server['server_slot']][2]
        if len(records)>=quota:
            raise Refused('completion server-owned Git query quota')
        completion_ready(host,workspace)
        is_fixture=False
        vector=('git','rev-parse','HEAD')
        command=Command(vector,str(workspace))
        environment=dict(actor['profile']['environment'])
    return issue(host,actor,raw,command,environment,
        maximum=len(commands)+ROOT_QUERIES.get(case,0)+(composed_queries(case) if case in COMPOSED_CASES else sum(row[2] for row in role_schedule(case))),
        fields={'command':command,'repository':str(workspace),'operation':'completion-fixture' if is_fixture else 'completion-head',
            'fixture_git':is_fixture})
