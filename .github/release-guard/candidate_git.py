"""Exact candidate-fixture consumers and additional authored mutations."""
from pathlib import Path
import ast

from content_manifest import Refused
from launch_policy import source_unit
from git_commands import Command
from git_operands import digest

TEST='tests/test_experimental_candidate.py'
PIN='6827bd92719ed7e138980b9e4dc3d9e6fdc775444093609fe78c0e806981c39e'
CONSUMERS={
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
CASES=tuple(TEST+'::'+name+('['+parameter+']' if parameter is not None else '') for name,parameters in CONSUMERS.items() for parameter in parameters)


def declarations(checkout,case,repository):
    if case not in CASES:
        raise Refused('candidate exact fixture consumer')
    unit=source_unit(checkout,TEST,PIN,('repo',))
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


def command(checkout,case,repository,ordinal,argv):
    setup,extras=declarations(checkout,case,repository)
    rows=(*setup,*extras)
    if not 0<=ordinal<len(rows) or not argv or argv[0]!='/usr/bin/git':
        raise Refused('candidate fixture finite command ordinal')
    expected=list(rows[ordinal])
    actual=argv[1:]
    if None in expected:
        index=expected.index(None)
        if len(actual)!=len(expected):
            raise Refused('candidate object operand shape')
        digest(actual[index])
        expected[index]=actual[index]
    if expected[-1].endswith(',OID,unsupported'):
        if len(actual)!=len(expected):
            raise Refused('candidate cache entry operand shape')
        parts=actual[-1].split(',')
        if len(parts)!=3 or (parts[0],parts[2])!=(expected[-1].split(',')[0],'unsupported'):
            raise Refused('candidate cache entry scope')
        digest(parts[1])
        expected[-1]=actual[-1]
    if actual!=expected:
        raise Refused('candidate original complete command')
    environment={'PATH':'/usr/bin:/bin','HOME':repository,'LC_ALL':'C',
        'GIT_CONFIG_NOSYSTEM':'1','GIT_CONFIG_GLOBAL':'/dev/null',
        'GIT_CONFIG_COUNT':'1','GIT_CONFIG_KEY_0':'maintenance.auto','GIT_CONFIG_VALUE_0':'false',
        'GIT_AUTHOR_DATE':'2000-01-01T00:00:00+0000','GIT_COMMITTER_DATE':'2000-01-01T00:00:00+0000'}
    return Command(tuple(argv),repository),environment


def proposal(host,actor,raw):
    records=[row for row in host.intents.values() if row['case']==host.case and row['role']=='git-command']
    repository=raw['cwd']
    value,environment=command(Path(host.meta['checkout']),host.case,repository,len(records),raw['argv'])
    if raw['executable']!='/usr/bin/git' or raw['stdin'] is not None or raw['environment']!=environment:
        raise Refused('candidate fixture exact executable environment or input')
    from git_observer import image
    from launch_policy import build_expected
    expected=build_expected(host.case,'/usr/bin/git',image(),value.argv,
        tuple(sorted(environment.items())),repository,'native')
    answer=host.git.launch(actor,'init' if not records else 'candidate-command',repository,value,expected,list(value.argv))
    return None if answer is None else {**answer,'translated':list(value.argv)}
