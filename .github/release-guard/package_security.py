"""Original copied/installed credential-choice negatives and supported init leaves."""
import ast
import os
from pathlib import Path

from content_manifest import Refused
from launch_policy import source_unit,assignment,admit_expected,build_expected
from owned_fixture import acquire

TEST='tests/contracts/test_lean_provider_security.py'
MATRIX=TEST+'::test_copied_source_and_installed_cli_protect_precommand_credentials'
CASES=(MATRIX,*(TEST+'::test_installed_supported_provider_matrix['+provider+']' for provider in ('claude','codex')))
PIN='af9d5961cf95854acfd21621ab89db1f63e1a3e0e3aec4c32ee624e2ff2789e9'
OPTIONS=('--agent','--orchestrator-provider','--worker-provider','--validator-provider','--terminal-reviewer-provider',
    '--worker-reasoning-effort','--validator-reasoning-effort','--terminal-reviewer-reasoning-effort','--scope')
SENTINEL='known-installed-choice-sentinel-8a17'

REFERENCES=(
    'tests/test_acp_runner.py::test_terminal_review_timeout_cleans_acp_and_mcp_children',
    'tests/test_capability_policy.py::test_ambient_credential_inventory_is_provider_neutral_and_deterministic[0]',
    'tests/test_capability_policy.py::test_codex_structured_config_drops_exact_aliases_and_preserves_config',
    'tests/test_capability_policy.py::test_credential_redaction_is_boundary_aware_and_deterministic',
    'tests/test_capability_policy.py::test_cyclic_containers_have_stable_value_free_boundary_diagnostics',
    'tests/test_capability_policy.py::test_filesystem_callbacks_enforce_absolute_traversal_symlink_and_read_only',
    'tests/test_capability_policy.py::test_only_explicit_unsafe_profile_emits_unrestricted_provider_settings',
    'tests/test_capability_policy.py::test_progress_redaction_spans_chunks_callbacks_and_message_ids',
    'tests/test_capability_policy.py::test_raw_acp_terminal_protocol_redacts_credential_values',
    'tests/test_capability_policy.py::test_role_environment_is_minimal_deterministic_and_credential_named',
    'tests/test_capability_policy.py::test_safe_codex_subprocess_settings_override_ambient_unrestricted',
    'tests/test_capability_policy.py::test_terminal_callbacks_enforce_process_cwd_and_environment',
    'tests/test_capability_policy.py::test_unsupported_profile_has_stable_provider_role_version_error',
    'tests/test_lean_provider_security_runtime.py::test_supported_provider_set_is_claude_and_codex_only',
    'tests/test_server.py::test_redacted_mcp_handoffs_survive_restart_and_mirroring',
)

REFERENCE_CASES=tuple(node+suffix for node in REFERENCES for suffix in (('[list]','[mapping]')
    if node.endswith('test_cyclic_containers_have_stable_value_free_boundary_diagnostics') else
    ('[unknown]','[safe-ish]') if node.endswith('test_unsupported_profile_has_stable_provider_role_version_error') else ('',)))


def matrix_program(checkout,bootstrap,trap):
    node=assignment(source_unit(checkout,TEST,PIN,('_run_cli_matrix',)),'script')
    def render(node):
        if isinstance(node,ast.Constant) and type(node.value) is str:
            return node.value
        if isinstance(node,ast.Name) and node.id=='bootstrap':
            return bootstrap
        if isinstance(node,ast.BinOp) and isinstance(node.op,ast.Add):
            return render(node.left)+render(node.right)
        if isinstance(node,ast.JoinedStr):
            result=[]
            for part in node.values:
                if isinstance(part,ast.Constant) and type(part.value) is str:
                    result.append(part.value)
                elif (isinstance(part,ast.FormattedValue) and ast.unparse(part.value)=='str(trap)'
                        and part.conversion==114 and part.format_spec is None):
                    result.append(repr(str(trap)))
                else:
                    raise Refused('credential matrix closed trap substitution')
            return ''.join(result)
        raise Refused('credential matrix original concatenation')
    return render(node)


def completed(host,row):
    if not row['consumed']:
        return False
    actor=host.actors[row['pid']]
    terminal=host.ledger.process(actor['birth']).terminal
    return terminal is not None and terminal[2]==row['security_status'] and actor['body_ready'] and host.ledger.reaped(actor['birth'],actor['token'])


def provenance(host):
    key='<installed-provenance>'
    row=host.fixture_roots.get(key)
    if row is None or not completed(host,row):
        raise Refused('installed fixture needs actual provenance exit and parent wait')
    return row


def proposal(host,actor,raw):
    from archive_snapshot import acquire as acquire_snapshot,retained
    from package_proposals import inputs,owned,environment
    from package_cases import literal
    host.root_only(actor)
    case=host.case
    if case not in CASES or raw['stdin'] is not None:
        raise Refused('credential package exact leaf')
    checkout,owned_root=Path(host.meta['checkout']),Path(host.meta['owned'])
    source_unit(checkout,TEST,PIN)
    data=inputs(host)
    native,pin=host.binding['entry']['path'],host.binding['entry']['sha256']
    records=[row for row in host.intents.values() if row['case']==case]
    if any(not completed(host,row) for row in records):
        raise Refused('credential matrix previous original parent wait')
    workspace=Path(raw['cwd'])
    fixture=host.fixture_roots.get('<installed-workspace>')
    if fixture is None:
        if case!=MATRIX or records:
            raise Refused('credential exact first fixture consumer')
        identity=owned(workspace,owned_root,'candidate-distribution')
        code=literal(checkout,'tests/contracts/conftest.py',None,'PROVENANCE_BODY')
        env=environment(host,case,'setup')
        env.pop('PYTHONPATH',None)
        env.setdefault('UV_CACHE_DIR','/tmp/unrest-worker-uv-cache')
        env.setdefault('UV_OFFLINE','1')
        vector=(native,'-S','-c',code,str(data['installed_site']),str(data['dependency_site']))
        value=build_expected('package:provenance',case,native,pin,vector,tuple(sorted(env.items())),str(workspace),'python-command')
        answer=admit_expected(host,actor,raw,value,'archive-installed',[native,'-I','-S',*vector[2:]],
            maximum=21,fields={'security_status':0,'security_operation':'provenance'})
        if answer is not None:
            host.fixture_roots['<installed-workspace>']=[str(workspace),identity]
            host.fixture_roots['<installed-provenance>']=host.intents[answer['ticket']]
        return answer
    provenance(host)
    if fixture!=[fixture[0],owned(Path(fixture[0]),owned_root,'candidate-distribution')]:
        raise Refused('credential retained installed workspace generation')
    phase=[row for row in records if row.get('security_operation')!='provenance']
    limit=20 if case==MATRIX else 1
    if len(phase)>=limit:
        raise Refused('credential package exact original count')
    env=environment(host,case,'call')
    env={key:value for key,value in env.items() if not any(marker in key.upper() for marker in ('API_KEY','TOKEN','PASSWORD','CREDENTIAL'))}
    env.pop('PYTHONPATH',None)
    env.pop('CODEX_PATH',None)
    sealed=None
    if case==MATRIX:
        index=len(phase)
        copied=index<10
        if copied:
            parent,info=acquire(str(workspace.parent),owned_root,case.split('::')[-1][:30],20000)
            if workspace!=parent/'copied-candidate' or workspace.resolve()!=workspace:
                raise Refused('credential original copied workspace')
            current=workspace.stat()
            if current.st_uid!=20000 or current.st_mode&0o6022:
                raise Refused('credential copied workspace custody')
            generation=(str(parent),info.st_dev,info.st_ino,current.st_dev,current.st_ino)
            if host.fixture_roots.setdefault(('credential-root',case),generation)!=generation:
                raise Refused('credential copied root changed')
            key=('credential-copy',case)
            if key not in host.fixture_roots:
                target=host.directory/('credential-copy-'+os.urandom(16).hex())
                host.fixture_roots[key]=(str(target),acquire_snapshot(workspace/'src',checkout/'src',target,'normal'))
            sealed=host.fixture_roots[key]
            retained(Path(sealed[0]),sealed[1])
            selected=workspace/'src'
        else:
            workspace=Path(fixture[0])
            selected=data['installed_site']
        bootstrap=f'import sys; sys.path[:0]=[{str(selected)!r}, {str(data["dependency_site"])!r}]; '
        code=matrix_program(checkout,bootstrap,workspace/'precommand-callback-trap')
        translated_code=matrix_program(checkout,f'import sys; sys.path[:0]=[{sealed[0]!r}, {str(data["dependency_site"])!r}]; ',workspace/'precommand-callback-trap') if copied else code
        ordinal=index%10
        option=OPTIONS[ordinal] if ordinal<9 else '--worker-provider'
        operand=SENTINEL if ordinal<9 else 'ordinary-unsupported-provider'
        if ordinal<9:
            env['OPENAI_API_KEY']=SENTINEL
        tail=('init',option,operand)
        status=2
    else:
        source_unit(checkout,TEST,PIN,('test_installed_supported_provider_matrix',))
        provider=case.rsplit('[',1)[1][:-1]
        target=Path(raw['argv'][-1])
        parent,_=acquire(str(target.parent),owned_root,case.split('::')[-1].split('[')[0][:30],20000)
        if target!=parent/provider or target.resolve()!=target:
            raise Refused('credential supported provider original workspace')
        env['UNREST_HOME']=str(parent/(provider+'-home'))
        code=f'import sys; sys.path[:0]=[{str(data["installed_site"])!r}, {str(data["dependency_site"])!r}]; from unrest_harness.cli import cli; cli.main()'
        translated_code=code
        workspace=Path(fixture[0])
        tail=('init','--agent',provider,'--workspace-dir',str(target))
        status=0
    vector=(native,'-S','-c',code,*tail)
    value=build_expected('package:credential',case,native,pin,vector,tuple(sorted(env.items())),str(workspace),'python-command')
    return admit_expected(host,actor,raw,value,'archive-installed',[native,'-I','-S','-c',translated_code,*tail],
        maximum=limit+1,fields={'security_status':status,'security_operation':'matrix' if case==MATRIX else 'provider',
            'credential_snapshot':sealed,'merged_output':True})


def count(host):
    case=host.case
    provenance(host)
    return (20 if case==MATRIX else 1)+int(any(row['case']==case and row.get('security_operation')=='provenance' for row in host.intents.values()))
