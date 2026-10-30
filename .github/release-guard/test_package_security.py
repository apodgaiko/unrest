"""Pinned original matrix parity and provenance readiness; no execution claim."""
import ast
from pathlib import Path
from types import SimpleNamespace

import pytest

from content_manifest import Refused
from launch_policy import source_unit
import package_security as security

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

ROOT=next(p for p in Path(__file__).resolve().parents if (p/'pyproject.toml').is_file())


def test_focused_security_selection_retains_every_crosswalk_reference():
    unit=source_unit(ROOT,security.TEST,security.PIN,())
    rows=ast.literal_eval(next(node.value for node in unit.body if isinstance(node,ast.Assign)
        and any(isinstance(target,ast.Name) and target.id=='SCENARIOS' for target in node.targets)))
    references=tuple(sorted({row[2] for row in rows if not row[2].startswith('local::')}))
    assert REFERENCES==references
    assert len(REFERENCE_CASES)==17


def test_security_parent_selectors_collect_all_original_parameters(monkeypatch):
    monkeypatch.setenv('PYTEST_DISABLE_PLUGIN_AUTOLOAD','1')
    nodes=[]
    class Collected:
        def pytest_collection_finish(self,session):
            nodes.extend(item.nodeid for item in session.items)
    code=pytest.main(['--collect-only','-q',*REFERENCES,*security.CASES],plugins=[Collected()])
    assert code==0 and tuple(nodes)==(*REFERENCE_CASES,*security.CASES)


def test_matrix_builder_matches_every_original_operand_without_executing_a_child(tmp_path):
    unit=source_unit(ROOT,security.TEST,security.PIN,('_run_cli_matrix',))
    captured=[]
    def run(argv,**kwargs):
        captured.append((argv,kwargs))
        output=('<redacted:OPENAI_API_KEY> is not one of' if 'OPENAI_API_KEY' in kwargs['env'] else
                'ordinary-unsupported-provider claude codex')
        return SimpleNamespace(returncode=2,stdout=output)
    namespace={'Path':Path,'subprocess':SimpleNamespace(run=run,PIPE=-1,STDOUT=-2)}
    exec(compile(ast.Module(body=[unit],type_ignores=[]),security.TEST,'exec'),namespace)
    cwd=tmp_path/'quoted\'s-copy'
    cwd.mkdir()
    bootstrap=f'import sys; sys.path[:0]=[{str(cwd/"src")!r}, "/dependencies"]; '
    namespace['_run_cli_matrix'](python=Path('/native'),bootstrap=bootstrap,cwd=cwd,environment={'PATH':'/bin'})
    assert len(captured)==10
    for index,(argv,kwargs) in enumerate(captured):
        assert argv[:4]==['/native','-S','-c',security.matrix_program(ROOT,bootstrap,cwd/'precommand-callback-trap')]
        assert argv[4:]==['init',security.OPTIONS[index] if index<9 else '--worker-provider',
            security.SENTINEL if index<9 else 'ordinary-unsupported-provider']
        assert kwargs['cwd']==cwd and kwargs['timeout']==30
        assert ('OPENAI_API_KEY' in kwargs['env'])==(index<9)


@pytest.mark.parametrize('mutation',['missing','not-consumed','no-terminal','body','wrong-status','not-waited',None])
def test_pending_fixture_binding_never_counts_as_completed_provenance(mutation):
    row={'consumed':mutation!='not-consumed','pid':2,'security_status':0}
    actor={'birth':object(),'token':'bound','body_ready':mutation!='body'}
    terminal=None if mutation=='no-terminal' else (4,0,1 if mutation=='wrong-status' else 0)
    host=SimpleNamespace(fixture_roots={} if mutation=='missing' else {'<installed-provenance>':row},actors={2:actor},
        ledger=SimpleNamespace(process=lambda birth:SimpleNamespace(terminal=terminal),
            reaped=lambda birth,token:mutation!='not-waited'))
    if mutation is None:
        assert security.provenance(host) is row
    else:
        with pytest.raises(Refused,match='actual provenance'):
            security.provenance(host)
