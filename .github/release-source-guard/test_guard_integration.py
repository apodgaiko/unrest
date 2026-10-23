"""Composition controls; Linux ownership/transport proof remains separate."""
from __future__ import annotations

import ast
import copy
import hashlib
import json
from pathlib import Path

import pytest

import phase_catalog
from test_own_constructor import (  # noqa: F401
    test_previous_callback_failure_precedes_own_effect_and_restores_exact_profile,
    test_restoration_attempts_profile_after_independent_os_errors,
    test_owned_directory_is_restored_removed_without_touching_source,
    test_changed_directory_identity_is_not_chmodded_or_removed,
    test_existing_negative_capsule_cannot_be_invoked_with_unknown_mode,
    test_current_native_gate_chains_original_arguments_and_restores_after_error,
)
# The existing host selection runs these new guard-only controls on Linux too.
from test_source_lease_integration import (  # noqa: F401
    test_lease_postinit_requires_complete_original_binding,
    test_lease_postinit_mutations_never_get_locale_exemption,
    test_original_empty_exec_environment_and_flags_are_exact,
    test_real_controlled_factory_frames_recheck_identity,
    test_shared_original_helper_declines_only_other_owner,
    test_source_temporary_environment_keeps_exact_generation,
    test_shared_route_order_uses_real_helper_and_own_probe_identity,
    test_exact_existing_controlled_fixture_mapping_stays_bound,
    test_extension_keeps_original_callback_for_nonlease,
    test_new_probe_reducer_requires_refused_child_and_all_lease_modes,
    test_legacy_registry_literal_keeps_its_original_source_anchor,
    test_original_registry_case_is_never_replaced_by_extension_admission,
    test_original_captured_popen_callsite_is_not_injected_raise,
    test_same_captured_popen_boundary_checks_live_own_frame,
)

from test_execution_owner import (  # noqa: F401
    test_real_own_identity_requires_complete_nested_context,
    test_original_nested_inventory_joins_immutable_source_AST_only,
    test_nested_reduction_requires_both_actual_child_joins,
    test_shared_physical_sites_use_exact_original_owner_sets,
)

from test_source_root import (  # noqa: F401
    test_complete_source_bind_and_finite_artifacts,
    test_inspected_container_drift_refuses,
    test_host_snapshot_drift_refuses,
    test_mountpoint_must_be_empty_and_real,
    test_probe_requires_actual_linux_source_identity,
    test_producer_canary_no_longer_claims_writable_root,
    test_own_proof_uses_unchanged_closed_transport,
    test_output_export_rejects_mount_generation_substitution,
    test_empty_dist_refuses_foreign_mount_or_owner,
)

from test_child_relative import (  # noqa: F401
    test_closed_applicable_inventory_includes_ordinary_routes,
    test_install_never_accepts_a_direct_caller,
    test_stopped_child_binding_refuses_before_receipt,
    test_no_constructor_record_retains_original_custody,
    test_prebody_extension_precedes_bootstrap_ready,
    test_stock_constructor_has_no_retry_or_private_execute_child_copy,
)

from test_source_custody import (  # noqa: F401
    test_custody_preparer_is_owned_before_launch,
    test_custody_setup_loader_needs_no_module_registration,
    test_custody_parent_delete_substitution_retains_new_object,
    test_custody_partial_chown_retries_only_known_owners,
    test_custody_unexpected_mount_absence_retains_ownership,
    test_custody_acquisition_fault_retains_retry,
    test_custody_cleanup_fault_retains_retry,
    test_custody_mount_query_error_retains_seal,
    test_custody_documented_absence_and_post_unmount_retry,
    test_custody_substitution_never_deletes_replacement,
    test_custody_parent_delete_failure_after_complete_tree,
    test_custody_partial_delete_detects_other_member_mutation,
    test_custody_dual_error_keeps_initiating_and_cleanup,
    test_custody_capsule_failure_prevents_unsealing,
    test_custody_release_proof_records_actual_disappearance,
)
from test_source_custody import custody  # noqa: F401

import release_source_inputs

ROOT = Path(__file__).resolve().parents[2]


def test_catalog_covers_every_command_and_every_encrypted_phase():
    workflow = (ROOT / '.github/workflows/ci.yml').read_text()
    phase_catalog.require_retention(workflow)
    phases = phase_catalog.catalog()
    assert {name: phase.command for name, phase in phases.items()} == json.loads(
        phase_catalog.REGISTRY.read_bytes())
    members = phase_catalog.retained_members()
    assert len(members) == len(set(members))
    for phase in phases.values():
        assert set(phase.encrypted_members) <= set(members)
    assert set(phase_catalog.ORDER) <= phases.keys()


@pytest.mark.parametrize('mutation', ['source', 'package', 'preparation', 'condition'])
def test_upload_drift_fails_before_execution(mutation):
    workflow = (ROOT / '.github/workflows/ci.yml').read_text()
    if mutation == 'condition':
        workflow = workflow.replace('        if: always()\n', '        if: success()\n')
    else:
        path = {'source': 'primary-source', 'package': 'primary-package-build',
                'preparation': 'primary-preparation'}[mutation]
        workflow = workflow.replace('            ${{ runner.temp }}/' + path + '/evidence.cms\n', '')
    with pytest.raises(RuntimeError):
        phase_catalog.require_retention(workflow)


def test_exact_version_transition_keeps_historical_template_and_core():
    template = json.loads((ROOT / '.github/release-source-guard/finite/source-template.json').read_bytes())
    original = copy.deepcopy(template)
    release_source_inputs.admit(template, ROOT, lambda root, name: (root / name).read_bytes())
    untouched = [row for row in template['anchor_inventory'] if row['path'] not in {'tests/test_acp_cleanup.py', 'tests/test_v045_release_records.py'}]
    assert untouched == [row for row in original['anchor_inventory'] if row['path'] not in {'tests/test_acp_cleanup.py', 'tests/test_v045_release_records.py'}]
    changed = [row for row in template['anchor_inventory'] if row['path'] == 'tests/test_acp_cleanup.py']
    expected = copy.deepcopy(release_source_inputs.CLEANUP_ANCHORS)
    for row in expected:
        row['source_sha256'] = release_source_inputs.POST['tests/test_acp_cleanup.py']
        if row['line'] == 124:
            row['expression_ast_sha256'] = release_source_inputs.CLEANUP_COMMIT_AST
    assert changed == expected and len(changed) == 5
    assert set(name for name, pin in template['product_pins'].items()
               if pin != original['product_pins'][name]) == set(release_source_inputs.POST)
    assert template['product_pins'] | release_source_inputs.PRE == original['product_pins']
    for name, pin in {
        'finite/runtime_guard.py': '68abd1e8ca8b2fed37a2fd2298dc39c1e8d822fa3c4065ceb53bc6a54e0684eb',
        'primary_source_authority.py': 'ac7de9fabf159b37517a8acfba9eea9b3d903750c05f8509e8b80627b8371abc',
    }.items():
        body = (ROOT / '.github/release-source-guard' / name).read_bytes()
        if name == 'finite/runtime_guard.py':
            delta = b'                "canonical-backend",\n                "source-canonical-stdlib-backend",\n'
            assert body.count(delta) == 1
            body = body.replace(delta, b'                "canonical-backend",\n', 1)
        assert hashlib.sha256(body).hexdigest() == pin


@pytest.mark.parametrize('mutation', ['preimage', 'postimage'])
def test_version_transition_never_adopts_observed_drift(mutation):
    template = json.loads((ROOT / '.github/release-source-guard/finite/source-template.json').read_bytes())
    if mutation == 'preimage':
        template['product_pins']['pyproject.toml'] = '0' * 64
    def read(root, name):
        body = (root / name).read_bytes()
        return body + b'foreign' if mutation == 'postimage' and name == 'pyproject.toml' else body
    with pytest.raises(RuntimeError):
        release_source_inputs.admit(template, ROOT, read)


@pytest.mark.parametrize('suffix', ['01', '06', '00', '07', '1', '01-extra', ''])
@pytest.mark.parametrize('workflow', ['CI', 'v0.4.6 source guard readiness', 'foreign'])
def test_preflight_context_is_finite_and_does_not_admit_historical_methods(monkeypatch, suffix, workflow):
    import preflight_policy
    from structured_evidence import EvidenceRefused
    monkeypatch.setenv('GITHUB_EVENT_NAME', 'push')
    monkeypatch.setenv('GITHUB_WORKFLOW', workflow)
    monkeypatch.setenv('GITHUB_REF', 'refs/heads/codex/release-v047-preflight-20261019-' + suffix)
    if workflow == 'CI' and suffix in {'01', '06'}:
        preflight_policy.context()
    else:
        with pytest.raises(EvidenceRefused):
            preflight_policy.context()


def test_acquired_preparation_failure_is_encrypted_without_adopting_stale_root(tmp_path, monkeypatch):
    import ci_shell
    from structured_evidence import canonical
    from preparation_retention import acquire
    root = acquire(tmp_path, 'primary-import')
    raw = root / 'raw'
    monkeypatch.setattr('preparation_retention.execution_identity', lambda *args: {'head_sha': 'a' * 40})
    marker = b'private preparation diagnostic'
    (raw / 'coordinator.log').write_bytes(marker)
    monkeypatch.setattr(ci_shell, 'ACTIVE_ROOT', root)
    monkeypatch.setattr(ci_shell, 'STAGE', 'image')
    def fail():
        raise RuntimeError('controlled preparation failure')
    monkeypatch.setattr(ci_shell, 'main', fail)
    assert ci_shell.retained_main() == 125
    metadata = json.loads((root / 'safe-provenance.json').read_bytes())
    assert metadata['stage'] == 'image' and metadata['exit_code'] == 125
    assert metadata['ciphertext_sha256'] == hashlib.sha256((root / 'evidence.cms').read_bytes()).hexdigest()
    assert marker not in canonical(metadata) and marker not in (root / 'evidence.cms').read_bytes()
    assert not raw.exists() and not (root / 'raw.tar.gz').exists()
    original = (root / 'evidence.cms').read_bytes()
    with pytest.raises(RuntimeError):
        ci_shell.retained_main()
    assert (root / 'evidence.cms').read_bytes() == original
    monkeypatch.setattr(ci_shell, 'ACTIVE_ROOT', None)
    with pytest.raises(RuntimeError):
        ci_shell.retained_main()
    assert sorted(path.name for path in tmp_path.iterdir()) == ['primary-import']


from test_lease_probe_lifetime import (  # noqa: F401, E402
    test_success_keeps_all_modes_and_actual_future_observation,
    test_main_timeout_preserves_worker_and_settles_before_shutdown,
    test_diagnostic_failure_cannot_erase_main_or_worker,
    test_cleanup_failure_retains_initiating_assertion,
    test_original_assertions_and_deadlines_have_ordered_unchanged_inventory,
    test_each_original_assertion_failure_remains_failure,
    probe,
    test_late_entered_never_supersedes_original_main_timeout,
    test_simultaneous_child_cleanup_is_serial_and_waits_are_labeled,
    test_independent_owned_descriptor_failures_attempt_every_stream,
    test_cleanup_diagnostic_errors_preserve_every_owned_action,
    test_unsettled_stream_is_retained_without_closing_a_reused_number,
    test_closed_stream_number_reuse_is_not_closed_by_later_cleanup,
)


@pytest.mark.parametrize('field', ['line', 'owner', 'route', 'source_sha256', 'expression_ast_sha256'])
def test_cleanup_setup_transition_refuses_every_anchor_binding_drift(field):
    template = json.loads((ROOT / '.github/release-source-guard/finite/source-template.json').read_bytes())
    row = next(row for row in template['anchor_inventory'] if row['path'] == 'tests/test_acp_cleanup.py')
    row[field] = 999 if field == 'line' else 'foreign'
    with pytest.raises(RuntimeError, match='cleanup_setup_anchor_preimage'):
        release_source_inputs.admit(template, ROOT, lambda root, name: (root / name).read_bytes())


@pytest.mark.parametrize('field', ['line', 'owner', 'route', 'source_sha256', 'expression_ast_sha256'])
def test_release_records_transition_refuses_every_original_anchor_drift(field):
    template = json.loads((ROOT / '.github/release-source-guard/finite/source-template.json').read_bytes())
    row = next(row for row in template['anchor_inventory'] if row['path'] == 'tests/test_v045_release_records.py')
    row[field] = 999 if field == 'line' else 'foreign'
    with pytest.raises(RuntimeError, match='release_records_anchor_preimage'):
        release_source_inputs.admit(template, ROOT, lambda root, name: (root / name).read_bytes())


def test_every_anchor_in_released_files_matches_current_pinned_source_and_expression():
    template = json.loads((ROOT / '.github/release-source-guard/finite/source-template.json').read_bytes())
    original = copy.deepcopy(template)
    release_source_inputs.admit(template, ROOT, lambda root, name: (root / name).read_bytes())
    for before, row in zip(original['anchor_inventory'], template['anchor_inventory'], strict=True):
        if row['path'] not in release_source_inputs.POST:
            assert row == before
            continue
        body = (ROOT / row['path']).read_bytes()
        assert row['source_sha256'] == hashlib.sha256(body).hexdigest() == release_source_inputs.POST[row['path']]
        calls = [n for n in ast.walk(ast.parse(body)) if isinstance(n, ast.Call)
                 and n.lineno == row['line']
                 and hashlib.sha256(ast.dump(n, include_attributes=False).encode()).hexdigest() == row['expression_ast_sha256']]
        assert len(calls) == 1
        assert {k: v for k, v in row.items() if k not in {'source_sha256', 'expression_ast_sha256'}} == {
            k: v for k, v in before.items() if k not in {'source_sha256', 'expression_ast_sha256'}}


def test_all_prepared_passive_anchors_match_current_source_bytes_and_expressions(monkeypatch):
    # Pure preparation control; Linux read-only custody is proved separately.
    import clock_source_inputs
    import candidate_template_source_inputs
    import approval_import_source_inputs
    import prepare_source
    template = json.loads((ROOT / '.github/release-source-guard/finite/source-template.json').read_bytes())
    def read(root, name):
        assert root in {ROOT, Path('/guard')}
        assert '..' not in Path(name).parts and not Path(name).is_absolute()
        base = ROOT / '.github/release-source-guard' if root == Path('/guard') else root
        return (base / name).read_bytes()
    monkeypatch.setattr(clock_source_inputs, 'read', read)
    clock_source_inputs.admit(template, ROOT)
    release_source_inputs.admit(template, ROOT, read)
    monkeypatch.setattr(prepare_source, 'ROOT', ROOT)
    monkeypatch.setattr(prepare_source, 'CLOCK_READER', read, raising=False)
    prepare_source.admit_ownership_document(template)
    prepare_source.admit_tracker_acquisition(template)
    candidate_template_source_inputs.admit(template, ROOT, read)
    approval_import_source_inputs.admit(template, ROOT, read)
    assert len(template['anchor_inventory']) == 176
    for row in template['anchor_inventory']:
        body = (ROOT / row['path']).read_bytes()
        assert row['source_sha256'] == hashlib.sha256(body).hexdigest(), row['path']
        calls = [n for n in ast.walk(ast.parse(body)) if isinstance(n, ast.Call)
                 and n.lineno == row['line']
                 and hashlib.sha256(ast.dump(n, include_attributes=False).encode()).hexdigest() == row['expression_ast_sha256']]
        assert len(calls) == 1, (row['path'], row['line'])


def test_actual_release_record_owner_has_current_passive_binding_before_any_native_launch(monkeypatch):
    import runpy
    import subprocess
    from finite.anchor_probe import observe
    template = json.loads((ROOT / '.github/release-source-guard/finite/source-template.json').read_bytes())
    release_source_inputs.admit(template, ROOT, lambda root, name: (root / name).read_bytes())
    state = {'checkout': str(ROOT), 'anchor_inventory': template['anchor_inventory']}
    module = runpy.run_path(str(ROOT / 'tests/test_v045_release_records.py'))
    captured = []
    class Observed(BaseException):
        pass
    def before_native(*args, **kwargs):
        captured.extend(observe(state, ROOT))
        raise Observed()
    monkeypatch.setattr(subprocess, 'run', before_native)
    with pytest.raises(Observed):
        module['test_v040_release_carriers_remain_exact_tag_bytes']()
    assert len(captured) == 1
    row = captured[0]
    assert row['path'] == 'tests/test_v045_release_records.py' and row['line'] == 130
    assert row['function'] == row['owner'] == 'test_v040_release_carriers_remain_exact_tag_bytes'
    assert row['source_sha256'] == release_source_inputs.POST[row['path']]


def test_every_finite_registry_source_binding_matches_current_file_bytes():
    rows = ast.literal_eval(ast.parse((ROOT / '.github/release-source-guard/finite/registry.py').read_bytes()).body[1].value)
    assert rows
    for row in rows:
        binding = row['source_binding']
        source = ROOT / Path(binding['path']).relative_to('/source')
        assert source.is_file(), binding['path']
        assert hashlib.sha256(source.read_bytes()).hexdigest() == binding['sha256'], row['class']
