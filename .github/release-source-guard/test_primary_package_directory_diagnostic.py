"""Directory observations cannot turn the original refusal into acceptance."""
from pathlib import Path
import ast
import os
from types import SimpleNamespace

import pytest

from primary_package_directory_diagnostic import metadata, refusal, capture
from structured_evidence import identity_check, EvidenceRefused
from test_primary_package_entry import execution


@pytest.mark.parametrize('epoch', ['01', '02', '03', '04', '05', '06'])
def test_exact_new_finite_family(epoch):
    identity_check(execution('cache-lineage-' + epoch))


@pytest.mark.parametrize('epoch', ['00', '07', '1', '001', '01-extra', '../01', '', '06/main'])
def test_no_new_family_prefix_authority(epoch):
    with pytest.raises(EvidenceRefused):
        identity_check(execution('cache-lineage-' + epoch))


@pytest.mark.parametrize('change', ['wrong-workflow', 'lookalike', 'wrong-repository'])
def test_new_family_context(change):
    value = execution('cache-lineage-01')
    if change == 'wrong-workflow':
        value['workflow_ref'] = value['workflow_ref'].replace('v046-source-readiness.yml', 'ci.yml')
    elif change == 'lookalike':
        value['workflow_ref'] += '-lookalike'
    else:
        value['repository'] = 'foreign/unrest'
    with pytest.raises(EvidenceRefused):
        identity_check(value)


def test_metadata_observes_membership_without_opening_file_bodies(tmp_path):
    initial = metadata(tmp_path)
    assert initial['empty'] is True and initial['inode'] == tmp_path.stat().st_ino
    (tmp_path / 'leaf').write_text('private-canary')
    result = metadata(tmp_path)
    assert result['leaf_count'] == 1 and not result['empty']
    assert 'private-canary' not in str(result) and 'leaf' not in str(result['leaf_names_sha256'])


def test_symlink_is_refused(tmp_path):
    target = tmp_path / 'target'
    target.mkdir()
    alias = tmp_path / 'alias'
    alias.symlink_to(target)
    with pytest.raises(OSError):
        metadata(alias)


def test_path_replacement_during_inspection_refused(tmp_path, monkeypatch):
    directory = tmp_path / 'directory'
    directory.mkdir()
    original = os.listdir
    changed = False
    def replace(fd):
        nonlocal changed
        result = original(fd)
        if not changed:
            changed = True
            directory.rename(tmp_path / 'old')
            directory.mkdir()
        return result
    monkeypatch.setattr(os, 'listdir', replace)
    with pytest.raises(RuntimeError, match='diagnostic_race'):
        metadata(directory)


def test_capture_failure_is_data_only():
    producers = SimpleNamespace(common={'cache': '/foreign'})
    capture(producers, {}, 'before-original-child')
    assert producers.package_directory_diagnostic_error == 'RuntimeError'


def test_refusal_requires_original_frame():
    with pytest.raises(RuntimeError, match='original_frame'):
        refusal(object(), {}, RuntimeError('primary_cache_output_extra_directory'), object())


@pytest.mark.parametrize('diagnostic_fails', [False, True])
def test_original_directory_exception_identity_preserved(monkeypatch, diagnostic_fails):
    import primary_package_directory_diagnostic as diagnostic
    original = RuntimeError('primary_cache_output_extra_directory')
    class Original:
        def completed_cache(self, event, trace):
            raise original
    path = Path(__file__).with_name('primary_package_build.py')
    node = next(n for n in ast.parse(path.read_bytes()).body
                if isinstance(n, ast.ClassDef) and n.name == 'PackageProducers')
    namespace = {'NativeProducers': Original}
    exec(compile(ast.Module(body=[node], type_ignores=[]), str(path), 'exec'), namespace)
    producers = namespace['PackageProducers']()
    producers.uv = {12: {'pid': 12}}
    def observe(*args):
        if diagnostic_fails:
            raise ValueError('diagnostic canary')
        return {'authority_granted': False}
    monkeypatch.setattr(diagnostic, 'refusal', observe)
    with pytest.raises(RuntimeError) as raised:
        producers.completed_cache({'pid': 12}, object())
    assert raised.value is original
    assert producers.package_cache_refusal['authority_granted'] is False


@pytest.mark.parametrize(('ref', 'workflow'), [
    ('00', 'v0.4.6 source guard readiness'), ('07', 'v0.4.6 source guard readiness'),
    ('1', 'v0.4.6 source guard readiness'), ('01-extra', 'v0.4.6 source guard readiness'),
    ('01', 'other workflow'), ('06/main', 'v0.4.6 source guard readiness'),
])
def test_controller_rejects_before_script_or_external_operation(monkeypatch, ref, workflow):
    import ci_shell
    monkeypatch.setattr(ci_shell.sys, 'argv', ['ci_shell.py', '--package-test', '/absent-script'])
    monkeypatch.setenv('GITHUB_WORKFLOW', workflow)
    monkeypatch.setenv('GITHUB_REF', 'refs/heads/codex/source-guard-structured-20261018-package-entry-cache-lineage-' + ref)
    with pytest.raises(RuntimeError, match='primary_package_test_workflow_identity'):
        ci_shell.main()
