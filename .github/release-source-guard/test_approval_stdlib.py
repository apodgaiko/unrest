"""Execution controls for unchanged approval fixtures without third-party startup."""
from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys

import pytest

from finite import approval_json_setup as setup, approval_stdlib as domain
from test_stdlib_backend import ROOT, RUNNER


@pytest.mark.parametrize('kind', sorted(domain.CLASSES))
@pytest.mark.parametrize('change', [None, 'case', 'flags', 'binding'])
def test_native_locale_projection_stays_on_exact_original_binding(kind, change):
    from primary_source_inputs import python_environment
    source, line, pin = setup.BINDINGS[kind]
    row = {'class': kind, 'case': 'tests/test_approval_recovery.py::test_actual_acp_owner_native_subprocess_order_and_cleanup[late_ack]',
           'source_binding': {'path': '/source/' + source, 'line': line, 'sha256': pin}}
    flags = [1, 1, 0]
    if change == 'case':
        row['case'] += '-foreign'
    elif change == 'flags':
        flags = [0, 0, 0]
    elif change == 'binding':
        row['source_binding']['sha256'] = 'foreign'
    assert python_environment({}, row, flags) == ({'LC_CTYPE': 'C.UTF-8'} if change is None else {})


@pytest.mark.parametrize(('mode', 'expected'), [
    ('original', None), ('checked-support', None), ('path', 'import_path_drift'),
    ('exec', 'unknown_exec'), ('forged', 'payload_dispatch'), ('module', 'new_module'),
    ('new-module', 'new_module'), ('support', 'support_exec'),
    ('import', 'unsealed_import'), ('extension-import', 'unsealed_import'),
    ('execution-spec', 'execution_spec_drift'), ('execution-bytes', 'isolated_profile_source_drift'),
])
def test_actual_approval_backend_closed_execution(tmp_path, mode, expected):
    if not (ROOT / 'tests/fixtures/approval_native_backend.py').is_file():
        pytest.skip('exact original fixture is absent from the source-free compartment')
    backend = tmp_path / 'controlled-backend'
    backend.write_bytes(f'#!{sys.executable}\n'.encode() + (ROOT / 'tests/fixtures/approval_native_backend.py').read_bytes())
    body = RUNNER.replace("payload={'target':str(source/domain.SCRIPT)}", "payload={'target':str(Path.cwd()/'controlled-backend'),'sys_argv':[str(Path.cwd()/'controlled-backend'),'app-server'],'orig_argv':[sys.executable,'-I','-S',str(Path.cwd()/'controlled-backend'),'app-server']}")
    body = body.replace("state={'guard':", "state={'class':'source-approval-python-backend','checkout':str(source),'owned_root':str(Path.cwd()),'product_pins':" + repr(setup.PURE) + ",'guard':")
    script = tmp_path / 'control.py'
    script.write_text(body)
    result = subprocess.run([sys.executable, '-I', '-S', str(script), str(ROOT), mode],
                            cwd=tmp_path, env={**os.environ, 'PYTHONPATH': '/forbidden/site'},
                            input='{"id":1,"method":"initialize","params":{}}\n',
                            text=True, capture_output=True, timeout=15)
    if expected is None:
        assert result.returncode == 0, result.stderr
        if mode == 'original':
            assert json.loads(result.stdout)['id'] == 1
        else:
            assert result.stdout.strip() == 'checked-support-complete'
    else:
        assert result.returncode != 0
        assert (expected if expected == 'isolated_profile_source_drift'
                else 'stdlib_backend_' + expected) in result.stderr, result.stderr


def test_translation_is_not_callable_as_an_alternative_admission():
    with pytest.raises(RuntimeError, match='original_admission'):
        domain.translate({'class': 'source-approval-python-backend'}, [sys.executable, '/owned/adapter', '/owned/scenario'],
                         {'guard': '/no/guard', 'direct_support': {'files': {}}})


def test_fixture_execution_controls_stay_in_source_bound_host_step():
    for name in ('v046-source-readiness.yml', 'ci.yml'):
        workflow = (ROOT / '.github/workflows' / name).read_text()
        selected = [line for line in workflow.splitlines() if 'run:' in line and 'test_approval_stdlib.py' in line]
        assert len(selected) == 1 and 'PYTHONDONTWRITEBYTECODE=1 env -u CODEX_PATH uv run pytest -q' in selected[0]
    assert '"/guard/test_approval_stdlib.py"' not in (Path(__file__).with_name('compartment_probe.py')).read_text()


def test_same_name_helper_cannot_mint_post_admission_translation(monkeypatch):
    from finite import approval_routes
    monkeypatch.setattr(domain, 'support', lambda state, name: vars(approval_routes))
    def registration():
        registered = {'class': 'source-approval-python-backend'}
        translated = [sys.executable, '/owned/backend', 'app-server']
        return domain.translate(registered, translated, {'case': approval_routes.CASE})
    with pytest.raises(RuntimeError, match='original_admission'):
        registration()


@pytest.mark.parametrize('container', [list, tuple])
def test_activation_replay_matches_original_admit_vector_normalization(monkeypatch, container):
    from types import SimpleNamespace
    vector = [Path('/original/backend'), 'app-server']
    translated = [sys.executable, '-I', '-S', '/original/backend', 'app-server']
    registration = {'class': 'source-approval-python-backend'}
    seen, rows = [], []
    def select(argv, *args):
        seen.append(argv)
        assert type(argv) is list and argv == ['/original/backend', 'app-server']
        return registration, translated
    def shared(activation):
        seen.append('current-stdlib-consumed')
    monkeypatch.setattr(domain, 'support', lambda state, name:
        {'select': select} if name == 'approval_routes.py' else {'shared': shared})
    activation = SimpleNamespace(state={}, emit=rows.append,
        refuse=lambda reason: pytest.fail(reason))
    original = container(vector)
    domain.activation(activation, None, {'args': original, 'launch_token': 'bound'},
                      translated, None, {}, registration)
    assert list(original) == vector
    assert seen == [['/original/backend', 'app-server'], 'current-stdlib-consumed']
    assert len(rows) == 1 and rows[0]['original_admission_retained']
