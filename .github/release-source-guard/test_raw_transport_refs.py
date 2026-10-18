import ast
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).parent


@pytest.mark.parametrize('suffix', ['01', '02', '03', '04',
                                    '00', '05', '06', '07', '1', '01-extra', '', 'foreign'])
@pytest.mark.parametrize('workflow', ['v0.4.6 source guard readiness', 'CI', 'foreign'])
def test_finite_raw_transport_controller_refs(suffix, workflow):
    tree = ast.parse((ROOT / 'ci_shell.py').read_bytes())
    gate = next(node for node in ast.walk(tree) if isinstance(node, ast.If)
                and isinstance(node.body[0], ast.Raise)
                and any(isinstance(child, ast.Constant) and child.value == 'primary_test_workflow_identity'
                        for child in ast.walk(node.body[0])))
    environment = {'GITHUB_WORKFLOW': workflow,
                   'GITHUB_REF': 'refs/heads/codex/source-guard-structured-20261018-raw-record-transport-' + suffix}
    refusal = eval(compile(ast.Expression(gate.test), 'actual_raw_transport_gate', 'eval'),
                   {'os': SimpleNamespace(environ=environment)})
    assert refusal is not (workflow == 'v0.4.6 source guard readiness'
                           and suffix in {'01', '02', '03', '04'})


@pytest.mark.parametrize('suffix', ['01', '02', '03', '04',
                                    '00', '05', '06', '07', '1', '01-extra', '', 'foreign'])
def test_finite_raw_transport_evidence_refs(suffix):
    from structured_evidence import identity_check, EvidenceRefused
    row = {'repository': 'apodgaiko/unrest', 'head_sha': 'a' * 40, 'workflow_sha': 'a' * 40,
           'run_id': '1', 'run_attempt': '1', 'support_sha256': 'b' * 64,
           'artifact_name': 'v046-source-primary-source-positive-1-1',
           'workflow_ref': ('apodgaiko/unrest/.github/workflows/v046-source-readiness.yml@'
                            'refs/heads/codex/source-guard-structured-20261018-raw-record-transport-' + suffix)}
    if suffix in {'01', '02', '03', '04'}:
        identity_check(row)
    else:
        with pytest.raises(EvidenceRefused):
            identity_check(row)


@pytest.mark.parametrize('tail', ['raw-record-transport', 'raw-record-transportx-01',
                                  'raw-record-transport01', 'raw-record-transport--01',
                                  'raw-record-transport-01-extra'])
def test_raw_transport_family_lookalikes_refused_at_both_gates(tail):
    from structured_evidence import identity_check, EvidenceRefused
    ref = 'refs/heads/codex/source-guard-structured-20261018-' + tail
    row = {'repository': 'apodgaiko/unrest', 'head_sha': 'a' * 40, 'workflow_sha': 'a' * 40,
           'run_id': '1', 'run_attempt': '1', 'support_sha256': 'b' * 64,
           'artifact_name': 'v046-source-primary-source-positive-1-1',
           'workflow_ref': 'apodgaiko/unrest/.github/workflows/v046-source-readiness.yml@' + ref}
    with pytest.raises(EvidenceRefused):
        identity_check(row)
    tree = ast.parse((ROOT / 'ci_shell.py').read_bytes())
    gate = next(node for node in ast.walk(tree) if isinstance(node, ast.If)
                and isinstance(node.body[0], ast.Raise)
                and any(isinstance(child, ast.Constant) and child.value == 'primary_test_workflow_identity'
                        for child in ast.walk(node.body[0])))
    assert eval(compile(ast.Expression(gate.test), 'actual_raw_transport_gate', 'eval'),
                {'os': SimpleNamespace(environ={'GITHUB_WORKFLOW': 'v0.4.6 source guard readiness',
                                               'GITHUB_REF': ref})}) is True

