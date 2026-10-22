"""All and only the original nine controlled approval scenarios are admitted."""
import ast
from pathlib import Path

import pytest

from finite import approval_routes as routes


@pytest.mark.parametrize('mode', routes.MODES)
def test_each_original_mode_is_derived_from_its_exact_case(mode):
    assert routes.selected_mode(routes.PREFIX + '[' + mode + ']') == mode
    assert routes.selected_mode(routes.PREFIX + '[' + mode + ']-foreign') is None


@pytest.mark.parametrize('case', [None, '', 'foreign', routes.PREFIX, routes.PREFIX + '[new]',
                                   routes.PREFIX + '[success] extra'])
def test_other_cases_gain_no_controlled_approval_launch(case):
    assert routes.selected_mode(case) is None
    assert routes.select([], None, None, {'case': case}, None, None) is None


def test_original_mode_parameters_and_backend_identity_gates_remain_closed():
    path = Path(routes.__file__)
    source = path.read_text()
    tree = ast.parse(source)
    assert source.count('scenario["mode"] != mode') == 1
    assert source.count('env["CONTROLLED_APPROVAL_MODE"] != mode') == 1
    assert 'backend_path.read_bytes() != backend_body' in source
    assert 'backend.read_bytes() != body' in source
    assert 'sha(backend) != local["backend_digest"]' in source
    assert not any(isinstance(n, ast.Call) and ast.unparse(n.func) in {'subprocess.Popen', 'os.system'}
                   for n in ast.walk(tree))


@pytest.mark.parametrize('boundary, mode', routes.DURABLE_MODES.items())
def test_exact_durable_boundaries_derive_original_modes(boundary, mode):
    from finite.approval_run_owner import boundary as select_boundary
    case = routes.DURABLE_PREFIX + '[' + boundary + ']'
    assert routes.selected_mode(case) == mode
    assert select_boundary(case) == boundary
    assert select_boundary(case + '-foreign') is None


def test_closed_bulk_diagnostic_keeps_existing_budget_and_original_deadlines():
    from primary_policy import TEST_APPROVAL_CLOSURE_CASES, TEST_SEAM_ROOT_SECONDS, root_seconds
    from test_primary_source_entry import inputs, COMMAND
    from primary_source_inputs import test_plan as make_plan
    text, _ = inputs()
    assert len(TEST_APPROVAL_CLOSURE_CASES) == 33
    script = (COMMAND + ' ' + ' '.join(TEST_APPROVAL_CLOSURE_CASES)).encode()
    plan = make_plan(script, text, 'TEST-positive')
    assert plan['timeout_seconds'] == root_seconds(plan) == TEST_SEAM_ROOT_SECONDS == 600
    assert plan['source_checkpoint_ready'] is False
    with pytest.raises(RuntimeError):
        make_plan((COMMAND + ' ' + ' '.join(TEST_APPROVAL_CLOSURE_CASES[:-1])).encode(), text, 'TEST-positive')


def test_approval_inventory_pipe_keeps_original_descriptor_custody(monkeypatch):
    import owned_multiprocess_authority as owned
    import approval_pipe_custody as pipe
    authority = object.__new__(owned.SourceAuthority)
    marker = object()
    monkeypatch.setattr(owned.OriginalSourceAuthority, 'pipe_binding', lambda *args: marker)
    monkeypatch.setattr(pipe, 'binding', lambda *args: pytest.fail('original result bypassed'))
    assert authority.pipe_binding(42) is marker


def test_unrelated_class_gets_no_approval_inventory_descriptor():
    import approval_pipe_custody as pipe
    from types import SimpleNamespace
    assert pipe.binding(SimpleNamespace(bound={42: {'registration': {'class': 'foreign'}}}), 42) is None


def approval_pipe_fixture(monkeypatch):
    import approval_pipe_custody as pipe
    from types import SimpleNamespace
    import copy
    original_read = Path.read_bytes
    import hashlib
    bodies = {Path('/source', pipe.SOURCE): b'synthetic original ACP caller',
              Path('/source', pipe.TEST): b'synthetic original approval cases'}
    monkeypatch.setattr(pipe, 'PIN', hashlib.sha256(bodies[Path('/source', pipe.SOURCE)]).hexdigest())
    monkeypatch.setattr(pipe, 'TEST_PIN', hashlib.sha256(bodies[Path('/source', pipe.TEST)]).hexdigest())
    monkeypatch.setattr(Path, 'read_bytes', lambda p: bodies[p] if p in bodies else original_read(p))
    monkeypatch.setattr(pipe, 'identity', lambda pid: {'ppid': 7})
    row = {'kind': 'exact_controlled_approval_registration', 'owner_pid': 7,
           'class': 'source-approval-mcp', 'source_binding': {'path': '/source/' + pipe.SOURCE,
           'line': 2191, 'sha256': pipe.PIN}, 'argv_sha256': 'a' * 64,
           'case': routes.PREFIX + '[success]', 'native_provider': False,
           'pipe_device': 1, 'pipe_inode': 2}
    rows = [copy.deepcopy(row), copy.deepcopy(row)]
    selected = {key: row[key] for key in ('class', 'source_binding', 'argv_sha256')}
    authority = SimpleNamespace(bound={42: {'registration': selected}},
                                manifest={'product_pins': {pipe.SOURCE: pipe.PIN, pipe.TEST: pipe.TEST_PIN}},
                                supervisor=SimpleNamespace(events=lambda: rows))
    return pipe, authority, rows


def test_only_two_identical_original_approval_registrations_bind_pipe(monkeypatch):
    pipe, authority, rows = approval_pipe_fixture(monkeypatch)
    assert pipe.binding(authority, 42) == rows[0]


@pytest.mark.parametrize('mutation', ['one', 'extra', 'different', 'foreign_case', 'native',
                                       'negative_fd', 'bool_fd', 'source_pin', 'argv', 'parent'])
def test_approval_pipe_registration_mutations_refuse(monkeypatch, mutation):
    pipe, authority, rows = approval_pipe_fixture(monkeypatch)
    if mutation == 'one':
        rows.pop()
    elif mutation == 'extra':
        rows.append(dict(rows[0]))
    elif mutation == 'different':
        rows[1]['pipe_inode'] = 9
    elif mutation == 'source_pin':
        authority.manifest['product_pins'][pipe.SOURCE] = '0' * 64
    else:
        key, value = {'foreign_case': ('case', 'foreign'), 'native': ('native_provider', True),
                      'negative_fd': ('pipe_inode', -1), 'bool_fd': ('pipe_inode', True),
                      'argv': ('argv_sha256', 'b' * 64), 'parent': ('owner_pid', 8)}[mutation]
        for row in rows:
            row[key] = value
    with pytest.raises(RuntimeError):
        pipe.binding(authority, 42)
