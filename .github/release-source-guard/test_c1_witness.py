"""Closed C1 custody vectors and original controlled campaign selection."""
from pathlib import Path
import hashlib
import json
import sys
from types import SimpleNamespace

import pytest

SUPPORT = Path(__file__).parent
sys.path.insert(0, str(SUPPORT))
from finite import orders_git as route  # noqa: E402
from finite.orders_git_data import CASES, PINS, SITES  # noqa: E402
from test_orders_git import named  # noqa: E402
import orders_git_custody as native  # noqa: E402

ROOT = SUPPORT.parent.parent
CASE = 'tests/test_controlled_python_acp.py::test_single_c1_fixed_timing_protocol_witness'
PRODUCT = 'src/unrest_harness/experimental_cohort.py'
CALLS = {567: ['init', '--initial-branch=main', '--object-format=sha1'],
         570: ['add', '.'], 571: ['commit', '-m', 'base'], 572: ['rev-parse', 'HEAD']}


def config(path):
    git = path / '.git'
    git.mkdir()
    (git / 'config').write_text('[core]\nrepositoryformatversion = 0\nfilemode = true\nbare = false\nlogallrefupdates = true\n')


@pytest.mark.parametrize('line', sorted(CALLS))
@pytest.mark.parametrize('change', [None, 'case', 'root', 'episode', 'vector', 'environment',
    'transport', 'fixture', 'runtime', 'configuration', 'timing', 'rounds', 'defect',
    'streaming', 'reuse', 'native', 'source', 'callable', 'globals'])
def test_c1_setup_exact_original_context(tmp_path, line, change):
    from unrest_harness import experimental_cohort as cohort, experimental_custody as custody
    from unrest_harness.experimental_session import ControlledTransport
    directory = tmp_path / 'pytest/case/campaign/C1/base'
    directory.mkdir(parents=True)
    if line != 567:
        config(directory)
    def code(path):
        return compile(Path(path).read_bytes(), str(path), 'exec', dont_inherit=True)
    transport = ControlledTransport(ROOT / 'tests/fixtures/controlled_python_acp.py', Path(sys.executable))
    local = dict(original=directory, episodes=('C1',), episode='C1', trusted_process=True,
                 package=None, fixture=ROOT / 'tests/fixtures/experimental_session_app_server.py',
                 transport=transport, configuration=None, controlled_timing=None,
                 controlled_rounds=None, controlled_terminal_defect=False, streaming=True, reuse=True)
    caller = SimpleNamespace(f_code=named(code(cohort.__file__), 'campaign'),
        f_globals=vars(cohort), f_lineno=line, f_locals=local)
    helper = SimpleNamespace(f_code=named(code(custody.__file__), 'git'), f_globals=vars(custody),
        f_lineno=38, f_back=caller, f_locals={'root': directory, 'arguments': tuple(CALLS[line])})
    vector = ['/usr/bin/git', '--no-replace-objects', *CALLS[line]]
    environment = dict(route.ENVIRONMENT)
    state = {'checkout': str(ROOT), 'owned_root': str(tmp_path), 'case': CASE,
        'runtime': {'realpath': str(Path(sys.executable).resolve())},
        'product_pins': dict(PINS), 'isolated_source_code': code, 'isolated_named': named}
    if change == 'case':
        state['case'] += '[other]'
    elif change in ('root', 'episode'):
        old, new = ('campaign', 'foreign') if change == 'root' else ('C1', 'P1')
        directory = Path(str(directory).replace('/' + old + '/', '/' + new + '/'))
        directory.mkdir(parents=True)
        helper.f_locals['root'] = local['original'] = directory
    elif change == 'vector':
        vector.append('--extra')
    elif change == 'environment':
        environment['GIT_CONFIG_GLOBAL'] = '/foreign'
    elif change == 'transport':
        local['transport'] = object()
    elif change == 'fixture':
        local['fixture'] = ROOT / 'tests/fixtures/controlled_python_acp.py'
    elif change == 'runtime':
        state['runtime']['realpath'] = '/foreign/python'
    elif change == 'configuration':
        local['configuration'] = object()
    elif change == 'timing':
        local['controlled_timing'] = ((0, 0), (0, 0))
    elif change == 'rounds':
        local['controlled_rounds'] = 1
    elif change == 'defect':
        local['controlled_terminal_defect'] = True
    elif change in ('streaming', 'reuse'):
        local[change] = False
    elif change == 'native':
        local['package'] = ROOT
    elif change == 'source':
        state['product_pins'][PRODUCT] = '0' * 64
    elif change == 'callable':
        caller.f_code = (lambda: None).__code__
    elif change == 'globals':
        caller.f_globals = dict(vars(cohort))
    selected = route.matches(vector, directory, environment, state, [helper],
                             {'PINS': PINS, 'SITES': SITES}, CASES)
    assert (selected is not None) is (change is None)
    if selected:
        registration = {**selected, 'owner_pid': 20, 'token': 'exact'}
        launch = {'registration': registration, 'owner_pid': 20, 'token': 'exact',
                  'cwd': str(directory), 'bootstrap_sha256': None,
                  'transformed_argv_sha256': hashlib.sha256(json.dumps(vector).encode()).hexdigest(),
                  'environment_sha256': hashlib.sha256(json.dumps(environment, sort_keys=True).encode()).hexdigest()}
        assert native.eligible(launch, vector, environment, str(directory), state, str(ROOT))


@pytest.mark.parametrize('candidate,scope', [('candidate-0', 'lane_a.txt'), ('candidate-1', 'lane_b.txt')])
@pytest.mark.parametrize('owner,line,args', [
    ('seal', 193, ['add', '--']), ('seal', 194, ['diff', '--cached', '--name-only', 'a' * 40]),
    ('seal', 197, ['commit', '--allow-empty', '-m', 'sealed candidate']),
    ('seal', 198, ['rev-parse', 'HEAD']), ('integrate', 235, ['add', '--']),
    ('integrate', 236, ['diff', '--cached', '--name-only', 'a' * 40]),
    ('integrate', 239, ['commit', '--allow-empty', '-m', 'authored lane integration']),
    ('integrate', 241, ['rev-parse', 'HEAD'])])
def test_c1_only_original_seal_and_integration_paths(tmp_path, candidate, scope, owner, line, args):
    path = tmp_path / 'pytest/case/campaign/C1' / (candidate if owner == 'seal' else 'integration')
    path.mkdir(parents=True)
    config(path)
    args = [*args, scope] if args == ['add', '--'] else args
    binding = {'function': owner, 'line': line}
    vector = ['/usr/bin/git', '--no-replace-objects', *args]
    assert route.repository_profile(vector, path, tmp_path, binding, 'campaign/C1')
    if owner == 'seal' and args[:2] == ['add', '--']:
        other = 'lane_b.txt' if scope == 'lane_a.txt' else 'lane_a.txt'
        assert not route.repository_profile([*vector[:-1], other], path, tmp_path, binding, 'campaign/C1')
    assert not route.repository_profile([*vector, '--extra'], path, tmp_path, binding, 'campaign/C1')
    assert not route.repository_profile(vector, path, tmp_path, binding, 'campaign/P1')


def test_c1_roster_and_setup_keep_native_negative_routes_out():
    from finite import backend_postimage_catalog as catalog, mock_backend_setup as setup
    from primary_policy import TEST_C1_WITNESS_CASES
    from primary_source_inputs import test_plan
    assert CASES[CASE] == 'campaign/C1'
    assert setup.WITNESS_CASES == frozenset({CASE})
    assert catalog.CASES[CASE]['script_sha256'] == setup.BACKEND_PIN
    assert setup.selected_script({'class': 'source-controlled-backend-postimage', 'case': CASE,
        'checkout': str(ROOT), 'owned_root': '/owned'}, {'target': '/owned/fake-app-server'}) == (
            '/owned/fake-app-server', setup.BACKEND_PIN)
    assert not any('native_pin_refusal' in case for case in TEST_C1_WITNESS_CASES)
    script = ('env -u CODEX_PATH uv run pytest -q ' + ' '.join(TEST_C1_WITNESS_CASES)).encode()
    plan = test_plan(script, 'diagnostic', 'TEST-positive')
    assert plan['timeout_seconds'] == 600 and plan['source_checkpoint_ready'] is False
    for extra in (b' --maxfail=1', b' -k timing'):
        with pytest.raises(RuntimeError, match='test_script'):
            test_plan(script + extra, 'diagnostic', 'TEST-positive')


@pytest.mark.parametrize('line,args', [(36, ['init', '--initial-branch=main', '--object-format=sha1']),
    (39, ['add', '.']), (40, ['commit', '-m', 'finite fixture']), (41, ['rev-parse', 'HEAD'])])
def test_c1_does_not_admit_other_fixture_setup_sites(tmp_path, line, args):
    path = tmp_path / 'pytest/case/campaign/C1/base'
    path.mkdir(parents=True)
    if line != 36:
        config(path)
    assert not route.repository_profile(['/usr/bin/git', '--no-replace-objects', *args],
        path, tmp_path, {'function': 'setup', 'line': line}, 'campaign/C1')


@pytest.mark.parametrize('kind', ['source-canonical-stdlib-backend', 'source-canonical-stdlib-acp'])
@pytest.mark.parametrize('change', [None, 'case', 'flags', 'binding'])
def test_c1_stdlib_locale_projection_is_exact(kind, change):
    from primary_source_inputs import python_environment
    source = 'src/unrest_harness/experimental_session.py' if kind.endswith('backend') else 'tests/fixtures/controlled_python_acp.py'
    pin = '7a3df1d049cd8a72aac48bc376154f7701335397ad8a0e0634cf2d0a9509cbd2' if kind.endswith('backend') else 'f5134a2d79b348b70b05a66566ff65d0049f102665200a22f3a6fcbd1c4f58be'
    binding = {'path': '/source/' + source, 'line': 506 if kind.endswith('backend') else 1, 'sha256': pin}
    if kind.endswith('backend'):
        binding['function'] = '_open_role_owned'
    row = {'class': kind, 'case': CASE, 'source_binding': binding}
    flags = [1, 1, 0]
    if change == 'case':
        row['case'] += '-foreign'
    elif change == 'flags':
        flags = [0, 0, 0]
    elif change == 'binding':
        binding['sha256'] = 'foreign'
    assert python_environment({}, row, flags) == ({'LC_CTYPE': 'C.UTF-8'} if change is None else {})
